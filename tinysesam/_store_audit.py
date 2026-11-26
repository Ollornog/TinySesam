"""The store part `audit`: the audit log.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    norm_identifier,
)


def audit_log(self, event, username=None, ip=None, detail=None):
    # The column is called `ip` — so an IP stands in it (B5-15). A real address in its
    # canonical form; everything else (a test peer, a Unix socket) only free of control characters
    # and capped, so that neither the panel nor `tinysesam audit` shows an invented row.
    if ip is not None:
        from . import security as _sec
        norm = _sec.ip_normalized(ip)
        if norm is None:
            ip = _sec.for_log(ip) or None
        else:
            ip = _sec.ip_pseudonym(norm) if self.audit_ip_pseudonym else norm
    self._exec("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
               (_store._now(), event, username, ip, detail))


def gc_audit(self, older_than_ts: int) -> int:
    """Delete audit rows before a point in time (`audit_retention_days`, B5-11)."""
    return self._exec("DELETE FROM audit WHERE ts < ?", (int(older_than_ts),)).rowcount


def anonymize_audit(self, username, replacement, additional=(), since=None, since_id=0,
                        unlimited=(), from_ids=None) -> int:
    """Take an account out of the audit log without deleting the rows (H-13).

    The row "on the 3rd at 14:02 a password was reset, from this IP" stays for
    forensics; WHO it was then stands only as `replacement`. `additional` are
    additional identifiers (the email address): under it, sign-in attempts stand in the
    column `username` (`find_user` accepts the address), and it occurs in the detail text.

    In the detail text the USERNAME is replaced only where one stands — `actor=<name>` and the head of
    `user_create`. Freely replacing every identical word hit
    foreign rows: with the account `admin`, `admin=0->1` in the role change of an
    OTHER account became `deleted#2=0->1`, with `password` the method of every failed attempt. An
    identifier with `@`, on the other hand, is unmistakable and is replaced everywhere.

    `seit`/`since_id` restrict this to rows from the creation of the account (`setup_limit`,
    `remove_account`): what was written before under the name or with the address
    did not belong to this account. Identifiers in `unlimited` apply without the limit. Without
    `seit` every row applies. More precise is `from_ids` (`{bucket: audit_from}` from `identifier_limits`,
    G2): from the joining of the identifier instead of from creation — otherwise, when deleting an
    account that had taken over a freed name, the previous owner's row was
    rewritten too. Where an identifier has none (existing data), `seit` applies.

    **The search in the detail text is a scan** — a substring search (`instr`) that no
    B-tree index narrows down; `idx_audit_name_ts`/`idx_audit_ts` help only the column
    `username` and the period from `seit`. For an unrestricted address (deletion by
    an admin, `address_unlimited`) it reads the whole audit log, and that grows without
    `audit_retention_days` without limit. Until 2026-09-26 this scan ran in ONE
    write transaction, under the write lock (`_lock`) and with an open SQLite transaction:
    every sign-in, every audit entry, every other worker waited out the whole search (G4).
    Now it reads in blocks by `id` (`_ANONYMOUS_BLOCK` rows) WITHOUT a write transaction and
    writes only the hits, per block in a short transaction — the row read there fresh
    and re-checked, so that nothing is overwritten that has changed since reading.
    The search runs up to the most recent row at its start; what comes afterwards was written
    by someone after the deletion.

    **What the deletion promise left out until 2026-09-27** (lockouts/counters audit round, F4 — already
    so on main):

    * **Every spelling of the typed identifier** (4a): `login_fail` writes the RAW
      input (`Émile `, ` emile@example.com`, `ＥＭＩＬＥ@example.com`), counted in the
      bucket (`norm_identifier`). `lower(username)` hit only ASCII variants of these. The block scan
      therefore also compares the column `username` in the bucket (SQL function `tinysesam_identifier`,
      only for queries of this connection), with the same limits per identifier. If a
      REMAINING account shares the bucket (namesake from existing data, as with
      `delete_attempts_for`), it stays with `lower()` — otherwise it would hit its rows.
    * **Earlier names and addresses** (4b): from the own rows `username_changed old=…` and
      `email_changed old=…` (`_earlier_identifiers`), each in the span in which the account
      carried them — the sign-in under the old name would otherwise keep standing with its IP.
    * **Values in the own rows** (4c): in every row whose `username` is afterwards
      the replacement name, the values of `old=`, `new=` and `to=` — the never redeemed address change,
      the address from LDAP/SAML, the old name.
    """
    if not username:
        return 0
    import re as _re
    without_deadline = {str(w) for w in unlimited if w}
    unclosed = self._WITHOUT_UPPER_LIMIT

    def start_from(value) -> tuple:
        if value in without_deadline:
            return (-1, -1, 0, -1, unclosed)
        waterline = (from_ids or {}).get(norm_identifier(value))
        if waterline is not None:
            return (-1, -1, 0, int(waterline), unclosed)
        if since is None:
            return (-1, -1, 0, -1, unclosed)
        return (int(since), int(since), int(since_id or 0), -1, unclosed)
    limit = "((ts > ? OR (ts = ? AND id >= ?)) AND id > ? AND id <= ?)"
    setup = (-1, -1, 0, -1) if since is None else (int(since), int(since), int(since_id or 0), -1)
    # Every identifier with its span: today's, then the earlier ones (4b) — read BEFORE
    # anything is rewritten; afterwards the rows they come from stand under `replacement`.
    identifiers = [(str(w), start_from(str(w))) for w in (username, *additional) if w]
    identifiers += self._earlier_identifiers(identifiers, setup, limit)
    # Compared folded (4a) only where no remaining account shares the bucket.
    fold = {t for t in {norm_identifier(w) for w, _ in identifiers} - {""}
              if self.account_by_bucket(t) is None}
    # The column `username`: via `idx_audit_name_ts`, short — one transaction.
    with self._writing():
        n = 0
        for value, limits in identifiers:
            n += self.db.execute(
                f"UPDATE audit SET username=? WHERE lower(username)=lower(?) AND {limit}",
                (replacement, value, *limits)).rowcount
        self.db.commit()
    above = int(self._one("SELECT max(id) AS m FROM audit")["m"] or 0)
    for value, limits in identifiers:
        w = _re.escape(value)
        end = r"(?![\w@.=-])"
        if "@" in value:
            pattern = _re.compile(r"(?<![\w@.-])" + w + end, _re.IGNORECASE)
        else:
            pattern = _re.compile(r"(?<![\w@.-])(actor)=" + w + end, _re.IGNORECASE)
        bucket = norm_identifier(value)
        folded = bucket in fold

        def rewrite(event, old, value=value, w=w, pattern=pattern) -> str:
            if "@" in value:
                return pattern.sub(replacement, old)
            new = pattern.sub(lambda m: m.group(1) + "=" + replacement, old)
            if event == "user_create":   # detail: "<name> service=…"
                new = _re.sub(r"^" + w + r"(?=\s|$)", replacement, new, count=1, flags=_re.IGNORECASE)
            return new

        def name_hits(name, bucket=bucket, folded=folded) -> bool:
            return folded and name is not None and name != replacement and norm_identifier(name) == bucket
        # Where the search begins: behind the watermark, or at the first row from `seit`
        # — before that no row satisfies the limit. `id + 0`, so that SQLite finds the minimum via
        # `idx_audit_ts` (only the rows from `seit`) and does not walk the table from the first
        # `id` until `ts` fits — for a young account that would be the whole log.
        below = max(limits[3], 0)
        if limits[0] >= 0:
            first = self._one("SELECT min(id + 0) AS m FROM audit WHERE ts >= ?",
                              (limits[0],))["m"]
            below = max(below, int(first) - 1 if first is not None else above)
        finish = min(above, limits[4])
        # The column `username` in the bucket (4a) only where folding is done: the function costs a
        # Python call per row.
        also_name = "OR tinysesam_identifier(username) = ?" if folded else ""
        while below < finish:
            until = min(below + self._ANONYMOUS_BLOCK, finish)
            # The block via the primary key (`id > ? AND id <= ?`, so it stands in the plan) —
            # never via `idx_audit_ts`: otherwise each block would read all rows from `seit`, and the
            # search would become quadratic (tests/test_audit_round2.py checks the plan).
            candidates = {z["id"]: z for z in self._all(
                "SELECT id, event, username, detail FROM audit WHERE id > ? AND id <= ? "
                f"AND (instr(lower(detail), lower(?)) > 0 {also_name}) AND {limit}",
                (below, until, value, *((bucket,) if folded else ()), *limits))
                if rewrite(z["event"], z["detail"] or "") != (z["detail"] or "")
                or name_hits(z["username"])}
            if candidates:
                with self._writing():
                    for zid in candidates:
                        z = self.db.execute("SELECT event, username, detail FROM audit WHERE id=?",
                                            (zid,)).fetchone()
                        if z is None:
                            continue          # cleared away meanwhile (`gc_audit`)
                        old = z["detail"] or ""
                        new = rewrite(z["event"], old)
                        name = replacement if name_hits(z["username"]) else z["username"]
                        if new != old or name != z["username"]:
                            self.db.execute("UPDATE audit SET username=?, detail=? WHERE id=?",
                                            (name, new if new != old else z["detail"], zid))
                            n += name != z["username"]
                    self.db.commit()
            below = until
    self._replace_own_values(replacement, above)
    return n


def _earlier_identifiers(self, current, setup, limit) -> list:
    """Earlier names and addresses of an account, each with the span in which it carried them —
    `[(kennung, limits)]` for `anonymize_audit` (H-13, audit round 2026-09-27, 4b).
    `current`: `[(name, limits), (address, limits)]`, `setup`: the limit of the creation
    without an upper bound.

    Read from the own rows: `username_changed` stands under the NEW name and names the
    old one (`old=`), `email_changed` under the name at the time of the change and
    names the old address. Backwards from today's name: the most recent rename in its span names the
    predecessor. It belonged to the account until that row, from the row that introduced IT — the
    most recent rename under it before that, not before creation —, otherwise from creation. Likewise the
    addresses, from the change rows under all names. Not covered: an address that came and went
    without `email_changed` (backfill from OIDC/LDAP) — there is no row for it. Via
    `idx_audit_name_ts`, no scan."""
    if not current:
        return []
    search = ("SELECT id, detail FROM audit WHERE lower(username) = lower(?) AND event = ? "
             f"AND {limit} ORDER BY id DESC")
    names: list = []
    name, limits = current[0]
    z = self._one(search + " LIMIT 1", (name, "username_changed", *limits))
    for _ in range(self._EARLIER_MAX):
        m = self._OLD_NAME.match(str(z["detail"] or "")) if z is not None else None
        old = m.group(1).strip() if m else ""
        if z is None or not old:
            break
        until = int(z["id"])
        z = self._one(search + " LIMIT 1", (old, "username_changed", *setup, until - 1))
        names.append((old, (-1, -1, 0, int(z["id"]) - 1, until) if z is not None else (*setup, until)))
    change: dict = {}
    for name, limits in [current[0], *names]:
        for line in self._all(search + f" LIMIT {self._EARLIER_MAX}", (name, "email_changed", *limits)):
            change[int(line["id"])] = line
    row = [change[i] for i in sorted(change, reverse=True)][:self._EARLIER_MAX]
    addresses: list = []
    for i, line in enumerate(row):
        m = self._OLD_MAIL.match(str(line["detail"] or ""))
        old = m.group(1) if m else ""
        if not old:
            continue
        until = int(line["id"])
        prior = row[i + 1] if i + 1 < len(row) else None
        addresses.append((old, (-1, -1, 0, int(prior["id"]) - 1, until) if prior is not None else (*setup, until)))
    return names + addresses


def _replace_own_values(self, replacement, above) -> None:
    """In the rows of the deleted account (`username` = replacement name, up to `above`) replace the values of
    `old=`, `new=` and `to=` (H-13, audit round 2026-09-27, 4c): the
    requested, never redeemed address change (`email_change_requested new=…`), the address from LDAP/SAML
    (`federation_email_confirm to=…`), the old name (`username_changed old=…`). Empty values
    stay empty. Via `idx_audit_name_ts`; written per `_ANONYMOUS_BLOCK` rows, the row
    read fresh."""
    def replace(detail) -> str:
        return self._OWN_VALUES.sub(lambda m: f"{m.group(1)}={replacement}", detail)
    hit = [int(z["id"]) for z in self._all(
        "SELECT id, detail FROM audit WHERE lower(username) = lower(?) AND id <= ?", (replacement, above))
        if z["detail"] and replace(z["detail"]) != z["detail"]]
    for i in range(0, len(hit), self._ANONYMOUS_BLOCK):
        with self._writing():
            for zid in hit[i:i + self._ANONYMOUS_BLOCK]:
                z = self.db.execute("SELECT username, detail FROM audit WHERE id=?", (zid,)).fetchone()
                if z is None or z["username"] != replacement or not z["detail"]:
                    continue
                self.db.execute("UPDATE audit SET detail=? WHERE id=?", (replace(z["detail"]), zid))
            self.db.commit()


def recent_audit(self, limit=100, username: str | None = None, since: int | None = None,
                 since_id: int = 0, from_id: int | None = None, without_events=()):
    """The most recent audit entries, newest first.

    `username` filters in SQL, not in the caller. That is the difference between "the
    last N entries of this account" and "the entries of this account among the last N" —
    and exactly that counts in the motivating case: a brute-force wave pushes thousands of
    rows in within minutes, and the account being sought then lies far behind any window. For the same reason
    `seit` (Unix seconds, inclusive) also filters in SQL; from the second `seit`
    itself only rows from `since_id` (see `setup_limit`). `from_id`: only rows with a
    larger id — the watermark of an identifier (`identifier_limits`, G2). `without_events`
    leaves out these events, likewise in SQL: a display that discards rows only afterwards
    would show fewer than `limit` — and the gap would reveal that there had been one (G12b).
    """
    conditions: list[str] = []
    values: list[object] = []
    if without_events:
        conditions.append(f"event NOT IN ({','.join('?' * len(without_events))})")
        values.extend(without_events)
    if username:
        conditions.append("lower(username) = lower(?)")
        values.append(username)
    if since:
        conditions.append("(ts > ? OR (ts = ? AND id >= ?))")
        values.extend((int(since), int(since), int(since_id or 0)))
    if from_id is not None:
        conditions.append("id > ?")
        values.append(int(from_id))
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    return self._all(f"SELECT * FROM audit{where} ORDER BY id DESC LIMIT ?", (*values, limit))

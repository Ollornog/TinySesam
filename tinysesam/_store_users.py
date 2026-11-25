"""The store part `users`: accounts: create, find, rename, roles, groups, delete, the owner and the admin claim.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (
    _email_unicode,
    json,
    norm_email,
    norm_identifier,
    replacement_name,
    time,
)
import sqlite3
from typing import Optional


# ---------- Users ----------
def create_user(self, username, display_name=None, email=None, is_admin=False, roles=None,
                is_service=False, email_verified=True, name_itself_chosen=False,
                name_source=None, managed_by=None) -> int:
    """Create an account (raw building block; the checks are done by `TinySesam.create_user`).

    Raises `sqlite3.IntegrityError` if the name or address is already the identifier of another account
    — also as a namesake in the counting bucket (`Alice`/`alice`, see `_trigger_sql`). Until
    2026-09-26 this went through here, unless exactly the same name or the same address
    already existed.

    Name and address belong to the account from this statement on: the watermarks (G2) arise in
    the same INSERT, as the highest id currently in `login_attempt` and `audit`. Likewise the
    marker `name_self_chosen` (G2-N) and the origin of the name (`name_source`) — between
    creation and marker there is no sign-in that could bind the account via the name."""
    mail = norm_email(email)
    cur = self._exec(
        "INSERT INTO users(username, display_name, email, email_verified, is_admin, roles, "
        "is_service, created_at, folded_name, folded_mail, name_attempt_from, mail_attempt_from, "
        "name_audit_from, mail_audit_from, name_self_chosen, name_source, managed_by) VALUES (?,?,?,?,?,?,?,?,?,?,"
        f"{self.WL_ATTEMPT},{self.WL_ATTEMPT},{self.WL_AUDIT},{self.WL_AUDIT},?,?,?)",
        (username, display_name or username, mail, 1 if email_verified else 0,
         1 if is_admin else 0,
         json.dumps(list(roles or [])), 1 if is_service else 0, _store._now(),
         norm_identifier(username), norm_identifier(mail), 1 if name_itself_chosen else 0,
         name_source or None, managed_by or None))
    return cur.lastrowid


def _set_identifier(self, user_id, column: str, value, bucket: str, proof=None) -> list:
    """The statements that replace name (`column="username"`) or address (`"email"`, with `proof`)
    together with the counting bucket — for `_rewrite`.

    If the identifier thereby moves to a DIFFERENT bucket, it belongs to the account only from now on: the
    watermarks (`name_attempt_from`/`name_audit_from` or `mail_…`, G2) go to the current state in the same
    statement. If the bucket stays (`B1` → `b1`, `u@bücher.example` →
    `u@xn--bcher-kva.example`), they stay — it is the same identifier. SQLite evaluates
    every expression in SET with the OLD row; the comparison therefore sees the previous bucket.

    Two statements, because the recompute trigger (`_trigger_sql`) cannot tell its own writer
    from a foreign one: it fires when the value changes but the bucket
    does not — and then raises the watermarks. Therefore the first statement sets an
    unchanged bucket to NULL itself (the trigger sees a changed bucket and stays
    silent; the identifier triggers check nothing — no identifier is added), and the
    second sets it back in the same transaction. It changes only the bucket and fires no
    trigger. Until 2026-09-26 the trigger set the bucket to NULL and the second statement
    set it back; with the watermarks that would already have shifted the limit for `B1` → `b1`.

    For the name a third is added at the front (`_remember_directory_name`, audit round 2026-09-27):
    an account with an LDAP binding whose name was the name in the directory keeps the old one as
    directory name — otherwise it would drop out of `count_identifiers` and out of the
    identifier space on renaming, until the next successful LDAP sign-in."""
    bucket_column, kind = ("folded_name", "name") if column == "username" else ("folded_mail", "mail")
    same = f"CASE WHEN {bucket_column} IS ? THEN"
    set_value = (f"{bucket_column} = {same} NULL ELSE ? END, "
              f"{kind}_attempt_from = {same} {kind}_attempt_from ELSE {self.WL_ATTEMPT} END, "
              f"{kind}_audit_from = {same} {kind}_audit_from ELSE {self.WL_AUDIT} END")
    first: tuple
    if proof is None:
        first = (f"UPDATE users SET {column}=?, {set_value} WHERE id=?",
                 (value, bucket, bucket, bucket, bucket, user_id))
    else:
        first = (f"UPDATE users SET {column}=?, email_verified=?, {set_value} WHERE id=?",
                 (value, 1 if proof else 0, bucket, bucket, bucket, bucket, user_id))
    beforehand = [self._remember_directory_name(user_id, bucket)] if column == "username" else []
    return beforehand + [first, (f"UPDATE users SET {bucket_column}=? WHERE id=?", (bucket, user_id))]


def _remember_directory_name(self, user_id, new_bucket) -> tuple:
    """The statement that, before a rename, records the previous name as the name in the directory
    on the LDAP binding (`federated_identity.directory_name_folded`, G5) — for `_set_identifier`.

    Occasion (audit round 2026-09-27): if an account is named the same locally and in the directory, NULL stands there
    (`set_binding_name` records only a differing name). If the operator
    (G13, panel, `tinysesam rename`) or the person themselves renamed the account, the
    directory name dropped out of `count_identifiers`: if a stranger had filled the series beneath it before, the
    LDAP sign-in stayed locked — panel reset and full sign-in by another route did not
    clear it, only `tinysesam unlock <directory name>`. And the name was free locally: another
    account could take it and, with every sign-in, clear the counters against the LDAP
    password.

    Only a real identifier (not the origin placeholder `WITHOUT_IDENTIFIER`): without a stable
    identifier LDAP matches via the name — after renaming, the old name no longer
    belongs to this account. Only if NULL stands (a differing name is already recorded and
    the younger one) and only if the bucket really changes. The old bucket is read in
    the same transaction, before the new name is written."""
    old = "(SELECT folded_name FROM users WHERE id = ?)"
    return (f"UPDATE federated_identity SET directory_name_folded = {old} WHERE source = 'ldap' AND user_id = ? "
            "AND directory_name_folded IS NULL AND substr(identifier, 1, length(?)) <> ? "
            f"AND {old} IS NOT NULL AND {old} <> '' AND {old} IS NOT ?",
            (user_id, user_id, self.WITHOUT_IDENTIFIER, self.WITHOUT_IDENTIFIER, user_id, user_id, user_id,
             new_bucket))


def _rewrite(self, steps) -> None:
    """Several statements in ONE transaction, one commit (like `_exec`, only for a list).
    If one fails — also on an identifier trigger (`IntegrityError`) — `_writing` rolls
    all of them back."""
    with self._writing():
        for sql, args in steps:
            self.db.execute(sql, args)
        self.db.commit()
        self._written = time.monotonic()
        self._clock_record()


def set_username(self, user_id, username, itself_chosen: Optional[bool] = None) -> None:
    """Replace the username — together with the counting bucket (`folded_name`) in the same transaction.
    The check happens beforehand (`TinySesam.change_username`); this only writes. If the name is
    already the identifier of another account (name, address or namesake in the bucket), the
    database rejects it: `sqlite3.IntegrityError`, nothing changed.

    `itself_chosen` sets the marker `users.name_self_chosen` (G2-N) in the same
    transaction and deletes the origin `users.name_source`: the new name comes from the person
    or the operator, no longer from the source that created the account. `None` leaves
    both as they are."""
    name = str(username or "").strip()
    steps = self._set_identifier(user_id, "username", name, norm_identifier(name))
    if itself_chosen is not None:
        steps.append(("UPDATE users SET name_self_chosen=?, name_source=NULL WHERE id=?",
                         (1 if itself_chosen else 0, user_id)))
    self._rewrite(steps)


def set_email(self, user_id, email, verified: bool = False):
    """Replace the address — **together with its proof**, by default "unconfirmed".

    The proof belongs to the address, not to the account: since `users.email_verified` decides
    on rights (`_maybe_promote_admin`, stage 2), a marker left standing would be
    the proof of the **old** address on the **new** one — exactly that was measured
    (B-bypass-8 from T-13): `eve@example.com` (proven) → `set_email(uid, "boss@example.com")` →
    first admin via the allowlist, without anyone having confirmed anything.

    Until then it said here that the marker stays "fail-closed". That held only for the
    one direction (unconfirmed stays unconfirmed); the other was fail-**open**. The
    default is therefore `verified=False`: whoever has a proof for the NEW address — a
    redeemed confirmation mail, an IdP claim from the same login — says so
    explicitly (`set_email(uid, mail, verified=True)`) or sets it afterwards with
    `set_email_verified`. Address and proof go into the database in ONE statement,
    so that there is no state in between in which the new address carries the old proof.
    The counting bucket of the address (`folded_mail`) goes along in the same transaction.

    If the address is already the identifier of another account (address, name or namesake in the
    bucket), the database rejects it: `sqlite3.IntegrityError`, nothing changed. Until
    2026-09-26 nothing checked here except `ux_users_email` (address against address)."""
    mail = norm_email(email)
    self._rewrite(self._set_identifier(user_id, "email", mail, norm_identifier(mail), bool(verified)))


def address_switch(self, user_id, email, name_follows: bool = False) -> None:
    """Enter the confirmed new address (with proof) and, if `name_follows`, set the name
    to the same address (email mode) — in ONE transaction.

    Written separately (`set_email`, then `set_username`), the second could fail
    after the first was already in place: new address, name still the old address — and the old
    address stayed occupied as the account's name. If one statement fails here (the new
    identifier has meanwhile been taken: `sqlite3.IntegrityError`), both stay as they were."""
    mail = norm_email(email)
    bucket = norm_identifier(mail)
    steps = self._set_identifier(user_id, "email", mail, bucket, True)
    if name_follows:
        steps += self._set_identifier(user_id, "username", mail, bucket)
    self._rewrite(steps)


def set_email_verified(self, user_id, verified: bool):
    """Record the proof for the address (`users.email_verified`).

    Separate from the address because the two are known separately: an IdP sends `email` in
    every login, but the claim `email_verified` only sometimes. And the marker must stay
    in place, because a login that brings no proof itself (local password, magic link)
    is also decided by it — otherwise the protection would depend on the sign-in route."""
    self._exec("UPDATE users SET email_verified=? WHERE id=?",
               (1 if verified else 0, user_id))


def get_roles(self, user_id) -> list:
    r = self._one("SELECT roles FROM users WHERE id=?", (user_id,))
    try:
        return json.loads(r["roles"]) if r else []
    except Exception:
        return []


def set_roles(self, user_id, roles):
    self._exec("UPDATE users SET roles=? WHERE id=?", (json.dumps(list(roles or [])), user_id))


def get_user(self, user_id) -> Optional[sqlite3.Row]:
    return self._one("SELECT * FROM users WHERE id=?", (user_id,))


def get_user_by_name(self, username) -> Optional[sqlite3.Row]:
    return self._one("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,))


def get_user_by_email(self, email) -> Optional[sqlite3.Row]:
    canonical = norm_email(email)
    if not canonical:
        return None
    # Also look for the form from before R4-06 (only trimmed and lowercase): a stored address
    # with an umlaut domain is still in Unicode form in existing data and would otherwise not be found.
    # And in BOTH directions (attack A5): the Unicode form is also recovered from the A-label
    # input — otherwise `user@xn--bcher-kva.example` did not find the existing entry
    # `user@bücher.example`, and the registration created a second account for the same
    # mailbox.
    old = str(email or "").strip().lower()
    unicode_form = _email_unicode(canonical)
    return self._one("SELECT * FROM users WHERE email COLLATE NOCASE IN (?, ?, ?) ORDER BY id LIMIT 1",
                     (canonical, old, unicode_form))


def deletion_guard(self, user) -> Optional[str]:
    """Why can this account NOT be deleted on purpose? `"owner"`, `"last_admin"` or None.

    The one protection rule of the deliberate deletion — shared by `TinySesam.delete_user`
    (panel, library) and `tinysesam delete` (command line), so that the two cannot drift
    apart: an owner is never deleted (the role must be handed over first), and neither is the
    last admin (otherwise the instance has no administration and the first-admin path opens up
    for the next best person)."""
    if user["is_owner"]:
        return "owner"
    if user["is_admin"] and sum(1 for x in self.list_users() if x["is_admin"]) <= 1:
        return "last_admin"
    return None


def account_footprint(self, user_id) -> tuple[int, int, int]:
    """What hangs on an account, as counts only (for `tinysesam delete`):
    `(sessions, identity links, API keys)`."""
    def n(sql):
        return int(self._one(sql, (user_id,))["n"])
    return (n("SELECT COUNT(*) AS n FROM session WHERE user_id=?"),
            n("SELECT COUNT(*) AS n FROM oidc_identity WHERE user_id=?")
            + n("SELECT COUNT(*) AS n FROM federated_identity WHERE user_id=?"),
            n("SELECT COUNT(*) AS n FROM api_key WHERE user_id=?"))


def remove_account(self, user_id, address_unlimited: bool = False) -> Optional[tuple[str, int]]:
    """Delete an account — the ONE deletion path that every caller goes through (H-13).

    Account together with credentials and sessions, the sign-in attempts under name and address, and
    in the audit log the name becomes `deleted#<id>` (`anonymize_audit`). A deleted
    account whose name still stands in every row is not deleted.

    Why here and not in the manager: until the T-13 integration there were four deletion paths with two
    different promises. `TinySesam.delete_user` anonymised, `gc()`, `tinysesam gc` (which
    works directly on the store) and the rollback after a failed confirmation send
    called `delete_user` and left name, foreign IP and the victim's address standing — a
    later namesake saw the stranger's registration as their own event
    (integration findings 12/18). The store is the deepest place that all paths share.

    **Only what arose from the creation of the account** (`setup_limit` — the same limit as
    `TinySesam.own_events`). Since `gc()` and the B6-5 rollback go through here, a stranger without
    an account triggers this path too: register, never confirm. Without a limit it
    rewrote rows that arose BEFORE his account and belong to others — the admin's invitation
    with the address in the detail, the failed attempt of a sprayer under the then
    free name, the one of the real address holder —, and their attempt rows disappeared
    from the per-IP throttling. A name or a typed-in address belonged before creation
    to nobody or to someone else. Sign-in attempts from the second of creation stay
    in place: whether they came before or after cannot be decided, and leaving them
    is the safe direction here (they expire with the lockout window).

    More precise since 2026-09-26 (G2): not from creation, but from **each identifier's
    joining** (`identifier_limits`) — an account gets name and address later too
    (rename, address change). To the exact row, also in the second of joining. The
    creation remains the fallback for existing data without a watermark.

    `address_unlimited=True` exempts a **proven** address (`address_proven`):
    it demonstrably belongs to the account and is also replaced in older rows (the
    invitation that led to the account). That is the deliberate deletion by an admin
    (`TinySesam.delete_user`, H-13) — not a path that an anonymous party triggers. `gc()`, the
    rollback and `_purge_demo` clear accounts that never belonged to anyone; there the
    limit applies to the address too. And even for deletion by an admin only for a
    PROVEN address: that of an open account (registration, link never redeemed) or
    of a registration without confirmation requirement was typed in by a stranger — without this
    distinction, clearing such accounts in the panel would rewrite the admin's invitation
    and the failed attempts of the real holder from BEFORE creation to `deleted#<id>`.

    The sign-in attempts of a counting bucket (`norm_identifier`) that a REMAINING account
    shares stay in place (see `delete_attempts_for`).

    Returns `(replacement name, anonymised rows)` — under the replacement name the
    caller writes its own row (`user_delete`, `signup_expired`, `verify_send_error`) —,
    None if the account does not exist."""
    u = self.get_user(user_id)
    if u is None:
        return None
    name, mail = str(u["username"]), (u["email"] or "")
    since, since_id = self.setup_limit(u)
    # More precise than creation: from when each identifier belonged to the account (G2). Read before
    # deleting — afterwards the row no longer exists.
    limits = self.identifier_limits(u)
    unlimited = (mail,) if (address_unlimited and self.address_proven(u)) else ()
    self.delete_user(user_id)
    self.delete_attempts_for(name, (mail,), after=since, unlimited=unlimited,
                             from_ids={t: g[0] for t, g in limits.items()})
    replacement = replacement_name(user_id)
    return replacement, self.anonymize_audit(name, replacement, (mail,), since=since, since_id=since_id,
                                            unlimited=unlimited,
                                            from_ids={t: g[1] for t, g in limits.items()})


def address_proven(self, user) -> bool:
    """Does the address of this account demonstrably belong to it? (`remove_account`, H-13)

    The marker `email_verified` AND no pending confirmation: an open account —
    locked, an unused `verify_email` token and no redeemed one — carries an address
    that someone typed in and never confirmed. Since schema 10 the registration creates it
    without the marker (which only the redeemed link sets). The token check here additionally catches
    an app that calls `create_user` with the default `email_verified=True` and then itself
    sends a confirmation link."""
    if not (user["email"] and user["email_verified"]):
        return False
    if not user["disabled"]:
        return True
    unclosed = self._one(
        "SELECT 1 AS x FROM magic_token WHERE user_id=? AND purpose='verify_email' "
        "  AND used_at IS NULL "
        "  AND NOT EXISTS (SELECT 1 FROM magic_token WHERE user_id=? AND purpose='verify_email' "
        "      AND used_at IS NOT NULL) LIMIT 1", (user["id"], user["id"]))
    return unclosed is None


def setup_limit(self, user) -> tuple[int, int]:
    """From where does an audit row belong to this account? `(seit, since_id)` — the fallback.

    Since 2026-09-26 the watermark of the identifier applies first (`identifier_limits`, G2): an
    account that takes over a name that became free otherwise saw here the sign-ins of the
    previous owner including their IP. This limit now carries only the existing data whose accounts do not have the
    watermark.

    `seit` is `created_at` (Unix seconds). From the second of creation itself only rows
    from `since_id` count: the registration row of the account (`signup`, for the placeholder
    `signup_taken`), which is written right after creation. Without it the limit would be
    accurate to the second only — and a stranger who registers in the same second in which
    the admin invites the address or a sprayer tries the free name would have their
    rows attributed. Exactly these paths (registration, `gc()`, B6-5) always have the row;
    an account without it (admin API, SSO, demo) falls back to `since_id = 0` — then
    the whole second counts.

    The row is searched only in the second of creation and the next (the password is hashed
    AFTER creation, the row may be one second later). A
    `signup_taken` row counts only if it was the creation of a **placeholder**: the
    placeholder carries no address, and its row names in the detail the address that is not
    its name. The other `signup_taken` row — someone registers with an
    address that already belongs to an account as a username (name = address), and no
    account is created — stands under exactly this name, also in the same or the
    next second. It is not the creation and shifts nothing; taken as an anchor,
    the admin's `user_create` row would drop out of the anonymisation.

    Filter for SQL: `ts > seit OR (ts = seit AND id >= since_id)`."""
    since = int(user["created_at"] or 0)
    placeholder = not user["email"]
    for z in self._all(
            "SELECT id, event, username, detail FROM audit WHERE event IN ('signup', 'signup_taken') "
            "AND lower(username) = lower(?) AND ts BETWEEN ? AND ? ORDER BY id",
            (str(user["username"]), since, since + 1)):
        if z["event"] == "signup" or (
                placeholder and norm_email(z["username"]) != norm_email(z["detail"])):
            return since, int(z["id"])
    return since, 0


def account_by_bucket(self, identifier, other_than=None) -> Optional[sqlite3.Row]:
    """The first account whose name or address falls into the same counting bucket as `kennung`.

    The bucket is `norm_identifier` (Python `lower()`), whereas the database's name check is
    `COLLATE NOCASE` — and that folds only ASCII. `Émile` and `émile` are two
    names for SQLite, one for the lockout counter. That is why each account carries its bucket as a column
    (`folded_name`/`folded_mail`, computed in Python), and the lookup goes through its index.

    Up to schema 10 the lookup ran as a loop over ALL accounts in Python — on every
    registration, and for one with a free address twice as often as for one with a
    taken address: from a few thousand accounts on, the response time of a single request revealed
    whether an address has an account (R4-03), and `gc()` grew with open × all accounts.
    The work here now depends neither on the number of accounts nor on whether and where the
    identifier is found (tests/test_audit_round2.py counts the SQLite steps).
    `other_than` leaves out one account (the ID currently at issue)."""
    bucket = norm_identifier(identifier)
    if not bucket:
        return None
    # Rows whose bucket could not be backfilled (database read-only) are checked by Python —
    # normally none.
    hit = [z for z in self._backfill_pots()
               if z["id"] != other_than and bucket in (norm_identifier(z["username"]), norm_identifier(z["email"]))]
    z = self._one("SELECT * FROM users WHERE (folded_name = ? OR folded_mail = ?) AND id IS NOT ? "
                  "ORDER BY id LIMIT 1", (bucket, bucket, other_than))
    if z is not None:
        hit.append(z)
    return min(hit, key=lambda t: t["id"]) if hit else None


def bucket_of_another(self, identifier, user_id) -> bool:
    """Is this identifier (in the counting bucket) the name or address of an account OTHER than `user_id`?

    The guard before every clearing under an identifier that the account does not itself carry as name or
    address (G5, G5-N1): under the name from the directory (`count_identifiers`) and
    under the typed identifier of a directory sign-in (`TinySesam._record_login`). A
    directory filter on `mail` resolves `chefin@example.com` to a third party whose
    `mail` attribute reads that way; without this guard every sign-in of the third party cleared the
    counters of the local holder of this address — unlimited guessing against her account.
    It is checked when clearing, not when writing: an identifier can change owner."""
    return self.account_by_bucket(identifier, other_than=user_id) is not None


def identifier_limits(self, user) -> dict:
    """From where does a row under name or address belong to this account? (limit a, G2)

    `{bucket: (versuch_ab, audit_from)}` for name and address in the counting bucket: rows in
    `login_attempt` or `audit` with a LARGER id belong to the account, the others belonged
    to nobody or to someone else. `None` means existing data (the columns only arrived with this
    state) — then, as until 2026-09-26, the creation applies (`created_at`, `setup_limit`).

    Until then the creation was the limit for EVERY identifier. But an account gets an identifier
    later too: on renaming, on address change, on backfilling an address from OIDC.
    The failed attempts that a stranger had made earlier under the then free name
    were cleared by the first full sign-in — also from the throttling of his IP —, and the
    account page showed the previous owner's sign-in including their IP.

    Name and address in the same bucket (email mode): the earlier of the two watermarks —
    the identifier belongs to the account since it was added by one of the two paths. If one
    of them is NULL, the fallback applies."""
    from_: dict = {}
    for column, kind in (("username", "name"), ("email", "mail")):
        bucket = norm_identifier(self._slot(user, column))
        if not bucket:
            continue
        values = tuple(None if w is None else int(w)
                      for w in (self._slot(user, f"{kind}_attempt_from"), self._slot(user, f"{kind}_audit_from")))
        if bucket in from_:
            values = tuple(None if a is None or b is None else min(a, b) for a, b in zip(from_[bucket], values))
        from_[bucket] = values
    return from_


def account_with_directory_name(self, identifier, other_than=None) -> Optional[sqlite3.Row]:
    """The account (not `other_than`) on whose binding this identifier stands as the name in the directory
    (`federated_identity.directory_name_folded`, G5) — or None. For `TinySesam.identifier_taken` and
    `tinysesam rename`; the database checks the same in the identifier triggers (`_trigger_sql`).
    Via `ix_fed_directory_name_folded`, no scan."""
    bucket = norm_identifier(identifier)
    if not bucket:
        return None
    z = self._one("SELECT user_id FROM federated_identity WHERE directory_name_folded = ? AND user_id IS NOT ? "
                  "ORDER BY user_id LIMIT 1", (bucket, other_than))
    return self.get_user(z["user_id"]) if z else None


def count_identifiers(self, user_id) -> set:
    """All identifiers (in the counting bucket) under which the series (B2-6) of this account can stand.

    Name and address — and the name under which the account signs in via a directory source
    (`federated_identity.directory_name_folded`, G5), provided it is not the name or address of an
    OTHER account (`bucket_of_another`) and does not also stand on another account's binding
    (audit round 2026-09-27, p1-a: after renaming and reassignment in the directory,
    two accounts carried the same name, and every full sign-in of the previous owner ended the series
    under which the new holder was being guessed against). Since then `set_binding_name` deletes the
    name on foreign bindings; if two exist in existing data, it counts for neither — until the next
    LDAP sign-in under it. The series counts under the TYPED identifier;
    after a rename in the directory (locally `alice`, there `alice.neu`), until
    2026-09-26 no way back cleared the series under `alice.neu` — one's own typos added up
    over the years, and a stranger permanently locked the person out with enough failed attempts.

    The one reader for every way back: `lift_lockout`, `_end_series` (panel reset),
    `tinysesam passwd` and `tinysesam unlock`."""
    u = self.get_user(user_id)
    if u is None:
        return set()
    identifiers = {norm_identifier(u["username"]), norm_identifier(u["email"])} - {""}
    for z in self._all("SELECT DISTINCT directory_name_folded FROM federated_identity WHERE user_id=? "
                       "AND directory_name_folded IS NOT NULL AND directory_name_folded <> ''", (user_id,)):
        bucket = norm_identifier(z["directory_name_folded"])
        if (bucket and bucket not in identifiers and not self.bucket_of_another(bucket, user_id)
                and self.account_with_directory_name(bucket, other_than=user_id) is None):
            identifiers.add(bucket)
    return identifiers


def set_binding_name(self, source: str, user_id, name) -> bool:
    """Record the name under which the account has just signed in via `quelle` on its
    binding (`federated_identity.directory_name_folded`, G5). Returns whether anything was written.

    Folded (`norm_identifier`) and only if it is neither name nor address of the account — the
    ways back know those anyway; then NULL stands. Only the most recent name: after two
    renames in the directory nobody signing in that way counts under the oldest any more.
    It writes only on a change, so at most one UPDATE per sign-in and normally
    none. Whether the name is the name or address of an OTHER account is checked by every reader
    (`count_identifiers`), not by this writer.

    **The most recent sign-in under the name proves who it belongs to** (audit round 2026-09-27,
    p1-a): if the same name stands on the binding of an OTHER account, it is stale there — renamed
    in the directory and reassigned. It is deleted there, even if it stays NULL here as own
    name or own address. Until then both carried it, every full sign-in of the
    previous owner ended the new holder's series, and `tinysesam unlock` named the account
    with the younger binding instead of the one that had last signed in that way."""
    u = self.get_user(user_id)
    if u is None:
        return False
    bucket = norm_identifier(name)
    if bucket and self.account_with_directory_name(bucket, other_than=user_id) is not None:
        self._exec("UPDATE federated_identity SET directory_name_folded=NULL WHERE directory_name_folded=? AND user_id IS NOT ?",
                   (bucket, user_id))
    value = None if not bucket or bucket in {norm_identifier(u["username"]), norm_identifier(u["email"])} else bucket
    if self._one("SELECT 1 AS x FROM federated_identity WHERE source=? AND user_id=? AND directory_name_folded IS NOT ?",
                 (source, user_id, value)) is None:
        return False
    self._exec("UPDATE federated_identity SET directory_name_folded=? WHERE source=? AND user_id=?",
               (value, source, user_id))
    return True


def release_directory_name(self, name) -> int:
    """Delete the name in the directory on ALL bindings — before creating an account that
    gets it as its name (`TinySesam._check_ldap`, audit round 2026-09-27). The directory has
    just signed in a different entry under this name; where it still stands, it is stale
    (see `set_binding_name`) — and without this the database would reject the creation (identifier
    trigger). Returns the number of deleted marks."""
    bucket = norm_identifier(name)
    if not bucket or self.account_with_directory_name(bucket) is None:
        return 0
    return self._exec("UPDATE federated_identity SET directory_name_folded=NULL WHERE directory_name_folded=?", (bucket,)).rowcount


def account_with_binding_name(self, identifier) -> Optional[sqlite3.Row]:
    """The account that last signed in under this identifier via a directory source
    (`federated_identity.directory_name_folded`, G5) — for `tinysesam unlock <name as typed>`.
    None if none or if the identifier is the name or address of an account (then THAT
    account is meant, `account_by_bucket`). Several hits (existing data, see `set_binding_name`):
    None — which one signed in last that way is recorded nowhere. Until 2026-09-27 it was the
    most recently BOUND one, and `unlock` cleared its own series too (audit round, p1-a)."""
    bucket = norm_identifier(identifier)
    if not bucket or self.account_by_bucket(bucket) is not None:
        return None
    z = self._all("SELECT DISTINCT user_id FROM federated_identity WHERE directory_name_folded=? LIMIT 2", (bucket,))
    return self.get_user(z[0]["user_id"]) if len(z) == 1 else None


def delete_user(self, user_id):
    """Remove the rows of an account — raw building block, only for `remove_account`.

    Whoever deletes an account calls `remove_account` (or `TinySesam.delete_user`): here
    the name stays in the audit log, and the sign-in attempts stay in place. A test ensures
    that there is no other caller."""
    with self._writing():
        for table in ("api_key", "app_password", "password_cred", "pin_cred", "totp_cred", "recovery_code",
                      "webauthn_cred", "oidc_identity", "federated_identity", "name_binding",
                      "session", "magic_token"):
            self.db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
        self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
        self.db.commit()


def email_taken(self, email, exclude_id=None) -> bool:
    u = self.get_user_by_email(email)
    return bool(u and u["id"] != exclude_id)


def identifier_collisions(self, limit: int = 50) -> list:
    """Accounts whose **username** is the **email** of an OTHER account (finding R4-12).

    Only the cross direction; all collisions in the identifier space (also name against name, address
    against address) are reported by `bucket_collisions`. New ones have been prevented by the database since 2026-09-26
    (`_trigger_sql`); what stands here comes from existing data (an older version, a raw
    UPDATE, a row of a foreign writer after the backfill of its bucket).

    The comparison runs over the counting bucket (`norm_identifier`). It folds more coarsely than NOCASE, with which
    `get_user_by_name`/`get_user_by_email` search — every collision that the sign-in finds
    is therefore also noticed here. Until 2026-09-26 NOCASE stood here; `Ärmel`/`ärmel` or a
    Unicode against the A-label domain of the same address were missing. A row without a bucket (file
    read-only, backfill not possible) does not count.
    Rows: `(name_id, kennung, mail_id, address)`. An account that carries the same string in
    BOTH its own columns is no collision (email mode, intended path).
    """
    self._backfill_pots()     # rows of a foreign writer count too
    return self._all(
        "SELECT n.id AS name_id, n.username AS identifier, e.id AS mail_id, e.email AS address "
        "FROM users n JOIN users e ON e.id <> n.id "
        "  AND e.folded_mail <> '' AND e.folded_mail = n.folded_name "
        "ORDER BY n.id LIMIT ?", (int(limit),))


def bucket_collisions(self, limit: int = 50) -> list:
    """All identifiers that belong to more than one account — as `[{"identifier", "ids"}, …]`.

    Counted in the counting bucket (`norm_identifier`) over names AND addresses: `Alice`/`alice`,
    name = foreign address, two spellings of the same address (`u@bücher.example` and
    `u@xn--bcher-kva.example`). An account whose name is its own address counts once
    (the `UNION` merges the row). New collisions are prevented by the database
    (`_trigger_sql`); this query reports those from existing data — for the start message, which
    previously saw only the cross direction (`identifier_collisions`). `ids` ascending, the
    identifiers by the oldest account involved. Rows of a foreign writer first get
    their bucket (`_backfill_pots`); if that cannot be written (file read-only),
    they do not count."""
    self._backfill_pots()
    lines = self._all(
        "SELECT folded, group_concat(id) AS ids FROM ("
        "  SELECT id, folded_name AS folded FROM users WHERE folded_name <> ''"
        "  UNION SELECT id, folded_mail FROM users WHERE folded_mail <> '') "
        "GROUP BY folded HAVING COUNT(*) > 1 ORDER BY MIN(id) LIMIT ?", (int(limit),))
    return [{"identifier": z["folded"], "ids": sorted(int(i) for i in str(z["ids"]).split(","))}
            for z in lines]


def list_users(self):
    return self._all("SELECT * FROM users ORDER BY username")


def lock_by_app(self, user_id) -> bool:
    """Set the application's lock — only on an active account: `UPDATE … WHERE disabled=0`. A lock of the
    operator or of a pending confirmation stays what it is. True if this call locked."""
    return self._exec("UPDATE users SET disabled=? WHERE id=? AND disabled=0",
                      (self.LOCKED_APP, user_id)).rowcount == 1


def unlock_by_app(self, user_id) -> bool:
    """Lift the application's lock — and only that one: `UPDATE … WHERE disabled=3`, never during a deletion's
    grace period (`delete_after`: an unlocked account the cleanup deletes). True if this call unlocked."""
    return self._exec("UPDATE users SET disabled=0 WHERE id=? AND disabled=? AND delete_after IS NULL",
                      (user_id, self.LOCKED_APP)).rowcount == 1


def schedule_deletion(self, user_id, until: int) -> bool:
    """Mark an account for deletion by its application (account API, stage B): `delete_after = until`, and the
    application's lock on an active account — a lock of the operator or of a pending confirmation stays what it
    is. Only once (`WHERE delete_after IS NULL`). True if this call marked it."""
    return self._exec("UPDATE users SET delete_after=?, disabled=CASE WHEN disabled=0 THEN ? ELSE disabled END "
                      "WHERE id=? AND delete_after IS NULL", (int(until), self.LOCKED_APP, user_id)).rowcount == 1


def cancel_deletion(self, user_id, now: Optional[int] = None) -> bool:
    """Take a deletion back: `delete_after` goes and the application's lock (3) is lifted; another lock stays.
    With `now` (the application) only before the deadline; without (the operator: panel, CLI) also after it, as
    long as the cleanup has not run. True if this call took it back."""
    sql = ("UPDATE users SET delete_after=NULL, disabled=CASE WHEN disabled=? THEN 0 ELSE disabled END "
           "WHERE id=? AND delete_after IS NOT NULL")
    args: tuple = (self.LOCKED_APP, user_id)
    if now is not None:
        sql += " AND delete_after > ?"
        args += (int(now),)
    return self._exec(sql, args).rowcount == 1


def adopt_account(self, user_id, app_id: str) -> bool:
    """Hand an account to an application (`managed_by = app_id`) — only one no application manages yet. The caller
    has checked the rule (`provisioning.adopt_refusal`). True if this call handed it over."""
    return self._exec("UPDATE users SET managed_by=? WHERE id=? AND managed_by IS NULL",
                      (app_id, user_id)).rowcount == 1


def release_account(self, user_id, app_id: str) -> bool:
    """Take an account away from its application (`managed_by = NULL`); a pending deletion by the application ends
    with it (its lock stays until the operator lifts it). True if this call released it."""
    return self._exec("UPDATE users SET managed_by=NULL, delete_after=NULL WHERE id=? AND managed_by=?",
                      (user_id, app_id)).rowcount == 1


def managed_counts(self) -> dict:
    """`{app_id: number of accounts}` for every value of `users.managed_by` — the start check names applications
    that hold accounts but are no longer configured."""
    return {str(r["managed_by"]): int(r["n"]) for r in self._all(
        "SELECT managed_by, COUNT(*) AS n FROM users WHERE managed_by IS NOT NULL AND managed_by <> '' "
        "GROUP BY managed_by ORDER BY managed_by")}


def gc_provisioning(self, now: int) -> int:
    """Delete the accounts whose grace period after a deletion by their application has run out — through the
    one deletion path (`remove_account`, the audit anonymised, H-13), audit `user_delete` with
    `reason=delete_after`. An account that is no longer the application's (released, or made administrator,
    owner or service account meanwhile) is not deleted: its mark goes (audit `provision_delete_cancelled`), a lock
    stays. Shared by `TinySesam.gc()` and `tinysesam gc`. Returns the number deleted."""
    n = 0
    for row in self._all("SELECT id, managed_by, is_admin, is_owner, is_service FROM users "
                         "WHERE delete_after IS NOT NULL AND delete_after <= ? ORDER BY id", (int(now),)):
        uid = int(row["id"])
        if not row["managed_by"] or row["is_admin"] or row["is_owner"] or row["is_service"]:
            if self._exec("UPDATE users SET delete_after=NULL WHERE id=? AND delete_after IS NOT NULL",
                          (uid,)).rowcount:
                who = self._one("SELECT username FROM users WHERE id=?", (uid,))
                self.audit_log("provision_delete_cancelled", who["username"] if who else None, None,
                               f"uid={uid} reason=not_app_account")
            continue
        app_id = str(row["managed_by"])
        # Not `address_unlimited`: the deletion came from an application key, not from the operator — a verified
        # address counts as the account's own only from its creation on (`remove_account`).
        removed = self.remove_account(uid)
        if removed is None:
            continue
        replacement, count = removed
        self.audit_log("user_delete", replacement, None,
                       f"uid={uid} audit_anonymized={count} reason=delete_after app={app_id}")
        n += 1
    return n


def merge_roles(self, user_id, allowlist, wanted) -> Optional[tuple]:
    """Replace the roles of `allowlist` on an account with `wanted` and keep every other role:
    `(current − allowlist) ∪ wanted`, read and written in ONE transaction (`BEGIN IMMEDIATE`, also across
    processes) — a change from the panel between reading and writing is not lost. Returns
    `(before, after)` as lists, or None if the account does not exist."""
    allowed = set(allowlist)
    with self._writing():
        self._begin_immediate()
        row = self.db.execute("SELECT roles FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            self.db.rollback()
            return None
        try:
            before = [str(r) for r in json.loads(row["roles"] or "[]")]
        except (ValueError, TypeError):
            before = []
        after = list(dict.fromkeys([r for r in before if r not in allowed] + list(wanted)))
        self.db.execute("UPDATE users SET roles=? WHERE id=?", (json.dumps(after), user_id))
        self.db.commit()
    return before, after


def set_display_name(self, user_id, display_name: str) -> bool:
    """Replace the display name (the caller checks the value). True if the account exists."""
    return self._exec("UPDATE users SET display_name=? WHERE id=?", (display_name, user_id)).rowcount == 1


def count_managed(self, app_id: str) -> int:
    """How many accounts an application manages (`users.managed_by`)."""
    row = self._one("SELECT COUNT(*) AS n FROM users WHERE managed_by=?", (app_id,))
    return int(row["n"]) if row else 0


def list_managed(self, app_id: str, after: int = 0, limit: int = 100) -> list:
    """The accounts of an application in id order, from `after` on (exclusive) — the account API filters what
    the application may see."""
    return self._all("SELECT * FROM users WHERE managed_by=? AND id>? ORDER BY id LIMIT ?",
                     (app_id, int(after), int(limit)))


def count_up(self, key: str, limit: int, ttl: int) -> bool:
    """Count one use under `key` in the `flow` table, but never beyond `limit` — atomic, also across processes
    (one conditional `UPDATE` in a `BEGIN IMMEDIATE` transaction). True if the use was counted (still within the
    limit). The row expires after `ttl` seconds and the flow cleanup removes it; the window is part of the key."""
    with self._writing():
        self._begin_immediate()
        self.db.execute("INSERT OR IGNORE INTO flow(key, data, expires_at) VALUES (?, '0', ?)",
                        (key, _store._now() + int(ttl)))
        counted = self.db.execute(
            "UPDATE flow SET data = CAST(CAST(data AS INTEGER) + 1 AS TEXT) "
            "WHERE key=? AND CAST(data AS INTEGER) < ?", (key, int(limit))).rowcount == 1
        self.db.commit()
    return counted


def counter(self, key: str) -> int:
    """The current count under `key` (`count_up`), 0 if there is none."""
    row = self._one("SELECT data FROM flow WHERE key=?", (key,))
    try:
        return int(row["data"]) if row else 0
    except (ValueError, TypeError):
        return 0


def set_disabled(self, user_id, disabled: bool, through_operator: bool = False):
    """Lock or unlock an account.

    `through_operator=True` is the operator's lock (admin panel): no confirmation link
    lifts it, only an explicit `set_disabled(uid, False)`. Without the marker it is
    the lock of a pending confirmation, which `confirmation_enable` lifts — and
    which does not downgrade an already existing operator lock.

    Locks from versions before this distinction carry 1 — and up to 0.19.x the lock
    in the panel did not discard the open one-time tokens, so a pending confirmation link would
    have lifted it after the upgrade. The migration to schema 10 (`_catch_up_inventory`)
    therefore raises every lock that the audit log knows as a panel lock to 2 and discards
    the open tokens in doing so. A lock whose row has already been deleted
    (`audit_retention_days`) stays 1; `POST <admin_path>/api/users/{id}/disable` with
    `{"disabled": true}` sets the marker without unlocking in between."""
    if disabled:
        # An owner cannot be locked — not even via the code path (owner model). Otherwise
        # `owner_count` would count an owner who cannot sign in.
        line = self._one("SELECT is_owner FROM users WHERE id=?", (user_id,))
        if line is not None and line["is_owner"]:
            from .errors import StateError
            raise StateError(f"Account {user_id} is an owner and cannot be locked — hand over the "
                             "owner role first.")
    if not disabled:
        # Unlocking by the operator also ends a deletion by the application (`delete_after`): otherwise the cleanup
        # would delete the account the operator has just opened again.
        self._exec("UPDATE users SET disabled=0, delete_after=NULL WHERE id=?", (user_id,))
    elif through_operator:
        self._exec("UPDATE users SET disabled=? WHERE id=?", (self.LOCKED_OPERATOR, user_id))
    else:
        self._exec("UPDATE users SET disabled=max(disabled, ?) WHERE id=?",
                   (self.LOCKED_CONFIRMATION, user_id))


def confirmation_enable(self, user_id) -> bool:
    """Lift the lock of a pending confirmation — never the operator's.

    True if the account is active afterwards (also: it was not locked at all). False if
    a lock remains; then the operator locked it, and only the operator lifts it again."""
    self._exec("UPDATE users SET disabled=0 WHERE id=? AND disabled=?",
               (user_id, self.LOCKED_CONFIRMATION))
    line = self._one("SELECT disabled FROM users WHERE id=?", (user_id,))
    return bool(line) and not line["disabled"]


def set_admin(self, user_id, is_admin: bool):
    self._exec("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))


def set_owner(self, user_id, owner: bool):
    """Set the owner flag. An owner is always an admin — and by hand (1): no identity
    provider takes the admin right from an owner (H-5 removes only the 2). The rules (at least
    one, only owners assign) are checked by the manager."""
    if owner:
        self._exec("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (user_id,))
    else:
        self._exec("UPDATE users SET is_owner=0 WHERE id=?", (user_id,))


def owner_count(self, without=None) -> int:
    """How many owners are there (excluding the account `without`)?"""
    line = self._one("SELECT COUNT(*) AS n FROM users WHERE is_owner=1 AND id <> ?",
                      (int(without) if without is not None else -1,))
    return int(line["n"])


def set_admin_from_idp(self, user_id):
    """Admin flag with the mark "granted by the identity provider" (`is_admin=2`, H-5).

    Only this value may be withdrawn again at the next login if the provider no longer
    delivers the group. A 1 (panel, CLI, `admin_identifiers`, `/auth/claim-admin`)
    is never touched by a provider. Everywhere else the flag counts as a truth value — 2 is admin like 1."""
    self._exec("UPDATE users SET is_admin=2 WHERE id=? AND is_admin=0", (user_id,))


def user_count(self) -> int:
    return self._one("SELECT COUNT(*) c FROM users")["c"]

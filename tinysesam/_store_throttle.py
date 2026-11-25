"""The store part `throttle`: brute-force regulation and consecutive failed attempts.

Methods of `Store`, loaded on first use (`Store.__getattr__`, the index `store._PARTS`). Each takes the
store as `self`, exactly as it did inside the class (T-112).
"""

from . import store as _store
from .store import (  # noqa: F401
    Optional,
    norm_identifier,
    now,
    time,
)


# ---------- Brute-force regulation ----------
def record_attempt(self, username, ip, success, method):
    self._exec("INSERT INTO login_attempt(ts, username, ip, success, method) VALUES (?,?,?,?,?)",
               (_store._now(), username, ip, 1 if success else 0, method))


def _fails_query(self, since, username=None, ip=None, method=None, exclude_methods=None,
                   from_id=None, only_confirmed=False, except_username=None):
    """The counting query for `count_fails` and `reserve_attempt` — one rule, two callers.
    `from_id`: only rows with a larger id (watermark of an identifier, G2).
    `only_confirmed`: without the pending pre-bookings (G9, `PREBOOKING_PENDING_SEC`)."""
    q = "SELECT COUNT(*) c FROM login_attempt WHERE success=0 AND ts>=?"
    args = [since]
    if only_confirmed:
        q += " AND (pending=0 OR ts<?)"
        args.append(_store._now() - self.PREBOOKING_PENDING_SEC)
    if from_id is not None:
        q += " AND id>?"
        args.append(int(from_id))
    if username:
        q += " AND username=? COLLATE NOCASE"
        args.append(username)
    if ip:
        q += " AND ip=?"
        args.append(ip)
    if except_username:
        q += " AND username<>? COLLATE NOCASE"
        args.append(except_username)
    if method:
        q += " AND method=?"
        args.append(method)
    if exclude_methods:
        place = ",".join("?" for _ in exclude_methods)
        q += f" AND (method IS NULL OR method NOT IN ({place}))"
        args.extend(exclude_methods)
    return q, args


def count_fails(self, since, username=None, ip=None, method=None, exclude_methods=None,
                from_id=None, only_confirmed=False, except_username=None) -> int:
    """Count failed attempts in the window — optionally only ONE method, or all EXCEPT some.

    `exclude_methods` is the counterpart of `method`: the login lockout wants to count everything
    that was a sign-in attempt — but not the old-password query of the account page, which lies in
    the same table (see `security.NOT_LOGIN_METHODS`). A row without a method
    (`NULL`, conceivable from old data) still counts: when in doubt, lock more strictly.

    Default: a pending pre-booking (`reserve_attempt(as_pending=True)`) counts — it
    CAN become a failed attempt. `only_confirmed=True` leaves it out (G9).
    """
    if not username and not ip:
        return 0
    q, args = self._fails_query(since, username, ip, method, exclude_methods, from_id,
                                  only_confirmed, except_username)
    return self._one(q, args)["c"]


def reserve_attempt(self, username, ip, method, rules, series=None, as_pending=False) -> tuple:
    """Check lockouts and pre-book the attempt **in the same transaction** as a failed attempt.

    `rules` is a list `(grund, limit, filter)`; `filter` are the keywords of
    `count_fails`. Returns `(id, None)` — the attempt may proceed and already stands as a
    failed attempt in the table — or `(None, grund)` if a rule applies.

    Why in advance and why in one transaction (R3-2, R3-7, R7-2): previously the entire password
    check (argon2, dozens of milliseconds) lay between `_is_locked()` and `record_attempt()`.
    A parallel burst of N requests read the same counter state N times,
    "not locked yet", and could guess N times — the limit applied only to attackers who
    politely ask one after another. Now every attempt reserves its place before it checks,
    and `BEGIN IMMEDIATE` turns counting and booking into one step, also across several
    processes (`uvicorn --workers N`): the file's write lock orders them.
    If the attempt succeeds, `finish_attempt` turns the row into a success; a process
    that dies in between leaves a failed attempt — when in doubt, stricter.

    `series=(topf, art, limit)` also pre-books the series of consecutive failed attempts (B2-6) —
    in the SAME transaction. The first version read the series beforehand and counted it only after
    the check: a parallel burst at the limit read "not full yet" N times and could guess
    N times (measured: 15 instead of 1). Returns then `(id, series state)` after the booking —
    the SETTLED state (`_series_confirmed`, without pending pre-bookings). If it reaches
    the limit, exactly this booking triggered the lockout; a pending one never reaches it here,
    only at its completion (`finish_attempt`, audit round 2026-09-27, p2 F3).

    **Pending (G9).** `as_pending=True` books the attempt with an open outcome (`offen=1`): it
    can become a failed attempt or none at all (directory outage, F-23 — withdrawn
    only once the outage is reported, with a directory that drops packets, hence after
    the timeout). If a rule or the series applies **only** because of such rows, the
    answer is `(None, "pending")`: not decided yet, no lockout. The caller asks
    again after a short pause (`_begin_attempt`). Previously every rejection in this
    window was a lockout with `failed login` for fail2ban and a lockout notice to the holder — even
    if not a single failed attempt remained afterwards. The burst (R7-2) stays slowed down: it
    waits until the pre-bookings are decided and then gets the real lockout. If
    a rule applies with the confirmed rows alone, its reason applies as before; an open
    row older than `PREBOOKING_PENDING_SEC` counts as a failed attempt.
    """
    with self._lock:
        self._begin_immediate()
        try:
            state = None
            pending = False
            bucket_s, kind_s, limit_s = series if series is not None else (None, None, 0)
            if bucket_s and self._series_sum(bucket_s) >= limit_s:
                if self._series_confirmed(bucket_s) >= limit_s:
                    self.db.execute("ROLLBACK")
                    return None, "lockout_series"
                pending = True
            for reason, limit, filt in rules:
                if not filt.get("username") and not filt.get("ip"):
                    continue
                q, args = self._fails_query(**filt)
                if self.db.execute(q, args).fetchone()["c"] < limit:
                    continue
                # Does the rule apply — even without the pending pre-bookings? Then it is a
                # lockout. Otherwise continue: a later rule may apply confirmed and takes precedence.
                q, args = self._fails_query(**filt, only_confirmed=True)
                if self.db.execute(q, args).fetchone()["c"] >= limit:
                    self.db.execute("ROLLBACK")
                    return None, reason
                pending = True
            if pending:
                self.db.execute("ROLLBACK")
                return None, "pending"
            cur = self.db.execute(
                "INSERT INTO login_attempt(ts, username, ip, success, method, pending) VALUES (?,?,?,0,?,?)",
                (_store._now(), username, ip, method, 1 if as_pending else 0))
            if bucket_s:
                self._series_plus(bucket_s, kind_s)
                state = self._series_confirmed(bucket_s)
            self.db.execute("COMMIT")
            return cur.lastrowid, state
        except Exception:
            self.db.execute("ROLLBACK")
            raise


def finish_attempt(self, attempt_id, success: bool, series=None) -> Optional[tuple]:
    """Complete an attempt pre-booked with `reserve_attempt`: success or failed attempt.

    Both end the pending state (`offen=0`, G9): a failed attempt counts from here also for
    `count_fails(only_confirmed=True)` — until then completing a failed attempt was a
    no-op. `series=(topf, art)` withdraws the pre-booking in the series on a success in the SAME
    transaction: separately it would stand in between neither as open nor as withdrawn,
    and whoever is waiting right now (`_begin_attempt`) would read the series one too high — at the
    limit a lockout with a lockout notice for nothing.

    With `series` it returns `(before, after)`: the settled state of the series
    (`_series_confirmed`) before and after the completion, both in one transaction
    (`BEGIN IMMEDIATE`, also across several processes). From that `_record_login` sees whether EXACTLY
    this completion crossed the limit (p2 F3). Until 2026-09-27 the state counted at
    booking: if in the meantime a full sign-in had ended the series, `lockout_series`
    stood in the log although nothing was locked. Without `series` None."""
    with self._writing():
        before = None
        if series:
            self._begin_immediate()
            before = self._series_confirmed(series[0])
        self.db.execute("UPDATE login_attempt SET success=?, pending=0 WHERE id=?",
                        (1 if success else 0, attempt_id))
        if success and series:
            self._series_minus(*series)
        state = (before, self._series_confirmed(series[0])) if series else None
        self.db.commit()
        self._written = time.monotonic()
        self._clock_record()
    return state


def cancel_attempt(self, attempt_id, series=None):
    """Withdraw a pre-booked attempt — it was none (e.g. directory outage, F-23).

    `series=(topf, art)` withdraws its pre-booking in the series in the same transaction —
    for the same reason as in `finish_attempt` (G9)."""
    with self._writing():
        self.db.execute("DELETE FROM login_attempt WHERE id=? AND success=0", (attempt_id,))
        if series:
            self._series_minus(*series)
        self.db.commit()
        self._written = time.monotonic()
        self._clock_record()


def clear_fails(self, username=None, ip=None, method=None, exclude_methods=None, since=None,
                from_id=None):
    """Delete failed attempts — optionally only those of ONE method, or all EXCEPT some.

    `method` is not a nicety but the core: without it a successful
    password login also cleared the TOTP and PIN failed attempts. Whoever knew the password (leak,
    reuse, phishing) signed in correctly once before every guess and
    thereby reset the lockout for the SECOND factor — as often as they liked. The regulation
    that the panel advertises as hardening never applied to the second factor.

    `exclude_methods` clears everything except those named — the path after a COMPLETE
    sign-in, which does not concern the own buckets (account page, step-up, scope).

    `from_id` clears only rows from the watermark of the identifier (`identifier_limits`, G2): what
    arose only when the identifier already belonged to the account. `seit` is the fallback for
    existing data without a watermark (Unix seconds, the creation of the account, inclusive).
    """
    where: str = ""
    args_m: tuple = ()
    if method is not None:
        where, args_m = " AND method=?", (method,)
    elif exclude_methods:
        place = ",".join("?" for _ in exclude_methods)
        where, args_m = f" AND (method IS NULL OR method NOT IN ({place}))", tuple(exclude_methods)
    if since is not None:
        # Only from a point in time (limit a): a complete sign-in clears what applied to THIS
        # account — not the failed attempts under its name or address from before
        # its creation (those applied to nobody or to someone else).
        where, args_m = where + " AND ts >= ?", args_m + (int(since),)
    if from_id is not None:
        # More precise than `seit` (G2): from the joining of the identifier, not from creation — and to
        # the exact row, also in the second of joining.
        where, args_m = where + " AND id > ?", args_m + (int(from_id),)
    if username:
        self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE" + where,
                   (username,) + args_m)
    if ip:
        self._exec("DELETE FROM login_attempt WHERE ip=?" + where, (ip,) + args_m)


def gc_attempts(self, older_than) -> int:
    return self._exec("DELETE FROM login_attempt WHERE ts < ?", (older_than,)).rowcount


# The table `login_attempt` knows only windows: `gc()` clears it after a day, and every
# threshold there counts from `lockout_window_sec`. Whoever guesses slowly — four attempts per window,
# around the clock —, stayed below every threshold, for as long as they liked. NIST SP 800-63B
# therefore demands a limit for CONSECUTIVE failed attempts that does not expire with time. It stands
# here, separate and without a time window, per identifier AND method: locking happens on the sum,
# what gets cleared is what the way back proves (a self-service reset only the password part,
# R4-13). The booking lies in `reserve_attempt`, atomic with the attempt itself.
def _series_sum(self, bucket) -> int:
    line = self.db.execute("SELECT COALESCE(SUM(count), 0) AS n FROM failure_series WHERE folded=?",
                            (bucket,)).fetchone()
    return int(line["n"])


def _series_confirmed(self, bucket) -> int:
    """The series without the pending pre-bookings (G9) — under `_lock`, without commit.

    Every open row in `login_attempt` has exactly one booking in the series under the same
    bucket (`reserve_attempt(as_pending=True)` books both in one transaction); a row that is
    older than `PREBOOKING_PENDING_SEC` counts as a failed attempt and is not subtracted."""
    unclosed = self.db.execute(
        "SELECT COUNT(*) AS n FROM login_attempt WHERE username=? COLLATE NOCASE AND pending=1 "
        "AND ts>=?", (bucket, _store._now() - self.PREBOOKING_PENDING_SEC)).fetchone()
    return max(0, self._series_sum(bucket) - int(unclosed["n"]))


def _series_minus(self, bucket, kind):
    self.db.execute("UPDATE failure_series SET count = count - 1 WHERE folded=? AND kind=? AND count > 0",
                    (bucket, kind or ""))


def _series_plus(self, bucket, kind):
    now = _store._now()
    self.db.execute("INSERT INTO failure_series(folded, kind, count, since, last_seen) VALUES (?, ?, 1, ?, ?) "
                    "ON CONFLICT(folded, kind) DO UPDATE SET count = count + 1, "
                    "last_seen = excluded.last_seen", (bucket, kind or "", now, now))


def failure_series(self, bucket) -> int:
    """How many consecutive failed attempts stand for this (folded) identifier, across all methods?"""
    if not bucket:
        return 0
    with self._lock:
        return self._series_sum(bucket)


def failure_series_confirmed(self, bucket) -> int:
    """Like `failure_series`, without the pending pre-bookings (G9): the consecutive failed attempts that
    are settled. The series lockout hangs on it; the sum alone can still fall."""
    if not bucket:
        return 0
    with self._lock:
        return self._series_confirmed(bucket)


def failure_series_without(self, bucket, kinds) -> int:
    """The series of this identifier WITHOUT the named kinds — what clearing only these kinds
    would leave standing (e.g. the self-service reset, which does not clear TOTP and `pin_chain`)."""
    if not bucket:
        return 0
    kinds = [str(a) for a in kinds]
    place = ",".join("?" for _ in kinds)
    with self._lock:
        line = self.db.execute(f"SELECT COALESCE(SUM(count), 0) AS n FROM failure_series "
                                f"WHERE folded=? AND kind NOT IN ({place})", [bucket, *kinds]).fetchone()
    return int(line["n"])


def increase_failure_series(self, bucket, kind="password") -> int:
    """Attach a failed attempt to the series (paths without pre-booking); returns the new sum."""
    if not bucket:
        return 0
    now = _store._now()
    self._exec("INSERT INTO failure_series(folded, kind, count, since, last_seen) VALUES (?, ?, 1, ?, ?) "
               "ON CONFLICT(folded, kind) DO UPDATE SET count = count + 1, last_seen = excluded.last_seen",
               (bucket, kind or "", now, now))
    return self.failure_series(bucket)


def lower_failure_series(self, bucket, kind) -> None:
    """Withdraw a pre-booking: the attempt was correct (or none at all — directory outage).

    Do not delete: a correct password with an open second factor is not a complete
    sign-in. The series before it stays, only this attempt does not count."""
    if not bucket:
        return
    self._exec("UPDATE failure_series SET count = count - 1 WHERE folded=? AND kind=? AND count > 0",
               (bucket, kind or ""))


def delete_failure_series(self, bucket, kinds=None) -> int:
    """End the series (`kinds=None`: entirely, otherwise only these methods); returns how many there were."""
    if not bucket:
        return 0
    if kinds is None:
        away = self.failure_series(bucket)
        self._exec("DELETE FROM failure_series WHERE folded=?", (bucket,))
        return away
    kinds = [str(a) for a in kinds]
    place = ",".join("?" for _ in kinds)
    line = self._one(f"SELECT COALESCE(SUM(count), 0) AS n FROM failure_series WHERE folded=? AND kind IN ({place})",
                      [bucket, *kinds])
    self._exec(f"DELETE FROM failure_series WHERE folded=? AND kind IN ({place})", [bucket, *kinds])
    return int(line["n"])


def gc_failure_series(self, older_than, limit) -> int:
    """Clear old, NOT triggered series (`zuletzt` before `older_than`, sum below `limit`).

    A triggered series stays: it is a lockout, and only a sign-in, a reset
    or the operator lifts it — not waiting. Without a limit the table would fill up with
    invented names; with it each remaining row costs an attacker `limit`
    failed attempts, each slowed down by the window thresholds."""
    return self._exec(
        "DELETE FROM failure_series WHERE folded IN (SELECT folded FROM failure_series GROUP BY folded "
        "HAVING MAX(last_seen) < ? AND SUM(count) < ?)", (int(older_than), int(limit))).rowcount


def delete_attempts_for(self, username, additional=(), after=None, unlimited=(), from_ids=None) -> int:
    """Delete the sign-in attempts of an account (when deleting the account, H-13).

    `additional` are additional identifiers under which it could sign in (the
    email address — `find_user` accepts it, and the attempt then stands under it).

    Counting happens under the bucket `norm_identifier` (NFKC, Python `lower()`, IDNA for addresses),
    so deleting happens there too — `lower()` in SQLite folds only ASCII and never hit the bucket
    `ärmel` of the account `Ärmel`, nor a name with compatibility characters (`ｂｅｒｔａ`) or an
    existing address in Unicode form (`u@bücher.example`). Rows from the time before
    `_bucket` stand under the raw input and are still found via SQLite `lower()`.

    Two limits (follow-up to integration findings 12/18):
    - `after` (Unix seconds): only attempts AFTER this second (the creation of the account) —
      before that they did not apply to it, and they count in the per-IP throttling of whoever
      made them. The second itself stays: whether an attempt in it came before or after creation
      cannot be decided, and a left-over attempt expires with the
      lockout window. Identifiers in `unlimited` apply without this limit.
      More precise is `from_ids` (`{bucket: versuch_ab}` from `identifier_limits`, G2): only attempts with
      a larger id than the watermark of the identifier — from its JOINING (rename,
      address change), not from creation, and to the exact row. Where an identifier has none
      (existing data), `after` applies.
    - If a REMAINING account carries the same bucket (a namesake such as `ｃｌａｒａ`/`clara`
      or `Émile`/`émile` from existing data, `account_by_bucket`), the bucket stays untouched.
      Otherwise removing an account, which an anonymous party can create and have cleared via `gc()`,
      would empty the account threshold of a stranger (R7-6/H-8)."""
    n = 0
    for value in (username, *[w for w in additional if w]):
        bucket = norm_identifier(value)
        if not bucket or self.account_by_bucket(bucket) is not None:
            continue
        waterline = (from_ids or {}).get(bucket)
        if value in unlimited:
            limit, start_from = "ts > ?", -1
        elif waterline is not None:
            limit, start_from = "id > ?", int(waterline)
        else:
            limit, start_from = "ts > ?", (-1 if after is None else int(after))
        raw = str(value)
        n += self._exec(f"DELETE FROM login_attempt WHERE {limit} "
                        "AND (username = ? OR lower(username) = lower(?) "
                        "OR lower(username) = lower(?))",
                        (start_from, bucket, raw, raw.strip())).rowcount
    return n

"""The building block `factors` of `TinySesam`: sign-in factors: password, passkeys, PIN, the lock rules, TOTP, recovery codes, reset, the factor chain.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from . import _chain
from . import security
from . import totp as _totp
from .errors import ConfigError
from .errors import StateError
from .passwords import dummy_verify
from .passwords import hash_password
from .passwords import needs_rehash
from .passwords import verify_password
from .store import norm_identifier
from fastapi import HTTPException
from fastapi import Request
from typing import Optional
from . import manager as _manager
from .manager import (
    _valid_rules,
)


# ---------- Password login ----------
def find_user(self, identifier) -> Optional[dict]:
    """Look up an account by login identifier — depending on `config.login_identifier`.

    "username" = username only, "email" = email only, "both" = both in the same field.
    With "both" the @ decides the order; both are still searched, so that a
    username containing @ does not suddenly become unfindable."""
    ident = (identifier or "").strip()
    if not ident:
        return None
    mode = getattr(self.cfg, "login_identifier", "both")
    if mode == "username":
        found = self.store.get_user_by_name(ident)
    elif mode == "email":
        found = self.store.get_user_by_email(ident)
    elif "@" in ident:
        found = self.store.get_user_by_email(ident) or self.store.get_user_by_name(ident)
    else:
        found = self.store.get_user_by_name(ident) or self.store.get_user_by_email(ident)
    return self._as_dict(found)


def _check_password(self, username, password) -> Optional[dict]:
    """Check username/email + password. Returns the account or None — and takes equally long for both outcomes (no account probing)."""
    u = self.find_user(username)
    if not u or u["disabled"]:
        dummy_verify(password)   # equalise timing (no user enumeration)
        return None
    h = self.store.get_password_hash(u["id"])
    if not h:
        dummy_verify(password)
        return None
    if not verify_password(password, h):
        return None
    if needs_rehash(h):
        self.store.set_password_hash(u["id"], hash_password(password))
    return u


# ---------- Manage passkeys ----------
def _webauthn_user_handle(self, user_id: int) -> bytes:
    """The WebAuthn user handle of an account for a NEW passkey: 64 bytes that look random (T-56).

    Up to 0.25.x the handle was the account ID as text (`b"7"`). An authenticator keeps the handle and hands it
    to every site that asks for a discoverable credential's account — a sequential number tells how many
    accounts an instance has and is the same on every instance that numbers alike. WebAuthn Level 3 §14.6.1
    recommends 64 random bytes. Kept here as HMAC-SHA-512 over the account ID with a random salt of this
    instance (setting `webauthn_handle_salt`, `Store.webauthn_handle_salt`): the same handle for every passkey of an
    account (an authenticator replaces a credential under the same handle instead of piling them up), no
    column, nothing to migrate. TinySesam never looks an account up by its handle — the sign-in finds the
    passkey by its credential ID —, so passkeys registered with the old handle keep working unchanged."""
    return hmac.new(self.store.webauthn_handle_salt(), b"webauthn-user-handle:%d" % int(user_id),
                    hashlib.sha512).digest()


def remove_passkey(self, user_id: int, passkey_id: int, ip: Optional[str] = None) -> bool:
    """Remove an account's passkey — deletion, audit line and `passkey_removed` in one.

    Both paths go through here: self-service (`/auth/passkey/delete`) and revocation
    by an admin in the panel. Before, each had its own lines, and after merging
    two branches only self-service reported the event — of all things the
    revocation on a FOREIGN account, performed by a taken-over admin account, stayed
    silent for the owner (integration finding 3). The audit line stands under the owner;
    if someone else acts, `audit()` adds `actor=` from the running request.

    Returns False if the account has no passkey with this ID — then nothing is
    deleted, logged or reported (before, self-service wrote a line and an event even for
    an invented passkey)."""
    if not any(int(c["id"]) == int(passkey_id) for c in self.store.list_webauthn(user_id)):
        return False
    self.store.delete_webauthn(int(passkey_id), user_id)
    # Losing a factor is exactly what one wants to look up later (B5-01).
    self.audit("passkey_delete", self._account_name(user_id), ip, f"id={int(passkey_id)}")
    self._security_event("passkey_removed", user_id, passkey_id=int(passkey_id))
    return True


# ---------- PIN login (personal PIN per user) ----------
def set_pin(self, user_id, pin):
    """Set/change the PIN. Minimum length from cfg.pin_min_length."""
    pin = str(pin or "")
    if len(pin) < self.cfg.pin_min_length:
        raise ConfigError(f"PIN too short (min. {self.cfg.pin_min_length})")
    self.store.set_pin_hash(user_id, hash_password(pin))
    self._security_event("pin_set", user_id)


def has_pin(self, user_id) -> bool:
    """Has this account set up a PIN?"""
    return self.store.has_pin(user_id)


def disable_pin(self, user_id):
    """Remove an account's PIN (is logged — a second factor does not vanish unnoticed)."""
    self.store.delete_pin(user_id)
    self.audit("pin_disable", self._account_name(user_id), detail=f"user={user_id}")
    self._security_event("pin_disabled", user_id)


def _check_pin(self, username, pin) -> Optional[dict]:
    """Like `_check_password`, only with the personal PIN."""
    u = self.find_user(username)
    if not u or u["disabled"]:
        dummy_verify(str(pin or ""))
        return None
    h = self.store.get_pin_hash(u["id"])
    if not h:
        dummy_verify(str(pin or ""))
        return None
    if not verify_password(str(pin or ""), h):
        return None
    if needs_rehash(h):
        self.store.set_pin_hash(u["id"], hash_password(str(pin)))
    return u


# Check factors against a known identity (step-up: the user is already fixed).
def _verify_user_password(self, user_id, password) -> bool:
    """Check the password of a KNOWN account (step-up: the identity is already fixed)."""
    h = self.store.get_password_hash(user_id)
    if not h:
        dummy_verify(password or "")
        return False
    if not verify_password(password or "", h):
        return False
    if needs_rehash(h):
        self.store.set_password_hash(user_id, hash_password(password))
    return True


def _verify_user_pin(self, user_id, pin) -> bool:
    """Like `_verify_user_password`, only with the PIN."""
    h = self.store.get_pin_hash(user_id)
    if not h:
        dummy_verify(str(pin or ""))
        return False
    if not verify_password(str(pin or ""), h):
        return False
    if needs_rehash(h):
        self.store.set_pin_hash(user_id, hash_password(str(pin)))
    return True


def stepup_options(self, user) -> list[str]:
    """What can THIS user confirm a step-up with? Order = suggestion.

    `config.stepup_methods` is a **wish, not a barrier**: if the user has set up none of the
    named methods, the confirmation falls back to everything they have —
    otherwise the area would be unreachable for them, without their being able to do anything about it.
    That includes the password with which they just signed in; `["totp"]` alone
    therefore does not guarantee that a second factor really stands before the sensitive area.

    Whoever wants the barrier sets `stepup_strict=True`: then the list stays empty if nothing
    wished for is set up, and the area stays closed until the user sets up the
    method."""
    cfg = self.cfg
    avail = []
    if cfg.totp_enabled and self.store.has_confirmed_totp(user["id"]):
        avail.append("totp")
    if cfg.pin_enabled and self.store.has_pin(user["id"]):
        avail.append("pin")
    if cfg.password_enabled and self.store.get_password_hash(user["id"]):
        avail.append("password")
    wanted = [m for m in (cfg.stepup_methods or []) if m in avail]
    if wanted:
        return wanted
    if cfg.stepup_methods and cfg.stepup_strict:
        return []              # wished for, but none of it set up → closed
    return avail               # the old way: the best the user has


def _is_pin_locked(self, username, ip, login: bool = True) -> bool:
    """Own, method-scoped lockout for the PIN (short keyspace). In addition to is_locked().

    The rejection is reported here (`_rejected`), as with every other lockout: until
    T-13 this was the only one to reject silently, and the security log was silent exactly when
    fail2ban was supposed to read. `login=False` for the step-up page — there the PIN is not a
    sign-in, the line then carries `failed verification`.
    """
    return self._check_lock(self._rules_pin(username, ip), username, ip, login)


def _is_password_change_locked(self, username, ip) -> bool:
    """Own, method-scoped lockout for the old-password prompt on the account page.

    The same design as `_is_pin_locked`, but with its own threshold
    (`password_change_max_attempts`) and **separate from the login lockout**: guessing stays
    throttled (R4-10 — the route was a silent password oracle), but a typo on the
    own account page does not lock the sign-in. The lockout applies exactly where
    the guessing happened.

    **Per account only, not per IP** (`ip` goes only into the log line). Until the
    second round an IP threshold counted here too — and behind NAT it locked
    bystanders again: three colleagues who mistyped locked the fourth out of his OWN
    password change, although he had entered nothing wrong. The rework set out to
    stop exactly that. It is not missing either: whoever guesses here already needs a
    valid session of the account whose password they are guessing — the victim is always the
    signed-in person themselves. Against knocking from outside, `_rate_ok(ip)` still stands.

    The rejection is reported here, not in the route: otherwise the
    security log would fall silent exactly when fail2ban is supposed to ban the IP (rationale at
    `_rejected`).
    """
    return self._check_lock(self._rules(username, ip, "password_change"),
                                username, ip, login=False)


def _is_reauth_locked(self, username, ip) -> bool:
    """Own, method-scoped lockout for the step-up confirmation (`/auth/reauth`).

    A step-up confirmation is **not a sign-in** — whoever performs it is already
    signed in. Until the second round its failed attempts nevertheless counted into the
    login bucket: five typos on the reauth page locked the user's **sign-in**
    for `lockout_window_sec`, correct password included. Now this bucket slows it
    (`reauth_max_attempts`), and **per account only**: the guessing hits exclusively
    the own account, an IP threshold would behind NAT hit only bystanders (`ip` goes only
    into the log line). The path stays throttled via `_rate_ok(ip)`.
    """
    return self._check_lock(self._rules(username, ip, "reauth"), username, ip, login=False)


def _is_resource_locked(self, username, ip) -> bool:
    """Own, method-scoped lockout for the area PIN (`/auth/resource/…`).

    `username` here is the pseudo name of the area (`res:<name>`) — there is no
    account. Until the second round the counter ran into the login bucket, and because
    **any visitor** may try the area PIN, that was an amplifier: three areas
    times five misses from the same address reached the login IP threshold
    (`max_login_attempts * ip_attempt_factor`) and locked the sign-in of accounts
    that had never done anything wrong.

    Two thresholds, and their order is the point (R7-3): **per address**
    `resource_max_attempts`, **per area** the `account_attempt_factor` multiple of it. Until
    T-13 it was the other way round — the area locked after `resource_max_attempts`, no matter
    from whom. A single stranger thus locked the area for ALL with five misses,
    including those who know the secret. Now his own address stops him, long
    before the area closes; that takes several connections. The area threshold cannot be
    dropped entirely: without it a distributed attacker guesses a four-digit
    PIN in hours, because every address brings its own attempts.
    """
    return self._check_lock(self._rules(username, ip, "resource"), username, ip, login=False)


def _is_totp_setup_locked(self, username, ip) -> bool:
    """Dedicated, method-scoped lockout for confirming the TOTP setup.

    Until T-13 the route `POST /auth/totp/setup` checked any number of codes, with no throttle,
    no lock and no log line (findings B2-12, R3-6) — the only OTP check
    where that was the case. Guessing gains little there (whoever sets up sees the secret), but
    a check without a brake and without a trace is exactly the one nobody looks at any more.
    Like `reauth`, **per account only** (`totp_setup_max_attempts`) and separate from the
    login lockout: five typos during setup should not lock the sign-in.

    Read-only: the route calls `_begin_attempt(…, "totp_setup")`, which checks and books in
    one step — with this method beforehand and `_record_login()` afterwards a parallel
    burst got past the limit.
    """
    return self._check_lock(self._rules(username, ip, "totp_setup"), username, ip, login=False)


# ---------- The lock rules: one source for checking and atomic booking ----------
def _rules_pin(self, username, ip, since=None) -> list:
    """The dedicated PIN bucket: `pin_max_attempts` per account, `ip_attempt_factor` times that per address.

    Per account and not per pair of account and address: a PIN often has only four digits,
    a distributed attacker would get through it within hours with pair counting."""
    since = self._window_start() if since is None else since
    username = norm_identifier(username)
    limit = self._sec("pin_max_attempts")
    return [("lockout_pin", limit, dict(since=since, username=username, method="pin")),
            ("lockout_pin_ip", limit * self._sec("ip_attempt_factor"),
             dict(since=since, ip=ip, method="pin"))]


def _window_start(self) -> int:
    return _manager._now() - self._sec("lockout_window_sec")


def _rules(self, username, ip, method) -> list:
    """Which counters apply to an attempt of this method? List of `(reason, limit, filter)`.

    `is_*_locked()` checks them, `_begin_attempt()` checks them AND books atomically — both read
    the same list so that the two paths are never of different strictness.

    **Sign-in** (everything except `security.OWN_BUCKET_METHODS`, R7-6/H-8): the first
    threshold counts per **pair of account and address** (`max_login_attempts`). Until T-13 it counted
    per account alone — then any stranger could lock out any account whose name they knew
    for a window with five requests, including the owner with the correct password. Per
    account a second, higher threshold remains (`account_attempt_factor` times) against
    guessing across many addresses; a single attacker no longer reaches it because the pair
    stops them first. Per address the NAT threshold (`ip_attempt_factor` times) remains against
    trying out many accounts.

    The account key is `_bucket(username)`, not the raw text — otherwise an
    attacker could set up arbitrarily many buckets for the same account with whitespace and spellings.
    """
    since = self._window_start()
    username = self._bucket(username, method)
    if method in ("password_change", "reauth", "totp_setup"):
        limit = self._sec(f"{method}_max_attempts")
        return [(f"lockout_{method}", limit, dict(since=since, username=username, method=method))]
    if method == "resource":
        limit = self._sec("resource_max_attempts")
        return [("lockout_resource_ip", limit, dict(since=since, ip=ip, method=method)),
                ("lockout_resource", limit * self._sec("account_attempt_factor"),
                 dict(since=since, username=username, method=method))]
    if method in security.SIGN_IN_OWN_LOCK:
        # A sign-in with a bucket of its own (T-66, app password): the same three thresholds as the
        # login — pair, account, address —, counted only over its own method.
        limit = self._sec("max_login_attempts")
        own = []
        if username and ip:
            own.append((f"lockout_{method}", limit, dict(since=since, username=username, ip=ip, method=method)))
        return own + [
            (f"lockout_{method}_account", limit * self._sec("account_attempt_factor"),
             dict(since=since, username=username, method=method)),
            (f"lockout_{method}_ip", limit * self._sec("ip_attempt_factor"),
             dict(since=since, ip=ip, method=method))]
    without = security.OWN_BUCKET_METHODS
    limit = self._sec("max_login_attempts")
    rules = []
    if username and ip:
        rules.append(("lockout_user", limit,
                       dict(since=since, username=username, ip=ip, exclude_methods=without)))
    rules += [
        ("lockout_account", limit * self._sec("account_attempt_factor"),
         dict(since=since, username=username, exclude_methods=without)),
        ("lockout_ip", limit * self._sec("ip_attempt_factor"),
         dict(since=since, ip=ip, exclude_methods=without)),
    ]
    if method == "pin":
        rules += self._rules_pin(username, ip, since)
    return rules


def _series_full(self, username) -> bool:
    """Has this identifier reached `account_max_consecutive_failures` failed attempts IN A ROW (B2-6)?

    Unlike every window threshold, this lock does not expire: it ends with a
    complete sign-in by another route (passkey, magic link, OIDC), a
    password reset or by the operator (panel reset, `tinysesam unlock`). Counting is
    per folded identifier, whether the account exists or not — otherwise the lock would reveal which
    names exist.

    Only what is settled (`failure_series_confirmed`, G9): a pending pre-booking can still
    be taken back — a deferral therefore never shows the streak-lock text."""
    return (self.store.failure_series_confirmed(norm_identifier(username))
            >= self._sec("account_max_consecutive_failures"))


def _series_reset_helps(self, username) -> bool:
    """Does a self-service reset lift the streak lock under this identifier?

    It clears only the shares of the first factors (`_SERIES_RESET_KINDS`), not TOTP and not
    the PIN in the chain step (`_PIN_CHAIN_SERIES`, G7). If those alone are at the limit, the lockout
    notice and security log still named the reset as a way out until 2026-09-27 — the owner
    reset their password and stayed locked. Only for texts to the owner and operator: the
    sign-in page shows everyone the same text (`err.locked_series`), otherwise it would reveal that
    someone is guessing the second factor under an identifier — and thus that the account exists."""
    return (self.store.failure_series_without(norm_identifier(username), self._SERIES_RESET_KINDS)
            < self._sec("account_max_consecutive_failures"))


def _series_way_out(self, username) -> str:
    """What the streak lock under this identifier lifts — for the security log."""
    if self._series_reset_helps(username):
        return "password reset, signing in another way, or `tinysesam unlock`"
    return ("signing in another way or `tinysesam unlock` (a password reset does not clear "
            "the failed attempts after the password: TOTP, PIN in the chain step)")


def _check_lock(self, rules, username, ip, login: bool) -> bool:
    """Check the rules read-only; the first one that applies is reported (`_rejected`).

    If a rule applies only because of pending pre-bookings (G9, `Store.reserve_attempt`), that is
    a deferral, not a lock: `True` without `failed login` and without a lockout notice
    (`_deferred`). A rule that applies as confirmed as well takes precedence."""
    pending = False
    if login and username:
        if self._series_full(username):
            self._rejected(username, ip, "lockout_series", login=True)
            return True
        pending = (self.store.failure_series(norm_identifier(username))
                     >= self._sec("account_max_consecutive_failures"))
    for reason, limit, filt in _valid_rules(rules):
        if self.store.count_fails(**filt) < limit:
            continue
        if self.store.count_fails(**filt, only_confirmed=True) >= limit:
            self._rejected(username, ip, reason, login=login)
            return True
        pending = True
    if pending:
        self._deferred(username, ip, login=login)
    return pending


def _begin_attempt(self, username, ip, method, include_pin: bool = False,
                      series_kind: Optional[str] = None, as_pending: bool = False) -> Optional[int]:
    """Admit a check attempt **atomically** and pre-book it as a failed attempt.

    Return: an attempt ID that goes back to `_record_login(..., attempt=id)`, or
    `None` — locked (already reported). Replaces the sequence `_is_locked()` → check →
    `_record_login()`, which let a parallel burst past the lock (R3-2, R3-7,
    R7-2; rationale at `Store.reserve_attempt`).

    `include_pin=True` also attaches the PIN bucket — for the step-up page, on which a PIN
    confirms but whose attempts land in the `reauth` bucket.

    `series_kind` books the attempt in the streak (B2-6) under a different kind than the
    method — `_PIN_CHAIN_SERIES` for a PIN that comes AFTER an already provided factor
    (chain step, route chain; G7). Window and buckets keep counting under `method`.

    `as_pending=True` books the attempt with an open outcome (G9, `Store.reserve_attempt`): for
    a check that can also turn out to be "no attempt at all" — the login route with LDAP, whose
    pre-booking is taken back on an outage (F-23). If an attempt would be rejected **only** because of
    such open pre-bookings, it waits until they are decided: at most
    `_PENDING_DEADLINE_SEC`, at most `_PENDING_WAIT_SLOTS` waiters per process. If it stays
    open, the answer is `None` as with a lock — but with `deferred login` instead of
    `failed login` in the security log (fail2ban does not ban) and without a lockout notice.
    """
    rules = self._rules(username, ip, method)
    if include_pin:
        rules = rules + self._rules_pin(username, ip)
    # The streak (B2-6) belongs in the SAME transaction as the attempt: checked and pre-booked
    # in `reserve_attempt`. Before, it was read ahead of it and counted only after the check — a
    # parallel burst at the limit could then guess for one attempt per request.
    series = None
    if method not in security.OWN_BUCKET_METHODS:
        series = (norm_identifier(username), series_kind or method, self._sec("account_max_consecutive_failures"))

    def book():
        return self.store.reserve_attempt(self._bucket(username, method), ip, method,
                                          _valid_rules(rules), series=series, as_pending=as_pending)

    attempt, response = book()
    if attempt is None and response == "pending":
        attempt, response = self._wait_pending(book)
    if attempt is None:
        login = method not in security.NOT_LOGIN_METHODS
        if response == "pending":
            self._deferred(username, ip, login=login)
        else:
            self._rejected(username, ip, response, login=login)
    elif series is not None:
        # The kind under which it WAS booked (`series[1]`), not the method: otherwise a
        # correct follow-up step would lower the kind `pin` and leave its pre-booking under `pin_chain`
        # standing (G7).
        self._series_prebookings[attempt] = (series[0], series[1], response)
        # Capped: an attempt that nobody ever completes (exception in the middle of the route)
        # would otherwise remain forever. Whoever drops out counts as a failed attempt — stricter,
        # never looser.
        while len(self._series_prebookings) > self._SERIES_PREBOOKINGS_MAX:
            self._series_prebookings.pop(next(iter(self._series_prebookings)), None)
    return attempt


def _wait_pending(self, book) -> tuple:
    """Wait until the pending pre-bookings are decided, then book again (G9).

    Return as for `Store.reserve_attempt`; `(None, "pending")` if the deadline expires or
    no waiting slot is free. Without a cap a burst would tie up every worker thread.

    Waiting blocks the calling thread — right for the synchronous routes (they run
    in the thread pool). `POST /auth/password` has also called its check in the thread pool since 0.22.0
    (`change_password`); it never goes pending anyway: its bucket counts only its own method, and
    that one never books open."""
    if not self._pending_places.acquire(blocking=False):
        return None, "pending"
    try:
        deadline = time.monotonic() + self._PENDING_DEADLINE_SEC
        while time.monotonic() < deadline:
            time.sleep(self._PENDING_BEAT_SEC)
            attempt, response = book()
            if attempt is not None or response != "pending":
                return attempt, response
        return None, "pending"
    finally:
        self._pending_places.release()


def _deferred(self, username, ip, login: bool = True) -> None:
    """A rejection that is not a lock: only pending pre-bookings in the way (G9).

    Own event word (`deferred login`/`deferred verification`) — the bundled
    fail2ban filters do not match it, and no lockout notice goes out: there may
    afterwards not be a single failed attempt in the table. It is logged anyway so that an
    operator can attribute the 429."""
    security.seclog.warning("deferred %s user=%s ip=%s reason=pending",
                            "login" if login else "verification",
                            security.for_log(username) or "-", security.for_log(ip))


def _password_repeated(self, username, ip, password) -> bool:
    """Has the same IP already sent exactly this wrong password to this account? Remembers it otherwise.

    Call only after a FAILED ATTEMPT: a correct password is never remembered. What is remembered is an HMAC with a
    subkey derived from the master key, truncated to 64 bits, in memory only and only for
    `password_repeat_window_sec`. Per process: with several workers a repetition that another
    worker receives counts in full again — the stricter direction.

    Repeating gains an attacker nothing, because the same password tests nothing new. Every OTHER wrong
    password keeps counting in full, and the IP throttle (`_rate_ok`) applies before everything else."""
    n = self._sec("password_repeat_memory")
    if n <= 0 or not password:
        return False
    window = self._sec("password_repeat_window_sec")
    identifier = norm_identifier(username)
    # PBKDF2 instead of a plain HMAC: the value arises from a password, so a hash that makes guessing expensive —
    # with a secret as salt so that a memory dump yields nothing without the master key.
    fp = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8", "surrogatepass"),
                             self._pw_repetition_key_name + identifier.encode("utf-8", "surrogatepass"),
                             self._PW_REPETITION_ROUNDS)[:8]
    key = (identifier, security.ip_normalized(ip) or str(ip))
    now = time.monotonic()
    with self._pw_repetition_lock:
        items = [(f, t) for f, t in self._pw_repetition.get(key, ()) if now - t < window]
        hit = any(hmac.compare_digest(f, fp) for f, _ in items)
        if not hit:
            items = (items + [(fp, now)])[-n:]
        self._pw_repetition[key] = items
        self._pw_repetition.move_to_end(key)
        while len(self._pw_repetition) > self._PW_REPETITION_PAIRS:
            self._pw_repetition.popitem(last=False)
    return hit


def _sign_in_complete(self, user_id, ip, method) -> None:
    """A sign-in is through with all factors: audit `login` and the line `login ok` in the security log.

    `unban=ja|no` (0.24.10, PO): may a guard (fail2ban) lift the lock on this IP? Only `yes` if, from
    this IP, there is NO failed attempt against ANOTHER account in the window. Otherwise an attacker with an own
    account lifts their ban by a sign-in between two bursts and guesses without limit at firewall level against
    other accounts. The question is about other accounts, not the own one: the own failed attempts have been
    cleared by the successful factor already (`_record_login`)."""
    u = self.store.get_user(user_id)
    name = u["username"] if u else None
    self.store.audit_log("login", name, ip, method)
    foreign = (self.store.count_fails(self._window_start(), ip=ip, except_username=norm_identifier(name),
                                    exclude_methods=security.NOT_LOGIN_METHODS)
             if ip and name else 1)
    security.seclog.info("%s user=%s ip=%s method=%s unban=%s", security.LOG_SUCCESS,
                         security.for_log(name or "?"), security.for_log(ip), security.for_log(method),
                         "yes" if foreign == 0 else "no")


def _revert_attempt(self, attempt) -> None:
    """Take back a pre-booked attempt — it was none (directory outage, F-23).

    Together with its pre-booking in the streak (B2-6), in one transaction (G9): an outage is
    not a failed attempt, neither in the window nor in a row."""
    booked = self._series_prebookings.pop(attempt, None)
    self.store.cancel_attempt(attempt, series=booked[:2] if booked else None)


def _attempt_failed(self, attempt) -> None:
    """Close a pre-booked attempt as a failed attempt, without `_record_login` (G9).

    For a route whose check ends with an unexpected exception: the attempt counts
    immediately — stricter in doubt, as with a process that dies in the middle — instead of
    staying pending for `Store.PREBOOKING_PENDING_SEC` and making sign-ins from the same address wait.
    The streak stays booked."""
    self._series_prebookings.pop(attempt, None)
    self.store.finish_attempt(attempt, False)


# ---------- MFA (TOTP) ----------
def _mfa_pending(self, user_id) -> bool:
    """TOTP required? Yes, if a confirmed TOTP exists for this account.

    There is no global enforcement here (any more): the switch `totp_required`, at which
    the earlier parenthetical remark was aimed, has been rejected in the constructor with `ConfigError`
    since 0.18.0. Enforcement happens via `login_chain` — and `_session_ok` evaluates that, not
    this method."""
    return self.store.has_confirmed_totp(user_id)


def _totp_step(self, secret, code):
    """The time step a code matches inside the window `totp_window` allows (T-57) — or None.

    RFC 6238 §5.2 recommends at most one step back for the transmission delay; ASVS 5.0 6.5.5 wants a TOTP
    to live no longer than needed. Up to 0.25.x a step ahead counted as well — a code that a fast clock
    showed 30 seconds early, and in sum a code that worked for 90 seconds."""
    back, ahead = _totp.WINDOWS.get(str(self.cfg.totp_window), _totp.WINDOWS["previous"])
    return _totp.matching_step(secret, code, back, ahead)


def _verify_totp(self, user_id, code) -> bool:
    """Check a TOTP code — and consume it in the process.

    A code is valid **exactly once**. Before, it was valid for 90 seconds as often as desired
    (`valid_window=1` = previous + current + next step), and two separate
    clients could sign in fully with the same code. NIST SP 800-63B is unambiguous on this point:
    "Verifiers SHALL accept a given OTP only once while it is valid."

    Which steps count is `totp_window` (T-57): by default the current and the previous one, no longer the next.
    """
    t = self.store.get_totp(user_id)
    if not t or not t["confirmed"]:
        return False
    step = self._totp_step(t["secret"], code)
    if step is None:
        return False
    # Book before the factor counts: whoever no longer gets the step was the second one.
    return self.store.consume_totp_step(user_id, step)


def totp_begin(self, user_id):
    """Start the setup: returns the secret and the `otpauth://` address for the
    authenticator — and newly raises `StateError` (not `ConfigError`, no silent success)
    if the account already has a confirmed TOTP.

    **Only as long as no confirmed TOTP exists.** Up to 0.18.0 every call overwrote the
    secret and reset `confirmed`: a confirmed second factor thereby silently disappeared,
    the recovery codes were left orphaned, and the session afterwards counted as fully valid with the
    password alone. Because `GET /auth/totp/setup` called this method unconditionally,
    a click on a foreign link was enough — a GET carries no CSRF token, and
    `SameSite=Lax` (default) sends the session cookie along with a top-level navigation
    (finding B2-1). Whoever wants to change authenticator switches TOTP off properly
    (`totp_disable` — CSRF-protected and logged) and sets it up anew.

    A running, still **unconfirmed** attempt continues to be replaced by a fresh
    one: there is nothing to lose there, and handing on a secret that was once issued
    would be worse than a new one.
    """
    if self.store.has_confirmed_totp(user_id):
        # The attempt itself is the interesting line: up to 0.18.0 this path left
        # no trace although it removed the second factor.
        self.audit("totp_setup_denied", self._account_name(user_id),
                   detail=f"user={user_id} reason=already_confirmed")
        raise StateError(
            f"Account {user_id} already has a confirmed TOTP — disable it first "
            f"(totp_disable), then set it up again.")
    u = self.store.get_user(user_id)
    if u is None:
        raise ConfigError(f"No account with ID {user_id} — TOTP cannot be set up.")
    # Recovery codes without a confirmed TOTP belong to a secret that nobody has any more.
    # Leaving them in place would keep the second factor open via codes that do not fit
    # the new setup.
    orphaned = self.store.count_recovery_codes(user_id)
    if orphaned:
        self.store.delete_recovery_codes(user_id)
        self.audit("recovery_orphan_deleted", str(u["username"]),
                   detail=f"user={user_id} n={orphaned}")
    secret = _totp.new_secret()
    self.store.set_totp(user_id, secret, confirmed=False)
    self.audit("totp_setup_start", str(u["username"]), detail=f"user={user_id}")
    uri = _totp.provisioning_uri(secret, u["username"], self.cfg.rp_name)
    return {"secret": secret, "uri": uri, "qr": _totp.qr_data_uri(uri)}


def totp_confirm(self, user_id, code) -> bool:
    """Complete the setup — only with a valid code is TOTP really on.

    The confirmation code is **consumed** like any other (finding B2-3): until T-13 this
    place only called `verify()` and did not book the time step. The same code, just typed in
    for the setup (and possibly read off while doing so), still signed in at
    `/auth/totp` for up to 90 seconds — the single-use promise from T-9 applied only to the
    sign-in, not to the setup. Whoever sets up under `login_chain=["password","totp"]`
    gets the TOTP step credited right away with this confirmation (the
    route does that, A-1) — otherwise the code just typed would be a failed attempt there.

    An **already confirmed** TOTP is not confirmed again by this method (A-4): it would
    otherwise report `totp_enabled` for something nobody set up, and would incidentally be a
    second code checker for the active factor with a bucket of its own."""
    t = self.store.get_totp(user_id)
    if not t or not code or t["confirmed"]:
        return False
    step = self._totp_step(t["secret"], code)
    if step is None or not self.store.consume_totp_step(user_id, step):
        return False
    self.store.confirm_totp(user_id)
    # From here on a new second factor applies — the counterpart to `totp_disable` and
    # until now the only factor change without a line (B5-07). It is precisely this that an
    # attacker with a taken-over session does in order to come back.
    self.audit("totp_enable", self._account_name(user_id), detail=f"user={user_id}")
    self._security_event("totp_enabled", user_id)
    return True


def totp_disable(self, user_id):
    """Remove TOTP, together with the recovery codes (both are logged)."""
    unclosed = self.store.count_recovery_codes(user_id)   # count before deleting
    had = self.store.has_confirmed_totp(user_id)
    self.store.delete_totp(user_id)
    self.store.delete_recovery_codes(user_id)   # without TOTP, recovery codes are moot
    # Switching off a second factor is what an attacker does first once they have
    # a session. Without an entry it cannot be traced afterwards — until 2026-09-21
    # it left no trace, although TOTP AND all recovery codes fall in the process.
    self.audit("totp_disable", self._account_name(user_id), detail=f"user={user_id} recovery_codes_deleted={unclosed}")
    if had:
        self._security_event("totp_disabled", user_id, recovery_codes_deleted=unclosed)


def generate_recovery_codes(self, user_id, n=None) -> list:
    """Generate new one-time codes (replaces existing ones). Plaintext return ONLY ONCE.

    Raises `ConfigError` with `recovery_codes_enabled=False` (T-94): codes that no route accepts would be a
    promise of a way back that does not exist — and the codes the account still holds stay untouched."""
    if not self.cfg.recovery_codes_enabled:
        raise ConfigError("recovery_codes_enabled=False — no recovery codes are issued or accepted")
    n = int(n or self.cfg.recovery_code_count)
    codes = ["-".join(secrets.token_hex(self._RECOVERY_BYTES) for _ in range(2)) for _ in range(n)]
    self.store.delete_recovery_codes(user_id)
    self.store.add_recovery_codes(user_id, [self.store.token_digests(self._rc_norm(c), "recovery")[0]
                                            for c in codes])
    self.audit("recovery_generate", self._account_name(user_id), detail=f"user={user_id} n={n}")
    self._security_event("recovery_codes_generated", user_id, count=n)
    return codes


def _rc_hash(self, code) -> str:
    """The stored digest of a recovery code: an HMAC with the pepper (kind `recovery`; T-72 for the other tokens).
    Up to 0.30.0 it was a plain sha256 — whoever could write the database file put the digest of a code of their
    own choosing next to an account and held its second factor. After a pepper rotation a code made with a previous
    pepper keeps being found (`Store.token_digest`); `keys retire` refuses while such a code is unused."""
    return self.store.token_digest(self._rc_norm(code), "recovery")


def _verify_recovery_code(self, user_id, code) -> bool:
    """Check and consume a one-time code. A code is valid exactly once.

    With `recovery_codes_enabled=False` (T-94) no code is looked at — it is neither accepted nor used up, so the
    codes stay as they were for the day the switch goes back on."""
    if not code or not self.cfg.recovery_codes_enabled:
        return False
    if not self.store.consume_recovery_code(user_id, self._rc_hash(code)):
        return False
    # Own line (B5-07/B2-7). A consumed code means: the authenticator was missing — or someone else has a
    # code. The owner should learn of either, and the operator should be able to tell it apart from a
    # TOTP sign-in (finding B2-7). Until T-13 nothing of that remained: no
    # audit line, no hint how many codes are left.
    rest = self.store.count_recovery_codes(user_id)
    self.audit("recovery_used", self._account_name(user_id), detail=f"user={user_id} remaining={rest}")
    security.seclog.warning("recovery code used user_id=%s remaining=%s", user_id, rest)
    self._security_event("recovery_code_used", user_id, remaining=rest)
    return True


def recovery_codes_remaining(self, user_id) -> int:
    """How many one-time codes this account still has."""
    return self.store.count_recovery_codes(user_id)


# ---------- Password reset (forgot password) ----------
def federated_only(self, user_id) -> bool:
    """Pure SSO account: bound to an IdP/a directory and without a local password.

    If the directory delivers no stable identifier, the login binds an origin placeholder
    (`_WITHOUT_IDENTIFIER`, A-4) — such an account also counts as federated here.

    Limit: an LDAP or SAML account that has not signed in since the update to this version
    carries no row yet and counts as local here.

    Not regulated here: the magic login link (`magiclink_enabled`) also goes to a pure
    SSO account — that is a sign-in route switched on by the operator, not a password that
    remains; whether it should be switched off for such accounts is a product decision."""
    return (self.store.has_foreign_identity(user_id)
            and not self.store.get_password_hash(user_id))


def send_password_reset(self, email, base_url) -> bool:
    """Send a reset link to an email address IF a matching user exists. Outwardly always the
    same message (no enumeration). `base_url` is checked (`ConfigError` for a
    foreign host, see `magic_url`).

    The check comes first — before the account lookup, so that "exception instead of False" does not
    reveal whether the address exists, and before the token is issued, so that no unusable
    token is left behind.

    The mail goes to the **stored** address, not to the input (R4-11): the lookup
    is lenient (case, whitespace), the delivery must not be.
    If delivery fails, the token is invalidated immediately (B6-12) and the error is passed on
    to the caller.
    """
    base_url = self._checked_base(base_url)
    u = self.store.get_user_by_email(email)
    if not u or u["disabled"] or u["is_service"]:
        return False
    if self.federated_only(u["id"]):
        # A pure SSO account gets no reset link (H-4). It would set a LOCAL
        # password — a second path past the IdP or directory: lock, group removal
        # and the provider's MFA requirement would then no longer apply, and with LDAP the
        # local password even wins over the directory (`_check_password` first). The response
        # to the outside stays the same (no account probing); the reason is in the audit log.
        self.audit("reset_sso_only", u["username"], detail="no local password, federated")
        return False
    destination = u["email"]
    if not self._mail_destination_ok(destination, "reset_password"):
        return False
    raw = self.create_magic_token("reset_password", user_id=u["id"], email=destination)
    url = self.magic_url(raw, base_url, "reset_password")
    mins = self.cfg.magiclink_ttl_min
    self._token_mail(raw, destination, self.t("mail.reset.subject"),
                     self.t("mail.reset.text", mins=mins, url=url),
                     html=self.t("mail.reset.html", mins=mins, url=url))
    return True


def _global_chain(self):
    """(factors, strict) of the global default chain, or (None, True) for classic mode."""
    return (list(self.cfg.login_chain), self.cfg.login_chain_strict) if self.cfg.login_chain else (None, True)


def _chain_satisfied(self, required, strict, done) -> bool:
    """Every step by a factor of its own — and in order if `strict`. A step may name
    alternatives (`"password|passkey"`, T-34); one factor never satisfies two steps."""
    return _chain.satisfied(required, done, strict)


def _next_factor(self, required, strict, done, user_id=None):
    """The next factor to ask for, or None. With alternatives in the open step: the first
    one the account has set up (`user_id`), otherwise the first one named."""
    options = _chain.next_options(required, done)
    if not options:
        return None
    if user_id is not None:
        have = self._account_factors(user_id)
        for f in options:
            if f in have:
                return f
    return options[0]


def _account_factors(self, user_id) -> set:
    """What this account can provide today. Federated factors and the sign-in link are not set
    up here and count as available (the provider or the mailbox decides)."""
    cfg = self.cfg
    have = {"oidc", "saml", "magic"}
    if cfg.password_enabled and (cfg.ldap_enabled or self.store.get_password_hash(user_id)):
        have.add("password")
    if self.store.has_confirmed_totp(user_id):
        have.add("totp")
    if self.store.list_webauthn(user_id):
        have.add("passkey")
    if self.store.has_pin(user_id):
        have.add("pin")
    return have


def _settable_factors(self) -> set:
    """The factors a setup page exists for in this configuration."""
    cfg = self.cfg
    out = set()
    if cfg.password_enabled and not cfg.ldap_enabled:
        out.add("password")     # with a directory the password lives there (B-10)
    if cfg.totp_enabled:
        out.add("totp")
    if cfg.passkey_enabled and getattr(self, "webauthn", None):
        out.add("passkey")
    if cfg.pin_enabled:
        out.add("pin")
    return out


def _default_satisfied(self, user_id, done) -> bool:
    """Classic policy (no login_chain): one identification factor + TOTP, if set up."""
    if not any(f in done for f in self._IDENTIFYING):
        return False
    if "passkey" in done:
        return True   # passkey alone = fully valid
    if self.store.has_confirmed_totp(user_id) and "totp" not in done:
        return False
    return True


def _session_ok(self, user_id, done, setup: bool = False) -> bool:
    """Does the factor list satisfy the ACTIVE global policy (chain or classic)?

    `setup=True`: the session is in the setup pass after a sign-in link (T-34,
    `_setup_session`) — then the pass's own rule counts as well (`_setup_ok`)."""
    req, strict = self._global_chain()
    if req is not None:
        ok = self._chain_satisfied(req, strict, done) or (setup and self._setup_ok(user_id, done))
    else:
        ok = self._default_satisfied(user_id, done)
    return (ok and self._link_requires(user_id, done) is None
            and not self._password_change_owed(user_id, done))


def _password_change_owed(self, user_id, done) -> bool:
    """Did this session sign in with a password that an administrator set (T-46)? Then the
    sign-in is not complete before the holder has chosen an own one (`/auth/setup`).

    Only when the password was really used in this session: a sign-in by passkey, OIDC or link
    does not make the start secret any better or worse — it waits for its first use. Not with a
    directory (`ldap_enabled`): there the password lives in the directory."""
    if "password" not in done or not self.cfg.password_enabled or self.cfg.ldap_enabled:
        return False
    return self.store.password_must_change(user_id)


def _next_login_step(self, user_id, done, setup: bool = False):
    """Next open factor up to the full (global) sign-in, or None when done. In the setup pass
    (`setup=True`, T-34) the step can also be `"setup"` — the page `/auth/setup`."""
    step = self._next_login_step_factors(user_id, done, setup)
    if step is None and self._password_change_owed(user_id, done):
        return "password_change"          # T-46: the start secret is replaced last
    return step


def _next_login_step_factors(self, user_id, done, setup: bool = False):
    req, strict = self._global_chain()
    if req is not None:
        if setup:
            return self._setup_step(user_id, done)
        if not self._chain_satisfied(req, strict, done):
            return self._next_factor(req, strict, done, user_id)
    elif not self._default_satisfied(user_id, done):
        return "totp"
    return self._link_requires(user_id, done)


def _setup_missing(self, user_id) -> list:
    """`[(step index, [factors to choose from])]` for every step of the global chain that the
    account cannot cover with what it has (each factor counts once). `[]` without a chain."""
    req, _ = self._global_chain()
    if req is None:
        return []
    have = self._account_factors(user_id)
    settable = self._settable_factors()
    st = _chain.steps(req)
    return [(i, [f for f in st[i] if f in settable and f not in have])
            for i in _chain.uncovered(req, have)]


def _setup_blocker(self, user_id, done) -> Optional[str]:
    """An existing second factor that has to be shown before anything is set up, or None.

    A setup window opened by the operator (`grant_mfa_enrollment`) lifts it — the lost-device
    case, decided by the operator for exactly this account (as in `totp_enrollment_user`)."""
    if "totp" in done or "passkey" in done:
        return None
    u = self.store.get_user(user_id)
    window = u["mfa_enroll_until"] if u else None
    if window and int(window) > _manager._now():
        return None
    if self.store.has_confirmed_totp(user_id):
        return "totp"
    if self.store.list_webauthn(user_id):
        return "passkey"
    return None


def _setup_ok(self, user_id, done) -> bool:
    """Is the pass complete: the existing second factor shown and the chain satisfied by what was
    provided and set up (order aside)? Every factor in `done` is one the account has (or a link /
    federated one), so a satisfied chain also means nothing is missing for the next sign-in."""
    req, _ = self._global_chain()
    if req is None or "magic" not in done:
        return False
    return self._setup_blocker(user_id, done) is None and _chain.satisfied(req, done, False)


def _setup_owed(self, user_id, done) -> Optional[str]:
    """A factor the account HAS for a step of the chain but has not provided in this session —
    it comes before any setup (the link replaces no existing factor). None if nothing is owed."""
    req, _ = self._global_chain()
    if req is None:
        return None
    st = _chain.steps(req)
    have = self._account_factors(user_id)
    covered = _chain.covered(req, have)
    part = ["|".join(o for o in st[i] if o in have) for i in covered]
    if not part or _chain.satisfied(part, done, False):
        return None
    return self._next_factor(part, False, done, user_id)


def _setup_step(self, user_id, done) -> Optional[str]:
    """The next step inside the pass: an existing second factor, a factor the account has and
    owes, `"setup"`, or the second factor after the link (`_link_requires`)."""
    first = self._setup_blocker(user_id, done) or self._setup_owed(user_id, done)
    if first:
        return first
    if self._setup_missing(user_id):
        return "setup"
    return self._link_requires(user_id, done)


def _setup_window(self) -> int:
    """How long a pass stays open: the step-up window, or the session lifetime when that is 0."""
    sec = int(self.cfg.stepup_max_age_sec or 0)
    return sec if sec > 0 else self._ttl(True)


def _begin_setup(self, token, user_id) -> bool:
    """Open the pass for the half session behind `token` — right after a link sign-in. False (and
    nothing opened) when there is nothing to set up or self-setup is not allowed."""
    req, _ = self._global_chain()
    s = self.store.get_session(token) if token else None
    if req is None or not s or s["mfa_ok"] or int(s["user_id"]) != int(user_id):
        return False
    missing = self._setup_missing(user_id)
    if not missing or any(not options for _, options in missing):
        return False                  # nothing to do — or a step nobody can set up here
    name = self._account_name(user_id)
    if not self.mfa_enrollment_allowed(user_id):
        self.audit("mfa_enrollment_denied", name, s["ip"],
                   f"kind={self.cfg.mfa_enrollment} via=link")
        return False
    self.store.put_flow(self._SETUP_FLOW + s["token_hash"], {"user_id": int(user_id)},
                        ttl=self._setup_window())
    self.audit("setup_pass_start", name, s["ip"],
               "missing=" + ",".join("|".join(options) for _, options in missing))
    return True


def _setup_session(self, s) -> bool:
    """Is this session row a half session inside an open setup pass?"""
    if not s or s["mfa_ok"] or self._global_chain()[0] is None:
        return False
    flow = self.store.peek_flow(self._SETUP_FLOW + s["token_hash"])
    if not flow or int(flow.get("user_id", -1)) != int(s["user_id"]):
        return False
    window = int(self.cfg.stepup_max_age_sec or 0)
    if window > 0 and (_manager._now() - int(s["created_at"] or 0)) > window:
        return False
    u = self.store.get_user(s["user_id"])
    if not u or u["disabled"]:
        return False
    return self.mfa_enrollment_allowed(int(s["user_id"]))


def _setup_offer(self, request) -> Optional[tuple]:
    """`(account, [factors], step number, steps missing)` for the page `/auth/setup` — or None
    when this request is not in a pass or the pass has nothing to set up right now."""
    s = self._session_from_request(request)
    if not self._setup_session(s):
        return None
    done = json.loads(s["factors_done"] or "[]")
    if self._setup_blocker(s["user_id"], done) or self._setup_owed(s["user_id"], done):
        return None                   # first what the account has — then the setup
    missing = self._setup_missing(s["user_id"])
    if not missing:
        return None
    u = self._as_dict(self.store.get_user(s["user_id"]))
    self._remember_request(request, u)
    return u, list(missing[0][1]), int(missing[0][0]), len(missing)


def _setup_user(self, request, factor: str) -> Optional[dict]:
    """The account of a half session in the pass if `factor` is what the pass offers now —
    otherwise None. The one door through which a setup route accepts a half session."""
    offer = self._setup_offer(request)
    if offer is None or factor not in offer[1]:
        return None
    return offer[0]


def _setup_record(self, request, factor: str) -> Optional[str]:
    """Note a factor set up in the pass on the session. If the sign-in is complete with it, the
    session becomes full under a NEW token (privilege change, as in `complete_totp`), which is
    returned for the cookie; otherwise None."""
    s = self._session_from_request(request)
    if not self._setup_session(s):
        return None
    done = json.loads(s["factors_done"] or "[]")
    if factor not in done:
        done.append(factor)
    ok = self._session_ok(s["user_id"], done, setup=True)
    self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
    if not ok:
        return None
    return self._setup_complete(s, done, factor)


def _setup_complete(self, s, done, factor) -> str:
    """The half session of a finished pass becomes a full one under a new token."""
    uid = s["user_id"]
    self._sign_in_complete(uid, s["ip"], factor)
    self._note_login(uid)
    self._lift_after_sign_in(uid, s["ip"])
    new_token = self._create_session(uid, self._ttl(bool(s["remember"])), True, s["method"],
                                     s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
    self._successor(s, new_token)
    self._setup_finished(s, done)
    self.store.delete_session_by_handle(s["token_hash"])
    self._other_after_completion(s, new_token)
    return new_token


def _setup_finished(self, s, done) -> None:
    """The pass of this (half) session is over: drop its state, note it in the audit log."""
    self.store.pop_flow(self._SETUP_FLOW + s["token_hash"])
    self.audit("setup_pass_done", self._account_name(s["user_id"]), s["ip"], "factors=" + ",".join(done))


def _link_allowed(self, user_id) -> bool:
    """`magiclink_first_login_only` (T-34): may a sign-in link sign this account in?

    Always without the switch. With it: an account that has never been fully signed in, or one
    that lacks a factor of the chain and may set it up itself (the pass would open). An account
    that is complete gets no link sign-in — not even from the admin: a forgotten factor is
    removed by the operator, who opens a setup window (`grant_mfa_enrollment`) and then hands out
    a link."""
    if not self.cfg.magiclink_first_login_only:
        return True
    u = self.store.get_user(user_id) if user_id is not None else None
    if not u:
        return False
    if u["first_login_at"] is None:
        return True
    missing = self._setup_missing(user_id)
    return bool(missing) and all(o for _, o in missing) and self.mfa_enrollment_allowed(user_id)


def _link_requires(self, user_id, done) -> Optional[str]:
    """Which second factor is still missing because the sign-in went through the sign-in link?
    None if none (ASVS 6.3.6, PO decision 2026-09-24, `magiclink_require_second_factor`).

    The link proves only the mailbox. If the account has a second factor, the
    sign-in requires it — otherwise the mailbox alone would be the key to an account that protected itself with
    an authenticator. The classic policy always required a set-up TOTP;
    open were only accounts with passkey and chains in which the link alone
    suffices (`["magic"]`). Accounts without a second factor are still signed in by the link alone (the
    price of C versus D, deliberately decided that way). Applies to the global policy and to every
    route chain (`require(factors=[…])`, G10)."""
    if not self.cfg.magiclink_require_second_factor or "magic" not in done:
        return None
    if "totp" in done or "passkey" in done:
        return None
    if self.store.has_confirmed_totp(user_id):
        return "totp"
    if self.store.list_webauthn(user_id):
        return "passkey"
    return None


def _factor_entry(self, step, nxt="/") -> str:
    """The address of the input page for a factor step, with `next` attached."""
    from urllib.parse import quote
    base = {"password": self.cfg.login_path, "pin": "/auth/pin", "oidc": "/auth/oidc/start",
            "passkey": self.cfg.login_path, "totp": "/auth/totp", "setup": "/auth/setup",
            "password_change": "/auth/setup",
            "magic": "/auth/magic/request", "saml": "/auth/saml/login"}.get(step, self.cfg.login_path)
    return f"{base}?next={quote(nxt or '/', safe='/')}"


async def json_body(self, request: Request) -> dict:
    """Read the JSON body robustly: invalid/empty body → 400 instead of 500. Enforces CSRF
    (header X-CSRF-Token) for cookie-based clients; API-key requests are exempt."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(400, self.t("api.json_invalid"))
    if not isinstance(data, dict):
        raise HTTPException(400, self.t("api.json_object"))
    if self.cfg.csrf_enabled and not self._csrf_dispensable(request):
        token = request.headers.get("x-csrf-token") or data.get("_csrf")
        if not self._origin_ok(request) or not self._verify_csrf(request, token):
            raise HTTPException(403, self.t("api.csrf"))
    return data

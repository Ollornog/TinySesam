"""The building block `hardening` of `TinySesam`: hardening (regulation, rate limit, audit), redirect safety, language.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import logging
import re
import secrets
import time
from . import config_check
from . import security
from . import topbar as _topbar
from .dialog import assets as _dialog_assets
from .errors import ConfigError
from .store import attempt_deadline as _attempt_deadline
from .store import norm_identifier
from .store import role_invalid
from .templates import PREFIX_PLACEHOLDER as _PREFIX_PLACEHOLDER
from .templates import inject_nonce as _inject_nonce
from fastapi import Request
from fastapi.responses import HTMLResponse
from starlette.responses import Response
from typing import Optional
from . import manager as _manager
from .manager import (
    _REQUEST,
    _proof_on_account,
)


# ---------- Hardening (regulation / rate limit / audit) ----------
def client_ip(self, request: Request) -> str:
    """The real client IP. Behind a proxy only from `X-Forwarded-For` if the peer is in `trusted_proxies` — otherwise the header would be forgeable."""
    return security.client_ip(request, self.cfg.trusted_proxies)


def _sec(self, key) -> int:
    """Hardening value: store setting (panel) OR default, always within `security.SECURITY_LIMITS`.

    Read via `security.read_hardening` — the CLI (`tinysesam passwd`) takes the same route;
    an existing value beyond the limits counts there as here as the nearest limit."""
    return security.read_hardening(self.store, key)


def all_security(self) -> dict:
    """All hardening thresholds as a dict (defaults, overridden by what is set in the panel)."""
    return {k: self._sec(k) for k in security.SECURITY_DEFAULTS}


def set_security(self, key, value):
    """Set a hardening threshold at runtime; it survives the restart in the database.

    Unknown key or value outside `security.SECURITY_LIMITS` → `ConfigError`,
    and nothing is written. Up to 0.19.x an unknown key silently dropped out and every
    value was accepted — `rate_limit_max=0` then locked every sign-in, including the one with which
    the value could have been turned back (R6-4)."""
    try:
        number = security.check_hardening(key, value)
    except ValueError as e:
        raise ConfigError(str(e)) from None
    self.store.set_setting(key, number)


def set_rate_limiter(self, limiter):
    """Attach a custom rate-limit backend — any object with allow(key, max, window)->bool."""
    self.rl = limiter


def _rejected(self, username, ip, reason: str, login: bool = True):
    word = security.LOG_SIGN_IN if login else security.LOG_CHECK
    security.seclog.warning("%s user=%s ip=%s method=blocked reason=%s", word,
                            security.for_log(username) or "-", security.for_log(ip), reason)
    if login and reason in self._ACCOUNT_LOCKS and username:
        self._lockout_notice(username, ip, reason)


def _lockout_notice(self, username, ip, reason) -> None:
    """Notify the owner that their account has been locked (ASVS 6.3.5, B1-12).

    In the request the same thing happens for EVERY name — one throttle per name, one job into
    the own outbox —, whether the account exists or not. Lookup and sending
    happen only in the background: otherwise the response time would reveal which names have an account
    (the same consideration as R4-05). Only to a taken address (H-3), never to a
    service account; at most one notice per name and lock window."""
    if not self.cfg.notify_login_failures or not self.mail_configured():
        return
    key_name = "lockout_notice:" + norm_identifier(username)
    if not self.rl.allow(key_name, 1, self._sec("lockout_window_sec")):
        return
    when = _manager._now()

    def _send():
        u = self.find_user(username)
        if not u or u.get("is_service") or not u.get("email") or not _proof_on_account(u):
            return
        # The actual throttle is in the database, not in memory: the key above
        # lies in the shared, capped limiter and can be displaced with enough foreign keys;
        # with several workers each has its own (finding 11). The audit log applies to
        # all processes and forgets nothing before the deadline.
        since = _manager._now() - self._sec("lockout_window_sec")
        if self.store._one("SELECT 1 FROM audit WHERE event = 'lockout_notice' AND lower(username)=lower(?) "
                           "AND ts >= ? LIMIT 1", (u["username"], since)):
            return
        subject = self.t("mail.lockout.subject")
        # Name the reset only if it also clears the streak (it does not clear TOTP and the PIN in the chain step,
        # `_series_reset_helps`).
        until = ""
        if reason == "lockout_series":
            until = (self.t("mail.lockout.until_reset") if self._series_reset_helps(username)
                   else self.t("mail.lockout.until_operator"))
        text = self.t("mail.lockout.text", name=u["username"], until=until,
                      time=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(when)),
                      ip=security.for_log(ip) or self.t("mail.unknown"))
        self.send_mail(u["email"], subject, text)
        self.store.audit_log("lockout_notice", u["username"], ip, f"reason={reason}")

    self._notice_outcome.enqueue(_send)


def _rate_ok(self, ip, login: bool = True) -> bool:
    """May this IP still? A no writes a line into the security log (fail2ban reads along).

    `login=False` for routes that are not a sign-in (password change, step-up, realm PIN):
    their line then carries `failed verification` instead of `failed login` — otherwise the
    bundled jail banned a signed-in user who keeps clicking on their own
    account page (final attack C-1).

    An IPv6 address counts as its /64, and its /48 has a ceiling of `security.RATE_NET48_FACTOR` times the limit:
    counted per /128, one subscriber had 2^64 buckets (follow-up of attack round A-4). IPv4 stays per address."""
    limit, window = self._sec("rate_limit_max"), self._sec("rate_limit_window_sec")
    bucket = security.ip_bucket(ip)
    permitted = self.rl.allow(bucket, limit, window)
    if permitted and bucket.endswith("/64"):
        permitted = self.rl.allow("net48:" + security.ip_bucket(ip, 48), limit * security.RATE_NET48_FACTOR,
                                  window)
    if not permitted:
        self._rejected(None, ip, "ratelimit", login=login)
    return permitted


def _is_locked(self, username, ip) -> bool:
    """Too many failed attempts in the window — per pair of account and IP, per account, per IP.

    The thresholds are in `_rules` (rationale there): the pair at `max_login_attempts`,
    the account alone at `account_attempt_factor` times that, the address alone at
    `ip_attempt_factor` times that (NAT). Without `ip` only the account threshold applies.

    Everything in `login_attempt` that was a **sign-in attempt** is counted; the methods from
    `security.OWN_BUCKET_METHODS` (the non-sign-ins and the app password, T-66) stay out. Otherwise a wrong guess that was not
    a sign-in at all would lock the sign-in too. The counter of these methods is not lost,
    it just has its own bucket (e.g. `_is_password_change_locked`).

    Read-only: the routes take `_begin_attempt()`, which checks and books in one step.
    """
    return self._check_lock(self._rules(username, ip, "password"), username, ip, login=True)


def _record_login(self, username, ip, success, method, attempt: Optional[int] = None,
                  source: str = "", account: Optional[int] = None):
    """Book a sign-in attempt. A success clears only the failed attempts of the SAME method.

    `attempt` is the ID from `_begin_attempt()`: then the attempt already stands as a
    failed attempt in the table and is only closed here instead of being counted a second time.

    `quelle` tells the audit log WHO checked the secret where the method does not
    reveal it (F-29): LDAP deliberately writes the factor `password` — lock and chain should
    treat both routes the same —, but in the log the operator must be able to separate them.
    A success with `quelle` writes a line of its own `login_<quelle>` (`login_ldap`,
    `login_local`), a failed attempt appends `source=…` to `login_fail` (`local+ldap`: both
    were asked, both refused). Empty = as before, no additional information.

    `account` is the ID of the account to which the identifier was resolved if that did not happen via
    name or address — with a directory sign-in (G5-N1). Then a success clears
    the failed attempts under the typed identifier only if it does not belong to ANOTHER account:
    a directory filter via `mail` also resolves `boss@example.com` to a third party
    whose `mail` attribute reads that — and every one of their sign-ins reset the local owner's
    account window until 2026-09-26 (distributed guessing without limit apart from streak and
    IP limit).

    If the identifier is the name or address of a local account, clearing starts from its joining that
    account (limit a, G2): failed attempts that a stranger made under the then free identifier
    before the rename or address change remain — they count in the
    throttling of THEIR IP. Details in `_cleanup_limit`."""
    bucket = self._bucket(username, method)   # the same key as when counting
    prebooked = self._series_prebookings.pop(attempt, None) if attempt is not None else None
    transition = None
    if attempt is None:
        self.store.record_attempt(bucket, ip, success, method)
    else:
        # On a success the pre-booking in the streak does not apply — taken back in the same
        # transaction as the closing (G9). The streak before it remains: a correct first
        # factor is not yet a complete sign-in (`lift_lockout`). On a
        # failed attempt the closing says how the streak stood before and after (p2 F3).
        transition = self.store.finish_attempt(attempt, bool(success),
                                              series=prebooked[:2] if prebooked else None)
    if success and source:
        self.store.audit_log(f"login_{source}", username, ip, f"{method} source={source}")
    if success:
        # ONLY the failed attempts of the same method: a password success says nothing about
        # whether someone is currently trying out TOTP codes. Before, it cleared them too and made
        # the second factor guessable. Everything else is cleared only by the COMPLETE sign-in
        # (`lift_lockout`).
        limit = self._cleanup_limit(bucket, method, account)
        if limit is not None:     # 'login' audit only at full completion
            self.store.clear_fails(username=bucket, method=method, **limit)
    else:
        # The REASON belongs in the server-side log. The HTTP response deliberately stays
        # the same (no account probing) — but in the audit log only the operator reads along,
        # and "wrong password", "account deactivated" and "username
        # mistyped" all said the same to them so far: `login_fail … password`. That is the most frequent
        # support case, and it could not be answered with built-in means.
        self.store.audit_log("login_fail", username, ip,
                             f"{method} reason={self._fail_reason(username, method)}"
                             + (f" source={source}" if source else ""))
        # fail2ban parses this line (ip=…)
        # `for_log`: the username comes from a form field. Unfiltered, it could be used
        # to create a second log line with a foreign IP and point fail2ban at third parties
        # (verified against real fail2ban 1.1.1).
        # The event word separates sign-in attempts from everything else: only `failed login`
        # matches the bundled failregex. A wrong guess at the password change, at the
        # step-up page or at a realm PIN is not a sign-in and must not lock out a
        # legitimate, signed-in user at firewall level (see
        # `security.log_event`).
        security.seclog.warning("%s user=%s ip=%s method=%s", security.log_event(method),
                                security.for_log(username), security.for_log(ip), method)
        if method not in security.OWN_BUCKET_METHODS:
            # The streak counts per folded identifier, like the account bucket (`_bucket`). Pre-booked
            # by `_begin_attempt`; only a route without pre-booking counts here. Exactly at the
            # crossing of the limit one line: from there the sign-in is permanently closed, and
            # the operator must know why someone can no longer sign in.
            #
            # The crossing is that of the SETTLED state (p2 F3). An immediately settled
            # booking (without pending) crosses the limit at the booking itself
            # (`prebooked[2]`, the settled state afterwards) — it is reported if the
            # streak still stands at closing. A pending one crosses it only with its
            # closing (`before < max_series <= afterwards`, in one transaction). Until 2026-09-27
            # the state at booking applied, pending pre-bookings included: if a
            # parallel full sign-in ended the streak, `lockout_series` stood in the log although
            # nothing was locked.
            max_series = self._sec("account_max_consecutive_failures")
            if prebooked and transition:
                before, afterwards = transition
                state = afterwards
                locked = before < max_series <= afterwards or max_series <= min(prebooked[2], afterwards)
            else:
                state = self.store.increase_failure_series(norm_identifier(username), method)
                locked = state == max_series
            if locked:
                self.store.audit_log("lockout_series", username, ip, f"failed_in_a_row={state}")
                security.seclog.warning(
                    "Sign-in for user=%s locked: %d failed attempts in a row. Lift: %s.",
                    security.for_log(username), state, self._series_way_out(username))


def _cleanup_limit(self, bucket, method, account: Optional[int] = None) -> Optional[dict]:
    """From where does a success clear the failed attempts under `topf`? Keywords for
    `Store.clear_fails` — or None: not at all (`_record_login`).

    * `account` given (directory sign-in): if the identifier belongs to ANOTHER account → None
      (G5-N1, `Store.bucket_of_another`). Otherwise without limit, as until then: the identifier
      belongs to the entry in the directory, not only from the local creation — that often arises
      only with exactly this sign-in, and the typos before it were made by the same person.
    * The identifier is the name or address of a local account → from its watermark (`from_id`,
      G2), for existing data without a watermark from the creation (`seit`).
    * Otherwise (a realm `res:<name>`, no identifier of an account) → without limit, as until
      then: there is no account to which the identifier belongs only from a point in time."""
    if method == "resource" or not bucket:
        return {}
    if account is not None:
        return None if self.store.bucket_of_another(bucket, account) else {}
    u = self.store.account_by_bucket(bucket)
    if u is None:
        return {}
    limit = self.store.identifier_limits(u).get(bucket)
    if limit is None:
        return {}
    return {"from_id": limit[0]} if limit[0] is not None else {"since": int(u["created_at"] or 0)}


def lift_lockout(self, user_id, methods=None) -> int:
    """Clear the sign-in failed attempts of an account; returns how many there were.

    Without `methods`: after a **complete** sign-in (R7-1). The login lockout counts
    method-blind — password, PIN and TOTP fill the same bucket —, but a success cleared
    only its own method. Whoever signed in by PIN after three mistyped TOTP codes
    carried the three along, and the account was never "fresh" again. A complete
    sign-in has passed every required factor; afterwards there is nothing left against which
    the old failed attempts protect. The own buckets (`OWN_BUCKET_METHODS`) remain:
    they belong to processes AFTER the sign-in, or beside it (the app password at the gate, T-66).

    With `methods`: only these. The self-service reset (R4-13) clears `("password",)`:
    it proves access to the mailbox and replaces the password — about PIN and TOTP it says
    nothing. If it also cleared their failed attempts, anyone with access to the mailbox would get, at
    every reset, fresh guesses against the second factor.

    Counting happened under the identifier someone typed — username OR email,
    with a directory sign-in also the name there (G5). Clearing therefore happens under all of them
    (`Store.count_identifiers`).
    """
    u = self.store.get_user(user_id)
    if not u:
        return 0
    away = 0
    # The streak (B2-6): a complete sign-in ends it entirely. A password reset
    # clears the shares of the first factors (`_SERIES_RESET_KINDS`), not the second — the same
    # reason as below (R4-13): the self-service reset proves the mailbox, not the
    # second factor. If it cleared the TOTP wrong guesses too, anyone with a mailbox and
    # password would get a fresh streak against TOTP per reset (measured in the attack on B2-6). The
    # operator clears entirely (`_end_series`, panel reset, `tinysesam unlock`).
    #
    # The streak is deliberately cleared WITHOUT limit a, even if it began before the identifier
    # joined (G2, option A): it has no IP and protects only whoever owns the identifier
    # NOW — before the joining it protected no account, so clearing takes protection from nobody
    # and launders no throttling of an IP. A limit in time would not work either:
    # the streak knows no individual times, and a streak begun before the joining
    # could otherwise no longer be ended by the new owner with any sign-in (permanent lock).
    kinds = None if methods is None else tuple(
        set(methods) | (set(self._SERIES_RESET_KINDS) if "password" in methods else set()))
    for identifier in self.store.count_identifiers(user_id):
        self.store.delete_failure_series(identifier, kinds=kinds)
    # The window from the joining of the identifier (limit a, G2): otherwise the first
    # complete sign-in would also clear the failed attempts that a stranger had made BEFORE the creation, the
    # rename or the address change under the same identifier — also from the
    # throttling of their IP. Until 2026-09-26 the limit was the creation of the account for every
    # identifier; it is now only the fallback for existing data without a watermark.
    # The directory name (G5) has no watermark: its window is cleared by the sign-in itself
    # (`_record_login`), here only the streak.
    since = int(u["created_at"] or 0)
    for identifier, (from_id, _) in self.store.identifier_limits(u).items():
        limit = {"since": since} if from_id is None else {"from_id": from_id}
        start_from = since if from_id is None else 0
        if methods is None:
            without = security.OWN_BUCKET_METHODS
            away += self.store.count_fails(start_from, username=identifier, exclude_methods=without, from_id=from_id)
            self.store.clear_fails(username=identifier, exclude_methods=without, **limit)
        else:
            for m in methods:
                away += self.store.count_fails(start_from, username=identifier, method=m, from_id=from_id)
                self.store.clear_fails(username=identifier, method=m, **limit)
    return away


def _lift_after_sign_in(self, user_id, ip=None) -> int:
    """`lift_lockout()` after a COMPLETE sign-in — and tell the holder if failed attempts came before it (T-63).

    The count is the streak (B2-6) the sign-in ends: the consecutive failed sign-in attempts under every
    identifier of the account, across methods (a guessed TOTP code counts as much as a wrong password). It is
    read BEFORE `lift_lockout` clears it; the window in `login_attempt` would not do — `_record_login` has
    already cleared the attempts of the method that just succeeded. From `_AFTER_FAILURES_MIN` on: audit
    `login_after_failures` (`failures=`; shown on the account page under "Recent activity") and the event
    `signed_in_after_failures` (`failures`, `ip`) — by mail with `notify_login_failures`. Returns the count."""
    failures = sum(self.store.failure_series_confirmed(k) for k in self.store.count_identifiers(user_id))
    self.lift_lockout(user_id)
    if failures >= self._AFTER_FAILURES_MIN:
        self.audit("login_after_failures", self._account_name(user_id), ip, f"failures={failures}")
        self._security_event("signed_in_after_failures", user_id, failures=failures, ip=ip)
    return failures


def _end_series(self, user_id) -> int:
    """End the streak of an account entirely (B2-6) — the operator's way (panel reset).

    Under name, address and the name in the directory (G5, `Store.count_identifiers`): counting
    happens under what someone typed."""
    return sum(self.store.delete_failure_series(k) for k in self.store.count_identifiers(user_id))


def _fail_reason(self, username, method=None) -> str:
    """Why did the sign-in fail — for the log, not for the response."""
    if method == "resource":
        # The pseudo-name `res:<name>` is never an account. `no_account` therefore stood at
        # EVERY wrong guess at a realm PIN — a line that nobody can evaluate.
        return "wrong_area_secret"
    u = self.find_user(username)
    if not u:
        return "no_account"
    if u["disabled"]:
        return "account_locked"
    if method == "app_password":
        # The account's own password plays no part here (T-66) — `no_password_set` would mislead.
        return "wrong_app_password"
    if not self.store.get_password_hash(u["id"]) and not self.store.has_pin(u["id"]):
        return "no_password_set"
    return "wrong_secret"


def audit(self, event, username=None, ip=None, detail=None):
    """Write an event into the audit log. `detail` takes everything that later answers the question "why".

    What the caller does not name, `audit()` supplements from the running request (B5-02): the
    IP, the signed-in account as `username` if none is named, and `actor=<name>` in the
    detail if the signed-in account is ANOTHER one than the affected — the admin who
    issues a key to a foreign account. `username` is thus always the account at issue;
    `tinysesam audit --user X` also finds what others did to X.
    """
    a = _REQUEST.get()
    if a:
        if ip is None:
            ip = a.get("ip")
        actor = a.get("actor")
        if actor:
            if username is None:
                username = actor
            elif str(username).lower() != str(actor).lower():
                detail = f"{detail} actor={actor}" if detail else f"actor={actor}"
        # The account API (`apps`): every line of the request names the application and the person it CLAIMS to
        # act for (`app=… actor_claimed=…`) — beside `actor=`, the service account, which is what is proven.
        claimed = a.get("claimed")
        if claimed:
            detail = f"{detail} {claimed}" if detail else claimed
    self.store.audit_log(event, username, ip, detail)


def _account_name(self, user_id) -> Optional[str]:
    """The username for an ID — for audit lines that would otherwise carry only `user=<id>`."""
    u = self.store.get_user(user_id) if user_id is not None else None
    return str(u["username"]) if u else None


def _remember_request(self, request, u=None) -> None:
    """Record the IP and signed-in account of the running request for `audit()` (`_REQUEST`)."""
    try:
        ip = self.client_ip(request)
    except Exception:        # dummy without header/client — then just without IP
        ip = None
    _REQUEST.set({"ip": ip, "actor": str(u["username"]) if u else None})


def gc(self, attempts_older_than_sec: int = 86400) -> dict:
    """Clean up: expired sessions/flows/magic tokens/realm unlocks + old
    login attempts. Call regularly (cron/startup/scheduler) — otherwise the tables grow.
    The audit log only if `audit_retention_days` sets a deadline (B5-11) — then the number
    appears under `audit`. Returns the number of deleted rows per area: `unverified_accounts`,
    `sessions`, `flow`, `magic_tokens`, `resource_unlocks`, `login_attempts`,
    `failure_series` (until 0.21.x `failure_seriesn`), possibly `audit`.
    `attempts_older_than_sec` lies between 0 (all failed attempts) and ten years in
    seconds, otherwise `ValueError`, before anything is deleted."""
    older = _manager._now() - _attempt_deadline(attempts_older_than_sec)
    # BEFORE the tokens: the characteristic "never confirmed" is the expired confirmation token —
    # if `gc_magic_tokens` clears it first, the account can no longer be recognised (R4-09).
    # Without this step an address that someone foreign had registered and never
    # confirmed remained taken forever: the real owner got "email taken".
    # The same loop as `tinysesam gc` — it is in the store so that both go through the one
    # deletion route (H-13, integration findings 12/18). Before, `gc()` had its own copy
    # that deleted the account past the anonymisation.
    numbers = {
        "unverified_accounts": self.store.gc_unconfirmed_accounts(),
        "sessions": self.store.gc_sessions(),
        "flow": self.store.gc_flow(),
        "magic_tokens": self.store.gc_magic_tokens(),
        "resource_unlocks": self.store.gc_resource_unlocks(),
        "login_attempts": self.store.gc_attempts(older),
        # Streaks not triggered after 90 days of rest; triggered ones remain (B2-6).
        "failure_series": self.store.gc_failure_series(
            _manager._now() - 90 * 86400, self._sec("account_max_consecutive_failures")),
    }
    # OAuth (T-36): expired codes and tokens, old grants, registrations that never led to a grant. Also with
    # the switch off — what an earlier run left behind should not stay forever.
    from . import oauth as _oauth_mod
    numbers.update(self.store.gc_oauth(_manager._now(), _oauth_mod.IDLE_CLIENT_SEC, _oauth_mod.REVOKED_KEEP_SEC))
    # Approvals (stage A): expire what waited too long, delete closed rows after the audit deadline. Only with
    # the switch on — without it nothing changes, not even the keys of this result.
    if getattr(self.cfg, "approvals_enabled", False):
        numbers.update(self._approvals().gc())
    # Account API (stage B): accounts whose grace period after a deletion by their application has run out.
    numbers["provisioning_deleted"] = self.store.gc_provisioning(_manager._now())
    days = int(self.cfg.audit_retention_days or 0)
    if days > 0:
        numbers["audit"] = self.store.gc_audit(_manager._now() - days * 86400)
    return numbers


def _check_orphaned_app_accounts(self) -> dict:
    """Accounts whose `managed_by` names an application that is not (or no longer) configured with
    `provisioning` — one warning per application with the number. They stay as they are; no key reaches them
    until the operator configures the application again or releases them (`tinysesam accounts release`).
    Returns `{app_id: count}`."""
    configured = set(self._provisioning().apps())
    orphaned = {a: n for a, n in self.store.managed_counts().items() if a not in configured}
    for app_id, n in orphaned.items():
        logging.getLogger("tinysesam").warning(
            "%d account(s) are managed by the application %s, which is not configured (apps[…].provisioning) — "
            "configure it again or release them: tinysesam accounts release --app %s",
            n, security.for_log(app_id), security.for_log(app_id))
    return orphaned


def _check_role_catalog(self) -> None:
    """The role catalog against the configuration, once at start: a catalog row whose name breaks T-85 (a foreign
    writer; it is never offered), a catalog row the configuration names as well (redundant — the configuration
    owns the role), and the role levels over every known role (`available_roles` ∪ catalog): a ladder without an
    entry, an entry missing a level role. The last two were `config_check` warnings until the catalog — without the
    database they would be false alarms for entries that come from the catalog."""
    from . import _role_catalog
    log = logging.getLogger("tinysesam")
    rows = [r["name"] for r in self.store.catalog_roles()]
    broken = [r for r in rows if role_invalid(r)]
    if broken:
        security.seclog.warning("The role catalog holds names with a comma, a control character or surrounding "
                                "spaces: %s. The panel does not offer them; delete them (tinysesam roles delete).",
                                security.for_log(", ".join(repr(r) for r in broken)))
    owned = _role_catalog.config_names(self.cfg)
    twice = [r for r in rows if r in owned]
    if twice:
        log.warning("The configuration names the catalog roles %s too — the configuration owns them; the catalog "
                    "rows are redundant and may be deleted.", security.for_log(", ".join(twice)))
    for line in config_check.ladder_coverage(self.cfg, self.known_roles()):
        log.warning("%s", line)
    if any(r.get("source") for r in self.store.catalog_roles()):
        self._check_idp_catalog()     # imported roles (T-102): stale ones, and those of a source switched off


def _check_app_accounts(self) -> list:
    """The applications of `apps` with `provisioning` whose service account is missing or is no service account —
    one security-log line each; their account API stays shut (every request checks the key's account anyway).
    Returns their ids."""
    shut: list = []
    apps = getattr(self.cfg, "apps", None) or {}
    if not isinstance(apps, dict):
        return shut
    for app_id, entry in sorted(apps.items(), key=lambda kv: str(kv[0])):
        if not isinstance(entry, dict) or not isinstance(entry.get("provisioning"), dict):
            continue
        name = entry.get("account")
        row = self.store.get_user_by_name(name) if isinstance(name, str) and name else None
        if row is None or row["is_service"] != 1:
            shut.append(app_id)
            security.seclog.warning(
                "Account API for application %s is shut: its service account %s %s. Create it as a service "
                "account (is_service) and issue an automation key for it.", security.for_log(str(app_id)),
                security.for_log(str(name)), "does not exist" if row is None else "is not a service account")
    return shut


def _panel_actions(self):
    """The panel's account actions (`admin.PanelActions`) for the entrances that are not the panel routes — the
    account API asks here, so it imports neither the panel nor the router."""
    from .admin import PanelActions
    return PanelActions(self)


def _claim_for_audit(self, claimed: str) -> None:
    """Add `claimed` (the account API: `app=… actor_claimed=…`) to every audit line of the running request."""
    state = dict(_REQUEST.get() or {})
    state["claimed"] = claimed
    _REQUEST.set(state)


def _provisioning(self):
    """The account API of this instance (`tinysesam.provisioning.Provisioning`), created on first use."""
    svc = getattr(self, "_provisioning_service", None)
    if svc is None:
        from .provisioning import Provisioning
        svc = self._provisioning_service = Provisioning(self)
    return svc


def _approvals(self):
    """The approvals of this instance (`tinysesam.approvals.Approvals`), created on first use."""
    svc = getattr(self, "_approval_service", None)
    if svc is None:
        from .approvals import Approvals
        svc = self._approval_service = Approvals(self)
    return svc


def _approvals_pending(self, viewer) -> Optional[int]:
    """How many approvals wait for `viewer` — None when approvals are off or the viewer is no session account
    (the top bar and `topbar_data` then show nothing of them)."""
    if not getattr(self.cfg, "approvals_enabled", False) or not viewer:
        return None
    try:
        via = viewer["_via"]
    except (KeyError, IndexError, TypeError):
        via = None
    if via not in (None, "session"):
        return None
    return self._approvals().pending_count(viewer)


def version(self) -> str:
    """The running version — for the panel. TinySesam does not update itself;
    whoever installed it does that (pinned tag / wheel of a release)."""
    from . import current_version
    return current_version()


# ---------- i18n ----------
def t(self, key, **fmt) -> str:
    """Translated text for key in config.lang (fallback en → key). Placeholders via {name}."""
    from .messages import translate
    return translate(self.cfg.lang, key, self._messages, **fmt)


def add_messages(self, lang, mapping: dict):
    """Add/override own translations (they take precedence over the built-in ones)."""
    self._messages.setdefault(lang, {}).update(mapping)


def set_template(self, name, fn):
    """Replace a built-in page with an own renderer: fn(auth, ctx) -> str | Response.

    Names: see `TinySesam.PAGES` (depending on the enabled features not all appear).
    String → HTML with status; Response → 1:1. An unknown name is an error, not a
    silent nothing.

    Under a subpath (T-15): `ctx["prefix"]` is the prefix that a TinySesam path
    needs in the browser (`f"{ctx['prefix']}/auth/logout"`; up to 0.21.x `ctx["prefix"]`).
    `ctx["next"]` and `ctx["action"]` are already paths of the browser; `ctx["admin_path"]` is
    a path of the app (prefix in front). The page `magic_confirm` gets `ctx["purpose"]`
    (`login`, `verify_email`, `email_change`; up to 0.21.x `ctx["zweck"]`). Which keys
    a page gets is stated in the docstring of its built-in renderer
    (`tinysesam/templates.py`) — all English since 0.22.0.
    """
    if name not in self.PAGES:
        raise ConfigError(f"Unknown page {name!r} — available: {', '.join(self.PAGES)}")
    self.templates.set(name, fn)


def csrf_token(self, request: Optional[Request] = None) -> str:
    """The CSRF token of this browser — reuse an existing cookie, otherwise roll a new one.

    Sets NO cookie. A newly rolled token is remembered by the request: a later
    `ensure_csrf(request, response)` sets exactly this one (the way for finished responses such as
    Jinja's `TemplateResponse` — not for one that signs in or out, see `ensure_csrf`). A
    cookie that does not look like a token does not count."""
    if request is not None and self.cfg.csrf_enabled:
        return self._csrf_of_request(request)[0]
    return secrets.token_urlsafe(24)


def render_page(self, template, status=200, request: Optional[Request] = None, **ctx) -> Response:
    """Pass `request` wherever there is one: then an already set CSRF token remains valid.
    Without `request` a new one is created — that overwrites the cookie and invalidates *other* open
    forms (the classic "form expired" trap)."""
    tok, fresh = None, False
    if request is not None:
        self._check_secure_flag(request)
    if self.cfg.csrf_enabled:
        tok, fresh = self._csrf_of_request(request)
        ctx.setdefault("csrf", tok)      # templates embed <input name=_csrf> / JS reads the cookie
    # One nonce per response. The built-in pages manage without inline handlers/style=;
    # the nonce travels centrally into every <script>/<style> (no threading through the templates)
    # and into the CSP header. An override that returns a response stays untouched —
    # it sets its CSP itself; ctx['nonce'] is available to it.
    nonce = secrets.token_urlsafe(16)
    ctx.setdefault("nonce", nonce)
    # For own templates (set_template): the prefix that app paths need in the browser (T-15).
    ctx.setdefault("prefix", self._prefix(request))
    # …and the dialog building block (T-35): `<style>` + `<script>` for tsAlert/tsConfirm/tsPrompt/tsSecret,
    # which the nonce below covers like every other block of the page.
    ctx.setdefault("dialog", _dialog_assets(self))
    # …and who is signed in, for the account menu of the top bar (T-64) — only on the pages that show it,
    # and only a full session (never an API key: the menu signs out a cookie).
    if template in _topbar.MENU_PAGES and "viewer" not in ctx and getattr(self.cfg, "topbar_enabled", True):
        ctx["viewer"] = self.session_user(request) if request is not None else None
    # …and the app frame (T-91): the frame of the host this person comes from, or None — chosen from the request,
    # but every target in it comes from `forward_apps`.
    if "frame" not in ctx:
        ctx["frame"] = self._frame(request, ctx) if getattr(self.cfg, "topbar_enabled", True) else None
    built_in = not self.templates.overridden(template)
    out = self.templates.render(template, self, ctx)
    if isinstance(out, Response):
        resp = out
    else:
        # The built-in pages write `__TS_P__` in front of every app path (forms, links,
        # fetch calls) — here it becomes the mount prefix (T-15). ONLY for them: the output
        # of an own template stays byte-identical (counter-check: a placeholder in data
        # would there have altered a checked target after the fact).
        if built_in:
            out = str(out).replace(_PREFIX_PLACEHOLDER, ctx["prefix"])
        resp = HTMLResponse(_inject_nonce(out, nonce), status_code=status)
        self._set_csp(resp, nonce, ctx["prefix"])
    if tok is not None and fresh:
        self._set_csrf_cookie(resp, tok)
    # Here too, not only in the route: error pages from `install_error_pages` pass
    # by no TinySesam route and otherwise carry not a single hardening header.
    return self._header_lines(resp)


def topbar_head(self, *, nonce: str = "") -> str:
    """`<head>` part of the top bar for an own page of the app (T-64): the light/dark restore (before the
    first paint), the `--ts-*` tokens (with `c22_stylesheet` also the C22 adapter and stylesheet) and the
    bar's CSS. `nonce`: the page's CSP nonce for every `<style>`/`<script>`/stylesheet; empty = none."""
    out = _topbar.head_for_app(self.cfg)
    return _inject_nonce(out, nonce) if nonce else out


def topbar(self, request: Request, *, nonce: str = "", current: str = "", layout: str = "") -> str:
    """The top bar of the built-in pages for an own page of the app (T-64) — first thing in `<body>`, with
    `topbar_head()` in `<head>`. Logo, name, `topbar_links` and, for a signed-in session, the account menu
    (account, admin panel for admins, light/dark/system, sign out as a POST with the CSRF field).
    `nonce`: the page's CSP nonce for its `<script>`; empty = none. `current`: "account", "admin" or a link path of
    `topbar_links` — that entry gets `aria-current=page`. `layout` (T-103): "top" or "side" (the same bar as a side
    bar; the page gives way by itself); empty = `shell_layout`. The CSRF cookie: `ensure_csrf(request, response)`
    on the response, as for every own form."""
    if layout and layout not in _topbar.LAYOUTS:
        raise ValueError(f"layout={layout!r}: \"top\" or \"side\"")
    viewer = self.session_user(request)
    out = (_topbar.render(self, viewer=viewer, csrf=self.csrf_token(request), current=current,
                          layout=layout or _topbar.layout_for(self))
           .replace(_PREFIX_PLACEHOLDER, self._prefix(request)) + f"<script>{_topbar.JS}</script>")
    return _inject_nonce(out, nonce) if nonce else out


def topbar_data(self, user=None, *, base: Optional[str] = None, host: str = "") -> dict:
    """The top bar as data (T-76) for an account — the same answer `GET /auth/topbar.json` gives its session: the
    links of `topbar_links` this account may see (`{"title", "href"}`), those of `topbar_menu_links` as
    `menu_links` (the account menu, always present, `[]` without an account), its display name, whether *Account*
    and *Admin panel* appear and where they lead, the sign-out address.

    For an application that uses TinySesam as a library but draws its UI elsewhere (a single-page app, a
    template engine of another language): hand it this dict, e.g. for the account behind `Remote-Id` or
    `session_user(request)`. `user`: an account dict (`get_user`, `session_user`) or None; a locked or unknown
    account counts as none (no links, no menu). `base` goes in front of TinySesam's own paths; default: `base_url`
    (empty without one — then the paths are relative to the root, put the mount prefix here). `host` (T-103): the
    application's host the bar is drawn on — its `frame` (layout of `apps[id].layout`, the app frame of
    `forward_apps[host]`); empty = `shell_layout`, no frame."""
    if base is None:
        base = (security.normalize_base(str(self.cfg.base_url or "").strip()) or "").rstrip("/")
    if user is not None:
        uid = user.get("id") if isinstance(user, dict) else _topbar._field(user, "id")
        row = self.store.get_user(uid) if uid is not None else None
        if row is None or row["disabled"]:
            user = None
    return _topbar.data(self, user, base=base, host=host)


def _check_secure_flag(self, request: Request) -> None:
    """`cookie_secure=False` although the browser comes over HTTPS? Say so loudly once (F-04).

    The most common production form is a TLS proxy in front of an app that itself sees only HTTP.
    Whoever leaves `cookie_secure=False` there (because it was needed locally without a certificate)
    sends the session cookie without the Secure flag — and nothing reported it: the
    configuration check deliberately stays silent (`base_url` is no statement about the
    transport), and the panel warns only about missing HTTPS. The request itself knows,
    though: scheme `https` or `X-Forwarded-Proto: https`. Loopback does NOT count here as
    secure (unlike in `_is_secure`) — local without a certificate is exactly the permitted case.
    One line per instance so that the log does not fill up."""
    if self.cfg.cookie_secure or self._secure_flag_reported:
        return
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if request.url.scheme != "https" and proto != "https":
        return
    self._secure_flag_reported = True
    security.seclog.warning(
        "Configuration: cookie_secure=False, but the browser comes in over HTTPS — session and "
        "CSRF cookie go out without the Secure flag and thus also over any plaintext connection "
        "to the same host. Set cookie_secure=True (that is the default).")


def _csp_header(self, nonce: str, prefix: str = "") -> str:
    """The CSP for the own pages. 'strict' = everything same-origin, script/style only via
    nonce (no 'unsafe-inline'); 'off' = no header; otherwise the own string with {nonce}.
    With `csp_report` the strict policy names the own report endpoint (relative to the page, `prefix` = mount)."""
    csp = (self.cfg.csp or "").strip()
    if not csp or csp == "off":
        return ""
    if csp == "strict":
        report = (f"; report-uri {prefix}{self._CSP_REPORT_PATH}; report-to {self._CSP_REPORT_GROUP}"
                  if self._csp_reporting() else "")
        # Background images from https addresses (brand_backgrounds) — exactly their origin, nothing beyond.
        foreign = sorted({"https://" + b[len("https://"):].split("/", 1)[0].split("?", 1)[0]
                        for b in (getattr(self.cfg, "brand_backgrounds", None) or []) if b.startswith("https://")})
        return ("default-src 'self'; "
                f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                f"img-src 'self' data:{''.join(' ' + h for h in foreign)}; base-uri 'none'; "
                f"form-action 'self'{''.join(' ' + h for h in self._form_destinations())}; "
                f"frame-ancestors 'self'; object-src 'none'{report}")
    return csp.replace("{nonce}", nonce)


def _csp_reporting(self) -> bool:
    return bool(getattr(self.cfg, "csp_report", False)) and (self.cfg.csp or "").strip() == "strict"


def _form_destinations(self) -> list:
    """Where a form of the own pages may lead, beyond `'self'` (0.24.13, `form-action`).

    `form-action` does not fall back to `default-src` (DAST 2026-10-11, ZAP 10055-13): without the directive an
    injected `<form action=https://foreign>` may send anywhere. Chrome also checks it on the redirect
    AFTER submitting (Firefox does not) — therefore the targets to which TinySesam itself redirects are listed here:
    the own `base_url` (sign-out on the app host goes to the gateway), the protected hosts from
    `trusted_redirect_hosts` and the client entries (sign-in, "Continue as …", return after sign-out),
    the OIDC provider including its sign-out endpoint (sign-out "everywhere") and the SAML IdP. Only hosts from the own
    configuration, no wildcard; a host without a scheme counts in the CSP for the page with its scheme (and
    http→https)."""
    from urllib.parse import urlsplit

    def host(url):
        try:
            n = urlsplit(url if "://" in url else "https://" + url).netloc
        except ValueError:
            return ""
        return n if n and re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", n) else ""

    c = self.cfg
    urls = [c.base_url or "", c.oidc_issuer or "", getattr(c, "saml_idp_sso_url", "") or ""]
    oidc = getattr(self, "oidc", None)
    meta = getattr(oidc, "_meta", None) if oidc is not None else None
    if isinstance(meta, dict):
        # Only what is already loaded — the head of a response triggers no network access.
        urls.append(str(meta.get("end_session_endpoint") or ""))
    destinations = {host(u) for u in urls if u and "://" in u}
    # Hosts from trusted_redirect_hosts (and the client hosts): `safe_next` compares only the name, any port
    # is allowed. In the CSP a host without a port counts only for the default port — hence `name:*`, otherwise
    # a redirect would get stuck that `next` has just allowed.
    for h in list(c.trusted_redirect_hosts or []) + list(getattr(c, "oidc_clients", None) or {}):
        n = host(str(h)).rsplit("]", 1)
        name = (n[0] + "]") if len(n) == 2 else n[0].split(":", 1)[0]
        if name:
            destinations.add(name + ":*")
    return sorted(z for z in destinations if z)


def _frame(self, request: Optional[Request] = None, ctx: Optional[dict] = None) -> Optional[dict]:
    """Which app frame a built-in page shows (T-91), in this order: `?app=<host>`; the host of an absolute `next` /
    `return_url` (query, then the page's ctx); `app=<host>` inside a relative one (so the reauth page inherits the
    frame of its target); `forward_frame_default`. Only a host of `forward_apps` with a frame counts — an unknown
    one changes nothing (no error, no difference to answer as an oracle), and nothing of the request ever becomes a
    link target."""
    from urllib.parse import parse_qs, urlsplit
    query = request.query_params if request is not None else {}
    ctx = ctx or {}
    frame = self._frame_of(query.get("app"))
    if frame:
        return frame
    targets = [v for v in ([query.get(k) for k in self._FRAME_TARGETS] + [ctx.get(k) for k in self._FRAME_TARGETS])
               if isinstance(v, str) and v and len(v) <= 4096]
    for target in targets:
        if "://" in target:
            try:
                frame = self._frame_of(urlsplit(target).hostname or "")
            except ValueError:
                frame = None
            if frame:
                return frame
    for target in targets:
        if target.startswith("/") and "?" in target:
            try:
                inner = parse_qs(urlsplit(target).query).get("app") or []
            except ValueError:
                inner = []
            frame = self._frame_of(inner[0] if inner else "")
            if frame:
                return frame
    return self._frame_of(getattr(self.cfg, "forward_frame_default", "") or "")


def _frame_of(self, host) -> Optional[dict]:
    """The app frame of a host — `{"host", "name", "home", "links"}` from `forward_apps[host]` — or None when the
    host has no entry with a frame (`home` or `links`) and a name. `home` is absolute on that host (a path in the
    config means a path there); `links` stay as configured, the bar resolves and filters them."""
    if not isinstance(host, str) or not host or len(host) > 253:
        return None
    want = host.strip().lower().rstrip(".")
    for h, e in (self.cfg.forward_apps or {}).items():
        if str(h).strip().lower().rstrip(".") != want or not isinstance(e, dict):
            continue
        name = str(e.get("name") or "").strip()
        if not name or not ({"home", "links"} & set(e)):
            return None
        raw = e.get("home")
        home: str = raw if isinstance(raw, str) and raw else "/"
        return {"host": want, "name": name, "home": _topbar.frame_href(want, home),
                "links": list(e.get("links") or [])}
    return None


def _header_lines(self, resp: Response) -> Response:
    """The hardening headers of every TinySesam response (R8-1, R8-5, R4-08, R5-2).

    Up to 0.19.0 only the rendered page carried a CSP; everything else — admin panel, JSON API,
    redirects with a token in the address — came without any header. `setdefault`, so that a
    route (or an override) that deliberately sets something else wins.

    * `nosniff` — a JSON response with user input in it is never interpreted as HTML.
    * `Referrer-Policy: same-origin` — reset, sign-in and invitation pages carry the token
      in the address; an image or link to the outside would otherwise take it along as `Referer`.
      Deliberately not `no-referrer`: with that the browser sets `Origin: null` on every
      same-origin POST, and an origin check in the proxy in front would reject the login form.
    * `Cache-Control: no-store` + `Vary: Cookie` — the responses depend on the session
      (account, session list, `/auth/me`); a shared cache in front must neither keep them
      nor hand them to the next visitor.
    * `X-Frame-Options: SAMEORIGIN` — only with `csp='strict'`, whose `frame-ancestors 'self'`
      it repeats for older browsers. An own policy or `off` (the proxy sets the
      CSP) itself decides who may embed; a fixed XFO would override that.
    * `Cross-Origin-Opener-Policy: same-origin` (T-52, ASVS 3.4.8) — same condition, HTML only: a page of
      another origin that opened the sign-in in a window (or was opened by it) gets no handle on it
      (`window.opener`, tab-nabbing, cross-window leaks). No built-in flow uses a popup: OIDC, SAML and
      the gate redirect in the same tab, and WebAuthn does not depend on the opener.
    """
    self._header_lines_in(resp.headers)
    return resp


def _header_lines_in(self, h) -> None:
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("Cache-Control", "no-store")
    vary = h.get("vary", "")
    if "cookie" not in [v.strip().lower() for v in vary.split(",")]:
        h["Vary"] = f"{vary}, Cookie" if vary.strip() else "Cookie"
    if ((self.cfg.csp or "").strip() == "strict"
            and h.get("content-type", "").startswith("text/html")):
        h.setdefault("X-Frame-Options", "SAMEORIGIN")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")


def _prefix(self, request: Optional[Request]) -> str:
    """The prefix under which TinySesam's pages lie in the browser, without a trailing slash.

    One source for all built-in pages and redirects (T-15): under `uvicorn --root-path
    /sso` behind a proxy that strips `/sso`, or as `Mount("/sso", app)`, they pointed
    until then out of the mount (`/auth/login` instead of `/sso/auth/login` → 404).

    **First the path of `base_url`** — it is TinySesam's public address and carries
    the prefix according to the docs anyway. Only so is the prefix right where the running request
    does not know it: in a guard of the host app outside the TinySesam mount (`root_path`
    is empty there) and behind a proxy that strips without `--root-path` (counter-check).
    Without `base_url` the request's `root_path`. A value of unexpected shape is not
    used (loudly, once) — better a 404 than a prefix that carries markup into a page."""
    if self.cfg.base_url:
        from urllib.parse import urlsplit
        raw = urlsplit(self.cfg.base_url).path.rstrip("/")
    elif request is None:
        return ""
    else:
        raw = str(request.scope.get("root_path") or "").rstrip("/")
    if not raw:
        return ""
    if not self._PREFIX_FORM.fullmatch(raw):
        if security.report_once("prefix_form"):
            security.seclog.warning("root_path %s has an unexpected form and is not used for pages and "
                                    "redirects (allowed: /part/part of A–Z a–z 0–9 . _ ~ -).",
                                    security.for_log(raw))
        return ""
    return raw


def _set_csp(self, resp: Response, nonce: str, prefix: str = "") -> None:
    """CSP of a built-in page — and with `csp_report` the `Reporting-Endpoints` header it points to."""
    policy = self._csp_header(nonce, prefix)
    if not policy:
        return
    resp.headers.setdefault("Content-Security-Policy", policy)
    if self._csp_reporting():
        resp.headers.setdefault("Reporting-Endpoints",
                                f'{self._CSP_REPORT_GROUP}="{prefix}{self._CSP_REPORT_PATH}"')


def browser_path(self, request: Optional[Request], path: str) -> str:
    """Convert an app path (`/auth/login`, `login_path`, `admin_path`, …) into the path
    the browser needs — with the mount prefix in front (T-15).

    Only for paths meant relative to the app. A `next` target is already a path of the
    browser (it comes from `request.url.path`, and the prefix is already there) and gets
    no second one. Absolute URLs and protocol-relative values remain as they are."""
    p = str(path or "")
    if not p.startswith("/") or p.startswith("//"):
        return p
    return self._prefix(request) + p


def safe_next(self, next_: str, request: Optional[Request] = None) -> str:
    """Secure the ?next= target against open redirect (only relative paths resp. trusted_redirect_hosts).

    With `request` the fallback `login_redirect` gets the mount prefix (T-15); the
    passed target itself remains as it is — it is already a path of the browser.

    The host of the own `base_url` always counts: a redirect to the own public
    address is by definition not an open redirect. Otherwise, with forward auth on
    ONE host (app and TinySesam under the same name), one would have to repeat the own host in
    `trusted_redirect_hosts` — if one forgets, the absolute `next=` is
    silently discarded and one lands on `login_redirect` after the login.
    """
    # By host name: `safe_next` compares the name, any port is allowed (as the CSP's `name:*`). An entry written
    # with a port (`app.example.com:8443`) never matched before and silently dropped every `next=` to it.
    hosts = [n for n in (security.host_name(h) for h in (self.cfg.trusted_redirect_hosts or [])) if n]
    if self.cfg.base_url:
        own = security.host_name(self.cfg.base_url)
        if own and own not in hosts:
            hosts.append(own)
    fallback = self.browser_path(request, self.cfg.login_redirect)
    if _PREFIX_PLACEHOLDER in str(next_ or ""):
        # The placeholder of the built-in pages has no business in a target: on replacing,
        # `/__TS_P__/evil.example` would become `//evil.example` (counter-check T-15).
        return fallback
    return security.safe_next(next_, fallback, hosts or None)

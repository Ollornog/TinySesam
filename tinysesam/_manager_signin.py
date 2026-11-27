"""The building block `signin` of `TinySesam`: sessions, signing in and step-up for own pages, step-up freshness.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import json
from . import security
from .errors import ConfigError
from .login_result import LoginResult
from .password_change_result import PasswordChangeResult
from fastapi import HTTPException
from fastapi import Request
from typing import NoReturn
from typing import Optional
from . import manager as _manager
from typing import TYPE_CHECKING

if TYPE_CHECKING:     # `self` typed where the checker must narrow after the raising helpers
    from .manager import TinySesam
from .manager import (
    _FRESH_MAX,
)


# ---------- Sessions ----------
def _ttl(self, remember: bool = True) -> int:
    """Server session lifetime. remember=False → short transient TTL (session cookie)."""
    hours = self.cfg.session_ttl_hours if remember else self.cfg.session_ttl_transient_hours
    return hours * 3600


def start_session(self, user_id, method, ip=None, ua=None, remember: bool = True) -> tuple[str, bool]:
    """New session with the first factor. Returns (token, session_ok). session_ok=False → further steps needed."""
    done = [method]
    mfa_ok = self._session_ok(user_id, done)
    token = self._create_session(user_id, self._ttl(remember), mfa_ok, method, ip, ua, remember,
                                  factors=done)
    if mfa_ok:   # full login completed → audit
        self._sign_in_complete(user_id, ip, method)
        self._note_login(user_id)
        self._lift_after_sign_in(user_id, ip)
    return token, mfa_ok


def _create_session(self, user_id, ttl, mfa_ok, method, ip=None, ua=None, remember=True,
                     factors=None) -> str:
    """THE place where a session row comes into being — and the full one is noted.

    A session that comes into being here already fully valid is a sign-in: first factor without
    chain, the last step of a chain (`apply_factor`, `complete_totp`), an
    identity switch. Setting its cookie (`set_cookie()`) then rotates the CSRF token
    in the same response (0.20.1) — no matter which route the sign-in came through, including an
    own one of the app (`start_session` + `set_cookie`). A step-up creates no row
    (`store.rotate_session`) and therefore rotates nothing. A guard in `tests/test_csrf.py`
    (E3) ensures that `store.create_session` is called only here."""
    token = self.store.create_session(user_id, ttl, mfa_ok, method, ip, ua, remember,
                                      factors=factors)
    if mfa_ok:
        self._reserve_sign_in(token)
    return token


def _reserve_sign_in(self, token: str) -> None:
    h = self.store.session_hash(token)
    with self._fresh_lock:
        self._fresh_sign_ins[h] = None
        while len(self._fresh_sign_ins) > _FRESH_MAX:
            self._fresh_sign_ins.popitem(last=False)


def _redeem_sign_in(self, token) -> bool:
    """Was this token a sign-in just now? Once yes, afterwards no."""
    if not token:
        return False
    h = self.store.session_hash(token)
    with self._fresh_lock:
        if h in self._fresh_sign_ins:
            del self._fresh_sign_ins[h]
            return True
    return False


def _note_login(self, user_id: int) -> None:
    """Record a complete login: `last_login_at` every time (schema 23, read by the account API), and the FIRST
    one (R3-1).

    The self-enrollment in the default operating mode hangs on this: an account may set up the factor required
    by the chain itself as long as it has never been used. The note
    closes this window — at the FIRST complete login, no matter by which
    route it came about. An open setup window is closed in the process: it was meant for
    exactly this one process."""
    if not self.store.mark_login(user_id, _manager._now()):
        return
    u = self.store.get_user(user_id)
    try:
        unclosed = u["mfa_enroll_until"] if u else None
    except (IndexError, KeyError):
        unclosed = None
    if unclosed:
        self.store.set_mfa_enroll_until(user_id, None)


def apply_factor(self, request, user_id, factor, ip=None, ua=None, remember=True,
                 email_verified: Optional[bool] = None) -> tuple[str, bool, bool]:
    """Apply a confirmed factor: attach to the running session of the same user
    (chain step) OR start a new session (first factor/identity switch).
    Returns (token, session_ok, is_new). With is_new the caller must call set_cookie(resp, token).

    `email_verified` passes a federated route through (OIDC: claim `email_verified`;
    SAML and LDAP know no evidence and pass `False` through) — this is where
    the first admin is decided, and an unverified address must not carry it. The factor goes
    along to `_maybe_promote_admin`: for a federated factor it applies fail-closed there,
    a forgotten argument therefore does not promote.

    A locked account never gets a session here (403) — no matter which route verified
    the factor. Every sign-in route ends in this method; the check in the individual
    routes remains, but the class no longer depends on every new route knowing it
    (H-18: sign-in link and passkey created a session for a locked account, which only
    `current_user()` discarded again)."""
    account = self.store.get_user(user_id)
    if not account or account["disabled"]:
        self.audit("login_disabled", str(account["username"]) if account else None, ip, factor)
        raise HTTPException(403, self.t("api.account_disabled"))
    s = self._session_from_request(request)
    if s and s["user_id"] == user_id:
        # same identity → attach the factor to the running session (chain/route step).
        # An identity switch (another user) falls through → new session.
        done = json.loads(s["factors_done"] or "[]")
        was_ok = bool(s["mfa_ok"])
        if was_ok and not self._counts_as_stepup(account, factor):
            # Attack round B, F3: a full session is refreshed only by a factor that the step-up itself accepts.
            # A sign-in link (mailed, admin-issued, cross-device approval) proves the mailbox or another
            # device, not the account's own confirmation — redeemed in a browser with a stale (stolen)
            # session cookie it made that session fresh, and `_require_fresh` let a new passkey or API key
            # through. The session stays as it is: full, but not fresh.
            self.audit("stepup_not_counted", str(account["username"]), ip, f"factor={factor}")
            return request.cookies.get(self.session_cookie_name), True, False
        in_setup = self._setup_session(s)
        if factor not in done:
            done.append(factor)
        ok = self._session_ok(user_id, done, setup=in_setup)
        self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
        self._maybe_promote_admin(self.store.get_user(user_id), email_verified,
                                  factor=factor)
        if ok and not was_ok:
            self._sign_in_complete(user_id, s["ip"], factor)
            self._note_login(user_id)
            self._lift_after_sign_in(user_id, s["ip"])
            # **New token on privilege change.** Here the session turns from a half login
            # into a fully valid one — OWASP Session Management Cheat Sheet: "The session ID must
            # be renewed or regenerated by the web application after any privilege level
            # change." Before, it kept its token: whoever could set a cookie on the victim before the login
            # (subdomain, plaintext HTTP) held a fully authenticated session
            # after the victim's second factor.
            new_token = self._create_session(
                user_id, self._ttl(bool(s["remember"])), True, s["method"],
                s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
            self._successor(s, new_token)
            if in_setup:
                self._setup_finished(s, done)
            self.store.delete_session_by_handle(s["token_hash"])
            self._other_after_completion(s, new_token)
            return new_token, ok, True      # is_new → the caller sets the cookie anew
        if ok and was_ok:
            # The session was already fully valid, the factor only refreshes it — that is a
            # step-up (mfa_at has just been set anew). That one also gets a new token
            # (F-06, ASVS 5.0 7.2.4); lifetime and sign-in time remain.
            turned = self.store.rotate_session(s["token_hash"], self._mercy())
            if turned:
                return turned, ok, True
        # The plaintext token from the cookie is returned — the caller builds
        # redirects and cookies from it. The session row holds only the handle.
        return request.cookies.get(self.session_cookie_name), ok, False
    token, ok = self.start_session(user_id, factor, ip, ua, remember)
    self._maybe_promote_admin(self.store.get_user(user_id), email_verified, factor=factor)
    return token, ok, True


def _counts_as_stepup(self, account, factor: str) -> bool:
    """Does `factor`, provided on a session that is already full, count as a fresh confirmation (step-up)?

    Yes for what `stepup_options()` offers this account (password, PIN, TOTP — narrowed by `stepup_methods`,
    so a password typed into the sign-in form does not get round `stepup_methods=["totp"]` either) and for the
    factors that sign the account in on their own (`_STEPUP_SIGN_INS`). Never for `magic`: a sign-in link does
    not even sign in an account with a second factor."""
    if factor == "magic":
        return False
    if factor in self._STEPUP_SIGN_INS:
        return True
    return factor in self.stepup_options(dict(account))


def _successor(self, old_line, new_token) -> None:
    """What hangs on the half session passes to the full one that replaces it — BEFORE
    deleting the old one: the OIDC rows (4a, otherwise the foreign key would take them along) and the
    explicit choice "stay signed in" (F-05).

    `old_line` is a whole row from `get_session` (`SELECT *`); the column has always existed since
    the migration to schema 11. If it is missing after all, that should fail loudly — a
    silent skip would lose the choice and with it the long idle period, without anyone
    noticing."""
    new = self.store.session_hash(new_token)
    self.store.move_oidc_session(old_line["token_hash"], new)
    if old_line["stay_chosen"]:
        self.store.set_session_stay(new)


def _other_after_completion(self, old_line, new_token) -> None:
    """If the half session recorded that the remaining ones are to be ended (limit d), then now — with
    the full session that has just come into being as the only one that stays.

    Occasion: the mandatory setup of TOTP in the middle of a chain (`password → totp → pin`)
    ends with a HALF session, and a half one must not end the remaining ones. The offer
    under ASVS 7.4.3 was previously omitted there entirely. Now the page asks as usual, and the
    consent is redeemed here as soon as the sign-in is complete. The column has existed
    since schema 11 (as with `_successor`: if missing, it fails loudly)."""
    if not old_line["end_others"]:
        return
    self.store.delete_user_sessions_except(old_line["user_id"], self.store.session_hash(new_token))
    u = self.store.get_user(old_line["user_id"])
    self.store.audit_log("sessions_revoke", u["username"] if u else None, old_line["ip"],
                         "scope=others after_enrollment=1")


def _login_redirect_after(self, request, token, user_id, nxt):
    """Target redirect after a factor: nxt if the session is complete, otherwise the input page of the next factor."""
    return self._after_the_factor(request, token, user_id, nxt)[0]


def _after_the_factor(self, request, token, user_id, nxt) -> tuple:
    """(onward, next, done) after a provided factor — the one source for the
    redirect of every sign-in route and for `LoginResult.next_url`/`next_factor`/`done`."""
    s = self.store.get_session(token)
    done = json.loads(s["factors_done"] or "[]") if s else []
    if s and s["mfa_ok"]:
        # Whoever explicitly signs in (again) wants to go to the application it returns to —
        # an earlier sign-out "here only" (T-22) no longer applies to that.
        if "://" in str(nxt or ""):
            from urllib.parse import urlsplit
            destination = (urlsplit(str(nxt)).hostname or "").lower()
            if destination:
                self.store.gate_resume(s["token_hash"], destination)
        return nxt, None, True
    step = self._next_login_step(user_id, done, setup=self._setup_session(s))
    return (self.browser_path(request, self._factor_entry(step, nxt)) if step else nxt), step, False


def complete_totp(self, token) -> Optional[str]:
    """Complete the TOTP step: attach factor `totp` to the running session. Returns a
    new session token that belongs in the cookie (`new = auth.complete_totp(token)`,
    `if new: auth.set_cookie(resp, new)`) — the old one is dead afterwards, also in a step-up.

    A new token is issued if the session thereby becomes fully valid or, already fully valid,
    is freshly confirmed (step-up, F-06). Otherwise `None` (nothing to do). Since F-06 this applies
    to the step-up as well: an own UI that ignores the return value there keeps
    a dead session in the cookie afterwards. At login (half → full) this was always so.

    Called this since 0.18.0 because the old name `complete_mfa` promised more than the method
    does — MFA is the whole chain, here it is about exactly one factor. `complete_mfa` remains
    as an alias and is not removed; a rename that breaks existing calls
    would not be worth the gain.
    """
    s = self.store.get_session(token)
    if not s:
        return None
    account = self.store.get_user(s["user_id"])
    if not account or account["disabled"]:
        # Locked between the first factor and TOTP: the half session ends here instead of
        # becoming a fully valid one (H-18, the same rule as in `apply_factor`).
        self.store.delete_session_by_handle(s["token_hash"])
        return None
    was_ok = bool(s["mfa_ok"])
    if was_ok and not self._counts_as_stepup(account, "totp"):
        # The same rule as in `apply_factor` (F3): a full session is refreshed only by what the step-up accepts
        # — here when `stepup_methods`/`stepup_strict` leave TOTP out.
        return None
    in_setup = self._setup_session(s)
    done = json.loads(s["factors_done"] or "[]")
    if "totp" not in done:
        done.append("totp")
    ok = self._session_ok(s["user_id"], done, setup=in_setup)
    self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
    if ok:
        self._sign_in_complete(s["user_id"], s["ip"], "totp")
    if ok and not was_ok:
        # The first complete sign-in closes the self-setup window (R3-1) — on this path, too.
        # Up to T-34 only `start_session` and `apply_factor` noted it: an account whose chain
        # ended with the TOTP step (mandatory setup, or the setup pass) stayed "never signed in",
        # and `mfa_enrollment="first_login"` and `magiclink_first_login_only` kept treating it so.
        self._note_login(s["user_id"])
        self._lift_after_sign_in(s["user_id"], s["ip"])
        # Privilege change → new token (OWASP Session Management). Returns it so that the
        # caller can set the cookie — the old token belongs to a deleted row.
        new_token = self._create_session(
            s["user_id"], self._ttl(bool(s["remember"])), True, s["method"],
            s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
        self._successor(s, new_token)
        if in_setup:
            self._setup_finished(s, done)
        self.store.delete_session_by_handle(s["token_hash"])
        self._other_after_completion(s, new_token)
        return new_token
    if ok and was_ok:
        # The session was already fully valid; `set_session_factors` has just set `mfa_at` anew
        # — that is a step-up, and it rotates the token like `/auth/reauth` and
        # `apply_factor` (F-06, ASVS 5.0 7.2.4). Before, it stayed: a cookie that was read along
        # thus got fresh sudo rights. Lifetime and sign-in time remain.
        return self.store.rotate_session(s["token_hash"], self._mercy())
    return None


def _stay_chosen(self, remember: Optional[bool]) -> bool:
    """Is "stay signed in" chosen? Without a tick in the form (`remember_me_enabled=False`) every
    session counts as persistent, as before; otherwise only an explicit True (F-05)."""
    return True if not self.cfg.remember_me_enabled else remember is True


def _sign_in_no(self, reason: str, status: int, text: str, further: str,
                    next_one: Optional[str] = None) -> LoginResult:
    """A failure: no session, no cookie — only reason, status and text."""
    return LoginResult(ok=False, reason=reason, status=status, message=self.t(text) if text else "",
                       next_url=further, next_factor=next_one)


def _sign_in_locked(self, identifier: str, further: str, next_one: Optional[str] = None,
                        text: str = "err.locked", reason: str = "locked") -> LoginResult:
    """The pre-booking was rejected. A streak lock (B2-6) does not expire —
    "temporary" would be a lie, and the user needs the way out. The message reveals
    nothing about the existence of the account: counting is per identifier, whether it exists or not.
    A deferral (G9) gets the same 429 and the same reason as a lock — otherwise
    the response would reveal that someone else is currently signing in under this identifier or address."""
    if self._series_full(identifier):
        return self._sign_in_no("locked_series", 429, "err.locked_series", further, next_one)
    return self._sign_in_no(reason, 429, text, further, next_one)


def _signed_in(self, request, token, new: bool, user_id: int, nxt: str) -> LoginResult:
    """A success: target and open factor from the same source as every redirect."""
    further, next_one, done = self._after_the_factor(request, token, user_id, nxt)
    return LoginResult._with_session(self, token if new else None, ok=True, reason="ok",
                                     status=303, next_url=further, next_factor=next_one,
                                     done=done, user=self.get_user(user_id))


def login_password(self, request: Request, username: str, password: str, *, next: str = "",
                   remember: Optional[bool] = None, csrf: Optional[str] = None) -> LoginResult:
    """Sign in with identifier and password — throttled, counted and locked like `POST /auth/login`, which calls exactly this method.

    The building block for an own login route (SPA, JSON, other fields). It checks the
    CSRF token (`csrf`, otherwise header `X-CSRF-Token`), throttles per IP, pre-books the attempt atomically
    (failed attempts per identifier, IP and pair, streak), asks with `ldap_enabled` the
    directory as a fallback (one identifier, one account; an outage is not a failed attempt),
    writes audit and security log (the lines for fail2ban) and creates the session —
    or attaches the factor to the running one. A `LoginResult` comes back:

        result = auth.login_password(request, username, password, next=next, csrf=csrf)
        if not result:
            return my_form(error=result.message, status=result.status)
        return result.redirect()     # to the open factor (result.next_factor) or to next

    `remember=True` is the ticked "stay signed in" box. Raises only what the route
    raises too: `HTTPException(403)` for a wrong CSRF token (and from `apply_factor` for an
    account that has just been locked) as well as the unexpected — the attempt then counts as a
    failed attempt. Synchronous: call from a `def` route (FastAPI uses the thread pool for it),
    in an `async def` route via `run_in_threadpool`."""
    cfg = self.cfg
    self.require_csrf(request, self._csrf_sent_along(request, csrf))
    nxt = self.safe_next(next, request)
    if not cfg.password_enabled:
        return self._sign_in_no("method_disabled", 404, "api.password_off", nxt)
    if not username or not password:
        return self._sign_in_no("missing", 400, "err.required", nxt)
    stay = self._stay_chosen(remember)
    ip = self.client_ip(request)
    if not self._rate_ok(ip):
        return self._sign_in_no("ratelimit", 429, "err.rate", nxt)
    # Check and book in ONE step (R7-2): with `_is_locked()` beforehand and
    # `_record_login()` afterwards the whole password check lay in between, and a parallel
    # burst read "not yet locked" N times. From here on the attempt already stands as a
    # failed attempt in the table; `_record_login(..., attempt=…)` turns it into a success.
    # With LDAP it stays pending until the directory has answered (G9): on an outage it is
    # taken back (F-23), and until then it must lock nobody, only make them wait.
    attempt = self._begin_attempt(username, ip, "password", as_pending=cfg.ldap_enabled)
    if attempt is None:
        return self._sign_in_locked(username, nxt)
    # The unexpected (programming error in the client, database gone, an HTTPException from the
    # check) turns the attempt into a failed attempt immediately — stricter in doubt, as before.
    # Without that it would stay pending for `Store.PREBOOKING_PENDING_SEC` and make sign-ins
    # from the same address wait (G9). From `_record_login` on it is closed.
    try:
        u = self._check_password(username, password)
        from_directory = False
        if not u and cfg.ldap_enabled:
            from .ldap_ import DirectoryNotReachable
            try:
                u = self._check_ldap(username, password)   # LDAP/lldap backend (factor 'password')
            except DirectoryNotReachable as e:
                # An outage is not a failed attempt (F-23): book nothing against account or IP
                # and no `failed login` in the security log — otherwise a few minutes of
                # directory outage would lock the users out, and fail2ban would ban them on top. The
                # response is the same 503 for every account, so it reveals nothing about its
                # existence (local wrong password and unknown name both end up here).
                self.audit("ldap_unavailable", username, ip, security.for_log(str(e))[:300])
                security.seclog.error("LDAP unreachable user=%s ip=%s reason=%s",
                                      security.for_log(username), security.for_log(ip),
                                      security.for_log(str(e)))
                # …but only the DIRECTORY's share is excused (A-1). If the account has
                # a local password and it was wrong, that is a failed attempt as always —
                # otherwise every outage would be a rate pause without account lock against precisely the
                # emergency account (local admin) that one needs at that moment; spread over many
                # IPs, only the IP rate limit would still apply. The response stays 503. A local account
                # WITH a password can thus be recognised during an outage by the later 429 —
                # the same lock that also hits it in normal operation; that is the smaller price.
                # The attempt has stood in the table since `_begin_attempt` (R7-2), as a
                # pending pre-booking (G9) — without a local password it is therefore
                # taken back, not merely not booked additionally. Until then it lets
                # sign-ins that would fail because of it wait instead of locking them; so that
                # this does not take until the timeout on every attempt, `_check_ldap` does not ask at all for
                # a pause after an outage (`ldap_.FailureMarker`) and
                # raises immediately.
                local = self.find_user(username)
                if local and self.store.get_password_hash(local["id"]):
                    self._record_login(username, ip, False, "password", attempt=attempt, source="local")
                else:
                    self._revert_attempt(attempt)
                return self._sign_in_no("directory_down", 503, "err.directory_down", nxt)
            from_directory = u is not None
    except BaseException:
        self._attempt_failed(attempt)
        raise
    # The same wrong password once more (0.24.9): no new failed attempt — neither in the window nor in the streak,
    # and no `failed login` for fail2ban. The response is the same 401 as for every failed attempt.
    if not u and self._password_repeated(username, ip, password):
        self._revert_attempt(attempt)
        # In the audit a `login_fail` like any other (account page and panel show it the same, no oracle), only the
        # reason says "repeated".
        self.store.audit_log("login_fail", username, ip, "password reason=repeated")
        security.seclog.info("%s user=%s ip=%s method=password", security.LOG_REPEATED,
                             security.for_log(username), security.for_log(ip))
        return self._sign_in_no("invalid", 401, "err.credentials", nxt)
    # Which route decided is recorded in the audit log (F-29): before, a
    # directory sign-in could not be told apart from a local one — both wrote
    # factor `password`, and on a failed attempt it said `reason=no_account`, although the
    # directory had been asked and had refused.
    # From the directory: pass along the account to which the identifier was resolved (G5-N1) —
    # a filter via `mail` also matches an identifier that locally belongs to ANOTHER account.
    # `_check_ldap` has rejected this case since 2026-09-27 (one identifier, one account); the
    # guard in `_cleanup_limit` remains the second safeguard.
    self._record_login(username, ip, bool(u), "password", attempt=attempt,
                       source=("" if not cfg.ldap_enabled else "ldap" if from_directory
                               else "local" if u else "local+ldap"),
                       account=u["id"] if from_directory and u else None)
    if not u:
        return self._sign_in_no("invalid", 401, "err.credentials", nxt)
    # If the account came from the directory, the email is an LDAP attribute — in many
    # directories maintained by whoever it belongs to, and confirmed by nobody. If the
    # operator trusts the directory (`ldap_email_trusted`) or names an evidence attribute
    # (`ldap_attr_email_verified`), the evidence on the account decides (None) — `_check_ldap`
    # sets it only if the source is trusted; otherwise "no
    # evidence" explicitly travels along here: an allowlist ADDRESS must not lead to first admin via LDAP (F-14).
    # The route cannot be recognised from the factor name — LDAP deliberately counts as `password`.
    token, _ok, new = self.apply_factor(request, u["id"], "password", ip,
                                        request.headers.get("user-agent"), stay,
                                        email_verified=(None if (cfg.ldap_email_trusted
                                                                   or security.proof_attribute(cfg, "ldap"))
                                                          else False)
                                        if from_directory else None)
    if cfg.remember_me_enabled and stay:
        self.store.set_session_stay(self.store.session_hash(token))     # F-05: explicitly chosen
    return self._signed_in(request, token, new, u["id"], nxt)


def login_pin(self, request: Request, pin: str, username: str = "", *, next: str = "",
              remember: Optional[bool] = None, csrf: Optional[str] = None) -> LoginResult:
    """Sign in with the personal PIN or provide the PIN step — throttled and locked like `POST /auth/pin`, which calls exactly this method.

    Three situations, like the route: on a full session (PIN as the factor of a route) and in the
    chain step after the first factor (`login_chain` with `pin`) the PIN belongs to the account of the
    session, `username` stays empty — wrong guesses there are booked under a dedicated streak kind
    that a self-service reset does not clear (G7). Without a session the PIN is a first factor
    with `username`, only with `pin_login` (`TinySesamConfig.pin_as_first_factor()`), otherwise
    `reason="method_disabled"` (404). A four-digit PIN is the most grateful target of a
    burst: login and PIN buckets are pre-booked in one step (R3-7). Result, CSRF,
    `remember` and exceptions as with `login_password`; `result.next_factor == "pin"` after a
    failure means: the same PIN page once more, without a name field."""
    cfg = self.cfg
    self.require_csrf(request, self._csrf_sent_along(request, csrf))
    nxt = self.safe_next(next, request)
    stay = self._stay_chosen(remember)
    ip = self.client_ip(request)
    # Already signed in → the PIN belongs to the running session, no user field needed.
    # "Signed in" here means: a full SESSION (0.20.1, `session_user`). With
    # `current_user()` a pure API-key request counted as signed in — the bolt
    # `pin_login=False` below did not apply, the PIN of the key's account was checked, and
    # `apply_factor` created a new, full session for lack of one: machine key + PIN
    # yielded an interactive session including the admin flag, which the key alone never carries.
    # A key arrives here only as a guest, and for that `pin_as_first_factor()` applies.
    me = self.session_user(request)
    # The chain step: first factor provided, the session is still pending (`pending_user`,
    # like `/auth/totp`). Until 2026-09-26 it went through the guest route — with `pin_login=False`
    # a chain `password → pin` was therefore a dead end (404), and its wrong guesses
    # booked like those of a first factor, which a self-service reset clears (G7).
    # If the form names ANOTHER account, it remains an identity switch via the
    # guest route; own PIN pages that send the name along remain in the chain step.
    # The half session counts only if the PIN is now its chain step (p2 F1): otherwise it
    # would check PINs in classic mode (oracle with only the password) or before the TOTP
    # of a strict chain, whose order could then never be fulfilled.
    half = None if me else self._pin_chain_step(request)
    if half and username:
        meant = self.find_user(username)
        if not meant or meant["id"] != half["id"]:
            half = None
    sequence = me or half      # the PIN comes AFTER an already provided factor
    unclosed = "pin" if sequence else None
    if not cfg.pin_enabled or (not sequence and not cfg.pin_as_first_factor()):
        # PIN is not a first factor — switched off or, in a strict chain behind
        # another factor, never fulfillable (G7: otherwise an oracle without a password).
        return self._sign_in_no("method_disabled", 404, "api.not_found", nxt)
    if not pin or (not sequence and not username):
        return self._sign_in_no("missing", 400, "err.required", nxt, unclosed)
    if not self._rate_ok(ip):
        return self._sign_in_no("ratelimit", 429, "err.rate", nxt, unclosed)
    ident = sequence["username"] if sequence else username
    if not ident:
        return self._sign_in_no("invalid", 401, "err.credentials", nxt, unclosed)
    # Login and PIN buckets in one atomic step (R3-7): a four-digit PIN
    # is the most grateful target of a parallel burst. Behind a provided factor
    # the streak books under its own kind: these wrong guesses arise only for whoever has the first
    # factor, and a self-service reset does not clear them (like TOTP, G7).
    attempt = self._begin_attempt(ident, ip, "pin",
                                     series_kind=self._PIN_CHAIN_SERIES if sequence else None)
    if attempt is None:
        return self._sign_in_locked(ident, nxt, unclosed)
    try:
        if sequence:
            u = self.get_user(sequence["id"]) if self._verify_user_pin(sequence["id"], pin) else None
        else:
            u = self._check_pin(ident, pin)
    except BaseException:
        self._attempt_failed(attempt)       # the unexpected counts immediately (as with the password)
        raise
    self._record_login(ident, ip, bool(u), "pin", attempt=attempt)
    if not u:
        return self._sign_in_no("invalid", 401, "err.credentials", nxt, unclosed)
    token, _ok, new = self.apply_factor(request, u["id"], "pin", ip,
                                        request.headers.get("user-agent"), stay)
    if cfg.remember_me_enabled and stay:
        self.store.set_session_stay(self.store.session_hash(token))  # F-05: explicitly chosen
    return self._signed_in(request, token, new, u["id"], nxt)


def login_totp(self, request: Request, code: str, *, next: str = "",
               csrf: Optional[str] = None) -> LoginResult:
    """Provide the TOTP step — with a TOTP code or a one-time code, throttled and locked like `POST /auth/totp`, which calls exactly this method.

    For the half session after the first factor (`result.next_factor == "totp"`
    of a previous `LoginResult`) and as a step-up of a full one — the step-up takes a TOTP code only, never a
    one-time recovery code (the same rule as `confirm_totp`; a recovery code is the way in when the
    authenticator is gone, not a confirmation). Both come from the cookie
    (`pending_user`/`session_user`, never from an API key); without a session the result is
    `reason="no_session"` with the login page as `next_url`. If the session thereby becomes full
    or freshly confirmed, it gets a new token — `redirect()`/`set_cookie()`
    set it; whoever ignores it has a dead session in the cookie. Result, CSRF and
    exceptions as with `login_password`."""
    cfg = self.cfg
    self.require_csrf(request, self._csrf_sent_along(request, csrf))
    nxt = self.safe_next(next, request)
    s = self._session_from_request(request)
    # The code of the account is checked whose session then proceeds — both from the
    # cookie (0.20.1, `session_user`). `current_user()` fell back to an API key here
    # if the session's account was locked; then the key account's code would have counted.
    pu = self.pending_user(request) or self.session_user(request)
    unclosed = "totp" if s and pu else None
    if not code:
        return self._sign_in_no("missing", 400, "err.required", nxt, unclosed)
    if not s or not pu:
        return self._sign_in_no("no_session", 401, "api.not_signed_in",
                                    self.browser_path(request, cfg.login_path))
    ip = self.client_ip(request)
    # Atomic as at login (R3-2): otherwise the check lies between lock and counting.
    throttle_ok = self._rate_ok(ip)
    attempt = self._begin_attempt(pu["username"], ip, "totp") if throttle_ok else None
    if attempt is None:
        return self._sign_in_locked(pu["username"], nxt, unclosed, text="err.retry",
                                        reason="locked" if throttle_ok else "ratelimit")
    # A one-time recovery code is the emergency way IN — for the half session whose authenticator is gone. On a
    # session that is already full it would be a step-up, and the confirmation page (`confirm_totp`) never took
    # one: a code from the drawer next to a stolen session cookie made that session fresh for new access. So on a
    # full session only a TOTP code counts — unless `stepup_options()` names recovery codes on purpose. The code
    # is then not even looked at, so it is not used up either.
    full = bool(s["mfa_ok"])
    recovery_ok = not full or "recovery" in self.stepup_options(pu)
    try:
        # accept a TOTP code OR (see above) a one-time recovery code
        correct = (self._verify_totp(pu["id"], code)
                   or (recovery_ok and self._verify_recovery_code(pu["id"], code)))
    except BaseException:
        self._attempt_failed(attempt)       # the unexpected counts immediately (as with the password)
        raise
    if not correct:
        self._record_login(pu["username"], ip, False, "totp", attempt=attempt)
        return self._sign_in_no("invalid", 401, "err.code", nxt, unclosed)
    self._record_login(pu["username"], ip, True, "totp", attempt=attempt)
    session_token = request.cookies.get(self.session_cookie_name)   # plaintext only here, in the cookie
    # If the session becomes fully valid through this factor, it gets a new token — the
    # privilege change. Likewise in a step-up on an already full session (F-06). In both
    # cases the cookie has to come along; if the session becomes full here (login), `set_cookie` also
    # rotates the CSRF token, in a step-up it does not — it would only invalidate the forms of the
    # other open tabs.
    renewed = self.complete_totp(session_token)
    return self._signed_in(request, renewed or session_token, bool(renewed), pu["id"], nxt)


def _only_with_session(self, request, purpose: str) -> tuple:
    """(account of the full session, None) — or (None, (status, text key)) for `no_session`.

    The account comes from `session_user()`, never from an API key (0.20.1): `/auth/reauth`
    until then checked the factor of the account from `current_user()` and afterwards refreshed the
    session from the cookie — with a HALF session `current_user()` fell back to the key,
    and machine key plus password replaced the second factor. For the password change
    (since 0.22.0): a machine key does not change a human's password, and without an own
    session the change ended ALL sessions of the account."""
    u = self.session_user(request)
    if u is not None:
        return u, None
    if self.cfg.apikey_enabled and self._extract_api_key(request):
        return None, (403, self._WITHOUT_SESSION_KEY[purpose])
    return None, (401, "api.not_signed_in")


def _stepup_secret(self, request: Request, u: dict, procedure: str, secret, nxt: str) -> Optional[LoginResult]:
    """Check a step-up secret (password, PIN, TOTP) of the session's account `u` — offered methods only, throttled,
    pre-booked in the own `reauth` bucket, logged for fail2ban. None when it is right, otherwise the refusal.

    The one checker of `_confirm` (the reauth page, `confirm_*`) and of the approvals' per-approval step-up
    (`tinysesam.approvals`): an approval confirms with exactly the same lock, counter and log lines as the reauth
    page, but changes nothing about the session — its confirmation belongs to the one action."""
    methods = self.stepup_options(u)
    if not methods:
        # This account has no method with which it could confirm here
        # (`stepup_strict`, or no factor set up at all yet). The attempt CANNOT
        # succeed — it is therefore not logged as a failed attempt, otherwise the
        # hopeless page feeds the lock of the same account.
        return self._sign_in_no("method_disabled", 403, "err.stepup_none", nxt)
    if not secret:
        # Empty is not a guess (0.22.0): until then a form submitted empty at
        # `/auth/reauth` counted as a failed attempt — as at login, `missing` now applies, without booking.
        return self._sign_in_no("missing", 400, "err.required", nxt)
    if procedure not in methods:
        # Only an offered method counts (`stepup_options`: `stepup_methods`,
        # `stepup_strict`). Otherwise an own page with a password field would bypass the default
        # `stepup_methods=["totp"]`. Nothing is checked here — so nothing is counted either.
        return self._sign_in_no("method_disabled", 403, "err.reauth", nxt)
    ip = self.client_ip(request)
    # Own bucket (`_is_reauth_locked`), not that of the login: a step-up confirmation
    # is not a sign-in — whoever is here is already signed in. With the shared
    # counter, five typos on this page locked the **sign-in** of the same
    # account for `lockout_window_sec`, correct password included. The path
    # remains throttled and logged, just in its own bucket. If the page offers the PIN,
    # its bucket applies too (C-3): a PIN locked at login cannot be guessed
    # on here.
    throttle_ok = self._rate_ok(ip, login=False)
    attempt = (self._begin_attempt(u["username"], ip, "reauth", include_pin="pin" in methods)
               if throttle_ok else None)
    if attempt is None:
        return self._sign_in_no("locked" if throttle_ok else "ratelimit", 429, "err.retry", nxt)
    if procedure == "password" and self._directory_password(u):
        # LDAP step-up (T-99): a fresh bind instead of a local hash. An outage is not a failed attempt (F-23, as at
        # sign-in): taken back, 503, the same lines as the sign-in's outage.
        from .ldap_ import DirectoryNotReachable
        try:
            correct = self._verify_directory_password(u, secret)
        except DirectoryNotReachable as e:
            self.audit("ldap_unavailable", u["username"], ip, security.for_log(str(e))[:300])
            security.seclog.error("LDAP unreachable user=%s ip=%s reason=%s", security.for_log(u["username"]),
                                  security.for_log(ip), security.for_log(str(e)))
            self._revert_attempt(attempt)
            return self._sign_in_no("directory_down", 503, "err.directory_down", nxt)
        except BaseException:
            self._attempt_failed(attempt)
            raise
    else:
        checker = {"totp": self._verify_totp, "pin": self._verify_user_pin,
                   "password": self._verify_user_password}[procedure]
        correct = checker(u["id"], secret)
    self._record_login(u["username"], ip, correct, "reauth", attempt=attempt)
    if not correct:
        return self._sign_in_no("invalid", 401, "err.reauth", nxt)
    return None


def _confirm(self, request: Request, procedure: str, secret, next: str,
                 csrf: Optional[str]) -> LoginResult:
    """The one source of `confirm_password`, `confirm_pin` and `confirm_totp` — and thus of
    `POST /auth/reauth`, which calls one of them depending on the field filled in."""
    cfg = self.cfg
    self.require_csrf(request, self._csrf_sent_along(request, csrf))
    nxt = self.safe_next(next, request)
    u, without = self._only_with_session(request, "reauth")
    if u is None:
        return self._sign_in_no("no_session", without[0], without[1],
                                    self.browser_path(request, cfg.login_path))
    refused = self._stepup_secret(request, u, procedure, secret, nxt)
    if refused is not None:
        return refused
    s = self._session_from_request(request)
    new = None
    if s:
        self.store.set_session_mfa(s["token_hash"], True)   # sets mfa_at=now → fresh again
        # Freshly confirmed means a new token (F-06): an old cookie that was read along would otherwise
        # hold exactly the session that has just received sudo rights. The old one still applies for
        # `session_rotation_grace_sec`, without freshness (A-6). The CSRF token stays.
        new = self.store.rotate_session(s["token_hash"], self._mercy())
    self.audit("stepup", u["username"], self.client_ip(request))
    return LoginResult._with_session(self, new, ok=True, reason="ok", status=303, next_url=nxt,
                                     done=True, user=self.get_user(u["id"]))


def confirm_password(self, request: Request, password: str, *, next: str = "",
                     csrf: Optional[str] = None) -> LoginResult:
    """Freshly confirm the session with the password of the own account (step-up) — throttled and locked like `POST /auth/reauth`, which calls exactly this method.

    The building block for an own step-up page (dialog of a single-page app, own
    form before a sensitive action). It checks the CSRF token (`csrf`, otherwise header
    `X-CSRF-Token`), requires a full session (an API key does not count: `no_session`, 403),
    admits only a method that `stepup_options()` offers this account, throttles per IP,
    pre-books the attempt atomically in the own bucket (`reauth_max_attempts`, not that of the
    login), writes audit and security log and, on success, makes the session fresh
    (`stepup_fresh`, `require(mfa=True)`) — with a new token, which `redirect()`/`set_cookie()`
    set. A `LoginResult` comes back:

        result = auth.confirm_password(request, password, next=next, csrf=csrf)
        if not result:
            return my_dialog(error=result.message, status=result.status)
        return result.redirect()     # to next, with the renewed session cookie

    An empty password is `missing` (400) and does not count. An LDAP account without a local password confirms with
    its directory password: a fresh bind that must lead to this account (T-99); a directory outage is `directory_down`
    (503) and does not count. Raises only what the route
    raises too: `HTTPException(403)` for a wrong CSRF token, plus the unexpected. Synchronous: call from
    a `def` route, in an `async def` route via `run_in_threadpool`."""
    return self._confirm(request, "password", password, next, csrf)


def confirm_pin(self, request: Request, pin: str, *, next: str = "",
                csrf: Optional[str] = None) -> LoginResult:
    """Freshly confirm the session with the PIN of the own account (step-up) — like `confirm_password`, throttled and locked like `POST /auth/reauth`.

    Like `confirm_password`, only with the PIN (`pin_enabled`, the account has one). If the
    page offers the PIN, the PIN bucket applies in addition (C-3): a PIN locked at the PIN sign-in
    cannot be guessed on here. The failed attempts themselves count in the `reauth` bucket."""
    return self._confirm(request, "pin", pin, next, csrf)


def confirm_totp(self, request: Request, code: str, *, next: str = "",
                 csrf: Optional[str] = None) -> LoginResult:
    """Freshly confirm the session with a TOTP code of the own account (step-up) — like `confirm_password`, throttled and locked like `POST /auth/reauth`.

    Like `confirm_password`, only with a TOTP code (each is valid once); a one-time code
    (recovery) does not count here — as on the built-in page. Not to be confused with
    `totp_confirm(user_id, code)`, which completes the setup of TOTP."""
    return self._confirm(request, "totp", code, next, csrf)


def change_password(self, request: Request, current: str, new: str, *,
                    csrf: Optional[str] = None) -> PasswordChangeResult:
    """Change the password of the own account — the old one checked throttled and locked like `POST /auth/password`, which calls exactly this method.

    The building block for an own password-change page. It checks the CSRF token (`csrf`, otherwise
    header `X-CSRF-Token`), requires a full session (an API key does not count:
    `no_session`, 403), throttles per IP, pre-books the attempt atomically in the own bucket
    (`password_change_max_attempts`, per account only; a typo here does not lock the
    sign-in), checks the old password against the session's account (never against a
    resolved identifier, R4-12), then the new one against the password rule. On success: new
    password, all OTHER sessions ended (the own one stays), open address-change links
    discarded, audit `password_change`. A `PasswordChangeResult` comes back:

        result = auth.change_password(request, current, new, csrf=csrf)
        if not result:
            return my_form(error=result.message, status=result.status)
        # result.api_keys_active: this many API keys remain valid — say so, do not conceal

    An empty old password is `missing` (400) and does not count. Raises only what the route
    raises too: `HTTPException(403)` for a wrong CSRF token, plus the unexpected. Synchronous:
    call from a `def` route, in an `async def` route via `run_in_threadpool`."""
    self.require_csrf(request, self._csrf_sent_along(request, csrf))

    def no(reason, status, text, **values) -> PasswordChangeResult:
        return PasswordChangeResult(ok=False, reason=reason, status=status,
                                    message=self.t(text, **values) if text else "")

    u, without = self._only_with_session(request, "password_change")
    if u is None:
        return no("no_session", *without)
    # An account without a local password on an instance with a directory signs in against the directory: there is
    # no old password here to check, and a new one would be a second password beside the directory's. Refused
    # before anything is counted — every try used to be a "wrong password" that locked the form.
    if self.cfg.ldap_enabled and not self.store.get_password_hash(u["id"]):
        return no("directory", 409, "api.password_directory")
    if not current:
        return no("missing", 400, "err.required")
    ip = self.client_ip(request)
    # The old password is a secret as at login — so the same triad of
    # throttle, lock and log. Without it `/auth/password` was a silent, unlimited
    # password oracle: any number of attempts, never a 429, no line in the security
    # log, no failed attempt in `login_attempt` — while the same failed attempt at login
    # locks after a few tries (R4-10; the login threshold is `max_login_attempts`,
    # default 5 and adjustable in the panel).
    #
    # The lock is a bucket of its OWN (`_is_password_change_locked`, own threshold
    # `password_change_max_attempts`), not that of the login: with the shared counter
    # five typos here locked the sign-in for 15 minutes — including this route, via
    # which the user could have worked off the lock. Behind NAT it even hit uninvolved colleagues via
    # `ip_attempt_factor`. It remains throttled (`_rate_ok`),
    # and logged too.
    throttle_ok = self._rate_ok(ip, login=False)
    attempt = self._begin_attempt(u["username"], ip, "password_change") if throttle_ok else None
    if attempt is None:
        return no("locked" if throttle_ok else "ratelimit", 429, "api.too_many")
    # Checked against the **ID** of the own session, not against the login identifier:
    # `_check_password(u["username"], …)` went through `find_user()` and could thereby resolve to a
    # FOREIGN account (attacker's username = victim's email, R4-12).
    # Then one would guess here not one's own password but the victim's — and the hit
    # silently set one's own password, so it stayed invisible.
    correct = self._verify_user_password(u["id"], current)
    # Own method: a hit here does NOT clear the login path's failed attempts
    # (`_record_login` deletes only those of the same method) — the lock stays where it applies.
    self._record_login(u["username"], ip, correct, "password_change", attempt=attempt)
    if not correct:
        return no("invalid", 403, "api.password_wrong")
    defect = self.password_policy_error(new or "", username=u["username"], email=u.get("email"), api=True)
    if defect:
        return PasswordChangeResult(ok=False, reason="policy", status=400, message=defect)
    self.set_password(u["id"], new)
    # end the user's other sessions (keep the current one) — default after a credential change
    s = self._session_from_request(request)
    self.store.delete_user_sessions_except(u["id"], s["token_hash"] if s else None)
    # An open address change may stem from one of the sessions just ended — it
    # falls with them (finding 1). Other links (sign-in link, reset) go to the own address.
    self.store.revoke_user_magic_tokens(u["id"], purposes=("email_change",))
    # API keys survive the own password change on purpose: they are meant for automations,
    # and a routine change should not shut those down wholesale (one account = often one
    # key = several integrations). It is still not concealed — whoever changes the password after a
    # break-in must know that a door is still open.
    # The app passwords (T-66) likewise: a phone calendar should not break with a routine change — counted, named.
    active = self.store.count_active_api_keys(u["id"])
    app_pw = self.store.app_passwords_active(u["id"])
    parts = [p for p in (f"api_keys_active={active}" if active else "",
                         f"app_passwords_active={app_pw}" if app_pw else "") if p]
    self.audit("password_change", u["username"], ip, " ".join(parts) or None)
    return PasswordChangeResult(ok=True, reason="ok", status=200, api_keys_active=active,
                                app_passwords_active=app_pw)


def set_initial_password(self, request: Request, new: str, *,
                         csrf: Optional[str] = None) -> PasswordChangeResult:
    """Give the own account its FIRST password — for an account that has none yet; `POST /auth/password/set` calls exactly this method.

    For accounts created by sign-in link, OIDC or passkey (B-10): `change_password` asks for
    the current password, which such an account does not have, so it could never get one.
    Here the old password is replaced by the freshness of the session, the same rule as for
    creating any other factor (`POST /auth/pin/set`): if the account already has something it
    can confirm with (`stepup_options()`, e.g. a TOTP or a PIN), a fresh step-up
    (`stepup_fresh()`, reason `stepup`); if it has nothing, the age of the sign-in
    (`login_fresh()`, both bounded by `stepup_max_age_sec`, reason `relogin`). A stolen,
    old session cookie therefore cannot plant a password that outlives the theft.

    Checks the CSRF token (`csrf`, otherwise header `X-CSRF-Token`), requires a full session
    (`no_session`, an API key never counts), throttles per IP (`ratelimit`), checks the
    password rule (`policy`). Refused when the account already has a password (`has_password`,
    409 — that is `change_password`), when password sign-in is off (`method_disabled`, 404) and
    when a directory is configured (`directory`, 409 — with `ldap_enabled` a local password
    would sit next to the directory one and keep working after the directory disables the
    account). On success: the password is set, the audit line `password_set` and the security
    event `password_changed` are written. Other sessions are NOT ended — like after a new factor
    the caller offers that (`count_other_sessions`). Synchronous: call from a `def` route, in
    an `async def` route via `run_in_threadpool`."""
    self.require_csrf(request, self._csrf_sent_along(request, csrf))

    def no(reason, status, text, **values) -> PasswordChangeResult:
        return PasswordChangeResult(ok=False, reason=reason, status=status,
                                    message=self.t(text, **values) if text else "")

    if not self.cfg.password_enabled:
        return no("method_disabled", 404, "api.password_off")
    u, without = self._only_with_session(request, "password_change")
    if u is None:
        return no("no_session", *without)
    if self.store.get_password_hash(u["id"]):
        return no("has_password", 409, "api.password_exists")
    if self.cfg.ldap_enabled:
        return no("directory", 409, "api.password_directory")
    # The freshness replaces the old password — the same split as `POST /auth/pin/set`.
    if self.stepup_options(u):
        if not self.stepup_fresh(request, u):
            return no("stepup", 403, "api.stepup")
    elif not self.login_fresh(request, u):
        return no("relogin", 403, "api.stepup_relogin")
    return self._first_password(request, u, new)


def _first_password(self, request: Request, u: dict, new: str, *, detail: str = "") -> PasswordChangeResult:
    """The part of setting a first password that both doors share — the account page
    (`set_initial_password`) and the setup pass (`_setup_password`): throttle, rule, set, audit."""
    ip = self.client_ip(request)
    if not self._rate_ok(ip, login=False):
        return PasswordChangeResult(ok=False, reason="ratelimit", status=429, message=self.t("api.too_many"))
    defect = self.password_policy_error(new or "", username=u["username"], email=u.get("email"), api=True)
    if defect:
        return PasswordChangeResult(ok=False, reason="policy", status=400, message=defect)
    self.set_password(u["id"], new)
    active = self.store.count_active_api_keys(u["id"])
    app_pw = self.store.app_passwords_active(u["id"])
    parts = [p for p in (f"api_keys_active={active}" if active else "",
                         f"app_passwords_active={app_pw}" if app_pw else "", detail) if p]
    self.audit("password_set", u["username"], ip, " ".join(parts) or None)
    return PasswordChangeResult(ok=True, reason="ok", status=200, api_keys_active=active,
                                app_passwords_active=app_pw)


def _setup_password(self, request: Request, new: str, *,
                    csrf: Optional[str] = None) -> tuple[PasswordChangeResult, Optional[str]]:
    """The first password inside the setup pass after a sign-in link (T-34) — `POST
    /auth/password/set` with a half session. Returns the result and, if the sign-in is complete
    with it, the new session token for the cookie.

    The half session is allowed only while the pass offers exactly `password` (`_setup_user`).
    The pass offers only factors the account does not have (`_setup_missing`), so nothing is
    replaced — that is the one guard, proven by mutation in `tests/test_link_onboarding.py`. The
    pass is fresh from the link (its window is the step-up window). Everything else as
    `set_initial_password`."""
    self.require_csrf(request, self._csrf_sent_along(request, csrf))
    if not self.cfg.password_enabled:
        return PasswordChangeResult(ok=False, reason="method_disabled", status=404,
                                    message=self.t("api.password_off")), None
    u = self._setup_user(request, "password")
    if u is None:
        return PasswordChangeResult(ok=False, reason="no_session", status=401,
                                    message=self.t("api.not_signed_in")), None
    result = self._first_password(request, u, new, detail="setup_pass=1")
    if not result:
        return result, None
    return result, self._setup_record(request, "password")


# ---------- Step-up freshness ----------
def stepup_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
    """True if the current session has freshly confirmed a factor (sudo freshness)."""
    user = user or self.current_user(request)
    if not user or user.get("_via") == "apikey":
        return False   # machine access cannot freshly confirm an interactive factor
    s = self._session_from_request(request)
    if not s or not s["mfa_ok"]:
        return False
    if self.cfg.stepup_max_age_sec > 0:
        if not s["mfa_at"] or (_manager._now() - s["mfa_at"]) > self.cfg.stepup_max_age_sec:
            return False
    return True


def login_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
    """True if the **sign-in** is at most `stepup_max_age_sec` ago.

    The weaker sister of `stepup_fresh()`: what is measured is the last sign-in of the account on this
    session — the session's start, or a later sign-in at the provider (`mfa_at`, T-49); a sign-in through a
    provider counts from the provider's `auth_time`, not from the round that brought it.

    Intended for exactly one situation — an account that has **no** factor with which it could
    confirm (`stepup_options()` empty, purely federated account without password, PIN
    and TOTP). For creating the FIRST factor the barrier there cannot hang on
    confirmation, otherwise the setup is a dead end: after the window expired,
    `/auth/pin/set` answered with 403, and the reauth page offered a password field that
    this account does not have. An API key is worth nothing here either.
    """
    user = user or self.current_user(request)
    if not user or user.get("_via") == "apikey":
        return False
    s = self._session_from_request(request)
    if not s:
        return False
    if self.cfg.stepup_max_age_sec > 0:
        # T-49: the later of sign-in and last confirmation, but never later than the confirmation itself. A new
        # session starts with `mfa_at` = sign-in, a sign-in through a provider with its `auth_time`
        # (`Store.backdate_confirmation`), and a fresh sign-in at the provider on this session (the confirmation
        # page's provider button) moves `mfa_at` forward — what this account can confirm with at all.
        since = s["mfa_at"] if s["mfa_at"] is not None else (s["created_at"] or 0)
        if (_manager._now() - since) > self.cfg.stepup_max_age_sec:
            return False
    return True


def _redirect_factor(self, request: Request, step) -> NoReturn:
    # Browser → redirect to the input page of the next factor; JSON → 401 + X-TinySesam-Factor.
    if step is None:
        self._deny(request)
    if "text/html" in request.headers.get("accept", ""):
        raise HTTPException(307, headers={"Location": self.browser_path(request, self._factor_entry(step, request.url.path))})
    raise HTTPException(401, self.t("api.factor"), headers={"X-TinySesam-Factor": step})


def _enforce_route_chain(self, request: Request, factors, strict) -> dict:
    """Enforce a route chain (`require(factors=[…])`) — **in addition** to the global rule.

    A route chain tightens, it never undercuts (PO decision 2026-09-27, "align"):
    First the session must be full for the GLOBAL rule (`mfa_ok`, as with `current_user`) —
    a half session goes first to the missing step of the global sign-in
    (`_next_login_step`). Until then the route's list alone sufficed: `factors=["password"]`
    opened the route to a half session whose account still owed TOTP, and
    `["pin", "password"]` that of an account with TOTP that had provided only PIN and password.
    After that the route's own list (`_chain_satisfied`) and the second factor after the
    sign-in link (`_link_requires`, G10). An API key does not satisfy a route chain."""
    strict = self.cfg.login_chain_strict if strict is None else strict
    s = self._session_from_request(request)
    usr = self._as_dict(self.store.get_user(s["user_id"])) if s else None
    if usr and usr["disabled"]:
        usr = None
    done = json.loads(s["factors_done"] or "[]") if s else []
    if usr is None or s is None:
        _redirect_factor(self, request, factors[0] if factors else "password")
    if not s["mfa_ok"]:
        # The global sign-in is still open: first its next step. `None` (nothing
        # open any more, but not full either — e.g. a factor removed in the meantime) → login.
        _redirect_factor(self, request, self._next_login_step(usr["id"], done,
                                                             setup=self._setup_session(s)))
    if not self._chain_satisfied(factors, strict, done):
        _redirect_factor(self, request, self._next_factor(factors, strict, done, usr["id"]))
    # The same rule as for the global policy (G10): if the sign-in went through the link and
    # the account has a second factor, a route chain like `["magic"]` demands it too — otherwise
    # the mailbox alone would open the route of an account that protected itself with TOTP/passkey.
    # If the chain itself contains `totp`/`passkey`, it is already provided (no double step).
    missing = self._link_requires(usr["id"], done)
    if missing is not None:
        _redirect_factor(self, request, missing)
    d = dict(usr)
    d["_via"] = "session"
    return d


def _enforce(self: TinySesam, request: Request, mfa=False, admin=False, role=None, factors=None,
             strict: Optional[bool] = None, admin_implies: Optional[bool] = None) -> dict:
    gchain, _ = self._global_chain()
    # The first branch always yields a dict, the other two can yield None and then
    # abort via `_deny`/`_redirect_factor`. Without this declaration a type checker
    # assumes the type of the first branch for the whole rest.
    u: Optional[dict]
    if factors is not None:
        # explicit route chain: never satisfiable via API key, drives own factor steps
        u = self._enforce_route_chain(request, factors, strict)
    elif gchain is None:
        # classic (fast path, unchanged)
        u = self.current_user(request)
        if not u:
            self._deny(request)
    else:
        # global chain: current_user mirrors it (mfa_ok); partial session → next step
        u = self.current_user(request)
        if not u:
            s = self._session_from_request(request)
            usr = self._as_dict(self.store.get_user(s["user_id"])) if s else None
            if not usr or usr["disabled"]:
                self._deny(request)   # no identity → login (first factor)
            done = json.loads(s["factors_done"] or "[]")
            self._redirect_factor(request, self._next_login_step(usr["id"], done,
                                                                 setup=self._setup_session(s)))
    if admin and not self.is_admin(u):
        raise HTTPException(403, self.t("api.admin"))
    if role:
        # One role or several (then ONE of them suffices — the same OR meaning as
        # ?roles=a,b in forward auth). Whoever requires ALL stacks two guards.
        necessary = [role] if isinstance(role, str) else list(role)
        if not any(self.has_role(u, r, admin_implies) for r in necessary):
            raise HTTPException(403, self.t("api.role", roles=", ".join(f"'{r}'" for r in necessary)))
    if mfa and not self.stepup_fresh(request, u):
        if u.get("_via") == "apikey":
            raise HTTPException(403, self.t("api.stepup_session"))
        self._deny_stepup(request)
    return u


def require_user(self, request: Request) -> dict:
    """FastAPI dependency (direct): enforces a signed-in (incl. MFA) user.
    Whoever needs no roles: `Depends(auth.require_user)` suffices."""
    return self._enforce(request)


def require_admin(self, request: Request) -> dict:
    """FastAPI dependency (direct): signed in + admin (+ step-up, when admin_require_mfa)."""
    return self._enforce(request, admin=True, mfa=self.cfg.admin_require_mfa)


def require_role(self, *roles, mfa: bool = False, admin_implies: Optional[bool] = None):
    """FastAPI dependency factory: signed in + role. `Depends(auth.require_role('editor'))`.

    **Several roles: one of them suffices** — `auth.require_role('editorial', 'proofreading')`.
    That is the same OR meaning as `?roles=a,b` in forward auth; otherwise the same
    question would mean something different depending on the operating mode. A list works as well
    (`require_role(['editorial', 'proofreading'])`), handy for roles from the configuration.

    Whoever requires **all** stacks two guards — `Depends` dependencies all run:
    `@app.get(..., dependencies=[Depends(auth.require_role('a')), Depends(auth.require_role('b'))])`.

    An admin satisfies the role by default — `admin_implies=False` really requires it.
    mfa=True additionally requires step-up freshness.
    """
    flat = []
    for r in roles:
        if isinstance(r, str):
            flat.append(r)
            continue
        try:
            flat.extend(r)
        except TypeError:
            # Catches the one call that changes through the variadic signature:
            # require_role("editor", True) used to mean mfa=True. mfa and admin_implies
            # are now keyword-only — loud instead of silently wrong.
            raise TypeError(f"require_role(): {r!r} is not a role. "
                            "Pass mfa/admin_implies as keyword arguments only.") from None
    if not flat:
        raise ConfigError("require_role() needs at least one role")

    def dep(request: Request) -> dict:
        return self._enforce(request, role=flat, mfa=mfa, admin_implies=admin_implies)
    return dep


def require(self, mfa: bool = False, admin: bool = False, role=None,
            factors: Optional[list] = None, strict: Optional[bool] = None,
            admin_implies: Optional[bool] = None):
    """General guard factory for arbitrary combinations — the "flag on the guard" route:
    `Depends(auth.require(mfa=True))`, `Depends(auth.require(admin=True, mfa=True))`.
    `role=` takes one role or several (`role=["editorial", "proofreading"]` → one suffices).
    factors=[...] additionally requires a specific factor chain for this route,
    strict=True/False controls the order: `Depends(auth.require(factors=['oidc','password']))`.
    The route chain tightens the global rule, it does not replace it: a session that is not yet full for the
    global sign-in (second factor open, chain incomplete) goes first
    to its missing step — also with `factors=["password"]` (since 2026-09-27; until then
    the route chain overrode the global one). If the sign-in went through the sign-in link and the
    account has TOTP or a passkey, a route chain demands it too
    (`magiclink_require_second_factor`, as in the global policy)."""
    def dep(request: Request) -> dict:
        return self._enforce(request, mfa=mfa, admin=admin, role=role, factors=factors,
                             strict=strict, admin_implies=admin_implies)
    return dep


def require_mfa(self, request: Request) -> dict:
    """FastAPI dependency (direct): signed in + fresh step-up confirmation."""
    return self._enforce(request, mfa=True)


def require_session(self, request: Request, user: Optional[dict] = None) -> dict:
    """Signed in — and **interactively** at that: a session yes, an API key no (403).

    The bolt for **creating** a factor (set up TOTP, register passkey,
    first PIN). `require_mfa()` covered only the removal; creation still hung on
    `current_user()`, and that accepts an API key. A leaked CI key
    thereby set up a factor that **it** controls: the TOTP secret is in the response
    of `GET /auth/totp/setup`, and a self-registered passkey is a full
    login — through it the key got a fresh interactive session and thus after all to the
    `require_mfa()` routes. The enrollment route was the lever that broke the lock.

    The check is for `_via == "apikey"`, not for `_via == "session"`: with
    TOTP setup under `login_chain=["password","totp"]` a user from
    `totp_enrollment_user()` is there — a session that has provided its first factor but is not yet
    fully signed in. It may set up, a machine credential may not.
    (The key management checks the other way round for `"session"` — it knows no such
    intermediate state and prefers to stay fail-closed.)
    """
    u = user or self.current_user(request)
    if not u:
        self._deny(request)
    if u.get("_via") == "apikey":
        raise HTTPException(403, self.t("api.needs_session"))
    return u


def _fresh_enough(self, request: Request, user: dict) -> Optional[str]:
    """The freshness rule for NEW access — None if this session may, otherwise the reason.

    `"stepup"`: the account has something it can confirm with (`stepup_options()`), and the last
    confirmation is older than `stepup_max_age_sec`. `"relogin"`: it has nothing (purely federated
    or passkey only) and the sign-in itself is that old — only a new sign-in helps. A fresh sign-in
    counts as a confirmation (`mfa_at` is set at sign-in), so right after signing in nothing more
    is asked."""
    if self.stepup_options(user):
        return None if self.stepup_fresh(request, user) else "stepup"
    if self.login_fresh(request, user):
        return None
    # T-49: an account linked to the provider confirms there (the confirmation page's provider button) — so it
    # is sent to that page like any other, instead of being told to sign out.
    return "stepup" if self._confirms_at_provider(user) else "relogin"


def _confirms_at_provider(self, user) -> bool:
    """Can this account confirm on the confirmation page through the OIDC provider (T-49)?"""
    return bool(self.cfg.oidc_enabled and self.cfg.oidc_reauth_check and user
                and self.store.is_oidc_account(user["id"]))


def _require_fresh(self, request: Request, user: Optional[dict] = None) -> dict:
    """The bolt in front of every route that creates NEW, lasting access to the account (B-12,
    ASVS 7.5.1, NIST SP 800-63B-4 §4.1.2.1): register a passkey, set up TOTP, set a PIN, create an
    API key, approve a cross-device sign-in, allow an OAuth program — and change name or address.

    Without it a stolen session cookie became a permanent way in: a passkey signs in alone and
    outlives sign-out, password change and session expiry; a TOTP locks the holder out under a
    chain; an API key carries the account's roles for 90 days. Now such a route wants an
    interactive session (never an API key, `require_session`) whose confirmation is fresh — the
    same freshness as `require_mfa()`: a confirmed factor within `stepup_max_age_sec`, or, for an
    account without anything to confirm with, a sign-in within that span (`login_fresh`).

    Refusal: `stepup` → 403 with `X-TinySesam-Reauth` (a browser page request goes to the reauth
    page), `relogin` → 403 `api.stepup_relogin` (the reauth page has no field for such an account).
    The setup pass after a sign-in link (T-34) and the mandatory TOTP setup in a chain do not come
    through here: their half session is fresh from the sign-in by construction and can set up only
    what is offered — the routes take that path before this one."""
    u = self.require_session(request, user)
    if u.get("_via") != "session":
        # A half session never reaches here through `current_user()`; a caller that passes one
        # in is mistaken — fail-closed.
        self._deny(request)
    why = self._fresh_enough(request, u)
    if why == "stepup":
        self._deny_stepup(request)
    if why == "relogin":
        raise HTTPException(403, self.t("api.stepup_relogin"))
    return u


def _reauth_target(self, request: Request, nxt: str) -> Optional[str]:
    """Where a PAGE (GET) that leads to new access sends a session that is not fresh — the reauth
    page with `next` (path AND query, unlike `_deny_stepup`) — or None if fresh. An account without
    anything to confirm with gets None as well: its page shows the refusal itself (`api.stepup_relogin`)."""
    u = self.session_user(request)
    if u is None or self._fresh_enough(request, u) != "stepup":
        return None
    from urllib.parse import quote
    return f"{self.browser_path(request, '/auth/reauth')}?next={quote(nxt, safe='')}"


def _extract_api_key(self, request: Request):
    h = request.headers.get("x-api-key")
    if h:
        return h.strip()
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        tok = auth[7:].strip()
        if tok.startswith("tsk_"):
            return tok
    return None


# ---------- App passwords (T-66) ----------
def app_password_hosts(self) -> list:
    """The applications that accept app passwords: `[{"host": …, "name": …}]` — the `forward_apps` entries with
    `"app_passwords": True`. Empty without `forward_auth_enabled` (only the gate reads app passwords): then the
    account page shows no such section and the routes do not exist."""
    if not self.cfg.forward_auth_enabled:
        return []
    out, seen = [], set()
    for h, e in (self.cfg.forward_apps or {}).items():
        if not isinstance(e, dict) or e.get("app_passwords") is not True:
            continue
        host = str(h).strip().lower().rstrip(".")
        if host and host not in seen:
            seen.add(host)
            out.append({"host": host, "name": str(e.get("name") or host)})
    return out

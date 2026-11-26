"""The building block `fastapi` of `TinySesam`: the FastAPI integration (guards, dependencies, routers, error pages).

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import logging
import re
import time
from . import config_check
from . import security
from .config import TinySesamConfig
from .errors import ConfigError
from fastapi import Request
from .manager import (
    _HSTSMiddleware,
    _HSTS_RE,
    _messages_of_language,
)


# ---------- FastAPI-Integration ----------
def _bolt(self, config: TinySesamConfig, *, on_setup: bool) -> None:
    """All checks that make construction fail — in the constructor and once more before
    `router()`/`admin_router()` (A2).

    Until then they stood only in the constructor; `_recheck` knew only `config_check` and
    the cookie fields. Whoever set `auth.cfg.allow_signup = True` afterwards built, alongside
    `admin_identifiers=["boss"]`, a router in which the first visitor registered as "boss"
    and became first admin. `on_setup=False` leaves out only `config_check` —
    `_recheck` has already run it via `TinySesamConfig._findings()`, warnings included."""
    if config.login_identifier not in ("username", "email", "both"):
        raise ConfigError("login_identifier must be 'username', 'email' or 'both'")
    if config.login_identifier == "email" and config.allow_signup and not config.signup_require_email:
        raise ConfigError("login_identifier='email' needs signup_require_email=True — "
                         "otherwise accounts arise that cannot sign in")
    # All remaining contradictions at once — at construction, not at the first login. The
    # checks above raise individually because each tells its own story;
    # what comes after is collected by config_check.py and reported together. Whoever has three things
    # wrong should read them once and not start three times.
    if on_setup:
        findings, notices = config_check.check_config(config)
        for notice in notices:
            security.seclog.warning("configuration: %s", notice)
        if findings:
            raise ConfigError("The configuration does not work like this:\n  - " + "\n  - ".join(findings))

    if config.cookie_samesite not in ("lax", "strict", "none"):
        raise ConfigError(
            "cookie_samesite must be 'lax', 'strict' or 'none' (lower case). "
            "Starlette only checks the value at the first cookie — and under `python -O` not at "
            "all, so the typo would end up in the Set-Cookie header.")
    if config.cookie_samesite == "none" and not config.cookie_secure:
        raise ConfigError(
            "cookie_samesite='none' requires cookie_secure=True — a browser discards a "
            "SameSite=None cookie without the Secure flag, the sign-in would never arrive.")
    if not isinstance(config.csp, str):
        raise ConfigError("csp must be a string ('strict', 'off' or a custom policy)")
    if config.https_mode not in ("off", "warn", "force"):
        raise ConfigError("https_mode must be 'off', 'warn' or 'force' — anything else "
                         "counts as 'no redirect', so a typo silently switches the "
                         "HTTPS enforcement off")
    # Browsers ignore an HSTS header they cannot parse — without a word. A typo would be a
    # switch that looks set and protects nothing.
    if not isinstance(config.hsts, str) or (config.hsts and not _HSTS_RE.fullmatch(config.hsts)):
        raise ConfigError(f"hsts={config.hsts!r}: expected '' or 'max-age=<seconds>' with optional "
                          "'; includeSubDomains' and '; preload'")
    # cookie_secure=False is right for local setups without a certificate and remains
    # allowed. Together with https_mode='force' it contradicts itself, though: the app then redirects
    # every request to HTTPS and still hands out the session cookie without the
    # Secure flag.
    #
    # Only what the app says about its OWN behaviour is checked — not what it claims about
    # the outside world. An earlier version also fired on
    # `base_url='https://…' + cookie_secure=False`; that sounded plausible but was wrong:
    # `base_url` is a commitment about the public address (SAML/OIDC build callbacks from it),
    # not about the transport between browser and app. Four suites of our own
    # need exactly this combination (public HTTPS URL, TestClient on http://) —
    # a guard that fires wrongly four times in the own house does so all the more with users.
    # `totp_required` was always a switch without a wire: it stood in the config, in
    # both READMEs ("enforce 2FA") and on the website — and was read nowhere in the
    # code. Whoever set it believed the second factor was enforced and it was
    # not. An ineffective security switch is more dangerous than none at all, because
    # it ends the search for the right way. The library therefore now says so loudly
    # instead of continuing to ignore it silently — and names the route that really applies.
    if getattr(config, "totp_required", False):
        raise ConfigError(
            "totp_required has never had any effect — the switch was not read anywhere. "
            "Whoever wants to make TOTP mandatory uses the factor chain: "
            "login_chain=['password', 'totp'] (with login_chain_strict=True). Without a chain "
            "the classic policy applies: TOTP is required as soon as it is set up.")
    if not config.cookie_secure and config.https_mode == "force":
        raise ConfigError(
            "https_mode='force' and cookie_secure=False contradict each other: the app "
            "redirects every request to HTTPS but hands out the session cookie without the "
            "Secure flag. Either cookie_secure=True, or https_mode='warn' "
            "(local/without certificate).")

    # First admin via allowlist + open self-registration: the allowlist vouches only for
    # WHICH name becomes admin — not WHO gets that name. If `admin_identifiers` stands
    # on a fresh instance with `allow_signup=True`, the first person to guess
    # the address registers exactly under it and is admin at the first login. That is the same
    # error the bootstrap is actually meant to avoid ("first one wins") — only one
    # stage later.
    #
    # The combination is viable only if the identity from the registration itself
    # is proven: an email address (not a pure username that nobody confirms),
    # mandatory at registration AND verified via confirmation link. Then whoever has the mailbox
    # has the name.
    #
    # This door is open not only with `allow_signup`. Every method that creates an account
    # itself at the first login creates it under a name that the foreign IdP
    # supplies: `oidc.py` takes `preferred_username`, SAML the NameID/attribute field, LDAP
    # the sign-in name. That is the same situation as with open registration — only
    # there the visitor determines the name and here the IdP, and with an IdP
    # with self-registration that is the same person.
    open_doors = []
    if config.allow_signup:
        open_doors.append("allow_signup=True")
    for an, create, name in (("oidc_enabled", "oidc_auto_create", "OIDC"),
                              ("saml_enabled", "saml_auto_create", "SAML"),
                              ("ldap_enabled", "ldap_auto_create", "LDAP")):
        if getattr(config, an, False) and getattr(config, create, False):
            open_doors.append(f"{create}=True ({name})")
    if config.admin_identifiers and open_doors:
        ids = [str(i).strip() for i in config.admin_identifiers if str(i).strip()]
        names = [i for i in ids if "@" not in i]
        if names:
            raise ConfigError(
                f"admin_identifiers={names} are usernames, and accounts arise here "
                f"on their own ({', '.join(open_doors)}): nobody confirms a "
                "username — whoever signs in first like that becomes first admin. With open "
                "registration enter an email address instead (with "
                "signup_require_email=True and signup_verify_email=True); with an IdP "
                "use the one-time-token route (/auth/claim-admin, see admin_claim_ttl_min) "
                "or switch off auto-creation and assign the account yourself beforehand "
                "(with OIDC, oidc_allowed_groups narrows the circle further).")
    if config.admin_identifiers and config.allow_signup:
        if not (config.signup_require_email and config.signup_verify_email):
            raise ConfigError(
                "admin_identifiers together with allow_signup=True requires "
                "signup_require_email=True AND signup_verify_email=True — otherwise "
                "anyone simply enters the admin address at registration and becomes admin at the "
                "first login. Alternatively allow_signup=False or the one-time-token route "
                "(/auth/claim-admin, see admin_claim_ttl_min).")
    # A typo in the field name ("mail" instead of "email") would otherwise simply omit the
    # header — silently, and visible only when debugging the foreign app. Header names are checked
    # against the permitted character set: a value with a line break would be header injection.
    if config.forward_headers:
        permitted = set(self.FORWARD_HEADERS_DEFAULT)
        # First the shape, then the names. `{"user": None}` slipped through (`names or []`
        # turned it into an empty list) and later tipped EVERY forward-auth request into
        # a 500; `{"user": 123}` killed the constructor with a raw `TypeError` that
        # an `except ConfigError` does not catch.
        for slot, value in config.forward_headers.items():
            if isinstance(value, str):
                continue
            if isinstance(value, (list, tuple)) and all(isinstance(x, str) for x in value):
                continue
            raise ConfigError(
                f"forward_headers[{slot!r}] must be a header name or a list of them "
                f"— but is {type(value).__name__}. Example: "
                '{"user": "Remote-User"} or {"user": ["Remote-User", "X-Auth-User"]}')
        unknown = [k for k in config.forward_headers if k not in permitted]
        if unknown:
            raise ConfigError(f"forward_headers: unknown field {unknown} — allowed are "
                             f"{sorted(permitted)}")
        # A mandatory slot can be renamed, never dropped: an empty list would be a hidden omission.
        for slot in self.FORWARD_HEADERS_MANDATORY:
            if slot in config.forward_headers and not config.forward_headers[slot]:
                raise ConfigError(
                    f"forward_headers[{slot!r}] is always sent (gate clients after spec v2 refuse a request "
                    f"without it) — rename it ({{{slot!r}: \"X-Account-Kind\"}}) or leave it out of the mapping "
                    f"to keep {self.FORWARD_HEADERS_DEFAULT[slot]!r}; an empty value cannot drop it")
        for slot, names in config.forward_headers.items():
            for name in ([names] if isinstance(names, str) else names or []):
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
                    raise ConfigError(f"forward_headers[{slot!r}]: {name!r} is not a valid "
                                     "header name")


def _recheck(self) -> None:
    """Check the config once more before routes arise from it (B3-14).

    The constructor checks and afterwards holds a **reference** to the config object. Whoever
    changes something in between (`auth.cfg.cookie_samesite = "Strict"`, `auth.cfg.base_url = ""`)
    used to bypass every guard — `TinySesamConfig.validate()` existed for that, nobody
    called it. Here is the last point at which an error is still noticed at startup instead of at the
    first click. The constructor has already issued warnings; here only what would have made
    construction fail counts — and ALL of it: `config_check` including the cookie fields and
    the constructor's bolts (`_bolt`, A2)."""
    error, _ = self.cfg._findings()
    if not error:
        try:
            self._bolt(self.cfg, on_setup=False)
        except ConfigError as e:
            error = [str(e)]
    if error:
        raise ConfigError("The configuration was changed after construction and does not "
                          "work like this:\n  - " + "\n  - ".join(error))


def _oauth_server(self):
    """The OAuth server (T-36) — built on first need, with the pepper keyring (ADR-12)."""
    if self._oauth is None:
        from . import oauth as _oauth_mod
        self._oauth = _oauth_mod.OAuthServer(self, self._pepper_keyring)
        if self.cfg.oauth_service_clients:
            from .oauth_services import ServiceClients
            self._oauth.services = ServiceClients(self._oauth)
    return self._oauth


def _oauth_revoke_user(self, user_id: int, reason: str) -> int:
    """End every connected device of an account (OAuth grants) — also with the switch off, for what is left."""
    if self._oauth is None and not self.store.oauth_user_grant_ids(user_id):
        return 0
    return self._oauth_server().revoke_user(user_id, reason)


def router(self):
    """The FastAPI router with all enabled routes. Mount once, done.

    Checks the config once more beforehand (`_recheck`) — a config broken
    after the constructor fails here with `ConfigError`, not only in operation."""
    self._recheck()
    from .router import build_router
    return build_router(self)


def close(self, timeout: float = 10.0) -> bool:
    """Shut down in order (T-67): refuse new background jobs, let the queued ones finish, close the database.

    The background outboxes (mails, notices, the OIDC re-check) use the database connection from worker
    threads. Closing it under a running job crashed the process (`sqlite3`, B-13); `auth.store.db.close()`
    does exactly that. `close()` first stops all three outboxes from taking jobs (a request still in flight
    that would enqueue one gets its response; the job is logged and dropped), waits up to `timeout` seconds in
    total for the queued ones, and only then closes the connection under the store lock.

    Returns True when everything is closed. If a job is still running at the deadline, the database stays
    open (a crash later would be worse than a connection left to the process end) and the result is False;
    calling again waits once more. Idempotent: after a successful close further calls return True at once.
    For FastAPI use `lifespan`; in a script, `with TinySesam(cfg) as auth:`."""
    if self._closed:
        return True
    end = time.monotonic() + max(0.0, timeout)
    drained = True
    for box in (self._outbox, self._notice_outcome, self._oidc_outcome):
        drained = box.close(max(0.0, end - time.monotonic())) and drained
    if not drained:
        logging.getLogger("tinysesam").warning(
            "close(): background jobs still running after %.1f s — the database stays open", timeout)
        return False
    self.store.close()
    self._closed = True
    return True


def admin_router(self):
    """Standalone admin router (relative paths) — mountable at any prefix / sub-app / port,
    or (admin_ui_enabled=False) only the JSON API for the own panel."""
    self._recheck()
    from .admin import build_admin_router
    return build_admin_router(self)


def _is_secure(self, request: Request) -> bool:
    """Is HTTPS active? (directly, via X-Forwarded-Proto behind a proxy, or localhost)."""
    if request.url.scheme == "https":
        return True
    if request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https":
        return True
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "localhost")


def install_error_pages(self, app):
    """Register themed error pages (opt-in). Browsers get the 'error' page (in the branding),
    API clients JSON; redirects (login/reauth/factor, via Location header) remain redirects."""
    from starlette.exceptions import HTTPException as _HTTPExc
    from starlette.responses import RedirectResponse, JSONResponse

    def _wants_html(request):
        return "text/html" in request.headers.get("accept", "")

    @app.exception_handler(_HTTPExc)
    async def _handle_http(request, exc):
        headers = exc.headers or {}
        loc = headers.get("Location") or headers.get("location")
        if loc:   # our _deny/_deny_stepup/_redirect_factor → pass the redirect through unchanged
            return RedirectResponse(loc, status_code=exc.status_code, headers=headers)
        if _wants_html(request):
            # Starlette's default text ("Not Found") is English — on the page in the language of the
            # installation, where there is a text for it. Own messages remain as they are.
            message = exc.detail
            from http import HTTPStatus as _HS
            try:
                standard = _HS(exc.status_code).phrase
            except ValueError:
                standard = None
            if message == standard and f"error.{exc.status_code}" in _messages_of_language(self):
                message = self.t(f"error.{exc.status_code}")
            return self.render_page("error", status=exc.status_code, request=request,
                                   code=exc.status_code, message=message)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=headers or None)

    @app.exception_handler(Exception)
    async def _handle_500(request, exc):
        if _wants_html(request):
            return self.render_page("error", status=500, request=request, code=500,
                                   message=self.t("error.oops"))
        # The JSON branch bypassed `render_page` and came without any hardening header (A2).
        return self._header_lines(JSONResponse({"detail": "internal server error"}, status_code=500))


def install_https(self, app):
    """HTTPS according to config.https_mode: 'force' → HTTP→HTTPS redirect middleware; 'warn'/'off' →
    also runs WITHOUT a certificate (with 'warn' a panel notice). Returns the mode."""
    if self.cfg.https_mode == "force":
        from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
        app.add_middleware(HTTPSRedirectMiddleware)
        self._install_hsts(app)
    return self.cfg.https_mode


def _install_hsts(self, app) -> None:
    """`Strict-Transport-Security` (`config.hsts`) on every HTTPS response of the app — the
    host app's own routes included, not only TinySesam's (ASVS 3.4.1). Part of
    `install_https` with `https_mode='force'`.

    Only on HTTPS: RFC 6797 §7.2 forbids the header over plain HTTP, and the redirect to HTTPS
    carries none. `setdefault`, so that an app that sets its own value wins."""
    if self.cfg.hsts:
        app.add_middleware(_HSTSMiddleware, value=self.cfg.hsts)



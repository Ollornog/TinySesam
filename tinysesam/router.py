"""FastAPI router: /auth/* — login (password), TOTP 2FA + setup, logout, /me.

The router is **conditional throughout**: almost every route hangs on a config switch — PIN,
resource locks, magic link, registration and e-mail confirmation, password reset,
forward auth, account page, API keys, admin panel and the OIDC/passkey/SAML methods. What a
concrete configuration makes of it is told more reliably by `[r.path for r in app.routes]` than by any
enumeration here.

The method routes depend not on the switch but on the finished, **built** method
(`auth.oidc`, `auth.webauthn`, `auth.saml`): a switch that is set but whose extra or mandatory field
is missing makes construction fail in the constructor already — it never gets here."""
from __future__ import annotations
import secrets
from urllib.parse import urlsplit
from fastapi import APIRouter, Request, Form, HTTPException
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as _StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from . import _shell
from .errors import ConfigError
from . import security
from .store import replacement_name, key_kind_of, name_invalid, norm_email, valid_email
from . import security


async def _response_of_handlers(request: Request, exc: Exception):
    """The response the app's exception handler would build for `exc` — or None.

    The same lookup as Starlette's `ExceptionMiddleware` (along the MRO in the table it
    puts into the scope), so that a handler of the host's own wins as it would without TinySesam.
    """
    from starlette.concurrency import run_in_threadpool
    import inspect
    tables = request.scope.get("starlette.exception_handlers")
    if not tables:
        return None
    h = next((tables[0][k] for k in type(exc).__mro__ if k in tables[0]), None)
    if h is None:
        return None
    if inspect.iscoroutinefunction(h):
        return await h(request, exc)
    return await run_in_threadpool(h, request, exc)


def hardened_route(auth) -> type[APIRoute]:
    """A route class that sends every response through `auth._header_lines`.

    As a route class and not as middleware: TinySesam is a router inside a foreign app.
    A middleware would hit every route of the host too — including its cache rules for static
    files. `include_router` adopts the class per route, so it applies
    to the admin panel under a freely chosen prefix as well.
    """
    class _HardenedRoute(APIRoute):
        def get_route_handler(self):
            inside = super().get_route_handler()

            async def handler(request: Request):
                try:
                    response = await inside(request)
                except _StarletteHTTPException as exc:   # FastAPI's HTTPException inherits from it
                    auth._header_lines_error(exc)
                    raise
                except RequestValidationError as exc:
                    # The 422 returns the input but carries no `headers` into which the
                    # header lines could be put (A2). So build the response here — with exactly the
                    # handler the app registered for it (the host's or FastAPI's
                    # default), so that nothing changes in its content.
                    response = await _response_of_handlers(request, exc)
                    if response is None:
                        raise
                # If the response writes the session (sign-in by any path, sign-out, step-up),
                # the cookies go along under the names from before `__Host-` (H-1). Central here,
                # so that no sign-in path can forget it.
                auth._delete_old_names(request, response)
                return auth._header_lines(response)
            return handler
    return _HardenedRoute


def build_router(auth) -> APIRouter:
    cfg = auth.cfg
    r = APIRouter(tags=["auth"], route_class=hardened_route(auth))

    # ---------- Login (password) ----------
    @r.get("/auth/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "", error: str = "", app: str = "", gate_host: str = "",
                   signed_out: str = ""):
        nxt = auth.safe_next(next, request)
        # Code exchange (T-26): `next` is then a path of the gateway; which app is meant is told by
        # `gate_host`. A name is shown only for a host from `forward_apps` — an invented one stays nameless.
        gh = str(gate_host or "").strip().lower()
        # `app` (T-14) only if a client of that name exists — a freely invented value
        # belongs neither in the button nor in a redirect.
        registry = getattr(auth, "oidc_clients", None)
        app = app if (app and registry is not None and registry.several and registry.known(app)) else ""
        if auth.current_user(request):
            session = request.cookies.get(auth.session_cookie_name) or ""
            destination_host = (urlsplit(nxt).hostname or "").lower() if "://" in nxt else ""
            # T-22: signed out of this application only — show the page, with "Continue as …",
            # instead of sending back (that would be a loop with forward auth).
            if session and destination_host and auth.store.gate_is_signed_out(auth.store.session_hash(session), destination_host):
                u = auth.session_user(request)
                gate_app = auth._forward_app(nxt)
                return auth.render_page("login", request=request, next=nxt, error=error, app=app,
                                        app_name=gate_app["name"], app_icon=gate_app["icon"],
                                        resume_user=(u["display_name"] or u["username"]) if u else "")
            # B-2: signed in, but without a (valid) approval for THIS application, the page sent
            # back to `next` — forward auth sent here again, a loop without end.
            # Only the provider grants the approval, so go there.
            session = request.cookies.get(auth.session_cookie_name) or ""
            if app and session and not auth._oidc_approval_valid(auth.store.session_hash(session), app)[0]:
                return RedirectResponse(f"{auth.browser_path(request, '/auth/oidc/start')}"
                                        f"?next={_q(nxt)}&app={_q(app)}", 303)
            return RedirectResponse(nxt, 303)
        gate_app = auth._forward_app(nxt if "://" in nxt else gh) if ("://" in nxt or gh) else {}
        return auth.render_page("login", request=request, next=nxt, error=error, app=app,
                                app_name=gate_app.get("name", ""), app_icon=gate_app.get("icon"),
                                info=auth.t("login.logged_out") if signed_out == "1" else "")

    @r.post("/auth/login")
    def login_submit(request: Request, username: str = Form(""), password: str = Form(""),
                     next: str = Form(""), remember: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        # One source (0.22.0): the whole flow — CSRF, IP throttle, pre-booking, LDAP fallback,
        # audit and security log, session — lives in `login_password`, the public
        # building block for custom login pages. Here only the result becomes the page. This route calls
        # no inner checker itself (guard in `tests/test_sign_in.py`).
        erg = auth.login_password(request, username, password, next=next,
                                  remember=_remember(cfg, remember), csrf=csrf_tok)
        if erg.reason == "method_disabled":
            raise HTTPException(404, erg.message)
        if not erg:
            # No 422 JSON in the face: the page once more, with a notice.
            return auth.render_page("login", request=request, status=erg.status, next=erg.next_url,
                                    error=erg.message)
        return erg.redirect()   # kind of cookie follows the session (A-2)

    # ---------- TOTP as a factor (2nd step or chain/route factor) ----------
    @r.get("/auth/totp", response_class=HTMLResponse)
    def totp_page(request: Request, next: str = "", error: str = ""):
        nxt = auth.safe_next(next, request)
        # The account from the cookie, as on submit (0.20.1, `session_user`): an API key has
        # no TOTP step here.
        full = auth.session_user(request)
        user = auth.pending_user(request) or full
        if not user:
            return RedirectResponse(auth.browser_path(request, cfg.login_path), 303)
        if not auth.store.has_confirmed_totp(user["id"]):
            # Factor totp required but not set up → to the setup. Allowed
            # for fully signed-in users and for the chain case (see totp_enrollment_user) — otherwise
            # login_chain=["password","totp"] would be a dead end for every account without TOTP.
            if full or auth.totp_enrollment_user(request):
                return RedirectResponse(f"{auth.browser_path(request, '/auth/totp/setup')}?next={_q(nxt)}", 303)
            return RedirectResponse(auth.browser_path(request, cfg.login_path), 303)
        return auth.render_page("totp", request=request, next=nxt, error=error)

    @r.post("/auth/totp")
    def totp_submit(request: Request, code: str = Form(""), next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        # One source (0.22.0): `login_totp` checks (TOTP or one-time code), throttles, books and
        # attaches the factor; here only the result becomes the page.
        erg = auth.login_totp(request, code, next=next, csrf=csrf_tok)
        if erg.reason == "no_session":
            return erg.redirect()                       # to the login page, without cookie
        if not erg:
            return auth.render_page("totp", request=request, status=erg.status, next=erg.next_url,
                                    error=erg.message)
        return erg.redirect()

    # ---------- Set up TOTP (signed-in user) ----------
    def _setup_next(request: Request, next_: str) -> str:
        """Where the setup page leads once TOTP is active (B-8): the given target — without one,
        a voluntary setup (full session) goes back to the account page, if it is on. The mandatory
        setup under the chain keeps the usual fallback (`login_redirect`)."""
        if not next_ and cfg.account_enabled and auth.session_user(request):
            # …in the app frame it came in with (T-91).
            app = auth._frame_app(request)
            return auth.browser_path(request, "/auth/account") + (f"?app={_q(app)}" if app else "")
        return auth.safe_next(next_, request)

    @r.get("/auth/totp/setup", response_class=HTMLResponse)
    def totp_setup(request: Request, next: str = ""):
        u = auth.current_user(request) or auth.totp_enrollment_user(request)
        if not u:
            return RedirectResponse(auth.browser_path(request, cfg.login_path), 303)
        # Factor CREATION is self-service — a session, no API key. Removal had been blocked since
        # R3-3, creation had not: a leaked CI key set up its own
        # TOTP and came back through the full login to the removal routes.
        auth.require_session(request, u)
        # Whoever already has a confirmed second factor must not lose it here — one
        # click on a foreign link was otherwise enough to reset TOTP to "unconfirmed"
        # (finding B2-1). The way to switch leads through the regular disabling
        # (POST /auth/totp/disable, CSRF-protected). `totp_begin` refuses that as well —
        # the guard here only delivers the readable answer instead of a server error.
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        # B-12: a new factor from a FULL session wants a fresh confirmation — the page sends a stale
        # one to the reauth page first and comes back here (path and query). The mandatory setup in a
        # chain (half session, `totp_enrollment_user`) is fresh from the sign-in and not asked.
        if u.get("_via") == "session":
            target = auth._reauth_target(request, str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))
            if target:
                return RedirectResponse(target, 303)
        # This GET writes NOTHING any more. Until the follow-up it called `totp_begin()` unconditionally:
        # for an account without confirmed TOTP every call thereby created a new secret
        # and replaced an attempt in progress — a foreign link invalidated the
        # QR image just scanned and triggered audit lines from outside. The finding text on B2-1
        # demanded both: refuse with confirmed TOTP AND begin only on explicit
        # request (POST with CSRF token). The secret therefore comes into being only in
        # `POST /auth/totp/setup/start`; this page merely shows the button for it.
        return auth.render_page("totp_setup", request=request, data=None, next=_setup_next(request, next))

    @r.post("/auth/totp/setup/start", response_class=HTMLResponse)
    def totp_setup_start(request: Request, next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        """Start the setup explicitly — here (and only here) the secret comes into being."""
        auth.require_csrf(request, csrf_tok)
        u = auth.current_user(request) or auth.totp_enrollment_user(request)
        if not u:
            return RedirectResponse(auth.browser_path(request, cfg.login_path), 303)
        # The same lock as on the GET, and here the more important one: this response carries the
        # TOTP secret in plain text. An API key must not get to see it — via the
        # self-registered factor it would otherwise obtain a fresh session.
        auth.require_session(request, u)
        if u.get("_via") == "session":
            auth._require_fresh(request, u)          # B-12: the secret only for a fresh confirmation
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        return auth.render_page("totp_setup", request=request, data=auth.totp_begin(u["id"]),
                                next=_setup_next(request, next))

    @r.post("/auth/totp/setup")
    def totp_setup_confirm(request: Request, code: str = Form(...), next: str = Form("")):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # Both accounts from the cookie (0.20.1, `session_user`): the enrollment branch below
        # completes the session with `complete_totp`.
        full = auth.session_user(request)
        # Ask before the confirmation — afterwards the account has a confirmed TOTP, and
        # `totp_enrollment_user` says None.
        enrollment = None if full else auth.totp_enrollment_user(request)
        # Without both: an API key gets the refusal with reason (403 `api.needs_session`, as
        # on the GET), whoever shows nothing at all gets the usual refusal of `require_session` (401;
        # only a call with `Accept: text/html` is redirected to sign-in — the form
        # of the page sends via `fetch`, so without).
        u = auth.require_session(request, full or enrollment)
        if full is not None:
            auth._require_fresh(request, full)       # B-12: the same bolt as at /start
        # Like GET and /start (A-4): an active TOTP is not "confirmed once more" here.
        # Otherwise this place would report `totp_enabled` for nothing and incidentally check codes of the
        # active factor with its own attempt bucket.
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        # Throttle, own bucket and log as at every other OTP check (B2-12/R3-6).
        # Own bucket, because setting up is not a sign-in: typos here must not fill the
        # login lockout. Check and book in ONE step as everywhere else
        # (R7-2): with `_is_totp_setup_locked()` beforehand and `_record_login()` afterwards the
        # code check lay in between, and a parallel burst slipped past the limit.
        ip = auth.client_ip(request)
        attempt = (auth._begin_attempt(u["username"], ip, "totp_setup")
                   if auth._rate_ok(ip, login=False) else None)
        if attempt is None:
            raise HTTPException(429, auth.t("api.too_many"))
        ok = auth.totp_confirm(u["id"], code)
        auth._record_login(u["username"], ip, ok, "totp_setup", attempt=attempt)
        if not ok:
            return JSONResponse({"ok": False, "other_sessions": 0})
        # B-9a: the recovery codes come with the factor, shown once on this page. Until now the setup
        # created none, and the account page greeted the fresh 2FA with "only 0 recovery codes left".
        # Nothing in the history asked for that — the codes simply came only from the button.
        # No step-up as at `/auth/totp/recovery` (R3-3): there the codes REPLACE a factor someone
        # else may hold; here the session has just proven the new factor itself (the code was
        # consumed), and whoever holds the secret needs no codes to get in. `totp_begin` already
        # cleared orphaned ones, an API key never gets this far (`require_session`).
        # T-94: `recovery_codes_enabled=False` — no codes, and the page goes straight on (it shows the code box only
        # for a non-empty list).
        codes = auth.generate_recovery_codes(u["id"]) if cfg.recovery_codes_enabled else []
        if not enrollment:
            # B1-7: after a new factor offer to end the other sessions — the number
            # tells the UI whether there is anything to offer.
            # B-8: and where to go afterwards. Without `next` the page stayed on "2FA active".
            return JSONResponse({"ok": True, "next": _setup_next(request, next), "recovery_codes": codes,
                                 "other_sessions": auth.count_other_sessions(request, u)})
        # Mandatory setup under the chain (A-1): the confirmation code IS the TOTP step.
        # It is now consumed; had the user typed it once more at /auth/totp, that would have
        # been a failed attempt — five times, and the login lockout including fail2ban lines
        # would lock the account that has just set itself up correctly.
        auth._record_login(u["username"], ip, True, "totp")
        session_token = request.cookies.get(auth.session_cookie_name)
        renewed = auth.complete_totp(session_token)
        further = renewed or session_token
        # B1-7 here too: enrollment is precisely the case with old sessions (device
        # lost, operator window). Counted at the NEW session — the old, half one was just
        # deleted by `complete_totp` (otherwise the new one would count as "other").
        # Only if the session is thereby full (`renewed`): if the chain has another step
        # (password → totp → pin), it stays half, and ending the other sessions
        # would fail with 401 — the page would have asked, the user agreed, and the lost
        # device would stay signed in. Better no offer then; the account page lists the sessions.
        response = JSONResponse({"ok": True, "next": auth._login_redirect_after(
            request, further, u["id"], auth.safe_next(next, request)), "recovery_codes": codes,
            "other_sessions": auth.count_other_sessions(request, u, token=renewed) if renewed else 0,
            # Boundary d: if the session stays half, the page asks anyway — redeemed at the
            # end of the chain (`/auth/sessions/revoke-after-login`).
            "other_sessions_after": 0 if renewed else auth.count_other_sessions(request, u)})
        if renewed:
            auth.set_cookie(response, renewed)   # also rotates the CSRF token on login
        return response

    @r.post("/auth/totp/disable")
    def totp_off(request: Request):
        # Without this line a <form method=POST> without a body from a foreign page was enough
        # to delete TOTP AND all recovery codes — the second factor gone without a trace.
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # **Factor management requires freshness** (finding R3-3). `current_user()` was enough here
        # so far — with two consequences: (1) a session whose step-up had long expired
        # (every `require(mfa=True)` guard gave it 403) could still
        # remove the second factor. (2) `current_user()` also accepts an **API key**: a leaked
        # machine credential that never provided an interactive factor silently deleted the TOTP and
        # PIN of its owner. `require_mfa()` closes both — for an API key
        # step-up freshness is constructively unreachable (403, `api.stepup_session`).
        u = auth.require_mfa(request)
        auth.totp_disable(u["id"])
        return {"ok": True, "other_sessions": auth.count_other_sessions(request, u)}   # B1-7

    @r.post("/auth/totp/recovery")
    def totp_recovery(request: Request):
        """Generate new one-time recovery codes (only with TOTP set up). Plain text ONLY ONCE."""
        if not cfg.recovery_codes_enabled:
            raise HTTPException(404)      # T-94: switched off — no route that issues codes
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        u = auth.require_mfa(request)   # R3-3: fresh factor confirmation, no API key
        if not auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(400, auth.t("api.totp_first"))
        return {"codes": auth.generate_recovery_codes(u["id"])}

    # ---------- PIN login (personal PIN, only if enabled) ----------
    if cfg.pin_enabled:
        @r.get("/auth/pin", response_class=HTMLResponse)
        def pin_page(request: Request, next: str = "", error: str = ""):
            """PIN entry. For signed-in users (PIN as additional factor of a route) and in the chain step
            after the first factor without a user field; for guests as a standalone page — the
            login page offers the PIN anyway."""
            nxt = auth.safe_next(next, request)
            # As on submit: an API key is a guest. The half session (first factor yes,
            # chain open) counts only if the PIN is its chain step (G7-N1, p2 F1).
            u = auth.session_user(request) or auth._pin_chain_step(request)
            if u:
                return auth.render_page("pin", request=request, next=nxt, error=error, username=u["username"])
            if not cfg.pin_as_first_factor():
                # PIN is no first factor → guests have no business here
                return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(nxt)}", 303)
            return auth.render_page("pin", request=request, next=nxt, error=error)

        @r.post("/auth/pin")
        def pin_submit(request: Request, pin: str = Form(""), username: str = Form(""),
                       next: str = Form(""), remember: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            # One source (0.22.0): which situation (full session, chain step, guest path), throttle,
            # pre-booking into login and PIN bucket, and series live in `login_pin`.
            erg = auth.login_pin(request, pin, username, next=next,
                                 remember=_remember(cfg, remember), csrf=csrf_tok)
            if erg.reason == "method_disabled":
                raise HTTPException(404)
            if not erg:
                ctx = {"next": erg.next_url, "error": erg.message}
                page_html = "login"
                if erg.next_factor == "pin":
                    # The PIN stands behind a provided factor: the same PIN page, without a
                    # name field, with the session's account (full or half).
                    page_html = "pin"
                    account = auth.session_user(request) or auth.pending_user(request)
                    if account:
                        ctx["username"] = account["username"]
                return auth.render_page(page_html, status=erg.status, request=request, **ctx)
            return erg.redirect()

        @r.post("/auth/pin/set")
        async def pin_set(request: Request):
            if auth.session_user(request) is None:
                setup = auth._setup_user(request, "pin")
                if setup is not None:
                    # T-34: the setup pass after a sign-in link. The account has no PIN (the pass
                    # offers only missing factors), the session is fresh from the link — the same
                    # reasoning as `login_fresh()` for the first factor.
                    b = await auth.json_body(request)
                    if not auth._rate_ok(auth.client_ip(request), login=False):
                        raise HTTPException(429, auth.t("api.too_many"))
                    try:
                        auth.set_pin(setup["id"], b.get("pin"))
                    except ValueError as e:
                        raise HTTPException(400, str(e))
                    auth.audit("pin_set", setup["username"], auth.client_ip(request), "setup_pass=1")
                    token = auth._setup_record(request, "pin")
                    return _setup_answer(request, setup["id"], token, str(b.get("next") or ""))
            # R3-3: REPLACING a PIN means exchanging a sign-in factor — only an
            # interactive session with fresh confirmation may do that. An API key gets through here in
            # no case, not even when creating (otherwise the key holder would set the
            # factor of its owner): the bolt therefore stands BEFORE the case distinction
            # and delivers the clear message instead of the freshness excuse.
            u = auth.require_session(request)
            # B-12: the one freshness rule for new access (`_require_fresh`) — the rule below in words.
            # The rule, exactly: `require_mfa()` applies to replacing AND to creating,
            # as soon as the account has anything at all with which it can confirm — even if that
            # is only its password. Because with `pin_login` a PIN is a full
            # first factor: whoever steals a fresh session cookie would otherwise set up
            # an access of their own that outlives the theft. Typing the password once more
            # is the hurdle that prevents exactly that; the account page leads there by itself via
            # `X-TinySesam-Reauth`. Only an account that has nothing at all
            # (purely federated) depends on the age of the sign-in — otherwise setup
            # would be a dead end for it.
            # The FIRST PIN of an account that has nothing with which it could confirm
            # (no password, no PIN, no TOTP — purely federated): `require_mfa()`
            # would be a dead end here, `stepup_options()` is empty and the reauth page
            # would have no field. Creating therefore depends on the age of the sign-in. No
            # `X-TinySesam-Reauth`: the reauth page cannot help this account, a
            # new login can. (An account WITH a PIN always has `stepup_options()`.)
            u = auth._require_fresh(request, u)
            b = await auth.json_body(request)
            try:
                auth.set_pin(u["id"], b.get("pin"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            auth.audit("pin_set", u["username"])
            return {"ok": True, "other_sessions": auth.count_other_sessions(request, u)}   # B1-7

        @r.post("/auth/pin/disable")
        def pin_off(request: Request):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            u = auth.require_mfa(request)   # R3-3: fresh factor confirmation, no API key
            # The line is written by `disable_pin` itself — with account and IP (B5-02). Here stood a
            # second one that wrote the same operation twice into the log.
            auth.disable_pin(u["id"])
            return {"ok": True, "other_sessions": auth.count_other_sessions(request, u)}   # B1-7

    # ---------- Shared resource secret (PIN/passphrase without a user account) ----------
    if cfg.resource_locks_enabled:
        def _res_ctx(row, name, nxt, error=""):
            return dict(name=name, kind=row["kind"], label=row["label"] or name, next=nxt, error=error)

        @r.get("/auth/resource/{name}", response_class=HTMLResponse)
        def resource_page(request: Request, name: str, next: str = "", error: str = ""):
            row = auth.store.get_resource_secret(name)
            if not row:
                raise HTTPException(404, auth.t("api.resource_unknown"))
            nxt = auth.safe_next(next, request)
            if auth.resource_unlocked(request, name):
                return RedirectResponse(nxt, 303)
            return auth.render_page("resource_unlock", request=request, **_res_ctx(row, name, nxt, error))

        @r.post("/auth/resource/{name}")
        def resource_submit(request: Request, name: str, secret: str = Form(""), next: str = Form(""),
                            csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            row = auth.store.get_resource_secret(name)
            if not row:
                raise HTTPException(404, auth.t("api.resource_unknown"))
            nxt = auth.safe_next(next, request)
            ip = auth.client_ip(request)
            pseudo = f"res:{name}"
            # Own bucket (`_is_resource_locked`): EVERY visitor may try the area PIN,
            # and through the login counter these wrong guesses locked, via
            # `ip_attempt_factor`, the sign-in of accounts that had nothing to do with it
            # (three areas of five wrong guesses were enough). Now the area is locked —
            # per area and, because unauthenticated users guess here, still per address as well.
            attempt = auth._begin_attempt(pseudo, ip, "resource") if auth._rate_ok(ip, login=False) else None
            if attempt is None:
                return auth.render_page("resource_unlock", request=request, status=429,
                                        **_res_ctx(row, name, nxt, auth.t("err.retry")))
            if not auth._check_resource(name, secret):
                auth._record_login(pseudo, ip, False, "resource", attempt=attempt)
                return auth.render_page("resource_unlock", request=request, status=401, **_res_ctx(row, name, nxt, auth.t("err.credentials")))
            auth._record_login(pseudo, ip, True, "resource", attempt=attempt)
            resp = RedirectResponse(nxt, 303)
            auth._unlock_resource(request, resp, name)
            auth.audit("resource_unlock", ip=ip, detail=name)
            return resp

    # ---------- Magic link (one-time login by e-mail) ----------
    # Two switches since T-33: `magiclink_enabled` mounts the redemption (links from mail, from the
    # admin panel, from app code), `magiclink_self_request` the request by mail. Without the
    # latter `/auth/magic/request` does not exist (404) — an issued link still redeems.
    if cfg.magiclink_enabled and cfg.magiclink_self_request:
        @r.get("/auth/magic/request", response_class=HTMLResponse)
        def magic_request_page(request: Request, next: str = ""):
            return auth.render_page("magic_request", request=request, next=auth.safe_next(next, request), sent=False, error="")

        @r.post("/auth/magic/request", response_class=HTMLResponse)
        def magic_request(request: Request, email: str = Form(""), next: str = Form(""),
                          csrf_tok: str = Form("", alias="_csrf")):
            # Without this check a foreign page could, via the victim's browser, have
            # sign-in links sent to arbitrary addresses — the only
            # state-changing route that got through without a token.
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next, request)
            ip = auth.client_ip(request)
            if not auth._rate_ok(ip):
                return auth.render_page("magic_request", request=request, status=429, next=nxt, sent=False,
                                        error=auth.t("err.rate"))
            # Without a trustworthy public address NO mail goes out: the link
            # would come from the requester's Host header, and for a mail to a
            # foreign mailbox the attacker sets that (R4-01).
            #
            # `require_public_base` and not `public_base`: the check stood here already, but
            # the empty case only wrote an audit line and fell below into the success page —
            # HTTP 200, "mail is on its way", no mail. The generic answer is right against
            # user enumeration and here concealed a total failure. A missing
            # `base_url` is not address-related: the abort reveals nothing about the mailbox,
            # and `config_check` prevents this state at construction anyway.
            base = _mail_base(auth, request)
            address = email.strip()

            # T-104: the frame the request stands in travels in the token (the form posts with `?app=`, else `next`).
            frame = (auth._frame(request, {"next": nxt}) or {}).get("host", "")

            def _dispatch():
                try:
                    auth.send_login_link(address, base, nxt, app=frame)
                except Exception:
                    auth.audit("magic_send_error", detail=address)   # do not leak errors to the outside
            # always the same answer (no user enumeration) — and at the same time: sending
            # happens only after the response (R4-05), in the own mail worker (B6-6).
            return auth.after_response(
                auth.render_page("magic_request", request=request, next=nxt, sent=True, error=""), _dispatch)

    if cfg.magiclink_enabled:
        def _no_request_route(token):
            # Without the self-request `/auth/magic/request` must be what it is: absent (404). The
            # pattern below would otherwise catch it as the token "request" and answer "link
            # invalid" (400) — plus a `token_invalid` line for a plain page visit. A real token
            # (43 characters from `token_urlsafe(32)`) is never this word.
            if token == "request":
                raise HTTPException(404)

        # R4-02: the link from the mail leads to a confirmation page, only its POST redeems.
        # Mail scanners (safe links, virus checkers, preview bots) open every link via GET —
        # so far this very fetch consumed the token, and the user landed on "link
        # invalid". A GET that signs in also signs in everyone who opens the link,
        # the scanner included. The page only checks (`peek_magic`), redeeming happens with a CSRF token.
        @r.get("/auth/magic/{token}", response_class=HTMLResponse)
        def magic_confirm(request: Request, token: str):
            """Only the sign-in link now. E-mail confirmation and invitation have had their own
            endpoints since 0.16 — otherwise disabling the magic link took both along."""
            _no_request_route(token)
            peeked = auth.peek_magic(token, purpose="login")
            if not peeked or auth._app_link_refused(peeked):
                auth._token_rejected("login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            # T-104: the page stands in the frame the link was asked for in (`frame` in the token).
            framed = auth._frame_of((peeked.get("payload") or {}).get("frame"))
            return auth.render_page("magic_confirm", request=request, purpose="login",
                                    action=auth.browser_path(request, f"/auth/magic/{_q(token)}"),
                                    **({"frame": framed} if framed else {}))

        @r.post("/auth/magic/{token}")
        def magic_redeem(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            _no_request_route(token)
            auth.require_csrf(request, csrf_tok)
            data = auth.redeem_magic(token, purpose="login")
            if not data or not data.get("user_id"):
                auth._token_rejected("login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            # T-34: "a link only for the first sign-in". Checked at redemption — the account may have
            # changed since the link was issued. The token is spent either way (single use).
            if not auth._link_allowed(data["user_id"]):
                auth.audit("magic_first_login_only", auth._account_name(data["user_id"]),
                           auth.client_ip(request))
                return auth.render_page("magic_invalid", request=request, status=403,
                                        message=auth.t("magic.first_only"))
            # A link an application obtained (account API) for an account that is no longer wholly the application's —
            # a foreign role, admin, delegate, released — or that someone signed in to since: spent, nobody signed in.
            if auth._app_link_refused(data):
                auth.audit("magic_app_link_refused", auth._account_name(data["user_id"]), auth.client_ip(request),
                           f"app={security.for_log(str((data.get('payload') or {}).get('app')))}")
                return auth.render_page("magic_invalid", request=request, status=403)
            return _login_after_token(auth, request, data["user_id"],
                                     auth.safe_next((data.get("payload") or {}).get("next") or "", request),
                                     link=True)

    # ---------- Cross-device sign-in (QR code, T-33) ----------
    if cfg.qr_login_enabled:
        def _qr_page(request, data, status=200, error=""):
            return auth.render_page("qr_login", request=request, status=status, error=error,
                                    code=data["code"], secret=data["secret"],
                                    expires_at=data["expires_at"], approve_url=data.get("approve_url") or "",
                                    qr=data.get("qr"), next=data.get("next") or "/", match=data.get("match") or "")

        @r.post("/auth/qr/start", response_class=HTMLResponse)
        def qr_start(request: Request, next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            """The new device opens a request — a POST, so that no foreign page and no prefetch writes
            rows (as with `/auth/totp/setup/start`, B2-1)."""
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next, request)
            if not auth._rate_ok(auth.client_ip(request), login=False):
                return auth.render_page("login", request=request, status=429, next=nxt, error=auth.t("err.rate"))
            data = auth._qr_start(request, nxt)
            data["next"] = nxt
            return _qr_page(request, data)

        @r.post("/auth/qr/status")
        def qr_status(request: Request, code: str = Form(""), secret: str = Form("")):
            """Poll of the new device: `pending`, `approved` or `invalid` (expired, used, denied, or
            not this device's request). Read-only; the secret goes in the body, never in the URL."""
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            # T-44 (RFC 10027 §6.1.11): polling has its own bucket — the page asks every two seconds,
            # the sign-in limit (`_rate_ok`) would trip after a minute. Generous for several devices
            # behind one address, tight enough that nobody hammers the table.
            ip = auth.client_ip(request)
            if not auth.rl.allow(f"qr_status:{security.ip_bucket(ip)}", _QR_STATUS_PER_MINUTE, 60):
                auth._rejected(None, ip, "qr_status_ratelimit", login=False)
                return JSONResponse({"state": "pending", "detail": auth.t("api.too_many")}, status_code=429)
            info = auth._qr_own(code, secret)
            if info is None:
                return JSONResponse({"state": "invalid"})
            return JSONResponse({"state": "approved" if info["user_id"] is not None else "pending"})

        @r.post("/auth/qr/finish")
        def qr_finish(request: Request, code: str = Form(""), secret: str = Form(""),
                      csrf_tok: str = Form("", alias="_csrf")):
            """The new device collects its session — only with the secret of ITS request."""
            auth.require_csrf(request, csrf_tok)
            ip = auth.client_ip(request)
            if not auth._rate_ok(ip, login=False):
                return auth.render_page("magic_invalid", request=request, status=429)
            own = auth._qr_own(code, secret)
            if own is not None and own["user_id"] is None:
                # Not approved yet: the same page again, with the same request.
                again = {"code": own["code"], "secret": secret, "expires_at": own["expires_at"],
                         "next": own["next"], "match": own.get("match") or "", **auth._qr_links(own["code"])}
                return _qr_page(request, again, status=409, error=auth.t("qr.not_yet"))
            data = auth._qr_redeem(code, secret)
            if not data:
                auth._token_rejected("qr_login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            auth.audit("qr_login", auth._account_name(data["user_id"]), ip, f"approved_from_device_ip={data['ip']}")
            # T-47: the holder learns that a device came in through an approval — hook, mail, activity.
            auth._security_event("device_signed_in", data["user_id"], method="qr_login", ip=ip,
                                 agent=str(data.get("agent") or "")[:200])
            return _login_after_token(auth, request, data["user_id"], auth.safe_next(data["next"], request),
                                     link=True)

        @r.get("/auth/qr/approve", response_class=HTMLResponse)
        def qr_approve_page(request: Request, code: str = ""):
            """The signed-in device: shows WHO asks (device, IP, time) before anything is approved."""
            u = auth.session_user(request)
            if not u:
                back = auth.browser_path(request, "/auth/qr/approve") + (f"?code={_q(code)}" if code else "")
                return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(back)}", 303)
            if not code:
                return auth.render_page("qr_approve", request=request, user=u, request_info=None, code="")
            if not auth._rate_ok(auth.client_ip(request), login=False):
                return auth.render_page("magic_invalid", request=request, status=429)
            info = auth._qr_peek(code)
            if not info or info["user_id"] is not None:
                auth._token_rejected("qr_login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            if not auth._qr_may_approve(u):
                return auth.render_page("qr_approve", request=request, status=403, user=u, request_info=None,
                                        code="", error=auth.t("qr.needs_second_factor"))
            if auth._fresh_enough(request, u) == "relogin":
                return auth.render_page("qr_approve", request=request, status=403, user=u, request_info=None,
                                        code="", error=auth.t("api.stepup_relogin"))
            # B-12: approving signs in a device — a fresh confirmation first, then back to this page.
            target = auth._reauth_target(request, auth.browser_path(request, "/auth/qr/approve") + f"?code={_q(info['code'])}")
            if target:
                return RedirectResponse(target, 303)
            return auth.render_page("qr_approve", request=request, user=u, request_info=info, code=info["code"])

        def _qr_decide(request, code, csrf_tok, approve: bool, match: str = ""):
            auth.require_csrf(request, csrf_tok)
            # Only a FULL interactive session approves: no API key, no half session (chain step
            # open) — `session_user` yields None for both. A foreign session cannot approve for
            # this account, and the approval of an attacker's code by the victim needs the
            # victim's click on a page that names the asking device.
            u = auth.session_user(request)
            if not u:
                raise HTTPException(401, auth.t("api.qr_needs_session"))
            if not auth._rate_ok(auth.client_ip(request), login=False):
                return auth.render_page("magic_invalid", request=request, status=429)
            if approve:
                # T-44: only an account with a second factor (switch), only with a fresh confirmation
                # (B-12), only with the number from the other screen. Refusing needs none of it.
                if not auth._qr_may_approve(u):
                    raise HTTPException(403, auth.t("qr.needs_second_factor"))
                auth._require_fresh(request, u)
                outcome = auth._qr_approve(code, u, match)
                if outcome == "mismatch":
                    return auth.render_page("qr_approve", request=request, status=400, user=u, request_info=None,
                                            code="", error=auth.t("qr.mismatch"))
                done = outcome == "ok"
            else:
                done = auth._qr_deny(code, u)
            if not done:
                auth._token_rejected("qr_login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("qr_approve", request=request, user=u, request_info=None, code="",
                                    decided="approved" if approve else "denied")

        @r.post("/auth/qr/approve", response_class=HTMLResponse)
        def qr_approve(request: Request, code: str = Form(""), match: str = Form(""),
                       csrf_tok: str = Form("", alias="_csrf")):
            return _qr_decide(request, code, csrf_tok, True, match)

        @r.post("/auth/qr/deny", response_class=HTMLResponse)
        def qr_deny(request: Request, code: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            return _qr_decide(request, code, csrf_tok, False)

    # ---------- Setup pass after a sign-in link (T-34) ----------
    # Only links open it (mailed, admin-issued, app-issued, cross-device), so the page exists only
    # with them. It shows what the chain still needs and the account lacks; the setup routes it
    # posts to (`/auth/password/set`, `/auth/pin/set`, `/auth/passkey/register/*`,
    # `/auth/totp/setup`) accept the half session for exactly the offered factor.
    # T-46: the same page asks a half session for an own password when it signed in with a start
    # secret from the administrator — so it exists wherever passwords do.
    if cfg.magiclink_enabled or cfg.qr_login_enabled or cfg.password_enabled:
        @r.get("/auth/setup", response_class=HTMLResponse)
        def account_setup(request: Request, next: str = ""):
            nxt = auth.safe_next(next, request)
            if auth.session_user(request):
                return RedirectResponse(nxt, 303)            # already fully signed in
            s = auth._session_from_request(request)
            if auth._renew_session(s):
                return auth.render_page("account_setup", request=request, options=["password"], left=1,
                                        next=nxt, pin_min=cfg.pin_min_length, renew=True)
            if not auth._setup_session(s):
                # No pass (none opened, expired, account locked): the regular sign-in.
                return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(nxt)}", 303)
            offer = auth._setup_offer(request)
            if offer is None:
                # Nothing to set up right now: an existing factor first, or a step to provide.
                done = __import__("json").loads(s["factors_done"] or "[]")
                step = auth._next_login_step(s["user_id"], done, setup=True)
                target = auth._factor_entry(step, nxt) if step and step != "setup" else \
                    f"{cfg.login_path}?next={_q(nxt)}"
                return RedirectResponse(auth.browser_path(request, target), 303)
            _u, options, _index, left = offer
            return auth.render_page("account_setup", request=request, options=options, left=left,
                                    next=nxt, pin_min=cfg.pin_min_length)

    # ---------- E-mail confirmation (own endpoint, independent of the magic link) ----------
    if cfg.signup_verify_email:
        @r.get("/auth/verify/{token}", response_class=HTMLResponse)
        def verify_confirm(request: Request, token: str):
            """Confirmation page instead of redeeming via GET — rationale at `/auth/magic/{token}` (R4-02)."""
            peeked = auth.peek_magic(token, purpose="verify_email")
            if not peeked:
                auth._token_rejected("verify_email", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            framed = auth._frame_of((peeked.get("payload") or {}).get("frame"))    # T-152: the frame of the request
            return auth.render_page("magic_confirm", request=request, purpose="verify_email",
                                    action=auth.browser_path(request, f"/auth/verify/{_q(token)}"),
                                    **({"frame": framed} if framed else {}))

        @r.post("/auth/verify/{token}")
        def verify_email(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            data = auth.redeem_magic(token, purpose="verify_email")
            if not data or not data.get("user_id"):
                auth._token_rejected("verify_email", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            uid = data["user_id"]
            # Lift only the block of the PENDING confirmation, never the operator's (H-18,
            # second attack round). Until then this route set `disabled` unconditionally to 0:
            # if the token only came into being after a block in the panel — an app pushes
            # `send_verify_email` into the outbox —, the block found nothing to discard, and
            # the link unblocked the account again and signed in.
            if not auth.store.confirmation_enable(uid):
                account = auth._account_name(uid)
                if account is None:                        # account deleted in the meantime
                    auth._token_rejected("verify_email", request)
                    return auth.render_page("magic_invalid", request=request, status=400)
                auth.audit("verify_blocked", account, auth.client_ip(request),
                           "account locked by operator")
                return auth.render_page("magic_invalid", request=request, status=403)
            # The redeemed link vouches for the address it went to — as long as it is still the account's
            # (it has not vouched for an address changed in the meantime). Before the sign-in
            # below: there `_maybe_promote_admin` decides about the note on the account.
            account_line = auth.store.get_user(uid)
            if (account_line is not None and account_line["email"] and data.get("email")
                    and norm_email(data.get("email")) == account_line["email"]):
                auth.store.set_email_verified(uid, True)
            # Account and IP belong in the line (B5-02): here an account is unblocked, and
            # without a name `tinysesam audit --user X` did not find the operation.
            auth.audit("email_verified", auth._account_name(uid), auth.client_ip(request),
                       data.get("email"))
            return _login_after_token(auth, request, uid, auth.safe_next("", request))

    # ---------- Invitation (own endpoint; the token is consumed only at registration) ----------
    if cfg.allow_signup:
        @r.get("/auth/invite/{token}")
        def invite_redeem(request: Request, token: str):
            peeked = auth.peek_magic(token, purpose="invite")
            if not peeked:
                auth._token_rejected("invite", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            # T-152: the registration page stands in the frame the invitation names (`frame` in the token).
            framed = auth._frame_of((peeked.get("payload") or {}).get("frame"))
            app_q = f"&app={_q(framed['host'])}" if framed else ""
            return RedirectResponse(f"{auth.browser_path(request, '/auth/register')}?invite={_q(token)}{app_q}", 303)

    # ---------- First admin via one-time token (only as long as there is no admin) ----------
    @r.get("/auth/claim-admin", response_class=HTMLResponse)
    def claim_admin(request: Request, token: str = ""):
        # The account comes from the SESSION, never from an API key: `current_user()` fell back to a key, and a
        # machine key — a service account's, too — plus the token made that account admin and owner. A service
        # account cannot sign in and its keys never carry the flag (R6-5): the instance then had an admin nobody
        # could be, and the first-admin path was closed for good.
        u = auth.session_user(request)
        if not u:
            if cfg.apikey_enabled and auth._extract_api_key(request):
                raise HTTPException(403, auth.t("api.needs_session"))
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={auth.browser_path(request, '/auth/claim-admin')}?token={_q(token)}", 303)
        if auth.admin_exists():
            raise HTTPException(404)          # no hint that the route once existed
        # Admin and owner are the largest new access there is (B-12): only from a fresh confirmation. A stale
        # session goes to the confirmation page and comes back here; one without anything to confirm with signs
        # in again. Right after the sign-in the route asks for, the session is fresh — nothing more is asked.
        target = auth._reauth_target(request, str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))
        if target:
            return RedirectResponse(target, 303)
        if auth._fresh_enough(request, u):
            raise HTTPException(403, auth.t("api.stepup_relogin"))
        # Throttled and logged (B5-16): until T-13 a signed-in account could guess here
        # as often as it liked, and no wrong guess left a trace. The token has 192 bits,
        # so guessing is hopeless — but whoever tries should be in the log, namely
        # as `failed verification` (no sign-in attempt, see `security.LOG_CHECK`).
        ip = auth.client_ip(request)
        if not auth._rate_ok(ip, login=False):
            raise HTTPException(429, auth.t("api.too_many"))
        if not auth._consume_admin_claim(token, u):
            auth._admin_claim_failure(u["username"], ip)
            raise HTTPException(403, auth.t("err.claim"))
        return RedirectResponse(auth.browser_path(request, cfg.admin_path), 303)

    # ---------- Step-up / reauth (sudo freshness for mfa=True guards) ----------
    def _only_session(request: Request):
        """The account whose session is confirmed here — from the session, never from an API key (0.20.1).

        The route checked the account's factor from `current_user()` and then refreshed the
        session from the cookie. With a HALF session (first factor yes, TOTP open)
        `current_user()` falls back to the API key — the key's account was then checked, and the session from the cookie
        was made full: someone else's half session became full with one's own
        key and one's own password, and in one's own account machine key and password replaced
        the second factor (including the admin flag, which the key alone does not carry). Now the
        account comes from `session_user()` — the FULL session of this very cookie, the same one the
        step-up refreshes. A key can never reach freshness anyway (`stepup_fresh`); if the
        request shows one without a session, the answer says so (403) instead of redirecting
        to the login page. Only for the page (GET) now: submitting has gone through `confirm_*` since 0.22.0,
        and the same rule stands there (`TinySesam._only_with_session`).
        """
        u = auth.session_user(request)
        if u is None and cfg.apikey_enabled and auth._extract_api_key(request):
            raise HTTPException(403, auth.t("api.stepup_session"))
        return u

    @r.get("/auth/reauth", response_class=HTMLResponse)
    def reauth_page(request: Request, next: str = "", error: str = ""):
        u = _only_session(request)
        if not u:
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(auth.safe_next(next, request))}", 303)
        methods = auth.stepup_options(u)
        # An empty list means `stepup_strict=True` and nothing suitable set up. Without a message of its own
        # there would be a page without a single input field here — the user would not see what
        # is expected of them.
        # Two empty cases (T-45): `stepup_strict` wants a method the account has not set up — then it
        # sets it up; or the account has nothing to confirm with at all (purely federated, passkey
        # only) — then only a new sign-in makes the session fresh, and the page says so.
        none_text = "err.stepup_none" if (cfg.stepup_strict and cfg.stepup_methods) else "err.stepup_relogin"
        # T-49: an account linked to the provider can confirm there; then the page no longer says "sign out and in".
        via_provider = auth._confirms_at_provider(u)
        if not methods and via_provider and none_text == "err.stepup_relogin":
            none_text = "err.stepup_provider"
        return auth.render_page("reauth", request=request, next=auth.safe_next(next, request),
                                error=error or ("" if methods else auth.t(none_text)),
                                username=u["username"], methods=methods, reauth_oidc=auth._confirms_at_oidc(u),
                                reauth_saml=auth._confirms_at_saml(u))

    @r.post("/auth/reauth")
    def reauth_submit(request: Request, code: str = Form(""), password: str = Form(""), pin: str = Form(""),
                      next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        # One source (0.22.0): CSRF, the session (never an API key), the offered methods,
        # throttle, pre-booking in its own bucket, audit and security log, freshness and new token
        # live in `confirm_totp`/`confirm_pin`/`confirm_password`, the public building blocks for
        # custom step-up pages. Here only the choice is made which field is filled in — in the
        # order of the page —, and the result becomes the page. This route calls no inner
        # checker itself (guard in `tests/test_confirm.py`).
        if code:
            erg = auth.confirm_totp(request, code, next=next, csrf=csrf_tok)
        elif pin:
            erg = auth.confirm_pin(request, pin, next=next, csrf=csrf_tok)
        else:
            erg = auth.confirm_password(request, password, next=next, csrf=csrf_tok)
        if erg.reason == "no_session":
            if erg.status == 403:           # an API key instead of a session (0.20.1)
                raise HTTPException(403, erg.message)
            return erg.redirect()           # to the login page, without cookie
        if not erg:
            # The page once more, with the methods of this account (for display only).
            u = auth.session_user(request)
            return auth.render_page("reauth", request=request, status=erg.status, next=erg.next_url,
                                    username=u["username"] if u else "",
                                    methods=auth.stepup_options(u) if u else [], error=erg.message,
                                    reauth_oidc=bool(u and auth._confirms_at_oidc(u)),
                                    reauth_saml=bool(u and auth._confirms_at_saml(u)))
        return erg.redirect()               # to next, with the renewed session cookie

    # ---------- Forgot / reset password (needs a mailer, NOT the magic link) ----------
    if cfg.password_reset_enabled:
        @r.get("/auth/forgot", response_class=HTMLResponse)
        def forgot_page(request: Request):
            return auth.render_page("forgot", request=request, sent=False, error="")

        @r.post("/auth/forgot", response_class=HTMLResponse)
        def forgot_submit(request: Request, email: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            ip = auth.client_ip(request)
            if not auth._rate_ok(ip):
                return auth.render_page("forgot", request=request, status=429, sent=False, error=auth.t("err.rate"))
            base = _mail_base(auth, request)   # fail closed, see /auth/magic/request
            address = email.strip()

            frame = (auth._frame(request) or {}).get("host", "")    # T-104: the frame travels in the token

            def _dispatch():
                try:
                    auth.send_password_reset(address, base, app=frame)
                except Exception:
                    auth.audit("reset_send_error", detail=address)
            # generic (no enumeration), sending after the response (R4-05/B6-6)
            return auth.after_response(auth.render_page("forgot", request=request, sent=True, error=""),
                                         _dispatch)

        @r.get("/auth/reset", response_class=HTMLResponse)
        def reset_page(request: Request, token: str = ""):
            peeked = auth.peek_magic(token, purpose="reset_password")
            if not peeked:
                # Without a token (bookmark, crawler) this is no presented link — no entry,
                # otherwise the security log would report a wrong guess that never happened (A3).
                if token:
                    auth._token_rejected("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            framed = auth._frame_of((peeked.get("payload") or {}).get("frame"))    # T-104: the frame of the request
            return auth.render_page("reset", request=request, token=token, error="",
                                    **({"frame": framed} if framed else {}))

        @r.post("/auth/reset", response_class=HTMLResponse)
        def reset_submit(request: Request, token: str = Form(""), password: str = Form(""),
                         csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            # The rule needs the account (context words) — so look it up first, WITHOUT consuming the token:
            # a rejected password should not invalidate the link.
            beforehand = auth.peek_magic(token, purpose="reset_password") or {}
            if not beforehand.get("user_id"):
                # A dead link first (A-8): otherwise with an expired link and weak
                # password it said "too easy", and only the second attempt revealed that the link no
                # longer applies. Nothing new is revealed by it — the GET says the same.
                # And the same trace as the GET (B5-18, integration finding 4): here EVERY dead
                # token returns — guessed, expired, already redeemed. The call behind
                # `redeem_magic` below reaches only the race between peek and redeem;
                # alone, it would have let reset tokens be probed by POST without an audit and
                # fail2ban line. Without a token no presented link (A3).
                if token:
                    auth._token_rejected("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            account = auth.store.get_user(beforehand["user_id"])
            defect = auth.password_policy_error(password, username=account["username"] if account else None,
                                          email=account["email"] if account else None)
            if defect:
                return auth.render_page("reset", request=request, status=400, token=token, error=defect)
            data = auth.redeem_magic(token, purpose="reset_password")   # consume now
            if not data or not data.get("user_id"):
                auth._token_rejected("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            uid = data["user_id"]
            auth.set_password(uid, password)
            auth.store.delete_user_sessions(uid)   # end all old sessions
            # The reset lifts the password block (R4-13). Before, it set the password
            # and left the failed attempts standing: whoever had locked themselves out and took the
            # intended path stood afterwards with the NEW password before the same 429.
            # Thus the reset is the way out of the block that does not depend on it (H-10).
            away = auth.lift_lockout(uid, methods=("password",))
            # And the API keys (R4-14). Whoever resets their password via "forgot" has lost their
            # account or fears it is taken over — the same case as the
            # admin reset, which has revoked the keys since 0.18.0. A key is a second,
            # equivalent sign-in; had it stayed valid, the reset would only have closed
            # the front door. (The change on the account page leaves them on purpose — there
            # the holder signs in with the old password, that is a routine change.)
            keys = auth._keys_revoked(uid, "password_reset")
            # And all open links (self-service attack round, finding 1): an address change
            # that an intruder requested from their session otherwise survived the reset —
            # the link lies in THEIR mailbox, one click later, and the next reset would go to them.
            links = auth.store.revoke_user_magic_tokens(uid)
            auth.audit("password_reset", auth._account_name(uid), auth.client_ip(request),
                       f"uid={uid} failed_attempts_discarded={away}"
                       + (f" api_keys_revoked={keys}" if keys else "")
                       + (f" links_revoked={links}" if links else ""))
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(auth.browser_path(request, '/'))}", 303)

    # ---------- Registration (only if allow_signup) ----------
    if cfg.allow_signup:
        def _reg_ctx(nxt, invite="", email="", error="", **extra):
            return dict(next=nxt, invite=invite, email=email, error=error,
                        invite_only=cfg.signup_invite_only, **extra)

        @r.get("/auth/register", response_class=HTMLResponse)
        def register_page(request: Request, next: str = "", invite: str = ""):
            nxt = auth.safe_next(next, request)
            if auth.current_user(request):
                return RedirectResponse(nxt, 303)
            inv = auth.peek_magic(invite, purpose="invite") if invite else None
            if invite and not inv:
                # The same trace as /auth/invite/<t> and the POST (B5-18): the page answers
                # differently depending on the token (403 or the pre-filled address) — without this line
                # invitation tokens could be probed silently here.
                auth._token_rejected("invite", request)
            if cfg.signup_invite_only and not inv:
                return auth.render_page("register", request=request, status=403,
                                        **_reg_ctx(nxt, error=auth.t("err.invite_required")))
            return auth.render_page("register", request=request, **_reg_ctx(nxt, invite=invite, email=(inv or {}).get("email") or ""))

        @r.post("/auth/register", response_class=HTMLResponse)
        def register_submit(request: Request, password: str = Form(""), username: str = Form(""),
                            email: str = Form(""), next: str = Form(""), invite: str = Form(""),
                            csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next, request)
            ip = auth.client_ip(request)
            if not auth._rate_ok(ip):
                return auth.render_page("register", request=request, status=429, **_reg_ctx(nxt, invite=invite, email=email,
                                        error=auth.t("err.rate")))
            inv = auth.peek_magic(invite, purpose="invite") if invite else None
            if invite and not inv:
                auth._token_rejected("invite", request)
            if cfg.signup_invite_only and not inv:
                return auth.render_page("register", request=request, status=403,
                                        **_reg_ctx(nxt, error=auth.t("err.invite_required")))
            username = username.strip()
            def err(msg, status=400):
                return auth.render_page("register", request=request, status=status,
                                        **_reg_ctx(nxt, invite=invite, email=email, error=msg))
            if not password:
                return err(auth.t("err.required"))
            defect = auth.password_policy_error(password, username=username, email=email)
            if defect:
                return err(defect)
            roles, is_admin = list(cfg.signup_default_roles), False
            email_final = norm_email(email)
            if inv:
                roles = (inv.get("payload") or {}).get("roles") or []
                is_admin = bool((inv.get("payload") or {}).get("is_admin"))
                email_final = norm_email(inv.get("email")) or email_final
            # E-mail is the login identifier → mandatory, plausible and unique
            if (cfg.signup_require_email or cfg.login_identifier == "email") and not email_final:
                return err(auth.t("err.email_required"))
            if email_final and not valid_email(email_final):
                return err(auth.t("err.email_invalid"))
            # Confirmation required but no mailer? Then do NOT silently wave it through.
            # Stands before the taken check: it does not depend on the address and reveals nothing.
            verify = cfg.signup_verify_email and not inv
            if verify and not auth.mail_configured():
                return err(auth.t("err.verify_no_mailer"), 500)
            # Check before creating, not after: otherwise a deactivated account would arise
            # that, for lack of a confirmation mail, can never be unblocked.
            verify_base = _mail_base(auth, request) if verify else ""
            # In e-mail mode there is no username field — the address IS the identifier.
            if cfg.login_identifier == "email":
                username = email_final or ""
            if not username:
                return err(auth.t("err.username_required"))
            if name_invalid(username):
                return err(auth.t("err.username_invalid"))
            # Username = one's own address? Then the address check below covers both.
            name_is_address = bool(email_final) and norm_email(username) == email_final
            # With confirmation a username must not be a FOREIGN address (attack A1): the
            # name check also searches the addresses crosswise and would have revealed with 409
            # that the address exists — R4-03 would be bypassed via the name field.
            if verify and "@" in username and not name_is_address:
                return err(auth.t("err.username_is_address"))
            # Check crosswise: username and e-mail are ONE identifier space (finding R4-12).
            # An address that already serves as another account's username is taken —
            # otherwise the registration occupies that account's login identifier and locks them out.
            # The name comes BEFORE the address (attack A1): the other way round a known,
            # taken name (`admin`) plus target address was an oracle — taken address 200,
            # free address 409 username_taken. A taken name is visible anyway (the
            # user has to choose another); now the answer to it no longer depends on the address.
            if not name_is_address and auth.identifier_taken(username):
                return err(auth.t("err.username_taken"), 409)
            if email_final and auth.identifier_taken(email_final):
                if verify:
                    # R4-03: with confirmation a taken address answers like a free one —
                    # 409 and "e-mail taken" revealed to anyone which addresses have an
                    # account. The holder gets a notice instead. Without confirmation
                    # that is not possible: there the success case signs in immediately, so the answer
                    # necessarily differs.
                    #
                    # The username is claimed just as in real creation (A1,
                    # second variant): a blocked placeholder without an address, with a never
                    # sent confirmation token. Otherwise the second registration of the
                    # same name revealed via 409 whether the first had created an account — that is, whether
                    # the address was free. `gc()` removes the placeholder when the
                    # token expires, just like a never-confirmed real account (R4-09). Creating
                    # including the password hash also equalizes the running time.
                    # If the name is the address (always with login_identifier='email'), the name
                    # itself is taken — the placeholder then gets a random name. Until
                    # 2026-09-24 this branch wrote only the audit line, the free one however account,
                    # block and token: measurable in the response time, an oracle "address taken?"
                    # (T-13, B1-12 / ASVS 6.3.8). Now the same work in both branches; `gc()`
                    # clears the placeholder when its token expires (R4-09).
                    try:
                        placeholder = auth.create_user(
                            f"reserved-{secrets.token_hex(6)}" if name_is_address else username,
                            password=password, roles=[], self_chosen_name=True)
                    except ConfigError:
                        # Race: the name has been taken since the check above (G12c) — the same
                        # answer the check would now give.
                        return err(auth.t("err.username_taken"), 409)
                    auth.store.set_disabled(placeholder, True)
                    auth.create_magic_token("verify_email", user_id=placeholder)
                    address = email_final

                    def _notice():
                        try:
                            auth._send_signup_notice(address, verify_base)
                        except Exception:
                            auth.audit("signup_notice_error", detail=address)
                    auth.audit("signup_taken", username, ip, detail=address)
                    return auth.after_response(
                        auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True)),
                        _notice)
                return err(auth.t("err.email_taken"), 409)
            # The address is vouched for here only if it comes from the invitation — the
            # admin sent that to exactly this mailbox. Typed in, it is a claim: with a
            # confirmation requirement the redeemed link provides the proof (`/auth/verify`), without
            # one never. Until schema 10 the default "vouched" stood here, and the deletion by
            # an admin therefore also removed the foreign-typed address from rows from before
            # creation — the admin's invitation, the failed attempts of the real holder
            # (`Store.remove_account`). Rights do not depend on it: an allowlist address
            # requires confirmation anyway with open registration (constructor guard).
            try:
                # The person typed the name themselves, even with an invitation: it says nothing
                # about who is called that in the directory — LDAP/SAML never bind this account via
                # it (G2-N).
                uid = auth.create_user(username, password=password, is_admin=is_admin, roles=roles,
                                       email=email_final or None,
                                       email_verified=bool(inv and norm_email(inv.get("email"))),
                                       self_chosen_name=True)
            except ConfigError as e:
                # Race (G12c): between the checks above and creation a
                # concurrent request has claimed the identifier, and the database rejects. The same
                # answers as above — until then a 500. A taken name stays visible; a
                # taken address with confirmation requirement gets the neutral page (R4-03), without
                # it 409.
                if getattr(e, "field", None) == "username" and not name_is_address:
                    return err(auth.t("err.username_taken"), 409)
                if verify:
                    auth.audit("signup_taken", username, ip, detail=f"{email_final} race=1")
                    return auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True))
                return err(auth.t("err.email_taken"), 409)
            if inv:
                auth.redeem_magic(invite, purpose="invite")   # consume the invitation now
            auth.audit("signup", username, ip)
            # E-mail confirmation required? (not with invitation — it counts as confirmed)
            if verify and email_final:
                auth.store.set_disabled(uid, True)

                def _revert(reason):
                    # B6-5: without a delivered confirmation the account is a corpse — blocked,
                    # never unblockable, and it keeps name and address occupied. Until 0.19 an HTTP 500
                    # followed. It is therefore removed again; the registration
                    # can simply be repeated afterwards.
                    # Via the one deletion path (H-13, integration findings 12/18): otherwise
                    # `signup` and this line including the IP would stay under the name, and whoever registers it later
                    # would see them on their account page as their own events (H-7).
                    auth.store.remove_account(uid)
                    auth.audit("verify_send_error", replacement_name(uid), ip,
                               detail=f"{reason}, account removed")

                page_html = auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True))
                # The token is created HERE, in the request; only the sending waits for the
                # outbox. A block by the operator discards open tokens (H-18) —
                # had it only come into being in the mail worker, a block in the waiting window found nothing, and
                # the belated link lifted it afterwards. Timing-neutral only with respect to the
                # placeholder branch of a taken address (R4-03, name ≠ address), which creates its
                # token in the request as well. If the name is the address (always with
                # login_identifier='email'), the taken branch writes only the audit line —
                # this timing oracle existed before and is in the backlog (T-13).
                try:
                    send = auth._verify_mail(uid, email_final, verify_base,
                                             app=(auth._frame(request) or {}).get("host", ""))     # T-152
                except Exception:
                    send = None
                if send is None:
                    _revert("dispatch")
                    return page_html

                def _dispatch():
                    try:
                        send()
                    except Exception:
                        _revert("dispatch")
                return auth.after_response(
                    page_html, _dispatch, on_overflow=lambda: _revert("queue_full"))
            token, ok, is_new = auth.apply_factor(request, uid, "password", ip,
                                                  request.headers.get("user-agent"), True)
            resp = RedirectResponse(auth._login_redirect_after(request, token, uid, nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            return resp

    # ---------- Forward auth (reverse proxy: Caddy forward_auth / nginx auth_request / Traefik) ----------

    # ---------- Own account (self-service) ----------
    @r.post("/auth/password")
    async def change_own_password(request: Request):
        # One source (0.22.0): session (never an API key), throttle, pre-booking in its own bucket
        # (R4-10), the old password against the session ID (R4-12), the password rule, ending the
        # other sessions, discarding open address-change links and the audit
        # live in `change_password`, the public building block for custom password-change pages.
        # Here only the JSON is read (including the CSRF check, as at every write route) and the
        # result becomes the response. This route calls no inner checker itself (guard in
        # `tests/test_confirm.py`).
        b = await auth.json_body(request)
        # In the thread pool: checking the old password (argon2) would otherwise halt the event loop.
        erg = await run_in_threadpool(auth.change_password, request, b.get("current") or "",
                                      b.get("new") or "",
                                      csrf=request.headers.get("x-csrf-token") or b.get("_csrf") or "")
        if not erg:
            raise HTTPException(erg.status, erg.message)
        return {"ok": True, "api_keys_active": erg.api_keys_active,
                "app_passwords_active": erg.app_passwords_active}

    def _setup_answer(request: Request, uid: int, token, nxt: str) -> JSONResponse:
        """The answer of a setup route inside the setup pass (T-34): where to go next — the following
        step or, once the sign-in is complete, the target — and the new cookie if it is complete."""
        current = token or request.cookies.get(auth.session_cookie_name)
        response = JSONResponse({"ok": True, "next": auth._login_redirect_after(
            request, current, uid, auth.safe_next(nxt, request)), "other_sessions": 0})
        if token:
            auth.set_cookie(response, token)
        return response

    @r.post("/auth/password/set")
    async def set_own_first_password(request: Request):
        # B-10: an account without a password (sign-in link, OIDC, passkey) gets its first one here.
        # One source like above: `set_initial_password` checks CSRF, session, freshness instead of the
        # old password, throttle and rule, and writes the audit line.
        b = await auth.json_body(request)
        renew = auth._renew_user(request) if auth.session_user(request) is None else None
        if renew is not None:
            # T-46: the half session after a sign-in with the administrator's start secret.
            erg, token = await run_in_threadpool(auth._renew_password, request, b.get("new") or "",
                                                 csrf=request.headers.get("x-csrf-token") or b.get("_csrf") or "")
            if not erg:
                raise HTTPException(erg.status, erg.message)
            return _setup_answer(request, renew["id"], token, str(b.get("next") or ""))
        setup = auth._setup_user(request, "password") if auth.session_user(request) is None else None
        if setup is not None:
            # T-34: the setup pass after a sign-in link — a half session that may set exactly this.
            erg, token = await run_in_threadpool(auth._setup_password, request, b.get("new") or "",
                                                 csrf=request.headers.get("x-csrf-token") or b.get("_csrf") or "")
            if not erg:
                raise HTTPException(erg.status, erg.message)
            return _setup_answer(request, setup["id"], token, str(b.get("next") or ""))
        erg = await run_in_threadpool(auth.set_initial_password, request, b.get("new") or "",
                                      csrf=request.headers.get("x-csrf-token") or b.get("_csrf") or "")
        if not erg:
            # Like every factor route: a stale step-up sends the account page to the reauth page.
            headers = ({"X-TinySesam-Reauth": auth.browser_path(request, "/auth/reauth")}
                       if erg.reason == "stepup" else None)
            raise HTTPException(erg.status, erg.message, headers=headers)
        # A new credential, like a new factor (B1-7): offer to end the other sessions.
        u = auth.session_user(request)
        return {"ok": True, "api_keys_active": erg.api_keys_active,
                "app_passwords_active": erg.app_passwords_active,
                "other_sessions": auth.count_other_sessions(request, u) if u else 0}

    if cfg.account_enabled:
        from ._routes_actions import account_ctx as _account_ctx

        @r.get("/auth/account", response_class=HTMLResponse)
        def account_page(request: Request):
            u = auth.current_user(request)
            if not u:
                return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(auth.browser_path(request, '/auth/account'))}", 303)
            # One source (T-91): the page reads the state from `account_overview`, the same function behind
            # `/auth/account.json` — page and data cannot drift apart; its action pages (T-105) read the same.
            view = auth.account_overview(u) or {}
            return auth.render_page("account", request=request, user=u, **_account_ctx(auth, request, u, view))

    # ---------- Self-service: username and address (PO decision 2026-09-25) ----------
    def _fresh_for_identifier(request: Request) -> dict:
        """Whoever changes their identifier confirms freshly beforehand — as when setting up a factor:
        with a stolen session cookie the name or the address could otherwise be bent over,
        and the reset link would then go to the thief. An account without any factor (purely federated)
        depends on the age of the sign-in. No API key (`require_session`)."""
        return auth._require_fresh(request)

    if cfg.self_service_username_change:
        @r.post("/auth/account/username")
        async def own_username(request: Request):
            b = await auth.json_body(request)
            u = _fresh_for_identifier(request)
            if not auth._rate_ok(auth.client_ip(request), login=False):
                raise HTTPException(429, auth.t("api.too_many"))
            try:
                new = auth.change_username(u["id"], b.get("username"), auth.client_ip(request))
            except ValueError as e:
                raise HTTPException(400, str(e))
            return {"ok": True, "username": new}

    if cfg.self_service_email_change:
        @r.post("/auth/account/email")
        async def own_email(request: Request):
            b = await auth.json_body(request)
            u = _fresh_for_identifier(request)
            if not auth._rate_ok(auth.client_ip(request), login=False):
                raise HTTPException(429, auth.t("api.too_many"))
            try:
                # T-152: the frame of the request (`?app=` of an action page) travels in the token.
                send = auth.request_email_change(u["id"], b.get("email"), auth.public_base(request),
                                                 app=(auth._frame(request) or {}).get("host", ""))
            except ConfigError:
                # First: `ConfigError` IS a `ValueError` (CodeQL py/unreachable-except). In
                # the reverse order the message about the base address went out as response text.
                raise HTTPException(400, auth.t("api.no_mail"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            # The same answer whether a link goes out or not (taken address, throttle) —
            # and sending only after the response (R4-05): no running time as an oracle.
            # If the queue is full, the token expires (`send.discard`): a link that was never
            # delivered would otherwise block the path via LDAP/SAML until its expiry.
            response = JSONResponse({"ok": True, "sent": True})
            return auth.after_response(response, send, on_overflow=send.discard) \
                if send else response

        @r.get("/auth/email/{token}", response_class=HTMLResponse)
        def email_confirm_page(request: Request, token: str):
            """Confirmation page instead of redeeming via GET — link scanners redeem nothing (R4-02)."""
            peeked = auth.peek_magic(token, purpose="email_change")
            if not peeked:
                auth._token_rejected("email_change", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            framed = auth._frame_of((peeked.get("payload") or {}).get("frame"))    # T-152: the frame of the request
            return auth.render_page("magic_confirm", request=request, purpose="email_change",
                                    action=auth.browser_path(request, f"/auth/email/{_q(token)}"),
                                    **({"frame": framed} if framed else {}))

        @r.post("/auth/email/{token}")
        def email_confirm(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            result = auth.confirm_email_change(token, auth.client_ip(request))
            if result is None:
                auth._token_rejected("email_change", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            if result == "taken":
                return auth.render_page("magic_invalid", request=request, status=409)
            destination = auth.browser_path(request, "/auth/account" if cfg.account_enabled else cfg.login_redirect)
            return RedirectResponse(destination, 303)

    # ---------- Manage own sessions ----------
    @r.get("/auth/sessions")
    def own_sessions(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        # The list names IP and browser of every session — that is a human's view of their
        # account, not a machine's (F-09). Viewing needs no fresh confirmation
        # (ASVS 5.0 7.5.2 demands it only for ending), but a real session.
        auth.require_session(request, u)
        cur = auth._session_from_request(request)
        # One source with `account_overview` (T-91): the same rows, here with address and browser string.
        return [{"created_at": s["created_at"], "ip": s["ip"], "method": s["method"], "user_agent": s["user_agent"],
                 "current": bool(s["current"]), "handle": s["handle"]}
                for s in auth._own_session_rows(u["id"], cur["token_hash"] if cur else None)]

    @r.post("/auth/sessions/end")
    async def own_session_end(request: Request):
        """End ONE other session by its session handle (T-105) — with a fresh confirmation, like ending the others
        (F-09). The own session is no target (that is signing out); a handle of another account ends nothing (404)."""
        if not auth.current_user(request):
            raise HTTPException(401)
        u = auth.require_mfa(request)
        handle = str((await auth.json_body(request)).get("handle") or "")
        cur = auth._session_from_request(request)
        own = auth.store.list_sessions(u["id"])
        if any(s["public_handle"] == handle and cur and s["token_hash"] == cur["token_hash"] for s in own):
            raise HTTPException(400, auth.t("api.invalid", reason="the current session — sign out instead"))
        if not auth.store.end_session_by_public_handle(u["id"], handle):
            raise HTTPException(404)
        # An open address change may stem from the ended session (as with "end the others", finding 1).
        auth.store.revoke_user_magic_tokens(u["id"], purposes=("email_change",))
        auth.audit("session_end", u["username"], auth.client_ip(request))
        return {"ok": True}

    @r.post("/auth/sessions/revoke-after-login")
    async def sessions_revoke_after_login(request: Request):
        """End the other sessions AS SOON AS this half sign-in is complete (boundary d).

        Only for a half session: a full one takes `/auth/sessions/revoke`. Nothing is ended
        here — the consent is noted, redeemed only after the last factor. So whoever has only the
        first factor cannot end anything with it that they could not fully do anyway."""
        await auth.json_body(request)                     # CSRF like every write route
        s = auth._session_from_request(request)
        if not s or s["mfa_ok"]:
            raise HTTPException(400, auth.t("api.invalid", reason="no half-finished sign-in"))
        auth.store.set_session_end_others(s["token_hash"])
        return {"ok": True}

    @r.post("/auth/sessions/revoke")
    async def own_sessions_revoke(request: Request):
        # Ending sessions requires a fresh confirmation (F-09, ASVS 5.0 7.5.2: "having
        # authenticated again with at least one factor"). Before, any session and any
        # API key sufficed: a stolen cookie threw the rightful holder off all other
        # devices, and "end all" even revoked their API keys. The
        # account page follows the `X-TinySesam-Reauth` hint by itself.
        if not auth.current_user(request):
            raise HTTPException(401)
        u = auth.require_mfa(request)
        scope = (await auth.json_body(request)).get("scope", "others")
        # An API key is a second, equivalent sign-in — it hangs on no session.
        # "end all" is the panic button (account probably taken over): the key belongs there.
        # "end others" is tidying up: the key stays, and the answer says how many keep
        # applying. Letting them run silently is the only thing that is not acceptable.
        keys_revoked = 0
        if scope == "all":
            auth.store.delete_user_sessions(u["id"])          # incl. current → signed out
            keys_revoked = auth._keys_revoked(u["id"], "sessions_revoked")
            auth.store.revoke_user_magic_tokens(u["id"])      # panic button: open links too (finding 1)
        else:
            cur = auth._session_from_request(request)
            auth.store.delete_user_sessions_except(u["id"], cur["token_hash"] if cur else None)
            # An open address change may stem from one of the ended sessions (finding 1).
            auth.store.revoke_user_magic_tokens(u["id"], purposes=("email_change",))
        auth.audit("sessions_revoke", u["username"], auth.client_ip(request),
                   scope + (f" api_keys_revoked={keys_revoked}" if keys_revoked else ""))
        # App passwords (T-66) follow the keys: revoked with "end all" (`_keys_revoked`), counted with "end others".
        return {"ok": True, "api_keys_revoked": keys_revoked,
                "api_keys_active": auth.store.count_active_api_keys(u["id"]),
                "app_passwords_active": auth.store.app_passwords_active(u["id"])}

    # ---------- Logout / me ----------
    def _provider_logout_url(s, back: str):
        """Logout at the provider, with the sign-in's ID token as a hint (T-22) — and with THE
        client through which it ran: PocketID accepts the hint only for the matching client."""
        stored = auth.store.get_oidc_id_token(s["token_hash"]) if s else None
        client, notice = stored if stored else ("", None)
        registry = getattr(auth, "oidc_clients", None)
        oidc = registry[client] if (client and registry is not None and registry.known(client)) else auth.oidc
        return oidc.end_session_url(back, id_token_hint=notice)

    def _sign_out(request: Request):
        # The account whose session ends here is logged — from the cookie (0.20.1,
        # `session_user`), not that of an API key sent along.
        u = auth.session_user(request) or auth.pending_user(request)
        # OIDC provider logout (optional): before the local logout check whether the session ran via OIDC
        oidc_logout_url = None
        if cfg.oidc_rp_logout and auth.oidc:
            s = auth._session_from_request(request)
            factors: list = []
            try:
                factors = __import__("json").loads(s["factors_done"] or "[]") if s else []
            except Exception:
                factors = []
            if s and (s["method"] == "oidc" or "oidc" in factors):
                # Without a trustworthy base NO post_logout_redirect_uri: otherwise the
                # IdP would send the victim after logout to the host from the Host header. The
                # local logout below runs anyway, just without the provider detour.
                base = auth.public_base(request)
                if base:
                    oidc_logout_url = _provider_logout_url(s, base + cfg.logout_redirect)
        if u:
            auth.audit("logout", u["username"], auth.client_ip(request))
        resp = RedirectResponse(oidc_logout_url or auth.browser_path(request, cfg.logout_redirect), 303)
        auth.logout(request, resp)
        return resp

    @r.get("/auth/logout")
    def logout(request: Request):
        # Logout CSRF (F-07): a GET that signs out can be triggered from any foreign page with an
        # <img src>. But the browser says where the navigation comes from. From the own
        # page, a neighbour subdomain (the sign-out button of a protected app) or
        # the address bar the link keeps working; from a FOREIGN page, instead of
        # signing out, a confirmation prompt with a POST form appears. Without the header (old browser, script)
        # the old behaviour stays — otherwise every existing sign-out link would break.
        if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
            return auth.render_page("logout", request=request)
        return _sign_out(request)

    @r.post("/auth/logout")
    def logout_post(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        """Sign out via form — with CSRF check, the way for custom UIs."""
        auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
        return _sign_out(request)

    @r.post("/auth/csp-report")
    async def csp_report(request: Request):
        """CSP violation reports of the browser (`csp_report`, T-52, ASVS 3.4.7) — into the security log.

        Without sign-in and without CSRF token: the browser sends reports on its own, without cookies. 404 while
        the switch is off; per IP `_CSP_REPORT_PER_IP` reports a minute; a body beyond `_CSP_REPORT_MAX_BYTES`
        is not read to its end (413)."""
        from fastapi.responses import Response as _Resp
        from starlette.concurrency import run_in_threadpool
        if not auth._csp_reporting():
            raise HTTPException(404)
        ip = auth.client_ip(request)
        # The limiter may be Redis (a network call): off the event loop, like the log write below.
        if not await run_in_threadpool(auth.rl.allow, f"csp_report:{ip or '?'}", auth._CSP_REPORT_PER_IP, 60):
            return _Resp(status_code=429)
        kind = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        if kind not in ("application/reports+json", "application/csp-report", "application/json"):
            return _Resp(status_code=415)
        raw = b""
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > auth._CSP_REPORT_MAX_BYTES:
                return _Resp(status_code=413)
        await run_in_threadpool(auth._csp_report_line, raw, ip)
        return _Resp(status_code=204)

    @r.get("/auth/me")
    def me(request: Request):
        u = auth.current_user(request)
        if not u:
            return JSONResponse({"authenticated": False}, 401)
        return {"authenticated": True, "id": u["id"], "username": u["username"],
                "display_name": u["display_name"], "is_admin": bool(u["is_admin"]),
                "roles": auth.user_roles(u)}

    # ---------- The top bar as data (T-76) ----------
    def _topbar_json(viewer, request: Request, host: str = ""):
        """What the top bar shows the account of this request — for an application that draws its own bar.
        `no-store` + `Vary: Cookie` (the answer depends on the session) and no CORS header: another origin's page
        cannot read it; an application fetches it server-side with the request's cookie or same-origin through
        the proxy (`/.tinysesam/topbar.json`). `host`: the application's host, for the part `frame` (T-103)."""
        base = (security.normalize_base(str(cfg.base_url or "").strip()) or "").rstrip("/") or auth._prefix(request)
        return JSONResponse(auth.topbar_data(viewer, base=base, host=host),
                            headers={"Cache-Control": "no-store", "Vary": "Cookie"})

    @r.get("/auth/topbar.json")
    def topbar_json(request: Request, app: str = ""):
        # `?app=<host>` names the frame like on the built-in pages (T-103); an unknown host changes nothing.
        return _topbar_json(auth.session_user(request), request, app[:253])

    # ---------- The shell component (T-103, spec §8d) ----------
    @r.get("/auth/shell.js")
    def shell_js(request: Request):
        return _shell.asset(auth, request, "js")

    @r.get("/auth/shell.css")
    def shell_css(request: Request):
        return _shell.asset(auth, request, "css")

    # ---------- The own account as data (T-91) ----------
    def _account_json(viewer, request: Request, app_host: str = ""):
        """The account page's state for the account of this request's FULL browser session — an API key, an OAuth
        token, an app password or a half session is "not signed in" (401). No parameter chooses an account. Like the
        bar: `no-store` + `Vary: Cookie`, no CORS header (another origin's page cannot read it), read only. 60 reads
        per account and minute (`_ACCOUNT_JSON_PER_MINUTE`); a refusal is a `failed verification` line, never a
        `failed login` (the fail2ban jail stays quiet). Reading is not audited — the own data, and every change goes
        through the audited routes of the account page."""
        headers = {"Cache-Control": "no-store", "Vary": "Cookie"}
        if not viewer:
            return JSONResponse({"authenticated": False, "signed_in": False}, 401, headers=headers)
        if not auth.rl.allow(f"account_json:{int(viewer['id'])}", auth._ACCOUNT_JSON_PER_MINUTE, 60):
            auth._rejected(viewer["username"], auth.client_ip(request), "ratelimit_account_json", login=False)
            return JSONResponse({"detail": auth.t("api.too_many")}, 429, headers={**headers, "Retry-After": "60"})
        base = (security.normalize_base(str(cfg.base_url or "").strip()) or "").rstrip("/") or auth._prefix(request)
        view = auth.account_overview(viewer, base=base, app_host=app_host or None, request=request)
        if view is None:
            return JSONResponse({"authenticated": False, "signed_in": False}, 401, headers=headers)
        return JSONResponse({"signed_in": True, **view}, headers=headers)

    @r.get("/auth/account.json")
    def account_json(request: Request):
        return _account_json(auth.session_user(request), request)

    # ---------- OIDC (only if enabled) ----------
    if auth.oidc:
        from .oidc import register_oidc_routes
        register_oidc_routes(r, auth)

    # ---------- Passkey / WebAuthn (only if enabled) ----------
    if auth.webauthn:
        from .webauthn_ import register_passkey_routes
        try:
            register_passkey_routes(r, auth)
        except ModuleNotFoundError as e:
            # Whoever deliberately enables passkey_enabled should be able to read what is missing — instead of
            # getting a ModuleNotFoundError from inside the library.
            #
            # `MissingExtra`, not `RuntimeError`: the docs show `except MissingExtra as e:
            # … e.extra` as the pattern, and for the passkey case that missed — as the
            # only method it raised a different type. (`MissingExtra` inherits from
            # `RuntimeError`, so existing code keeps catching it.)
            from .errors import MissingExtra
            raise MissingExtra(
                "passkey_enabled=True, but the extra [passkey] is not installed "
                "(pip install 'tinysesam[passkey]'). Without it there are no passkey routes; "
                "passkey_enabled=False switches them off.", extra="passkey") from e

    # ---------- Approvals (stage A, only if enabled) ----------
    if cfg.approvals_enabled:
        from .approvals import register_routes as register_approval_routes
        register_approval_routes(r, auth)

    # ---------- Account API for applications (stage A, only with an application in `apps` that has provisioning) ----
    if any(isinstance(e, dict) and isinstance(e.get("provisioning"), dict)
           for e in (cfg.apps.values() if isinstance(getattr(cfg, "apps", None), dict) else [])):
        from .provisioning import register_routes as register_provisioning_routes
        register_provisioning_routes(r, auth)

    # ---------- Permission API for applications (T-101, only with an application that has permission_scopes) ----
    if any(isinstance(e, dict) and e.get("permission_scopes")
           for e in (cfg.apps.values() if isinstance(getattr(cfg, "apps", None), dict) else [])):
        from ._permissions_api import register_routes as register_permission_routes
        register_permission_routes(r, auth)

    # ---------- SAML 2.0 SP (only if enabled) ----------
    if auth.saml:
        from fastapi.responses import Response as _Resp

        def _saml_base(request: Request):
            proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
            host = (request.headers.get("x-forwarded-host") or request.headers.get("host")
                    or request.url.netloc).split(",")[0].strip()
            return f"{proto}://{host}"

        def _saml_req(request: Request, form=None):
            """The `req` set for python3-saml — built from the CHECKED base (F-16).

            Before, scheme and host from `X-Forwarded-Proto`/`Host` stood here. python3-saml
            computes from them the address it considers its own and compares it with the
            `Destination` of the assertion — so the requester co-determined this comparison.
            """
            from .saml_ import request_context
            return request_context(_saml_base_url(request), request.url.path,
                                   form=form, query=request.query_params)

        # Anchor against smuggled-in assertions: the ID of the AuthnRequest lies until the ACS in
        # a cookie of its own, short-lived.
        #
        # SameSite is here NOT from the config: the ACS is a cross-site POST (the IdP has
        # the browser submit a form), and the browser then does not send a Lax cookie
        # along — the default `cookie_samesite="lax"` would therefore lose the anchor at every
        # real login. Only `SameSite=None` can come along, and that requires `Secure`.
        # Without `cookie_secure` it therefore stays with the config value: locally/in the TestClient the
        # POST is same-site and gets through, for a real IdP this setup is none anyway.
        _SAMLFLOW = "tinysesam_saml_flow"
        _SAMLAPV = "samlapv:"       # flow row: the approval an AuthnRequest was sent for (T-99), keyed by its ID

        # SAML builds its own entity ID and the ACS URL from the base. If it comes from the
        # Host header, a foreign name migrates into the AuthnRequest and the metadata —
        # hence no carrying on here without a checked base (R4-01).
        def _saml_base_url(request: Request) -> str:
            return auth.require_public_base(request, _saml_base(request))

        from ._routes_link import SAML_LINK_FLOW, register_saml_link     # T-99: the person links a SAML identity
        register_saml_link(r, auth, _saml_req, _saml_base_url, _SAMLFLOW,
                           "none" if cfg.cookie_secure else cfg.cookie_samesite)

        @r.get("/auth/saml/login")
        def saml_login(request: Request, next: str = "", reauth: str = "", approval: str = ""):
            base = _saml_base_url(request)
            # T-70: `reauth=1` (the confirmation page's provider button) sends `ForceAuthn="true"`; the request
            # remembers it and when it was sent, the ACS confirms only with an `AuthnInstant` from after that.
            # Passed only when asked: a client set by hand (`auth.saml = own_client`) without the argument keeps working.
            # T-99: `approval=<id>` (an approval page's provider button) — always `ForceAuthn`, and a fresh `AuthnInstant`
            # becomes the step-up of THAT approval only (the ACS leaves a one-time grant, as `/auth/oidc/start` does).
            from .approvals import valid_id as _approval_id
            bound = approval if (cfg.approvals_enabled and cfg.saml_reauth_check and _approval_id(approval)) else ""
            force = {"force_authn": True} if (reauth or bound) and cfg.saml_reauth_check else {}
            url, rid = auth.saml.login_url(_saml_req(request), base, return_to=auth.safe_next(next, request), **force)
            if bound and rid:
                auth.store.put_flow(_SAMLAPV + rid, {"approval": bound}, ttl=600)
            resp = RedirectResponse(url, 303)
            # `__Host-` in front where possible (A-1) — otherwise a neighbour subdomain sets the anchor.
            auth._set_flow_cookie(resp, _SAMLFLOW, rid or "", max_age=600,
                                    samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
            return resp

        @r.post("/auth/saml/acs")            # POST from the IdP → exempt from CSRF (signature protects)
        async def saml_acs(request: Request):
            # Rate-limited like every other sign-in entry (F-22). The ACS accepts a POST without CSRF and
            # without a session and runs it through the XML signature check — the
            # most expensive work an unauthenticated user can trigger here, and until 0.19.x the
            # only sign-in route without a throttle.
            ip = auth.client_ip(request)
            if not auth._rate_ok(ip):
                raise HTTPException(429, auth.t("err.rate"))
            form = await request.form()
            base = _saml_base_url(request)
            rid = request.cookies.get(auth.flow_cookie_name(_SAMLFLOW)) or ""
            data = auth.saml.process(_saml_req(request, form), base, request_id=rid)
            if not data:
                # NOT the magic-link page ("this link is invalid, expired or already
                # used") — this was about no link, and the message sent the first
                # run against a real IdP in the wrong direction. The reason is in the log.
                auth.audit("saml_invalid", None, ip, "assertion rejected (reason in the security log)")
                raise HTTPException(400, auth.t("err.saml"))
            link = auth.store.pop_flow(SAML_LINK_FLOW + rid) if rid else None
            if link:
                # A link flow (T-99): bind this identity to the account that started it — never a sign-in, no account
                # found or created by the assertion (`_check_saml` is not asked).
                refused = auth._finish_saml_link(request, link, data)
                if refused is not None:
                    raise HTTPException(refused[0], auth.t(refused[1]))
                resp = RedirectResponse(auth.browser_path(request, "/auth/account"), 303)
                auth._delete_flow_cookie(resp, _SAMLFLOW, samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
                return resp
            u = auth._check_saml(data.get("nameid"), data.get("attrs") or {}, ip=ip)
            if not u:
                # The reason (group, no account, blocked, identifier taken) is written by
                # `_check_saml` itself into the audit log — here only the answer to the browser.
                raise HTTPException(403, auth.t("api.saml_denied"))
            nxt = auth.safe_next(form.get("RelayState") or "", request)
            # The approval this request was sent for — read once, bound to the request ID `process` just redeemed.
            approval = str((auth.store.pop_flow(_SAMLAPV + rid) or {}).get("approval") or "") if rid else ""
            # T-70 (ASVS 5.0 6.8.4, SAML 2.0 Core §2.7.2 `AuthnInstant`): when did the person really authenticate at
            # the provider? A round through its running session is silent — up to 0.31.x it counted as a fresh
            # confirmation: a step-up on a full session, a new session "signed in now". With `saml_reauth_check` the
            # assertion's `AuthnInstant` decides — the same rule as `auth_time` for OIDC (T-49). Missing (a broken
            # response: the attribute is mandatory) it never confirms a step-up; a new session then counts from this
            # sign-in, as for OIDC without `auth_time`.
            authenticated = data.get("authn_instant") if cfg.saml_reauth_check else None
            asked = int(data.get("asked") or 0)
            provider_fresh = authenticated is not None and asked > 0 and authenticated >= asked - 60
            before = auth._session_from_request(request)
            stepping_up = bool(before and before["user_id"] == u["id"] and before["mfa_ok"])
            if cfg.saml_reauth_check and stepping_up and not provider_fresh:
                age = "missing" if authenticated is None else (asked - authenticated if asked else "unknown")
                if approval:
                    # The approval page asked for a sign-in and the provider did not do one: no grant — back to the
                    # page, which says so. Fail-closed also without `AuthnInstant`.
                    auth.audit("saml_reauth_stale", str(u["username"]), ip, f"approval={approval} authn_instant={age}")
                    resp = RedirectResponse(auth.browser_path(request, f"/auth/approvals/{approval}")
                                            + "?stepup=stale-saml", 303)
                    auth._delete_flow_cookie(resp, _SAMLFLOW,
                                             samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
                    return resp
                if data.get("reauth"):
                    # The confirmation page asked for a sign-in (`ForceAuthn`) and the provider did not do one: no
                    # step-up — the page says so instead of a silent success.
                    auth.audit("saml_reauth_stale", str(u["username"]), ip, f"authn_instant={age}")
                    resp = auth.render_page("reauth", status=401, request=request, next=nxt,
                                            username=str(u["username"]), methods=auth.stepup_options(u),
                                            reauth_oidc=auth._confirms_at_oidc(u), reauth_saml=False,
                                            error=auth.t("err.saml_reauth_stale"))
                    auth._delete_flow_cookie(resp, _SAMLFLOW,
                                             samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
                    return resp
                # Any other round on a full session: it runs on, but it does not refresh the confirmation.
                auth.audit("stepup_not_counted", str(u["username"]), ip, "factor=saml reason=no_fresh_authn_instant")
                resp = RedirectResponse(nxt, 303)
                auth._delete_flow_cookie(resp, _SAMLFLOW,
                                         samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
                return resp
            # SAML has no `email_verified`: no standard attribute says that the IdP has
            # checked the address. Without `saml_email_trusted` (default) and without a vouching attribute
            # (`saml_attr_email_verified`) "no proof" therefore travels along here — an
            # allowlist ADDRESS never becomes first admin via SAML (F-14). With one of the two
            # the proof set on the account by `_check_saml` counts. The factor `saml`
            # additionally stands in `_FEDERATED_FACTORS`, so omitting it would be no hole.
            token, ok, is_new = auth.apply_factor(request, u["id"], "saml",
                                                  auth.client_ip(request),
                                                  request.headers.get("user-agent"),
                                                  email_verified=bool(
                                                      (cfg.saml_email_trusted or security.proof_attribute(cfg, "saml"))
                                                      and u.get("email")
                                                      and u.get("email_verified")))
            if is_new and authenticated is not None and not (before and before["user_id"] == u["id"]):
                # A NEW session: its confirmation dates from the provider's sign-in, not from this round (T-70).
                auth.store.backdate_confirmation(token, authenticated)
            if approval and stepping_up and provider_fresh and authenticated is not None:
                # The step-up of one approval: consumed once by `POST /auth/approvals/{id}` of this account (T-99).
                auth.store.put_flow("apvsaml:" + approval, {"user_id": int(u["id"]), "auth_time": int(authenticated)},
                                    ttl=300)
            resp = RedirectResponse(auth._login_redirect_after(request, token, u["id"], nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            # requested once, redeemed once
            auth._delete_flow_cookie(resp, _SAMLFLOW,
                                      samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
            return resp

        @r.get("/auth/saml/metadata")
        def saml_metadata(request: Request):
            base = _saml_base_url(request)
            return _Resp(content=auth.saml.metadata(base), media_type="application/xml")

    # ---------- The person's links to providers (T-99): unlink, link LDAP ----------
    if cfg.oidc_enabled or cfg.saml_enabled or cfg.ldap_enabled:
        from ._routes_link import register_routes as register_link_routes
        register_link_routes(r, auth)

    # ---------- API keys: self-service for the signed-in user ----------
    if cfg.apikey_enabled:
        @r.get("/auth/apikeys")
        def apikeys_list(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            return [key_view(k) for k in auth.list_api_keys(u["id"])]

        def _only_with_session(request: Request):
            """Managing keys presupposes an interactive session.

            `create_api_key` cuts the scope against the **account's** roles — not against those
            of the caller. A key restricted to `["lager"]` could thereby issue itself a
            key with all roles of the account and so lift its own restriction.
            Instead of threading the intersection through the whole call path, the simpler
            rule applies: keys are issued by a human, not by a key.
            """
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            if u.get("_via") != "session":
                raise HTTPException(403, auth.t("api.key_needs_session"))
            return u

        @r.post("/auth/apikeys")
        async def apikeys_create(request: Request):
            u = _only_with_session(request)
            # B-12: a key is a second way in that carries the account's roles for months — only from a
            # fresh confirmation, so a stolen cookie cannot mint one (revoking needs no freshness).
            u = auth._require_fresh(request, u)
            b = await auth.json_body(request)
            # `kind` decides what the key can do (R6-5): "automation" works alone, but
            # never carries the admin flag; "human" is valid only together with a session of the same
            # account. The default is the narrower of the two. The names up to 0.21.x ("automat",
            # "mensch") are an input error, whose text names the new ones (no alias).
            # An unusable scope, "unlimited" without permission or an unknown kind
            # are input errors, not server errors — the same class as R6-8 in the panel.
            try:
                return auth.create_api_key(u["id"], name=b.get("name"),
                                           expires_days=b.get("expires_days"), roles=b.get("roles"),
                                           kind=str(b.get("kind") or "automation"))
            except (ConfigError, ValueError, TypeError) as e:
                raise HTTPException(400, auth.t("api.invalid", reason=str(e)))

        @r.post("/auth/apikeys/{key_id}/revoke")
        def apikeys_revoke(request: Request, key_id: int):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            u = _only_with_session(request)
            auth.revoke_api_key(key_id, u["id"])   # block, do not delete
            return {"ok": True}

    # ---------- App passwords (T-66): self-service for the signed-in user ----------
    # Only when an application takes them (`forward_apps[host]["app_passwords"]`). Managed from an interactive
    # session only — never with an API key, an OAuth token or an app password itself.
    if auth.app_password_hosts():
        def _app_password_holder(request: Request) -> dict:
            u = auth.session_user(request)
            if not u:
                raise HTTPException(401)
            return u

        @r.get("/auth/app-passwords")
        def app_passwords_list(request: Request):
            u = _app_password_holder(request)
            return [{k: v for k, v in p.items() if k != "username"} for p in auth.list_app_passwords(u["id"])]

        @r.post("/auth/app-passwords")
        async def app_passwords_create(request: Request):
            # B-12: lasting access to the account — only from a fresh confirmation, so a stolen cookie cannot
            # mint one (revoking needs no freshness).
            u = auth._require_fresh(request, _app_password_holder(request))
            b = await auth.json_body(request)
            try:
                return auth.create_app_password(u["id"], b.get("name"), hosts=b.get("hosts"),
                                                expires_days=b.get("expires_days"))
            except (ConfigError, ValueError, TypeError) as e:
                raise HTTPException(400, auth.t("api.invalid", reason=str(e)))

        @r.post("/auth/app-passwords/{pw_id}/revoke")
        async def app_passwords_revoke(request: Request, pw_id: int):
            await auth.json_body(request)                     # CSRF like every write route
            u = _app_password_holder(request)
            if not auth.revoke_app_password(pw_id, u["id"]):
                raise HTTPException(404, auth.t("api.not_found"))
            return {"ok": True}

    # ---------- OAuth 2.1 for MCP clients (T-36, ADR-11) ----------
    if cfg.oauth_enabled:
        from . import oauth as _oauth_mod
        _oauth_mod.add_routes(auth, r)

    # ---------- Admin panel — at config.admin_path; mountable elsewhere via auth.admin_router() ----------
    if cfg.admin_enabled:
        r.include_router(auth.admin_router(), prefix=cfg.admin_path)

    # The TinySesam area of an application (T-104, surface "hybrid") and the action pages (T-105, surface "headless"):
    # beside the account page they lead to.
    if cfg.account_enabled:
        from ._routes_actions import add_routes as _add_routes_actions
        from ._routes_area import add_routes as _add_routes_area
        _add_routes_area(r, auth, cfg)
        _add_routes_actions(r, auth, cfg)

    # Forward auth and the gate (T-112: its own module, imported only when `cfg.forward_auth_enabled` is on).
    if cfg.forward_auth_enabled:
        from ._routes_forward import add_routes as _add_routes_forward
        _add_routes_forward(r, auth, cfg, _account_json=_account_json, _provider_logout_url=_provider_logout_url,
                            _topbar_json=_topbar_json)
    return r


#: Polls of `/auth/qr/status` per address and minute (T-44). The page polls every two seconds — 30 a
#: minute per device; four devices behind one address still fit.
_QR_STATUS_PER_MINUTE = 120


def _mail_base(auth, request) -> str:
    """The base for a sent link — or HTTP 503, never a 500 and never a silent 200.

    `config_check` does not let a mail feature without `base_url` start at all. If the
    config is changed AFTER the constructor (`auth.cfg.base_url = ""`),
    `require_public_base()` raises `ConfigError` at request time — and no route caught it: the
    user got "internal server error", the operator a stack trace with no hint that it is
    the configuration. 503 says what it is: the service is not operational this way.
    The reason goes once into the security log (not per request), the answer reveals nothing
    about the mailbox and nothing about the setup.
    """
    from . import security
    try:
        return auth.require_public_base(request)
    except ConfigError as e:
        if security.report_once("mail_basis"):
            security.seclog.error("Cannot send a link, request answered with 503: %s", e)
        raise HTTPException(503, auth.t("api.base_missing"))


def _key_kind(k) -> str:
    """The kind of a key record with an English name — compatible with files from before schema 7
    and with values up to 0.21.x (`store.key_kind_of`)."""
    return key_kind_of(k)


def key_view(k) -> dict:
    return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
            "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"]),
            "kind": _key_kind(k)}


def _login_after_token(auth, request, uid, nxt, link: bool = False):
    """After a redeemed e-mail token, sign in (factor `magic`) and redirect.

    Common to sign-in link and e-mail confirmation: both prove the same — the recipient
    has access to the mailbox. A global factor chain can still demand a further step;
    that is why the path goes via `apply_factor`/`_login_redirect_after` instead of straight into
    a session.

    `link=True` (sign-in link and cross-device sign-in, T-34): if the account lacks factors for the
    chain, the setup pass opens — the redirect then leads to `/auth/setup`.
    """
    from fastapi.responses import RedirectResponse
    token, ok, is_new = auth.apply_factor(request, uid, "magic",
                                          auth.client_ip(request), request.headers.get("user-agent"))
    if link and not ok:
        auth._begin_setup(token, uid)
    resp = RedirectResponse(auth._login_redirect_after(request, token, uid, nxt), 303)
    if is_new:
        auth.set_cookie(resp, token)
    return resp


def _remember(cfg, val) -> bool:
    """Evaluate remember-me from the form. If the checkbox is globally off, always persistent."""
    if not cfg.remember_me_enabled:
        return True
    return str(val) in ("1", "true", "on", "yes")


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s or "/", safe="/")

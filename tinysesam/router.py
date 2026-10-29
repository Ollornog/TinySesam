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

from .errors import ConfigError
from . import security
from .store import ersatzname, key_kind_of, name_ungueltig, norm_email, valid_email
from . import security


async def _antwort_des_handlers(request: Request, exc: Exception):
    """The response the app's exception handler would build for `exc` — or None.

    The same lookup as Starlette's `ExceptionMiddleware` (along the MRO in the table it
    puts into the scope), so that a handler of the host's own wins as it would without TinySesam.
    """
    from starlette.concurrency import run_in_threadpool
    import inspect
    tabellen = request.scope.get("starlette.exception_handlers")
    if not tabellen:
        return None
    h = next((tabellen[0][k] for k in type(exc).__mro__ if k in tabellen[0]), None)
    if h is None:
        return None
    if inspect.iscoroutinefunction(h):
        return await h(request, exc)
    return await run_in_threadpool(h, request, exc)


def gehaertete_route(auth) -> type[APIRoute]:
    """A route class that sends every response through `auth._kopfzeilen`.

    As a route class and not as middleware: TinySesam is a router inside a foreign app.
    A middleware would hit every route of the host too — including its cache rules for static
    files. `include_router` adopts the class per route, so it applies
    to the admin panel under a freely chosen prefix as well.
    """
    class _GehaerteteRoute(APIRoute):
        def get_route_handler(self):
            innen = super().get_route_handler()

            async def handler(request: Request):
                try:
                    antwort = await innen(request)
                except _StarletteHTTPException as exc:   # FastAPI's HTTPException inherits from it
                    auth._kopfzeilen_fehler(exc)
                    raise
                except RequestValidationError as exc:
                    # The 422 returns the input but carries no `headers` into which the
                    # header lines could be put (A2). So build the response here — with exactly the
                    # handler the app registered for it (the host's or FastAPI's
                    # default), so that nothing changes in its content.
                    antwort = await _antwort_des_handlers(request, exc)
                    if antwort is None:
                        raise
                # If the response writes the session (sign-in by any path, sign-out, step-up),
                # the cookies go along under the names from before `__Host-` (H-1). Central here,
                # so that no sign-in path can forget it.
                auth._altnamen_loeschen(request, antwort)
                return auth._kopfzeilen(antwort)
            return handler
    return _GehaerteteRoute


def build_router(auth) -> APIRouter:
    cfg = auth.cfg
    r = APIRouter(tags=["auth"], route_class=gehaertete_route(auth))

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
        app = app if (app and registry is not None and registry.mehrere and registry.bekannt(app)) else ""
        if auth.current_user(request):
            sitzung = request.cookies.get(auth.session_cookie_name) or ""
            ziel_host = (urlsplit(nxt).hostname or "").lower() if "://" in nxt else ""
            # T-22: signed out of this application only — show the page, with "Continue as …",
            # instead of sending back (that would be a loop with forward auth).
            if sitzung and ziel_host and auth.store.gate_ist_abgemeldet(auth.store.session_hash(sitzung), ziel_host):
                u = auth.session_user(request)
                return auth.render_page("login", request=request, next=nxt, error=error, app=app,
                                        app_name=auth._forward_app(nxt)["name"],
                                        resume_user=(u["display_name"] or u["username"]) if u else "")
            # B-2: signed in, but without a (valid) approval for THIS application, the page sent
            # back to `next` — forward auth sent here again, a loop without end.
            # Only the provider grants the approval, so go there.
            sitzung = request.cookies.get(auth.session_cookie_name) or ""
            if app and sitzung and not auth._oidc_approval_valid(auth.store.session_hash(sitzung), app)[0]:
                return RedirectResponse(f"{auth.browser_path(request, '/auth/oidc/start')}"
                                        f"?next={_q(nxt)}&app={_q(app)}", 303)
            return RedirectResponse(nxt, 303)
        return auth.render_page("login", request=request, next=nxt, error=error, app=app,
                                app_name=auth._forward_app(nxt)["name"] if "://" in nxt
                                else (auth._forward_app(gh)["name"] if gh else ""),
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
        voll = auth.session_user(request)
        user = auth.pending_user(request) or voll
        if not user:
            return RedirectResponse(auth.browser_path(request, cfg.login_path), 303)
        if not auth.store.has_confirmed_totp(user["id"]):
            # Factor totp required but not set up → to the setup. Allowed
            # for fully signed-in users and for the chain case (see totp_enrollment_user) — otherwise
            # login_chain=["password","totp"] would be a dead end for every account without TOTP.
            if voll or auth.totp_enrollment_user(request):
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
        # This GET writes NOTHING any more. Until the follow-up it called `totp_begin()` unconditionally:
        # for an account without confirmed TOTP every call thereby created a new secret
        # and replaced an attempt in progress — a foreign link invalidated the
        # QR image just scanned and triggered audit lines from outside. The finding text on B2-1
        # demanded both: refuse with confirmed TOTP AND begin only on explicit
        # request (POST with CSRF token). The secret therefore comes into being only in
        # `POST /auth/totp/setup/start`; this page merely shows the button for it.
        return auth.render_page("totp_setup", request=request, data=None, next=auth.safe_next(next, request))

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
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        return auth.render_page("totp_setup", request=request, data=auth.totp_begin(u["id"]),
                                next=auth.safe_next(next, request))

    @r.post("/auth/totp/setup")
    def totp_setup_confirm(request: Request, code: str = Form(...), next: str = Form("")):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # Both accounts from the cookie (0.20.1, `session_user`): the enrollment branch below
        # completes the session with `complete_totp`.
        voll = auth.session_user(request)
        # Ask before the confirmation — afterwards the account has a confirmed TOTP, and
        # `totp_enrollment_user` says None.
        einschreibung = None if voll else auth.totp_enrollment_user(request)
        # Without both: an API key gets the refusal with reason (403 `api.needs_session`, as
        # on the GET), whoever shows nothing at all gets the usual refusal of `require_session` (401;
        # only a call with `Accept: text/html` is redirected to sign-in — the form
        # of the page sends via `fetch`, so without).
        u = auth.require_session(request, voll or einschreibung)
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
        versuch = (auth._begin_attempt(u["username"], ip, "totp_setup")
                   if auth._rate_ok(ip, login=False) else None)
        if versuch is None:
            raise HTTPException(429, auth.t("api.too_many"))
        ok = auth.totp_confirm(u["id"], code)
        auth._record_login(u["username"], ip, ok, "totp_setup", versuch=versuch)
        if not (ok and einschreibung):
            # B1-7: after a new factor offer to end the other sessions — the number
            # tells the UI whether there is anything to offer.
            return JSONResponse({"ok": ok, "other_sessions": auth.count_other_sessions(request, u) if ok else 0})
        # Mandatory setup under the chain (A-1): the confirmation code IS the TOTP step.
        # It is now consumed; had the user typed it once more at /auth/totp, that would have
        # been a failed attempt — five times, and the login lockout including fail2ban lines
        # would lock the account that has just set itself up correctly.
        auth._record_login(u["username"], ip, True, "totp")
        sitzungs_token = request.cookies.get(auth.session_cookie_name)
        erneuert = auth.complete_totp(sitzungs_token)
        weiter = erneuert or sitzungs_token
        # B1-7 here too: enrollment is precisely the case with old sessions (device
        # lost, operator window). Counted at the NEW session — the old, half one was just
        # deleted by `complete_totp` (otherwise the new one would count as "other").
        # Only if the session is thereby full (`erneuert`): if the chain has another step
        # (password → totp → pin), it stays half, and ending the other sessions
        # would fail with 401 — the page would have asked, the user agreed, and the lost
        # device would stay signed in. Better no offer then; the account page lists the sessions.
        antwort = JSONResponse({"ok": True, "next": auth._login_redirect_after(
            request, weiter, u["id"], auth.safe_next(next, request)),
            "other_sessions": auth.count_other_sessions(request, u, token=erneuert) if erneuert else 0,
            # Boundary d: if the session stays half, the page asks anyway — redeemed at the
            # end of the chain (`/auth/sessions/revoke-after-login`).
            "other_sessions_after": 0 if erneuert else auth.count_other_sessions(request, u)})
        if erneuert:
            auth.set_cookie(antwort, erneuert)   # also rotates the CSRF token on login
        return antwort

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
            u = auth.session_user(request) or auth._pin_kettenschritt(request)
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
                seite = "login"
                if erg.next_factor == "pin":
                    # The PIN stands behind a provided factor: the same PIN page, without a
                    # name field, with the session's account (full or half).
                    seite = "pin"
                    konto = auth.session_user(request) or auth.pending_user(request)
                    if konto:
                        ctx["username"] = konto["username"]
                return auth.render_page(seite, status=erg.status, request=request, **ctx)
            return erg.redirect()

        @r.post("/auth/pin/set")
        async def pin_set(request: Request):
            # R3-3: REPLACING a PIN means exchanging a sign-in factor — only an
            # interactive session with fresh confirmation may do that. An API key gets through here in
            # no case, not even when creating (otherwise the key holder would set the
            # factor of its owner): the bolt therefore stands BEFORE the case distinction
            # and delivers the clear message instead of the freshness excuse.
            u = auth.require_session(request)
            # The rule, exactly: `require_mfa()` applies to replacing AND to creating,
            # as soon as the account has anything at all with which it can confirm — even if that
            # is only its password. Because with `pin_login` a PIN is a full
            # first factor: whoever steals a fresh session cookie would otherwise set up
            # an access of their own that outlives the theft. Typing the password once more
            # is the hurdle that prevents exactly that; the account page leads there by itself via
            # `X-TinySesam-Reauth`. Only an account that has nothing at all
            # (purely federated) depends on the age of the sign-in — otherwise setup
            # would be a dead end for it.
            if auth.has_pin(u["id"]) or auth.stepup_options(u):
                u = auth.require_mfa(request)
            elif not auth.login_fresh(request, u):
                # The FIRST PIN of an account that has nothing with which it could confirm
                # (no password, no PIN, no TOTP — purely federated): `require_mfa()`
                # would be a dead end here, `stepup_options()` is empty and the reauth page
                # would have no field. Creating therefore depends on the age of the sign-in. No
                # `X-TinySesam-Reauth`: the reauth page cannot help this account, a
                # new login can.
                raise HTTPException(403, auth.t("api.stepup_relogin"))
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
            versuch = auth._begin_attempt(pseudo, ip, "resource") if auth._rate_ok(ip, login=False) else None
            if versuch is None:
                return auth.render_page("resource_unlock", request=request, status=429,
                                        **_res_ctx(row, name, nxt, auth.t("err.retry")))
            if not auth._check_resource(name, secret):
                auth._record_login(pseudo, ip, False, "resource", versuch=versuch)
                return auth.render_page("resource_unlock", request=request, status=401, **_res_ctx(row, name, nxt, auth.t("err.credentials")))
            auth._record_login(pseudo, ip, True, "resource", versuch=versuch)
            resp = RedirectResponse(nxt, 303)
            auth._unlock_resource(request, resp, name)
            auth.audit("resource_unlock", ip=ip, detail=name)
            return resp

    # ---------- Magic link (one-time login by e-mail) ----------
    if cfg.magiclink_enabled:
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
            base = _mail_basis(auth, request)
            adresse = email.strip()

            def _versand():
                try:
                    auth.send_login_link(adresse, base, nxt)
                except Exception:
                    auth.audit("magic_send_error", detail=adresse)   # do not leak errors to the outside
            # always the same answer (no user enumeration) — and at the same time: sending
            # happens only after the response (R4-05), in the own mail worker (B6-6).
            return auth.after_response(
                auth.render_page("magic_request", request=request, next=nxt, sent=True, error=""), _versand)

        # R4-02: the link from the mail leads to a confirmation page, only its POST redeems.
        # Mail scanners (safe links, virus checkers, preview bots) open every link via GET —
        # so far this very fetch consumed the token, and the user landed on "link
        # invalid". A GET that signs in also signs in everyone who opens the link,
        # the scanner included. The page only checks (`peek_magic`), redeeming happens with a CSRF token.
        @r.get("/auth/magic/{token}", response_class=HTMLResponse)
        def magic_confirm(request: Request, token: str):
            """Only the sign-in link now. E-mail confirmation and invitation have had their own
            endpoints since 0.16 — otherwise disabling the magic link took both along."""
            if not auth.peek_magic(token, purpose="login"):
                auth._token_rejected("login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("magic_confirm", request=request, purpose="login",
                                    action=auth.browser_path(request, f"/auth/magic/{_q(token)}"))

        @r.post("/auth/magic/{token}")
        def magic_redeem(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            data = auth.redeem_magic(token, purpose="login")
            if not data or not data.get("user_id"):
                auth._token_rejected("login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return _login_nach_token(auth, request, data["user_id"],
                                     auth.safe_next((data.get("payload") or {}).get("next") or "", request))

    # ---------- E-mail confirmation (own endpoint, independent of the magic link) ----------
    if cfg.signup_verify_email:
        @r.get("/auth/verify/{token}", response_class=HTMLResponse)
        def verify_confirm(request: Request, token: str):
            """Confirmation page instead of redeeming via GET — rationale at `/auth/magic/{token}` (R4-02)."""
            if not auth.peek_magic(token, purpose="verify_email"):
                auth._token_rejected("verify_email", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("magic_confirm", request=request, purpose="verify_email",
                                    action=auth.browser_path(request, f"/auth/verify/{_q(token)}"))

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
            if not auth.store.bestaetigung_freischalten(uid):
                konto = auth._kontoname(uid)
                if konto is None:                        # account deleted in the meantime
                    auth._token_rejected("verify_email", request)
                    return auth.render_page("magic_invalid", request=request, status=400)
                auth.audit("verify_blocked", konto, auth.client_ip(request),
                           "account locked by operator")
                return auth.render_page("magic_invalid", request=request, status=403)
            # The redeemed link vouches for the address it went to — as long as it is still the account's
            # (it has not vouched for an address changed in the meantime). Before the sign-in
            # below: there `_maybe_promote_admin` decides about the note on the account.
            konto_zeile = auth.store.get_user(uid)
            if (konto_zeile is not None and konto_zeile["email"] and data.get("email")
                    and norm_email(data.get("email")) == konto_zeile["email"]):
                auth.store.set_email_verified(uid, True)
            # Account and IP belong in the line (B5-02): here an account is unblocked, and
            # without a name `tinysesam audit --user X` did not find the operation.
            auth.audit("email_verified", auth._kontoname(uid), auth.client_ip(request),
                       data.get("email"))
            return _login_nach_token(auth, request, uid, auth.safe_next("", request))

    # ---------- Invitation (own endpoint; the token is consumed only at registration) ----------
    if cfg.allow_signup:
        @r.get("/auth/invite/{token}")
        def invite_redeem(request: Request, token: str):
            if not auth.peek_magic(token, purpose="invite"):
                auth._token_rejected("invite", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return RedirectResponse(f"{auth.browser_path(request, '/auth/register')}?invite={_q(token)}", 303)

    # ---------- First admin via one-time token (only as long as there is no admin) ----------
    @r.get("/auth/claim-admin", response_class=HTMLResponse)
    def claim_admin(request: Request, token: str = ""):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={auth.browser_path(request, '/auth/claim-admin')}?token={_q(token)}", 303)
        if auth.admin_exists():
            raise HTTPException(404)          # no hint that the route once existed
        # Throttled and logged (B5-16): until T-13 a signed-in account could guess here
        # as often as it liked, and no wrong guess left a trace. The token has 192 bits,
        # so guessing is hopeless — but whoever tries should be in the log, namely
        # as `failed verification` (no sign-in attempt, see `security.LOG_PRUEFUNG`).
        ip = auth.client_ip(request)
        if not auth._rate_ok(ip, login=False):
            raise HTTPException(429, auth.t("api.too_many"))
        if not auth._consume_admin_claim(token, u):
            auth._admin_claim_failure(u["username"], ip)
            raise HTTPException(403, auth.t("err.claim"))
        return RedirectResponse(auth.browser_path(request, cfg.admin_path), 303)

    # ---------- Step-up / reauth (sudo freshness for mfa=True guards) ----------
    def _nur_sitzung(request: Request):
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
        and the same rule stands there (`TinySesam._nur_mit_sitzung`).
        """
        u = auth.session_user(request)
        if u is None and cfg.apikey_enabled and auth._extract_api_key(request):
            raise HTTPException(403, auth.t("api.stepup_session"))
        return u

    @r.get("/auth/reauth", response_class=HTMLResponse)
    def reauth_page(request: Request, next: str = "", error: str = ""):
        u = _nur_sitzung(request)
        if not u:
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(auth.safe_next(next, request))}", 303)
        methods = auth.stepup_options(u)
        # An empty list means `stepup_strict=True` and nothing suitable set up. Without a message of its own
        # there would be a page without a single input field here — the user would not see what
        # is expected of them.
        return auth.render_page("reauth", request=request, next=auth.safe_next(next, request),
                                error=error or ("" if methods else auth.t("err.stepup_none")),
                                username=u["username"], methods=methods)

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
                                    methods=auth.stepup_options(u) if u else [], error=erg.message)
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
            base = _mail_basis(auth, request)   # fail closed, see /auth/magic/request
            adresse = email.strip()

            def _versand():
                try:
                    auth.send_password_reset(adresse, base)
                except Exception:
                    auth.audit("reset_send_error", detail=adresse)
            # generic (no enumeration), sending after the response (R4-05/B6-6)
            return auth.after_response(auth.render_page("forgot", request=request, sent=True, error=""),
                                         _versand)

        @r.get("/auth/reset", response_class=HTMLResponse)
        def reset_page(request: Request, token: str = ""):
            if not auth.peek_magic(token, purpose="reset_password"):
                # Without a token (bookmark, crawler) this is no presented link — no entry,
                # otherwise the security log would report a wrong guess that never happened (A3).
                if token:
                    auth._token_rejected("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("reset", request=request, token=token, error="")

        @r.post("/auth/reset", response_class=HTMLResponse)
        def reset_submit(request: Request, token: str = Form(""), password: str = Form(""),
                         csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            # The rule needs the account (context words) — so look it up first, WITHOUT consuming the token:
            # a rejected password should not invalidate the link.
            vorab = auth.peek_magic(token, purpose="reset_password") or {}
            if not vorab.get("user_id"):
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
            konto = auth.store.get_user(vorab["user_id"])
            mangel = auth.password_policy_error(password, username=konto["username"] if konto else None,
                                          email=konto["email"] if konto else None)
            if mangel:
                return auth.render_page("reset", request=request, status=400, token=token, error=mangel)
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
            weg = auth.lift_lockout(uid, methods=("password",))
            # And the API keys (R4-14). Whoever resets their password via "forgot" has lost their
            # account or fears it is taken over — the same case as the
            # admin reset, which has revoked the keys since 0.18.0. A key is a second,
            # equivalent sign-in; had it stayed valid, the reset would only have closed
            # the front door. (The change on the account page leaves them on purpose — there
            # the holder signs in with the old password, that is a routine change.)
            keys = auth._keys_widerrufen(uid, "password_reset")
            # And all open links (self-service attack round, finding 1): an address change
            # that an intruder requested from their session otherwise survived the reset —
            # the link lies in THEIR mailbox, one click later, and the next reset would go to them.
            links = auth.store.revoke_user_magic_tokens(uid)
            auth.audit("password_reset", auth._kontoname(uid), auth.client_ip(request),
                       f"uid={uid} failed_attempts_discarded={weg}"
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
            mangel = auth.password_policy_error(password, username=username, email=email)
            if mangel:
                return err(mangel)
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
            verify_base = _mail_basis(auth, request) if verify else ""
            # In e-mail mode there is no username field — the address IS the identifier.
            if cfg.login_identifier == "email":
                username = email_final or ""
            if not username:
                return err(auth.t("err.username_required"))
            if name_ungueltig(username):
                return err(auth.t("err.username_invalid"))
            # Username = one's own address? Then the address check below covers both.
            name_ist_adresse = bool(email_final) and norm_email(username) == email_final
            # With confirmation a username must not be a FOREIGN address (attack A1): the
            # name check also searches the addresses crosswise and would have revealed with 409
            # that the address exists — R4-03 would be bypassed via the name field.
            if verify and "@" in username and not name_ist_adresse:
                return err(auth.t("err.username_is_address"))
            # Check crosswise: username and e-mail are ONE identifier space (finding R4-12).
            # An address that already serves as another account's username is taken —
            # otherwise the registration occupies that account's login identifier and locks them out.
            # The name comes BEFORE the address (attack A1): the other way round a known,
            # taken name (`admin`) plus target address was an oracle — taken address 200,
            # free address 409 username_taken. A taken name is visible anyway (the
            # user has to choose another); now the answer to it no longer depends on the address.
            if not name_ist_adresse and auth.identifier_taken(username):
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
                        platzhalter = auth.create_user(
                            f"reserviert-{secrets.token_hex(6)}" if name_ist_adresse else username,
                            password=password, roles=[], self_chosen_name=True)
                    except ConfigError:
                        # Race: the name has been taken since the check above (G12c) — the same
                        # answer the check would now give.
                        return err(auth.t("err.username_taken"), 409)
                    auth.store.set_disabled(platzhalter, True)
                    auth.create_magic_token("verify_email", user_id=platzhalter)
                    adresse = email_final

                    def _hinweis():
                        try:
                            auth._send_signup_notice(adresse, verify_base)
                        except Exception:
                            auth.audit("signup_notice_error", detail=adresse)
                    auth.audit("signup_taken", username, ip, detail=adresse)
                    return auth.after_response(
                        auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True)),
                        _hinweis)
                return err(auth.t("err.email_taken"), 409)
            # The address is vouched for here only if it comes from the invitation — the
            # admin sent that to exactly this mailbox. Typed in, it is a claim: with a
            # confirmation requirement the redeemed link provides the proof (`/auth/verify`), without
            # one never. Until schema 10 the default "vouched" stood here, and the deletion by
            # an admin therefore also removed the foreign-typed address from rows from before
            # creation — the admin's invitation, the failed attempts of the real holder
            # (`Store.konto_entfernen`). Rights do not depend on it: an allowlist address
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
                if getattr(e, "field", None) == "username" and not name_ist_adresse:
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

                def _zuruecknehmen(grund):
                    # B6-5: without a delivered confirmation the account is a corpse — blocked,
                    # never unblockable, and it keeps name and address occupied. Until 0.19 an HTTP 500
                    # followed. It is therefore removed again; the registration
                    # can simply be repeated afterwards.
                    # Via the one deletion path (H-13, integration findings 12/18): otherwise
                    # `signup` and this line including the IP would stay under the name, and whoever registers it later
                    # would see them on their account page as their own events (H-7).
                    auth.store.konto_entfernen(uid)
                    auth.audit("verify_send_error", ersatzname(uid), ip,
                               detail=f"{grund}, account removed")

                seite = auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True))
                # The token is created HERE, in the request; only the sending waits for the
                # outbox. A block by the operator discards open tokens (H-18) —
                # had it only come into being in the mail worker, a block in the waiting window found nothing, and
                # the belated link lifted it afterwards. Timing-neutral only with respect to the
                # placeholder branch of a taken address (R4-03, name ≠ address), which creates its
                # token in the request as well. If the name is the address (always with
                # login_identifier='email'), the taken branch writes only the audit line —
                # this timing oracle existed before and is in the backlog (T-13).
                try:
                    senden = auth._verify_mail(uid, email_final, verify_base)
                except Exception:
                    senden = None
                if senden is None:
                    _zuruecknehmen("versand")
                    return seite

                def _versand():
                    try:
                        senden()
                    except Exception:
                        _zuruecknehmen("versand")
                return auth.after_response(
                    seite, _versand, on_overflow=lambda: _zuruecknehmen("warteschlange_voll"))
            token, ok, is_new = auth.apply_factor(request, uid, "password", ip,
                                                  request.headers.get("user-agent"), True)
            resp = RedirectResponse(auth._login_redirect_after(request, token, uid, nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            return resp

    # ---------- Forward auth (reverse proxy: Caddy forward_auth / nginx auth_request / Traefik) ----------
    if cfg.forward_auth_enabled:
        from fastapi.responses import Response

        def _required_roles(request: Request) -> list:
            """Roles that the **proxy** demands for this route: `?roles=a,b` (several allowed)
            or header `X-TinySesam-Roles`. Without it /auth/forward stays binary as before.

            The value is read from the sub-request the proxy makes — it sits in
            its configuration, not with the client. Still, the evaluation is deliberately
            **fail-closed**: several values are AND-ed, commas within one value are
            OR. So if a client itself appends a `roles=` or the header (because a setup passes the
            client query through), it can only tighten the check — never loosen it.
            """
            groups = []
            for raw in list(request.query_params.getlist("roles")) + \
                       [request.headers.get("x-tinysesam-roles") or ""]:
                rs = [r.strip() for r in str(raw).split(",") if r.strip()]
                if rs:
                    groups.append(rs)
            return groups

        def _forward_abweisung_protokollieren(request: Request, orig: str) -> None:
            """A 401 of forward auth into the audit log — if there was evidence (B5-17).

            So far this response wrote nothing. It is logged when the request
            BROUGHT something along that is not (or no longer) valid: a session cookie without a valid session, a
            session in the middle of the factor step, an API key. That is the reason to look —
            an expired, stolen or guessed credential. A call entirely WITHOUT evidence
            is the ordinary first visit before login; logging it would bury the log
            under page views, and the proxy's access log has it anyway. Throttled per
            IP and reason, because a browser with an expired cookie has every sub-request of a page
            (images, scripts) rejected individually.
            """
            if request.cookies.get(auth.session_cookie_name):
                grund = "mfa_open" if auth.pending_user(request) else "session_invalid"
            elif cfg.apikey_enabled and auth._extract_api_key(request):
                grund = "api_key_invalid"
            else:
                return
            ip = auth.client_ip(request)
            if auth._einmal_je(("forward401", ip, grund), 300):
                auth.audit("forward_denied", None, ip,
                           f"reason={grund} url={security.url_fuer_log(orig)}")

        def _link_modus(host: str) -> bool:
            """Central gateway with code exchange (T-26): for a protected app host that is not
            the own one. There is no session there, only the host's connection."""
            from urllib.parse import urlsplit as _us
            return bool(cfg.gate_link_enabled and host and host in auth._gate_hosts()
                        and host != (_us(auth.gate_issuer()).hostname or "").lower())

        def _anmelden_url(orig: str, request: Request, direkt: bool = False) -> str:
            host = (urlsplit(orig).hostname or "").lower()
            if _link_modus(host):
                return auth._gate_link_url(host, orig, request)
            return auth._forward_login_url(orig, request, direkt=direkt)

        def _forward(request: Request):
            u = auth.current_user(request)   # session OR API key
            orig = auth._forwarded_url(request)
            _host = (urlsplit(orig).hostname or "").lower()
            # The session row on which approval, "sign out here only" and gate token depend: from the
            # own cookie, otherwise — central gateway, T-26 — from this host's connection.
            s = auth._session_from_request(request) if u else None
            if not u and _link_modus(_host):
                s = auth._gate_link_sitzung(request, _host)
                u = auth._konto_der_sitzung(s) if s else None
            handle = s["token_hash"] if s else ""
            if u:
                # If this installation protects several applications, "signed in" is not enough:
                # who may enter which one was decided by the provider per client (T-14). The note
                # for it hangs on the SESSION — an API key has none and is not meant
                # here either; for it the previous answer stays.
                anwendung = auth._oidc_application(orig)
                # Signed out of this application only (T-22): the session is valid, just not here —
                # until the human picks "Continue as …" on the login page. Always the page, never the
                # direct path to the provider: that one silently signed in again.
                if handle and _host and auth.store.gate_ist_abgemeldet(handle, _host):
                    return Response(status_code=401,
                                    headers={"X-TinySesam-Location": _anmelden_url(orig, request),
                                             "X-TinySesam-Reason": "app-signed-out",
                                             "WWW-Authenticate": 'FormBased realm="TinySesam"'})
                if anwendung and handle:
                    ja, grund = auth._oidc_approval_valid(handle, anwendung)
                    if not ja:
                        # No 403: the provider should be asked, the human not turned away.
                        # There they usually still have a session, the jump is a flicker for them.
                        # Only if the provider declines does the human see its own refusal —
                        # namely the provider's, because the approval is maintained there.
                        auth.audit("oidc_app_revalidate", u["username"], auth.client_ip(request),
                                   f"app={anwendung} reason={grund}")
                        # Directly to the provider (B-2): via the login page it went in circles, the
                        # page saw the session and sent back.
                        login = _anmelden_url(orig, request, direkt=True)
                        return Response(status_code=401,
                                        headers={"X-TinySesam-Location": login,
                                                 "X-TinySesam-Reason": "app-" + grund,
                                                 "WWW-Authenticate": 'FormBased realm="TinySesam"'})
                # Role check in proxy mode. If the role is missing, it is **403, not 401**:
                # a 401 would send the already signed-in user back to login, which sends them
                # straight back here — a loop at whose end the same role is still missing.
                fehlend = [g for g in _required_roles(request)
                           if not any(auth.has_role(u, r) for r in g)]
                if fehlend:
                    # A 403 in the proxy log does not say who failed at what. The panel has
                    # the audit log anyway — so there, where one looks later.
                    auth.audit("forward_role_denied", u["username"], auth.client_ip(request),
                               f"url={security.url_fuer_log(orig)} missing={';'.join(','.join(g) for g in fehlend)}")
                    return Response(status_code=403, headers={"X-TinySesam-Reason": "role"})
                # Which headers these are is controlled by config.forward_headers (default: Remote-*).
                kopf = auth._forward_response_headers(u)
                # Gate token (ADR-9): the proxy sets it as a cookie on the application's host and
                # then checks it itself — until it expires, no request gets here any more.
                gate = auth._gate_cookie(request, u, orig, _required_roles(request), sitzung=s)
                if gate:
                    kopf["X-TinySesam-Gate-Cookie"] = gate
                return Response(status_code=200, headers=kopf)
            # Login mode of the application (T-21): "direct" leads a page request straight to the
            # provider; background requests always go to the login page.
            direkt = (auth._forward_app(orig)["login"] == "direct" and auth._ist_seitenaufruf(request)
                      and list(cfg.enabled_methods()) == ["oidc"])
            login = _anmelden_url(orig, request, direkt=direkt)
            _forward_abweisung_protokollieren(request, orig)
            # Caddy's forward_auth shortcut passes only the 401 through → handle_response/redir needed
            return Response(status_code=401, headers={"X-TinySesam-Location": login,
                                                      "WWW-Authenticate": 'FormBased realm="TinySesam"'})

        @r.get("/auth/forward")
        def forward_auth(request: Request):
            return _forward(request)

        @r.get("/auth/verify")
        def verify_auth(request: Request):
            return _forward(request)

        # ---------- Signing out at the application (T-22) ----------
        # These paths live on the APPLICATION'S HOST (the proxy passes /.tinysesam/* to TinySesam):
        # only there can the gate cookie be deleted, it is host-only.
        GATE_SCOPES = ("app", "all")

        def _link_aufheben(request: Request, resp) -> None:
            """Sever this browser's connection to this host (T-26): row gone, cookie gone."""
            roh = request.cookies.get(auth._GATE_LINK_COOKIE) or ""
            if roh:
                auth.store.gate_link_entfernen(auth.store.session_hash(roh))
                auth._gate_set_cookie(resp, auth._GATE_LINK_COOKIE, "", 0)

        def _gate_logout(request: Request, host: str, scope: str, nxt: str):
            # The session via the own cookie OR the connection of this host (T-26).
            s = auth._gate_sitzung(request, host)
            u = auth.session_user(request) or auth.pending_user(request) or (auth._konto_der_sitzung(s) if s else None)
            ip = auth.client_ip(request)
            if scope == "app":
                if s:
                    auth.store.gate_abmelden(s["token_hash"], host)
                if u:
                    auth.audit("logout_app", u["username"], ip, f"host={host}")
                resp = RedirectResponse(nxt, 303)
                auth._gate_cookie_loeschen(resp)
                _link_aufheben(request, resp)
                return resp
            # "all" at the app host WITHOUT a connection (e.g. after "sign out here only"): the session lies with the
            # gateway, and only there is its cookie. Go there, it ends there — otherwise it would silently persist.
            if not s and _link_modus(host):
                resp = RedirectResponse(f"{auth.gate_issuer()}{auth.browser_path(request, '/auth/gate/logout')}"
                                        f"?host={_q(host)}", 303)
                auth._gate_cookie_loeschen(resp)
                _link_aufheben(request, resp)
                return resp
            # "all": this session ends — it carries every application behind the same sign-in —, with
            # oidc_rp_logout also the one at the provider, with the ID token as a hint.
            ziel = None
            if cfg.oidc_rp_logout and auth.oidc and s:
                try:
                    faktoren = __import__("json").loads(s["factors_done"] or "[]")
                except Exception:
                    faktoren = []
                if s["method"] == "oidc" or "oidc" in faktoren:
                    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
                    ziel = _provider_logout_url(s, f"{proto}://{host}/.tinysesam/after-logout")
            if u:
                auth.audit("logout", u["username"], ip, f"host={host} scope=all")
            resp = RedirectResponse(ziel or "/.tinysesam/after-logout", 303)
            auth.logout(request, resp)
            # Signed in via the connection: the session lies on the gateway, there is no own cookie
            # here — it ends via its handle, and with it every connection (foreign key).
            if s and not auth._session_from_request(request):
                auth.store.delete_session_by_handle(s["token_hash"])
            auth._gate_cookie_loeschen(resp)
            _link_aufheben(request, resp)
            return resp

        def _weiter_sec(host: str) -> int:
            """Waiting time of the "Signed out" page before it leads back to the application (PO 2026-10-10) — only in
            "direct" mode: there the path "/" starts a new sign-in right at the provider. In "page" mode
            it leads to the own sign-in page, which already shows the sign-out itself."""
            if auth._forward_app(host)["login"] != "direct":
                return 0
            return int(getattr(cfg, "forward_logged_out_sec", 0) or 0)

        def _gate_host_oder_404(request: Request) -> str:
            host = auth._gate_host(request)
            if not host:
                raise HTTPException(404, auth.t("api.not_found"))
            return host

        @r.get("/.tinysesam/logout", response_class=HTMLResponse)
        def gate_logout_get(request: Request, scope: str = "", next: str = ""):
            host = _gate_host_oder_404(request)
            nxt = auth.safe_next(next or "/", request)
            modus = scope if scope in GATE_SCOPES else auth._forward_app(host)["logout"]
            name = auth._forward_app(host)["name"]
            if modus not in GATE_SCOPES:          # "ask"
                return auth.render_page("gate_logout", request=request, scope="", app_name=name, next=nxt)
            # Logout CSRF like /auth/logout (F-07): from a foreign page ask first.
            if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
                return auth.render_page("gate_logout", request=request, scope=modus, app_name=name, next=nxt)
            return _gate_logout(request, host, modus, nxt)

        @r.post("/.tinysesam/logout")
        def gate_logout_post(request: Request, scope: str = Form(""), next: str = Form(""),
                             csrf_tok: str = Form("", alias="_csrf")):
            host = _gate_host_oder_404(request)
            auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
            if scope not in GATE_SCOPES:
                raise HTTPException(400, auth.t("api.invalid", reason="scope (app | all)"))
            return _gate_logout(request, host, scope, auth.safe_next(next or "/", request))

        @r.get("/.tinysesam/after-logout", response_class=HTMLResponse)
        def gate_after_logout(request: Request):
            """Return path from the provider after signing out — triggered by TinySesam or by the
            application itself (its RP logout with this address as logout callback URL). In the
            second case the session still exists: it ends here, from a foreign page only
            after confirmation (F-07)."""
            host = _gate_host_oder_404(request)
            if auth._gate_sitzung(request, host):
                if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
                    return auth.render_page("gate_logout", request=request, scope="all",
                                            app_name=auth._forward_app(host)["name"], next="/")
                return _gate_logout(request, host, "all", "/")
            # Code exchange in "page" mode (PO 2026-10-08): straight to the sign-in page with "You have been signed out",
            # instead of an intermediate page whose only button leads exactly there.
            if _link_modus(host) and auth._forward_app(host)["login"] == "page":
                resp = RedirectResponse("/.tinysesam/start?rd=%2F&signed_out=1", 303)
            else:
                resp = auth.render_page("gate_logged_out", request=request, app_name=auth._forward_app(host)["name"],
                                        redirect_sec=_weiter_sec(host))
            auth._gate_cookie_loeschen(resp)
            return resp

        @r.post("/auth/gate/resume")
        def gate_resume(request: Request, next: str = Form(""), gate_host: str = Form(""),
                        csrf_tok: str = Form("", alias="_csrf")):
            """"Continue as …" on the login page after signing out of this application only.
            `gate_host` (T-26): with the code exchange the page stands on the gateway, `next` points to
            its own path — the application's host then comes along explicitly."""
            auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
            nxt = auth.safe_next(next, request)
            s = auth._session_from_request(request)
            u = auth.session_user(request)
            if not s or not u:
                return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(nxt)}", 303)
            gh = str(gate_host or "").strip().lower()
            host = gh if gh in auth._gate_hosts() else ((urlsplit(nxt).hostname or "").lower() if "://" in nxt else "")
            if host:
                auth.store.gate_fortsetzen(s["token_hash"], host)
                auth.audit("gate_resume", u["username"], auth.client_ip(request), f"host={host}")
            return RedirectResponse(nxt, 303)

        # ---------- Code exchange: central gateway, session stays on its host (T-26) ----------
        if cfg.gate_link_enabled:
            import hashlib as _hashlib

            def _h(wert: str) -> str:
                return _hashlib.sha256(str(wert or "").encode()).hexdigest()

            @r.get("/.tinysesam/start")
            def gate_link_start(request: Request, rd: str = "/", signed_out: str = ""):
                """On the app host: begin the exchange. The flow is bound to THIS browser
                (cookie for this host only), otherwise someone could slip a victim a foreign return path
                and thereby pull them into their account."""
                host = _gate_host_oder_404(request)
                if not auth._rate_ok(auth.client_ip(request)):
                    raise HTTPException(429, auth.t("err.rate"))
                ziel = str(rd or "/")
                # Only a path of THIS host — never a foreign address, never `//` (scheme-relative).
                if not ziel.startswith("/") or ziel.startswith("//") or "\\" in ziel:
                    ziel = "/"
                proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
                ablauf, bindung = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
                auth.store.put_flow("gatelink:" + ablauf, {"host": host, "rd": ziel, "binding": _h(bindung),
                                                           "proto": "http" if proto == "http" else "https",
                                                           "signed_out": signed_out == "1"}, ttl=600)
                basis = auth.gate_issuer()
                resp = RedirectResponse(f"{basis}{auth.browser_path(request, '/auth/gate/authorize')}?flow={_q(ablauf)}", 303)
                auth._gate_set_cookie(resp, auth._GATE_LINKFLOW_COOKIE, bindung, 600)
                return resp

            @r.get("/auth/gate/authorize", response_class=HTMLResponse)
            def gate_link_authorize(request: Request, flow: str = ""):
                """On the gateway: check the session (otherwise sign in), then issue a one-time code for exactly
                this app host and go back there."""
                f = auth.store.pop_flow("gatelink:" + str(flow or ""))
                if not f or f.get("host") not in auth._gate_hosts():
                    raise HTTPException(400, auth.t("api.invalid", reason="flow"))
                host = f["host"]
                hier = f"{auth.browser_path(request, '/auth/gate/authorize')}?flow={_q(flow)}"

                def _zurueck_in_den_ablauf():
                    # The flow waits for the sign-in — the same identifier, new deadline.
                    auth.store.put_flow("gatelink:" + str(flow), f, ttl=600)

                s = auth._session_from_request(request)
                u = auth._konto_der_sitzung(s) if s else None
                anwendung = auth._oidc_application(host)
                if not u:
                    _zurueck_in_den_ablauf()
                    if auth._forward_app(host)["login"] == "direct" and list(cfg.enabled_methods()) == ["oidc"]:
                        ziel = f"{auth.browser_path(request, '/auth/oidc/start')}?next={_q(hier)}"
                    else:
                        # gate_host: the sign-in page sees only `next` (the gateway's path) — without the host
                        # it would say "TinySesam" instead of "Sign in to <app>" (PO 2026-10-08).
                        ziel = f"{auth.browser_path(request, cfg.login_path)}?next={_q(hier)}&gate_host={_q(host)}"
                        if f.get("signed_out"):
                            ziel += "&signed_out=1"
                    if anwendung:
                        ziel += f"&app={_q(anwendung)}"
                    return RedirectResponse(ziel, 303)
                if auth.store.gate_ist_abgemeldet(s["token_hash"], host):
                    _zurueck_in_den_ablauf()
                    return auth.render_page("login", request=request, next=hier, app=anwendung,
                                            app_name=auth._forward_app(host)["name"], gate_host=host,
                                            resume_user=u["display_name"] or u["username"])
                if anwendung and not auth._oidc_approval_valid(s["token_hash"], anwendung)[0]:
                    _zurueck_in_den_ablauf()
                    return RedirectResponse(f"{auth.browser_path(request, '/auth/oidc/start')}?next={_q(hier)}"
                                            f"&app={_q(anwendung)}", 303)
                code = secrets.token_urlsafe(32)
                auth.store.put_flow("gatecode:" + _h(code), {"handle": s["token_hash"], "host": host,
                                                              "rd": f["rd"], "binding": f.get("binding") or ""}, ttl=120)
                return RedirectResponse(f"{f['proto']}://{host}/.tinysesam/callback?code={_q(code)}", 303)

            @r.get("/auth/gate/logout")
            def gate_link_logout(request: Request, host: str = ""):
                """On the gateway: "sign out everywhere", triggered by an app host that does not know
                the session. From a foreign page (logout CSRF, F-07) not here, but
                back to the confirmation on the app host — whose confirmation then comes same-site."""
                h = str(host or "").strip().lower()
                if h not in auth._gate_hosts():
                    raise HTTPException(400, auth.t("api.invalid", reason="host"))
                if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
                    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
                    return RedirectResponse(f"{'http' if proto == 'http' else 'https'}://{h}/.tinysesam/logout", 303)
                if not auth._session_from_request(request):
                    # Here too no session: nothing left to end. Show the "Signed out" page HERE —
                    # not on the app host: whoever bypasses the gate (mesh) reaches no
                    # TinySesam there. And NOT in _gate_logout, which without a session led back here (loop).
                    return RedirectResponse(f"{auth.browser_path(request, '/auth/gate/logged-out')}?host={_q(h)}", 303)
                return _gate_logout(request, h, "all", "/")

            @r.get("/auth/gate/logged-out", response_class=HTMLResponse)
            def gate_link_logged_out(request: Request, host: str = ""):
                """On the gateway: "Signed out" for an app host — with "Sign in again" to THIS app.
                For paths on which the app host has no TinySesam in front of it (mesh bypassing the gate)."""
                h = str(host or "").strip().lower()
                if h not in auth._gate_hosts():
                    raise HTTPException(400, auth.t("api.invalid", reason="host"))
                proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
                # The host comes from the configured list, not from the request: the value that is put into
                # the address is the list's own entry.
                h = next(x for x in auth._gate_hosts() if x == h)
                basis = f"{'http' if proto == 'http' else 'https'}://{h}"
                if auth._forward_app(h)["login"] == "page":
                    return RedirectResponse(f"{basis}/.tinysesam/start?rd=%2F&signed_out=1", 303)
                return auth.render_page("gate_logged_out", request=request, app_name=auth._forward_app(h)["name"],
                                        again_url=f"{basis}/", redirect_sec=_weiter_sec(h))

            @r.get("/.tinysesam/callback")
            def gate_link_callback(request: Request, code: str = ""):
                """On the app host: redeem the code (exactly once, only here, only in the browser that
                began the flow) and create the connection for this host."""
                host = _gate_host_oder_404(request)
                f = auth.store.pop_flow("gatecode:" + _h(code)) if code else None
                bindung = request.cookies.get(auth._GATE_LINKFLOW_COOKIE) or ""
                if (not f or f.get("host") != host or not bindung
                        or not secrets.compare_digest(_h(bindung), str(f.get("binding") or ""))):
                    security.seclog.warning("gate-link: return path without a matching code or without a binding — rejected (host=%s)",
                                            security.fuer_log(host))
                    raise HTTPException(400, auth.t("api.invalid", reason="code"))
                s = auth.store.get_session_by_handle(f["handle"])
                if not s or not s["mfa_ok"]:
                    raise HTTPException(400, auth.t("api.invalid", reason="session"))
                verbindung = secrets.token_urlsafe(32)
                auth.store.gate_link_anlegen(auth.store.session_hash(verbindung), s["token_hash"], host)
                u = auth._konto_der_sitzung(s)
                if u:
                    auth.audit("gate_link", u["username"], auth.client_ip(request), f"host={host}")
                resp = RedirectResponse(f.get("rd") or "/", 303)
                restzeit = max(60, int(s["expires_at"]) - int(__import__("time").time()))
                auth._gate_set_cookie(resp, auth._GATE_LINK_COOKIE, verbindung, restzeit)
                auth._gate_set_cookie(resp, auth._GATE_LINKFLOW_COOKIE, "", 0)
                return resp

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
        return {"ok": True, "api_keys_active": erg.api_keys_active}

    if cfg.account_enabled:
        @r.get("/auth/account", response_class=HTMLResponse)
        def account_page(request: Request):
            u = auth.current_user(request)
            if not u:
                return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={_q(auth.browser_path(request, '/auth/account'))}", 303)
            # The account page asks which factors an account maintains, not what the login page
            # starts with: a PIN that a strict chain permits only as a follow-up factor (G7) needs
            # its section anyway, as does one that the chain demands (with `pin_login=False`).
            methoden = cfg.enabled_methods()
            if cfg.pin_enabled and (cfg.pin_login or "pin" in (cfg.login_chain or [])) and "pin" not in methoden:
                methoden.append("pin")
            return auth.render_page("account", request=request, user=u, methods=methoden,
                                    has_totp=auth.store.has_confirmed_totp(u["id"]),
                                    recovery_left=auth.recovery_codes_remaining(u["id"]),
                                    recovery_warn=auth._RECOVERY_WARN_THRESHOLD,
                                    has_pin=(cfg.pin_enabled and auth.has_pin(u["id"])),
                                    is_admin=bool(u["is_admin"]), admin_path=cfg.admin_path,
                                    events=auth.own_events(u["id"]),
                                    username_change=(cfg.self_service_username_change
                                                     and cfg.login_identifier != "email"
                                                     and not cfg.ldap_enabled),
                                    email_change=(cfg.self_service_email_change and auth.mail_configured()))

    # ---------- Self-service: username and address (PO decision 2026-09-25) ----------
    def _frisch_fuer_kennung(request: Request) -> dict:
        """Whoever changes their identifier confirms freshly beforehand — as when setting up a factor:
        with a stolen session cookie the name or the address could otherwise be bent over,
        and the reset link would then go to the thief. An account without any factor (purely federated)
        depends on the age of the sign-in. No API key (`require_session`)."""
        u = auth.require_session(request)
        if auth.stepup_options(u):
            return auth.require_mfa(request)
        if not auth.login_fresh(request, u):
            raise HTTPException(403, auth.t("api.stepup_relogin"))
        return u

    if cfg.self_service_username_change:
        @r.post("/auth/account/username")
        async def own_username(request: Request):
            b = await auth.json_body(request)
            u = _frisch_fuer_kennung(request)
            if not auth._rate_ok(auth.client_ip(request), login=False):
                raise HTTPException(429, auth.t("api.too_many"))
            try:
                neu = auth.change_username(u["id"], b.get("username"), auth.client_ip(request))
            except ValueError as e:
                raise HTTPException(400, str(e))
            return {"ok": True, "username": neu}

    if cfg.self_service_email_change:
        @r.post("/auth/account/email")
        async def own_email(request: Request):
            b = await auth.json_body(request)
            u = _frisch_fuer_kennung(request)
            if not auth._rate_ok(auth.client_ip(request), login=False):
                raise HTTPException(429, auth.t("api.too_many"))
            try:
                senden = auth.request_email_change(u["id"], b.get("email"), auth.public_base(request))
            except ConfigError:
                # First: `ConfigError` IS a `ValueError` (CodeQL py/unreachable-except). In
                # the reverse order the message about the base address went out as response text.
                raise HTTPException(400, auth.t("api.no_mail"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            # The same answer whether a link goes out or not (taken address, throttle) —
            # and sending only after the response (R4-05): no running time as an oracle.
            # If the queue is full, the token expires (`senden.verwerfen`): a link that was never
            # delivered would otherwise block the path via LDAP/SAML until its expiry.
            antwort = JSONResponse({"ok": True, "sent": True})
            return auth.after_response(antwort, senden, on_overflow=senden.verwerfen) \
                if senden else antwort

        @r.get("/auth/email/{token}", response_class=HTMLResponse)
        def email_confirm_page(request: Request, token: str):
            """Confirmation page instead of redeeming via GET — link scanners redeem nothing (R4-02)."""
            if not auth.peek_magic(token, purpose="email_change"):
                auth._token_rejected("email_change", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("magic_confirm", request=request, purpose="email_change",
                                    action=auth.browser_path(request, f"/auth/email/{_q(token)}"))

        @r.post("/auth/email/{token}")
        def email_confirm(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            ergebnis = auth.confirm_email_change(token, auth.client_ip(request))
            if ergebnis is None:
                auth._token_rejected("email_change", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            if ergebnis == "taken":
                return auth.render_page("magic_invalid", request=request, status=409)
            ziel = auth.browser_path(request, "/auth/account" if cfg.account_enabled else cfg.login_redirect)
            return RedirectResponse(ziel, 303)

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
        cur_tok = cur["token_hash"] if cur else None
        out = []
        for s in auth.store.list_sessions(u["id"]):
            out.append({"created_at": s["created_at"], "ip": s["ip"], "method": s["method"],
                        "user_agent": (s["user_agent"] or "")[:120], "current": s["token_hash"] == cur_tok})
        return out

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
        auth.store.set_session_andere_beenden(s["token_hash"])
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
        keys_widerrufen = 0
        if scope == "all":
            auth.store.delete_user_sessions(u["id"])          # incl. current → signed out
            keys_widerrufen = auth._keys_widerrufen(u["id"], "sessions_revoked")
            auth.store.revoke_user_magic_tokens(u["id"])      # panic button: open links too (finding 1)
        else:
            cur = auth._session_from_request(request)
            auth.store.delete_user_sessions_except(u["id"], cur["token_hash"] if cur else None)
            # An open address change may stem from one of the ended sessions (finding 1).
            auth.store.revoke_user_magic_tokens(u["id"], purposes=("email_change",))
        auth.audit("sessions_revoke", u["username"], auth.client_ip(request),
                   scope + (f" api_keys_revoked={keys_widerrufen}" if keys_widerrufen else ""))
        return {"ok": True, "api_keys_revoked": keys_widerrufen,
                "api_keys_active": auth.store.count_active_api_keys(u["id"])}

    # ---------- Logout / me ----------
    def _provider_logout_url(s, zurueck: str):
        """Logout at the provider, with the sign-in's ID token as a hint (T-22) — and with THE
        client through which it ran: PocketID accepts the hint only for the matching client."""
        gespeichert = auth.store.get_oidc_id_token(s["token_hash"]) if s else None
        client, hinweis = gespeichert if gespeichert else ("", None)
        registry = getattr(auth, "oidc_clients", None)
        oidc = registry[client] if (client and registry is not None and registry.bekannt(client)) else auth.oidc
        return oidc.end_session_url(zurueck, id_token_hint=hinweis)

    def _abmelden(request: Request):
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
        return _abmelden(request)

    @r.post("/auth/logout")
    def logout_post(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        """Sign out via form — with CSRF check, the way for custom UIs."""
        auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
        return _abmelden(request)

    @r.get("/auth/me")
    def me(request: Request):
        u = auth.current_user(request)
        if not u:
            return JSONResponse({"authenticated": False}, 401)
        return {"authenticated": True, "id": u["id"], "username": u["username"],
                "display_name": u["display_name"], "is_admin": bool(u["is_admin"]),
                "roles": auth.user_roles(u)}

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
            from .saml_ import request_kontext
            return request_kontext(_saml_basis(request), request.url.path,
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

        # SAML builds its own entity ID and the ACS URL from the base. If it comes from the
        # Host header, a foreign name migrates into the AuthnRequest and the metadata —
        # hence no carrying on here without a checked base (R4-01).
        def _saml_basis(request: Request) -> str:
            return auth.require_public_base(request, _saml_base(request))

        @r.get("/auth/saml/login")
        def saml_login(request: Request, next: str = ""):
            base = _saml_basis(request)
            url, rid = auth.saml.login_url(_saml_req(request), base, return_to=auth.safe_next(next, request))
            resp = RedirectResponse(url, 303)
            # `__Host-` in front where possible (A-1) — otherwise a neighbour subdomain sets the anchor.
            auth._flow_cookie_setzen(resp, _SAMLFLOW, rid or "", max_age=600,
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
            base = _saml_basis(request)
            data = auth.saml.process(_saml_req(request, form), base,
                                     request_id=request.cookies.get(auth.flow_cookie_name(_SAMLFLOW)) or "")
            if not data:
                # NOT the magic-link page ("this link is invalid, expired or already
                # used") — this was about no link, and the message sent the first
                # run against a real IdP in the wrong direction. The reason is in the log.
                auth.audit("saml_invalid", None, ip, "assertion rejected (reason in the security log)")
                raise HTTPException(400, auth.t("err.saml"))
            u = auth._check_saml(data.get("nameid"), data.get("attrs") or {}, ip=ip)
            if not u:
                # The reason (group, no account, blocked, identifier taken) is written by
                # `_check_saml` itself into the audit log — here only the answer to the browser.
                raise HTTPException(403, auth.t("api.saml_denied"))
            nxt = auth.safe_next(form.get("RelayState") or "", request)
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
                                                      (cfg.saml_email_trusted or security.beleg_attribut(cfg, "saml"))
                                                      and u.get("email")
                                                      and u.get("email_verified")))
            resp = RedirectResponse(auth._login_redirect_after(request, token, u["id"], nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            # requested once, redeemed once
            auth._flow_cookie_loeschen(resp, _SAMLFLOW,
                                      samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
            return resp

        @r.get("/auth/saml/metadata")
        def saml_metadata(request: Request):
            base = _saml_basis(request)
            return _Resp(content=auth.saml.metadata(base), media_type="application/xml")

    # ---------- API keys: self-service for the signed-in user ----------
    if cfg.apikey_enabled:
        @r.get("/auth/apikeys")
        def apikeys_list(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            return [key_view(k) for k in auth.list_api_keys(u["id"])]

        def _nur_mit_sitzung(request: Request):
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
            u = _nur_mit_sitzung(request)
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
            u = _nur_mit_sitzung(request)
            auth.revoke_api_key(key_id, u["id"])   # block, do not delete
            return {"ok": True}

    # ---------- Admin panel — at config.admin_path; mountable elsewhere via auth.admin_router() ----------
    if cfg.admin_enabled:
        r.include_router(auth.admin_router(), prefix=cfg.admin_path)

    return r


def _mail_basis(auth, request) -> str:
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
        if security.einmal_melden("mail_basis"):
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


def _login_nach_token(auth, request, uid, nxt):
    """After a redeemed e-mail token, sign in (factor `magic`) and redirect.

    Common to sign-in link and e-mail confirmation: both prove the same — the recipient
    has access to the mailbox. A global factor chain can still demand a further step;
    that is why the path goes via `apply_factor`/`_login_redirect_after` instead of straight into
    a session.
    """
    from fastapi.responses import RedirectResponse
    token, ok, is_new = auth.apply_factor(request, uid, "magic",
                                          auth.client_ip(request), request.headers.get("user-agent"))
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

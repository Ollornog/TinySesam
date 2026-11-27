"""Forward auth and the gate: /auth/forward for the reverse proxy, the gate token, the app-host code exchange and its sign-out paths.

Registered by `router.build_router` only when `cfg.forward_auth_enabled` is on: with it off this module is never
imported (T-112).
"""
from __future__ import annotations

import secrets
from urllib.parse import quote, urlsplit

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from . import app_passwords as _ap
from . import security


def _q(s: str) -> str:
    """A path for a query value (the same rule as `router._q`)."""
    return quote(s or "/", safe="/")


def add_routes(r, auth, cfg, *, _account_json, _provider_logout_url, _topbar_json) -> None:
    """The routes of this building block on the router `r`."""
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

    def _log_forward_rejection(request: Request, orig: str) -> None:
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
            reason = "mfa_open" if auth.pending_user(request) else "session_invalid"
        elif cfg.apikey_enabled and auth._extract_api_key(request):
            reason = "api_key_invalid"
        else:
            return
        ip = auth.client_ip(request)
        if auth._once_per(("forward401", ip, reason), 300):
            auth.audit("forward_denied", None, ip,
                       f"reason={reason} url={security.url_for_log(orig)}")

    def _link_mode(host: str) -> bool:
        """Central gateway with code exchange (T-26): for a protected app host that is not
        the own one. There is no session there, only the host's connection."""
        from urllib.parse import urlsplit as _us
        return bool(cfg.gate_link_enabled and host and host in auth._gate_hosts()
                    and host != (_us(auth.gate_issuer()).hostname or "").lower())

    def _sign_in_url(orig: str, request: Request, direct: bool = False) -> str:
        host = (urlsplit(orig).hostname or "").lower()
        if _link_mode(host):
            return auth._gate_link_url(host, orig, request)
        return auth._forward_login_url(orig, request, direct=direct)

    def _bearer(request: Request) -> str:
        h = request.headers.get("authorization", "")
        return h[7:].strip() if h[:7].lower() == "bearer " else ""

    # The applications that take app passwords (T-66) — fixed with the configuration, like the routes.
    app_password_hosts = auth.app_password_hosts()

    def _from_browser(request: Request) -> bool:
        """Does the proxied request come from a browser? Browsers send `Sec-Fetch-*` with every request
        (also with scripts and images); WebDAV, CalDAV and Git clients send none. Older browsers: `Accept`
        with text/html for a page."""
        h = request.headers
        if any(k.startswith("sec-fetch-") for k in h.keys()):
            return True
        return "text/html" in (h.get("accept") or "").lower()

    def _forward(request: Request):
        orig = auth._forwarded_url(request)
        if auth._forwarded_conflict(request):
            # X-Original-URL and X-Forwarded-* name different targets (attack round B, F1): one of them is
            # the browser's own. No credential is looked at — whichever host was chosen, it could be the
            # wrong one. The sign-in page for the X-Forwarded-* target, as for anyone not signed in.
            ip = auth.client_ip(request)
            if auth._once_per(("forward401", ip, "forwarded_conflict"), 300):
                security.seclog.warning(
                    "forward auth refused from %s: X-Original-URL and X-Forwarded-Host/-Proto/-Uri name "
                    "different targets — the proxy passes one of them through from the client; let the "
                    "proxy set or remove both (see deploy/forward-auth)", security.for_log(ip))
                auth.audit("forward_denied", None, ip,
                           f"reason=forwarded_conflict url={security.url_for_log(orig)}")
            return Response(status_code=401, headers={"X-TinySesam-Location": _sign_in_url(orig, request),
                                                      "X-TinySesam-Reason": "forwarded-conflict",
                                                      "WWW-Authenticate": 'FormBased realm="TinySesam"'})
        u = auth.current_user(request)   # session OR API key
        # OAuth access token (T-36): only here, at the resource — never at TinySesam's own routes. The
        # account, the grant and the audience are checked on every request.
        oauth_resource = auth._oauth.resource_for(orig) if (cfg.oauth_enabled and auth._oauth) else None
        presented = _bearer(request)
        if not u and cfg.oauth_enabled and auth._oauth and presented.startswith("tsat_"):
            u, why = auth._oauth.user_for(presented, orig, auth.client_ip(request))
            if not u:
                ip = auth.client_ip(request)
                if auth._once_per(("forward401", ip, "oauth_" + why), 300):
                    auth.audit("forward_denied", None, ip,
                               f"reason=oauth_token_{why} url={security.url_for_log(orig)}")
                if oauth_resource:
                    return Response(status_code=401, headers={
                        "WWW-Authenticate": auth._oauth.challenge(oauth_resource, True),
                        "X-TinySesam-Reason": "oauth"})
        _host = (urlsplit(orig).hostname or "").lower()
        # App password by Basic auth (T-66): only for an application that allows it, and only when nothing
        # else signed the request in. A refused one answers with a Basic challenge further down.
        app_pw = bool(app_password_hosts) and auth._forward_app(orig)["app_passwords"]
        basic_refused = ""
        if not u and app_pw:
            u, outcome = auth._app_password_user(request, orig)
            basic_refused = "" if u else outcome
        # The session row on which approval, "sign out here only" and gate token depend: from the
        # own cookie, otherwise — central gateway, T-26 — from this host's connection.
        s = auth._session_from_request(request) if u and u.get("_via") not in ("oauth", "app_password") else None
        if not u and _link_mode(_host):
            s = auth._gate_link_session(request, _host)
            u = auth._account_of_session(s) if s else None
        handle = s["token_hash"] if s else ""
        if u:
            # If this installation protects several applications, "signed in" is not enough:
            # who may enter which one was decided by the provider per client (T-14). The note
            # for it hangs on the SESSION — an API key has none and is not meant
            # here either; for it the previous answer stays.
            application = auth._oidc_application(orig)
            # Signed out of this application only (T-22): the session is valid, just not here —
            # until the human picks "Continue as …" on the login page. Always the page, never the
            # direct path to the provider: that one silently signed in again.
            if handle and _host and auth.store.gate_is_signed_out(handle, _host):
                return Response(status_code=401,
                                headers={"X-TinySesam-Location": _sign_in_url(orig, request),
                                         "X-TinySesam-Reason": "app-signed-out",
                                         "WWW-Authenticate": 'FormBased realm="TinySesam"'})
            if application and handle:
                yes, reason = auth._oidc_approval_valid(handle, application)
                if not yes:
                    # No 403: the provider should be asked, the human not turned away.
                    # There they usually still have a session, the jump is a flicker for them.
                    # Only if the provider declines does the human see its own refusal —
                    # namely the provider's, because the approval is maintained there.
                    auth.audit("oidc_app_revalidate", u["username"], auth.client_ip(request),
                               f"app={application} reason={reason}")
                    # Directly to the provider (B-2): via the login page it went in circles, the
                    # page saw the session and sent back.
                    login = _sign_in_url(orig, request, direct=True)
                    return Response(status_code=401,
                                    headers={"X-TinySesam-Location": login,
                                             "X-TinySesam-Reason": "app-" + reason,
                                             "WWW-Authenticate": 'FormBased realm="TinySesam"'})
            # Role check in proxy mode. If the role is missing, it is **403, not 401**:
            # a 401 would send the already signed-in user back to login, which sends them
            # straight back here — a loop at whose end the same role is still missing.
            absent = [g for g in _required_roles(request)
                       if not any(auth.has_role(u, r) for r in g)]
            if absent:
                # A 403 in the proxy log does not say who failed at what. The panel has
                # the audit log anyway — so there, where one looks later.
                auth.audit("forward_role_denied", u["username"], auth.client_ip(request),
                           f"url={security.url_for_log(orig)} missing={';'.join(','.join(g) for g in absent)}")
                return Response(status_code=403, headers={"X-TinySesam-Reason": "role"})
            # Which headers these are is controlled by config.forward_headers (default: Remote-*).
            head = auth._forward_response_headers(u, _host)
            # Gate token (ADR-9): the proxy sets it as a cookie on the application's host and
            # then checks it itself — until it expires, no request gets here any more.
            gate = auth._gate_cookie(request, u, orig, _required_roles(request), session=s)
            if gate:
                head["X-TinySesam-Gate-Cookie"] = gate
            return Response(status_code=200, headers=head)
        # An application that takes app passwords (T-66) asks a client without a browser for Basic auth
        # (RFC 7617) — a WebDAV or CalDAV client cannot follow a redirect to a sign-in page. A browser
        # (`Sec-Fetch-*`, or `Accept: text/html`) still goes to the sign-in page: a Basic challenge there would
        # pop up the browser's own password dialog. `X-TinySesam-Location` stays for a proxy template
        # without the `basic` branch. Under an OAuth resource (T-36) a client without credentials gets the
        # Bearer challenge below — an MCP client must learn where to sign in, not be asked for a password.
        if app_pw and (basic_refused or (not oauth_resource and not _from_browser(request))):
            _log_forward_rejection(request, orig)
            return Response(status_code=401, headers={
                "WWW-Authenticate": auth._header_value(_ap.challenge(auth._forward_app(orig)["name"] or _host)),
                "X-TinySesam-Reason": "basic",
                "X-TinySesam-Location": _sign_in_url(orig, request)})
        # An OAuth resource answers like one (RFC 9728 §5.1): the client learns where to get a token —
        # no redirect to a login page it cannot show.
        if oauth_resource:
            _log_forward_rejection(request, orig)
            return Response(status_code=401, headers={
                "WWW-Authenticate": auth._oauth.challenge(oauth_resource, bool(presented)),
                "X-TinySesam-Reason": "oauth"})
        # Login mode of the application (T-21): "direct" leads a page request straight to the
        # provider; background requests always go to the login page.
        direct = (auth._forward_app(orig)["login"] == "direct" and auth._is_page_view(request)
                  and list(cfg.enabled_methods()) == ["oidc"])
        login = _sign_in_url(orig, request, direct=direct)
        _log_forward_rejection(request, orig)
        # Caddy's forward_auth shortcut passes only the 401 through → handle_response/redir needed
        return Response(status_code=401, headers={"X-TinySesam-Location": login,
                                                  "WWW-Authenticate": 'FormBased realm="TinySesam"'})

    @r.get("/auth/forward")
    def forward_auth(request: Request):
        return _forward(request)

    @r.get("/auth/gate/jwks.json")
    def gate_jwks():
        """The public gate keys (T-48) for caddy-jwt's `jwk_url`: active + previous within their overlap. Public
        like any JWKS — it carries no secret. Five minutes in a cache: a rotation reaches the proxy anyway,
        because an unknown `kid` makes caddy-jwt fetch the set again."""
        return JSONResponse(auth.gate_jwks(), headers={"Cache-Control": "public, max-age=300"})

    @r.get("/auth/verify")
    def verify_auth(request: Request):
        return _forward(request)

    # ---------- Signing out at the application (T-22) ----------
    # These paths live on the APPLICATION'S HOST (the proxy passes /.tinysesam/* to TinySesam):
    # only there can the gate cookie be deleted, it is host-only.
    GATE_SCOPES = ("app", "all")

    def _lift_link(request: Request, resp) -> None:
        """Sever this browser's connection to this host (T-26): row gone, cookie gone."""
        raw = request.cookies.get(auth._GATE_LINK_COOKIE) or ""
        if raw:
            auth.store.remove_gate_link(auth.store.session_hash(raw))
            auth._gate_set_cookie(resp, auth._GATE_LINK_COOKIE, "", 0)

    def _gate_logout(request: Request, host: str, scope: str, nxt: str):
        # The session via the own cookie OR the connection of this host (T-26).
        s = auth._gate_session(request, host)
        u = auth.session_user(request) or auth.pending_user(request) or (auth._account_of_session(s) if s else None)
        ip = auth.client_ip(request)
        if scope == "app":
            if s:
                auth.store.gate_sign_out(s["token_hash"], host)
            if u:
                auth.audit("logout_app", u["username"], ip, f"host={host}")
            resp = RedirectResponse(nxt, 303)
            auth._delete_gate_cookie(resp)
            _lift_link(request, resp)
            return resp
        # "all" at the app host WITHOUT a connection (e.g. after "sign out here only"): the session lies with the
        # gateway, and only there is its cookie. Go there, it ends there — otherwise it would silently persist.
        if not s and _link_mode(host):
            resp = RedirectResponse(f"{auth.gate_issuer()}{auth.browser_path(request, '/auth/gate/logout')}"
                                    f"?host={_q(host)}", 303)
            auth._delete_gate_cookie(resp)
            _lift_link(request, resp)
            return resp
        # "all": this session ends — it carries every application behind the same sign-in —, with
        # oidc_rp_logout also the one at the provider, with the ID token as a hint.
        destination = None
        if cfg.oidc_rp_logout and auth.oidc and s:
            try:
                factors = __import__("json").loads(s["factors_done"] or "[]")
            except Exception:
                factors = []
            if s["method"] == "oidc" or "oidc" in factors:
                proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
                destination = _provider_logout_url(s, f"{proto}://{host}/.tinysesam/after-logout")
        if u:
            auth.audit("logout", u["username"], ip, f"host={host} scope=all")
        resp = RedirectResponse(destination or "/.tinysesam/after-logout", 303)
        auth.logout(request, resp)
        # Signed in via the connection: the session lies on the gateway, there is no own cookie
        # here — it ends via its handle, and with it every connection (foreign key).
        if s and not auth._session_from_request(request):
            auth.store.delete_session_by_handle(s["token_hash"])
        auth._delete_gate_cookie(resp)
        _lift_link(request, resp)
        return resp

    def _further_sec(host: str) -> int:
        """Waiting time of the "Signed out" page before it leads back to the application (PO 2026-10-10) — only in
        "direct" mode: there the path "/" starts a new sign-in right at the provider. In "page" mode
        it leads to the own sign-in page, which already shows the sign-out itself."""
        if auth._forward_app(host)["login"] != "direct":
            return 0
        return int(getattr(cfg, "forward_logged_out_sec", 0) or 0)

    def _gate_host_or_404(request: Request) -> str:
        host = auth._gate_host(request)
        if not host:
            raise HTTPException(404, auth.t("api.not_found"))
        return host

    @r.get("/.tinysesam/logout", response_class=HTMLResponse)
    def gate_logout_get(request: Request, scope: str = "", next: str = ""):
        host = _gate_host_or_404(request)
        nxt = auth.safe_next(next or "/", request)
        mode = scope if scope in GATE_SCOPES else auth._forward_app(host)["logout"]
        name = auth._forward_app(host)["name"]
        if mode not in GATE_SCOPES:          # "ask"
            return auth.render_page("gate_logout", request=request, scope="", app_name=name, next=nxt)
        # Logout CSRF like /auth/logout (F-07): from a foreign page ask first.
        if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
            return auth.render_page("gate_logout", request=request, scope=mode, app_name=name, next=nxt)
        return _gate_logout(request, host, mode, nxt)

    @r.post("/.tinysesam/logout")
    def gate_logout_post(request: Request, scope: str = Form(""), next: str = Form(""),
                         csrf_tok: str = Form("", alias="_csrf")):
        host = _gate_host_or_404(request)
        auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
        if scope not in GATE_SCOPES:
            raise HTTPException(400, auth.t("api.invalid", reason="scope (app | all)"))
        return _gate_logout(request, host, scope, auth.safe_next(next or "/", request))

    @r.get("/.tinysesam/topbar.json")
    def gate_topbar_json(request: Request):
        """The top bar as data on the APPLICATION'S host (T-76): the page of an application behind the gate fetches
        it same-origin — the proxy passes /.tinysesam/* to TinySesam with the browser's cookies, which it strips
        before the application. The session via the own cookie or this host's connection (T-26)."""
        host = _gate_host_or_404(request)
        s = auth._gate_session(request, host)
        return _topbar_json(auth._account_of_session(s) if s else None, request)

    @r.get("/.tinysesam/account.json")
    def gate_account_json(request: Request):
        """The own account as data on the APPLICATION'S host (T-91), like `/.tinysesam/topbar.json`: fetched
        same-origin by the application's page, the session via the own cookie or this host's connection (T-26).
        The links carry `app=<host>` when the host has an app frame. Read only — no writing route under
        `/.tinysesam/`, where the application's host counts as an own origin."""
        host = _gate_host_or_404(request)
        s = auth._gate_session(request, host)
        return _account_json(auth._account_of_session(s) if s else None, request, host)

    @r.get("/.tinysesam/after-logout", response_class=HTMLResponse)
    def gate_after_logout(request: Request):
        """Return path from the provider after signing out — triggered by TinySesam or by the
        application itself (its RP logout with this address as logout callback URL). In the
        second case the session still exists: it ends here, from a foreign page only
        after confirmation (F-07)."""
        host = _gate_host_or_404(request)
        if auth._gate_session(request, host):
            if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
                return auth.render_page("gate_logout", request=request, scope="all",
                                        app_name=auth._forward_app(host)["name"], next="/")
            return _gate_logout(request, host, "all", "/")
        # Code exchange in "page" mode (PO 2026-10-08): straight to the sign-in page with "You have been signed out",
        # instead of an intermediate page whose only button leads exactly there.
        if _link_mode(host) and auth._forward_app(host)["login"] == "page":
            resp = RedirectResponse("/.tinysesam/start?rd=%2F&signed_out=1", 303)
        else:
            resp = auth.render_page("gate_logged_out", request=request, app_name=auth._forward_app(host)["name"],
                                    redirect_sec=_further_sec(host))
        auth._delete_gate_cookie(resp)
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
            auth.store.gate_resume(s["token_hash"], host)
            auth.audit("gate_resume", u["username"], auth.client_ip(request), f"host={host}")
        return RedirectResponse(nxt, 303)

    # ---------- Code exchange: central gateway, session stays on its host (T-26) ----------
    if cfg.gate_link_enabled:
        # The one-time code and the browser binding are stored as an HMAC with the pepper (`Store.token_digest`,
        # kinds `gatecode`/`gatebinding`, @51b7a1). Up to 0.30.0 they were a plain sha256: whoever could write the
        # database file put a `gatecode:` row for a chosen code and binding next to a session handle (the handles
        # stand in the file) and redeemed it at the app host — a connection into that session. Looked up with
        # every pepper of the keyring, the active one first: an exchange begun before a rotation still ends.
        def _binding_digest(value: str) -> str:
            return auth.store.token_digests(str(value or ""), "gatebinding")[0]

        def _binding_matches(value: str, stored: str) -> bool:
            return any(secrets.compare_digest(d, str(stored or ""))
                       for d in auth.store.token_digests(str(value or ""), "gatebinding"))

        def _pop_code(code: str):
            for d in auth.store.token_digests(str(code or ""), "gatecode"):
                f = auth.store.pop_flow("gatecode:" + d)
                if f is not None:
                    return f
            return None

        @r.get("/.tinysesam/start")
        def gate_link_start(request: Request, rd: str = "/", signed_out: str = ""):
            """On the app host: begin the exchange. The flow is bound to THIS browser
            (cookie for this host only), otherwise someone could slip a victim a foreign return path
            and thereby pull them into their account."""
            host = _gate_host_or_404(request)
            if not auth._rate_ok(auth.client_ip(request)):
                raise HTTPException(429, auth.t("err.rate"))
            destination = str(rd or "/")
            # Only a path of THIS host — never a foreign address, never `//` (scheme-relative).
            if not destination.startswith("/") or destination.startswith("//") or "\\" in destination:
                destination = "/"
            proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
            expiry, binding = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            auth.store.put_flow("gatelink:" + expiry, {"host": host, "rd": destination, "binding": _binding_digest(binding),
                                                       "proto": "http" if proto == "http" else "https",
                                                       "signed_out": signed_out == "1"}, ttl=600)
            base = auth.gate_issuer()
            resp = RedirectResponse(f"{base}{auth.browser_path(request, '/auth/gate/authorize')}?flow={_q(expiry)}", 303)
            auth._gate_set_cookie(resp, auth._GATE_LINKFLOW_COOKIE, binding, 600)
            return resp

        @r.get("/auth/gate/authorize", response_class=HTMLResponse)
        def gate_link_authorize(request: Request, flow: str = ""):
            """On the gateway: check the session (otherwise sign in), then issue a one-time code for exactly
            this app host and go back there."""
            f = auth.store.pop_flow("gatelink:" + str(flow or ""))
            if not f or f.get("host") not in auth._gate_hosts():
                raise HTTPException(400, auth.t("api.invalid", reason="flow"))
            host = f["host"]
            here = f"{auth.browser_path(request, '/auth/gate/authorize')}?flow={_q(flow)}"

            def _back_into_the_flow():
                # The flow waits for the sign-in — the same identifier, new deadline.
                auth.store.put_flow("gatelink:" + str(flow), f, ttl=600)

            s = auth._session_from_request(request)
            u = auth._account_of_session(s) if s else None
            application = auth._oidc_application(host)
            if not u:
                _back_into_the_flow()
                if auth._forward_app(host)["login"] == "direct" and list(cfg.enabled_methods()) == ["oidc"]:
                    destination = f"{auth.browser_path(request, '/auth/oidc/start')}?next={_q(here)}"
                else:
                    # gate_host: the sign-in page sees only `next` (the gateway's path) — without the host
                    # it would say "TinySesam" instead of "Sign in to <app>" (PO 2026-10-08).
                    destination = f"{auth.browser_path(request, cfg.login_path)}?next={_q(here)}&gate_host={_q(host)}"
                    if f.get("signed_out"):
                        destination += "&signed_out=1"
                if application:
                    destination += f"&app={_q(application)}"
                return RedirectResponse(destination, 303)
            if auth.store.gate_is_signed_out(s["token_hash"], host):
                _back_into_the_flow()
                return auth.render_page("login", request=request, next=here, app=application,
                                        app_name=auth._forward_app(host)["name"], gate_host=host,
                                        resume_user=u["display_name"] or u["username"])
            if application and not auth._oidc_approval_valid(s["token_hash"], application)[0]:
                _back_into_the_flow()
                return RedirectResponse(f"{auth.browser_path(request, '/auth/oidc/start')}?next={_q(here)}"
                                        f"&app={_q(application)}", 303)
            code = secrets.token_urlsafe(32)
            auth.store.put_flow("gatecode:" + auth.store.token_digests(code, "gatecode")[0],
                                {"handle": s["token_hash"], "host": host, "rd": f["rd"],
                                 "binding": f.get("binding") or ""}, ttl=120)
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
            base = f"{'http' if proto == 'http' else 'https'}://{h}"
            if auth._forward_app(h)["login"] == "page":
                return RedirectResponse(f"{base}/.tinysesam/start?rd=%2F&signed_out=1", 303)
            return auth.render_page("gate_logged_out", request=request, app_name=auth._forward_app(h)["name"],
                                    again_url=f"{base}/", redirect_sec=_further_sec(h))

        @r.get("/.tinysesam/callback")
        def gate_link_callback(request: Request, code: str = ""):
            """On the app host: redeem the code (exactly once, only here, only in the browser that
            began the flow) and create the connection for this host."""
            host = _gate_host_or_404(request)
            f = _pop_code(code) if code else None
            binding = request.cookies.get(auth._GATE_LINKFLOW_COOKIE) or ""
            if (not f or f.get("host") != host or not binding
                    or not _binding_matches(binding, f.get("binding") or "")):
                security.seclog.warning("gate-link: return path without a matching code or without a binding — rejected (host=%s)",
                                        security.for_log(host))
                raise HTTPException(400, auth.t("api.invalid", reason="code"))
            s = auth.store.get_session_by_handle(f["handle"])
            if not s or not s["mfa_ok"]:
                raise HTTPException(400, auth.t("api.invalid", reason="session"))
            connection = secrets.token_urlsafe(32)
            auth.store.create_gate_link(auth.store.session_hash(connection), s["token_hash"], host)
            u = auth._account_of_session(s)
            if u:
                auth.audit("gate_link", u["username"], auth.client_ip(request), f"host={host}")
            resp = RedirectResponse(f.get("rd") or "/", 303)
            remaining_time = max(60, int(s["expires_at"]) - int(__import__("time").time()))
            auth._gate_set_cookie(resp, auth._GATE_LINK_COOKIE, connection, remaining_time)
            auth._gate_set_cookie(resp, auth._GATE_LINKFLOW_COOKIE, "", 0)
            return resp

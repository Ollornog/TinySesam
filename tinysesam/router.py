"""FastAPI-Router: /auth/* — Login (Passwort), TOTP-2FA + -Einrichtung, Logout, /me.
OIDC- und Passkey-Routen werden nur registriert, wenn in der Config aktiviert."""
from __future__ import annotations
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from .store import norm_email, valid_email


def build_router(auth) -> APIRouter:
    cfg = auth.cfg
    r = APIRouter(tags=["auth"])

    def _client(request: Request):
        return (request.client.host if request.client else None), request.headers.get("user-agent")

    # ---------- Login (Passwort) ----------
    @r.get("/auth/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "/", error: str = ""):
        nxt = auth.safe_next(next)
        if auth.current_user(request):
            return RedirectResponse(nxt, 303)
        return auth.render_page("login", next=nxt, error=error)

    @r.post("/auth/login")
    def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                     next: str = Form("/"), remember: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        auth.require_csrf(request, csrf_tok)
        if not cfg.password_enabled:
            raise HTTPException(404, "Passwort-Login deaktiviert")
        nxt = auth.safe_next(next)
        remember_me = _remember(cfg, remember)
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip):
            return auth.render_page("login", status=429, next=nxt, error=auth.t("err.rate"))
        if auth.is_locked(username, ip):
            return auth.render_page("login", status=429, next=nxt, error=auth.t("err.locked"))
        u = auth.check_password(username, password)
        if not u and cfg.ldap_enabled:
            u = auth.check_ldap(username, password)   # LDAP/lldap-Backend (Faktor 'password')
        auth.record_login(username, ip, bool(u), "password")
        if not u:
            return auth.render_page("login", status=401, next=nxt, error=auth.t("err.credentials"))
        token, ok, is_new = auth.apply_factor(request, u["id"], "password", ip,
                                              request.headers.get("user-agent"), remember_me)
        resp = RedirectResponse(auth.login_redirect_after(request, token, u["id"], nxt), 303)
        if is_new:
            auth.set_cookie(resp, token, remember=remember_me)
        return resp

    # ---------- TOTP als Faktor (2. Schritt oder Ketten-/Route-Faktor) ----------
    @r.get("/auth/totp", response_class=HTMLResponse)
    def totp_page(request: Request, next: str = "/", error: str = ""):
        nxt = auth.safe_next(next)
        user = auth.pending_user(request) or auth.current_user(request)
        if not user:
            return RedirectResponse(cfg.login_path, 303)
        if not auth.store.has_confirmed_totp(user["id"]):
            # Faktor totp verlangt, aber nicht eingerichtet → Einrichtung (nur wenn schon eingeloggt)
            if auth.current_user(request):
                return RedirectResponse(f"/auth/totp/setup?next={_q(nxt)}", 303)
            return RedirectResponse(cfg.login_path, 303)
        return auth.render_page("totp", next=nxt, error=error)

    @r.post("/auth/totp")
    def totp_submit(request: Request, code: str = Form(...), next: str = Form("/"), csrf_tok: str = Form("", alias="_csrf")):
        auth.require_csrf(request, csrf_tok)
        nxt = auth.safe_next(next)
        s = auth.session_from_request(request)
        pu = auth.pending_user(request) or auth.current_user(request)
        if not s or not pu:
            return RedirectResponse(cfg.login_path, 303)
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip) or auth.is_locked(pu["username"], ip):
            return auth.render_page("totp", status=429, next=nxt, error=auth.t("err.retry"))
        # TOTP-Code ODER Einmal-Recovery-Code akzeptieren
        if not auth.verify_totp(pu["id"], code) and not auth.verify_recovery_code(pu["id"], code):
            auth.record_login(pu["username"], ip, False, "totp")
            return auth.render_page("totp", status=401, next=nxt, error=auth.t("err.code"))
        auth.record_login(pu["username"], ip, True, "totp")
        auth.complete_mfa(s["token"])
        return RedirectResponse(auth.login_redirect_after(request, s["token"], pu["id"], nxt), 303)

    # ---------- TOTP einrichten (eingeloggter User) ----------
    @r.get("/auth/totp/setup", response_class=HTMLResponse)
    def totp_setup(request: Request):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(cfg.login_path, 303)
        return auth.render_page("totp_setup", data=auth.totp_begin(u["id"]))

    @r.post("/auth/totp/setup")
    def totp_setup_confirm(request: Request, code: str = Form(...)):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        return JSONResponse({"ok": auth.totp_confirm(u["id"], code)})

    @r.post("/auth/totp/disable")
    def totp_off(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        auth.totp_disable(u["id"])
        return {"ok": True}

    @r.post("/auth/totp/recovery")
    def totp_recovery(request: Request):
        """Neue Einmal-Recovery-Codes erzeugen (nur mit eingerichtetem TOTP). Klartext NUR EINMAL."""
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        if not auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(400, "erst 2FA einrichten")
        return {"codes": auth.generate_recovery_codes(u["id"])}

    # ---------- PIN-Login (persönliche PIN, nur wenn aktiviert) ----------
    if cfg.pin_enabled:
        @r.get("/auth/pin")
        def pin_page(request: Request, next: str = "/"):
            return RedirectResponse(f"{cfg.login_path}?next={_q(auth.safe_next(next))}", 303)

        @r.post("/auth/pin")
        def pin_submit(request: Request, username: str = Form(...), pin: str = Form(...),
                       next: str = Form("/"), remember: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next)
            remember_me = _remember(cfg, remember)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("login", status=429, next=nxt, error=auth.t("err.rate"))
            if auth.is_locked(username, ip) or auth.is_pin_locked(username, ip):
                return auth.render_page("login", status=429, next=nxt, error=auth.t("err.locked"))
            u = auth.check_pin(username, pin)
            auth.record_login(username, ip, bool(u), "pin")
            if not u:
                return auth.render_page("login", status=401, next=nxt, error=auth.t("err.credentials"))
            token, ok, is_new = auth.apply_factor(request, u["id"], "pin", ip,
                                                  request.headers.get("user-agent"), remember_me)
            resp = RedirectResponse(auth.login_redirect_after(request, token, u["id"], nxt), 303)
            if is_new:
                auth.set_cookie(resp, token, remember=remember_me)
            return resp

        @r.post("/auth/pin/set")
        async def pin_set(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            b = await auth.json_body(request)
            try:
                auth.set_pin(u["id"], b.get("pin"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            auth.audit("pin_set", u["username"])
            return {"ok": True}

        @r.post("/auth/pin/disable")
        def pin_off(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            auth.disable_pin(u["id"])
            auth.audit("pin_disable", u["username"])
            return {"ok": True}

    # ---------- Geteiltes Ressourcen-Geheimnis (PIN/Passphrase ohne User-Konto) ----------
    if cfg.resource_locks_enabled:
        def _res_ctx(row, name, nxt, error=""):
            return dict(name=name, kind=row["kind"], label=row["label"] or name, next=nxt, error=error)

        @r.get("/auth/resource/{name}", response_class=HTMLResponse)
        def resource_page(request: Request, name: str, next: str = "/", error: str = ""):
            row = auth.store.get_resource_secret(name)
            if not row:
                raise HTTPException(404, "unbekannte Ressource")
            nxt = auth.safe_next(next)
            if auth.resource_unlocked(request, name):
                return RedirectResponse(nxt, 303)
            return auth.render_page("resource_unlock", **_res_ctx(row, name, nxt, error))

        @r.post("/auth/resource/{name}")
        def resource_submit(request: Request, name: str, secret: str = Form(...), next: str = Form("/"),
                            csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            row = auth.store.get_resource_secret(name)
            if not row:
                raise HTTPException(404, "unbekannte Ressource")
            nxt = auth.safe_next(next)
            ip = auth.client_ip(request)
            pseudo = f"res:{name}"
            if not auth.rate_ok(ip) or auth.is_locked(pseudo, ip):
                return auth.render_page("resource_unlock", status=429,
                                        **_res_ctx(row, name, nxt, "Zu viele Versuche — bitte warten."))
            if not auth.check_resource(name, secret):
                auth.record_login(pseudo, ip, False, "resource")
                return auth.render_page("resource_unlock", status=401, **_res_ctx(row, name, nxt, "Falsch"))
            auth.record_login(pseudo, ip, True, "resource")
            resp = RedirectResponse(nxt, 303)
            auth.unlock_resource(request, resp, name)
            auth.audit("resource_unlock", ip=ip, detail=name)
            return resp

    # ---------- Magic-Link (Einmal-Login per E-Mail) ----------
    if cfg.magiclink_enabled:
        @r.get("/auth/magic/request", response_class=HTMLResponse)
        def magic_request_page(request: Request, next: str = "/"):
            return auth.render_page("magic_request", next=auth.safe_next(next), sent=False, error="")

        @r.post("/auth/magic/request", response_class=HTMLResponse)
        def magic_request(request: Request, email: str = Form(...), next: str = Form("/")):
            nxt = auth.safe_next(next)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("magic_request", status=429, next=nxt, sent=False,
                                        error=auth.t("err.rate"))
            base = cfg.base_url or str(request.base_url)
            try:
                auth.send_login_link(email.strip(), base, nxt)
            except Exception:
                auth.audit("magic_send_error", detail=email)   # Fehler nicht nach außen leaken
            # immer dieselbe Antwort (keine User-Enumeration)
            return auth.render_page("magic_request", next=nxt, sent=True, error="")

        @r.get("/auth/magic/{token}")
        def magic_redeem(request: Request, token: str):
            info = auth.peek_magic(token)
            if not info:
                return auth.render_page("magic_invalid", status=400)
            # Einladung: NICHT hier verbrauchen → zur Registrierung weiterreichen
            if info["purpose"] == "invite":
                if not cfg.allow_signup:
                    return auth.render_page("magic_invalid", status=400)
                return RedirectResponse(f"/auth/register?invite={_q(token)}", 303)
            # Passwort-Reset: NICHT hier verbrauchen → zur Reset-Seite weiterreichen
            if info["purpose"] == "reset_password":
                return RedirectResponse(f"/auth/reset?token={_q(token)}", 303)
            data = auth.redeem_magic(token)
            if not data:
                return auth.render_page("magic_invalid", status=400)
            handled = _magic_dispatch(auth, request, data)
            if handled is not None:
                return handled
            raise HTTPException(400, "nicht unterstützter Token-Zweck")

    # ---------- Step-up / Reauth (Sudo-Frische für mfa=True-Guards) ----------
    @r.get("/auth/reauth", response_class=HTMLResponse)
    def reauth_page(request: Request, next: str = "/", error: str = ""):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(f"{cfg.login_path}?next={_q(auth.safe_next(next))}", 303)
        return auth.render_page("reauth", next=auth.safe_next(next), error=error,
                                username=u["username"], has_totp=auth.store.has_confirmed_totp(u["id"]))

    @r.post("/auth/reauth")
    def reauth_submit(request: Request, code: str = Form(""), password: str = Form(""), next: str = Form("/"),
                      csrf_tok: str = Form("", alias="_csrf")):
        auth.require_csrf(request, csrf_tok)
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(cfg.login_path, 303)
        nxt = auth.safe_next(next)
        ip = auth.client_ip(request)
        has_totp = auth.store.has_confirmed_totp(u["id"])
        if not auth.rate_ok(ip) or auth.is_locked(u["username"], ip):
            return auth.render_page("reauth", status=429, next=nxt, username=u["username"],
                                    has_totp=has_totp, error=auth.t("err.retry"))
        ok = auth.verify_totp(u["id"], code) if has_totp else bool(auth.check_password(u["username"], password))
        auth.record_login(u["username"], ip, ok, "reauth")
        if not ok:
            return auth.render_page("reauth", status=401, next=nxt, username=u["username"],
                                    has_totp=has_totp, error=auth.t("err.reauth"))
        s = auth.session_from_request(request)
        if s:
            auth.store.set_session_mfa(s["token"], True)   # setzt mfa_at=now → wieder frisch
        auth.audit("stepup", u["username"], ip)
        return RedirectResponse(nxt, 303)

    # ---------- Passwort vergessen / zurücksetzen (braucht magiclink_enabled + Mailer) ----------
    if cfg.password_reset_enabled and cfg.magiclink_enabled:
        @r.get("/auth/forgot", response_class=HTMLResponse)
        def forgot_page(request: Request):
            return auth.render_page("forgot", sent=False, error="")

        @r.post("/auth/forgot", response_class=HTMLResponse)
        def forgot_submit(request: Request, email: str = Form(...), csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("forgot", status=429, sent=False, error=auth.t("err.rate"))
            base = cfg.base_url or str(request.base_url)
            try:
                auth.send_password_reset(email.strip(), base)
            except Exception:
                auth.audit("reset_send_error", detail=email)
            return auth.render_page("forgot", sent=True, error="")   # generisch (keine Enumeration)

        @r.get("/auth/reset", response_class=HTMLResponse)
        def reset_page(request: Request, token: str = ""):
            if not auth.peek_magic(token, purpose="reset_password"):
                return auth.render_page("magic_invalid", status=400)
            return auth.render_page("reset", token=token, error="")

        @r.post("/auth/reset", response_class=HTMLResponse)
        def reset_submit(request: Request, token: str = Form(...), password: str = Form(...),
                         csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            if len(password) < auth.sec("password_min_length"):
                return auth.render_page("reset", status=400, token=token,
                                        error=auth.t("err.pw_short", n=auth.sec("password_min_length")))
            data = auth.redeem_magic(token, purpose="reset_password")   # jetzt verbrauchen
            if not data or not data.get("user_id"):
                return auth.render_page("magic_invalid", status=400)
            uid = data["user_id"]
            auth.set_password(uid, password)
            auth.store.delete_user_sessions(uid)   # alle alten Sitzungen beenden
            auth.audit("password_reset", detail=f"uid={uid}")
            return RedirectResponse(f"{cfg.login_path}?next=/", 303)

    # ---------- Registrierung (nur wenn allow_signup) ----------
    if cfg.allow_signup:
        def _reg_ctx(nxt, invite="", email="", error="", **extra):
            return dict(next=nxt, invite=invite, email=email, error=error,
                        invite_only=cfg.signup_invite_only, **extra)

        @r.get("/auth/register", response_class=HTMLResponse)
        def register_page(request: Request, next: str = "/", invite: str = ""):
            nxt = auth.safe_next(next)
            if auth.current_user(request):
                return RedirectResponse(nxt, 303)
            inv = auth.peek_magic(invite, purpose="invite") if invite else None
            if cfg.signup_invite_only and not inv:
                return auth.render_page("register", status=403,
                                        **_reg_ctx(nxt, error=auth.t("err.invite_required")))
            return auth.render_page("register", **_reg_ctx(nxt, invite=invite, email=(inv or {}).get("email") or ""))

        @r.post("/auth/register", response_class=HTMLResponse)
        def register_submit(request: Request, username: str = Form(...), password: str = Form(...),
                            email: str = Form(""), next: str = Form("/"), invite: str = Form(""),
                            csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("register", status=429, **_reg_ctx(nxt, invite=invite, email=email,
                                        error=auth.t("err.rate")))
            inv = auth.peek_magic(invite, purpose="invite") if invite else None
            if cfg.signup_invite_only and not inv:
                return auth.render_page("register", status=403,
                                        **_reg_ctx(nxt, error=auth.t("err.invite_required")))
            username = username.strip()
            def err(msg, status=400):
                return auth.render_page("register", status=status,
                                        **_reg_ctx(nxt, invite=invite, email=email, error=msg))
            if not username:
                return err(auth.t("err.username_required"))
            if len(password) < auth.sec("password_min_length"):
                return err(auth.t("err.pw_short", n=auth.sec("password_min_length")))
            if auth.store.get_user_by_name(username):
                return err(auth.t("err.username_taken"), 409)
            roles, is_admin = list(cfg.signup_default_roles), False
            email_final = norm_email(email)
            if inv:
                roles = (inv.get("payload") or {}).get("roles") or []
                is_admin = bool((inv.get("payload") or {}).get("is_admin"))
                email_final = norm_email(inv.get("email")) or email_final
            # E-Mail ist Login-Kennung → Pflicht, plausibel und eindeutig
            if cfg.signup_require_email and not email_final:
                return err(auth.t("err.email_required"))
            if email_final and not valid_email(email_final):
                return err(auth.t("err.email_invalid"))
            if email_final and auth.store.email_taken(email_final):
                return err(auth.t("err.email_taken"), 409)
            # Bestätigung verlangt, aber kein Mailer? Dann NICHT stillschweigend durchwinken.
            verify = cfg.signup_verify_email and not inv
            if verify and not auth.mail_configured():
                return err(auth.t("err.verify_no_mailer"), 500)
            uid = auth.create_user(username, password=password, is_admin=is_admin, roles=roles,
                                   email=email_final or None)
            if inv:
                auth.redeem_magic(invite, purpose="invite")   # Einladung jetzt verbrauchen
            auth.audit("signup", username, ip)
            # E-Mail-Bestätigung nötig? (nicht bei Einladung — die gilt als bestätigt)
            if verify and email_final:
                auth.store.set_disabled(uid, True)
                auth.send_verify_email(uid, email_final, cfg.base_url or str(request.base_url))
                return auth.render_page("register", **_reg_ctx(nxt, sent_verify=True))
            token, ok, is_new = auth.apply_factor(request, uid, "password", ip,
                                                  request.headers.get("user-agent"), True)
            resp = RedirectResponse(auth.login_redirect_after(request, token, uid, nxt), 303)
            if is_new:
                auth.set_cookie(resp, token, remember=True)
            return resp

    # ---------- Forward-Auth (Reverse-Proxy: Caddy forward_auth / nginx auth_request / Traefik) ----------
    if cfg.forward_auth_enabled:
        from fastapi.responses import Response

        def _forward(request: Request):
            u = auth.current_user(request)   # Session ODER API-Key
            if u:
                groups = auth.user_roles(u) + (["admin"] if u["is_admin"] else [])
                headers = {
                    "Remote-User": str(u["username"] or ""),
                    "Remote-Name": str(u["display_name"] or u["username"] or ""),
                    "Remote-Email": str(u["email"] or ""),
                    "Remote-Groups": ",".join(groups),
                }
                return Response(status_code=200, headers=headers)
            orig = auth.forwarded_url(request)
            login = auth.forward_login_url(orig, request)
            # Caddys forward_auth-Shortcut reicht nur die 401 durch → handle_response/redir nötig
            return Response(status_code=401, headers={"X-TinySesam-Location": login,
                                                      "WWW-Authenticate": 'FormBased realm="TinySesam"'})

        @r.get("/auth/forward")
        def forward_auth(request: Request):
            return _forward(request)

        @r.get("/auth/verify")
        def verify_auth(request: Request):
            return _forward(request)

    # ---------- Eigenes Konto (Selbstverwaltung) ----------
    @r.post("/auth/password")
    async def change_own_password(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        b = await auth.json_body(request)
        if not auth.check_password(u["username"], b.get("current") or ""):
            raise HTTPException(403, "aktuelles Passwort falsch")
        new = b.get("new") or ""
        if len(new) < auth.sec("password_min_length"):
            raise HTTPException(400, f"Passwort zu kurz (min. {auth.sec('password_min_length')})")
        auth.set_password(u["id"], new)
        # andere Sitzungen des Users beenden (aktuelle behalten) — Standard nach Credential-Wechsel
        s = auth.session_from_request(request)
        auth.store.delete_user_sessions_except(u["id"], s["token"] if s else None)
        auth.audit("password_change", u["username"], auth.client_ip(request))
        return {"ok": True}

    if cfg.account_enabled:
        @r.get("/auth/account", response_class=HTMLResponse)
        def account_page(request: Request):
            u = auth.current_user(request)
            if not u:
                return RedirectResponse(f"{cfg.login_path}?next=/auth/account", 303)
            return auth.render_page("account", user=u, methods=cfg.enabled_methods(),
                                    has_totp=auth.store.has_confirmed_totp(u["id"]),
                                    has_pin=(cfg.pin_enabled and auth.has_pin(u["id"])),
                                    is_admin=bool(u["is_admin"]), admin_path=cfg.admin_path)

    # ---------- Eigene Sitzungen verwalten ----------
    @r.get("/auth/sessions")
    def own_sessions(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        cur = auth.session_from_request(request)
        cur_tok = cur["token"] if cur else None
        out = []
        for s in auth.store.list_sessions(u["id"]):
            out.append({"created_at": s["created_at"], "ip": s["ip"], "method": s["method"],
                        "user_agent": (s["user_agent"] or "")[:120], "current": s["token"] == cur_tok})
        return out

    @r.post("/auth/sessions/revoke")
    async def own_sessions_revoke(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        scope = (await auth.json_body(request)).get("scope", "others")
        if scope == "all":
            auth.store.delete_user_sessions(u["id"])          # inkl. aktueller → ausgeloggt
        else:
            cur = auth.session_from_request(request)
            auth.store.delete_user_sessions_except(u["id"], cur["token"] if cur else None)
        auth.audit("sessions_revoke", u["username"], auth.client_ip(request), scope)
        return {"ok": True}

    # ---------- Logout / me ----------
    @r.get("/auth/logout")
    def logout(request: Request):
        u = auth.current_user(request) or auth.pending_user(request)
        # OIDC-Provider-Logout (optional): vor dem lokalen Logout prüfen, ob die Sitzung via OIDC lief
        oidc_logout_url = None
        if cfg.oidc_rp_logout and auth.oidc:
            s = auth.session_from_request(request)
            factors = []
            try:
                factors = __import__("json").loads(s["factors_done"] or "[]") if s else []
            except Exception:
                factors = []
            if s and (s["method"] == "oidc" or "oidc" in factors):
                base = (cfg.base_url or str(request.base_url)).rstrip("/")
                oidc_logout_url = auth.oidc.end_session_url(base + cfg.logout_redirect)
        if u:
            auth.audit("logout", u["username"], auth.client_ip(request))
        resp = RedirectResponse(oidc_logout_url or cfg.logout_redirect, 303)
        auth.logout(request, resp)
        return resp

    @r.get("/auth/me")
    def me(request: Request):
        u = auth.current_user(request)
        if not u:
            return JSONResponse({"authenticated": False}, 401)
        return {"authenticated": True, "id": u["id"], "username": u["username"],
                "display_name": u["display_name"], "is_admin": bool(u["is_admin"]),
                "roles": auth.user_roles(u)}

    # ---------- OIDC (nur wenn aktiviert) ----------
    if auth.oidc:
        from .oidc import register_oidc_routes
        register_oidc_routes(r, auth)

    # ---------- Passkey / WebAuthn (nur wenn aktiviert) ----------
    if auth.webauthn:
        from .webauthn_ import register_passkey_routes
        register_passkey_routes(r, auth)

    # ---------- SAML 2.0 SP (nur wenn aktiviert) ----------
    if auth.saml:
        from fastapi.responses import Response as _Resp

        def _saml_base(request: Request):
            proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
            host = (request.headers.get("x-forwarded-host") or request.headers.get("host")
                    or request.url.netloc).split(",")[0].strip()
            return f"{proto}://{host}"

        def _saml_req(request: Request, form=None):
            proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
            host = (request.headers.get("x-forwarded-host") or request.headers.get("host")
                    or request.url.netloc).split(",")[0].strip()
            return {"https": "on" if proto == "https" else "off", "http_host": host,
                    "script_name": request.url.path, "get_data": dict(request.query_params),
                    "post_data": {k: v for k, v in (form or {}).items()}}

        @r.get("/auth/saml/login")
        def saml_login(request: Request, next: str = "/"):
            base = cfg.base_url or _saml_base(request)
            url = auth.saml.login_url(_saml_req(request), base, return_to=auth.safe_next(next))
            return RedirectResponse(url, 303)

        @r.post("/auth/saml/acs")            # POST vom IdP → von CSRF ausgenommen (Signatur schützt)
        async def saml_acs(request: Request):
            form = await request.form()
            base = cfg.base_url or _saml_base(request)
            data = auth.saml.process(_saml_req(request, form), base)
            if not data:
                return auth.render_page("magic_invalid", status=400)
            u = auth.check_saml(data.get("nameid"), data.get("attrs") or {})
            if not u:
                raise HTTPException(403, "SAML: kein Zugriff")
            nxt = auth.safe_next(form.get("RelayState") or "/")
            token, ok, is_new = auth.apply_factor(request, u["id"], "saml",
                                                  auth.client_ip(request), request.headers.get("user-agent"))
            resp = RedirectResponse(auth.login_redirect_after(request, token, u["id"], nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            return resp

        @r.get("/auth/saml/metadata")
        def saml_metadata(request: Request):
            base = cfg.base_url or _saml_base(request)
            return _Resp(content=auth.saml.metadata(base), media_type="application/xml")

    # ---------- API-Keys: Self-Service für den eingeloggten User ----------
    if cfg.apikey_enabled:
        @r.get("/auth/apikeys")
        def apikeys_list(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            return [key_view(k) for k in auth.list_api_keys(u["id"])]

        @r.post("/auth/apikeys")
        async def apikeys_create(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            b = await auth.json_body(request)
            return auth.create_api_key(u["id"], name=b.get("name"),
                                       expires_days=b.get("expires_days"), roles=b.get("roles"))

        @r.post("/auth/apikeys/{key_id}/revoke")
        def apikeys_revoke(request: Request, key_id: int):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            auth.revoke_api_key(key_id, u["id"])   # sperren, nicht löschen
            return {"ok": True}

    # ---------- Admin-Panel — an config.admin_path; via auth.admin_router() auch woanders montierbar ----------
    if cfg.admin_enabled:
        r.include_router(auth.admin_router(), prefix=cfg.admin_path)

    return r


def key_view(k) -> dict:
    return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
            "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"])}


def _magic_dispatch(auth, request, data):
    """Einen eingelösten Magic-Token nach Zweck behandeln. Gibt eine Response oder None (unbehandelt)."""
    from fastapi.responses import RedirectResponse
    if data["purpose"] == "login" and data.get("user_id"):
        uid = data["user_id"]
        nxt = auth.safe_next((data.get("payload") or {}).get("next") or "/")
        token, ok, is_new = auth.apply_factor(request, uid, "magic",
                                              auth.client_ip(request), request.headers.get("user-agent"))
        resp = RedirectResponse(auth.login_redirect_after(request, token, uid, nxt), 303)
        if is_new:
            auth.set_cookie(resp, token)
        return resp
    if data["purpose"] == "verify_email" and data.get("user_id"):
        uid = data["user_id"]
        auth.store.set_disabled(uid, False)   # Konto aktivieren
        auth.audit("email_verified", detail=data.get("email"))
        token, ok, is_new = auth.apply_factor(request, uid, "magic",
                                              auth.client_ip(request), request.headers.get("user-agent"))
        resp = RedirectResponse(auth.login_redirect_after(request, token, uid, "/"), 303)
        if is_new:
            auth.set_cookie(resp, token)
        return resp
    return None


def _remember(cfg, val) -> bool:
    """Remember-me aus dem Formular auswerten. Ist die Checkbox global aus, gilt immer persistent."""
    if not cfg.remember_me_enabled:
        return True
    return str(val) in ("1", "true", "on", "yes")


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s or "/", safe="/")

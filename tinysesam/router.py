"""FastAPI-Router: /auth/* — Login (Passwort), TOTP-2FA + -Einrichtung, Logout, /me.
OIDC- und Passkey-Routen werden nur registriert, wenn in der Config aktiviert."""
from __future__ import annotations
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse


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
                     next: str = Form("/"), remember: str = Form("")):
        if not cfg.password_enabled:
            raise HTTPException(404, "Passwort-Login deaktiviert")
        nxt = auth.safe_next(next)
        remember_me = _remember(cfg, remember)
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip):
            return auth.render_page("login", status=429, next=nxt, error="Zu viele Anfragen — bitte kurz warten.")
        if auth.is_locked(username, ip):
            return auth.render_page("login", status=429, next=nxt, error="Zu viele Fehlversuche — vorübergehend gesperrt.")
        u = auth.check_password(username, password)
        auth.record_login(username, ip, bool(u), "password")
        if not u:
            return auth.render_page("login", status=401, next=nxt, error="Falsche Zugangsdaten")
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
    def totp_submit(request: Request, code: str = Form(...), next: str = Form("/")):
        nxt = auth.safe_next(next)
        s = auth.session_from_request(request)
        pu = auth.pending_user(request) or auth.current_user(request)
        if not s or not pu:
            return RedirectResponse(cfg.login_path, 303)
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip) or auth.is_locked(pu["username"], ip):
            return auth.render_page("totp", status=429, next=nxt, error="Zu viele Versuche — bitte warten.")
        if not auth.verify_totp(pu["id"], code):
            auth.record_login(pu["username"], ip, False, "totp")
            return auth.render_page("totp", status=401, next=nxt, error="Code falsch")
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

    # ---------- PIN-Login (persönliche PIN, nur wenn aktiviert) ----------
    if cfg.pin_enabled:
        @r.get("/auth/pin")
        def pin_page(request: Request, next: str = "/"):
            return RedirectResponse(f"{cfg.login_path}?next={_q(auth.safe_next(next))}", 303)

        @r.post("/auth/pin")
        def pin_submit(request: Request, username: str = Form(...), pin: str = Form(...),
                       next: str = Form("/"), remember: str = Form("")):
            nxt = auth.safe_next(next)
            remember_me = _remember(cfg, remember)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("login", status=429, next=nxt, error="Zu viele Anfragen — bitte kurz warten.")
            if auth.is_locked(username, ip) or auth.is_pin_locked(username, ip):
                return auth.render_page("login", status=429, next=nxt, error="Zu viele Fehlversuche — vorübergehend gesperrt.")
            u = auth.check_pin(username, pin)
            auth.record_login(username, ip, bool(u), "pin")
            if not u:
                return auth.render_page("login", status=401, next=nxt, error="Falsche Zugangsdaten")
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
            b = await request.json()
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
        def resource_submit(request: Request, name: str, secret: str = Form(...), next: str = Form("/")):
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

    # ---------- Step-up / Reauth (Sudo-Frische für mfa=True-Guards) ----------
    @r.get("/auth/reauth", response_class=HTMLResponse)
    def reauth_page(request: Request, next: str = "/", error: str = ""):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(f"{cfg.login_path}?next={_q(auth.safe_next(next))}", 303)
        return auth.render_page("reauth", next=auth.safe_next(next), error=error,
                                username=u["username"], has_totp=auth.store.has_confirmed_totp(u["id"]))

    @r.post("/auth/reauth")
    def reauth_submit(request: Request, code: str = Form(""), password: str = Form(""), next: str = Form("/")):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(cfg.login_path, 303)
        nxt = auth.safe_next(next)
        ip = auth.client_ip(request)
        has_totp = auth.store.has_confirmed_totp(u["id"])
        if not auth.rate_ok(ip) or auth.is_locked(u["username"], ip):
            return auth.render_page("reauth", status=429, next=nxt, username=u["username"],
                                    has_totp=has_totp, error="Zu viele Versuche — bitte warten.")
        ok = auth.verify_totp(u["id"], code) if has_totp else bool(auth.check_password(u["username"], password))
        auth.record_login(u["username"], ip, ok, "reauth")
        if not ok:
            return auth.render_page("reauth", status=401, next=nxt, username=u["username"],
                                    has_totp=has_totp, error="Bestätigung fehlgeschlagen")
        s = auth.session_from_request(request)
        if s:
            auth.store.set_session_mfa(s["token"], True)   # setzt mfa_at=now → wieder frisch
        auth.audit("stepup", u["username"], ip)
        return RedirectResponse(nxt, 303)

    # ---------- Logout / me ----------
    @r.get("/auth/logout")
    def logout(request: Request):
        u = auth.current_user(request) or auth.pending_user(request)
        if u:
            auth.audit("logout", u["username"], auth.client_ip(request))
        resp = RedirectResponse(cfg.logout_redirect, 303)
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
            b = await request.json()
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


def _remember(cfg, val) -> bool:
    """Remember-me aus dem Formular auswerten. Ist die Checkbox global aus, gilt immer persistent."""
    if not cfg.remember_me_enabled:
        return True
    return str(val) in ("1", "true", "on", "yes")


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s or "/", safe="/")

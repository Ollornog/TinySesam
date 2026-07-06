"""FastAPI-Router: /auth/* — Login (Passwort), TOTP-2FA + -Einrichtung, Logout, /me.
OIDC- und Passkey-Routen werden nur registriert, wenn in der Config aktiviert."""
from __future__ import annotations
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from . import templates as T


def build_router(auth) -> APIRouter:
    cfg = auth.cfg
    r = APIRouter(tags=["auth"])

    def _client(request: Request):
        return (request.client.host if request.client else None), request.headers.get("user-agent")

    # ---------- Login (Passwort) ----------
    @r.get("/auth/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "/", error: str = ""):
        if auth.current_user(request):
            return RedirectResponse(next or cfg.login_redirect, 303)
        return T.login_page(auth, next, error)

    @r.post("/auth/login")
    def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
        if not cfg.password_enabled:
            raise HTTPException(404, "Passwort-Login deaktiviert")
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip):
            return T.login_page(auth, next, "Zu viele Anfragen — bitte kurz warten.", status=429)
        if auth.is_locked(username, ip):
            return T.login_page(auth, next, "Zu viele Fehlversuche — vorübergehend gesperrt.", status=429)
        u = auth.check_password(username, password)
        auth.record_login(username, ip, bool(u), "password")
        if not u:
            return T.login_page(auth, next, "Falsche Zugangsdaten", status=401)
        token, mfa_ok = auth.start_session(u["id"], "password", ip, request.headers.get("user-agent"))
        resp = RedirectResponse(next or cfg.login_redirect, 303) if mfa_ok \
            else RedirectResponse(f"/auth/totp?next={next}", 303)
        auth.set_cookie(resp, token)
        return resp

    # ---------- TOTP als 2. Faktor ----------
    @r.get("/auth/totp", response_class=HTMLResponse)
    def totp_page(request: Request, next: str = "/", error: str = ""):
        if not auth.pending_user(request):
            return RedirectResponse(cfg.login_path, 303)
        return T.totp_page(auth, next, error)

    @r.post("/auth/totp")
    def totp_submit(request: Request, code: str = Form(...), next: str = Form("/")):
        s = auth.session_from_request(request)
        pu = auth.pending_user(request)
        if not s or not pu:
            return RedirectResponse(cfg.login_path, 303)
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip) or auth.is_locked(pu["username"], ip):
            return T.totp_page(auth, next, "Zu viele Versuche — bitte warten.", status=429)
        if not auth.verify_totp(pu["id"], code):
            auth.record_login(pu["username"], ip, False, "totp")
            return T.totp_page(auth, next, "Code falsch", status=401)
        auth.record_login(pu["username"], ip, True, "totp")
        auth.complete_mfa(s["token"])
        return RedirectResponse(next or cfg.login_redirect, 303)

    # ---------- TOTP einrichten (eingeloggter User) ----------
    @r.get("/auth/totp/setup", response_class=HTMLResponse)
    def totp_setup(request: Request):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(cfg.login_path, 303)
        return T.totp_setup_page(auth, auth.totp_begin(u["id"]))

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

    # ---------- Admin-Panel (nur Admins) ----------
    if cfg.admin_enabled:
        from .admin import register_admin_routes
        register_admin_routes(r, auth)

    return r


def key_view(k) -> dict:
    return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
            "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"])}

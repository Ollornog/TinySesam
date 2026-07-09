"""OIDC (Authorization Code Flow) für einen generischen Provider (PocketID, Keycloak, …).

httpx für Discovery/Token, authlib.jose für die ID-Token-Verifikation (Signatur gegen JWKS +
iss/aud/exp). state & nonce liegen kurzlebig im Store (flow), nicht im Client → CSRF-/Replay-fest.
Beide Libs sind optional-Extra `[oidc]`.
"""
from __future__ import annotations
import secrets
from urllib.parse import urlencode

from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse

from . import security


class OIDCClient:
    def __init__(self, issuer, client_id, client_secret, scopes):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self._meta = None
        self._jwks = None

    def meta(self):
        if self._meta is None:
            import httpx
            self._meta = httpx.get(self.issuer + "/.well-known/openid-configuration",
                                   timeout=10, follow_redirects=True).json()
        return self._meta

    def _jwkset(self):
        if self._jwks is None:
            import httpx
            from authlib.jose import JsonWebKey
            self._jwks = JsonWebKey.import_key_set(httpx.get(self.meta()["jwks_uri"], timeout=10).json())
        return self._jwks

    def auth_url(self, redirect_uri, state, nonce):
        q = urlencode({"response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri,
                       "scope": self.scopes, "state": state, "nonce": nonce})
        return self.meta()["authorization_endpoint"] + "?" + q

    def exchange(self, code, redirect_uri, nonce):
        import httpx
        from authlib.jose import jwt
        tok = httpx.post(self.meta()["token_endpoint"], timeout=15, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": self.client_id, "client_secret": self.client_secret}).json()
        if "id_token" not in tok:
            raise HTTPException(502, f"OIDC-Token-Fehler: {tok.get('error', 'unbekannt')}")
        claims = jwt.decode(tok["id_token"], self._jwkset(),
                            claims_options={"iss": {"essential": True, "value": self.meta()["issuer"]},
                                            "aud": {"essential": True, "value": self.client_id}})
        claims.validate()  # exp/iat/nbf
        if nonce and claims.get("nonce") != nonce:
            raise HTTPException(400, "OIDC nonce mismatch")
        return claims, tok

    def end_session_url(self, post_logout_redirect_uri=None):
        """RP-initiated-Logout-URL beim Provider (oder None, wenn nicht unterstützt).
        Ohne id_token_hint (wird nicht gespeichert) — best effort; manche Provider verlangen es."""
        try:
            ep = self.meta().get("end_session_endpoint")
        except Exception:
            ep = None
        if not ep:
            return None
        params = {"client_id": self.client_id}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return ep + ("&" if "?" in ep else "?") + urlencode(params)

    def userinfo(self, access_token):
        try:
            import httpx
            ep = self.meta().get("userinfo_endpoint")
            if not ep or not access_token:
                return {}
            return httpx.get(ep, headers={"Authorization": f"Bearer {access_token}"}, timeout=10).json()
        except Exception:
            return {}


def register_oidc_routes(router, auth):
    cfg = auth.cfg
    oidc: OIDCClient = auth.oidc
    if cfg.base_url:
        # Sichtbar machen, was der IdP als Redirect-URI kennen muss. Stimmt es nicht überein,
        # meldet den Fehler sonst erst der Provider — nach dem Login, ohne Hinweis auf die Ursache.
        security.seclog.info("OIDC-Redirect-URI: %s", cfg.base_url.rstrip("/") + cfg.oidc_callback_path)

    def _redirect_uri(request: Request):
        base = cfg.base_url or str(request.base_url).rstrip("/")
        return base.rstrip("/") + cfg.oidc_callback_path

    @router.get("/auth/oidc/start")
    def oidc_start(request: Request, next: str = "/"):
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        auth.store.put_flow("oidc:" + state, {"nonce": nonce, "next": next}, ttl=600)
        return RedirectResponse(oidc.auth_url(_redirect_uri(request), state, nonce), 303)

    @router.get(cfg.oidc_callback_path)
    def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        if error:
            raise HTTPException(400, f"OIDC-Fehler: {error}")
        flow = auth.store.pop_flow("oidc:" + state)
        if not flow:
            raise HTTPException(400, "OIDC-state ungültig oder abgelaufen")
        claims, tok = oidc.exchange(code, _redirect_uri(request), flow["nonce"])
        info = {**oidc.userinfo(tok.get("access_token")), **dict(claims)}

        if cfg.oidc_allowed_groups:
            groups = info.get(cfg.oidc_group_claim) or []
            if not (set(cfg.oidc_allowed_groups) & set(groups if isinstance(groups, list) else [groups])):
                raise HTTPException(403, "Kein Zugriff — erforderliche Gruppe fehlt")

        issuer, sub = oidc.meta()["issuer"], claims["sub"]
        uid = auth.store.get_oidc_user(issuer, sub)
        if not uid:
            if not cfg.oidc_auto_create:
                raise HTTPException(403, "Kein mit diesem SSO-Konto verknüpfter Account")
            username = info.get("preferred_username") or info.get("email") or ("oidc-" + sub[:8])
            base_un, i = username, 1
            while auth.store.get_user_by_name(username):
                i += 1
                username = f"{base_un}{i}"
            uid = auth.create_user(username, display_name=info.get("name") or username, email=info.get("email"))
            auth.store.link_oidc(issuer, sub, uid)

        # OIDC-Gruppen → lokale Rollen (falls gemappt)
        _grp = info.get(cfg.oidc_group_claim) or []
        auth.apply_idp_groups(uid, _grp if isinstance(_grp, list) else [_grp], cfg.oidc_group_role_map)

        ip, ua = (request.client.host if request.client else None), request.headers.get("user-agent")
        token, ok, is_new = auth.apply_factor(request, uid, "oidc", ip, ua)
        target = auth.login_redirect_after(request, token, uid,
                                           auth.safe_next(flow.get("next") or cfg.login_redirect))
        resp = RedirectResponse(target, 303)
        if is_new:
            auth.set_cookie(resp, token)
        return resp

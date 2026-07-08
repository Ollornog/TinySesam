"""Passkey / WebAuthn — Registrierung (eingeloggter User) + passwortloser Login (discoverable).

Nutzt py_webauthn (Extra `[passkey]`). Challenges liegen kurzlebig im Store (flow) und sind über
ein httponly-Cookie an den Browser gebunden. Passkeys sind phishing-resistent → gelten als
vollwertiger Login (kein zusätzliches TOTP nötig).

Origin/RP müssen zur echten Domain passen (config.rp_id = Domain ohne Schema/Port, config.origin =
exaktes Browser-Origin). Über http://localhost testbar, produktiv nur über HTTPS.
"""
from __future__ import annotations
import json as _json
import secrets

from fastapi import Request, HTTPException
from fastapi.responses import Response, JSONResponse

_WAFLOW = "tinysesam_waflow"


def register_passkey_routes(router, auth):
    cfg = auth.cfg
    from webauthn import (generate_registration_options, verify_registration_response,
                          generate_authentication_options, verify_authentication_response, options_to_json)
    from webauthn.helpers.structs import (PublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria,
                                          ResidentKeyRequirement, UserVerificationRequirement)
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    def _set_flow_cookie(resp, fk):
        resp.set_cookie(_WAFLOW, fk, max_age=300, httponly=True, secure=cfg.cookie_secure,
                        samesite=cfg.cookie_samesite, path=cfg.cookie_path)

    # ---------- Registrierung (eingeloggter User) ----------
    @router.post("/auth/passkey/register/begin")
    def reg_begin(request: Request):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        existing = auth.store.list_webauthn(u["id"])
        opts = generate_registration_options(
            rp_id=cfg.rp_id, rp_name=cfg.rp_name,
            user_id=str(u["id"]).encode(), user_name=u["username"],
            user_display_name=u["display_name"] or u["username"],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"]))
                                 for c in existing],
        )
        fk = secrets.token_urlsafe(24)
        auth.store.put_flow("wareg:" + fk, {"challenge": bytes_to_base64url(opts.challenge), "user_id": u["id"]}, ttl=300)
        resp = Response(content=options_to_json(opts), media_type="application/json")
        _set_flow_cookie(resp, fk)
        return resp

    @router.post("/auth/passkey/register/finish")
    async def reg_finish(request: Request, name: str = ""):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        fk = request.cookies.get(_WAFLOW)
        flow = auth.store.pop_flow("wareg:" + fk) if fk else None
        if not flow:
            raise HTTPException(400, "Registrierung abgelaufen")
        body = await request.body()
        v = verify_registration_response(credential=body.decode(),
                                         expected_challenge=base64url_to_bytes(flow["challenge"]),
                                         expected_rp_id=cfg.rp_id, expected_origin=cfg.origin)
        try:
            transports = _json.loads(body).get("response", {}).get("transports")
        except Exception:
            transports = None
        auth.store.add_webauthn(flow["user_id"], bytes_to_base64url(v.credential_id),
                                bytes_to_base64url(v.credential_public_key), v.sign_count,
                                transports, name or "Passkey")
        return {"ok": True}

    # ---------- Passwortloser Login (discoverable credential) ----------
    @router.post("/auth/passkey/login/begin")
    def login_begin(request: Request):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        opts = generate_authentication_options(rp_id=cfg.rp_id,
                                               user_verification=UserVerificationRequirement.PREFERRED)
        fk = secrets.token_urlsafe(24)
        auth.store.put_flow("walogin:" + fk, {"challenge": bytes_to_base64url(opts.challenge)}, ttl=300)
        resp = Response(content=options_to_json(opts), media_type="application/json")
        _set_flow_cookie(resp, fk)
        return resp

    @router.post("/auth/passkey/login/finish")
    async def login_finish(request: Request, next: str = "/"):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        fk = request.cookies.get(_WAFLOW)
        flow = auth.store.pop_flow("walogin:" + fk) if fk else None
        if not flow:
            raise HTTPException(400, "Login abgelaufen")
        body = await request.body()
        data = _json.loads(body)
        row = auth.store.get_webauthn_by_credid(data.get("id") or data.get("rawId"))
        if not row:
            raise HTTPException(400, "Unbekannter Passkey")
        v = verify_authentication_response(
            credential=body.decode(), expected_challenge=base64url_to_bytes(flow["challenge"]),
            expected_rp_id=cfg.rp_id, expected_origin=cfg.origin,
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=row["sign_count"], require_user_verification=False)
        auth.store.update_webauthn_signcount(row["id"], v.new_sign_count)
        ip, ua = (request.client.host if request.client else None), request.headers.get("user-agent")
        token, ok, is_new = auth.apply_factor(request, row["user_id"], "passkey", ip, ua)
        target = auth.login_redirect_after(request, token, row["user_id"], auth.safe_next(next))
        resp = JSONResponse({"ok": True, "redirect": target})
        if is_new:
            auth.set_cookie(resp, token)
        return resp

    # ---------- Verwaltung ----------
    @router.get("/auth/passkey/list")
    def pk_list(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        return [{"id": c["id"], "name": c["name"], "created_at": c["created_at"], "last_used": c["last_used"]}
                for c in auth.store.list_webauthn(u["id"])]

    @router.post("/auth/passkey/delete")
    async def pk_delete(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        b = await auth.json_body(request)
        auth.store.delete_webauthn(int(b["id"]), u["id"])
        return {"ok": True}

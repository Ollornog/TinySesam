"""Passkey / WebAuthn — registration (signed-in user) + passwordless login (discoverable).

Uses py_webauthn (extra `[passkey]`). Challenges live briefly in the store (flow) and are bound to
the browser by an httponly cookie. Passkeys are phishing-resistant → count as a
full login (no additional TOTP needed).

Origin/RP must match the real domain (config.rp_id = domain without scheme/port, config.origin =
exact browser origin). Testable via http://localhost, in production only over HTTPS.
"""
from __future__ import annotations
import json as _json
import secrets

from fastapi import Request, HTTPException
from fastapi.responses import Response, JSONResponse

_WAFLOW = "tinysesam_waflow"


from . import errors, security


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Turn a bare import error into a message that says what to do.

    The extras are deliberately imported LAZILY here (only on use). The price for that was,
    up to 0.18.0, a `ModuleNotFoundError: webauthn` in the middle of the sign-in — for the operator
    a defect, when only one word was missing in the install command."""
    return errors.MissingExtra(
        "The extra [passkey] is not installed (pip install 'tinysesam[passkey]') — "
        f"missing: {e.name or 'webauthn'}.", extra="passkey")


def register_passkey_routes(router, auth):
    cfg = auth.cfg
    from webauthn import (generate_registration_options, verify_registration_response,
                          generate_authentication_options, verify_authentication_response, options_to_json)
    from webauthn.helpers.structs import (PublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria,
                                          ResidentKeyRequirement, UserVerificationRequirement)
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    def _uv_anforderung(cfg):
        """The user verification as a WebAuthn value — `required` (default) or `preferred` (B2-10).

        A passkey signs in **alone** in TinySesam. Without user verification it proves only
        possession of the key: the unlocked computer, the inserted stick, the phone briefly put
        down. That is why `required` is the default — and the response is also checked at
        login, not just requested."""
        art = str(getattr(cfg, "passkey_user_verification", "required") or "required")
        return (UserVerificationRequirement.REQUIRED if art == "required"
                else UserVerificationRequirement.PREFERRED)

    if str(getattr(cfg, "passkey_user_verification", "required")) != "required":
        security.seclog.warning(
            "passkey_user_verification=%r: A passkey without user verification signs in on its own and "
            "then only proves possession of the key — an unlocked computer or a "
            "plugged-in stick suffices. This is a deliberate decision for old "
            "authenticators; for new deployments the value belongs on 'required'.",
            cfg.passkey_user_verification)

    def _set_flow_cookie(resp, fk):
        # `__Host-` in front, where possible (A-1): a flow cookie planted by a neighboring subdomain
        # attached the victim to the attacker's challenge.
        auth._flow_cookie_setzen(resp, _WAFLOW, fk, max_age=300)

    # ---------- Registration (signed-in user) ----------
    @router.post("/auth/passkey/register/begin")
    def reg_begin(request: Request):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # CREATING a passkey requires an interactive session. `current_user()` was not enough
        # here: it accepts an API key, and for a real key the
        # CSRF check does not apply anyway (`_csrf_entbehrlich`). A leaked CI key thereby registered
        # a passkey OF ITS OWN — and a passkey is a full login: through it
        # the key got a fresh interactive session and suddenly stood in front of exactly the
        # `require_mfa()` routes that have locked it out since R3-3. The creation was the
        # lever by which the bolt against the silently degrading key was bypassed.
        u = auth.require_session(request)
        existing = auth.store.list_webauthn(u["id"])
        opts = generate_registration_options(
            rp_id=cfg.rp_id, rp_name=cfg.rp_name,
            user_id=str(u["id"]).encode(), user_name=u["username"],
            user_display_name=u["display_name"] or u["username"],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=_uv_anforderung(cfg)),
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
        u = auth.require_session(request)   # same bolt as at begin
        fk = request.cookies.get(auth.flow_cookie_name(_WAFLOW))
        flow = auth.store.pop_flow("wareg:" + fk) if fk else None
        if not flow:
            raise HTTPException(400, auth.t("api.passkey_reg_expired"))
        # The new factor belongs to the account that is signed in here — not to the one from the
        # flow cookie. Whoever can set a cookie via a subdomain would otherwise slip in a
        # foreign flow and the passkey would land on another account.
        if flow["user_id"] != u["id"]:
            raise HTTPException(400, auth.t("api.passkey_reg_expired"))
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
        # A new passkey is a new full login path on this account. Up to 0.18.x
        # it came about without a trace — whoever set it up secretly left nothing behind (B5-01).
        auth.audit("passkey_create", u["username"], auth.client_ip(request),
                   f"name={name or 'Passkey'}")
        auth._security_event("passkey_added", u["id"], name=name or "Passkey")
        resp = JSONResponse({"ok": True, "other_sessions": auth.count_other_sessions(request, u)})  # B1-7
        # The flow is consumed (pop_flow) — the cookie for it binds nothing any more and would only
        # keep going along to every app (B-20). OIDC and SAML delete theirs on the way back as well.
        auth._flow_cookie_loeschen(resp, _WAFLOW)
        return resp

    # ---------- Passwordless login (discoverable credential) ----------
    @router.post("/auth/passkey/login/begin")
    def login_begin(request: Request):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # Throttling like at every other login entry point (B2-10). Without it this was the only
        # sign-in path without a brake: every call also created a `flow` row that expires only
        # after five minutes — a convenient way to make the database grow.
        if not auth._rate_ok(auth.client_ip(request)):
            raise HTTPException(429, auth.t("err.rate"))
        opts = generate_authentication_options(rp_id=cfg.rp_id,
                                               user_verification=_uv_anforderung(cfg))
        fk = secrets.token_urlsafe(24)
        auth.store.put_flow("walogin:" + fk, {"challenge": bytes_to_base64url(opts.challenge)}, ttl=300)
        resp = Response(content=options_to_json(opts), media_type="application/json")
        _set_flow_cookie(resp, fk)
        return resp

    @router.post("/auth/passkey/login/finish")
    async def login_finish(request: Request, next: str = ""):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        fk = request.cookies.get(auth.flow_cookie_name(_WAFLOW))
        flow = auth.store.pop_flow("walogin:" + fk) if fk else None
        if not flow:
            raise HTTPException(400, auth.t("api.passkey_login_expired"))
        ip_roh = auth.client_ip(request)
        if not auth._rate_ok(ip_roh):
            raise HTTPException(429, auth.t("err.rate"))
        body = await request.body()
        data = _json.loads(body)
        row = auth.store.get_webauthn_by_credid(data.get("id") or data.get("rawId"))
        if not row:
            # An unknown key is a failed attempt like any other — with the
            # event word the fail2ban jail matches on. Up to 0.18.x the
            # passkey path left no trace at all: neither creation nor deletion nor failed sign-in
            # (B2-10, B5-01). Whoever probed here did so unobserved.
            security.seclog.warning("%s user=%s ip=%s method=passkey reason=unknown_key",
                                    security.log_ereignis("passkey"), "?",
                                    security.fuer_log(ip_roh))
            auth.audit("passkey_unknown", None, ip_roh)
            raise HTTPException(400, auth.t("api.passkey_unknown"))
        try:
            v = verify_authentication_response(
                credential=body.decode(), expected_challenge=base64url_to_bytes(flow["challenge"]),
                expected_rp_id=cfg.rp_id, expected_origin=cfg.origin,
                credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=row["sign_count"],
            # The authenticator's response is now also CHECKED. Before, the request said
            # "preferred" and here `False`: an authenticator could thus say no,
            # and the login counted anyway — the request was non-binding in both directions.
                require_user_verification=(str(cfg.passkey_user_verification) == "required"))
        except Exception as e:
            # Signature wrong, challenge old, user verification refused — all the same for the
            # attacker, not for the log. The exception type suffices: its text can carry the
            # content of the request and thus does not belong in a line that fail2ban reads.
            besitzer = auth.store.get_user(row["user_id"])
            security.seclog.warning("%s user=%s ip=%s method=passkey reason=%s",
                                    security.log_ereignis("passkey"),
                                    security.fuer_log(str(besitzer["username"]) if besitzer else "?"),
                                    security.fuer_log(ip_roh), type(e).__name__)
            auth.audit("passkey_failed", str(besitzer["username"]) if besitzer else None, ip_roh,
                       f"reason={type(e).__name__}")
            raise HTTPException(400, auth.t("api.passkey_unknown"))
        auth.store.update_webauthn_signcount(row["id"], v.new_sign_count)
        # client_ip, not request.client.host: behind a reverse proxy the peer is the
        # proxy. The raw peer IP would otherwise end up in the session list and in the log — and
        # the IP lockout would have lumped all users behind the same proxy together.
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
        token, ok, is_new = auth.apply_factor(request, row["user_id"], "passkey", ip, ua)
        target = auth._login_redirect_after(request, token, row["user_id"], auth.safe_next(next, request))
        resp = JSONResponse({"ok": True, "redirect": target})
        if is_new:
            auth.set_cookie(resp, token)
        auth._flow_cookie_loeschen(resp, _WAFLOW)   # flow consumed, see reg_finish
        return resp

    # ---------- Management ----------
    @router.get("/auth/passkey/list")
    def pk_list(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        return [{"id": c["id"], "name": c["name"], "created_at": c["created_at"], "last_used": c["last_used"]}
                for c in auth.store.list_webauthn(u["id"])]

    @router.post("/auth/passkey/delete")
    async def pk_delete(request: Request):
        # R3-3: deleting a passkey takes a full factor away from the account. That requires
        # an interactive session with fresh confirmation — `current_user()` would also have let through a
        # stale session and any API key.
        u = auth.require_mfa(request)
        b = await auth.json_body(request)
        # An integer or a digit string, otherwise 400. `int()` alone took `true` as
        # passkey 1 and `1.9` as 1, and `1e400`/`Infinity` (json.loads: float('inf')) raised
        # OverflowError — HTTP 500 instead of the promised 400.
        roh = b.get("id")
        if isinstance(roh, str) and roh.isascii() and roh.isdigit():
            roh = int(roh)
        if isinstance(roh, bool) or not isinstance(roh, int):
            raise HTTPException(400, auth.t("api.invalid", reason="id"))
        passkey_id = roh
        # Deletion, audit line (B5-01) and `passkey_removed` in one — the same path as the
        # revocation in the admin panel (integration finding 3). A passkey the account does not have
        # is 404 and leaves neither line nor event.
        if not auth.remove_passkey(u["id"], passkey_id, auth.client_ip(request)):
            raise HTTPException(404, auth.t("api.not_found"))
        return {"ok": True, "other_sessions": auth.count_other_sessions(request, u)}   # B1-7

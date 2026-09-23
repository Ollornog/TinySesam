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


from . import errors, security


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Aus einem nackten Importfehler eine Meldung machen, die sagt, was zu tun ist.

    Die Extras werden hier bewusst LAZY importiert (erst beim Benutzen). Der Preis dafür war
    bis 0.18.0 ein `ModuleNotFoundError: webauthn` mitten im Anmeldevorgang — für den Betreiber
    ein Defekt, dabei fehlte nur eine Zeile im Install-Befehl."""
    return errors.MissingExtra(
        "Das Extra [passkey] ist nicht installiert (pip install 'tinysesam[passkey]') — "
        f"es fehlt: {e.name or 'webauthn'}.", extra="passkey")


def register_passkey_routes(router, auth):
    cfg = auth.cfg
    from webauthn import (generate_registration_options, verify_registration_response,
                          generate_authentication_options, verify_authentication_response, options_to_json)
    from webauthn.helpers.structs import (PublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria,
                                          ResidentKeyRequirement, UserVerificationRequirement)
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    def _uv_anforderung(cfg):
        """Die Nutzerprüfung als WebAuthn-Wert — `required` (Vorgabe) oder `preferred` (B2-10).

        Ein Passkey meldet in TinySesam **allein** an. Ohne Nutzerprüfung belegt er nur den
        Besitz des Schlüssels: der entsperrte Rechner, der eingesteckte Stick, das kurz aus der
        Hand gelegte Telefon. Deshalb ist `required` die Vorgabe — und die Antwort wird beim
        Login auch geprüft, nicht nur erbeten."""
        art = str(getattr(cfg, "passkey_user_verification", "required") or "required")
        return (UserVerificationRequirement.REQUIRED if art == "required"
                else UserVerificationRequirement.PREFERRED)

    if str(getattr(cfg, "passkey_user_verification", "required")) != "required":
        security.seclog.warning(
            "passkey_user_verification=%r: Ein Passkey ohne Nutzerprüfung meldet allein an und "
            "belegt dann nur den Besitz des Schlüssels — ein entsperrter Rechner oder ein "
            "eingesteckter Stick genügt. Das ist eine bewusste Entscheidung für alte "
            "Authentikatoren; für einen neuen Bestand gehört der Wert auf 'required'.",
            cfg.passkey_user_verification)

    def _set_flow_cookie(resp, fk):
        # `__Host-` davor, wo möglich (A-1): Ein von einer Nachbar-Subdomain untergeschobenes
        # Flow-Cookie hängte das Opfer an die Challenge des Angreifers.
        auth._flow_cookie_setzen(resp, _WAFLOW, fk, max_age=300)

    # ---------- Registrierung (eingeloggter User) ----------
    @router.post("/auth/passkey/register/begin")
    def reg_begin(request: Request):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # Einen Passkey ANZULEGEN verlangt eine interaktive Sitzung. `current_user()` genügte
        # hier nicht: Es akzeptiert einen API-Key, und für einen echten Key entfällt die
        # CSRF-Prüfung ohnehin (`_csrf_entbehrlich`). Ein abgeflossener CI-Key registrierte
        # damit einen EIGENEN Passkey — und ein Passkey ist ein vollwertiger Login: Darüber
        # bekam der Key eine frische interaktive Sitzung und stand plötzlich vor genau den
        # `require_mfa()`-Routen, die ihn seit R3-3 aussperren sollten. Die Anlage war der
        # Hebel, mit dem der Riegel gegen den lautlos abbauenden Key umgangen wurde.
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
        u = auth.require_session(request)   # derselbe Riegel wie beim begin
        fk = request.cookies.get(auth.flow_cookie_name(_WAFLOW))
        flow = auth.store.pop_flow("wareg:" + fk) if fk else None
        if not flow:
            raise HTTPException(400, auth.t("api.passkey_reg_expired"))
        # Der neue Faktor gehört an das Konto, das hier angemeldet ist — nicht an das aus dem
        # Flow-Cookie. Wer über eine Subdomain ein Cookie setzen kann, schiebt sonst einen
        # fremden Flow unter und der Passkey landet an einem anderen Konto.
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
        # Ein neuer Passkey ist ein neuer vollwertiger Login-Weg an diesem Konto. Bis 0.18.x
        # entstand er spurlos — wer ihn sich heimlich einrichtete, hinterliess nichts (B5-01).
        auth.audit("passkey_create", u["username"], auth.client_ip(request),
                   f"name={name or 'Passkey'}")
        auth.sicherheitsereignis("passkey_added", u["id"], name=name or "Passkey")
        return {"ok": True, "other_sessions": auth.andere_sitzungen(request, u)}   # B1-7

    # ---------- Passwortloser Login (discoverable credential) ----------
    @router.post("/auth/passkey/login/begin")
    def login_begin(request: Request):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # Drosselung wie an jedem anderen Login-Einstieg (B2-10). Ohne sie war dies die einzige
        # Anmeldestrecke ohne Bremse: Jeder Aufruf legte zudem eine `flow`-Zeile an, die erst
        # nach fünf Minuten verfällt — ein bequemer Weg, die Datenbank wachsen zu lassen.
        if not auth.rate_ok(auth.client_ip(request)):
            raise HTTPException(429, auth.t("err.rate"))
        opts = generate_authentication_options(rp_id=cfg.rp_id,
                                               user_verification=_uv_anforderung(cfg))
        fk = secrets.token_urlsafe(24)
        auth.store.put_flow("walogin:" + fk, {"challenge": bytes_to_base64url(opts.challenge)}, ttl=300)
        resp = Response(content=options_to_json(opts), media_type="application/json")
        _set_flow_cookie(resp, fk)
        return resp

    @router.post("/auth/passkey/login/finish")
    async def login_finish(request: Request, next: str = "/"):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        fk = request.cookies.get(auth.flow_cookie_name(_WAFLOW))
        flow = auth.store.pop_flow("walogin:" + fk) if fk else None
        if not flow:
            raise HTTPException(400, auth.t("api.passkey_login_expired"))
        ip_roh = auth.client_ip(request)
        if not auth.rate_ok(ip_roh):
            raise HTTPException(429, auth.t("err.rate"))
        body = await request.body()
        data = _json.loads(body)
        row = auth.store.get_webauthn_by_credid(data.get("id") or data.get("rawId"))
        if not row:
            # Ein unbekannter Schlüssel ist ein Fehlversuch wie jeder andere — mit dem
            # Ereigniswort, auf das die fail2ban-Jail matcht. Bis 0.18.x hinterliess der
            # Passkey-Pfad überhaupt keine Spur: weder Anlage noch Löschung noch Fehlanmeldung
            # (B2-10, B5-01). Wer hier durchprobierte, tat das unbeobachtet.
            security.seclog.warning("%s user=%s ip=%s method=passkey grund=unbekannter_schluessel",
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
            # Die Antwort des Authenticators wird jetzt auch GEPRÜFT. Vorher stand in der
            # Anfrage „preferred" und hier `False`: Ein Authenticator konnte also nein sagen,
            # und der Login galt trotzdem — die Bitte war unverbindlich in beide Richtungen.
                require_user_verification=(str(cfg.passkey_user_verification) == "required"))
        except Exception as e:
            # Signatur falsch, Challenge alt, Nutzerprüfung verweigert — für den Angreifer alles
            # dasselbe, für das Protokoll nicht. Der Typ der Ausnahme reicht: Ihr Text kann den
            # Inhalt der Anfrage tragen und gehört damit nicht in eine Zeile, die fail2ban liest.
            besitzer = auth.store.get_user(row["user_id"])
            security.seclog.warning("%s user=%s ip=%s method=passkey grund=%s",
                                    security.log_ereignis("passkey"),
                                    security.fuer_log(str(besitzer["username"]) if besitzer else "?"),
                                    security.fuer_log(ip_roh), type(e).__name__)
            auth.audit("passkey_failed", str(besitzer["username"]) if besitzer else None, ip_roh,
                       f"grund={type(e).__name__}")
            raise HTTPException(400, auth.t("api.passkey_unknown"))
        auth.store.update_webauthn_signcount(row["id"], v.new_sign_count)
        # client_ip, nicht request.client.host: Hinter einem Reverse-Proxy ist der Peer der
        # Proxy. Die rohe Peer-IP landete sonst in der Sitzungsliste und im Protokoll — und
        # die IP-Sperre haette alle Nutzer hinter demselben Proxy in einen Topf geworfen.
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
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
        # R3-3: Einen Passkey zu löschen nimmt dem Konto einen vollwertigen Faktor. Das verlangt
        # eine interaktive Sitzung mit frischer Bestätigung — `current_user()` hätte auch eine
        # veraltete Sitzung und jeden API-Key durchgelassen.
        u = auth.require_mfa(request)
        b = await auth.json_body(request)
        auth.store.delete_webauthn(int(b["id"]), u["id"])
        # Einen Faktor zu verlieren ist genau das, was man später nachlesen will (B5-01).
        auth.audit("passkey_delete", u["username"], auth.client_ip(request), f"id={b['id']}")
        auth.sicherheitsereignis("passkey_removed", u["id"], passkey_id=int(b["id"]))
        return {"ok": True, "other_sessions": auth.andere_sitzungen(request, u)}   # B1-7

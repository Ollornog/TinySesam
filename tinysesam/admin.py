"""Admin-Panel als eigenständiger, montierbarer Router.

    auth.admin_router()                                       # APIRouter, RELATIVE Pfade
    app.include_router(auth.admin_router(), prefix="/admin")  # frei wählbarer Pfad
    # oder auf Sub-App / eigenem Port / Subdomain mounten (Host-Routing der App)

Standardmäßig mountet `auth.router()` es zusätzlich unter `config.admin_path` (Default /auth/admin).
`admin_ui_enabled=False` → nur die JSON-API (`/api/*`), damit die UI in ein bestehendes Panel
eingebettet werden kann. Die eingebaute UI ermittelt ihre Basis-URL selbst → läuft an jedem
Mountpunkt. Nur Admins.
"""
from __future__ import annotations
import html
import json
import secrets

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse

from .errors import ConfigError, StateError
from .router import _key_art, _mail_basis, gehaertete_route
from . import security
from .store import norm_email, valid_email
from .templates import brand, favicon_link, inject_nonce as _inject_nonce
from .theme import TOKENS


def build_admin_router(auth) -> APIRouter:
    cfg = auth.cfg
    ar = APIRouter(tags=["admin"], route_class=gehaertete_route(auth))

    def guard(request: Request):
        # Admin + (optional) Step-up-MFA. Browser-Seitenaufruf → Redirect zu Login/Reauth;
        # JSON-/fetch-Aufrufe → 401/403 (Panel-UI lädt nach Reauth neu).
        #
        # CSRF wird HIER geprüft, nicht je Route: Zwei Panel-Routen hatten die Prüfung nicht
        # (Key sperren, Ressource löschen), weil sie keinen JSON-Body lesen und json_body damit
        # nie zum Zug kam. Eine Klasse zu schliessen ist verlässlicher, als sie Route für Route
        # zu flicken — die nächste neue Route ist sonst wieder offen.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
        return auth._enforce(request, admin=True, mfa=cfg.admin_require_mfa)

    def owner_schutz(me, uid: int):
        """Ein Owner-Konto ändert nur ein Owner (Owner-Modell). Sonst setzte ein Admin dem Owner ein
        neues Passwort und wäre selbst Owner — der Schutz vor dem Löschen wäre dann eine Tür mit
        offenem Fenster daneben."""
        ziel = auth.store.get_user(uid)
        if ziel and ziel["is_owner"] and not (me and me.get("is_owner")):
            raise HTTPException(403, auth.t("api.owner_only"))
        return ziel

    def protokoll(request: Request, ereignis: str, detail=None):
        """Eine Admin-Aktion protokollieren — mit Akteur und IP.

        Ohne beides ist das Audit-Log für die Aufarbeitung wertlos: Es hielt fest, DASS ein
        Konto gesperrt oder ein Passwort zurückgesetzt wurde, nicht von wem und von wo. Bei
        mehreren Admins ist das genau die Frage, die man hinterher stellt. Wie bei CSRF steht
        das hier an einer Stelle und nicht in jeder Route — die nächste neue Route erbt es.
        """
        wer = auth.current_user(request)
        auth.audit(ereignis, wer["username"] if wer else None, auth.client_ip(request), detail)

    def andere_aktive_admins(uid: int) -> int:
        """Wie viele aktive, interaktive Admins bleiben, wenn `uid` keiner mehr ist?

        Gezählt wird, wer sich wirklich als Admin anmelden kann: nicht gesperrt, kein
        Service-Konto (das hat keine Sitzung, und seine Keys tragen das Flag nie, R6-5)."""
        return sum(1 for u in auth.store.list_users()
                   if u["is_admin"] and not u["disabled"] and not u["is_service"]
                   and int(u["id"]) != int(uid))

    def rollen_aus(b: dict) -> list:
        """`roles` aus dem Body: eine Liste aus Texten — sonst 400, und zwar VOR jedem Schreiben.

        Die Datenbank nimmt jedes JSON; eine Rolle `1` oder `null` fiel erst beim Protokollieren
        auf (`','.join`), NACHDEM Rollen und Admin-Flag geschrieben waren: HTTP 500 ohne
        Audit-Zeile (Integrationsfund 8). Ein Text wie `"admin"` wurde von `list()` still in
        Buchstaben zerlegt. Fehlt das Feld (oder ist es leer), heisst das „keine Rollen"."""
        roh = b.get("roles")
        if not roh:
            return []
        if not isinstance(roh, list) or not all(isinstance(x, str) for x in roh):
            raise HTTPException(400, auth.t("api.invalid", grund="roles"))
        return list(roh)

    def uview(u):
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
                "email": u["email"], "is_admin": bool(u["is_admin"]), "is_owner": bool(u["is_owner"]),
                "is_service": bool(u["is_service"]),
                "roles": json.loads(u["roles"] or "[]"), "disabled": bool(u["disabled"]), "created_at": u["created_at"]}

    def kview(k):
        return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
                "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"]),
                "kind": _key_art(k)}

    # ---------- Benutzer / Service-Accounts ----------
    @ar.get("/api/users")
    def users(request: Request):
        guard(request)
        return [uview(u) for u in auth.store.list_users()]

    @ar.post("/api/users")
    async def user_create(request: Request):
        guard(request)
        b = await auth.json_body(request)
        username = (b.get("username") or "").strip()
        email = norm_email(b.get("email"))
        if email and not valid_email(email):
            raise HTTPException(400, auth.t("api.email_invalid"))
        # Kreuzweise prüfen (Fund R4-12): Benutzername und E-Mail sind EIN Kennungs-Raum —
        # eine Adresse, die schon Benutzername eines anderen Kontos ist, ist vergeben.
        if email and auth.kennung_vergeben(email):
            raise HTTPException(409, auth.t("api.email_taken"))
        # Im E-Mail-Modus ist die Adresse die Kennung — Benutzername darf entfallen.
        if not username and cfg.login_identifier == "email" and not b.get("is_service"):
            username = email or ""
        if not username:
            raise HTTPException(400, auth.t("api.username_req"))
        if auth.kennung_vergeben(username):
            raise HTTPException(409, auth.t("api.user_exists"))
        roles = rollen_aus(b)
        # Service-Konto + Admin (R6-2): Früher fiel `is_admin` hier still weg, über die
        # Rollen-Route liess sich das Flag danach aber doch setzen. Ein solches Konto kann sich
        # nicht anmelden, seine Keys tragen das Flag nie (R6-5) — es zählt nur als „es gibt
        # einen Admin" und schliesst damit den Erst-Admin-Weg, ohne dass jemand Admin ist.
        # Laut abweisen statt still verwerfen: Wer beides ankreuzt, hat etwas anderes gemeint.
        if b.get("is_service") and b.get("is_admin"):
            raise HTTPException(400, auth.t("api.service_admin"))
        if b.get("is_service"):
            uid = auth.create_service(username, roles=roles, display_name=b.get("display_name"))
        else:
            # Dieselbe Passwortregel wie an jeder anderen Setzstelle (Fund B2-13): Bis T-13 nahm
            # das Panel jedes Passwort an, auch `1` — ausgerechnet der Weg, auf dem die
            # Erstpasswörter ganzer Teams entstehen. Ohne Passwort bleibt erlaubt (SSO/Passkey).
            if b.get("password"):
                mangel = auth.passwort_mangel(b["password"], username=username, email=email, api=True)
                if mangel:
                    raise HTTPException(400, mangel)
            uid = auth.create_user(username, password=b.get("password") or None,
                                   is_admin=bool(b.get("is_admin")), roles=roles,
                                   display_name=b.get("display_name"), email=email)
        protokoll(request, "user_create", f"{username} service={bool(b.get('is_service'))}")
        return {"id": uid}

    @ar.post("/api/users/{uid}/disable")
    async def user_disable(request: Request, uid: int):
        me = guard(request)
        b = await auth.json_body(request)
        disabled = bool(b.get("disabled", True))
        if disabled and uid == me["id"]:
            raise HTTPException(400, auth.t("api.no_self_lock"))
        ziel = owner_schutz(me, uid)
        if disabled and ziel and ziel["is_owner"]:
            raise HTTPException(400, auth.t("api.owner_protected"))
        # Mit Betreiber-Vermerk: Kein Bestätigungslink hebt diese Sperre auf, auch einer nicht,
        # der erst nach ihr entsteht (H-18, zweite Angriffsrunde) — s. `Store.set_disabled`.
        auth.store.set_disabled(uid, disabled, durch_betreiber=True)
        keys = 0
        if disabled:
            auth.store.delete_user_sessions(uid)
            # `verify_api_key` lehnt Keys gesperrter Konten schon ab. Trotzdem widerrufen: Wird
            # das Konto später wieder freigegeben, lebte sonst ein Key wieder auf, von dem
            # niemand mehr weiss.
            keys = auth.store.revoke_user_api_keys(uid)
            # Dasselbe für offene Einmal-Token: Ein Bestätigungslink aus der Registrierung hob die
            # Sperre sonst wieder auf (H-18, „deaktiviertes Konto über keinen Pfad").
            auth.store.revoke_user_magic_tokens(uid)
        protokoll(request, "user_disable" if disabled else "user_enable",
              f"uid={uid}" + (f" api_keys_revoked={keys}" if keys else ""))
        return {"ok": True}

    @ar.post("/api/users/{uid}/password")
    async def user_password(request: Request, uid: int):
        owner_schutz(guard(request), uid)
        b = await auth.json_body(request)
        if not b.get("password"):
            raise HTTPException(400, auth.t("api.password_req"))
        ziel = auth.store.get_user(uid)
        mangel = auth.passwort_mangel(b["password"], username=ziel["username"] if ziel else None,
                                      email=ziel["email"] if ziel else None, api=True)
        if mangel:
            raise HTTPException(400, mangel)   # B2-13: auch der Admin-Reset hält die Regel ein
        auth.set_password(uid, b["password"])
        auth.store.delete_user_sessions(uid)   # Admin-Reset → alle Sitzungen beenden (Re-Login erzwingen)
        # Neu gebunden: Passwort-Fehlversuche und die Serien-Sperre (B2-6) enden hier — die Serie
        # GANZ, anders als beim Selbstbedienungs-Reset: Hier entscheidet der Betreiber, nicht wer
        # das Postfach hat. Sonst stünde das Konto nach dem Reset weiter vor der Tür.
        auth.sperre_aufheben(uid, methoden=("password",))
        auth._serie_beenden(uid)
        # Ein Admin setzt ein fremdes Passwort zurück, wenn das Konto verloren oder übernommen
        # ist. Blieben die API-Keys gültig, hätte das Aussperren nur die Haustür geschlossen —
        # der Key ist eine zweite, gleichwertige Anmeldung.
        keys = auth.store.revoke_user_api_keys(uid)
        protokoll(request, "user_password_reset", f"uid={uid} api_keys_revoked={keys}")
        return {"ok": True, "api_keys_revoked": keys}

    @ar.post("/api/users/{uid}/roles")
    async def user_roles(request: Request, uid: int):
        me = guard(request)
        b = await auth.json_body(request)
        ziel = owner_schutz(me, uid)
        if ziel is None:
            raise HTTPException(404)
        rollen = rollen_aus(b)          # geprüft VOR jedem Schreibzugriff, wie R6-1 darunter
        if "is_admin" in b:
            neu = bool(b["is_admin"])
            if not neu and ziel["is_owner"]:
                raise HTTPException(400, auth.t("api.owner_protected"))
            if neu and ziel["is_service"]:
                raise HTTPException(400, auth.t("api.service_admin"))      # R6-2, s. user_create
            # Den letzten Admin nicht entmachten (R6-1). Ohne Admin öffnet sich der
            # Erst-Admin-Weg wieder: Ein neues Einmal-Token entsteht, und wer es liest — im Log,
            # in der Konsole — wird Admin. Das Panel ist danach für niemanden mehr erreichbar,
            # der es zurückdrehen könnte. Geprüft VOR jedem Schreibzugriff, damit die Rollen
            # nicht halb gesetzt stehen bleiben.
            if not neu and ziel["is_admin"] and not andere_aktive_admins(uid):
                raise HTTPException(400, auth.t("api.last_admin"))
        # Vorher/Nachher ins Protokoll (R6-7): „uid=5" sagte, DASS sich Rechte änderten, nicht
        # welche. Ob jemand Admin wurde, ist aber genau die Frage nach einem Vorfall.
        # `str` je Rolle: Ein Altbestand aus der Zeit vor der Prüfung (oder aus eigenem Code) darf
        # die Zeile nicht sprengen — sie entsteht NACH dem Schreiben, und ein Fehler hier hiess
        # „geändert, aber nicht protokolliert" (Integrationsfund 8).
        vorher = ziel
        rollen_vorher = sorted(map(str, auth.user_roles(vorher))) if vorher else []
        admin_vorher = bool(vorher["is_admin"]) if vorher else False
        auth.set_roles(uid, rollen)
        # Nur bei einer ECHTEN Änderung schreiben (H-5): Das Panel schickt den Haken bei jedem
        # Speichern der Rollen mit. `set_admin(True)` schrieb dann eine 1 über die 2 eines vom
        # Identity Provider vergebenen Flags — aus dem entziehbaren wurde still ein dauerhaftes
        # Admin-Recht, und der nächste Login ohne Admin-Gruppe nahm es nicht mehr (Angriff auf H-5).
        if "is_admin" in b and bool(b["is_admin"]) != bool(ziel["is_admin"]):
            auth.store.set_admin(uid, bool(b["is_admin"]))
        nachher = auth.store.get_user(uid)
        rollen_nachher = sorted(map(str, auth.user_roles(nachher))) if nachher else []
        admin_nachher = bool(nachher["is_admin"]) if nachher else False
        detail = (f"uid={uid} rollen={','.join(rollen_vorher) or '-'}"
                  f"->{','.join(rollen_nachher) or '-'}")
        if admin_vorher != admin_nachher:
            detail += f" admin={int(admin_vorher)}->{int(admin_nachher)}"
        protokoll(request, "user_roles", detail)
        return {"ok": True}

    # ---------- Passkeys fremder Konten / Konto löschen (B5-08) ----------
    # Bisher konnte nur der Inhaber einen Passkey entfernen. Ist das Gerät gestohlen und der
    # Mensch ausgesperrt, blieb dem Betreiber nur die Datenbank. Dasselbe beim Löschen eines
    # Kontos: Sperren ging, Löschen (etwa auf Verlangen nach Art. 17 DSGVO) nicht.
    @ar.get("/api/users/{uid}/passkeys")
    def user_passkeys(request: Request, uid: int):
        guard(request)
        return [{"id": c["id"], "name": c["name"], "created_at": c["created_at"],
                 "last_used": c["last_used"]} for c in auth.store.list_webauthn(uid)]

    @ar.post("/api/users/{uid}/passkeys/{cid}/delete")
    def user_passkey_delete(request: Request, uid: int, cid: int):
        owner_schutz(guard(request), uid)
        # Über denselben Weg wie die Selbstbedienung (Integrationsfund 3): Löschen, Audit-Zeile
        # unter dem Inhaber (der Admin als akteur=, so findet `tinysesam audit --user <inhaber>`
        # den Widerruf) und `passkey_removed` an `on_security_event` — der Inhaber erfährt,
        # dass ihm ein Faktor genommen wurde, auch wenn es ein anderer war.
        if not auth.remove_passkey(uid, cid):
            raise HTTPException(404, auth.t("api.not_found"))
        return {"ok": True}

    @ar.post("/api/users/{uid}/owner")
    async def user_owner(request: Request, uid: int):
        """Owner-Rolle vergeben oder abgeben — nur ein Owner darf das."""
        me = guard(request)
        if not me.get("is_owner"):
            raise HTTPException(403, auth.t("api.owner_only"))
        b = await auth.json_body(request)
        try:
            if not auth.set_owner(uid, bool(b.get("owner", True))):
                raise HTTPException(404, auth.t("api.not_found"))
        except StateError:
            raise HTTPException(400, auth.t("api.last_owner"))
        except ConfigError:
            raise HTTPException(400, auth.t("api.owner_inactive"))
        return {"ok": True}

    @ar.post("/api/users/{uid}/delete")
    def user_delete(request: Request, uid: int):
        me = guard(request)
        if uid == me["id"]:
            raise HTTPException(400, auth.t("api.no_self_delete"))
        ziel = owner_schutz(me, uid)
        if ziel and ziel["is_owner"]:
            raise HTTPException(409, auth.t("api.owner_protected"))
        try:
            if not auth.delete_user(uid):
                raise HTTPException(404, auth.t("api.not_found"))
        except StateError:
            raise HTTPException(409, auth.t("api.last_admin_delete"))
        return {"ok": True}

    # ---------- API-Keys (je User) ----------
    @ar.get("/api/users/{uid}/keys")
    def user_keys(request: Request, uid: int):
        guard(request)
        return [kview(k) for k in auth.list_api_keys(uid)]

    @ar.post("/api/users/{uid}/keys")
    async def user_key_create(request: Request, uid: int):
        wer = guard(request)
        owner_schutz(wer, uid)
        # Dieselbe Regel wie an der Selbstbedienungs-Route (`_nur_mit_sitzung`, R6-6):
        # Schlüssel gibt ein Mensch aus, kein Schlüssel. Hier fehlte sie — der Panel-Pfad war
        # der Umweg, auf dem ein Key einen neuen Key mintet, und zwar für ein BELIEBIGES Konto.
        # Heute hält schon R6-5 (ein Automaten-Key trägt kein Admin-Flag, ein Menschen-Key
        # gilt nur neben der Sitzung); diese Zeile hängt nicht davon ab, dass das so bleibt.
        if wer.get("_via") != "session":
            raise HTTPException(403, auth.t("api.key_needs_session"))
        b = await auth.json_body(request)
        # Die Audit-Zeile schreibt `create_api_key` — mit Besitzer, IP und akteur= (B5-04/R6-3).
        # `create_api_key` wirft `ConfigError` für einen Scope ohne gültige Rolle und für
        # „unbefristet" ohne Erlaubnis; eine unbrauchbare Zahl ist ein `ValueError`. Ungefangen
        # war das ein HTTP 500 (R6-8) — der Admin sah „internal server error" statt des Grundes.
        try:
            return auth.create_api_key(uid, name=b.get("name"), expires_days=b.get("expires_days"),
                                       roles=b.get("roles"))
        except (ConfigError, ValueError, TypeError) as e:
            raise HTTPException(400, auth.t("api.invalid", grund=str(e)))

    @ar.post("/api/keys/{kid}/revoke")
    def key_revoke(request: Request, kid: int):
        guard(request)
        # Die Audit-Zeile schreibt `revoke_api_key` — mit Besitzer, IP und akteur= (B5-04/R6-3).
        auth.revoke_api_key(kid)
        return {"ok": True}

    # ---------- Sitzungen ----------
    @ar.get("/api/sessions")
    def sessions(request: Request):
        guard(request)
        # Auch Lesen wird protokolliert (B5-12): Die Liste nennt IP und Anmeldeweg jedes
        # Nutzers, und wer als Admin mitliest, soll dabei selbst eine Spur hinterlassen.
        protokoll(request, "sessions_read")
        names = {u["id"]: u["username"] for u in auth.store.list_users()}
        # `full` ist das HANDLE (sha256 des Tokens), nicht das Token: Es benennt die Sitzung zum
        # Beenden und taugt nicht zum Anmelden. Vorher stand hier das echte Sitzungstoken jedes
        # Nutzers — wer die Panel-Antwort sah, konnte jede fremde Sitzung übernehmen.
        return [{"full": s["token_hash"], "user": names.get(s["user_id"], s["user_id"]), "method": s["method"],
                 "ip": s["ip"], "created_at": s["created_at"], "mfa_ok": bool(s["mfa_ok"])}
                for s in auth.store.list_sessions()]

    @ar.post("/api/sessions/revoke")
    async def session_revoke(request: Request):
        guard(request)
        b = await auth.json_body(request)
        if b.get("token"):
            auth.store.delete_session_by_handle(b["token"])
        elif b.get("user_id"):
            auth.store.delete_user_sessions(int(b["user_id"]))
        protokoll(request, "session_revoke", f"user_id={b.get('user_id')}" if b.get("user_id") else "eine Sitzung")
        return {"ok": True}

    # ---------- Einladungen (Magic-Invite) ----------
    if cfg.magiclink_enabled:
        @ar.post("/api/invite")
        async def invite(request: Request):
            guard(request)
            b = await auth.json_body(request)
            email = (b.get("email") or "").strip()
            # Der Einladungslink geht per Mail an einen Dritten und trägt ein gültiges
            # Token — er darf nie aus dem Host-Header gebaut werden (R4-01).
            base = _mail_basis(auth, request)
            # Dieselbe Prüfung wie beim Anlegen: Die Rollen landen erst beim Einlösen im Konto —
            # eine kaputte Rolle fiele dann dem Eingeladenen vor die Füsse, nicht dem Admin.
            res = auth.create_invite(email or None, base, roles=rollen_aus(b),
                                     is_admin=bool(b.get("is_admin")), ttl_min=b.get("ttl_min"))
            return {"url": res["url"], "emailed": bool(email and auth.mail_configured())}

    # ---------- Geteilte Ressourcen-Geheimnisse ----------
    if cfg.resource_locks_enabled:
        @ar.get("/api/resources")
        def resources(request: Request):
            guard(request)
            return [{"name": r["name"], "kind": r["kind"], "label": r["label"], "created_at": r["created_at"]}
                    for r in auth.list_resource_secrets()]

        @ar.post("/api/resources")
        async def resource_set(request: Request):
            guard(request)
            b = await auth.json_body(request)
            name = (b.get("name") or "").strip()
            if not name or not b.get("secret"):
                raise HTTPException(400, auth.t("api.name_secret_req"))
            try:
                auth.set_resource_secret(name, b["secret"], kind=b.get("kind") or "pin", label=b.get("label"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            protokoll(request, "resource_set", name)
            return {"ok": True}

        @ar.post("/api/resources/{name}/delete")
        def resource_delete(request: Request, name: str):
            guard(request)
            auth.remove_resource_secret(name)
            protokoll(request, "resource_delete", name)
            return {"ok": True}

    # ---------- Härtung / Audit ----------
    @ar.get("/api/security")
    def security_get(request: Request):
        guard(request)
        return auth.all_security()

    @ar.post("/api/security")
    async def security_set(request: Request):
        guard(request)
        # Vorher/Nachher (R6-7): Wer `max_login_attempts` von 5 auf 5000 stellt, schaltet die
        # Sperre faktisch ab — im Protokoll stand bisher nur, DASS etwas gespeichert wurde.
        vorher = auth.all_security()
        werte = await auth.json_body(request)
        # Erst ALLE prüfen, dann schreiben: Ein ungültiger Wert in der Mitte liess sonst die
        # Hälfte gespeichert zurück. Und ohne Grenzen legte ein Tippfehler die Instanz still
        # (`rate_limit_max=0` sperrt jede Anmeldung, auch die zum Zurückdrehen — R6-4).
        try:
            geprueft = {k: security.pruefe_haertung(k, v) for k, v in werte.items()}
        except ValueError as e:
            raise HTTPException(400, auth.t("api.invalid", grund=str(e)))
        for k, v in geprueft.items():
            auth.set_security(k, v)
        nachher = auth.all_security()
        geaendert = [f"{k}={vorher[k]}->{nachher[k]}" for k in sorted(nachher)
                     if vorher.get(k) != nachher[k]]
        protokoll(request, "security_update", " ".join(geaendert) or "unverändert")
        return nachher

    @ar.get("/api/version")
    def version_get(request: Request):
        guard(request)
        return {"version": auth.version()}

    @ar.get("/api/audit")
    def audit(request: Request, limit: int = 100):
        guard(request)
        protokoll(request, "audit_read", f"limit={limit}")    # B5-12, s. sessions_read
        return [{"ts": a["ts"], "event": a["event"], "username": a["username"], "ip": a["ip"], "detail": a["detail"]}
                for a in auth.store.recent_audit(limit)]

    # ---------- eingebaute UI (optional) ----------
    if cfg.admin_ui_enabled:
        @ar.get("", response_class=HTMLResponse)
        def admin_page(request: Request):
            guard(request)
            warn = ""
            if cfg.https_mode == "warn" and not auth.is_secure(request):
                warn = ("<div class=warnbar>⚠ Unverschlüsselt (kein HTTPS) — Zugangsdaten gehen im Klartext. "
                        "Nur im vertrauenswürdigen Netz nutzen oder HTTPS davorschalten.</div>")
            # Mountpunkt → relative API-Basis
            # Dieselbe CSP wie jede andere eingebaute Seite (R8-1). Bis 0.19.0 kam ausgerechnet
            # das Panel, das Konten anlegt und Rechte vergibt, ohne CSP und ohne Schutz gegen
            # Einbetten. Möglich wurde es erst, als die Inline-Handler verschwanden (`data-on`).
            nonce = secrets.token_urlsafe(16)
            resp = HTMLResponse(_inject_nonce(
                render_panel(auth, request.url.path.rstrip("/"), warn=warn), nonce))
            policy = auth._csp_header(nonce)
            if policy:
                resp.headers.setdefault("Content-Security-Policy", policy)
            # Ein VORHANDENES Cookie übernehmen, nicht überschreiben — dieselbe Behandlung wie
            # in `render_page`. Diese Stelle war der dritte Setzer und der letzte, der bei jedem
            # Aufruf neu würfelte: Wer das Panel in einem zweiten Reiter öffnete, machte damit
            # das Formular im ersten ungültig, und der POST dort antwortete mit 403 ohne
            # Erklärung. Gegen einen Angreifer schützte das nie — getroffen wurde der eigene
            # Nutzer. (War als B-1 auf „nach 1.0" vertagt; durch die neuen CSRF-Prüfungen im
            # Panel trifft es inzwischen mehr Wege als bei der Meldung.)
            # Seit 0.20.1 über `ensure_csrf()` — dieselbe Prüfung, dieselben Attribute wie überall.
            auth.ensure_csrf(request, resp)
            return resp

    return ar


#: Alle Texte des Panels. Das Panel baut seine Oberfläche im Browser, deshalb reisen sie als
#: JSON mit (`const L`) statt in den Vorlagentext eingesetzt zu werden. Ein Schlüssel je Eintrag,
#: übersetzt über `auth.t()` — dieselbe Tabelle wie Login-, Konto- und Fehlerseite.
_KEYS = (
    "locale app tab.users tab.sessions tab.security tab.audit new_user create save saved "
    "f.username f.email f.email_optional f.password f.roles f.admin f.service "
    "f.key_name f.key_expires "
    "th.user th.email th.type th.roles th.status th.actions th.method th.ip th.since th.mfa "
    "th.time th.event th.detail "
    "active disabled revoked enable disable btn.pw btn.roles btn.keys btn.passkeys btn.delete "
    "passkeys no_passkeys confirm.delete confirm.pk_delete "
    "err.email err.generic confirm.disable confirm.enable confirm.revoke "
    "prompt.pw pw_set roles_groups no_roles api_keys create_key last_used expires "
    "never_expires revoke key_once end_session hardening version installed update_note"
).split()


def panel_texts(auth) -> dict:
    """Die Panel-Texte in der Sprache der laufenden Config. `cancel`/`logout` teilen sich alle
    Seiten, deshalb tragen sie keinen `admin.`-Vorsatz."""
    texts = {k: auth.t(f"admin.{k}") for k in _KEYS}
    texts["cancel"] = auth.t("cancel")
    texts["logout"] = auth.t("logout")
    return texts


def render_panel(auth, base: str, warn: str = "") -> str:
    """Panel-HTML für eine gegebene API-Basis. Einziger Ort, an dem `_PAGE` befüllt wird —
    damit z.B. eine Demo-/Vorschau-Einbindung dieselbe UI zeigt wie das echte Panel.

    Die Sprache kommt aus `cfg.lang`, wie bei jeder anderen eingebauten Seite. Wer sie pro
    Anfrage umschaltet (`?lang=`), bekommt das Panel übersetzt mitgeliefert.
    """
    cfg = auth.cfg
    return (_PAGE.replace("__TOKENS__", TOKENS)
            .replace("__BRANDHEAD__", getattr(cfg, "brand_head", "") or "")
            .replace("__HEADER__", brand(getattr(cfg, "brand_header", ""), auth))
            .replace("__FOOTER__", brand(getattr(cfg, "brand_footer", ""), auth))
            # `rp_name` ist Text, kein Markup (R8-3) — die übrigen Seiten escapen ihn längst.
            # `base` kommt aus dem Anfragepfad und landet in einem JS-String; json.dumps plus
            # `<`-Maskierung hält ihn dort.
            .replace("__RP__", html.escape(cfg.rp_name))
            .replace('"__BASE__"', json.dumps(base).replace("<", "\\u003c"))
            .replace("__ICON__", favicon_link(getattr(cfg, "brand_icon", "")))
            .replace("__WARN__", warn).replace("__CSRFCK__", auth.csrf_cookie_name)
            .replace("__ROLES__", json.dumps(list(cfg.available_roles)))
            .replace("__REQMAIL__", "true" if (cfg.signup_require_email or
                                              cfg.login_identifier == "email") else "false")
            .replace("__LANG__", cfg.lang)
            # `ensure_ascii=False`: die Seite ist UTF-8, „Härtung" gehört als „Härtung" hinein,
            # nicht als `Härtung`. Nur `<` wird maskiert — eine eigene Übersetzung
            # (`add_messages`) mit "</script>" beendete sonst den Skriptblock.
            .replace("__I18N__",
                     json.dumps(panel_texts(auth), ensure_ascii=False).replace("<", "\\u003c"))
            .replace("__BRANDCSS__", getattr(cfg, "brand_css", "") or ""))


_PAGE = r"""<!doctype html><html lang=__LANG__><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">__ICON__<title>__RP__ — Admin</title>
<style>
__TOKENS__
/* Alles unter .tsadmin gekapselt — sonst faerbt es auf brand_header/brand_footer ab. */
*{box-sizing:border-box}
body{font-family:var(--ts-font);margin:0;background:var(--ts-bg);color:var(--ts-ink);
  min-height:100vh;display:flex;flex-direction:column}
.tsadmin{flex:1}
.tsadmin .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:8px 20px;font-size:13px;
  border-bottom:1px solid var(--ts-warn-line)}
.tsadmin header{padding:14px 20px;background:var(--ts-surface);border-bottom:1px solid var(--ts-line);
  display:flex;gap:14px;align-items:center}
.tsadmin header h1{font-size:17px;margin:0}
.tsadmin a{color:var(--ts-link);text-decoration:none}
.tsadmin .tabs{display:flex;gap:6px;padding:12px 20px 0;flex-wrap:wrap}
.tsadmin .tab{padding:7px 13px;border-radius:8px 8px 0 0;background:var(--ts-surface);cursor:pointer;
  font-size:14px;border:1px solid transparent;border-bottom:none}
.tsadmin .tab.on{background:var(--ts-surface-2);border-color:var(--ts-line);color:var(--ts-link)}
.tsadmin .wrap{max-width:1000px;margin:0 auto;padding:18px 20px}
.tsadmin table{width:100%;border-collapse:collapse;font-size:13px}
.tsadmin th{text-align:left;color:var(--ts-muted);font-weight:600}
.tsadmin td,.tsadmin th{padding:7px 8px;border-bottom:1px solid var(--ts-line-soft);white-space:nowrap}
.tsadmin button{cursor:pointer;background:var(--ts-accent);color:var(--ts-accent-ink);border:0;
  border-radius:6px;padding:6px 11px;font-size:13px}
.tsadmin button.sec{background:var(--ts-neutral);color:var(--ts-neutral-ink)}
.tsadmin button.warn{background:var(--ts-danger);color:#fff}
.tsadmin button.ok{background:var(--ts-success);color:#fff}
.tsadmin input,.tsadmin select{background:var(--ts-field-bg);color:var(--ts-ink);
  border:1px solid var(--ts-field-line);border-radius:6px;padding:6px 9px;font-size:13px}
.tsadmin .badge{padding:1px 7px;border-radius:20px;font-size:11px;font-weight:600;
  background:var(--ts-chip);color:var(--ts-muted)}
.tsadmin .badge.red{background:var(--ts-err-bg);color:var(--ts-err-ink)}
.tsadmin .badge.grn{background:var(--ts-ok-bg);color:var(--ts-ok-ink)}
.tsadmin .badge.svc{background:var(--ts-info-bg);color:var(--ts-info-ink)}
.tsadmin .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}
.tsadmin .card{background:var(--ts-surface);border:1px solid var(--ts-line);
  border-radius:calc(var(--ts-radius) - 2px);padding:14px;margin-bottom:14px}
.tsadmin h2{font-size:13px;color:var(--ts-muted);text-transform:uppercase;letter-spacing:.05em;margin:0 0 10px}
.tsadmin .muted{color:var(--ts-muted)}
.tsadmin .w120{width:120px}.tsadmin .w150{width:150px}.tsadmin .w200{width:200px}
.tsadmin .w230{width:230px}.tsadmin .w280{width:280px}.tsadmin .mr12{margin-right:12px}
.tsadmin .small{font-size:12px}
.tsadmin code{background:var(--ts-field-bg);border:1px solid var(--ts-field-line);border-radius:5px;
  padding:2px 6px;font-size:12px}
__BRANDCSS__
</style>__BRANDHEAD__</head><body>
__HEADER__
<div class=tsadmin>
__WARN__
<header><h1>🧠 __RP__ · Admin</h1><a href="/" id=applink>← App</a><a href="/auth/logout" id=outlink>Logout</a></header>
<div class=tabs id=tabs></div>
<div class=wrap id=view></div>
<script>
const B="__BASE__";                                    // Mountpunkt (frei wählbar) → relative API-Aufrufe
const ROLES=__ROLES__;                                 // bekannte Rollen/Gruppen (config.available_roles)
const REQMAIL=__REQMAIL__;                             // config.signup_require_email (E-Mail Pflicht)
const L=__I18N__;                                      // Texte in config.lang — siehe messages.py
document.getElementById("applink").textContent="← "+L.app;
document.getElementById("outlink").textContent=L.logout;
const TABS=[["users",L["tab.users"]],["sessions",L["tab.sessions"]],["security",L["tab.security"]],["audit",L["tab.audit"]]];
let cur="users";
const g=(u)=>fetch(B+u).then(r=>r.json());
function tsCsrf(){return (document.cookie.match(/(?:^|; )__CSRFCK__=([^;]+)/)||[])[1]||''}
// Eine Abweisung (4xx/5xx) kommt IMMER als {detail:"<Text>"} zurück, auch ohne JSON-Körper. Vorher
// sah p() nur den Körper: savesec meldete „gespeichert", obwohl der Server 400 sagte, pw „Passwort
// gesetzt" trotz abgelehnter Regel, saveroles lud still neu (Integrationsfund 10).
const p=(u,b)=>fetch(B+u,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":tsCsrf()},body:JSON.stringify(b||{})})
  .then(async r=>{let j=null;try{j=await r.json()}catch(e){}
    if(r.ok)return j||{};
    return {detail:(j&&typeof j.detail==="string"&&j.detail)||L["err.generic"]}});
// Den Grund einer Abweisung zeigen — true, wenn es eine war. Jede Aktion, die p() ruft, geht hier
// durch (ein Test hält das fest), damit die nächste neue Aktion nicht wieder still scheitert.
const abgewiesen=r=>{if(r&&r.detail){alert(r.detail);return true}return false};
const esc=s=>(s??"").toString().replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
// Ein Knopf bekommt seine Aktion als data-on (Name) und data-a (Argumente als JSON), nie als
// onclick. Zwei Gruende: Die CSP des Panels erlaubt Skript nur per Nonce, ein Inline-Handler
// liefe gar nicht (R8-1). Und Daten in einem onclick sind Code — der Browser dekodiert das
// Attribut und laesst den JS-Parser darueber laufen; aus &#39; wurde wieder ein Apostroph, und
// ein Benutzername wie  bob');alert(document.cookie);//  lief im Browser der Administratorin.
// data-a dagegen wird nur mit JSON.parse gelesen: Was darin steht, bleibt ein Wert.
const on=(f,...a)=>`data-on="${f}" data-a="${esc(JSON.stringify(a))}"`;
const dt=t=>t?new Date(t*1000).toLocaleString(L.locale):"—";
function tabs(){document.getElementById("tabs").innerHTML=TABS.map(([k,l])=>`<div class="tab ${k==cur?'on':''}" ${on("go",k)}>${esc(l)}</div>`).join("")}
function go(k){cur=k;tabs();({users:users,sessions:sessions,security:security,audit:audit})[k]()}
const V=h=>document.getElementById("view").innerHTML=h;

async function users(){
  const us=await g("/api/users");
  V(`<div class=card><h2>${esc(L.new_user)}</h2><div class=row>
    <input id=nu placeholder="${esc(L["f.username"])}"><input id=ne type=email placeholder="${esc(REQMAIL?L["f.email"]:L["f.email_optional"])}">
    <input id=np type=password placeholder="${esc(L["f.password"])}">
    <input id=nr placeholder="${esc(L["f.roles"])}" class=w200>
    <label><input type=checkbox id=na> ${esc(L["f.admin"])}</label><label><input type=checkbox id=ns> ${esc(L["f.service"])}</label>
    <button ${on("mkuser")}>${esc(L.create)}</button></div></div>
    <table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.email"])}</th><th>${esc(L["th.type"])}</th><th>${esc(L["th.roles"])}</th><th>${esc(L["th.status"])}</th><th>${esc(L["th.actions"])}</th></tr>`+
    us.map(u=>`<tr><td><b>${esc(u.username)}</b></td>
      <td>${esc(u.email)||'<span class=muted>—</span>'}</td>
      <td>${u.is_owner?'<span class="badge grn">owner</span> ':''}${u.is_admin?'<span class="badge grn">admin</span> ':''}${u.is_service?'<span class="badge svc">service</span>':'<span class=badge>user</span>'}</td>
      <td>${esc((u.roles||[]).join(", "))||'—'}</td>
      <td>${u.disabled?`<span class="badge red">${esc(L.disabled)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`}</td>
      <td>
        <button class="${u.disabled?'ok':'warn'}" ${on("dis",u.id,!u.disabled)}>${esc(u.disabled?L.enable:L.disable)}</button>
        <button class=sec ${on("pw",u.id)}>${esc(L["btn.pw"])}</button>
        <button class=sec ${on("roles",u.id,(u.roles||[]).join(','),u.is_admin?1:0)}>${esc(L["btn.roles"])}</button>
        <button class=sec ${on("keys",u.id,u.username)}>${esc(L["btn.keys"])}</button>
        <button class=sec ${on("pks",u.id,u.username)}>${esc(L["btn.passkeys"])}</button>
        <button class=sec ${on("own",u.id,!u.is_owner)}>${esc(u.is_owner?L["btn.owner_off"]:L["btn.owner_on"])}</button>
        <button class=warn ${on("deluser",u.id)}>${esc(L["btn.delete"])}</button>
      </td></tr><tr id=r${u.id}></tr><tr id=k${u.id}></tr>`).join("")+`</table>`);
}
async function mkuser(){const b={username:nu.value,email:ne.value,password:np.value,roles:nr.value.split(",").map(s=>s.trim()).filter(Boolean),is_admin:na.checked,is_service:ns.checked};
  if(REQMAIL&&!ns.checked&&!ne.value.trim())return alert(L["err.email"]);
  const r=await p("/api/users",b);if(!abgewiesen(r))users()}
async function own(id,o){if(!confirm(o?L["confirm.owner_on"]:L["confirm.owner_off"]))return;abgewiesen(await p(`/api/users/${id}/owner`,{owner:o}));users()}
async function dis(id,d){if(!confirm(d?L["confirm.disable"]:L["confirm.enable"]))return;abgewiesen(await p(`/api/users/${id}/disable`,{disabled:d}));users()}
async function pw(id){const v=prompt(L["prompt.pw"]);if(v&&!abgewiesen(await p(`/api/users/${id}/password`,{password:v})))alert(L.pw_set)}
async function roles(id,cur,isadmin){
  const have=new Set((cur||"").split(",").map(s=>s.trim()).filter(Boolean));
  const inner = ROLES.length
    ? ROLES.map(r=>`<label class=mr12><input type=checkbox class="rc_${id}" value="${esc(r)}" ${have.has(r)?"checked":""}> ${esc(r)}</label>`).join("")
    : `<input id="rf${id}" value="${esc(cur)}" placeholder="${esc(L["f.roles"])}" class=w280>`;
  document.getElementById("r"+id).innerHTML=`<td colspan=5><div class=card><h2>${esc(L.roles_groups)}</h2>
    <div class=row>${inner||`<span class=muted>${esc(L.no_roles)}</span>`}</div>
    <div class=row><label><input type=checkbox id="ra${id}" ${isadmin?"checked":""}> ${esc(L["f.admin"])}</label>
      <button ${on("saveroles",id)}>${esc(L.save)}</button>
      <button class=sec ${on("clr",id)}>${esc(L.cancel)}</button></div></div></td>`;
}
async function saveroles(id){
  const roles = ROLES.length
    ? [...document.querySelectorAll(".rc_"+id+":checked")].map(c=>c.value)
    : (document.getElementById("rf"+id).value||"").split(",").map(s=>s.trim()).filter(Boolean);
  abgewiesen(await p(`/api/users/${id}/roles`,{roles,is_admin:document.getElementById("ra"+id).checked}));users();
}
async function keys(id,name){const ks=await g(`/api/users/${id}/keys`);
  document.getElementById("k"+id).innerHTML=`<td colspan=5><div class=card><h2>${esc(L.api_keys)} · ${esc(name)}</h2>
    <div class=row><input id=kn placeholder="${esc(L["f.key_name"])}"><input id=ke type=number placeholder="${esc(L["f.key_expires"])}" class=w150>
    <button ${on("mkkey",id)}>${esc(L.create_key)}</button></div>
    <table>`+ks.map(k=>`<tr><td><code>${esc(k.prefix)}</code> ${esc(k.name||'')}</td><td>${k.revoked?`<span class="badge red">${esc(L.revoked)}</span>`:`<span class="badge grn">${esc(L.active)}</span>`}</td>
      <td>${esc(L.last_used)} ${dt(k.last_used)}</td><td>${k.expires_at?esc(L.expires)+' '+dt(k.expires_at):esc(L.never_expires)}</td>
      <td>${k.revoked?'':`<button class=warn ${on("revk",k.id,id,name)}>${esc(L.revoke)}</button>`}</td></tr>`).join("")+`</table></div></td>`}
async function mkkey(id){const r=await p(`/api/users/${id}/keys`,{name:kn.value,expires_days:ke.value?parseInt(ke.value):null});
  if(!abgewiesen(r)&&r.key)prompt(L.key_once,r.key);keys(id,"")}
async function pks(id,name){const ps=await g(`/api/users/${id}/passkeys`);
  document.getElementById("k"+id).innerHTML=`<td colspan=5><div class=card><h2>${esc(L.passkeys)} · ${esc(name)}</h2>
    <table>`+(ps.length?ps.map(c=>`<tr><td>${esc(c.name||'')}</td><td>${dt(c.created_at)}</td><td>${esc(L.last_used)} ${dt(c.last_used)}</td>
      <td><button class=warn ${on("delpk",id,c.id,name)}>${esc(L.revoke)}</button></td></tr>`).join(""):`<tr><td class=muted>${esc(L.no_passkeys)}</td></tr>`)+`</table></div></td>`}
async function delpk(uid,cid,name){if(confirm(L["confirm.pk_delete"])){abgewiesen(await p(`/api/users/${uid}/passkeys/${cid}/delete`));pks(uid,name)}}
async function deluser(id){if(!confirm(L["confirm.delete"]))return;if(!abgewiesen(await p(`/api/users/${id}/delete`)))users()}
async function revk(kid,uid,name){if(confirm(L["confirm.revoke"])){abgewiesen(await p(`/api/keys/${kid}/revoke`));keys(uid,name)}}

async function sessions(){const ss=await g("/api/sessions");
  V(`<table><tr><th>${esc(L["th.user"])}</th><th>${esc(L["th.method"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.since"])}</th><th>${esc(L["th.mfa"])}</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.method)}</td><td>${esc(s.ip)}</td><td>${dt(s.created_at)}</td>
      <td>${s.mfa_ok?'✓':'—'}</td><td><button class=warn ${on("revs",s.full)}>${esc(L.end_session)}</button></td></tr>`).join("")+`</table>`)}
async function revs(t){abgewiesen(await p("/api/sessions/revoke",{token:t}));sessions()}
function clr(id){document.getElementById("r"+id).innerHTML=""}

async function security(){const s=await g("/api/security");const v=await g("/api/version");
  V(`<div class=card><h2>${esc(L.hardening)}</h2>`+
    Object.entries(s).map(([k,v])=>`<div class=row><label class=w230>${esc(k)}</label><input id="s_${esc(k)}" value="${esc(v)}" type=number class=w120></div>`).join("")+
    `<div class=row><button ${on("savesec",Object.keys(s))}>${esc(L.save)}</button></div></div>`+
    `<div class=card><h2>${esc(L.version)}</h2><div class=row>${esc(L.installed)} <code>${esc(v.version)}</code></div>
     <div class="muted small">${esc(L.update_note)}</div></div>`)}
async function savesec(keys){const b={};keys.forEach(k=>b[k]=parseInt(document.getElementById("s_"+k).value));if(!abgewiesen(await p("/api/security",b)))alert(L.saved)}


async function audit(){const a=await g("/api/audit?limit=120");
  V(`<table><tr><th>${esc(L["th.time"])}</th><th>${esc(L["th.event"])}</th><th>${esc(L["th.user"])}</th><th>${esc(L["th.ip"])}</th><th>${esc(L["th.detail"])}</th></tr>`+
    a.map(e=>`<tr><td>${dt(e.ts)}</td><td>${esc(e.event)}</td><td>${esc(e.username)||'—'}</td><td>${esc(e.ip)||'—'}</td><td>${esc(e.detail)||''}</td></tr>`).join("")+`</table>`)}

// Ein delegierter Listener fuer alle Knoepfe, auch die per innerHTML nachgeladenen. Nur Namen
// aus ACT sind aufrufbar — data-on waehlt eine Aktion aus, es nennt keinen beliebigen Code.
const ACT={go,mkuser,dis,pw,roles,saveroles,clr,keys,mkkey,revk,revs,savesec,pks,delpk,deluser};
document.addEventListener("click",e=>{const el=e.target.closest("[data-on]");
  if(!el||!ACT[el.dataset.on])return;ACT[el.dataset.on](...JSON.parse(el.dataset.a||"[]"))});
tabs();users();
</script>
</div>__FOOTER__</body></html>"""

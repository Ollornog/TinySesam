"""TinySesam — zentrale Auth-Klasse. Orchestriert Store, Passwort, TOTP, (optional) OIDC & Passkey.

Einbindung:
    from tinysesam import TinySesam, TinySesamConfig
    auth = TinySesam(TinySesamConfig(db_path="app.db", rp_id="app.example.com", origin="https://app.example.com"))
    auth.ensure_admin("admin", "startpw")          # ersten Admin anlegen (nur wenn leer)
    app.include_router(auth.router())              # /auth/* Routen + Login-UI
    @app.get("/geheim")
    def geheim(user = Depends(auth.require_user)):  # geschützt
        return {"hi": user["username"]}
"""
from __future__ import annotations
import re
import time
import json
import hashlib
import secrets
from typing import Any, Literal, NoReturn, Optional, cast

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from . import konfigpruefung
from .errors import ConfigError, MissingExtra
from .config import TinySesamConfig
from .store import Store, norm_email
from .passwords import hash_password, verify_password, needs_rehash, dummy_verify
from .templates import Templates
from . import totp as _totp
from . import security


# Setzt nonce="…" in jedes <script>/<style>, das noch keins hat. Zentral, statt den Nonce
# durch jede Template-Funktion zu faedeln. Sicher, weil keine der eingebauten Seiten den
# String "<script"/"<style" INNERHALB eines JS-Strings ausgibt (geprueft) — nur echte Tags.
_NONCE_TAG = re.compile(r'<(script|style)(?![^>]*\bnonce=)(?=[\s>])')


def _inject_nonce(html_str: str, nonce: str) -> str:
    return _NONCE_TAG.sub(rf'<\g<1> nonce="{nonce}"', html_str)


def _samesite(wert: str) -> Literal["lax", "strict", "none"]:
    """Der Konstruktor lässt nur diese drei Werte zu (s. TinySesam.__init__); hier steht es
    noch einmal für den Typprüfer, dem die Zusage von dort nicht folgt."""
    return cast(Literal["lax", "strict", "none"], wert)


#: Welcher Schalter welches Extra braucht — Schalter → (Modul, Extra).
#: Steht hier, nicht im Test: Eine Kopie in tests/ wäre beim nächsten neuen Verfahren still
#: veraltet. Der Test prüft jetzt GEGEN diese Tabelle.
SCHALTER_BRAUCHT_EXTRA = {
    "passkey_enabled": ("webauthn", "passkey"),
    "oidc_enabled": ("authlib", "oidc"),
    "saml_enabled": ("onelogin", "saml"),
    "ldap_enabled": ("ldap3", "ldap"),
}


class TinySesam:
    def __init__(self, config: TinySesamConfig):
        if config.login_identifier not in ("username", "email", "both"):
            raise ConfigError("login_identifier muss 'username', 'email' oder 'both' sein")
        if config.login_identifier == "email" and config.allow_signup and not config.signup_require_email:
            raise ConfigError("login_identifier='email' braucht signup_require_email=True — "
                             "sonst entstehen Konten, die sich nicht anmelden können")
        # Alle übrigen Widersprüche auf einmal — beim Aufbau, nicht beim ersten Login. Die
        # Prüfungen oben werfen einzeln, weil jede für sich eine eigene Geschichte erzählt;
        # was danach kommt, sammelt konfigpruefung.py und meldet es gemeinsam. Wer drei Dinge
        # falsch hat, soll sie einmal lesen und nicht dreimal starten.
        befunde, hinweise = konfigpruefung.pruefe(config)
        for hinweis in hinweise:
            security.seclog.warning("Konfiguration: %s", hinweis)
        if befunde:
            raise ConfigError("Die Konfiguration geht so nicht auf:\n  - " + "\n  - ".join(befunde))

        # Ein eingeschalteter Schalter ohne sein Extra: Bis 0.18.0 fiel das je nach Methode
        # unterschiedlich auf — bei Passkey mit einer verständlichen Meldung, sonst als
        # ModuleNotFoundError aus dem Innern der Bibliothek oder erst beim ersten Login als 500.
        # Hier steht es an einer Stelle, scheitert beim Aufbau und sagt, welche Zeile fehlt.
        import importlib.util as _ilu

        for schalter, (modul, extra) in SCHALTER_BRAUCHT_EXTRA.items():
            if not getattr(config, schalter, False):
                continue
            try:
                da = _ilu.find_spec(modul) is not None
            except (ImportError, ValueError):
                da = False
            if not da:
                raise MissingExtra(
                    f"{schalter}=True, aber das Extra [{extra}] ist nicht installiert "
                    f"(pip install 'tinysesam[{extra}]'). Ohne es fehlt das Modul '{modul}'; "
                    f"{schalter}=False schaltet die Methode ab.", extra=extra)

        if config.cookie_samesite not in ("lax", "strict", "none"):
            raise ConfigError(
                "cookie_samesite muss 'lax', 'strict' oder 'none' sein (klein geschrieben). "
                "Starlette prüft den Wert erst beim ersten Cookie — und unter `python -O` gar "
                "nicht, dann stünde der Tippfehler im Set-Cookie-Header.")
        if config.cookie_samesite == "none" and not config.cookie_secure:
            raise ConfigError(
                "cookie_samesite='none' verlangt cookie_secure=True — ein Browser verwirft ein "
                "SameSite=None-Cookie ohne Secure-Flag, die Anmeldung käme nie an.")
        if not isinstance(config.csp, str):
            raise ConfigError("csp muss ein String sein ('strict', 'off' oder eine eigene Policy)")
        if config.https_mode not in ("off", "warn", "force"):
            raise ConfigError("https_mode muss 'off', 'warn' oder 'force' sein — alles andere "
                             "gilt als 'kein Redirect', ein Tippfehler schaltet den HTTPS-Zwang "
                             "also still ab")
        # cookie_secure=False ist für lokale Aufbauten ohne Zertifikat richtig und bleibt
        # erlaubt. Zusammen mit https_mode='force' widerspricht es sich aber: Die App leitet
        # dann jeden Request auf HTTPS um und gibt das Session-Cookie trotzdem ohne
        # Secure-Flag heraus.
        #
        # Geprüft wird nur, was die App über ihr EIGENES Verhalten sagt — nicht, was sie über
        # die Außenwelt behauptet. Eine frühere Fassung schlug auch bei
        # `base_url='https://…' + cookie_secure=False` an; das klang plausibel, war aber falsch:
        # `base_url` ist eine Zusage über die öffentliche Adresse (SAML/OIDC bauen daraus
        # Callbacks), nicht über den Transport zwischen Browser und App. Vier eigene Suiten
        # brauchen genau diese Kombination (öffentliche HTTPS-URL, TestClient auf http://) —
        # ein Wächter, der im eigenen Haus viermal falsch anschlägt, tut es bei Nutzern erst recht.
        # `totp_required` war seit jeher ein Schalter ohne Draht: Er stand in der Config, in
        # beiden READMEs („2FA erzwingen") und auf der Website — und wurde an keiner Stelle im
        # Code gelesen. Wer ihn setzte, glaubte den zweiten Faktor erzwungen zu haben und hatte
        # ihn nicht. Ein wirkungsloser Sicherheitsschalter ist gefährlicher als gar keiner, denn
        # er beendet die Suche nach dem richtigen Weg. Deshalb sagt es die Bibliothek jetzt laut,
        # statt ihn weiter stumm zu ignorieren — und nennt den Weg, der wirklich greift.
        if getattr(config, "totp_required", False):
            raise ConfigError(
                "totp_required hat nie etwas bewirkt — der Schalter wurde an keiner Stelle "
                "gelesen. Wer TOTP verbindlich verlangen will, nimmt die Faktor-Kette: "
                "login_chain=['password', 'totp'] (mit login_chain_strict=True). Ohne Kette "
                "gilt die klassische Policy: TOTP wird verlangt, sobald es eingerichtet ist.")
        if not config.cookie_secure and config.https_mode == "force":
            raise ConfigError(
                "https_mode='force' und cookie_secure=False widersprechen sich: Die App "
                "leitet jeden Request auf HTTPS um, gibt das Session-Cookie aber ohne "
                "Secure-Flag heraus. Entweder cookie_secure=True, oder https_mode='warn' "
                "(lokal/ohne Zertifikat).")

        # Erst-Admin per Allowlist + offene Selbst-Registrierung: Die Allowlist verbürgt nur,
        # WELCHER Name Admin wird — nicht, WER diesen Namen bekommt. Steht `admin_identifiers`
        # auf einer frischen Instanz mit `allow_signup=True`, registriert sich der Erste, der
        # die Adresse errät, genau darunter und ist beim ersten Login Admin. Das ist derselbe
        # Fehler, den der Bootstrap eigentlich vermeiden soll ("der Erste gewinnt") — nur eine
        # Stufe später.
        #
        # Tragfähig ist die Kombination nur, wenn die Identität aus der Registrierung selbst
        # belegt ist: eine E-Mail-Adresse (kein reiner Benutzername, den niemand bestätigt),
        # bei der Registrierung Pflicht UND per Bestätigungslink verifiziert. Dann hat den
        # Namen, wer das Postfach hat.
        if config.admin_identifiers and config.allow_signup:
            ids = [str(i).strip() for i in config.admin_identifiers if str(i).strip()]
            namen = [i for i in ids if "@" not in i]
            if namen:
                raise ConfigError(
                    f"admin_identifiers={namen} sind Benutzernamen und allow_signup=True: Ein "
                    "Benutzername wird bei der Registrierung von niemandem bestätigt — wer sich "
                    "als Erster so anmeldet, wird Erst-Admin. Entweder eine E-Mail-Adresse "
                    "eintragen (mit signup_require_email=True und signup_verify_email=True), "
                    "oder allow_signup=False, oder den Einmal-Token-Weg nutzen "
                    "(/auth/claim-admin, s. admin_claim_ttl_min).")
            if not (config.signup_require_email and config.signup_verify_email):
                raise ConfigError(
                    "admin_identifiers zusammen mit allow_signup=True verlangt "
                    "signup_require_email=True UND signup_verify_email=True — sonst trägt "
                    "jeder die Admin-Adresse bei der Registrierung einfach ein und wird beim "
                    "ersten Login Admin. Alternativ allow_signup=False oder der Einmal-Token-Weg "
                    "(/auth/claim-admin, s. admin_claim_ttl_min).")
        # Ein Tippfehler im Feldnamen ("mail" statt "email") würde den Header sonst einfach
        # weglassen — still, und erst beim Debuggen der fremden App zu sehen. Header-Namen werden
        # gegen das erlaubte Zeichenset geprüft: ein Wert mit Zeilenumbruch wäre Header-Injection.
        if config.forward_headers:
            erlaubt = set(self.FORWARD_HEADERS_DEFAULT)
            unbekannt = [k for k in config.forward_headers if k not in erlaubt]
            if unbekannt:
                raise ConfigError(f"forward_headers: unbekanntes Feld {unbekannt} — erlaubt sind "
                                 f"{sorted(erlaubt)}")
            for feld, namen in config.forward_headers.items():
                for name in ([namen] if isinstance(namen, str) else namen or []):
                    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
                        raise ConfigError(f"forward_headers[{feld!r}]: {name!r} ist kein gültiger "
                                         "Header-Name")
        self.cfg = config
        self.store = Store(config.db_path)
        self.templates = Templates()
        self._messages: dict = {}
        self._mailer_override = None
        self.oidc = None
        self.webauthn = None
        self.ldap = None
        self.saml = None
        if config.security_log:
            security.attach_security_log(config.security_log)
        # Beide Limiter haben dieselbe `allow()`-Schnittstelle; `Any` sagt das, ohne für zwei
        # Implementierungen ein Protocol einzuführen.
        self.rl: Any = security.RateLimiter()
        if config.redis_url:
            try:
                self.rl = security.RedisRateLimiter(config.redis_url)
            except Exception:
                security.seclog.warning("Redis-Rate-Limit nicht verfügbar → In-Memory-Fallback")
        if config.ldap_enabled and config.ldap_url:
            from .ldap_ import LDAPClient
            self.ldap = LDAPClient(config)
        if config.saml_enabled and config.saml_idp_sso_url and config.saml_idp_x509cert:
            from .saml_ import SAMLClient
            self.saml = SAMLClient(config)
        if config.oidc_enabled and config.oidc_issuer and config.oidc_client_id:
            from .oidc import OIDCClient
            self.oidc = OIDCClient(config.oidc_issuer, config.oidc_client_id,
                                   config.oidc_client_secret, config.oidc_scopes)
        if config.passkey_enabled:
            from . import webauthn_ as wa
            self.webauthn = wa
        if config.demo_mode:
            security.seclog.warning(
                "DEMO-MODUS aktiv: Beispielkonten %s mit bekanntem Passwort. NICHT produktiv betreiben.",
                ", ".join(self.DEMO_USERS))
            self.seed_demo()
        elif self.store.get_setting("demo_users"):
            n = self.purge_demo()                       # Demo-Modus abgeschaltet → Konten sind weg
            if n:
                security.seclog.warning("Demo-Modus aus: %d Beispielkonto(en) gelöscht.", n)
        # Forward-Auth über mehrere Hosts, aber ohne cookie_domain: Das Session-Cookie ist
        # host-only, also gibt es KEIN geteiltes SSO — jeder Host verlangt eine eigene Anmeldung.
        # Die Login-URL wird pro Host gebaut (siehe forward_login_url), damit daraus wenigstens
        # keine stille Redirect-Schleife wird. Das ist vorab beweisbar, ohne über die Außenwelt
        # zu raten: die Hosts stehen in der eigenen Konfiguration.
        if config.forward_auth_enabled and config.base_url and not config.cookie_domain:
            from urllib.parse import urlsplit
            own = urlsplit(config.base_url).hostname or ""
            fremd = [h for h in (config.trusted_redirect_hosts or []) if h and h != own]
            if fremd:
                security.seclog.warning(
                    "Forward-Auth ohne cookie_domain: Das Session-Cookie gilt nur host-only auf %s, "
                    "nicht auf %s. Diese Hosts verlangen je eine eigene Anmeldung (die Login-Seite "
                    "wird dort gebaut). Für gemeinsames SSO über Subdomains cookie_domain setzen, "
                    "z.B. '.%s'.", own or "?", ", ".join(fremd),
                    ".".join(own.split(".")[-2:]) if own.count(".") >= 1 else "example.com")
        tok = self.admin_claim_token()
        if tok:
            security.seclog.warning(
                "Kein Admin vorhanden. Ersten Admin setzen: anmelden, dann /auth/claim-admin?token=%s "
                "(gültig %d Minuten, genau einmal einlösbar).", tok, config.admin_claim_ttl_min)

    # ---------- User-Verwaltung ----------
    def create_user(self, username, password=None, is_admin=False, roles=None,
                    display_name=None, email=None, is_service=False) -> int:
        """Ein Konto anlegen und seine ID zurückgeben. `is_service=True` für Maschinen: kein Login, nur API-Keys."""
        email = norm_email(email)
        if email and self.store.email_taken(email):
            raise ConfigError("E-Mail-Adresse ist bereits vergeben")
        uid = self.store.create_user(username, display_name, email, is_admin, roles, is_service)
        if password:
            self.store.set_password_hash(uid, hash_password(password))
        return uid

    # Rollen (optional). Wer nur „eingeloggt oder nicht" braucht, nimmt require_user.
    # Andere Projekte differenzieren User über is_admin + frei definierbare roles.
    def user_roles(self, user) -> list:
        """Die Rollen eines Kontos als Liste."""
        import json
        try:
            return json.loads(user["roles"] or "[]")
        except Exception:
            return []

    def is_admin(self, user) -> bool:
        """Ist dieses Konto Admin? Nimmt eine Kontozeile, kein Request."""
        return bool(user["is_admin"])

    def has_role(self, user, role, admin_implies=None) -> bool:
        """Hat der User die Rolle? Ein Admin erfüllt standardmäßig JEDE Rolle
        (`config.admin_implies_roles`). Wer Rechte allein an IdP-Gruppen hängt, schaltet das ab —
        sonst ist jeder lokale Admin automatisch auch „editor", „viewer", … ."""
        if admin_implies is None:
            admin_implies = self.cfg.admin_implies_roles
        if admin_implies and bool(user["is_admin"]):
            return True
        return role in self.user_roles(user)

    def set_roles(self, user_id, roles):
        """Die Rollen eines Kontos ersetzen."""
        self.store.set_roles(user_id, roles)

    def apply_idp_groups(self, user_id, groups, mapping: dict, substring: Optional[bool] = None):
        """IdP-Gruppen → lokale Rollen (beim Login). Ziel '__admin__' setzt das Admin-Flag (nur grant,
        nie automatisch entziehen). Gemappte Rollen werden synchronisiert (bei Wegfall der Gruppe
        entfernt), manuell vergebene Rollen bleiben.

        Verglichen wird standardmäßig **exakt** (`config.group_match`). Teilstring nur, wo er nötig
        ist — bei LDAP kommen ganze `memberOf`-DNs an. Sonst würde `admin` auch auf `nicht-admin`
        passen: eine stille Rechteausweitung."""
        if not mapping:
            return
        if substring is None:
            substring = self.cfg.group_match == "substring"
        gs = [str(g) for g in (groups or [])]
        if substring:
            matched = {role for key, role in mapping.items() if any(str(key) in g for g in gs)}
        else:
            matched = {role for key, role in mapping.items() if str(key) in gs}
        managed = {role for role in mapping.values() if role != "__admin__"}
        current = set(self.store.get_roles(user_id))
        new_roles = (current - managed) | {r for r in matched if r != "__admin__"}
        if new_roles != current:
            self.store.set_roles(user_id, sorted(new_roles))
        if "__admin__" in matched:
            u = self.store.get_user(user_id)
            if u and not u["is_admin"]:
                self.store.set_admin(user_id, True)

    # ---------- API-Keys / Service-Accounts (maschineller Zugang, Daemons) ----------
    def create_service(self, username, roles=None, display_name=None) -> int:
        """Service-/Daemon-Account: kein interaktiver Login, nur API-Keys. Rollen = Rechte-Scope."""
        return self.create_user(username, is_service=True, roles=roles, display_name=display_name or username)

    def create_api_key(self, user_id, name=None, expires_days=None, roles=None) -> dict:
        """Neuen API-Key erzeugen. Rückgabe enthält 'key' im KLARTEXT — nur EINMAL (danach nur der Hash).

        `roles` ist ein **Scope**, kein Rechtezuwachs: Die Liste wird auf die Rollen des Besitzers
        beschnitten. Ein Key kann damit weniger können als sein Besitzer, nie mehr.

        Bis 2026-09-21 wurde die Liste ungeprüft übernommen, und beim Prüfen überschrieb sie die
        Rollen des Kontos. Jeder angemeldete Nutzer konnte sich damit über die Selbstbedienungs-Route
        `POST /auth/apikeys` beliebige Rollen ausstellen — unsichtbar, weil das Konto in der
        Datenbank rollenlos blieb. Im Forward-Auth-Betrieb ging die erfundene Rolle als Remote-Group
        an die nachgelagerte App.
        """
        raw = "tsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:12] + "…"
        expires_at = (int(time.time()) + int(expires_days) * 86400) if expires_days is not None else None

        abgeschnitten = []
        if roles is not None:
            besitzer = self.store.get_user(user_id)
            erlaubt = set(self.user_roles(besitzer)) if besitzer else set()
            gewuenscht = [str(x) for x in roles]
            abgeschnitten = sorted(set(gewuenscht) - erlaubt)
            roles = sorted(set(gewuenscht) & erlaubt)

        kid = self.store.add_api_key(user_id, name, prefix, key_hash, roles, expires_at)
        detail = f"user={user_id} key={kid} name={name}"
        if abgeschnitten:
            # In den Audit-Eintrag, nicht nur verwerfen: Wer das versucht, soll sichtbar sein.
            detail += f" verworfene_rollen={','.join(abgeschnitten)}"
        self.audit("apikey_create", detail=detail)
        return {"id": kid, "key": raw, "prefix": prefix, "expires_at": expires_at,
                "roles": roles, "verworfene_rollen": abgeschnitten}

    def verify_api_key(self, key):
        """(user, key_roles|None) bei gültigem Key, sonst (None, None)."""
        if not key or not key.startswith("tsk_"):
            return None, None
        row = self.store.get_api_key_by_hash(hashlib.sha256(key.encode()).hexdigest())
        if not row or row["revoked"]:
            return None, None
        if row["expires_at"] and row["expires_at"] < int(time.time()):
            return None, None
        u = self.store.get_user(row["user_id"])
        if not u or u["disabled"]:
            return None, None
        self.store.touch_api_key(row["id"])
        try:
            kr = json.loads(row["roles"] or "[]")
        except Exception:
            kr = []
        return u, (kr or None)

    def _extract_api_key(self, request: Request):
        h = request.headers.get("x-api-key")
        if h:
            return h.strip()
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok.startswith("tsk_"):
                return tok
        return None

    def list_api_keys(self, user_id):
        """Die API-Keys eines Kontos — ohne die Schlüssel selbst, die gibt es nur einmal bei der Ausgabe."""
        return self.store.list_api_keys(user_id)

    def revoke_api_key(self, key_id, user_id=None):
        """Einen Key entwerten. Er bleibt in der Liste stehen — wer ihn ausgestellt hat, soll das sehen."""
        self.store.revoke_api_key(key_id, user_id)
        self.audit("apikey_revoke", detail=f"key={key_id}")

    def set_password(self, user_id, password):
        """Das Passwort eines Kontos setzen (ohne das alte zu prüfen — das ist Sache des Aufrufers)."""
        self.store.set_password_hash(user_id, hash_password(password))

    def ensure_admin(self, username, password) -> bool:
        """Bootstrap: legt einen Admin an, WENN noch kein User existiert. True bei Anlage."""
        if self.store.user_count() == 0:
            self.create_user(username, password, is_admin=True)
            return True
        return False

    # ---------- Erst-Admin (Bootstrap) ----------
    # Bewusst NICHT "der erste registrierte User wird Admin": bei offener Registrierung gewinnt,
    # wer als Erstes da ist — auch ein Fremder, der die frische Instanz findet. Stattdessen zwei
    # explizite Wege, beide nur wirksam, SOLANGE es keinen Admin gibt.
    def admin_exists(self) -> bool:
        """Gibt es mindestens einen Admin? Die beiden Bootstrap-Wege greifen nur, solange nicht."""
        return any(u["is_admin"] for u in self.store.list_users())

    def maybe_promote_admin(self, user) -> bool:
        """Weg 1: Allowlist. Wer in `admin_identifiers` steht (Name ODER E-Mail), wird beim Login
        Admin — egal über welche Methode (auch OIDC/SAML/LDAP). Danach nie wieder."""
        ids = {str(i).strip().lower() for i in self.cfg.admin_identifiers if str(i).strip()}
        if not ids or not user or user["is_admin"] or self.admin_exists():
            return False
        cand = {str(user["username"] or "").lower(), str(user["email"] or "").lower()} - {""}
        if not (cand & ids):
            return False
        self.store.set_admin(user["id"], True)
        self.audit("admin_bootstrap", user["username"], detail="admin_identifiers")
        security.seclog.warning("Erst-Admin per admin_identifiers vergeben: %s", user["username"])
        return True

    def admin_claim_token(self) -> Optional[str]:
        """Weg 2: Einmal-Token. Solange kein Admin existiert, gibt es ein Token, das genau einmal
        eingelöst werden kann (`/auth/claim-admin?token=…`). Es steht nur im Log/in der Konsole —
        wer den Server betreibt, hat es; wer bloß die URL kennt, nicht. Läuft ab."""
        # Kein Panel, keine lokalen Admins → kein Token. Sonst hätte eine reine OIDC-App einen
        # Weg zum Admin, den sie gar nicht vorgesehen hat (und der im Log stünde).
        if not self.cfg.admin_enabled or self.cfg.admin_claim_ttl_min <= 0 or self.admin_exists():
            return None
        raw = self.store.get_setting("admin_claim")
        now = int(time.time())
        if raw:
            token, exp = raw.split(":", 1)
            if int(exp) > now:
                return token
        token = secrets.token_urlsafe(24)
        self.store.set_setting("admin_claim", f"{token}:{now + self.cfg.admin_claim_ttl_min * 60}")
        return token

    def consume_admin_claim(self, token, user) -> bool:
        """Das Einmal-Token einlösen und dieses Konto zum Admin machen. Gilt genau einmal."""
        if not token or not user or not self.cfg.admin_enabled or self.admin_exists():
            return False
        raw = self.store.get_setting("admin_claim")
        if not raw:
            return False
        want, exp = raw.split(":", 1)
        if int(exp) <= int(time.time()) or not secrets.compare_digest(token, want):
            return False
        self.store.set_setting("admin_claim", "")     # einmalig
        self.store.set_admin(user["id"], True)
        self.audit("admin_bootstrap", user["username"], detail="claim_token")
        security.seclog.warning("Erst-Admin per Einmal-Token vergeben: %s", user["username"])
        return True

    # ---------- Demo-Modus ----------
    DEMO_USERS = ("demo", "demoadmin")

    def seed_demo(self) -> None:
        """Beispielkonten anlegen (idempotent). Nur bei `demo_mode=True`."""
        ids = []
        for name in self.DEMO_USERS:
            u = self.store.get_user_by_name(name)
            if u:
                ids.append(str(u["id"]))
                continue
            uid = self.create_user(name, password=self.cfg.demo_password, is_admin=(name == "demoadmin"))
            if self.cfg.pin_enabled:
                self.set_pin(uid, self.cfg.demo_pin)
            ids.append(str(uid))
        self.store.set_setting("demo_users", ",".join(ids))

    def purge_demo(self) -> int:
        """Die von `seed_demo` angelegten Konten wieder entfernen — genau die, keine gleichnamigen."""
        raw = self.store.get_setting("demo_users") or ""
        n = 0
        for sid in filter(None, raw.split(",")):
            u = self.store.get_user(int(sid))
            if u and u["username"] in self.DEMO_USERS:
                self.store.delete_user_sessions(u["id"])
                self.store.delete_user(u["id"])
                n += 1
        self.store.set_setting("demo_users", "")
        return n

    @staticmethod
    def _als_dict(zeile) -> Optional[dict]:
        """Eine Datenbankzeile als das zurückgeben, was die Signatur verspricht.

        Die nutzerseitigen Methoden sind seit jeher `-> Optional[dict]` annotiert und lieferten
        eine `sqlite3.Row`. Das Paket trägt `Typing :: Typed` und eine `py.typed` — die Zusage
        wurde nur nie gemessen. Praktisch fällt es auf, sobald jemand der Annotation glaubt:
        `u.get("email")` gibt es auf einer Row nicht, und der `AttributeError` kommt aus einer
        Zeile, die laut Typ nicht falsch sein kann. Auf der Store-Ebene bleibt die Row — dort
        ist sie dokumentiert und gewollt.
        """
        return dict(zeile) if zeile is not None else None

    def get_user(self, user_id) -> Optional[dict]:
        """Ein Konto per ID lesen, oder None."""
        return self._als_dict(self.store.get_user(user_id))

    # ---------- Passwort-Login ----------
    def find_user(self, identifier) -> Optional[dict]:
        """Konto zur Login-Kennung suchen — je nach `config.login_identifier`.

        "username" = nur Benutzername, "email" = nur E-Mail, "both" = beides im selben Feld.
        Bei "both" entscheidet das @ die Reihenfolge; gefunden wird trotzdem beides, damit ein
        Benutzername mit @ nicht plötzlich unauffindbar ist."""
        ident = (identifier or "").strip()
        if not ident:
            return None
        mode = getattr(self.cfg, "login_identifier", "both")
        if mode == "username":
            gefunden = self.store.get_user_by_name(ident)
        elif mode == "email":
            gefunden = self.store.get_user_by_email(ident)
        elif "@" in ident:
            gefunden = self.store.get_user_by_email(ident) or self.store.get_user_by_name(ident)
        else:
            gefunden = self.store.get_user_by_name(ident) or self.store.get_user_by_email(ident)
        return self._als_dict(gefunden)

    def check_password(self, username, password) -> Optional[dict]:
        """Benutzername/E-Mail + Passwort prüfen. Gibt das Konto zurück oder None — und braucht bei beiden Ausgängen gleich lange (keine Konto-Erkundung)."""
        u = self.find_user(username)
        if not u or u["disabled"]:
            dummy_verify(password)   # Timing angleichen (keine User-Enumeration)
            return None
        h = self.store.get_password_hash(u["id"])
        if not h:
            dummy_verify(password)
            return None
        if not verify_password(password, h):
            return None
        if needs_rehash(h):
            self.store.set_password_hash(u["id"], hash_password(password))
        return u

    # ---------- LDAP / lldap (Passwort-Backend) ----------
    def check_ldap(self, username, password) -> Optional[dict]:
        """Passwort gegen LDAP prüfen. Bei Erfolg lokalen User finden/anlegen und zurückgeben.
        Zählt wie ein Passwort-Login (Faktor 'password')."""
        if not self.ldap:
            return None
        info = self.ldap.authenticate(username, password)
        if not info:
            return None
        # Gruppen-Gate (Teilstring-Match gegen memberOf/Gruppen-Werte)
        allowed = self.cfg.ldap_allowed_groups
        if allowed:
            groups = info.get("groups") or []
            if not any(a and any(a in str(g) for g in groups) for a in allowed):
                return None
        u = self.store.get_user_by_name(username)
        if not u:
            if not self.cfg.ldap_auto_create:
                return None
            uid = self.create_user(username, display_name=info.get("name") or username, email=info.get("email"))
            u = self.store.get_user(uid)
            if u is None:                      # gerade angelegt — kann nur bei einem Defekt fehlen
                return None
        elif u["disabled"]:
            return None
        self.apply_idp_groups(u["id"], info.get("groups"), self.cfg.ldap_group_role_map,
                              substring=True)   # memberOf liefert ganze DNs
        return self._als_dict(self.store.get_user(u["id"]))   # frisch (gemappte Rollen)

    # ---------- SAML (Attribute → lokaler User) ----------
    def check_saml(self, nameid, attrs) -> Optional[dict]:
        """Aus einer geprüften SAML-Assertion einen lokalen User finden/anlegen. Faktor 'saml'."""
        from .saml_ import first, as_list
        cfg = self.cfg
        username = first(attrs, cfg.saml_attr_username) if cfg.saml_attr_username else None
        username = (username or nameid or "").strip()
        if not username:
            return None
        if cfg.saml_allowed_groups:
            groups = as_list(attrs, cfg.saml_attr_groups)
            if not (set(cfg.saml_allowed_groups) & set(str(g) for g in groups)):
                return None
        u = self.store.get_user_by_name(username)
        if not u:
            if not cfg.saml_auto_create:
                return None
            uid = self.create_user(username, display_name=first(attrs, cfg.saml_attr_name) or username,
                                   email=first(attrs, cfg.saml_attr_email))
            u = self.store.get_user(uid)
            if u is None:                      # gerade angelegt — kann nur bei einem Defekt fehlen
                return None
        elif u["disabled"]:
            return None
        self.apply_idp_groups(u["id"], as_list(attrs, cfg.saml_attr_groups), cfg.saml_group_role_map)
        return self._als_dict(self.store.get_user(u["id"]))   # frisch (gemappte Rollen)

    # ---------- PIN-Login (persönliche PIN pro User) ----------
    def set_pin(self, user_id, pin):
        """PIN setzen/ändern. Mindestlänge aus cfg.pin_min_length."""
        pin = str(pin or "")
        if len(pin) < self.cfg.pin_min_length:
            raise ConfigError(f"PIN zu kurz (min. {self.cfg.pin_min_length})")
        self.store.set_pin_hash(user_id, hash_password(pin))

    def has_pin(self, user_id) -> bool:
        """Hat dieses Konto eine PIN eingerichtet?"""
        return self.store.has_pin(user_id)

    def disable_pin(self, user_id):
        """Die PIN eines Kontos entfernen (wird protokolliert — ein zweiter Faktor verschwindet nicht unbemerkt)."""
        self.store.delete_pin(user_id)
        self.audit("pin_disable", detail=f"user={user_id}")

    def check_pin(self, username, pin) -> Optional[dict]:
        """Wie `check_password`, nur mit der persönlichen PIN."""
        u = self.find_user(username)
        if not u or u["disabled"]:
            dummy_verify(str(pin or ""))
            return None
        h = self.store.get_pin_hash(u["id"])
        if not h:
            dummy_verify(str(pin or ""))
            return None
        if not verify_password(str(pin or ""), h):
            return None
        if needs_rehash(h):
            self.store.set_pin_hash(u["id"], hash_password(str(pin)))
        return u

    # Faktoren gegen eine bekannte Identität prüfen (Step-up: der User steht schon fest).
    def verify_user_password(self, user_id, password) -> bool:
        """Das Passwort eines BEKANNTEN Kontos prüfen (Step-up: die Identität steht schon fest)."""
        h = self.store.get_password_hash(user_id)
        if not h:
            dummy_verify(password or "")
            return False
        if not verify_password(password or "", h):
            return False
        if needs_rehash(h):
            self.store.set_password_hash(user_id, hash_password(password))
        return True

    def verify_user_pin(self, user_id, pin) -> bool:
        """Wie `verify_user_password`, nur mit der PIN."""
        h = self.store.get_pin_hash(user_id)
        if not h:
            dummy_verify(str(pin or ""))
            return False
        if not verify_password(str(pin or ""), h):
            return False
        if needs_rehash(h):
            self.store.set_pin_hash(user_id, hash_password(str(pin)))
        return True

    def stepup_options(self, user) -> list[str]:
        """Womit kann DIESER User eine Step-up-Bestätigung leisten? Reihenfolge = Vorschlag.

        `config.stepup_methods` schränkt ein (z.B. `["pin"]`). Hat der User keine der gewünschten
        Methoden eingerichtet, fällt es auf seine verfügbaren zurück — sonst wäre der Bereich
        für ihn unerreichbar, ohne dass er etwas dagegen tun könnte."""
        cfg = self.cfg
        avail = []
        if cfg.totp_enabled and self.store.has_confirmed_totp(user["id"]):
            avail.append("totp")
        if cfg.pin_enabled and self.store.has_pin(user["id"]):
            avail.append("pin")
        if cfg.password_enabled and self.store.get_password_hash(user["id"]):
            avail.append("password")
        wanted = [m for m in (cfg.stepup_methods or []) if m in avail]
        return wanted or avail

    def is_pin_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für PIN (kurzer Keyspace). Zusätzlich zu is_locked()."""
        since = int(time.time()) - self.sec("lockout_window_sec")
        limit = self.sec("pin_max_attempts")
        if username and self.store.count_fails(since, username=username, method="pin") >= limit:
            return True
        if ip and self.store.count_fails(since, ip=ip, method="pin") >= limit * self.sec("ip_attempt_factor"):
            return True
        return False

    # ---------- MFA (TOTP) ----------
    def mfa_pending(self, user_id) -> bool:
        """TOTP verlangt? Ja wenn confirmed-TOTP existiert (oder global erzwungen + eingerichtet)."""
        return self.store.has_confirmed_totp(user_id)

    def verify_totp(self, user_id, code) -> bool:
        """Einen TOTP-Code gegen das Geheimnis dieses Kontos prüfen."""
        t = self.store.get_totp(user_id)
        return bool(t and t["confirmed"] and _totp.verify(t["secret"], code))

    def totp_begin(self, user_id):
        """Die Einrichtung starten: liefert Geheimnis und die `otpauth://`-Adresse für den Authenticator."""
        secret = _totp.new_secret()
        self.store.set_totp(user_id, secret, confirmed=False)
        u = self.store.get_user(user_id)
        uri = _totp.provisioning_uri(secret, u["username"], self.cfg.rp_name)
        return {"secret": secret, "uri": uri, "qr": _totp.qr_data_uri(uri)}

    def totp_confirm(self, user_id, code) -> bool:
        """Die Einrichtung abschliessen — erst mit einem gültigen Code ist TOTP wirklich an."""
        t = self.store.get_totp(user_id)
        if t and _totp.verify(t["secret"], code):
            self.store.confirm_totp(user_id)
            return True
        return False

    def totp_disable(self, user_id):
        """TOTP entfernen, samt der Recovery-Codes (beides wird protokolliert)."""
        offen = self.store.count_recovery_codes(user_id)   # vor dem Löschen zählen
        self.store.delete_totp(user_id)
        self.store.delete_recovery_codes(user_id)   # ohne TOTP sind Recovery-Codes gegenstandslos
        # Das Abschalten eines zweiten Faktors ist das, was ein Angreifer als Erstes tut, wenn er
        # eine Sitzung hat. Ohne Eintrag ist es hinterher nicht nachvollziehbar — bis 2026-09-21
        # hinterliess es keine Spur, obwohl dabei TOTP UND alle Recovery-Codes fallen.
        self.audit("totp_disable", detail=f"user={user_id} recovery_codes_geloescht={offen}")

    # ---------- Recovery-Codes (2FA-Ersatz bei verlorenem Authenticator) ----------
    #: Zufallsbytes je Hälfte eines Recovery-Codes. Zwei Hälften à 4 Byte = **64 Bit**.
    #: Vorher waren es 3 Byte (48 Bit). Das ist für einen Code, der den zweiten Faktor ERSETZT
    #: und unbegrenzt gültig bleibt, zu knapp: Ein TOTP-Code hat zwar nur eine Million
    #: Möglichkeiten, gilt aber 30 Sekunden — ein Recovery-Code gilt, bis er benutzt wird.
    #: Bestehende Codes bleiben gültig (gespeichert wird ohnehin nur der Hash); neu erzeugte
    #: sind länger.
    RECOVERY_BYTES = 4

    def generate_recovery_codes(self, user_id, n=None) -> list:
        """Neue Einmal-Codes erzeugen (ersetzt vorhandene). Klartext-Rückgabe NUR EINMAL."""
        n = int(n or self.cfg.recovery_code_count)
        codes = ["-".join(secrets.token_hex(self.RECOVERY_BYTES) for _ in range(2)) for _ in range(n)]
        self.store.delete_recovery_codes(user_id)
        self.store.add_recovery_codes(user_id, [self._rc_hash(c) for c in codes])
        self.audit("recovery_generate", detail=f"user={user_id} n={n}")
        return codes

    @staticmethod
    def _rc_hash(code) -> str:
        norm = str(code or "").strip().lower().replace(" ", "")
        return hashlib.sha256(norm.encode()).hexdigest()

    def verify_recovery_code(self, user_id, code) -> bool:
        """Einen Einmal-Code prüfen und verbrauchen. Ein Code gilt genau einmal."""
        if not code:
            return False
        return self.store.consume_recovery_code(user_id, self._rc_hash(code))

    def recovery_codes_remaining(self, user_id) -> int:
        """Wie viele Einmal-Codes dieses Konto noch hat."""
        return self.store.count_recovery_codes(user_id)

    # ---------- Passwort-Reset (Forgot-Password) ----------
    def send_password_reset(self, email, base_url) -> bool:
        """Reset-Link an eine E-Mail schicken, WENN ein passender User existiert. Nach außen immer
        gleiche Meldung (keine Enumeration)."""
        u = self.store.get_user_by_email(email)
        if not u or u["disabled"] or u["is_service"]:
            return False
        raw = self.create_magic_token("reset_password", user_id=u["id"], email=email)
        url = self.magic_url(raw, base_url, "reset_password")
        mins = self.cfg.magiclink_ttl_min
        self.send_mail(email, "Passwort zurücksetzen",
                       f"Zum Zurücksetzen deines Passworts diesen Link öffnen (gültig {mins} Minuten):\n\n{url}\n\n"
                       f"Wenn du das nicht angefordert hast, ignoriere diese E-Mail.",
                       html=f'<p>Passwort zurücksetzen (gültig {mins} Minuten):</p><p><a href="{url}">Neues Passwort setzen</a></p>')
        return True

    # ---------- Faktor-Ketten-Engine ----------
    IDENTIFYING = ("password", "pin", "oidc", "passkey", "magic", "saml")  # Faktoren, die den User identifizieren

    def _global_chain(self):
        """(factors, strict) der globalen Standard-Kette, oder (None, True) für klassischen Modus."""
        return (list(self.cfg.login_chain), self.cfg.login_chain_strict) if self.cfg.login_chain else (None, True)

    def _chain_satisfied(self, required, strict, done) -> bool:
        if strict:
            pos = [done.index(f) for f in required if f in done]
            return len(pos) == len(required) and pos == sorted(pos)   # alle da UND in Reihenfolge
        return all(f in done for f in required)

    def _next_factor(self, required, strict, done):
        for f in required:
            if f not in done:
                return f
        return None

    def _default_satisfied(self, user_id, done) -> bool:
        """Klassische Policy (keine login_chain): ein Identifikationsfaktor + TOTP, falls eingerichtet."""
        if not any(f in done for f in self.IDENTIFYING):
            return False
        if "passkey" in done:
            return True   # Passkey allein = vollwertig
        if self.store.has_confirmed_totp(user_id) and "totp" not in done:
            return False
        return True

    def _session_ok(self, user_id, done) -> bool:
        """Erfüllt die Faktorliste die AKTIVE globale Policy (Kette oder klassisch)?"""
        req, strict = self._global_chain()
        if req is not None:
            return self._chain_satisfied(req, strict, done)
        return self._default_satisfied(user_id, done)

    def next_login_step(self, user_id, done):
        """Nächster offener Faktor bis zur vollen (globalen) Anmeldung, oder None wenn fertig."""
        req, strict = self._global_chain()
        if req is not None:
            return None if self._chain_satisfied(req, strict, done) else self._next_factor(req, strict, done)
        return None if self._default_satisfied(user_id, done) else "totp"

    def factor_entry(self, step, nxt="/") -> str:
        """Die Adresse der Eingabeseite für einen Faktor-Schritt, mit `next` daran."""
        from urllib.parse import quote
        base = {"password": self.cfg.login_path, "pin": "/auth/pin", "oidc": "/auth/oidc/start",
                "passkey": self.cfg.login_path, "totp": "/auth/totp",
                "magic": "/auth/magic/request", "saml": "/auth/saml/login"}.get(step, self.cfg.login_path)
        return f"{base}?next={quote(nxt or '/', safe='/')}"

    async def json_body(self, request: Request) -> dict:
        """JSON-Body robust lesen: ungültiger/leerer Body → 400 statt 500. Erzwingt CSRF
        (Header X-CSRF-Token) für cookie-basierte Clients; API-Key-Requests sind ausgenommen."""
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, self.t("api.json_invalid"))
        if not isinstance(data, dict):
            raise HTTPException(400, self.t("api.json_object"))
        if self.cfg.csrf_enabled and not self._extract_api_key(request):
            token = request.headers.get("x-csrf-token") or data.get("_csrf")
            if not self.verify_csrf(request, token):
                raise HTTPException(403, self.t("api.csrf"))
        return data

    # ---------- CSRF (Double-Submit) ----------
    def issue_csrf(self, response: Response) -> str:
        """CSRF-Token erzeugen und als Cookie setzen — für eigene Templates (Jinja & Co.), die nicht
        über `render_page()` laufen. Rückgabe gehört ins Formularfeld `_csrf` bzw. den Header
        `X-CSRF-Token`. Ist CSRF abgeschaltet, passiert nichts und der Rückgabewert ist leer."""
        if not self.cfg.csrf_enabled:
            return ""
        token = secrets.token_urlsafe(24)
        response.set_cookie(self.cfg.csrf_cookie, token, secure=self.cfg.cookie_secure,
                            samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)
        return token

    def verify_csrf(self, request: Request, submitted) -> bool:
        """Passt das mitgeschickte CSRF-Token zum Cookie? Vergleich in konstanter Zeit."""
        if not self.cfg.csrf_enabled:
            return True
        import hmac
        cookie = request.cookies.get(self.cfg.csrf_cookie)
        return bool(cookie) and bool(submitted) and hmac.compare_digest(str(cookie), str(submitted))

    def require_csrf(self, request: Request, submitted):
        """Für Formular-POSTs: wirft 403, wenn der CSRF-Token fehlt/nicht passt (API-Key ausgenommen)."""
        if self.cfg.csrf_enabled and not self._extract_api_key(request) and not self.verify_csrf(request, submitted):
            raise HTTPException(403, self.t("api.csrf"))

    # ---------- E-Mail-Versand ----------
    def set_mailer(self, fn):
        """Eigenen Mail-Versand einhängen: fn(to, subject, text, html=None). Überschreibt SMTP."""
        self._mailer_override = fn

    def mail_configured(self) -> bool:
        """Kann überhaupt eine Mail hinausgehen — per SMTP oder per `set_mailer`?"""
        return bool(self._mailer_override or self.cfg.smtp_host)

    def send_mail(self, to, subject, text, html=None):
        """Eine Mail versenden — über SMTP oder den per `set_mailer` gesetzten Weg."""
        from .mailer import SMTPMailer
        fn = self._mailer_override or SMTPMailer(self.cfg)
        fn(to, subject, text, html)

    # ---------- Magic-/Einmal-Token ----------
    def create_magic_token(self, purpose, user_id=None, email=None, ttl_min=None, payload=None) -> str:
        """Einmal-Token erzeugen (Klartext-Rückgabe). Nur der sha256-Hash liegt in der DB."""
        raw = secrets.token_urlsafe(32)
        h = hashlib.sha256(raw.encode()).hexdigest()
        ttl = int(ttl_min if ttl_min is not None else self.cfg.magiclink_ttl_min) * 60
        self.store.add_magic_token(h, purpose, int(time.time()) + ttl, user_id, email, payload)
        return raw

    #: Wo ein Token eingelöst wird — je Zweck ein eigener Endpunkt. Bis 0.15 liefen alle vier
    #: über /auth/magic/{token}: wer den Magic-Link abschaltete, verlor damit auch E-Mail-
    #: Bestätigung und Einladung, die damit nichts zu tun haben.
    TOKEN_PATHS = {
        "login": "/auth/magic/{t}",
        "verify_email": "/auth/verify/{t}",
        "invite": "/auth/invite/{t}",
        "reset_password": "/auth/reset?token={t}",
    }

    def magic_url(self, raw, base_url, purpose="login") -> str:
        """Der Link, den der Empfänger anklickt — Pfad je nach Zweck (`TOKEN_PATHS`)."""
        from urllib.parse import quote
        pfad = self.TOKEN_PATHS[purpose].format(t=quote(str(raw), safe=""))
        return f"{str(base_url).rstrip('/')}{pfad}"

    def redeem_magic(self, raw, purpose=None) -> Optional[dict]:
        """Token einlösen (one-shot). Gibt {purpose,user_id,email,payload} oder None (ungültig/abgelaufen/benutzt)."""
        if not raw:
            return None
        h = hashlib.sha256(raw.encode()).hexdigest()
        row = self.store.get_magic_token(h)
        if not row or (purpose and row["purpose"] != purpose):
            return None
        if not self.store.use_magic_token(h):
            return None
        return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
                "payload": json.loads(row["payload"]) if row["payload"] else None}

    def peek_magic(self, raw, purpose=None) -> Optional[dict]:
        """Token prüfen OHNE ihn zu verbrauchen (für den Invite-Flow: erst bei Registrierung einlösen)."""
        if not raw:
            return None
        row = self.store.get_magic_token(hashlib.sha256(raw.encode()).hexdigest())
        if not row or row["used_at"] or row["expires_at"] < int(time.time()):
            return None
        if purpose and row["purpose"] != purpose:
            return None
        return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
                "payload": json.loads(row["payload"]) if row["payload"] else None}

    def create_invite(self, email, base_url, roles=None, is_admin=False, ttl_min=None) -> dict:
        """Einladung erzeugen (+ optional versenden). Rückgabe {url, token}. Der Token trägt die
        vorgesehenen Rollen/Adminrechte; eingelöst wird er erst bei der Registrierung."""
        raw = self.create_magic_token("invite", email=email, ttl_min=ttl_min,
                                      payload={"roles": list(roles or []), "is_admin": bool(is_admin)})
        url = self.magic_url(raw, base_url, "invite")
        if email and self.mail_configured():
            self.send_mail(email, "Deine Einladung",
                           f"Du wurdest eingeladen, ein Konto anzulegen:\n\n{url}\n",
                           html=f'<p>Du wurdest eingeladen, ein Konto anzulegen:</p><p><a href="{url}">Konto erstellen</a></p>')
        self.audit("invite_create", detail=email)
        return {"url": url, "token": raw}

    def send_verify_email(self, user_id, email, base_url) -> bool:
        """Den Bestätigungslink für eine Adresse verschicken. False, wenn kein Mailer da ist."""
        if not (email and self.mail_configured()):
            return False
        raw = self.create_magic_token("verify_email", user_id=user_id, email=email)
        url = self.magic_url(raw, base_url, "verify_email")
        self.send_mail(email, "E-Mail bestätigen",
                       f"Bitte bestätige deine E-Mail-Adresse:\n\n{url}\n",
                       html=f'<p>Bitte bestätige deine E-Mail-Adresse:</p><p><a href="{url}">Bestätigen</a></p>')
        return True

    def send_login_link(self, email, base_url, next="/") -> bool:
        """Login-Link an eine E-Mail schicken, WENN ein passender interaktiver User existiert.
        Rückgabe nur intern — nach außen immer dieselbe Meldung (keine User-Enumeration)."""
        u = self.store.get_user_by_email(email)
        if not u or u["disabled"] or u["is_service"]:
            return False
        raw = self.create_magic_token("login", user_id=u["id"], email=email, payload={"next": next})
        url = self.magic_url(raw, base_url)
        mins = self.cfg.magiclink_ttl_min
        self.send_mail(email, "Dein Anmelde-Link",
                       f"Zum Anmelden diesen Link öffnen (gültig {mins} Minuten):\n\n{url}\n\n"
                       f"Wenn du das nicht angefordert hast, ignoriere diese E-Mail.",
                       html=f'<p>Zum Anmelden diesen Link öffnen (gültig {mins} Minuten):</p>'
                            f'<p><a href="{url}">Jetzt anmelden</a></p>'
                            f'<p style="color:#888">Wenn du das nicht angefordert hast, ignoriere diese E-Mail.</p>')
        return True

    # ---------- Sessions ----------
    def _ttl(self, remember: bool = True) -> int:
        """Server-Session-Lebensdauer. remember=False → kurze Transient-TTL (Session-Cookie)."""
        hours = self.cfg.session_ttl_hours if remember else self.cfg.session_ttl_transient_hours
        return hours * 3600

    def start_session(self, user_id, method, ip=None, ua=None, remember: bool = True) -> tuple[str, bool]:
        """Neue Session mit dem ersten Faktor. Gibt (token, session_ok). session_ok=False → weitere Schritte nötig."""
        done = [method]
        mfa_ok = self._session_ok(user_id, done)
        token = self.store.create_session(user_id, self._ttl(remember), mfa_ok, method, ip, ua, remember, factors=done)
        if mfa_ok:   # voller Login abgeschlossen → Audit
            u = self.store.get_user(user_id)
            self.store.audit_log("login", u["username"] if u else None, ip, method)
        return token, mfa_ok

    def apply_factor(self, request, user_id, factor, ip=None, ua=None, remember=True) -> tuple[str, bool, bool]:
        """Einen bestätigten Faktor anwenden: an die laufende Sitzung desselben Users anhängen
        (Ketten-Schritt) ODER eine neue Sitzung starten (Erstfaktor/Identitätswechsel).
        Gibt (token, session_ok, is_new). Bei is_new muss der Aufrufer set_cookie(resp, token) rufen."""
        s = self.session_from_request(request)
        if s and s["user_id"] == user_id:
            # gleiche Identität → Faktor an laufende Sitzung anhängen (Ketten-/Route-Schritt).
            # Ein Identitätswechsel (anderer User) fällt durch → neue Sitzung.
            done = json.loads(s["factors_done"] or "[]")
            was_ok = bool(s["mfa_ok"])
            if factor not in done:
                done.append(factor)
            ok = self._session_ok(user_id, done)
            self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
            self.maybe_promote_admin(self.store.get_user(user_id))
            if ok and not was_ok:
                u = self.store.get_user(user_id)
                self.store.audit_log("login", u["username"] if u else None, s["ip"], factor)
            # Zurück geht das Klartext-Token aus dem Cookie — der Aufrufer baut daraus
            # Redirects und Cookies. In der Sitzungs-Zeile steht nur noch das Handle.
            return request.cookies.get(self.cfg.session_cookie), ok, False
        token, ok = self.start_session(user_id, factor, ip, ua, remember)
        self.maybe_promote_admin(self.store.get_user(user_id))
        return token, ok, True

    def login_redirect_after(self, request, token, user_id, nxt):
        """Zielredirect nach einem Faktor: nxt wenn Sitzung komplett, sonst Eingabeseite des nächsten Faktors."""
        s = self.store.get_session(token)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if s and s["mfa_ok"]:
            return nxt
        step = self.next_login_step(user_id, done)
        return self.factor_entry(step, nxt) if step else nxt

    def complete_totp(self, token):
        """Den TOTP-Schritt abschließen: Faktor `totp` an die laufende Sitzung anhängen.

        Heißt seit 0.18.0 so, weil der alte Name `complete_mfa` mehr versprach, als die Methode
        tut — MFA ist die ganze Kette, hier geht es um genau einen Faktor. `complete_mfa` bleibt
        als Alias bestehen und wird nicht entfernt; ein Umbenennen, das bestehende Aufrufe
        bricht, wäre den Gewinn nicht wert.
        """
        s = self.store.get_session(token)
        if not s:
            return
        done = json.loads(s["factors_done"] or "[]")
        if "totp" not in done:
            done.append("totp")
        ok = self._session_ok(s["user_id"], done)
        self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
        if ok:
            u = self.store.get_user(s["user_id"])
            self.store.audit_log("login", u["username"] if u else None, s["ip"], "totp")

    def complete_mfa(self, token):
        """Historischer Name für `complete_totp()` — bleibt erhalten, damit nichts bricht."""
        return self.complete_totp(token)

    def session_from_request(self, request):
        """Die Sitzungszeile zu diesem Request, oder None. `row["token_hash"]` ist ihr Handle."""
        return self.store.get_session(request.cookies.get(self.cfg.session_cookie))

    def current_user(self, request) -> Optional[dict]:
        """Das angemeldete Konto zu diesem Request — aus der Sitzung ODER einem API-Key. None, wenn niemand angemeldet ist."""
        # 1) Session (Mensch, inkl. MFA)
        s = self.session_from_request(request)
        if s and s["mfa_ok"]:
            u = self.store.get_user(s["user_id"])
            if u and not u["disabled"]:
                d = dict(u)
                d["_via"] = "session"
                return d
        # 2) API-Key (maschinell / Daemon) — der Key IST der Faktor, kein MFA
        if self.cfg.apikey_enabled:
            key = self._extract_api_key(request)
            if key:
                u, key_roles = self.verify_api_key(key)
                if u:
                    d = dict(u)
                    d["_via"] = "apikey"
                    if key_roles is not None:
                        # SCHNITTMENGE, nicht Überschreibung: Der Scope verengt, er erweitert nie.
                        # Zweite Schicht neben der Begrenzung in create_api_key — sie greift auch
                        # für Keys, die vor dem Fix angelegt wurden oder direkt in der Datenbank
                        # stehen. `is_admin` bleibt unberührt, das kommt aus der Nutzerzeile.
                        d["roles"] = json.dumps(sorted(set(key_roles) & set(self.user_roles(u))))
                    return d
        return None

    def pending_user(self, request) -> Optional[dict]:
        """User einer Session, die noch im MFA-Schritt hängt (mfa_ok=0)."""
        s = self.session_from_request(request)
        if not s or s["mfa_ok"]:
            return None
        return self._als_dict(self.store.get_user(s["user_id"]))

    def set_cookie(self, response, token, remember: bool = True):
        """Session-Cookie setzen. remember=True → persistentes Cookie (max_age = lange TTL);
        remember=False → reines Session-Cookie (max_age=None, endet beim Browser-Schließen)."""
        kw = dict(httponly=True, secure=self.cfg.cookie_secure,
                  samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        if remember:
            kw["max_age"] = self._ttl(True)   # type: ignore[assignment]  # kw trägt gemischte Typen
        response.set_cookie(self.cfg.session_cookie, token, **kw)

    def logout(self, request, response):
        """Die Sitzung dieses Requests beenden und das Cookie löschen."""
        s = self.session_from_request(request)
        if s:
            self.store.delete_session_by_handle(s["token_hash"])
        kw = dict(path=self.cfg.cookie_path)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.delete_cookie(self.cfg.session_cookie, **kw)

    # ---------- Härtung (Regulation / Rate-Limit / Audit) ----------
    def client_ip(self, request: Request) -> str:
        """Die echte Client-IP. Hinter einem Proxy nur dann aus `X-Forwarded-For`, wenn der Peer in `trusted_proxies` steht — sonst wäre der Header fälschbar."""
        return security.client_ip(request, self.cfg.trusted_proxies)

    def sec(self, key) -> int:
        """Härtungs-Wert: Store-Setting (Panel) ODER Default."""
        v = self.store.get_setting(key)
        try:
            return int(v) if v is not None else security.SECURITY_DEFAULTS[key]
        except Exception:
            return security.SECURITY_DEFAULTS[key]

    def all_security(self) -> dict:
        """Alle Härtungs-Schwellen als Dict (Vorgaben, überschrieben von dem, was im Panel steht)."""
        return {k: self.sec(k) for k in security.SECURITY_DEFAULTS}

    def set_security(self, key, value):
        """Eine Härtungs-Schwelle zur Laufzeit setzen; sie überlebt den Neustart in der Datenbank."""
        if key in security.SECURITY_DEFAULTS:
            self.store.set_setting(key, int(value))

    def set_rate_limiter(self, limiter):
        """Eigenes Rate-Limit-Backend einhängen — beliebiges Objekt mit allow(key, max, window)->bool."""
        self.rl = limiter

    # Abgewiesen wird an elf Stellen im Router; gemeldet wird HIER, in der Prüfung selbst.
    # Grund: Solange der App-Lockout griff, rief niemand mehr `record_login()` — die App
    # antwortete 429 und schrieb keine Zeile. Damit verstummte das Sicherheits-Log genau in dem
    # Moment, in dem fail2ban die IP hätte bannen sollen: Der App-Lockout blendete den Wächter
    # aus, der ihn ablösen soll. Die elf Aufrufstellen einzeln zu flicken hiesse, dass die
    # nächste neue Route wieder stumm ist.
    #
    # Das Format ist bewusst dasselbe wie bei einem echten Fehlversuch — der mitgelieferte
    # fail2ban-Filter (`failed login user=… ip=<HOST> method=.*`) greift dadurch sofort, auch
    # in Installationen, die ihre Filterdatei nie anfassen. `reason=` sagt, warum.
    def _abgewiesen(self, username, ip, grund: str):
        security.seclog.warning("failed login user=%s ip=%s method=blocked reason=%s",
                                username or "-", ip, grund)

    def rate_ok(self, ip) -> bool:
        """Darf diese IP noch? Ein Nein schreibt eine Zeile ins Sicherheits-Log (fail2ban liest mit)."""
        erlaubt = self.rl.allow(ip or "?", self.sec("rate_limit_max"), self.sec("rate_limit_window_sec"))
        if not erlaubt:
            self._abgewiesen(None, ip, "ratelimit")
        return erlaubt

    def is_locked(self, username, ip) -> bool:
        """Zu viele Fehlversuche im Fenster — pro User ODER pro IP (IP-Schwelle höher wg. NAT)."""
        since = int(time.time()) - self.sec("lockout_window_sec")
        if username and self.store.count_fails(since, username=username) >= self.sec("max_login_attempts"):
            self._abgewiesen(username, ip, "lockout_user")
            return True
        if ip and self.store.count_fails(since, ip=ip) >= self.sec("max_login_attempts") * self.sec("ip_attempt_factor"):
            self._abgewiesen(username, ip, "lockout_ip")
            return True
        return False

    def record_login(self, username, ip, success, method):
        """Einen Anmeldeversuch verbuchen. Ein Erfolg räumt nur die Fehlversuche DERSELBEN Methode weg."""
        self.store.record_attempt(username, ip, success, method)
        if success:
            # NUR die Fehlversuche derselben Methode: Ein Passwort-Erfolg sagt nichts darueber,
            # ob jemand gerade TOTP-Codes durchprobiert. Vorher raeumte er sie mit weg und machte
            # den zweiten Faktor ratbar.
            self.store.clear_fails(username=username, method=method)   # 'login'-Audit erst beim vollen Abschluss
        else:
            self.store.audit_log("login_fail", username, ip, method)
            # fail2ban parst diese Zeile (ip=…)
            security.seclog.warning("failed login user=%s ip=%s method=%s", username, ip, method)

    def audit(self, event, username=None, ip=None, detail=None):
        """Einen Vorgang ins Audit-Log schreiben. `detail` nimmt alles, was später die Frage „warum" beantwortet."""
        self.store.audit_log(event, username, ip, detail)

    def gc(self, attempts_older_than_sec: int = 86400) -> dict:
        """Aufräumen: abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte
        Login-Versuche. Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen.
        Das Audit-Log bleibt (bewusst) unangetastet. Gibt Anzahl gelöschter Zeilen je Bereich."""
        older = int(time.time()) - int(attempts_older_than_sec)
        return {
            "sessions": self.store.gc_sessions(),
            "flow": self.store.gc_flow(),
            "magic_tokens": self.store.gc_magic_tokens(),
            "resource_unlocks": self.store.gc_resource_unlocks(),
            "login_attempts": self.store.gc_attempts(older),
        }

    def version(self) -> str:
        """Die laufende Version — fürs Panel. TinySesam aktualisiert sich nicht selbst;
        das erledigt, wer es installiert hat (gepinnter Tag / Wheel eines Releases)."""
        from . import current_version
        return current_version()

    # ---------- Forward-Auth (Reverse-Proxy) ----------
    #: Vorgabe: der Satz, den Authelia/Traefik-Aufbauten erwarten.
    FORWARD_HEADERS_DEFAULT = {"user": "Remote-User", "name": "Remote-Name",
                               "email": "Remote-Email", "groups": "Remote-Groups"}

    def forward_response_headers(self, user) -> dict:
        """Die Header, die der Proxy bei einer erfolgreichen Prüfung an die App weiterreicht.

        `config.forward_headers` ist die **vollständige** Liste, nicht eine Ergänzung: Wer nur
        `{"user": "X-WEBAUTH-USER"}` setzt, verschickt auch nur den einen Header — so ist „ich will
        die E-Mail-Adresse nicht rausgeben" eine Weglassung und kein zweiter Schalter. Ein Feld darf
        auf mehrere Namen zeigen, wenn eine App den einen und ein Zwischenstück den anderen liest.
        """
        werte = {
            "user": str(user["username"] or ""),
            "name": str(user["display_name"] or user["username"] or ""),
            "email": str(user["email"] or ""),
            "groups": ",".join(self.user_roles(user) + (["admin"] if user["is_admin"] else [])),
        }
        out = {}
        for feld, namen in (self.cfg.forward_headers or self.FORWARD_HEADERS_DEFAULT).items():
            for name in ([namen] if isinstance(namen, str) else namen):
                out[name] = self._header_wert(werte[feld])
        return out

    @staticmethod
    def _header_wert(wert: str) -> str:
        """Einen Wert so herrichten, dass er als HTTP-Header durchgeht.

        Bis 0.18.0 ging er roh hinaus, und zwei Dinge brachen daran:

        1. **Zeilenumbrüche.** Ein Anzeigename wie `"Bose\r\nX-Remote-Groups: admin"` — bei OIDC
           oder SAML kommt der Name vom fremden IdP — wäre Header-Injection. `h11` fängt das
           zwar ab, aber mit `LocalProtocolError`: Die Antwort bricht ab, und der Betroffene
           kommt gar nicht mehr durch die Forward-Auth. Aus einer Injection wird so eine
           Selbstsperre mit kryptischer Meldung.
        2. **Namen jenseits von Latin-1.** HTTP-Header sind Latin-1; `"Иван"` oder `"测试"` sind
           nicht kodierbar, und der ASGI-Server antwortet mit 500. Das ist kein Angriff, das ist
           ein Dienstag in einem internationalen Unternehmen — der Nutzer kann die geschützte
           App schlicht nicht benutzen.

        Steuerzeichen fliegen raus. Der Rest geht **immer als UTF-8 über die Leitung** (die Bytes
        werden Latin-1-transparent durchgereicht) — verlustfrei, und die nachgelagerte App liest
        den Header als UTF-8.

        Bewusst *immer*, nicht nur im Notfall: Ein Wechsel je nach Inhalt wäre die schlimmere
        Lösung. „Müller" käme dann als Latin-1 an und „Иван" als UTF-8, und keine App könnte
        wissen, was sie gerade hat. Für reines ASCII — den Normalfall — ändert sich nichts, weil
        ASCII in beiden Kodierungen dieselben Bytes hat.
        """
        sauber = "".join(z for z in str(wert or "") if z >= " " and z != "\x7f")
        return sauber.encode("utf-8").decode("latin-1")

    def forwarded_url(self, request: Request) -> str:
        """Ursprüngliche vom Proxy angefragte URL rekonstruieren (Caddy/Traefik: X-Forwarded-*,
        nginx: X-Original-URL). Fallback: Referer bzw. '/'."""
        h = request.headers
        orig = h.get("x-original-url")           # nginx auth_request
        if orig and "://" in orig:
            return orig
        proto = (h.get("x-forwarded-proto") or "https").split(",")[0].strip()
        host = (h.get("x-forwarded-host") or h.get("host") or "").split(",")[0].strip()
        uri = h.get("x-forwarded-uri") or orig or h.get("x-original-uri") or "/"
        if host:
            return f"{proto}://{host}{uri}"
        return h.get("referer") or "/"

    def forward_login_url(self, orig_url: str, request: Optional[Request] = None) -> str:
        """Zentrale Login-URL (auf base_url bzw. abgeleitet) mit next=<orig_url>.

        Ausnahme gegen eine stille Endlosschleife: **ohne `cookie_domain` gilt das Session-Cookie
        host-only.** Zeigt die Login-URL dann auf einen anderen Host als den angefragten, setzt
        TinySesam das Cookie auf Host A und schickt den Browser nach Host B, wo es nicht
        mitgeschickt wird — der Proxy fragt erneut, es geht wieder zum Login, ohne Fehlermeldung
        und ohne Logzeile. Steht der angefragte Host in `trusted_redirect_hosts`, bauen wir die
        Login-URL deshalb dort: derselbe Host, auf dem das Cookie gilt.

        `base_url` bleibt davon unberührt — OIDC-/SAML-Callbacks brauchen weiter die eine feste
        Adresse, die beim IdP hinterlegt ist. Betroffen ist nur die eigene Login-Seite.
        Der echte Fix für SSO über mehrere Subdomains bleibt `cookie_domain=".example.com"`.
        """
        from urllib.parse import quote, urlsplit
        base = self.cfg.base_url
        if not base and request is not None:
            h = request.headers
            proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
            host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc).split(",")[0].strip()
            base = f"{proto}://{host}"
        if base and not self.cfg.cookie_domain:
            # Host aus orig_url, nicht erneut aus den Headern: forwarded_url() hat X-Original-URL
            # und X-Forwarded-* bereits ausgewertet. Die Whitelist trusted_redirect_hosts ist
            # zugleich der Schutz — ein gefälschter X-Forwarded-Host kann die Login-URL nicht
            # auf einen fremden Host umbiegen.
            o = urlsplit(orig_url or "")
            if (o.scheme in ("http", "https") and o.hostname
                    and o.hostname != (urlsplit(base).hostname or "")
                    and o.hostname in (self.cfg.trusted_redirect_hosts or [])):
                base = f"{o.scheme}://{o.netloc}"
        return f"{str(base).rstrip('/')}{self.cfg.login_path}?next={quote(orig_url or '/', safe='')}"

    # ---------- i18n ----------
    def t(self, key, **fmt) -> str:
        """Übersetzten Text für key in config.lang (Fallback en → key). Platzhalter via {name}."""
        from .messages import translate
        return translate(self.cfg.lang, key, self._messages, **fmt)

    def add_messages(self, lang, mapping: dict):
        """Eigene Übersetzungen ergänzen/überschreiben (haben Vorrang vor den eingebauten)."""
        self._messages.setdefault(lang, {}).update(mapping)

    # ---------- Views / Redirect-Sicherheit ----------
    #: Die Seiten, die sich ersetzen lassen — dieselbe Liste, die `render_page()` bedient.
    #: Der Docstring nannte früher 'magic_sent' und 'resource_pin', die es beide nie gab, und
    #: liess sieben echte weg. Ein Tippfehler blieb dabei folgenlos-still: Die eigene Seite
    #: wurde eingetragen und nie aufgerufen.
    SEITEN = ("account", "error", "forgot", "login", "magic_invalid", "magic_request", "pin",
              "reauth", "register", "reset", "resource_unlock", "totp", "totp_setup")

    def set_template(self, name, fn):
        """Eine eingebaute Seite durch einen eigenen Renderer ersetzen: fn(auth, ctx) -> str | Response.

        Namen: siehe `TinySesam.SEITEN` (je nach aktivierten Features erscheinen nicht alle).
        String → HTML mit Status; Response → 1:1. Ein unbekannter Name ist ein Fehler, kein
        stilles Nichts.
        """
        if name not in self.SEITEN:
            raise ConfigError(f"Unbekannte Seite {name!r} — es gibt: {', '.join(self.SEITEN)}")
        self.templates.set(name, fn)

    def csrf_token(self, request: Optional[Request] = None) -> str:
        """Das CSRF-Token dieses Browsers — vorhandenes Cookie wiederverwenden, sonst neu würfeln."""
        if request is not None and self.cfg.csrf_enabled:
            cur = request.cookies.get(self.cfg.csrf_cookie)
            if cur:
                return cur
        return secrets.token_urlsafe(24)

    def render_page(self, template, status=200, request: Optional[Request] = None, **ctx) -> Response:
        """`request` mitgeben, wo es eins gibt: dann bleibt ein bereits gesetztes CSRF-Token gültig.
        Ohne `request` entsteht ein neues — das überschreibt das Cookie und macht *andere* offene
        Formulare ungültig (klassische „Formular abgelaufen"-Falle)."""
        tok, fresh = None, False
        if self.cfg.csrf_enabled:
            cur = request.cookies.get(self.cfg.csrf_cookie) if request is not None else None
            tok = cur or secrets.token_urlsafe(24)
            fresh = cur is None
            ctx.setdefault("csrf", tok)      # Templates betten <input name=_csrf> ein / JS liest das Cookie
        # Ein Nonce je Antwort. Die eingebauten Seiten kommen ohne Inline-Handler/style= aus;
        # der Nonce wandert zentral in jedes <script>/<style> (kein Faedeln durch die Templates)
        # und in den CSP-Header. Ein Override, das eine Response liefert, bleibt unberuehrt —
        # es setzt seine CSP selbst; ctx['nonce'] steht ihm zur Verfuegung.
        nonce = secrets.token_urlsafe(16)
        ctx.setdefault("nonce", nonce)
        out = self.templates.render(template, self, ctx)
        if isinstance(out, Response):
            resp = out
        else:
            resp = HTMLResponse(_inject_nonce(out, nonce), status_code=status)
            policy = self._csp_header(nonce)
            if policy:
                resp.headers.setdefault("Content-Security-Policy", policy)
        if tok is not None and fresh:
            # NICHT httponly: die eingebauten JS-Aufrufe lesen das Cookie und senden X-CSRF-Token
            resp.set_cookie(self.cfg.csrf_cookie, tok, secure=self.cfg.cookie_secure,
                            samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)
        return resp

    def _csp_header(self, nonce: str) -> str:
        """Die CSP für die eigenen Seiten. 'strict' = alles same-origin, Skript/Style nur per
        Nonce (kein 'unsafe-inline'); 'off' = kein Header; sonst der eigene String mit {nonce}."""
        csp = (self.cfg.csp or "").strip()
        if not csp or csp == "off":
            return ""
        if csp == "strict":
            return ("default-src 'self'; "
                    f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                    "img-src 'self' data:; base-uri 'none'; "
                    "frame-ancestors 'self'; object-src 'none'")
        return csp.replace("{nonce}", nonce)

    def safe_next(self, next_: str) -> str:
        """?next=-Ziel gegen Open-Redirect absichern (nur relative Pfade bzw. trusted_redirect_hosts).

        Der Host der eigenen `base_url` zählt immer mit: ein Redirect auf die eigene öffentliche
        Adresse ist per Definition kein Open Redirect. Sonst müsste man beim Forward-Auth auf
        EINEM Host (App und TinySesam unter demselben Namen) den eigenen Host in
        `trusted_redirect_hosts` wiederholen — vergisst man das, wird das absolute `next=`
        stillschweigend verworfen und man landet nach dem Login auf `login_redirect`.
        """
        hosts = list(self.cfg.trusted_redirect_hosts or [])
        if self.cfg.base_url:
            from urllib.parse import urlsplit
            own = urlsplit(self.cfg.base_url).hostname or ""
            if own and own not in hosts:
                hosts.append(own)
        return security.safe_next(next_, self.cfg.login_redirect, hosts or None)

    # ---------- FastAPI-Integration ----------
    def router(self):
        """Der FastAPI-Router mit allen aktivierten Routen. Einmal einbinden, fertig."""
        from .router import build_router
        return build_router(self)

    def admin_router(self):
        """Eigenständiger Admin-Router (relative Pfade) — an beliebigem Prefix / Sub-App / Port
        montierbar, oder (admin_ui_enabled=False) nur die JSON-API fürs eigene Panel."""
        from .admin import build_admin_router
        return build_admin_router(self)

    def is_secure(self, request: Request) -> bool:
        """HTTPS aktiv? (direkt, via X-Forwarded-Proto hinter Proxy, oder localhost)."""
        if request.url.scheme == "https":
            return True
        if request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https":
            return True
        host = request.client.host if request.client else ""
        return host in ("127.0.0.1", "::1", "localhost")

    def install_error_pages(self, app):
        """Themed Fehlerseiten registrieren (opt-in). Browser bekommen die 'error'-Seite (im Branding),
        API-Clients JSON; Redirects (Login/Reauth/Faktor, via Location-Header) bleiben Redirects."""
        from starlette.exceptions import HTTPException as _HTTPExc
        from starlette.responses import RedirectResponse, JSONResponse

        def _wants_html(request):
            return "text/html" in request.headers.get("accept", "")

        @app.exception_handler(_HTTPExc)
        async def _handle_http(request, exc):
            headers = exc.headers or {}
            loc = headers.get("Location") or headers.get("location")
            if loc:   # unser _deny/_deny_stepup/_redirect_factor → Redirect unverändert durchreichen
                return RedirectResponse(loc, status_code=exc.status_code, headers=headers)
            if _wants_html(request):
                return self.render_page("error", status=exc.status_code, request=request,
                                       code=exc.status_code, message=exc.detail)
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=headers or None)

        @app.exception_handler(Exception)
        async def _handle_500(request, exc):
            if _wants_html(request):
                return self.render_page("error", status=500, request=request, code=500,
                                       message=self.t("error.oops"))
            return JSONResponse({"detail": "internal server error"}, status_code=500)

    def install_https(self, app):
        """HTTPS gemäß config.https_mode: 'force' → HTTP→HTTPS-Redirect-Middleware; 'warn'/'off' →
        läuft auch OHNE Zertifikat (bei 'warn' Panel-Hinweis). Gibt den Modus zurück."""
        if self.cfg.https_mode == "force":
            from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
            app.add_middleware(HTTPSRedirectMiddleware)
        return self.cfg.https_mode

    def _deny(self, request: Request) -> NoReturn:
        # HTML-Browser → Redirect zum Login; sonst (API/JSON) → 401
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.cfg.login_path}?next={nxt}"})
        raise HTTPException(401, self.t("api.not_signed_in"))

    def _deny_stepup(self, request: Request) -> NoReturn:
        # eingeloggt, aber Faktor nicht frisch. Browser → Redirect zu /auth/reauth; sonst 403 + Hinweis-Header.
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"/auth/reauth?next={nxt}"})
        raise HTTPException(403, self.t("api.stepup"), headers={"X-TinySesam-Reauth": "/auth/reauth"})

    # ---------- Step-up-Frische ----------
    def stepup_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
        """True, wenn die aktuelle Sitzung frisch einen Faktor bestätigt hat (Sudo-Frische)."""
        user = user or self.current_user(request)
        if not user or user.get("_via") == "apikey":
            return False   # maschineller Zugang kann keinen interaktiven Faktor frisch bestätigen
        s = self.session_from_request(request)
        if not s or not s["mfa_ok"]:
            return False
        if self.cfg.stepup_max_age_sec > 0:
            if not s["mfa_at"] or (int(time.time()) - s["mfa_at"]) > self.cfg.stepup_max_age_sec:
                return False
        return True

    def _redirect_factor(self, request: Request, step) -> NoReturn:
        # Browser → Redirect zur Eingabeseite des nächsten Faktors; JSON → 401 + X-TinySesam-Factor.
        if step is None:
            self._deny(request)
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(307, headers={"Location": self.factor_entry(step, request.url.path)})
        raise HTTPException(401, self.t("api.factor"), headers={"X-TinySesam-Factor": step})

    def _enforce_route_chain(self, request: Request, factors, strict) -> dict:
        strict = self.cfg.login_chain_strict if strict is None else strict
        s = self.session_from_request(request)
        usr = self._als_dict(self.store.get_user(s["user_id"])) if s else None
        if usr and usr["disabled"]:
            usr = None
        done = json.loads(s["factors_done"] or "[]") if s else []
        if usr is None:
            self._redirect_factor(request, factors[0] if factors else "password")
        if self._chain_satisfied(factors, strict, done):
            d = dict(usr)
            d["_via"] = "session"
            return d
        self._redirect_factor(request, self._next_factor(factors, strict, done))

    def _enforce(self, request: Request, mfa=False, admin=False, role=None, factors=None,
                 strict: Optional[bool] = None, admin_implies: Optional[bool] = None) -> dict:
        gchain, _ = self._global_chain()
        # Der erste Zweig liefert immer ein dict, die beiden anderen können None liefern und
        # brechen dann über `_deny`/`_redirect_factor` ab. Ohne diese Deklaration nimmt ein
        # Typprüfer den Typ des ersten Zweigs für den ganzen Rest an.
        u: Optional[dict]
        if factors is not None:
            # explizite Route-Kette: nie per API-Key erfüllbar, treibt eigene Faktor-Schritte
            u = self._enforce_route_chain(request, factors, strict)
        elif gchain is None:
            # klassisch (Schnellpfad, unverändert)
            u = self.current_user(request)
            if not u:
                self._deny(request)
        else:
            # globale Kette: current_user spiegelt sie (mfa_ok); partielle Sitzung → nächster Schritt
            u = self.current_user(request)
            if not u:
                s = self.session_from_request(request)
                usr = self._als_dict(self.store.get_user(s["user_id"])) if s else None
                if not usr or usr["disabled"]:
                    self._deny(request)   # keine Identität → Login (erster Faktor)
                done = json.loads(s["factors_done"] or "[]")
                self._redirect_factor(request, self.next_login_step(usr["id"], done))
        if admin and not self.is_admin(u):
            raise HTTPException(403, self.t("api.admin"))
        if role:
            # Eine Rolle oder mehrere (dann genügt EINE davon — dieselbe ODER-Bedeutung wie
            # ?roles=a,b im Forward-Auth). Wer ALLE verlangt, stapelt zwei Guards.
            noetig = [role] if isinstance(role, str) else list(role)
            if not any(self.has_role(u, r, admin_implies) for r in noetig):
                raise HTTPException(403, self.t("api.role", rollen=", ".join(f"'{r}'" for r in noetig)))
        if mfa and not self.stepup_fresh(request, u):
            if u.get("_via") == "apikey":
                raise HTTPException(403, self.t("api.stepup_session"))
            self._deny_stepup(request)
        return u

    def require_user(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): erzwingt eingeloggten (inkl. MFA) User.
        Wer keine Rollen braucht: `Depends(auth.require_user)` genügt."""
        return self._enforce(request)

    def require_admin(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): eingeloggt + Admin (+ Step-up, wenn admin_require_mfa)."""
        return self._enforce(request, admin=True, mfa=self.cfg.admin_require_mfa)

    def require_role(self, *roles, mfa: bool = False, admin_implies: Optional[bool] = None):
        """FastAPI-Dependency-Factory: eingeloggt + Rolle. `Depends(auth.require_role('editor'))`.

        **Mehrere Rollen: eine davon genügt** — `auth.require_role('redaktion', 'lektorat')`.
        Das ist dieselbe ODER-Bedeutung wie `?roles=a,b` im Forward-Auth; sonst hiesse dieselbe
        Frage je nach Betriebsmodus etwas anderes. Eine Liste geht auch
        (`require_role(['redaktion', 'lektorat'])`), praktisch für Rollen aus der Konfiguration.

        Wer **alle** verlangt, stapelt zwei Guards — `Depends`-Abhängigkeiten laufen alle:
        `@app.get(..., dependencies=[Depends(auth.require_role('a')), Depends(auth.require_role('b'))])`.

        Ein Admin erfüllt die Rolle standardmäßig mit — `admin_implies=False` verlangt sie wirklich.
        mfa=True verlangt zusätzlich Step-up-Frische.
        """
        flach = []
        for r in roles:
            if isinstance(r, str):
                flach.append(r)
                continue
            try:
                flach.extend(r)
            except TypeError:
                # Fängt den einen Aufruf, der sich durch die variadische Signatur ändert:
                # require_role("editor", True) meinte früher mfa=True. mfa und admin_implies
                # sind jetzt keyword-only — laut statt still falsch.
                raise TypeError(f"require_role(): {r!r} ist keine Rolle. "
                                "mfa/admin_implies nur noch als Schlüsselwort übergeben.") from None
        if not flach:
            raise ConfigError("require_role() braucht mindestens eine Rolle")

        def dep(request: Request) -> dict:
            return self._enforce(request, role=flach, mfa=mfa, admin_implies=admin_implies)
        return dep

    def require(self, mfa: bool = False, admin: bool = False, role=None,
                factors: Optional[list] = None, strict: Optional[bool] = None,
                admin_implies: Optional[bool] = None):
        """Allgemeine Guard-Factory für beliebige Kombinationen — der „Flag am Guard"-Weg:
        `Depends(auth.require(mfa=True))`, `Depends(auth.require(admin=True, mfa=True))`.
        `role=` nimmt eine Rolle oder mehrere (`role=["redaktion", "lektorat"]` → eine genügt).
        factors=[...] verlangt eine bestimmte Faktor-Kette für diese Route (überschreibt die globale),
        strict=True/False steuert die Reihenfolge: `Depends(auth.require(factors=['oidc','password']))`."""
        def dep(request: Request) -> dict:
            return self._enforce(request, mfa=mfa, admin=admin, role=role, factors=factors,
                                 strict=strict, admin_implies=admin_implies)
        return dep

    def require_mfa(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): eingeloggt + frische Step-up-Bestätigung."""
        return self._enforce(request, mfa=True)

    # ---------- Geteilte Ressourcen-Geheimnisse (PIN oder Passphrase, ohne User-Konto) ----------
    def set_resource_secret(self, name, secret, kind="pin", label=None):
        """Geheimnis für einen Bereich setzen/ändern. kind='pin' (numerisch) | 'password' (Passphrase)."""
        if not secret:
            raise ConfigError("leeres Geheimnis")
        if kind not in ("pin", "password"):
            raise ConfigError("kind muss 'pin' oder 'password' sein")
        self.store.set_resource_secret(name, hash_password(str(secret)), kind, label)

    def remove_resource_secret(self, name):
        """Eine gesperrte Ressource wieder freigeben (die Sperre entfernen, nicht entsperren)."""
        self.store.delete_resource_secret(name)

    def list_resource_secrets(self):
        """Alle gesperrten Ressourcen (Namen und Beschreibungen, keine Geheimnisse)."""
        return self.store.list_resource_secrets()

    def check_resource(self, name, secret) -> bool:
        """Das Geheimnis einer gesperrten Ressource prüfen (ohne sie freizuschalten — das tut `unlock_resource`)."""
        row = self.store.get_resource_secret(name)
        return bool(row and verify_password(str(secret or ""), row["hash"]))

    def resource_unlocked(self, request: Request, name) -> bool:
        """Ist diese Ressource für diesen Browser gerade freigeschaltet?"""
        return self.store.is_resource_unlocked(request.cookies.get(self.cfg.resource_cookie), name)

    def unlock_resource(self, request: Request, response, name):
        """Eine Ressource für diesen Browser freischalten und das Cookie setzen."""
        token = request.cookies.get(self.cfg.resource_cookie) or secrets.token_urlsafe(32)
        ttl = self.cfg.resource_unlock_ttl_hours * 3600
        self.store.add_resource_unlock(token, name, int(time.time()) + ttl)
        kw = dict(httponly=True, secure=self.cfg.cookie_secure, samesite=_samesite(self.cfg.cookie_samesite),
                  path=self.cfg.cookie_path, max_age=ttl)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.set_cookie(self.cfg.resource_cookie, token, **kw)

    def require_resource(self, name: str):
        """FastAPI-Dependency-Factory: Bereich erst nach Eingabe des Ressourcen-Geheimnisses zugänglich.
        Unabhängig vom Benutzer-Login. `Depends(auth.require_resource('fotos'))`."""
        def dep(request: Request):
            if not self.resource_unlocked(request, name):
                if "text/html" in request.headers.get("accept", ""):
                    from urllib.parse import quote
                    nxt = quote(request.url.path, safe="/")
                    raise HTTPException(307, headers={"Location": f"/auth/resource/{name}?next={nxt}"})
                raise HTTPException(401, self.t("api.resource_locked"))
            return True
        return dep

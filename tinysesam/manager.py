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
import os
import re
import sys
import time
import json
import hashlib
import secrets
from typing import Any, Literal, NoReturn, Optional, cast

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from . import konfigpruefung
from .errors import ConfigError, StateError
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


def _host_aus(wert: str) -> str:
    """Nur der Hostname einer Adresse — oder "" bei einer kaputten (offene IPv6-Klammer u.ä.).

    Wird als Schlüssel für `security.einmal_melden()` gebraucht: Der Hinweis gehört zum Host,
    nicht zur einzelnen URL — sonst hebt jeder neue Pfad die Sperre auf und der Log-Sturm ist
    wieder da.
    """
    from urllib.parse import urlsplit
    try:
        return urlsplit(str(wert or "")).hostname or ""
    except ValueError:
        return ""


def _inject_nonce(html_str: str, nonce: str) -> str:
    return _NONCE_TAG.sub(rf'<\g<1> nonce="{nonce}"', html_str)


def _auf_stderr(zeile: str) -> None:
    """Eine Zeile an den Betreiber, nicht an das Log.

    Der Weg ist bewusst `sys.stderr` und nicht `seclog`: Was hier steht, ist für den Menschen
    gedacht, der den Dienst startet — nicht für eine Datei, die fail2ban liest, logrotate
    archiviert und ein Log-Versand mitnimmt (B5-03). `sys.stderr` wird bei jedem Aufruf frisch
    nachgeschlagen, damit ein umgelenktes stderr (Tests, Wrapper) wirklich greift.
    """
    try:
        sys.stderr.write(zeile.rstrip("\n") + "\n")
        sys.stderr.flush()
    except Exception:
        pass            # kein stderr (pythonw, geschlossener Deskriptor) — kein Grund abzubrechen


def _samesite(wert: str) -> Literal["lax", "strict", "none"]:
    """Der Konstruktor lässt nur diese drei Werte zu (s. TinySesam.__init__); hier steht es
    noch einmal für den Typprüfer, dem die Zusage von dort nicht folgt."""
    return cast(Literal["lax", "strict", "none"], wert)


def _beleg_am_konto(user) -> bool:
    """Der Vermerk `users.email_verified` einer Kontozeile.

    Fehlt die Spalte — eine Zeile aus einer fremden Quelle, ein Testaufbau mit einem
    Wörterbuch —, gilt „bestätigt": genau der Stand jeder Installation vor dieser Spalte,
    also keine stille Verschärfung für Bestandsdaten. Wo ein Anmeldeweg es besser weiss,
    reist der Beleg ohnehin als Parameter mit (`maybe_promote_admin(user, email_bestaetigt=…)`)
    und gewinnt."""
    try:
        return bool(user["email_verified"])
    except (IndexError, KeyError, TypeError):
        return True


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
        #
        # Offen ist diese Tür nicht nur bei `allow_signup`. Jedes Verfahren, das beim ersten
        # Login selbst ein Konto anlegt, legt es unter einem Namen an, den der fremde IdP
        # liefert: `oidc.py` nimmt `preferred_username`, SAML das NameID-/Attributfeld, LDAP
        # den Anmeldenamen. Das ist dieselbe Lage wie bei der offenen Registrierung — nur
        # bestimmt den Namen dort der Besucher und hier der IdP, und bei einem IdP mit
        # Selbstregistrierung ist das dieselbe Person.
        offene_tueren = []
        if config.allow_signup:
            offene_tueren.append("allow_signup=True")
        for an, anlegen, name in (("oidc_enabled", "oidc_auto_create", "OIDC"),
                                  ("saml_enabled", "saml_auto_create", "SAML"),
                                  ("ldap_enabled", "ldap_auto_create", "LDAP")):
            if getattr(config, an, False) and getattr(config, anlegen, False):
                offene_tueren.append(f"{anlegen}=True ({name})")
        if config.admin_identifiers and offene_tueren:
            ids = [str(i).strip() for i in config.admin_identifiers if str(i).strip()]
            namen = [i for i in ids if "@" not in i]
            if namen:
                raise ConfigError(
                    f"admin_identifiers={namen} sind Benutzernamen, und Konten entstehen hier "
                    f"von selbst ({', '.join(offene_tueren)}): Einen Benutzernamen bestätigt "
                    "niemand — wer sich als Erster so anmeldet, wird Erst-Admin. Bei offener "
                    "Registrierung stattdessen eine E-Mail-Adresse eintragen (mit "
                    "signup_require_email=True und signup_verify_email=True); bei einem IdP "
                    "den Einmal-Token-Weg nutzen (/auth/claim-admin, s. admin_claim_ttl_min) "
                    "oder das Auto-Anlegen abschalten und das Konto vorher selbst vergeben "
                    "(bei OIDC grenzt oidc_allowed_groups den Kreis zusätzlich ein).")
        if config.admin_identifiers and config.allow_signup:
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
            # Erst die Form, dann die Namen. `{"user": None}` rutschte durch (`namen or []`
            # machte daraus eine leere Liste) und kippte später JEDEN Forward-Auth-Request in
            # ein 500; `{"user": 123}` tötete den Konstruktor mit einem rohen `TypeError`, den
            # ein `except ConfigError` nicht fängt.
            for feld, wert in config.forward_headers.items():
                if isinstance(wert, str):
                    continue
                if isinstance(wert, (list, tuple)) and all(isinstance(x, str) for x in wert):
                    continue
                raise ConfigError(
                    f"forward_headers[{feld!r}] muss ein Header-Name sein oder eine Liste davon "
                    f"— ist aber {type(wert).__name__}. Beispiel: "
                    '{"user": "Remote-User"} oder {"user": ["Remote-User", "X-Auth-User"]}')
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
        # Fehlt hier ein Extra, ist das ein Betriebsfehler und keine Feinheit: Der Aufbau
        # scheitert mit dem Namen des Pakets statt mit einem ModuleNotFoundError aus der Tiefe
        # oder — schlimmer — erst beim ersten Anmeldeversuch als 500.
        #
        # Geprüft wird hier und nicht im Konstruktor-Kopf, und zwar an der Bedingung „ist das
        # Verfahren VOLLSTÄNDIG konfiguriert": Wer `oidc_enabled=True` setzt, aber keinen
        # `issuer`, will den Client offensichtlich selbst mitbringen (`auth.oidc = …`) — so
        # arbeiten vier eigene Suiten. Ein Wächter, der schon am Schalter anschlägt, verbietet
        # diesen Weg. Dass ein halb konfiguriertes Verfahren auffällt, erledigt konfigpruefung.
        # `find_spec` statt eines Import-Versuchs: Die Extras werden überall LAZY importiert
        # (erst beim Verbinden, beim Token-Tausch, beim Prüfen einer Assertion). Ein fehlendes
        # Paket fiel deshalb nicht beim Aufbau auf, sondern beim ersten Anmeldeversuch — als
        # 500 aus dem Innern der Bibliothek.
        # Warnen, nicht werfen. Ein Client lässt sich ersetzen (`auth.ldap = eigener_client`),
        # und genau so arbeiten vier eigene Suiten — ein Wächter, der hier abbricht, verbietet
        # das. Geworfen wird an der Stelle, an der es nie falsch sein kann: am lazy Import im
        # jeweiligen Modul. Der Betreiber sieht es also beim Start im Log und, falls er das
        # übersieht, beim ersten Anmeldeversuch als lesbaren `MissingExtra` statt als 500.
        def _verlange(modul, schalter, extra):
            import importlib.util as _ilu
            try:
                da = _ilu.find_spec(modul) is not None
            except (ImportError, ValueError):
                da = False
            if not da:
                security.seclog.warning(
                    "%s=True, aber das Extra [%s] ist nicht installiert (pip install "
                    "'tinysesam[%s]') — das Modul '%s' fehlt. Sofern der Client nicht selbst "
                    "gesetzt wird, scheitert die Anmeldung über dieses Verfahren.",
                    schalter, extra, extra, modul)

        if config.ldap_enabled and config.ldap_url:
            _verlange("ldap3", "ldap_enabled", "ldap")
            from .ldap_ import LDAPClient
            self.ldap = LDAPClient(config)
        if config.saml_enabled and config.saml_idp_sso_url and config.saml_idp_x509cert:
            _verlange("onelogin", "saml_enabled", "saml")
            from .saml_ import SAMLClient
            self.saml = SAMLClient(config)
        if config.oidc_enabled and config.oidc_issuer and config.oidc_client_id:
            _verlange("authlib", "oidc_enabled", "oidc")
            from .oidc import OIDCClient
            self.oidc = OIDCClient(config.oidc_issuer, config.oidc_client_id,
                                   config.oidc_client_secret, config.oidc_scopes)
        if config.passkey_enabled:
            # Passkey kennt keine unvollständige Konfiguration: Wer den Schalter umlegt, will es.
            _verlange("webauthn", "passkey_enabled", "passkey")
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
        # Kreuz-Kollisionen im Bestand: Seit R4-12 prüft `create_user` kreuzweise, aber die
        # Datenbank hat keinen UNIQUE-Index über BEIDE Namensräume — eine Kollision aus einer
        # älteren Fassung (oder aus zwei gleichzeitigen Registrierungen, denn Prüfung und INSERT
        # sind nicht atomar) steht weiter drin und wird von nichts gemeldet. Sie ist nicht
        # harmlos: `find_user` löst die Kennung dann mehrdeutig auf, und der rechtmäßige Inhaber
        # kann ausgesperrt sein. Bereinigt wird von Hand (welches Konto den Namen behält, kann
        # keine Bibliothek entscheiden) — gesagt wird es beim Start.
        kollisionen = self.store.kennungs_kollisionen()
        if kollisionen:
            beispiele = "; ".join(
                f"user_id={z['name_id']} heisst '{security.fuer_log(z['kennung'])}' und ist "
                f"zugleich E-Mail von user_id={z['mail_id']}" for z in kollisionen[:3])
            security.seclog.warning(
                "%d Kennungs-Kollision(en) im Bestand: Benutzername und E-Mail sind EIN "
                "Kennungs-Raum (find_user sucht in beiden Spalten), die Datenbank erzwingt das "
                "aber nur je Spalte. Die Anmeldung mit dieser Kennung ist mehrdeutig, der "
                "rechtmäßige Inhaber kann ausgesperrt sein. Betroffen: %s%s. Eine der beiden "
                "Kennungen ändern (Admin-Panel oder CLI).",
                len(kollisionen), beispiele,
                " (weitere folgen)" if len(kollisionen) > 3 else "")
        tok = self.admin_claim_token()
        if tok:
            self._admin_claim_bekanntgeben(tok)

    # ---------- User-Verwaltung ----------
    def kennung_vergeben(self, kennung, exclude_id=None) -> Optional[dict]:
        """Gehört diese Login-Kennung schon einem Konto — in IRGENDEINEM der beiden Namensräume?

        Benutzername und E-Mail sind keine getrennten Räume: `find_user` durchsucht bei
        `login_identifier="both"` (Vorgabe) **beide** Spalten, und bei einer Kennung mit `@`
        gewinnt die E-Mail. Wer getrennt prüft, lässt zu, dass ein Fremder die E-Mail eines
        bestehenden Kontos als *Benutzernamen* einträgt (oder umgekehrt) — ab da löst die Kennung
        auf das fremde Konto auf und der Rechtmäßige ist ausgesperrt (Fund R4-12).

        Geprüft wird **immer** kreuzweise, auch in den Modi "username" und "email": der Modus ist
        ein Schalter, den ein Betrieb später umlegt; eine Kollision, die heute schläft, wäre dann
        sofort scharf. Rückgabe ist das Konto, dem die Kennung gehört, sonst None. `exclude_id`
        lässt ein Konto aus — für Prüfungen an einem bestehenden Konto.
        """
        kennung = (kennung or "").strip()
        if not kennung:
            return None
        for treffer in (self.store.get_user_by_name(kennung), self.store.get_user_by_email(kennung)):
            if treffer is not None and treffer["id"] != exclude_id:
                return self._als_dict(treffer)
        return None

    def create_user(self, username, password=None, is_admin=False, roles=None,
                    display_name=None, email=None, is_service=False,
                    email_verified: bool = True) -> int:
        """Ein Konto anlegen und seine ID zurückgeben. `is_service=True` für Maschinen: kein
        Login, nur API-Keys. Eine bereits vergebene Kennung wirft `ConfigError` — **neu auch
        beim doppelten Benutzernamen**, der bis 0.18.x als `sqlite3.IntegrityError` aus der
        Datenbank kam (`e.feld`/`e.besitzer_id` sagen, was kollidierte).

        Benutzername und E-Mail müssen **kreuzweise** frei sein (`kennung_vergeben`) — sonst
        besetzt ein neues Konto die Login-Kennung eines bestehenden. Die Prüfung sitzt hier,
        damit sie für JEDEN Weg gilt: Selbst-Registrierung, Admin-API, Einladung, Erst-Admin
        (`ensure_admin`), Service-Konten (`create_service`) und die automatische Anlage aus
        OIDC/LDAP/SAML. Das CLI ist bewusst nicht dabei: Es kann keine Konten anlegen
        (`version`, `passwd`, `backup`, `restore`, `gc`, `audit`, `unlock`).

        `email_verified=False` legt die Adresse als **unbestätigt** ab: geführt und
        weitergereicht wie jede andere, aber ohne Tragkraft für Rechte (Erst-Admin/Allowlist,
        siehe `maybe_promote_admin`). Das ist der Fall jedes Anmeldewegs, der für die Adresse
        nicht einsteht: ein IdP ohne den Claim `email_verified`, **und grundsätzlich SAML und
        LDAP** — dort gibt es gar kein Attribut, das eine Prüfung behauptet.
        Die Vorgabe `True` gilt für die Wege, bei denen der Betreiber oder eine Bestätigungsmail
        für die Adresse einsteht (Admin-API, Erst-Admin, Service-Konten, Einladung, Registrierung
        — dort verlangt der Konstruktor-Wächter `signup_verify_email`, sobald eine
        Allowlist-Adresse im Spiel ist).

        Eine vergebene Kennung wirft `ConfigError` mit dem Wortlaut „<Feld> ist bereits
        vergeben" und gesetztem `e.feld` (`"username"`/`"email"`) plus `e.besitzer_id` —
        daran, nicht am übersetzten Text, unterscheidet ein Aufrufer die beiden Fälle.

        ⚠️ **Geändert gegenüber 0.18.x:** Nur die doppelte *E-Mail* warf dort schon
        `ConfigError`. Ein doppelter *Benutzername* lief bis in die Datenbank und kam als
        `sqlite3.IntegrityError` zurück; er wird jetzt vorher abgefangen und wirft denselben
        `ConfigError`. Wer auf `IntegrityError` fängt, fängt diesen Fall nicht mehr."""
        username = (username or "").strip()
        email = norm_email(email)
        for feld, schluessel, kennung in (("Benutzername", "username", username),
                                          ("E-Mail-Adresse", "email", email)):
            besitzer = self.kennung_vergeben(kennung) if kennung else None
            if besitzer:
                security.seclog.warning(
                    "Konto nicht angelegt: %s ist bereits Login-Kennung von user_id=%s", feld, besitzer["id"])
                # Der Wortlaut ist der von 0.18.x ("… ist bereits vergeben"). Weil ein
                # `ConfigError` allein nicht verrät, WAS kollidierte, prüfen Aufrufer den Text —
                # die brüchigste Art, ein Programm zu steuern, aber eine verbreitete. Ein Fix
                # darf ihr nicht die Grundlage wegziehen. Er nennt aber das Feld, das WIRKLICH
                # kollidiert: Der neue Auslöser (Benutzername = fremde E-Mail und umgekehrt)
                # trägt je nach Richtung den Benutzernamen- ODER den E-Mail-Text, nicht immer
                # denselben. Verlässlich unterscheiden lässt er sich an `feld`/`besitzer_id`.
                fehler = ConfigError(f"{feld} ist bereits vergeben")
                fehler.feld = schluessel
                fehler.besitzer_id = int(besitzer["id"])
                raise fehler
        uid = self.store.create_user(username, display_name, email, is_admin, roles, is_service,
                                     email_verified=email_verified)
        if password:
            self.store.set_password_hash(uid, hash_password(password))
        return uid

    # Rollen (optional). Wer nur „eingeloggt oder nicht" braucht, nimmt require_user.
    # Andere Projekte differenzieren User über is_admin + frei definierbare roles.
    def user_roles(self, user) -> list:
        """Die Rollen eines Kontos als Liste."""
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

        **Bleibt nach dem Schnitt nichts übrig, wirft die Methode `ConfigError` und legt keinen
        Key an** — ein Tippfehler in `roles` gibt also eine Ausnahme, keinen Key. Warum kein
        leerer Scope: Der Grund steht unten am Code, er kehrte die Wirkung ins Gegenteil.

        Zurück kommt `{"id", "key", "prefix", "expires_at", "roles", "verworfene_rollen"}`.
        `key` ist der Klartext und hier das einzige Mal zu sehen; `verworfene_rollen` nennt, was
        der Schnitt entfernt hat (dieselbe Angabe steht im Audit-Eintrag).
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
            # Bleibt nach dem Beschneiden NICHTS übrig, darf der Key nicht entstehen.
            #
            # Die Spalte `api_key.roles` kennt nur einen leeren Wert, und der bedeutet „kein
            # Scope, erbt die Rollen des Besitzers". Ein zu `[]` zusammengeschrumpfter Scope
            # würde damit zu seinem Gegenteil: Wer einen Key auf `["lagre"]` scopen will (ein
            # Tippfehler), bekäme einen Key mit ALLEN Rollen des Kontos. Diese Beschneidung war
            # als Rechte-Begrenzung gedacht und wäre so eine Rechte-Erweiterung geworden —
            # schlimmer als vor dem Fix.
            #
            # Deshalb ein Fehler statt einer Annahme: Was gemeint war, weiß nur der Aufrufer.
            if not roles:
                raise ConfigError(
                    f"API-Key-Scope {sorted(set(gewuenscht))} enthält keine Rolle, die das Konto "
                    f"hat ({sorted(erlaubt) or 'keine'}). Ein Key kann nur weniger können als "
                    "sein Besitzer, nie mehr - und ein leerer Scope hiesse in der Datenbank "
                    "'erbt alles'. Entweder eine vorhandene Rolle nennen oder `roles` weglassen "
                    "(dann erbt der Key die Rollen des Kontos).")

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

    #: Faktoren, mit denen die Identität von einem FREMDEN Anbieter kommt. Für sie gilt in
    #: `maybe_promote_admin` fail-closed: Ohne ausdrücklichen Beleg trägt eine Allowlist-Adresse
    #: dort keine Erst-Admin-Entscheidung — ein neuer föderierter Weg, der den Beleg zu
    #: übergeben vergisst, befördert also nicht, sondern verweigert.
    #: `ldap` steht bewusst nicht hier: LDAP schreibt den Faktor `password` (s. `check_ldap`),
    #: ist am Faktornamen also nicht zu erkennen — sein Aufrufer reicht den Beleg, den es dort
    #: gar nicht gibt, ausdrücklich als `False` durch.
    FOEDERIERTE_FAKTOREN = ("oidc", "saml")

    def maybe_promote_admin(self, user, email_bestaetigt: Optional[bool] = None,
                            faktor: Optional[str] = None) -> bool:
        """Weg 1: Allowlist. Wer in `admin_identifiers` steht, wird beim Login Admin — egal über
        welche Methode (auch OIDC/SAML/LDAP); eine Allowlist-ADRESSE aber nur mit einem Beleg,
        dass sie dem Anmeldenden gehört, und über SAML/LDAP gibt es keinen. Danach nie wieder.

        **Ein Eintrag mit `@` wird NUR gegen die E-Mail geprüft, einer ohne NUR gegen den
        Benutzernamen.** Vorher galt „Name ODER E-Mail" für jeden Eintrag, und das machte den
        Konstruktor-Wächter wirkungslos: Der verlangt bei offener Registrierung eine
        *E-Mail-Adresse* in der Allowlist, mit der Begründung „den Namen hat, wer das Postfach
        hat". Ein Benutzername ist aber ein freies Textfeld — wer sich als
        `username="chef@example.com"` registriert und SEIN eigenes Postfach bestätigt, wurde
        damit Erst-Admin. Der Wächter prüfte die Konfiguration, der Vergleich hier aber etwas
        anderes; die Lücke war nur verschoben.

        `email_bestaetigt` ist der **Beleg für die Adresse**, mit dem der Aufrufer anreist:
        `True`/`False` sagt ein föderierter Anmeldeweg über den Claim `email_verified`,
        `None` heisst „dieser Anmeldeweg weiss es nicht". Ohne Beleg zählt eine Treffer-Adresse
        nicht: Sonst genügte ein IdP mit Selbstregistrierung, um sich die Admin-Adresse
        einzutragen und beim ersten Login Erst-Admin zu werden.

        Belegt wird in zwei Stufen, beide fail-closed:

        1. **Föderierter Weg ohne Beleg verweigert.** Einen Beleg gibt es nur bei OIDC (Claim
           `email_verified`, OIDC Core 5.1). **SAML und LDAP kennen keinen** — kein
           Standard-Attribut sagt, dass ein Verzeichnis die Adresse geprüft hat, und ein
           `mail`-Attribut pflegt der Nutzer in vielen Verzeichnissen selbst. Damit das nicht am
           Gedächtnis des Aufrufers hängt: `faktor` aus `FOEDERIERTE_FAKTOREN` verlangt
           `email_bestaetigt is True`, ein vergessenes Argument verweigert. LDAP schreibt den
           Faktor `password` und ist daran nicht zu erkennen — dort reicht der Aufrufer
           `email_bestaetigt=False` durch.
        2. **Sonst entscheidet der Vermerk am Konto** (`users.email_verified`, gelesen von
           `_beleg_am_konto`). Die Adresse eines IdP ohne den Claim wird seit dieser Fassung ganz
           normal ins Konto geschrieben (sonst verlöre eine bestehende Installation Kontoname und
           `Remote-Email`) — sie darf nur nichts tragen. Hinge das allein am Parameter, wäre der
           Schutz eine Frage des Anmeldewegs: derselbe Datensatz, einmal über einen lokalen Weg
           (Magic-Link, Passwort) angemeldet, käme mit `None` herein und wäre befördert worden.
           Der Vermerk steht in der Datenbank und gilt deshalb für jeden Weg.

        Der Benutzername bleibt davon unberührt — für ihn ist der Konstruktor-Wächter zuständig,
        der Allowlist-Namen verbietet, sobald Konten von selbst entstehen.
        """
        ids = {str(i).strip().lower() for i in self.cfg.admin_identifiers if str(i).strip()}
        if not ids or not user or user["is_admin"] or self.admin_exists():
            return False
        adressen = {i for i in ids if "@" in i}
        namen = ids - adressen
        trifft_adresse = str(user["email"] or "").lower() in adressen
        trifft_name = str(user["username"] or "").lower() in namen
        if trifft_adresse and not trifft_name:
            # Zwei Stufen, beide fail-closed: Ein ausdrücklicher Beleg des Anmeldewegs gewinnt.
            # Schweigt der Weg (`None`), verweigert ein föderierter Faktor grundsätzlich — auch
            # wenn er das Argument schlicht vergessen hat —, und sonst entscheidet der Vermerk
            # am Konto.
            if email_bestaetigt is not None:
                belegt, grund = email_bestaetigt is True, "email_unbestaetigt"
            elif (faktor or "") in self.FOEDERIERTE_FAKTOREN:
                belegt, grund = False, f"ohne_beleg:{faktor or '?'}"
            else:
                belegt, grund = _beleg_am_konto(user), "email_unbestaetigt"
            if not belegt:
                security.seclog.warning(
                    "Erst-Admin NICHT vergeben: %s trägt die Allowlist-Adresse %s, für diesen "
                    "Anmeldeweg (%s) liegt aber kein Bestätigungsbeleg vor (OIDC: Claim "
                    "email_verified; SAML und LDAP kennen keinen; sonst der Vermerk am Konto). "
                    "Die Adresse bleibt am Konto, sie trägt nur diese Entscheidung nicht. "
                    "Belegter Weg: /auth/claim-admin.",
                    user["username"], user["email"], faktor or "?")
                self.audit("admin_bootstrap_denied", user["username"], detail=grund)
                return False
        if not (trifft_adresse or trifft_name):
            return False
        self.store.set_admin(user["id"], True)
        self.audit("admin_bootstrap", user["username"], detail="admin_identifiers")
        security.seclog.warning("Erst-Admin per admin_identifiers vergeben: %s", user["username"])
        return True

    def _admin_claim_bekanntgeben(self, token: str) -> None:
        """Den Wert des Erst-Admin-Einmal-Tokens dem **Betreiber** zeigen — nicht dem Log.

        Bis 0.18.x stand der Token im Klartext in der Zeile, die `security.seclog` schreibt. Ist
        `security_log` gesetzt, ist das genau die Datei, auf die die mitgelieferte fail2ban-Jail
        zeigt: sie entstand ohne Rechtevorgabe (gemessen `-rw-rw-r--`), logrotate hebt sie
        wochenlang auf und jedes Log-Shipping nimmt sie mit. Wer sie lesen konnte und irgendein
        Konto auf der Instanz hatte, rief `/auth/claim-admin?token=…` auf und war Admin (B5-03).

        Der Wert geht deshalb nach **stderr** — die Konsole dessen, der den Dienst startet, und
        der einzige Empfänger, den der Docstring von `admin_claim_token` je gemeint hat. Wo
        stderr selbst eingesammelt wird (journal, Container-Logs), nennt der Betreiber mit
        `admin_claim_token_file` eine Datei; die legt TinySesam mit 0600 an. Ins Log kommt nur
        noch, **wo** der Token steht.
        """
        ttl = self.cfg.admin_claim_ttl_min
        pfad = str(self.cfg.admin_claim_token_file or "").strip()
        wohin = "auf stderr (Konsole des Betreibers)"
        geschrieben = False
        if pfad:
            try:
                # Ohne O_TRUNC öffnen und die Rechte am Deskriptor setzen, BEVOR das Geheimnis
                # hineingeht: Bei einer schon vorhandenen Datei ignoriert der mode-Parameter von
                # os.open die Vorgabe, und ein chmod hinterher liesse ein Fenster offen.
                fd = os.open(pfad, os.O_CREAT | os.O_WRONLY, 0o600)
                try:
                    if hasattr(os, "fchmod"):
                        os.fchmod(fd, 0o600)
                    os.ftruncate(fd, 0)
                    os.write(fd, (token + "\n").encode("utf-8"))
                finally:
                    os.close(fd)
                wohin = f"in {pfad} (Rechte 0600)"
                geschrieben = True
            except OSError as e:
                # Kein Grund, den Start zu verweigern — aber der Betreiber muss den Token
                # bekommen, sonst kommt er nicht an seine eigene Instanz.
                _auf_stderr(f"TinySesam: admin_claim_token_file {pfad} nicht schreibbar "
                            f"({type(e).__name__}) — der Token steht stattdessen hier:")
                wohin = f"auf stderr ({pfad} war nicht schreibbar)"
        if not geschrieben:
            _auf_stderr(f"TinySesam: Kein Admin vorhanden. Ersten Admin setzen — anmelden, dann "
                        f"/auth/claim-admin?token={token} (gültig {ttl} Minuten, genau einmal "
                        f"einlösbar).")
        security.seclog.warning(
            "Kein Admin vorhanden. Ein Einmal-Token für /auth/claim-admin wurde ausgegeben %s "
            "— gültig %d Minuten, genau einmal einlösbar. Der Wert steht bewusst NICHT im Log.",
            wohin, ttl)

    def admin_claim_token(self) -> Optional[str]:
        """Weg 2: Einmal-Token. Solange kein Admin existiert, gibt es ein Token, das genau einmal
        eingelöst werden kann (`/auth/claim-admin?token=…`). Der Wert geht beim Start auf stderr
        bzw. in `admin_claim_token_file` (0600) — wer den Server betreibt, hat ihn; wer bloß die
        URL kennt oder das Log lesen kann, nicht (B5-03). Läuft ab."""
        # Kein Panel, keine lokalen Admins → kein Token. Sonst hätte eine reine OIDC-App einen
        # Weg zum Admin, den sie gar nicht vorgesehen hat.
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
        """Beispielkonten anlegen (idempotent). Verlangt `demo_mode=True`.

        Die Prüfung sitzt seit 2026-09-21 **hier** und nicht mehr nur beim Aufrufer im Konstruktor.
        Der Docstring versprach sie vorher schon — der Rumpf hielt sie nicht: Ein direkter Aufruf
        bei `demo_mode=False` legte `demo` und `demoadmin` an, letzteres mit `is_admin=1` und dem
        dokumentierten Standardpasswort, beide sofort anmeldefähig und ohne Warnung im Log.
        """
        if not self.cfg.demo_mode:
            raise ConfigError(
                "seed_demo() verlangt demo_mode=True. Ohne den Schalter entstünden sonst zwei "
                "anmeldefähige Konten mit bekanntem Passwort — eines davon Admin — und der "
                "Warnhinweis im Log bliebe aus.")
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
        Zählt wie ein Passwort-Login (Faktor 'password').

        Die übernommene Adresse (`info["email"]`) ist ein Verzeichnisattribut ohne Beleg — in
        vielen Verzeichnissen pflegt sie der Nutzer selbst. Das hat **zwei** Folgen, und beide
        sind nötig:

        * Ein neu angelegtes Konto bekommt die Adresse mit `email_verified=False` — der Vermerk
          am Konto behauptet nicht, was niemand belegt hat.
        * Wer diesen Weg selbst einbindet, reicht `email_bestaetigt=False` an `apply_factor`
          durch (so macht es die mitgelieferte Login-Route). Am Faktornamen ist der Weg nicht
          erkennbar — `password` steht nicht in `FOEDERIERTE_FAKTOREN`, weil ein lokales
          Passwort dort auch ankommt.

        Nur das zweite allein schützte bloss DIESEN Login: Der Angreifer richtete sich in der
        frisch angemeldeten Sitzung eine PIN oder einen Passkey ein, meldete sich damit erneut
        an — dieser Faktor reist ohne Beleg an —, und der Vermerk am Konto befördert ihn doch
        (B-umgehung-1 aus T-13). Sonst könnte eine Allowlist-Adresse über LDAP den Erst-Admin
        bestimmen (F-14)."""
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
            try:
                # Adresse UND Beleg gehen zusammen ins Konto: Das `mail`-Attribut belegt
                # nichts, also darf der Vermerk am Konto es auch nicht behaupten. Stünde hier
                # die Vorgabe `True`, wäre der Riegel oben nur für DIESEN Login zu — der
                # nächste Faktor, den sich der Angreifer selbst einrichtet (PIN, Passkey),
                # reist ohne Beleg an, liest den Vermerk und befördert doch (B-umgehung-1 aus T-13).
                uid = self.create_user(username, display_name=info.get("name") or username,
                                       email=info.get("email"), email_verified=False)
            except ConfigError:
                # Name oder Adresse gehören lokal schon jemandem (Fund R4-12). Fail-closed:
                # lieber keine Anmeldung als ein Konto, das eine fremde Kennung besetzt.
                self.audit("ldap_ident_taken", username)
                return None
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
        """Aus einer geprüften SAML-Assertion einen lokalen User finden/anlegen. Faktor 'saml'.

        Die Adresse aus dem Attribut trägt keinen Beleg (SAML kennt kein `email_verified`).
        Deshalb legt dieser Weg mit `email_verified=False` an, und der Faktor `saml` steht in
        `FOEDERIERTE_FAKTOREN`: Eine Allowlist-ADRESSE wird über diesen Weg nie zum Erst-Admin,
        auch wenn ein Aufrufer den Beleg nicht nennt — und auch nicht über einen zweiten,
        selbst eingerichteten Faktor beim nächsten Login (B-umgehung-1 aus T-13)."""
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
            try:
                # Wie bei LDAP (B-umgehung-1 aus T-13): Die Adresse aus der Assertion kommt ohne
                # Beleg, also wird sie auch ohne Beleg abgelegt. Sonst trüge der Vermerk am
                # Konto einen Freifahrtschein für jeden späteren Anmeldeweg, der selbst
                # nichts belegt.
                uid = self.create_user(username, display_name=first(attrs, cfg.saml_attr_name) or username,
                                       email=first(attrs, cfg.saml_attr_email), email_verified=False)
            except ConfigError:
                # Wie bei LDAP (Fund R4-12): eine schon vergebene Kennung legt kein Konto an.
                self.audit("saml_ident_taken", username)
                return None
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

        `config.stepup_methods` ist ein **Wunsch, keine Schranke**: Hat der Nutzer keines der
        genannten Verfahren eingerichtet, fällt die Bestätigung auf alles zurück, was er hat —
        sonst wäre der Bereich für ihn unerreichbar, ohne dass er etwas dagegen tun könnte.
        Das schliesst das Passwort ein, mit dem er sich gerade angemeldet hat; `["totp"]` allein
        garantiert also nicht, dass vor dem sensiblen Bereich wirklich ein zweiter Faktor steht.

        Wer die Schranke will, setzt `stepup_strict=True`: Dann bleibt die Liste leer, wenn nichts
        Gewünschtes eingerichtet ist, und der Bereich bleibt verschlossen, bis der Nutzer das
        Verfahren einrichtet."""
        cfg = self.cfg
        avail = []
        if cfg.totp_enabled and self.store.has_confirmed_totp(user["id"]):
            avail.append("totp")
        if cfg.pin_enabled and self.store.has_pin(user["id"]):
            avail.append("pin")
        if cfg.password_enabled and self.store.get_password_hash(user["id"]):
            avail.append("password")
        wanted = [m for m in (cfg.stepup_methods or []) if m in avail]
        if wanted:
            return wanted
        if cfg.stepup_methods and cfg.stepup_strict:
            return []              # gewünscht, aber nichts davon eingerichtet → verschlossen
        return avail               # der alte Weg: das beste, was der Nutzer hat

    def is_pin_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für PIN (kurzer Keyspace). Zusätzlich zu is_locked()."""
        since = int(time.time()) - self.sec("lockout_window_sec")
        limit = self.sec("pin_max_attempts")
        if username and self.store.count_fails(since, username=username, method="pin") >= limit:
            return True
        if ip and self.store.count_fails(since, ip=ip, method="pin") >= limit * self.sec("ip_attempt_factor"):
            return True
        return False

    def is_password_change_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Alt-Passwort-Abfrage der Kontoseite.

        Dieselbe Bauform wie `is_pin_locked`, aber mit eigener Schwelle
        (`password_change_max_attempts`) und **getrennt vom Login-Lockout**: Raten bleibt
        gedrosselt (R4-10 — die Route war ein stilles Passwort-Orakel), ein Tippfehler auf der
        eigenen Kontoseite sperrt aber nicht die Anmeldung. Die Sperre gilt genau dort, wo
        geraten wurde.

        **Nur pro Konto, nicht pro IP** (`ip` geht bloss in die Protokollzeile). Bis zur
        zweiten Runde zählte auch hier eine IP-Schwelle mit — und die verriegelte hinter NAT
        wieder Unbeteiligte: Drei vertippte Kollegen sperrten dem vierten seinen EIGENEN
        Passwortwechsel, obwohl er nichts falsch eingegeben hatte. Der Umbau war angetreten,
        genau das abzustellen. Sie fehlt auch nicht: Wer hier rät, braucht bereits eine
        gültige Sitzung des Kontos, dessen Passwort er rät — das Opfer ist immer der
        Angemeldete selbst. Gegen das Klopfen von aussen steht weiter `rate_ok(ip)`.

        Die Abweisung wird hier gemeldet, nicht in der Route: Sonst verstummte das
        Sicherheits-Log genau dann, wenn fail2ban die IP bannen soll (Begründung bei
        `_abgewiesen`).
        """
        return self._methoden_sperre(username, ip, "password_change",
                                     self.sec("password_change_max_attempts"))

    def is_reauth_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Step-up-Bestätigung (`/auth/reauth`).

        Eine Step-up-Bestätigung ist **keine Anmeldung** — wer sie leistet, ist schon
        angemeldet. Bis zur zweiten Runde zählten ihre Fehlversuche trotzdem in den
        Login-Topf: Fünf Tippfehler an der Reauth-Seite sperrten dem Nutzer die **Anmeldung**
        für `lockout_window_sec`, samt dem korrekten Passwort. Jetzt bremst sie dieser Topf
        (`reauth_max_attempts`), und zwar **nur pro Konto**: Das Raten trifft ausschliesslich
        das eigene Konto, eine IP-Schwelle träfe hinter NAT nur Unbeteiligte (`ip` geht bloss
        in die Protokollzeile). Gedrosselt bleibt der Weg über `rate_ok(ip)`.
        """
        return self._methoden_sperre(username, ip, "reauth", self.sec("reauth_max_attempts"))

    def is_resource_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Bereichs-PIN (`/auth/resource/…`).

        `username` ist hier der Pseudo-Name des Bereichs (`res:<name>`) — ein Konto gibt es
        nicht. Bis zur zweiten Runde lief der Zähler in den Login-Topf, und weil die
        Bereichs-PIN **jeder Besucher** probieren darf, war das ein Verstärker: Drei Bereiche
        mal fünf Fehlgriffe von derselben Adresse erreichten die Login-IP-Schwelle
        (`max_login_attempts * ip_attempt_factor`) und verriegelten die Anmeldung von Konten,
        die nie etwas falsch gemacht hatten.

        Die IP-Schwelle bleibt hier — anders als bei `password_change`/`reauth` — erhalten
        (`resource_max_attempts * ip_attempt_factor`): Dieser Weg steht Unangemeldeten offen,
        das Opfer ist also kein bestimmter Angemeldeter, und ohne IP-Dimension könnte ein
        Angreifer über viele Bereichsnamen beliebig weiterraten. Sie sperrt jetzt aber nur
        noch das, was sie schützt — Bereiche, keine Anmeldungen.
        """
        return self._methoden_sperre(username, ip, "resource", self.sec("resource_max_attempts"),
                                     ip_faktor=self.sec("ip_attempt_factor"))

    def _methoden_sperre(self, username, ip, method, limit, ip_faktor=0) -> bool:
        """Gemeinsamer Rumpf der methodengebundenen Sperren (`is_*_locked`).

        `ip_faktor=0` heisst: **keine** IP-Dimension — die Methode trifft nur den, der rät
        (siehe `is_password_change_locked`). Nur wo ein Fremder von aussen raten kann, zählt
        zusätzlich die Adresse mit (`is_resource_locked`).
        """
        since = int(time.time()) - self.sec("lockout_window_sec")
        if username and self.store.count_fails(since, username=username, method=method) >= limit:
            self._abgewiesen(username, ip, f"lockout_{method}", login=False)
            return True
        if ip_faktor and ip and self.store.count_fails(since, ip=ip, method=method) >= limit * ip_faktor:
            self._abgewiesen(username, ip, f"lockout_{method}_ip", login=False)
            return True
        return False

    # ---------- MFA (TOTP) ----------
    def mfa_pending(self, user_id) -> bool:
        """TOTP verlangt? Ja, wenn ein bestätigtes TOTP für dieses Konto existiert.

        Eine globale Erzwingung gibt es hier nicht (mehr): Der Schalter `totp_required`, auf den
        der frühere Klammerzusatz zielte, wird seit 0.18.0 im Konstruktor mit `ConfigError`
        abgewiesen. Erzwungen wird über `login_chain` — und die wertet `_session_ok` aus, nicht
        diese Methode."""
        return self.store.has_confirmed_totp(user_id)

    def verify_totp(self, user_id, code) -> bool:
        """Einen TOTP-Code prüfen — und ihn dabei verbrauchen.

        Ein Code gilt **genau einmal**. Vorher galt er 90 Sekunden lang beliebig oft
        (`valid_window=1` = vorheriger + aktueller + nächster Schritt), und zwei getrennte
        Clients konnten sich mit demselben Code voll anmelden. NIST SP 800-63B ist an der Stelle
        eindeutig: „Verifiers SHALL accept a given OTP only once while it is valid."
        """
        t = self.store.get_totp(user_id)
        if not t or not t["confirmed"]:
            return False
        schritt = _totp.passender_schritt(t["secret"], code)
        if schritt is None:
            return False
        # Buchen, bevor der Faktor gilt: Wer den Schritt nicht mehr bekommt, war der Zweite.
        return self.store.totp_step_verbrauchen(user_id, schritt)

    def totp_begin(self, user_id):
        """Die Einrichtung starten: liefert Geheimnis und `otpauth://`-Adresse für den
        Authenticator — und wirft neu `StateError` (kein `ConfigError`, kein stiller Erfolg),
        wenn das Konto bereits ein bestätigtes TOTP hat.

        **Nur solange kein bestätigtes TOTP existiert.** Bis 0.18.0 überschrieb jeder Aufruf das
        Geheimnis und setzte `confirmed` zurück: Ein bestätigter zweiter Faktor fiel damit still
        weg, die Recovery-Codes blieben verwaist liegen, und die Sitzung galt danach allein mit
        dem Passwort als vollwertig. Weil `GET /auth/totp/setup` diese Methode unbedingt rief,
        genügte dafür ein Klick auf einen fremden Link — ein GET trägt kein CSRF-Token, und
        `SameSite=Lax` (Vorgabe) schickt das Sitzungscookie bei einer Top-Level-Navigation mit
        (Fund B2-1). Wer den Authenticator wechseln will, schaltet TOTP regulär ab
        (`totp_disable` — CSRF-geschützt und protokolliert) und richtet es neu ein.

        Ein laufender, noch **unbestätigter** Versuch wird weiterhin durch einen frischen
        ersetzt: Dort ist nichts zu verlieren, und ein einmal ausgegebenes Geheimnis
        weiterzureichen wäre schlechter als ein neues.
        """
        if self.store.has_confirmed_totp(user_id):
            # Der Versuch selbst ist die interessante Zeile: Bis 0.18.0 hinterliess dieser Weg
            # keine Spur, obwohl er den zweiten Faktor entfernte.
            self.audit("totp_setup_denied", detail=f"user={user_id} grund=bereits_bestaetigt")
            raise StateError(
                f"Konto {user_id} hat bereits ein bestätigtes TOTP — erst abschalten "
                f"(totp_disable), dann neu einrichten.")
        u = self.store.get_user(user_id)
        if u is None:
            raise ConfigError(f"Kein Konto mit der ID {user_id} — TOTP lässt sich nicht einrichten.")
        # Recovery-Codes ohne bestätigtes TOTP gehören zu einem Geheimnis, das niemand mehr hat.
        # Sie liegen zu lassen hiesse, den zweiten Faktor über Codes offen zu halten, die zur
        # neuen Einrichtung nicht passen.
        verwaist = self.store.count_recovery_codes(user_id)
        if verwaist:
            self.store.delete_recovery_codes(user_id)
            self.audit("recovery_verwaist_geloescht", detail=f"user={user_id} n={verwaist}")
        secret = _totp.new_secret()
        self.store.set_totp(user_id, secret, confirmed=False)
        self.audit("totp_setup_start", detail=f"user={user_id}")
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
    #: Zufallsbytes je Hälfte eines Recovery-Codes. Zwei Hälften à 7 Byte = **112 Bit**.
    #: Vorher waren es 3 Byte (48 Bit), dann 4 (64). Beides ist für einen Code zu knapp, der den
    #: zweiten Faktor ERSETZT und unbegrenzt gültig bleibt: Ein TOTP-Code hat zwar nur eine
    #: Million Möglichkeiten, gilt aber 30 Sekunden — ein Recovery-Code gilt, bis er benutzt wird.
    #: 112 Bit ist die Schwelle, ab der NIST SP 800-63B für ein „look-up secret" einen einfachen
    #: Einweg-Hash genügen lässt; darunter verlangt es Salt und ein Passwort-Hashverfahren. Da
    #: die Codes hier mit sha256 liegen, ist die Schwelle die richtige Wahl.
    #: Bestehende Codes bleiben gültig (gespeichert wird ohnehin nur der Hash); neu erzeugte
    #: sind länger.
    RECOVERY_BYTES = 7

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
        gleiche Meldung (keine Enumeration). `base_url` wird geprüft (`ConfigError` bei einem
        fremden Host, siehe `magic_url`).

        Geprüft wird als Erstes — vor der Kontosuche, damit „Ausnahme statt False" nicht
        verrät, ob es die Adresse gibt, und vor der Token-Vergabe, damit kein unbrauchbarer
        Token zurückbleibt.
        """
        base_url = self._gepruefte_basis(base_url)
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
        if self.cfg.csrf_enabled and not self._csrf_entbehrlich(request):
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

    def _csrf_entbehrlich(self, request: Request) -> bool:
        """Darf dieser Request die CSRF-Prüfung überspringen?

        Nur dann, wenn er **tatsächlich per API-Key** angemeldet ist. Bis zum zweiten Audit
        genügte dafür, dass `_extract_api_key()` irgendetwas zurückgab — der Wert wurde nicht
        geprüft, und ob überhaupt ein Key benutzt wurde, auch nicht. Ein beliebiger Header
        `X-API-Key: erfunden` schaltete die Prüfung also ab, die Anmeldung lief danach über das
        **Sitzungs-Cookie** weiter (`current_user` fragt die Sitzung zuerst), und das sogar bei
        `apikey_enabled=False`. Der Mechanismus, auf dem der CSRF-Schutz ruht, war damit vom
        Aufrufer abschaltbar.

        Der Grund für die Ausnahme bleibt richtig: Eine fremde Seite kann ohne CORS-Freigabe
        keinen eigenen Header setzen, und ein Daemon hat kein Cookie. Nur muss der Key echt
        sein — und wo eine Sitzung mitläuft, zählt die Sitzung.
        """
        if not self.cfg.apikey_enabled:
            return False
        key = self._extract_api_key(request)
        if not key:
            return False
        if self.store.get_session(request.cookies.get(self.cfg.session_cookie) or ""):
            return False        # Cookie im Spiel → CSRF gilt, egal was im Header steht
        return self.verify_api_key(key)[0] is not None

    def require_csrf(self, request: Request, submitted):
        """Für Formular-POSTs: wirft 403, wenn der CSRF-Token fehlt/nicht passt.

        Ausgenommen sind nur Requests, die wirklich per API-Key angemeldet sind — s.
        `_csrf_entbehrlich`."""
        if self.cfg.csrf_enabled and not self._csrf_entbehrlich(request) \
                and not self.verify_csrf(request, submitted):
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
        """Der Link, den der Empfänger anklickt — Pfad je nach Zweck (`TOKEN_PATHS`). `base_url`
        wird geprüft: ein fremder Host wirft `ConfigError` — in einer Route liefert
        `public_base(request)` die geprüfte Basis.

        Die Prüfung sitzt hier, weil hier alle vier Mail-Wege zusammenlaufen: Reset,
        Anmelde-Link, Bestätigung und Einladung. Damit gilt der Schutz unabhängig davon, wer die
        Route baut — auch für eine App mit eigenem Formular. Erlaubt sind `base_url`, ein Host
        aus `trusted_redirect_hosts` und Loopback.
        """
        from urllib.parse import quote
        pfad = self.TOKEN_PATHS[purpose].format(t=quote(str(raw), safe=""))
        return f"{self._gepruefte_basis(base_url)}{pfad}"

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
        vorgesehenen Rollen/Adminrechte; eingelöst wird er erst bei der Registrierung. `base_url`
        wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

        Geprüft wird vor der Token-Vergabe, damit ein abgewiesener Aufruf keinen
        Einladungs-Token hinterlässt.
        """
        base_url = self._gepruefte_basis(base_url)
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
        """Den Bestätigungslink für eine Adresse verschicken. False, wenn kein Mailer da ist.
        `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).
        """
        base_url = self._gepruefte_basis(base_url)
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
        Rückgabe nur intern — nach außen immer dieselbe Meldung (keine User-Enumeration).
        `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

        Geprüft wird als Erstes — vor der Kontosuche, damit die Ausnahme keine Adresse verrät.
        """
        base_url = self._gepruefte_basis(base_url)
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

    def apply_factor(self, request, user_id, factor, ip=None, ua=None, remember=True,
                     email_bestaetigt: Optional[bool] = None) -> tuple[str, bool, bool]:
        """Einen bestätigten Faktor anwenden: an die laufende Sitzung desselben Users anhängen
        (Ketten-Schritt) ODER eine neue Sitzung starten (Erstfaktor/Identitätswechsel).
        Gibt (token, session_ok, is_new). Bei is_new muss der Aufrufer set_cookie(resp, token) rufen.

        `email_bestaetigt` reicht ein föderierter Weg durch (OIDC: Claim `email_verified`;
        SAML und LDAP kennen keinen Beleg und reichen `False` durch) — hier entscheidet sich
        der Erst-Admin, und eine unbelegte Adresse darf ihn nicht tragen. Der Faktor geht
        mit an `maybe_promote_admin`: Für einen föderierten Faktor gilt dort fail-closed,
        ein vergessenes Argument befördert also nicht."""
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
            self.maybe_promote_admin(self.store.get_user(user_id), email_bestaetigt,
                                     faktor=factor)
            if ok and not was_ok:
                u = self.store.get_user(user_id)
                self.store.audit_log("login", u["username"] if u else None, s["ip"], factor)
                # **Neues Token beim Rechtewechsel.** Die Sitzung wird hier vom halben Login
                # zur vollwertigen — OWASP Session Management Cheat Sheet: „The session ID must
                # be renewed or regenerated by the web application after any privilege level
                # change." Vorher behielt sie ihr Token: Wer dem Opfer vor dem Login ein Cookie
                # setzen konnte (Subdomain, Klartext-HTTP), hielt nach dessen zweitem Faktor
                # eine voll authentisierte Sitzung.
                neu_token = self.store.create_session(
                    user_id, self._ttl(bool(s["remember"])), True, s["method"],
                    s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
                self.store.delete_session_by_handle(s["token_hash"])
                return neu_token, ok, True      # is_new → der Aufrufer setzt das Cookie neu
            # Zurück geht das Klartext-Token aus dem Cookie — der Aufrufer baut daraus
            # Redirects und Cookies. In der Sitzungs-Zeile steht nur noch das Handle.
            return request.cookies.get(self.cfg.session_cookie), ok, False
        token, ok = self.start_session(user_id, factor, ip, ua, remember)
        self.maybe_promote_admin(self.store.get_user(user_id), email_bestaetigt, faktor=factor)
        return token, ok, True

    def login_redirect_after(self, request, token, user_id, nxt):
        """Zielredirect nach einem Faktor: nxt wenn Sitzung komplett, sonst Eingabeseite des nächsten Faktors."""
        s = self.store.get_session(token)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if s and s["mfa_ok"]:
            return nxt
        step = self.next_login_step(user_id, done)
        return self.factor_entry(step, nxt) if step else nxt

    def complete_totp(self, token) -> Optional[str]:
        """Den TOTP-Schritt abschließen: Faktor `totp` an die laufende Sitzung anhängen.

        Gibt ein **neues Sitzungs-Token** zurück, wenn die Sitzung dadurch vollwertig wird —
        dann gehört es ins Cookie. Sonst `None` (nichts zu tun).

        Heißt seit 0.18.0 so, weil der alte Name `complete_mfa` mehr versprach, als die Methode
        tut — MFA ist die ganze Kette, hier geht es um genau einen Faktor. `complete_mfa` bleibt
        als Alias bestehen und wird nicht entfernt; ein Umbenennen, das bestehende Aufrufe
        bricht, wäre den Gewinn nicht wert.
        """
        s = self.store.get_session(token)
        if not s:
            return None
        war_ok = bool(s["mfa_ok"])
        done = json.loads(s["factors_done"] or "[]")
        if "totp" not in done:
            done.append("totp")
        ok = self._session_ok(s["user_id"], done)
        self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
        if ok:
            u = self.store.get_user(s["user_id"])
            self.store.audit_log("login", u["username"] if u else None, s["ip"], "totp")
        if ok and not war_ok:
            # Rechtewechsel → neues Token (OWASP Session Management). Gibt es zurück, damit der
            # Aufrufer das Cookie setzen kann; wer den Rückgabewert ignoriert, behält das alte
            # Verhalten, denn die Sitzung wandert mit.
            neu_token = self.store.create_session(
                s["user_id"], self._ttl(bool(s["remember"])), True, s["method"],
                s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
            self.store.delete_session_by_handle(s["token_hash"])
            return neu_token
        return None

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

    def totp_enrollment_user(self, request) -> Optional[dict]:
        """Wer darf TOTP einrichten, **ohne** schon voll angemeldet zu sein? Sonst None.

        Genau eine Lage: Die globale `login_chain` verlangt `totp`, der Nutzer hat seinen
        Erstfaktor erbracht (die Sitzung hängt im MFA-Schritt) und noch kein bestätigtes TOTP.

        Ohne diesen Weg ist `login_chain=["password","totp"]` für jedes Konto ohne eingerichtetes
        TOTP eine **Sackgasse**: Das richtige Passwort führt auf `/auth/totp`, das mangels
        Geheimnis auf die Login-Seite zurückleitet — und die Einrichtungsseite verlangte einen
        voll angemeldeten Nutzer, den es unter dieser Kette nie geben kann. Das Konto kam weder
        herein noch an die Einrichtung; der Betreiber musste an die Datenbank.

        Sicherheitlich ist das kein Nachlass: Wer hier steht, hat den Erstfaktor bereits erbracht,
        und ohne die Kette (klassischer Modus) hätte ihn dasselbe Passwort ohnehin vollständig
        angemeldet. Die Einrichtung allein meldet niemanden an — der Faktor gilt erst, wenn im
        nächsten Schritt ein Code aus dem frischen Geheimnis stimmt.
        """
        u = self.pending_user(request)
        if not u or self.store.has_confirmed_totp(u["id"]):
            return None
        req, _ = self._global_chain()
        return u if req and "totp" in req else None

    def csrf_rotieren(self, response) -> str:
        """Ein frisches CSRF-Token setzen — beim Login.

        Das naive Double-Submit gilt als anfällig gegen *cookie injection*: Wer über eine
        Subdomain ein Cookie setzen kann, setzt ein passendes CSRF-Paar gleich mit. Das OWASP
        CSRF Prevention Cheat Sheet empfiehlt deshalb eine Bindung an „a session-dependent value
        that changes with each login". Das Token beim Anmelden zu erneuern ist davon der billige
        Teil und kostet nichts.
        """
        return self.issue_csrf(response)

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
    #
    # `login=False` für die Abweisungen der Nicht-Login-Töpfe: Die tragen das andere
    # Ereigniswort (`security.LOG_PRUEFUNG`) und laufen damit an der mitgelieferten Jail
    # vorbei — sonst bannte ein angemeldeter Nutzer sich mit ein paar Tippfehlern auf der
    # eigenen Kontoseite selbst auf Firewall-Ebene aus, und jeder weitere Klick nach der
    # App-Sperre beschleunigte den Bann noch (Begründung bei `security.LOG_ANMELDUNG`).
    def _abgewiesen(self, username, ip, grund: str, login: bool = True):
        wort = security.LOG_ANMELDUNG if login else security.LOG_PRUEFUNG
        security.seclog.warning("%s user=%s ip=%s method=blocked reason=%s", wort,
                                security.fuer_log(username) or "-", security.fuer_log(ip), grund)

    def rate_ok(self, ip) -> bool:
        """Darf diese IP noch? Ein Nein schreibt eine Zeile ins Sicherheits-Log (fail2ban liest mit)."""
        erlaubt = self.rl.allow(ip or "?", self.sec("rate_limit_max"), self.sec("rate_limit_window_sec"))
        if not erlaubt:
            self._abgewiesen(None, ip, "ratelimit")
        return erlaubt

    def is_locked(self, username, ip) -> bool:
        """Zu viele Fehlversuche im Fenster — pro User ODER pro IP (IP-Schwelle höher wg. NAT).

        Gezählt wird alles in `login_attempt`, was ein **Anmeldeversuch** war; die Methoden aus
        `security.NICHT_LOGIN_METHODEN` bleiben draussen. Sonst sperrt ein Fehlgriff, der gar
        keine Anmeldung war, die Anmeldung mit — und zwar für einen Nutzer, der die Sperre nicht
        abtragen kann (ein Erfolg räumt nur die eigene Methode weg). Der Zähler dieser Methoden
        geht nicht verloren, er hat nur seinen eigenen Topf (z.B. `is_password_change_locked`).
        """
        since = int(time.time()) - self.sec("lockout_window_sec")
        ohne = security.NICHT_LOGIN_METHODEN
        if username and self.store.count_fails(since, username=username,
                                               exclude_methods=ohne) >= self.sec("max_login_attempts"):
            self._abgewiesen(username, ip, "lockout_user")
            return True
        if ip and self.store.count_fails(since, ip=ip, exclude_methods=ohne) >= \
                self.sec("max_login_attempts") * self.sec("ip_attempt_factor"):
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
            # Der GRUND gehört ins serverseitige Protokoll. Die HTTP-Antwort bleibt bewusst
            # gleich (keine Konto-Erkundung) — im Audit-Log liest aber nur der Betreiber mit,
            # und ihm sagten „falsches Passwort", „Konto deaktiviert" und „Benutzername
            # vertippt" bisher dasselbe: `login_fail … password`. Das ist der häufigste
            # Supportfall, und er war mit Bordmitteln nicht zu beantworten.
            self.store.audit_log("login_fail", username, ip,
                                 f"{method} grund={self._fehl_grund(username)}")
            # fail2ban parst diese Zeile (ip=…)
            # `fuer_log`: Der Benutzername kommt aus einem Formularfeld. Ungefiltert liess
            # sich damit eine zweite Logzeile mit fremder IP erzeugen und fail2ban gegen Dritte
            # richten (belegt gegen echtes fail2ban 1.1.1).
            # Das Ereigniswort trennt Anmeldeversuche von allem anderen: Nur `failed login`
            # trifft die mitgelieferte failregex. Ein Fehlgriff am Passwortwechsel, an der
            # Step-up-Seite oder an einer Bereichs-PIN ist keine Anmeldung und darf keinen
            # legitimen, angemeldeten Nutzer auf Firewall-Ebene aussperren (siehe
            # `security.log_ereignis`).
            security.seclog.warning("%s user=%s ip=%s method=%s", security.log_ereignis(method),
                                    security.fuer_log(username), security.fuer_log(ip), method)

    def _fehl_grund(self, username) -> str:
        """Warum ist die Anmeldung gescheitert — für das Protokoll, nicht für die Antwort."""
        u = self.find_user(username)
        if not u:
            return "kein_konto"
        if u["disabled"]:
            return "konto_gesperrt"
        if not self.store.get_password_hash(u["id"]) and not self.store.has_pin(u["id"]):
            return "kein_passwort_gesetzt"
        return "falsches_geheimnis"

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

        Die Basis kommt aus `public_base()`, also aus derselben einen Regel wie überall:
        `base_url` gewinnt (die Header werden dann gar nicht erst gelesen), sonst zählt ein
        abgeleiteter Host nur aus `trusted_redirect_hosts` oder Loopback, sonst bleibt "".
        **Die eine Ausnahme ist der Absatz oben** und sie ist bewusst: ohne `cookie_domain`
        darf der angefragte — mitvertraute — Host die Login-Seite an sich ziehen, sonst dreht
        sich die Anmeldung im Kreis. `konfigpruefung` sagt diesen Fall beim Start an.
        """
        from urllib.parse import quote, urlsplit
        kandidat = ""
        if not self.cfg.base_url and request is not None:
            h = request.headers
            proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
            host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc).split(",")[0].strip()
            # Auch hier gilt R4-01: Host und X-Forwarded-Host kommen vom Anfragenden. Hält die
            # abgeleitete Basis der Prüfung nicht stand, bleibt die Login-URL relativ — der
            # Browser löst sie gegen den aufgerufenen Host auf, ein fremder Name kommt so
            # nicht in die Umleitung.
            kandidat = f"{proto}://{host}" if host else ""
        base = self.public_base(kandidat=kandidat)
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

    def public_base(self, request: Optional[Request] = None, kandidat: str = "") -> str:
        """Die öffentliche Basis-URL für alles, was das Haus verlässt — Mail-Links,
        Redirect-URIs, SAML-Metadaten. Leer heißt: es gibt keine, der Aufrufer bricht ab.

        Bis 0.18.0 leiteten zehn Stellen diese Adresse selbst aus der Anfrage ab — sechsmal als
        `cfg.base_url or str(request.base_url)` (Magic-Link, Reset, Bestätigung, OIDC-Post-Logout,
        OIDC-Redirect-URI, Admin-Einladung), dreimal für SAML und einmal in der Forward-Auth-
        Umleitung. Der abgeleitete Teil ist der rohe `Host`-Header und damit eine Eingabe des
        Angreifers: Wer für ein
        fremdes Postfach „Passwort vergessen" anstößt und dabei `Host: angreifer.example`
        setzt, ließ TinySesam eine echte Mail mit einem echten Reset-Token verschicken, deren
        Link auf den Server des Angreifers zeigte (R4-01/R8-4, CWE-644). `trusted_redirect_hosts`
        schützte nur `?next=`, nicht diesen Weg.

        Jetzt gilt: `base_url` gewinnt immer — steht sie, kommt gar nichts aus dem Request.
        Sonst wird der abgeleitete Host geprüft (`security.eigener_host`), und nur ein
        Host aus `trusted_redirect_hosts` oder eine Loopback-Adresse zählt als der eigene.

        **Dies ist die einzige Stelle, an der diese Frage entschieden wird.**
        `require_public_base()` und `_gepruefte_basis()` rufen sie beide und machen nur aus dem
        leeren Ergebnis einen Fehler — mit dem Text, der zu ihrem Aufrufer passt.
        `forward_login_url()` fragt ebenfalls hier (mit seiner einen, im Docstring dort
        begründeten Ausnahme). Zwei Fassungen derselben Regel liefen auseinander, sobald mehrere
        eigene Namen im Spiel waren: Die Routen hielten `base_url`, der Weg über die Methoden
        ließ den `Host`-Header auswählen — und die Lücke saß genau im Unterschied.

        `kandidat` erlaubt einer Route, eine anders abgeleitete Basis prüfen zu lassen (SAML
        wertet `X-Forwarded-Proto/Host` selbst aus) — geprüft wird sie nach derselben Regel.

        **Der Pfadanteil gehört dazu**, aus beiden Quellen: `base_url="https://example.com/sso"`
        behält ihr Präfix, und eine abgeleitete Basis übernimmt den `root_path` des Servers
        (`security.sichere_basis`). Ohne das bekam eine unter einem Unterpfad montierte App
        Mail-Links ohne Präfix — und wer ihn danach noch einmal anhängt, Links mit vierfachem.
        Das Ergebnis ist die **fertige** Basis: Es wird nichts mehr daran angefügt.

        Die Zusage reicht so weit und nicht weiter: **die verschickten Links** tragen den
        Unterpfad. Die eingebauten Seiten tragen ihn nicht (ihre Ziele stehen wurzel-absolut in
        `templates.py`) — siehe `backlog/T-15-unterpfad-montage.md`.

        Wer eine Basis braucht und ohne sie nicht weiterarbeiten darf, nimmt
        `require_public_base()` — diese Methode hier gibt "" zurück und überlässt die
        Entscheidung dem Aufrufer. Genau zwei Stellen dürfen das, weil beide einen tragfähigen
        Rückweg haben: der OIDC-Post-Logout (ohne Basis entfällt der Provider-Umweg, der lokale
        Logout läuft trotzdem) und `forward_login_url()` (ohne Basis bleibt die Umleitung
        relativ, der Browser löst sie gegen den aufgerufenen Host auf).
        """
        if self.cfg.base_url:
            return str(self.cfg.base_url).rstrip("/")
        roh = str(kandidat or (str(request.base_url) if request is not None else "")).strip()
        basis = security.sichere_basis(roh, self.cfg.trusted_redirect_hosts)
        if not basis and roh and security.einmal_melden("public_base:" + _host_aus(roh)):
            # Einmal laut sagen, warum nichts passiert — sonst sucht der Betreiber den Fehler
            # beim Mailer. fail2ban liest diesen Logger mit, und der Forward-Auth fragt hier bei
            # JEDER anonymen Anfrage nach (ein Seitenaufruf sind zwanzig Unterressourcen): Ein
            # Sturm gleicher Zeilen wäre selbst ein Befund, deshalb sagt `einmal_melden()` es
            # einmal je Prozess und Host — der Hinweis auf base_url steht in der Zeile.
            security.seclog.warning(
                "Kein vertrauenswürdiger öffentlicher Host: %s stammt aus dem Host-Header und "
                "steht weder in trusted_redirect_hosts noch ist er Loopback. Der Vorgang bricht "
                "ab (sonst ginge ein Link auf einen fremden Host hinaus). Abhilfe: base_url "
                "setzen. Diese Zeile kommt einmal je Host, nicht je Anfrage.",
                security.fuer_log(roh))
        return basis

    def require_public_base(self, request: Optional[Request] = None, kandidat: str = "") -> str:
        """Wie `public_base()`, nur ohne Rückweg: keine geprüfte Basis → `ConfigError`.

        Für jeden Weg, der eine absolute Adresse **in fremde Hand** gibt: Link in einer Mail,
        Redirect-URI beim IdP, Entity-ID in SAML-Metadaten.

        Bis 0.18.x war das an jeder Stelle anders gelöst, und zwei Stellen lösten es falsch:
        `/auth/forgot` und `/auth/magic/request` schrieben bei fehlender Basis nur eine
        Audit-Zeile und rendeten **weiter die Erfolgsseite** — HTTP 200, „Mail ist unterwegs",
        keine Mail. Dieselbe Antwort verhindert die Benutzer-Enumeration, und genau deshalb
        verdeckte sie hier den Totalausfall: Passwort-Reset und Magic-Link waren für alle Nutzer
        kaputt, sichtbar nur im Log. Die übrigen Stellen warfen `HTTPException(500)` — richtig
        im Ergebnis, aber ein Serverfehler mitten im Anmeldeversuch, obwohl schon beim Aufbau
        feststand, dass es nicht gehen kann.

        Beides ist weg. `konfigpruefung` macht `base_url` zur Pflicht, sobald einer dieser Wege
        an ist — der Aufbau scheitert also, bevor ein Nutzer auf „Passwort vergessen" klickt.
        Diese Methode ist das zweite Schloss für den Rest: eine Config, die nach dem Konstruktor
        geändert wurde (sie wird zur Request-Zeit gelesen). Dann bricht der Vorgang mit einer
        Meldung ab, die sagt, was einzutragen ist — nicht mit stillem Erfolg.
        """
        basis = self.public_base(request, kandidat)
        if not basis:
            raise ConfigError(
                "Keine vertrauenswürdige öffentliche Adresse: base_url ist leer, und der Host "
                "aus der Anfrage ist nicht als eigener belegt (er steht nicht in "
                "trusted_redirect_hosts und ist keine Loopback-Adresse). Aus dem Host-Header "
                "wird hier nichts geraten — er ist eine Eingabe des Anfragenden, und bei einer "
                "Mail an ein fremdes Postfach ist das der Angreifer (R4-01). Abhilfe: base_url "
                "auf die öffentliche Adresse dieser App setzen, z.B. "
                "base_url=\"https://auth.example.com\"; unter einem Unterpfad montiert mit "
                "Präfix (\"https://example.com/sso\").")
        return basis

    def _gepruefte_basis(self, base_url) -> str:
        """Eine von AUSSEN übergebene Basis-Adresse prüfen, bevor sie in einen Link wandert.

        `public_base()` sitzt in den Routen — wer TinySesam einbettet, baut sein „Passwort
        vergessen"-Formular aber oft selbst und ruft dann `send_password_reset(mail, basis)`
        auf. Folgte diese App dem naheliegenden Muster `str(request.base_url)`, war sie R4-01
        voll ausgesetzt, obwohl die eingebaute Route längst abriegelte: Die Prüfung stand nur
        in der Route, nicht in der Methode. Deshalb prüft jetzt jeder Weg, der einen Link
        verschickt, seine Basis selbst — `magic_url()` und die vier Absender darüber.

        Es ist **dieselbe eine Regel** — diese Methode ruft `public_base()` und macht aus dem
        leeren Ergebnis einen Fehler, so wie `require_public_base()` es für die Routen tut.
        Der Unterschied liegt nur im Text der Ausnahme, der vom übergebenen Wert spricht:

        * Steht `cfg.base_url`, **gewinnt sie unbedingt** — mit Schema und Pfadanteil. Die
          übergebene Basis kommt gar nicht zum Zug. Das fängt auch den Fall, in dem hinter einem
          TLS-terminierenden Proxy `str(request.base_url)` ein `http://` liefert (der Link bliebe
          sonst still unverschlüsselt) **und** den Fall mehrerer mitvertrauter Namen: Bis zur
          zweiten Nacharbeit gewann `base_url` hier nur, wenn der übergebene Host zufällig
          derselbe war; sonst entschied `trusted_redirect_hosts`. Damit konnte der `Host`-Header
          weiter *auswählen*, welcher der eigenen Namen in den Reset-Link kommt — genau der Kern
          von R4-01, nur eine Ebene tiefer.
        * Ohne `base_url` muss der Host aus `trusted_redirect_hosts` kommen oder Loopback sein
          (`security.sichere_basis`). Ein Pfad in der Basis bleibt erhalten (App unter einem
          Unterpfad montiert), eine Benutzerangabe im Host nicht.
        * Alles andere ist ein Fremdname → `ConfigError`. Kein Token, keine Mail, ein Fehler,
          den der Entwickler beim ersten Versuch sieht — statt eines Links, den das Opfer
          anklickt.

        **Idempotent**, und das ist keine Feinheit: Die vier Absender prüfen ihre Basis vor der
        Token-Vergabe, `magic_url()` prüft sie noch einmal, weil dort auch eine App landet, die
        nur diese eine Methode ruft. Die erste Fassung hängte den Pfadanteil dabei jedes Mal neu
        an eine Basis, die ihn schon trug (`sichere_basis()` gibt ihn seit N1 mit zurück) — aus
        `https://example.com/portal` wurde über vier Stationen
        `https://example.com/portal/portal/portal/portal/auth/reset?token=…`. Die Mail ging
        hinaus, der Empfänger klickte, der Link war 404: kein Fehler, keine Logzeile. Deshalb
        wird hier nichts mehr angehängt, und ein Test schickt eine Basis MIT Pfad durch alle
        fünf Wege und **zählt** die Vorkommen des Präfixes.
        """
        roh = str(base_url or "").strip()
        basis = self.public_base(kandidat=roh)
        # Ersetzt wird still — aber nicht lautlos: Wer eine andere Adresse übergibt als die, die
        # am Ende im Link steht, hat entweder den Request durchgereicht (dann ist das genau der
        # Schutz) oder sich vertan (dann sucht er sonst lange). Einmal je Host, nicht je Anfrage:
        # der Wert kommt bei diesem Muster aus dem `Host`-Header.
        if basis and roh and _host_aus(roh) and _host_aus(roh) != _host_aus(basis) \
                and security.einmal_melden("gepruefte_basis:" + _host_aus(roh)):
            security.seclog.warning(
                "Übergebene Basis-Adresse %s wird durch base_url (%s) ersetzt — base_url ist die "
                "Zusage des Betreibers und gewinnt immer. Kommt der Wert aus str(request.base_url), "
                "ist es der Host-Header des Anfragenden; genau darüber zeigte ein Reset-Link auf "
                "einen fremden Server (R4-01). Diese Zeile kommt einmal je Host, nicht je Anfrage.",
                security.fuer_log(roh), security.fuer_log(basis))
        if not basis:
            # Geloggt hat `public_base()` bereits (einmal je Host). Im Text der Ausnahme steht
            # die gekürzte, von Steuerzeichen befreite Fassung: Der Wert kommt vom Anfragenden,
            # und eine Ausnahme wandert in Protokolle und Fehlerseiten.
            raise ConfigError(
                f"Diese Basis-Adresse geht nicht in einen verschickten Link: "
                f"{security.fuer_log(roh)!r}. Erlaubt "
                "sind base_url, ein Host aus trusted_redirect_hosts und Loopback. Wer die Basis "
                "aus dem Request nimmt, nimmt den Host-Header des Anfragenden — bei einer Mail an "
                "ein fremdes Postfach also den des Angreifers. In einer Route liefert "
                "auth.public_base(request) die geprüfte Basis (leer = abbrechen).")
        return basis

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

    def login_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
        """True, wenn die **Anmeldung** höchstens `stepup_max_age_sec` zurückliegt.

        Die schwächere Schwester von `stepup_fresh()`: gemessen wird nicht die letzte
        Faktor-Bestätigung, sondern das Alter der Sitzung (`created_at`, also der Login).

        Gedacht für genau eine Lage — ein Konto, das **keinen** Faktor hat, mit dem es
        bestätigen könnte (`stepup_options()` leer, rein föderiertes Konto ohne Passwort, PIN
        und TOTP). Für das Anlegen des ERSTEN Faktors kann die Schranke dort nicht an der
        Bestätigung hängen, sonst ist die Einrichtung eine Sackgasse: Nach Ablauf des Fensters
        antwortete `/auth/pin/set` mit 403, und die Reauth-Seite bot ein Passwortfeld an, das
        dieses Konto nicht hat. Ein API-Key ist auch hier nichts wert.
        """
        user = user or self.current_user(request)
        if not user or user.get("_via") == "apikey":
            return False
        s = self.session_from_request(request)
        if not s:
            return False
        if self.cfg.stepup_max_age_sec > 0:
            if (int(time.time()) - (s["created_at"] or 0)) > self.cfg.stepup_max_age_sec:
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
        if not self._chain_satisfied(factors, strict, done):
            self._redirect_factor(request, self._next_factor(factors, strict, done))
        d = dict(usr)
        d["_via"] = "session"
        return d

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

    def require_session(self, request: Request, user: Optional[dict] = None) -> dict:
        """Eingeloggt — und zwar **interaktiv**: eine Sitzung ja, ein API-Key nein (403).

        Der Riegel für die **Anlage** eines Faktors (TOTP einrichten, Passkey registrieren,
        erste PIN). `require_mfa()` deckte nur den Abbau; die Anlage hing weiter an
        `current_user()`, und das akzeptiert einen API-Key. Ein abgeflossener CI-Key richtete
        damit einen Faktor ein, den **er** kontrolliert: das TOTP-Geheimnis steht in der Antwort
        von `GET /auth/totp/setup`, und ein selbst registrierter Passkey ist ein vollwertiger
        Login — über ihn kam der Key an eine frische interaktive Sitzung und damit doch an die
        `require_mfa()`-Routen. Die Enrollment-Route war der Hebel, der die Sperre aushob.

        Geprüft wird auf `_via == "apikey"`, nicht auf `_via == "session"`: Bei der
        TOTP-Einrichtung unter `login_chain=["password","totp"]` steht dort ein Nutzer aus
        `totp_enrollment_user()` — eine Sitzung, die ihren Erstfaktor erbracht hat, aber noch
        nicht vollständig angemeldet ist. Die darf einrichten, ein Maschinen-Credential nicht.
        (Die Schlüssel-Verwaltung prüft umgekehrt auf `"session"` — sie kennt keinen solchen
        Zwischenzustand und bleibt lieber fail-closed.)
        """
        u = user or self.current_user(request)
        if not u:
            self._deny(request)
        if u.get("_via") == "apikey":
            raise HTTPException(403, self.t("api.needs_session"))
        return u

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

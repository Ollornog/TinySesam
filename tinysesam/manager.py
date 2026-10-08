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
import json
import hashlib
import html as _html
import secrets
import sqlite3
import time
import warnings
import contextvars
from typing import Any, Callable, Literal, NoReturn, Optional, cast

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from . import konfigpruefung
from .errors import ConfigError, StateError
from .config import TinySesamConfig
from .store import (Store, key_kind_of, name_ungueltig, norm_email, norm_kennung, jetzt as _jetzt,
                    payload_lesen, valid_email, versuchsfrist as _versuchsfrist)
from .passwords import hash_password, verify_password, needs_rehash, dummy_verify
from . import passwords as _passwords
from . import passwords as _pw
from .templates import PRAEFIX_PLATZHALTER as _PRAEFIX_PLATZHALTER, Templates, inject_nonce as _inject_nonce
from . import totp as _totp
from . import security
from .ldap_ import VERBINDUNGS_TIMEOUT as _LDAP_TIMEOUT
from ._veraltet import Veraltet
from .login_result import LoginResult
from .password_change_result import PasswordChangeResult

#: IP und angemeldetes Konto der Anfrage, die gerade bearbeitet wird (B5-02, B5-04).
#:
#: Die Konto-Methoden (`totp_disable`, `create_api_key`, `create_invite`, …) bekommen keinen
#: Request — sie sind auch ohne einen aufrufbar. Ihre Audit-Zeilen standen deshalb ohne IP und
#: ohne Konto da (`detail="user=5"`), und `tinysesam audit --user X` fand sie nicht. Gesetzt
#: wird der Wert dort, wo TinySesam die Anfrage ohnehin auflöst (`current_user` und
#: Verwandte); `audit()` liest ihn. Ein ContextVar, keine Instanzvariable: Er gilt je Anfrage
#: (je asyncio-Task bzw. je Threadpool-Aufruf) und kann nicht in eine parallele überlaufen.
_ANFRAGE: contextvars.ContextVar = contextvars.ContextVar("tinysesam_anfrage", default=None)


# Setzt nonce="…" in jedes <script>/<style>, das noch keins hat. Zentral, statt den Nonce
# durch jede Template-Funktion zu faedeln. Sicher, weil keine der eingebauten Seiten den
# String "<script"/"<style" INNERHALB eines JS-Strings ausgibt (geprueft) — nur echte Tags.


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


class _DictKopfzeilen:
    """Die drei Zugriffe, die `_kopfzeilen_in` braucht, über einem gewöhnlichen dict.

    Nachsehen ohne Rücksicht auf Groß-/Kleinschreibung, Schreiben auf den Schlüssel, der schon da
    ist — sonst unter der übergebenen Schreibweise. So bleibt `exc.headers["Location"]` lesbar.
    """
    def __init__(self, d: dict):
        self.d = d

    def _schluessel(self, name: str):
        return next((k for k in self.d if k.lower() == name.lower()), None)

    def get(self, name: str, vorgabe=None):
        k = self._schluessel(name)
        return vorgabe if k is None else self.d[k]

    def setdefault(self, name: str, wert: str):
        if self._schluessel(name) is None:
            self.d[name] = wert

    def __setitem__(self, name: str, wert: str):
        self.d[self._schluessel(name) or name] = wert


def _dn_teile(wert: str) -> list[str]:
    """Einen DN an den UNmaskierten Kommas zerlegen (`cn=a\\,b,ou=x` hat zwei Teile, nicht drei)."""
    teile, aktuell, maskiert = [], [], False
    for zeichen in str(wert):
        if maskiert:
            aktuell.append(zeichen)
            maskiert = False
        elif zeichen == "\\":
            aktuell.append(zeichen)
            maskiert = True
        elif zeichen == ",":
            teile.append("".join(aktuell).strip())
            aktuell = []
        else:
            aktuell.append(zeichen)
    teile.append("".join(aktuell).strip())
    return teile


def gruppe_passt(schluessel, gruppe, teilstring: bool = False, dn: bool = False) -> bool:
    """Passt der Schlüssel aus `*_group_role_map`/`ldap_allowed_groups` auf diese Gruppe?

    `teilstring=True` ist der alte Vergleich (`schluessel in gruppe`) und nur noch auf
    ausdrücklichen Wunsch da (`group_match="substring"`). Bis 0.19.x galt er für LDAP IMMER,
    egal was `group_match` sagte (F-19): `admin` passte dann auf `cn=nicht-admin,…` und
    `staff` auf `cn=staffextern,…` — wer im Verzeichnis eine Gruppe benennen darf, bekam
    Rolle und Admin-Flag.

    `dn=True` (LDAP, `memberOf` liefert ganze DNs) vergleicht **genau**, aber nach Bestandteilen:
    der ganze DN, ein **Anfang** aus ganzen RDNs (`cn=staff` oder `cn=staff,ou=groups` — der
    Teil-DN ohne Basis, wie ihn die README als Beispiel zeigt) oder der Wert des ersten RDN
    (`staff`). Gross/klein zählt dort nicht — LDAP vergleicht Namen so, und `CN=Staff,OU=Groups`
    ist dieselbe Gruppe. So bleibt die gewohnte Schreibweise gültig, ohne dass ein Namensteil
    eine fremde Gruppe trifft: verglichen werden nur ganze Bestandteile, vorn beginnend.
    """
    s, g = str(schluessel), str(gruppe)
    if not s:
        return False
    if teilstring:
        return s in g
    if s == g:
        return True
    if not dn or "=" not in g:
        return False
    g_teile = [t.lower() for t in _dn_teile(g)]
    if "=" in s:
        # Ganzer DN oder Teil-DN von vorn (A-3): `cn=admins,ou=g` trifft
        # `cn=admins,ou=g,dc=example,dc=com`. Bis zum ersten Fix dieser Runde deckte das der
        # Teilstring ab; ohne diesen Zweig fiel ein so geschriebener Schlüssel nach dem Update
        # still weg — Admin-Mapping weg, oder als ldap_allowed_groups jeder Nutzer abgewiesen.
        s_teile = [t.lower() for t in _dn_teile(s)]
        return g_teile[:len(s_teile)] == s_teile
    _, _, wert = g_teile[0].partition("=")
    return s.strip().lower() == wert.strip()


def _teilstring_hinweis(schluessel, gruppen, feld: str) -> None:
    """Einmal je Schlüssel sagen, wenn er nur noch per Teilstring treffen würde (A-3).

    Bis 0.19.x verglich LDAP immer per Teilstring (F-19). Ein Schlüssel, der damals griff und
    heute nicht mehr, kostet nach dem Update still Rollen oder — in `ldap_allowed_groups` — den
    ganzen Zugang. Statisch ist das nicht zu erkennen (es hängt an den DNs des Verzeichnisses),
    also fällt es beim ersten Login auf, bei dem es passiert."""
    s = str(schluessel)
    if not s or not any(s in str(g) for g in gruppen):
        return
    if any(gruppe_passt(s, g, dn=True) for g in gruppen):
        return
    if security.einmal_melden(f"ldap_teilstring:{feld}:{s}"):
        security.seclog.warning(
            "LDAP: der Schlüssel %r in %s trifft nur noch als Teilstring (%s) und greift seit "
            "0.20.0 nicht mehr — verglichen wird nach DN-Bestandteilen. Schreibweise ändern "
            "(ganzer DN, Teil-DN von vorn wie 'cn=admins,ou=groups', oder nur der CN) oder "
            "group_match='substring' setzen.", security.fuer_log(s), feld,
            security.fuer_log(next(str(g) for g in gruppen if s in str(g)))[:200])


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


def _stderr_ist_konsole() -> bool:
    """Liest hier ein Mensch mit, oder sammelt jemand stderr ein (Container, journal, Pipe)?

    Im Container IST stderr das Log (`docker logs`), unter systemd das Journal. Was „nur für die
    Konsole des Betreibers" gedacht ist, darf dann nicht dorthin (Fund aus dem Betrieb,
    2026-09-27). Wie `_auf_stderr` bei jedem Aufruf frisch nachgeschlagen.
    """
    try:
        return bool(sys.stderr is not None and sys.stderr.isatty())
    except Exception:
        return False


#: Was als CSRF-Token aus einem Cookie übernommen wird (0.20.1). Nur URL-sichere Zeichen — nichts,
#: was in einem HTML-Attribut, einem Header oder einer Cookie-Zeile etwas anrichtet —, mindestens
#: so lang wie das, was TinySesam selbst würfelt (`token_urlsafe(24)`: 32 Zeichen, 192 Bit),
#: höchstens 128. Ein Cookie, das anders aussieht, wird ersetzt statt in ein Formular geschrieben.
_CSRF_FORM = re.compile(r"[A-Za-z0-9_-]{32,128}")

#: Unter diesem Schlüssel im ASGI-Scope merkt sich eine Anfrage das Token, das sie NEU gewürfelt
#: hat — damit `csrf_token(request)` vor dem Rendern und `ensure_csrf(request, antwort)` danach
#: dasselbe liefern. Der Scope gehört genau einer Anfrage; nichts läuft in eine andere über.
_CSRF_SCOPE = "tinysesam.csrf_neu"

#: Wie viele eben angemeldete, noch nicht ins Cookie gesetzte Sitzungen sich ein Prozess merkt.
#: Zwischen `_sitzung_anlegen()` und `set_cookie()` liegt eine Anfrage; die Grenze fängt nur
#: eigene Routen ab, die eine Sitzung anlegen und nie ein Cookie setzen.
_FRISCH_MAX = 1024


def _samesite(wert: str) -> Literal["lax", "strict", "none"]:
    """Der Konstruktor lässt nur diese drei Werte zu (s. TinySesam.__init__); hier steht es
    noch einmal für den Typprüfer, dem die Zusage von dort nicht folgt."""
    return cast(Literal["lax", "strict", "none"], wert)


def _beleg_wahr(wert) -> bool:
    """Sagt ein Attribut aus LDAP/SAML „diese Adresse ist geprüft"? Nur ausdrücklich wahre Werte
    zählen (True, "true", "1", "yes", "ja"); alles andere — auch ein fehlendes Attribut — nicht."""
    if isinstance(wert, bool):
        return wert
    return str(wert or "").strip().lower() in ("true", "1", "yes", "ja")


def _beleg_am_konto(user) -> bool:
    """Der Vermerk `users.email_verified` einer Kontozeile.

    Fehlt die Spalte — eine Zeile aus einer fremden Quelle, ein Testaufbau mit einem
    Wörterbuch —, gilt „bestätigt": genau der Stand jeder Installation vor dieser Spalte,
    also keine stille Verschärfung für Bestandsdaten. Wo ein Anmeldeweg es besser weiss,
    reist der Beleg ohnehin als Parameter mit (`_maybe_promote_admin(user, email_bestaetigt=…)`)
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



def _gueltige_regeln(regeln) -> list:
    """Nur die Regeln, deren Schlüssel belegt sind.

    Eine Regel „je Konto" ohne Konto würde sonst stillschweigend zu einer „je Adresse" mit
    falscher Grenze (`count_fails` lässt einen leeren Filter einfach weg)."""
    return [r for r in regeln
            if all(r[2].get(k) for k in ("username", "ip") if k in r[2])]

def _messages_der_sprache(auth) -> dict:
    from .messages import MESSAGES
    return MESSAGES.get(auth.cfg.lang) or MESSAGES["en"]


class TinySesam:
    def __init__(self, config: TinySesamConfig):
        self._riegel(config, beim_aufbau=True)
        self.cfg = config
        self.store = Store(config.db_path)
        self.store.leerlauf_sek = (max(0, int(config.session_idle_minutes or 0)) * 60,
                                   max(0, int(config.session_idle_minutes_remember or 0)) * 60)
        # TOTP-Geheimnisse nur verschlüsselt (H-14/H-15, Pflicht). Schlüssel aus der Umgebung, der
        # Konfiguration oder neben der Datenbank; ein falscher bricht den Start ab.
        from . import geheimnis as _geheimnis
        _schluessel, self._schluessel_herkunft = _geheimnis.schluessel_laden(
            config.db_path, config.secrets_key_file)
        self.store.tresor = _geheimnis.Tresor(_schluessel)
        # Gate-Token (ADR-9, T-19): Der Signaturschlüssel wird aus demselben Grundschlüssel
        # abgeleitet — kein zweites Geheimnis zum Sichern und Verteilen. Immer abgeleitet, auch
        # wenn das Gate aus ist: `tinysesam gate-key` soll den Proxy vorbereiten können, bevor
        # der Schalter umgelegt wird.
        from . import gate as _gate
        self._gate_schluessel = _gate.schluessel_ableiten(_schluessel)
        self.store.geheimnisse_heben()
        # B6-8: Ohne das Extra [argon2] scheitert jede Anmeldung gegen einen argon2-Hash — bis
        # hierher ohne ein Wort, das Konto sah für den Nutzer einfach „falsches Passwort" aus.
        # Beim Start zählen und sagen, wie viele es trifft; der Start selbst bleibt möglich
        # (Passkey, OIDC und SSO hängen nicht daran, und ein Dienst, der wegen eines fehlenden
        # Pakets gar nicht mehr hochkommt, wäre der grössere Ausfall).
        if not _passwords.argon2_verfuegbar():
            betroffen = self.store.zaehle_argon2_hashes()
            if betroffen:
                security.seclog.error("%s (%d betroffene Hashes)", _passwords.ARGON2_FEHLT, betroffen)
        self.store.audit_ip_pseudonym = bool(config.audit_ip_pseudonymize)
        self._protokoll_drossel: dict = {}   # siehe `_einmal_je`
        # Eben voll angemeldete Sitzungen (Handle), deren Cookie noch nicht gesetzt ist — siehe
        # `_sitzung_anlegen` und `set_cookie` (CSRF-Rotation beim Anmelden, 0.20.1).
        from collections import OrderedDict
        import threading
        self._frische_anmeldungen: "OrderedDict[str, None]" = OrderedDict()
        self._frisch_lock = threading.Lock()
        self.templates = Templates()
        self._messages: dict = {}
        self._mailer_override = None
        from .mailer import Postausgang
        self._postausgang = Postausgang()
        # Eigener, kleiner Postausgang für Sperr-Hinweise (ASVS 6.3.5): Ihn füllt, wer Fehlversuche
        # schickt — eine Flut soll Anmelde-Links und Resets im Hauptausgang nicht verdrängen.
        self._hinweis_ausgang = Postausgang(arbeiter=1, max_offen=50)
        # Die OIDC-Nachprüfung (4a) tauscht Refresh-Tokens im Hintergrund: Ein hängender Provider
        # hielte sonst jede fällige Anfrage bis zum Timeout fest — aus `async`-Routen samt Event-Loop
        # (Angriff auf die zweite Runde, Fund 6, dieselbe Klasse wie B6-6).
        self._oidc_ausgang = Postausgang(arbeiter=2, max_offen=200)
        #: Opt-in-Benachrichtigung bei Sicherheitsereignissen am eigenen Konto (Fund B2-2,
        #: Empfehlung H-6) — siehe `SECURITY_EVENTS`. Aufruf `hook(ereignis, konto,
        #: details)`; `konto` hat `id`, `username`, `email`, `display_name`. TinySesam
        #: verschickt selbst nichts: welche Mail, welcher Kanal, welche Sprache, entscheidet
        #: die App.
        self.on_security_event: Optional[Callable[[str, dict, dict], Any]] = None
        self._blockliste = self._blockliste_laden(config.password_blocklist_file)
        # Versuchs-ID → (Kennung, Methode, Serienstand nach der Buchung) für die in
        # `_versuch_beginnen` vorgebuchte Serie (B2-6). Im Speicher genügt: Stirbt der Prozess
        # dazwischen, bleibt die Vorbuchung als Fehlversuch stehen — im Zweifel strenger.
        self._serie_vorbuchungen: dict = {}
        # Warteplätze für Anmeldungen, die nur wegen schwebender Vorbuchungen nicht weiterkämen
        # (G9, `_versuch_beginnen`) — gedeckelt, damit Wartende nicht alle Worker-Threads belegen.
        self._schwebe_plaetze = threading.BoundedSemaphore(self._SCHWEBE_WARTEPLAETZE)
        self.oidc = None
        self.webauthn = None
        self.ldap = None
        # Der Ausfall-Merker hängt am Manager, nicht am Client: Er gilt auch für einen selbst
        # gesetzten Client (`auth.ldap = eigener_client`) — Begründung bei `AusfallMerker`.
        from .ldap_ import AusfallMerker
        self._ldap_ausfall = AusfallMerker()
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
            from .oidc import OIDCClients, VORGABE_CLIENT
            # `self.oidc` bleibt der Einzel-Client und damit die öffentliche Fläche von 0.18.0
            # (Tests und fremder Code greifen darauf zu). `self.oidc_clients` ist die Zuordnung
            # Host → Client; ohne `cfg.oidc_clients` enthält sie genau diesen einen (T-14).
            self.oidc_clients = OIDCClients(config)
            self.oidc = self.oidc_clients[VORGABE_CLIENT]
        if config.passkey_enabled:
            # Passkey kennt keine unvollständige Konfiguration: Wer den Schalter umlegt, will es.
            _verlange("webauthn", "passkey_enabled", "passkey")
            from . import webauthn_ as wa
            self.webauthn = wa
        if config.demo_mode and not self.store.get_setting("demo_users") \
                and self.store.user_count() > 0:
            # Die eine technische Schranke, die eine echte Demo nie trifft (B3-8): Eine Demo
            # beginnt auf einer LEEREN Datenbank — dort legt sie ihre Konten an und merkt sie
            # sich (`demo_users`), jeder spätere Start erkennt sie wieder, auch mit inzwischen
            # registrierten Besuchern. Wer `demo_mode` dagegen erstmals auf einer Datenbank
            # einschaltet, die schon Konten hat, schaltet ihn auf Bestandsdaten ein — also
            # produktiv. Vorher entstand dann still ein Admin-Konto mit bekanntem Passwort.
            raise ConfigError(
                "demo_mode=True auf einer Datenbank, die schon Konten hat und nie eine Demo war "
                f"({config.db_path!r}). Die Demo legt ein Admin-Konto mit bekanntem Passwort an — "
                "auf Bestandsdaten ist das eine Hintertür. Für eine Demo eine eigene, leere "
                "Datenbank nehmen (db_path).")
        if config.demo_mode:
            security.seclog.warning(
                "DEMO-MODUS aktiv: Beispielkonten %s mit bekanntem Passwort. NICHT produktiv betreiben.",
                ", ".join(self._DEMO_USERS))
            self._seed_demo()
        elif self.store.get_setting("demo_users"):
            n = self._purge_demo()                       # Demo-Modus abgeschaltet → Konten sind weg
            if n:
                security.seclog.warning("Demo-Modus aus: %d Beispielkonto(en) gelöscht.", n)
        # Forward-Auth über mehrere Hosts, aber ohne cookie_domain: Das Session-Cookie ist
        # host-only, also gibt es KEIN geteiltes SSO — jeder Host verlangt eine eigene Anmeldung.
        # Die Login-URL wird pro Host gebaut (siehe forward_login_url), damit daraus wenigstens
        # keine stille Redirect-Schleife wird. Das ist vorab beweisbar, ohne über die Außenwelt
        # zu raten: die Hosts stehen in der eigenen Konfiguration.
        # Mit dem Code-Austausch (T-26) ist host-only gerade gewollt: Die App-Hosts bekommen eine
        # Verbindung, keine eigene Anmeldung — die Warnung wäre dort ein Fehlalarm.
        if (config.forward_auth_enabled and config.base_url and not config.cookie_domain
                and not getattr(config, "gate_link_enabled", False)):
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
        # Kollisionen im Kennungsraum aus dem Bestand: Neue verhindert seit 2026-09-26 die
        # Datenbank (Trigger über die Zähl-Töpfe, `Store._trigger_sql`), aber eine aus einer
        # älteren Fassung, aus einem rohen UPDATE oder aus einer Zeile eines fremden Schreibers
        # steht weiter drin. Sie ist nicht harmlos: `find_user` löst die Kennung dann mehrdeutig
        # auf, der rechtmäßige Inhaber kann ausgesperrt sein, und zwei Konten teilen sich die
        # Sperrschwelle. Bereinigt wird von Hand (welches Konto den Namen behält, kann keine
        # Bibliothek entscheiden) — gesagt wird es beim Start, und zwar vollständig: Bis dahin sah
        # die Meldung nur „Name = fremde Adresse" per NOCASE, nicht `Alice`/`alice` oder zwei
        # Schreibweisen derselben Adresse (`topf_kollisionen`).
        kollisionen = self.store.topf_kollisionen()
        if kollisionen:
            beispiele = "; ".join(
                f"Kennung '{security.fuer_log(z['kennung'])}': "
                + ", ".join(f"user_id={i}" for i in z["ids"]) for z in kollisionen[:5])
            security.seclog.warning(
                "%d Kennungs-Kollision(en) im Bestand: Benutzername und E-Mail sind EIN "
                "Kennungs-Raum (find_user sucht in beiden Spalten, Namensvetter wie Alice/alice "
                "teilen sich die Sperrschwelle). Neue verhindert die Datenbank; diese stammen aus "
                "der Zeit davor und bleiben, bis eine der Kennungen geändert ist. Die Anmeldung "
                "mit dieser Kennung ist mehrdeutig, der rechtmäßige Inhaber kann ausgesperrt "
                "sein. Betroffen: %s%s. Zu ändern ist eine der Kennungen. Den Benutzernamen: im "
                "Admin-Panel („Umbenennen“, POST <admin_path>/api/users/<id>/username), mit "
                "tinysesam rename --db <datei> '#<user_id>' <neuer-name>, der Inhaber selbst auf "
                "der Konto-Seite oder aus dem einbettenden Dienst "
                "auth.change_username(user_id, new_username, by_operator=True) — alle prüfen beide "
                "Namensräume (im Modus login_identifier='email' folgt der Name der Adresse). Die "
                "E-Mail aus dem einbettenden Dienst über "
                "store.set_email(user_id, adresse) (wirft sqlite3.IntegrityError, wenn die neue "
                "Adresse schon Kennung eines anderen Kontos ist). Achtung bei der E-Mail: "
                "store.set_email() legt die neue Adresse vorgabegemäss als UNBESTÄTIGT ab "
                "(users.email_verified=0) — der Beleg der alten Adresse gilt nicht für eine "
                "andere. Wer einen Beleg für die neue hat, übergibt verified=True.",
                len(kollisionen), beispiele,
                " (weitere folgen)" if len(kollisionen) > 5 else "")
        # Kontonamen mit Steuer-/Formatzeichen (seit 2026-09-24 nicht mehr anlegbar) im Bestand:
        # Die Forward-Auth weist die ab, deren Zeichen die Header-Säuberung entfernen würde (sonst
        # wäre `Remote-User` ein fremder Name). Gesagt wird es beim Start, nicht erst je Anfrage.
        auffaellig = [z for z in self.store._all("SELECT id, username FROM users")
                      if name_ungueltig(z["username"])]
        if auffaellig:
            security.seclog.warning(
                "%d Kontoname(n) mit Steuer- oder Formatzeichen im Bestand (user_id %s). Neue legt "
                "TinySesam so nicht mehr an; Namen mit C0-Steuerzeichen bekommen an der "
                "Forward-Auth keine Freigabe (Remote-User wäre ein anderer Name). Umbenennen: im "
                "Admin-Panel („Umbenennen“), mit tinysesam rename --db <datei> '#<user_id>' "
                "<neuer-name>, der Inhaber selbst auf der Konto-Seite oder aus dem einbettenden "
                "Dienst auth.change_username(user_id, new_username, by_operator=True) — alle prüfen, "
                "dass der neue Name in Benutzernamen UND Adressen frei ist.",
                len(auffaellig), ", ".join(str(z["id"]) for z in auffaellig[:10]))
        # Bindung über den Namen (G1): Die Frist beginnt je Quelle beim ersten Start, an dem sie
        # eingeschaltet ist — für den Bestand also mit dem Update —, und genau einmal (der Merker
        # bleibt, s. `Store.foederation_seit`). Danach eine Zeile je Quelle, solange es noch Konten
        # gibt, die sich über den Namen binden würden, und die Tür noch offen ist.
        for _quelle, _an in (("ldap", config.ldap_enabled), ("saml", config.saml_enabled)):
            if _an:
                self._namensbindung_bestand_melden(_quelle, self._foederation_seit(_quelle))
        tok = self.admin_claim_token()
        if tok:
            self._admin_claim_bekanntgeben(tok)
        else:
            self._claim_datei_weg()          # ein Rest aus einem Lauf ohne Admin (T-17)

    # ---------- Owner ----------
    def _erster_owner(self, user_id) -> None:
        """Der erste Admin einer Instanz wird auch ihr erster Owner (Bootstrap-Wege)."""
        if self.store.owner_count() == 0:
            self.store.set_owner(user_id, True)
            u = self.store.get_user(user_id)
            self.store.audit_log("owner_grant", u["username"] if u else None, None, "quelle=erst_admin")

    def set_owner(self, user_id: int, owner: bool) -> bool:
        """Die Owner-Rolle vergeben (`owner=True`) oder abgeben (`False`). False = kein solches Konto.

        Owner sind Admins, die sich nicht löschen, sperren oder entmachten lassen; es gibt immer
        mindestens einen, und nur Owner vergeben die Rolle (das prüft die aufrufende Route). Die
        Rolle abgeben geht nur, wenn ein ANDERER Owner bleibt (`StateError`). Service-Konten und
        gesperrte Konten werden nicht Owner (`ConfigError`) — ein Owner muss sich anmelden können."""
        u = self.store.get_user(user_id)
        if not u:
            return False
        if owner:
            if u["is_service"] or u["disabled"]:
                raise ConfigError("Owner kann nur ein aktives, interaktives Konto werden.")
            if not u["is_owner"]:
                self.store.set_owner(user_id, True)
                self.audit("owner_grant", u["username"])
            return True
        if u["is_owner"]:
            if self.store.owner_count(ohne=user_id) == 0:
                raise StateError(f"Konto {user_id} ist der letzte Owner. Erst einen anderen Owner "
                                 "bestimmen, dann die Rolle abgeben.")
            self.store.set_owner(user_id, False)
            self.audit("owner_revoke", u["username"])
        return True

    # ---------- User-Verwaltung ----------
    def identifier_taken(self, identifier, exclude_id=None) -> Optional[dict]:
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

        Und über den **Zähl-Topf** des Sperrzählers (`Store.konto_mit_topf`): `Émile` und
        `émile` sind für SQLite-NOCASE (nur ASCII) zwei Namen, für `norm_kennung` einer. Zwei
        solche Konten teilten sich die Konto-Schwelle gegen verteiltes Raten — und wurde das eine
        entfernt (auch anonym auslösbar: Registrierung, die `gc()` abräumt), gingen die
        Fehlversuche des anderen mit. Ein solcher Namensvetter gilt deshalb als vergeben.

        **Und über den Namen im Verzeichnis** (`federated_identity.name_topf`, G5; Prüfrunde
        2026-09-27): Unter einer Kennung prüft die Login-Route das lokale Passwort des Kontos UND
        das LDAP-Passwort des Eintrags. Hiess ein lokales Konto so wie eine andere Person im
        Verzeichnis (Selbstbedienung, Registrierung, Umbenennen im Panel), räumte jede seiner
        Anmeldungen die Zähler, unter denen gegen deren LDAP-Passwort geraten wurde — die
        Sperren wirkten nicht mehr. Ein Name, der an der Bindung eines ANDEREN Kontos steht, gilt
        deshalb als vergeben (die Kennung, die nach dem Umbenennen im Verzeichnis dort steht, und
        der alte Name eines umbenannten LDAP-Kontos, s. `Store._verzeichnisname_merken`).

        **Eine Vorprüfung, die Datenbank entscheidet** (seit 2026-09-26): Zwischen dieser
        Antwort und dem Schreiben kann eine gleichzeitige Anfrage die Kennung belegen. Das
        Schreiben weist sie dann ab (Trigger über die Zähl-Töpfe, `Store._trigger_sql`), und die
        Aufrufer machen daraus dieselbe Antwort wie hier („vergeben").
        """
        identifier = (identifier or "").strip()
        if not identifier:
            return None
        for treffer in (self.store.get_user_by_name(identifier), self.store.get_user_by_email(identifier),
                        self.store.konto_mit_topf(identifier, ausser=exclude_id),
                        self.store.konto_mit_verzeichnisname(identifier, ausser=exclude_id)):
            if treffer is not None and treffer["id"] != exclude_id:
                return self._als_dict(treffer)
        return None

    def create_user(self, username, password=None, is_admin=False, roles=None,
                    display_name=None, email=None, is_service=False,
                    email_verified: bool = True, *, self_chosen_name: bool = False) -> int:
        """Ein Konto anlegen und seine ID zurückgeben. `is_service=True` für Maschinen: kein
        Login, nur API-Keys. Eine bereits vergebene Kennung wirft `ConfigError` — **neu auch
        beim doppelten Benutzernamen**, der bis 0.18.x als `sqlite3.IntegrityError` aus der
        Datenbank kam (`e.field`/`e.owner_id` sagen, was kollidierte).

        Benutzername und E-Mail müssen **kreuzweise** frei sein (`identifier_taken`) — sonst
        besetzt ein neues Konto die Login-Kennung eines bestehenden. Die Prüfung sitzt hier,
        damit sie für JEDEN Weg gilt: Selbst-Registrierung, Admin-API, Einladung, Erst-Admin
        (`ensure_admin`), Service-Konten (`create_service`) und die automatische Anlage aus
        OIDC/LDAP/SAML. Das CLI ist bewusst nicht dabei: Es kann keine Konten anlegen; sein
        `rename` (G13) lädt den Manager nicht und prüft dieselben drei Treffer selbst.

        `email_verified=False` legt die Adresse als **unbestätigt** ab: geführt und
        weitergereicht wie jede andere, aber ohne Tragkraft für Rechte (Erst-Admin/Allowlist,
        siehe `_maybe_promote_admin`). Das ist der Fall jedes Anmeldewegs, der für die Adresse
        nicht einsteht: ein IdP ohne den Claim `email_verified`, **und grundsätzlich SAML und
        LDAP** — dort gibt es gar kein Attribut, das eine Prüfung behauptet.
        Die Vorgabe `True` gilt für die Wege, bei denen der Betreiber für die Adresse einsteht
        (Admin-API, Erst-Admin, Service-Konten, Einladung an diese Adresse). Die
        Selbst-Registrierung legt die eingetippte Adresse mit `False` an; den Beleg setzt erst der
        eingelöste Bestätigungslink (`/auth/verify`), ohne Bestätigungspflicht bleibt es beim
        `False`. Wer selbst registriert und `send_verify_email` schickt, übergibt ebenfalls
        `False` — sonst gilt die Adresse als belegt, bevor jemand den Link eingelöst hat.

        Eine vergebene Kennung wirft `ConfigError` mit dem Wortlaut „<Feld> ist bereits
        vergeben" und gesetztem `e.field` (`"username"`/`"email"`) plus `e.owner_id` —
        daran, nicht am übersetzten Text, unterscheidet ein Aufrufer die beiden Fälle.

        ⚠️ **Geändert gegenüber 0.18.x:** Nur die doppelte *E-Mail* warf dort schon
        `ConfigError`. Ein doppelter *Benutzername* lief bis in die Datenbank und kam als
        `sqlite3.IntegrityError` zurück; er wird jetzt vorher abgefangen und wirft denselben
        `ConfigError`. Wer auf `IntegrityError` fängt, fängt diesen Fall nicht mehr.

        **Auch im Wettlauf** (seit 2026-09-26): Belegt eine gleichzeitige Anfrage die Kennung
        zwischen Prüfung und Anlage, weist die Datenbank das INSERT ab — und auch das kommt als
        derselbe `ConfigError`. `e.owner_id` kann dann `None` sein: wenn das andere Konto
        schon wieder entfernt ist, bevor hier nachgesehen wird.

        `self_chosen_name=True`: Die Person hat den Namen selbst eingetippt (Registrierung,
        auch mit Einladung). Eine Anmeldung über LDAP/SAML bindet dieses Konto dann nie über den
        Namen (G2-N, `users.name_selbst_gewaehlt`). Die eingebaute Registrierung setzt es; wer eine
        eigene baut, übergibt es ebenfalls. Vorgabe `False`: Den Namen vergibt der Betreiber. Wer
        Konten aus einer EIGENEN fremden Quelle anlegt (ein weiterer Identity Provider), übergibt es
        auch: Dort gewählte Namen sagen nichts darüber, wer im Verzeichnis so heisst."""
        return self._konto_anlegen(username, password, is_admin, roles, display_name, email,
                                   is_service, email_verified, name_selbst_gewaehlt=self_chosen_name)

    def _konto_anlegen(self, username, password=None, is_admin=False, roles=None, display_name=None,
                       email=None, is_service=False, email_verified: bool = True, *,
                       name_selbst_gewaehlt: bool = False, name_quelle: Optional[str] = None) -> int:
        """`create_user` samt Herkunft des Namens (`users.name_quelle`, Angriffsrunde 2026-09-26):
        die Anlage aus OIDC, SAML und LDAP. Ein Name, den eine Quelle mitbringt, bindet das Konto
        nie über den Namen an eine ANDERE (`_nachbindung_grund`) — `preferred_username`, NameID und
        `uid` wählt man bei einem IdP mit Selbstregistrierung selbst. Nachgestellt: `chefin` meldet
        sich über OIDC an, die echte chefin danach über LDAP, und das OIDC-Konto trug danach ihre
        Kennung und ihre Rollen. Dieselbe Quelle darf ihren Platzhalter weiter durch die echte
        Kennung ersetzen. Nicht öffentlich: Wer selbst anlegt, nimmt `self_chosen_name=True` (`create_user`)."""
        username = (username or "").strip()
        email = norm_email(email)
        if name_ungueltig(username):
            # Zentral hier, weil jeder Anlegeweg hier endet (Registrierung, Panel, CLI, OIDC,
            # SAML, LDAP): Ein Name mit Steuerzeichen wird in `Remote-User` zu einem ANDEREN
            # Namen (s. `name_ungueltig`). Die föderierten Wege weichen vorher auf einen
            # Ersatznamen aus; wer hier landet, bekommt eine Abweisung.
            fehler = ConfigError("Benutzername enthält Steuer- oder Formatzeichen")
            fehler.field = "username"
            raise fehler
        for feld, schluessel, kennung in (("Benutzername", "username", username),
                                          ("E-Mail-Adresse", "email", email)):
            besitzer = self.identifier_taken(kennung) if kennung else None
            if besitzer:
                security.seclog.warning(
                    "Konto nicht angelegt: %s ist bereits Login-Kennung von user_id=%s", feld, besitzer["id"])
                # Der Wortlaut ist der von 0.18.x ("… ist bereits vergeben"). Weil ein
                # `ConfigError` allein nicht verrät, WAS kollidierte, prüfen Aufrufer den Text —
                # die brüchigste Art, ein Programm zu steuern, aber eine verbreitete. Ein Fix
                # darf ihr nicht die Grundlage wegziehen. Er nennt aber das Feld, das WIRKLICH
                # kollidiert: Der neue Auslöser (Benutzername = fremde E-Mail und umgekehrt)
                # trägt je nach Richtung den Benutzernamen- ODER den E-Mail-Text, nicht immer
                # denselben. Verlässlich unterscheiden lässt er sich an `field`/`owner_id`.
                fehler = ConfigError(f"{feld} ist bereits vergeben")
                fehler.field = schluessel
                fehler.owner_id = int(besitzer["id"])
                raise fehler
        try:
            uid = self.store.create_user(username, display_name, email, is_admin, roles, is_service,
                                         email_verified=email_verified,
                                         name_selbst_gewaehlt=name_selbst_gewaehlt,
                                         name_quelle=name_quelle)
        except sqlite3.IntegrityError as fehler_db:
            # Wettlauf (G12c): Zwischen der Prüfung oben und dem INSERT hat eine gleichzeitige
            # Anfrage die Kennung belegt, und die Datenbank weist ab (Kennungs-Trigger, UNIQUE auf
            # Name oder Adresse). Jeder IntegrityError dieses INSERT heisst „vergeben". Welche
            # Kennung, sagt eine zweite Prüfung — ist das andere Konto schon wieder weg, bleibt es
            # beim Benutzernamen ohne Besitzer.
            treffer = [(feld, schluessel, self.identifier_taken(kennung) if kennung else None)
                       for feld, schluessel, kennung in (("Benutzername", "username", username),
                                                         ("E-Mail-Adresse", "email", email))]
            feld, schluessel, besitzer = next((t for t in treffer if t[2]), treffer[0])
            security.seclog.warning(
                "Konto nicht angelegt (Wettlauf): %s wurde zwischen Prüfung und Anlage "
                "Login-Kennung von user_id=%s", feld, besitzer["id"] if besitzer else "?")
            fehler = ConfigError(f"{feld} ist bereits vergeben")
            fehler.field = schluessel
            fehler.owner_id = int(besitzer["id"]) if besitzer else None
            raise fehler from fehler_db
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

    def apply_idp_groups(self, user_id, groups, mapping: dict, substring: Optional[bool] = None,
                         dn: bool = False):
        """IdP-Gruppen → lokale Rollen (beim Login). Gemappte Rollen werden synchronisiert (bei
        Wegfall der Gruppe entfernt), manuell vergebene Rollen bleiben. Ziel '__admin__' setzt das
        Admin-Flag und nimmt es wieder, wenn es vom Provider stammt (H-5).

        Ziel '__admin__' setzt das Admin-Flag — und nimmt es seit H-5 auch wieder, wenn der Provider
        die Gruppe nicht mehr liefert, aber **nur ein Flag, das er selbst vergeben hat**
        (`is_admin=2`, `Store.set_admin_vom_idp`). Bis dahin war es „nur grant": Wer beim Provider
        aus der Admin-Gruppe flog, blieb hier Admin, bis jemand es im Panel bemerkte. Ein Admin aus
        dem Panel, dem CLI, `admin_identifiers` oder `/auth/claim-admin` bleibt unberührt — sonst
        entzöge ein falsch konfigurierter Provider dem Betreiber seinen eigenen Zugang. Ein Flag
        aus der Zeit vor H-5 trägt den Vermerk nicht und bleibt deshalb ebenfalls stehen.
        Nimmt der Provider so den **letzten** Admin, befördert `admin_identifiers` danach
        niemanden mehr (G6); das Einmal-Token für `/auth/claim-admin` geht sofort an den
        Betreiber (stderr bzw. `admin_claim_token_file`).

        Verglichen wird standardmäßig **exakt** (`config.group_match`). Sonst würde `admin` auch
        auf `nicht-admin` passen: eine stille Rechteausweitung. `dn=True` (LDAP) vergleicht einen
        Gruppen-DN nach seinen Bestandteilen statt als Text (`gruppe_passt`): ganzer DN, erster
        RDN (`cn=staff`) oder dessen Wert (`staff`) — nie ein Teilstring."""
        if not mapping:
            return
        if substring is None:
            substring = self.cfg.group_match == "substring"
        gs = [str(g) for g in (groups or [])]
        matched = {role for key, role in mapping.items()
                   if any(gruppe_passt(key, g, substring, dn) for g in gs)}
        if dn and not substring:
            for key in mapping:
                _teilstring_hinweis(key, gs, "ldap_group_role_map")
        managed = {role for role in mapping.values() if role != "__admin__"}
        current = set(self.store.get_roles(user_id))
        new_roles = (current - managed) | {r for r in matched if r != "__admin__"}
        if new_roles != current:
            self.store.set_roles(user_id, sorted(new_roles))
        u = self.store.get_user(user_id)
        if "__admin__" in matched:
            if u and not u["is_admin"]:
                self.store.set_admin_vom_idp(user_id)
                self.audit("idp_admin_grant", u["username"], detail="quelle=idp")
        elif "__admin__" in mapping.values() and u and u["is_admin"] == 2:
            # Das Mapping kennt eine Admin-Gruppe, der Provider liefert sie nicht mehr: Das Flag,
            # das er vergeben hat, geht. Laut, weil es auch der letzte Admin sein kann.
            self.store.set_admin(user_id, False)
            self.audit("idp_admin_revoke", u["username"], detail="quelle=idp gruppe_entfallen=1")
            security.seclog.warning("Admin-Flag entzogen: user=%s, der Identity Provider liefert die "
                                    "Admin-Gruppe nicht mehr.", security.fuer_log(u["username"]))
            if not self.admin_exists():
                # War es der letzte Admin (G6), bleibt die Allowlist ab jetzt zu: Sonst beförderte
                # `_maybe_promote_admin` im selben Login — über `apply_factor` — die Person wieder,
                # als Admin „von Hand" (1) und Erst-Owner, den kein Provider mehr entzieht und
                # niemand löschen oder sperren kann. Und nicht nur sie: jedes Konto mit einem
                # Allowlist-Eintrag. Offen bleibt nur der belegte Weg des Betreibers — das
                # Einmal-Token, jetzt sofort ausgegeben (bis dahin nur beim Start), und das CLI.
                # Der Merker gilt für die Instanz und wird nie zurückgesetzt; er wirkt ohnehin nur,
                # solange es keinen Admin gibt. Parallele Entzüge setzen ihn idempotent.
                self.store.set_setting("allowlist_nach_idp_entzug", str(_jetzt()))
                security.seclog.warning(
                    "Kein Admin mehr: Der Identity Provider hat der Instanz ihren letzten Admin "
                    "entzogen. admin_identifiers befördert danach niemanden mehr. Notweg: "
                    "tinysesam owner --db <datei> <benutzer> oder /auth/claim-admin mit dem "
                    "Einmal-Token (Konsole bzw. admin_claim_token_file).")
                tok = self.admin_claim_token()
                if tok:
                    self._admin_claim_bekanntgeben(tok)

    # ---------- API-Keys / Service-Accounts (maschineller Zugang, Daemons) ----------
    def create_service(self, username, roles=None, display_name=None) -> int:
        """Service-/Daemon-Account: kein interaktiver Login, nur API-Keys. Rollen = Rechte-Scope."""
        return self.create_user(username, is_service=True, roles=roles, display_name=display_name or username)

    def create_api_key(self, user_id, name=None, expires_days=None, roles=None,
                       kind: str = "automation") -> dict:
        """Neuen API-Key erzeugen. Rückgabe enthält 'key' im KLARTEXT — nur EINMAL (danach nur der Hash).

        **Zwei Arten** (R6-5), weil ein Key zwei ganz verschiedene Dinge sein kann:

        * ``kind="automation"`` (Vorgabe) — ein Dienst, ein Skript, eine CI. Er arbeitet allein,
          trägt aber **nie das Admin-Flag** seines Besitzers und erfüllt keine Route, die Admin
          verlangt. Bis 0.18.x war ein Key eines Admins eine vollständige Admin-Schreib-API,
          ohne zweiten Faktor und ohne CSRF-Schicht: Nutzer anlegen, `is_admin` setzen,
          Passwörter zurücksetzen. Ein abgeflossener CI-Key war damit die Instanz.
        * ``kind="human"`` — ein Werkzeug, das ein Mensch selbst bedient. Er gilt **nur
          zusammen mit einer gültigen Sitzung desselben Kontos**; dafür trägt er die vollen
          Rechte. Allein abgeflossen ist er wertlos.

        Bis 0.21.x hiessen die Arten `"automat"` und `"mensch"`. Seit 0.22.0 gilt nur der
        englische Name (ohne Alias, PO-Entscheid 2026-09-27) — ein alter wirft `ConfigError`, der
        den neuen nennt. Gespeicherte Keys hat die Migration umgeschrieben (Schema 12).

        `expires_days` fehlt bei einem Automaten-Key nicht folgenlos: Dann greift
        `apikey_default_days` (Vorgabe 90). `expires_days=0` heisst „unbefristet" und braucht
        `apikey_allow_unlimited=True` — ein Key ohne Ablauf überlebt den Menschen, der ihn
        ausgestellt hat, und das Projekt, für das er gedacht war.

        `roles` ist ein **Scope**, kein Rechtezuwachs: Die Liste wird auf die Rollen des Besitzers
        beschnitten. Ein Key kann damit weniger können als sein Besitzer, nie mehr.

        **Bleibt nach dem Schnitt nichts übrig, wirft die Methode `ConfigError` und legt keinen
        Key an** — ein Tippfehler in `roles` gibt also eine Ausnahme, keinen Key. Warum kein
        leerer Scope: Der Grund steht unten am Code, er kehrte die Wirkung ins Gegenteil.

        Zurück kommt `{"id", "key", "prefix", "expires_at", "roles", "dropped_roles", "kind"}`.
        `key` ist der Klartext und hier das einzige Mal zu sehen; `dropped_roles` nennt, was der
        Schnitt entfernt hat (dieselbe Angabe steht im Audit-Eintrag, dort als
        `verworfene_rollen=` — die Audit-Zeile bleibt, wie sie war; bis 0.21.x hiess auch der
        Schlüssel hier so).
        Bis 2026-09-21 wurde die Liste ungeprüft übernommen, und beim Prüfen überschrieb sie die
        Rollen des Kontos. Jeder angemeldete Nutzer konnte sich damit über die Selbstbedienungs-Route
        `POST /auth/apikeys` beliebige Rollen ausstellen — unsichtbar, weil das Konto in der
        Datenbank rollenlos blieb. Im Forward-Auth-Betrieb ging die erfundene Rolle als Remote-Group
        an die nachgelagerte App.
        """
        if kind not in self._KEY_ARTEN:
            neu_name = Store.KEY_ARTEN_ALT.get(str(kind))
            raise ConfigError(
                (f"API-Key-Art {kind!r} heisst seit 0.22.0 {neu_name!r}. " if neu_name else
                 f"API-Key-Art {kind!r} gibt es nicht. ")
                + "'automation' arbeitet allein (ohne Admin-Rechte), 'human' gilt nur zusammen "
                  "mit einer Sitzung desselben Kontos.")
        raw = "tsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:12] + "…"
        # Ablauf: 0 heisst ausdrücklich „unbefristet" und braucht die Erlaubnis; None heisst
        # „keine Angabe" und bekommt die Vorgabe. Beides auseinanderzuhalten ist der Punkt —
        # vorher war `None` stillschweigend unbefristet, und das war der häufigste Fall.
        if expires_days is None:
            expires_days = int(self.cfg.apikey_default_days or 0)
        expires_days = int(expires_days)
        # Genau NULL heisst unbefristet. Ein negativer Wert ist ein Ablauf in der Vergangenheit,
        # also ein von vornherein toter Key — das ist kein Unfug, sondern der Weg, einen Key
        # anzulegen, der sofort ungültig ist (die Suite prüft damit die Ablaufprüfung selbst).
        if expires_days == 0:
            if not self.cfg.apikey_allow_unlimited:
                raise ConfigError(
                    "Ein API-Key ohne Ablauf ist ein Geheimnis, das niemand mehr zurücknimmt — er "
                    "überlebt den Menschen, der ihn ausgestellt hat, und das Projekt, für das er "
                    "gedacht war. Entweder expires_days setzen (Vorgabe: "
                    f"apikey_default_days={self.cfg.apikey_default_days}) oder, wenn es wirklich "
                    "keinen anderen Weg gibt, apikey_allow_unlimited=True.")
            expires_at = None
        else:
            expires_at = _jetzt() + expires_days * 86400

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

        kid = self.store.add_api_key(user_id, name, prefix, key_hash, roles, expires_at, kind=kind)
        detail = f"user={user_id} key={kid} name={name} art={self._key_art_audit(kind)}"
        if expires_at is None:
            # Ausdrücklich ins Protokoll: Ein unbefristeter Key ist eine Entscheidung, keine
            # Einstellung — wer später fragt „seit wann liegt das Ding herum", findet hier etwas.
            detail += " ablauf=unbefristet"
        if abgeschnitten:
            # In den Audit-Eintrag, nicht nur verwerfen: Wer das versucht, soll sichtbar sein.
            detail += f" verworfene_rollen={','.join(abgeschnitten)}"
        self.audit("apikey_create", self._kontoname(user_id), detail=detail)
        self._sicherheitsereignis("api_key_created", user_id, key_id=kid, name=name or "")
        return {"id": kid, "key": raw, "prefix": prefix, "expires_at": expires_at,
                "roles": roles, "dropped_roles": abgeschnitten, "kind": kind}

    #: Die Arten eines API-Keys (R6-5), seit 0.22.0 englisch: `automation` arbeitet allein und
    #: trägt nie das Admin-Flag, `human` gilt nur zusammen mit einer Sitzung desselben Kontos.
    _KEY_ARTEN = ("automation", "human")
    #: Die Schreibweise in Audit-Zeilen (`apikey_create … art=`, `apikey_use … art=`): die von
    #: 0.21.x. Audit- und Log-Zeilen ändern sich mit der Übersetzung nicht — Filter der Betreiber
    #: hängen an ihnen (PO-Entscheid 2026-09-27).
    _KEY_ART_AUDIT = {neu: alt for alt, neu in Store.KEY_ARTEN_ALT.items()}

    @staticmethod
    def _key_kind(row) -> str:
        """Die Art einer Key-Zeile mit englischem Namen (Schema 12).

        Ein Wert bis 0.21.x (`automat`, `mensch`) wird abgebildet (`Store.KEY_ARTEN_ALT`) — eine
        ältere Fassung, die nach einem Rückschritt auf der Datei lief, schreibt ihn wieder. Leer
        oder ohne Spalte (Datei vor Schema 7) heisst `automation`. Alles andere bleibt, wie es
        ist, und gilt, weil es nicht `human` ist, als Automaten-Key (fail-closed, R6-6)."""
        return key_kind_of(row)

    @classmethod
    def _key_art_audit(cls, kind) -> str:
        return cls._KEY_ART_AUDIT.get(kind, kind)

    def verify_api_key(self, key):
        """(user, key_roles|None) bei gültigem Key, sonst (None, None).

        Die **Art** des Keys steht danach in `self._letzte_key_art` — `current_user()` braucht
        sie, und eine dritte Rückgabe hätte jeden fremden Aufrufer gebrochen (M-1 friert die
        Oberfläche für 1.0 ein). Wer die Art selbst wissen will, nimmt `api_key_kind(key)`.
        `user` ist ein Konto-Dict wie bei `get_user()` (seit 0.22.0; vorher die Datenbankzeile).
        """
        self._letzte_key_art = "automation"
        if not key or not key.startswith("tsk_"):
            return None, None
        row = self.store.get_api_key_by_hash(hashlib.sha256(key.encode()).hexdigest())
        if not row:
            self._key_protokoll(None, "unbekannt")
            return None, None
        if row["revoked"]:
            self._key_protokoll(row, "widerrufen")
            return None, None
        if row["expires_at"] and row["expires_at"] < _jetzt():
            self._key_protokoll(row, "abgelaufen")
            return None, None
        u = self.store.get_user(row["user_id"])
        if not u or u["disabled"]:
            self._key_protokoll(row, "konto_gesperrt")
            return None, None
        ruht = self._key_ruht(u)
        if ruht:
            self._key_protokoll(row, ruht)
            return None, None
        self.store.touch_api_key(row["id"])
        self._key_protokoll(row, None)
        self._letzte_key_art = self._key_kind(row)
        try:
            kr = json.loads(row["roles"] or "[]")
        except Exception:
            kr = []
        return self._als_dict(u), (kr or None)

    def _key_ruht(self, u) -> Optional[str]:
        """Ruhen die API-Keys dieses Kontos, weil der Identity Provider es nicht (mehr) trägt?
        Rückgabe: der Grund (`idp_nein`, `idp_unbestaetigt`) oder None (Fund 8).

        Nur für Konten mit OIDC-Bindung, und nur, solange OIDC eingerichtet ist — ohne Provider
        gäbe es niemanden, der bestätigen könnte, und jeder Key stünde nach der Frist still.

        * **Nein des Providers** (`idp_bestaetigt_at = 0`, gesetzt von der Nachprüfung 4a): Die
          Sitzung endete dort schon; ohne diese Prüfung lief ein Automaten-Key weiter, bis zu
          `apikey_default_days` lang — derselbe Fehler, den PocketID bis 2.5.0 selbst hatte
          (CVE-2026-43983: gesperrtes Konto behält den Zugriff über ein altes Token).
        * **Keine Bestätigung binnen `oidc_apikey_confirm_days`**: Wer nur noch per Skript
          arbeitet, hat keine Sitzung, die 4a nachprüft. So fällt ein beim Provider gesperrtes
          Konto spätestens nach der Frist auf.

        Gelöscht wird nichts: `invalid_grant` unterscheidet nicht zwischen „gesperrt" und „nur
        abgelaufen" (RFC 6749 5.2) — die nächste Anmeldung über den Provider weckt die Keys."""
        if self.oidc is None:
            return None
        try:
            stand = u["idp_bestaetigt_at"]
        except (IndexError, KeyError):
            return None                       # Zeile ohne die Spalte: nur vor `_migrate`
        if not self.store.ist_oidc_konto(u["id"]):
            return None
        if int(stand if stand is not None else 1) <= 0:
            return "idp_nein"
        frist = int(self.cfg.oidc_apikey_confirm_days or 0) * 86400
        if frist and (stand is None or _jetzt() - int(stand) > frist):
            return "idp_unbestaetigt"
        return None

    def _idp_nein(self, user_id, name, ip, client, grund) -> None:
        """Der Provider hat Nein gesagt (4a): Sitzung ist schon beendet — jetzt ruhen auch die
        Keys (Fund 8). Eine Zeile im Audit-Log nennt, wie viele es betrifft."""
        self.store.idp_verweigert(user_id)
        aktiv = [k for k in self.store.list_api_keys(user_id) if not k["revoked"]]
        if aktiv:
            self.store.audit_log("api_keys_ruhen", name, ip,
                                 f"client={client} grund={grund} anzahl={len(aktiv)}")

    #: Wie lange dieselbe Key-Nutzung (Key, IP, Ausgang) nicht erneut ins Audit-Log geht (B5-05).
    #: Ein Key ist für Automatiken da, die ihn im Sekundentakt vorlegen; eine Zeile je Anfrage
    #: begrübe das übrige Log. Eine je Stunde und Adresse beantwortet die Fragen, die man nach
    #: einem Abfluss stellt: seit wann, von wo, und kam eine NEUE Adresse dazu.
    _APIKEY_AUDIT_FENSTER = 3600
    _DROSSEL_MAX = 10000

    def _einmal_je(self, schluessel, fenster_sek: float) -> bool:
        """True, wenn `schluessel` im Fenster noch nicht protokolliert wurde — und merkt ihn vor.

        Für Ereignisse, die in Salven kommen (Key-Nutzung, abgewiesene Forward-Auth). Je Prozess;
        mehrere Worker schreiben also je eine Zeile, das ist gewollt billiger als ein Abgleich.
        """
        jetzt = _jetzt()
        if jetzt - self._protokoll_drossel.get(schluessel, 0) < fenster_sek:
            return False
        if len(self._protokoll_drossel) >= self._DROSSEL_MAX:
            self._protokoll_drossel.clear()   # Deckel: wer Adressen durchprobiert, füllt keinen Speicher
        self._protokoll_drossel[schluessel] = jetzt
        return True

    def _key_protokoll(self, row, grund: Optional[str]) -> None:
        """Eine Key-Nutzung (grund=None) oder -Abweisung protokollieren — gedrosselt (B5-05).

        Bis hierhin kannte das System von einem Key nur `last_used`: kein Wer, kein Woher, und
        ein abgewiesener Key hinterliess gar nichts. Gerade der ist aber das Signal — ein
        widerrufener Key, der weiter anklopft, heisst: Er liegt noch irgendwo, oder er ist
        abgeflossen. Die IP kommt aus der laufenden Anfrage (`_ANFRAGE`).
        """
        a = _ANFRAGE.get() or {}
        ip = a.get("ip")
        kid = row["id"] if row is not None else None
        if not self._einmal_je(("apikey", kid, ip, grund), self._APIKEY_AUDIT_FENSTER):
            return
        besitzer = self._kontoname(row["user_id"]) if row is not None else None
        art = self._key_art_audit(self._key_kind(row)) if row is not None else "?"
        if grund is None:
            self.store.audit_log("apikey_use", besitzer, ip, f"key={kid} art={art}")
            return
        detail = f"key={kid} grund={grund}" if kid is not None else f"grund={grund}"
        self.store.audit_log("apikey_denied", besitzer, ip, detail)
        security.seclog.warning("api key denied user=%s ip=%s grund=%s",
                                security.fuer_log(besitzer or "-"), security.fuer_log(ip), grund)

    def api_key_kind(self, key) -> str:
        """Die Art eines Keys (`"automation"`/`"human"`, bis 0.21.x `"automat"`/`"mensch"`) —
        ohne ihn zu benutzen. `""` für einen unbekannten Key."""
        row = self.store.get_api_key_by_hash(hashlib.sha256((key or "").encode()).hexdigest())
        return self._key_kind(row) if row else ""

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

    def list_api_keys(self, user_id) -> list:
        """Die API-Keys eines Kontos — ohne die Schlüssel selbst, die gibt es nur einmal bei der
        Ausgabe. Je Key ein Dict (Spalten von `api_key`), `kind` mit englischem Namen (Schema 12;
        bis 0.21.x die Datenbankzeile mit dem gespeicherten Wert)."""
        return [{**dict(k), "kind": self._key_kind(k)} for k in self.store.list_api_keys(user_id)]

    def revoke_api_key(self, key_id, user_id=None):
        """Einen Key entwerten. Er bleibt in der Liste stehen — wer ihn ausgestellt hat, soll das sehen."""
        besitzer = self.store.api_key_owner(key_id)
        vorher = self.store.count_active_api_keys(besitzer) if besitzer is not None else 0
        self.store.revoke_api_key(key_id, user_id)
        self.audit("apikey_revoke", self._kontoname(besitzer), detail=f"key={key_id}")
        if besitzer is not None and self.store.count_active_api_keys(besitzer) < vorher:
            self._sicherheitsereignis("api_key_revoked", besitzer, key_id=key_id)

    #: Warum alle Keys eines Kontos widerrufen wurden — `reason` im Ereignis `api_keys_revoked`
    #: (`on_security_event`). Bis 0.21.x deutsch (`sperre`, `admin_passwort`, `passwort_reset`,
    #: `sitzungen_beendet`), mit den Schlüsseln `anzahl`/`grund` statt `count`/`reason`.
    _KEYS_WIDERRUFEN_GRUENDE = ("account_disabled", "admin_password_reset", "password_reset",
                                "sessions_revoked")

    def _keys_widerrufen(self, user_id, grund: str) -> int:
        """Alle gültigen Keys eines Kontos entwerten — und den Inhaber benachrichtigen (Grenze e).

        Der eine Weg für Reset, Sperre, Admin-Passwort und `sessions/revoke`: Vorher stand der
        Widerruf dort nur im Audit-Log, der Inhaber erfuhr nichts. `grund` ist einer aus
        `_KEYS_WIDERRUFEN_GRUENDE`."""
        if grund not in self._KEYS_WIDERRUFEN_GRUENDE:
            raise ValueError(f"unbekannter Grund {grund!r} — erlaubt: {self._KEYS_WIDERRUFEN_GRUENDE}")
        n = self.store.revoke_user_api_keys(user_id)
        if n:
            self._sicherheitsereignis("api_keys_revoked", user_id, count=n, reason=grund)
        return n

    def set_password(self, user_id, password):
        """Das Passwort eines Kontos setzen (ohne das alte zu prüfen — das ist Sache des Aufrufers).

        Die Passwortregel (`password_policy_error`) prüft hier **nicht** — das tun die Setzstellen
        (Registrierung, Reset, Kontoseite, Admin-Panel, CLI), weil nur sie eine lesbare Antwort
        geben können. Wer diese Methode aus eigenem Code ruft, fragt vorher `password_policy_error()`.
        Benachrichtigt wird immer (`password_changed`), egal über welchen Weg."""
        self.store.set_password_hash(user_id, hash_password(password))
        self._sicherheitsereignis("password_changed", user_id)

    @staticmethod
    def _blockliste_laden(pfad) -> frozenset:
        """Die Betreiber-Blockliste (`password_blocklist_file`) einlesen — einmal, beim Start.

        Fehlt die Datei, bricht der Start ab (`ConfigError`) statt still ohne Liste
        weiterzulaufen: Wer eine Liste angibt, verlässt sich auf sie. Zeilen, die kein UTF-8
        sind, liest `blockliste_lesen` als Latin-1 — sonst kam hier ein roher
        `UnicodeDecodeError` statt einer brauchbaren Liste (A-3)."""
        if not pfad:
            return frozenset()
        try:
            return _pw.blockliste_lesen(pfad)
        except OSError as e:
            raise ConfigError(f"password_blocklist_file {pfad!r} lässt sich nicht lesen: {e}") from e

    def password_policy_error(self, password, *, username=None, email=None, api: bool = False) -> Optional[str]:
        """Die Passwortregel für ein NEUES Passwort — `None` heisst „in Ordnung", sonst der
        übersetzte Grund (`api=True`: der Text für eine JSON-Antwort).

        Eine Regel für alle Setzstellen: Registrierung, Passwort-Reset, Kontoseite und das
        Admin-Panel (dort fehlte bis zu T-13 jede Prüfung, Fund B2-13). Sie prüft Mindest-
        (`password_min_length`) und Höchstlänge (R4-07), die eingebaute plus die eigene
        Blockliste und kontextbezogene Wörter — Dienstname (`rp_name`), Benutzername und der
        Namensteil der E-Mail-Adresse (B2-5/H-17). Einzelheiten: `passwords.passwort_mangel`."""
        kontext = [self.cfg.rp_name, username or ""]
        if email:
            kontext.append(str(email).split("@", 1)[0])
        befund = _pw.passwort_mangel(password or "", self._passwort_mindestlaenge(),
                                     kontext=kontext, blockliste=self._blockliste)
        if befund is None:
            return None
        grund, werte = befund
        schluessel = {"short": ("api.password_short", "err.pw_short"),
                      "long": ("api.password_long", "err.pw_long"),
                      "weak": ("api.password_weak", "err.pw_weak")}[grund]
        return self.t(schluessel[0] if api else schluessel[1], **werte)

    def _passwort_allein_moeglich(self) -> bool:
        """Kann das Passwort in dieser Konfiguration ALLEIN vollständig anmelden?

        Ja im klassischen Modus (keine `login_chain`): Ein Konto ohne TOTP meldet sich mit dem
        Passwort allein an — und ein TOTP lässt sich später wieder entfernen. Ja auch bei einer
        Kette, die ausser dem Passwort nichts verlangt. Nein erst, wenn die globale Kette einen
        weiteren Faktor erzwingt (`["password", "totp"]`, `["oidc", "password"]`).

        Bewusst eine Aussage über die KONFIGURATION, nicht über das einzelne Konto: Wer heute
        TOTP hat, kann es morgen entfernen, und das Passwort bliebe mit der kürzeren Länge allein
        stehen.

        Und nur mit `mfa_enrollment="strict"`: Bei `"first_login"` (Vorgabe) und `"grace"` richtet
        ein Konto den verlangten zweiten Faktor beim ersten Mal selbst ein — wer nur das Passwort
        kennt, bindet dann seinen eigenen Authenticator und ist drin. Genau die Erstpasswörter
        (Panel, Einladung, Registrierung) melden in diesem Fenster also allein an (gemessen im
        Angriff auf B2-4). Erst wenn der Betreiber die Einrichtung vergibt, ist das Passwort nie
        allein. Grenze: ein vom Betreiber geöffnetes Fenster (`grant_mfa_enrollment`) — das ist
        seine bewusste Entscheidung für genau ein Konto."""
        kette = list(self.cfg.login_chain or ())
        if not kette or not (set(kette) - {"password"}):
            return True
        return self.cfg.mfa_enrollment != "strict"

    def _passwort_mindestlaenge(self) -> int:
        """Die Mindestlänge für ein NEUES Passwort (B2-4, NIST SP 800-63B-4, 3.1.1.2).

        Die Norm verlangt 15 Zeichen, wenn das Passwort allein anmelden kann, und 8, wenn es nur
        Teil einer Anmeldung mit weiterem Faktor ist. Beide Werte sind im Panel einstellbar
        (`password_min_length_single_factor`, `password_min_length`); wer die strengere Regel
        nicht will, setzt die erste auf 8. Bestehende Passwörter bleiben gültig — die Regel gilt,
        wo ein Passwort gesetzt wird."""
        basis = self._sec("password_min_length")
        if self._passwort_allein_moeglich():
            return max(basis, self._sec("password_min_length_single_factor"))
        return basis

    # ---------- Benachrichtigung bei Sicherheitsereignissen (Opt-in) ----------
    #: Die Ereignisse, zu denen `on_security_event` gerufen wird — alles, was einen Anmelde-
    #: faktor des Kontos anlegt, ändert, entfernt oder verbraucht. Seit T-13 (Grenze e) auch der
    #: Widerruf von API-Keys: einzeln (`api_key_revoked`) und gesammelt bei Reset, Sperre und
    #: `sessions/revoke` (`api_keys_revoked`, mit Anzahl und Grund). NIST SP 800-63B verlangt, den Inhaber über solche Änderungen zu
    #: benachrichtigen; bis T-13 erfuhr er von keiner (Fund B2-2): Ein Angreifer mit einer
    #: Sitzung konnte TOTP abschalten, einen Passkey hinzufügen oder das Passwort ändern, und der
    #: Inhaber sah es erst beim nächsten Login — wenn überhaupt. Die Details (drittes Argument
    #: des Hooks), seit 0.22.0 mit englischen Schlüsseln: `api_key_created` `key_id`, `name`;
    #: `api_key_revoked` `key_id`; `api_keys_revoked` `count`, `reason` (`account_disabled`,
    #: `admin_password_reset`, `password_reset`, `sessions_revoked`); `totp_disabled`
    #: `recovery_codes_deleted`; `recovery_codes_generated` `count`; `recovery_code_used`
    #: `remaining`; `passkey_added` `name`; `passkey_removed` `passkey_id`; `username_changed`
    #: und `email_changed` `old`, `new`; die übrigen keine.
    SECURITY_EVENTS = (
        "password_changed", "pin_set", "pin_disabled", "totp_enabled", "totp_disabled",
        "recovery_codes_generated", "recovery_code_used", "passkey_added", "passkey_removed",
        "api_key_created", "api_key_revoked", "api_keys_revoked",
        "email_changed", "username_changed",
    )

    def _sicherheitsereignis(self, ereignis: str, user_id, **details) -> None:
        """`on_security_event` für ein Ereignis aus `SECURITY_EVENTS` rufen, falls gesetzt.

        Ein Fehler im Hook bricht den Vorgang **nicht** ab — die Änderung ist zu diesem Zeitpunkt
        schon geschrieben, und ein ausgefallener Mailserver darf den Passwortwechsel nicht
        scheitern lassen. Er landet aber im Sicherheits-Log: Eine Benachrichtigung, die still
        ausbleibt, ist schlechter als keine, auf die sich niemand verlässt. Der Hook läuft
        synchron im Request; wer Mails verschickt, reiht sie besser in eine Warteschlange ein."""
        hook = self.on_security_event
        if hook is None:
            return
        zeile = self.store.get_user(user_id)
        if zeile is None:
            return
        konto = {"id": zeile["id"], "username": zeile["username"], "email": zeile["email"],
                 "display_name": zeile["display_name"]}
        try:
            hook(ereignis, konto, dict(details))
        except Exception as e:
            security.seclog.warning("on_security_event fehlgeschlagen ereignis=%s user_id=%s: %s",
                                    ereignis, zeile["id"], security.fuer_log(repr(e)))

    def ensure_admin(self, username, password) -> bool:
        """Bootstrap: legt einen Admin an, WENN noch kein User existiert. True bei Anlage."""
        if self.store.user_count() == 0:
            uid = self.create_user(username, password, is_admin=True)
            self._erster_owner(uid)
            return True
        return False

    # ---------- Erst-Admin (Bootstrap) ----------
    # Bewusst NICHT "der erste registrierte User wird Admin": bei offener Registrierung gewinnt,
    # wer als Erstes da ist — auch ein Fremder, der die frische Instanz findet. Stattdessen zwei
    # explizite Wege, beide nur wirksam, SOLANGE es keinen Admin gibt — die Allowlist zudem nie
    # mehr, nachdem der Identity Provider der Instanz ihren letzten Admin entzogen hat (G6).
    def delete_user(self, user_id: int) -> bool:
        """Ein Konto samt aller Zugangsdaten löschen (B5-08) — und es aus dem Audit-Log nehmen (H-13).

        Die Audit-Zeilen bleiben stehen (was geschah, wann, von welcher IP), nur der Name wird zu
        `gelöscht#<id>` — auch bei Anmeldeversuchen unter der E-Mail-Adresse und dort, wo Name
        (`akteur=`) oder Adresse im Detailtext stehen (s. `Store.audit_anonymisieren`). Ein
        gelöschtes Konto, dessen Name weiter in jeder Zeile steht, ist nicht gelöscht; ein Log,
        dem die Zeilen fehlen, taugt nicht mehr zur Aufarbeitung.

        Die Anmeldeversuche verschwinden unter jeder Schreibweise, unter der der Sperr-Topf sie
        zählt (NFKC, IDNA, s. `Store.delete_attempts_for`). Ausnahme: ein Topf, den ein
        verbleibendes Konto teilt (`ｃｌａｒａ` und `clara`) — der bleibt bis zum gewöhnlichen
        Aufräumen stehen, sonst höbe das Löschen des einen die Sperre des anderen auf.

        Ersetzt wird, was ab der Anlage des Kontos entstand; eine BELEGTE Adresse auch in
        älteren Zeilen (etwa in der Einladung, die zu dem Konto führte) — sie gehört dem Konto
        nachweislich (`Store.adresse_belegt`). Die Adresse eines offenen Kontos (Link nie
        eingelöst) oder einer Registrierung ohne Bestätigungspflicht ist nicht belegt; sie hat
        womöglich ein Fremder eingetippt. Ein Name gehörte vor der Anlage niemandem oder jemand
        anderem; ein Fehlversuch darunter bleibt, wie er war (s. `Store.konto_entfernen`).

        Der letzte Admin lässt sich nicht löschen (`StateError`) — sonst stünde die Instanz ohne
        Verwaltung da, und der Erst-Admin-Weg öffnete sich für den Nächstbesten. Gibt False
        zurück, wenn es das Konto nicht gibt.
        """
        u = self.store.get_user(user_id)
        if not u:
            return False
        if u["is_owner"]:
            raise StateError(f"Konto {user_id} ist Owner und kann nicht gelöscht werden — erst die "
                             "Owner-Rolle abgeben (dazu muss ein anderer Owner bestehen).")
        if u["is_admin"] and sum(1 for x in self.store.list_users() if x["is_admin"]) <= 1:
            raise StateError(f"Konto {user_id} ist der letzte Admin und kann nicht gelöscht werden.")
        # Der eine Löschweg (`Store.konto_entfernen`) — derselbe, über den `gc()`, `tinysesam gc`
        # und die Rücknahme einer Registrierung löschen (Integrationsfunde 12/18). Nur hier, bei
        # der bewussten Löschung, gilt eine belegte Adresse auch vor der Anlage als die des
        # Kontos — die anderen Wege kann ein Fremder auslösen (`Store.adresse_belegt`).
        entfernt = self.store.konto_entfernen(user_id, adresse_unbefristet=True)
        if entfernt is None:
            return False
        ersatz, n = entfernt
        self.audit("user_delete", ersatz, detail=f"uid={user_id} audit_anonymisiert={n}")
        return True

    def set_disabled(self, user_id: int, disabled: bool) -> bool:
        """Ein Konto als Betreiber sperren oder entsperren — mit derselben Wirkung wie das Panel
        (`POST <admin_path>/api/users/{id}/disable`, das genau diese Methode ruft).

        **Sperren** (`disabled=True`):

        * mit Betreiber-Vermerk: Kein Bestätigungslink hebt die Sperre auf, auch einer nicht, der
          erst danach entsteht (H-18) — nur `set_disabled(user_id, False)`;
        * alle Sitzungen des Kontos enden, seine API-Keys werden widerrufen (Ereignis
          `api_keys_revoked` mit `reason="account_disabled"`), offene Einmal-Token verworfen
          (Anmelde-, Bestätigungs-, Reset-, Adresswechsel-Link). Der Widerruf der Keys bleibt
          beim Entsperren bestehen — sonst lebte ein Key wieder auf, von dem niemand mehr weiss;
        * ein **Owner** lässt sich nicht sperren: `StateError`, und nichts ist geschehen.

        **Entsperren** hebt jede Sperre auf, auch die einer ausstehenden Bestätigung.

        Audit wie im Panel: `user_disable` bzw. `user_enable` mit `uid=<id>` (beim Sperren mit
        Keys dazu `api_keys_revoked=<n>`) — in einer Anfrage unter dem angemeldeten Konto (dem
        Admin), ohne Anfrage unter dem betroffenen. Was vom Aufrufer abhängt, prüft die Route: Das
        Panel lässt niemanden sich selbst sperren und ein Owner-Konto nur von einem Owner ändern.
        Rückgabe False, wenn es das Konto nicht gibt (dann geschieht nichts).

        Bis 0.21.x zeigte die Doku dafür `auth.store.set_disabled(uid, True, durch_betreiber=True)`
        — das setzt nur den Vermerk: Sitzungen, Keys und Links blieben gültig. `auth.store` ist
        Innenleben ohne Zusage (PO-Entscheid 2026-09-27)."""
        u = self.store.get_user(user_id)
        if not u:
            return False
        uid = int(u["id"])
        # Zuerst der Vermerk: Bei einem Owner wirft der Store, bevor irgendetwas geschehen ist.
        self.store.set_disabled(uid, bool(disabled), durch_betreiber=True)
        keys = 0
        if disabled:
            self.store.delete_user_sessions(uid)
            # `verify_api_key` lehnt Keys gesperrter Konten schon ab. Trotzdem widerrufen: Wird
            # das Konto später wieder freigegeben, lebte sonst ein Key wieder auf, von dem
            # niemand mehr weiss.
            keys = self._keys_widerrufen(uid, "account_disabled")
            # Dasselbe für offene Einmal-Token: Ein Bestätigungslink aus der Registrierung hob die
            # Sperre sonst wieder auf (H-18, „deaktiviertes Konto über keinen Pfad").
            self.store.revoke_user_magic_tokens(uid)
        # Aus einer Anfrage mit angemeldetem Konto (Panel, eigene Admin-Route) nennt `audit()` den
        # Akteur als Konto — dieselbe Zeile, die das Panel bis 0.21.x selbst schrieb.
        anfrage = _ANFRAGE.get() or {}
        self.audit("user_disable" if disabled else "user_enable",
                   None if anfrage.get("akteur") else str(u["username"]),
                   detail=f"uid={uid}" + (f" api_keys_revoked={keys}" if keys else ""))
        return True

    #: Wie die Kontoseite ein Ereignis nennt, wenn es nicht sein eigener Name ist (G12b). Der
    #: Antrag auf eine vergebene oder eine Allowlist-Adresse erscheint wie jeder Antrag — sonst
    #: stünde auf der Kontoseite, was die Antwort verschweigt. `None` blendet aus:
    #: `federation_email_confirm` entsteht nur, wenn der Link an eine FREIE Adresse hinausging, und
    #: verriete dasselbe einem LDAP-Nutzer, der sein `mail`-Attribut selbst setzt. Ebenso
    #: `ldap_kennung_abgewiesen` (Prüfrunde 2026-09-27): Die Zeile steht unter der eingetippten
    #: Kennung und entsteht nur, wenn das LDAP-Passwort des ANDEREN Eintrags stimmte — auf der
    #: Kontoseite des lokalen Inhabers wäre sie genau das Orakel, das die Abweisung schliesst. Das
    #: Audit-Log des Betreibers behält die echten Namen.
    _EIGENE_ANSICHT = {"email_change_taken": "email_change_requested",
                       "email_change_reserved": "email_change_requested",
                       "federation_email_confirm": None,
                       "ldap_kennung_abgewiesen": None}

    def own_events(self, user_id: int, limit: int = 20) -> list:
        """Die jüngsten Audit-Ereignisse eines Kontos, für die Kontoseite (H-7).

        Nur Zeit, Ereignis und IP — das Detail bleibt beim Betreiber: Bei einer Admin-Aktion
        nennt es fremde Konten, und eine Anzeige für den Kontoinhaber soll nicht mehr zeigen als
        sein eigenes Konto. Genau das, was man dort sucht: „War das ich?"

        Hat ein ANDERER die Zeile ausgelöst (`akteur=` im Detail, s. `audit()`), steht dort
        dessen IP — die des Admins. Die bleibt weg; `by_admin` sagt stattdessen, dass es nicht
        der Kontoinhaber war.

        Gezählt wird erst ab der Anlage des Kontos (`Store.anlage_grenze`). Der Filter geht über
        den NAMEN, und ein Name kann vorher einem anderen gehört haben: einem gelöschten Konto,
        dessen Zeilen ein älterer Stand nicht anonymisiert hat (Integrationsfund 12), oder
        niemandem — dann steht dort der Fehlversuch eines Fremden unter dem damals freien Namen,
        samt seiner IP.

        Seit 2026-09-26 zählt nicht die Anlage, sondern der Beitritt des NAMENS (G2): Wer einen
        freigewordenen Namen übernimmt (Umbenennen), sah vorher die Anmeldung des Vorbesitzers
        samt dessen IP. Die Anlage bleibt der Rückfall für den Bestand ohne Wasserlinie.

        Ebenfalls seit 2026-09-26 zeigt sie einen Adresswechsel-Antrag immer als
        `email_change_requested`, ob die Adresse frei, vergeben oder reserviert war, und
        `federation_email_confirm` gar nicht (`_EIGENE_ANSICHT`, G12b). Eine Abweisung BEIM
        BESTÄTIGEN (`beim_bestaetigen=1`) behält ihren Namen: Die 409 hat sie dem Klickenden
        ohnehin gesagt, und nur, wer den Link aus dem Postfach hat, kommt dorthin.
        """
        u = self.store.get_user(user_id) if user_id is not None else None
        if not u:
            return []
        aus = []
        # Dieselbe Grenze wie `konto_entfernen`: die Wasserlinie des Namens, sonst die Anlage.
        name = str(u["username"])
        audit_ab = self.store.kennung_grenzen(u).get(norm_kennung(name), (None, None))[1]
        seit, seit_id = self.store.anlage_grenze(u) if audit_ab is None else (None, 0)
        ausblenden = tuple(e for e, ansicht in self._EIGENE_ANSICHT.items() if ansicht is None)
        for z in self.store.recent_audit(max(1, int(limit)), username=name, seit=seit, seit_id=seit_id,
                                         ab_id=audit_ab, ohne_events=ausblenden):
            fremd = bool(re.search(r"(?:^|\s)akteur=", z["detail"] or ""))
            ereignis = z["event"]
            if not re.search(r"(?:^|\s)beim_bestaetigen=1(?:\s|$)", z["detail"] or ""):
                ereignis = self._EIGENE_ANSICHT.get(ereignis, ereignis)
            aus.append({"ts": z["ts"], "event": ereignis,
                        "ip": None if fremd else z["ip"], "by_admin": fremd})
        return aus

    def admin_exists(self) -> bool:
        """Gibt es mindestens einen Admin? Die beiden Bootstrap-Wege greifen nur, solange nicht."""
        return any(u["is_admin"] for u in self.store.list_users())

    #: Faktoren, mit denen die Identität von einem FREMDEN Anbieter kommt. Für sie gilt in
    #: `_maybe_promote_admin` fail-closed: Ohne ausdrücklichen Beleg trägt eine Allowlist-Adresse
    #: dort keine Erst-Admin-Entscheidung — ein neuer föderierter Weg, der den Beleg zu
    #: übergeben vergisst, befördert also nicht, sondern verweigert.
    #: `ldap` steht bewusst nicht hier: LDAP schreibt den Faktor `password` (s. `_check_ldap`),
    #: ist am Faktornamen also nicht zu erkennen — sein Aufrufer reicht den Beleg, den es dort
    #: gar nicht gibt, ausdrücklich als `False` durch.
    _FOEDERIERTE_FAKTOREN = ("oidc", "saml")

    def _maybe_promote_admin(self, user, email_bestaetigt: Optional[bool] = None,
                             faktor: Optional[str] = None) -> bool:
        """Weg 1: Allowlist. Wer in `admin_identifiers` steht, wird beim Login Admin — egal über
        welche Methode (auch OIDC/SAML/LDAP); eine Allowlist-ADRESSE aber nur mit einem Beleg,
        dass sie dem Anmeldenden gehört, und über SAML/LDAP gibt es keinen. Danach nie wieder —
        auch nicht, nachdem der Identity Provider der Instanz ihren letzten Admin entzogen hat (G6).

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
           Gedächtnis des Aufrufers hängt: `faktor` aus `_FOEDERIERTE_FAKTOREN` verlangt
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

        **Nach einem Entzug durch den Identity Provider nie wieder** (G6): Hat der Provider der
        Instanz ihren letzten Admin genommen (`apply_idp_groups`, H-5), befördert die Allowlist
        niemanden mehr — sonst machte sie die Person im selben Login wieder zum Admin „von Hand"
        und Erst-Owner, den kein Provider mehr entzieht (Audit `admin_bootstrap_denied
        nach_idp_entzug`). Zurück ins Panel führen dann das Einmal-Token (`/auth/claim-admin`,
        sofort ausgegeben) und `tinysesam owner`.
        """
        ids = {str(i).strip().lower() for i in self.cfg.admin_identifiers if str(i).strip()}
        if not ids or not user or user["is_admin"] or self.admin_exists():
            return False
        adressen = {i for i in ids if "@" in i}
        namen = ids - adressen
        trifft_adresse = str(user["email"] or "").lower() in adressen
        trifft_name = str(user["username"] or "").lower() in namen
        if not (trifft_adresse or trifft_name):
            return False
        if self.store.get_setting("allowlist_nach_idp_entzug"):
            # G6: Der Identity Provider hat der Instanz ihren letzten Admin entzogen
            # (`apply_idp_groups`) — die Allowlist öffnet sich danach nicht wieder, für niemanden.
            security.seclog.warning(
                "Erst-Admin NICHT vergeben: %s steht in admin_identifiers, aber der Identity "
                "Provider hat der Instanz ihren letzten Admin entzogen — die Allowlist öffnet sich "
                "danach nicht wieder. Notweg: tinysesam owner --db <datei> <benutzer> oder "
                "/auth/claim-admin.", security.fuer_log(user["username"]))
            self.audit("admin_bootstrap_denied", user["username"], detail="nach_idp_entzug")
            return False
        if trifft_adresse and not trifft_name:
            # Zwei Stufen, beide fail-closed: Ein ausdrücklicher Beleg des Anmeldewegs gewinnt.
            # Schweigt der Weg (`None`), verweigert ein föderierter Faktor grundsätzlich — auch
            # wenn er das Argument schlicht vergessen hat —, und sonst entscheidet der Vermerk
            # am Konto.
            if email_bestaetigt is not None:
                belegt, grund = email_bestaetigt is True, "email_unbestaetigt"
            elif (faktor or "") in self._FOEDERIERTE_FAKTOREN:
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
                    security.fuer_log(user["username"]), security.fuer_log(user["email"]),
                    faktor or "?")
                self.audit("admin_bootstrap_denied", user["username"], detail=grund)
                return False
        self.store.set_admin(user["id"], True)
        self._erster_owner(user["id"])
        self.audit("admin_bootstrap", user["username"], detail="admin_identifiers")
        security.seclog.warning("Erst-Admin per admin_identifiers vergeben: %s",
                                security.fuer_log(user["username"]))
        return True

    def _claim_datei_auto(self) -> str:
        """`<db_path>.claim` — wohin das Einmal-Token geht, wenn stderr keine Konsole ist (T-17).

        Neben der Datenbank, weil dort ohnehin schreiben darf, wer den Dienst betreibt, und weil
        auch `<db_path>.key` dort liegt. Leer ohne Datei (`:memory:`): Dann bleibt nur stderr.
        """
        db = str(self.cfg.db_path or "").strip()
        return "" if db in ("", ":memory:") else db + ".claim"

    def _claim_datei_weg(self) -> None:
        """Die automatisch angelegte Token-Datei entfernen — nach dem Einlösen, und beim Start,
        wenn es kein Token (mehr) gibt. Eine selbst gewählte `admin_claim_token_file` bleibt
        stehen (ihr Pfad kann ein eingehängtes Geheimnis sein); ihr Inhalt ist dann ungültig."""
        pfad = self._claim_datei_auto()
        if pfad:
            try:
                os.remove(pfad)
            except FileNotFoundError:
                pass  # schon weg (nie angelegt oder bereits eingelöst) — genau der Zielzustand
            except OSError as e:
                security.seclog.warning("Token-Datei %s liess sich nicht entfernen (%s) — ihr "
                                        "Inhalt ist ungültig.", pfad, type(e).__name__)

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

        **Seit 0.22.0 (T-17) auch ohne diese Einstellung:** Ist stderr keine Konsole (Container,
        journal, Pipe — `sys.stderr.isatty()` falsch), schreibt TinySesam den Token nach
        `<db_path>.claim` (0600) und nennt nur den Pfad. Bis dahin stand er dort im Klartext in
        `docker logs` — direkt vor der Zeile „Der Wert steht bewusst NICHT im Log". Ohne
        Datenbank-Datei (`:memory:`) oder wenn die Datei nicht entsteht, bleibt nur stderr, und
        der Text sagt ehrlich, dass der Wert dann im Log des Dienstes steht. Nach dem Einlösen
        verschwindet die Datei (`_claim_datei_weg`).
        """
        ttl = self.cfg.admin_claim_ttl_min
        pfad = str(self.cfg.admin_claim_token_file or "").strip()
        konsole = _stderr_ist_konsole()
        automatisch = False
        if not pfad and not konsole:
            pfad = self._claim_datei_auto()
            automatisch = bool(pfad)
        # Was die Zeile im Log sagt, muss stimmen — auch im Rückfall. Bis 0.21.x stand dort
        # „Der Wert steht bewusst NICHT im Log", während er im Container zwei Zeilen darüber stand.
        wohin = ("steht auf der Konsole (stderr), nicht in dieser Zeile" if konsole else
                 "steht auf stderr — und stderr ist hier KEINE Konsole: Der Wert steht damit im "
                 "Log des Dienstes (journal, docker logs). Abhilfe: admin_claim_token_file setzen "
                 "oder eine Datenbank-Datei statt :memory:")
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
                wohin = f"steht in {pfad} (Rechte 0600), nicht im Log"
                geschrieben = True
            except OSError as e:
                # Kein Grund, den Start zu verweigern — aber der Betreiber muss den Token
                # bekommen, sonst kommt er nicht an seine eigene Instanz.
                name = "die Token-Datei" if automatisch else "admin_claim_token_file"
                _auf_stderr(f"TinySesam: {name} {pfad} nicht schreibbar "
                            f"({type(e).__name__}) — der Token steht stattdessen hier:")
                wohin = f"{wohin} ({pfad} war nicht schreibbar: {type(e).__name__})"
        if not geschrieben:
            _auf_stderr(f"TinySesam: Kein Admin vorhanden. Ersten Admin setzen — anmelden, dann "
                        f"/auth/claim-admin?token={token} (gültig {ttl} Minuten, genau einmal "
                        f"einlösbar).")
        security.seclog.warning(
            "Kein Admin vorhanden. Das Einmal-Token für /auth/claim-admin %s — gültig %d "
            "Minuten, genau einmal einlösbar.", wohin, ttl)

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
        now = _jetzt()
        if raw:
            token, exp = raw.split(":", 1)
            if int(exp) > now:
                return token
        token = secrets.token_urlsafe(24)
        self.store.set_setting("admin_claim", f"{token}:{now + self.cfg.admin_claim_ttl_min * 60}")
        return token

    def _consume_admin_claim(self, token, user) -> bool:
        """Das Einmal-Token einlösen und dieses Konto zum Admin machen. Gilt genau einmal."""
        if not token or not user or not self.cfg.admin_enabled or self.admin_exists():
            return False
        raw = self.store.get_setting("admin_claim")
        if not raw:
            return False
        want, exp = raw.split(":", 1)
        if int(exp) <= _jetzt() or not secrets.compare_digest(token, want):
            return False
        self.store.set_setting("admin_claim", "")     # einmalig
        self._claim_datei_weg()                        # die Datei trägt nur noch Ungültiges (T-17)
        self.store.set_admin(user["id"], True)
        self._erster_owner(user["id"])
        self.audit("admin_bootstrap", user["username"], detail="claim_token")
        security.seclog.warning("Erst-Admin per Einmal-Token vergeben: %s",
                                security.fuer_log(user["username"]))
        return True

    def _admin_claim_fehlgriff(self, username, ip) -> None:
        """Einen gescheiterten Erst-Admin-Claim festhalten — Audit-Log und Sicherheits-Log (B5-16)."""
        self.audit("admin_claim_fail", username, ip)
        security.seclog.warning("%s user=%s ip=%s method=claim_admin", security.LOG_PRUEFUNG,
                                security.fuer_log(username), security.fuer_log(ip))

    # ---------- Demo-Modus ----------
    _DEMO_USERS = ("demo", "demoadmin")

    def _seed_demo(self) -> None:
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
        for name in self._DEMO_USERS:
            u = self.store.get_user_by_name(name)
            if u:
                ids.append(str(u["id"]))
                continue
            uid = self.create_user(name, password=self.cfg.demo_password, is_admin=(name == "demoadmin"))
            if self.cfg.pin_enabled:
                self.set_pin(uid, self.cfg.demo_pin)
            ids.append(str(uid))
        self.store.set_setting("demo_users", ",".join(ids))

    def _purge_demo(self) -> int:
        """Die von `_seed_demo` angelegten Konten wieder entfernen — genau die, keine gleichnamigen."""
        raw = self.store.get_setting("demo_users") or ""
        n = 0
        for sid in filter(None, raw.split(",")):
            u = self.store.get_user(int(sid))
            if u and u["username"] in self._DEMO_USERS:
                # Über den einen Löschweg (H-13): Legt `_seed_demo` die Namen später neu an, sähe
                # das neue Konto sonst die Ereignisse des alten als seine eigenen (H-7).
                self.store.konto_entfernen(u["id"])
                n += 1
        self.store.set_setting("demo_users", "")
        return n

    #: Was ein Konto-Dict der öffentlichen Oberfläche trägt (`current_user`, `session_user`,
    #: `pending_user`, `get_user`, `find_user`, `identifier_taken`, `verify_api_key`,
    #: `LoginResult.user`, die `require_*`-Wächter) — die Spalten, die das Konto beschreiben. Die
    #: Buchhaltung des Stores bleibt draussen: Zähl-Töpfe (`topf_name`, `topf_mail`),
    #: Wasserlinien (`name_versuch_ab` …), Herkunft und Selbstwahl des Namens (`name_quelle`,
    #: `name_selbst_gewaehlt`), die letzte Bestätigung durch den IdP (`idp_bestaetigt_at`). Bis
    #: 0.21.x ging die ganze Zeile hinaus, mit deutschen Spaltennamen; seit 0.22.0 ist die
    #: öffentliche Oberfläche englisch (PO-Entscheid 2026-09-27), und Innenleben gehört nicht in
    #: ihre Zusage. Eine Liste der erlaubten statt der verbotenen Spalten: Eine neue Spalte des
    #: Stores wird nicht still zur Zusage. Dazu kommen je nach Weg `_via` und `_key_kind`.
    _KONTO_FELDER = ("id", "username", "display_name", "email", "email_verified", "is_admin",
                     "is_owner", "roles", "is_service", "disabled", "first_login_at",
                     "mfa_enroll_until", "created_at")

    @classmethod
    def _als_dict(cls, zeile) -> Optional[dict]:
        """Eine Kontozeile als das zurückgeben, was die Signatur verspricht — ein `dict` mit den
        Feldern aus `_KONTO_FELDER`.

        Die nutzerseitigen Methoden sind seit jeher `-> Optional[dict]` annotiert und lieferten
        eine `sqlite3.Row`. Das Paket trägt `Typing :: Typed` und eine `py.typed` — die Zusage
        wurde nur nie gemessen. Praktisch fällt es auf, sobald jemand der Annotation glaubt:
        `u.get("email")` gibt es auf einer Row nicht, und der `AttributeError` kommt aus einer
        Zeile, die laut Typ nicht falsch sein kann. Auf der Store-Ebene bleibt die Row — dort
        ist sie dokumentiert und gewollt, samt allen Spalten.
        """
        if zeile is None:
            return None
        da = set(zeile.keys())
        return {k: zeile[k] for k in cls._KONTO_FELDER if k in da}

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

    def _check_password(self, username, password) -> Optional[dict]:
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
    #: Quellen, die eine fremde Identität über eine stabile Kennung binden (F-11). OIDC steht
    #: nicht dabei: Es hat mit `issuer`+`sub` seit jeher eine eigene, stabilere Zuordnung.
    FEDERATED_SOURCES = ("ldap", "saml")
    #: Platzhalter-Kennung für ein Konto, das über eine Quelle OHNE stabile Kennung kam (A-4).
    #: Die Zeile in `federated_identity` sagt nur „dieses Konto stammt aus LDAP/SAML" — sonst
    #: zählte es für `federated_only()` als lokal und bekäme einen Reset-Link, dessen Passwort
    #: danach vor dem Verzeichnis gewinnt. Je Konto eindeutig (Primärschlüssel quelle+kennung),
    #: nie für eine Zuordnung gelesen, und eine echte Kennung ersetzt ihn beim nächsten Login —
    #: durch dieselbe Tür wie Lage 4 (`_nachbindung_grund`).
    _OHNE_KENNUNG = Store.OHNE_KENNUNG

    def _fremde_identitaet_aufloesen(self, quelle: str, kennung: str, username: str,
                                     anlegen, name_zuordnen: bool = True,
                                     nur_konto: Optional[int] = None) -> Optional[dict]:
        """Ein lokales Konto zu einer fremden Identität finden, binden oder anlegen (F-11).

        `kennung` ist die **stabile** Kennung aus dem Verzeichnis (objectGUID/entryUUID bei LDAP,
        NameID bei SAML), `username` der Name, über den bis 0.19.0 allein zugeordnet wurde.
        `anlegen()` legt ein neues Konto an und gibt dessen ID zurück oder `None`.

        Vier Lagen, und die dritte ist der eigentliche Riegel:

        1. **Die Kennung ist gebunden** → dieses Konto, auch wenn der Name sich geändert hat.
           Genau dafür ist die Bindung da: Eine Umbenennung im Verzeichnis ist kein Kontowechsel.
        2. **Kennung unbekannt, Name frei** → anlegen und binden.
        3. **Kennung unbekannt, Name gehört einem Konto, das schon eine ANDERE Kennung trägt**
           → **abweisen**. Das ist der Angriff: Im Verzeichnis entsteht unter dem Namen einer
           gelöschten Person ein neues Konto, und ohne diesen Riegel erbte es deren lokale Rollen.
        4. **Kennung unbekannt, Name gehört einem noch ungebundenen Konto** → nachbinden. Das ist
           der Bestandsfall: Konten aus der Zeit vor F-11 haben keine Kennung, und irgendwann
           muss jedes von ihnen einmal daran kommen. Der PO hat diesen Weg für diese Runde
           ausdrücklich freigegeben; er verlässt sich noch einmal auf den Namen, aber nur ein
           einziges Mal je Konto, und er hinterlässt eine Audit-Zeile. Seit 2026-09-26 nur noch
           durch eine Tür (`_nachbindung_grund`): nicht nach der Frist
           (`federation_name_binding_days`, G1 — sonst fiele ein ruhendes Konto an die nächste
           Person mit diesem Namen) und nie für einen selbst gewählten Namen
           (`users.name_selbst_gewaehlt`, G2-N — sonst benennt sich ein lokales Konto nach
           jemandem aus dem Verzeichnis und erbt dessen Gruppen) und nie für einen Namen, den eine
           andere Quelle beim Anlegen mitgebracht hat (`users.name_quelle`, Angriffsrunde
           2026-09-26 — derselbe Angriff über `preferred_username` oder SAML), es sei denn, der
           Betreiber hat die Bindung für dieses Konto geöffnet (`federation_unbind`). Sonst
           wird abgewiesen wie in Lage 3. Dasselbe gilt für den Ersatz eines Herkunfts-Platzhalters.

        Ohne Kennung (das Verzeichnis liefert keine) bleibt es beim Namen — dem ungeschützten
        Zustand. Das sagt eine Zeile je Quelle, und `federation_require_stable_id=True` macht
        daraus eine Abweisung. Die ERSTE Zuordnung eines vorhandenen Kontos geht dabei durch
        dieselbe Tür wie Lage 4; ein Konto, das die Quelle schon kennt (Platzhalter), bleibt.

        `name_zuordnen=False`: Der Name ist keine Aussage über die Person — eine unbelegte
        Adresse aus einer Quelle, der der Betreiber nicht traut (`*_email_trusted=False`). Dann
        gibt es weder Lage 4 (nachbinden über den Namen) noch eine Zuordnung ohne Kennung: Wer
        beim IdP die Adresse eines lokalen Kontos als Namen einträgt, übernähme sonst genau
        dieses Konto (Angriff auf die dritte Runde). Ohne Kennung wird abgewiesen, mit Kennung
        gebunden oder neu angelegt — nie über den Namen.

        `nur_konto`: Die Auflösung darf nur bei DIESEM Konto enden (`_check_ldap`: das Konto, dessen
        lokales Geheimnis unter derselben Kennung geprüft wird). Führt sie zu einem anderen — einer
        Bindung, einem Namen, einer Anlage —, wird abgewiesen, bevor irgendetwas geschrieben ist
        (`_kennung_zweier_konten`). None: keine Einschränkung.
        """
        jetzt = _jetzt()
        roh = str(kennung or "")
        kennung = roh.strip()
        formfehler = self._kennung_formfehler(roh)
        if formfehler:
            security.seclog.warning("%s: Kennung %s abgewiesen (user=%s)", quelle,
                                    "mit Rand- oder Steuerzeichen" if formfehler == "Rand-/Steuerzeichen"
                                    else "in Platzhalter-Form", security.fuer_log(username))
            self.audit(f"{quelle}_kennung_ungueltig", username, detail=formfehler)
            return None
        if not kennung and not name_zuordnen:
            security.seclog.warning(
                "%s: Name ist eine unbelegte Adresse und es gibt keine stabile Kennung (user=%s) — "
                "abgewiesen. Eine Zuordnung über diesen Namen wäre eine Übernahme. Abhilfe: "
                "%s_attr_id setzen oder der Quelle trauen (%s_email_trusted).",
                quelle, security.fuer_log(username), quelle, quelle)
            self.audit(f"{quelle}_ohne_kennung", username, detail="abgewiesen: Adresse als Name")
            return None
        if not kennung:
            if self.cfg.federation_require_stable_id:
                security.seclog.warning(
                    "%s: keine stabile Kennung in der Antwort (user=%s) — abgewiesen, weil "
                    "federation_require_stable_id=True. Das Attribut steht in %s_attr_id.",
                    quelle, security.fuer_log(username), quelle)
                self.audit(f"{quelle}_ohne_kennung", username, detail="abgewiesen")
                return None
            if security.einmal_melden(f"fed_ohne_kennung:{quelle}"):
                security.seclog.warning(
                    "%s liefert keine stabile Kennung — die Zuordnung hängt am Benutzernamen, "
                    "wie vor 0.20.0. Wer im Verzeichnis umbenennt oder ein gelöschtes Konto "
                    "unter demselben Namen neu anlegt, bekommt damit dasselbe lokale Konto. "
                    "Abhilfe: %s_attr_id setzen (entryUUID, objectGUID) und danach "
                    "federation_require_stable_id=True.", quelle, quelle)
            gebunden_uid = None
        else:
            gebunden_uid = self.store.get_federated_user(quelle, kennung)

        if gebunden_uid:
            if nur_konto is not None and int(gebunden_uid) != int(nur_konto):
                self._kennung_zweier_konten(quelle, username, nur_konto, gebunden_uid)
                return None
            u = self.store.get_user(gebunden_uid)
            return self._als_dict(u) if u else None

        u = self.store.get_user_by_name(username) if name_zuordnen else None
        if nur_konto is not None and (u is None or int(u["id"]) != int(nur_konto)):
            self._kennung_zweier_konten(quelle, username, nur_konto, u["id"] if u else None)
            return None
        if u is None:
            uid = anlegen()
            if uid is None:
                return None
            self.store.link_federated(quelle, kennung or f"{self._OHNE_KENNUNG}{uid}", uid, jetzt)
            neu = self.store.get_user(uid)
            return self._als_dict(neu) if neu else None

        vorhandene = self.store.get_federated_kennung(quelle, u["id"])
        # Nur der Herkunfts-Platzhalter, keine Kennung: wie ungebunden (Lage 4). Gelöst wird er
        # erst, wenn die Tür offen ist — eine Abweisung lässt das Konto, wie es war.
        platzhalter = bool(vorhandene) and str(vorhandene).startswith(self._OHNE_KENNUNG)
        if not kennung:
            if not vorhandene:
                # Erste Zuordnung eines vorhandenen Kontos, allein über den Namen: dieselbe Tür
                # wie Lage 4 (G1, G2-N). Danach Herkunft festhalten (A-4) — siehe _OHNE_KENNUNG.
                if not self._namensbindung_erlaubt(quelle, "", u, username):
                    return None
                self.store.link_federated(quelle, f"{self._OHNE_KENNUNG}{u['id']}", u["id"], jetzt)
                self.store.namensbindung_schliessen(quelle, u["id"])
        else:
            if vorhandene and not platzhalter and vorhandene != kennung:
                # Lage 3: Das Konto gehört jemand anderem, auch wenn der Name derselbe ist.
                security.seclog.warning(
                    "%s: Konto %s ist schon an eine andere Kennung gebunden — die Anmeldung mit "
                    "einer neuen Kennung unter demselben Namen wird abgewiesen. Im Verzeichnis "
                    "wurde vermutlich umbenannt oder ein Konto neu angelegt. Der Betreiber löst "
                    "die Bindung, wenn das gewollt ist.", quelle, security.fuer_log(username))
                self.audit(f"{quelle}_kennung_wechsel", str(u["username"]),
                           detail="abgewiesen: Konto traegt bereits eine andere Kennung")
                return None
            if not vorhandene or platzhalter:
                # Lage 4: Nachbindung — ein einziges Mal je Konto, nur durch die Tür, und sie
                # steht im Protokoll.
                if not self._namensbindung_erlaubt(quelle, kennung, u, username):
                    return None
                if platzhalter:
                    self.store.unlink_federated(quelle, u["id"])
                self.store.link_federated(quelle, kennung, u["id"], jetzt)
                self.store.namensbindung_schliessen(quelle, u["id"])
                self.audit(f"{quelle}_kennung_gebunden", str(u["username"]),
                           detail="nachgebunden beim Login")
        return self._als_dict(self.store.get_user(u["id"]))

    def _kennung_zweier_konten(self, quelle: str, username: str, lokal_id, ziel_id) -> None:
        """Die Anmeldung über `quelle` abweisen: Die eingetippte Kennung gehört lokal dem Konto
        `lokal_id`, der Eintrag im Verzeichnis aber einem anderen (`ziel_id`, None = es würde neu
        angelegt). Logzeile mit Abhilfe, Audit `<quelle>_kennung_abgewiesen grund=kennung_zweier_konten`.
        Der Aufrufer gibt danach None zurück, die Route verbucht einen Fehlversuch (Prüfrunde
        2026-09-27, p1-d)."""
        security.seclog.warning(
            "%s: Anmeldung unter %s abgewiesen — die Kennung ist Name oder Adresse von Konto %s, der "
            "Eintrag im Verzeichnis gehört aber %s. Unter einer Kennung prüft TinySesam nie die "
            "Geheimnisse zweier Personen: Die Anmeldung der einen räumte sonst die Sperrzähler, unter "
            "denen gegen die andere geraten wird. Abhilfe: das lokale Konto umbenennen (Panel oder "
            "`tinysesam rename`) oder den Namen im Verzeichnis ändern.",
            quelle.upper(), security.fuer_log(username), lokal_id,
            f"Konto {ziel_id}" if ziel_id is not None else "keinem Konto (es würde neu angelegt)")
        self.audit(f"{quelle}_kennung_abgewiesen", username,
                   detail=f"grund=kennung_zweier_konten lokal={lokal_id} "
                          f"verzeichnis={ziel_id if ziel_id is not None else 'neu'}")

    @classmethod
    def _kennung_formfehler(cls, roh) -> Optional[str]:
        """Taugt dieser Wert als fremde Kennung? None = ja, sonst der Grund (Anmeldung und
        Bestandsbindung prüfen mit DERSELBEN Funktion).

        * Rand-Leerraum oder Steuerzeichen: Getrimmt fiele die Kennung auf die Bindung eines
          ANDEREN Kontos (`chefin\u2028` → `chefin`, Gegenprüfung). Aus einem echten Verzeichnis
          kommt so etwas nicht — abweisen statt passend machen.
        * Die Form des Herkunfts-Platzhalters: Sie träfe über `get_federated_user` genau das
          Konto, dessen ID sie nennt. Ein Verzeichnis liefert UUID/GUID — also ein manipuliertes
          Attribut."""
        roh = str(roh or "")
        if roh != roh.strip() or name_ungueltig(roh):
            return "Rand-/Steuerzeichen"
        if roh.startswith(cls._OHNE_KENNUNG):
            return "Platzhalter-Form"
        return None

    #: Warum ein Konto nicht über den Namen gebunden wird (`_nachbindung_grund`) — Kürzel und
    #: Erklärung, für den Bericht von `federation_bind_existing` (`reason`). Seit 0.22.0 englisch
    #: (PO-Entscheid 2026-09-27); die Kürzel bis 0.21.x stehen weiter in Audit und Sicherheits-Log.
    NAME_BINDING_REFUSALS = {
        "address_as_name": "the name says nothing about the person (control characters, or the "
                           "unverified mail value of a source that is not trusted)",
        "invalid_identifier": "the identifier is unusable (leading/trailing or control characters, "
                              "or placeholder form)",
        "conflict": "the identifier already belongs to another account",
        "bound_elsewhere": "the account already carries a different identifier",
        "self_chosen_name": "the name was chosen by the person (sign-up or rename) and says nothing "
                            "about who has that name in the directory",
        "name_from_other_source": "the name comes from another source that created the account "
                                  "(OIDC, SAML or LDAP) and says nothing about who has that name "
                                  "in this one",
        "binding_window_expired": "the window for binding by name has passed "
                                  "(federation_name_binding_days)",
    }
    #: Dieselben Gründe in Audit (`<quelle>_namensbindung_zu … grund=`) und Sicherheits-Log: Kürzel
    #: und Text von 0.21.x. Diese Zeilen ändern sich mit der Übersetzung nicht — Filter der
    #: Betreiber hängen an ihnen (PO-Entscheid 2026-09-27).
    _NACHBINDUNG_PROTOKOLL = {
        "address_as_name": ("adresse_als_name", "der Name sagt nichts über die Person "
                            "(Steuerzeichen, oder der unbelegte mail-Wert einer Quelle, der nicht "
                            "vertraut wird)"),
        "invalid_identifier": ("kennung_ungueltig", "die Kennung taugt nicht (Rand-/Steuerzeichen "
                               "oder Platzhalter-Form)"),
        "conflict": ("konflikt", "die Kennung gehört schon einem anderen Konto"),
        "bound_elsewhere": ("anders_gebunden", "das Konto trägt schon eine andere Kennung"),
        "self_chosen_name": ("name_selbst_gewaehlt", "der Name ist selbst gewählt (Registrierung "
                             "oder Umbenennen) und sagt nichts darüber, wer im Verzeichnis so heisst"),
        "name_from_other_source": ("name_aus_quelle", "der Name stammt aus einer anderen Quelle, "
                                   "die das Konto angelegt hat (OIDC, SAML oder LDAP), und sagt "
                                   "nichts darüber, wer in dieser so heisst"),
        "binding_window_expired": ("frist", "die Frist für die Bindung über den Namen ist "
                                   "abgelaufen (federation_name_binding_days)"),
    }

    def _nachbindung_grund(self, quelle: str, kennung: str, konto, *, name_belegt: bool = True,
                           frist: bool = True) -> Optional[str]:
        """Darf das Konto `konto` über seinen Namen an die fremde Kennung `kennung` gebunden
        werden? `None` = ja, sonst der Grund (Schlüssel aus `NAME_BINDING_REFUSALS`; im Audit
        und im Sicherheits-Log das Kürzel von 0.21.x, `_NACHBINDUNG_PROTOKOLL`).

        EIN Entscheid für die Anmeldung (Lage 4, Ersatz eines Platzhalters, erste Zuordnung ohne
        Kennung — `kennung=""`) und für die Bestandsbindung (`federation_bind_existing`). Kopiert
        drifteten die beiden auseinander, und der eine Weg bände, was der andere abweist (G1).

        * `name_belegt=False`: Der Name ist der unbelegte `mail`-Wert einer Quelle, der nicht
          vertraut wird (`_ldap_name_belegt`) — er sagt nichts über die Person.
        * Kennung: Form (`_kennung_formfehler`), nicht schon an ein anderes Konto gebunden, das
          Konto trägt nicht schon eine andere (Lage 3).
        * **Selbst gewählter Name** (G2-N): Ein Konto, das sich selbst registriert oder umbenannt
          hat (`users.name_selbst_gewaehlt`), wird nie über den Namen gebunden. Nachgestellt:
          `eve` benennt sich in `chefin` um, einen Namen, den es nur im Verzeichnis gibt; die
          echte chefin meldet sich über LDAP an, ihre Kennung landet an eves Konto, die Rolle aus
          `ldap_group_role_map` auch — und eve meldet sich weiter mit ihrem Passwort an.
        * **Name aus einer anderen Quelle** (`users.name_quelle`, Angriffsrunde 2026-09-26): Ein
          Konto, das OIDC, SAML oder LDAP angelegt hat, trägt den Namen, den die Person DORT hat —
          bei einem IdP mit Selbstregistrierung ein selbst gewählter. Nachgestellt: `chefin` über
          OIDC, danach die echte chefin über LDAP; ihre Kennung und ihre Rollen landeten im
          OIDC-Konto, und der Angreifer meldete sich weiter über OIDC an. Dieselbe Quelle ist
          ausgenommen: Sie ersetzt ihren eigenen Platzhalter durch die echte Kennung.
        * **Frist** (`frist=True`, G1): `federation_name_binding_days` ab dem Merker der Quelle bzw.
          der Anlage des Kontos, was später ist (`_namensfrist_offen`). Die Bestandsbindung prüft
          sie nicht — sie IST der ausdrückliche Weg des Betreibers.

        Die drei letzten hebt eine vom Betreiber geöffnete Bindung auf (`federation_unbind`,
        Tabelle `namensbindung`)."""
        if not name_belegt or name_ungueltig(str(konto["username"] or "")):
            return "address_as_name"
        if kennung:
            if self._kennung_formfehler(kennung):
                return "invalid_identifier"
            anderes = self.store.get_federated_user(quelle, kennung)
            if anderes is not None and int(anderes) != int(konto["id"]):
                return "conflict"
            vorhandene = self.store.get_federated_kennung(quelle, konto["id"])
            if vorhandene and not vorhandene.startswith(self._OHNE_KENNUNG) and vorhandene != kennung:
                return "bound_elsewhere"
        jetzt = _jetzt()
        if self.store.namensbindung_offen(quelle, konto["id"], jetzt):
            return None
        try:
            selbst = bool(konto["name_selbst_gewaehlt"])
        except (IndexError, KeyError):
            selbst = False       # Zeile ohne die Spalte (fremde Quelle): wie der Bestand
        if selbst:
            return "self_chosen_name"
        try:
            herkunft = str(konto["name_quelle"] or "")
        except (IndexError, KeyError):
            herkunft = ""        # Zeile ohne die Spalte (fremde Quelle): wie der Bestand
        if herkunft and herkunft != quelle:
            return "name_from_other_source"
        if frist and not self._namensfrist_offen(quelle, konto, jetzt):
            return "binding_window_expired"
        return None

    def _namensbindung_erlaubt(self, quelle: str, kennung: str, konto, username: str) -> bool:
        """Die Tür für Lage 4 bei der Anmeldung: `_nachbindung_grund`, und eine Abweisung wie in
        Lage 3 — Logzeile mit Kennung und Abhilfe, Audit `<quelle>_namensbindung_zu`."""
        grund = self._nachbindung_grund(quelle, kennung, konto)
        if grund is None:
            return True
        kuerzel, text = self._NACHBINDUNG_PROTOKOLL.get(grund, (grund, grund))
        tage = int(self.cfg.federation_name_binding_days)
        security.seclog.warning(
            "%s: Konto %s (user_id=%s) wird nicht über den Namen an die Kennung %s gebunden — %s. "
            "Die Anmeldung wird abgewiesen. Ist es dieselbe Person: "
            "auth.federation_unbind('%s', %s) öffnet die Bindung für die nächste Anmeldung "
            "(%d Tag(e)); den Bestand bindet auth.federation_bind_existing('%s').",
            quelle, security.fuer_log(username), konto["id"],
            security.fuer_log(kennung) if kennung else "(keine)",
            text, quelle, konto["id"], max(tage, 1), quelle)
        self.audit(f"{quelle}_namensbindung_zu", str(konto["username"]),
                   detail=f"grund={kuerzel} kennung={kennung or '-'}")
        return False

    def _foederation_seit(self, quelle: str) -> int:
        """Ab wann gilt die Frist für die Bindung über den Namen (G1)? Der Merker der Quelle
        (`Store.foederation_seit`), gesetzt beim ersten Start mit eingeschalteter Quelle — oder
        hier, wenn sie ohne Schalter benutzt wird (ein selbst gesetzter Client). Genau einmal:
        Ein Merker, der bei jedem Start neu gesetzt würde, schenkte jedem Neustart eine neue
        Frist. Nur lesbar: dann ab jetzt."""
        try:
            return self.store.foederation_seit(quelle, _jetzt())
        except (sqlite3.OperationalError, ValueError):
            return _jetzt()

    def _namensfrist_offen(self, quelle: str, konto, jetzt: int) -> bool:
        """Bindet der Name dieses Konto noch (G1)? `federation_name_binding_days` Tage ab dem
        Merker der Quelle oder der Anlage des Kontos, was später ist — eine Vorab-Anlage im Panel
        hat damit ihre eigene Frist. `-1` = immer, `0` = nie."""
        tage = int(self.cfg.federation_name_binding_days)
        if tage < 0:
            return True
        ab = max(int(konto["created_at"] or 0), self._foederation_seit(quelle))
        return jetzt < ab + tage * 86400

    def _namensbindung_bestand_melden(self, quelle: str, seit: int) -> None:
        """Startmeldung (G1): Wie viele Konten tragen für diese Quelle noch keine Kennung, und bis
        wann bindet sie der Name? Nur solange die Tür für den Bestand offen ist — danach meldet
        sich jede Abweisung selbst, und ein lokaler Admin stünde sonst für immer im Log."""
        tage = int(self.cfg.federation_name_binding_days)
        if tage <= 0:
            return            # 0: nur ausdrücklich; -1: warnt die Konfigurationsprüfung
        bis = seit + tage * 86400
        if _jetzt() >= bis:
            return
        try:
            konten = self.store.ohne_bindung(quelle)
        except sqlite3.OperationalError:
            return
        if not konten:
            return
        ohne_pw = sum(1 for k in konten if not k["hat_passwort"])
        weg = (f"auth.federation_bind_existing('{quelle}')" if quelle == "ldap"
               else f"auth.federation_bind_existing('{quelle}', mapping={{name: kennung}})")
        security.seclog.warning(
            "%s: %d Konto(en) ohne Bindung an eine Kennung der Quelle (davon %d ohne lokales "
            "Passwort). Bis %s (federation_name_binding_days=%d) bindet die nächste Anmeldung "
            "sie über den Namen, danach nicht mehr — ein ruhendes Konto fiele sonst an die nächste "
            "Person mit demselben Namen. Jetzt binden: %s (Trockenlauf), dann mit apply=True.",
            quelle.upper(), len(konten), ohne_pw,
            time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(bis)), tage, weg)

    def federation_unbind(self, source: str, user_id: int) -> int:
        """Die Bindung eines Kontos an eine fremde Identität lösen (Betreiber-Weg) — und die
        Bindung über den Namen für die nächste Anmeldung öffnen. Gibt die Zahl der gelösten
        Bindungen zurück (0: das Konto war nicht gebunden).

        Gebraucht, wenn im Verzeichnis wirklich umgezogen wurde — dann ist die alte Kennung tot
        und das Konto soll die neue bekommen. Dass das ein bewusster Schritt ist und kein
        Nebeneffekt einer Anmeldung, ist der Punkt.

        Seit 2026-09-26 (G1, G2-N) öffnet der Aufruf zugleich die Tür für Lage 4: Die nächste
        Anmeldung über diese Quelle bindet das Konto über seinen Namen, auch nach der Frist
        (`federation_name_binding_days`), auch mit selbst gewähltem Namen und auch mit einem Namen
        aus einer anderen Quelle (`users.name_quelle`) — für
        `max(federation_name_binding_days, 1)` Tage oder bis die Bindung steht. Auf einem
        ungebundenen Konto heisst der Aufruf also „für die nächste Anmeldung öffnen" (Vorab-Anlage,
        Rückkehrer, ein Konto, das die Frist verpasst hat). Die Abweisung im Log nennt den Aufruf."""
        weg = self.store.unlink_federated(source, user_id)
        u = self.store.get_user(user_id)
        bis = None
        if u is not None:
            bis = _jetzt() + max(int(self.cfg.federation_name_binding_days), 1) * 86400
            self.store.namensbindung_oeffnen(source, user_id, bis)
        self.audit(f"{source}_kennung_geloest", str(u["username"]) if u else None,
                   detail=f"namensbindung_offen_bis={bis}" if bis else None)
        return weg

    def federation_bind_existing(self, source: str, *, mapping: Optional[dict] = None,
                                 apply: bool = False) -> dict:
        """Bestandskonten an ihre Kennung in LDAP/SAML binden, ohne auf ihre Anmeldung zu warten (G1).

        Konten aus der Zeit vor den Kennungen (F-11) binden sich bei der nächsten Anmeldung über
        ihren Namen — aber nur innerhalb der Frist (`federation_name_binding_days`). Ein ruhendes
        Konto meldet sich nie an; genau das fiele sonst an die nächste Person mit dem Namen. Diese
        Methode bindet den Bestand ausdrücklich. **Vorgabe ist ein Trockenlauf**: Erst mit
        `apply=True` wird geschrieben.

        * **LDAP ohne `mapping`**: je Konto ohne Kennung eine Suche im Verzeichnis
          (`LDAPClient.eintrag_suchen`, Dienstkonto oder anonym, ohne Passwort des Nutzers). Es
          muss genau EIN Eintrag sein. Ein Ausfall (`VerzeichnisNichtErreichbar`) bricht ab —
          vor dem ersten Schreiben: Gesucht wird erst alles, dann gebunden.
        * **`mapping={Kontoname: Kennung}`** — für SAML (es gibt keinen Suchweg ohne Anmeldung;
          die NameIDs etwa aus einem Export des IdP) oder für einzelne LDAP-Konten. Läuft ohne
          Verzeichnis.

        Entschieden wird je Konto mit demselben Helfer wie bei der Anmeldung
        (`_nachbindung_grund`, ohne die Frist). Konten mit lokalem Passwort werden nur berichtet
        (`local_password`): Ihr Name kann einem anderen Menschen gehören als der Eintrag im
        Verzeichnis — der Betreiber öffnet sie einzeln mit `federation_unbind`.

        Rückgabe (Listen von Einträgen mit `user_id`, `username`, `local` = Anzeigename/Adresse
        hier, `directory` = dasselbe im Verzeichnis, `identifier`, bei Abweisungen `reason`):

        * `bound` — gebunden (im Trockenlauf: würde gebunden). **Vor `apply` lesen**: War ein
          Name schon vor dem Lauf wiederverwendet, bindet auch diese Methode die falsche Person —
          `local` und `directory` nebeneinander zeigen es.
        * `conflict` — die Kennung gehört schon einem anderen Konto (`bound_to`), oder zwei
          Konten nennen dieselbe
        * `ambiguous` — mehr als ein Eintrag im Verzeichnis (`matches`: wie viele)
        * `not_in_directory`, `no_identifier` — kein Eintrag bzw. einer ohne stabile Kennung
          (`ldap_attr_id`)
        * `refused` — mit `reason`: einer aus `NAME_BINDING_REFUSALS` oder `no_account`,
          `service_account`, `disabled`, `already_bound`
        * `local_password` — Konto mit lokalem Passwort, nur berichtet

        Dazu `source` und `applied`. Bis 0.21.x hiessen die Schlüssel und Gründe deutsch
        (`quelle`, `ausgefuehrt`, `gebunden`, `abgewiesen`/`grund` …; PO-Entscheid 2026-09-27,
        Tabelle im CHANGELOG zu 0.22.0). Jede Bindung schreibt `<quelle>_kennung_gebunden` mit
        `detail=migration`, der Lauf eine Summenzeile ins Sicherheits-Log — beide wie bisher.
        Einen CLI-Befehl gibt es nicht: LDAP und SAML laufen nur eingebettet, und das CLI kennt die
        Konfiguration nicht."""
        if source not in self.FEDERATED_SOURCES:
            raise ValueError(f"source muss eine von {self.FEDERATED_SOURCES} sein, nicht {source!r}")
        suchen = None
        if mapping is None:
            if source != "ldap":
                raise ValueError(
                    "SAML kennt keinen Suchweg ohne Anmeldung — die Kennungen kommen als "
                    "mapping={Kontoname: NameID} (etwa aus einem Export des IdP).")
            if not self.ldap:
                raise ConfigError("LDAP ist nicht eingerichtet (ldap_enabled, ldap_url) — oder "
                                  "mapping={Kontoname: Kennung} übergeben.")
            suchen = getattr(self.ldap, "eintrag_suchen", None)
            if not callable(suchen):
                raise ConfigError("Der gesetzte LDAP-Client kann nicht suchen (eintrag_suchen) — "
                                  "mapping={Kontoname: Kennung} übergeben.")
        bericht: dict = {"source": source, "applied": bool(apply), "bound": [],
                         "conflict": [], "ambiguous": [], "not_in_directory": [],
                         "no_identifier": [], "refused": [], "local_password": []}
        # Konto → Kennung aus der Zuordnung (None: im Verzeichnis suchen).
        paare: list[tuple[Any, Optional[str]]] = []
        if mapping is None:
            paare = [(k, None) for k in self.store.ohne_bindung(source)]
        else:
            for name, wert in mapping.items():
                k = self.store.get_user_by_name(str(name or "").strip())
                if k is None:
                    bericht["refused"].append({"user_id": None, "username": str(name),
                                               "reason": "no_account"})
                else:
                    paare.append((k, str(wert or "")))
        plan = []
        for konto, vorgabe in paare:
            e: dict = {"user_id": int(konto["id"]), "username": konto["username"],
                       "local": {"name": konto["display_name"], "email": konto["email"]}}
            if konto["is_service"] or konto["disabled"]:
                bericht["refused"].append(dict(e, reason="service_account" if konto["is_service"]
                                               else "disabled"))
                continue
            vorhandene = self.store.get_federated_kennung(source, konto["id"])
            if vorhandene and not vorhandene.startswith(self._OHNE_KENNUNG):
                bericht["refused"].append(dict(e, identifier=vorhandene, reason=(
                    "already_bound" if vorgabe is None or vorhandene == vorgabe else "bound_elsewhere")))
                continue
            name_belegt = True
            kennung = vorgabe or ""
            if suchen is not None:
                treffer = suchen(konto["username"])     # VerzeichnisNichtErreichbar bricht ab
                if not treffer:
                    bericht["not_in_directory"].append(e)
                    continue
                if len(treffer) > 1:
                    bericht["ambiguous"].append(dict(e, matches=len(treffer)))
                    continue
                info = treffer[0]
                e["directory"] = {"name": info.get("name"), "email": info.get("email")}
                kennung = str(info.get("id") or "")
                name_belegt = self._ldap_name_belegt(konto["username"], info)
            if not kennung:
                # Keine Kennung, auch eine leere in der Zuordnung: Gebunden würde über den Namen.
                bericht["no_identifier"].append(e)
                continue
            e["identifier"] = kennung
            grund = self._nachbindung_grund(source, kennung, konto, name_belegt=name_belegt,
                                            frist=False)
            if grund == "conflict":
                bericht["conflict"].append(dict(e, bound_to=self.store.get_federated_user(source, kennung)))
            elif grund:
                bericht["refused"].append(dict(e, reason=grund))
            elif self.store.get_password_hash(konto["id"]):
                bericht["local_password"].append(e)
            else:
                plan.append(e)
        # Zwei Konten, eine Kennung (Zuordnung mit Dublette): keines.
        from collections import Counter
        doppelt = {k for k, n in Counter(e["identifier"] for e in plan).items() if n > 1}
        bericht["conflict"] += [e for e in plan if e["identifier"] in doppelt]
        plan = [e for e in plan if e["identifier"] not in doppelt]
        if not apply:
            bericht["bound"] = plan
            return bericht
        for e in plan:
            # Atomar gegen eine Anmeldung, die seit der Prüfung gebunden hat (`Store.nachbinden`).
            if self.store.nachbinden(source, e["identifier"], e["user_id"], _jetzt()):
                self.audit(f"{source}_kennung_gebunden", str(e["username"]), detail="migration")
                bericht["bound"].append(e)
            else:
                bericht["conflict"].append(dict(e, bound_to=self.store.get_federated_user(source, e["identifier"])))
        security.seclog.warning(
            "federation_bind_existing(%s): %d gebunden, %d Konflikt, %d mehrdeutig, %d nicht im "
            "Verzeichnis, %d ohne Kennung, %d abgewiesen, %d mit lokalem Passwort (nur berichtet).",
            source, len(bericht["bound"]), len(bericht["conflict"]), len(bericht["ambiguous"]),
            len(bericht["not_in_directory"]), len(bericht["no_identifier"]),
            len(bericht["refused"]), len(bericht["local_password"]))
        return bericht

    def _ldap_vertraut(self, info) -> bool:
        """Traut der Betreiber der Adresse dieses Eintrags? Pauschal (`ldap_email_trusted`) oder
        für DIESEN Eintrag belegt (Beleg-Attribut `ldap_attr_email_verified`)."""
        return bool(self.cfg.ldap_email_trusted) or (
            bool(security.beleg_attribut(self.cfg, "ldap")) and _beleg_wahr(info.get("email_verified")))

    def _ldap_name_belegt(self, username, info) -> bool:
        """Sagt der Name etwas über die Person im Verzeichnis? Nein bei Steuerzeichen — und wenn er
        der unbelegte `mail`-Wert des Eintrags IST (Quelle nicht vertraut). Anmeldung und
        Bestandsbindung fragen hier; nur dann darf über den Namen einem Konto zugeordnet werden.

        Maßgeblich ist, ob die Eingabe der unbelegte Wert IST — nicht, ob sie wie eine Adresse
        aussieht: `mail` ist ein freies Attribut (RFC 4524), ein Angreifer setzt es auch auf
        `chefin` (Gegenprüfung); ein UPN mit `@` dagegen ist die Bind-Kennung und belegt."""
        if name_ungueltig(username):
            return False
        mail_wert = norm_kennung(info.get("email") or "")
        return not (not self._ldap_vertraut(info) and mail_wert
                    and norm_kennung(username) == mail_wert)

    def _check_ldap(self, username, password) -> Optional[dict]:
        """Passwort gegen LDAP prüfen. Bei Erfolg lokalen User finden/anlegen und zurückgeben.
        Zählt wie ein Passwort-Login (Faktor 'password').

        Die übernommene Adresse (`info["email"]`) ist ein Verzeichnisattribut ohne Beleg — in
        vielen Verzeichnissen pflegt sie der Nutzer selbst. Der Betreiber sagt, ob er ihr traut
        (`ldap_email_trusted`, seit dem PO-Entscheid 2026-09-25 Vorgabe nein; oder für diesen
        Eintrag per `ldap_attr_email_verified`): Dann gilt sie als belegt und trägt Rechte. Traut
        er ihr nicht, wird sie nicht direkt verwendet (Bestätigungslink, s.
        `_adresse_aus_quelle_belegen`), und eine
        eingetippte Adresse wird nicht Kontoname (Ersatzname `ldap-…`, keine Zuordnung über den
        Namen). Für diesen Fall — und das war bis dahin die Regel — galt und gilt, **zwei**
        Folgen, beide nötig:

        * Ein neu angelegtes Konto bekommt die Adresse mit `email_verified=False` — der Vermerk
          am Konto behauptet nicht, was niemand belegt hat.
        * Wer diesen Weg selbst einbindet, reicht `email_verified=False` an `apply_factor`
          durch (so macht es die mitgelieferte Login-Route). Am Faktornamen ist der Weg nicht
          erkennbar — `password` steht nicht in `_FOEDERIERTE_FAKTOREN`, weil ein lokales
          Passwort dort auch ankommt.

        Nur das zweite allein schützte bloss DIESEN Login: Der Angreifer richtete sich in der
        frisch angemeldeten Sitzung eine PIN oder einen Passkey ein, meldete sich damit erneut
        an — dieser Faktor reist ohne Beleg an —, und der Vermerk am Konto befördert ihn doch
        (B-umgehung-1 aus T-13). Sonst könnte eine Allowlist-Adresse über LDAP den Erst-Admin
        bestimmen (F-14).

        **Eine Kennung, ein Konto** (Prüfrunde 2026-09-27, p1-d): Die Login-Route fragt LDAP erst,
        nachdem das lokale Passwort des Kontos zur Kennung (`find_user`) nicht gepasst hat. Führt
        der Eintrag im Verzeichnis zu einem ANDEREN Konto (gebunden, über den Namen oder neu
        angelegt), wird abgewiesen, bevor etwas geschrieben ist (`_kennung_zweier_konten`) — die
        Route verbucht einen Fehlversuch. Sonst prüfte eine Kennung die Geheimnisse zweier
        Personen, und die Anmeldung der einen räumte die Zähler, unter denen gegen die andere
        geraten wird (lokal `alice.neu` neben dem Verzeichnisnamen `alice.neu` einer anderen Person,
        oder eine Registrierung mit der Verzeichnisadresse bei einem Filter über `mail`). Das trifft
        auch die Anmeldung eines Verzeichnis-Dritten unter der Adresse eines lokalen Kontos (bis
        dahin nur für die Zähler abgesichert, G5-N1)."""
        if not self.ldap:
            return None
        from .ldap_ import AnfrageAbgebrochen, VerzeichnisNichtErreichbar, eingabe_zu_lang
        # Länger als jede echte Anmeldung: nicht ans Verzeichnis, sondern wie ein falsches
        # Passwort (Fehlversuch, `failed login`). Hier und nicht erst im Client, damit es auch für
        # einen selbst gesetzten Client gilt — und bevor der Merker einen Probenplatz vergibt.
        # Vorher schickte die Login-Route jede Länge durch: Ein Passwort mit 270 000 Zeichen
        # liess slapd die Verbindung beenden (s. `ldap_.AnfrageAbgebrochen`).
        if eingabe_zu_lang(username, password):
            return None
        # Nach einem Ausfall wird das Verzeichnis eine Weile gar nicht erst gefragt: Die Route
        # hat den Versuch schon vorgebucht (R7-2) und nimmt ihn erst zurück, wenn der Ausfall
        # gemeldet ist — ohne den Merker schwebte er bei jedem Anlauf bis zum Timeout und
        # sperrte derweil Unbeteiligte (Begründung bei `ldap_.AusfallMerker`).
        merker = self._ldap_ausfall
        probe = merker.zugang()
        try:
            info = self.ldap.authenticate(username, password)
        except AnfrageAbgebrochen:
            # Nur DIESE Anfrage ist gescheitert, schnell und nach dem Senden ihrer Eingaben —
            # kein Beleg für einen Ausfall. Den Merker scharf zu schalten, gäbe jedem Absender
            # einer präparierten Anmeldung einen Schalter, der LDAP für alle abstellt. War sie die
            # Probe, fragt die nächste Anmeldung nach.
            if probe:
                merker.freigeben()
            raise
        except VerzeichnisNichtErreichbar as e:
            merker.ausgefallen(e, war_probe=probe)
            raise
        except BaseException:
            if probe:
                merker.freigeben()
            raise
        merker.erreicht()
        if not info:
            return None
        # Gruppen-Gate gegen memberOf — nach DN-Bestandteilen, nicht als Teilstring (F-19):
        # `staff` liess sonst auch `cn=staffextern,…` durch. `group_match="substring"` holt
        # den alten Vergleich ausdrücklich zurück.
        allowed = self.cfg.ldap_allowed_groups
        teilstring = self.cfg.group_match == "substring"
        if allowed:
            groups = info.get("groups") or []
            if not teilstring:
                for a in allowed:
                    _teilstring_hinweis(a, groups, "ldap_allowed_groups")
            if not any(gruppe_passt(a, g, teilstring, dn=True) for a in allowed for g in groups):
                self.audit("ldap_group_denied", username,
                           detail=f"verlangt={sorted(str(a) for a in allowed)}")
                return None
        # Nicht vertraut und die Eingabe ist eine Adresse (ein Suchfilter über `mail`, "Anmeldung mit
        # Name oder E-Mail"): Dann ist der Name dieselbe unbelegte Adresse — als Kontoname und
        # `Remote-User` besetzte er die Kennung der Inhaberin, und über den Namen gebunden
        # übernähme er deren Konto (Angriff auf die dritte Runde). Wie bei SAML: Ersatzname,
        # keine Zuordnung über den Namen.
        kennung_ldap = info.get("id") or ""
        quelle_vertraut = self._ldap_vertraut(info)
        ldap_name = username
        name_zuordnen = True
        if not self._ldap_name_belegt(username, info):
            ldap_name = "ldap-" + hashlib.sha256((kennung_ldap or username).encode()).hexdigest()[:8]
            name_zuordnen = False

        def _anlegen():
            if not self.cfg.ldap_auto_create:
                return None
            try:
                # Adresse UND Beleg gehen zusammen ins Konto: Das `mail`-Attribut belegt
                # nichts, also darf der Vermerk am Konto es auch nicht behaupten. Stünde hier
                # die Vorgabe `True`, wäre der Riegel oben nur für DIESEN Login zu — der
                # nächste Faktor, den sich der Angreifer selbst einrichtet (PIN, Passkey),
                # reist ohne Beleg an, liest den Vermerk und befördert doch (B-umgehung-1 aus T-13).
                # Der Betreiber sagt, ob er dem Verzeichnis traut (`ldap_email_trusted`, Vorgabe
                # nein, oder das Beleg-Attribut): dann mit Beleg, sonst gar nicht (H-3).
                vertraut = quelle_vertraut
                name = ldap_name
                if name == username:
                    # Das Verzeichnis hat eben diesen Eintrag unter dem Namen angemeldet; steht er
                    # noch an der Bindung eines anderen Kontos, ist er dort veraltet (p1-a) — und
                    # hielte die Anlage sonst als „vergeben" auf.
                    self.store.verzeichnisname_freigeben(name)
                i = 1
                while name != username and self.identifier_taken(name):
                    i += 1
                    name = f"{ldap_name}{i}"
                return self._konto_anlegen(name, display_name=info.get("name") or name,
                                           email=info.get("email") if vertraut else None,
                                           email_verified=vertraut and bool(info.get("email")),
                                           name_quelle="ldap")
            except ConfigError:
                # Name oder Adresse gehören lokal schon jemandem (Fund R4-12). Fail-closed:
                # lieber keine Anmeldung als ein Konto, das eine fremde Kennung besetzt.
                self.audit("ldap_ident_taken", username)
                return None

        # Zugeordnet wird über die STABILE Kennung des Verzeichnisses, nicht über den Namen
        # (F-11). Der Name bleibt der Rückfall für Konten, die noch keine Bindung haben. Gehört die
        # Kennung lokal einem Konto, darf die Auflösung nur dort enden (p1-d, s. oben).
        lokal = self.find_user(username)
        u = self._fremde_identitaet_aufloesen("ldap", kennung_ldap, username, _anlegen,
                                              name_zuordnen=name_zuordnen,
                                              nur_konto=int(lokal["id"]) if lokal else None)
        if not u or u["disabled"]:
            return None
        # Den eingetippten Namen an der Bindung vermerken, wenn er weder Name noch Adresse des
        # Kontos ist (G5): Nach einer Umbenennung im Verzeichnis (lokal `alice`, dort `alice.neu`)
        # zählt die Serie (B2-6) unter `alice.neu`, und ohne den Vermerk räumte sie kein Rückweg —
        # weder die volle Anmeldung noch der Panel-Reset noch `tinysesam unlock`. Wem er sonst
        # noch gehört, prüft der Leser (`Store.zaehl_kennungen`), nicht dieser Schreiber.
        if not name_ungueltig(username):
            self.store.bindung_name_setzen("ldap", u["id"], username)
        self._adresse_aus_quelle_belegen(u, info.get("email"), quelle_vertraut, "ldap")
        # memberOf liefert ganze DNs → Vergleich nach Bestandteilen (F-19). Bis 0.20.0 stand
        # hier `substring=True` fest verdrahtet, und `group_match` war für LDAP wirkungslos.
        self.apply_idp_groups(u["id"], info.get("groups"), self.cfg.ldap_group_role_map, dn=True)
        return self._als_dict(self.store.get_user(u["id"]))   # frisch (gemappte Rollen)

    # ---------- SAML (Attribute → lokaler User) ----------
    def _check_saml(self, nameid, attrs, ip: Optional[str] = None) -> Optional[dict]:
        """Aus einer geprüften SAML-Assertion einen lokalen User finden/anlegen. Faktor 'saml'.

        Die Adresse aus dem Attribut trägt keinen Beleg (SAML kennt kein `email_verified`).
        Seit dem PO-Entscheid 2026-09-24 sagt der Betreiber, ob er ihr traut
        (`saml_email_trusted`, Vorgabe nein). Ohne Vertrauen wird sie nicht verwendet, ein
        Kontoname mit `@` weicht einem Ersatznamen, und über einen solchen Namen wird nie ein
        vorhandenes Konto zugeordnet. Der Faktor `saml` steht in `_FOEDERIERTE_FAKTOREN`: Eine Allowlist-ADRESSE wird über diesen Weg nie zum Erst-Admin,
        auch wenn ein Aufrufer den Beleg nicht nennt — und auch nicht über einen zweiten,
        selbst eingerichteten Faktor beim nächsten Login (B-umgehung-1 aus T-13).

        Jede fachliche Abweisung hinterlässt eine Audit-Zeile mit Grund (F-22): Bis 0.20.0
        endeten Gruppen-Gate, fehlendes Konto und gesperrtes Konto stumm in einer 403 — „ich komme
        nicht rein" war serverseitig nicht zu beantworten. `ip` reicht die ACS-Route durch."""
        from .saml_ import first, as_list
        cfg = self.cfg
        username = first(attrs, cfg.saml_attr_username) if cfg.saml_attr_username else None
        roh_name = str(username or nameid or "")
        # Geprüft wird der UNGETRIMMTE Wert: `strip()` entfernt auch U+2028, U+0085 und Unicode-
        # Leerzeichen — `chefin\u2028` würde sonst `chefin` (Gegenprüfung).
        username = roh_name.strip()
        if not username:
            self.audit("saml_denied", None, ip, "grund=kein_name")
            return None
        pauschal = bool(cfg.saml_email_trusted)
        _attr = security.beleg_attribut(cfg, "saml")
        mail = first(attrs, cfg.saml_attr_email)
        # Das Beleg-Attribut belegt die ADRESSE dieses Logins — nicht den Namen. Bei einem IdP mit
        # Selbstregistrierung (genau dafür ist es da) wählt der Nutzer seine NameID selbst:
        # `bob@example.com` als Name, die eigene Adresse bestätigt. Hier galt der Name dann als
        # belegt und wurde über Lage 4 dem lokalen Konto `bob@example.com` zugeordnet —
        # Übernahme (Angriffsrunde Selbstbedienung, Fund 1). Wie bei OIDC (`email_verified`):
        # Ein Name mit `@` ist nur belegt, wenn er GENAU die belegte Adresse ist.
        beleg = bool(_attr) and _beleg_wahr(first(attrs, _attr)) and valid_email(norm_email(mail or "") or "")
        vertraut = pauschal or beleg
        # Die stabile Kennung ist die `NameID` — oder ein Attribut, wenn der IdP transiente
        # NameIDs schickt (`saml_attr_id`). Der Name ist nur noch der Rückfall (F-11).
        kennung = (first(attrs, cfg.saml_attr_id) if cfg.saml_attr_id else nameid) or ""
        # Ohne Vertrauen in die Adressen dieses IdP (Vorgabe) wie H-3 bei OIDC: Ein Name mit `@`
        # (NameID im Format emailAddress, ein UPN) ist dieselbe unbelegte Adresse unter anderem
        # Namen — als Kontoname und `Remote-User` besetzte er die Kennung der echten Inhaberin.
        # Gilt nur für NEUE Konten; ein gebundenes behält seinen Namen. Geprüft wird gefaltet
        # (`＠` U+FF20 wird zu `@`, R2-1).
        neu_name = username
        name_zuordnen = True
        # Unbelegt ist der Name, wenn er eine Adresse ist — oder wenn er aus dem Adress-Attribut
        # selbst stammt (`saml_attr_username` = `saml_attr_email`): Dann trägt er, was der Nutzer
        # dort eingetragen hat, auch `chefin` ohne `@` (Gegenprüfung).
        unbelegt = (not pauschal) and (
            "@" in norm_kennung(username)
            or (bool(cfg.saml_attr_username) and cfg.saml_attr_username == cfg.saml_attr_email)
        ) and not (beleg and norm_kennung(username) == norm_kennung(mail or ""))
        if name_ungueltig(roh_name) or unbelegt:
            neu_name = "saml-" + hashlib.sha256((kennung or username).encode()).hexdigest()[:8]
            name_zuordnen = False
        if cfg.saml_allowed_groups:
            groups = as_list(attrs, cfg.saml_attr_groups)
            if not (set(cfg.saml_allowed_groups) & set(str(g) for g in groups)):
                self.audit("saml_denied", username, ip,
                           f"grund=gruppe verlangt={sorted(cfg.saml_allowed_groups)}")
                return None
        def _anlegen():
            if not cfg.saml_auto_create:
                self.audit("saml_denied", username, ip, "grund=kein_konto saml_auto_create=False")
                return None
            try:
                # Wie bei LDAP (B-umgehung-1 aus T-13): Die Adresse aus der Assertion kommt ohne
                # Beleg, also wird sie auch ohne Beleg abgelegt. Sonst trüge der Vermerk am
                # Konto einen Freifahrtschein für jeden späteren Anmeldeweg, der selbst
                # nichts belegt.
                name = neu_name
                i = 1
                while name != username and self.identifier_taken(name):
                    i += 1
                    name = f"{neu_name}{i}"
                anzeige = first(attrs, cfg.saml_attr_name) or name
                return self._konto_anlegen(name, display_name=anzeige,
                                           email=mail if vertraut else None,
                                           email_verified=vertraut and bool(mail),
                                           name_quelle="saml")
            except ConfigError:
                # Wie bei LDAP (Fund R4-12): eine schon vergebene Kennung legt kein Konto an.
                self.audit("saml_ident_taken", username)
                return None

        u = self._fremde_identitaet_aufloesen("saml", kennung, username, _anlegen,
                                              name_zuordnen=name_zuordnen)
        if u and u["disabled"]:
            self.audit("saml_denied", str(u["username"]), ip, "grund=konto_gesperrt")
            return None
        if not u:
            return None     # Grund steht schon im Audit-Log (Anlegen/Kennung)
        self._adresse_aus_quelle_belegen(u, mail, vertraut, "saml")
        self.apply_idp_groups(u["id"], as_list(attrs, cfg.saml_attr_groups), cfg.saml_group_role_map)
        return self._als_dict(self.store.get_user(u["id"]))   # frisch (gemappte Rollen)

    def _adresse_aus_quelle_belegen(self, u, mail, vertraut, quelle: str = "") -> None:
        """Die Adresse aus einer Quelle (LDAP/SAML) an das Konto bringen.

        * **Vertraut** (Schalter oder Beleg-Attribut dieses Logins): belegt DIESELBE Adresse am
          Konto (über eine andere sagt die Quelle nichts; dieselbe Regel wie beim OIDC-Claim),
          nur nach oben; ein Konto ohne Adresse bekommt sie, wenn sie frei ist (wie H-3 bei OIDC).
        * **Nicht vertraut** (PO-Entscheid 2026-09-25): Mit `federation_email_confirm`, Mailer und
          `base_url` geht einmal ein Bestätigungslink an die Adresse — derselbe Weg wie der
          Mailwechsel der Selbstbedienung (`request_email_change`). Erst der Klick macht sie zur
          Adresse des Kontos. Nur für Konten OHNE belegte Adresse, höchstens ein ZUGESTELLTER
          Link am Tag (G12a, s. unten).
        Schweigen nimmt keinem Konto den Beleg, den der Betreiber selbst gesetzt hat.

        Gezählt werden Versände, gedämpft Versuche (G12a, seit 2026-09-26). Bis dahin verbrauchte
        schon der Versuch das Tageskontingent (je Prozess, im Speicher): Eine gedrosselte
        Zieladresse oder ein gescheiterter Versand kostete den Link für einen ganzen Tag, und
        mehrere Worker schickten je einen. Jetzt steht der Versand in der Datenbank
        (`federation_email_confirm … konto=<id>`, erst nach dem Versand, `Store.quellmail_seit`).
        Eine vergebene oder reservierte Adresse bekommt nie einen Link; ihr Versuch (mit
        Audit-Zeile `konto=<id> …`) zählt ebenfalls in der Datenbank, höchstens einer am Tag. Bis
        zur Angriffsrunde 2026-09-26 dämpfte ihn nur der Speicher — je Worker und bis zum Neustart:
        Eine freie Adresse hinterliess auf der Kontoseite genau einen Antrag, eine vergebene mit
        jedem weiteren Worker einen mehr, und ein LDAP-Nutzer, der sein `mail` selbst pflegt, las
        daran ab, ob eine fremde Adresse ein Konto hat. Der Speicher dämpft nur noch das, was
        vorübergeht — eine Drossel, ein Mailserver-Fehler: nach `mail_per_address_window_sec` wieder."""
        if not mail or not u:
            return
        adresse = norm_email(mail)
        konto_mail = norm_email(u["email"] or "")
        if vertraut:
            if konto_mail == adresse and not u["email_verified"]:
                self.store.set_email_verified(u["id"], True)
            elif not konto_mail and not self.identifier_taken(adresse, exclude_id=u["id"]):
                try:
                    self.store.set_email(u["id"], adresse, verified=True)
                except sqlite3.IntegrityError:
                    # Wettlauf: inzwischen Kennung eines anderen Kontos — das Konto bleibt ohne
                    # Adresse, wie bei der Vorprüfung (fail-closed).
                    self.audit(f"{quelle or 'quelle'}_email_taken", str(u["username"]), None,
                               "nachgetragen=0 wettlauf=1")
            return
        # Ein Konto mit belegter Adresse behält sie — auch eine andere als die der Quelle: Die hat
        # der Inhaber selbst bestätigt (Selbstbedienung), und ein Link bei jeder Anmeldung, der sie
        # ersetzen will, wäre Belästigung. Wechseln kann er selbst über die Konto-Seite.
        if u["email_verified"]:
            return
        if not (self.cfg.federation_email_confirm and self.cfg.base_url and self.mail_configured()):
            return
        # Keiner, solange einer offen ist, und höchstens ein erledigter Antrag je Konto und Tag —
        # zugestellt oder abgewiesen (vergeben, reserviert), gezählt in der Datenbank, über alle
        # Worker. Sonst schriebe jede Anmeldung eine Audit-Zeile, und ihre Zahl auf der Kontoseite
        # verriete, ob die Adresse vergeben ist (Angriffsrunde 2026-09-26). Lebt ein Link länger
        # als einen Tag (`email_change_ttl_min`), so lange: Ein zugestellter hält den nächsten
        # Versuch ohnehin bis zu seinem Ablauf auf (`offener_token`), eine Abweisung muss es genauso
        # — und auch dann, wenn der Inhaber seinen offenen Link verwirft (Passwortwechsel).
        # Jeder offene Link des Kontos hält auf, an welche Adresse auch immer (p2 F2): Die Zeile
        # `federation_email_confirm` entsteht erst nach dem Versand. Mit dem Filter auf die Adresse
        # schickte ein zweiter Worker, solange der erste Link noch im Postausgang lag, einen an ein
        # anderes `mail` — kam er an, war die erste Adresse frei (eine vergebene schreibt ihre
        # Abweisung sofort), und das Konto bekam zwei Links an einem Tag.
        frist = max(86400, int(self.cfg.email_change_ttl_min) * 60)
        if self.store.offener_token(u["id"], "email_change"):
            return
        if self.store.quellmail_seit(u["id"], _jetzt() - frist):
            return
        # Was vorübergeht (Drossel, Mailserver), dämpft der Speicher je Prozess (G12a): nach dem
        # Fenster der Mail-Drossel wieder. Für jedes Ziel gleich — gefragt wird „vergeben?" erst in
        # `_wechsel_beantragen`, mit derselben Arbeit für beide Antworten (G12b).
        if not self.rl.allow(f"quellmail:{u['id']}", 1, int(self._sec("mail_per_address_window_sec"))):
            return
        try:
            senden = self._wechsel_beantragen(u["id"], adresse, self.cfg.base_url, quelle=quelle or "quelle")
        except (ValueError, ConfigError):
            return
        if senden is None:
            return
        uid, name = u["id"], u["username"]
        # Die Zeile im Kontext der Anfrage schreiben (IP wie bisher), aber erst im Postausgang
        # und nur, wenn der Link wirklich hinausging — sie ist das Tageskontingent.
        anfrage = contextvars.copy_context()

        def _versand():
            if senden():
                anfrage.run(self.audit, "federation_email_confirm", name,
                            detail=f"konto={uid} quelle={quelle} an={adresse}")
        if not self._hinweis_ausgang.einreihen(_versand):
            # Warteschlange voll: Der Link geht nie hinaus. Sein Token verfällt sofort — sonst
            # hielte er als offener Link (`offener_token`) jeden neuen bis zu seinem Ablauf auf,
            # ohne dass je einer zugestellt war. Den nächsten Versuch dämpft der Speicher wie
            # nach einem gescheiterten Versand (`quellmail:<id>`, das Fenster der Mail-Drossel).
            senden.verwerfen()

    # ---------- Passkeys verwalten ----------
    def remove_passkey(self, user_id: int, passkey_id: int, ip: Optional[str] = None) -> bool:
        """Einen Passkey eines Kontos entfernen — Löschen, Audit-Zeile und `passkey_removed` in einem.

        Beide Wege laufen hierüber: die Selbstbedienung (`/auth/passkey/delete`) und der Widerruf
        durch einen Admin im Panel. Vorher hatte jeder seine eigenen Zeilen, und nach dem
        Zusammenführen zweier Zweige meldete nur die Selbstbedienung das Ereignis — ausgerechnet
        der Widerruf an einem FREMDEN Konto, den ein übernommenes Admin-Konto vornimmt, blieb
        für den Inhaber still (Integrationsfund 3). Die Audit-Zeile steht unter dem Inhaber;
        handelt ein anderer, ergänzt `audit()` `akteur=` aus der laufenden Anfrage.

        Gibt False zurück, wenn das Konto keinen Passkey mit dieser ID hat — dann wird weder
        gelöscht noch protokolliert noch gemeldet (vorher schrieb die Selbstbedienung auch für
        einen erfundenen Passkey eine Zeile und ein Ereignis)."""
        if not any(int(c["id"]) == int(passkey_id) for c in self.store.list_webauthn(user_id)):
            return False
        self.store.delete_webauthn(int(passkey_id), user_id)
        # Einen Faktor zu verlieren ist genau das, was man später nachlesen will (B5-01).
        self.audit("passkey_delete", self._kontoname(user_id), ip, f"id={int(passkey_id)}")
        self._sicherheitsereignis("passkey_removed", user_id, passkey_id=int(passkey_id))
        return True

    # ---------- PIN-Login (persönliche PIN pro User) ----------
    def set_pin(self, user_id, pin):
        """PIN setzen/ändern. Mindestlänge aus cfg.pin_min_length."""
        pin = str(pin or "")
        if len(pin) < self.cfg.pin_min_length:
            raise ConfigError(f"PIN zu kurz (min. {self.cfg.pin_min_length})")
        self.store.set_pin_hash(user_id, hash_password(pin))
        self._sicherheitsereignis("pin_set", user_id)

    def has_pin(self, user_id) -> bool:
        """Hat dieses Konto eine PIN eingerichtet?"""
        return self.store.has_pin(user_id)

    def disable_pin(self, user_id):
        """Die PIN eines Kontos entfernen (wird protokolliert — ein zweiter Faktor verschwindet nicht unbemerkt)."""
        self.store.delete_pin(user_id)
        self.audit("pin_disable", self._kontoname(user_id), detail=f"user={user_id}")
        self._sicherheitsereignis("pin_disabled", user_id)

    def _check_pin(self, username, pin) -> Optional[dict]:
        """Wie `_check_password`, nur mit der persönlichen PIN."""
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
    def _verify_user_password(self, user_id, password) -> bool:
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

    def _verify_user_pin(self, user_id, pin) -> bool:
        """Wie `_verify_user_password`, nur mit der PIN."""
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

    def _is_pin_locked(self, username, ip, login: bool = True) -> bool:
        """Eigener, methoden-scoped Lockout für PIN (kurzer Keyspace). Zusätzlich zu is_locked().

        Die Abweisung wird hier gemeldet (`_abgewiesen`), wie bei jeder anderen Sperre: Bis
        T-13 wies diese als einzige stumm ab, und das Sicherheits-Log schwieg genau dann, wenn
        fail2ban lesen sollte. `login=False` für die Step-up-Seite — dort ist die PIN keine
        Anmeldung, die Zeile trägt dann `failed verification`.
        """
        return self._sperre_pruefen(self._regeln_pin(username, ip), username, ip, login)

    def _is_password_change_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Alt-Passwort-Abfrage der Kontoseite.

        Dieselbe Bauform wie `_is_pin_locked`, aber mit eigener Schwelle
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
        Angemeldete selbst. Gegen das Klopfen von aussen steht weiter `_rate_ok(ip)`.

        Die Abweisung wird hier gemeldet, nicht in der Route: Sonst verstummte das
        Sicherheits-Log genau dann, wenn fail2ban die IP bannen soll (Begründung bei
        `_abgewiesen`).
        """
        return self._sperre_pruefen(self._regeln(username, ip, "password_change"),
                                    username, ip, login=False)

    def _is_reauth_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Step-up-Bestätigung (`/auth/reauth`).

        Eine Step-up-Bestätigung ist **keine Anmeldung** — wer sie leistet, ist schon
        angemeldet. Bis zur zweiten Runde zählten ihre Fehlversuche trotzdem in den
        Login-Topf: Fünf Tippfehler an der Reauth-Seite sperrten dem Nutzer die **Anmeldung**
        für `lockout_window_sec`, samt dem korrekten Passwort. Jetzt bremst sie dieser Topf
        (`reauth_max_attempts`), und zwar **nur pro Konto**: Das Raten trifft ausschliesslich
        das eigene Konto, eine IP-Schwelle träfe hinter NAT nur Unbeteiligte (`ip` geht bloss
        in die Protokollzeile). Gedrosselt bleibt der Weg über `_rate_ok(ip)`.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "reauth"), username, ip, login=False)

    def _is_resource_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Bereichs-PIN (`/auth/resource/…`).

        `username` ist hier der Pseudo-Name des Bereichs (`res:<name>`) — ein Konto gibt es
        nicht. Bis zur zweiten Runde lief der Zähler in den Login-Topf, und weil die
        Bereichs-PIN **jeder Besucher** probieren darf, war das ein Verstärker: Drei Bereiche
        mal fünf Fehlgriffe von derselben Adresse erreichten die Login-IP-Schwelle
        (`max_login_attempts * ip_attempt_factor`) und verriegelten die Anmeldung von Konten,
        die nie etwas falsch gemacht hatten.

        Zwei Schwellen, und ihre Reihenfolge ist der Punkt (R7-3): **je Adresse**
        `resource_max_attempts`, **je Bereich** das `account_attempt_factor`-fache davon. Bis
        T-13 war es umgekehrt — der Bereich sperrte schon nach `resource_max_attempts`, egal von
        wem. Ein einzelner Fremder verriegelte so mit fünf Fehlgriffen den Bereich für ALLE,
        auch für die, die das Geheimnis kennen. Jetzt stoppt ihn seine eigene Adresse, lange
        bevor der Bereich zugeht; dafür braucht es mehrere Anschlüsse. Ganz fallen lassen lässt
        sich die Bereichsschwelle nicht: Ohne sie rät ein verteilter Angreifer eine vierstellige
        PIN in Stunden, weil jede Adresse ihre eigenen Versuche mitbringt.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "resource"), username, ip, login=False)

    def _is_totp_setup_locked(self, username, ip) -> bool:
        """Eigener, methoden-scoped Lockout für die Bestätigung der TOTP-Einrichtung.

        Die Route `POST /auth/totp/setup` prüfte bis T-13 beliebig viele Codes, ohne Drossel,
        ohne Sperre und ohne Protokollzeile (Funde B2-12, R3-6) — die einzige OTP-Prüfstelle,
        an der das so war. Raten bringt dort wenig (wer einrichtet, sieht das Geheimnis), aber
        eine Prüfstelle ohne Bremse und ohne Spur ist genau die, nach der niemand mehr schaut.
        Wie `reauth` **nur pro Konto** (`totp_setup_max_attempts`) und getrennt vom
        Login-Lockout: Fünf Tippfehler beim Einrichten sollen nicht die Anmeldung sperren.

        Nur lesend: Die Route nimmt `_versuch_beginnen(…, "totp_setup")`, das prüft und bucht in
        einem Schritt — mit dieser Methode vorab und `_record_login()` danach kam eine parallele
        Salve an der Grenze vorbei.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "totp_setup"), username, ip, login=False)

    # ---------- Die Sperr-Regeln: eine Quelle für Prüfen und atomares Verbuchen ----------
    def _regeln_pin(self, username, ip, since=None) -> list:
        """Der eigene PIN-Topf: pro Konto `pin_max_attempts`, pro Adresse das `ip_attempt_factor`-fache.

        Pro Konto und nicht pro Paar aus Konto und Adresse: Eine PIN hat oft nur vier Stellen,
        ein verteilter Angreifer hätte sie mit Paar-Zählung in Stunden durch."""
        since = self._fenster_beginn() if since is None else since
        username = norm_kennung(username)
        grenze = self._sec("pin_max_attempts")
        return [("lockout_pin", grenze, dict(since=since, username=username, method="pin")),
                ("lockout_pin_ip", grenze * self._sec("ip_attempt_factor"),
                 dict(since=since, ip=ip, method="pin"))]

    @staticmethod
    def _topf(username, method) -> str:
        """Unter welchem Namen ein Versuch zählt: die Kennung so gefaltet wie `find_user` sie liest.

        Gezählt wurde bis zur dritten Runde unter dem ROH eingetippten Text, gesucht aber
        getrimmt und ohne Gross-/Kleinschreibung. `' opfer'`, `'opfer '`, `'\topfer'` trafen
        dasselbe Konto und füllten je einen eigenen Topf — die Konto-Schwelle gegen verteiltes
        Raten (R7-6/H-8) band damit nichts. Ausgenommen ist der Bereichs-Pseudoname
        `res:<name>`: Den setzt der Server aus einem Bereich, den es geben muss."""
        return username if method == "resource" else norm_kennung(username)

    def _fenster_beginn(self) -> int:
        return _jetzt() - self._sec("lockout_window_sec")

    def _regeln(self, username, ip, method) -> list:
        """Welche Zähler gelten für einen Versuch dieser Methode? Liste `(grund, grenze, filter)`.

        `is_*_locked()` prüft sie, `_versuch_beginnen()` prüft sie UND bucht atomar — beide lesen
        dieselbe Liste, damit die beiden Wege nie verschieden streng sind.

        **Anmeldung** (alles ausser `security.NICHT_LOGIN_METHODEN`, R7-6/H-8): Die erste
        Schwelle zählt je **Paar aus Konto und Adresse** (`max_login_attempts`). Bis T-13 zählte
        sie je Konto allein — dann sperrte jeder Fremde jedes Konto, dessen Namen er kannte,
        mit fünf Anfragen für ein Fenster aus, samt dem Inhaber mit dem richtigen Passwort. Je
        Konto bleibt eine zweite, höhere Schwelle (`account_attempt_factor`-fach) gegen das
        Raten über viele Adressen; die erreicht ein Einzelner nicht mehr, weil ihn das Paar
        vorher stoppt. Je Adresse bleibt die NAT-Schwelle (`ip_attempt_factor`-fach) gegen
        das Durchprobieren vieler Konten.

        Der Konto-Schlüssel ist `_topf(username)`, nicht der rohe Text — sonst stellt sich ein
        Angreifer mit Leerzeichen und Schreibweisen beliebig viele Töpfe für dasselbe Konto auf.
        """
        since = self._fenster_beginn()
        username = self._topf(username, method)
        if method in ("password_change", "reauth", "totp_setup"):
            grenze = self._sec(f"{method}_max_attempts")
            return [(f"lockout_{method}", grenze, dict(since=since, username=username, method=method))]
        if method == "resource":
            grenze = self._sec("resource_max_attempts")
            return [("lockout_resource_ip", grenze, dict(since=since, ip=ip, method=method)),
                    ("lockout_resource", grenze * self._sec("account_attempt_factor"),
                     dict(since=since, username=username, method=method))]
        ohne = security.NICHT_LOGIN_METHODEN
        grenze = self._sec("max_login_attempts")
        regeln = []
        if username and ip:
            regeln.append(("lockout_user", grenze,
                           dict(since=since, username=username, ip=ip, exclude_methods=ohne)))
        regeln += [
            ("lockout_account", grenze * self._sec("account_attempt_factor"),
             dict(since=since, username=username, exclude_methods=ohne)),
            ("lockout_ip", grenze * self._sec("ip_attempt_factor"),
             dict(since=since, ip=ip, exclude_methods=ohne)),
        ]
        if method == "pin":
            regeln += self._regeln_pin(username, ip, since)
        return regeln

    def _serie_voll(self, username) -> bool:
        """Hat diese Kennung `account_max_consecutive_failures` Fehlversuche IN FOLGE erreicht (B2-6)?

        Anders als jede Fenster-Schwelle läuft diese Sperre nicht ab: Sie endet mit einer
        vollständigen Anmeldung auf einem anderen Weg (Passkey, Magic-Link, OIDC), einem
        Passwort-Reset oder durch den Betreiber (Panel-Reset, `tinysesam unlock`). Gezählt wird
        je gefalteter Kennung, ob es das Konto gibt oder nicht — sonst verriete die Sperre, welche
        Namen existieren.

        Nur was feststeht (`fehlserie_bestaetigt`, G9): Eine schwebende Vorbuchung kann noch
        zurückgenommen werden — ein Aufschub zeigt deshalb nie den Text der Serien-Sperre."""
        return (self.store.fehlserie_bestaetigt(norm_kennung(username))
                >= self._sec("account_max_consecutive_failures"))

    def _serie_reset_hilft(self, username) -> bool:
        """Hebt ein Selbstbedienungs-Reset die Serien-Sperre unter dieser Kennung auf?

        Er räumt nur die Anteile der ersten Faktoren (`_SERIE_RESET_ARTEN`), nicht TOTP und nicht
        die PIN im Kettenschritt (`_SERIE_PIN_FOLGE`, G7). Stehen die allein an der Grenze, nannten
        Sperrhinweis und Sicherheits-Log bis 2026-09-27 trotzdem den Reset als Ausweg — der Inhaber
        setzte sein Passwort zurück und blieb gesperrt. Nur für Texte an Inhaber und Betreiber: Die
        Anmeldeseite zeigt jedem denselben Text (`err.locked_serie`), sonst verriete sie, dass
        unter einer Kennung jemand am zweiten Faktor rät — und damit, dass es das Konto gibt."""
        return (self.store.fehlserie_ohne(norm_kennung(username), self._SERIE_RESET_ARTEN)
                < self._sec("account_max_consecutive_failures"))

    def _serie_ausweg(self, username) -> str:
        """Was die Serien-Sperre unter dieser Kennung aufhebt — für das Sicherheits-Log."""
        if self._serie_reset_hilft(username):
            return "Passwort-Reset, Anmeldung über einen anderen Weg oder `tinysesam unlock`"
        return ("Anmeldung über einen anderen Weg oder `tinysesam unlock` (ein Passwort-Reset räumt "
                "die Fehlversuche nach dem Passwort nicht: TOTP, PIN im Kettenschritt)")

    def _sperre_pruefen(self, regeln, username, ip, login: bool) -> bool:
        """Die Regeln lesend prüfen; die erste, die greift, wird gemeldet (`_abgewiesen`).

        Greift eine Regel nur wegen schwebender Vorbuchungen (G9, `Store.reserve_attempt`), ist das
        ein Aufschub, keine Sperre: `True` ohne `failed login` und ohne Sperrhinweis
        (`_aufgeschoben`). Eine Regel, die auch bestätigt greift, geht vor."""
        schwebend = False
        if login and username:
            if self._serie_voll(username):
                self._abgewiesen(username, ip, "lockout_serie", login=True)
                return True
            schwebend = (self.store.fehlserie(norm_kennung(username))
                         >= self._sec("account_max_consecutive_failures"))
        for grund, grenze, filt in _gueltige_regeln(regeln):
            if self.store.count_fails(**filt) < grenze:
                continue
            if self.store.count_fails(**filt, nur_bestaetigt=True) >= grenze:
                self._abgewiesen(username, ip, grund, login=login)
                return True
            schwebend = True
        if schwebend:
            self._aufgeschoben(username, ip, login=login)
        return schwebend

    def _versuch_beginnen(self, username, ip, method, auch_pin: bool = False,
                          serie_art: Optional[str] = None, schweben: bool = False) -> Optional[int]:
        """Einen Prüfversuch **atomar** zulassen und vorab als Fehlversuch verbuchen.

        Rückgabe: eine Versuchs-ID, die an `_record_login(..., versuch=id)` zurückgeht, oder
        `None` — gesperrt (bereits gemeldet). Ersetzt die Folge `_is_locked()` → prüfen →
        `_record_login()`, die eine parallele Salve an der Sperre vorbeiliess (R3-2, R3-7,
        R7-2; Begründung bei `Store.reserve_attempt`).

        `auch_pin=True` hängt den PIN-Topf mit an — für die Step-up-Seite, auf der eine PIN
        bestätigt, deren Versuche aber im Topf `reauth` landen.

        `serie_art` bucht den Versuch in der Serie (B2-6) unter einer anderen Art als der
        Methode — `_SERIE_PIN_FOLGE` für eine PIN, die HINTER einem schon erbrachten Faktor steht
        (Kettenschritt, Route-Kette; G7). Fenster und Töpfe zählen weiter unter `method`.

        `schweben=True` bucht den Versuch mit offenem Ausgang (G9, `Store.reserve_attempt`): für
        eine Prüfung, die auch „gar kein Versuch" ergeben kann — die Login-Route mit LDAP, deren
        Vorbuchung bei einem Ausfall zurückgenommen wird (F-23). Würde ein Versuch **nur** wegen
        solcher offenen Vorbuchungen abgewiesen, wartet er, bis sie entschieden sind: höchstens
        `_SCHWEBE_FRIST_SEK`, höchstens `_SCHWEBE_WARTEPLAETZE` Wartende je Prozess. Bleibt es
        offen, ist die Antwort `None` wie bei einer Sperre — aber mit `deferred login` statt
        `failed login` im Sicherheits-Log (fail2ban bannt nicht) und ohne Sperrhinweis.
        """
        regeln = self._regeln(username, ip, method)
        if auch_pin:
            regeln = regeln + self._regeln_pin(username, ip)
        # Die Serie (B2-6) gehört in DIESELBE Transaktion wie der Versuch: geprüft und vorgebucht
        # in `reserve_attempt`. Vorher davor gelesen und erst nach der Prüfung gezählt — eine
        # parallele Salve an der Grenze durfte dann jeder Anfrage einen Versuch lang raten.
        serie = None
        if method not in security.NICHT_LOGIN_METHODEN:
            serie = (norm_kennung(username), serie_art or method, self._sec("account_max_consecutive_failures"))

        def buchen():
            return self.store.reserve_attempt(self._topf(username, method), ip, method,
                                              _gueltige_regeln(regeln), serie=serie, schweben=schweben)

        versuch, antwort = buchen()
        if versuch is None and antwort == "schwebend":
            versuch, antwort = self._schwebe_abwarten(buchen)
        if versuch is None:
            login = method not in security.NICHT_LOGIN_METHODEN
            if antwort == "schwebend":
                self._aufgeschoben(username, ip, login=login)
            else:
                self._abgewiesen(username, ip, antwort, login=login)
        elif serie is not None:
            # Die Art, unter der gebucht WURDE (`serie[1]`), nicht die Methode: Sonst senkte ein
            # richtiger Folgeschritt die Art `pin` und liesse seine Vorbuchung unter `pin_folge`
            # stehen (G7).
            self._serie_vorbuchungen[versuch] = (serie[0], serie[1], antwort)
            # Gedeckelt: Ein Versuch, den nie jemand abschliesst (Ausnahme mitten in der Route),
            # bliebe sonst für immer liegen. Wer herausfällt, zählt als Fehlversuch — strenger,
            # nie lockerer.
            while len(self._serie_vorbuchungen) > self._SERIE_VORBUCHUNGEN_MAX:
                self._serie_vorbuchungen.pop(next(iter(self._serie_vorbuchungen)), None)
        return versuch

    _SERIE_VORBUCHUNGEN_MAX = 10000

    #: Schwebende Vorbuchungen (G9, `_versuch_beginnen`): wie viele Anmeldungen je Prozess
    #: gleichzeitig warten dürfen, wie lange höchstens (eine Verzeichnis-Frage bis zu ihrem Timeout
    #: und etwas Luft) und in welchem Takt sie nachfragen. Jedes Nachfragen nimmt die Schreibsperre
    #: (`BEGIN IMMEDIATE`) — bei voller Belegung höchstens rund 40 kurze Transaktionen je Sekunde.
    _SCHWEBE_WARTEPLAETZE = 8
    _SCHWEBE_FRIST_SEK = _LDAP_TIMEOUT + 2
    _SCHWEBE_TAKT_SEK = 0.2

    def _schwebe_abwarten(self, buchen) -> tuple:
        """Warten, bis die schwebenden Vorbuchungen entschieden sind, dann erneut buchen (G9).

        Rückgabe wie `Store.reserve_attempt`; `(None, "schwebend")`, wenn die Frist abläuft oder
        kein Warteplatz frei ist. Ohne Deckel hielte eine Salve jeden Worker-Thread fest.

        Das Warten blockiert den aufrufenden Thread — richtig für die synchronen Routen (sie laufen
        im Threadpool). Auch `POST /auth/password` ruft seine Prüfung seit 0.22.0 im Threadpool
        (`change_password`); sie schwebt ohnehin nie: Ihr Topf zählt nur die eigene Methode, und
        die bucht nie offen."""
        if not self._schwebe_plaetze.acquire(blocking=False):
            return None, "schwebend"
        try:
            frist = time.monotonic() + self._SCHWEBE_FRIST_SEK
            while time.monotonic() < frist:
                time.sleep(self._SCHWEBE_TAKT_SEK)
                versuch, antwort = buchen()
                if versuch is not None or antwort != "schwebend":
                    return versuch, antwort
            return None, "schwebend"
        finally:
            self._schwebe_plaetze.release()

    def _aufgeschoben(self, username, ip, login: bool = True) -> None:
        """Eine Abweisung, die keine Sperre ist: nur schwebende Vorbuchungen im Weg (G9).

        Eigenes Ereigniswort (`deferred login`/`deferred verification`) — die mitgelieferten
        fail2ban-Filter treffen es nicht, und es geht kein Sperrhinweis hinaus: Womöglich steht
        danach kein einziger Fehlversuch in der Tabelle. Protokolliert wird trotzdem, damit ein
        Betreiber die 429 zuordnen kann."""
        security.seclog.warning("deferred %s user=%s ip=%s reason=pending",
                                "login" if login else "verification",
                                security.fuer_log(username) or "-", security.fuer_log(ip))

    def _versuch_zuruecknehmen(self, versuch) -> None:
        """Einen vorgebuchten Versuch zurücknehmen — er war keiner (Verzeichnis-Ausfall, F-23).

        Mitsamt seiner Vorbuchung in der Serie (B2-6), in einer Transaktion (G9): Ein Ausfall ist
        kein Fehlversuch, weder im Fenster noch in Folge."""
        gebucht = self._serie_vorbuchungen.pop(versuch, None)
        self.store.cancel_attempt(versuch, serie=gebucht[:2] if gebucht else None)

    def _versuch_gescheitert(self, versuch) -> None:
        """Einen vorgebuchten Versuch als Fehlversuch abschliessen, ohne `_record_login` (G9).

        Für eine Route, deren Prüfung mit einer unerwarteten Ausnahme endet: Der Versuch zählt
        sofort — im Zweifel strenger, wie bei einem Prozess, der mittendrin stirbt —, statt
        `Store.VORBUCHUNG_SCHWEBE_SEK` lang zu schweben und Anmeldungen derselben Adresse warten
        zu lassen. Die Serie bleibt gebucht."""
        self._serie_vorbuchungen.pop(versuch, None)
        self.store.finish_attempt(versuch, False)

    # ---------- MFA (TOTP) ----------
    def _mfa_pending(self, user_id) -> bool:
        """TOTP verlangt? Ja, wenn ein bestätigtes TOTP für dieses Konto existiert.

        Eine globale Erzwingung gibt es hier nicht (mehr): Der Schalter `totp_required`, auf den
        der frühere Klammerzusatz zielte, wird seit 0.18.0 im Konstruktor mit `ConfigError`
        abgewiesen. Erzwungen wird über `login_chain` — und die wertet `_session_ok` aus, nicht
        diese Methode."""
        return self.store.has_confirmed_totp(user_id)

    def _verify_totp(self, user_id, code) -> bool:
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
            self.audit("totp_setup_denied", self._kontoname(user_id),
                       detail=f"user={user_id} grund=bereits_bestaetigt")
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
            self.audit("recovery_verwaist_geloescht", str(u["username"]),
                       detail=f"user={user_id} n={verwaist}")
        secret = _totp.new_secret()
        self.store.set_totp(user_id, secret, confirmed=False)
        self.audit("totp_setup_start", str(u["username"]), detail=f"user={user_id}")
        uri = _totp.provisioning_uri(secret, u["username"], self.cfg.rp_name)
        return {"secret": secret, "uri": uri, "qr": _totp.qr_data_uri(uri)}

    def totp_confirm(self, user_id, code) -> bool:
        """Die Einrichtung abschliessen — erst mit einem gültigen Code ist TOTP wirklich an.

        Der Bestätigungscode wird **verbraucht** wie jeder andere (Fund B2-3): Bis T-13 prüfte
        diese Stelle nur `verify()` und buchte den Zeitschritt nicht. Derselbe Code, eben zur
        Einrichtung eingetippt (und dabei womöglich abgelesen), meldete danach an
        `/auth/totp` noch bis zu 90 Sekunden an — die Einmal-Zusage aus T-9 galt nur für die
        Anmeldung, nicht für die Einrichtung. Wer unter `login_chain=["password","totp"]`
        einrichtet, bekommt den TOTP-Schritt mit dieser Bestätigung gleich gutgeschrieben (die
        Route erledigt das, A-1) — sonst wäre der eben getippte Code dort ein Fehlversuch.

        Ein **schon bestätigtes** TOTP bestätigt diese Methode nicht noch einmal (A-4): Sie meldete
        sonst `totp_enabled` für etwas, das niemand eingerichtet hat, und war nebenbei ein
        zweiter Code-Prüfer für den aktiven Faktor mit eigenem Versuchstopf."""
        t = self.store.get_totp(user_id)
        if not t or not code or t["confirmed"]:
            return False
        schritt = _totp.passender_schritt(t["secret"], code)
        if schritt is None or not self.store.totp_step_verbrauchen(user_id, schritt):
            return False
        self.store.confirm_totp(user_id)
        # Ab hier gilt ein neuer zweiter Faktor — das Gegenstück zu `totp_disable` und
        # bisher die einzige Faktor-Änderung ohne Zeile (B5-07). Gerade sie ist es, die ein
        # Angreifer mit einer übernommenen Sitzung vornimmt, um wiederzukommen.
        self.audit("totp_enable", self._kontoname(user_id), detail=f"user={user_id}")
        self._sicherheitsereignis("totp_enabled", user_id)
        return True

    def totp_disable(self, user_id):
        """TOTP entfernen, samt der Recovery-Codes (beides wird protokolliert)."""
        offen = self.store.count_recovery_codes(user_id)   # vor dem Löschen zählen
        hatte = self.store.has_confirmed_totp(user_id)
        self.store.delete_totp(user_id)
        self.store.delete_recovery_codes(user_id)   # ohne TOTP sind Recovery-Codes gegenstandslos
        # Das Abschalten eines zweiten Faktors ist das, was ein Angreifer als Erstes tut, wenn er
        # eine Sitzung hat. Ohne Eintrag ist es hinterher nicht nachvollziehbar — bis 2026-09-21
        # hinterliess es keine Spur, obwohl dabei TOTP UND alle Recovery-Codes fallen.
        self.audit("totp_disable", self._kontoname(user_id), detail=f"user={user_id} recovery_codes_geloescht={offen}")
        if hatte:
            self._sicherheitsereignis("totp_disabled", user_id, recovery_codes_deleted=offen)

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
    _RECOVERY_BYTES = 7
    #: Ab so wenigen verbleibenden Codes zeigt die Kontoseite eine Warnung und das
    #: Sicherheits-Log eine Zeile — wer sie aufbraucht, soll rechtzeitig neue erzeugen.
    _RECOVERY_WARNSCHWELLE = 3

    def generate_recovery_codes(self, user_id, n=None) -> list:
        """Neue Einmal-Codes erzeugen (ersetzt vorhandene). Klartext-Rückgabe NUR EINMAL."""
        n = int(n or self.cfg.recovery_code_count)
        codes = ["-".join(secrets.token_hex(self._RECOVERY_BYTES) for _ in range(2)) for _ in range(n)]
        self.store.delete_recovery_codes(user_id)
        self.store.add_recovery_codes(user_id, [self._rc_hash(c) for c in codes])
        self.audit("recovery_generate", self._kontoname(user_id), detail=f"user={user_id} n={n}")
        self._sicherheitsereignis("recovery_codes_generated", user_id, count=n)
        return codes

    @staticmethod
    def _rc_hash(code) -> str:
        norm = str(code or "").strip().lower().replace(" ", "")
        return hashlib.sha256(norm.encode()).hexdigest()

    def _verify_recovery_code(self, user_id, code) -> bool:
        """Einen Einmal-Code prüfen und verbrauchen. Ein Code gilt genau einmal."""
        if not code:
            return False
        if not self.store.consume_recovery_code(user_id, self._rc_hash(code)):
            return False
        # Eigene Zeile (B5-07/B2-7). Ein verbrauchter Code heisst: Der Authenticator fehlte — oder jemand anderes hat einen
        # Code. Beides soll der Inhaber erfahren, und der Betreiber soll es von einer
        # TOTP-Anmeldung unterscheiden können (Fund B2-7). Bis T-13 blieb davon nichts: keine
        # Audit-Zeile, kein Hinweis, wie viele Codes noch übrig sind.
        rest = self.store.count_recovery_codes(user_id)
        self.audit("recovery_used", self._kontoname(user_id), detail=f"user={user_id} verbleibend={rest}")
        security.seclog.warning("recovery code used user_id=%s verbleibend=%s", user_id, rest)
        self._sicherheitsereignis("recovery_code_used", user_id, remaining=rest)
        return True

    def recovery_codes_remaining(self, user_id) -> int:
        """Wie viele Einmal-Codes dieses Konto noch hat."""
        return self.store.count_recovery_codes(user_id)

    # ---------- Passwort-Reset (Forgot-Password) ----------
    def federated_only(self, user_id) -> bool:
        """Reines SSO-Konto: an einen IdP/ein Verzeichnis gebunden und ohne lokales Passwort.

        Liefert das Verzeichnis keine stabile Kennung, bindet der Login einen Herkunfts-Platzhalter
        (`_OHNE_KENNUNG`, A-4) — auch so ein Konto zählt hier als föderiert.

        Grenze: Ein LDAP- oder SAML-Konto, das sich seit dem Update auf diese Fassung nicht
        angemeldet hat, trägt noch keine Zeile und zählt hier als lokal.

        Nicht hier geregelt: Der Magic-Login-Link (`magiclink_enabled`) geht auch an ein reines
        SSO-Konto — das ist ein vom Betreiber eingeschalteter Anmeldeweg, kein Passwort, das
        bleibt; ob er für solche Konten abgeschaltet gehört, ist eine Produktentscheidung."""
        return (self.store.has_foreign_identity(user_id)
                and not self.store.get_password_hash(user_id))

    def send_password_reset(self, email, base_url) -> bool:
        """Reset-Link an eine E-Mail schicken, WENN ein passender User existiert. Nach außen immer
        gleiche Meldung (keine Enumeration). `base_url` wird geprüft (`ConfigError` bei einem
        fremden Host, siehe `magic_url`).

        Geprüft wird als Erstes — vor der Kontosuche, damit „Ausnahme statt False" nicht
        verrät, ob es die Adresse gibt, und vor der Token-Vergabe, damit kein unbrauchbarer
        Token zurückbleibt.

        Die Mail geht an die **gespeicherte** Adresse, nicht an die Eingabe (R4-11): Die Suche
        ist nachsichtig (Gross-/Kleinschreibung, Leerzeichen), der Versand darf es nicht sein.
        Scheitert der Versand, wird der Token sofort entwertet (B6-12) und der Fehler geht an
        den Aufrufer weiter.
        """
        base_url = self._gepruefte_basis(base_url)
        u = self.store.get_user_by_email(email)
        if not u or u["disabled"] or u["is_service"]:
            return False
        if self.federated_only(u["id"]):
            # Ein reines SSO-Konto bekommt keinen Reset-Link (H-4). Er setzte ein LOKALES
            # Passwort — ein zweiter Weg an IdP bzw. Verzeichnis vorbei: Sperre, Gruppenentzug
            # und MFA-Pflicht des Providers griffen dann nicht mehr, und bei LDAP gewinnt das
            # lokale Passwort sogar vor dem Verzeichnis (`_check_password` zuerst). Die Antwort
            # nach aussen bleibt dieselbe (keine Konto-Erkundung); der Grund steht im Audit-Log.
            self.audit("reset_sso_only", u["username"], detail="kein lokales Passwort, föderiert")
            return False
        ziel = u["email"]
        if not self._mail_ziel_ok(ziel, "reset_password"):
            return False
        raw = self.create_magic_token("reset_password", user_id=u["id"], email=ziel)
        url = self.magic_url(raw, base_url, "reset_password")
        mins = self.cfg.magiclink_ttl_min
        self._token_mail(raw, ziel, "Passwort zurücksetzen",
                         f"Zum Zurücksetzen deines Passworts diesen Link öffnen (gültig {mins} Minuten):\n\n{url}\n\n"
                         f"Wenn du das nicht angefordert hast, ignoriere diese E-Mail.",
                         html=f'<p>Passwort zurücksetzen (gültig {mins} Minuten):</p><p><a href="{url}">Neues Passwort setzen</a></p>')
        return True

    # ---------- Faktor-Ketten-Engine ----------
    _IDENTIFYING = ("password", "pin", "oidc", "passkey", "magic", "saml")  # Faktoren, die den User identifizieren

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
        if not any(f in done for f in self._IDENTIFYING):
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
            ok = self._chain_satisfied(req, strict, done)
        else:
            ok = self._default_satisfied(user_id, done)
        return ok and self._link_braucht(user_id, done) is None

    def _next_login_step(self, user_id, done):
        """Nächster offener Faktor bis zur vollen (globalen) Anmeldung, oder None wenn fertig."""
        req, strict = self._global_chain()
        if req is not None:
            if not self._chain_satisfied(req, strict, done):
                return self._next_factor(req, strict, done)
        elif not self._default_satisfied(user_id, done):
            return "totp"
        return self._link_braucht(user_id, done)

    def _link_braucht(self, user_id, done) -> Optional[str]:
        """Welcher zweite Faktor fehlt noch, weil die Anmeldung über den Anmelde-Link lief?
        None, wenn keiner (ASVS 6.3.6, PO-Entscheid 2026-09-24, `magiclink_require_second_factor`).

        Der Link beweist nur das Postfach. Hat das Konto einen zweiten Faktor, verlangt ihn die
        Anmeldung — sonst wäre das Postfach allein der Schlüssel zu einem Konto, das sich mit
        einem Authenticator geschützt hat. Die klassische Policy verlangte ein eingerichtetes TOTP
        schon immer; offen waren Konten nur mit Passkey und Ketten, in denen der Link allein
        genügt (`["magic"]`). Konten ohne zweiten Faktor meldet der Link weiter allein an (der
        Preis von C gegenüber D, bewusst so entschieden). Gilt für die globale Policy und für jede
        Route-Kette (`require(factors=[…])`, G10)."""
        if not self.cfg.magiclink_require_second_factor or "magic" not in done:
            return None
        if "totp" in done or "passkey" in done:
            return None
        if self.store.has_confirmed_totp(user_id):
            return "totp"
        if self.store.list_webauthn(user_id):
            return "passkey"
        return None

    def _factor_entry(self, step, nxt="/") -> str:
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
            if not self._herkunft_ok(request) or not self._verify_csrf(request, token):
                raise HTTPException(403, self.t("api.csrf"))
        return data

    # ---------- CSRF (Double-Submit) ----------
    def issue_csrf(self, response: Response) -> str:
        """Ein NEUES CSRF-Token würfeln und als Cookie setzen; Rückgabe ist das Token. Für eine
        Seite mit Formular ist `ensure_csrf()` der Weg — dieses hier entwertet die Formulare in
        allen anderen offenen Reitern.

        Gedacht für das bewusste Erneuern (`_csrf_rotieren()`). Ersetzt eine CSRF-Zeile, die die
        Antwort schon trägt, statt eine zweite anzuhängen. Ist CSRF abgeschaltet, passiert
        nichts und der Rückgabewert ist leer."""
        if not self.cfg.csrf_enabled:
            return ""
        token = secrets.token_urlsafe(24)
        self._csrf_cookie_setzen(response, token)
        return token

    def ensure_csrf(self, request: Request, response: Response) -> str:
        """Ein gültiges CSRF-Cookie sicherstellen und das Token fürs Formular zurückgeben.

        Der Weg für eigene Seiten einer einbettenden App (0.20.1): Ein vorhandenes, gültiges
        Token bleibt — die Formulare in anderen Reitern gelten weiter, und die Antwort bekommt
        keine Set-Cookie-Zeile. Fehlt es oder sieht der Cookie-Wert nicht wie ein Token aus
        (`_CSRF_FORM`), wird ein neues gesetzt, mit denselben Attributen wie bei `issue_csrf()`.
        Hat diese Antwort das Token schon gedreht (`set_cookie()` nach einer Anmeldung) oder
        gelöscht (`logout()`), gilt das: nach der Anmeldung das neue, nach dem Abmelden ein
        frisches — nie das alte aus dem Request. Ist CSRF abgeschaltet: nichts, Rückgabe "".

        Zwei Formen, je nachdem, wann die Antwort entsteht:

        * FastAPI-Antwortparameter (`def seite(request: Request, response: Response)`, die Seite
          als Rückgabewert): `csrf = auth.ensure_csrf(request, response)`, dann rendern.
        * Fertige Antwort (Jinja `TemplateResponse`): `csrf = auth.csrf_token(request)` vor dem
          Rendern, danach `auth.ensure_csrf(request, antwort)` — beide liefern in derselben
          Anfrage dasselbe Token. **Nicht in einer Antwort, die an- oder abmeldet:** Die Seite
          ist gerendert, bevor `set_cookie()`/`logout()` das Token wechselt, ihr Formular trüge
          das alte (403 beim Absenden). Dort umleiten; die Folgeanfrage rendert mit dem neuen
          Cookie. Mit dem Antwortparameter geht es: erst `set_cookie()`, dann `ensure_csrf()`.

        Eigenes JS kennt den Cookie-Namen nicht von selbst — `auth.csrf_cookie_name` ist Python.
        Die Seite reicht ihn mit (Template-Variable oder `<meta>`), oder das JS nimmt den Wert
        aus dem Formularfeld `_csrf` und schickt ihn als `X-CSRF-Token`."""
        if not self.cfg.csrf_enabled:
            return ""
        in_antwort = self._csrf_in_antwort(response)
        if in_antwort is not None and _CSRF_FORM.fullmatch(in_antwort):
            return in_antwort                       # eben gedreht oder schon gesetzt
        if in_antwort is not None:
            # In dieser Antwort gelöscht (Abmelden) oder mit Unbrauchbarem gesetzt — das Token
            # aus dem Request gilt damit nicht mehr, also ein frisches.
            token = self._csrf_neu(request)
        else:
            token, neu = self._csrf_der_anfrage(request)
            if not neu:
                return token
        self._csrf_cookie_setzen(response, token)
        return token

    def _csrf_der_anfrage(self, request) -> tuple:
        """(token, neu): das gültige Token aus dem Cookie, sonst ein neues — je Anfrage genau
        eins, damit `csrf_token()` und `ensure_csrf()` sich einig sind. Gemeinsam für
        `render_page`, `csrf_token`, `ensure_csrf` und das Admin-Panel: Wo einer ein Cookie
        übernähme, das ein anderer ersetzt, bekämen zwei Seiten zwei Token."""
        cur = request.cookies.get(self.csrf_cookie_name) if request is not None else None
        if cur and _CSRF_FORM.fullmatch(cur):
            return cur, False
        scope = getattr(request, "scope", None)
        gemerkt = scope.get(_CSRF_SCOPE) if isinstance(scope, dict) else None
        if gemerkt:
            return gemerkt, True
        return self._csrf_neu(request), True

    @staticmethod
    def _csrf_neu(request) -> str:
        token = secrets.token_urlsafe(24)
        scope = getattr(request, "scope", None)
        if isinstance(scope, dict):
            scope[_CSRF_SCOPE] = token
        return token

    def _csrf_cookie_setzen(self, response, token: str) -> None:
        """DIE Stelle, die das CSRF-Cookie schreibt — ersetzt eine Zeile, die diese Antwort
        schon dafür trägt, statt eine zweite anzuhängen. NICHT httponly: Die eingebauten
        JS-Aufrufe lesen das Cookie und senden `X-CSRF-Token`."""
        self._set_cookie_entfernen(response, self.csrf_cookie_name)
        response.set_cookie(self.csrf_cookie_name, token, secure=self.cfg.cookie_secure,
                            samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)

    def _csrf_cookie_loeschen(self, response) -> None:
        """Das CSRF-Cookie beim Browser löschen — mit Secure und Pfad wie beim Setzen, sonst
        verwirft der Browser das Löschen eines `__Host-`-Cookies still."""
        self._set_cookie_entfernen(response, self.csrf_cookie_name)
        response.delete_cookie(self.csrf_cookie_name, path=self.cfg.cookie_path,
                               secure=self.cfg.cookie_secure,
                               samesite=_samesite(self.cfg.cookie_samesite))

    def _csrf_in_antwort(self, response) -> Optional[str]:
        """Der Wert, den diese Antwort schon für das CSRF-Cookie setzt: None = keine Zeile,
        "" = gelöscht."""
        praefix = self.csrf_cookie_name.encode("latin-1") + b"="
        wert = None
        for schluessel, zeile in getattr(response, "raw_headers", None) or []:
            if schluessel.lower() == b"set-cookie" and zeile.startswith(praefix):
                wert = zeile[len(praefix):].split(b";", 1)[0].strip().decode("latin-1")
        if wert is None:
            return None
        return "" if wert in ("", '""') else wert

    @staticmethod
    def _set_cookie_entfernen(response, name: str) -> None:
        """Set-Cookie-Zeilen für genau diesen Namen aus der Antwort nehmen. Die Liste wird an
        Ort und Stelle geändert: `response.headers` hält einen Verweis auf dieselbe Liste."""
        roh = getattr(response, "raw_headers", None)
        if roh is None:
            return
        praefix = name.encode("latin-1") + b"="
        roh[:] = [(k, v) for k, v in roh if not (k.lower() == b"set-cookie" and v.startswith(praefix))]

    def _verify_csrf(self, request: Request, submitted) -> bool:
        """Passt das mitgeschickte CSRF-Token zum Cookie? Vergleich in konstanter Zeit."""
        if not self.cfg.csrf_enabled:
            return True
        import hmac
        cookie = request.cookies.get(self.csrf_cookie_name)
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
        if self.store.get_session(request.cookies.get(self.session_cookie_name) or ""):
            return False        # Cookie im Spiel → CSRF gilt, egal was im Header steht
        # Die IP vor der Key-Prüfung festhalten: Diese Prüfung läuft VOR `current_user`, und
        # `verify_api_key` protokolliert Nutzung und Abweisung (B5-05). Ohne den Aufruf stand ein
        # widerrufener Key an einer POST-Route ohne Adresse im Log, und ein gültiger doppelt —
        # einmal ohne, einmal mit IP, weil die IP Teil des Drosselschlüssels ist.
        self._anfrage_merken(request)
        return self.verify_api_key(key)[0] is not None

    def require_csrf(self, request: Request, submitted):
        """Für Formular-POSTs: wirft 403, wenn der CSRF-Token fehlt/nicht passt.

        Ausgenommen sind nur Requests, die wirklich per API-Key angemeldet sind — s.
        `_csrf_entbehrlich`."""
        if self.cfg.csrf_enabled and not self._csrf_entbehrlich(request) \
                and not (self._herkunft_ok(request) and self._verify_csrf(request, submitted)):
            raise HTTPException(403, self.t("api.csrf"))

    def _eigene_hosts(self, request: Request) -> set:
        """Die Hostnamen, unter denen diese Instanz im Browser steht.

        Host-Header und X-Forwarded-Host kann ein fremdes Skript im Browser des Opfers nicht
        setzen — sie sagen also, wohin der Browser WOLLTE. Dazu `base_url`, damit ein Proxy,
        der den Host umschreibt, nicht aussperrt.

        `trusted_redirect_hosts` gehören NICHT dazu. Sie sind erlaubte Ziele für `?next=`, und
        im Forward-Auth-Aufbau sind das die geschützten Apps — fremder Code aus Sicht von
        TinySesam. Als eigener Origin gezählt, bestand ein Formular-POST einer kompromittierten
        App die Herkunftsprüfung (Login-CSRF, Sitzungsaktionen im Namen des Opfers)."""
        from urllib.parse import urlsplit

        def name(netloc):
            try:
                return (urlsplit("//" + netloc.strip()).hostname or "") if netloc else ""
            except ValueError:
                return ""
        h = request.headers
        hosts = {name(h.get("host", "")), name((h.get("x-forwarded-host") or "").split(",")[0]),
                 name(request.url.netloc)}
        if self.cfg.base_url:
            hosts.add(urlsplit(self.cfg.base_url).hostname or "")
        hosts.discard("")
        return hosts

    def _herkunft_ok(self, request: Request) -> bool:
        """Vorprüfung vor dem Double-Submit-Vergleich (H-2, F-02).

        Das Token allein beweist nur, dass Cookie und Formularfeld zusammenpassen. Wer über eine
        Nachbar-Subdomain ein Cookie setzen kann (cookie tossing), setzt das passende Paar gleich
        mit und schickt das Opfer per Formular in SEIN Konto (Login-CSRF). Der Browser verrät
        aber, woher der Request kommt: `Origin` bei jedem POST, `Sec-Fetch-Site` bei jedem
        Request an eine sichere Adresse (HTTPS oder `localhost`; über HTTP schickt kein Browser
        `Sec-Fetch-*`, so will es die Fetch-Metadata-Spezifikation). Die kann eine fremde Seite
        nicht fälschen.

        * `Sec-Fetch-Site: same-origin` → ja. Das sagt der Browser selbst, gemessen an der
          Adresse, die ER sieht — damit bleibt eine App hinter einem Proxy bedienbar, der den
          Host umschreibt, ohne X-Forwarded-Host zu setzen (nginx-Vorgabe), auch ohne
          `base_url` (A-3). Eine Nachbar-Subdomain bekommt hier `same-site`, nie `same-origin`.
        * `Origin` gesetzt → er muss ein eigener Host sein, sonst nein. `same-site` von einer
          Nachbar-Subdomain mit ihrem eigenen Origin fällt hier heraus.
        * kein brauchbarer `Origin` (fehlt oder `null`), aber `Sec-Fetch-Site: same-site` oder
          `cross-site` → nein. `null` bekommt eine Nachbar-Subdomain schon, wenn sie ihre Seite
          mit `Referrer-Policy: no-referrer` ausliefert; `same-site` sagt der Browser trotzdem.
          Bis zur Nacharbeit fiel hier nur `cross-site` heraus, und wo das CSRF-Cookie kein
          `__Host-` tragen kann, entschied für die Nachbar-Subdomain wieder allein das Token.
          Das schließt diese Regel nur über HTTPS (siehe den letzten Punkt).
        * `Origin` fehlt oder ist `null`, und `Sec-Fetch-Site` sagt `none` (vom Nutzer selbst
          angestoßen, keine Seite kann das auslösen) → das Token entscheidet allein.
        * `Origin` fehlt oder ist `null`, und `Sec-Fetch-Site` fehlt → das Token entscheidet
          ebenfalls allein. Das ist nicht nur der alte Browser, das Skript oder der TestClient,
          sondern **jeder Browser über HTTP** (`cookie_secure=False`, außer `localhost`). Dort
          kommt eine Nachbar-Subdomain mit `Origin: null` (Seite mit
          `Referrer-Policy: no-referrer`) bis zum Token durch, und ohne `Secure` trägt das
          CSRF-Cookie kein `__Host-`, lässt sich also unterschieben. Über HTTP schützt diese
          Prüfung deshalb nicht vor Login-CSRF aus der Nachbarschaft. Abweisen brächte dort wenig:
          In derselben Konfiguration lässt sich schon das Sitzungs-Cookie selbst unterschieben
          (bekannte Grenze, SECURITY.md).
        """
        if not self.cfg.csrf_origin_check:
            return True
        from urllib.parse import urlsplit
        if (request.headers.get("sec-fetch-site") or "").strip().lower() == "same-origin":
            return True
        origin = (request.headers.get("origin") or "").strip()
        if origin and origin != "null":
            try:
                host = (urlsplit(origin).hostname or "").lower()
            except ValueError:
                host = ""
            if host and host in self._eigene_hosts(request):
                return True
            security.seclog.warning(
                "csrf origin rejected origin=%s ip=%s — fremde Herkunft. Steht die App hinter "
                "einem Proxy, der den Host umschreibt: base_url setzen.",
                security.fuer_log(origin[:200]), security.fuer_log(self.client_ip(request)))
            return False
        seite = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if seite in ("same-site", "cross-site"):
            security.seclog.warning("csrf origin rejected sec-fetch-site=%s origin=%s ip=%s",
                                    seite, "null" if origin else "-",
                                    security.fuer_log(self.client_ip(request)))
            return False
        return True

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

    def _mail_ziel_ok(self, adresse, zweck, topf="mail") -> bool:
        """Darf an diese Adresse noch eine Mail? Gedrosselt je **Ziel**, nicht je Absender (R4-04).

        Die IP-Drossel der Routen schützt den Server, nicht das Postfach: Wer über wechselnde
        Adressen „Passwort vergessen" für ein fremdes Konto anstösst, füllte dessen Postfach
        unbegrenzt. Die Abweisung ist nach aussen unsichtbar (dieselbe Antwort wie sonst) und
        steht im Audit-Log, damit der Betreiber die Flut sieht.

        `topf` trennt Kontingente: Anmelde-Link und Reset teilen sich einen (beide bringen den
        Inhaber ins Konto — wer sie für ihn anstösst, schickt ihm brauchbare Links). Der Hinweis
        der Registrierung hat einen eigenen (Angriff A2): Ihn löst jeder Fremde aus, er trägt
        keinen Token, und im gemeinsamen Topf verbrauchten drei fremde Registrierungen das
        Kontingent, mit dem der Inhaber sich selbst einen Link schickt — bei Betrieb nur mit
        Anmelde-Link eine wiederholbare Aussperrung.
        """
        schluessel = f"{topf}:" + (norm_email(adresse) or "")
        if self.rl.allow(schluessel, self._sec("mail_per_address_max"),
                         self._sec("mail_per_address_window_sec")):
            return True
        self.audit("mail_ratelimit", detail=f"{zweck} an={adresse}")
        return False

    @staticmethod
    def _token_hash(raw) -> str:
        return hashlib.sha256(str(raw).encode()).hexdigest()

    def _token_mail(self, raw, to, subject, text, html=None) -> bool:
        """Eine Mail mit Einmal-Token verschicken. Scheitert der Versand, ist der Token sofort
        verbraucht (B6-12): Sonst lag ein gültiger, nie zugestellter Link bis zum Ablauf in der
        Datenbank — ein Beweisstück ohne Empfänger, und bei einem Relay, das die Mail doch noch
        nachreicht, ein Link, von dem der Absender glaubt, es gebe ihn nicht.

        Ist der Token vor dem Versand schon verworfen oder eingelöst, geht keine Mail hinaus:
        Liegt zwischen Anlage und Versand der Postausgang, kann der Betreiber das Konto in der
        Zwischenzeit gesperrt haben (H-18) — die Mail trüge dann nur noch einen toten Link.

        True, wenn die Mail hinausging; False, wenn der Token schon weg war (G12a zählt nur
        zugestellte Links); ein Fehler des Versands kommt als Ausnahme."""
        zeile = self.store.get_magic_token(self._token_hash(raw))
        if not zeile or zeile["used_at"]:
            return False
        try:
            self.send_mail(to, subject, text, html)
        except Exception:
            self.store.expire_magic_token(self._token_hash(raw))
            raise
        return True

    def after_response(self, resp, task, on_overflow=None):
        """`task()` erst NACH dem Versand der Antwort ausführen, im eigenen Mail-Arbeiter
        (`mailer.Postausgang`, R4-05/B6-6). Gibt `resp` zurück."""
        from starlette.background import BackgroundTask
        resp.background = BackgroundTask(self._postausgang.nachher(task, on_overflow))
        return resp

    #: Deckel für `token_invalid`-Zeilen im Audit-Log: höchstens so viele je Fenster (global).
    _TOKEN_AUDIT_MAX = 20
    _TOKEN_AUDIT_FENSTER_SEC = 60

    def _token_abgewiesen(self, zweck, request: Optional[Request] = None, grund="ungueltig"):
        """Ein ungültiger/abgelaufener/verbrauchter Einmal-Token wurde vorgelegt (B5-18).

        Bisher hinterliess das keine Spur: Wer Reset- oder Anmelde-Token durchprobierte, sah der
        Betreiber nirgends. Audit-Zeile für den Betreiber, Sicherheits-Log mit dem Wort der
        Nicht-Login-Prüfungen (`failed verification`) — ein veralteter Link im eigenen
        Postfach ist kein Anmeldeversuch und darf niemanden per fail2ban aussperren.
        """
        ip = self.client_ip(request) if request is not None else None
        # Das Sicherheits-Log bekommt jede Zeile: Es rotiert, und die Verify-Jail von fail2ban
        # bannt daraus genau den, der Links durchprobiert.
        self._abgewiesen(None, ip, f"token_{zweck}", login=False)
        # Das Audit-Log dagegen räumt `gc()` nie auf, und die Routen sind anonym und ungedrosselt
        # (Angriff A3): Jeder GET auf /auth/magic/<Unsinn> schrieb dauerhaft eine Datenbankzeile —
        # eine Festplatte liess sich so füllen. Gedeckelt wird deshalb global je Zeitfenster,
        # nicht je IP (die wechselt ein Angreifer), und wenn der Deckel greift, steht genau
        # EINE Zeile dazu im Audit — sonst sähe der Betreiber die Flut nicht.
        fenster = self._TOKEN_AUDIT_FENSTER_SEC
        if self.rl.allow("audit:token_invalid", self._TOKEN_AUDIT_MAX, fenster):
            self.audit("token_invalid", ip=ip, detail=f"zweck={zweck} grund={grund}")
        elif self.rl.allow("audit:token_invalid_gedrosselt", 1, fenster):
            self.audit("token_invalid_throttled", ip=ip,
                       detail=f"mehr als {self._TOKEN_AUDIT_MAX} in {fenster}s — weitere nur im Sicherheits-Log")

    # ---------- Magic-/Einmal-Token ----------
    def create_magic_token(self, purpose, user_id=None, email=None, ttl_min=None, payload=None) -> str:
        """Einmal-Token erzeugen (Klartext-Rückgabe). Nur der sha256-Hash liegt in der DB."""
        raw = secrets.token_urlsafe(32)
        h = hashlib.sha256(raw.encode()).hexdigest()
        ttl = int(ttl_min if ttl_min is not None else self.cfg.magiclink_ttl_min) * 60
        self.store.add_magic_token(h, purpose, _jetzt() + ttl, user_id, email, payload)
        return raw

    #: Wo ein Token eingelöst wird — je Zweck ein eigener Endpunkt. Bis 0.15 liefen alle vier
    #: über /auth/magic/{token}: wer den Magic-Link abschaltete, verlor damit auch E-Mail-
    #: Bestätigung und Einladung, die damit nichts zu tun haben.
    TOKEN_PATHS = {
        "login": "/auth/magic/{t}",
        "verify_email": "/auth/verify/{t}",
        "invite": "/auth/invite/{t}",
        "reset_password": "/auth/reset?token={t}",
        "email_change": "/auth/email/{t}",
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
        """Token einlösen (one-shot). Gibt {purpose,user_id,email,payload} oder None (ungültig/abgelaufen/benutzt).

        `payload` mit englischen Schlüsseln (Schema 12): Ein Adresswechsel-Link trägt `old`, die
        bisherige Adresse — bis 0.21.x `alt`, das wird beim Lesen abgebildet (`payload_lesen`)."""
        if not raw:
            return None
        h = hashlib.sha256(raw.encode()).hexdigest()
        row = self.store.get_magic_token(h)
        if not row or (purpose and row["purpose"] != purpose):
            return None
        if not self.store.use_magic_token(h):
            return None
        return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
                "payload": payload_lesen(row["purpose"], row["payload"])}

    def peek_magic(self, raw, purpose=None) -> Optional[dict]:
        """Token prüfen OHNE ihn zu verbrauchen (für den Invite-Flow: erst bei Registrierung einlösen).
        Rückgabe wie `redeem_magic`."""
        if not raw:
            return None
        row = self.store.get_magic_token(hashlib.sha256(raw.encode()).hexdigest())
        if not row or row["used_at"] or row["expires_at"] < _jetzt():
            return None
        if purpose and row["purpose"] != purpose:
            return None
        return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
                "payload": payload_lesen(row["purpose"], row["payload"])}

    def create_invite(self, email, base_url, roles=None, is_admin=False, ttl_min=None) -> dict:
        """Einladung erzeugen (+ optional versenden). Rückgabe {url, token}. Der Token trägt die
        vorgesehenen Rollen/Adminrechte; eingelöst wird er erst bei der Registrierung. `base_url`
        wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

        Geprüft wird vor der Token-Vergabe, damit ein abgewiesener Aufruf keinen
        Einladungs-Token hinterlässt. Scheitert der Versand, ist der Token entwertet (B6-12).
        """
        base_url = self._gepruefte_basis(base_url)
        raw = self.create_magic_token("invite", email=email, ttl_min=ttl_min,
                                      payload={"roles": list(roles or []), "is_admin": bool(is_admin)})
        url = self.magic_url(raw, base_url, "invite")
        if email and self.mail_configured():
            self._token_mail(raw, email, "Deine Einladung",
                             f"Du wurdest eingeladen, ein Konto anzulegen:\n\n{url}\n",
                             html=f'<p>Du wurdest eingeladen, ein Konto anzulegen:</p><p><a href="{url}">Konto erstellen</a></p>')
        self.audit("invite_create", detail=email)
        return {"url": url, "token": raw}

    def send_verify_email(self, user_id, email, base_url) -> bool:
        """Den Bestätigungslink für eine Adresse verschicken. False, wenn kein Mailer da ist.
        `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).
        Scheitert der Versand, ist der Token entwertet (B6-12) und der Fehler geht weiter.
        Der Link schaltet ein Konto frei, dessen Bestätigung aussteht (Registrierung), nie eines,
        das der Betreiber gesperrt hat (Admin-Panel, `set_disabled(user_id, True)`) — auch dann
        nicht, wenn der Link erst nach dieser Sperre entsteht, etwa weil der Aufruf über
        `after_response` wartet (H-18).
        Eingelöst setzt er den Beleg für die Adresse (`email_verified`), solange sie noch die des
        Kontos ist.
        """
        senden = self._verify_mail(user_id, email, base_url)
        if senden is None:
            return False
        senden()
        return True

    def _verify_mail(self, user_id, email, base_url):
        """Den Bestätigungstoken JETZT anlegen und den Versand als Funktion zurückgeben — oder
        None, wenn kein Mailer da ist. `base_url` wird geprüft wie bei `send_verify_email`.

        Getrennt, weil die Registrierung nur den Versand in den Postausgang schiebt (R4-05/B6-6),
        nicht die Token-Vergabe: Die Sperre durch den Betreiber verwirft offene Token (H-18).
        Entstand der Token erst im Mail-Arbeiter, fand eine Sperre im Wartefenster nichts, und
        der verspätete Link hob sie danach wieder auf (T-13-Angriff, mail × betrieb)."""
        base_url = self._gepruefte_basis(base_url)
        if not (email and self.mail_configured()):
            return None
        raw = self.create_magic_token("verify_email", user_id=user_id, email=email)
        url = self.magic_url(raw, base_url, "verify_email")

        def senden():
            self._token_mail(raw, email, "E-Mail bestätigen",
                             f"Bitte bestätige deine E-Mail-Adresse:\n\n{url}\n",
                             html=f'<p>Bitte bestätige deine E-Mail-Adresse:</p><p><a href="{url}">Bestätigen</a></p>')
        return senden

    # ---------- Selbstbedienung: Benutzername und Adresse (PO-Entscheid 2026-09-25) ----------
    #: Länger ist kein Name mehr, sondern eine Nutzlast (Header, Logzeilen, Panel).
    NAME_MAX = 150

    def change_username(self, user_id, new_username, ip: Optional[str] = None, *,
                        by_operator: bool = False) -> str:
        """Den eigenen Benutzernamen ändern. Gibt den neuen Namen zurück, `ValueError` mit dem
        Grund, wenn er nicht geht.

        **Ein selbst gewählter Name bindet nicht über LDAP/SAML** (G2-N): Das Konto trägt danach
        `users.name_selbst_gewaehlt`, und eine Anmeldung über eine föderierte Quelle bindet es nie
        über den Namen — sonst benennt sich ein lokales Konto nach jemandem aus dem Verzeichnis
        und erbt bei dessen nächster Anmeldung Kennung und Gruppen. Wer als **Betreiber**
        umbenennt (aus dem einbettenden Dienst, etwa um eine Kollision aufzulösen), übergibt
        `by_operator=True`: Dann steht der Name für den Betreiber, der Merker fällt, und die
        Audit-Zeile sagt `durch=betreiber`.

        Alles, was am Konto hängt — Sitzungen, Keys, Faktoren, Rollen, Bindungen an LDAP/SAML/OIDC —
        hängt an der ID, nicht am Namen, und bleibt. Nach aussen ändert sich `Remote-User`; stabil
        ist `Remote-Id`. Dieselben Regeln wie beim Anlegen (frei in BEIDEN Namensräumen, keine
        Steuerzeichen) und drei eigene:

        * **Kein Name mit `@`**, ausser der eigenen belegten Adresse: Sonst besetzte jemand die
          Adresse einer Person, die es hier noch nicht gibt, und die bekäme bei der Registrierung
          „vergeben" (dieselbe Regel wie die Registrierung mit Bestätigung, Angriff A1).
        * **Kein Name aus `admin_identifiers`**: Wer sich so nennt, würde beim nächsten Login
          Erst-Admin. Die Antwort ist dieselbe wie bei „vergeben" — die Allowlist bleibt verborgen.
        * **Nicht im Modus `login_identifier="email"`**: Dort ist der Name die Adresse und folgt ihr.
        * **Neben LDAP nur als Betreiber** (`by_operator=True`, seit 2026-09-27): Dort kommen die
          Namen aus dem Verzeichnis; ein Konto, das sich selbst umbenennt, könnte den Namen einer
          Person annehmen, die sich noch nie angemeldet hat, und sie aussperren."""
        konto = self.store.get_user(user_id)
        if not konto:
            raise ValueError(self.t("api.not_found"))
        if self.cfg.login_identifier == "email":
            raise ValueError(self.t("api.username_follows_email"))
        # Neben LDAP benennt sich niemand selbst um (PO-Entscheid 2026-09-27): Ein lokales Konto
        # könnte den Verzeichnisnamen einer Person annehmen, die sich noch nie angemeldet hat, und
        # sie damit aussperren — dieselbe Lücke wie die offene Registrierung. Der Betreiber darf.
        if self.cfg.ldap_enabled and not by_operator:
            raise ValueError(self.t("api.username_from_directory"))
        name = str(new_username or "").strip()
        if not name:
            raise ValueError(self.t("err.username_required"))
        if len(name) > self.NAME_MAX or name_ungueltig(name):
            raise ValueError(self.t("err.username_invalid"))
        eigene = norm_email(konto["email"]) if konto["email"] and konto["email_verified"] else None
        if "@" in norm_kennung(name) and norm_email(name) != eigene:
            raise ValueError(self.t("api.username_is_address"))
        if name == konto["username"]:
            return name
        erlaubt = {norm_kennung(i) for i in (self.cfg.admin_identifiers or []) if str(i).strip()}
        if self.identifier_taken(name, exclude_id=user_id) or norm_kennung(name) in erlaubt:
            raise ValueError(self.t("api.user_exists"))
        alt = konto["username"]
        try:
            # Merker und Name in einer Transaktion (G2-N) — dazwischen könnte eine Anmeldung über
            # LDAP/SAML das Konto sonst noch über den neuen Namen binden.
            self.store.set_username(user_id, name, selbst_gewaehlt=not by_operator)
        except sqlite3.IntegrityError:
            # Wettlauf: zwischen Prüfung und Schreiben vergeben — die Datenbank entscheidet.
            raise ValueError(self.t("api.user_exists")) from None
        self.audit("username_changed", name, ip,
                   f"alt={alt} durch=betreiber" if by_operator else f"alt={alt}")
        self._sicherheitsereignis("username_changed", user_id, old=alt, new=name)
        return name

    def request_email_change(self, user_id, new_email, base_url):
        """Den Wechsel auf eine neue Adresse beantragen: Bestätigungslink an die NEUE. Gibt die
        Versandfunktion zurück (für `after_response`) — auch dann, wenn die Adresse vergeben
        oder reserviert ist und kein Link hinausgeht; `senden()` sagt es mit True/False. None nur
        bei einer Drossel und für die eigene, schon belegte Adresse. `ValueError` bei einer
        ungültigen Adresse oder ohne Mailer. Fällt der Versand aus, bevor er beginnt (volle
        Warteschlange), lässt `senden.verwerfen()` den Token verfallen — als `on_overflow` für
        `after_response` (seit 2026-09-27).

        Die Antwort an den Anfragenden ist in jedem Fall dieselbe: Ist die Adresse schon Kennung
        eines anderen Kontos (oder steht sie in `admin_identifiers`), geht kein Link hinaus, und
        das steht nur im Audit-Log — sonst wäre die Konto-Seite ein Orakel für vergebene
        Adressen. Gültig ist die neue Adresse erst mit dem Klick (`confirm_email_change`), vorher
        ändert sich nichts.

        **Ein Zweig für jedes Ziel** (G12b, seit 2026-09-26). Bis dahin kehrte der Antrag auf
        eine vergebene Adresse früh zurück, und das war an drei Stellen zu sehen, obwohl die
        Antwort gleich lautete: Der Hinweis an die eigene Adresse kam nur bei einer freien, der
        Antrag verbrauchte das Kontingent des Kontos nur bei einer freien, und die Konto-Seite
        nannte `email_change_taken`. Dazu die Laufzeit: eine Zeile weniger in der Datenbank und
        kein Versand nach der Antwort. Jetzt: erst die Drosseln (für jedes Ziel), dann in jedem
        Fall ein Token und eine Audit-Zeile — bei „nein" ein Wegwerf-Token, von Anfang an
        abgelaufen (niemand kennt den Klartext, `offener_token` und das Einlösen sehen ihn nicht,
        `gc()` räumt ihn; das Muster von R4-03 bei der Registrierung) —, dann immer ein Sender,
        der den Hinweis an die eigene Adresse in jedem Fall schickt. Die Konto-Seite zeigt jeden
        Antrag als `email_change_requested` (`own_events`)."""
        return self._wechsel_beantragen(user_id, new_email, base_url)

    def _wechsel_beantragen(self, user_id, neu, base_url, quelle: str = ""):
        """`request_email_change`, mit der Quelle für den Weg über LDAP/SAML
        (`_adresse_aus_quelle_belegen`). Mit `quelle` beginnt das Detail der Audit-Zeile mit
        `konto=<id> quelle=<quelle>` — für jedes Ergebnis gleich, frei wie vergeben. Daran zählt die
        Datenbank auch die Abweisungen (`Store.quellmail_seit`, Angriffsrunde 2026-09-26)."""
        konto = self.store.get_user(user_id)
        if not konto:
            raise ValueError(self.t("api.not_found"))
        # Erst falten, dann prüfen (wie Registrierung und Admin-API): `x＠evil.test@example.com`
        # ist roh gültig und gefaltet eine Adresse mit zwei `@` — sie wäre Token-Ziel, Empfänger
        # und nach dem Klick die belegte Adresse des Kontos (Angriffsrunde, Fund 3).
        mail = norm_email(neu or "") or ""
        if not valid_email(mail):
            raise ValueError(self.t("api.email_invalid"))
        if not self.mail_configured():
            raise ValueError(self.t("api.no_mail"))
        base_url = self._gepruefte_basis(base_url)
        if mail == norm_email(konto["email"] or "") and konto["email_verified"]:
            return None
        # Je KONTO gedrosselt (Angriffsrunde, Fund 3 der Selbstbedienung): Der Topf je Zieladresse
        # schützt ein Postfach, nicht vor dem Streuen — ein Konto schickte sonst Mails an beliebig
        # viele fremde Adressen, bis nur noch die IP-Drossel bremst (Ruf der Absenderdomain, und
        # jede Mail ist ein Vorwand zum Klicken). Dasselbe Kontingent wie je Zieladresse.
        # VOR der Frage „vergeben?" (G12b): Sonst probte ein Konto vergebene Adressen ohne
        # Kontingent, und nach drei Proben verriet der Link an die eigene Kontrolladresse, ob sie
        # vergeben waren.
        if not self.rl.allow(f"wechsel-konto:{user_id}", self._sec("mail_per_address_max"),
                             self._sec("mail_per_address_window_sec")):
            self.audit("mail_ratelimit", konto["username"], detail=f"email_change konto={user_id}")
            return None
        # Eigener Topf (wie der Registrierungs-Hinweis, Angriff A2): Den Wechsel auf eine FREMDE
        # Adresse beantragt jeder mit einem Konto — im Topf `mail` verbrauchte er das Kontingent,
        # mit dem sich der Inhaber jener Adresse selbst einen Anmelde-Link schickt.
        if not self._mail_ziel_ok(mail, "email_change", topf="wechsel"):
            return None
        # Eine Adresse aus `admin_identifiers` bekommt keinen Wechsel-Link (wie der Name): Auf einer
        # Instanz ohne Admin klickte der Inhaber „bestätige deine neue Adresse" leicht für seine
        # eigene Einrichtung — und das FREMDE Konto trüge danach die belegte Allowlist-Adresse und
        # wäre bei der nächsten Anmeldung Erst-Admin. Dieselbe Antwort wie „vergeben".
        nein = ("email_change_taken" if self.identifier_taken(mail, exclude_id=user_id)
                else "email_change_reserved" if self._allowlist_adresse(mail) else None)
        # Dieselbe Arbeit der Datenbank in beiden Fällen (G12b): bei „nein" ein Token, der schon
        # abgelaufen ist, wenn er entsteht.
        raw = self.create_magic_token("email_change", user_id=user_id, email=mail,
                                      ttl_min=(-1 if nein else int(self.cfg.email_change_ttl_min)),
                                      payload={"old": konto["email"] or ""})
        url = self.magic_url(raw, base_url, "email_change")
        herkunft = f"konto={int(user_id)} quelle={quelle} " if quelle else ""
        self.audit(nein or "email_change_requested", konto["username"], detail=f"{herkunft}neu={mail}")
        # Die Mail nennt das Konto: Wer eine Adresse bestätigt, soll sehen, für WELCHES — sonst
        # bestätigt ein gutgläubiger Klick die eigene Adresse für ein fremdes Konto (Verdacht aus
        # der Angriffsrunde; betrifft vor allem den Weg über LDAP/SAML, wo der Antrag nicht vom
        # Inhaber der Adresse kommt).
        name = str(konto["username"])
        alt = norm_email(konto["email"] or "") if konto["email_verified"] else None

        def senden() -> bool:
            try:
                return (not nein) and self._token_mail(
                    raw, mail, "Neue E-Mail-Adresse bestätigen",
                    f"Bitte bestätige, dass dies die E-Mail-Adresse deines Kontos „{name}“ "
                    f"werden soll:\n\n{url}\n\n"
                    "Ist das nicht dein Konto oder warst du das nicht, ignoriere diese E-Mail — "
                    "es ändert sich nichts.",
                    html=f'<p>Bitte bestätige, dass dies die E-Mail-Adresse deines Kontos '
                         f'„{_html.escape(name)}“ werden soll:</p>'
                         f'<p><a href="{url}">Adresse bestätigen</a></p>'
                         f'<p>Ist das nicht dein Konto oder warst du das nicht, ignoriere diese '
                         f'E-Mail — es ändert sich nichts.</p>')
            finally:
                # In JEDEM Fall (G12b) — auch wenn kein Link hinausging, und auch wenn der Versand
                # des Links scheiterte: Der Text („gilt erst, wenn der Link geklickt ist") stimmt
                # immer, und sein Ausbleiben verriete „vergeben".
                if alt and alt != mail:
                    self._wechsel_antrag_hinweis(alt, name, mail)

        def verwerfen() -> None:
            """Der Versand fällt aus, bevor er beginnt (Warteschlange voll): Der Token verfällt
            sofort, wie nach einem gescheiterten Versand (B6-12) — ein nie zugestellter Link hielte
            sonst als offener den nächsten bis zu seinem Ablauf auf (`offener_token`)."""
            self.store.expire_magic_token(self._token_hash(raw))
        senden.verwerfen = verwerfen   # type: ignore[attr-defined]
        return senden

    def _wechsel_antrag_hinweis(self, alt, name, neu) -> None:
        """Schon der ANTRAG eines Adresswechsels geht an die bisherige, belegte Adresse
        (Angriffsrunde, Fund 1): Stammt er aus einer übernommenen Sitzung, erfährt der Inhaber
        davon, bevor der Link eingelöst ist — und ein Passwortwechsel oder „Sitzungen beenden"
        verwirft ihn. **Ohne Link** (nichts, dessen Basis zu prüfen wäre; test_selbstbedienung)."""
        if self._mail_ziel_ok(alt, "email_change_notice", topf="hinweis"):
            self.send_mail(alt, "Änderung deiner E-Mail-Adresse beantragt",
                           f"Für dein Konto „{name}“ wurde beantragt, die E-Mail-Adresse auf {neu} "
                           "zu ändern. Sie gilt erst, wenn der Link an die neue Adresse geklickt ist.\n\n"
                           "Warst du das nicht, ändere sofort dein Passwort oder beende alle Sitzungen — "
                           "das verwirft den Antrag.")

    def _allowlist_adresse(self, mail) -> bool:
        """Steht diese Adresse in `admin_identifiers`?"""
        return norm_email(mail or "") in {norm_email(i) for i in (self.cfg.admin_identifiers or [])
                                          if "@" in str(i)}

    def confirm_email_change(self, raw, ip: Optional[str] = None) -> Optional[str]:
        """Den Bestätigungslink einlösen. Rückgabe: "ok", "taken" (inzwischen Kennung eines
        anderen Kontos; bis 0.21.x "vergeben") oder None (ungültig, abgelaufen, benutzt, Konto
        gesperrt/weg).

        Danach ist die neue Adresse die des Kontos, **mit Beleg** (der Klick hat das Postfach
        bewiesen). Im Modus `login_identifier="email"` zieht der Benutzername mit, wenn er die
        alte Adresse war. Offene Links an die alte Adresse (Reset, Anmelde-Link) gelten nicht
        mehr — sie gehörten einem Postfach, das nicht mehr zum Konto gehört. Die alte Adresse
        bekommt einen Hinweis (ASVS 6.3.7)."""
        data = self.redeem_magic(raw, purpose="email_change")
        if not data or not data.get("user_id"):
            return None
        uid = data["user_id"]
        konto = self.store.get_user(uid)
        if not konto or konto["disabled"]:
            return None
        mail = norm_email(data.get("email") or "")
        if not mail:
            return None
        if self.identifier_taken(mail, exclude_id=uid):
            self.audit("email_change_taken", konto["username"], ip, f"neu={mail} beim_bestaetigen=1")
            return "taken"
        if self._allowlist_adresse(mail):     # erst nach dem Antrag in die Liste gekommen
            self.audit("email_change_reserved", konto["username"], ip, f"neu={mail} beim_bestaetigen=1")
            return "taken"
        alt = konto["email"] or ""
        # Adresse und (im E-Mail-Modus) der Name in EINER Transaktion: Getrennt geschrieben
        # stand nach einem Fehlschlag des zweiten die neue Adresse neben dem alten Namen.
        name_folgt = (self.cfg.login_identifier == "email" and bool(alt)
                      and norm_email(konto["username"]) == norm_email(alt))
        try:
            self.store.adresse_wechseln(uid, mail, name_folgt=name_folgt)
        except sqlite3.IntegrityError:
            # Wettlauf (G12c): Die Adresse ist zwischen Prüfung und Schreiben Kennung eines
            # anderen Kontos geworden. Dieselbe Antwort wie oben; nichts ist geändert.
            self.audit("email_change_taken", konto["username"], ip,
                       f"neu={mail} beim_bestaetigen=1 wettlauf=1")
            return "taken"
        self.store.revoke_user_magic_tokens(uid)
        name = self._kontoname(uid)
        self.audit("email_changed", name, ip, f"alt={alt} neu={mail}")
        self._sicherheitsereignis("email_changed", uid, old=alt, new=mail)
        if alt and self.mail_configured():
            def hinweis():
                self.send_mail(alt, "Deine E-Mail-Adresse wurde geändert",
                               f"Die E-Mail-Adresse deines Kontos ist jetzt {mail}.\n\n"
                               "Warst du das nicht, melde dich sofort beim Betreiber — und ändere dein Passwort.")
            self._hinweis_ausgang.einreihen(hinweis)
        return "ok"

    def _send_signup_notice(self, email, base_url) -> bool:
        """Hinweis an den Inhaber einer Adresse, mit der sich jemand erneut registrieren wollte (R4-03).

        Die Registrierung antwortet bei eingeschalteter Bestätigung für eine vergebene Adresse
        genauso wie für eine freie („Bestätigungsmail ist unterwegs") — sonst verriet sie per
        409 und Text, welche Adressen ein Konto haben. Der echte Inhaber bekommt stattdessen
        diese Mail: kein Token, nur der Weg zur Anmeldung. Gedrosselt wie jede Mail (R4-04), aber
        im eigenen Topf — sonst sperrte sie den Inhaber von seinen eigenen Links aus (A2).
        """
        base_url = self._gepruefte_basis(base_url)
        u = self.store.get_user_by_email(email)
        if not u or u["is_service"] or not self.mail_configured():
            return False
        ziel = u["email"]
        if not self._mail_ziel_ok(ziel, "signup_notice", topf="hinweis"):
            return False
        login = f"{base_url}{self.cfg.login_path}"
        self.send_mail(ziel, "Registrierung mit deiner Adresse",
                       f"Jemand wollte mit dieser Adresse ein neues Konto anlegen. Es gibt aber schon eines.\n\n"
                       f"Warst du das, melde dich hier an:\n{login}\n\n"
                       f"Wenn nicht, kannst du diese E-Mail ignorieren.",
                       html=f'<p>Jemand wollte mit dieser Adresse ein neues Konto anlegen. Es gibt aber schon eines.</p>'
                            f'<p><a href="{login}">Zur Anmeldung</a></p>'
                            f'<p>Wenn du das nicht warst, kannst du diese E-Mail ignorieren.</p>')
        return True

    def send_login_link(self, email, base_url, next="/") -> bool:
        """Login-Link an eine E-Mail schicken, WENN ein passender interaktiver User existiert.
        Rückgabe nur intern — nach außen immer dieselbe Meldung (keine User-Enumeration).
        `base_url` wird geprüft (`ConfigError` bei einem fremden Host, siehe `magic_url`).

        Geprüft wird als Erstes — vor der Kontosuche, damit die Ausnahme keine Adresse verrät.
        Versandt wird an die gespeicherte Adresse (R4-11), gedrosselt je Ziel (R4-04); ein
        gescheiterter Versand entwertet den Token (B6-12).
        """
        base_url = self._gepruefte_basis(base_url)
        u = self.store.get_user_by_email(email)
        if not u or u["disabled"] or u["is_service"]:
            return False
        ziel = u["email"]
        if not self._mail_ziel_ok(ziel, "login"):
            return False
        raw = self.create_magic_token("login", user_id=u["id"], email=ziel, payload={"next": next})
        url = self.magic_url(raw, base_url)
        mins = self.cfg.magiclink_ttl_min
        self._token_mail(raw, ziel, "Dein Anmelde-Link",
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
        token = self._sitzung_anlegen(user_id, self._ttl(remember), mfa_ok, method, ip, ua, remember,
                                      factors=done)
        if mfa_ok:   # voller Login abgeschlossen → Audit
            u = self.store.get_user(user_id)
            self.store.audit_log("login", u["username"] if u else None, ip, method)
            self._vermerke_erstlogin(user_id)
            self.lift_lockout(user_id)
        return token, mfa_ok

    def _sitzung_anlegen(self, user_id, ttl, mfa_ok, method, ip=None, ua=None, remember=True,
                         factors=None) -> str:
        """DIE Stelle, an der eine Sitzungszeile entsteht — und die volle wird vorgemerkt.

        Eine Sitzung, die hier schon vollwertig entsteht, ist eine Anmeldung: Erstfaktor ohne
        Kette, der letzte Schritt einer Kette (`apply_factor`, `complete_totp`), ein
        Identitätswechsel. Das Setzen ihres Cookies (`set_cookie()`) dreht dann das CSRF-Token
        in derselben Antwort (0.20.1) — egal, über welche Route die Anmeldung kam, auch über eine
        eigene der App (`start_session` + `set_cookie`). Ein Step-up legt keine Zeile an
        (`store.rotate_session`) und dreht deshalb nichts. Ein Wächter in `tests/test_csrf.py`
        (E3) hält fest, dass `store.create_session` nur hier gerufen wird."""
        token = self.store.create_session(user_id, ttl, mfa_ok, method, ip, ua, remember,
                                          factors=factors)
        if mfa_ok:
            self._anmeldung_vormerken(token)
        return token

    def _anmeldung_vormerken(self, token: str) -> None:
        h = self.store.session_hash(token)
        with self._frisch_lock:
            self._frische_anmeldungen[h] = None
            while len(self._frische_anmeldungen) > _FRISCH_MAX:
                self._frische_anmeldungen.popitem(last=False)

    def _anmeldung_einloesen(self, token) -> bool:
        """War dieses Token eben eine Anmeldung? Einmal ja, danach nein."""
        if not token:
            return False
        h = self.store.session_hash(token)
        with self._frisch_lock:
            if h in self._frische_anmeldungen:
                del self._frische_anmeldungen[h]
                return True
        return False

    def _vermerke_erstlogin(self, user_id: int) -> None:
        """Den ersten vollständigen Login festhalten (R3-1).

        Daran hängt das Selbst-Enrollment in der Vorgabe-Betriebsart: Ein Konto darf den von der
        Kette verlangten Faktor selbst einrichten, solange es noch nie benutzt wurde. Der Vermerk
        schliesst dieses Fenster — und zwar beim ERSTEN vollständigen Login, egal auf welchem
        Weg er zustande kam. Ein offenes Einrichtungsfenster wird dabei geschlossen: Es war für
        genau diesen einen Vorgang gedacht."""
        if not self.store.mark_first_login(user_id, _jetzt()):
            return
        u = self.store.get_user(user_id)
        try:
            offen = u["mfa_enroll_until"] if u else None
        except (IndexError, KeyError):
            offen = None
        if offen:
            self.store.set_mfa_enroll_until(user_id, None)

    def apply_factor(self, request, user_id, factor, ip=None, ua=None, remember=True,
                     email_verified: Optional[bool] = None) -> tuple[str, bool, bool]:
        """Einen bestätigten Faktor anwenden: an die laufende Sitzung desselben Users anhängen
        (Ketten-Schritt) ODER eine neue Sitzung starten (Erstfaktor/Identitätswechsel).
        Gibt (token, session_ok, is_new). Bei is_new muss der Aufrufer set_cookie(resp, token) rufen.

        `email_verified` reicht ein föderierter Weg durch (OIDC: Claim `email_verified`;
        SAML und LDAP kennen keinen Beleg und reichen `False` durch) — hier entscheidet sich
        der Erst-Admin, und eine unbelegte Adresse darf ihn nicht tragen. Der Faktor geht
        mit an `_maybe_promote_admin`: Für einen föderierten Faktor gilt dort fail-closed,
        ein vergessenes Argument befördert also nicht.

        Ein gesperrtes Konto bekommt hier nie eine Sitzung (403) — egal, welcher Weg den Faktor
        geprüft hat. Jeder Anmeldeweg endet in dieser Methode; die Prüfung in den einzelnen
        Wegen bleibt, aber die Klasse hängt nicht mehr daran, dass jeder neue Weg sie kennt
        (H-18: Anmelde-Link und Passkey legten für ein gesperrtes Konto eine Sitzung an, die
        erst `current_user()` wieder verwarf)."""
        konto = self.store.get_user(user_id)
        if not konto or konto["disabled"]:
            self.audit("login_disabled", str(konto["username"]) if konto else None, ip, factor)
            raise HTTPException(403, self.t("api.account_disabled"))
        s = self._session_from_request(request)
        if s and s["user_id"] == user_id:
            # gleiche Identität → Faktor an laufende Sitzung anhängen (Ketten-/Route-Schritt).
            # Ein Identitätswechsel (anderer User) fällt durch → neue Sitzung.
            done = json.loads(s["factors_done"] or "[]")
            was_ok = bool(s["mfa_ok"])
            if factor not in done:
                done.append(factor)
            ok = self._session_ok(user_id, done)
            self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
            self._maybe_promote_admin(self.store.get_user(user_id), email_verified,
                                      faktor=factor)
            if ok and not was_ok:
                u = self.store.get_user(user_id)
                self.store.audit_log("login", u["username"] if u else None, s["ip"], factor)
                self._vermerke_erstlogin(user_id)
                self.lift_lockout(user_id)
                # **Neues Token beim Rechtewechsel.** Die Sitzung wird hier vom halben Login
                # zur vollwertigen — OWASP Session Management Cheat Sheet: „The session ID must
                # be renewed or regenerated by the web application after any privilege level
                # change." Vorher behielt sie ihr Token: Wer dem Opfer vor dem Login ein Cookie
                # setzen konnte (Subdomain, Klartext-HTTP), hielt nach dessen zweitem Faktor
                # eine voll authentisierte Sitzung.
                neu_token = self._sitzung_anlegen(
                    user_id, self._ttl(bool(s["remember"])), True, s["method"],
                    s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
                self._nachfolger(s, neu_token)
                self.store.delete_session_by_handle(s["token_hash"])
                self._andere_nach_abschluss(s, neu_token)
                return neu_token, ok, True      # is_new → der Aufrufer setzt das Cookie neu
            if ok and was_ok:
                # Die Sitzung war schon vollwertig, der Faktor frischt sie nur auf — das ist ein
                # Step-up (mfa_at ist eben neu gesetzt worden). Auch der bekommt ein neues Token
                # (F-06, ASVS 5.0 7.2.4); Laufzeit und Anmeldezeitpunkt bleiben dabei.
                gedreht = self.store.rotate_session(s["token_hash"], self._gnade())
                if gedreht:
                    return gedreht, ok, True
            # Zurück geht das Klartext-Token aus dem Cookie — der Aufrufer baut daraus
            # Redirects und Cookies. In der Sitzungs-Zeile steht nur noch das Handle.
            return request.cookies.get(self.session_cookie_name), ok, False
        token, ok = self.start_session(user_id, factor, ip, ua, remember)
        self._maybe_promote_admin(self.store.get_user(user_id), email_verified, faktor=factor)
        return token, ok, True

    def _nachfolger(self, alte_zeile, neu_token) -> None:
        """Was an der halben Sitzung hängt, geht auf die volle über, die sie ersetzt — VOR dem
        Löschen der alten: die OIDC-Zeilen (4a, sonst nähme der Fremdschlüssel sie mit) und die
        ausdrückliche Wahl „Angemeldet bleiben" (F-05).

        `alte_zeile` ist eine ganze Zeile aus `get_session` (`SELECT *`); die Spalte gibt es seit
        der Migration auf Schema 11 immer. Fehlte sie doch, soll das laut scheitern — ein
        stilles Übergehen verlöre die Wahl und damit die lange Leerlauf-Frist, ohne dass es
        jemand merkt."""
        neu = self.store.session_hash(neu_token)
        self.store.oidc_sitzung_umhaengen(alte_zeile["token_hash"], neu)
        if alte_zeile["bleiben_gewaehlt"]:
            self.store.set_session_bleiben(neu)

    def _andere_nach_abschluss(self, alte_zeile, neu_token) -> None:
        """War an der halben Sitzung vermerkt, die übrigen zu beenden (Grenze d), dann jetzt — mit
        der vollen Sitzung, die eben entstanden ist, als einziger, die bleibt.

        Anlass: Die Pflicht-Einrichtung von TOTP mitten in einer Kette (`password → totp → pin`)
        endet mit einer HALBEN Sitzung, und eine halbe darf die übrigen nicht beenden. Das Angebot
        nach ASVS 7.4.3 entfiel dort bisher ganz. Jetzt fragt die Seite wie sonst auch, und die
        Zustimmung wird hier eingelöst, sobald die Anmeldung vollständig ist. Die Spalte gibt es
        seit Schema 11 immer (wie bei `_nachfolger`: fehlt sie, scheitert es laut)."""
        if not alte_zeile["andere_beenden"]:
            return
        self.store.delete_user_sessions_except(alte_zeile["user_id"], self.store.session_hash(neu_token))
        u = self.store.get_user(alte_zeile["user_id"])
        self.store.audit_log("sessions_revoke", u["username"] if u else None, alte_zeile["ip"],
                             "scope=others nach_einschreibung=1")

    def _login_redirect_after(self, request, token, user_id, nxt):
        """Zielredirect nach einem Faktor: nxt wenn Sitzung komplett, sonst Eingabeseite des nächsten Faktors."""
        return self._nach_dem_faktor(request, token, user_id, nxt)[0]

    def _nach_dem_faktor(self, request, token, user_id, nxt) -> tuple:
        """(weiter, naechster, fertig) nach einem erbrachten Faktor — die eine Quelle für die
        Umleitung jedes Anmeldewegs und für `LoginResult.next_url`/`next_factor`/`done`."""
        s = self.store.get_session(token)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if s and s["mfa_ok"]:
            # Wer sich ausdrücklich (wieder) anmeldet, will in die Anwendung, zu der es zurückgeht —
            # eine frühere Abmeldung „nur hier" (T-22) gilt dafür nicht mehr.
            if "://" in str(nxt or ""):
                from urllib.parse import urlsplit
                ziel = (urlsplit(str(nxt)).hostname or "").lower()
                if ziel:
                    self.store.gate_fortsetzen(s["token_hash"], ziel)
            return nxt, None, True
        step = self._next_login_step(user_id, done)
        return (self.browser_path(request, self._factor_entry(step, nxt)) if step else nxt), step, False

    def complete_totp(self, token) -> Optional[str]:
        """Den TOTP-Schritt abschließen: Faktor `totp` an die laufende Sitzung anhängen. Gibt ein
        neues Sitzungs-Token zurück, das ins Cookie gehört (`neu = auth.complete_totp(token)`,
        `if neu: auth.set_cookie(resp, neu)`) — das alte ist danach tot, auch beim Step-up.

        Ein neues Token gibt es, wenn die Sitzung dadurch vollwertig wird oder, schon vollwertig,
        frisch bestätigt ist (Step-up, F-06). Sonst `None` (nichts zu tun). Seit F-06 gilt das
        auch für den Step-up: Eine eigene Oberfläche, die den Rückgabewert dort ignoriert, hält
        danach eine tote Sitzung im Cookie. Beim Login (halb → voll) war das schon immer so.

        Heißt seit 0.18.0 so, weil der alte Name `complete_mfa` mehr versprach, als die Methode
        tut — MFA ist die ganze Kette, hier geht es um genau einen Faktor. `complete_mfa` bleibt
        als Alias bestehen und wird nicht entfernt; ein Umbenennen, das bestehende Aufrufe
        bricht, wäre den Gewinn nicht wert.
        """
        s = self.store.get_session(token)
        if not s:
            return None
        konto = self.store.get_user(s["user_id"])
        if not konto or konto["disabled"]:
            # Zwischen erstem Faktor und TOTP gesperrt: Die halbe Sitzung endet hier, statt
            # zur vollwertigen zu werden (H-18, dieselbe Regel wie in `apply_factor`).
            self.store.delete_session_by_handle(s["token_hash"])
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
            self.lift_lockout(s["user_id"])
            # Rechtewechsel → neues Token (OWASP Session Management). Gibt es zurück, damit der
            # Aufrufer das Cookie setzen kann — das alte Token gehört zu einer gelöschten Zeile.
            neu_token = self._sitzung_anlegen(
                s["user_id"], self._ttl(bool(s["remember"])), True, s["method"],
                s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
            self._nachfolger(s, neu_token)
            self.store.delete_session_by_handle(s["token_hash"])
            self._andere_nach_abschluss(s, neu_token)
            return neu_token
        if ok and war_ok:
            # Die Sitzung war schon vollwertig; `set_session_factors` hat eben `mfa_at` neu
            # gesetzt — das ist ein Step-up, und der dreht das Token wie `/auth/reauth` und
            # `apply_factor` (F-06, ASVS 5.0 7.2.4). Vorher blieb es: Ein mitgelesenes Cookie
            # bekam so frische Sudo-Rechte. Laufzeit und Anmeldezeitpunkt bleiben.
            return self.store.rotate_session(s["token_hash"], self._gnade())
        return None

    # ---------- Anmelden für eigene Seiten (Stufe A, 0.22.0) ----------
    # PO-Befund 2026-09-26: Die README zeigte `check_password` + `start_session` als Bausteine
    # einer eigenen Login-Seite. Die inneren Prüfer drosseln nicht — Sperre, Zähler, Serie und
    # die fail2ban-Zeilen standen nur in den Routen. Diese drei Methoden SIND jetzt die Routen:
    # `POST /auth/login`, `/auth/pin` und `/auth/totp` rufen sie und rendern nur noch das
    # Ergebnis. Eine Quelle, kein Drift — `tests/test_anmelden.py` hält per AST fest, dass keine
    # der drei Routen einen inneren Prüfer selbst ruft, und prüft eigene Seiten gegen die
    # eingebauten (dieselben Audit- und Log-Zeilen).

    @staticmethod
    def _csrf_mitgeschickt(request, csrf: Optional[str]) -> Optional[str]:
        """Das mitgeschickte CSRF-Token: das Argument, sonst der Header `X-CSRF-Token`."""
        return request.headers.get("x-csrf-token") if csrf is None else csrf

    def _bleiben_gewaehlt(self, remember: Optional[bool]) -> bool:
        """„Angemeldet bleiben“ gewählt? Ohne Haken im Formular (`remember_me_enabled=False`) gilt
        jede Sitzung als bleibend, wie bisher; sonst nur ein ausdrückliches True (F-05)."""
        return True if not self.cfg.remember_me_enabled else remember is True

    def _anmeldung_nein(self, grund: str, status: int, text: str, weiter: str,
                        naechster: Optional[str] = None) -> LoginResult:
        """Ein Misserfolg: keine Sitzung, kein Cookie — nur Grund, Status und Text."""
        return LoginResult(ok=False, reason=grund, status=status, message=self.t(text) if text else "",
                           next_url=weiter, next_factor=naechster)

    def _anmeldung_gesperrt(self, kennung: str, weiter: str, naechster: Optional[str] = None,
                            text: str = "err.locked", grund: str = "locked") -> LoginResult:
        """Die Vorbuchung wurde abgewiesen. Eine Serien-Sperre (B2-6) läuft nicht ab —
        „vorübergehend“ wäre gelogen, und der Nutzer braucht den Weg hinaus. Die Meldung verrät
        nichts über die Existenz des Kontos: gezählt wird je Kennung, ob es sie gibt oder nicht.
        Ein Aufschub (G9) bekommt dieselbe 429 und denselben Grund wie eine Sperre — sonst
        verriete die Antwort, dass gerade jemand anderes unter dieser Kennung oder Adresse anmeldet."""
        if self._serie_voll(kennung):
            return self._anmeldung_nein("locked_series", 429, "err.locked_serie", weiter, naechster)
        return self._anmeldung_nein(grund, 429, text, weiter, naechster)

    def _angemeldet(self, request, token, neu: bool, user_id: int, nxt: str) -> LoginResult:
        """Ein Erfolg: Ziel und offener Faktor aus derselben Quelle wie jede Umleitung."""
        weiter, naechster, fertig = self._nach_dem_faktor(request, token, user_id, nxt)
        return LoginResult._with_session(self, token if neu else None, ok=True, reason="ok",
                                         status=303, next_url=weiter, next_factor=naechster,
                                         done=fertig, user=self.get_user(user_id))

    def login_password(self, request: Request, username: str, password: str, *, next: str = "",
                       remember: Optional[bool] = None, csrf: Optional[str] = None) -> LoginResult:
        """Mit Kennung und Passwort anmelden — gedrosselt, gezählt und gesperrt wie `POST /auth/login`, die genau diese Methode ruft.

        Der Baustein für eine eigene Login-Route (SPA, JSON, andere Felder). Er prüft das
        CSRF-Token (`csrf`, sonst Header `X-CSRF-Token`), drosselt je IP, bucht den Versuch atomar
        vor (Fehlversuche je Kennung, IP und Paar, Serie), fragt mit `ldap_enabled` das
        Verzeichnis als Rückfall (eine Kennung, ein Konto; ein Ausfall ist kein Fehlversuch),
        schreibt Audit- und Sicherheits-Log (die Zeilen für fail2ban) und legt die Sitzung an —
        oder hängt den Faktor an die laufende. Zurück kommt ein `LoginResult`:

            result = auth.login_password(request, username, password, next=next, csrf=csrf)
            if not result:
                return mein_formular(fehler=result.message, status=result.status)
            return result.redirect()     # zum offenen Faktor (result.next_factor) oder nach next

        `remember=True` ist der angehakte Haken „Angemeldet bleiben“. Wirft nur, was die Route
        auch wirft: `HTTPException(403)` bei falschem CSRF-Token (und aus `apply_factor` für ein
        Konto, das eben gesperrt wurde) sowie Unerwartetes — der Versuch zählt dann als
        Fehlversuch. Synchron: aus einer `def`-Route rufen (FastAPI nimmt dafür den Threadpool),
        in einer `async def`-Route über `run_in_threadpool`."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        if not cfg.password_enabled:
            return self._anmeldung_nein("method_disabled", 404, "api.password_off", nxt)
        if not username or not password:
            return self._anmeldung_nein("missing", 400, "err.required", nxt)
        bleiben = self._bleiben_gewaehlt(remember)
        ip = self.client_ip(request)
        if not self._rate_ok(ip):
            return self._anmeldung_nein("ratelimit", 429, "err.rate", nxt)
        # Prüfen und Verbuchen in EINEM Schritt (R7-2): Mit `_is_locked()` vorab und
        # `_record_login()` danach lag die ganze Passwortprüfung dazwischen, und eine parallele
        # Salve las N-mal „noch nicht gesperrt". Der Versuch steht ab hier schon als
        # Fehlversuch in der Tabelle; `_record_login(..., versuch=…)` macht ihn zum Erfolg.
        # Mit LDAP schwebt er, bis das Verzeichnis geantwortet hat (G9): Bei einem Ausfall wird er
        # zurückgenommen (F-23), und bis dahin darf er niemanden sperren, sondern nur warten lassen.
        versuch = self._versuch_beginnen(username, ip, "password", schweben=cfg.ldap_enabled)
        if versuch is None:
            return self._anmeldung_gesperrt(username, nxt)
        # Unerwartetes (Programmfehler im Client, Datenbank weg, eine HTTPException aus der
        # Prüfung) macht den Versuch sofort zum Fehlversuch — im Zweifel strenger, wie bisher.
        # Ohne das schwebte er `Store.VORBUCHUNG_SCHWEBE_SEK` lang und liesse Anmeldungen
        # derselben Adresse warten (G9). Ab `_record_login` ist er abgeschlossen.
        try:
            u = self._check_password(username, password)
            aus_verzeichnis = False
            if not u and cfg.ldap_enabled:
                from .ldap_ import VerzeichnisNichtErreichbar
                try:
                    u = self._check_ldap(username, password)   # LDAP/lldap-Backend (Faktor 'password')
                except VerzeichnisNichtErreichbar as e:
                    # Ein Ausfall ist kein Fehlversuch (F-23): nichts gegen Konto oder IP verbuchen
                    # und kein `failed login` ins Sicherheits-Log — sonst sperrte ein paar Minuten
                    # Verzeichnis-Ausfall die Nutzer aus, und fail2ban bannte sie obendrein. Die
                    # Antwort ist für jedes Konto dieselbe 503, verrät also nichts über dessen
                    # Existenz (lokal falsches Passwort und unbekannter Name kommen beide hier an).
                    self.audit("ldap_unavailable", username, ip, security.fuer_log(str(e))[:300])
                    security.seclog.error("LDAP nicht erreichbar user=%s ip=%s grund=%s",
                                          security.fuer_log(username), security.fuer_log(ip),
                                          security.fuer_log(str(e)))
                    # …aber nur der Anteil des VERZEICHNISSES ist entschuldigt (A-1). Hat das Konto
                    # ein lokales Passwort und war es falsch, ist das ein Fehlversuch wie immer —
                    # sonst wäre jeder Ausfall eine Rate-Pause ohne Kontosperre gegen genau das
                    # Notfallkonto (lokaler Admin), das man in dem Moment braucht; verteilt über viele
                    # IPs griffe nur noch das IP-Ratelimit. Die Antwort bleibt 503. Ein lokales Konto
                    # MIT Passwort lässt sich so während eines Ausfalls an der späteren 429 erkennen —
                    # dieselbe Sperre, die es im Normalbetrieb auch trifft; das ist der kleinere Preis.
                    # Der Versuch steht seit `_versuch_beginnen` schon in der Tabelle (R7-2), als
                    # schwebende Vorbuchung (G9) — ohne lokales Passwort wird er also
                    # zurückgenommen, nicht nur nicht zusätzlich verbucht. Bis dahin lässt er
                    # Anmeldungen, die an ihm scheitern würden, warten, statt sie zu sperren; damit
                    # das nicht bei jedem Anlauf bis zum Timeout dauert, fragt `_check_ldap` nach
                    # einem Ausfall eine Pause lang gar nicht erst (`ldap_.AusfallMerker`) und
                    # wirft sofort.
                    lokal = self.find_user(username)
                    if lokal and self.store.get_password_hash(lokal["id"]):
                        self._record_login(username, ip, False, "password", versuch=versuch, quelle="lokal")
                    else:
                        self._versuch_zuruecknehmen(versuch)
                    return self._anmeldung_nein("directory_down", 503, "err.directory_down", nxt)
                aus_verzeichnis = u is not None
        except BaseException:
            self._versuch_gescheitert(versuch)
            raise
        # Welcher Weg entschieden hat, steht im Audit-Log (F-29): Vorher war eine
        # Verzeichnis-Anmeldung von einer lokalen nicht zu unterscheiden — beide schrieben
        # Faktor `password`, und bei einem Fehlversuch hiess es `grund=kein_konto`, obwohl das
        # Verzeichnis gefragt worden war und abgelehnt hatte.
        # Aus dem Verzeichnis: das Konto mitgeben, zu dem die Kennung aufgelöst wurde (G5-N1) —
        # ein Filter über `mail` trifft auch eine Kennung, die lokal einem ANDEREN Konto gehört.
        # Diesen Fall weist `_check_ldap` seit 2026-09-27 ab (eine Kennung, ein Konto); der
        # Wächter in `_raeumgrenze` bleibt die zweite Sicherung.
        self._record_login(username, ip, bool(u), "password", versuch=versuch,
                           quelle=("" if not cfg.ldap_enabled else "ldap" if aus_verzeichnis
                                   else "lokal" if u else "lokal+ldap"),
                           konto=u["id"] if aus_verzeichnis and u else None)
        if not u:
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt)
        # Kam das Konto aus dem Verzeichnis, ist die E-Mail ein LDAP-Attribut — in vielen
        # Verzeichnissen von dem gepflegt, dem es gehört, und von niemandem bestätigt. Traut der
        # Betreiber dem Verzeichnis (`ldap_email_trusted`) oder nennt er ein Beleg-Attribut
        # (`ldap_attr_email_verified`), entscheidet der Beleg am Konto (None) — den setzt
        # `_check_ldap` nur, wenn die Quelle vertraut ist; sonst reist hier ausdrücklich „kein
        # Beleg" mit: Eine Allowlist-ADRESSE darf über LDAP nicht zum Erst-Admin führen (F-14).
        # Am Faktornamen ist der Weg nicht zu erkennen — LDAP zählt bewusst als `password`.
        token, _ok, neu = self.apply_factor(request, u["id"], "password", ip,
                                            request.headers.get("user-agent"), bleiben,
                                            email_verified=(None if (cfg.ldap_email_trusted
                                                                       or security.beleg_attribut(cfg, "ldap"))
                                                              else False)
                                            if aus_verzeichnis else None)
        if cfg.remember_me_enabled and bleiben:
            self.store.set_session_bleiben(self.store.session_hash(token))     # F-05: ausdrücklich gewählt
        return self._angemeldet(request, token, neu, u["id"], nxt)

    def login_pin(self, request: Request, pin: str, username: str = "", *, next: str = "",
                  remember: Optional[bool] = None, csrf: Optional[str] = None) -> LoginResult:
        """Mit der persönlichen PIN anmelden oder den PIN-Schritt erbringen — gedrosselt und gesperrt wie `POST /auth/pin`, die genau diese Methode ruft.

        Drei Lagen, wie die Route: auf einer vollen Sitzung (PIN als Faktor einer Route) und im
        Kettenschritt nach dem ersten Faktor (`login_chain` mit `pin`) gilt die PIN dem Konto der
        Sitzung, `username` bleibt leer — Fehlgriffe buchen dort unter einer eigenen Serien-Art,
        die ein Selbstbedienungs-Reset nicht räumt (G7). Ohne Sitzung ist die PIN ein Erstfaktor
        mit `username`, nur mit `pin_login` (`TinySesamConfig.pin_as_first_factor()`), sonst
        `reason="method_disabled"` (404). Eine vierstellige PIN ist das dankbarste Ziel einer
        Salve: Login- und PIN-Topf werden in einem Schritt vorgebucht (R3-7). Ergebnis, CSRF,
        `remember` und Ausnahmen wie bei `login_password`; `result.next_factor == "pin"` nach einem
        Fehlschlag heisst: dieselbe PIN-Seite noch einmal, ohne Namensfeld."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        bleiben = self._bleiben_gewaehlt(remember)
        ip = self.client_ip(request)
        # Schon eingeloggt → die PIN gehört zur laufenden Sitzung, kein Benutzerfeld nötig.
        # „Eingeloggt" heisst hier: eine volle SITZUNG (0.20.1, `session_user`). Mit
        # `current_user()` galt eine reine API-Key-Anfrage als eingeloggt — der Riegel
        # `pin_login=False` unten griff nicht, geprüft wurde die PIN des Key-Kontos, und
        # `apply_factor` legte mangels Sitzung eine neue, volle an: Automaten-Key + PIN
        # ergaben eine interaktive Sitzung samt Admin-Flag, das der Key allein nie trägt.
        # Ein Key kommt hier nur als Gast an, und für den gilt `pin_as_first_factor()`.
        me = self.session_user(request)
        # Der Kettenschritt: erster Faktor erbracht, die Sitzung hängt noch (`pending_user`,
        # wie `/auth/totp`). Bis 2026-09-26 lief er über den Gästeweg — mit `pin_login=False`
        # war eine Kette `password → pin` darum eine Sackgasse (404), und seine Fehlgriffe
        # buchten wie die eines Erstfaktors, die ein Selbstbedienungs-Reset räumt (G7).
        # Nennt das Formular ein ANDERES Konto, bleibt es ein Identitätswechsel über den
        # Gästeweg; eigene PIN-Seiten, die den Namen mitschicken, bleiben im Kettenschritt.
        # Die halbe Sitzung zählt nur, wenn die PIN jetzt ihr Kettenschritt ist (p2 F1): Sonst
        # prüfte sie PINs im klassischen Modus (Orakel mit nur dem Passwort) oder vor dem TOTP
        # einer strikten Kette, deren Reihenfolge danach nie mehr erfüllbar war.
        halb = None if me else self._pin_kettenschritt(request)
        if halb and username:
            gemeint = self.find_user(username)
            if not gemeint or gemeint["id"] != halb["id"]:
                halb = None
        folge = me or halb      # die PIN steht HINTER einem schon erbrachten Faktor
        offen = "pin" if folge else None
        if not cfg.pin_enabled or (not folge and not cfg.pin_as_first_factor()):
            # PIN ist kein Erstfaktor — abgeschaltet oder, in einer strikten Kette hinter
            # einem anderen Faktor, nie mehr erfüllbar (G7: sonst ein Orakel ohne Passwort).
            return self._anmeldung_nein("method_disabled", 404, "api.not_found", nxt)
        if not pin or (not folge and not username):
            return self._anmeldung_nein("missing", 400, "err.required", nxt, offen)
        if not self._rate_ok(ip):
            return self._anmeldung_nein("ratelimit", 429, "err.rate", nxt, offen)
        ident = folge["username"] if folge else username
        if not ident:
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt, offen)
        # Login- und PIN-Topf in einem atomaren Schritt (R3-7): Eine vierstellige PIN
        # ist das dankbarste Ziel einer parallelen Salve. Hinter einem erbrachten Faktor
        # bucht die Serie unter eigener Art: Diese Fehlgriffe erzeugt nur, wer den ersten
        # Faktor hat, und ein Selbstbedienungs-Reset räumt sie nicht (wie TOTP, G7).
        versuch = self._versuch_beginnen(ident, ip, "pin",
                                         serie_art=self._SERIE_PIN_FOLGE if folge else None)
        if versuch is None:
            return self._anmeldung_gesperrt(ident, nxt, offen)
        try:
            if folge:
                u = self.get_user(folge["id"]) if self._verify_user_pin(folge["id"], pin) else None
            else:
                u = self._check_pin(ident, pin)
        except BaseException:
            self._versuch_gescheitert(versuch)       # Unerwartetes zählt sofort (wie beim Passwort)
            raise
        self._record_login(ident, ip, bool(u), "pin", versuch=versuch)
        if not u:
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt, offen)
        token, _ok, neu = self.apply_factor(request, u["id"], "pin", ip,
                                            request.headers.get("user-agent"), bleiben)
        if cfg.remember_me_enabled and bleiben:
            self.store.set_session_bleiben(self.store.session_hash(token))  # F-05: ausdrücklich gewählt
        return self._angemeldet(request, token, neu, u["id"], nxt)

    def login_totp(self, request: Request, code: str, *, next: str = "",
                   csrf: Optional[str] = None) -> LoginResult:
        """Den TOTP-Schritt erbringen — mit einem TOTP-Code oder einem Einmal-Code, gedrosselt und gesperrt wie `POST /auth/totp`, die genau diese Methode ruft.

        Für die halbe Sitzung nach dem ersten Faktor (`result.next_factor == "totp"`
        eines vorigen `LoginResult`) und als Step-up einer vollen. Beides kommt aus dem Cookie
        (`pending_user`/`session_user`, nie aus einem API-Key); ohne Sitzung ist das Ergebnis
        `reason="no_session"` mit der Login-Seite als `next_url`. Wird die Sitzung dadurch voll
        oder frisch bestätigt, bekommt sie ein neues Token — `redirect()`/`set_cookie()`
        setzen es; wer es ignoriert, hat eine tote Sitzung im Cookie. Ergebnis, CSRF und
        Ausnahmen wie bei `login_password`."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        s = self._session_from_request(request)
        # Geprüft wird der Code des Kontos, dessen Sitzung danach weiterkommt — beide aus dem
        # Cookie (0.20.1, `session_user`). `current_user()` fiel hier auf einen API-Key zurück,
        # wenn das Konto der Sitzung gesperrt war; dann hätte der Code des Key-Kontos gezählt.
        pu = self.pending_user(request) or self.session_user(request)
        offen = "totp" if s and pu else None
        if not code:
            return self._anmeldung_nein("missing", 400, "err.required", nxt, offen)
        if not s or not pu:
            return self._anmeldung_nein("no_session", 401, "api.not_signed_in",
                                        self.browser_path(request, cfg.login_path))
        ip = self.client_ip(request)
        # Atomar wie am Login (R3-2): Die Prüfung liegt sonst zwischen Sperre und Zählung.
        drossel_ok = self._rate_ok(ip)
        versuch = self._versuch_beginnen(pu["username"], ip, "totp") if drossel_ok else None
        if versuch is None:
            return self._anmeldung_gesperrt(pu["username"], nxt, offen, text="err.retry",
                                            grund="locked" if drossel_ok else "ratelimit")
        try:
            # TOTP-Code ODER Einmal-Recovery-Code akzeptieren
            richtig = self._verify_totp(pu["id"], code) or self._verify_recovery_code(pu["id"], code)
        except BaseException:
            self._versuch_gescheitert(versuch)       # Unerwartetes zählt sofort (wie beim Passwort)
            raise
        if not richtig:
            self._record_login(pu["username"], ip, False, "totp", versuch=versuch)
            return self._anmeldung_nein("invalid", 401, "err.code", nxt, offen)
        self._record_login(pu["username"], ip, True, "totp", versuch=versuch)
        sitzungs_token = request.cookies.get(self.session_cookie_name)   # Klartext nur hier, im Cookie
        # Wird die Sitzung durch diesen Faktor vollwertig, bekommt sie ein neues Token — der
        # Rechtewechsel. Ebenso beim Step-up auf einer schon vollen Sitzung (F-06). In beiden
        # Fällen muss das Cookie mit; wird die Sitzung hier voll (Login), dreht `set_cookie`
        # auch das CSRF-Token, beim Step-up nicht — es entwertete nur die Formulare der
        # anderen offenen Reiter.
        erneuert = self.complete_totp(sitzungs_token)
        return self._angemeldet(request, erneuert or sitzungs_token, bool(erneuert), pu["id"], nxt)

    # ---------- Step-up und Passwortwechsel für eigene Seiten (Stufe A, 0.22.0) ----------
    # PO-Entscheid 2026-09-27: dasselbe Muster wie `login_*` für die Bestätigung vor heiklen
    # Aktionen (bis dahin nur die eingebaute Seite `/auth/reauth`) und für den eigenen
    # Passwortwechsel (bis dahin nur `POST /auth/password`). Die inneren Prüfer
    # (`_verify_user_password`, `_verify_user_pin`, `_verify_totp`) drosseln nicht; diese Methoden
    # tun, was die Routen tun — weil die Routen sie rufen. `tests/test_bestaetigen.py` hält per AST
    # fest, dass keine der beiden Routen einen inneren Prüfer selbst ruft, und misst eigene Seiten
    # gegen die eingebauten (dieselben Status, Audit-, Log- und Zählerzeilen).

    #: Wer eine Bestätigung oder einen Passwortwechsel ohne Sitzung versucht, bekommt `no_session`.
    #: Zeigt die Anfrage statt einer Sitzung einen API-Key, heisst das 403 mit diesem Text — der
    #: Key wird dabei nicht geprüft, er zählt hier schlicht nicht (0.20.1).
    _OHNE_SITZUNG_KEY = {"reauth": "api.stepup_session", "password_change": "api.password_needs_session"}

    def _nur_mit_sitzung(self, request, zweck: str) -> tuple:
        """(Konto der vollen Sitzung, None) — oder (None, (Status, Textschlüssel)) für `no_session`.

        Das Konto kommt aus `session_user()`, nie aus einem API-Key (0.20.1): `/auth/reauth`
        prüfte bis dahin den Faktor des Kontos aus `current_user()` und frischte danach die
        Sitzung aus dem Cookie auf — bei einer HALBEN Sitzung fiel `current_user()` auf den Key
        zurück, und Automaten-Key plus Passwort ersetzten den zweiten Faktor. Beim Passwortwechsel
        (seit 0.22.0): Ein Automaten-Key ändert kein Passwort eines Menschen, und ohne eigene
        Sitzung beendete der Wechsel ALLE Sitzungen des Kontos."""
        u = self.session_user(request)
        if u is not None:
            return u, None
        if self.cfg.apikey_enabled and self._extract_api_key(request):
            return None, (403, self._OHNE_SITZUNG_KEY[zweck])
        return None, (401, "api.not_signed_in")

    def _bestaetigen(self, request: Request, verfahren: str, geheimnis, next: str,
                     csrf: Optional[str]) -> LoginResult:
        """Die eine Quelle von `confirm_password`, `confirm_pin` und `confirm_totp` — und damit von
        `POST /auth/reauth`, die je nach ausgefülltem Feld eine von ihnen ruft."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        u, ohne = self._nur_mit_sitzung(request, "reauth")
        if u is None:
            return self._anmeldung_nein("no_session", ohne[0], ohne[1],
                                        self.browser_path(request, cfg.login_path))
        methods = self.stepup_options(u)
        if not methods:
            # Dieses Konto hat kein Verfahren, mit dem es hier bestätigen könnte
            # (`stepup_strict`, oder noch gar kein Faktor eingerichtet). Der Versuch KANN nicht
            # gelingen — er wird deshalb nicht als Fehlversuch protokolliert, sonst füttert die
            # aussichtslose Seite die Sperre desselben Kontos.
            return self._anmeldung_nein("method_disabled", 403, "err.stepup_none", nxt)
        if not geheimnis:
            # Leer ist kein Rateversuch (0.22.0): Bis dahin zählte ein leer abgeschicktes Formular
            # an `/auth/reauth` als Fehlversuch — wie am Login gilt jetzt `missing`, ohne Buchung.
            return self._anmeldung_nein("missing", 400, "err.required", nxt)
        if verfahren not in methods:
            # Nur ein angebotenes Verfahren zählt (`stepup_options`: `stepup_methods`,
            # `stepup_strict`). Sonst umginge eine eigene Seite mit Passwortfeld die Vorgabe
            # `stepup_methods=["totp"]`. Geprüft wird hier nichts — also auch nichts gezählt.
            return self._anmeldung_nein("method_disabled", 403, "err.reauth", nxt)
        ip = self.client_ip(request)
        # Eigener Topf (`_is_reauth_locked`), nicht der des Logins: Eine Step-up-Bestätigung
        # ist keine Anmeldung — wer hier steht, ist bereits angemeldet. Mit dem geteilten
        # Zähler sperrten fünf Tippfehler auf dieser Seite die **Anmeldung** desselben
        # Kontos für `lockout_window_sec`, samt dem korrekten Passwort. Gedrosselt und
        # protokolliert bleibt der Weg, nur eben in seinem eigenen Topf. Bietet die Seite die PIN
        # an, gilt deren Topf mit (C-3): Eine am Login gesperrte PIN lässt sich hier nicht
        # weiterraten.
        drossel_ok = self._rate_ok(ip, login=False)
        versuch = (self._versuch_beginnen(u["username"], ip, "reauth", auch_pin="pin" in methods)
                   if drossel_ok else None)
        if versuch is None:
            return self._anmeldung_nein("locked" if drossel_ok else "ratelimit", 429, "err.retry", nxt)
        pruefer = {"totp": self._verify_totp, "pin": self._verify_user_pin,
                   "password": self._verify_user_password}[verfahren]
        richtig = pruefer(u["id"], geheimnis)
        self._record_login(u["username"], ip, richtig, "reauth", versuch=versuch)
        if not richtig:
            return self._anmeldung_nein("invalid", 401, "err.reauth", nxt)
        s = self._session_from_request(request)
        neu = None
        if s:
            self.store.set_session_mfa(s["token_hash"], True)   # setzt mfa_at=now → wieder frisch
            # Frisch bestätigt heisst neues Token (F-06): Ein mitgelesenes altes Cookie hielte
            # sonst genau die Sitzung, die eben Sudo-Rechte bekommen hat. Das alte gilt noch
            # `session_rotation_grace_sec` lang, ohne Frische (A-6). Das CSRF-Token bleibt.
            neu = self.store.rotate_session(s["token_hash"], self._gnade())
        self.audit("stepup", u["username"], ip)
        return LoginResult._with_session(self, neu, ok=True, reason="ok", status=303, next_url=nxt,
                                         done=True, user=self.get_user(u["id"]))

    def confirm_password(self, request: Request, password: str, *, next: str = "",
                         csrf: Optional[str] = None) -> LoginResult:
        """Die Sitzung mit dem Passwort des eigenen Kontos frisch bestätigen (Step-up) — gedrosselt und gesperrt wie `POST /auth/reauth`, die genau diese Methode ruft.

        Der Baustein für eine eigene Step-up-Seite (Dialog einer Single-Page-App, eigenes
        Formular vor einer heiklen Aktion). Er prüft das CSRF-Token (`csrf`, sonst Header
        `X-CSRF-Token`), verlangt eine volle Sitzung (ein API-Key zählt nicht: `no_session`, 403),
        lässt nur ein Verfahren zu, das `stepup_options()` diesem Konto anbietet, drosselt je IP,
        bucht den Versuch atomar im eigenen Topf vor (`reauth_max_attempts`, nicht der des
        Logins), schreibt Audit- und Sicherheits-Log und macht die Sitzung bei Erfolg frisch
        (`stepup_fresh`, `require(mfa=True)`) — mit neuem Token, das `redirect()`/`set_cookie()`
        setzen. Zurück kommt ein `LoginResult`:

            result = auth.confirm_password(request, password, next=next, csrf=csrf)
            if not result:
                return mein_dialog(fehler=result.message, status=result.status)
            return result.redirect()     # nach next, mit dem erneuerten Sitzungs-Cookie

        Ein leeres Passwort ist `missing` (400) und zählt nicht. Wirft nur, was die Route auch
        wirft: `HTTPException(403)` bei falschem CSRF-Token, dazu Unerwartetes. Synchron: aus
        einer `def`-Route rufen, in einer `async def`-Route über `run_in_threadpool`."""
        return self._bestaetigen(request, "password", password, next, csrf)

    def confirm_pin(self, request: Request, pin: str, *, next: str = "",
                    csrf: Optional[str] = None) -> LoginResult:
        """Die Sitzung mit der PIN des eigenen Kontos frisch bestätigen (Step-up) — wie `confirm_password`, gedrosselt und gesperrt wie `POST /auth/reauth`.

        Wie `confirm_password`, nur mit der PIN (`pin_enabled`, das Konto hat eine). Bietet die
        Seite die PIN an, gilt zusätzlich der PIN-Topf (C-3): Eine an der PIN-Anmeldung gesperrte
        PIN lässt sich hier nicht weiterraten. Die Fehlversuche selbst zählen im Topf `reauth`."""
        return self._bestaetigen(request, "pin", pin, next, csrf)

    def confirm_totp(self, request: Request, code: str, *, next: str = "",
                     csrf: Optional[str] = None) -> LoginResult:
        """Die Sitzung mit einem TOTP-Code des eigenen Kontos frisch bestätigen (Step-up) — wie `confirm_password`, gedrosselt und gesperrt wie `POST /auth/reauth`.

        Wie `confirm_password`, nur mit einem TOTP-Code (jeder gilt einmal); ein Einmal-Code
        (Recovery) zählt hier nicht — wie auf der eingebauten Seite. Nicht zu verwechseln mit
        `totp_confirm(user_id, code)`, das die Einrichtung von TOTP abschliesst."""
        return self._bestaetigen(request, "totp", code, next, csrf)

    def change_password(self, request: Request, current: str, new: str, *,
                        csrf: Optional[str] = None) -> PasswordChangeResult:
        """Das Passwort des eigenen Kontos ändern — das alte gedrosselt und gesperrt geprüft wie `POST /auth/password`, die genau diese Methode ruft.

        Der Baustein für eine eigene Passwortwechsel-Seite. Er prüft das CSRF-Token (`csrf`, sonst
        Header `X-CSRF-Token`), verlangt eine volle Sitzung (ein API-Key zählt nicht:
        `no_session`, 403), drosselt je IP, bucht den Versuch atomar im eigenen Topf vor
        (`password_change_max_attempts`, nur pro Konto; ein Tippfehler hier sperrt nicht die
        Anmeldung), prüft das alte Passwort gegen das Konto der Sitzung (nie gegen eine
        aufgelöste Kennung, R4-12), dann das neue gegen die Passwortregel. Bei Erfolg: neues
        Passwort, alle ANDEREN Sitzungen beendet (die eigene bleibt), offene Adresswechsel-Links
        verworfen, Audit `password_change`. Zurück kommt ein `PasswordChangeResult`:

            result = auth.change_password(request, current, new, csrf=csrf)
            if not result:
                return mein_formular(fehler=result.message, status=result.status)
            # result.api_keys_active: so viele API-Keys gelten weiter — sagen, nicht verschweigen

        Ein leeres altes Passwort ist `missing` (400) und zählt nicht. Wirft nur, was die Route
        auch wirft: `HTTPException(403)` bei falschem CSRF-Token, dazu Unerwartetes. Synchron:
        aus einer `def`-Route rufen, in einer `async def`-Route über `run_in_threadpool`."""
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))

        def nein(grund, status, text, **werte) -> PasswordChangeResult:
            return PasswordChangeResult(ok=False, reason=grund, status=status,
                                        message=self.t(text, **werte) if text else "")

        u, ohne = self._nur_mit_sitzung(request, "password_change")
        if u is None:
            return nein("no_session", *ohne)
        if not current:
            return nein("missing", 400, "err.required")
        ip = self.client_ip(request)
        # Das alte Passwort ist ein Geheimnis wie am Login — also derselbe Dreiklang aus
        # Drossel, Sperre und Protokoll. Ohne ihn war `/auth/password` ein stilles, unbegrenztes
        # Passwort-Orakel: beliebig viele Versuche, nie eine 429, keine Zeile im Sicherheits-
        # Log, kein Fehlversuch in `login_attempt` — während derselbe Fehlversuch am Login
        # nach wenigen Anläufen sperrt (R4-10; die Login-Schwelle ist `max_login_attempts`,
        # Vorgabe 5 und im Panel einstellbar).
        #
        # Die Sperre ist ein EIGENER Topf (`_is_password_change_locked`, eigene Schwelle
        # `password_change_max_attempts`), nicht der des Logins: Mit dem geteilten Zähler
        # sperrten fünf Tippfehler hier die Anmeldung für 15 Minuten — samt dieser Route, über
        # die der Nutzer die Sperre hätte abtragen können. Hinter NAT traf es über
        # `ip_attempt_factor` sogar unbeteiligte Kollegen. Gedrosselt bleibt es (`_rate_ok`),
        # protokolliert auch.
        drossel_ok = self._rate_ok(ip, login=False)
        versuch = self._versuch_beginnen(u["username"], ip, "password_change") if drossel_ok else None
        if versuch is None:
            return nein("locked" if drossel_ok else "ratelimit", 429, "api.too_many")
        # Geprüft wird gegen die **ID** der eigenen Sitzung, nicht gegen die Login-Kennung:
        # `_check_password(u["username"], …)` lief durch `find_user()` und konnte damit auf ein
        # FREMDES Konto auflösen (Benutzername des Angreifers = E-Mail des Opfers, R4-12).
        # Dann riet man hier nicht sein eigenes Passwort, sondern dessen — und der Treffer
        # setzte still das eigene Passwort, blieb also unsichtbar.
        richtig = self._verify_user_password(u["id"], current)
        # Eigene Methode: Ein Treffer hier räumt die Fehlversuche des Login-Pfads NICHT weg
        # (`_record_login` löscht nur die derselben Methode) — die Sperre bleibt, wo sie gilt.
        self._record_login(u["username"], ip, richtig, "password_change", versuch=versuch)
        if not richtig:
            return nein("invalid", 403, "api.password_wrong")
        mangel = self.password_policy_error(new or "", username=u["username"], email=u.get("email"), api=True)
        if mangel:
            return PasswordChangeResult(ok=False, reason="policy", status=400, message=mangel)
        self.set_password(u["id"], new)
        # andere Sitzungen des Users beenden (aktuelle behalten) — Standard nach Credential-Wechsel
        s = self._session_from_request(request)
        self.store.delete_user_sessions_except(u["id"], s["token_hash"] if s else None)
        # Ein offener Adresswechsel stammt womöglich aus einer der eben beendeten Sitzungen — er
        # fällt mit ihnen (Fund 1). Andere Links (Anmelde-Link, Reset) gehen an die eigene Adresse.
        self.store.revoke_user_magic_tokens(u["id"], purposes=("email_change",))
        # API-Keys überleben den eigenen Passwortwechsel mit Absicht: Sie sind für Automatiken
        # da, und ein Routine-Wechsel soll die nicht reihenweise stilllegen (ein Konto = oft ein
        # Key = mehrere Integrationen). Verschwiegen wird es trotzdem nicht — wer nach einem
        # Einbruch das Passwort ändert, muss wissen, dass da noch eine Tür offen ist.
        aktiv = self.store.count_active_api_keys(u["id"])
        self.audit("password_change", u["username"], ip, f"api_keys_active={aktiv}" if aktiv else None)
        return PasswordChangeResult(ok=True, reason="ok", status=200, api_keys_active=aktiv)

    def _session_from_request(self, request):
        """Die Sitzungszeile zu diesem Request, oder None. `row["token_hash"]` ist ihr Handle.

        Eine OIDC-Sitzung wird hier alle `oidc_session_refresh_minutes` beim Provider nachgeprüft
        (4a): Verweigert er, ist die Sitzung weg, und dieser Request gilt als nicht angemeldet."""
        s = self.store.get_session(request.cookies.get(self.session_cookie_name))
        if s is not None and not self._oidc_nachpruefen(s):
            return None
        return s

    def _oidc_sitzung_merken(self, token, client, sub, refresh_token) -> None:
        """Das Refresh-Token zur (eben entstandenen) Sitzung legen (4a) — mit der client_id, an
        die es ging."""
        if not int(self.cfg.oidc_session_refresh_minutes or 0) or not token:
            return
        self.store.set_oidc_sitzung(self.store.session_hash(token), client, sub, refresh_token,
                                    client_id=self.oidc_clients[client].client_id)

    def _gnade(self) -> int:
        """Gnadenfrist des alten Tokens nach dem Drehen, in Sekunden (A-6)."""
        return max(0, int(self.cfg.session_rotation_grace_sec or 0))

    def _oidc_nachpruefen(self, s) -> bool:
        """Folgt die Sitzung dem Provider noch? False = die Sitzung ist beendet (4a).

        Alle `oidc_session_refresh_minutes` wird das Refresh-Token getauscht — je Client der
        Sitzung, im Hintergrund (`_oidc_tausch`). Diese Anfrage beansprucht den fälligen Tausch
        nur (`oidc_sitzung_beanspruchen`, genau eine von vielen parallelen) und läuft weiter; das
        Ergebnis gilt ab der nächsten Anfrage. So blockiert ein hängender Provider nichts, und zwei
        Anfragen tauschen nie dasselbe Token (Rotation beim Provider). Gesperrte Konten fragt
        niemand beim Provider nach — sie kommen ohnehin nicht herein (F-17)."""
        frist = int(self.cfg.oidc_session_refresh_minutes or 0) * 60
        if not frist or self.oidc is None:
            return True
        zeilen = self.store.get_oidc_sitzungen(s["token_hash"])
        if not zeilen:
            return True
        konto = self.store.get_user(s["user_id"])
        if not konto or konto["disabled"]:
            return True
        jetzt = _jetzt()
        grenze = int(self.cfg.oidc_session_max_unverified_hours or 0) * 3600
        for z in zeilen:
            try:
                erfolg = z["erfolg_at"]
            except (IndexError, KeyError):
                erfolg = None
            # Seit wann hat der Provider nicht mehr Ja gesagt? Ohne Stand (Zeile aus der Zeit vor
            # der Spalte) zählt der letzte Tausch.
            seit = int(erfolg if erfolg is not None else z["geprueft_at"])
            if grenze and jetzt - seit > grenze:
                # Obergrenze ohne erfolgreiche Nachprüfung: Die Sitzung endet. Das ist KEIN Nein
                # des Providers — die API-Keys ruhen dadurch nicht (Fund 8 bleibt am echten Nein).
                self.store.delete_session_by_handle(s["token_hash"])
                konto_name = konto["username"] if konto else None
                self.store.audit_log("oidc_unbestaetigt", konto_name, s["ip"],
                                     f"client={z['client']} stunden={grenze // 3600}")
                security.seclog.warning(
                    "OIDC-Nachprüfung seit über %d Stunden ohne Ergebnis — Sitzung beendet. Prüfen: "
                    "Client-Secret/Client beim Provider, Erreichbarkeit. user=%s",
                    grenze // 3600, security.fuer_log(konto_name))
                return False
            if jetzt - int(z["geprueft_at"]) < frist:
                continue
            if not self.store.oidc_sitzung_beanspruchen(s["token_hash"], z["client"], z["geprueft_at"], jetzt):
                continue          # eine andere Anfrage tauscht gerade
            if not self._oidc_ausgang.einreihen(lambda z=z: self._oidc_tausch(s, z, frist)):
                # Warteschlange voll: Anspruch zurückgeben, die nächste Anfrage versucht es wieder.
                self.store.oidc_sitzung_geprueft(s["token_hash"], z["client"], z["geprueft_at"])
        return True

    def _oidc_tausch(self, s, z, frist) -> None:
        """Ein Refresh-Token beim Provider tauschen und das Ergebnis anwenden (4a, im Hintergrund).

        * verweigert der Provider (gesperrt, gelöscht, entgruppt, der Anwendung entzogen) → die
          Sitzung endet, mit Zeile im Audit-Log;
        * liefert er frische Angaben → Gruppen, erlaubte Gruppen und das vom Provider vergebene
          Admin-Flag werden neu bewertet (H-5 wirkt damit binnen Minuten) — aber nur, wenn der
          Gruppen-Claim überhaupt dabei ist: Fehlt er, hiesse „keine Gruppen" sonst, jede gemappte
          Rolle zu entziehen;
        * ist er nicht erreichbar → nichts ändert sich, neuer Versuch in einer Minute. Ein Ausfall
          des Providers soll niemanden abmelden."""
        handle, client = s["token_hash"], z["client"]
        konto = self.store.get_user(s["user_id"])
        name = konto["username"] if konto else None
        try:
            ausgestellt_fuer = z["client_id"]
        except (IndexError, KeyError):
            ausgestellt_fuer = None
        if not self.oidc_clients.bekannt(client) or (
                ausgestellt_fuer and ausgestellt_fuer != self.oidc_clients[client].client_id):
            # Die Anwendung wurde aus `oidc_clients` genommen, oder der Client wurde beim Provider
            # neu angelegt (andere client_id). Der Tausch liefe mit falschen Zugangsdaten, der
            # Provider sagte Nein, und das träfe das Konto (Angriff auf die dritte Runde und
            # Gegenprüfung). Die Zeile geht, die Sitzung bleibt bis zu ihrem Ablauf.
            self.store.oidc_sitzung_verwerfen(handle, client)
            security.seclog.warning("OIDC-Nachprüfung: Client %s ist nicht mehr (so) eingerichtet — "
                                    "Zeile verworfen, kein Nein. user=%s",
                                    security.fuer_log(client), security.fuer_log(name))
            return
        try:
            refresh = self.store.tresor.entschluesseln(z["refresh"])
        except Exception:   # noqa: BLE001 — falscher Schlüssel: der Start prüft das; hier nichts verbrennen
            self.store.oidc_sitzung_geprueft(handle, client, _jetzt() - frist + 60,
                                             alt_verschluesselt=z["refresh"])
            return
        gefragt = _jetzt()
        status, info, tok = self.oidc_clients[client].refresh(refresh, z["sub"])
        jetzt = _jetzt()
        # Während des Tauschs kann die Sitzung ein neues Token bekommen haben (Step-up, Abschluss
        # eines Faktors) — ihr heutiges Handle steht an der Zeile, gefunden über das Token.
        handle = self.store.oidc_sitzung_handle(client, z["refresh"]) or handle
        if status == "fehler":
            self.store.oidc_sitzung_geprueft(handle, client, jetzt - frist + 60, alt_verschluesselt=z["refresh"])
            security.seclog.warning("OIDC-Nachprüfung ohne Ergebnis (%s): Provider nicht erreichbar oder "
                                    "ein Fehler des Clients (Zugangsdaten, Grant) — Sitzung bleibt, "
                                    "neuer Versuch in einer Minute. user=%s",
                                    security.fuer_log(str(tok.get("error", "?"))), security.fuer_log(name))
            return
        if status == "abgelehnt":
            self.store.delete_session_by_handle(handle)
            fehler = security.fuer_log(str(tok.get('error', '?')))
            self.store.audit_log("oidc_widerruf", name, s["ip"], f"client={client} grund={fehler}")
            self._idp_nein(s["user_id"], name, s["ip"], client, fehler)
            return
        lebt = self.store.oidc_sitzung_geprueft(handle, client, jetzt, tok.get("refresh_token"),
                                                alt_verschluesselt=z["refresh"], erfolg=True)
        eintrag = self.oidc_clients.eintrag(client)
        if self.cfg.oidc_group_claim in info:
            roh = info.get(self.cfg.oidc_group_claim) or []
            gruppen = roh if isinstance(roh, list) else [roh]
            erlaubte = eintrag["allowed_groups"]
            if erlaubte and not (set(erlaubte) & set(map(str, gruppen))):
                self.store.delete_session_by_handle(handle)
                self.store.audit_log("oidc_widerruf", name, s["ip"], f"client={client} grund=gruppe")
                self._idp_nein(s["user_id"], name, s["ip"], client, "gruppe")
                return
            self.apply_idp_groups(s["user_id"], gruppen, eintrag["group_role_map"])
        if lebt:
            # Nur, wenn die Sitzung noch da ist: Ein paralleles Nein über einen anderen Client
            # kann sie inzwischen beendet haben — dann bestätigt dieses Ja nichts mehr.
            self.store.idp_bestaetigen(s["user_id"], gefragt)

    def current_user(self, request) -> Optional[dict]:
        """Das angemeldete Konto zu diesem Request — aus der Sitzung ODER einem API-Key. None, wenn niemand angemeldet ist.

        Nicht die Quelle für eine Route, die einen Faktor auf die laufende Sitzung anwendet, sie
        auffrischt oder beendet — dort gehört das Konto aus `session_user()` (0.20.1)."""
        # Erst die IP merken, dann auflösen: Auch ein abgewiesener API-Key (B5-05) soll mit der
        # Adresse im Protokoll stehen, von der er kam.
        self._anfrage_merken(request)
        u = self._current_user_ermitteln(request)
        if u:
            self._anfrage_merken(request, u)
        return u

    def session_user(self, request) -> Optional[dict]:
        """Das Konto der vollen Sitzung dieses Requests — wie `current_user()`, nur nie aus einem API-Key.

        **Die Quelle für jede Route mit Sitzungswirkung** (0.20.1): Wer einen Faktor prüft und
        ihn danach auf die Sitzung anwendet (`apply_factor`, `complete_totp`), sie auffrischt
        (Step-up) oder beendet, nimmt das Konto von hier. `current_user()` fällt ohne volle
        Sitzung auf den API-Key zurück. In einer solchen Route prüfte der Faktor dann das Konto
        des Keys, und die Wirkung traf das Cookie: `/auth/reauth` machte die halbe Sitzung eines
        anderen voll, `/auth/pin` hob bei `pin_login=False` den Riegel „PIN ist kein Erstfaktor"
        aus und legte aus Automaten-Key und PIN eine volle Sitzung an — samt dem Admin-Flag, das
        der Key allein nie trägt (R6-5). Für diese Routen ist ein Key „nicht angemeldet".

        Eine halbe Sitzung (erster Faktor ja, Kette offen) liefert None; die liest
        `pending_user()`. Ein Wächter in `tests/test_stepup.py` hält fest, dass keine Stelle
        des Pakets mit Sitzungswirkung ihr Konto aus einer Quelle nimmt, die einen Key annimmt.
        Dieselbe Regel gilt für eigene Routen der App, die `apply_factor()` für „das
        angemeldete Konto" rufen."""
        self._anfrage_merken(request)
        u = self._konto_der_sitzung(self._session_from_request(request))
        if u:
            self._anfrage_merken(request, u)
        return u

    def _konto_der_sitzung(self, s) -> Optional[dict]:
        """Das Konto einer VOLLEN Sitzungszeile, gesperrte Konten ausgenommen — oder None."""
        if s and s["mfa_ok"]:
            u = self.store.get_user(s["user_id"])
            if u and not u["disabled"]:
                d: dict = self._als_dict(u) or {}
                d["_via"] = "session"
                return d
        return None

    def _current_user_ermitteln(self, request) -> Optional[dict]:
        # 1) Session (Mensch, inkl. MFA) — dieselbe Auflösung wie `session_user()`
        s = self._session_from_request(request)
        d = self._konto_der_sitzung(s)
        if d:
            return d
        # 2) API-Key (maschinell / Daemon) — der Key IST der Faktor, kein MFA
        if self.cfg.apikey_enabled:
            key = self._extract_api_key(request)
            if key:
                u, key_roles = self.verify_api_key(key)
                art = getattr(self, "_letzte_key_art", "automation")
                if u and art == "human":
                    # Ein Menschen-Key gilt NUR zusammen mit einer Sitzung desselben Kontos
                    # (R6-5). Allein abgeflossen ist er wertlos — das ist der ganze Unterschied
                    # zum Automaten-Key, und dafür darf er die vollen Rechte tragen.
                    if not (s and s["mfa_ok"] and s["user_id"] == u["id"]):
                        security.seclog.warning(
                            "API-Key der Art 'mensch' ohne passende Sitzung vorgelegt "
                            "(user=%s ip=%s) — abgewiesen.",
                            security.fuer_log(str(u["username"])),
                            security.fuer_log(self.client_ip(request)))
                        return None
                if u:
                    d = dict(u)
                    d["_via"] = "apikey"
                    d["_key_kind"] = art
                    # `!= "human"` statt `== "automation"`: fail-closed für jede Art, die es nicht
                    # gibt (ein Tippfehler in der Spalte, ein Wert aus einer fremden Fassung).
                    # Vorher behielt ein Key mit `kind="Automat"` das Admin-Flag (R6-6). Die
                    # Werte bis 0.21.x (`mensch`) kommen schon abgebildet an (`_key_kind`).
                    if art != "human" and d.get("is_admin"):
                        # Der Kern von R6-5: Ein Automaten-Key trägt das Admin-Flag seines
                        # Besitzers NICHT. Vorher war jeder Key eines Admins eine vollständige
                        # Admin-Schreib-API — ohne zweiten Faktor, ohne CSRF-Schicht. Die Rollen
                        # bleiben (dafür gibt es den Scope), das Flag nicht.
                        d["is_admin"] = 0
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
        s = self._session_from_request(request)
        if not s or s["mfa_ok"]:
            return None
        u = self._als_dict(self.store.get_user(s["user_id"]))
        if u:
            self._anfrage_merken(request, u)
        return u

    def _pin_kettenschritt(self, request) -> Optional[dict]:
        """Das Konto der halben Sitzung, wenn die PIN jetzt ihr Kettenschritt ist — sonst None.

        Ja nur, wenn die globale `login_chain` die PIN verlangt, sie in dieser Sitzung noch fehlt
        und sie, in einer strikten Kette, der nächste Schritt ist. Bis 2026-09-27 genügte jede
        halbe Sitzung (G7-N1): Im klassischen Modus mit `pin_login=False` prüfte `/auth/pin` dann
        die PIN für jeden, der nur das Passwort hatte (falsch 401, richtig 303 — dort ein Orakel,
        das es vorher nicht gab), und in einer strikten Kette `password → totp → pin` stand die PIN
        vor dem TOTP in der Sitzung. Deren Reihenfolge war danach nie mehr erfüllbar, und jede
        weitere Anmeldung im selben Browser hing an ihr fest, bis zum Abmelden (p2 F1)."""
        u = self.pending_user(request)
        req, strict = self._global_chain()
        if not u or not req or "pin" not in req:
            return None
        s = self._session_from_request(request)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if "pin" in done or (strict and self._next_factor(req, strict, done) != "pin"):
            return None
        return u

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
        angemeldet. Die Einrichtung allein meldet niemanden an — der Faktor gilt erst, wenn ein
        Code aus dem frischen Geheimnis stimmt. Das ist der Bestätigungscode selbst: Die Route
        `POST /auth/totp/setup` schliesst den TOTP-Schritt damit ab (A-1), denn der Code ist
        verbraucht und an `/auth/totp` nur noch ein Fehlversuch.
        """
        u = self.pending_user(request)
        if not u or self.store.has_confirmed_totp(u["id"]):
            return None
        req, _ = self._global_chain()
        if not (req and "totp" in req):
            return None
        if self.store.list_webauthn(u["id"]):
            # Hat das Konto schon einen starken zweiten Faktor (Passkey), richtet es sich einen
            # weiteren nur ein, wer ihn in DIESER Sitzung vorgelegt hat — oder in einem Fenster,
            # das der Betreiber ausdrücklich geöffnet hat (verlorenes Gerät; das Fenster gewinnt
            # wie in `mfa_enrollment_allowed`). Sonst richtete sich das Postfach selbst einen zweiten
            # Faktor ein und umginge den Passkey: über den Anmelde-Link (ASVS 6.3.6, Angriff auf die
            # dritte Runde) oder über „Passwort vergessen" und dann das neue Passwort (Gegenprüfung).
            # Konten OHNE zweiten Faktor dürfen es weiter — das ist der bewusste Preis von Option C.
            s = self._session_from_request(request)
            done = json.loads(s["factors_done"] or "[]") if s else []
            konto = self.store.get_user(u["id"])
            fenster = konto["mfa_enroll_until"] if konto else None
            if "passkey" not in done and not (fenster and int(fenster) > _jetzt()):
                self.audit("mfa_enrollment_denied", str(konto["username"]) if konto else None,
                           detail="Konto hat einen Passkey, der in dieser Sitzung fehlt")
                return None
        if not self.mfa_enrollment_allowed(u["id"]):
            # Kein stilles Nein: Wer hier scheitert, hat das richtige Passwort und steht vor
            # einer Tür, die sich nicht öffnet. Die Zeile sagt dem Betreiber, welcher Weg bleibt.
            #
            # **Ohne `log_ereignis`**, also ohne das Wort, auf das die fail2ban-Jail matcht: Das
            # hier ist kein Fehlversuch. Wer bis hierher kommt, hat sein richtiges Passwort
            # eingegeben — ihn dafür auch noch sperren zu lassen wäre genau verkehrt herum. Der
            # Name kommt aus der frisch geholten Kontozeile, nicht aus dem Request.
            konto = self.store.get_user(u["id"])
            security.seclog.warning(
                "mfa enrollment denied user=%s art=%s — der zweite Faktor fehlt und darf hier "
                "nicht mehr eingerichtet werden. Weg: auth.grant_mfa_enrollment(uid) oder das "
                "Admin-Panel.",
                security.fuer_log(str(konto["username"]) if konto else "?"),
                self.cfg.mfa_enrollment)
            self.audit("mfa_enrollment_denied", str(konto["username"]) if konto else None,
                       detail=f"art={self.cfg.mfa_enrollment}")
            return None
        return u

    #: Die erlaubten Werte von `cfg.mfa_enrollment` — als Liste, damit ein Tippfehler beim
    #: Aufbau auffällt und nicht erst dann, wenn jemand vor der Tür steht.
    MFA_ENROLLMENT_MODES = ("first_login", "grace", "strict")

    def mfa_enrollment_allowed(self, user_id: int, now: Optional[int] = None) -> bool:
        """Darf dieses Konto den von der Kette verlangten Faktor **selbst** einrichten? (R3-1)

        Drei Betriebsarten (`cfg.mfa_enrollment`), plus ein vom Betreiber geöffnetes Fenster,
        das immer gewinnt — das ist der Weg für jedes Konto, dem die Betriebsart es sonst
        verwehrt (Admin-Panel, Einladung, `grant_mfa_enrollment`).

        Die Gefahr, um die es geht: Wer das Passwort eines **bestehenden** Kontos hat, band sich
        vorher seinen eigenen Authenticator ein. Bei einem Konto, das noch nie benutzt wurde, ist
        das Risiko ein anderes — dort ist der erste Anmeldende der rechtmässige, so wie bei einem
        Einladungslink auch.
        """
        now = _jetzt() if now is None else int(now)
        u = self.store.get_user(user_id)
        if not u:
            return False
        fenster = None
        try:
            fenster = u["mfa_enroll_until"]
        except (IndexError, KeyError):
            fenster = None            # Datei vor Schema 8
        if fenster and int(fenster) > now:
            return True
        art = str(self.cfg.mfa_enrollment or "first_login")
        if art == "strict":
            return False
        if art == "grace":
            tage = max(0, int(self.cfg.mfa_enrollment_grace_days or 0))
            return (now - int(u["created_at"])) <= tage * 86400
        # "first_login": erlaubt, solange dieses Konto noch nie vollständig angemeldet war.
        try:
            return u["first_login_at"] is None
        except (IndexError, KeyError):
            return True               # Datei vor Schema 8: die Chance bleibt

    def grant_mfa_enrollment(self, user_id: int, minutes: int = 60) -> int:
        """Ein Einrichtungsfenster öffnen und seinen Ablauf zurückgeben.

        Der Weg des Betreibers, wenn jemand sein Gerät verloren hat oder `mfa_enrollment="strict"`
        gilt. Bewusst zeitlich begrenzt: ein dauerhaft offenes Fenster wäre die alte Lücke unter
        neuem Namen."""
        bis = _jetzt() + max(1, int(minutes)) * 60
        self.store.set_mfa_enroll_until(user_id, bis)
        u = self.store.get_user(user_id)
        self.audit("mfa_enrollment_granted", str(u["username"]) if u else None,
                   detail=f"minuten={minutes}")
        return bis

    def revoke_mfa_enrollment(self, user_id: int) -> None:
        """Ein offenes Einrichtungsfenster sofort schliessen."""
        self.store.set_mfa_enroll_until(user_id, None)
        u = self.store.get_user(user_id)
        self.audit("mfa_enrollment_revoked", str(u["username"]) if u else None)

    def _csrf_rotieren(self, response) -> str:
        """Ein frisches CSRF-Token setzen — beim Login.

        Das naive Double-Submit gilt als anfällig gegen *cookie injection*: Wer über eine
        Subdomain ein Cookie setzen kann, setzt ein passendes CSRF-Paar gleich mit. Das OWASP
        CSRF Prevention Cheat Sheet empfiehlt deshalb eine Bindung an „a session-dependent value
        that changes with each login". Das Token beim Anmelden zu erneuern ist davon der billige
        Teil und kostet nichts.

        Seit 0.20.1 ruft `set_cookie()` die Methode selbst, sobald das Token zu einer eben
        angemeldeten Sitzung gehört — jeder Anmeldeweg, auch eine eigene Route der App mit
        `start_session` + `set_cookie`. Bis 0.20.0 geschah das nur am Ende eines TOTP-Schritts,
        obwohl dieser Docstring es für jeden Login versprach. Direkt rufen muss sie nur, wer eine
        Anmeldung ohne `set_cookie()` baut. Ersetzt eine CSRF-Zeile, die die Antwort schon trägt.
        """
        return self.issue_csrf(response)

    # ---------- Cookie-Namen (H-1) ----------
    def _cookie_name(self, basis: str, host_only: bool = False) -> str:
        """`__Host-` davor, wo der Browser es zulässt (Secure, kein Domain, Pfad `/`).

        Ein `__Host-`-Cookie kann nur der eigene Host über HTTPS setzen — eine Nachbar-Subdomain
        kann es weder anlegen noch mit einem `Domain=.example.com`-Cookie gleichen Namens
        überschatten. Genau darauf baut das Unterschieben eines Sitzungs-, CSRF- oder
        Freigabe-Tokens (F-01, F-02). Zur Request-Zeit berechnet, weil `cfg` nach dem Aufbau
        geändert werden darf.

        `host_only=True` für Cookies, die nie mit `cookie_domain` gesetzt werden (das
        CSRF-Cookie und die Flow-Cookies von OIDC, SAML und Passkey) — die dürfen das Präfix
        auch dann tragen.

        Der Pfad muss wörtlich `/` sein: Bei `cookie_path=""` schickt `set_cookie` gar kein
        `Path`-Attribut, und ein `__Host-`-Cookie ohne `Path=/` verwirft der Browser still —
        dann käme etwa das CSRF-Cookie nie an und jeder POST scheiterte (A-7)."""
        c = self.cfg
        if (getattr(c, "cookie_host_prefix", True) and c.cookie_secure
                and (host_only or not c.cookie_domain)
                and c.cookie_path == "/" and not basis.startswith("__")):
            return "__Host-" + basis
        return basis

    def flow_cookie_name(self, base: str) -> str:
        """Name eines Flow-Cookies (OIDC, SAML, Passkey) — mit `__Host-`, wo möglich (A-1).

        Das Flow-Cookie bindet einen Anmeldevorgang an den Browser, der ihn begonnen hat. Kann
        eine Nachbar-Subdomain es per `Domain=.example.com` setzen, schiebt sie dem Opfer den
        Flow des Angreifers unter und lockt es auf die Callback-URL — Login-CSRF, obwohl das
        Sitzungs-Cookie selbst schon gepräfixt ist."""
        return self._cookie_name(base, host_only=True)

    def _flow_cookie_setzen(self, response, basis: str, wert: str, max_age: int,
                           samesite: Optional[str] = None) -> None:
        """Ein Flow-Cookie setzen: httponly, host-only, kurzlebig."""
        response.set_cookie(self.flow_cookie_name(basis), wert, max_age=max_age, httponly=True,
                            secure=self.cfg.cookie_secure,
                            samesite=_samesite(samesite or self.cfg.cookie_samesite),
                            path=self.cfg.cookie_path)

    def _flow_cookie_loeschen(self, response, basis: str,
                             samesite: Optional[str] = None) -> None:
        # Mit Secure: Ein `__Host-`-Set-Cookie ohne Secure nimmt der Browser nicht an, auch
        # nicht das löschende.
        response.delete_cookie(self.flow_cookie_name(basis), path=self.cfg.cookie_path,
                               secure=self.cfg.cookie_secure, httponly=True,
                               samesite=_samesite(samesite or self.cfg.cookie_samesite))

    @property
    def session_cookie_name(self) -> str:
        """Der tatsächliche Name des Sitzungs-Cookies (mit `__Host-`, wo möglich)."""
        return self._cookie_name(self.cfg.session_cookie)

    @property
    def csrf_cookie_name(self) -> str:
        """Der tatsächliche Name des CSRF-Cookies — eigenes JS bekommt ihn von der Seite.

        JS kann diese Property nicht lesen: Die Seite reicht den Namen mit (Template-Variable
        oder `<meta>`), oder das JS nimmt das Token aus dem Formularfeld `_csrf`, das
        `ensure_csrf()` liefert.

        Mit `__Host-` auch bei gesetztem `cookie_domain`: Das CSRF-Cookie setzt TinySesam nie
        mit Domain (`issue_csrf`, `render_page`, Admin-Panel), es ist immer host-only. Ohne
        Präfix konnte im Forward-Auth-Aufbau jede geschützte App ein `tinysesam_csrf` für die
        ganze Domain setzen und das Double-Submit mit ihrem eigenen Wert bestehen."""
        return self._cookie_name(self.cfg.csrf_cookie, host_only=True)

    @property
    def resource_cookie_name(self) -> str:
        """Der tatsächliche Name des Freigabe-Cookies der Bereichs-PIN."""
        return self._cookie_name(self.cfg.resource_cookie)

    def set_cookie(self, response, token, remember: Optional[bool] = None):
        """Session-Cookie setzen. remember=True → persistentes Cookie (max_age = lange TTL);
        remember=False → reines Session-Cookie (max_age=None, endet beim Browser-Schließen).

        Ohne `remember` richtet sich die Art nach der Sitzung, zu der das Token gehört (A-2):
        Ein Step-up oder ein Ketten-Schritt dreht das Token einer LAUFENDEN Sitzung, und deren
        Art hat der Nutzer beim ersten Faktor gewählt. Vorher galt hier stumpf `True` — eine
        Sitzung ohne „Angemeldet bleiben" bekam nach dem Einlösen eines Magic-Links ein Cookie
        für sieben Tage, das das Schließen des Browsers am geteilten Rechner überlebte.
        Gibt es keine Sitzung zum Token, bleibt es beim persistenten Cookie wie bisher.

        Ist das Token eine eben entstandene Anmeldung (`start_session`, der letzte Schritt einer
        Kette), setzt dieselbe Antwort auch ein neues CSRF-Token (0.20.1). Wer danach in dieser
        Antwort ein Formular rendert, holt das Token mit `ensure_csrf(request, response)` — über
        den FastAPI-Antwortparameter. Eine fertige Antwort ist dann schon gerendert und ihr
        Formular trüge das alte Token: dort umleiten statt ein Formular ausliefern."""
        if remember is None:
            s = self.store.get_session(token)
            remember = bool(s["remember"]) if s else True
        kw = dict(httponly=True, secure=self.cfg.cookie_secure,
                  samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        if remember:
            kw["max_age"] = self._ttl(True)   # type: ignore[assignment]  # kw trägt gemischte Typen
        response.set_cookie(self.session_cookie_name, token, **kw)
        # Eine Anmeldung dreht das CSRF-Token (OWASP: „changes with each login"). Zentral hier,
        # nicht je Route: Jede Anmeldung setzt dieses Cookie, und jede volle Sitzung ist bei
        # ihrer Entstehung vorgemerkt (`_sitzung_anlegen`). Ein Step-up dreht nicht.
        if self._anmeldung_einloesen(token):
            self._csrf_rotieren(response)

    def rotate_session(self, request, response) -> Optional[str]:
        """Der laufenden Sitzung ein neues Token geben und das Cookie setzen (F-06).

        Für jeden Rechtewechsel, der KEINE neue Sitzung anlegt — der Step-up. OWASP Session
        Management: „The session ID must be renewed … after any privilege level change";
        ASVS 5.0 7.2.4 verlangt das ausdrücklich auch bei der Re-Authentisierung. Wer das alte
        Token mitgelesen hat, hält danach eine tote Sitzung statt einer frisch bestätigten.
        Laufzeit und Anmeldezeitpunkt bleiben; das Cookie behält seine Art (persistent oder
        nicht). Gibt das neue Token zurück, oder None ohne Sitzung.

        Räumt dabei die Cookies unter den Namen von vor dem `__Host-`-Präfix ab (H-1) — wie
        `logout()` auch dann, wenn eine eigene Route der App die Methode ruft."""
        s = self._session_from_request(request)
        if not s:
            return None
        neu = self.store.rotate_session(s["token_hash"], self._gnade())
        if neu:
            self.set_cookie(response, neu, remember=bool(s["remember"]))
            self._altnamen_loeschen(request, response)
        return neu

    def count_other_sessions(self, request, user, token: Optional[str] = None) -> int:
        """Wie viele Sitzungen dieses Kontos laufen AUSSER der aktuellen? (B1-7)

        Die Antwort jeder Faktor-Änderung trägt die Zahl als `other_sessions`: ASVS 5.0 7.4.3
        verlangt nach Anlage oder Entfernung eines Faktors das Angebot, die übrigen Sitzungen zu
        beenden. Die Kontoseite fragt dann nach; wer eine eigene Oberfläche baut, liest das Feld.

        Die Pflicht-Einrichtung von TOTP mitten in einer Kette (`password → totp → pin`) meldet
        hier 0, weil die Sitzung danach noch halb ist und eine halbe die übrigen nicht beenden
        darf — sie meldet die Zahl als `other_sessions_after`, und die Zustimmung wird beim
        Abschluss der Kette eingelöst (`_andere_nach_abschluss`, Grenze d).

        `token`: das Klartext-Token der eigenen Sitzung, wenn es in DIESER Antwort gewechselt
        hat (die Pflicht-Einrichtung von TOTP schliesst die Anmeldung ab und dreht dabei das
        Token). Das Cookie des Requests nennt dann eine Sitzung, die es nicht mehr gibt — gegen
        sie gezählt, liefe die neue eigene Sitzung als „andere" mit."""
        s = self.store.get_session(token) if token else self._session_from_request(request)
        eigen = s["token_hash"] if s else None
        return sum(1 for z in self.store.list_sessions(user["id"]) if z["token_hash"] != eigen)

    def _cookie_loeschen(self, response, name):
        # Secure muss mit: Ein Browser nimmt ein `__Host-`-Set-Cookie ohne Secure nicht an —
        # auch nicht das, das es löschen soll.
        kw = dict(path=self.cfg.cookie_path, secure=self.cfg.cookie_secure, httponly=True,
                  samesite=_samesite(self.cfg.cookie_samesite))
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.delete_cookie(name, **kw)

    def _altnamen(self) -> list:
        """Die Namen von Sitzungs-, CSRF- und Freigabe-Cookie aus der Zeit vor dem
        `__Host-`-Präfix (H-1) — nur die, bei denen das Präfix jetzt tatsächlich greift. Wo es
        nicht greift, IST der alte Name der aktuelle. Die Flow-Cookies fehlen bewusst: Sie
        leben nur Minuten."""
        paare = ((self.session_cookie_name, self.cfg.session_cookie),
                 (self.csrf_cookie_name, self.cfg.csrf_cookie),
                 (self.resource_cookie_name, self.cfg.resource_cookie))
        return [basis for name, basis in paare if name != basis]

    def _altnamen_loeschen(self, request, response) -> None:
        """Cookies unter den Altnamen beim Browser löschen, wenn diese Antwort die Sitzung
        schreibt (Anmelden, Abmelden, Step-up).

        Gerufen von der Routen-Klasse (jede eingebaute Route), von `logout()` und von
        `rotate_session()` — die beiden öffentlichen Methoden haben den Request. `set_cookie()`
        hat ihn nicht: Eine eigene Anmelderoute der App (`start_session` + `set_cookie`) lässt
        die Altnamen stehen, bis der Browser das nächste Mal über eine dieser Stellen läuft oder
        sie ablaufen. TinySesam liest sie ohnehin nicht mehr.

        TinySesam liest sie nach dem Umstieg auf `__Host-` nicht mehr, aber der Browser schickte
        sie bis zu ihrem Ablauf weiter mit (Sitzung bis zu sieben Tage) — an TinySesam und an
        jede App dahinter. Mit den neuen Namen zusammen waren das mehr tinysesam-Cookies, als
        die nginx-Vorlagen herausfiltern konnten (B-20). Gelöscht wird nur, was der Browser
        mitgeschickt hat, und host-only: So waren sie gesetzt, denn das Präfix greift nur ohne
        `cookie_domain` (das CSRF-Cookie trug nie eine Domain). Läuft auf demselben Host eine
        zweite Instanz mit gleichem Basisnamen und ohne Präfix, verliert sie ihr Cookie — zwei
        Instanzen auf einem Host brauchen ohnehin eigene Namen (`session_cookie`).

        Die Sitzung und die Freigaben hinter den alten Cookies enden mit: Das Token darin war
        sonst bis zu sieben Tage weiter gültig — unter dem neuen Namen vorgezeigt, meldete es
        an, und es war gerade das Cookie, das an die Apps durchrutschte. Wer es vorzeigt, darf
        es auch beenden; das ist dieselbe Regel wie beim Abmelden."""
        alt = [n for n in self._altnamen() if n in request.cookies]
        if not alt:
            return
        gesetzt = {wert.split(b"=", 1)[0].strip().decode("latin-1")
                   for schluessel, wert in getattr(response, "raw_headers", [])
                   if schluessel.lower() == b"set-cookie"}
        if self.session_cookie_name not in gesetzt:
            return
        for name in alt:
            if name in gesetzt:
                continue
            wert = request.cookies.get(name) or ""
            if wert and name == self.cfg.session_cookie:
                self.store.delete_session(wert)
            elif wert and name == self.cfg.resource_cookie:
                self.store.delete_resource_unlocks(wert)
            response.delete_cookie(name, path=self.cfg.cookie_path,
                                   secure=self.cfg.cookie_secure, httponly=True,
                                   samesite=_samesite(self.cfg.cookie_samesite))

    def logout(self, request, response):
        """Die Sitzung dieses Requests beenden, die Bereichs-Freigaben dieses Browsers mit, und
        die Cookies löschen — Sitzung, Freigabe und seit 0.20.1 auch das CSRF-Cookie, dazu die
        Cookies unter den Namen von vor dem `__Host-`-Präfix.

        Die Freigaben gehören dazu (F-08): Bis 0.20 überlebten sie das Abmelden um bis zu
        `resource_unlock_ttl_hours`. Wer sich am geteilten Rechner abmeldet, erwartet, dass
        danach nichts mehr offen ist — auch nicht der mit einer PIN gesperrte Bereich."""
        s = self._session_from_request(request)
        if s:
            self.store.delete_session_by_handle(s["token_hash"])
        self._cookie_loeschen(response, self.session_cookie_name)
        freigabe = request.cookies.get(self.resource_cookie_name)
        if freigabe:
            self.store.delete_resource_unlocks(freigabe)
            self._cookie_loeschen(response, self.resource_cookie_name)
        # Das CSRF-Token endet mit der Sitzung (0.20.1): Bis 0.20.0 überlebte es Abmelden und
        # Neuanmelden bis zum Schliessen des Browsers. Die nächste Seite setzt ein frisches;
        # `ensure_csrf()` in derselben Antwort ebenso.
        if self.cfg.csrf_enabled or request.cookies.get(self.csrf_cookie_name):
            self._csrf_cookie_loeschen(response)
        # Auch hier, nicht nur in der Routen-Klasse: `logout()` ist öffentlich und wird aus
        # eigenen Routen der App gerufen, an denen die Klasse nicht hängt.
        self._altnamen_loeschen(request, response)

    # ---------- Härtung (Regulation / Rate-Limit / Audit) ----------
    def client_ip(self, request: Request) -> str:
        """Die echte Client-IP. Hinter einem Proxy nur dann aus `X-Forwarded-For`, wenn der Peer in `trusted_proxies` steht — sonst wäre der Header fälschbar."""
        return security.client_ip(request, self.cfg.trusted_proxies)

    def _sec(self, key) -> int:
        """Härtungs-Wert: Store-Setting (Panel) ODER Default, immer innerhalb von `security.SECURITY_GRENZEN`.

        Gelesen über `security.haertung_lesen` — denselben Weg nimmt das CLI (`tinysesam passwd`);
        ein Bestandswert jenseits der Grenzen gilt dort wie hier als die nächste Grenze."""
        return security.haertung_lesen(self.store, key)

    def all_security(self) -> dict:
        """Alle Härtungs-Schwellen als Dict (Vorgaben, überschrieben von dem, was im Panel steht)."""
        return {k: self._sec(k) for k in security.SECURITY_DEFAULTS}

    def set_security(self, key, value):
        """Eine Härtungs-Schwelle zur Laufzeit setzen; sie überlebt den Neustart in der Datenbank.

        Unbekannter Schlüssel oder Wert ausserhalb von `security.SECURITY_GRENZEN` → `ConfigError`,
        und nichts wird geschrieben. Bis 0.19.x fiel ein unbekannter Schlüssel still weg und jeder
        Wert wurde übernommen — `rate_limit_max=0` sperrte danach jede Anmeldung, auch die, mit
        der man den Wert hätte zurückdrehen können (R6-4)."""
        try:
            zahl = security.pruefe_haertung(key, value)
        except ValueError as e:
            raise ConfigError(str(e)) from None
        self.store.set_setting(key, zahl)

    def set_rate_limiter(self, limiter):
        """Eigenes Rate-Limit-Backend einhängen — beliebiges Objekt mit allow(key, max, window)->bool."""
        self.rl = limiter

    # Abgewiesen wird an elf Stellen im Router; gemeldet wird HIER, in der Prüfung selbst.
    # Grund: Solange der App-Lockout griff, rief niemand mehr `_record_login()` — die App
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
    #: Sperrgründe, die ein KONTO betreffen (nicht eine Adresse oder das Ratelimit): Nur sie lösen
    #: den Hinweis an den Inhaber aus (ASVS 6.3.5).
    _KONTO_SPERREN = ("lockout_user", "lockout_account", "lockout_serie", "lockout_pin")

    def _abgewiesen(self, username, ip, grund: str, login: bool = True):
        wort = security.LOG_ANMELDUNG if login else security.LOG_PRUEFUNG
        security.seclog.warning("%s user=%s ip=%s method=blocked reason=%s", wort,
                                security.fuer_log(username) or "-", security.fuer_log(ip), grund)
        if login and grund in self._KONTO_SPERREN and username:
            self._sperrhinweis(username, ip, grund)

    def _sperrhinweis(self, username, ip, grund) -> None:
        """Den Inhaber benachrichtigen, dass sein Konto gesperrt wurde (ASVS 6.3.5, B1-12).

        In der Anfrage geschieht für JEDEN Namen dasselbe — eine Drossel je Name, ein Auftrag in
        den eigenen Postausgang —, ob es das Konto gibt oder nicht. Nachgeschlagen und verschickt
        wird erst im Hintergrund: Sonst verriete die Antwortzeit, welche Namen ein Konto haben
        (dieselbe Überlegung wie R4-05). Nur an eine belegte Adresse (H-3), nie an ein
        Service-Konto; höchstens ein Hinweis je Name und Sperrfenster."""
        if not self.cfg.notify_login_failures or not self.mail_configured():
            return
        schluessel = "sperrhinweis:" + norm_kennung(username)
        if not self.rl.allow(schluessel, 1, self._sec("lockout_window_sec")):
            return
        zeit = _jetzt()

        def _senden():
            u = self.find_user(username)
            if not u or u.get("is_service") or not u.get("email") or not _beleg_am_konto(u):
                return
            # Die eigentliche Drossel steht in der Datenbank, nicht im Speicher: Der Schlüssel oben
            # liegt im gemeinsamen, gedeckelten Limiter und lässt sich mit genug fremden Schlüsseln
            # verdrängen; mit mehreren Workern hat jeder seinen (Fund 11). Das Audit-Log gilt für
            # alle Prozesse und vergisst nichts vor der Frist.
            seit = _jetzt() - self._sec("lockout_window_sec")
            if self.store._one("SELECT 1 FROM audit WHERE event='sperrhinweis' AND lower(username)=lower(?) "
                               "AND ts >= ? LIMIT 1", (u["username"], seit)):
                return
            betreff = "Gesperrte Anmeldung bei deinem Konto"
            # Den Reset nur nennen, wenn er die Serie auch räumt (TOTP und die PIN im Kettenschritt
            # räumt er nicht, `_serie_reset_hilft`).
            bis = ""
            if grund == "lockout_serie":
                bis = (" — bis du dein Passwort zurücksetzt oder der Betreiber sie freigibt"
                       if self._serie_reset_hilft(username) else
                       " — bis der Betreiber sie freigibt. Ein Passwort-Reset hebt diese Sperre nicht "
                       "auf: Die Fehlversuche galten dem Schritt nach dem Passwort")
            text = (f"Für dein Konto „{u['username']}“ gab es mehrere fehlgeschlagene Anmeldeversuche; "
                    f"die Anmeldung ist deshalb vorübergehend gesperrt" + bis
                    + f".\n\nZeitpunkt: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(zeit))}\n"
                    f"Adresse der Versuche: {security.fuer_log(ip) or 'unbekannt'}\n\n"
                    "Warst du das nicht, ändere dein Passwort und richte einen zweiten Faktor ein.")
            self.send_mail(u["email"], betreff, text)
            self.store.audit_log("sperrhinweis", u["username"], ip, f"grund={grund}")

        self._hinweis_ausgang.einreihen(_senden)

    def _rate_ok(self, ip, login: bool = True) -> bool:
        """Darf diese IP noch? Ein Nein schreibt eine Zeile ins Sicherheits-Log (fail2ban liest mit).

        `login=False` für Routen, die keine Anmeldung sind (Passwortwechsel, Step-up, Bereichs-PIN):
        Ihre Zeile trägt dann `failed verification` statt `failed login` — sonst bannte die
        mitgelieferte Jail einen angemeldeten Nutzer, der auf seiner eigenen Kontoseite
        weiterklickt (Abschlussangriff C-1)."""
        erlaubt = self.rl.allow(ip or "?", self._sec("rate_limit_max"), self._sec("rate_limit_window_sec"))
        if not erlaubt:
            self._abgewiesen(None, ip, "ratelimit", login=login)
        return erlaubt

    def _is_locked(self, username, ip) -> bool:
        """Zu viele Fehlversuche im Fenster — je Paar aus Konto und IP, je Konto, je IP.

        Die Schwellen stehen in `_regeln` (Begründung dort): das Paar bei `max_login_attempts`,
        das Konto allein beim `account_attempt_factor`-fachen, die Adresse allein beim
        `ip_attempt_factor`-fachen (NAT). Ohne `ip` gilt nur die Konto-Schwelle.

        Gezählt wird alles in `login_attempt`, was ein **Anmeldeversuch** war; die Methoden aus
        `security.NICHT_LOGIN_METHODEN` bleiben draussen. Sonst sperrt ein Fehlgriff, der gar
        keine Anmeldung war, die Anmeldung mit. Der Zähler dieser Methoden geht nicht verloren,
        er hat nur seinen eigenen Topf (z.B. `_is_password_change_locked`).

        Nur lesend: Die Routen nehmen `_versuch_beginnen()`, das prüft und bucht in einem Schritt.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "password"), username, ip, login=True)

    def _record_login(self, username, ip, success, method, versuch: Optional[int] = None,
                      quelle: str = "", konto: Optional[int] = None):
        """Einen Anmeldeversuch verbuchen. Ein Erfolg räumt nur die Fehlversuche DERSELBEN Methode weg.

        `versuch` ist die ID aus `_versuch_beginnen()`: Dann steht der Versuch schon als
        Fehlversuch in der Tabelle und wird hier nur abgeschlossen, statt ein zweites Mal
        gezählt zu werden.

        `quelle` sagt dem Audit-Log, WER das Geheimnis geprüft hat, wo die Methode es nicht
        verrät (F-29): LDAP schreibt bewusst den Faktor `password` — Sperre und Kette sollen
        beide Wege gleich behandeln —, im Protokoll muss der Betreiber sie aber trennen können.
        Ein Erfolg mit `quelle` schreibt eine eigene Zeile `login_<quelle>` (`login_ldap`,
        `login_lokal`), ein Fehlversuch hängt `quelle=…` an `login_fail` an (`lokal+ldap`: beide
        wurden gefragt, beide lehnten ab). Leer = wie bisher, keine Zusatzangabe.

        `konto` ist die ID des Kontos, zu dem die Kennung aufgelöst wurde, wenn das nicht über
        Name oder Adresse geschah — bei einer Verzeichnis-Anmeldung (G5-N1). Dann räumt ein Erfolg
        die Fehlversuche unter der eingetippten Kennung nur, wenn sie keinem ANDEREN Konto gehört:
        Ein Verzeichnisfilter über `mail` löst `chefin@example.com` auch zu einem Dritten auf,
        dessen `mail`-Attribut so lautet — und jede seiner Anmeldungen setzte bis 2026-09-26 das
        Kontofenster der lokalen Inhaberin zurück (verteiltes Raten ohne Grenze ausser Serie und
        IP-Limit).

        Ist die Kennung Name oder Adresse eines lokalen Kontos, wird ab ihrem Beitritt zu diesem
        Konto geräumt (Grenze a, G2): Fehlversuche, die ein Fremder vor dem Umbenennen oder
        Adresswechsel unter der damals freien Kennung gemacht hat, bleiben stehen — sie zählen in
        der Drosselung SEINER IP. Einzelheiten in `_raeumgrenze`."""
        topf = self._topf(username, method)   # derselbe Schlüssel wie beim Zählen
        vorgebucht = self._serie_vorbuchungen.pop(versuch, None) if versuch is not None else None
        uebergang = None
        if versuch is None:
            self.store.record_attempt(topf, ip, success, method)
        else:
            # Bei einem Erfolg gilt die Vorbuchung in der Serie nicht — zurückgenommen in derselben
            # Transaktion wie der Abschluss (G9). Die Serie davor bleibt: Ein richtiger erster
            # Faktor ist noch keine vollständige Anmeldung (`lift_lockout`). Bei einem
            # Fehlversuch sagt der Abschluss, wie die Serie davor und danach feststand (p2 F3).
            uebergang = self.store.finish_attempt(versuch, bool(success),
                                                  serie=vorgebucht[:2] if vorgebucht else None)
        if success and quelle:
            self.store.audit_log(f"login_{quelle}", username, ip, f"{method} quelle={quelle}")
        if success:
            # NUR die Fehlversuche derselben Methode: Ein Passwort-Erfolg sagt nichts darueber,
            # ob jemand gerade TOTP-Codes durchprobiert. Vorher raeumte er sie mit weg und machte
            # den zweiten Faktor ratbar. Alles übrige räumt erst die VOLLSTÄNDIGE Anmeldung
            # (`lift_lockout`).
            grenze = self._raeumgrenze(topf, method, konto)
            if grenze is not None:     # 'login'-Audit erst beim vollen Abschluss
                self.store.clear_fails(username=topf, method=method, **grenze)
        else:
            # Der GRUND gehört ins serverseitige Protokoll. Die HTTP-Antwort bleibt bewusst
            # gleich (keine Konto-Erkundung) — im Audit-Log liest aber nur der Betreiber mit,
            # und ihm sagten „falsches Passwort", „Konto deaktiviert" und „Benutzername
            # vertippt" bisher dasselbe: `login_fail … password`. Das ist der häufigste
            # Supportfall, und er war mit Bordmitteln nicht zu beantworten.
            self.store.audit_log("login_fail", username, ip,
                                 f"{method} grund={self._fehl_grund(username, method)}"
                                 + (f" quelle={quelle}" if quelle else ""))
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
            if method not in security.NICHT_LOGIN_METHODEN:
                # Die Serie zählt je gefalteter Kennung, wie der Konto-Topf (`_topf`). Vorgebucht
                # hat sie `_versuch_beginnen`; nur ein Weg ohne Vorbuchung zählt hier. Genau beim
                # Übergang über die Grenze eine Zeile: ab da ist die Anmeldung dauerhaft zu, und
                # der Betreiber muss wissen, warum sich jemand nicht mehr anmelden kann.
                #
                # Der Übergang ist der des FESTSTEHENDEN Stands (p2 F3). Eine sofort feststehende
                # Buchung (ohne Schweben) überschreitet die Grenze bei der Buchung selbst
                # (`vorgebucht[2]`, der feststehende Stand danach) — gemeldet wird er, wenn die
                # Serie beim Abschluss noch steht. Eine schwebende überschreitet sie erst mit ihrem
                # Abschluss (`vorher < max_serie <= nachher`, in einer Transaktion). Bis 2026-09-27
                # galt der Stand bei der Buchung, samt schwebender Vorbuchungen: Beendete eine
                # parallele volle Anmeldung die Serie, stand `lockout_serie` im Protokoll, obwohl
                # nichts gesperrt war.
                max_serie = self._sec("account_max_consecutive_failures")
                if vorgebucht and uebergang:
                    vorher, nachher = uebergang
                    stand = nachher
                    gesperrt = vorher < max_serie <= nachher or max_serie <= min(vorgebucht[2], nachher)
                else:
                    stand = self.store.fehlserie_erhoehen(norm_kennung(username), method)
                    gesperrt = stand == max_serie
                if gesperrt:
                    self.store.audit_log("lockout_serie", username, ip, f"fehlversuche_in_folge={stand}")
                    security.seclog.warning(
                        "Anmeldung für user=%s gesperrt: %d Fehlversuche in Folge. Aufheben: %s.",
                        security.fuer_log(username), stand, self._serie_ausweg(username))

    def _raeumgrenze(self, topf, method, konto: Optional[int] = None) -> Optional[dict]:
        """Ab wo räumt ein Erfolg die Fehlversuche unter `topf`? Schlüsselwörter für
        `Store.clear_fails` — oder None: gar nicht (`_record_login`).

        * `konto` gegeben (Verzeichnis-Anmeldung): Gehört die Kennung einem ANDEREN Konto → None
          (G5-N1, `Store.topf_eines_anderen`). Sonst ohne Grenze, wie bis dahin: Die Kennung
          gehört dem Eintrag im Verzeichnis, nicht erst ab der lokalen Anlage — die entsteht oft
          erst mit genau dieser Anmeldung, und die Tippfehler davor galten derselben Person.
        * Die Kennung ist Name oder Adresse eines lokalen Kontos → ab ihrer Wasserlinie (`ab_id`,
          G2), im Bestand ohne Wasserlinie ab der Anlage (`seit`).
        * Sonst (ein Bereich `res:<name>`, keine Kennung eines Kontos) → ohne Grenze, wie bis
          dahin: Es gibt kein Konto, dem die Kennung erst ab einem Zeitpunkt gehört."""
        if method == "resource" or not topf:
            return {}
        if konto is not None:
            return None if self.store.topf_eines_anderen(topf, konto) else {}
        u = self.store.konto_mit_topf(topf)
        if u is None:
            return {}
        grenze = self.store.kennung_grenzen(u).get(topf)
        if grenze is None:
            return {}
        return {"ab_id": grenze[0]} if grenze[0] is not None else {"seit": int(u["created_at"] or 0)}

    #: Welche Anteile der Serie (B2-6) ein Selbstbedienungs-Reset räumt: die der ERSTEN Faktoren.
    #: Die kann jeder erzeugen, ohne ein Geheimnis zu kennen — ein Fremder sperrt mit falschen PINs
    #: ein Konto, dessen Inhaberin nicht einmal eine PIN hat. Blieben sie stehen, hülfe der Reset
    #: nicht mehr, zu dem die Meldung rät (Angriff auf die Fixes, R2-2). TOTP-Fehlgriffe dagegen
    #: erzeugt nur, wer das Passwort schon hat; die räumt nur eine vollständige Anmeldung oder der
    #: Betreiber (R4-13). Ebenso eine PIN HINTER einem schon erbrachten Faktor (Kettenschritt der
    #: halben Sitzung, Route-Kette der vollen): Sie bucht unter `_SERIE_PIN_FOLGE` und bleibt stehen
    #: wie TOTP (G7). Bis 2026-09-26 kannte die Art die Stellung nicht — in einer Kette
    #: `password → pin` räumte der Reset die Fehlgriffe des zweiten Faktors mit.
    _SERIE_RESET_ARTEN = ("password", "pin")
    #: Die Art der Serie für eine PIN hinter einem schon erbrachten Faktor (G7). `login_attempt`
    #: und der PIN-Topf zählen sie weiter als `pin`; nur der Selbstbedienungs-Reset unterscheidet.
    _SERIE_PIN_FOLGE = "pin_folge"

    def lift_lockout(self, user_id, methods=None) -> int:
        """Die Anmelde-Fehlversuche eines Kontos wegräumen; gibt zurück, wie viele es waren.

        Ohne `methods`: nach einer **vollständigen** Anmeldung (R7-1). Der Login-Lockout zählt
        methodenblind — Passwort, PIN und TOTP füllen denselben Topf —, ein Erfolg räumte aber
        nur die eigene Methode weg. Wer sich nach drei vertippten TOTP-Codes per PIN anmeldete,
        trug die drei weiter mit sich, und das Konto war nie wieder „frisch". Eine vollständige
        Anmeldung hat jeden verlangten Faktor bestanden; danach gibt es nichts mehr, wogegen
        die alten Fehlversuche schützen. Die eigenen Töpfe (`NICHT_LOGIN_METHODEN`) bleiben:
        Sie gehören zu Vorgängen NACH der Anmeldung.

        Mit `methods`: nur diese. Der Selbstbedienungs-Reset (R4-13) räumt `("password",)`:
        Er beweist Zugriff aufs Postfach und ersetzt das Passwort — über PIN und TOTP sagt er
        nichts. Räumte er auch deren Fehlversuche, bekäme jeder mit Zugriff aufs Postfach bei
        jedem Reset frische Rateversuche gegen den zweiten Faktor.

        Gezählt wurde unter der Kennung, die jemand eingetippt hat — Benutzername ODER E-Mail,
        bei einer Verzeichnis-Anmeldung auch der Name dort (G5). Geräumt wird deshalb unter allen
        (`Store.zaehl_kennungen`).
        """
        u = self.store.get_user(user_id)
        if not u:
            return 0
        weg = 0
        # Die Serie (B2-6): Eine vollständige Anmeldung beendet sie ganz. Ein Passwort-Reset
        # die Anteile der ersten Faktoren (`_SERIE_RESET_ARTEN`), nicht den zweiten — derselbe
        # Grund wie unten (R4-13): Der Selbstbedienungs-Reset beweist das Postfach, nicht den
        # zweiten Faktor. Räumte er die TOTP-Fehlgriffe mit, bekäme jeder mit Postfach und
        # Passwort je Reset eine frische Serie gegen TOTP (gemessen im Angriff auf B2-6). Der
        # Betreiber räumt ganz (`_serie_beenden`, Panel-Reset, `tinysesam unlock`).
        #
        # Die Serie wird bewusst OHNE Grenze a geräumt, auch wenn sie vor dem Beitritt der
        # Kennung begann (G2, Option A): Sie hat keine IP und schützt nur den, dem die Kennung
        # JETZT gehört — vor dem Beitritt schützte sie kein Konto, Räumen nimmt also niemandem
        # Schutz und wäscht keine Drosselung einer IP. Eine Grenze in der Zeit ginge auch gar
        # nicht: Die Serie kennt keine Einzelzeiten, und eine vor dem Beitritt begonnene Serie
        # könnte der neue Inhaber sonst mit keiner Anmeldung mehr beenden (Dauersperre).
        arten = None if methods is None else tuple(
            set(methods) | (set(self._SERIE_RESET_ARTEN) if "password" in methods else set()))
        for kennung in self.store.zaehl_kennungen(user_id):
            self.store.fehlserie_loeschen(kennung, arten=arten)
        # Das Fenster ab dem Beitritt der Kennung (Grenze a, G2): Sonst räumte die erste
        # vollständige Anmeldung auch die Fehlversuche, die ein Fremder VOR der Anlage, dem
        # Umbenennen oder dem Adresswechsel unter derselben Kennung gemacht hatte — auch aus der
        # Drosselung seiner IP. Bis 2026-09-26 war die Grenze die Anlage des Kontos für jede
        # Kennung; sie ist jetzt nur noch der Rückfall für den Bestand ohne Wasserlinie.
        # Der Verzeichnisname (G5) hat keine Wasserlinie: Sein Fenster räumt die Anmeldung selbst
        # (`_record_login`), hier nur die Serie.
        since = int(u["created_at"] or 0)
        for kennung, (ab_id, _) in self.store.kennung_grenzen(u).items():
            grenze = {"seit": since} if ab_id is None else {"ab_id": ab_id}
            ab = since if ab_id is None else 0
            if methods is None:
                ohne = security.NICHT_LOGIN_METHODEN
                weg += self.store.count_fails(ab, username=kennung, exclude_methods=ohne, ab_id=ab_id)
                self.store.clear_fails(username=kennung, exclude_methods=ohne, **grenze)
            else:
                for m in methods:
                    weg += self.store.count_fails(ab, username=kennung, method=m, ab_id=ab_id)
                    self.store.clear_fails(username=kennung, method=m, **grenze)
        return weg

    def _serie_beenden(self, user_id) -> int:
        """Die Serie eines Kontos ganz beenden (B2-6) — der Weg des Betreibers (Panel-Reset).

        Unter Name, Adresse und dem Namen im Verzeichnis (G5, `Store.zaehl_kennungen`): gezählt
        wird unter dem, was jemand eingetippt hat."""
        return sum(self.store.fehlserie_loeschen(k) for k in self.store.zaehl_kennungen(user_id))

    def _fehl_grund(self, username, method=None) -> str:
        """Warum ist die Anmeldung gescheitert — für das Protokoll, nicht für die Antwort."""
        if method == "resource":
            # Der Pseudo-Name `res:<name>` ist nie ein Konto. `kein_konto` stand deshalb bei
            # JEDEM Fehlgriff an einer Bereichs-PIN — eine Zeile, die niemand auswerten kann.
            return "falsches_bereichsgeheimnis"
        u = self.find_user(username)
        if not u:
            return "kein_konto"
        if u["disabled"]:
            return "konto_gesperrt"
        if not self.store.get_password_hash(u["id"]) and not self.store.has_pin(u["id"]):
            return "kein_passwort_gesetzt"
        return "falsches_geheimnis"

    def audit(self, event, username=None, ip=None, detail=None):
        """Einen Vorgang ins Audit-Log schreiben. `detail` nimmt alles, was später die Frage „warum" beantwortet.

        Was der Aufrufer nicht nennt, ergänzt `audit()` aus der laufenden Anfrage (B5-02): die
        IP, das angemeldete Konto als `username`, wenn keins genannt ist, und `akteur=<name>` im
        Detail, wenn das angemeldete Konto ein ANDERES ist als das betroffene — der Admin, der
        einem fremden Konto einen Key ausstellt. `username` ist damit immer das Konto, um das es
        geht; `tinysesam audit --user X` findet auch das, was andere an X getan haben.
        """
        a = _ANFRAGE.get()
        if a:
            if ip is None:
                ip = a.get("ip")
            akteur = a.get("akteur")
            if akteur:
                if username is None:
                    username = akteur
                elif str(username).lower() != str(akteur).lower():
                    detail = f"{detail} akteur={akteur}" if detail else f"akteur={akteur}"
        self.store.audit_log(event, username, ip, detail)

    def _kontoname(self, user_id) -> Optional[str]:
        """Der Benutzername zu einer ID — für Audit-Zeilen, die sonst nur `user=<id>` trügen."""
        u = self.store.get_user(user_id) if user_id is not None else None
        return str(u["username"]) if u else None

    def _anfrage_merken(self, request, u=None) -> None:
        """IP und angemeldetes Konto der laufenden Anfrage für `audit()` festhalten (`_ANFRAGE`)."""
        try:
            ip = self.client_ip(request)
        except Exception:        # Attrappe ohne Header/Client — dann eben ohne IP
            ip = None
        _ANFRAGE.set({"ip": ip, "akteur": str(u["username"]) if u else None})

    def gc(self, attempts_older_than_sec: int = 86400) -> dict:
        """Aufräumen: abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte
        Login-Versuche. Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen.
        Das Audit-Log nur, wenn `audit_retention_days` eine Frist setzt (B5-11) — dann steht
        die Zahl unter `audit`. Gibt Anzahl gelöschter Zeilen je Bereich: `unverified_accounts`,
        `sessions`, `flow`, `magic_tokens`, `resource_unlocks`, `login_attempts`,
        `failure_series` (bis 0.21.x `fehlserien`), gegebenenfalls `audit`.
        `attempts_older_than_sec` liegt zwischen 0 (alle Fehlversuche) und zehn Jahren in
        Sekunden, sonst `ValueError`, bevor irgendetwas gelöscht wird."""
        older = _jetzt() - _versuchsfrist(attempts_older_than_sec)
        # VOR den Tokens: Das Merkmal „nie bestätigt" ist der abgelaufene Bestätigungstoken —
        # räumt `gc_magic_tokens` ihn zuerst weg, ist das Konto nicht mehr zu erkennen (R4-09).
        # Ohne diesen Schritt blieb eine Adresse, die jemand fremdes registriert und nie
        # bestätigt hatte, für immer belegt: Der echte Inhaber bekam „E-Mail vergeben".
        # Dieselbe Schleife wie `tinysesam gc` — sie steht im Store, damit beide über den einen
        # Löschweg gehen (H-13, Integrationsfunde 12/18). Vorher hatte `gc()` eine eigene Kopie,
        # die das Konto an der Anonymisierung vorbei löschte.
        zahlen = {
            "unverified_accounts": self.store.gc_unbestaetigte_konten(),
            "sessions": self.store.gc_sessions(),
            "flow": self.store.gc_flow(),
            "magic_tokens": self.store.gc_magic_tokens(),
            "resource_unlocks": self.store.gc_resource_unlocks(),
            "login_attempts": self.store.gc_attempts(older),
            # Nicht ausgelöste Serien nach 90 Tagen Ruhe; ausgelöste bleiben (B2-6).
            "failure_series": self.store.gc_fehlserien(
                _jetzt() - 90 * 86400, self._sec("account_max_consecutive_failures")),
        }
        tage = int(self.cfg.audit_retention_days or 0)
        if tage > 0:
            zahlen["audit"] = self.store.gc_audit(_jetzt() - tage * 86400)
        return zahlen

    def version(self) -> str:
        """Die laufende Version — fürs Panel. TinySesam aktualisiert sich nicht selbst;
        das erledigt, wer es installiert hat (gepinnter Tag / Wheel eines Releases)."""
        from . import current_version
        return current_version()

    # ---------- Forward-Auth (Reverse-Proxy) ----------
    #: Vorgabe: der Satz, den Authelia/Traefik-Aufbauten erwarten.
    #: `Remote-Id` ist die Konto-ID — der einzige Wert, der eine Umbenennung und einen Mailwechsel
    #: übersteht (PO-Entscheid 2026-09-25: „alles an die ID hängen"). Eine App, die Nutzer darüber
    #: zuordnet, verwechselt nach einer Änderung niemanden.
    FORWARD_HEADERS_DEFAULT = {"user": "Remote-User", "name": "Remote-Name",
                               "email": "Remote-Email", "groups": "Remote-Groups", "id": "Remote-Id"}

    def _forward_response_headers(self, user) -> dict:
        """Die Header, die der Proxy bei einer erfolgreichen Prüfung an die App weiterreicht.

        `config.forward_headers` ist die **vollständige** Liste, nicht eine Ergänzung: Wer nur
        `{"user": "X-WEBAUTH-USER"}` setzt, verschickt auch nur den einen Header — so ist „ich will
        die E-Mail-Adresse nicht rausgeben" eine Weglassung und kein zweiter Schalter. Ein Feld darf
        auf mehrere Namen zeigen, wenn eine App den einen und ein Zwischenstück den anderen liest.
        """
        if any(z < " " or z == "\x7f" for z in str(user["username"] or "")):
            # Die Säuberung unten nähme das Zeichen heraus und schickte den Namen eines ANDEREN
            # Kontos (`chefin\x01` → `chefin`). Fail-closed: lieber keine Freigabe als eine
            # fremde Identität. Genau die Zeichen, die `_header_wert` entfernt (C0, DEL) — ein
            # ZWNJ in einem persischen Bestandsnamen geht verlustfrei durch und kollidiert nicht
            # (Gegenprüfung). Neue Namen lässt `create_user` so gar nicht mehr zu.
            security.seclog.warning("forward-auth abgewiesen: Kontoname mit Steuerzeichen (user_id=%s)",
                                    user["id"])
            raise HTTPException(403, self.t("api.name_invalid"))
        werte = self._forward_werte(user)
        out = {}
        for feld, namen in (self.cfg.forward_headers or self.FORWARD_HEADERS_DEFAULT).items():
            for name in ([namen] if isinstance(namen, str) else namen):
                out[name] = self._header_wert(werte[feld])
        return out

    def _forward_werte(self, user) -> dict:
        """Die Werte hinter den Forward-Auth-Headern und den Claims des Gate-Tokens — EINE Quelle,
        damit der Proxy auf beiden Wegen dieselbe Identität weiterreicht."""
        return {
            "id": str(user["id"]),
            "user": str(user["username"] or ""),
            "name": str(user["display_name"] or user["username"] or ""),
            "email": str(user["email"] or ""),
            "groups": ",".join(self.user_roles(user) + (["admin"] if user["is_admin"] else [])),
        }

    def gate_public_key(self) -> str:
        """Der öffentliche Schlüssel der Gate-Token (ADR-9): 32 Rohbytes, Base64 — der Wert für
        `sign_key` in Caddys `jwtauth` (mit `sign_alg EdDSA`). Öffentlich, kein Geheimnis.

        Er folgt dem Grundschlüssel der Installation (`TINYSESAM_SECRETS_KEY`, `secrets_key_file`
        bzw. `<db>.key`). Wird der gewechselt, braucht der Proxy diesen Wert neu."""
        from . import gate as _gate
        return _gate.oeffentlich_b64(self._gate_schluessel)

    def gate_issuer(self) -> str:
        """`iss` der Gate-Token: `base_url` ohne Schrägstrich am Ende, ohne sie `"tinysesam"`.
        Fest statt aus der Anfrage abgeleitet — der Proxy vergleicht es mit seiner Konfiguration."""
        return (security.normalisiere_basis(str(self.cfg.base_url or "").strip()) or "").rstrip("/") or "tinysesam"

    def _gate_hosts(self) -> set:
        """Hosts, für die ein Gate-Token ausgestellt wird: die geschützten (`trusted_redirect_hosts`,
        `oidc_clients`) und der eigene aus `base_url`. Für jeden anderen nicht — `X-Forwarded-Host`
        kommt vom Aufrufer, und ein Token für einen Host, den diese Installation gar nicht schützt,
        hätte keinen Zweck ausser dem eines Angreifers."""
        from urllib.parse import urlsplit
        hosts = {str(h).strip().lower().rstrip(".") for h in (self.cfg.trusted_redirect_hosts or []) if h}
        hosts |= {str(h).strip().lower().rstrip(".") for h in (self.cfg.oidc_clients or {}) if h}
        eigen = urlsplit(self.gate_issuer()).hostname
        if eigen:
            hosts.add(eigen.lower())
        return hosts

    _GATE_LINK_COOKIE = "__Host-tinysesam_link"
    _GATE_LINKFLOW_COOKIE = "__Host-tinysesam_linkflow"

    def _gate_link_sitzung(self, request, host: str):
        """Die Sitzungszeile hinter dem Verbindungs-Cookie dieses App-Hosts (T-26) — oder None.

        Das Cookie gilt nur für den Host, für den es ausgestellt wurde: Die Zeile in `gate_link` trägt
        ihn, und ein Cookie, das an einem anderen Host auftaucht, findet nichts. Die Sitzung selbst wird
        mit denselben Regeln geprüft wie über das eigene Cookie (Ablauf, Inaktivität, OIDC-Nachprüfung)."""
        if not self.cfg.gate_link_enabled or not host:
            return None
        roh = request.cookies.get(self._GATE_LINK_COOKIE) or ""
        if not roh:
            return None
        handle = self.store.gate_link_handle(self.store.session_hash(roh), host)
        if not handle:
            return None
        s = self.store.get_session_by_handle(handle)
        if s is not None and not self._oidc_nachpruefen(s):
            return None
        return s

    def _gate_sitzung(self, request, host: str = ""):
        """Die Sitzung dieser Anfrage für das Gate: das eigene Cookie, sonst die Verbindung des Hosts."""
        return self._session_from_request(request) or self._gate_link_sitzung(request, host)

    def _gate_set_cookie(self, response, name: str, wert: str, max_age: int) -> None:
        """Ein host-only Cookie unter `__Host-` — Secure, Path=/, ohne Domain (sonst verwirft es der
        Browser). Mit `max_age=0` löscht es."""
        response.headers.append("set-cookie", f"{name}={wert}; Path=/; Max-Age={int(max_age)}; "
                                              "Secure; HttpOnly; SameSite=Lax")

    def _gate_link_url(self, host: str, orig_url: str, request=None) -> str:
        """Wohin ein App-Host ohne Verbindung geschickt wird: auf SEINEN `/.tinysesam/start` (T-26)."""
        from urllib.parse import quote, urlsplit
        o = urlsplit(orig_url or "")
        schema = o.scheme if o.scheme in ("http", "https") else "https"
        netloc = o.netloc or host
        rest = (o.path or "/") + (("?" + o.query) if o.query else "")
        return f"{schema}://{netloc}/.tinysesam/start?rd={quote(rest, safe='')}"

    def _gate_cookie(self, request, user, orig_url: str, rollen_gruppen, sitzung=None) -> Optional[str]:
        """Der `Set-Cookie`-Wert mit einem frischen Gate-Token — oder None.

        Nur für eine volle SITZUNG desselben Kontos, nie für einen API-Key: Ein Automat hält
        kein Cookie, und ein Token aus einem Key lebte im Browser weiter, nachdem der Key
        widerrufen ist. Nur für einen geschützten Host (`_gate_hosts`). Die verlangten Rollen
        stehen in der Zielgruppe (`gate.zielgruppe`), damit ein Token aus einer Prüfung ohne
        Rollen an einem Pfad mit Rollen nicht gilt."""
        if not self.cfg.gate_token_enabled:
            return None
        from urllib.parse import urlsplit
        from . import gate as _gate
        host = (urlsplit(orig_url or "").hostname or "").lower().rstrip(".")
        if not host or host not in self._gate_hosts():
            return None
        s = sitzung if sitzung is not None else self._session_from_request(request)
        if not s or not s["mfa_ok"] or s["user_id"] != user["id"]:
            return None
        felder = self.cfg.forward_headers or self.FORWARD_HEADERS_DEFAULT
        werte = self._forward_werte(user)
        claims = {feld: "".join(z for z in werte[feld] if z >= " " and z != "\x7f") for feld in felder}
        ttl = int(self.cfg.gate_token_ttl_sec)
        token = _gate.ausstellen(self._gate_schluessel, iss=self.gate_issuer(),
                                 aud=_gate.zielgruppe(host, rollen_gruppen), sub=str(user["id"]),
                                 claims=claims, ttl=ttl, jetzt=_jetzt())
        return _gate.set_cookie(self.cfg.gate_cookie_name, token, ttl)

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

    def _forwarded_url(self, request: Request) -> str:
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

    def _forward_app(self, url_oder_host: str) -> dict:
        """Die Einstellungen des Gates für eine Anwendung (T-21): `name` und `login`, aus
        `forward_apps[host]` mit `forward_login` als Rückfall. Der Host ohne Port, klein."""
        from urllib.parse import urlsplit
        roh = str(url_oder_host or "")
        host = ((urlsplit(roh).hostname if "://" in roh else roh.split(":", 1)[0]) or "").lower().rstrip(".")
        e = {}
        for h, werte in (self.cfg.forward_apps or {}).items():
            if str(h).strip().lower().rstrip(".") == host:
                e = dict(werte or {})
                break
        return {"name": str(e.get("name") or ""), "login": str(e.get("login") or self.cfg.forward_login),
                "logout": str(e.get("logout") or self.cfg.forward_logout)}

    def _gate_host(self, request) -> str:
        """Der geschützte Host, an den diese Anfrage ging (über den Proxy: X-Forwarded-Host, sonst
        Host) — oder "", wenn diese Installation ihn nicht schützt. Für die Abmelde-Wege unter
        `/.tinysesam/`: Sie wirken auf das Gate-Cookie GENAU dieses Hosts."""
        h = request.headers
        roh = (h.get("x-forwarded-host") or h.get("host") or "").split(",")[0].strip()
        host = roh.rsplit(":", 1)[0] if roh.count(":") == 1 else roh
        host = host.lower().rstrip(".")
        return host if host and host in self._gate_hosts() else ""

    def _gate_cookie_loeschen(self, response) -> None:
        """Das Gate-Cookie dieses Hosts löschen (Attribute wie beim Setzen, sonst gilt es nicht)."""
        response.headers.append("set-cookie", f"{self.cfg.gate_cookie_name}=; Path=/; Max-Age=0; "
                                              "Secure; HttpOnly; SameSite=Lax")

    @staticmethod
    def _ist_seitenaufruf(request: Optional[Request]) -> bool:
        """Lädt der Browser hier eine SEITE (und nicht ein Skript, ein Bild, ein XHR)?

        `Sec-Fetch-Mode: navigate` sagt es ausdrücklich; der Proxy reicht die Header der Anfrage an
        `/auth/forward` weiter. Ohne den Header (ältere Browser, Werkzeuge) zählt `Accept: text/html`.
        Wozu: Nur ein Seitenaufruf darf direkt zum Provider. Ein Hintergrund-Abruf, der dorthin
        umgeleitet wird, kann mit der Anmeldeseite des Providers nichts anfangen — und jeder
        begänne einen eigenen OIDC-Flow (Datenbankzeile, Rate-Limit)."""
        if request is None:
            return False
        h = request.headers
        modus = (h.get("sec-fetch-mode") or "").strip().lower()
        if modus:
            return modus == "navigate"
        return "text/html" in (h.get("accept") or "").lower()

    def _forward_login_url(self, orig_url: str, request: Optional[Request] = None,
                           direkt: bool = False) -> str:
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
            kandidat = f"{self._login_schema(proto, host)}://{host}" if host else ""
        base = self.public_base(candidate=kandidat)
        if base and not self.cfg.cookie_domain:
            # Host aus orig_url, nicht erneut aus den Headern: forwarded_url() hat X-Original-URL
            # und X-Forwarded-* bereits ausgewertet. Die Whitelist trusted_redirect_hosts ist
            # zugleich der Schutz — ein gefälschter X-Forwarded-Host kann die Login-URL nicht
            # auf einen fremden Host umbiegen.
            o = urlsplit(orig_url or "")
            if (o.scheme in ("http", "https") and o.hostname
                    and o.hostname != (urlsplit(base).hostname or "")
                    and o.hostname in (self.cfg.trusted_redirect_hosts or [])):
                # Durch dieselbe Formprüfung wie jede andere Basis (R5-1): `o.netloc` ist roh und
                # trug eine Benutzerangabe (`https://fremd.example@app.example.com`) unverändert
                # in die Login-URL; das Schema kam ungeprüft aus X-Forwarded-Proto/X-Original-URL.
                base = security.normalisiere_basis(
                    f"{self._login_schema(o.scheme, o.hostname)}://{o.netloc}") or base
        # Ursprung der Basis + Pfad der Login-Seite MIT Präfix (T-15): Die Basis kann den Präfix
        # schon tragen (base_url) oder gar nicht (abgeleitet, neu gebaut für den angefragten Host) —
        # `browser_path()` setzt ihn aus der einen Quelle, deshalb zählt von der Basis nur Schema und Host.
        ursprung = ""
        if base:
            teile = urlsplit(str(base))
            ursprung = f"{teile.scheme}://{teile.netloc}"
        # `direkt` (T-21, und jede Nachprüfung beim Provider, B-2): gleich in die OIDC-Runde statt
        # auf die Login-Seite.
        pfad = "/auth/oidc/start" if direkt else self.cfg.login_path
        ziel = f"{ursprung}{self.browser_path(request, pfad)}?next={quote(orig_url or '/', safe='')}"
        # Schützt diese Installation mehrere Anwendungen, gehört der Ziel-Host in die Login-URL:
        # Nur so weiss `/auth/oidc/start`, für welchen Client es die Runde beginnen muss (T-14).
        # Ohne die Angabe liefe jede Anmeldung über den Vorgabe-Client, und die Freigabe, die der
        # Provider je Client vergibt, wäre wirkungslos.
        anwendung = self._oidc_anwendung(orig_url)
        if anwendung:
            ziel += f"&app={quote(anwendung, safe='')}"
        return ziel

    def _login_schema(self, schema: str, host: str) -> str:
        """Das Schema der Login-URL, wenn es aus der Anfrage kommt (R5-1).

        Ohne `base_url` stammt es aus `X-Forwarded-Proto` bzw. `X-Original-URL` — Eingaben, die
        nicht nur der Proxy setzt. Mit `cookie_secure=True` ist `http` dort nie richtig: Das
        Sitzungs-Cookie käme über http gar nicht an, das Passwort aber ginge im Klartext über das
        Netz. Also https, ausser bei Loopback (lokaler Aufbau ohne Zertifikat)."""
        schema = (schema or "").strip().lower()
        if schema not in ("http", "https"):
            schema = "https"
        if schema == "http" and self.cfg.cookie_secure:
            from urllib.parse import urlsplit
            try:
                name = urlsplit("//" + (host or "")).hostname or ""
            except ValueError:
                name = ""
            if not security.eigener_host(name):      # ohne Liste: nur Loopback zählt
                schema = "https"
        return schema

    # ---------- Freigaben je Anwendung (T-14) ----------
    def _oidc_anwendung(self, url_oder_host: str) -> str:
        """Der Client-Schlüssel für diese Adresse — "" wenn diese Installation nur eine
        Anwendung schützt. Der leere Rückgabewert ist Absicht: Er hält jede Aufrufstelle
        wortgleich beim Verhalten von 0.18.0, solange `oidc_clients` leer ist."""
        from urllib.parse import urlsplit
        registry = getattr(self, "oidc_clients", None)
        if not registry or not registry.mehrere:
            return ""
        roh = str(url_oder_host or "")
        host = urlsplit(roh).hostname if "://" in roh else roh
        return registry.schluessel_fuer_host(host or "")

    def _vermerke_oidc_freigabe(self, token: str, client: str, rollen=None) -> None:
        """Der Provider hat für diese Anwendung zugestimmt — an der Sitzung vermerken."""
        self.store.put_oidc_grant(self.store.session_hash(token), client or "*",
                                  _jetzt(), rollen)

    def _oidc_freigabe_gueltig(self, token_hash: str, client: str) -> tuple:
        """Darf diese Sitzung in diese Anwendung? Rückgabe `(ja, grund)`.

        `grund` ist "" bei Ja, sonst "fehlt" (der Provider hat für diese Anwendung nie
        zugestimmt) oder "veraltet" (die Zustimmung ist älter als `oidc_revalidate_minutes`).
        Der Unterschied zählt: Beim ersten Fall war der Mensch hier noch nie, beim zweiten
        läuft nur die Frist ab — und der Sprung über den Provider ist dann in aller Regel
        unsichtbar, weil dessen Sitzung weiterbesteht.

        Ohne mehrere Clients ist die Antwort immer Ja. Eine Installation mit einem Client
        verhält sich damit exakt wie 0.18.0, auch wenn `oidc_revalidate_minutes` gesetzt ist:
        Es gibt dort keine Freigabe je Anwendung, die ablaufen könnte.
        """
        registry = getattr(self, "oidc_clients", None)
        if not registry or not registry.mehrere:
            return True, ""
        grant = self.store.get_oidc_grant(token_hash, client or "*")
        if not grant:
            return False, "fehlt"
        frist = int(self.cfg.oidc_revalidate_minutes or 0) * 60
        if frist and (_jetzt() - int(grant["checked_at"])) > frist:
            return False, "veraltet"
        return True, ""

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
    PAGES = ("account", "error", "forgot", "gate_logged_out", "gate_logout", "gateway_home", "login", "logout",
             "magic_confirm", "magic_invalid",
              "magic_request", "pin", "reauth", "register", "reset", "resource_unlock", "totp",
              "totp_setup")

    def set_template(self, name, fn):
        """Eine eingebaute Seite durch einen eigenen Renderer ersetzen: fn(auth, ctx) -> str | Response.

        Namen: siehe `TinySesam.PAGES` (je nach aktivierten Features erscheinen nicht alle).
        String → HTML mit Status; Response → 1:1. Ein unbekannter Name ist ein Fehler, kein
        stilles Nichts.

        Unter einem Unterpfad (T-15): `ctx["prefix"]` ist der Präfix, den ein Pfad von TinySesam
        im Browser braucht (`f"{ctx['prefix']}/auth/logout"`; bis 0.21.x `ctx["praefix"]`).
        `ctx["next"]` und `ctx["action"]` sind schon Pfade des Browsers; `ctx["admin_path"]` ist
        ein Pfad der App (Präfix davor). Die Seite `magic_confirm` bekommt `ctx["purpose"]`
        (`login`, `verify_email`, `email_change`; bis 0.21.x `ctx["zweck"]`). Welche Schlüssel
        eine Seite bekommt, steht im Docstring ihres eingebauten Renderers
        (`tinysesam/templates.py`) — seit 0.22.0 alle englisch.
        """
        if name not in self.PAGES:
            raise ConfigError(f"Unbekannte Seite {name!r} — es gibt: {', '.join(self.PAGES)}")
        self.templates.set(name, fn)

    def csrf_token(self, request: Optional[Request] = None) -> str:
        """Das CSRF-Token dieses Browsers — vorhandenes Cookie wiederverwenden, sonst neu würfeln.

        Setzt KEIN Cookie. Ein neu gewürfeltes Token merkt sich die Anfrage: Ein späteres
        `ensure_csrf(request, antwort)` setzt genau dieses (der Weg für fertige Antworten wie
        Jinjas `TemplateResponse` — nicht für eine, die an- oder abmeldet, s. `ensure_csrf`). Ein
        Cookie, das nicht wie ein Token aussieht, zählt nicht."""
        if request is not None and self.cfg.csrf_enabled:
            return self._csrf_der_anfrage(request)[0]
        return secrets.token_urlsafe(24)

    def render_page(self, template, status=200, request: Optional[Request] = None, **ctx) -> Response:
        """`request` mitgeben, wo es eins gibt: dann bleibt ein bereits gesetztes CSRF-Token gültig.
        Ohne `request` entsteht ein neues — das überschreibt das Cookie und macht *andere* offene
        Formulare ungültig (klassische „Formular abgelaufen"-Falle)."""
        tok, fresh = None, False
        if request is not None:
            self._pruefe_secure_flag(request)
        if self.cfg.csrf_enabled:
            tok, fresh = self._csrf_der_anfrage(request)
            ctx.setdefault("csrf", tok)      # Templates betten <input name=_csrf> ein / JS liest das Cookie
        # Ein Nonce je Antwort. Die eingebauten Seiten kommen ohne Inline-Handler/style= aus;
        # der Nonce wandert zentral in jedes <script>/<style> (kein Faedeln durch die Templates)
        # und in den CSP-Header. Ein Override, das eine Response liefert, bleibt unberuehrt —
        # es setzt seine CSP selbst; ctx['nonce'] steht ihm zur Verfuegung.
        nonce = secrets.token_urlsafe(16)
        ctx.setdefault("nonce", nonce)
        # Für eigene Templates (set_template): der Präfix, den App-Pfade im Browser brauchen (T-15).
        ctx.setdefault("prefix", self._praefix(request))
        eingebaut = not self.templates.ueberschrieben(template)
        out = self.templates.render(template, self, ctx)
        if isinstance(out, Response):
            resp = out
        else:
            # Die eingebauten Seiten schreiben vor jeden Pfad der App `__TS_P__` (Formulare, Links,
            # fetch-Aufrufe) — hier wird daraus der Montage-Präfix (T-15). NUR bei ihnen: Die Ausgabe
            # eines eigenen Templates bleibt byte-gleich (Gegenprüfung: ein Platzhalter in Daten
            # hätte dort ein geprüftes Ziel nachträglich verändert).
            if eingebaut:
                out = str(out).replace(_PRAEFIX_PLATZHALTER, ctx["prefix"])
            resp = HTMLResponse(_inject_nonce(out, nonce), status_code=status)
            policy = self._csp_header(nonce)
            if policy:
                resp.headers.setdefault("Content-Security-Policy", policy)
        if tok is not None and fresh:
            self._csrf_cookie_setzen(resp, tok)
        # Auch hier, nicht nur in der Route: Fehlerseiten aus `install_error_pages` laufen an
        # keiner TinySesam-Route vorbei und tragen sonst keine einzige Härtungskopfzeile.
        return self._kopfzeilen(resp)

    def _kopfzeilen(self, resp: Response) -> Response:
        """Die Härtungskopfzeilen jeder TinySesam-Antwort (R8-1, R8-5, R4-08, R5-2).

        Bis 0.19.0 trug nur die gerenderte Seite eine CSP; alles andere — Admin-Panel, JSON-API,
        Umleitungen mit Token in der Adresse — kam ohne jede Kopfzeile. `setdefault`, damit eine
        Route (oder ein Override), die bewusst etwas anderes setzt, gewinnt.

        * `nosniff` — eine JSON-Antwort mit Benutzereingabe darin wird nie als HTML gedeutet.
        * `Referrer-Policy: same-origin` — Reset-, Anmelde- und Einladungsseiten tragen das Token
          in der Adresse; ein Bild oder Link nach aussen nähme es sonst als `Referer` mit.
          Bewusst nicht `no-referrer`: Damit setzt der Browser bei jedem gleich-origin-POST
          `Origin: null`, und eine Origin-Prüfung im Proxy davor wiese das Login-Formular ab.
        * `Cache-Control: no-store` + `Vary: Cookie` — die Antworten hängen an der Sitzung
          (Konto, Sitzungsliste, `/auth/me`); ein geteilter Cache davor darf sie weder aufheben
          noch dem nächsten Besucher geben.
        * `X-Frame-Options: SAMEORIGIN` — nur bei `csp='strict'`, deren `frame-ancestors 'self'`
          es für ältere Browser wiederholt. Eine eigene Policy oder `off` (der Proxy setzt die
          CSP) entscheidet selbst, wer einbetten darf; ein festes XFO würde das überstimmen.
        """
        self._kopfzeilen_in(resp.headers)
        return resp

    _secure_flag_gemeldet = False

    def _pruefe_secure_flag(self, request: Request) -> None:
        """`cookie_secure=False`, obwohl der Browser über HTTPS kommt? Einmal laut sagen (F-04).

        Die häufigste Produktionsform ist ein TLS-Proxy vor einer App, die selbst nur HTTP sieht.
        Wer dort `cookie_secure=False` stehen lässt (weil es lokal ohne Zertifikat nötig war),
        verschickt das Sitzungs-Cookie ohne Secure-Flag — und nichts meldete das: Die
        Konfigurationsprüfung schweigt bewusst (`base_url` ist keine Aussage über den
        Transport), und das Panel warnt nur bei fehlendem HTTPS. Der Request selbst weiss es
        aber: Schema `https` oder `X-Forwarded-Proto: https`. Loopback zählt hier NICHT als
        sicher (anders als in `_is_secure`) — lokal ohne Zertifikat ist genau der erlaubte Fall.
        Eine Zeile je Instanz, damit das Log nicht vollläuft."""
        if self.cfg.cookie_secure or self._secure_flag_gemeldet:
            return
        proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        if request.url.scheme != "https" and proto != "https":
            return
        self._secure_flag_gemeldet = True
        security.seclog.warning(
            "Konfiguration: cookie_secure=False, aber der Browser kommt über HTTPS — Sitzungs- und "
            "CSRF-Cookie gehen ohne Secure-Flag hinaus und damit auch über jede Klartext-Verbindung "
            "zum selben Host. cookie_secure=True setzen (das ist die Vorgabe).")

    def _kopfzeilen_fehler(self, exc) -> None:
        """Dieselben Kopfzeilen für eine `HTTPException` aus einer TinySesam-Route.

        Die Antwort baut dort der Exception-Handler des Gastgebers (oder Starlettes Vorgabe) —
        die Routen-Klasse bekommt sie nie zu sehen. Beide übernehmen aber `exc.headers`; also
        wandern die Kopfzeilen dort hinein. Das 401 von `/auth/admin` ohne Sitzung ist genau so
        eine Antwort.

        `exc.headers` bleibt ein gewöhnliches dict mit den Schlüsseln, wie die Route sie schrieb.
        Ein Umweg über `MutableHeaders` schrieb sie klein — ein Handler des Gastgebers mit
        `exc.headers["Location"]` fand die Umleitung dann nicht mehr und lieferte einen 307 ohne
        Ziel (A1). Deshalb: Groß-/Kleinschreibung nur beim Nachsehen ignorieren, nie beim Schreiben.
        """
        exc.headers = dict(exc.headers or {})
        self._kopfzeilen_in(_DictKopfzeilen(exc.headers))

    def _kopfzeilen_in(self, h) -> None:
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("Cache-Control", "no-store")
        vary = h.get("vary", "")
        if "cookie" not in [v.strip().lower() for v in vary.split(",")]:
            h["Vary"] = f"{vary}, Cookie" if vary.strip() else "Cookie"
        if ((self.cfg.csp or "").strip() == "strict"
                and h.get("content-type", "").startswith("text/html")):
            h.setdefault("X-Frame-Options", "SAMEORIGIN")

    def _csp_header(self, nonce: str) -> str:
        """Die CSP für die eigenen Seiten. 'strict' = alles same-origin, Skript/Style nur per
        Nonce (kein 'unsafe-inline'); 'off' = kein Header; sonst der eigene String mit {nonce}."""
        csp = (self.cfg.csp or "").strip()
        if not csp or csp == "off":
            return ""
        if csp == "strict":
            # Hintergrundbilder von https-Adressen (brand_backgrounds) — genau deren Herkunft, nichts darüber hinaus.
            fremd = sorted({"https://" + b[len("https://"):].split("/", 1)[0].split("?", 1)[0]
                            for b in (getattr(self.cfg, "brand_backgrounds", None) or []) if b.startswith("https://")})
            return ("default-src 'self'; "
                    f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                    f"img-src 'self' data:{''.join(' ' + h for h in fremd)}; base-uri 'none'; "
                    "frame-ancestors 'self'; object-src 'none'")
        return csp.replace("{nonce}", nonce)

    def public_base(self, request: Optional[Request] = None, candidate: str = "") -> str:
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
        `_forward_login_url()` fragt ebenfalls hier (mit seiner einen, im Docstring dort
        begründeten Ausnahme). Zwei Fassungen derselben Regel liefen auseinander, sobald mehrere
        eigene Namen im Spiel waren: Die Routen hielten `base_url`, der Weg über die Methoden
        ließ den `Host`-Header auswählen — und die Lücke saß genau im Unterschied.

        `candidate` erlaubt einer Route, eine anders abgeleitete Basis prüfen zu lassen (SAML
        wertet `X-Forwarded-Proto/Host` selbst aus) — geprüft wird sie nach derselben Regel.

        **Der Pfadanteil gehört dazu**, aus beiden Quellen: `base_url="https://example.com/sso"`
        behält ihr Präfix, und eine abgeleitete Basis übernimmt den `root_path` des Servers
        (`security.sichere_basis`). Ohne das bekam eine unter einem Unterpfad montierte App
        Mail-Links ohne Präfix — und wer ihn danach noch einmal anhängt, Links mit vierfachem.
        Das Ergebnis ist die **fertige** Basis: Es wird nichts mehr daran angefügt.

        Die verschickten Links tragen den Unterpfad über diese Basis; die eingebauten Seiten und
        Umleitungen seit T-15 über `_praefix()`/`browser_path()` — aus derselben `base_url`.

        Wer eine Basis braucht und ohne sie nicht weiterarbeiten darf, nimmt
        `require_public_base()` — diese Methode hier gibt "" zurück und überlässt die
        Entscheidung dem Aufrufer. Genau zwei Stellen dürfen das, weil beide einen tragfähigen
        Rückweg haben: der OIDC-Post-Logout (ohne Basis entfällt der Provider-Umweg, der lokale
        Logout läuft trotzdem) und `_forward_login_url()` (ohne Basis bleibt die Umleitung
        relativ, der Browser löst sie gegen den aufgerufenen Host auf).
        """
        if self.cfg.base_url:
            # Auch die KONFIGURIERTE Basis läuft durch dieselbe Formprüfung wie die abgeleitete
            # (C-7). Vorher sah sie nur `strip().rstrip("/")`: `https://wer:was@auth.example`
            # stand damit in jedem Reset-Link und in jeder Redirect-URI, ein Fragment schnitt
            # den angehängten Token ab. `konfigpruefung` weist beides schon beim Aufbau ab —
            # diese Zeile ist der Boden darunter, denn eine Config lässt sich nach dem
            # Konstruktor noch verändern.
            basis = security.normalisiere_basis(str(self.cfg.base_url))
            if not basis:
                raise StateError(
                    "base_url ist gesetzt, aber keine brauchbare Basis-Adresse: "
                    f"{str(self.cfg.base_url)!r}. Erwartet wird Schema http/https und ein Host, "
                    "ohne Benutzerangabe, Abfrage oder Fragment (erlaubt ist ein Unterpfad, z.B. "
                    "\"https://example.com/sso\"). Geraten wird hier nichts.")
            return basis
        roh = str(candidate or (str(request.base_url) if request is not None else "")).strip()
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

    def require_public_base(self, request: Optional[Request] = None, candidate: str = "") -> str:
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
        basis = self.public_base(request, candidate)
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
        basis = self.public_base(candidate=roh)
        # Ersetzt wird still — aber nicht lautlos: Wer eine andere Adresse übergibt als die, die
        # am Ende im Link steht, hat entweder den Request durchgereicht (dann ist das genau der
        # Schutz) oder sich vertan (dann sucht er sonst lange). Einmal je Adresse, nicht je
        # Anfrage: der Wert kommt bei diesem Muster aus dem `Host`-Header.
        #
        # Verglichen wird die **ganze** Basis, nicht nur der Host (C-5): Eine App unter einem
        # Unterpfad, die `https://auth.example/falsch` übergibt, während `base_url` auf
        # `https://auth.example/sso` steht, bekam vorher keine Zeile — gleicher Host, also
        # schwieg die Stelle. Genau dieser Fall (falsches Präfix → 404 beim Empfänger) ist der,
        # den der CHANGELOG verspricht zu melden.
        _vergleich = security.normalisiere_basis(roh) or roh.rstrip("/")
        if basis and roh and _vergleich != basis \
                and security.einmal_melden("gepruefte_basis:" + _vergleich):
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

    #: Was als Montage-Präfix (`root_path`) in Seiten und Umleitungen darf (T-15). Der Wert kommt
    #: vom ASGI-Server (`--root-path`) oder aus einer Starlette-Montage, nicht vom Browser — er
    #: landet aber unmaskiert in Attributen und Skripten, deshalb nur diese Zeichen.
    _PRAEFIX_FORM = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")

    def _praefix(self, request: Optional[Request]) -> str:
        """Der Präfix, unter dem TinySesams Seiten im Browser liegen, ohne Schrägstrich am Ende.

        Eine Quelle für alle eingebauten Seiten und Umleitungen (T-15): Unter `uvicorn --root-path
        /sso` hinter einem Proxy, der `/sso` abschneidet, oder als `Mount("/sso", app)` zeigten sie
        bis dahin aus der Montage heraus (`/auth/login` statt `/sso/auth/login` → 404).

        **Zuerst der Pfad der `base_url`** — sie ist die öffentliche Adresse von TinySesam und trägt
        den Präfix laut Doku ohnehin. Nur so stimmt der Präfix auch dort, wo die laufende Anfrage
        ihn nicht kennt: in einem Guard der Host-App ausserhalb der TinySesam-Montage (`root_path`
        ist dort leer) und hinter einem Proxy, der ohne `--root-path` abschneidet (Gegenprüfung).
        Ohne `base_url` der `root_path` der Anfrage. Ein Wert in unerwarteter Form wird nicht
        benutzt (laut, einmal) — lieber ein 404 als ein Präfix, der Markup in eine Seite trägt."""
        if self.cfg.base_url:
            from urllib.parse import urlsplit
            roh = urlsplit(self.cfg.base_url).path.rstrip("/")
        elif request is None:
            return ""
        else:
            roh = str(request.scope.get("root_path") or "").rstrip("/")
        if not roh:
            return ""
        if not self._PRAEFIX_FORM.fullmatch(roh):
            if security.einmal_melden("praefix_form"):
                security.seclog.warning("root_path %s hat eine unerwartete Form und wird für Seiten und "
                                        "Umleitungen nicht benutzt (erlaubt: /teil/teil aus A–Z a–z 0–9 . _ ~ -).",
                                        security.fuer_log(roh))
            return ""
        return roh

    def browser_path(self, request: Optional[Request], path: str) -> str:
        """Einen Pfad der App (`/auth/login`, `login_path`, `admin_path`, …) in den Pfad umrechnen,
        den der Browser braucht — mit dem Montage-Präfix davor (T-15).

        Nur für Pfade, die relativ zur App gemeint sind. Ein `next`-Ziel ist schon ein Pfad des
        Browsers (es kommt aus `request.url.path`, und dort steht der Präfix bereits) und bekommt
        keinen zweiten. Absolute URLs und protokoll-relative Angaben bleiben, wie sie sind."""
        p = str(path or "")
        if not p.startswith("/") or p.startswith("//"):
            return p
        return self._praefix(request) + p

    def safe_next(self, next_: str, request: Optional[Request] = None) -> str:
        """?next=-Ziel gegen Open-Redirect absichern (nur relative Pfade bzw. trusted_redirect_hosts).

        Mit `request` bekommt der Rückfall `login_redirect` den Montage-Präfix (T-15); das
        übergebene Ziel selbst bleibt, wie es ist — es ist bereits ein Pfad des Browsers.

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
        rueckfall = self.browser_path(request, self.cfg.login_redirect)
        if _PRAEFIX_PLATZHALTER in str(next_ or ""):
            # Der Platzhalter der eingebauten Seiten hat in einem Ziel nichts verloren: Beim Ersetzen
            # würde `/__TS_P__/evil.example` zu `//evil.example` (Gegenprüfung T-15).
            return rueckfall
        return security.safe_next(next_, rueckfall, hosts or None)

    # ---------- FastAPI-Integration ----------
    def _riegel(self, config: TinySesamConfig, *, beim_aufbau: bool) -> None:
        """Alle Prüfungen, die den Aufbau scheitern lassen — beim Konstruktor und noch einmal vor
        `router()`/`admin_router()` (A2).

        Sie standen bis dahin nur im Konstruktor; `_nachpruefen` kannte nur `konfigpruefung` und
        die Cookie-Felder. Wer danach `auth.cfg.allow_signup = True` setzte, baute neben
        `admin_identifiers=["chef"]` einen Router, in dem sich der erste Besucher als „chef"
        registrierte und Erst-Admin wurde. `beim_aufbau=False` lässt nur `konfigpruefung` weg —
        die hat `_nachpruefen` über `TinySesamConfig._befunde()` schon gefahren, samt Warnungen."""
        if config.login_identifier not in ("username", "email", "both"):
            raise ConfigError("login_identifier muss 'username', 'email' oder 'both' sein")
        if config.login_identifier == "email" and config.allow_signup and not config.signup_require_email:
            raise ConfigError("login_identifier='email' braucht signup_require_email=True — "
                             "sonst entstehen Konten, die sich nicht anmelden können")
        # Alle übrigen Widersprüche auf einmal — beim Aufbau, nicht beim ersten Login. Die
        # Prüfungen oben werfen einzeln, weil jede für sich eine eigene Geschichte erzählt;
        # was danach kommt, sammelt konfigpruefung.py und meldet es gemeinsam. Wer drei Dinge
        # falsch hat, soll sie einmal lesen und nicht dreimal starten.
        if beim_aufbau:
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

    def _nachpruefen(self) -> None:
        """Die Config noch einmal prüfen, bevor aus ihr Routen entstehen (B3-14).

        Der Konstruktor prüft und hält danach eine **Referenz** auf das Config-Objekt. Wer
        dazwischen etwas umstellt (`auth.cfg.cookie_samesite = "Strict"`, `auth.cfg.base_url = ""`),
        umging bisher jeden Wächter — `TinySesamConfig.validate()` gab es dafür, aufgerufen hat es
        niemand. Hier ist der letzte Punkt, an dem ein Fehler noch beim Start auffällt statt beim
        ersten Klick. Warnungen hat der Konstruktor schon gesagt; hier zählt nur, was den Aufbau
        hätte scheitern lassen — und zwar ALLES davon: `konfigpruefung` samt Cookie-Feldern und
        die Riegel des Konstruktors (`_riegel`, A2)."""
        fehler, _ = self.cfg._befunde()
        if not fehler:
            try:
                self._riegel(self.cfg, beim_aufbau=False)
            except ConfigError as e:
                fehler = [str(e)]
        if fehler:
            raise ConfigError("Die Konfiguration wurde nach dem Aufbau geändert und geht so nicht "
                              "auf:\n  - " + "\n  - ".join(fehler))

    def router(self):
        """Der FastAPI-Router mit allen aktivierten Routen. Einmal einbinden, fertig.

        Prüft die Config vorher noch einmal (`_nachpruefen`) — eine nach dem Konstruktor
        kaputt gestellte Config scheitert hier mit `ConfigError`, nicht erst im Betrieb."""
        self._nachpruefen()
        from .router import build_router
        return build_router(self)

    def admin_router(self):
        """Eigenständiger Admin-Router (relative Pfade) — an beliebigem Prefix / Sub-App / Port
        montierbar, oder (admin_ui_enabled=False) nur die JSON-API fürs eigene Panel."""
        self._nachpruefen()
        from .admin import build_admin_router
        return build_admin_router(self)

    def _is_secure(self, request: Request) -> bool:
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
                # Starlettes Standardtext („Not Found“) ist englisch — auf der Seite in der Sprache der
                # Installation, wo es dafür einen Text gibt. Eigene Meldungen bleiben, wie sie sind.
                nachricht = exc.detail
                from http import HTTPStatus as _HS
                try:
                    standard = _HS(exc.status_code).phrase
                except ValueError:
                    standard = None
                if nachricht == standard and f"error.{exc.status_code}" in _messages_der_sprache(self):
                    nachricht = self.t(f"error.{exc.status_code}")
                return self.render_page("error", status=exc.status_code, request=request,
                                       code=exc.status_code, message=nachricht)
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=headers or None)

        @app.exception_handler(Exception)
        async def _handle_500(request, exc):
            if _wants_html(request):
                return self.render_page("error", status=500, request=request, code=500,
                                       message=self.t("error.oops"))
            # Der JSON-Zweig ging an `render_page` vorbei und kam ohne jede Härtungskopfzeile (A2).
            return self._kopfzeilen(JSONResponse({"detail": "internal server error"}, status_code=500))

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
            raise HTTPException(307, headers={"Location": f"{self.browser_path(request, self.cfg.login_path)}?next={nxt}"})
        raise HTTPException(401, self.t("api.not_signed_in"))

    def _deny_stepup(self, request: Request) -> NoReturn:
        # eingeloggt, aber Faktor nicht frisch. Browser → Redirect zu /auth/reauth; sonst 403 + Hinweis-Header.
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.browser_path(request, '/auth/reauth')}?next={nxt}"})
        raise HTTPException(403, self.t("api.stepup"),
                            headers={"X-TinySesam-Reauth": self.browser_path(request, "/auth/reauth")})

    # ---------- Step-up-Frische ----------
    def stepup_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
        """True, wenn die aktuelle Sitzung frisch einen Faktor bestätigt hat (Sudo-Frische)."""
        user = user or self.current_user(request)
        if not user or user.get("_via") == "apikey":
            return False   # maschineller Zugang kann keinen interaktiven Faktor frisch bestätigen
        s = self._session_from_request(request)
        if not s or not s["mfa_ok"]:
            return False
        if self.cfg.stepup_max_age_sec > 0:
            if not s["mfa_at"] or (_jetzt() - s["mfa_at"]) > self.cfg.stepup_max_age_sec:
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
        s = self._session_from_request(request)
        if not s:
            return False
        if self.cfg.stepup_max_age_sec > 0:
            if (_jetzt() - (s["created_at"] or 0)) > self.cfg.stepup_max_age_sec:
                return False
        return True

    def _redirect_factor(self, request: Request, step) -> NoReturn:
        # Browser → Redirect zur Eingabeseite des nächsten Faktors; JSON → 401 + X-TinySesam-Factor.
        if step is None:
            self._deny(request)
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(307, headers={"Location": self.browser_path(request, self._factor_entry(step, request.url.path))})
        raise HTTPException(401, self.t("api.factor"), headers={"X-TinySesam-Factor": step})

    def _enforce_route_chain(self, request: Request, factors, strict) -> dict:
        """Eine Route-Kette (`require(factors=[…])`) durchsetzen — **zusätzlich** zur globalen Regel.

        Eine Route-Kette verschärft, sie unterschreitet nie (PO-Entscheid 2026-09-27, „Angleichen"):
        Erst muss die Sitzung für die GLOBALE Regel voll sein (`mfa_ok`, wie bei `current_user`) —
        eine halbe Sitzung geht zuerst zum fehlenden Schritt der globalen Anmeldung
        (`_next_login_step`). Bis dahin genügte die Liste der Route allein: `factors=["password"]`
        öffnete die Route einer halben Sitzung, deren Konto noch TOTP schuldete, und
        `["pin", "password"]` die eines Kontos mit TOTP, das nur PIN und Passwort erbracht hatte.
        Danach die eigene Liste der Route (`_chain_satisfied`) und der zweite Faktor nach dem
        Anmelde-Link (`_link_braucht`, G10). Ein API-Key erfüllt keine Route-Kette."""
        strict = self.cfg.login_chain_strict if strict is None else strict
        s = self._session_from_request(request)
        usr = self._als_dict(self.store.get_user(s["user_id"])) if s else None
        if usr and usr["disabled"]:
            usr = None
        done = json.loads(s["factors_done"] or "[]") if s else []
        if usr is None or s is None:
            self._redirect_factor(request, factors[0] if factors else "password")
        if not s["mfa_ok"]:
            # Die globale Anmeldung ist noch offen: erst deren nächster Schritt. `None` (nichts
            # mehr offen, aber auch nicht voll — etwa ein inzwischen entfernter Faktor) → Login.
            self._redirect_factor(request, self._next_login_step(usr["id"], done))
        if not self._chain_satisfied(factors, strict, done):
            self._redirect_factor(request, self._next_factor(factors, strict, done))
        # Dieselbe Regel wie für die globale Policy (G10): Lief die Anmeldung über den Link und hat
        # das Konto einen zweiten Faktor, verlangt auch eine Route-Kette wie `["magic"]` ihn — sonst
        # öffnete das Postfach allein die Route eines Kontos, das sich mit TOTP/Passkey geschützt
        # hat. Enthält die Kette selbst `totp`/`passkey`, ist er schon erbracht (kein Doppelschritt).
        fehlt = self._link_braucht(usr["id"], done)
        if fehlt is not None:
            self._redirect_factor(request, fehlt)
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
                s = self._session_from_request(request)
                usr = self._als_dict(self.store.get_user(s["user_id"])) if s else None
                if not usr or usr["disabled"]:
                    self._deny(request)   # keine Identität → Login (erster Faktor)
                done = json.loads(s["factors_done"] or "[]")
                self._redirect_factor(request, self._next_login_step(usr["id"], done))
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
        factors=[...] verlangt für diese Route zusätzlich eine bestimmte Faktor-Kette,
        strict=True/False steuert die Reihenfolge: `Depends(auth.require(factors=['oidc','password']))`.
        Die Route-Kette verschärft die globale Regel, sie ersetzt sie nicht: Eine Sitzung, die für die
        globale Anmeldung noch nicht voll ist (zweiter Faktor offen, Kette unvollständig), geht zuerst
        zu deren fehlendem Schritt — auch bei `factors=["password"]` (seit 2026-09-27; bis dahin
        überschrieb die Route-Kette die globale). Lief die Anmeldung über den Anmelde-Link und hat das
        Konto TOTP oder einen Passkey, verlangt auch eine Route-Kette ihn
        (`magiclink_require_second_factor`, wie in der globalen Policy)."""
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

    def _check_resource(self, name, secret) -> bool:
        """Das Geheimnis einer gesperrten Ressource prüfen (ohne sie freizuschalten — das tut `_unlock_resource`)."""
        row = self.store.get_resource_secret(name)
        return bool(row and verify_password(str(secret or ""), row["hash"]))

    def resource_unlocked(self, request: Request, name) -> bool:
        """Ist diese Ressource für diesen Browser gerade freigeschaltet?"""
        return self.store.is_resource_unlocked(request.cookies.get(self.resource_cookie_name), name)

    def _unlock_resource(self, request: Request, response, name):
        """Eine Ressource für diesen Browser freischalten und das Cookie setzen.

        Jede Freischaltung bekommt ein **neues** Token (F-01). Vorher übernahm sie das Token aus
        dem Cookie des Browsers: Wer dem Opfer vorher ein eigenes untergeschoben hatte
        (Nachbar-Subdomain, Klartext-HTTP), kannte danach das Token eines freigeschalteten
        Browsers — Session-Fixation, nur für die Bereichs-PIN. Was dieser Browser schon offen
        hatte, zieht auf das neue Token um."""
        alt = request.cookies.get(self.resource_cookie_name)
        token = secrets.token_urlsafe(32)
        if alt:
            self.store.move_resource_unlocks(alt, token)
        ttl = self.cfg.resource_unlock_ttl_hours * 3600
        self.store.add_resource_unlock(token, name, _jetzt() + ttl)
        kw = dict(httponly=True, secure=self.cfg.cookie_secure, samesite=_samesite(self.cfg.cookie_samesite),
                  path=self.cfg.cookie_path, max_age=ttl)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.set_cookie(self.resource_cookie_name, token, **kw)

    def require_resource(self, name: str):
        """FastAPI-Dependency-Factory: Bereich erst nach Eingabe des Ressourcen-Geheimnisses zugänglich.
        Unabhängig vom Benutzer-Login. `Depends(auth.require_resource('fotos'))`."""
        def dep(request: Request):
            if not self.resource_unlocked(request, name):
                if "text/html" in request.headers.get("accept", ""):
                    from urllib.parse import quote
                    nxt = quote(request.url.path, safe="/")
                    raise HTTPException(307, headers={"Location": f"{self.browser_path(request, '/auth/resource/' + name)}?next={nxt}"})
                raise HTTPException(401, self.t("api.resource_locked"))
            return True
        return dep

    # ---------- Stufe C: veraltete Namen, fallen mit 1.0 weg ----------
    # PO-Entscheid 2026-09-26: Diese Namen sind Verdrahtung der eingebauten Routen und gehören nicht
    # zur Zusage (Stufe C). Bis 0.21.x trugen sie keinen Unterstrich und sahen aus wie jede andere
    # Methode — `check_password` stand sogar als Baustein in der README, obwohl es nicht drosselt.
    # Seit 0.22.0 heisst die Implementierung `_name`, und TinySesam ruft nur noch diese. Der alte
    # Name bleibt bis 1.0 als Alias, der beim Aufruf (Konstanten: beim Lesen) genau eine
    # `DeprecationWarning` mit dem Ersatz auslöst. `tests/test_api_surface.py` hält die Liste gegen
    # `tests/api_surface.json` (Stufe C), prüft Warnung und Ziel jedes Alias und verbietet, dass
    # Code im Paket einen alten Namen benutzt; `tests/run_all.py` macht eine solche Warnung aus dem
    # Paket selbst zum Fehler.

    def __init_subclass__(cls, **kwargs):
        """Eine Unterklasse, die einen alten Namen überschreibt, bekommt eine `RuntimeWarning`.

        Bis 0.21.x wirkte eine überschriebene `check_password` auf die eingebauten Routen; seit
        0.22.0 rufen sie `_check_password`, und die Überschreibung läuft still ins Leere. Bei
        einer Prüfmethode ist das genau die Sorte Änderung, die niemand bemerkt, bis sie zählt —
        deshalb eine Warnung, die ohne Filter sichtbar ist (keine `DeprecationWarning`)."""
        super().__init_subclass__(**kwargs)
        for name, wert in vars(cls).items():
            alias = next((vars(b)[name] for b in cls.__mro__[1:] if name in vars(b)), None)
            if isinstance(alias, Veraltet) and not isinstance(wert, Veraltet):
                warnings.warn(
                    f"{cls.__name__}.{name} überschreibt einen veralteten Namen und wirkt seit "
                    f"0.22.0 nicht mehr: TinySesam ruft intern `{alias.ziel}`. {alias.meldung}",
                    RuntimeWarning, stacklevel=2)

    admin_claim_fehlgriff = Veraltet(
        "_admin_claim_fehlgriff", "ohne Ersatz; die Route `/auth/claim-admin` protokolliert selbst")
    check_ldap = Veraltet(
        "_check_ldap", "stattdessen `login_password` (fragt das Verzeichnis als Rückfall, "
        "drosselt und sperrt wie `POST /auth/login`)")
    check_password = Veraltet(
        "_check_password", "stattdessen `login_password` (drosselt, zählt und sperrt wie "
        "`POST /auth/login`), für ein eigenes Aussehen allein `set_template(\"login\", …)`; "
        "`check_password` selbst drosselt nicht")
    check_pin = Veraltet(
        "_check_pin", "stattdessen `login_pin` (drosselt, zählt und sperrt wie `POST /auth/pin`), "
        "für ein eigenes Aussehen allein `set_template(\"pin\", …)`; `check_pin` selbst drosselt "
        "nicht")
    check_resource = Veraltet(
        "_check_resource", "stattdessen `POST /auth/resource/{name}` (drosselt und sperrt) bzw. "
        "`require_resource`")
    check_saml = Veraltet(
        "_check_saml", "stattdessen `POST /auth/saml/acs`, das die Signatur der Assertion prüft; "
        "`check_saml` vertraut seinen Argumenten")
    complete_mfa = Veraltet("complete_totp", "stattdessen `complete_totp` (gleiches Verhalten)")
    consume_admin_claim = Veraltet(
        "_consume_admin_claim", "stattdessen die Route `/auth/claim-admin`, `ensure_admin` oder "
        "`admin_identifiers`")
    csrf_rotieren = Veraltet(
        "_csrf_rotieren", "stattdessen `set_cookie` (dreht das CSRF-Token bei der Anmeldung mit) "
        "bzw. `issue_csrf`")
    factor_entry = Veraltet(
        "_factor_entry", "ohne Ersatz; `require_user`/`require` leiten selbst zum offenen Faktor")
    forward_login_url = Veraltet(
        "_forward_login_url", "ohne Ersatz; die Route `/auth/forward` baut die Login-Adresse selbst")
    forward_response_headers = Veraltet(
        "_forward_response_headers", "ohne Ersatz; welche Header `/auth/forward` setzt, steuert "
        "`forward_headers`")
    forwarded_url = Veraltet(
        "_forwarded_url", "ohne Ersatz; die Route `/auth/forward` liest die Proxy-Header selbst")
    is_locked = Veraltet(
        "_is_locked", "stattdessen `login_password`, `login_pin` bzw. `login_totp`, die "
        "atomar prüfen und buchen; `is_locked` liest nur und lässt parallele Salven durch")
    is_password_change_locked = Veraltet(
        "_is_password_change_locked", "stattdessen `change_password` (prüft und bucht atomar wie "
        "`POST /auth/password`)")
    is_pin_locked = Veraltet(
        "_is_pin_locked", "stattdessen `login_pin` (prüft und bucht atomar wie `POST /auth/pin`)")
    is_reauth_locked = Veraltet(
        "_is_reauth_locked", "stattdessen `confirm_password`, `confirm_pin` bzw. `confirm_totp` "
        "(prüfen und buchen atomar wie `/auth/reauth`, wohin `require(mfa=True)` leitet)")
    is_resource_locked = Veraltet(
        "_is_resource_locked", "stattdessen `POST /auth/resource/{name}` (prüft und bucht atomar)")
    is_secure = Veraltet(
        "_is_secure", "ohne Ersatz; die Warnung ohne HTTPS steuert `https_mode`")
    is_totp_setup_locked = Veraltet(
        "_is_totp_setup_locked", "stattdessen `POST /auth/totp/setup` (prüft und bucht atomar)")
    login_redirect_after = Veraltet(
        "_login_redirect_after", "stattdessen `next_url` bzw. `redirect()` am Ergebnis von "
        "`login_password`, `login_pin` oder `login_totp` (nächster Faktor oder `next`)")
    maybe_promote_admin = Veraltet(
        "_maybe_promote_admin", "stattdessen `admin_identifiers` oder `ensure_admin`; direkt "
        "gerufen umgeht es den Adressbeleg")
    mfa_pending = Veraltet(
        "_mfa_pending", "ohne Ersatz (der Name meint „hat ein bestätigtes TOTP“); dasselbe "
        "liefert `auth.store.has_confirmed_totp(user_id)` — Innenleben, ohne Zusage")
    next_login_step = Veraltet(
        "_next_login_step", "ohne Ersatz; `require_user`/`require` leiten selbst zum offenen "
        "Faktor")
    oidc_anwendung = Veraltet(
        "_oidc_anwendung", "ohne Ersatz; die Zuordnung steht in `oidc_clients`")
    oidc_freigabe_gueltig = Veraltet(
        "_oidc_freigabe_gueltig", "ohne Ersatz; die Zuordnung steht in `oidc_clients`")
    purge_demo = Veraltet(
        "_purge_demo", "stattdessen `demo_mode=False` (räumt die Demo-Konten beim Start)")
    rate_ok = Veraltet(
        "_rate_ok", "stattdessen `login_password`, `login_pin` bzw. `login_totp` (drosseln "
        "je IP), ein eigener Limiter per `set_rate_limiter`")
    record_login = Veraltet(
        "_record_login", "stattdessen `login_password`, `login_pin` bzw. `login_totp`, die "
        "jeden Versuch verbuchen; falsch gerufen räumt es fremde Fehlversuchszähler")
    sec = Veraltet("_sec", "stattdessen `all_security()`")
    seed_demo = Veraltet(
        "_seed_demo", "stattdessen `demo_mode=True` (legt die Demo-Konten beim Start an)")
    send_signup_notice = Veraltet(
        "_send_signup_notice", "ohne Ersatz; `POST /auth/register` verschickt den Hinweis selbst")
    session_from_request = Veraltet(
        "_session_from_request", "stattdessen `current_user` bzw. `session_user`")
    sicherheitsereignis = Veraltet(
        "_sicherheitsereignis", "ohne Ersatz; TinySesam ruft den Hook `on_security_event` selbst")
    token_abgewiesen = Veraltet(
        "_token_abgewiesen", "ohne Ersatz; die eingebauten Token-Routen protokollieren selbst")
    unlock_resource = Veraltet(
        "_unlock_resource", "stattdessen `POST /auth/resource/{name}` (prüft das Geheimnis vorher)")
    verify_csrf = Veraltet("_verify_csrf", "stattdessen `require_csrf`")
    verify_recovery_code = Veraltet(
        "_verify_recovery_code", "stattdessen `login_totp` (nimmt auch Einmal-Codes, drosselt "
        "und sperrt wie `POST /auth/totp`); `verify_recovery_code` selbst drosselt nicht")
    verify_totp = Veraltet(
        "_verify_totp", "stattdessen `login_totp` (drosselt und sperrt wie `POST /auth/totp`), "
        "für den Step-up `confirm_totp`; `verify_totp` selbst drosselt nicht")
    verify_user_password = Veraltet(
        "_verify_user_password", "stattdessen `confirm_password` (Step-up, drosselt und sperrt wie "
        "`/auth/reauth`) bzw. `change_password` (wie `POST /auth/password`); "
        "`verify_user_password` selbst drosselt nicht")
    verify_user_pin = Veraltet(
        "_verify_user_pin", "stattdessen `confirm_pin` (Step-up, drosselt und sperrt wie "
        "`/auth/reauth`); `verify_user_pin` selbst drosselt nicht")
    vermerke_oidc_freigabe = Veraltet(
        "_vermerke_oidc_freigabe", "ohne Ersatz; die Zuordnung steht in `oidc_clients`")
    versuch_beginnen = Veraltet(
        "_versuch_beginnen", "stattdessen `login_password`, `login_pin` bzw. `login_totp`, "
        "die jeden Versuch atomar vorbuchen")

    APIKEY_AUDIT_FENSTER = Veraltet("_APIKEY_AUDIT_FENSTER", "ohne Ersatz, ein interner Wert")
    DEMO_USERS = Veraltet(
        "_DEMO_USERS", "ohne Ersatz; die Demo-Konten heissen `demo` und `demoadmin` (README)")
    FOEDERIERTE_FAKTOREN = Veraltet(
        "_FOEDERIERTE_FAKTOREN", "ohne Ersatz, eine innere Entscheidungsliste für den Erst-Admin")
    IDENTIFYING = Veraltet(
        "_IDENTIFYING", "ohne Ersatz; welche Faktoren identifizieren, steht in docs/BETRIEB.md")
    RECOVERY_BYTES = Veraltet("_RECOVERY_BYTES", "ohne Ersatz, ein interner Wert")
    RECOVERY_WARNSCHWELLE = Veraltet(
        "_RECOVERY_WARNSCHWELLE", "stattdessen `recovery_codes_remaining` und eine eigene Schwelle")
    # Kam mit 0.21.0 (G7) und stand dort im CHANGELOG als Weg für eigene PIN-Seiten
    # (`versuch_beginnen(…, serie_art=auth.SERIE_PIN_FOLGE)`) — veröffentlicht, also ein Alias
    # wie jeder andere C-Name, nicht bloss umbenannt.
    SERIE_PIN_FOLGE = Veraltet(
        "_SERIE_PIN_FOLGE", "stattdessen `login_pin` (bucht eine PIN hinter einem erbrachten "
        "Faktor selbst unter dieser Serien-Art)")

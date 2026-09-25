"""LDAP/lldap-Backend: Passwort gegen einen Verzeichnis-Bind prüfen (Extra `[ldap]`, ldap3).

Zwei Modi:
- **Direkt-Bind** (`ldap_user_dn_template`, z.B. lldap `uid={username},ou=people,dc=…`): bindet direkt
  mit dem User-DN + Passwort und liest anschließend Attribute.
- **Search-then-Bind** (`ldap_bind_dn`/`ldap_bind_password` + `ldap_user_base`/`ldap_user_filter`):
  Service-Account sucht den User, dann Re-Bind mit dessen DN + Passwort.

Gibt bei Erfolg {username, email, name, groups} zurück, bei falschem Passwort/unbekanntem Konto
None. Ist das Verzeichnis nicht erreichbar oder nicht benutzbar (Netz, TLS, Dienstkonto), fliegt
`VerzeichnisNichtErreichbar` — ein Ausfall ist kein Fehlversuch des Anmeldenden (F-23).
Benutzernamen werden für Filter/DN escaped (LDAP-Injection-Schutz). **Verweisen (Referrals) folgt
dieses Modul nie** — sonst bindet ldap3 auf dem verwiesenen Host mit denselben Zugangsdaten
(s. `_OHNE_REFERRALS`). Ein verworfener Verweis wird ins Sicherheits-Log geschrieben
(`_verweis_melden`), damit der Betrieb den Grund der Abweisung sieht und nicht bloß
„Passwort falsch" für jeden Nutzer.
"""
from __future__ import annotations

import threading
import time

from . import errors
from .security import beleg_attribut, fuer_log, seclog


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Aus einem nackten Importfehler eine Meldung machen, die sagt, was zu tun ist.

    Die Extras werden hier bewusst LAZY importiert (erst beim Benutzen). Der Preis dafür war
    bis 0.18.0 ein `ModuleNotFoundError: ldap3` mitten im Anmeldevorgang — für den Betreiber
    ein Defekt, dabei fehlte nur eine Zeile im Install-Befehl."""
    return errors.MissingExtra(
        "Das Extra [ldap] ist nicht installiert (pip install 'tinysesam[ldap]') — "
        f"es fehlt: {e.name or 'ldap3'}.", extra="ldap")


#: Referrals NICHT verfolgen — auf JEDER Verbindung, die dieses Modul aufmacht.
#:
#: ldap3 folgt einem Verweis (`SearchResultDone resultCode=10`) von sich aus und baut dazu eine
#: neue Verbindung zu dem Host auf, den die ANTWORT nennt — mit denselben Zugangsdaten
#: (`create_referral_connection` reicht `user`/`password` der Connection weiter). Damit genügt
#: eine eingeschobene oder von einem übernommenen Verzeichnis gesetzte Referral, um DN und
#: Passwort des Dienstkontos an einen fremden Server zu schicken; auf der Benutzer-Verbindung
#: wäre es das Passwort des Anmeldenden. Nachgestellt mit zwei LDAP-Servern auf Loopback: beim
#: fremden Host kam der vollständige BindRequest samt Klartext-Passwort an (Audit T-13, F-28).
#:
#: Bewusst hart und ohne Schalter: Ein Verweis, dem man mit Zugangsdaten folgt, ist kein
#: Betriebsmodus, den ein Konfigurationsfeld zurückholen sollte. Wer über mehrere AD-Domänen
#: suchen muss, fragt den Global Catalog (Port 3268/3269) ab, statt Verweisen zu folgen.
#: Ohne Verfolgung endet die Suche ergebnislos → `authenticate()` gibt `None` zurück (fail-closed).
#: Damit das nicht stumm passiert, meldet `_verweis_melden()` den Fall im Sicherheits-Log.
_OHNE_REFERRALS = {"auto_referrals": False}


def _verweis_melden(conn, was: str, username: str) -> None:
    """Eine Suche, die das Verzeichnis mit einem VERWEIS beantwortet hat, ins Sicherheits-Log
    schreiben — sonst endet der Login stumm als „Passwort falsch".

    Ohne diese Zeile war der Preis des F-28-Fixes unsichtbar: Wer über mehrere AD-Domänen sucht,
    bekam nach dem Update für **jeden** Nutzer eine Abweisung und nichts, was auf die Ursache
    zeigt (der Global-Catalog-Hinweis stand nur im Quelltext). Gemeldet wird nur der
    Verweis-Fall; eine gewöhnlich leere Suche (Konto gibt es nicht) ist keine Auffälligkeit
    und würde das Log fluten.

    Die Verweis-Adresse kommt aus einer FREMDEN Antwort und geht deshalb durch `fuer_log` —
    ein Zeilenumbruch darin wäre eine zusätzliche, frei erfundene Zeile in genau dem Log, das
    fail2ban liest (dieselbe Falle wie beim Benutzernamen).
    """
    try:
        ergebnis = getattr(conn, "result", None) or {}
        verweise = ergebnis.get("referrals") or []
        code = ergebnis.get("result")
    except Exception:            # fremdes/unerwartetes Connection-Objekt — nie den Login stören
        return
    if not verweise and code != 10:
        return
    seclog.warning(
        "LDAP: %s für user=%s endete mit einem VERWEIS (referral) auf %s — dem folgt TinySesam "
        "bewusst nicht (sonst ginge das Passwort an den verwiesenen Host, Fund F-28). Die "
        "Anmeldung scheitert deshalb, obwohl das Konto existieren kann. Wer über mehrere "
        "AD-Domänen sucht, fragt den Global Catalog ab (Port 3268/3269) und setzt "
        "ldap_user_base auf die Wurzel.",
        was, fuer_log(username),
        ", ".join(fuer_log(v) for v in verweise[:3]) or "(Host nicht genannt)")


class VerzeichnisNichtErreichbar(errors.TinySesamError, RuntimeError):
    """Das Verzeichnis hat die Frage nicht beantwortet — Netz, TLS, Dienstkonto (F-23).

    Bis 0.20.0 endete jeder Fehler in `authenticate()` als `None`, also als „Passwort falsch":
    Der Login verbuchte einen Fehlversuch, fail2ban las `failed login`, und nach ein paar
    Minuten Ausfall waren die Nutzer gesperrt, die nichts falsch gemacht hatten. Im Protokoll
    war der Ausfall vom falschen Passwort nicht zu unterscheiden. Diese Ausnahme trennt die
    beiden Fälle; die Login-Route antwortet dann 503 und verbucht nichts gegen das Konto."""


class AnfrageAbgebrochen(VerzeichnisNichtErreichbar):
    """Das Verzeichnis hat DIESE Anfrage abgebrochen — nicht bewiesen, dass es weg ist.

    Geworfen, wenn ein Schritt, der Eingaben des Anmeldenden trug (Benutzersuche, Benutzer-Bind,
    Attributsuche), schnell mit einem Kommunikationsfehler endet: Verbindung vom Server
    beendet, Senden oder Empfangen gescheitert. Genau das löst ein Anmeldender mit dem Inhalt
    seiner Anfrage selbst aus — OpenLDAP beendet die Sitzung, sobald eine PDU auf der noch
    anonymen Sitzung grösser als `sockbuf_max_incoming` ist (Vorgabe 262143 Byte).

    Für die Login-Route ist es dasselbe wie ein Ausfall (Unterklasse: 503, kein Fehlversuch).
    `TinySesam.check_ldap` schaltet damit aber den `AusfallMerker` NICHT scharf: Bis zur
    Nachbesserung der T-13-Integration tat es das, und EINE präparierte Anmeldung ohne Konto gab
    jeder LDAP-Nutzerin 30 s lang 503 — alle paar Sekunden wiederholt dauerhaft, ohne dass den
    Absender das einen Fehlversuch kostete. Der Merker ist für Fehlschläge da, die HÄNGEN (ohne
    ihn schwebte jeder vorgebuchte Versuch bis zum Timeout); ein schneller Abbruch schwebt nicht.
    """


#: Wie lange ein Verbindungsaufbau und eine Antwort dauern dürfen. Ohne Grenze hing ein Login
#: bei einem Verzeichnis, das Pakete verwirft statt abzulehnen, so lange wie der TCP-Timeout
#: des Betriebssystems (Minuten) — mit einem Worker-Thread je wartendem Nutzer.
VERBINDUNGS_TIMEOUT = 10

#: Ab welcher Dauer ein gescheiterter Schritt, der Eingaben des Anmeldenden trug, als „das
#: Verzeichnis hängt" gilt (Sekunden) — dann schaltet er den `AusfallMerker` scharf wie jeder
#: Ausfall. Darunter ist es ein Abbruch DIESER Anfrage (`AnfrageAbgebrochen`). Die Grenze trennt
#: die beiden Fälle, für die der Merker da ist bzw. nicht: Ein hängendes Verzeichnis antwortet
#: erst nach `VERBINDUNGS_TIMEOUT`, ein Abbruch wegen des Inhalts kommt in Millisekunden.
HAENGER_SEK = 1.0

#: Obergrenzen für das, was eine Anmeldung ans Verzeichnis schicken darf (Zeichen). Länger ist
#: keine Anmeldung: Benutzernamen, UPNs und Adressen bleiben weit unter 256 Zeichen, und
#: `passwords.PASSWORT_MAX_LAENGE` erlaubt beim Setzen 256 — 1024 lassen Verzeichnissen mit
#: eigener Passwortregel reichlich Luft. Selbst voll ausgenutzt (UTF-8, maskierte DN-Zeichen)
#: bleibt eine Bind-PDU damit unter 16 KiB, weit unter slapds 256 KiB für anonyme Sitzungen.
#: Was darüber liegt, fragt TinySesam gar nicht erst und behandelt es wie ein falsches Passwort.
LDAP_NAME_MAX = 256
LDAP_PASSWORT_MAX = 1024


def eingabe_zu_lang(username, password) -> bool:
    """Ist Benutzername oder Passwort länger als jede echte Anmeldung (`LDAP_NAME_MAX`,
    `LDAP_PASSWORT_MAX`)? Dann nicht ans Verzeichnis damit — s. `AnfrageAbgebrochen`."""
    return (len(str(username or "")) > LDAP_NAME_MAX
            or len(str(password or "")) > LDAP_PASSWORT_MAX)

#: Wie lange nach einem Ausfall das Verzeichnis gar nicht erst gefragt wird (Sekunden, s.
#: `AusfallMerker`). So lange wie die Redis-Pause: Kürzer hiesse mehr hängende Proben, länger
#: hiesse, dass ein zurückgekehrtes Verzeichnis spürbar später wieder angenommen wird.
AUSFALL_PAUSE_SEK = 30


class AusfallMerker:
    """Merkt sich einen Verzeichnis-Ausfall, damit nicht jede Anmeldung bis zum Timeout hängt.

    Vorbild ist die Redis-Pause (`security.RedisRateLimiter`). Hier ist sie mehr als Komfort: Die
    Login-Route bucht jeden Versuch VORAB als Fehlversuch (`versuch_beginnen`, R7-2) und nimmt ihn
    bei einem Ausfall erst zurück, wenn `VerzeichnisNichtErreichbar` kommt (F-23). Bei einem
    Verzeichnis, das Pakete verwirft, ist das nach `VERBINDUNGS_TIMEOUT`. Bis dahin zählte jede
    hängende Anmeldung für Konto, Paar und Adresse mit — und zwar während des GANZEN Ausfalls,
    denn jeder neue Anlauf hing wieder zehn Sekunden: 15 Kollegen hinter einer NAT-Adresse, und
    der lokale Notfall-Admin bekam mit richtigem Passwort 429; jede weitere Abweisung schrieb
    `failed login … reason=lockout_ip`, und fail2ban bannte die Adresse. Genau das sollte F-23
    verhindern.

    Scharf schaltet ihn nur ein Fehlschlag, der das Verzeichnis als Ganzes betrifft —
    Verbindungsaufbau, TLS, Dienstkonto, oder eine Frage, die bis zum Timeout HING. Bricht das
    Verzeichnis dagegen nur eine einzelne Anfrage schnell ab (`AnfrageAbgebrochen`, etwa slapd bei
    einer übergrossen PDU), trifft das nur diese: Sonst legte eine präparierte Anmeldung ohne
    Konto die LDAP-Anmeldung aller 30 s lang still, beliebig oft wiederholt.

    Ablauf: Nach einem Ausfall ruht das Verzeichnis `pause_sec` lang — jede Frage bekommt sofort
    `VerzeichnisNichtErreichbar`, der vorgebuchte Versuch ist Millisekunden später zurückgenommen.
    Danach fragt **genau eine** Anmeldung nach (Probe); alle anderen bekommen weiter sofort den
    Ausfall, bis sie zurück ist. So schwebt auch beim Nachfragen höchstens ein Versuch. Antwortet
    das Verzeichnis — auch mit „Passwort falsch" —, ist es wieder frei; sonst beginnt die nächste
    Pause. Gemeldet wird der Wechsel (einmal beim Ausfall, einmal bei der Rückkehr), nicht jede
    Anfrage.

    **Was bleibt:** das erste Fenster. Bevor die erste Frage scheitert, weiss niemand, dass das
    Verzeichnis weg ist; Anmeldungen, die in diesen höchstens `VERBINDUNGS_TIMEOUT` Sekunden
    beginnen, schweben wie vorher. Das geschieht einmal je Ausfall und je Prozess (der Merker lebt
    im Prozess, bei `--workers N` also N-mal, zeitgleich). Ganz schliessen liesse es sich nur mit
    einem Schwebezustand der Vorbuchung in der Datenbank.

    `uhr` ist austauschbar, damit ein Test die Pause ablaufen lassen kann, ohne zu warten.
    """

    def __init__(self, pause_sec: float = AUSFALL_PAUSE_SEK, uhr=None):
        self.pause_sec = pause_sec
        self._uhr = uhr or time.monotonic
        self._lock = threading.Lock()
        self._gestoert = False
        self._pause_bis = 0.0
        self._probe = False
        self._grund = ""

    def zugang(self) -> bool:
        """Darf diese Anmeldung das Verzeichnis fragen? Wirft `VerzeichnisNichtErreichbar`, wenn nicht.

        Rückgabe `True`: Diese Anmeldung ist die Probe nach einer Pause — sie MUSS mit
        `ausgefallen()`, `erreicht()` oder `freigeben()` enden, sonst fragt niemand mehr nach."""
        with self._lock:
            if not self._gestoert:
                return False
            rest = self._pause_bis - self._uhr()
            if rest > 0 or self._probe:
                grund = self._grund
                warum = (f"nächster Versuch in {rest:.0f} s" if rest > 0
                         else "eine andere Anmeldung fragt gerade nach")
            else:
                self._probe = True
                return True
        raise VerzeichnisNichtErreichbar(
            f"LDAP-Verzeichnis gilt nach einem Fehlschlag als nicht erreichbar ({warum}): {grund}")

    def ausgefallen(self, fehler, war_probe: bool = False) -> None:
        """Die Frage ist gescheitert: Pause (neu) beginnen, den Wechsel einmal melden.

        Den Platz der Probe gibt nur die Probe selbst frei — ein Nachzügler aus dem ersten
        Fenster, der erst jetzt in sein Timeout läuft, liesse sonst eine zweite Probe zu."""
        with self._lock:
            self._pause_bis = self._uhr() + self.pause_sec
            if war_probe:
                self._probe = False
            self._grund = str(fehler)[:300]
            neu = not self._gestoert
            self._gestoert = True
        if neu:
            seclog.warning("LDAP-Verzeichnis nicht erreichbar (%s) — Anmeldungen über das "
                           "Verzeichnis bekommen %d s lang sofort 503, danach fragt eine einzelne "
                           "Anmeldung wieder nach.", fuer_log(str(fehler)), int(self.pause_sec))

    def erreicht(self) -> None:
        """Das Verzeichnis hat geantwortet (auch mit „Passwort falsch"): wieder frei."""
        if not self._gestoert:
            return
        with self._lock:
            war = self._gestoert
            self._gestoert = False
            self._probe = False
        if war:
            seclog.warning("LDAP-Verzeichnis wieder erreichbar — Anmeldungen fragen es wieder.")

    def freigeben(self) -> None:
        """Eine Probe endete ohne Antwort und ohne Ausfall (anderer Fehler): Platz freigeben."""
        with self._lock:
            self._probe = False


def _ausfall_arten() -> tuple:
    """Die ldap3-Fehler, die „Verzeichnis nicht erreichbar/benutzbar" heissen — nicht „falsches
    Passwort". Ein falsches Benutzerpasswort wirft keinen davon: `bind()` gibt dann False zurück.
    `LDAPBindError` kommt nur aus dem `auto_bind` des Dienstkontos — dessen Zugangsdaten sind
    Betreiberkonfiguration, nicht der Fehler des Anmeldenden."""
    try:
        from ldap3.core import exceptions as lx
    except ImportError:          # untergeschobenes ldap3 ohne Ausnahme-Modul (Testattrappe)
        return ()
    return (lx.LDAPCommunicationError, lx.LDAPStartTLSError, lx.LDAPBindError,
            lx.LDAPMaximumRetriesError, lx.LDAPSSLConfigurationError)


def _inhaltsfreie_arten() -> tuple:
    """Die Ausfall-Arten, die der INHALT einer Anfrage nicht auslösen kann: Die Verbindung kam
    nicht zustande (TCP, bei `ldaps://` auch der TLS-Handschlag), StartTLS scheiterte, die
    TLS-Konfiguration taugt nicht, oder das Dienstkonto kam nicht hinein. Bis dahin ist nichts
    vom Anmeldenden über die Leitung gegangen."""
    try:
        from ldap3.core import exceptions as lx
    except ImportError:
        return ()
    return (lx.LDAPSocketOpenError, lx.LDAPStartTLSError, lx.LDAPBindError,
            lx.LDAPSSLConfigurationError)


class LDAPClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def _server(self):
        try:
            import ldap3
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        # `allowed_referral_hosts=[]` ist das zweite Schloss gegen die Referral-Falle (s.
        # `_OHNE_REFERRALS`): ldap3 vergibt hier per Vorgabe `[('*', True)]` — „jeder Host, und
        # zwar mit Zugangsdaten". Selbst wenn irgendwann jemand eine Connection ohne
        # `auto_referrals=False` anlegt, findet ldap3 dann keinen erlaubten Verweis-Host mehr.
        return ldap3.Server(self.cfg.ldap_url, get_info=ldap3.NONE, allowed_referral_hosts=[],
                            tls=self._tls(ldap3), connect_timeout=VERBINDUNGS_TIMEOUT)

    def _tls(self, ldap3):
        """Die TLS-Einstellungen für `ldaps://` und StartTLS (F-12).

        Bis 0.19.0 gab es sie gar nicht: `ldap3.Server(...)` ohne `tls=` prüft das Zertifikat
        **nicht** (`validate=CERT_NONE` ist ldap3s Vorgabe). Verschlüsselt hiess damit nur „nicht
        mitlesbar von jemandem, der nicht dazwischensitzt". Wer den Verkehr umlenkt, hält ein
        eigenes Zertifikat hin, bekommt das Passwort des Dienstkontos und jedes
        Benutzerpasswort, und reicht die Antwort an das echte Verzeichnis weiter — für beide
        Seiten sieht der Vorgang normal aus.

        `ldap_tls_verify=False` bleibt möglich (ein Verzeichnis mit selbstsigniertem Zertifikat
        und ohne eigene CA-Datei), meldet sich aber beim Aufbau.
        """
        import ssl
        if not self.cfg.ldap_tls_verify:
            return ldap3.Tls(validate=ssl.CERT_NONE)
        return ldap3.Tls(validate=ssl.CERT_REQUIRED,
                         ca_certs_file=(self.cfg.ldap_tls_ca_file or None))

    def authenticate(self, username: str, password: str):
        if not username or not password:
            return None
        if eingabe_zu_lang(username, password):
            return None      # keine Anmeldung, sondern der Hebel aus `AnfrageAbgebrochen`
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
            from ldap3.utils.dn import escape_rdn
        except ModuleNotFoundError as e:
            # NICHT verschlucken. Diese Stelle ist der Weg, den ein Login nimmt: Ohne `ldap3`
            # gab `authenticate()` einfach `None` zurück, die App antwortete 401, und das sah
            # aus wie ein falsches Passwort. Der Betreiber sucht dann tagelang am falschen Ende
            # — während anderswo (`_server()`) korrekt ein `MissingExtra` flog.
            raise _fehlt_extra(e) from e
        except Exception:
            return None
        cfg = self.cfg
        server = self._server()
        # Welcher Schritt läuft, seit wann, und trägt er Eingaben des Anmeldenden? Daran hängt,
        # ob ein Fehlschlag das Verzeichnis als Ganzes betrifft oder nur diese Anfrage (s.
        # `AnfrageAbgebrochen`, `HAENGER_SEK`).
        eingabe, seit = False, time.monotonic()
        try:
            if cfg.ldap_user_dn_template:
                user_dn = cfg.ldap_user_dn_template.format(username=escape_rdn(username))
            else:
                # Search-then-Bind: erst mit Service-Account suchen
                # **TLS VOR dem Bind** (F-12). Vorher stand `auto_bind=True` hier und
                # `start_tls()` eine Zeile später: Das Passwort des Dienstkontos war also schon
                # über die Leitung, bevor sie verschlüsselt wurde. Ein Mitleser brauchte nicht
                # einmal einen Angriff — nur Geduld. `AUTO_BIND_TLS_BEFORE_BIND` ist genau dafür
                # da; die Benutzer-Verbindung unten machte es von Anfang an richtig.
                svc = ldap3.Connection(
                    server, user=cfg.ldap_bind_dn or None,
                    password=cfg.ldap_bind_password or None,
                    auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if cfg.ldap_start_tls
                               else ldap3.AUTO_BIND_NO_TLS),
                    receive_timeout=VERBINDUNGS_TIMEOUT, **_OHNE_REFERRALS)
                flt = cfg.ldap_user_filter.format(username=escape_filter_chars(username))
                attrs = _attributliste(cfg)
                eingabe, seit = True, time.monotonic()        # der Filter trägt den Benutzernamen
                svc.search(cfg.ldap_user_base, flt, attributes=attrs)
                if not svc.entries:
                    _verweis_melden(svc, "die Benutzersuche", username)
                    svc.unbind()
                    return None
                user_dn = svc.entries[0].entry_dn
                svc.unbind()
            # Re-Bind mit dem User-DN + Passwort → prüft das Passwort
            conn = ldap3.Connection(server, user=user_dn, password=password,
                                    receive_timeout=VERBINDUNGS_TIMEOUT, **_OHNE_REFERRALS)
            # Verbindung und TLS ausdrücklich VOR dem Bind: Scheitern sie, ist vom Anmeldenden
            # noch nichts gesendet — ein Ausfall des Verzeichnisses, gleich wie lange es dauerte.
            eingabe, seit = False, time.monotonic()
            conn.open()
            if cfg.ldap_start_tls:
                conn.start_tls()
            eingabe, seit = True, time.monotonic()            # Bind: Benutzer-DN und Passwort
            if not conn.bind():
                return None
            attrs = _attributliste(cfg)
            conn.search(user_dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=attrs)
            entry = conn.entries[0] if conn.entries else None
            if entry is None:
                # Auch hier: Ein Verweis auf der Attribut-Suche lässt E-Mail, Name und Gruppen
                # fehlen — mit ldap_allowed_groups ist das eine Abweisung ohne erkennbaren Grund.
                _verweis_melden(conn, "die Attribut-Suche", username)
            info: dict = {"username": username, "email": None, "name": username, "groups": [],
                          "id": None}
            if entry is not None:
                info["email"] = _first(entry, cfg.ldap_attr_email)
                info["name"] = _first(entry, cfg.ldap_attr_name) or username
                info["groups"] = _list(entry, cfg.ldap_group_attr)
                info["id"] = _stabile_kennung(entry, cfg)
                if beleg_attribut(cfg, "ldap"):
                    info["email_verified"] = _first(entry, beleg_attribut(cfg, "ldap"))
            conn.unbind()
            return info
        except _ausfall_arten() as e:
            # Kein `None`: Das hiesse „Passwort falsch" und kostete den Nutzer einen Fehlversuch
            # für einen Ausfall, den er nicht verursacht hat (F-23).
            #
            # Nur diese Anfrage, wenn alles drei zutrifft: Der Schritt trug Eingaben des
            # Anmeldenden, der Fehler gehört nicht zu denen, die vor dem Senden entstehen, und es
            # ging SCHNELL. Ein Verzeichnis, das hängt, meldet sich erst nach dem Timeout — das ist
            # ein Ausfall, auch wenn es erst beim Benutzer-Bind hängt (Backend blockiert).
            dauer = time.monotonic() - seit
            nur_diese = (eingabe and dauer < HAENGER_SEK
                         and not isinstance(e, _inhaltsfreie_arten()))
            # Die Kennzeichnung steht VORN: Route und Audit kürzen den Grund (`fuer_log`, 64 Zeichen).
            if nur_diese:
                raise AnfrageAbgebrochen(
                    f"LDAP: nur diese Anfrage abgebrochen — {type(e).__name__}: {e} "
                    f"({cfg.ldap_url})") from e
            raise VerzeichnisNichtErreichbar(
                f"LDAP-Verzeichnis {cfg.ldap_url} nicht benutzbar: {type(e).__name__}: {e}") from e
        except Exception:
            return None


#: Attribute, in denen Verzeichnisse ihre stabile Kennung führen — in dieser Reihenfolge
#: probiert, wenn `ldap_attr_id` leer ist. `entryUUID` ist der Standard (RFC 4530, OpenLDAP,
#: lldap), `objectGUID` die Fassung von Active Directory. Ein Benutzername gehört NICHT dazu:
#: Er ist der Wert, den diese Kennung gerade ersetzen soll (F-11).
STABILE_KENNUNG_ATTRIBUTE = ("entryUUID", "objectGUID")


def _attributliste(cfg) -> list:
    """Alle Attribute, die geholt werden müssen — inklusive der stabilen Kennung.

    Sie fehlte hier bis 0.19.0, weil sie niemand las. Wird sie nicht angefordert, liefert der
    Server sie auch nicht: Die Bindung wäre dann still ohne Kennung, also wieder über den Namen.
    """
    namen = [cfg.ldap_attr_email, cfg.ldap_attr_name, cfg.ldap_group_attr]
    if beleg_attribut(cfg, "ldap"):
        namen.append(beleg_attribut(cfg, "ldap"))
    namen += [cfg.ldap_attr_id] if cfg.ldap_attr_id else list(STABILE_KENNUNG_ATTRIBUTE)
    gesehen, raus = set(), []
    for a in namen:
        if a and a.lower() not in gesehen:
            gesehen.add(a.lower())
            raus.append(a)
    return raus


def _stabile_kennung(entry, cfg):
    """Die stabile Kennung aus dem Eintrag — als Text, damit sie in die Datenbank passt.

    `objectGUID` kommt bei Active Directory als Bytes; roh abgelegt wäre sie je nach ldap3-Fassung
    einmal so und einmal anders zu lesen. Deshalb hier eine feste Darstellung.
    """
    kandidaten = [cfg.ldap_attr_id] if cfg.ldap_attr_id else list(STABILE_KENNUNG_ATTRIBUTE)
    for attr in kandidaten:
        wert = _first(entry, attr)
        if wert in (None, ""):
            continue
        if isinstance(wert, (bytes, bytearray)):
            return wert.hex()
        return str(wert)
    return None


def _first(entry, attr):
    try:
        v = entry[attr].value if attr in entry else None
    except Exception:
        return None
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def _list(entry, attr):
    try:
        v = entry[attr].value if attr in entry else None
    except Exception:
        return []
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]

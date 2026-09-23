"""Härtung: echte Client-IP (Trusted-Proxy), Rate-Limiting, fail2ban-Logger.
Die Brute-Force-Regulation selbst lebt im Manager (DB-basiert, Panel-konfigurierbar)."""
from __future__ import annotations
import os
import stat
import time
import logging
import logging.handlers
import ipaddress
import re
from urllib.parse import urlsplit
from collections import OrderedDict, deque

# fail2ban parst diesen Logger. Failed-Login-Zeilen enthalten "ip=<IP>" → Filter matcht darauf.
seclog = logging.getLogger("tinysesam.security")

def fuer_log(wert) -> str:
    """Einen fremden Wert so herrichten, dass er eine Logzeile nicht sprengen kann.

    Der Benutzername kommt roh aus einem Formularfeld und landete ungefiltert in der Zeile, die
    fail2ban liest. Ein `\n` darin erzeugt eine **zusätzliche Zeile** — und wer vorn und hinten
    einen Umbruch setzt, schiebt die echte `ip=`-Angabe auf eine Folgezeile, die der Filter nicht
    mehr matcht, und lässt dazwischen eine frei erfundene stehen. fail2ban zählt dann die
    Fehlversuche einer **vom Angreifer gewählten** IP, während die echte null Treffer erzeugt.
    Bei `maxretry = 6` genügen sechs Anfragen, um eine beliebige Adresse auszusperren — die des
    Admins, eines Partners, einer Überwachungssonde.

    Steuerzeichen fliegen also raus, und die Länge wird gedeckelt (ein 4-kB-Benutzername ist
    keine Anmeldung, sondern ein Versuch, das Log zu fluten).
    """
    text = "".join(z for z in str(wert if wert is not None else "") if z >= " " and z != "\x7f")
    return (text[:64] + "…") if len(text) > 64 else text


#: Rechte, mit denen die Security-Logdatei angelegt wird — bei der ersten Zeile und nach jeder
#: Rotation. Vorher entstand sie mit der Prozess-umask, in der Praxis `-rw-rw-r--`: welt-lesbar.
#: In den Zeilen stehen Benutzernamen und IP-Adressen; bis 0.18.x stand dort sogar das
#: Erst-Admin-Einmal-Token (B5-03). fail2ban liest die Datei als root, ein Log-Versand über die
#: Gruppe reicht — niemand sonst braucht sie. Gegenstück zu `Store.DATEIRECHTE` (0600).
LOG_DATEIRECHTE = 0o640


class _SicherheitsLogHandler(logging.handlers.WatchedFileHandler):
    """WatchedFileHandler, der die Datei mit `LOG_DATEIRECHTE` anlegt statt mit der umask.

    Das `mode`-Argument von `os.open` kann Rechte nur **wegnehmen** (die umask wird weiterhin
    abgezogen), nie hinzufügen — enger als 0640 eingestellte Betriebe bleiben also eng.
    Der Umweg über `opener` statt eines `chmod` danach vermeidet das Fenster, in dem die Datei
    offen dasteht, und greift auch dann, wenn logrotate die Datei wegnimmt und der Handler sie
    beim nächsten Satz **neu** anlegt — genau dort wäre ein einmaliges chmod beim Start wirkungslos.
    """

    def _open(self):
        def opener(pfad, flags):
            return os.open(pfad, flags, LOG_DATEIRECHTE)
        return open(self.baseFilename, self.mode, encoding=self.encoding,
                    errors=self.errors, opener=opener)


def attach_security_log(path: str) -> bool:
    """Den Security-Logger zusätzlich in eine Datei schreiben lassen — das, was die fail2ban-Jail
    liest (`deploy/fail2ban/`). Ohne diesen Handler zeigt die mitgelieferte Jail auf eine Datei,
    die nie entsteht: sie wäre still wirkungslos.

    Idempotent (derselbe Pfad wird nicht zweimal angehängt — mehrere TinySesam-Instanzen im selben
    Prozess sind erlaubt) und nicht start-verhindernd: ein nicht schreibbarer Pfad ist ein Grund
    zu warnen, aber keiner, die Anmeldung stillzulegen. Das Format trägt den Zeitstempel vorn,
    den fail2ban zum Datieren der Treffer braucht.

    Neu angelegt wird die Datei mit `LOG_DATEIRECHTE` (0640), nicht mehr mit der umask; eine
    schon vorhandene, welt-lesbare Datei wird gemeldet, aber nicht umgeschrieben.
    """
    path = str(path)
    for h in seclog.handlers:
        if getattr(h, "_tinysesam_path", None) == path:
            return True
    schon_da = os.path.exists(path)
    try:
        # WatchedFileHandler, nicht FileHandler: logrotate benennt die Datei um und legt eine
        # neue an — ein FileHandler hält den alten Inode offen und schreibt ab da in die
        # umbenannte Datei weiter. Die neue bliebe leer, und die fail2ban-Jail läse ab der
        # ERSTEN Rotation nichts mehr: kein Fehler, keine Meldung, nur ein Wächter, der nicht
        # mehr wacht. Der Watched-Handler prüft vor jeder Zeile Inode und Gerät und öffnet neu.
        # (Unter Windows ohne Wirkung — dort lässt sich eine offene Datei ohnehin nicht
        # umbenennen, und `copytruncate` ist der Weg.)
        h = _SicherheitsLogHandler(path, encoding="utf-8")
    except OSError as e:
        seclog.warning("security_log %s nicht schreibbar (%s) — fail2ban bekommt nichts zu lesen.",
                       path, e)
        return False
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    # Eigene Markierung am Handler, damit derselbe Pfad nicht zweimal angehängt wird. `setattr`
    # statt direkter Zuweisung: Das Attribut ist unseres, nicht das der Klasse — ein Typprüfer
    # meldete hier sonst zu Recht einen Fehler.
    setattr(h, "_tinysesam_path", path)
    seclog.addHandler(h)
    # Ohne eigenen Level erbt der Logger den der Wurzel; steht der auf ERROR, fehlen genau die
    # WARNING-Zeilen mit den Fehlversuchen.
    if seclog.level == logging.NOTSET or seclog.level > logging.WARNING:
        seclog.setLevel(logging.WARNING)
    # Erst hier, nach dem Level: Eine Warnung, die der Logger verwirft, ist keine. Eine
    # BESTEHENDE Datei wird nicht umgeschrieben — eine bewusste Freigabe an eine Gruppe
    # (Log-Versand, `adm`) ist eine Entscheidung des Betreibers, keine Lücke. Still bleibt sie
    # trotzdem nicht: In den Zeilen stehen Benutzernamen und IP-Adressen.
    if schon_da:
        try:
            modus = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            modus = 0
        if modus & 0o007:
            seclog.warning(
                "security_log %s ist welt-lesbar (%o). Darin stehen Benutzernamen und "
                "IP-Adressen. Enger stellen: chmod 640 %s", path, modus, path)
    return True


# Härtungs-Defaults — im Admin-Panel überschreibbar (store.setting). Nur diese Keys sind einstellbar.
SECURITY_DEFAULTS = {
    "max_login_attempts": 5,        # Fehlversuche je Konto UND IP (Paar) im Fenster → Lockout
    "lockout_window_sec": 900,      # Beobachtungs-/Sperrfenster (15 min)
    "ip_attempt_factor": 3,         # IP-Lockout-Schwelle = max_login_attempts * Faktor (mehrere User hinter NAT)
    "account_attempt_factor": 3,    # Konto-Schwelle über alle IPs = max_login_attempts * Faktor (verteiltes Raten)
    "rate_limit_max": 30,           # max Requests pro IP …
    "rate_limit_window_sec": 60,    # … je Fenster auf Auth-Endpoints
    "password_min_length": 8,
    "pin_max_attempts": 5,          # eigener, methoden-scoped Fehlversuch-Zähler für PIN (kurzer Keyspace)
    "password_change_max_attempts": 5,  # eigener Zähler für die Alt-Passwort-Abfrage auf der Kontoseite
    "reauth_max_attempts": 5,       # eigener Zähler für die Step-up-Bestätigung (/auth/reauth)
    "resource_max_attempts": 5,     # eigener Zähler für die Bereichs-PIN (/auth/resource/…, ohne Konto)
}

# Methoden aus `login_attempt`, die KEIN Anmeldeversuch sind und deshalb nicht in den
# Login-Lockout (`is_locked`) zählen dürfen — und daneben der Riegel, der jede von ihnen
# STATTDESSEN bremst.
#
# Warum überhaupt: Die Alt-Passwort-Abfrage der Kontoseite, die Step-up-Bestätigung und die
# Bereichs-PIN verbuchen ihre Fehlversuche in derselben Tabelle wie der Login (R4-10 — sonst
# wären sie stille Orakel). `is_locked` zählte aber methodenblind, und damit sperrten fünf
# Tippfehler auf der EIGENEN Kontoseite die Anmeldung für 15 Minuten — abtragen konnte der
# Nutzer sie durch nichts, denn ein Erfolg räumt nur die Fehlversuche derselben Methode weg.
# Hinter NAT reichten drei Kollegen mit je fünf Tippfehlern, um einem völlig unbeteiligten
# Vierten den Login zu verriegeln (`ip_attempt_factor`); bei der Bereichs-PIN genügten dafür
# fremde Besucher, die gar kein Konto haben.
#
# Die Zuordnung ist Absicht und keine Bequemlichkeit: Wer eine Methode hier einträgt, nimmt
# sie aus dem Login-Lockout — ohne eigenen Topf wäre sie damit unbegrenzt ratbar. Deshalb
# steht der Ersatz daneben, `NICHT_LOGIN_METHODEN` wird daraus abgeleitet (eine Methode ohne
# Riegel lässt sich gar nicht erst eintragen), und ein Test hält die Tabelle gegen die
# Methoden, mit denen der Router `record_login()` wirklich ruft.
#
# Bewusst eine **Ausnahmeliste**, keine Positivliste der Login-Methoden: Eine neue
# Anmeldemethode zählt damit von sich aus mit. Eine vergessene Zeile kostet hier Bequemlichkeit
# (eine Sperre zählt strenger als nötig), eine vergessene Zeile in einer Positivliste hätte ein
# Loch im Lockout gekostet.
EIGENE_SPERRE = {
    "password_change": "is_password_change_locked",
    "reauth": "is_reauth_locked",
    "resource": "is_resource_locked",
}

NICHT_LOGIN_METHODEN = tuple(EIGENE_SPERRE)

#: Das Ereigniswort der Zeile im Sicherheits-Log. **Nur `failed login` trifft die
#: mitgelieferte fail2ban-failregex** (`deploy/fail2ban/tinysesam-filter.conf`) — und das ist
#: der Punkt: Ein Fehlgriff aus `NICHT_LOGIN_METHODEN` stammt von jemandem, der schon
#: angemeldet ist (Kontoseite, Step-up) oder der gar kein Konto braucht (Bereichs-PIN). Mit
#: demselben Wort bannte die ausgelieferte Jail (`maxretry = 6`) einen legitimen Nutzer nach
#: ein paar Tippfehlern auf Firewall-Ebene aus — und zwar für die ganze Instanz, nicht für die
#: Route. Verschärfend: Ab der App-Sperre erzeugt jeder weitere Klick eine weitere Zeile.
#: Protokolliert wird deshalb unverändert, nur unter eigenem Namen; wer auch diese Zeilen
#: bannen will, nimmt die zweite, mildere Jail aus `deploy/fail2ban/`.
LOG_ANMELDUNG = "failed login"
LOG_PRUEFUNG = "failed verification"


def log_ereignis(method) -> str:
    """Welches Ereigniswort gehört in die Sicherheits-Log-Zeile dieser Methode?

    `failed login` nur für echte Anmeldeversuche — alles aus `NICHT_LOGIN_METHODEN` bekommt
    `failed verification` und läuft damit an der mitgelieferten fail2ban-Jail vorbei."""
    return LOG_PRUEFUNG if method in NICHT_LOGIN_METHODEN else LOG_ANMELDUNG


def safe_next(next_: str, default: str = "/", allowed_hosts=None) -> str:
    """Open-Redirect-Schutz für ?next=-Ziele.

    Erlaubt nur *relative* Pfade auf demselben Host (beginnen mit genau einem '/', kein
    protokoll-relatives '//', kein Schema, kein Backslash). Absolute URLs sind nur erlaubt,
    wenn ihr Host in allowed_hosts steht (für den Forward-Auth-/SSO-Fall). Alles andere → default.
    """
    if not next_:
        return default
    n = next_.strip()
    # relativer Pfad: genau ein führender Slash, kein Schema/Backslash/protokoll-relativ
    if n.startswith("/") and not n.startswith("//") and "\\" not in n and "://" not in n:
        return n
    if allowed_hosts:
        try:
            parts = urlsplit(n)
        except Exception:
            return default
        host = parts.hostname or ""
        if parts.scheme in ("http", "https") and host and host in allowed_hosts:
            return n
    return default


def eigener_host(host: str, allowed_hosts=None) -> bool:
    """Darf dieser Host in eine Adresse, die das Haus verlässt (Mail-Link, Redirect-URI)?

    Der Host aus `request.base_url` ist der rohe `Host`-Header, also eine **Eingabe des
    Clients** — kein Proxy und kein ASGI-Server prüft ihn. Wer eine Reset-Mail für ein fremdes
    Postfach anstößt und dabei `Host: angreifer.example` setzt, bekam bis 0.18.0 genau diesen
    Host in den Link, den das Opfer per Mail erhält (R4-01/R8-4). Deshalb gilt ein abgeleiteter
    Host nur, wenn er beweisbar der eigene ist:

    * er steht in `trusted_redirect_hosts` — derselbe Kreis, dem schon `?next=` trauen darf, oder
    * er ist eine Loopback-Adresse. Ein Link auf `localhost` nützt keinem Angreifer: er landet
      beim Empfänger selbst. Damit bleibt der lokale Aufbau ohne `base_url` benutzbar.

    Alles andere ist ein Fremdname. Der Aufrufer bricht dann ab — eine Mail, die gar nicht
    hinausgeht, ist besser als eine mit einem Link auf den Server des Angreifers.
    """
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return False
    if allowed_hosts and h in {str(a).strip().lower() for a in allowed_hosts if a}:
        return True
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


#: Welcher Pfadanteil aus einer abgeleiteten Basis mit hinausgehen darf. Eng gefasst und
#: fail-closed: Hier steht ein Mount-Präfix (`/sso`, `/auth/v2`), nichts anderes. Alles mit
#: Doppel-Schrägstrich, Prozentzeichen oder Leerraum fällt durch, und `.`/`..` als Segment
#: ebenso (`/../etc` wird nirgends normalisiert und stand sonst genau so in der Mail) — dann
#: gibt es keine Basis, statt eine halb geratene.
_PFAD_OK = re.compile(r"(?:/(?!\.{1,2}(?:/|$))[A-Za-z0-9._~-]+)+")


def normalisiere_basis(kandidat: str) -> str:
    """Eine Basis-URL auf ihre **Form** prüfen und kanonisch zusammensetzen — oder "" (fail closed).

    Beantwortet **nicht** die Frage, ob der Host der eigene ist; das macht `sichere_basis()`.
    Getrennt seit 0.18.0, weil beide Zweige von `TinySesam.public_base()` dieselbe Form brauchen:
    Bis dahin lief nur der **abgeleitete** Zweig hier durch, während ein konfiguriertes `base_url`
    lediglich `strip().rstrip("/")` sah und die Konfigurationsprüfung es mit einem groben
    Schema-und-Host-Muster abnahm. Damit kam durch, was hier scheitert: eine Benutzerangabe im Host
    (`https://wer:was@auth.example` — sie stünde in jedem Reset-Link und in jeder Redirect-URI),
    ein Fragment oder eine Abfrage, ein unzulässiger Port, ein Pfad mit `..` oder `//`. Eine Regel,
    zwei Aufrufer — nicht zwei Regelwerke, von denen eines schwächer ist.

    Der **Pfadanteil kommt mit**: `request.base_url` trägt den `root_path` des ASGI-Servers
    (uvicorn `--root-path`, ein `Mount`), und bis 0.18.x warf diese Funktion ihn weg. Wer die
    App unter einem Unterpfad montiert hatte, bekam Mail-Links ohne das Präfix — also
    404 statt Reset-Formular. Der `root_path` ist Serverkonfiguration, keine Client-Eingabe
    (weder uvicorn noch Starlette leiten ihn aus einem Header ab), er wird aber trotzdem gegen
    `_PFAD_OK` geprüft: eine Basis, die wir nicht sauber zusammensetzen können, gibt es nicht.
    """
    roh = str(kandidat or "").strip()
    if not roh:
        return ""
    try:
        teile = urlsplit(roh)
    except Exception:
        return ""
    if teile.scheme not in ("http", "https") or not teile.netloc:
        return ""
    # Abfrage und Fragment gehören nicht in eine Basis: Was hinten angehängt wird (Token, Pfad),
    # stünde sonst HINTER dem `#` und erreichte den Server nie — der Link sähe gültig aus und
    # führte ins Leere.
    if teile.query or teile.fragment:
        return ""
    host = teile.hostname or ""
    if not host:
        return ""
    # Neu zusammengesetzt statt `netloc` übernommen: eine Benutzerangabe im Host
    # (`https://vertraut.example@…`) wäre sonst Teil jedes ausgehenden Links. Geprüft wird
    # ohnehin nur `hostname`, also darf auch nur der hinaus.
    try:
        port = teile.port
    except ValueError:
        return ""
    if ":" in host:
        host = f"[{host}]"
    pfad = (teile.path or "").rstrip("/")
    if pfad and not _PFAD_OK.fullmatch(pfad):
        return ""
    return f"{teile.scheme}://{host}" + (f":{port}" if port else "") + pfad


def sichere_basis(kandidat: str, allowed_hosts=None) -> str:
    """Eine **abgeleitete** Basis-URL prüfen: Form (`normalisiere_basis`) **und** eigener Host.

    Leer heißt: es gibt keine vertrauenswürdige öffentliche Adresse. Nicht raten — abbrechen.
    Der Unterschied zu `normalisiere_basis()` ist die Herkunft: Was aus dem `Host`-Header kommt,
    muss zusätzlich belegen, dass es ein eigener Name ist (R4-01/CWE-644).
    """
    roh = str(kandidat or "").strip()
    if not roh:
        return ""
    try:
        host = urlsplit(roh).hostname or ""
    except Exception:
        return ""
    if not eigener_host(host, allowed_hosts):
        return ""
    return normalisiere_basis(roh)


def is_trusted(ip: str, trusted_nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in trusted_nets)
    except Exception:
        return False


# Peers, über die schon geklagt wurde — eine Fehlkonfiguration meldet sich einmal, nicht pro
# Request. Ein Log-Sturm wird weggefiltert und hilft niemandem.
_GEMELDETE_PEERS: set = set()

#: Schlüssel, zu denen schon eine Hinweiszeile im Security-Log steht (`einmal_melden`).
#: Gedeckelt: Der Schlüssel stammt aus der Anfrage, und wer den `Host`-Header durchprobiert,
#: soll weder die Datei noch den Speicher füllen.
#:
#: Der Deckel gilt **je Zeitfenster**, nicht für die Lebensdauer des Prozesses (C-4, 0.18.0):
#: Vorher genügten 512 erfundene `Host`-Werte, um die Stelle bis zum Neustart stillzulegen —
#: danach blieb auch der Hinweis auf den **echten** Betriebsfehler aus. Ein Angreifer konnte
#: also nicht nur Lärm machen, sondern gezielt eine Warnung abschalten. Jetzt beginnt nach
#: `_GEMELDET_FENSTER_SEK` ein neues Fenster, und das Erreichen des Deckels sagt einmal laut,
#: dass ab hier geschwiegen wird — eine unsichtbare Unterdrückung wäre dasselbe Loch.
_GEMELDET_MAX = 512
_GEMELDET_FENSTER_SEK = 3600
_GEMELDET: set = set()

#: Beginn des laufenden Fensters und ob der Deckel darin schon gemeldet wurde. Bewusst ein dict
#: und keine zwei Modul-Variablen: Die müssten in jeder schreibenden Funktion `global` heissen,
#: und eine per `global` gesetzte Variable liest CodeQL als ungenutzt (py/unused-global-variable)
#: — ein Fehlalarm, den man sonst je Fassung neu abweisen müsste.
_GEMELDET_FENSTER = {"beginn": 0.0, "ueberlauf": False}


def einmal_melden(schluessel: str, jetzt: float | None = None) -> bool:
    """True genau beim ersten Aufruf mit diesem Schlüssel, danach False — gegen Log-Stürme.

    Dieselbe Idee wie `_GEMELDETE_PEERS` in `client_ip()`, nur allgemein: Ein Hinweis auf eine
    **Fehlkonfiguration** sagt beim ersten Mal alles; wiederholt er sich je Anfrage, füllt er
    die Datei, auf die die fail2ban-Jail zeigt und die logrotate wochenlang aufhebt. Ein
    Seitenaufruf mit zwanzig Unterressourcen schrieb so zwanzig gleiche Zeilen, ein Crawler
    beliebig viele — die Meldung wird dadurch nicht richtiger, nur lauter.

    Der Schlüssel gehört zur Ursache, nicht zur einzelnen Anfrage (also der Host, nicht die
    vollständige URL) — sonst hebt jeder neue Pfad die Sperre wieder auf.

    Der Zustand ist prozessweit: Ein Test, der die Zeile sehen will, leert `_GEMELDET` vorher
    (Tests müssen wiederholbar bleiben) — dafür gibt es `einmal_melden_zuruecksetzen()`.

    `jetzt` ist nur für Tests da: So lässt sich der Fensterwechsel prüfen, ohne eine Stunde zu
    warten (ein Test, der schläft, ist kein Test).
    """
    t = time.time() if jetzt is None else float(jetzt)
    if t - _GEMELDET_FENSTER["beginn"] >= _GEMELDET_FENSTER_SEK:
        _GEMELDET.clear()
        _GEMELDET_FENSTER["beginn"] = t
        _GEMELDET_FENSTER["ueberlauf"] = False
    if schluessel in _GEMELDET:
        return False
    if len(_GEMELDET) >= _GEMELDET_MAX:
        if not _GEMELDET_FENSTER["ueberlauf"]:
            _GEMELDET_FENSTER["ueberlauf"] = True
            # Direkt und nicht über `einmal_melden()` — sonst geriete die Meldung über den
            # Deckel in denselben Deckel. Genau eine Zeile je Fenster.
            seclog.warning(
                "Hinweis-Deckel erreicht: %d verschiedene Schlüssel in diesem Fenster (%d s). "
                "Weitere Hinweise dieser Art bleiben bis zum Fensterwechsel aus. Wer den "
                "Host-Header durchprobiert, erzeugt genau dieses Bild — steht base_url, ist "
                "der Host-Header ohnehin ohne Wirkung.",
                _GEMELDET_MAX, _GEMELDET_FENSTER_SEK)
        return False
    _GEMELDET.add(schluessel)
    return True


def einmal_melden_zuruecksetzen() -> None:
    """Den Hinweis-Speicher leeren (Tests, und ein Betrieb, der bewusst neu hören will)."""
    _GEMELDET.clear()
    _GEMELDET_FENSTER["beginn"] = 0.0
    _GEMELDET_FENSTER["ueberlauf"] = False


def client_ip(request, trusted_nets) -> str:
    """Echte Client-IP. Nur wenn der direkte Peer vertrauenswürdig ist, wird X-Forwarded-For ausgewertet
    (rechteste NICHT-vertrauenswürdige Adresse) — sonst ist XFF fälschbar.

    **Der häufigste Fehlbetrieb ist still**: Im Container ist der Proxy ein anderer Container,
    also nicht `127.0.0.1`. Die Vorgabe passt dann nicht, XFF wird verworfen, und JEDER Nutzer
    erscheint unter der Proxy-IP — Rate-Limit und IP-Sperre gelten ab da kollektiv, und fail2ban
    bannt im Ernstfall den Proxy, also alle. Nichts davon sieht nach einem Fehler aus. Deshalb
    sagt diese Funktion einmal je Peer Bescheid.
    """
    peer = request.client.host if request.client else "?"
    xff = request.headers.get("x-forwarded-for")
    if xff and is_trusted(peer, trusted_nets):
        for ip in reversed([p.strip() for p in xff.split(",") if p.strip()]):
            if not is_trusted(ip, trusted_nets):
                return ip
    if xff and peer not in _GEMELDETE_PEERS:
        _GEMELDETE_PEERS.add(peer)
        if not is_trusted(peer, trusted_nets):
            seclog.warning(
                "X-Forwarded-For von %s wird ignoriert: Der Peer steht nicht in trusted_proxies "
                "(%s). Alle Nutzer erscheinen jetzt unter dieser einen IP — Rate-Limit und "
                "IP-Sperre wirken kollektiv. Im Container ist der Proxy KEIN 127.0.0.1: das "
                "Netz des Proxys eintragen, z.B. trusted_proxies=['172.28.0.0/16'].",
                peer, list(trusted_nets or []))
        else:
            # Peer vertraut, aber KEINE nicht-vertrauenswürdige Adresse im XFF gefunden — das
            # ist der Fall `trusted_proxies=['0.0.0.0/0']`: Wenn jede Adresse als Proxy gilt,
            # bleibt keine als Client übrig, und XFF ist wirkungslos statt großzügig.
            seclog.warning(
                "X-Forwarded-For (%s) enthält keine Adresse ausserhalb von trusted_proxies (%s) "
                "— es bleibt bei der Peer-IP %s. Ein Eintrag wie 0.0.0.0/0 entwertet XFF, statt "
                "ihm zu vertrauen: Nur das Netz des eigenen Proxys eintragen.",
                xff, list(trusted_nets or []), peer)
    return peer


class RateLimiter:
    """In-memory Token-Bucket pro Schlüssel (IP), pro Prozess. Für Single-Worker-Deployments;
    bei mehreren Workern greift zusätzlich die DB-basierte Regulation (Lockout). Für ein
    prozessübergreifendes Limit RedisRateLimiter nutzen (config.redis_url).

    **Gedeckelt** (R7-5): Bis T-13 wuchs das Wörterbuch mit jeder neuen Adresse und schrumpfte
    nie — ein leerer Eimer blieb als Schlüssel stehen. Wer die Quelladresse wechselt (IPv6
    liefert davon ein /64 pro Anschluss), füllte so den Speicher des Prozesses. Jetzt gilt
    `max_keys`, und darüber geht der am längsten ruhende Schlüssel zuerst — jede Anfrage, auch
    eine abgewiesene, rückt ihren Schlüssel nach vorn. Wer gerade gebremst wird, fragt also
    ständig und bleibt; verdrängt wird, wessen letzter Versuch am weitesten zurückliegt.
    """
    def __init__(self, max_keys: int = 100_000):
        self._hits: OrderedDict = OrderedDict()
        self.max_keys = max(1, int(max_keys))

    def allow(self, key: str, max_requests: int, window_sec: int) -> bool:
        now = time.time()
        dq = self._hits.get(key)
        if dq is None:
            dq = self._hits[key] = deque()
        self._hits.move_to_end(key)
        while dq and dq[0] < now - window_sec:
            dq.popleft()
        if len(dq) >= max_requests:
            return False
        dq.append(now)
        while len(self._hits) > self.max_keys:
            self._hits.popitem(last=False)
        return True

    def __len__(self) -> int:
        return len(self._hits)


class RedisRateLimiter:
    """Prozessübergreifendes Rate-Limit über Redis (Fixed-Window-Counter) — für Multi-Worker/
    Multi-Instanz. Gleiche allow()-Schnittstelle.

    **Bei einem Redis-Ausfall wird nicht aufgemacht, sondern je Prozess weitergezählt** (B6-1).
    Bis T-13 hiess es hier „fail-open (erlauben)" mit der Begründung, die DB-Sperre greife ja
    weiter. Die gibt es aber nur an den Anmelde-Routen; Magic-Link-Anforderung, Passwort
    vergessen, Registrierung und der Start der Föderation hängen allein an diesem Limit — ohne
    Redis waren sie offen, und die ersten beiden verschicken Mails an beliebige Adressen. Jetzt
    übernimmt ein eingebauter `RateLimiter`: pro Prozess statt über alle, also bis zu N-mal so
    grosszügig — aber eine Grenze. Ausgesperrt wird durch den Ausfall niemand.

    **Und er wird bemerkt** (B6-2): Der Konstruktor fragt Redis einmal (`ping`), statt den
    Ausfall erst beim ersten Besucher zu entdecken. Gemeldet wird der **Wechsel** — einmal beim
    Ausfall, einmal bei der Rückkehr —, nicht jede Anfrage: vorher schrieb jede Anfrage eine
    Warnzeile in genau die Datei, die fail2ban liest. Nach einem Fehler ruht Redis
    `pause_sec` lang, danach wird es wieder versucht; so hängt nicht jede Anfrage im Timeout
    eines toten Servers. Dazu kurze Socket-Timeouts: Ein Redis, das nicht antwortet (statt
    abzulehnen), hielt sonst jede Anfrage unbegrenzt fest.
    """
    def __init__(self, url: str, prefix: str = "tsrl", pause_sec: float = 30.0, timeout_sec: float = 1.0):
        import redis   # Extra [redis]
        self.client = redis.from_url(url, socket_connect_timeout=timeout_sec, socket_timeout=timeout_sec)
        self.prefix = prefix
        self._einrichten(pause_sec)
        try:
            self.client.ping()
        except Exception as e:
            self._ausgefallen(e)

    def _einrichten(self, pause_sec: float = 30.0) -> None:
        """Rückfall-Zustand anlegen (auch für Tests, die `__init__` umgehen)."""
        self.ersatz = RateLimiter()
        self.pause_sec = pause_sec
        self._pause_bis = 0.0
        self._gestoert = False

    def _ausgefallen(self, fehler) -> None:
        self._pause_bis = time.time() + self.pause_sec
        if not self._gestoert:
            self._gestoert = True
            seclog.warning("Redis-Rate-Limit nicht erreichbar (%s) — es zählt jetzt jeder Prozess "
                           "für sich weiter, bis Redis wieder antwortet.", fehler)

    def allow(self, key: str, max_requests: int, window_sec: int) -> bool:
        if not hasattr(self, "ersatz"):
            self._einrichten()
        if self._gestoert and time.time() < self._pause_bis:
            return self.ersatz.allow(key, max_requests, window_sec)
        try:
            bucket = int(time.time() // max(1, window_sec))
            rk = f"{self.prefix}:{key}:{window_sec}:{bucket}"
            pipe = self.client.pipeline()
            pipe.incr(rk)
            pipe.expire(rk, window_sec)
            count = pipe.execute()[0]
        except Exception as e:
            self._ausgefallen(e)
            return self.ersatz.allow(key, max_requests, window_sec)
        if self._gestoert:
            self._gestoert = False
            seclog.warning("Redis-Rate-Limit wieder erreichbar — es zählt wieder über alle Prozesse.")
        return int(count) <= max_requests

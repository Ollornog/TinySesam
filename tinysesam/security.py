"""Härtung: echte Client-IP (Trusted-Proxy), Rate-Limiting, fail2ban-Logger.
Die Brute-Force-Regulation selbst lebt im Manager (DB-basiert, Panel-konfigurierbar)."""
from __future__ import annotations
import os
import stat
import time
import logging
import logging.handlers
import ipaddress
from urllib.parse import urlsplit
from collections import defaultdict, deque

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
    "max_login_attempts": 5,        # Fehlversuche pro User im Fenster → Lockout
    "lockout_window_sec": 900,      # Beobachtungs-/Sperrfenster (15 min)
    "ip_attempt_factor": 3,         # IP-Lockout-Schwelle = max_login_attempts * Faktor (mehrere User hinter NAT)
    "rate_limit_max": 30,           # max Requests pro IP …
    "rate_limit_window_sec": 60,    # … je Fenster auf Auth-Endpoints
    "password_min_length": 8,
    "pin_max_attempts": 5,          # eigener, methoden-scoped Fehlversuch-Zähler für PIN (kurzer Keyspace)
}


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


def sichere_basis(kandidat: str, allowed_hosts=None) -> str:
    """Eine abgeleitete Basis-URL prüfen: Rückgabe ohne Schrägstrich am Ende, oder "" (fail closed).

    Leer heißt: es gibt keine vertrauenswürdige öffentliche Adresse. Nicht raten — abbrechen.
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
    host = teile.hostname or ""
    if not eigener_host(host, allowed_hosts):
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
    return f"{teile.scheme}://{host}" + (f":{port}" if port else "")


def is_trusted(ip: str, trusted_nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in trusted_nets)
    except Exception:
        return False


# Peers, über die schon geklagt wurde — eine Fehlkonfiguration meldet sich einmal, nicht pro
# Request. Ein Log-Sturm wird weggefiltert und hilft niemandem.
_GEMELDETE_PEERS: set = set()


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
    prozessübergreifendes Limit RedisRateLimiter nutzen (config.redis_url)."""
    def __init__(self):
        self._hits = defaultdict(deque)

    def allow(self, key: str, max_requests: int, window_sec: int) -> bool:
        now = time.time()
        dq = self._hits[key]
        while dq and dq[0] < now - window_sec:
            dq.popleft()
        if len(dq) >= max_requests:
            return False
        dq.append(now)
        return True


class RedisRateLimiter:
    """Prozessübergreifendes Rate-Limit über Redis (Fixed-Window-Counter) — für Multi-Worker/
    Multi-Instanz. Gleiche allow()-Schnittstelle. Bei Redis-Fehler: fail-open (erlauben) + Log,
    damit ein Redis-Ausfall keine Nutzer aussperrt (die DB-Lockout-Regulation greift weiter)."""
    def __init__(self, url: str, prefix: str = "tsrl"):
        import redis   # Extra [redis]
        self.client = redis.from_url(url)
        self.prefix = prefix

    def allow(self, key: str, max_requests: int, window_sec: int) -> bool:
        try:
            bucket = int(time.time() // max(1, window_sec))
            rk = f"{self.prefix}:{key}:{window_sec}:{bucket}"
            pipe = self.client.pipeline()
            pipe.incr(rk)
            pipe.expire(rk, window_sec)
            count = pipe.execute()[0]
            return int(count) <= max_requests
        except Exception as e:
            seclog.warning("redis rate-limit fail-open: %s", e)
            return True

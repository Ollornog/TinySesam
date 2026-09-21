"""Härtung: echte Client-IP (Trusted-Proxy), Rate-Limiting, fail2ban-Logger.
Die Brute-Force-Regulation selbst lebt im Manager (DB-basiert, Panel-konfigurierbar)."""
from __future__ import annotations
import time
import logging
import logging.handlers
import ipaddress
from urllib.parse import urlsplit
from collections import defaultdict, deque

# fail2ban parst diesen Logger. Failed-Login-Zeilen enthalten "ip=<IP>" → Filter matcht darauf.
seclog = logging.getLogger("tinysesam.security")

def attach_security_log(path: str) -> bool:
    """Den Security-Logger zusätzlich in eine Datei schreiben lassen — das, was die fail2ban-Jail
    liest (`deploy/fail2ban/`). Ohne diesen Handler zeigt die mitgelieferte Jail auf eine Datei,
    die nie entsteht: sie wäre still wirkungslos.

    Idempotent (derselbe Pfad wird nicht zweimal angehängt — mehrere TinySesam-Instanzen im selben
    Prozess sind erlaubt) und nicht start-verhindernd: ein nicht schreibbarer Pfad ist ein Grund
    zu warnen, aber keiner, die Anmeldung stillzulegen. Das Format trägt den Zeitstempel vorn,
    den fail2ban zum Datieren der Treffer braucht.
    """
    path = str(path)
    for h in seclog.handlers:
        if getattr(h, "_tinysesam_path", None) == path:
            return True
    try:
        # WatchedFileHandler, nicht FileHandler: logrotate benennt die Datei um und legt eine
        # neue an — ein FileHandler hält den alten Inode offen und schreibt ab da in die
        # umbenannte Datei weiter. Die neue bliebe leer, und die fail2ban-Jail läse ab der
        # ERSTEN Rotation nichts mehr: kein Fehler, keine Meldung, nur ein Wächter, der nicht
        # mehr wacht. Der Watched-Handler prüft vor jeder Zeile Inode und Gerät und öffnet neu.
        # (Unter Windows ohne Wirkung — dort lässt sich eine offene Datei ohnehin nicht
        # umbenennen, und `copytruncate` ist der Weg.)
        h = logging.handlers.WatchedFileHandler(path, encoding="utf-8")
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

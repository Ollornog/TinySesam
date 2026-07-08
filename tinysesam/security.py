"""Härtung: echte Client-IP (Trusted-Proxy), Rate-Limiting, fail2ban-Logger.
Die Brute-Force-Regulation selbst lebt im Manager (DB-basiert, Panel-konfigurierbar)."""
from __future__ import annotations
import time
import logging
import ipaddress
from urllib.parse import urlsplit
from collections import defaultdict, deque

# fail2ban parst diesen Logger. Failed-Login-Zeilen enthalten "ip=<IP>" → Filter matcht darauf.
seclog = logging.getLogger("tinysesam.security")

# Härtungs-Defaults — im Admin-Panel überschreibbar (store.setting). Nur diese Keys sind einstellbar.
SECURITY_DEFAULTS = {
    "max_login_attempts": 5,        # Fehlversuche pro User im Fenster → Lockout
    "lockout_window_sec": 900,      # Beobachtungs-/Sperrfenster (15 min)
    "ip_attempt_factor": 3,         # IP-Lockout-Schwelle = max_login_attempts * Faktor (mehrere User hinter NAT)
    "rate_limit_max": 30,           # max Requests pro IP …
    "rate_limit_window_sec": 60,    # … je Fenster auf Auth-Endpoints
    "password_min_length": 8,
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


def client_ip(request, trusted_nets) -> str:
    """Echte Client-IP. Nur wenn der direkte Peer vertrauenswürdig ist, wird X-Forwarded-For ausgewertet
    (rechteste NICHT-vertrauenswürdige Adresse) — sonst ist XFF fälschbar."""
    peer = request.client.host if request.client else "?"
    xff = request.headers.get("x-forwarded-for")
    if xff and is_trusted(peer, trusted_nets):
        for ip in reversed([p.strip() for p in xff.split(",") if p.strip()]):
            if not is_trusted(ip, trusted_nets):
                return ip
    return peer


class RateLimiter:
    """In-memory Token-Bucket pro Schlüssel (IP), pro Prozess. Für Single-Worker-Deployments;
    bei mehreren Workern greift zusätzlich die DB-basierte Regulation (Lockout)."""
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

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
import time
import json
import hashlib
import secrets
from typing import Optional

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from .config import TinySesamConfig
from .store import Store
from .passwords import hash_password, verify_password, needs_rehash
from .templates import Templates
from . import totp as _totp
from . import security


class TinySesam:
    def __init__(self, config: TinySesamConfig):
        self.cfg = config
        self.store = Store(config.db_path)
        self.templates = Templates()
        self.oidc = None
        self.webauthn = None
        self.rl = security.RateLimiter()
        if config.oidc_enabled and config.oidc_issuer and config.oidc_client_id:
            from .oidc import OIDCClient
            self.oidc = OIDCClient(config.oidc_issuer, config.oidc_client_id,
                                   config.oidc_client_secret, config.oidc_scopes)
        if config.passkey_enabled:
            from . import webauthn_ as wa
            self.webauthn = wa

    # ---------- User-Verwaltung ----------
    def create_user(self, username, password=None, is_admin=False, roles=None,
                    display_name=None, email=None, is_service=False) -> int:
        uid = self.store.create_user(username, display_name, email, is_admin, roles, is_service)
        if password:
            self.store.set_password_hash(uid, hash_password(password))
        return uid

    # Rollen (optional). paperlaiss braucht das NICHT — dort reicht require_user (eingeloggt/nicht).
    # Andere Projekte differenzieren User über is_admin + frei definierbare roles.
    def user_roles(self, user) -> list:
        import json
        try:
            return json.loads(user["roles"] or "[]")
        except Exception:
            return []

    def is_admin(self, user) -> bool:
        return bool(user["is_admin"])

    def has_role(self, user, role) -> bool:
        return bool(user["is_admin"]) or role in self.user_roles(user)

    def set_roles(self, user_id, roles):
        self.store.set_roles(user_id, roles)

    # ---------- API-Keys / Service-Accounts (maschineller Zugang, Daemons) ----------
    def create_service(self, username, roles=None, display_name=None) -> int:
        """Service-/Daemon-Account: kein interaktiver Login, nur API-Keys. Rollen = Rechte-Scope."""
        return self.create_user(username, is_service=True, roles=roles, display_name=display_name or username)

    def create_api_key(self, user_id, name=None, expires_days=None, roles=None) -> dict:
        """Neuen API-Key erzeugen. Rückgabe enthält 'key' im KLARTEXT — nur EINMAL (danach nur der Hash)."""
        raw = "tsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:12] + "…"
        expires_at = (int(time.time()) + int(expires_days) * 86400) if expires_days is not None else None
        kid = self.store.add_api_key(user_id, name, prefix, key_hash, roles, expires_at)
        self.audit("apikey_create", detail=f"user={user_id} key={kid} name={name}")
        return {"id": kid, "key": raw, "prefix": prefix, "expires_at": expires_at}

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
        return self.store.list_api_keys(user_id)

    def revoke_api_key(self, key_id, user_id=None):
        self.store.revoke_api_key(key_id, user_id)
        self.audit("apikey_revoke", detail=f"key={key_id}")

    def set_password(self, user_id, password):
        self.store.set_password_hash(user_id, hash_password(password))

    def ensure_admin(self, username, password) -> bool:
        """Bootstrap: legt einen Admin an, WENN noch kein User existiert. True bei Anlage."""
        if self.store.user_count() == 0:
            self.create_user(username, password, is_admin=True)
            return True
        return False

    def get_user(self, user_id):
        return self.store.get_user(user_id)

    # ---------- Passwort-Login ----------
    def check_password(self, username, password) -> Optional[dict]:
        u = self.store.get_user_by_name(username)
        if not u or u["disabled"]:
            return None
        h = self.store.get_password_hash(u["id"])
        if not h or not verify_password(password, h):
            return None
        if needs_rehash(h):
            self.store.set_password_hash(u["id"], hash_password(password))
        return u

    # ---------- MFA (TOTP) ----------
    def mfa_pending(self, user_id) -> bool:
        """TOTP verlangt? Ja wenn confirmed-TOTP existiert (oder global erzwungen + eingerichtet)."""
        return self.store.has_confirmed_totp(user_id)

    def verify_totp(self, user_id, code) -> bool:
        t = self.store.get_totp(user_id)
        return bool(t and t["confirmed"] and _totp.verify(t["secret"], code))

    def totp_begin(self, user_id):
        secret = _totp.new_secret()
        self.store.set_totp(user_id, secret, confirmed=False)
        u = self.store.get_user(user_id)
        uri = _totp.provisioning_uri(secret, u["username"], self.cfg.rp_name)
        return {"secret": secret, "uri": uri, "qr": _totp.qr_data_uri(uri)}

    def totp_confirm(self, user_id, code) -> bool:
        t = self.store.get_totp(user_id)
        if t and _totp.verify(t["secret"], code):
            self.store.confirm_totp(user_id)
            return True
        return False

    def totp_disable(self, user_id):
        self.store.delete_totp(user_id)

    # ---------- Sessions ----------
    def _ttl(self, remember: bool = True) -> int:
        """Server-Session-Lebensdauer. remember=False → kurze Transient-TTL (Session-Cookie)."""
        hours = self.cfg.session_ttl_hours if remember else self.cfg.session_ttl_transient_hours
        return hours * 3600

    def start_session(self, user_id, method, ip=None, ua=None, remember: bool = True) -> tuple[str, bool]:
        """Session anlegen. Gibt (token, mfa_ok). mfa_ok=False → TOTP-Schritt nötig."""
        needs = self.mfa_pending(user_id)
        # Passkey ist bereits ein starker Faktor → kein zusätzliches TOTP nötig
        mfa_ok = (method == "passkey") or (not needs)
        token = self.store.create_session(user_id, self._ttl(remember), mfa_ok, method, ip, ua, remember)
        if mfa_ok:   # voller Login abgeschlossen → Audit
            u = self.store.get_user(user_id)
            self.store.audit_log("login", u["username"] if u else None, ip, method)
        return token, mfa_ok

    def complete_mfa(self, token):
        self.store.set_session_mfa(token, True)
        s = self.store.get_session(token)
        if s:
            u = self.store.get_user(s["user_id"])
            self.store.audit_log("login", u["username"] if u else None, s["ip"], "totp")

    def session_from_request(self, request):
        return self.store.get_session(request.cookies.get(self.cfg.session_cookie))

    def current_user(self, request) -> Optional[dict]:
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
                    if key_roles is not None:      # Key-Scope überschreibt die User-Rollen
                        d["roles"] = json.dumps(key_roles)
                    return d
        return None

    def pending_user(self, request) -> Optional[dict]:
        """User einer Session, die noch im MFA-Schritt hängt (mfa_ok=0)."""
        s = self.session_from_request(request)
        if not s or s["mfa_ok"]:
            return None
        return self.store.get_user(s["user_id"])

    def set_cookie(self, response, token, remember: bool = True):
        """Session-Cookie setzen. remember=True → persistentes Cookie (max_age = lange TTL);
        remember=False → reines Session-Cookie (max_age=None, endet beim Browser-Schließen)."""
        kw = dict(httponly=True, secure=self.cfg.cookie_secure,
                  samesite=self.cfg.cookie_samesite, path=self.cfg.cookie_path)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        if remember:
            kw["max_age"] = self._ttl(True)
        response.set_cookie(self.cfg.session_cookie, token, **kw)

    def logout(self, request, response):
        s = self.session_from_request(request)
        if s:
            self.store.delete_session(s["token"])
        kw = dict(path=self.cfg.cookie_path)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.delete_cookie(self.cfg.session_cookie, **kw)

    # ---------- Härtung (Regulation / Rate-Limit / Audit) ----------
    def client_ip(self, request: Request) -> str:
        return security.client_ip(request, self.cfg.trusted_proxies)

    def sec(self, key) -> int:
        """Härtungs-Wert: Store-Setting (Panel) ODER Default."""
        v = self.store.get_setting(key)
        try:
            return int(v) if v is not None else security.SECURITY_DEFAULTS[key]
        except Exception:
            return security.SECURITY_DEFAULTS[key]

    def all_security(self) -> dict:
        return {k: self.sec(k) for k in security.SECURITY_DEFAULTS}

    def set_security(self, key, value):
        if key in security.SECURITY_DEFAULTS:
            self.store.set_setting(key, int(value))

    def rate_ok(self, ip) -> bool:
        return self.rl.allow(ip or "?", self.sec("rate_limit_max"), self.sec("rate_limit_window_sec"))

    def is_locked(self, username, ip) -> bool:
        """Zu viele Fehlversuche im Fenster — pro User ODER pro IP (IP-Schwelle höher wg. NAT)."""
        since = int(time.time()) - self.sec("lockout_window_sec")
        if username and self.store.count_fails(since, username=username) >= self.sec("max_login_attempts"):
            return True
        if ip and self.store.count_fails(since, ip=ip) >= self.sec("max_login_attempts") * self.sec("ip_attempt_factor"):
            return True
        return False

    def record_login(self, username, ip, success, method):
        self.store.record_attempt(username, ip, success, method)
        if success:
            self.store.clear_fails(username=username)   # 'login'-Audit erst beim vollen Abschluss (start_session/complete_mfa)
        else:
            self.store.audit_log("login_fail", username, ip, method)
            # fail2ban parst diese Zeile (ip=…)
            security.seclog.warning("failed login user=%s ip=%s method=%s", username, ip, method)

    def audit(self, event, username=None, ip=None, detail=None):
        self.store.audit_log(event, username, ip, detail)

    # ---------- Update (Panel-editierbar: manuell/automatisch + Version-Pin) ----------
    def update_settings(self) -> dict:
        return {"mode": self.store.get_setting("update_mode") or "manual",   # manual | auto
                "pin": self.store.get_setting("update_pin") or ""}           # z.B. 'v0.2.0'; leer = neueste

    def set_update_setting(self, key, value):
        if key == "mode" and value in ("manual", "auto"):
            self.store.set_setting("update_mode", value)
        elif key == "pin":
            self.store.set_setting("update_pin", str(value or ""))

    def update_status(self) -> dict:
        from . import updater
        pin = self.store.get_setting("update_pin") or None
        st = updater.update_available(pin=pin)
        st["mode"] = self.store.get_setting("update_mode") or "manual"
        return st

    def run_update(self) -> dict:
        """Update anstoßen (auf gepinnte Version oder neueste). Host-App muss danach neu starten."""
        from . import updater
        pin = self.store.get_setting("update_pin") or None
        ref = pin or (updater.latest_version() or {}).get("ref")
        r = updater.self_update(ref=ref)
        self.audit("update", detail=f"pin={pin} ref={ref} ok={r.get('ok')}")
        return r

    def auto_update(self) -> dict:
        """Für Startup/Cron: nur im Modus 'auto' und nur wenn ein Update verfügbar ist."""
        if (self.store.get_setting("update_mode") or "manual") != "auto":
            return {"skipped": "manueller Modus"}
        st = self.update_status()
        return self.run_update() if st.get("available") else {"up_to_date": True, **st}

    # ---------- Views / Redirect-Sicherheit ----------
    def set_template(self, name, fn):
        """Eine eingebaute Seite durch einen eigenen Renderer ersetzen: fn(auth, ctx) -> str | Response.
        Namen: 'login', 'totp', 'totp_setup', 'account', 'register', 'magic_request', 'magic_sent',
        'resource_pin' (je nach aktivierten Features). String → HTML mit Status; Response → 1:1."""
        self.templates.set(name, fn)

    def render_page(self, name, status=200, **ctx) -> Response:
        out = self.templates.render(name, self, ctx)
        if isinstance(out, Response):
            return out
        return HTMLResponse(out, status_code=status)

    def safe_next(self, next_: str) -> str:
        """?next=-Ziel gegen Open-Redirect absichern (nur relative Pfade bzw. trusted_redirect_hosts)."""
        return security.safe_next(next_, self.cfg.login_redirect, self.cfg.trusted_redirect_hosts or None)

    # ---------- FastAPI-Integration ----------
    def router(self):
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

    def install_https(self, app):
        """HTTPS gemäß config.https_mode: 'force' → HTTP→HTTPS-Redirect-Middleware; 'warn'/'off' →
        läuft auch OHNE Zertifikat (bei 'warn' Panel-Hinweis). Gibt den Modus zurück."""
        if self.cfg.https_mode == "force":
            from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
            app.add_middleware(HTTPSRedirectMiddleware)
        return self.cfg.https_mode

    def _deny(self, request: Request):
        # HTML-Browser → Redirect zum Login; sonst (API/JSON) → 401
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.cfg.login_path}?next={nxt}"})
        raise HTTPException(401, "nicht eingeloggt")

    def require_user(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): erzwingt eingeloggten (inkl. MFA) User.
        paperlaiss: `Depends(auth.require_user)` — mehr braucht es dort nicht."""
        u = self.current_user(request)
        if not u:
            self._deny(request)
        return u

    def require_admin(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): eingeloggt + Admin."""
        u = self.require_user(request)
        if not self.is_admin(u):
            raise HTTPException(403, "Adminrechte nötig")
        return u

    def require_role(self, role: str):
        """FastAPI-Dependency-Factory: eingeloggt + Rolle (oder Admin). `Depends(auth.require_role('editor'))`."""
        def dep(request: Request) -> dict:
            u = self.require_user(request)
            if not self.has_role(u, role):
                raise HTTPException(403, f"Rolle '{role}' nötig")
            return u
        return dep

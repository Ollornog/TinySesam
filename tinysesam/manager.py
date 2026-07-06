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
from typing import Optional

from fastapi import Request, HTTPException

from .config import TinySesamConfig
from .store import Store
from .passwords import hash_password, verify_password, needs_rehash
from . import totp as _totp
from . import security


class TinySesam:
    def __init__(self, config: TinySesamConfig):
        self.cfg = config
        self.store = Store(config.db_path)
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
    def create_user(self, username, password=None, is_admin=False, roles=None, display_name=None, email=None) -> int:
        uid = self.store.create_user(username, display_name, email, is_admin, roles)
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
    def _ttl(self) -> int:
        return self.cfg.session_ttl_hours * 3600

    def start_session(self, user_id, method, ip=None, ua=None) -> tuple[str, bool]:
        """Session anlegen. Gibt (token, mfa_ok). mfa_ok=False → TOTP-Schritt nötig."""
        needs = self.mfa_pending(user_id)
        # Passkey ist bereits ein starker Faktor → kein zusätzliches TOTP nötig
        mfa_ok = (method == "passkey") or (not needs)
        token = self.store.create_session(user_id, self._ttl(), mfa_ok, method, ip, ua)
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
        s = self.session_from_request(request)
        if not s or not s["mfa_ok"]:
            return None
        u = self.store.get_user(s["user_id"])
        if not u or u["disabled"]:
            return None
        return u

    def pending_user(self, request) -> Optional[dict]:
        """User einer Session, die noch im MFA-Schritt hängt (mfa_ok=0)."""
        s = self.session_from_request(request)
        if not s or s["mfa_ok"]:
            return None
        return self.store.get_user(s["user_id"])

    def set_cookie(self, response, token):
        response.set_cookie(self.cfg.session_cookie, token, max_age=self._ttl(),
                            httponly=True, secure=self.cfg.cookie_secure,
                            samesite=self.cfg.cookie_samesite, path=self.cfg.cookie_path)

    def logout(self, request, response):
        s = self.session_from_request(request)
        if s:
            self.store.delete_session(s["token"])
        response.delete_cookie(self.cfg.session_cookie, path=self.cfg.cookie_path)

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

    # ---------- FastAPI-Integration ----------
    def router(self):
        from .router import build_router
        return build_router(self)

    def _deny(self, request: Request):
        # HTML-Browser → Redirect zum Login; sonst (API/JSON) → 401
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(307, headers={"Location": f"{self.cfg.login_path}?next={request.url.path}"})
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

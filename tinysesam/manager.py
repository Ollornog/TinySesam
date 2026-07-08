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
from .passwords import hash_password, verify_password, needs_rehash, dummy_verify
from .templates import Templates
from . import totp as _totp
from . import security


class TinySesam:
    def __init__(self, config: TinySesamConfig):
        self.cfg = config
        self.store = Store(config.db_path)
        self.templates = Templates()
        self._mailer_override = None
        self.oidc = None
        self.webauthn = None
        self.ldap = None
        self.rl = security.RateLimiter()
        if config.ldap_enabled and config.ldap_url:
            from .ldap_ import LDAPClient
            self.ldap = LDAPClient(config)
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
        elif u["disabled"]:
            return None
        return u

    # ---------- PIN-Login (persönliche PIN pro User) ----------
    def set_pin(self, user_id, pin):
        """PIN setzen/ändern. Mindestlänge aus cfg.pin_min_length."""
        pin = str(pin or "")
        if len(pin) < self.cfg.pin_min_length:
            raise ValueError(f"PIN zu kurz (min. {self.cfg.pin_min_length})")
        self.store.set_pin_hash(user_id, hash_password(pin))

    def has_pin(self, user_id) -> bool:
        return self.store.has_pin(user_id)

    def disable_pin(self, user_id):
        self.store.delete_pin(user_id)

    def check_pin(self, username, pin) -> Optional[dict]:
        u = self.store.get_user_by_name(username)
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

    # ---------- Faktor-Ketten-Engine ----------
    IDENTIFYING = ("password", "pin", "oidc", "passkey", "magic")  # Faktoren, die den User identifizieren

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
        from urllib.parse import quote
        base = {"password": self.cfg.login_path, "pin": "/auth/pin", "oidc": "/auth/oidc/start",
                "passkey": self.cfg.login_path, "totp": "/auth/totp",
                "magic": "/auth/magic/request"}.get(step, self.cfg.login_path)
        return f"{base}?next={quote(nxt or '/', safe='/')}"

    @staticmethod
    async def json_body(request: Request) -> dict:
        """JSON-Body robust lesen: ungültiger/leerer Body → 400 statt 500."""
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, "ungültiger JSON-Body")
        if not isinstance(data, dict):
            raise HTTPException(400, "JSON-Objekt erwartet")
        return data

    # ---------- E-Mail-Versand ----------
    def set_mailer(self, fn):
        """Eigenen Mail-Versand einhängen: fn(to, subject, text, html=None). Überschreibt SMTP."""
        self._mailer_override = fn

    def mail_configured(self) -> bool:
        return bool(self._mailer_override or self.cfg.smtp_host)

    def send_mail(self, to, subject, text, html=None):
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

    def magic_url(self, raw, base_url) -> str:
        return f"{str(base_url).rstrip('/')}/auth/magic/{raw}"

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
        url = self.magic_url(raw, base_url)
        if email and self.mail_configured():
            self.send_mail(email, "Deine Einladung",
                           f"Du wurdest eingeladen, ein Konto anzulegen:\n\n{url}\n",
                           html=f'<p>Du wurdest eingeladen, ein Konto anzulegen:</p><p><a href="{url}">Konto erstellen</a></p>')
        self.audit("invite_create", detail=email)
        return {"url": url, "token": raw}

    def send_verify_email(self, user_id, email, base_url) -> bool:
        if not (email and self.mail_configured()):
            return False
        raw = self.create_magic_token("verify_email", user_id=user_id, email=email)
        url = self.magic_url(raw, base_url)
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
            self.store.set_session_factors(s["token"], done, mfa_ok=ok)
            if ok and not was_ok:
                u = self.store.get_user(user_id)
                self.store.audit_log("login", u["username"] if u else None, s["ip"], factor)
            return s["token"], ok, False
        token, ok = self.start_session(user_id, factor, ip, ua, remember)
        return token, ok, True

    def login_redirect_after(self, request, token, user_id, nxt):
        """Zielredirect nach einem Faktor: nxt wenn Sitzung komplett, sonst Eingabeseite des nächsten Faktors."""
        s = self.store.get_session(token)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if s and s["mfa_ok"]:
            return nxt
        step = self.next_login_step(user_id, done)
        return self.factor_entry(step, nxt) if step else nxt

    def complete_mfa(self, token):
        """TOTP-Schritt abschließen (Faktor 'totp' anhängen). Rückwärtskompatibler Name."""
        s = self.store.get_session(token)
        if not s:
            return
        done = json.loads(s["factors_done"] or "[]")
        if "totp" not in done:
            done.append("totp")
        ok = self._session_ok(s["user_id"], done)
        self.store.set_session_factors(token, done, mfa_ok=ok)
        if ok:
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

    # ---------- Forward-Auth (Reverse-Proxy) ----------
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

    def forward_login_url(self, orig_url: str, request: Request = None) -> str:
        """Zentrale Login-URL (auf base_url bzw. abgeleitet) mit next=<orig_url>."""
        from urllib.parse import quote
        base = self.cfg.base_url
        if not base and request is not None:
            h = request.headers
            proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
            host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc).split(",")[0].strip()
            base = f"{proto}://{host}"
        return f"{str(base).rstrip('/')}{self.cfg.login_path}?next={quote(orig_url or '/', safe='')}"

    # ---------- Views / Redirect-Sicherheit ----------
    def set_template(self, name, fn):
        """Eine eingebaute Seite durch einen eigenen Renderer ersetzen: fn(auth, ctx) -> str | Response.
        Namen: 'login', 'totp', 'totp_setup', 'account', 'register', 'magic_request', 'magic_sent',
        'resource_pin' (je nach aktivierten Features). String → HTML mit Status; Response → 1:1."""
        self.templates.set(name, fn)

    def render_page(self, template, status=200, **ctx) -> Response:
        out = self.templates.render(template, self, ctx)
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

    def _deny_stepup(self, request: Request):
        # eingeloggt, aber Faktor nicht frisch. Browser → Redirect zu /auth/reauth; sonst 403 + Hinweis-Header.
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"/auth/reauth?next={nxt}"})
        raise HTTPException(403, "Step-up-Bestätigung nötig", headers={"X-TinySesam-Reauth": "/auth/reauth"})

    # ---------- Step-up-Frische ----------
    def stepup_fresh(self, request: Request, user: dict = None) -> bool:
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

    def _redirect_factor(self, request: Request, step):
        # Browser → Redirect zur Eingabeseite des nächsten Faktors; JSON → 401 + X-TinySesam-Factor.
        if step is None:
            self._deny(request)
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(307, headers={"Location": self.factor_entry(step, request.url.path)})
        raise HTTPException(401, "weiterer Faktor nötig", headers={"X-TinySesam-Factor": step})

    def _enforce_route_chain(self, request: Request, factors, strict) -> dict:
        strict = self.cfg.login_chain_strict if strict is None else strict
        s = self.session_from_request(request)
        usr = self.store.get_user(s["user_id"]) if s else None
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

    def _enforce(self, request: Request, mfa=False, admin=False, role=None, factors=None, strict=None) -> dict:
        gchain, _ = self._global_chain()
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
                usr = self.store.get_user(s["user_id"]) if s else None
                if not usr or usr["disabled"]:
                    self._deny(request)   # keine Identität → Login (erster Faktor)
                done = json.loads(s["factors_done"] or "[]")
                self._redirect_factor(request, self.next_login_step(usr["id"], done))
        if admin and not self.is_admin(u):
            raise HTTPException(403, "Adminrechte nötig")
        if role and not self.has_role(u, role):
            raise HTTPException(403, f"Rolle '{role}' nötig")
        if mfa and not self.stepup_fresh(request, u):
            if u.get("_via") == "apikey":
                raise HTTPException(403, "Step-up-MFA nötig — nur per interaktiver Sitzung")
            self._deny_stepup(request)
        return u

    def require_user(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): erzwingt eingeloggten (inkl. MFA) User.
        paperlaiss: `Depends(auth.require_user)` — mehr braucht es dort nicht."""
        return self._enforce(request)

    def require_admin(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): eingeloggt + Admin (+ Step-up, wenn admin_require_mfa)."""
        return self._enforce(request, admin=True, mfa=self.cfg.admin_require_mfa)

    def require_role(self, role: str, mfa: bool = False):
        """FastAPI-Dependency-Factory: eingeloggt + Rolle (oder Admin). `Depends(auth.require_role('editor'))`.
        mfa=True verlangt zusätzlich Step-up-Frische."""
        def dep(request: Request) -> dict:
            return self._enforce(request, role=role, mfa=mfa)
        return dep

    def require(self, mfa: bool = False, admin: bool = False, role: str = None,
                factors: list = None, strict: bool = None):
        """Allgemeine Guard-Factory für beliebige Kombinationen — der „Flag am Guard"-Weg:
        `Depends(auth.require(mfa=True))`, `Depends(auth.require(admin=True, mfa=True))`.
        factors=[...] verlangt eine bestimmte Faktor-Kette für diese Route (überschreibt die globale),
        strict=True/False steuert die Reihenfolge: `Depends(auth.require(factors=['oidc','password']))`."""
        def dep(request: Request) -> dict:
            return self._enforce(request, mfa=mfa, admin=admin, role=role, factors=factors, strict=strict)
        return dep

    def require_mfa(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): eingeloggt + frische Step-up-Bestätigung."""
        return self._enforce(request, mfa=True)

    # ---------- Geteilte Ressourcen-Geheimnisse (PIN oder Passphrase, ohne User-Konto) ----------
    def set_resource_secret(self, name, secret, kind="pin", label=None):
        """Geheimnis für einen Bereich setzen/ändern. kind='pin' (numerisch) | 'password' (Passphrase)."""
        if not secret:
            raise ValueError("leeres Geheimnis")
        if kind not in ("pin", "password"):
            raise ValueError("kind muss 'pin' oder 'password' sein")
        self.store.set_resource_secret(name, hash_password(str(secret)), kind, label)

    def remove_resource_secret(self, name):
        self.store.delete_resource_secret(name)

    def list_resource_secrets(self):
        return self.store.list_resource_secrets()

    def check_resource(self, name, secret) -> bool:
        row = self.store.get_resource_secret(name)
        return bool(row and verify_password(str(secret or ""), row["hash"]))

    def resource_unlocked(self, request: Request, name) -> bool:
        return self.store.is_resource_unlocked(request.cookies.get(self.cfg.resource_cookie), name)

    def unlock_resource(self, request: Request, response, name):
        token = request.cookies.get(self.cfg.resource_cookie) or secrets.token_urlsafe(32)
        ttl = self.cfg.resource_unlock_ttl_hours * 3600
        self.store.add_resource_unlock(token, name, int(time.time()) + ttl)
        kw = dict(httponly=True, secure=self.cfg.cookie_secure, samesite=self.cfg.cookie_samesite,
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
                raise HTTPException(401, "Ressource gesperrt")
            return True
        return dep

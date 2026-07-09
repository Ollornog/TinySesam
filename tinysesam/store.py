"""SQLite-Store für TinySesam: Nutzer, Credentials (Passwort/TOTP/WebAuthn/OIDC) und Sessions.

Bewusst stdlib-`sqlite3` (kein ORM): leichtgewichtig, keine zusätzliche Abhängigkeit.
Thread-safe über ein Lock + `check_same_thread=False` (FastAPI-Worker teilen sich die Instanz).
"""
from __future__ import annotations
import sqlite3, threading, time, secrets, json, logging
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    email         TEXT,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    roles         TEXT NOT NULL DEFAULT '[]',   -- JSON-Liste feingranularer Rollen (optional)
    is_service    INTEGER NOT NULL DEFAULT 0,   -- Service-/Daemon-Account: kein interaktiver Login, nur API-Key
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_key (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT,
    prefix     TEXT NOT NULL,                   -- Anzeige (tsk_xxxx…), NICHT der Key
    key_hash   TEXT UNIQUE NOT NULL,            -- sha256(vollständiger Key)
    roles      TEXT NOT NULL DEFAULT '[]',      -- Key-Scope; leer = erbt User-Rollen
    created_at INTEGER NOT NULL,
    last_used  INTEGER,
    expires_at INTEGER,                          -- NULL = unbefristet
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS password_cred (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash     TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pin_cred (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash     TEXT NOT NULL,               -- wie Passwort gehasht (argon2/scrypt)
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS totp_cred (
    user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret    TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_code (   -- Einmal-Codes als 2FA-Ersatz (verlorener Authenticator)
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,                 -- sha256(normalisierter Code)
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE TABLE IF NOT EXISTS webauthn_cred (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,   -- base64url
    public_key    TEXT NOT NULL,          -- base64url (COSE)
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,                   -- JSON-Liste
    name          TEXT,
    created_at    INTEGER NOT NULL,
    last_used     INTEGER
);
CREATE TABLE IF NOT EXISTS oidc_identity (
    issuer   TEXT NOT NULL,
    subject  TEXT NOT NULL,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject)
);
CREATE TABLE IF NOT EXISTS session (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    mfa_ok     INTEGER NOT NULL DEFAULT 0,   -- erfüllt die aktive Login-Policy (Kette/2FA) vollständig
    mfa_at     INTEGER,                       -- Zeitpunkt der letzten Faktor-Bestätigung (Step-up-Frische)
    method     TEXT,                          -- erster/primärer Faktor: password|pin|passkey|oidc|magic
    factors_done TEXT NOT NULL DEFAULT '[]',  -- JSON-Liste erfüllter Faktoren (Ketten-Engine)
    remember   INTEGER NOT NULL DEFAULT 1,   -- „Angemeldet bleiben" (persistentes Cookie)
    ip         TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS flow (            -- kurzlebiger State (OIDC state/nonce, WebAuthn-Challenge)
    key        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,               -- JSON
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS setting (         -- Runtime-Settings (Härtungs-Schwellen, Panel-editierbar)
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS magic_token (      -- Einmal-Token (Magic-Link / Invite / E-Mail-Verify)
    token_hash TEXT PRIMARY KEY,               -- sha256(Klartext-Token)
    purpose    TEXT NOT NULL,                  -- login | invite | verify_email | …
    user_id    INTEGER,                        -- optional: an bestehenden User gebunden
    email      TEXT,
    payload    TEXT,                            -- JSON (z.B. Rollen, Ressource)
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER                          -- gesetzt bei Einlösung → one-shot
);
CREATE TABLE IF NOT EXISTS resource_secret (  -- geteiltes Ressourcen-Geheimnis (ohne User-Konto)
    name       TEXT PRIMARY KEY,
    hash       TEXT NOT NULL,                 -- wie Passwort gehasht
    kind       TEXT NOT NULL DEFAULT 'pin',   -- 'pin' (numerisch) | 'password' (Passphrase)
    label      TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_unlock (  -- freigeschaltete Ressourcen je Unlock-Token (Cookie)
    token      TEXT NOT NULL,
    resource   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (token, resource)
);
CREATE TABLE IF NOT EXISTS login_attempt (   -- Brute-Force-Regulation
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT,
    ip       TEXT,
    success  INTEGER NOT NULL,
    method   TEXT
);
CREATE TABLE IF NOT EXISTS audit (           -- Audit-Log (Login/Logout/Admin-Aktionen)
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    event    TEXT NOT NULL,
    username TEXT,
    ip       TEXT,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_cred(user_id);
CREATE INDEX IF NOT EXISTS idx_attempt_user ON login_attempt(username, ts);
CREATE INDEX IF NOT EXISTS idx_attempt_ip ON login_attempt(ip, ts);
CREATE INDEX IF NOT EXISTS idx_apikey_user ON api_key(user_id);
"""


def norm_email(email) -> Optional[str]:
    """E-Mail kanonisch speichern: getrimmt und klein. `None` bleibt `None` (Konto ohne Adresse)."""
    e = (email or "").strip().lower()
    return e or None


def valid_email(email) -> bool:
    """Bewusst nachsichtig: genau ein @, links und rechts was dran, rechts ein Punkt, keine Leerzeichen.
    Ob die Adresse existiert, beantwortet nur der Bestätigungslink (`signup_verify_email`)."""
    e = (email or "").strip()
    if not e or " " in e or e.count("@") != 1:
        return False
    local, _, domain = e.partition("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _now() -> int:
    return int(time.time())


class Store:
    def __init__(self, db_path: str):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.Lock()
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self._migrate()

    def _migrate(self):
        """Additive Migrationen für bestehende DBs: fehlende Spalten nachrüsten (idempotent)."""
        adds = {
            "session": [("mfa_at", "INTEGER"), ("remember", "INTEGER NOT NULL DEFAULT 1"),
                        ("factors_done", "TEXT NOT NULL DEFAULT '[]'")],
        }
        with self._lock:
            for table, cols in adds.items():
                have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
                for name, decl in cols:
                    if name not in have:
                        self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
            # E-Mail eindeutig (Login-Kennung) — partiell, damit Konten ohne E-Mail erlaubt bleiben.
            # Bestandsdaten mit Dubletten: Index kann nicht angelegt werden → laut sagen, nicht crashen.
            try:
                self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email "
                                "ON users(lower(email)) WHERE email IS NOT NULL AND email <> ''")
            except sqlite3.IntegrityError:
                logging.getLogger("tinysesam").warning(
                    "users.email enthält Dubletten — Eindeutigkeits-Index nicht angelegt. "
                    "Doppelte Adressen bereinigen, sonst ist Login per E-Mail mehrdeutig.")
            self.db.commit()

    def _one(self, sql, args=()):
        with self._lock:
            cur = self.db.execute(sql, args)
            return cur.fetchone()

    def _all(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def _exec(self, sql, args=()):
        with self._lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    # ---------- Users ----------
    def create_user(self, username, display_name=None, email=None, is_admin=False, roles=None, is_service=False) -> int:
        cur = self._exec(
            "INSERT INTO users(username, display_name, email, is_admin, roles, is_service, created_at) VALUES (?,?,?,?,?,?,?)",
            (username, display_name or username, norm_email(email), 1 if is_admin else 0,
             json.dumps(list(roles or [])), 1 if is_service else 0, _now()))
        return cur.lastrowid

    def set_email(self, user_id, email):
        self._exec("UPDATE users SET email=? WHERE id=?", (norm_email(email), user_id))

    def get_roles(self, user_id) -> list:
        r = self._one("SELECT roles FROM users WHERE id=?", (user_id,))
        try:
            return json.loads(r["roles"]) if r else []
        except Exception:
            return []

    def set_roles(self, user_id, roles):
        self._exec("UPDATE users SET roles=? WHERE id=?", (json.dumps(list(roles or [])), user_id))

    def get_user(self, user_id) -> Optional[sqlite3.Row]:
        return self._one("SELECT * FROM users WHERE id=?", (user_id,))

    def get_user_by_name(self, username) -> Optional[sqlite3.Row]:
        return self._one("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,))

    def get_user_by_email(self, email) -> Optional[sqlite3.Row]:
        email = norm_email(email)
        if not email:
            return None
        return self._one("SELECT * FROM users WHERE email=? COLLATE NOCASE ORDER BY id LIMIT 1", (email,))

    def delete_user(self, user_id):
        """User + alle seine Zugangsdaten entfernen. Der Audit-Log bleibt (Nachvollziehbarkeit)."""
        with self._lock:
            for table in ("api_key", "password_cred", "pin_cred", "totp_cred", "recovery_code",
                          "webauthn_cred", "oidc_identity", "session", "magic_token"):
                self.db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
            self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
            self.db.commit()

    def email_taken(self, email, exclude_id=None) -> bool:
        u = self.get_user_by_email(email)
        return bool(u and u["id"] != exclude_id)

    def list_users(self):
        return self._all("SELECT * FROM users ORDER BY username")

    def set_disabled(self, user_id, disabled: bool):
        self._exec("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user_id))

    def set_admin(self, user_id, is_admin: bool):
        self._exec("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))

    def user_count(self) -> int:
        return self._one("SELECT COUNT(*) c FROM users")["c"]

    # ---------- Passwort ----------
    def set_password_hash(self, user_id, hash_):
        self._exec("INSERT INTO password_cred(user_id, hash, updated_at) VALUES (?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash, updated_at=excluded.updated_at",
                   (user_id, hash_, _now()))

    def get_password_hash(self, user_id) -> Optional[str]:
        r = self._one("SELECT hash FROM password_cred WHERE user_id=?", (user_id,))
        return r["hash"] if r else None

    # ---------- PIN ----------
    def set_pin_hash(self, user_id, hash_):
        self._exec("INSERT INTO pin_cred(user_id, hash, updated_at) VALUES (?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET hash=excluded.hash, updated_at=excluded.updated_at",
                   (user_id, hash_, _now()))

    def get_pin_hash(self, user_id) -> Optional[str]:
        r = self._one("SELECT hash FROM pin_cred WHERE user_id=?", (user_id,))
        return r["hash"] if r else None

    def delete_pin(self, user_id):
        self._exec("DELETE FROM pin_cred WHERE user_id=?", (user_id,))

    def has_pin(self, user_id) -> bool:
        return self.get_pin_hash(user_id) is not None

    # ---------- TOTP ----------
    def set_totp(self, user_id, secret, confirmed=False):
        self._exec("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?,?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, confirmed=excluded.confirmed",
                   (user_id, secret, 1 if confirmed else 0, _now()))

    def confirm_totp(self, user_id):
        self._exec("UPDATE totp_cred SET confirmed=1 WHERE user_id=?", (user_id,))

    def get_totp(self, user_id) -> Optional[sqlite3.Row]:
        return self._one("SELECT * FROM totp_cred WHERE user_id=?", (user_id,))

    def delete_totp(self, user_id):
        self._exec("DELETE FROM totp_cred WHERE user_id=?", (user_id,))

    def has_confirmed_totp(self, user_id) -> bool:
        r = self.get_totp(user_id)
        return bool(r and r["confirmed"])

    # ---------- Recovery-Codes ----------
    def delete_recovery_codes(self, user_id):
        self._exec("DELETE FROM recovery_code WHERE user_id=?", (user_id,))

    def add_recovery_codes(self, user_id, hashes):
        now = _now()
        with self._lock:
            self.db.executemany("INSERT INTO recovery_code(user_id, code_hash, created_at) VALUES (?,?,?)",
                                [(user_id, h, now) for h in hashes])
            self.db.commit()

    def consume_recovery_code(self, user_id, code_hash) -> bool:
        """Einen ungenutzten Code atomar entwerten. True nur beim ersten gültigen Einlösen."""
        with self._lock:
            cur = self.db.execute(
                "UPDATE recovery_code SET used_at=? WHERE id=(SELECT id FROM recovery_code "
                "WHERE user_id=? AND code_hash=? AND used_at IS NULL LIMIT 1)",
                (_now(), user_id, code_hash))
            self.db.commit()
            return cur.rowcount == 1

    def count_recovery_codes(self, user_id) -> int:
        return self._one("SELECT COUNT(*) c FROM recovery_code WHERE user_id=? AND used_at IS NULL",
                         (user_id,))["c"]

    # ---------- WebAuthn ----------
    def add_webauthn(self, user_id, credential_id, public_key, sign_count, transports, name):
        self._exec("INSERT INTO webauthn_cred(user_id, credential_id, public_key, sign_count, transports, name, created_at) "
                   "VALUES (?,?,?,?,?,?,?)",
                   (user_id, credential_id, public_key, sign_count, json.dumps(transports or []), name, _now()))

    def get_webauthn_by_credid(self, credential_id) -> Optional[sqlite3.Row]:
        return self._one("SELECT * FROM webauthn_cred WHERE credential_id=?", (credential_id,))

    def list_webauthn(self, user_id):
        return self._all("SELECT * FROM webauthn_cred WHERE user_id=? ORDER BY created_at", (user_id,))

    def update_webauthn_signcount(self, cred_row_id, sign_count):
        self._exec("UPDATE webauthn_cred SET sign_count=?, last_used=? WHERE id=?", (sign_count, _now(), cred_row_id))

    def delete_webauthn(self, cred_row_id, user_id):
        self._exec("DELETE FROM webauthn_cred WHERE id=? AND user_id=?", (cred_row_id, user_id))

    # ---------- OIDC-Link ----------
    def link_oidc(self, issuer, subject, user_id):
        self._exec("INSERT OR REPLACE INTO oidc_identity(issuer, subject, user_id) VALUES (?,?,?)",
                   (issuer, subject, user_id))

    def get_oidc_user(self, issuer, subject) -> Optional[int]:
        r = self._one("SELECT user_id FROM oidc_identity WHERE issuer=? AND subject=?", (issuer, subject))
        return r["user_id"] if r else None

    # ---------- Sessions ----------
    def create_session(self, user_id, ttl_seconds, mfa_ok, method, ip=None, ua=None, remember=True,
                       factors=None) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        self._exec("INSERT INTO session(token, user_id, created_at, expires_at, mfa_ok, mfa_at, method, "
                   "factors_done, remember, ip, user_agent) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (token, user_id, now, now + ttl_seconds, 1 if mfa_ok else 0,
                    (now if mfa_ok else None), method, json.dumps(list(factors or [])),
                    1 if remember else 0, ip, ua))
        return token

    def set_session_factors(self, token, factors, mfa_ok=None):
        if mfa_ok is None:
            self._exec("UPDATE session SET factors_done=?, mfa_at=? WHERE token=?",
                       (json.dumps(list(factors)), _now(), token))
        else:
            self._exec("UPDATE session SET factors_done=?, mfa_ok=?, mfa_at=? WHERE token=?",
                       (json.dumps(list(factors)), 1 if mfa_ok else 0, _now(), token))

    def get_session(self, token) -> Optional[sqlite3.Row]:
        if not token:
            return None
        r = self._one("SELECT * FROM session WHERE token=?", (token,))
        if r and r["expires_at"] < _now():
            self.delete_session(token)
            return None
        return r

    def set_session_mfa(self, token, ok=True):
        self._exec("UPDATE session SET mfa_ok=?, mfa_at=? WHERE token=?",
                   (1 if ok else 0, (_now() if ok else None), token))

    def delete_session(self, token):
        self._exec("DELETE FROM session WHERE token=?", (token,))

    def delete_user_sessions(self, user_id):
        self._exec("DELETE FROM session WHERE user_id=?", (user_id,))

    def delete_user_sessions_except(self, user_id, keep_token):
        """Alle Sitzungen eines Users beenden AUSSER einer (z.B. die aktuelle bei Selbst-PW-Änderung)."""
        self._exec("DELETE FROM session WHERE user_id=? AND token!=?", (user_id, keep_token or ""))

    def gc_sessions(self) -> int:
        return self._exec("DELETE FROM session WHERE expires_at < ?", (_now(),)).rowcount

    def gc_flow(self) -> int:
        return self._exec("DELETE FROM flow WHERE expires_at < ?", (_now(),)).rowcount

    def list_sessions(self, user_id=None):
        if user_id is not None:
            return self._all("SELECT * FROM session WHERE user_id=? ORDER BY created_at DESC", (user_id,))
        return self._all("SELECT * FROM session ORDER BY created_at DESC")

    # ---------- Flow-State (OIDC / WebAuthn, kurzlebig, one-shot) ----------
    def put_flow(self, key, data: dict, ttl=600):
        self._exec("INSERT OR REPLACE INTO flow(key, data, expires_at) VALUES (?,?,?)",
                   (key, json.dumps(data), _now() + ttl))

    def pop_flow(self, key) -> Optional[dict]:
        r = self._one("SELECT data, expires_at FROM flow WHERE key=?", (key,))
        if not r:
            return None
        self._exec("DELETE FROM flow WHERE key=?", (key,))
        if r["expires_at"] < _now():
            return None
        try:
            return json.loads(r["data"])
        except Exception:
            return None

    # ---------- Runtime-Settings (Panel-editierbar) ----------
    def get_setting(self, key) -> Optional[str]:
        r = self._one("SELECT value FROM setting WHERE key=?", (key,))
        return r["value"] if r else None

    def set_setting(self, key, value):
        self._exec("INSERT OR REPLACE INTO setting(key, value) VALUES (?,?)", (key, str(value)))

    def all_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self._all("SELECT key, value FROM setting")}

    # ---------- Brute-Force-Regulation ----------
    def record_attempt(self, username, ip, success, method):
        self._exec("INSERT INTO login_attempt(ts, username, ip, success, method) VALUES (?,?,?,?,?)",
                   (_now(), username, ip, 1 if success else 0, method))

    def count_fails(self, since, username=None, ip=None, method=None) -> int:
        if not username and not ip:
            return 0
        q = "SELECT COUNT(*) c FROM login_attempt WHERE success=0 AND ts>=?"
        args = [since]
        if username:
            q += " AND username=? COLLATE NOCASE"
            args.append(username)
        if ip:
            q += " AND ip=?"
            args.append(ip)
        if method:
            q += " AND method=?"
            args.append(method)
        return self._one(q, args)["c"]

    def clear_fails(self, username=None, ip=None):
        if username:
            self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE", (username,))
        if ip:
            self._exec("DELETE FROM login_attempt WHERE ip=?", (ip,))

    def gc_attempts(self, older_than) -> int:
        return self._exec("DELETE FROM login_attempt WHERE ts < ?", (older_than,)).rowcount

    # ---------- Magic-/Einmal-Token ----------
    def add_magic_token(self, token_hash, purpose, expires_at, user_id=None, email=None, payload=None):
        self._exec("INSERT INTO magic_token(token_hash, purpose, user_id, email, payload, created_at, expires_at) "
                   "VALUES (?,?,?,?,?,?,?)",
                   (token_hash, purpose, user_id, email, json.dumps(payload) if payload is not None else None,
                    _now(), expires_at))

    def get_magic_token(self, token_hash):
        return self._one("SELECT * FROM magic_token WHERE token_hash=?", (token_hash,))

    def use_magic_token(self, token_hash) -> bool:
        """Atomar als benutzt markieren. True nur beim ERSTEN gültigen Einlösen (one-shot)."""
        with self._lock:
            cur = self.db.execute(
                "UPDATE magic_token SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
                (_now(), token_hash, _now()))
            self.db.commit()
            return cur.rowcount == 1

    def gc_magic_tokens(self) -> int:
        return self._exec("DELETE FROM magic_token WHERE expires_at < ? OR used_at IS NOT NULL", (_now(),)).rowcount

    # ---------- Geteilte Ressourcen-Geheimnisse ----------
    def set_resource_secret(self, name, hash_, kind="pin", label=None):
        self._exec("INSERT INTO resource_secret(name, hash, kind, label, created_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT(name) DO UPDATE SET hash=excluded.hash, kind=excluded.kind, label=excluded.label",
                   (name, hash_, kind, label, _now()))

    def get_resource_secret(self, name):
        return self._one("SELECT * FROM resource_secret WHERE name=?", (name,))

    def list_resource_secrets(self):
        return self._all("SELECT name, kind, label, created_at FROM resource_secret ORDER BY name")

    def delete_resource_secret(self, name):
        self._exec("DELETE FROM resource_secret WHERE name=?", (name,))
        self._exec("DELETE FROM resource_unlock WHERE resource=?", (name,))

    def add_resource_unlock(self, token, resource, expires_at):
        self._exec("INSERT OR REPLACE INTO resource_unlock(token, resource, expires_at) VALUES (?,?,?)",
                   (token, resource, expires_at))

    def is_resource_unlocked(self, token, resource) -> bool:
        if not token:
            return False
        r = self._one("SELECT expires_at FROM resource_unlock WHERE token=? AND resource=?", (token, resource))
        if not r:
            return False
        if r["expires_at"] < _now():
            self._exec("DELETE FROM resource_unlock WHERE token=? AND resource=?", (token, resource))
            return False
        return True

    def gc_resource_unlocks(self) -> int:
        return self._exec("DELETE FROM resource_unlock WHERE expires_at < ?", (_now(),)).rowcount

    # ---------- Audit-Log ----------
    def audit_log(self, event, username=None, ip=None, detail=None):
        self._exec("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                   (_now(), event, username, ip, detail))

    def recent_audit(self, limit=100):
        return self._all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))

    # ---------- API-Keys ----------
    def add_api_key(self, user_id, name, prefix, key_hash, roles=None, expires_at=None) -> int:
        cur = self._exec(
            "INSERT INTO api_key(user_id, name, prefix, key_hash, roles, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
            (user_id, name, prefix, key_hash, json.dumps(list(roles or [])), _now(), expires_at))
        return cur.lastrowid

    def get_api_key_by_hash(self, key_hash):
        return self._one("SELECT * FROM api_key WHERE key_hash=?", (key_hash,))

    def list_api_keys(self, user_id):
        return self._all("SELECT * FROM api_key WHERE user_id=? ORDER BY created_at DESC", (user_id,))

    def touch_api_key(self, key_id):
        self._exec("UPDATE api_key SET last_used=? WHERE id=?", (_now(), key_id))

    def revoke_api_key(self, key_id, user_id=None):
        if user_id is not None:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=? AND user_id=?", (key_id, user_id))
        else:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=?", (key_id,))

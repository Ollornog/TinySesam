"""SQLite-Store für TinySesam: Nutzer, Credentials (Passwort/TOTP/WebAuthn/OIDC) und Sessions.

Bewusst stdlib-`sqlite3` (kein ORM): leichtgewichtig, keine zusätzliche Abhängigkeit.
Thread-safe über ein Lock + `check_same_thread=False` (FastAPI-Worker teilen sich die Instanz).
"""
from __future__ import annotations
import sqlite3, threading, time, secrets, json
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
CREATE TABLE IF NOT EXISTS totp_cred (
    user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret    TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
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
    mfa_ok     INTEGER NOT NULL DEFAULT 0,   -- 2FA bestanden (oder nicht nötig)
    method     TEXT,                          -- password|passkey|oidc
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
            (username, display_name or username, email, 1 if is_admin else 0,
             json.dumps(list(roles or [])), 1 if is_service else 0, _now()))
        return cur.lastrowid

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
    def create_session(self, user_id, ttl_seconds, mfa_ok, method, ip=None, ua=None) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        self._exec("INSERT INTO session(token, user_id, created_at, expires_at, mfa_ok, method, ip, user_agent) "
                   "VALUES (?,?,?,?,?,?,?,?)",
                   (token, user_id, now, now + ttl_seconds, 1 if mfa_ok else 0, method, ip, ua))
        return token

    def get_session(self, token) -> Optional[sqlite3.Row]:
        if not token:
            return None
        r = self._one("SELECT * FROM session WHERE token=?", (token,))
        if r and r["expires_at"] < _now():
            self.delete_session(token)
            return None
        return r

    def set_session_mfa(self, token, ok=True):
        self._exec("UPDATE session SET mfa_ok=? WHERE token=?", (1 if ok else 0, token))

    def delete_session(self, token):
        self._exec("DELETE FROM session WHERE token=?", (token,))

    def delete_user_sessions(self, user_id):
        self._exec("DELETE FROM session WHERE user_id=?", (user_id,))

    def gc_sessions(self):
        self._exec("DELETE FROM session WHERE expires_at < ?", (_now(),))

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

    def count_fails(self, since, username=None, ip=None) -> int:
        if username:
            return self._one("SELECT COUNT(*) c FROM login_attempt WHERE success=0 AND ts>=? AND username=? COLLATE NOCASE",
                             (since, username))["c"]
        if ip:
            return self._one("SELECT COUNT(*) c FROM login_attempt WHERE success=0 AND ts>=? AND ip=?",
                             (since, ip))["c"]
        return 0

    def clear_fails(self, username=None, ip=None):
        if username:
            self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE", (username,))
        if ip:
            self._exec("DELETE FROM login_attempt WHERE ip=?", (ip,))

    def gc_attempts(self, older_than):
        self._exec("DELETE FROM login_attempt WHERE ts < ?", (older_than,))

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

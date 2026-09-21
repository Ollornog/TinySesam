"""SQLite-Store für TinySesam: Nutzer, Credentials (Passwort/TOTP/WebAuthn/OIDC) und Sessions.

Bewusst stdlib-`sqlite3` (kein ORM): leichtgewichtig, keine zusätzliche Abhängigkeit.
Thread-safe über ein Lock + `check_same_thread=False` (FastAPI-Worker teilen sich die Instanz).
"""
from __future__ import annotations
import sqlite3, threading, time, secrets, json, logging, hashlib, os, stat
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
    created_at INTEGER NOT NULL,
    last_step INTEGER                          -- zuletzt verbrauchter Zeitschritt; ein Code gilt
                                               -- genau einmal (NIST SP 800-63B: „SHALL accept a
                                               -- given OTP only once while it is valid")
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
    token_hash TEXT PRIMARY KEY,               -- sha256(Klartext-Token); der Klartext steht NUR im
                                               -- Cookie des Browsers. Wer die Datei liest, bekommt
                                               -- damit keine übernehmbare Sitzung (s. magic_token,
                                               -- das es von Anfang an so hält).
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
    #: Rechte für eine NEU angelegte Datenbank. Hier stehen Passwort-Hashes, TOTP-Geheimnisse
    #: und E-Mail-Adressen; auf einem geteilten Host konnte sie bis 0.18.0 jeder lesen (0644,
    #: je nach umask). Bei einer bestehenden Datei wird nichts umgestellt — wer bewusst eine
    #: Gruppe freigegeben hat, soll das behalten —, aber es gibt eine Warnung.
    DATEIRECHTE = 0o600

    def __init__(self, db_path: str):
        neu = db_path not in (":memory:", "") and not os.path.exists(db_path)
        if neu:
            # Die Datei entsteht direkt mit engen Rechten. Ein chmod NACH dem Verbinden hätte
            # ein Zeitfenster, in dem sie offen dasteht — und genau in dem Moment schreibt
            # SQLite das Schema hinein.
            try:
                os.close(os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.DATEIRECHTE))
            except OSError:
                neu = False                      # Verzeichnis fehlt o.ä. — sqlite3 meldet es gleich
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.Lock()
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self._migrate()
        self._dateirechte_pruefen(db_path, neu)

    def _dateirechte_pruefen(self, db_path: str, neu: bool):
        """WAL und SHM tragen dieselben Daten wie die Datenbank — sie bekommen dieselben Rechte.

        Die Hauptdatei selbst wird nur bei einer bestehenden Installation beurteilt, nicht
        umgeschrieben: eine bewusste Gruppenfreigabe ist eine Entscheidung des Betreibers, keine
        Lücke. Still bleibt sie trotzdem nicht."""
        if db_path in (":memory:", ""):
            return
        try:
            modus = stat.S_IMODE(os.stat(db_path).st_mode)
        except OSError:
            return
        for anhang in ("-wal", "-shm"):
            pfad = db_path + anhang
            try:
                if os.path.exists(pfad) and stat.S_IMODE(os.stat(pfad).st_mode) != modus:
                    os.chmod(pfad, modus)
            except OSError:
                pass                              # Dateisystem ohne Rechte (Windows, manche Mounts)
        if not neu and modus & 0o077:
            logging.getLogger("tinysesam").warning(
                "Die Datenbank %s ist für andere Konten lesbar (%o). Darin stehen Passwort-Hashes "
                "und TOTP-Geheimnisse. Enger stellen: chmod 600 %s", db_path, modus, db_path)

    #: Stand des Schemas. Wird bei jeder Änderung an SCHEMA/_migrate() um eins erhöht.
    #:
    #: 1 — bis 0.17.x (kein Stempel; wird beim ersten Öffnen nachgetragen)
    #: 2 — 0.18.0: `session.token` → `session.token_hash` (sha256 statt Klartext)
    #: 3 — 0.18.0: `totp_cred.last_step` (ein TOTP-Code gilt genau einmal)
    #: 4 — 0.18.0: `resource_unlock.token` trägt den sha256 statt des Klartexts
    SCHEMA_VERSION = 4

    def _migrate(self):
        """Additive Migrationen für bestehende DBs: fehlende Spalten nachrüsten (idempotent).

        Am Ende steht `PRAGMA user_version` auf `SCHEMA_VERSION`. Bis 0.18.0 gab es diesen
        Stempel nicht: Welchen Stand eine Datei hat, war nur an ihren Spaltennamen zu erraten —
        und eine Datei aus einer NEUEREN Fassung öffnete eine ältere TinySesam-Version
        stillschweigend, mit Tabellen, die sie nicht kennt. Der Stempel macht daraus eine
        Ansage statt eines rätselhaften Verhaltens."""
        adds = {
            "session": [("mfa_at", "INTEGER"), ("remember", "INTEGER NOT NULL DEFAULT 1"),
                        ("factors_done", "TEXT NOT NULL DEFAULT '[]'")],
            "totp_cred": [("last_step", "INTEGER")],
        }
        with self._lock:
            for table, cols in adds.items():
                have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
                for name, decl in cols:
                    if name not in have:
                        self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

            # Sitzungs-Tokens lagen bis 0.18.0 im Klartext in der Datei. Der Hash lässt sich aus
            # dem Klartext ausrechnen — bestehende Anmeldungen überleben die Umstellung also, die
            # Cookies bleiben gültig.
            #
            # **In EINER Transaktion, mit BEGIN IMMEDIATE.** Die erste Fassung fuhr das
            # `ALTER TABLE` allein: Pythons sqlite3 öffnet vor DDL keine Transaktion, der
            # Umbenennung folgte also sofort ein Commit, und das Nachhashen lief getrennt. Ein
            # Abbruch dazwischen (SIGKILL, OOM, Container-Neustart mitten im Upgrade) hinterliess
            # eine Spalte `token_hash` **mit Klartext darin** — dauerhaft, denn die Bedingung
            # unten wird nie wieder wahr, und der Stempel sagt danach „migriert". Genau das, was
            # die Umstellung beseitigen soll, wäre für immer geblieben.
            #
            # `BEGIN IMMEDIATE` nimmt die Schreibsperre sofort. Das löst zugleich den zweiten
            # Fall: Bei mehreren Prozessen (`uvicorn --workers N`) las Worker A die Spaltenliste,
            # B migrierte fertig, A fuhr sein ALTER — und starb mit `no such column: "token"`.
            # Jetzt wartet A auf die Sperre und sieht danach den fertigen Zustand.
            self.db.execute("BEGIN IMMEDIATE")
            try:
                spalten = {r["name"] for r in self.db.execute("PRAGMA table_info(session)")}
                if "token" in spalten and "token_hash" not in spalten:
                    self.db.execute("ALTER TABLE session RENAME COLUMN token TO token_hash")
                zeilen = self.db.execute(
                    "SELECT token_hash FROM session WHERE length(token_hash) <> 64"
                    " OR token_hash GLOB '*[^0-9a-f]*'").fetchall()
                self.db.executemany(
                    "UPDATE session SET token_hash=? WHERE token_hash=?",
                    [(hashlib.sha256(z["token_hash"].encode()).hexdigest(), z["token_hash"])
                     for z in zeilen if z["token_hash"]])
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            if zeilen:
                logging.getLogger("tinysesam").info(
                    "Sitzungstabelle migriert: %d Token gehasht, Anmeldungen bleiben gültig.",
                    len(zeilen))

            # Eine Datei aus der Zukunft: Diese Fassung kennt ihre Tabellen nicht vollständig
            # und würde beim Schreiben Lücken hinterlassen. Das ist kein Grund abzustürzen —
            # aber ein sehr guter, es laut zu sagen.
            # Freischaltungen aus der Zeit vor der Umstellung lassen sich nicht umrechnen: Aus
            # dem Klartext wird der Hash, aus dem Hash nichts. Sie werden verworfen — betroffen
            # sind nur offene Ressourcen-Freigaben, und die holt man sich mit dem Geheimnis in
            # Sekunden zurück. Eine halb gehashte Tabelle wäre schlimmer.
            vorhanden_vorab = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if 0 < vorhanden_vorab < 4:
                weg = self.db.execute("DELETE FROM resource_unlock").rowcount
                if weg:
                    logging.getLogger("tinysesam").info(
                        "%d Ressourcen-Freigaben verworfen (Token werden jetzt gehasht abgelegt).", weg)

            vorhanden = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if vorhanden > self.SCHEMA_VERSION:
                logging.getLogger("tinysesam").warning(
                    "Die Datenbank trägt Schema-Version %d, diese TinySesam-Fassung kennt nur %d. "
                    "Sie stammt aus einer neueren Version — mit dieser hier zu schreiben kann "
                    "Daten unvollständig lassen. Passende Version installieren oder die Datei "
                    "aus einer Sicherung zurückspielen.", vorhanden, self.SCHEMA_VERSION)
            elif vorhanden != self.SCHEMA_VERSION:
                self.db.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
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
    # Gespeichert wird der sha256 des Tokens, nie das Token selbst. Alles, was aus einer
    # Sitzungs-Zeile kommt (`row["token_hash"]`), ist deshalb ein Handle: Es benennt eine Sitzung
    # und taugt nicht zum Anmelden. Der Klartext lebt zwischen `create_session()` und dem Cookie.
    @staticmethod
    def session_hash(token: str) -> str:
        return hashlib.sha256((token or "").encode()).hexdigest()

    def create_session(self, user_id, ttl_seconds, mfa_ok, method, ip=None, ua=None, remember=True,
                       factors=None) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        self._exec("INSERT INTO session(token_hash, user_id, created_at, expires_at, mfa_ok, mfa_at, "
                   "method, factors_done, remember, ip, user_agent) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (self.session_hash(token), user_id, now, now + ttl_seconds, 1 if mfa_ok else 0,
                    (now if mfa_ok else None), method, json.dumps(list(factors or [])),
                    1 if remember else 0, ip, ua))
        return token

    @staticmethod
    def _handle(wert) -> str:
        """Ein Handle ist ein sha256-Hexdigest. Wer hier versehentlich ein Klartext-Token
        hereinreicht, bekommt einen Fehler — sonst liefe das UPDATE ins Leere und die Sitzung
        behielte still ihren alten Stand (ein zweiter Faktor, der nicht ankommt, fällt niemandem
        auf, bis er fehlt)."""
        h = str(wert or "")
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError("Sitzungs-Handle erwartet (token_hash aus der Sitzungs-Zeile), "
                             f"kein Klartext-Token: {h[:12]!r}…")
        return h

    def set_session_factors(self, handle, factors, mfa_ok=None):
        h = self._handle(handle)
        if mfa_ok is None:
            self._exec("UPDATE session SET factors_done=?, mfa_at=? WHERE token_hash=?",
                       (json.dumps(list(factors)), _now(), h))
        else:
            self._exec("UPDATE session SET factors_done=?, mfa_ok=?, mfa_at=? WHERE token_hash=?",
                       (json.dumps(list(factors)), 1 if mfa_ok else 0, _now(), h))

    def get_session(self, token) -> Optional[sqlite3.Row]:
        if not token:
            return None
        r = self._one("SELECT * FROM session WHERE token_hash=?", (self.session_hash(token),))
        if r and r["expires_at"] < _now():
            self.delete_session(token)
            return None
        return r

    def set_session_mfa(self, handle, ok=True):
        self._exec("UPDATE session SET mfa_ok=?, mfa_at=? WHERE token_hash=?",
                   (1 if ok else 0, (_now() if ok else None), self._handle(handle)))

    def delete_session(self, token):
        """Klartext-Token (aus dem Cookie) — für Logout."""
        self._exec("DELETE FROM session WHERE token_hash=?", (self.session_hash(token),))

    def delete_session_by_handle(self, handle):
        """Handle aus einer Sitzungs-Zeile — für Admin-Panel und „andere Sitzungen beenden"."""
        self._exec("DELETE FROM session WHERE token_hash=?", (self._handle(handle),))

    def delete_user_sessions(self, user_id):
        self._exec("DELETE FROM session WHERE user_id=?", (user_id,))

    def delete_user_sessions_except(self, user_id, keep_handle):
        """Alle Sitzungen eines Users beenden AUSSER einer (z.B. die aktuelle bei Selbst-PW-Änderung).

        `keep_handle` ist das `token_hash` aus der Sitzungs-Zeile, nicht das Cookie."""
        self._exec("DELETE FROM session WHERE user_id=? AND token_hash!=?", (user_id, keep_handle or ""))

    def totp_step_verbrauchen(self, user_id, step: int) -> bool:
        """Einen TOTP-Zeitschritt als verbraucht buchen. True, wenn er noch frei war.

        Der Vergleich und das Schreiben stecken in EINEM `UPDATE … WHERE`: Zwei gleichzeitige
        Anfragen mit demselben Code können so nicht beide gewinnen — SQLite serialisiert die
        Schreiber, und der zweite trifft keine Zeile mehr.
        """
        cur = self._exec(
            "UPDATE totp_cred SET last_step=? WHERE user_id=? AND (last_step IS NULL OR last_step < ?)",
            (int(step), user_id, int(step)))
        return cur.rowcount == 1

    def gc_sessions(self) -> int:
        return self._exec("DELETE FROM session WHERE expires_at < ?", (_now(),)).rowcount

    @classmethod
    def sichere_datei(cls, quelle: str, ziel: str) -> str:
        """Eine Datenbankdatei sichern, OHNE sie anzufassen — der Weg für `tinysesam backup`.

        Warum nicht einfach `Store(quelle).backup(ziel)`: Der Konstruktor setzt
        `PRAGMA journal_mode=WAL`, legt fehlende Tabellen an und fährt `_migrate()`. Er
        **schreibt** also, und zwar bevor irgendetwas kopiert ist. Wer vor einem Update das
        einzig Richtige tut und sichert, hätte damit die laufende Installation auf das neue
        Schema gehoben, während noch der alte Code läuft — der Rückweg wäre zu, und eine Datei
        im alten Schema gäbe es danach nirgends mehr. Das Sicherheitsnetz hätte zerstört, was es
        sichern soll.

        Deshalb hier eine eigene Verbindung im Modus `ro`: Sie migriert nicht, legt nichts an
        und braucht kein schreibbares Verzeichnis. Die Online-Backup-API liest darüber trotzdem
        einen konsistenten Stand samt WAL.
        """
        if not os.path.exists(quelle):
            raise FileNotFoundError(quelle)
        neu_angelegt = not os.path.exists(ziel)
        if neu_angelegt:
            try:
                os.close(os.open(ziel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, cls.DATEIRECHTE))
            except OSError:
                neu_angelegt = False
        quell_db = sqlite3.connect(f"file:{quelle}?mode=ro", uri=True)
        ziel_db = sqlite3.connect(ziel)
        try:
            quell_db.backup(ziel_db)
        finally:
            ziel_db.close()
            quell_db.close()
        for anhang in ("", "-wal", "-shm"):
            try:
                if os.path.exists(ziel + anhang):
                    os.chmod(ziel + anhang, cls.DATEIRECHTE)
            except OSError:
                pass
        return ziel

    def backup(self, ziel: str) -> str:
        """Eine konsistente Kopie der Datenbank schreiben, im laufenden Betrieb.

        **Eine Datei-Kopie taugt nicht.** Die Datenbank läuft im WAL-Modus: Alles seit dem
        letzten Checkpoint steht in `…-wal`, nicht in der `.db`. Wer nur die `.db` kopiert (cp,
        rsync, ein Backup-Agent, der Muster kennt), bekommt einen Torso — gemessen: eine frische
        Instanz mit fünf Konten ergab eine Kopie ohne auch nur die Tabelle `users`. Der Fehler
        fällt erst beim Zurückspielen auf.

        Hier läuft SQLites Online-Backup: Es nimmt die Sperren, die es braucht, zieht WAL mit und
        liefert eine Datei, die für sich allein stimmt. Die Kopie bekommt dieselben engen Rechte
        wie das Original — ein Backup mit Passwort-Hashes ist so schützenswert wie die Quelle.
        """
        neu_angelegt = not os.path.exists(ziel)
        if neu_angelegt:
            try:
                os.close(os.open(ziel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.DATEIRECHTE))
            except OSError:
                neu_angelegt = False
        ziel_db = sqlite3.connect(ziel)
        try:
            with self._lock:
                self.db.backup(ziel_db)
        finally:
            ziel_db.close()
        for anhang in ("", "-wal", "-shm"):
            try:
                if os.path.exists(ziel + anhang):
                    os.chmod(ziel + anhang, self.DATEIRECHTE)
            except OSError:
                pass
        return ziel

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

    def clear_fails(self, username=None, ip=None, method=None):
        """Fehlversuche loeschen — optional nur die EINER Methode.

        `method` ist keine Feinheit, sondern der Kern: Ohne sie raeumte ein erfolgreicher
        Passwort-Login auch die TOTP- und PIN-Fehlversuche weg. Wer das Passwort kannte (Leak,
        Wiederverwendung, Phishing), meldete sich vor jedem Rateversuch einmal korrekt an und
        setzte damit die Sperre fuer den ZWEITEN Faktor zurueck — beliebig oft. Die Regulierung,
        die das Panel als Haertung ausweist, griff fuer den zweiten Faktor nie.
        """
        wo_method, args_method = ("", ()) if method is None else (" AND method=?", (method,))
        if username:
            self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE" + wo_method,
                       (username,) + args_method)
        if ip:
            self._exec("DELETE FROM login_attempt WHERE ip=?" + wo_method, (ip,) + args_method)

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

    # Auch hier nur der Hash. Der Token stand im Klartext in der Datei und war identisch mit dem
    # Cookie: Wer die Datei las, hängte sich den Wert in den Browser und war zwölf Stunden in
    # jedem freigeschalteten Bereich — dasselbe Bedrohungsmodell, das die Sitzungs-Umstellung
    # begründet, nur eine Tabelle weiter. Der Token hat 256 Bit, sha256 genügt also.
    def add_resource_unlock(self, token, resource, expires_at):
        self._exec("INSERT OR REPLACE INTO resource_unlock(token, resource, expires_at) VALUES (?,?,?)",
                   (self.session_hash(token), resource, expires_at))

    def is_resource_unlocked(self, token, resource) -> bool:
        if not token:
            return False
        h = self.session_hash(token)
        r = self._one("SELECT expires_at FROM resource_unlock WHERE token=? AND resource=?", (h, resource))
        if not r:
            return False
        if r["expires_at"] < _now():
            self._exec("DELETE FROM resource_unlock WHERE token=? AND resource=?", (h, resource))
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

    def revoke_user_api_keys(self, user_id) -> int:
        """Alle noch gültigen Keys eines Kontos entwerten. Gibt zurück, wie viele es waren —
        die Zahl gehört ins Protokoll und in die Antwort, sonst merkt niemand, was still
        weggefallen ist (oder eben weiterläuft)."""
        return self._exec("UPDATE api_key SET revoked=1 WHERE user_id=? AND revoked=0",
                          (user_id,)).rowcount

    def count_active_api_keys(self, user_id) -> int:
        r = self._one("SELECT COUNT(*) AS n FROM api_key WHERE user_id=? AND revoked=0", (user_id,))
        return r["n"] if r else 0

    def revoke_api_key(self, key_id, user_id=None):
        if user_id is not None:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=? AND user_id=?", (key_id, user_id))
        else:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=?", (key_id,))

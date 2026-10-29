-- TinySesam schema 15 (the code of main at a7aa98c, before the English database names), produced by that code;
-- the rows are hand-made and carry every renamed table, column, index, trigger and setting key.
BEGIN TRANSACTION;
CREATE TABLE api_key (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT,
    prefix     TEXT NOT NULL,                   -- display (tsk_xxxx…), NOT the key
    key_hash   TEXT UNIQUE NOT NULL,            -- sha256(full key)
    roles      TEXT NOT NULL DEFAULT '[]',      -- key scope; empty = inherits user roles
    -- What kind of key is this? (R6-5)
    --   'automation' (default): works on its own, NEVER carries its owner's admin flag and
    --                           satisfies no route that requires admin. For services and scripts.
    --   'human'               : only valid TOGETHER with a valid session of the same account.
    --                           In return it carries the full rights — the way for a tool that
    --                           a person operates themselves (CLI on their own machine).
    -- Up to 0.21.x the values were called 'automat' and 'mensch' (schema 12, `_werte_englisch`); they are
    -- still read (`KEY_ARTEN_ALT`). Up to 0.18.x there was no such distinction: every key
    -- of an admin was a complete admin write API, without a second factor and without a
    -- CSRF layer — a leaked CI key was the instance.
    kind       TEXT NOT NULL DEFAULT 'automation',
    created_at INTEGER NOT NULL,
    last_used  INTEGER,
    expires_at INTEGER,                          -- NULL = no expiry
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE audit (           -- audit log (login/logout/admin actions)
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    event    TEXT NOT NULL,
    username TEXT,
    ip       TEXT,
    detail   TEXT
);
INSERT INTO "audit" VALUES(1,1793237238,'login_ok','alice','203.0.113.7','reason=ok');
CREATE TABLE federated_identity (
    quelle      TEXT NOT NULL,              -- 'ldap' | 'saml'
    kennung     TEXT NOT NULL,              -- the stable identifier from the directory
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gebunden_at INTEGER NOT NULL,           -- when the binding came about (also: bound later)
    -- The name under which the account last signed in via this source, in the counting bucket
    -- (`norm_kennung`) — only if it is neither name nor address of the account (G5). After a
    -- rename in the directory the person types the NEW name, and the series is counted under it
    -- (B2-6); without this column no way back would clear it. NULL = none (or never seen).
    -- The name belongs to the account that last signed in like this (`bindung_name_setzen` deletes
    -- it from foreign bindings), and no other account can take it as name or address
    -- (identifier trigger, `TinySesam.identifier_taken`; review round lockouts/counters 2026-09-27).
    name_topf   TEXT,
    PRIMARY KEY (quelle, kennung)
);
INSERT INTO "federated_identity" VALUES('ldap','uid-bob',2,1793237249,'bob');
INSERT INTO "federated_identity" VALUES('saml','nameid-carol',3,1793237259,NULL);
INSERT INTO "federated_identity" VALUES('ldap','~ohne-kennung:alice',1,1793237250,NULL);
CREATE TABLE fehlserie (       -- failed attempts IN A ROW per identifier, without a time window (B2-6)
    topf    TEXT NOT NULL,                   -- folded identifier, the same key as login_attempt.username
    art     TEXT NOT NULL,                   -- method (password, pin, totp …): a reset only clears its own
    anzahl  INTEGER NOT NULL,
    seit    INTEGER NOT NULL,                -- first failed attempt of the current series
    zuletzt INTEGER NOT NULL,
    PRIMARY KEY (topf, art)
);
INSERT INTO "fehlserie" VALUES('bob','password',3,1793237239,1793237247);
INSERT INTO "fehlserie" VALUES('alice','pin_chain',1,1793237243,1793237243);
CREATE TABLE flow (            -- short-lived state (OIDC state/nonce, WebAuthn challenge)
    key        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,               -- JSON
    expires_at INTEGER NOT NULL
);
CREATE TABLE gate_abgemeldet (
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    at         INTEGER NOT NULL,
    PRIMARY KEY (token_hash, host)
);
INSERT INTO "gate_abgemeldet" VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','app.example.com',1793237278);
CREATE TABLE gate_link (
    link_hash  TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE login_attempt (   -- brute-force regulation
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT,
    ip       TEXT,
    success  INTEGER NOT NULL,
    method   TEXT,
    offen    INTEGER NOT NULL DEFAULT 0      -- 1: pre-booked, outcome still open (G9, `reserve_attempt`)
);
INSERT INTO "login_attempt" VALUES(1,1793237238,'alice','203.0.113.7',1,'password',0);
INSERT INTO "login_attempt" VALUES(2,1793237239,'bob','203.0.113.8',0,'password',1);
INSERT INTO "login_attempt" VALUES(3,1793237240,'bob','203.0.113.8',0,'pin_chain',0);
CREATE TABLE magic_token (      -- one-time token (magic link / invite / e-mail verify)
    token_hash TEXT PRIMARY KEY,               -- sha256(plaintext token)
    purpose    TEXT NOT NULL,                  -- login | invite | verify_email | …
    user_id    INTEGER,                        -- optional: bound to an existing user
    email      TEXT,
    payload    TEXT,                            -- JSON (e.g. roles, resource)
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER                          -- set on redemption → one-shot
);
CREATE TABLE namensbindung (
    quelle  TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bis     INTEGER NOT NULL,
    PRIMARY KEY (quelle, user_id)
);
INSERT INTO "namensbindung" VALUES('ldap',3,1793323638);
INSERT INTO "namensbindung" VALUES('saml',2,1793410038);
CREATE TABLE oidc_grant (
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client     TEXT NOT NULL,                 -- key from cfg.oidc_clients, "*" = single client
    granted_at INTEGER NOT NULL,              -- first approval (stays, even across re-checks)
    checked_at INTEGER NOT NULL,              -- last confirmation by the provider
    roles      TEXT NOT NULL DEFAULT '[]',    -- roles the provider yielded FOR THIS application
    PRIMARY KEY (token_hash, client)
);
CREATE TABLE oidc_id_token (
    token_hash TEXT PRIMARY KEY REFERENCES session(token_hash) ON DELETE CASCADE,
    client     TEXT NOT NULL,
    id_token   TEXT NOT NULL
);
CREATE TABLE oidc_identity (
    issuer   TEXT NOT NULL,
    subject  TEXT NOT NULL,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject)
);
CREATE TABLE oidc_sitzung (    -- refresh token of an OIDC session per client (4a, revocation follows the IdP)
    token_hash  TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client      TEXT NOT NULL,                -- key from cfg.oidc_clients, "*" = single client
    sub         TEXT NOT NULL,                -- subject at the provider; a different one ends the session
    refresh     TEXT NOT NULL,                -- encrypted (vault.Vault), never in plaintext
    geprueft_at INTEGER NOT NULL,             -- last exchange (or: claimed, see Store)
    client_id   TEXT,                         -- to which client_id the token went (NULL: before this column)
    erfolg_at   INTEGER,                      -- last SUCCESSFUL re-check (upper bound without re-check); NULL: before this column
    PRIMARY KEY (token_hash, client)
);
INSERT INTO "oidc_sitzung" VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','default','sub-1','v1:refresh',1793237268,'client-1',1793237269);
CREATE TABLE password_cred (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash     TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE pin_cred (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash     TEXT NOT NULL,               -- hashed like a password (argon2/scrypt)
    updated_at INTEGER NOT NULL
);
CREATE TABLE recovery_code (   -- one-time codes as 2FA substitute (lost authenticator)
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,                 -- sha256(normalized code)
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE TABLE resource_secret (  -- shared resource secret (without a user account)
    name       TEXT PRIMARY KEY,
    hash       TEXT NOT NULL,                 -- hashed like a password
    kind       TEXT NOT NULL DEFAULT 'pin',   -- 'pin' (numeric) | 'password' (passphrase)
    label      TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE resource_unlock (  -- unlocked resources per unlock token (cookie)
    token      TEXT NOT NULL,
    resource   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (token, resource)
);
CREATE TABLE session (
    token_hash TEXT PRIMARY KEY,               -- sha256(plaintext token); the plaintext is ONLY in the
                                               -- browser's cookie. Whoever reads the file does not get
                                               -- a hijackable session that way (see magic_token,
                                               -- which has done it like this from the start).
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    mfa_ok     INTEGER NOT NULL DEFAULT 0,   -- fully satisfies the active login policy (chain/2FA)
    mfa_at     INTEGER,                       -- time of the last factor confirmation (step-up freshness)
    method     TEXT,                          -- first/primary factor: password|pin|passkey|oidc|magic
    factors_done TEXT NOT NULL DEFAULT '[]',  -- JSON list of satisfied factors (chain engine)
    remember   INTEGER NOT NULL DEFAULT 1,   -- "stay signed in" (persistent cookie)
    ip         TEXT,
    user_agent TEXT,
    zuletzt    INTEGER,                       -- last request with this session (inactivity timeout, F-05)
    andere_beenden INTEGER NOT NULL DEFAULT 0, -- half session: end the others when the chain completes (limit d)
    bleiben_gewaehlt INTEGER NOT NULL DEFAULT 0, -- "stay signed in" EXPLICITLY chosen (F-05: then the second idle limit applies)
    nachfolger TEXT                           -- superseded by this session (grace period after rotation, A-6); NULL = current
);
INSERT INTO "session" VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,1793237238,1793240838,1,NULL,'password','["password"]',1,'203.0.113.7','probe',1793237298,0,1,NULL);
INSERT INTO "session" VALUES('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',2,1793237238,1793240838,1,NULL,'password','["password"]',0,'203.0.113.8','probe',NULL,1,0,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
CREATE TABLE setting (         -- runtime settings (hardening thresholds, editable in the panel)
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO "setting" VALUES('allowlist_nach_idp_entzug','1793237300');
INSERT INTO "setting" VALUES('idp_bestand_gesetzt','1793237238');
INSERT INTO "setting" VALUES('name_quelle_nachgetragen','1793237238');
INSERT INTO "setting" VALUES('name_selbst_nachgetragen','1793237238');
INSERT INTO "setting" VALUES('uhr_stand','1793237400');
INSERT INTO "setting" VALUES('panel_sperren_bis','1793237500');
INSERT INTO "setting" VALUES('foederation_seit:ldap','1793237238');
INSERT INTO "setting" VALUES('foederation_seit:saml','1793237239');
INSERT INTO "setting" VALUES('login_max_attempts','7');
CREATE TABLE totp_cred (
    user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret    TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_step INTEGER                          -- last consumed time step; a code is valid
                                               -- exactly once (NIST SP 800-63B: "SHALL accept a
                                               -- given OTP only once while it is valid")
);
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    email         TEXT,
    -- Does the address carry proof? 1 = yes (local registration once the confirmation link
    -- has been redeemed, or via an invitation to exactly this address; set by admin/CLI; an
    -- IdP with the claim), 0 = no. No does NOT mean "invalid": the
    -- address is kept and passed on as usual (`Remote-Email`), it just carries no
    -- rights — first admin/allowlist require the proof (`maybe_promote_admin`). An IdP that does not
    -- send `email_verified` (OIDC Core 5.1: optional; Entra ID) thereby ends up at 0,
    -- instead of losing the address. Default 1: existing data from before this column
    -- keeps its behaviour (the ALTER TABLE fills every existing row with it).
    email_verified INTEGER NOT NULL DEFAULT 1,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    -- Owner (decision 2026-09-24): always admin (set by hand, 1), cannot be deleted, cannot be locked, cannot be
    -- demoted; the role can be passed on, there is always at least one. Only owners grant it.
    is_owner      INTEGER NOT NULL DEFAULT 0,
    roles         TEXT NOT NULL DEFAULT '[]',   -- JSON list of fine-grained roles (optional)
    is_service    INTEGER NOT NULL DEFAULT 0,   -- service/daemon account: no interactive login, API key only
    -- 0 = active. 1 = locked because confirmation of the address is pending (registration, or
    -- `set_disabled(uid, True)` of an embedding app) — the confirmation link lifts that.
    -- 2 = locked by the operator (admin panel) — NO link lifts that, only the operator.
    disabled      INTEGER NOT NULL DEFAULT 0,
    -- When was this account fully signed in for the FIRST time? NULL = never (R3-1).
    -- Self-enrollment hangs on it: if the chain requires a second factor, an
    -- account may set it up itself as long as it has never been used — not afterwards.
    -- Otherwise the password of an EXISTING account would suffice to give oneself the second factor,
    -- and the chain would protect exactly those it was not meant for.
    first_login_at INTEGER,
    -- A time window for enrollment opened by the operator (admin panel, invitation).
    -- NULL/expired = closed. The way for any account the operating mode would otherwise deny it.
    mfa_enroll_until INTEGER,
    created_at    INTEGER NOT NULL,
    -- The counting bucket of the lockout counter (`norm_kennung`) of name and address, as columns with an index
    -- (schema 10). `konto_mit_topf` used to fold all accounts in Python on EVERY call: registration
    -- with a free address thereby took measurably longer than with a taken one
    -- (R4-03), and `gc()` grew with open accounts × all accounts. Set by `create_user` and
    -- `set_email`. NULL means "not computed yet" — a row from another writer
    -- (older version after a downgrade, raw SQL, a rename by hand, see the
    -- triggers in `_migrate`) — and is filled in later (`_toepfe_nachtragen`). '' = no address.
    -- Through the buckets the database also enforces the shared identifier space (`_trigger_sql`).
    topf_name     TEXT,
    topf_mail     TEXT,
    idp_bestaetigt_at INTEGER, -- last confirmation by the OIDC provider; 0 = no, NULL = never (finding 8)
    -- From when does the identifier belong to this account? (limit a, G2) The highest `login_attempt.id`
    -- or `audit.id` at the moment name or address entered their counting bucket — at
    -- creation, on rename, on address change and when an address is added later. What lies below
    -- belonged to nobody or to someone else. An id instead of a time: exact even within
    -- one second, and independent of the clock. NULL = data from before this column, then
    -- creation counts as the limit (`created_at`, `anlage_grenze`). Set by `create_user` and
    -- `_kennung_setzen`, with a foreign writer by the recompute trigger (`_trigger_sql`).
    name_versuch_ab INTEGER,
    mail_versuch_ab INTEGER,
    name_audit_ab   INTEGER,
    mail_audit_ab   INTEGER,
    -- From which federated source does the name originate ('oidc', 'saml', 'ldap')? Set when the
    -- source creates the account; NULL = assigned by the operator, chosen by the person or data from before
    -- this column. A name from one source says nothing about who is called that in ANOTHER:
    -- `preferred_username` or `uid` is chosen by oneself with an IdP that has self-registration. A
    -- sign-in via another source therefore never binds this account via the name
    -- (`_nachbindung_grund`, attack round 2026-09-26); the same source may keep replacing its placeholder
    -- with the real identifier. A rename resets it.
    name_quelle     TEXT,
    -- Did the person choose the name themselves (registration, renaming in self-service)?
    -- 1 = yes: then it says nothing about who is called that in the directory, and a sign-in via
    -- LDAP/SAML never binds this account via the name (G2-N, `_nachbindung_grund`). 0 = assigned by the
    -- operator (panel, API, rename with `by_operator=True`) or from a source
    -- (then `name_quelle` says which).
    name_selbst_gewaehlt INTEGER NOT NULL DEFAULT 0
);
INSERT INTO "users" VALUES(1,'alice','Alice','alice@example.com',1,1,1,'[]',0,0,NULL,NULL,1793237238,'alice','alice@example.com',1793237243,1793237239,1793237240,1793237241,1793237242,'oidc',1);
INSERT INTO "users" VALUES(2,'bob',NULL,'bob@example.com',1,0,0,'[]',0,0,NULL,NULL,1793237248,'bob','bob@example.com',NULL,NULL,NULL,NULL,NULL,'ldap',0);
INSERT INTO "users" VALUES(3,'carol',NULL,NULL,1,0,0,'[]',0,0,NULL,NULL,1793237258,'carol','',NULL,NULL,NULL,NULL,NULL,NULL,1);
CREATE TABLE webauthn_cred (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT UNIQUE NOT NULL,   -- base64url
    public_key    TEXT NOT NULL,          -- base64url (COSE)
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,                   -- JSON list
    name          TEXT,
    created_at    INTEGER NOT NULL,
    last_used     INTEGER
);
CREATE INDEX idx_session_user ON session(user_id);
CREATE INDEX idx_webauthn_user ON webauthn_cred(user_id);
CREATE INDEX idx_audit_name_ts ON audit(lower(username), ts);
CREATE INDEX idx_audit_ts ON audit(ts);
CREATE INDEX idx_attempt_user ON login_attempt(username, ts);
CREATE INDEX idx_attempt_ip ON login_attempt(ip, ts);
CREATE INDEX idx_apikey_user ON api_key(user_id);
CREATE INDEX idx_fed_quelle_user ON federated_identity(quelle, user_id);
CREATE UNIQUE INDEX ux_users_email ON users(lower(email)) WHERE email IS NOT NULL AND email <> '';
CREATE INDEX ix_users_topf_name ON users(topf_name);
CREATE INDEX ix_users_topf_mail ON users(topf_mail);
CREATE INDEX ix_fed_name_topf ON federated_identity(name_topf);
CREATE INDEX ix_users_name_nocase ON users(username COLLATE NOCASE);
CREATE INDEX ix_users_email_nocase ON users(email COLLATE NOCASE);
CREATE TRIGGER trg_users_topf_name AFTER UPDATE OF username ON users WHEN NEW.topf_name IS OLD.topf_name AND NEW.username IS NOT OLD.username BEGIN UPDATE users SET topf_name = NULL, name_versuch_ab = (SELECT COALESCE(MAX(id), 0) FROM login_attempt), name_audit_ab = (SELECT COALESCE(MAX(id), 0) FROM audit) WHERE id = NEW.id; END;
CREATE TRIGGER trg_users_topf_mail AFTER UPDATE OF email ON users WHEN NEW.topf_mail IS OLD.topf_mail AND NEW.email IS NOT OLD.email BEGIN UPDATE users SET topf_mail = NULL, mail_versuch_ab = (SELECT COALESCE(MAX(id), 0) FROM login_attempt), mail_audit_ab = (SELECT COALESCE(MAX(id), 0) FROM audit) WHERE id = NEW.id; END;
CREATE TRIGGER trg_users_wechsel_name AFTER UPDATE OF topf_name ON users WHEN NEW.topf_name IS NOT NULL AND NEW.topf_name IS NOT OLD.topf_name AND NEW.username IS NOT OLD.username BEGIN UPDATE users SET name_versuch_ab = (SELECT COALESCE(MAX(id), 0) FROM login_attempt), name_audit_ab = (SELECT COALESCE(MAX(id), 0) FROM audit) WHERE id = NEW.id; END;
CREATE TRIGGER trg_users_wechsel_mail AFTER UPDATE OF topf_mail ON users WHEN NEW.topf_mail IS NOT NULL AND NEW.topf_mail IS NOT OLD.topf_mail AND NEW.email IS NOT OLD.email BEGIN UPDATE users SET mail_versuch_ab = (SELECT COALESCE(MAX(id), 0) FROM login_attempt), mail_audit_ab = (SELECT COALESCE(MAX(id), 0) FROM audit) WHERE id = NEW.id; END;
CREATE TRIGGER trg_users_kennung_insert BEFORE INSERT ON users WHEN (NEW.topf_name IS NOT NULL AND NEW.topf_name <> '' AND (EXISTS (SELECT 1 FROM users WHERE (topf_name = NEW.topf_name OR topf_mail = NEW.topf_name)) OR EXISTS (SELECT 1 FROM federated_identity WHERE name_topf = NEW.topf_name))) OR (NEW.topf_mail IS NOT NULL AND NEW.topf_mail <> '' AND (EXISTS (SELECT 1 FROM users WHERE (topf_name = NEW.topf_mail OR topf_mail = NEW.topf_mail)) OR EXISTS (SELECT 1 FROM federated_identity WHERE name_topf = NEW.topf_mail))) BEGIN SELECT RAISE(ABORT, 'tinysesam: identifier taken'); END;
CREATE TRIGGER trg_users_kennung_update BEFORE UPDATE OF username, email ON users WHEN (NEW.topf_name IS NOT OLD.topf_name AND NEW.topf_name <> '' AND (EXISTS (SELECT 1 FROM users WHERE id IS NOT NEW.id AND (topf_name = NEW.topf_name OR topf_mail = NEW.topf_name)) OR EXISTS (SELECT 1 FROM federated_identity WHERE user_id IS NOT NEW.id AND name_topf = NEW.topf_name))) OR (NEW.topf_mail IS NOT OLD.topf_mail AND NEW.topf_mail <> '' AND (EXISTS (SELECT 1 FROM users WHERE id IS NOT NEW.id AND (topf_name = NEW.topf_mail OR topf_mail = NEW.topf_mail)) OR EXISTS (SELECT 1 FROM federated_identity WHERE user_id IS NOT NEW.id AND name_topf = NEW.topf_mail))) BEGIN SELECT RAISE(ABORT, 'tinysesam: identifier taken'); END;
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('users',3);
INSERT INTO "sqlite_sequence" VALUES('login_attempt',3);
INSERT INTO "sqlite_sequence" VALUES('audit',1);
COMMIT;
PRAGMA user_version = 15;

"""The SQLite schema of TinySesam (baseline 26, T-111): one `CREATE … IF NOT EXISTS` per table and index.

Applied by `Store._open_schema` to a new database; a change after the baseline raises `Store.SCHEMA_VERSION` with
one migration step (AGENTS.md, pitfalls). Kept apart from `store.py` so that the store itself stays small (T-112).
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
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
    -- 3 = locked by the application that manages the account (account API, schema 23) — it lifts only this
    -- value, never 1 or 2; the operator lifts every lock. Every check reads `disabled <> 0`.
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
    -- The counting bucket of the lockout counter (`norm_identifier`) of name and address, as columns with an index
    -- (schema 10). `account_by_bucket` used to fold all accounts in Python on EVERY call: registration
    -- with a free address thereby took measurably longer than with a taken one
    -- (R4-03), and `gc()` grew with open accounts × all accounts. Set by `create_user` and
    -- `set_email`. NULL means "not computed yet" — a row from another writer
    -- (older version after a downgrade, raw SQL, a rename by hand, see the
    -- triggers in `_trigger_sql`) — and is filled in later (`_backfill_pots`). '' = no address.
    -- Through the buckets the database also enforces the shared identifier space (`_trigger_sql`).
    folded_name     TEXT,
    folded_mail     TEXT,
    idp_confirmed_at INTEGER, -- last confirmation by the OIDC provider; 0 = no, NULL = never (finding 8)
    -- From when does the identifier belong to this account? (limit a, G2) The highest `login_attempt.id`
    -- or `audit.id` at the moment name or address entered their counting bucket — at
    -- creation, on rename, on address change and when an address is added later. What lies below
    -- belonged to nobody or to someone else. An id instead of a time: exact even within
    -- one second, and independent of the clock. NULL = data from before this column, then
    -- creation counts as the limit (`created_at`, `setup_limit`). Set by `create_user` and
    -- `_set_identifier`, with a foreign writer by the recompute trigger (`_trigger_sql`).
    name_attempt_from INTEGER,
    mail_attempt_from INTEGER,
    name_audit_from   INTEGER,
    mail_audit_from   INTEGER,
    -- 1 = the password was set by an administrator (panel: new account or reset) and is a start
    -- secret only (T-46, ASVS 6.4.1): the next password sign-in stays half until the holder chose an
    -- own one. Any password the holder sets clears it (`TinySesam.set_password`).
    password_must_change INTEGER NOT NULL DEFAULT 0,
    -- Which application created the account through the account API (`apps`, schema 23)? Its id; NULL = the
    -- operator or the person. Set only on creation by the application (later: by the operator, adopt/release).
    -- Ownership hangs on this column alone, never on the roles (draft "account API", section 3).
    managed_by      TEXT,
    -- The last complete sign-in (schema 23), set at the same place as `first_login_at`, on every one.
    last_login_at   INTEGER,
    -- Deletion with a grace period (schema 23; stage B of the account API): from this time the account is removed.
    -- NULL = not scheduled.
    delete_after    INTEGER,
    -- From which federated source does the name originate ('oidc', 'saml', 'ldap')? Set when the
    -- source creates the account; NULL = assigned by the operator, chosen by the person or data from before
    -- this column. A name from one source says nothing about who is called that in ANOTHER:
    -- `preferred_username` or `uid` is chosen by oneself with an IdP that has self-registration. A
    -- sign-in via another source therefore never binds this account via the name
    -- (`_rebinding_reason`, attack round 2026-09-26); the same source may keep replacing its placeholder
    -- with the real identifier. A rename resets it.
    name_source     TEXT,
    -- Did the person choose the name themselves (registration, renaming in self-service)?
    -- 1 = yes: then it says nothing about who is called that in the directory, and a sign-in via
    -- LDAP/SAML never binds this account via the name (G2-N, `_rebinding_reason`). 0 = assigned by the
    -- operator (panel, API, rename with `by_operator=True`) or from a source
    -- (then `name_source` says which).
    name_self_chosen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_key (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT,
    prefix     TEXT NOT NULL,                   -- display (tsk_xxxx…), NOT the key
    key_hash   TEXT UNIQUE NOT NULL,            -- HMAC with the pepper (`Store.token_digest`, T-72)
    roles      TEXT NOT NULL DEFAULT '[]',      -- key scope; empty = inherits user roles
    -- What kind of key is this? (R6-5)
    --   'automation' (default): works on its own, NEVER carries its owner's admin flag and
    --                           satisfies no route that requires admin. For services and scripts.
    --   'human'               : only valid TOGETHER with a valid session of the same account.
    --                           In return it carries the full rights — the way for a tool that
    --                           a person operates themselves (CLI on their own machine).
    -- Up to 0.18.x there was no such distinction: every key
    -- of an admin was a complete admin write API, without a second factor and without a
    -- CSRF layer — a leaked CI key was the instance.
    kind       TEXT NOT NULL DEFAULT 'automation',
    created_at INTEGER NOT NULL,
    last_used  INTEGER,
    expires_at INTEGER,                          -- NULL = no expiry
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS password_cred (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash     TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pin_cred (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash     TEXT NOT NULL,               -- hashed like a password (argon2/scrypt)
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS totp_cred (
    user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret    TEXT NOT NULL,
    confirmed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_step INTEGER                          -- last consumed time step; a code is valid
                                               -- exactly once (NIST SP 800-63B: "SHALL accept a
                                               -- given OTP only once while it is valid")
);
CREATE TABLE IF NOT EXISTS recovery_code (   -- one-time codes as 2FA substitute (lost authenticator)
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,                 -- HMAC with the pepper (`Store.token_digest`, kind `recovery`)
    created_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE TABLE IF NOT EXISTS webauthn_cred (
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
CREATE TABLE IF NOT EXISTS oidc_identity (
    issuer   TEXT NOT NULL,
    subject  TEXT NOT NULL,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject)
);
-- Foreign identity → local account, via a STABLE identifier of the directory (F-11).
-- OIDC has `oidc_identity` for that (issuer+sub); LDAP and SAML bound solely via the
-- username up to 0.19.0. A name is not forgery-proof, though: whoever renames in the directory or
-- recreates a deleted account under the same name gets the same local account including
-- its roles. The identifier here is objectGUID/entryUUID (LDAP) or the NameID (SAML) — it
-- survives a rename and is not reused.
CREATE TABLE IF NOT EXISTS federated_identity (
    source      TEXT NOT NULL,              -- 'ldap' | 'saml'
    identifier     TEXT NOT NULL,              -- the stable identifier from the directory
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bound_at INTEGER NOT NULL,           -- when the binding came about (also: bound later)
    -- The name under which the account last signed in via this source, in the counting bucket
    -- (`norm_identifier`) — only if it is neither name nor address of the account (G5). After a
    -- rename in the directory the person types the NEW name, and the series is counted under it
    -- (B2-6); without this column no way back would clear it. NULL = none (or never seen).
    -- The name belongs to the account that last signed in like this (`set_binding_name` deletes
    -- it from foreign bindings), and no other account can take it as name or address
    -- (identifier trigger, `TinySesam.identifier_taken`; review round lockouts/counters 2026-09-27).
    directory_name_folded   TEXT,
    PRIMARY KEY (source, identifier)
);
-- Binding via the name opened by the operator (G1): until `until` the next sign-in via
-- LDAP/SAML binds this account via its name, even after the deadline (`federation_name_binding_days`)
-- and even with a self-chosen name. Written by `federation_unbind`, deleted as soon as
-- the binding stands. Without a row the deadline decides.
CREATE TABLE IF NOT EXISTS name_binding (
    source  TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    until     INTEGER NOT NULL,
    PRIMARY KEY (source, user_id)
);
CREATE TABLE IF NOT EXISTS session (
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
    last_seen    INTEGER,                       -- last request with this session (inactivity timeout, F-05)
    end_others INTEGER NOT NULL DEFAULT 0, -- half session: end the others when the chain completes (limit d)
    stay_chosen INTEGER NOT NULL DEFAULT 0, -- "stay signed in" EXPLICITLY chosen (F-05: then the second idle limit applies)
    successor TEXT                           -- superseded by this session (grace period after rotation, A-6); NULL = current
);
-- Which application has the provider approved for this session? (T-14)
-- One row per session AND application: whoever signs in for app-a does not thereby get
-- access to app-b — the provider decides again there. Without this table there would only be the
-- question "signed in yes/no", and that cannot represent the approval per client.
CREATE TABLE IF NOT EXISTS oidc_grant (
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client     TEXT NOT NULL,                 -- key from cfg.oidc_clients, "*" = single client
    granted_at INTEGER NOT NULL,              -- first approval (stays, even across re-checks)
    checked_at INTEGER NOT NULL,              -- last confirmation by the provider
    roles      TEXT NOT NULL DEFAULT '[]',    -- roles the provider yielded FOR THIS application
    PRIMARY KEY (token_hash, client)
);
CREATE TABLE IF NOT EXISTS oidc_session (    -- refresh token of an OIDC session per client (4a, revocation follows the IdP)
    token_hash  TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client      TEXT NOT NULL,                -- key from cfg.oidc_clients, "*" = single client
    sub         TEXT NOT NULL,                -- subject at the provider; a different one ends the session
    refresh     TEXT NOT NULL,                -- encrypted (vault.Vault), never in plaintext
    checked_at INTEGER NOT NULL,             -- last exchange (or: claimed, see Store)
    client_id   TEXT,                         -- to which client_id the token went (NULL: before this column)
    success_at   INTEGER,                      -- last SUCCESSFUL re-check (upper bound without re-check); NULL: before this column
    PRIMARY KEY (token_hash, client)
);
-- Signed out of ONLY THIS application (T-22, `forward_logout="app"`): the session stays, but the
-- forward auth no longer lets it through for this host until the person explicitly
-- chooses "continue" on the login page. Without the row "sign out only here" would be a page reload.
CREATE TABLE IF NOT EXISTS gate_signed_out (
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    at         INTEGER NOT NULL,
    PRIMARY KEY (token_hash, host)
);
-- The ID token of the sign-in, encrypted (vault.Vault) — only as `id_token_hint` for the
-- logout at the provider (T-22). PocketID does not end its session without the hint, but
-- shows a confirmation prompt and does not redirect back afterwards.
-- The link of an app host to the central session (code exchange, T-26): the session stays
-- on the gateway's host; the app host only gets a cookie of its own, whose hash is stored here.
-- It is valid ONLY for its host and ends with the session (ON DELETE CASCADE).
CREATE TABLE IF NOT EXISTS gate_link (
    link_hash  TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oidc_id_token (
    token_hash TEXT PRIMARY KEY REFERENCES session(token_hash) ON DELETE CASCADE,
    client     TEXT NOT NULL,
    id_token   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS flow (            -- short-lived state (OIDC state/nonce, WebAuthn challenge)
    key        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,               -- JSON
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS setting (         -- runtime settings (hardening thresholds, editable in the panel)
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS magic_token (      -- one-time token (magic link / invite / e-mail verify)
    token_hash TEXT PRIMARY KEY,               -- HMAC with the pepper (`Store.token_digest`, T-72)
    purpose    TEXT NOT NULL,                  -- login | invite | verify_email | …
    user_id    INTEGER,                        -- optional: bound to an existing user
    email      TEXT,
    payload    TEXT,                            -- JSON (e.g. roles, resource)
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER                          -- set on redemption → one-shot
);
CREATE TABLE IF NOT EXISTS resource_secret (  -- shared resource secret (without a user account)
    name       TEXT PRIMARY KEY,
    hash       TEXT NOT NULL,                 -- hashed like a password
    kind       TEXT NOT NULL DEFAULT 'pin',   -- 'pin' (numeric) | 'password' (passphrase)
    label      TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_unlock (  -- unlocked resources per unlock token (cookie)
    token      TEXT NOT NULL,
    resource   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (token, resource)
);
CREATE TABLE IF NOT EXISTS login_attempt (   -- brute-force regulation
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    username TEXT,
    ip       TEXT,
    success  INTEGER NOT NULL,
    method   TEXT,
    pending    INTEGER NOT NULL DEFAULT 0      -- 1: pre-booked, outcome still open (G9, `reserve_attempt`)
);
CREATE TABLE IF NOT EXISTS failure_series (       -- failed attempts IN A ROW per identifier, without a time window (B2-6)
    folded    TEXT NOT NULL,                   -- folded identifier, the same key as login_attempt.username
    kind     TEXT NOT NULL,                   -- method (password, pin, totp …): a reset only clears its own
    count  INTEGER NOT NULL,
    since    INTEGER NOT NULL,                -- first failed attempt of the current series
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (folded, kind)
);
CREATE TABLE IF NOT EXISTS audit (           -- audit log (login/logout/admin actions)
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    event    TEXT NOT NULL,
    username TEXT,
    ip       TEXT,
    detail   TEXT
);
-- OAuth 2.1 authorization server for human-operated tools (T-36, ADR-11). Tokens and codes are stored only
-- as an HMAC digest keyed with the pepper, which is never in this file (`tinysesam/oauth.py`).
CREATE TABLE IF NOT EXISTS oauth_client (    -- registered by the client itself (RFC 7591): public, no secret
    client_id     TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,             -- JSON list, loopback only
    created_at    INTEGER NOT NULL,
    created_ip    TEXT,
    last_used     INTEGER                    -- last authorization or token exchange
);
CREATE TABLE IF NOT EXISTS oauth_request (   -- authorization request between /authorize and the consent
    id_hash      TEXT PRIMARY KEY,
    browser_hash TEXT NOT NULL,              -- digest of the flow cookie: only the browser that started it
    client_id    TEXT NOT NULL REFERENCES oauth_client(client_id) ON DELETE CASCADE,
    params       TEXT NOT NULL,              -- JSON: redirect_uri, state, code_challenge, scope, resource
    expires_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_code (      -- authorization code: single use, bound to everything it came from
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    resource       TEXT NOT NULL,
    scope          TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    consumed_at    INTEGER,                  -- set atomically on the first exchange
    grant_id       INTEGER,                  -- the grant it was exchanged for: a second use revokes it
    consent_via    TEXT                      -- NULL = the consent page, pairing = a pairing code (ADR-14)
);
CREATE TABLE IF NOT EXISTS oauth_grant (     -- one connected device: client registration + token family
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id      TEXT NOT NULL REFERENCES oauth_client(client_id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource       TEXT NOT NULL,            -- the audience of every token of the family (RFC 8707)
    scope          TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    created_ip     TEXT,
    last_used      INTEGER,
    last_ip        TEXT,
    expires_at     INTEGER,                  -- absolute maximum (oauth_refresh_max_days); NULL = none
    revoked_at     INTEGER,
    revoked_reason TEXT,
    consent_via    TEXT                      -- copied from the code: how the person allowed it (ADR-14)
);
CREATE TABLE IF NOT EXISTS oauth_token (
    token_hash TEXT PRIMARY KEY,
    grant_id   INTEGER NOT NULL REFERENCES oauth_grant(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,                -- access | refresh
    scope      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,                      -- refresh: exchanged once (rotation); a second use is reuse
    successor  TEXT                          -- refresh, grace window only: the successor pair, encrypted (vault)
);
-- OAuth for services (T-60, ADR-13): a service is an `oauth_client` row plus this one. It authenticates with
-- `private_key_jwt` (RFC 7523), and only its PUBLIC keys are stored — nothing here lets anyone sign.
CREATE TABLE IF NOT EXISTS oauth_service_client (
    client_id      TEXT PRIMARY KEY REFERENCES oauth_client(client_id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    roles          TEXT,                     -- JSON scope, NULL = the account roles
    resources      TEXT NOT NULL,            -- JSON list: the resources it may get tokens for
    created_by     TEXT,                     -- who issued the pairing code
    last_ip        TEXT,
    revoked_at     INTEGER,
    revoked_reason TEXT
);
CREATE TABLE IF NOT EXISTS oauth_client_key (
    client_id  TEXT NOT NULL REFERENCES oauth_client(client_id) ON DELETE CASCADE,
    kid        TEXT NOT NULL,                -- RFC 7638 thumbprint of the public key
    jwk        TEXT NOT NULL,                -- the public JWK (OKP Ed25519 or EC P-256), never a private part
    created_at INTEGER NOT NULL,
    created_ip TEXT,
    expires_at INTEGER,                      -- oauth_service_key_days after creation, NULL = none
    retire_at  INTEGER,                      -- NULL = current key, otherwise accepted until then (rotation overlap)
    last_used  INTEGER,
    PRIMARY KEY (client_id, kid)
);
CREATE TABLE IF NOT EXISTS oauth_assertion (   -- `jti` of every accepted client assertion until its `exp` (replay)
    client_id  TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (client_id, jti)
);
-- Keys of their own purpose (T-48, ADR-12): the gate signing key and the OAuth pepper, when no environment variable
-- or file provides them. Encrypted with the vault (AAD: purpose and kid) — the database alone does not give them,
-- the vault key alone does not either. One active key per purpose (`since IS NULL`), the others are previous.
CREATE TABLE IF NOT EXISTS key_material (
    purpose    TEXT NOT NULL,                -- gate | oauth-pepper
    kid        TEXT NOT NULL,
    material   TEXT NOT NULL,                -- vault ciphertext
    created_at INTEGER NOT NULL,
    since      INTEGER,                      -- NULL = active; otherwise no longer active since
    note       TEXT,                         -- free text; `derived-v1` (≤ 0.25.x) is refused at start
    PRIMARY KEY (purpose, kid)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_key_material_active ON key_material(purpose) WHERE since IS NULL;
-- App passwords (T-66): a password per device for Basic auth at the gate, valid only for the hosts it names.
-- Only the digest is stored (HMAC with the pepper keyring, `app_passwords.digest`); `kid` names the pepper that made
-- it — a use with a previous pepper rewrites it with the active one. Revoked rows stay (the holder sees them).
CREATE TABLE IF NOT EXISTS app_password (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    digest         TEXT UNIQUE NOT NULL,
    kid            TEXT NOT NULL,
    hosts          TEXT NOT NULL,            -- JSON list of the hosts it is valid for (forward_apps)
    created_at     INTEGER NOT NULL,
    created_ip     TEXT,
    expires_at     INTEGER,                  -- NULL = no expiry (app_password_allow_unlimited)
    last_used      INTEGER,
    last_ip        TEXT,
    revoked_at     INTEGER,
    revoked_reason TEXT                      -- holder | admin | account_disabled | admin_password_reset | …
);
-- Approvals (schema 22): a request to confirm ONE sensitive action, made by a token (class a: a TinySesam action) or
-- later by an application (class b). The row is the whole state machine: every transition is one
-- `UPDATE … WHERE state = <old>`, so two confirmations race to exactly one winner. `payload` is canonical JSON
-- (RFC 8785 for the values used here: strings, integers, booleans, lists), `payload_hash` its SHA-256 in base64url.
-- No secret lives here: the id is public in the link, the match code is shown on both sides.
CREATE TABLE IF NOT EXISTS approval (
    id             TEXT PRIMARY KEY,           -- apv_ + 128 bits of randomness (base32)
    class          TEXT NOT NULL,              -- tinysesam | app
    type           TEXT NOT NULL,              -- e.g. tinysesam.account.set_roles
    app_id         TEXT,                       -- class b only (stage B), otherwise NULL
    subject_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,   -- who must confirm
    requester_kind TEXT NOT NULL,              -- apikey | oauth | app
    requester_ref  TEXT NOT NULL,              -- key id, grant id or app account id
    payload        TEXT NOT NULL,
    payload_hash   TEXT NOT NULL,
    match_code     TEXT NOT NULL,              -- "418 207": in the channel of the requester and on the page
    return_url     TEXT,                       -- class b, browser entry only (stage B)
    nonce          TEXT,                       -- class b, browser entry: the state sent by the application
    state          TEXT NOT NULL,              -- pending | approved | consumed | rejected | expired | withdrawn
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    decided_at     INTEGER,
    issued_at      INTEGER,                    -- class b: when the confirmation was handed out (stage B)
    stepup_amr     TEXT,                       -- JSON list of RFC 8176 values of the per-approval step-up
    auth_time      INTEGER,                    -- when that step-up happened
    result         TEXT,                       -- class a: ok | forbidden | not_found | invalid | conflict
    ip_request     TEXT,
    ip_decision    TEXT
);
-- The role catalog (schema 25): roles an administrator added in the panel or with `tinysesam roles`, so the panel offers
-- them next to `available_roles`. It grants nothing: headers, tokens and `has_role` read only the roles an account
-- holds. A role the configuration names is no catalog role (the configuration stays the truth).
CREATE TABLE IF NOT EXISTS role_catalog (
    name         TEXT PRIMARY KEY,         -- the role exactly as stored on accounts
    name_compare TEXT NOT NULL UNIQUE,     -- casefold(name): no "Editors" next to "editors"
    created_at   INTEGER NOT NULL,
    created_by   TEXT                      -- account name of the actor, "cli", or NULL (own code)
);
CREATE INDEX IF NOT EXISTS idx_approval_subject ON approval(subject_id, state);
CREATE INDEX IF NOT EXISTS idx_approval_requester ON approval(requester_kind, requester_ref, created_at);
CREATE INDEX IF NOT EXISTS idx_app_password_user ON app_password(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_grant_user ON oauth_grant(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_grant_client ON oauth_grant(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_token_grant ON oauth_token(grant_id);
CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_cred(user_id);
-- Limit c (integration attack): `setup_limit` and `anonymize_audit` search by name and
-- time. Without an index that ran over the whole audit log — its size grows with the retention.
-- Only name and time: the search in the DETAIL text (`anonymize_audit`) is a substring search
-- that no index narrows down — it remains a scan, but since G4 runs in blocks without a write lock.
CREATE INDEX IF NOT EXISTS idx_audit_name_ts ON audit(lower(username), ts);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_attempt_user ON login_attempt(username, ts);
CREATE INDEX IF NOT EXISTS idx_attempt_ip ON login_attempt(ip, ts);
CREATE INDEX IF NOT EXISTS idx_apikey_user ON api_key(user_id);
-- G1: "Which accounts still carry no identifier for this source?" (startup message, binding of existing accounts)
-- asks for its row per account; without an index that would read all bindings of the source per account.
CREATE INDEX IF NOT EXISTS idx_fed_source_user ON federated_identity(source, user_id);
-- Permissions (schema 27, T-100, ADR-17): what an application declares it can do, per application (`apps` id). The
-- application registers (configuration `apps[id].permissions` or `register_permissions`); registering grants nothing.
-- A permission that leaves its manifest is `orphaned`: it grants nothing, is shown, and can be deleted.
CREATE TABLE IF NOT EXISTS app_permission (
    app             TEXT NOT NULL,            -- the application's id in `apps`
    name            TEXT NOT NULL,            -- e.g. docs.delete (name rule in `permissions.NAME`)
    label           TEXT NOT NULL DEFAULT '{}',   -- JSON {"en": …, "de": …}
    description     TEXT NOT NULL DEFAULT '{}',   -- JSON {"en": …, "de": …}
    danger          INTEGER NOT NULL DEFAULT 0,   -- 1: assigning it in the panel needs a fresh confirmation
    suggested_roles TEXT NOT NULL DEFAULT '[]',   -- JSON list: a hint in the panel, never a grant
    source          TEXT NOT NULL,            -- config | app: whose manifest names it
    registered_at   INTEGER NOT NULL,
    orphaned_at     INTEGER,                  -- set when it left its manifest: grants nothing from then on
    PRIMARY KEY (app, name)
);
-- Which role holds which permission of which application — assigned by an administrator, never by the application.
-- `active` = 0: the permission was orphaned meanwhile; the row is shown, but it grants nothing again by itself — not even
-- when the permission comes back (an administrator assigns it anew).
CREATE TABLE IF NOT EXISTS role_permission (
    role       TEXT NOT NULL,
    app        TEXT NOT NULL,
    name       TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    granted_at INTEGER NOT NULL,
    granted_by TEXT,                          -- account name of the administrator, "config", or NULL (own code)
    PRIMARY KEY (role, app, name),
    FOREIGN KEY (app, name) REFERENCES app_permission(app, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_role_permission_app ON role_permission(app, name);
"""

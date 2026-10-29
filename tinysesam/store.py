"""SQLite store for TinySesam: users, credentials (password/TOTP/WebAuthn/OIDC) and sessions.

Deliberately stdlib `sqlite3` (no ORM): lightweight, no extra dependency.
Thread-safe via a lock + `check_same_thread=False` (FastAPI workers share the instance).

What happens with a read-only, full or locked database and with a jump of the system clock
is described for operators in `docs/OPERATIONS.md` (failure behaviour).
"""
from __future__ import annotations
import contextlib, sqlite3, threading, time, secrets, json, logging, hashlib, os, re, stat, unicodedata
from typing import Any, Optional

from . import _vocabulary

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
    -- triggers in `_migrate`) — and is filled in later (`_backfill_pots`). '' = no address.
    -- Through the buckets the database also enforces the shared identifier space (`_trigger_sql`).
    topf_name     TEXT,
    topf_mail     TEXT,
    idp_bestaetigt_at INTEGER, -- last confirmation by the OIDC provider; 0 = no, NULL = never (finding 8)
    -- From when does the identifier belong to this account? (limit a, G2) The highest `login_attempt.id`
    -- or `audit.id` at the moment name or address entered their counting bucket — at
    -- creation, on rename, on address change and when an address is added later. What lies below
    -- belonged to nobody or to someone else. An id instead of a time: exact even within
    -- one second, and independent of the clock. NULL = data from before this column, then
    -- creation counts as the limit (`created_at`, `setup_limit`). Set by `create_user` and
    -- `_set_identifier`, with a foreign writer by the recompute trigger (`_trigger_sql`).
    name_versuch_ab INTEGER,
    mail_versuch_ab INTEGER,
    name_audit_ab   INTEGER,
    mail_audit_ab   INTEGER,
    -- From which federated source does the name originate ('oidc', 'saml', 'ldap')? Set when the
    -- source creates the account; NULL = assigned by the operator, chosen by the person or data from before
    -- this column. A name from one source says nothing about who is called that in ANOTHER:
    -- `preferred_username` or `uid` is chosen by oneself with an IdP that has self-registration. A
    -- sign-in via another source therefore never binds this account via the name
    -- (`_rebinding_reason`, attack round 2026-09-26); the same source may keep replacing its placeholder
    -- with the real identifier. A rename resets it.
    name_quelle     TEXT,
    -- Did the person choose the name themselves (registration, renaming in self-service)?
    -- 1 = yes: then it says nothing about who is called that in the directory, and a sign-in via
    -- LDAP/SAML never binds this account via the name (G2-N, `_rebinding_reason`). 0 = assigned by the
    -- operator (panel, API, rename with `by_operator=True`) or from a source
    -- (then `name_quelle` says which).
    name_selbst_gewaehlt INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_key (
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
    -- Up to 0.21.x the values were called 'automat' and 'mensch' (schema 12, `_values_english`); they are
    -- still read (`KEY_KINDS_OLD`). Up to 0.18.x there was no such distinction: every key
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
    code_hash  TEXT NOT NULL,                 -- sha256(normalized code)
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
    quelle      TEXT NOT NULL,              -- 'ldap' | 'saml'
    kennung     TEXT NOT NULL,              -- the stable identifier from the directory
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gebunden_at INTEGER NOT NULL,           -- when the binding came about (also: bound later)
    -- The name under which the account last signed in via this source, in the counting bucket
    -- (`norm_identifier`) — only if it is neither name nor address of the account (G5). After a
    -- rename in the directory the person types the NEW name, and the series is counted under it
    -- (B2-6); without this column no way back would clear it. NULL = none (or never seen).
    -- The name belongs to the account that last signed in like this (`set_binding_name` deletes
    -- it from foreign bindings), and no other account can take it as name or address
    -- (identifier trigger, `TinySesam.identifier_taken`; review round lockouts/counters 2026-09-27).
    name_topf   TEXT,
    PRIMARY KEY (quelle, kennung)
);
-- Binding via the name opened by the operator (G1): until `bis` the next sign-in via
-- LDAP/SAML binds this account via its name, even after the deadline (`federation_name_binding_days`)
-- and even with a self-chosen name. Written by `federation_unbind`, deleted as soon as
-- the binding stands. Without a row the deadline decides.
CREATE TABLE IF NOT EXISTS namensbindung (
    quelle  TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bis     INTEGER NOT NULL,
    PRIMARY KEY (quelle, user_id)
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
    zuletzt    INTEGER,                       -- last request with this session (inactivity timeout, F-05)
    andere_beenden INTEGER NOT NULL DEFAULT 0, -- half session: end the others when the chain completes (limit d)
    bleiben_gewaehlt INTEGER NOT NULL DEFAULT 0, -- "stay signed in" EXPLICITLY chosen (F-05: then the second idle limit applies)
    nachfolger TEXT                           -- superseded by this session (grace period after rotation, A-6); NULL = current
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
CREATE TABLE IF NOT EXISTS oidc_sitzung (    -- refresh token of an OIDC session per client (4a, revocation follows the IdP)
    token_hash  TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client      TEXT NOT NULL,                -- key from cfg.oidc_clients, "*" = single client
    sub         TEXT NOT NULL,                -- subject at the provider; a different one ends the session
    refresh     TEXT NOT NULL,                -- encrypted (vault.Vault), never in plaintext
    geprueft_at INTEGER NOT NULL,             -- last exchange (or: claimed, see Store)
    client_id   TEXT,                         -- to which client_id the token went (NULL: before this column)
    erfolg_at   INTEGER,                      -- last SUCCESSFUL re-check (upper bound without re-check); NULL: before this column
    PRIMARY KEY (token_hash, client)
);
-- Signed out of ONLY THIS application (T-22, `forward_logout="app"`): the session stays, but the
-- forward auth no longer lets it through for this host until the person explicitly
-- chooses "continue" on the login page. Without the row "sign out only here" would be a page reload.
CREATE TABLE IF NOT EXISTS gate_abgemeldet (
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
    token_hash TEXT PRIMARY KEY,               -- sha256(plaintext token)
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
    offen    INTEGER NOT NULL DEFAULT 0      -- 1: pre-booked, outcome still open (G9, `reserve_attempt`)
);
CREATE TABLE IF NOT EXISTS fehlserie (       -- failed attempts IN A ROW per identifier, without a time window (B2-6)
    topf    TEXT NOT NULL,                   -- folded identifier, the same key as login_attempt.username
    art     TEXT NOT NULL,                   -- method (password, pin, totp …): a reset only clears its own
    anzahl  INTEGER NOT NULL,
    seit    INTEGER NOT NULL,                -- first failed attempt of the current series
    zuletzt INTEGER NOT NULL,
    PRIMARY KEY (topf, art)
);
CREATE TABLE IF NOT EXISTS audit (           -- audit log (login/logout/admin actions)
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    event    TEXT NOT NULL,
    username TEXT,
    ip       TEXT,
    detail   TEXT
);
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
CREATE INDEX IF NOT EXISTS idx_fed_quelle_user ON federated_identity(quelle, user_id);
"""


#: Characters where IDNA 2003 (stdlib codec) and IDNA 2008 differ: the stdlib codec
#: turns `straße.example` into `strasse.example` — a DIFFERENT domain. A domain containing one of them
#: stays in Unicode form instead of being rewritten incorrectly.
_IDNA_DEVIANTS = frozenset("ßς\u200c\u200d")


def _domain_canonical(domain: str) -> str:
    """Bring a domain into A-label form (`xn--…`) when that is unambiguous (R4-06).

    Otherwise `bücher.example` and `xn--bcher-kva.example` are stored as two different addresses
    in the database although both mean the same mailbox — two accounts, two "taken" checks
    that cannot see each other. What cannot be rewritten safely stays unchanged."""
    if domain.isascii() or any(z in _IDNA_DEVIANTS for z in domain):
        return domain
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain


def _email_unicode(email: str) -> str:
    """The address with its domain in Unicode form (`xn--bcher-kva.example` → `bücher.example`).

    Only for looking up existing addresses from before R4-06 that are still stored that way — never
    for storing. What cannot be decoded is returned unchanged."""
    local, at, domain = email.rpartition("@")
    if not at or "xn--" not in domain:
        return email
    try:
        return f"{local}@{domain.encode('ascii').decode('idna').lower()}"
    except UnicodeError:
        return email


def key_kind_of(row) -> str:
    """The kind of a key row with the English name (schema 12): `automation` or `human`.

    A value up to 0.21.x (`automaton`, `human`) is mapped (`Store.KEY_KINDS_OLD`) — an older
    version that ran on the file after a rollback writes it again. Empty or without the
    column (file before schema 7) means `automation`. Anything else stays as it is and, because
    it is not `human`, counts as an automation key (fail-closed, R6-6). Here and not on the manager, so that
    router and admin panel can read it without importing the manager (no import cycle)."""
    try:
        value = str(row["kind"] or "automation")
    except (IndexError, KeyError, TypeError):
        return "automation"
    return Store.KEY_KINDS_OLD.get(value, value)

def norm_email(email) -> Optional[str]:
    """Store an email canonically: NFKC, trimmed, lowercase, domain as A-label. `None` stays `None`.

    NFKC folds compatibility characters (R4-06): a full-width `ａｄｍｉｎ@example.com` is afterwards
    the same as `admin@example.com` — before, they were two identifiers that looked the same
    in the panel."""
    e = unicodedata.normalize("NFKC", str(email or "")).strip().lower()
    if not e:
        return None
    local, at, domain = e.rpartition("@")
    if at and domain:
        e = f"{local}@{_domain_canonical(domain)}"
    return e


def _fonts(text: str) -> set:
    """The scripts of the letters in `text` (first word of the Unicode name: LATIN,
    CYRILLIC, GREEK …). Digits and punctuation do not count."""
    return {unicodedata.name(z, "?").split(" ", 1)[0] for z in text if z.isalpha()}


#: Scripts that belong together in ONE language and may therefore be mixed (attack A6,
#: modelled on UTS #39 "Highly Restrictive"): Japanese writes kanji with hiragana and katakana
#: (`山田たろう`, `例え`), Korean hanja with hangul, Chinese han with bopomofo. Without this
#: exception the script check rejected ordinary Japanese addresses and IDN domains. Latin
#: deliberately belongs to no group — `аdmin` (Cyrillic/Latin) stays rejected.
_FONT_GROUPS = (
    frozenset({"CJK", "IDEOGRAPHIC", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"}),
    frozenset({"CJK", "IDEOGRAPHIC", "HANGUL"}),
    frozenset({"CJK", "IDEOGRAPHIC", "BOPOMOFO"}),
)


def _a_font(part: str) -> bool:
    """Do the letters come from one script — or from a group that belongs together?"""
    s = _fonts(part)
    return len(s) <= 1 or any(s <= group for group in _FONT_GROUPS)


def name_invalid(name) -> bool:
    """Does a username contain control, format or separator characters (Cc/Cf/Zl/Zp)?

    Such characters separate two identifiers that look the same to a human and to an HTTP header:
    `manager\\x01` is a different name from `manager` for `identifier_taken`, but the forward-auth
    header sanitising strips the control character — the protected app received
    `Remote-User: manager` from a foreign account (attack in the third round). The same rule
    as for addresses (`valid_email`)."""
    return any(unicodedata.category(z) in ("Cc", "Cf", "Zl", "Zp") for z in str(name or ""))


def norm_identifier(identifier) -> str:
    """The login identifier as the lockout counter keeps it: NFKC, trimmed, lowercase — and an
    address as canonical as `norm_email` stores it.

    Must fold at least as coarsely as `TinySesam.find_user` (strip, `norm_email`, NOCASE):
    every spelling that hits the same account belongs in the same counting bucket. Otherwise a
    distributed attacker with `' victim'`, `'victim '`, `'\tvictim'` … sets up any number of
    fresh buckets, and the account threshold across all addresses binds nothing. `lower()`
    folds more coarsely than NOCASE (also outside ASCII) — two names that differ only in that
    then share a bucket. That is stricter, never looser.

    Until the integration of T-13 this was only strip + lower. Since R4-06, however, `norm_email` also folds
    NFKC and IDNA, and `find_user` thereby found `ｖｉｃｔｉｍ@example.com`,
    `victim＠example.com` (full-width @) and every mixed form — each with its own bucket, 2^16 for
    this one address alone. Hence NFKC first, THEN look for the `@`: the full-width @ U+FF20
    only becomes one through folding. Counting deliberately happens under the folded INPUT,
    not under the account it hits: this way the lockout behaves the same for existing and
    invented identifiers and does not reveal which address belongs to which username
    (username and address of an account are therefore two buckets; `lift_lockout`
    clears both). Namesakes from existing data (`Émile`/`émile`) share a bucket; none can be
    created anew (`TinySesam.identifier_taken` asks
    `Store.account_by_bucket`), and `delete_attempts_for` leaves a shared bucket in place."""
    k = unicodedata.normalize("NFKC", str(identifier or "")).strip().lower()
    if "@" in k:
        return norm_email(k) or ""
    return k


def _identifier_sql(value) -> Optional[str]:
    """`norm_identifier` for SQLite (`tinysesam_kennung`): NULL stays NULL, and an error becomes NULL
    instead of an exception in the middle of the query."""
    if value is None:
        return None
    try:
        return norm_identifier(value)
    except Exception:
        return None


def valid_email(email) -> bool:
    """Deliberately lenient: exactly one @, something on the left and right, a dot on the right, no spaces.
    Whether the address exists is answered only by the confirmation link (`signup_verify_email`).

    Also rejected is anything built to be confusable (R4-06): invisible characters
    (control and format characters such as zero-width joiner) and a part that mixes scripts —
    `аdmin@example.com` with a Cyrillic `а` looks like the admin mailbox in the panel. An
    address entirely in one script (`müller@…`, `иван@…`) stays allowed, as do the mixtures of one
    language from `_FONT_GROUPS` (`山田たろう@…`)."""
    e = (email or "").strip()
    if not e or " " in e or e.count("@") != 1:
        return False
    if any(unicodedata.category(z) in ("Cc", "Cf") for z in e):
        return False
    local, _, domain = e.partition("@")
    if not (bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")):
        return False
    return all(_a_font(part) for part in [local, *domain.split(".")])


class _Clock:
    """The time source for everything in the database that carries a deadline.

    Sessions, one-time tokens, step-up freshness, lockout windows and flow state compare a
    stored timestamp with "now". With the bare wall clock (`time.time()`), a backwards jump
    revived all of it: an NTP correction, a Raspberry Pi that boots with an old date
    without a backup battery, a VM snapshot — an expired session was valid again, an
    expired magic link could be redeemed, an old step-up was "fresh" again (B6-9).

    That is why this clock never runs backwards: it follows the wall clock forwards, but backwards only
    with the elapsed **monotonic** time (`time.monotonic()` knows no jumps). After a
    jump back by an hour it therefore keeps counting normally instead of standing still for an hour
    — deadlines keep expiring. Across a restart the database itself carries the state:
    `Store()` raises the clock to the most recent timestamp it finds (`at_least()`) —
    including the state that `Store` writes at most once a minute (`uhr_stand`, on every
    write access and on every write probe of the health check). What expired in the last minute before
    a restart, or during a time in which nothing was written at all, can therefore
    remain valid for up to that interval longer — but not for its full remaining lifetime.

    The price: if the wall clock once jumped wrongly FORWARDS, the clock stays there until the wall clock
    catches up — deadlines are then internally consistent, just dated in the future. That is the
    safe direction, and it is logged as a warning.

    `wall`/`mono` are interchangeable so that a test can set up a jump without bending the clock of
    the whole process. Without them, `time.time`/`time.monotonic` are looked up on EVERY
    call rather than bound at import: an embedding app that patches `time.time` in its tests
    (`mock.patch`, `monkeypatch`, freezegun) thereby sets this clock too.
    It cannot be turned back this way — that is exactly the protection above.

    freezegun additionally replaces `time.monotonic`, namely with the frozen time on the
    epoch scale instead of the uptime. Carried forward, that would be a jump of decades
    (and one back when leaving `freeze_time`). A monotonic step that goes backwards
    or is larger than `MONO_STEP_MAX_SEC` therefore does not count as elapsed time:
    under freezegun the clock follows the frozen wall clock forwards (including `tick()`/`move_to()`);
    after leaving, it continues from the advanced state with the real
    monotonic time — as after `mock.patch`. The lead therefore remains: for the lifetime
    of the process (real time does not catch up, both run at the same speed) and via
    `uhr_stand` in this database for every later opening, as long as the pause in between is shorter
    than the lead. That is the safe direction; a test that sets the clock far ahead
    therefore uses its own throwaway database. The price of the plausibility limit is paid only by
    a backwards jump of the wall clock that falls into a pause of more than a year without any call:
    then the wall clock that jumped back applies, but never less than the most recently issued
    state. The same rule applies to the monotonic stamps of the `Store` (`_fresh`): a negative
    distance is expired, not fresh.
    """

    #: Lag of the wall clock from which a warning is written (seconds). Below that
    #: it is normal NTP jitter.
    WARN_FROM_SEC = 5

    #: Largest step of monotonic time between two calls that still counts as elapsed time
    #: (seconds). A real step is the pause between two requests; freezegun instead delivers
    #: the frozen time on the epoch scale (≈1.8e9 s) — a jump of decades.
    #: One year separates the two safely without giving up the protection after a long pause.
    MONO_STEP_MAX_SEC = 365 * 86400

    def __init__(self, wall=None, mono=None):
        # Look up on EVERY call, do not bind at construction: whoever patches `time.time`
        # (`mock.patch`, `monkeypatch`, freezegun) sets this clock too (see docstring).
        def _wall():
            return time.time()

        def _mono():
            return time.monotonic()
        self.wall = wall or _wall
        self.mono = mono or _mono
        self._lock = threading.Lock()
        self._state = 0.0          # last issued time (wall-clock scale)
        self._mono = None          # monotonic time at that issue
        self._reported = False     # lag already reported? (one line per jump, not per request)

    def now(self) -> int:
        with self._lock:
            wall, mono = float(self.wall()), float(self.mono())
            step = mono - self._mono if self._mono is not None else 0.0
            if not 0.0 <= step <= self.MONO_STEP_MAX_SEC:
                # No real monotonic clock (backwards, or a jump of decades: freezegun
                # replaces `time.monotonic` with the epoch time). Do not advance — otherwise
                # the clock jumped ahead by ≈57 years and `uhr_stand` pinned every later opening of the
                # database there. The wall clock forwards still applies, backwards the clock stands —
                # even if the monotonic source itself jumps back (leaving freeze_time).
                step = 0.0
            self._state, self._mono = max(wall, self._state + step), mono
            self._check_backlog(wall)
            return int(self._state)

    def at_least(self, ts) -> None:
        """Raise the clock to at least `ts` (most recent timestamp of the database when opening)."""
        if not ts:
            return
        with self._lock:
            if float(ts) > self._state:
                self._state, self._mono = float(ts), float(self.mono())
            self._check_backlog(float(self.wall()))

    def _check_backlog(self, wall: float) -> None:
        backlog = self._state - wall
        if backlog > self.WARN_FROM_SEC and not self._reported:
            self._reported = True
            logging.getLogger("tinysesam").warning(
                "The system clock is %d s behind the last time used (backward jump "
                "or wrong date after startup). TinySesam keeps counting monotonically so that "
                "expired sessions and one-time tokens do not become valid again (after a "
                "restart from the last saved state, at most one minute old) — "
                "check the time (NTP).", int(backlog))
        elif backlog <= self.WARN_FROM_SEC:
            self._reported = False


#: One clock per process: several `Store` instances in the same process must not
#: contradict each other, and a backwards jump hits the whole process, not one database.
_CLOCK = _Clock()


def now() -> int:
    """Current time (Unix seconds) that never runs backwards — see `_Clock`."""
    return _CLOCK.now()


#: Longest age after which `gc` deletes old login attempts (seconds): ten years like
#: `audit_retention_days`. The limit is not a recommendation for retention — the lockout sees
#: only its window anyway —, but keeps the number within the range SQLite can compute.
ATTEMPT_DEADLINE_MAX_SEC = 3660 * 86400


def attempt_deadline(seconds) -> int:
    """Check `attempts_older_than_sec` of `gc` — BEFORE anything is deleted.

    Without a limit, ±10**20 aborted with `OverflowError` after sessions, flows, tokens and unlocks
    were already gone; a negative value deleted every failed attempt, including those in the running
    lockout window, and thereby lifted every account lockout. 0 stays allowed: the documented way
    to clear all failed attempts. `True` is not an age (it would mean one second). `ValueError` if
    the value does not fit."""
    try:
        if isinstance(seconds, bool):
            raise ValueError
        number = int(seconds)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"attempts_older_than_sec={seconds!r} is not a whole number of seconds.") from None
    if not 0 <= number <= ATTEMPT_DEADLINE_MAX_SEC:
        raise ValueError(f"attempts_older_than_sec={number} is outside 0…{ATTEMPT_DEADLINE_MAX_SEC} "
                         "(seconds). 0 clears all failed attempts.")
    return number


def _now() -> int:
    return _CLOCK.now()


def replacement_name(user_id) -> str:
    """Who represents a deleted account in the audit log (H-13): `deleted#<id>` (up to 0.24.x `gelöscht#<id>`).

    One place for the format — every deletion path writes its closing line under it, even
    one that no longer finds the account (otherwise the clear name would appear there again)."""
    return f"{_vocabulary.REPLACEMENT_PREFIX}{int(user_id)}"


#: Keys in the payload of an address-change link up to 0.21.x and their English replacement (schema 12).
_PAYLOAD_KEY_NAME_OLD = {"email_change": {"alt": "old"}}


def read_payload(purpose, text) -> Optional[dict]:
    """The payload of a one-time token as a dict — with English keys (schema 12).

    An address-change link carried `{"alt": <previous address>}` up to 0.21.x, and
    `{"old": …}` since 0.22.0. An old key is mapped, even if the migration has not
    reached it — an older version that issued a link after a rollback writes
    it that way again. A key that is already English wins. `None` without a payload."""
    if not text:
        return None
    data = json.loads(text)
    for old, new in _PAYLOAD_KEY_NAME_OLD.get(purpose, {}).items():
        if isinstance(data, dict) and old in data:
            value = data.pop(old)
            data.setdefault(new, value)
    return data


class Store:
    #: Permissions for a NEWLY created database. It holds password hashes, TOTP secrets
    #: and email addresses; on a shared host anyone could read it up to 0.18.0 (0644,
    #: depending on umask). Nothing is changed on an existing file — whoever deliberately
    #: released a group should keep that —, but there is a warning.
    FILE_PERMISSIONS = 0o600

    def __init__(self, db_path: str):
        new = db_path not in (":memory:", "") and not os.path.exists(db_path)
        if new:
            # The file is created directly with narrow permissions. A chmod AFTER connecting would have
            # a window in which it stands open — and that is exactly when
            # SQLite writes the schema into it.
            try:
                os.close(os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.FILE_PERMISSIONS))
            except OSError:
                new = False                      # directory missing or similar — sqlite3 reports it right away
        self.db = sqlite3.connect(db_path, check_same_thread=False,
                                  timeout=self.BUSY_TIMEOUT_MS / 1000)
        self.db.row_factory = sqlite3.Row
        # Explicitly, not as the silent default of Python's `sqlite3` (5 s): the value decides
        # whether a second writer — another worker, `tinysesam` on the command line, a
        # WAL checkpoint, a running backup — waits or aborts a login with "database is locked"
        # as a 500 (B6-11). The PRAGMA repeats the value so that it can be read off
        # the connection itself, no matter how it was opened.
        self.db.execute(f"PRAGMA busy_timeout={int(self.BUSY_TIMEOUT_MS)}")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        # Deleted data is overwritten, not just freed: a replaced plaintext secret
        # (before encryption, H-14/H-15) or a deleted account would otherwise remain readable in free
        # pages of the file — and thereby in every backup — depending on the SQLite build.
        self.db.execute("PRAGMA secure_delete=ON")
        # The counting bucket as an SQL function — ONLY for queries of this connection (`anonymize_audit`),
        # never in schema, trigger or index: there it would break every writer without it (`_trigger_sql`).
        self.db.create_function("tinysesam_kennung", 1, _identifier_sql, deterministic=True)
        self._lock = threading.Lock()
        self._clock_secured: Optional[float] = None   # monotonic time of the last saved clock state
        self._written: Optional[float] = None     # monotonic time of the last successful commit
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self._migrate()
        self._check_file_permissions(db_path, new)
        _CLOCK.at_least(self._youngest_timestamp())

    #: How long a request waits for a locked database before giving up (ms).
    #: Twice Python's default: a checkpoint or a backup on slow
    #: storage (SD card, network drive) takes longer than 5 s, and an aborted login
    #: is more expensive than a slow one. No longer — the worker thread is stuck for that long.
    BUSY_TIMEOUT_MS = 10_000

    def _youngest_timestamp(self) -> int:
        """The most recent event timestamp of the database — the clock state across a restart.

        Only points in time at which something HAPPENED (created, logged), no deadlines: an
        `expires_at` is in the future by design and would set the clock ahead."""
        queries = ("SELECT MAX(created_at) AS t FROM session",
                    "SELECT MAX(created_at) AS t FROM magic_token",
                    "SELECT ts AS t FROM audit ORDER BY id DESC LIMIT 1",
                    "SELECT ts AS t FROM login_attempt ORDER BY id DESC LIMIT 1",
                    f"SELECT CAST(value AS INTEGER) AS t FROM setting WHERE key='{self.CLOCK_STATE}'")
        values = []
        for sql in queries:
            try:
                r = self._one(sql)
            except sqlite3.Error:
                continue
            if r and r["t"]:
                values.append(int(r["t"]))
        return max(values, default=0)

    def _check_file_permissions(self, db_path: str, new: bool):
        """WAL and SHM carry the same data as the database — they get the same permissions.

        The main file itself is only assessed on an existing installation, not
        rewritten: a deliberate group release is a decision of the operator, not a
        gap. It still does not stay silent."""
        if db_path in (":memory:", ""):
            return
        try:
            mode = stat.S_IMODE(os.stat(db_path).st_mode)
        except OSError:
            return
        for attachment in ("-wal", "-shm"):
            path = db_path + attachment
            try:
                if os.path.exists(path) and stat.S_IMODE(os.stat(path).st_mode) != mode:
                    os.chmod(path, mode)
            except OSError:
                pass                              # file system without permissions (Windows, some mounts)
        if not new and mode & 0o077:
            logging.getLogger("tinysesam").warning(
                "The database %s is readable by other accounts (%o). It contains password hashes "
                "and TOTP secrets. Tighten it: chmod 600 %s", db_path, mode, db_path)

    #: State of the schema. Raised by one with every change to SCHEMA/_migrate().
    #:
    #: 1 — up to 0.17.x (no stamp; added on first opening)
    #: 2 — 0.18.0: `session.token` → `session.token_hash` (sha256 instead of plaintext)
    #: 3 — 0.18.0: `totp_cred.last_step` (a TOTP code is valid exactly once)
    #: 4 — 0.18.0: `resource_unlock.token` carries the sha256 instead of the plaintext
    #: 5 — `users.email_verified`: the proof for the address, separate from the address itself
    #: 6 — `oidc_grant`: approval per application (T-14)
    #: 7 — `api_key.kind`: automation and human keys (R6-5)
    #: 8 — `users.first_login_at`, `users.mfa_enroll_until` (R3-1) — state of 0.19.0
    #: 9 — `federated_identity`: stable directory identifiers for LDAP/SAML (F-11)
    #: 10 — `users.topf_name`/`topf_mail` with index and triggers, indexes for the search by name
    #:      and address (NOCASE); existing data: lockouts from the panel to the operator mark
    #:      (`disabled=2`), addresses of open sign-ups without proof (`_migrate`)
    #: 11 — `fehlserie`: consecutive failed attempts per identifier (B2-6); `users.is_admin=2` means
    #:      "granted by the identity provider" (H-5) — the column itself stays as it is;
    #:      `users.is_owner` (owner); `session.zuletzt` (inactivity timeout, F-05);
    #:      `session.andere_beenden` (limit d); `oidc_sitzung` (refresh token, 4a);
    #:      `users.idp_bestaetigt_at` (API keys follow the IdP, finding 8); triggers
    #:      `trg_users_kennung_insert`/`_update`: name and address are ONE identifier space, enforced
    #:      by the database (G12c; created on every start, not at the stamp);
    #:      `users.name_versuch_ab`/`mail_versuch_ab`/`name_audit_ab`/`mail_audit_ab`: from when an
    #:      identifier belongs to the account (G2, NULL in existing data), plus the recompute triggers that raise them on
    #:      a foreign writer; `federated_identity.name_topf`: the name in the directory
    #:      (G5); `login_attempt.offen`: a pre-booking whose outcome is still open (G9). All
    #:      of it additive and idempotent on every start — state of 0.21.0.
    #: 12 — 0.22.0: stored values of the public interface in English (PO decision
    #:      2026-09-27): `api_key.kind` `automaton`/`human` → `automation`/`human` (on EVERY start —
    #:      for keys that an older version issued after a rollback), in the payload of
    #:      open address-change links `old` → `old` (on the jump to 12; `_values_english`).
    #:      An old value is still read correctly (`KEY_KINDS_OLD`, `read_payload`). No
    #:      column changes. The stamp rises because an older version reads the new values DIFFERENTLY:
    #:      0.21.x takes a `human` key for an automation key (valid without a session). It
    #:      still opens the file, but reports the newer schema version at start — way back
    #:      with SQL in docs/OPERATIONS.md.
    #: 13 — `gate_abgemeldet` (signed out of one application only, T-22) and `oidc_id_token` (the
    #:      ID token as a sign-out hint for the provider, encrypted). Additive; an older version
    #:      leaves both tables in place, but does not rotate them along when rotating a session — the
    #:      rows then drop away with the old session (sign-out "here only" forgotten, provider
    #:      logout without hint), nothing more.
    #: 14 — `gate_link`: connection of an app host to the central session (code exchange, T-26).
    #:      Additive; an older version leaves the table in place and does not rotate it along —
    #:      the app host then loses its connection and fetches a new one via the code exchange.
    #: 15 — the stored and logged key vocabulary in English (PO decision 2026-10-29,
    #:      `Store._vocabulary_english`, `tinysesam/_vocabulary.py`): `audit.event` (`oidc_widerruf` →
    #:      `oidc_revoked`, `ldap_kennung_gebunden` → `ldap_identifier_bound` …), the keys and tokens in
    #:      `audit.detail` (`grund=kein_konto` → `reason=no_account` …), the replacement name in
    #:      `audit.username` (`gelöscht#<id>` → `deleted#<id>`), `fehlserie.art`/`login_attempt.method`
    #:      (`pin_folge` → `pin_chain`), and the message of the identifier triggers (`tinysesam: kennung
    #:      vergeben` → `tinysesam: identifier taken`; replaced by `_set_trigger` on every start). No
    #:      column changes. The stamp rises because an older version does not know the new values: it
    #:      still opens the file and reports the newer schema version at start, shows the new event names
    #:      as unknown (display only) — and does not recognise an address-change conflict
    #:      (`on_confirmation=1`, `own_events`) or the counted lockout notice (`lockout_notice`) in a new row.
    #:      Way back with SQL in docs/OPERATIONS.md. Read paths take the old and the new spelling.
    SCHEMA_VERSION = 15

    #: The stored values up to 0.21.x and their English replacement (schema 12). The migration
    #: rewrites them, and whoever reads still maps an old value: an older version that ran
    #: on the same file after a rollback has left old values behind again.
    KEY_KINDS_OLD = {"automat": "automation", "mensch": "human"}

    #: From this schema state on, `topf_name`/`topf_mail` are computed with today's `norm_identifier`.
    #: Whoever changes the folding in `norm_identifier` raises `SCHEMA_VERSION` and sets this
    #: value to match — otherwise the buckets of the existing data would stand in the old folding in the index, and
    #: `account_by_bucket` would no longer find namesakes.
    BUCKET_SCHEMA = 10

    def _migrate(self):
        """Additive migrations for existing DBs: add missing columns (idempotent).

        At the end `PRAGMA user_version` is set to `SCHEMA_VERSION`. Up to 0.18.0 this stamp did
        not exist: which state a file had could only be guessed from its column names —
        and a file from a NEWER version was opened silently by an older TinySesam version,
        with tables it does not know. The stamp turns that into an
        announcement instead of puzzling behaviour."""
        adds = {
            "session": [("mfa_at", "INTEGER"), ("remember", "INTEGER NOT NULL DEFAULT 1"),
                        ("factors_done", "TEXT NOT NULL DEFAULT '[]'"),
                        # NULL for existing sessions: counts as `created_at` (F-05).
                        ("zuletzt", "INTEGER"),
                        ("andere_beenden", "INTEGER NOT NULL DEFAULT 0"),
                        ("bleiben_gewaehlt", "INTEGER NOT NULL DEFAULT 0"),
                        # NULL = the current session; set only for a superseded token in the
                        # grace period after rotation (A-6).
                        ("nachfolger", "TEXT")],
            "totp_cred": [("last_step", "INTEGER")],
            # The client_id to which a refresh token went: if the operator recreates the client at the
            # provider, it rejects every old token — that is no "no" to the account.
            "oidc_sitzung": [("client_id", "TEXT"), ("erfolg_at", "INTEGER")],
            # Existing keys count as automation keys: the narrower interpretation. A key
            # that could previously serve admin routes loses that — exactly that is
            # the point of R6-5, and a rejected call leaves a row.
            "api_key": [("kind", "TEXT NOT NULL DEFAULT 'automation'")],
            # `DEFAULT 1` fills every existing row: addresses that were created before this column
            # keep exactly their previous effect. An address only gets 0 if
            # a caller explicitly enters it without proof (OIDC without `email_verified`).
            "users": [("email_verified", "INTEGER NOT NULL DEFAULT 1"),
                      # Both NULL for existing accounts: whoever has no TOTP yet should be able to set it up at
                      # the next login — the latch applies from then on (R3-1).
                      ("first_login_at", "INTEGER"), ("mfa_enroll_until", "INTEGER"),
                      # NULL = not yet computed; backfilled further below for existing data.
                      # Without NOT NULL: an older version (rollback) keeps creating accounts.
                      ("topf_name", "TEXT"), ("topf_mail", "TEXT"),
                      # 0 for existing data; who becomes owner is decided by `Store._catch_up_owner`.
                      ("is_owner", "INTEGER NOT NULL DEFAULT 0"),
                      # Existing data: set to "now" below for OIDC accounts (finding 8).
                      ("idp_bestaetigt_at", "INTEGER"),
                      # NULL for existing data: the limit is then the creation, as until 2026-09-26 (G2).
                      # Do not backfill "now" — the account page would otherwise show nothing from before
                      # the update, and own failed attempts would remain until the end of the window.
                      ("name_versuch_ab", "INTEGER"), ("mail_versuch_ab", "INTEGER"),
                      ("name_audit_ab", "INTEGER"), ("mail_audit_ab", "INTEGER"),
                      # 0 for existing data; whoever registered or renamed themselves backfills
                      # it once below (`NAME_ITSELF_BACKFILLED`, G2-N).
                      ("name_selbst_gewaehlt", "INTEGER NOT NULL DEFAULT 0"),
                      # NULL for existing data; where the origin is proven, backfilled once below
                      # (`NAME_SOURCE_BACKFILLED`, attack round 2026-09-26).
                      ("name_quelle", "TEXT")],
            # NULL: never logged in under a different name yet (G5); arises at the next login.
            "federated_identity": [("name_topf", "TEXT")],
            # 0 for existing data: every present row is a completed attempt (G9).
            "login_attempt": [("offen", "INTEGER NOT NULL DEFAULT 0")],
        }
        # `_writing`, not only `_lock`: the final commit below takes DELETE and stamp with it.
        # If something fails before that, without a rollback a transaction would stay open on the
        # connection (the AST guard in tests/test_hardening2.py demands this for every commit).
        with self._writing():
            # `fehlserie` initially came with schema 11 without a column `art` (a never published
            # intermediate state). Such a table is recreated — otherwise every login would end in
            # a 500. The series in it are lost; that is the lesser harm.
            _fs = {r["name"] for r in self.db.execute("PRAGMA table_info(fehlserie)")}
            if _fs and "art" not in _fs:
                ddl = re.search(r"CREATE TABLE IF NOT EXISTS fehlserie \(.*?\n\);", SCHEMA, re.S)
                if ddl is None:     # it is in SCHEMA; if it is missing there, that is an error here
                    raise RuntimeError("SCHEMA contains no table fehlserie")
                self.db.execute("DROP TABLE fehlserie")
                self.db.execute(ddl.group(0))
            for table, cols in adds.items():
                have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
                for name, decl in cols:
                    if name not in have:
                        self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

            # Session tokens were stored in plaintext in the file up to 0.18.0. The hash can be computed from
            # the plaintext — existing logins thus survive the switch, the
            # cookies stay valid.
            #
            # **In ONE transaction, with BEGIN IMMEDIATE.** The first version ran the
            # `ALTER TABLE` alone: Python's sqlite3 opens no transaction before DDL, so the
            # rename was followed by an immediate commit, and the rehashing ran separately. An
            # abort in between (SIGKILL, OOM, container restart in the middle of the upgrade) left
            # a column `token_hash` **with plaintext in it** — permanently, because the condition
            # below never becomes true again, and the stamp then says "migrated". Exactly what
            # the switch is meant to remove would have remained forever.
            #
            # `BEGIN IMMEDIATE` takes the write lock immediately. That also solves the second
            # case: with several processes (`uvicorn --workers N`), worker A read the column list,
            # B finished migrating, A ran its ALTER — and died with `no such column: "token"`.
            # Now A waits for the lock and afterwards sees the finished state.
            self.db.execute("BEGIN IMMEDIATE")
            try:
                columns = {r["name"] for r in self.db.execute("PRAGMA table_info(session)")}
                if "token" in columns and "token_hash" not in columns:
                    self.db.execute("ALTER TABLE session RENAME COLUMN token TO token_hash")
                lines = self.db.execute(
                    "SELECT token_hash FROM session WHERE length(token_hash) <> 64"
                    " OR token_hash GLOB '*[^0-9a-f]*'").fetchall()
                self.db.executemany(
                    "UPDATE session SET token_hash=? WHERE token_hash=?",
                    [(hashlib.sha256(z["token_hash"].encode()).hexdigest(), z["token_hash"])
                     for z in lines if z["token_hash"]])
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            if lines:
                logging.getLogger("tinysesam").info(
                    "Session table migrated: %d tokens hashed, sign-ins stay valid.",
                    len(lines))

            # Unlocks from the time before the switch cannot be converted: the hash
            # is made from the plaintext, nothing from the hash. They are discarded — only open
            # resource approvals are affected, and those are fetched back with the secret in
            # seconds. A half-hashed table would be worse.
            #
            # This is detected by the VALUE, not by the schema stamp. The first version asked
            # `0 < user_version < 4` — and thereby missed exactly the case it was
            # written for: `user_version` itself only arrived with 0.18.0, an existing file from
            # 0.17.0 carries 0 there, and `0 < 0` is false. The plaintext entries would therefore have
            # remained; they would never have matched again (the hash is searched since then)
            # and unnoticed would have occupied space until their expiry. The test for this is in
            # tests/test_legacy_data.py.
            # Two conditions, both necessary: the stamp says "this file has not been through yet"
            # (and keeps the scan out of every further start), the VALUE says which row
            # really is plaintext. The stamp alone was not enough — see above.
            present_beforehand = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if present_beforehand < self.SCHEMA_VERSION:
                away = self.db.execute(
                    "DELETE FROM resource_unlock WHERE length(token) <> 64"
                    " OR token GLOB '*[^0-9a-f]*'").rowcount
                if away:
                    logging.getLogger("tinysesam").info(
                        "%d resource approvals discarded (tokens are now stored hashed).", away)

            # Schema 10. The steps run in the same transaction as the stamp below: if
            # the start aborts in between, the stamp is missing too, and the next start runs them again
            # (every step is repeatable). The existing-data steps run on EVERY start, not only
            # on the jump over the stamp — for what an older writer may have left behind
            # since then (`_catch_up_inventory`).
            without_bucket = self.db.execute(
                "SELECT * FROM users" + ("" if present_beforehand < self.BUCKET_SCHEMA else
                                         " WHERE topf_name IS NULL OR topf_mail IS NULL")).fetchall()
            if self.db.execute("SELECT 1 FROM setting WHERE key='idp_bestand_gesetzt'").fetchone() is None:
                # The deadline for the API keys of an OIDC account (finding 8) starts for existing data
                # with the update — otherwise all keys would be dormant right after the update until everyone has
                # signed in once via the provider. Exactly once: if it ran on every start,
                # every restart would give an unconfirmed account a new deadline.
                #
                # Tied to the marker, not to "column created in this run": the ALTER is immediately
                # permanent, this UPDATE only with the final commit. An abort in between
                # (OOM, restart in the middle of the update) left the column without a value, and no
                # start backfilled it (attack on the third round). Marker and value go in the
                # same commit. Here and not directly after the ALTER: an UPDATE opens a
                # transaction in Python's sqlite3, and the `BEGIN IMMEDIATE` above would fail.
                self.db.execute("UPDATE users SET idp_bestaetigt_at=? WHERE idp_bestaetigt_at IS NULL "
                                "AND id IN (SELECT user_id FROM oidc_identity)", (_now(),))
                self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES ('idp_bestand_gesetzt', ?)",
                                (str(_now()),))
            if self.db.execute("SELECT 1 FROM setting WHERE key=?",
                               (self.NAME_ITSELF_BACKFILLED,)).fetchone() is None:
                self._backfill_name_itself()
            if self.db.execute("SELECT 1 FROM setting WHERE key=?",
                               (self.NAME_SOURCE_BACKFILLED,)).fetchone() is None:
                self._backfill_name_source()
            self._catch_up_owner()
            # Schema 12: the stored values in English (see `_values_english`). Read-only and
            # values of an older version in it: that must not prevent a start that worked
            # before — the old values are read correctly anyway. An upgrade, on the other hand, writes,
            # like every migration.
            try:
                rewritten = self._values_english(links=present_beforehand < 12)
            except sqlite3.OperationalError as e:
                if present_beforehand < self.SCHEMA_VERSION:
                    raise
                rewritten = 0
                logging.getLogger("tinysesam").warning(
                    "Values of an older version not rewritten to the English names (%s): "
                    "the database is not writable. They are still read correctly.", e)
            if rewritten:
                logging.getLogger("tinysesam").info(
                    "%d stored values rewritten to the English names (schema 12: "
                    "API key kinds, address-change links).", rewritten)
            # Schema 15: the audit log and the series kinds in English (see `_vocabulary_english`). Only on
            # the jump over the stamp: the audit log can be large, and a row that an older version writes
            # afterwards is mapped by the read paths (`_vocabulary`). An upgrade writes, like every
            # migration — a read-only file with an old stamp already failed at the steps above.
            if present_beforehand < 15:
                rewritten = self._vocabulary_english()
                if rewritten:
                    logging.getLogger("tinysesam").info(
                        "%d stored values rewritten to the English vocabulary (schema 15: audit events, "
                        "keys and tokens in the audit details, replacement names, series kinds).",
                        rewritten)
            if present_beforehand < 10:
                self._catch_up_inventory(True, without_bucket)
            else:
                try:
                    self._catch_up_inventory(False, without_bucket)
                except sqlite3.OperationalError as e:
                    # As with the bucket below: this must not prevent a start that worked before.
                    # With this stamp the transaction contains only this step.
                    self.db.rollback()
                    logging.getLogger("tinysesam").warning(
                        "Existing-data steps not applied (%s): lockouts from the panel of an older "
                        "version only carry the operator marker after a start with "
                        "write access.", e)
            try:
                self._write_pots(without_bucket)
            except sqlite3.OperationalError:
                # Read-only (volume mounted read-only) and rows of a foreign
                # writer without a bucket: this must not prevent the start, which worked before —
                # `account_by_bucket` then checks such rows itself (`_backfill_pots`). An
                # upgrade, on the other hand, needs the buckets, like every other migration its columns.
                if present_beforehand < self.BUCKET_SCHEMA:
                    raise
                logging.getLogger("tinysesam").warning(
                    "Counting buckets of %d account(s) not filled in: the database is not "
                    "writable. The bucket check still sees them, only more slowly.", len(without_bucket))

            # A file from the future: this version does not fully know its tables
            # and would leave gaps when writing. That is no reason to crash —
            # but a very good one to say so loudly.
            present = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if present > self.SCHEMA_VERSION:
                logging.getLogger("tinysesam").warning(
                    "The database carries schema version %d, this TinySesam version only knows %d. "
                    "It comes from a newer version — writing with this one can leave "
                    "data incomplete. Install the matching version or restore the file "
                    "from a backup.", present, self.SCHEMA_VERSION)
            elif present != self.SCHEMA_VERSION:
                self.db.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            # Email unique (login identifier) — partial, so that accounts without an email stay allowed.
            # Existing data with duplicates: the index cannot be created → say so loudly, do not crash.
            try:
                self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email "
                                "ON users(lower(email)) WHERE email IS NOT NULL AND email <> ''")
            except sqlite3.IntegrityError:
                logging.getLogger("tinysesam").warning(
                    "users.email contains duplicates — uniqueness index not created. "
                    "Clean up duplicate addresses, otherwise login by e-mail is ambiguous.")
            # Schema 10: every lookup of an identifier goes through an index, none through the whole
            # table. With a scan, the runtime of a registration depended on whether (and how
            # early) the address is found — with many accounts an oracle for taken addresses
            # (R4-03). `get_user_by_name`/`get_user_by_email` compare with NOCASE; the
            # UNIQUE index on `username` (BINARY) and `ux_users_email` (`lower(email)`) do not fit
            # that, so SQLite read every row.
            # The name in the directory (G5) counts in the identifier space (audit round 2026-09-27) — the
            # identifier triggers ask for it on every creation and every rename.
            for sql in ("CREATE INDEX IF NOT EXISTS ix_users_topf_name ON users(topf_name)",
                        "CREATE INDEX IF NOT EXISTS ix_users_topf_mail ON users(topf_mail)",
                        "CREATE INDEX IF NOT EXISTS ix_fed_name_topf ON federated_identity(name_topf)",
                        "CREATE INDEX IF NOT EXISTS ix_users_name_nocase ON users(username COLLATE NOCASE)",
                        "CREATE INDEX IF NOT EXISTS ix_users_email_nocase ON users(email COLLATE NOCASE)"):
                self.db.execute(sql)
            # The triggers over the buckets (recompute and identifier space, see `_trigger_sql`). A
            # file on which they cannot be created (read-only) must not prevent the start:
            # no new account is created there anyway, and the pre-check
            # (`identifier_taken`) remains. It is still reported.
            try:
                self._set_trigger()
            except sqlite3.OperationalError as e:
                logging.getLogger("tinysesam").warning(
                    "Triggers over username and address not created (%s): the database "
                    "only enforces the shared identifier space after a start with "
                    "write access.", e)
            self.db.commit()

    #: Message of the identifier triggers (`sqlite3.IntegrityError`): name or address falls into the
    #: counting bucket of ANOTHER account. Callers recognise the case by `IntegrityError`, not by the text.
    #: Up to 0.24.x the text was `tinysesam: kennung grant`; `_set_trigger` replaces the trigger
    #: because its definition differs (schema 15).
    IDENTIFIER_GRANT = "tinysesam: identifier taken"

    #: The watermarks of an identifier (G2) as an SQL expression: the highest id that exists NOW.
    #: Everything created afterwards has a larger one (`AUTOINCREMENT` never issues an id twice).
    #: Only built-in functions — same reason as for the triggers.
    WL_ATTEMPT = "(SELECT COALESCE(MAX(id), 0) FROM login_attempt)"
    WL_AUDIT = "(SELECT COALESCE(MAX(id), 0) FROM audit)"

    @classmethod
    def _trigger_sql(cls) -> list:
        """The triggers on `users` as `(name, CREATE statement)`. Only built-in SQL functions:
        the sqlite3 tool and older versions must still be able to write (a
        Python function in the trigger or in the index expression would break every writer without it with
        "no such function").

        **Recompute** (`trg_users_topf_name`/`_mail`, schema 10): another writer changes
        name or address without carrying the bucket along (an older version after a rollback,
        the manual rename that the collision guard recommends at start): then the bucket is
        stale — and NULL means "recompute". Only if the value REALLY changes: whoever sets
        the same address again keeps their bucket (until 2026-09-26 it stood at NULL afterwards until the
        next backfill, and the identifier triggers did not see the account for that long).
        The same trigger raises the watermarks of the identifier (`name_versuch_ab` … , G2) to the
        current state: a foreign writer has assigned a new identifier, and what stood before under
        it did not belong to this account. That is the stricter direction — also for a
        rename that only changes the spelling. The own writers never fire it
        (`_set_identifier`); otherwise even `B1` → `b1` would shift the limit.

        **Change with bucket** (`trg_users_wechsel_name`/`_mail`, audit round 2026-09-27): a foreign
        writer that carries the bucket ITSELF (`store.set_email` from 0.20.1 sets address and
        `topf_mail` in one statement) does not fire the recompute trigger — the bucket does
        change. Until then the watermark stayed at the state of the OLD identifier, and the first
        full sign-in cleared the failed attempts that a stranger had made under the new one before the change,
        also from the throttling of his IP. This trigger raises them when, in the same
        statement, the value AND the bucket change (to a bucket, not to NULL). The backfill
        (`_write_pots`: only the bucket) does not fire it, nor does `B1` → `b1` in `_set_identifier`
        (there the bucket is at NULL in between); on a real change in
        `_set_identifier` it sets the same state that the statement has already written.

        **Identifier space** (`trg_users_kennung_insert`/`_update`, G12c): username and address
        are ONE space (`find_user` searches both), and the counting bucket folds more coarsely than NOCASE
        (`Alice`/`alice`, `Émile`/`émile`, full-width, Unicode and A-label domain). Until then the database
        knew only `UNIQUE(username)` (BINARY) and `ux_users_email` — check
        (`identifier_taken`) and write were separate, and two simultaneous registrations
        of the same identifier (one as name, one as address) both got through. Now the
        database rejects a NEWLY assigned bucket that is already the name or address of another account
        — in the same statement as the write, under SQLite's single writer.
        Why each part:

        * `UPDATE OF username, email`, not `OF topf_*`: the backfill (`_write_pots`)
          sets only buckets and therefore does not check. Existing data with a collision does not break the start.
        * `NEW IS NOT OLD`: only a newly assigned bucket is checked. Setting one's own
          address again and a raw UPDATE (bucket stays, the trigger above then sets it
          to NULL) go through — a collision in existing data is reported, not prevented.
        * `id IS NOT NEW.id` (UPDATE only): the same row may carry name = address
          (email mode). On INSERT the row is not yet in the table.
        * Rows without a bucket (NULL: a foreign writer, not yet backfilled) count only from
          the backfill — which `identifier_taken` triggers before every creation.
        * **The name in the directory of ANOTHER account** (`federated_identity.name_topf`, G5)
          counts (audit round 2026-09-27). Under one identifier the login route checks two
          secrets — the local password of the account and the LDAP password of the entry. If
          a local account took on the directory name of another person (self-service,
          registration), each of its sign-ins cleared the counters under which the other's
          LDAP password was being guessed. On UPDATE only foreign bindings (`user_id IS NOT NEW.id`):
          whoever returns to their own directory name may do so.

        The lookup runs over `ix_users_topf_name`/`ix_users_topf_mail`/`ix_fed_name_topf`, no
        scan: the work does not depend on the number of accounts (step counting in
        tests/test_identifier_space.py and tests/test_audit_round2.py)."""
        def new(column, old, id_from):
            other = "id IS NOT NEW.id AND " if id_from else ""
            foreign = "user_id IS NOT NEW.id AND " if id_from else ""
            return (f"(NEW.{column} IS NOT {old} AND NEW.{column} <> '' AND (EXISTS (SELECT 1 FROM users "
                    f"WHERE {other}(topf_name = NEW.{column} OR topf_mail = NEW.{column})) "
                    f"OR EXISTS (SELECT 1 FROM federated_identity WHERE {foreign}name_topf = NEW.{column})))")
        reject = f"BEGIN SELECT RAISE(ABORT, '{cls.IDENTIFIER_GRANT}'); END"
        kinds = (("username", "topf_name", "name"), ("email", "topf_mail", "mail"))
        sql = [(f"trg_users_{bucket}",
                f"CREATE TRIGGER IF NOT EXISTS trg_users_{bucket} AFTER UPDATE OF {column} ON users "
                f"WHEN NEW.{bucket} IS OLD.{bucket} AND NEW.{column} IS NOT OLD.{column} "
                f"BEGIN UPDATE users SET {bucket} = NULL, {kind}_versuch_ab = {cls.WL_ATTEMPT}, "
                f"{kind}_audit_ab = {cls.WL_AUDIT} WHERE id = NEW.id; END")
               for column, bucket, kind in kinds]
        sql += [(f"trg_users_wechsel_{kind}",
                 f"CREATE TRIGGER IF NOT EXISTS trg_users_wechsel_{kind} AFTER UPDATE OF {bucket} ON users "
                 f"WHEN NEW.{bucket} IS NOT NULL AND NEW.{bucket} IS NOT OLD.{bucket} "
                 f"AND NEW.{column} IS NOT OLD.{column} "
                 f"BEGIN UPDATE users SET {kind}_versuch_ab = {cls.WL_ATTEMPT}, "
                 f"{kind}_audit_ab = {cls.WL_AUDIT} WHERE id = NEW.id; END")
                for column, bucket, kind in kinds]
        sql.append(("trg_users_kennung_insert",
                    "CREATE TRIGGER IF NOT EXISTS trg_users_kennung_insert BEFORE INSERT ON users "
                    f"WHEN {new('topf_name', 'NULL', False)} OR {new('topf_mail', 'NULL', False)} "
                    + reject))
        sql.append(("trg_users_kennung_update",
                    "CREATE TRIGGER IF NOT EXISTS trg_users_kennung_update BEFORE UPDATE OF username, email "
                    f"ON users WHEN {new('topf_name', 'OLD.topf_name', True)} "
                    f"OR {new('topf_mail', 'OLD.topf_mail', True)} " + reject))
        return sql

    def _set_trigger(self) -> None:
        """Create the triggers from `_trigger_sql` — or replace them if an older version created them
        differently (without commit, under `_lock`, part of `_migrate`).

        `CREATE TRIGGER IF NOT EXISTS` alone would leave a trigger from schema 10 forever
        as it was back then. The comparison is made with the text in `sqlite_master` (SQLite stores it
        without `IF NOT EXISTS`; whitespace does not count). If it matches, nothing is written — not even
        on a read-only file."""
        for name, sql in self._trigger_sql():
            should = " ".join(sql.replace(" IF NOT EXISTS", "", 1).split())
            stands = self.db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                                    (name,)).fetchone()
            if stands is not None and " ".join(str(stands[0] or "").split()) == should:
                continue
            if stands is not None:
                self.db.execute(f"DROP TRIGGER IF EXISTS {name}")
            self.db.execute(sql)

    #: Setting key: has `users.name_selbst_gewaehlt` been backfilled for existing data (G2-N)?
    NAME_ITSELF_BACKFILLED = "name_selbst_nachgetragen"

    def _backfill_name_itself(self) -> None:
        """Backfill `users.name_selbst_gewaehlt` once for existing data from the audit log (G2-N;
        without commit, under `_lock`, part of `_migrate`).

        The column came after 0.20.1; until then nothing recorded where a name came from. The
        audit log knows it for the two paths that count: `signup` (registration, also with
        invitation) and `username_changed` (rename) stand under the name the account
        carried afterwards. Only a row under TODAY's name and from the creation of the account on is counted —
        an older one belonged to another account with this name. The lookup runs over
        `idx_audit_name_ts` (name, time), not through the whole log.

        Limits, deliberately in the safe direction: an account renamed by the operator carried
        the same row until then (`username_changed`) and gets the marker too — the account
        then no longer binds via the name, and the operator opens it with `federation_unbind`. What
        the retention (`audit_retention_days`) has already deleted is not detected; 0.20.1 did not know
        renaming, there only the registration remains.

        Exactly once, via the marker `NAME_ITSELF_BACKFILLED` in the same commit: if it ran on every
        start, the row of a later rename by the operator would make the account a
        self-named one again."""
        self.db.execute(
            "UPDATE users SET name_selbst_gewaehlt = 1 WHERE name_selbst_gewaehlt = 0 AND is_service = 0 "
            "AND EXISTS (SELECT 1 FROM audit a WHERE lower(a.username) = lower(users.username) "
            "AND a.ts >= users.created_at AND a.event IN ('signup', 'username_changed'))")
        self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                        (self.NAME_ITSELF_BACKFILLED, str(_now())))

    def _values_english(self, links: bool = True) -> int:
        """Bring stored values of the public interface to their English names (schema
        12, PO decision 2026-09-27) — without commit, under `_lock`, part of `_migrate`.

        * `api_key.kind`: `automaton` → `automation`, `human` → `human` (`KEY_KINDS_OLD`) — the kind
          is seen by everyone who lists keys (`list_api_keys`, `api_key_kind`, `GET /auth/apikeys`,
          the panel). On EVERY start, not only on the jump over the stamp: an older version
          that ran on the file after a rollback has written old values again, and it
          does not lower the stamp. The table is small.
        * Payload of open address-change links (`magic_token`, `purpose='email_change'`): `old` →
          `old` (`read_payload`) — visible via `peek_magic`/`redeem_magic`. Only with
          `links=True` (on the jump to 12): the search goes through all one-time tokens, and they grow
          until the next `gc` — on every start that would cost a run through the table
          (measured in `tests/test_legacy_data.py`, "Aufwand"). A link that an older version
          issues afterwards is mapped by `read_payload` on reading; it expires soon anyway.

        Idempotent; it writes only where there is something to rewrite — a read-only file
        without old values starts as before. Returns: the number of changed rows.

        Not translated here: the audit log and the kinds of the series (`fehlserie.art`) — those are
        rewritten on the jump to schema 15 (`_vocabulary_english`) — and the column names (they stay)."""
        n = 0
        for old, new in self.KEY_KINDS_OLD.items():
            if self.db.execute("SELECT 1 FROM api_key WHERE kind=? LIMIT 1", (old,)).fetchone():
                n += self.db.execute("UPDATE api_key SET kind=? WHERE kind=?", (new, old)).rowcount
        for purpose, key_name in (_PAYLOAD_KEY_NAME_OLD.items() if links else ()):
            for old in key_name:
                for z in self.db.execute(
                        "SELECT token_hash, payload FROM magic_token WHERE purpose=? AND payload LIKE ?",
                        (purpose, f'%"{old}"%')).fetchall():
                    try:
                        new_text = json.dumps(read_payload(purpose, z["payload"]))
                    except ValueError:
                        continue          # not JSON: not ours, do not touch
                    if new_text != z["payload"]:
                        self.db.execute("UPDATE magic_token SET payload=? WHERE token_hash=?",
                                        (new_text, z["token_hash"]))
                        n += 1
        return n

    #: Rows per block when `_vocabulary_english` walks through `audit.detail`.
    _VOCABULARY_BLOCK = 5000

    def _vocabulary_english(self) -> int:
        """Bring the stored and logged key vocabulary to its English names (schema 15, PO decision
        2026-10-29) — without commit, under `_lock`, part of `_migrate`, on the jump over the stamp.

        What is rewritten, and only that (the mapping itself is in `tinysesam/_vocabulary.py`, pure
        functions that the tests use as well):

        * `audit.event`: the exact names (`oidc_widerruf` → `oidc_revoked`, …) and the families
          `<oidc|saml|ldap>_kennung_gebunden` → `<…>_identifier_bound` etc. (`audit_event_new`) —
          in ONE statement, one pass over the table.
        * `audit.detail`: the keys of the `key=value` pairs and the tokens behind `reason=`/`source=`/…
          (`audit_detail_new`): keys only where one stands as a key (start or after a space, directly
          before `=`), values only behind their key, never free text that happens to contain the word.
          Rows of free-text events (`ldap_unavailable`, `resource_unlock`, `user_create`) keep their keys.
          Block by block over `id`, each changed row written once.
        * `audit.username`: `gelöscht#<id>` → `deleted#<id>` (digits only; a name that merely begins with
          it stays), likewise inside the details (`actor=`, the head of `user_create`).
        * `fehlserie.art` and `login_attempt.method`: `pin_folge` → `pin_chain`. If both kinds exist for
          an identifier (the old one written by an older version after a rollback), the counts are
          ADDED up (stricter, never looser than dropping one) and the old row goes.

        The trigger message (`tinysesam: kennung grant` → `identifier taken`) is not touched here:
        `_set_trigger` replaces a trigger whose definition differs, on every start.

        Idempotent (a second run changes 0 rows) and it writes only where there is something to
        rewrite — a read-only file without old values starts as before. Returns the number of changed
        rows (event names count per row, details per row, series per row)."""
        V = _vocabulary
        n = 0
        # (1) event names: one statement for all of them.
        pairs = dict(V.AUDIT_EVENTS_OLD)
        for source in V.AUDIT_SOURCES:
            for old, new in V.AUDIT_FAMILIES_OLD.items():
                pairs[source + old] = source + new
        place = ",".join("?" * len(pairs))
        if self.db.execute(f"SELECT 1 FROM audit WHERE event IN ({place}) LIMIT 1", tuple(pairs)).fetchone():
            case = " ".join("WHEN ? THEN ?" for _ in pairs)
            args = [x for old, new in pairs.items() for x in (old, new)]
            n += self.db.execute(
                f"UPDATE audit SET event = CASE event {case} ELSE event END WHERE event IN ({place})",
                (*args, *pairs)).rowcount
        # (2) the replacement name of deleted accounts (digits only after the prefix).
        old_prefix, new_prefix = V.REPLACEMENT_PREFIX_OLD, V.REPLACEMENT_PREFIX
        length = len(old_prefix)
        where_replacement = ("substr(username, 1, ?) = ? AND length(username) > ? "
                        "AND substr(username, ?) NOT GLOB '*[^0-9]*'")
        values_replacement = (length, old_prefix, length, length + 1)
        if self.db.execute(f"SELECT 1 FROM audit WHERE {where_replacement} LIMIT 1", values_replacement).fetchone():
            n += self.db.execute(
                f"UPDATE audit SET username = ? || substr(username, ?) WHERE {where_replacement}",
                (new_prefix, length + 1, *values_replacement)).rowcount
        # (3) the detail text, block by block over the primary key. The event is read AFTER step 1, so
        # it is already the new name — `audit_detail_new` takes either.
        last = 0
        while True:
            lines = self.db.execute(
                "SELECT id, event, detail FROM audit WHERE id > ? AND detail IS NOT NULL AND detail <> '' "
                "ORDER BY id LIMIT ?", (last, self._VOCABULARY_BLOCK)).fetchall()
            if not lines:
                break
            for z in lines:
                new_detail = V.audit_detail_new(z["detail"], z["event"])
                if new_detail != z["detail"]:
                    self.db.execute("UPDATE audit SET detail=? WHERE id=?", (new_detail, z["id"]))
                    n += 1
            last = lines[-1]["id"]
        # (4) the kinds of the streak and the methods.
        for old, new in V.KINDS_OLD.items():
            for z in self.db.execute("SELECT topf, anzahl, seit, zuletzt FROM fehlserie WHERE art=?",
                                     (old,)).fetchall():
                if self.db.execute("SELECT 1 FROM fehlserie WHERE topf=? AND art=?", (z["topf"], new)).fetchone():
                    self.db.execute(
                        "UPDATE fehlserie SET anzahl = anzahl + ?, seit = MIN(seit, ?), zuletzt = MAX(zuletzt, ?) "
                        "WHERE topf=? AND art=?", (z["anzahl"], z["seit"], z["zuletzt"], z["topf"], new))
                    self.db.execute("DELETE FROM fehlserie WHERE topf=? AND art=?", (z["topf"], old))
                else:
                    self.db.execute("UPDATE fehlserie SET art=? WHERE topf=? AND art=?", (new, z["topf"], old))
                n += 1
            if self.db.execute("SELECT 1 FROM login_attempt WHERE method=? LIMIT 1", (old,)).fetchone():
                n += self.db.execute("UPDATE login_attempt SET method=? WHERE method=?", (new, old)).rowcount
        return n

    #: Setting key: has `users.name_quelle` been backfilled for existing data (attack round 2026-09-26)?
    NAME_SOURCE_BACKFILLED = "name_quelle_nachgetragen"

    #: How far apart creation and binding of a source may be for the binding to count as "the
    #: source created the account" (`_backfill_name_source`). On creation both happen in
    #: the same sign-in, without a directory call in between — fractions of a second.
    SETUP_TOLERANCE_SEC = 2

    def _backfill_name_source(self) -> None:
        """Backfill `users.name_quelle` once for existing data where the origin is proven (without
        commit, under `_lock`, part of `_migrate`).

        * **OIDC:** every row in `oidc_identity` has been written by the callback since v0.1 on CREATING
          the account — it never links an existing one. The account therefore carries the provider's name.
        * **LDAP/SAML:** a binding (also the placeholder) that arose with the creation of the account
          (`gebunden_at` at most `SETUP_TOLERANCE_SEC` before or after `created_at`). A later
          re-binding does not count — the account already existed then, and its name came from elsewhere.

        Excluded: service accounts and self-chosen names (the marker above already carries them).
        Accounts from before the identifiers (F-11, up to 0.19) have no binding from creation and stay
        NULL — the deadline applies to them (`federation_name_binding_days`). Limit in the safe
        direction: if the operator creates an account and binds it within two seconds, it counts as created by
        the source; another source binds it then only if the operator opens it
        (`federation_unbind`).

        Exactly once, via the marker `NAME_SOURCE_BACKFILLED` in the same commit: if it ran on every start,
        an account renamed by the operator would get its source back."""
        self.db.execute(
            "UPDATE users SET name_quelle = 'oidc' WHERE name_quelle IS NULL AND is_service = 0 "
            "AND name_selbst_gewaehlt = 0 AND id IN (SELECT user_id FROM oidc_identity)")
        from_setup = ("FROM federated_identity f WHERE f.user_id = users.id "
                      "AND abs(f.gebunden_at - users.created_at) <= ?")
        self.db.execute(
            f"UPDATE users SET name_quelle = (SELECT f.quelle {from_setup} "
            "ORDER BY f.gebunden_at, f.quelle LIMIT 1) "
            "WHERE name_quelle IS NULL AND is_service = 0 AND name_selbst_gewaehlt = 0 "
            f"AND EXISTS (SELECT 1 {from_setup})",
            (self.SETUP_TOLERANCE_SEC, self.SETUP_TOLERANCE_SEC))
        self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                        (self.NAME_SOURCE_BACKFILLED, str(_now())))

    #: Setting key: up to which `audit.id` the panel lockouts of older writers have already been
    #: caught up (`_catch_up_inventory`). If it is missing, the next start reads the audit log
    #: in full once — that is only slower, not wrong (every step is repeatable).
    PANEL_WATERLINE = "panel_sperren_bis"

    #: How many identifiers at most in one `IN (…)` (SQLite up to 3.32: 999 parameters).
    IN_PIECE = 500

    @staticmethod
    def _uid_from_detail(detail) -> Optional[int]:
        """The account id from the detail of a panel row: `uid=<id>` or `uid=<id> …`.

        The same form that the SQL version compared (`detail = 'uid=' || id` or
        `LIKE 'uid=' || id || ' %'`): only ASCII digits without a leading zero, then end or a
        space. The panel has written this form unchanged since 0.3.0."""
        head = str(detail or "").split(" ", 1)[0]
        if not head.startswith("uid="):
            return None
        number = head[4:]
        if not (number.isascii() and number.isdigit()) or number != str(int(number)):
            return None
        return int(number)

    def _catch_up_owner(self) -> None:
        """If there are admins but no owner (existing data from before the owner model), the oldest admin
        becomes owner — preferably one that someone set by hand (`is_admin=1`), active and not a
        service account. Once, with a row in the audit log. Runs in the migration (under the
        write lock, directly on the connection) — BEFORE the watermark of the existing-data steps, so that
        its own row does not count as "new since the last start". Without an admin it stays with the
        first-admin path, which also assigns the first owner."""
        columns = {r["name"] for r in self.db.execute("PRAGMA table_info(users)")}
        if "is_owner" not in columns:
            return
        if self.db.execute("SELECT 1 FROM users WHERE is_owner=1 LIMIT 1").fetchone():
            return
        # ONLY an active, manually set admin (`is_admin=1`). A flag granted by the identity provider
        # (2) would otherwise make him a permanent owner at the next start — and thereby
        # an admin that no provider revokes anymore (attack on the second round, finding 1).
        # A locked admin would be an owner who cannot sign in (finding 2).
        u = self.db.execute(
            "SELECT id, username FROM users WHERE is_admin = 1 AND is_service = 0 AND disabled = 0 "
            "ORDER BY id LIMIT 1").fetchone()
        if u is None:
            if self.db.execute("SELECT 1 FROM users WHERE is_admin <> 0 LIMIT 1").fetchone():
                logging.getLogger("tinysesam").warning(
                    "No owner: there are admins, but none active and set by hand (only ones "
                    "granted by the identity provider, or locked). Designate an owner: "
                    "`tinysesam owner --db <file> <user>`.")
            return
        self.db.execute("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (u["id"],))
        self.db.execute("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                        (_now(), "owner_grant", u["username"], None, "source=existing oldest_admin"))
        logging.getLogger("tinysesam").warning(
            "Owner model: %s is now owner (oldest admin). Further owners are granted by an owner in the "
            "admin panel.", u["username"])

    def _catch_up_inventory(self, from_start: bool, without_bucket) -> None:
        """Bring existing data to schema 10 (without commit, under `_lock` — part of `_migrate`).

        On upgrade (`from_start`) for all existing data, afterwards on **every** start for what
        an older writer may have left behind since then. An older version opens a
        schema-10 file, warns and keeps writing; it leaves the stamp at 10 (rollback without
        backup). If it locks in the panel during this window, `disabled=1` stands again with an open
        confirmation link, and if the step hung on the stamp, it would never run again: the old link
        would lift the lock and sign in (H-18, measured with 0.19.0). The trace of the older
        writer is different per step — audit rows since the watermark for the locks,
        rows without a bucket (`topf_name`) for the registrations.

        1. **Locks from the panel get the operator mark** (`disabled=2`). Up to this
           version the panel lock wrote `disabled=1` — the same value as a pending
           confirmation, and the confirmation link lifts that. Up to 0.19.x the lock
           did not even discard the open tokens. The panel lock is recognised from the audit log: the
           most recent entry `user_disable`/`user_enable` with `uid=<id>` is `user_disable`, and the
           account is at 1 (today's lock writes 2, a 1 behind it therefore comes from an
           older writer). For such accounts the open one-time tokens are discarded at the same time —
           as with a lock of today. It is read **once in sequence**, only the rows
           after the watermark (`PANEL_WATERLINE`, on upgrade from 0): the first version searched
           the whole audit log for each locked account (measured 60 s with 1,000,000 rows × 1,000
           accounts, under the write lock — a second worker failed at `busy_timeout`).
           Limits: a lock whose row `audit_retention_days` has already deleted stays
           undetected; for that, `POST <admin_path>/api/users/{id}/disable` with
           `{"disabled": true}` locks again without unlocking. And in the safe direction: if an
           app lifts a lock of today without an audit row and then locks itself (1) before the
           service restarts, it counts as an operator lock at the next start.
        2. **Addresses of open registrations carry no proof** (`email_verified=0`). The
           registration created them with the marker 1 although the link was still outstanding; since
           this version only the redeemed link sets it. Open means: locked, never
           signed in, an unused `verify_email` token and no redeemed one. Otherwise
           the deletion by an admin would also take the address typed in by a stranger from older rows
           (`remove_account`) — even when a lock in the panel has discarded the tokens
           by which the account is otherwise recognisable as open. After the upgrade only for
           rows without a bucket (only a foreign writer creates them) and for the accounts from
           step 1. Step 2 runs before step 1, which discards exactly these tokens."""
        log = logging.getLogger("tinysesam")
        # Reading and writing under ONE write lock: a second worker that is just redeeming a
        # confirmation link sees the lock before or after, not in between. On
        # upgrade `_migrate` already holds the transaction (DELETE above).
        if not self.db.in_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        line = self.db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit'").fetchone()
        until = int(line[0]) if line and line[0] else 0
        stored = self.db.execute("SELECT value FROM setting WHERE key=?",
                                      (self.PANEL_WATERLINE,)).fetchone()
        stored = stored[0] if stored else None
        start_from = 0
        if not from_start and stored is not None and str(stored).isdigit():
            start_from = int(stored)
        if start_from > until:
            start_from = 0          # counter smaller than the watermark (table recreated): read everything
        youngest = {}
        for event, detail in self.db.execute(
                "SELECT event, detail FROM audit WHERE id > ? AND id <= ? "
                "AND event IN ('user_disable', 'user_enable') ORDER BY id", (start_from, until)):
            uid = self._uid_from_detail(detail)
            if uid is not None:
                youngest[uid] = event
        candidates = sorted(uid for uid, event in youngest.items() if event == "user_disable")

        def pieces(ids):
            ids = list(ids)
            for i in range(0, len(ids), self.IN_PIECE):
                part = ids[i:i + self.IN_PIECE]
                yield part, ",".join("?" * len(part))

        addresses = 0
        destination = None if from_start else {z["id"] for z in without_bucket} | set(candidates)
        if destination is None or destination:
            unclosed = sorted(z[0] for z in self.db.execute(
                "SELECT user_id FROM magic_token WHERE purpose = 'verify_email' AND user_id IS NOT NULL "
                "GROUP BY user_id HAVING SUM(used_at IS NULL) > 0 AND SUM(used_at IS NOT NULL) = 0")
                if destination is None or z[0] in destination)
            for part, ph in pieces(unclosed):
                addresses += self.db.execute(
                    f"UPDATE users SET email_verified=0 WHERE id IN ({ph}) AND email_verified <> 0 "
                    "AND disabled <> 0 AND first_login_at IS NULL", part).rowcount
        panel = []
        for part, ph in pieces(candidates):
            ids = [z[0] for z in self.db.execute(
                f"SELECT id FROM users WHERE id IN ({ph}) AND disabled = ?",
                (*part, self.LOCKED_CONFIRMATION))]
            if not ids:
                continue
            ph = ",".join("?" * len(ids))
            self.db.execute(f"UPDATE users SET disabled=? WHERE id IN ({ph}) AND disabled = ?",
                            (self.LOCKED_OPERATOR, *ids, self.LOCKED_CONFIRMATION))
            self.db.execute(f"DELETE FROM magic_token WHERE user_id IN ({ph}) AND used_at IS NULL", ids)
            panel += ids
        if stored is None or str(stored) != str(until):
            self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                            (self.PANEL_WATERLINE, str(until)))
        if from_start and (addresses or panel):
            log.info("Schema 10: %d lockout(s) from the panel now carry the operator marker (open "
                     "one-time tokens discarded), %d address(es) of open registrations count as "
                     "unproven until confirmed.", len(panel), addresses)
        elif addresses or panel:
            log.warning("An older TinySesam version has written to this database (downgrade "
                        "without a backup?): %d lockout(s) from its panel now carry the "
                        "operator marker (open one-time tokens discarded), %d address(es) of its "
                        "open registrations count as unproven until confirmed.",
                        len(panel), addresses)

    def _write_pots(self, lines) -> None:
        """Compute `topf_name`/`topf_mail` for these account rows (without commit, under `_lock`).

        Written only if name and address are still the ones read: if another
        writer changes them in between, its trigger sets the bucket to NULL, and the next call
        recomputes — instead of the bucket of the old name remaining here."""
        self.db.executemany(
            "UPDATE users SET topf_name=?, topf_mail=? WHERE id=? AND username IS ? AND email IS ?",
            [(norm_identifier(z["username"]), norm_identifier(z["email"]), z["id"], z["username"], z["email"])
             for z in lines])

    def _backfill_pots(self) -> list:
        """Backfill missing counting buckets — the rows of another writer (see `topf_name`).

        Returns the rows that could NOT be written (database read-only, locked);
        the caller checks those itself. Normally that is none, and it costs one query
        over the index — independent of which identifier is being looked up."""
        unclosed = self._all("SELECT * FROM users WHERE topf_name IS NULL OR topf_mail IS NULL")
        if not unclosed:
            return []
        try:
            with self._writing():
                self._write_pots(unclosed)
                self.db.commit()
        except sqlite3.Error:
            return unclosed
        return []

    def _one(self, sql, args=()):
        with self._lock:
            cur = self.db.execute(sql, args)
            return cur.fetchone()

    def _all(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def _discard(self) -> None:
        """Roll back an open transaction (under `_lock`) — after a failed write."""
        try:
            self.db.rollback()
        except sqlite3.Error:
            pass     # connection closed or similar — then nothing is left open either

    def _begin_immediate(self) -> None:
        """`BEGIN IMMEDIATE` for a self-managed transaction (under `_lock`) — counting and
        booking in one step, also across several processes (`reserve_attempt`, `finish_attempt`)."""
        if self.db.in_transaction:
            # The second lock behind `_writing`: if a transaction is lying around anyway (a
            # writer that did not roll back on failure), the BEGIN below would fail on it —
            # and with it every sign-in until someone else committed. Its content is the remainder
            # of a FAILED write; it is discarded, not booked along. Loud, because
            # it is an error elsewhere.
            logging.getLogger("tinysesam").warning(
                "Open transaction found on the database connection (remnant of a "
                "failed write) — discarded before the sign-in attempt counts.")
            self._discard()
        self.db.execute("BEGIN IMMEDIATE")

    @contextlib.contextmanager
    def _writing(self):
        """Hold `_lock`, write — and on failure DISCARD the transaction.

        Python's `sqlite3` silently opens a `BEGIN` before every INSERT/UPDATE/DELETE. If
        the write failed (a foreign writer held the lock longer than `busy_timeout`,
        volume full, file read-only), this transaction stayed open on the SHARED connection.
        Measured: `reserve_attempt` begins with an explicit `BEGIN IMMEDIATE`
        and failed with "cannot start a transaction within a transaction" — every sign-in
        ended with a 500 until some other write happened to commit. It was triggered
        by the write probe of `/healthz` alone, which is reachable without sign-in. In addition:
        that foreign commit would take along what a multi-part writer (`delete_user`) had already
        written before the failure.

        Every write path therefore runs through here (or through `_exec`, which does so too); whoever manages the
        transaction themselves (`reserve_attempt`, `rotate_session`, `_clock_record`, the
        inner block of `_migrate`) puts each commit in a `try` whose broad `except`
        (without type, `Exception` or `BaseException` — `sqlite3.Error` does not catch a binding error such as
        OverflowError) or `finally` rolls back. tests/test_hardening2.py checks this via the
        syntax tree for every commit in this class — not merely whether `rollback()`
        appears somewhere in the function."""
        with self._lock:
            try:
                yield
            except BaseException:
                self._discard()
                raise

    def _exec(self, sql, args=()):
        with self._writing():
            cur = self.db.execute(sql, args)
            self.db.commit()
            self._written = time.monotonic()
            self._clock_record()
            return cur

    #: Setting key of the saved clock state (see `_Clock`) and how often it is written at most
    #: (seconds).
    CLOCK_STATE = "uhr_stand"
    CLOCK_SECURE_SEC = 60

    def _write_clock_state(self) -> None:
        """Raise `uhr_stand` to `now()` — only UPWARDS (without commit, under `_lock`).

        `_migrate()` already writes before `Store()` has raised the clock from the database;
        there `now()` is still the wrong wall clock of a boot with an old date. A blind
        overwrite would delete exactly the state that is about to raise the clock."""
        now_s = _now()
        self.db.execute("INSERT OR IGNORE INTO setting(key, value) VALUES (?, ?)",
                        (self.CLOCK_STATE, str(now_s)))
        self.db.execute("UPDATE setting SET value=? WHERE key=? AND CAST(value AS INTEGER) < ?",
                        (str(now_s), self.CLOCK_STATE, now_s))

    @staticmethod
    def _fresh(since, m, deadline) -> bool:
        """Is the monotonic stamp `seit` less than `deadline` seconds before `m`?

        A NEGATIVE distance counts as expired, not as fresh: freezegun delivers
        `time.monotonic` on the epoch scale (≈1.8e9). A write under `freeze_time`
        left the stamps there, and afterwards every distance was negative, hence always "shorter than
        the deadline" — `uhr_stand` was no longer saved in the whole process, the write probe
        checked only the connection (second attack round, same class as in `_Clock.now`).
        A distance above any deadline is expired anyway."""
        return since is not None and 0 <= m - since < deadline

    def _clock_record(self) -> None:
        """Save the clock state — at most once per `CLOCK_SECURE_SEC` (under `_lock`).

        Without it a restart knew only the last event in the database: what expired afterwards
        applied again for its full remaining lifetime after a boot with an old date (B6-9). Own
        commit AFTER the actual write: if it fails (volume full), it must not drag down the
        already confirmed write — the state is a bonus."""
        m = time.monotonic()
        if self._fresh(self._clock_secured, m, self.CLOCK_SECURE_SEC):
            return
        try:
            self._write_clock_state()
            self.db.commit()
            self._clock_secured = m
        except Exception as error:
            # Rolled back on EVERY failure, only the database error is swallowed (the
            # clock state is a precaution). Until the final round, `except sqlite3.Error:` caught here —
            # a binding error such as OverflowError is not one and left the transaction open;
            # only the outer `_writing` of `_exec` saved it.
            self._discard()
            if not isinstance(error, sqlite3.Error):
                raise

    # ---------- Users ----------
    def create_user(self, username, display_name=None, email=None, is_admin=False, roles=None,
                    is_service=False, email_verified=True, name_itself_chosen=False,
                    name_source=None) -> int:
        """Create an account (raw building block; the checks are done by `TinySesam.create_user`).

        Raises `sqlite3.IntegrityError` if the name or address is already the identifier of another account
        — also as a namesake in the counting bucket (`Alice`/`alice`, see `_trigger_sql`). Until
        2026-09-26 this went through here, unless exactly the same name or the same address
        already existed.

        Name and address belong to the account from this statement on: the watermarks (G2) arise in
        the same INSERT, as the highest id currently in `login_attempt` and `audit`. Likewise the
        marker `name_selbst_gewaehlt` (G2-N) and the origin of the name (`name_quelle`) — between
        creation and marker there is no sign-in that could bind the account via the name."""
        mail = norm_email(email)
        cur = self._exec(
            "INSERT INTO users(username, display_name, email, email_verified, is_admin, roles, "
            "is_service, created_at, topf_name, topf_mail, name_versuch_ab, mail_versuch_ab, "
            "name_audit_ab, mail_audit_ab, name_selbst_gewaehlt, name_quelle) VALUES (?,?,?,?,?,?,?,?,?,?,"
            f"{self.WL_ATTEMPT},{self.WL_ATTEMPT},{self.WL_AUDIT},{self.WL_AUDIT},?,?)",
            (username, display_name or username, mail, 1 if email_verified else 0,
             1 if is_admin else 0,
             json.dumps(list(roles or [])), 1 if is_service else 0, _now(),
             norm_identifier(username), norm_identifier(mail), 1 if name_itself_chosen else 0,
             name_source or None))
        return cur.lastrowid

    def _set_identifier(self, user_id, column: str, value, bucket: str, proof=None) -> list:
        """The statements that replace name (`column="username"`) or address (`"email"`, with `proof`)
        together with the counting bucket — for `_rewrite`.

        If the identifier thereby moves to a DIFFERENT bucket, it belongs to the account only from now on: the
        watermarks (`name_versuch_ab`/`name_audit_ab` or `mail_…`, G2) go to the current state in the same
        statement. If the bucket stays (`B1` → `b1`, `u@bücher.example` →
        `u@xn--bcher-kva.example`), they stay — it is the same identifier. SQLite evaluates
        every expression in SET with the OLD row; the comparison therefore sees the previous bucket.

        Two statements, because the recompute trigger (`_trigger_sql`) cannot tell its own writer
        from a foreign one: it fires when the value changes but the bucket
        does not — and then raises the watermarks. Therefore the first statement sets an
        unchanged bucket to NULL itself (the trigger sees a changed bucket and stays
        silent; the identifier triggers check nothing — no identifier is added), and the
        second sets it back in the same transaction. It changes only the bucket and fires no
        trigger. Until 2026-09-26 the trigger set the bucket to NULL and the second statement
        set it back; with the watermarks that would already have shifted the limit for `B1` → `b1`.

        For the name a third is added at the front (`_remember_directory_name`, audit round 2026-09-27):
        an account with an LDAP binding whose name was the name in the directory keeps the old one as
        directory name — otherwise it would drop out of `count_identifiers` and out of the
        identifier space on renaming, until the next successful LDAP sign-in."""
        bucket_column, kind = ("topf_name", "name") if column == "username" else ("topf_mail", "mail")
        same = f"CASE WHEN {bucket_column} IS ? THEN"
        set_value = (f"{bucket_column} = {same} NULL ELSE ? END, "
                  f"{kind}_versuch_ab = {same} {kind}_versuch_ab ELSE {self.WL_ATTEMPT} END, "
                  f"{kind}_audit_ab = {same} {kind}_audit_ab ELSE {self.WL_AUDIT} END")
        first: tuple
        if proof is None:
            first = (f"UPDATE users SET {column}=?, {set_value} WHERE id=?",
                     (value, bucket, bucket, bucket, bucket, user_id))
        else:
            first = (f"UPDATE users SET {column}=?, email_verified=?, {set_value} WHERE id=?",
                     (value, 1 if proof else 0, bucket, bucket, bucket, bucket, user_id))
        beforehand = [self._remember_directory_name(user_id, bucket)] if column == "username" else []
        return beforehand + [first, (f"UPDATE users SET {bucket_column}=? WHERE id=?", (bucket, user_id))]

    def _remember_directory_name(self, user_id, new_bucket) -> tuple:
        """The statement that, before a rename, records the previous name as the name in the directory
        on the LDAP binding (`federated_identity.name_topf`, G5) — for `_set_identifier`.

        Occasion (audit round 2026-09-27): if an account is named the same locally and in the directory, NULL stands there
        (`set_binding_name` records only a differing name). If the operator
        (G13, panel, `tinysesam rename`) or the person themselves renamed the account, the
        directory name dropped out of `count_identifiers`: if a stranger had filled the series beneath it before, the
        LDAP sign-in stayed locked — panel reset and full sign-in by another route did not
        clear it, only `tinysesam unlock <directory name>`. And the name was free locally: another
        account could take it and, with every sign-in, clear the counters against the LDAP
        password.

        Only a real identifier (not the origin placeholder `WITHOUT_IDENTIFIER`): without a stable
        identifier LDAP matches via the name — after renaming, the old name no longer
        belongs to this account. Only if NULL stands (a differing name is already recorded and
        the younger one) and only if the bucket really changes. The old bucket is read in
        the same transaction, before the new name is written."""
        old = "(SELECT topf_name FROM users WHERE id = ?)"
        return (f"UPDATE federated_identity SET name_topf = {old} WHERE quelle = 'ldap' AND user_id = ? "
                "AND name_topf IS NULL AND substr(kennung, 1, length(?)) <> ? "
                f"AND {old} IS NOT NULL AND {old} <> '' AND {old} IS NOT ?",
                (user_id, user_id, self.WITHOUT_IDENTIFIER, self.WITHOUT_IDENTIFIER, user_id, user_id, user_id,
                 new_bucket))

    def _rewrite(self, steps) -> None:
        """Several statements in ONE transaction, one commit (like `_exec`, only for a list).
        If one fails — also on an identifier trigger (`IntegrityError`) — `_writing` rolls
        all of them back."""
        with self._writing():
            for sql, args in steps:
                self.db.execute(sql, args)
            self.db.commit()
            self._written = time.monotonic()
            self._clock_record()

    def set_username(self, user_id, username, itself_chosen: Optional[bool] = None) -> None:
        """Replace the username — together with the counting bucket (`topf_name`) in the same transaction.
        The check happens beforehand (`TinySesam.change_username`); this only writes. If the name is
        already the identifier of another account (name, address or namesake in the bucket), the
        database rejects it: `sqlite3.IntegrityError`, nothing changed.

        `itself_chosen` sets the marker `users.name_selbst_gewaehlt` (G2-N) in the same
        transaction and deletes the origin `users.name_quelle`: the new name comes from the person
        or the operator, no longer from the source that created the account. `None` leaves
        both as they are."""
        name = str(username or "").strip()
        steps = self._set_identifier(user_id, "username", name, norm_identifier(name))
        if itself_chosen is not None:
            steps.append(("UPDATE users SET name_selbst_gewaehlt=?, name_quelle=NULL WHERE id=?",
                             (1 if itself_chosen else 0, user_id)))
        self._rewrite(steps)

    def set_email(self, user_id, email, verified: bool = False):
        """Replace the address — **together with its proof**, by default "unconfirmed".

        The proof belongs to the address, not to the account: since `users.email_verified` decides
        on rights (`_maybe_promote_admin`, stage 2), a marker left standing would be
        the proof of the **old** address on the **new** one — exactly that was measured
        (B-bypass-8 from T-13): `eve@example.com` (proven) → `set_email(uid, "boss@example.com")` →
        first admin via the allowlist, without anyone having confirmed anything.

        Until then it said here that the marker stays "fail-closed". That held only for the
        one direction (unconfirmed stays unconfirmed); the other was fail-**open**. The
        default is therefore `verified=False`: whoever has a proof for the NEW address — a
        redeemed confirmation mail, an IdP claim from the same login — says so
        explicitly (`set_email(uid, mail, verified=True)`) or sets it afterwards with
        `set_email_verified`. Address and proof go into the database in ONE statement,
        so that there is no state in between in which the new address carries the old proof.
        The counting bucket of the address (`topf_mail`) goes along in the same transaction.

        If the address is already the identifier of another account (address, name or namesake in the
        bucket), the database rejects it: `sqlite3.IntegrityError`, nothing changed. Until
        2026-09-26 nothing checked here except `ux_users_email` (address against address)."""
        mail = norm_email(email)
        self._rewrite(self._set_identifier(user_id, "email", mail, norm_identifier(mail), bool(verified)))

    def address_switch(self, user_id, email, name_follows: bool = False) -> None:
        """Enter the confirmed new address (with proof) and, if `name_follows`, set the name
        to the same address (email mode) — in ONE transaction.

        Written separately (`set_email`, then `set_username`), the second could fail
        after the first was already in place: new address, name still the old address — and the old
        address stayed occupied as the account's name. If one statement fails here (the new
        identifier has meanwhile been taken: `sqlite3.IntegrityError`), both stay as they were."""
        mail = norm_email(email)
        bucket = norm_identifier(mail)
        steps = self._set_identifier(user_id, "email", mail, bucket, True)
        if name_follows:
            steps += self._set_identifier(user_id, "username", mail, bucket)
        self._rewrite(steps)

    def set_email_verified(self, user_id, verified: bool):
        """Record the proof for the address (`users.email_verified`).

        Separate from the address because the two are known separately: an IdP sends `email` in
        every login, but the claim `email_verified` only sometimes. And the marker must stay
        in place, because a login that brings no proof itself (local password, magic link)
        is also decided by it — otherwise the protection would depend on the sign-in route."""
        self._exec("UPDATE users SET email_verified=? WHERE id=?",
                   (1 if verified else 0, user_id))

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
        canonical = norm_email(email)
        if not canonical:
            return None
        # Also look for the form from before R4-06 (only trimmed and lowercase): a stored address
        # with an umlaut domain is still in Unicode form in existing data and would otherwise not be found.
        # And in BOTH directions (attack A5): the Unicode form is also recovered from the A-label
        # input — otherwise `user@xn--bcher-kva.example` did not find the existing entry
        # `user@bücher.example`, and the registration created a second account for the same
        # mailbox.
        old = str(email or "").strip().lower()
        unicode_form = _email_unicode(canonical)
        return self._one("SELECT * FROM users WHERE email COLLATE NOCASE IN (?, ?, ?) ORDER BY id LIMIT 1",
                         (canonical, old, unicode_form))

    def deletion_guard(self, user) -> Optional[str]:
        """Why can this account NOT be deleted on purpose? `"owner"`, `"last_admin"` or None.

        The one protection rule of the deliberate deletion — shared by `TinySesam.delete_user`
        (panel, library) and `tinysesam delete` (command line), so that the two cannot drift
        apart: an owner is never deleted (the role must be handed over first), and neither is the
        last admin (otherwise the instance has no administration and the first-admin path opens up
        for the next best person)."""
        if user["is_owner"]:
            return "owner"
        if user["is_admin"] and sum(1 for x in self.list_users() if x["is_admin"]) <= 1:
            return "last_admin"
        return None

    def account_footprint(self, user_id) -> tuple[int, int, int]:
        """What hangs on an account, as counts only (for `tinysesam delete`):
        `(sessions, identity links, API keys)`."""
        def n(sql):
            return int(self._one(sql, (user_id,))["n"])
        return (n("SELECT COUNT(*) AS n FROM session WHERE user_id=?"),
                n("SELECT COUNT(*) AS n FROM oidc_identity WHERE user_id=?")
                + n("SELECT COUNT(*) AS n FROM federated_identity WHERE user_id=?"),
                n("SELECT COUNT(*) AS n FROM api_key WHERE user_id=?"))

    def remove_account(self, user_id, address_unlimited: bool = False) -> Optional[tuple[str, int]]:
        """Delete an account — the ONE deletion path that every caller goes through (H-13).

        Account together with credentials and sessions, the sign-in attempts under name and address, and
        in the audit log the name becomes `deleted#<id>` (`anonymize_audit`). A deleted
        account whose name still stands in every row is not deleted.

        Why here and not in the manager: until the T-13 integration there were four deletion paths with two
        different promises. `TinySesam.delete_user` anonymised, `gc()`, `tinysesam gc` (which
        works directly on the store) and the rollback after a failed confirmation send
        called `delete_user` and left name, foreign IP and the victim's address standing — a
        later namesake saw the stranger's registration as their own event
        (integration findings 12/18). The store is the deepest place that all paths share.

        **Only what arose from the creation of the account** (`setup_limit` — the same limit as
        `TinySesam.own_events`). Since `gc()` and the B6-5 rollback go through here, a stranger without
        an account triggers this path too: register, never confirm. Without a limit it
        rewrote rows that arose BEFORE his account and belong to others — the admin's invitation
        with the address in the detail, the failed attempt of a sprayer under the then
        free name, the one of the real address holder —, and their attempt rows disappeared
        from the per-IP throttling. A name or a typed-in address belonged before creation
        to nobody or to someone else. Sign-in attempts from the second of creation stay
        in place: whether they came before or after cannot be decided, and leaving them
        is the safe direction here (they expire with the lockout window).

        More precise since 2026-09-26 (G2): not from creation, but from **each identifier's
        joining** (`identifier_limits`) — an account gets name and address later too
        (rename, address change). To the exact row, also in the second of joining. The
        creation remains the fallback for existing data without a watermark.

        `address_unlimited=True` exempts a **proven** address (`address_proven`):
        it demonstrably belongs to the account and is also replaced in older rows (the
        invitation that led to the account). That is the deliberate deletion by an admin
        (`TinySesam.delete_user`, H-13) — not a path that an anonymous party triggers. `gc()`, the
        rollback and `_purge_demo` clear accounts that never belonged to anyone; there the
        limit applies to the address too. And even for deletion by an admin only for a
        PROVEN address: that of an open account (registration, link never redeemed) or
        of a registration without confirmation requirement was typed in by a stranger — without this
        distinction, clearing such accounts in the panel would rewrite the admin's invitation
        and the failed attempts of the real holder from BEFORE creation to `deleted#<id>`.

        The sign-in attempts of a counting bucket (`norm_identifier`) that a REMAINING account
        shares stay in place (see `delete_attempts_for`).

        Returns `(replacement name, anonymised rows)` — under the replacement name the
        caller writes its own row (`user_delete`, `signup_expired`, `verify_send_error`) —,
        None if the account does not exist."""
        u = self.get_user(user_id)
        if u is None:
            return None
        name, mail = str(u["username"]), (u["email"] or "")
        since, since_id = self.setup_limit(u)
        # More precise than creation: from when each identifier belonged to the account (G2). Read before
        # deleting — afterwards the row no longer exists.
        limits = self.identifier_limits(u)
        unlimited = (mail,) if (address_unlimited and self.address_proven(u)) else ()
        self.delete_user(user_id)
        self.delete_attempts_for(name, (mail,), after=since, unlimited=unlimited,
                                 from_ids={t: g[0] for t, g in limits.items()})
        replacement = replacement_name(user_id)
        return replacement, self.anonymize_audit(name, replacement, (mail,), since=since, since_id=since_id,
                                                unlimited=unlimited,
                                                from_ids={t: g[1] for t, g in limits.items()})

    def address_proven(self, user) -> bool:
        """Does the address of this account demonstrably belong to it? (`remove_account`, H-13)

        The marker `email_verified` AND no pending confirmation: an open account —
        locked, an unused `verify_email` token and no redeemed one — carries an address
        that someone typed in and never confirmed. Since schema 10 the registration creates it
        without the marker (which only the redeemed link sets), and `_migrate` backfills this for
        open registrations from existing data. The token check here additionally catches
        an app that calls `create_user` with the default `email_verified=True` and then itself
        sends a confirmation link."""
        if not (user["email"] and user["email_verified"]):
            return False
        if not user["disabled"]:
            return True
        unclosed = self._one(
            "SELECT 1 AS x FROM magic_token WHERE user_id=? AND purpose='verify_email' "
            "  AND used_at IS NULL "
            "  AND NOT EXISTS (SELECT 1 FROM magic_token WHERE user_id=? AND purpose='verify_email' "
            "      AND used_at IS NOT NULL) LIMIT 1", (user["id"], user["id"]))
        return unclosed is None

    def setup_limit(self, user) -> tuple[int, int]:
        """From where does an audit row belong to this account? `(seit, since_id)` — the fallback.

        Since 2026-09-26 the watermark of the identifier applies first (`identifier_limits`, G2): an
        account that takes over a name that became free otherwise saw here the sign-ins of the
        previous owner including their IP. This limit now carries only the existing data whose accounts do not have the
        watermark.

        `seit` is `created_at` (Unix seconds). From the second of creation itself only rows
        from `since_id` count: the registration row of the account (`signup`, for the placeholder
        `signup_taken`), which is written right after creation. Without it the limit would be
        accurate to the second only — and a stranger who registers in the same second in which
        the admin invites the address or a sprayer tries the free name would have their
        rows attributed. Exactly these paths (registration, `gc()`, B6-5) always have the row;
        an account without it (admin API, SSO, demo) falls back to `since_id = 0` — then
        the whole second counts.

        The row is searched only in the second of creation and the next (the password is hashed
        AFTER creation, the row may be one second later). A
        `signup_taken` row counts only if it was the creation of a **placeholder**: the
        placeholder carries no address, and its row names in the detail the address that is not
        its name. The other `signup_taken` row — someone registers with an
        address that already belongs to an account as a username (name = address), and no
        account is created — stands under exactly this name, also in the same or the
        next second. It is not the creation and shifts nothing; taken as an anchor,
        the admin's `user_create` row would drop out of the anonymisation.

        Filter for SQL: `ts > seit OR (ts = seit AND id >= since_id)`."""
        since = int(user["created_at"] or 0)
        placeholder = not user["email"]
        for z in self._all(
                "SELECT id, event, username, detail FROM audit WHERE event IN ('signup', 'signup_taken') "
                "AND lower(username) = lower(?) AND ts BETWEEN ? AND ? ORDER BY id",
                (str(user["username"]), since, since + 1)):
            if z["event"] == "signup" or (
                    placeholder and norm_email(z["username"]) != norm_email(z["detail"])):
                return since, int(z["id"])
        return since, 0

    def account_by_bucket(self, identifier, other_than=None) -> Optional[sqlite3.Row]:
        """The first account whose name or address falls into the same counting bucket as `kennung`.

        The bucket is `norm_identifier` (Python `lower()`), whereas the database's name check is
        `COLLATE NOCASE` — and that folds only ASCII. `Émile` and `émile` are two
        names for SQLite, one for the lockout counter. That is why each account carries its bucket as a column
        (`topf_name`/`topf_mail`, computed in Python), and the lookup goes through its index.

        Up to schema 10 the lookup ran as a loop over ALL accounts in Python — on every
        registration, and for one with a free address twice as often as for one with a
        taken address: from a few thousand accounts on, the response time of a single request revealed
        whether an address has an account (R4-03), and `gc()` grew with open × all accounts.
        The work here now depends neither on the number of accounts nor on whether and where the
        identifier is found (tests/test_audit_round2.py counts the SQLite steps).
        `other_than` leaves out one account (the ID currently at issue)."""
        bucket = norm_identifier(identifier)
        if not bucket:
            return None
        # Rows whose bucket could not be backfilled (database read-only) are checked by Python —
        # normally none.
        hit = [z for z in self._backfill_pots()
                   if z["id"] != other_than and bucket in (norm_identifier(z["username"]), norm_identifier(z["email"]))]
        z = self._one("SELECT * FROM users WHERE (topf_name = ? OR topf_mail = ?) AND id IS NOT ? "
                      "ORDER BY id LIMIT 1", (bucket, bucket, other_than))
        if z is not None:
            hit.append(z)
        return min(hit, key=lambda t: t["id"]) if hit else None

    def bucket_of_another(self, identifier, user_id) -> bool:
        """Is this identifier (in the counting bucket) the name or address of an account OTHER than `user_id`?

        The guard before every clearing under an identifier that the account does not itself carry as name or
        address (G5, G5-N1): under the name from the directory (`count_identifiers`) and
        under the typed identifier of a directory sign-in (`TinySesam._record_login`). A
        directory filter on `mail` resolves `chefin@example.com` to a third party whose
        `mail` attribute reads that way; without this guard every sign-in of the third party cleared the
        counters of the local holder of this address — unlimited guessing against her account.
        It is checked when clearing, not when writing: an identifier can change owner."""
        return self.account_by_bucket(identifier, other_than=user_id) is not None

    @staticmethod
    def _slot(line, name):
        """A column of the account row — None if it does not (yet) exist (dummy, old dict)."""
        try:
            return line[name]
        except (IndexError, KeyError):
            return None

    def identifier_limits(self, user) -> dict:
        """From where does a row under name or address belong to this account? (limit a, G2)

        `{bucket: (versuch_ab, audit_from)}` for name and address in the counting bucket: rows in
        `login_attempt` or `audit` with a LARGER id belong to the account, the others belonged
        to nobody or to someone else. `None` means existing data (the columns only arrived with this
        state) — then, as until 2026-09-26, the creation applies (`created_at`, `setup_limit`).

        Until then the creation was the limit for EVERY identifier. But an account gets an identifier
        later too: on renaming, on address change, on backfilling an address from OIDC.
        The failed attempts that a stranger had made earlier under the then free name
        were cleared by the first full sign-in — also from the throttling of his IP —, and the
        account page showed the previous owner's sign-in including their IP.

        Name and address in the same bucket (email mode): the earlier of the two watermarks —
        the identifier belongs to the account since it was added by one of the two paths. If one
        of them is NULL, the fallback applies."""
        from_: dict = {}
        for column, kind in (("username", "name"), ("email", "mail")):
            bucket = norm_identifier(self._slot(user, column))
            if not bucket:
                continue
            values = tuple(None if w is None else int(w)
                          for w in (self._slot(user, f"{kind}_versuch_ab"), self._slot(user, f"{kind}_audit_ab")))
            if bucket in from_:
                values = tuple(None if a is None or b is None else min(a, b) for a, b in zip(from_[bucket], values))
            from_[bucket] = values
        return from_

    def account_with_directory_name(self, identifier, other_than=None) -> Optional[sqlite3.Row]:
        """The account (not `other_than`) on whose binding this identifier stands as the name in the directory
        (`federated_identity.name_topf`, G5) — or None. For `TinySesam.identifier_taken` and
        `tinysesam rename`; the database checks the same in the identifier triggers (`_trigger_sql`).
        Via `ix_fed_name_topf`, no scan."""
        bucket = norm_identifier(identifier)
        if not bucket:
            return None
        z = self._one("SELECT user_id FROM federated_identity WHERE name_topf = ? AND user_id IS NOT ? "
                      "ORDER BY user_id LIMIT 1", (bucket, other_than))
        return self.get_user(z["user_id"]) if z else None

    def count_identifiers(self, user_id) -> set:
        """All identifiers (in the counting bucket) under which the series (B2-6) of this account can stand.

        Name and address — and the name under which the account signs in via a directory source
        (`federated_identity.name_topf`, G5), provided it is not the name or address of an
        OTHER account (`bucket_of_another`) and does not also stand on another account's binding
        (audit round 2026-09-27, p1-a: after renaming and reassignment in the directory,
        two accounts carried the same name, and every full sign-in of the previous owner ended the series
        under which the new holder was being guessed against). Since then `set_binding_name` deletes the
        name on foreign bindings; if two exist in existing data, it counts for neither — until the next
        LDAP sign-in under it. The series counts under the TYPED identifier;
        after a rename in the directory (locally `alice`, there `alice.neu`), until
        2026-09-26 no way back cleared the series under `alice.neu` — one's own typos added up
        over the years, and a stranger permanently locked the person out with enough failed attempts.

        The one reader for every way back: `lift_lockout`, `_end_series` (panel reset),
        `tinysesam passwd` and `tinysesam unlock`."""
        u = self.get_user(user_id)
        if u is None:
            return set()
        identifiers = {norm_identifier(u["username"]), norm_identifier(u["email"])} - {""}
        for z in self._all("SELECT DISTINCT name_topf FROM federated_identity WHERE user_id=? "
                           "AND name_topf IS NOT NULL AND name_topf <> ''", (user_id,)):
            bucket = norm_identifier(z["name_topf"])
            if (bucket and bucket not in identifiers and not self.bucket_of_another(bucket, user_id)
                    and self.account_with_directory_name(bucket, other_than=user_id) is None):
                identifiers.add(bucket)
        return identifiers

    def set_binding_name(self, source: str, user_id, name) -> bool:
        """Record the name under which the account has just signed in via `quelle` on its
        binding (`federated_identity.name_topf`, G5). Returns whether anything was written.

        Folded (`norm_identifier`) and only if it is neither name nor address of the account — the
        ways back know those anyway; then NULL stands. Only the most recent name: after two
        renames in the directory nobody signing in that way counts under the oldest any more.
        It writes only on a change, so at most one UPDATE per sign-in and normally
        none. Whether the name is the name or address of an OTHER account is checked by every reader
        (`count_identifiers`), not by this writer.

        **The most recent sign-in under the name proves who it belongs to** (audit round 2026-09-27,
        p1-a): if the same name stands on the binding of an OTHER account, it is stale there — renamed
        in the directory and reassigned. It is deleted there, even if it stays NULL here as own
        name or own address. Until then both carried it, every full sign-in of the
        previous owner ended the new holder's series, and `tinysesam unlock` named the account
        with the younger binding instead of the one that had last signed in that way."""
        u = self.get_user(user_id)
        if u is None:
            return False
        bucket = norm_identifier(name)
        if bucket and self.account_with_directory_name(bucket, other_than=user_id) is not None:
            self._exec("UPDATE federated_identity SET name_topf=NULL WHERE name_topf=? AND user_id IS NOT ?",
                       (bucket, user_id))
        value = None if not bucket or bucket in {norm_identifier(u["username"]), norm_identifier(u["email"])} else bucket
        if self._one("SELECT 1 AS x FROM federated_identity WHERE quelle=? AND user_id=? AND name_topf IS NOT ?",
                     (source, user_id, value)) is None:
            return False
        self._exec("UPDATE federated_identity SET name_topf=? WHERE quelle=? AND user_id=?",
                   (value, source, user_id))
        return True

    def release_directory_name(self, name) -> int:
        """Delete the name in the directory on ALL bindings — before creating an account that
        gets it as its name (`TinySesam._check_ldap`, audit round 2026-09-27). The directory has
        just signed in a different entry under this name; where it still stands, it is stale
        (see `set_binding_name`) — and without this the database would reject the creation (identifier
        trigger). Returns the number of deleted marks."""
        bucket = norm_identifier(name)
        if not bucket or self.account_with_directory_name(bucket) is None:
            return 0
        return self._exec("UPDATE federated_identity SET name_topf=NULL WHERE name_topf=?", (bucket,)).rowcount

    def account_with_binding_name(self, identifier) -> Optional[sqlite3.Row]:
        """The account that last signed in under this identifier via a directory source
        (`federated_identity.name_topf`, G5) — for `tinysesam unlock <name as typed>`.
        None if none or if the identifier is the name or address of an account (then THAT
        account is meant, `account_by_bucket`). Several hits (existing data, see `set_binding_name`):
        None — which one signed in last that way is recorded nowhere. Until 2026-09-27 it was the
        most recently BOUND one, and `unlock` cleared its own series too (audit round, p1-a)."""
        bucket = norm_identifier(identifier)
        if not bucket or self.account_by_bucket(bucket) is not None:
            return None
        z = self._all("SELECT DISTINCT user_id FROM federated_identity WHERE name_topf=? LIMIT 2", (bucket,))
        return self.get_user(z[0]["user_id"]) if len(z) == 1 else None

    def delete_user(self, user_id):
        """Remove the rows of an account — raw building block, only for `remove_account`.

        Whoever deletes an account calls `remove_account` (or `TinySesam.delete_user`): here
        the name stays in the audit log, and the sign-in attempts stay in place. A test ensures
        that there is no other caller."""
        with self._writing():
            for table in ("api_key", "password_cred", "pin_cred", "totp_cred", "recovery_code",
                          "webauthn_cred", "oidc_identity", "federated_identity", "namensbindung",
                          "session", "magic_token"):
                self.db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
            self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
            self.db.commit()

    def email_taken(self, email, exclude_id=None) -> bool:
        u = self.get_user_by_email(email)
        return bool(u and u["id"] != exclude_id)

    def identifier_collisions(self, limit: int = 50) -> list:
        """Accounts whose **username** is the **email** of an OTHER account (finding R4-12).

        Only the cross direction; all collisions in the identifier space (also name against name, address
        against address) are reported by `bucket_collisions`. New ones have been prevented by the database since 2026-09-26
        (`_trigger_sql`); what stands here comes from existing data (an older version, a raw
        UPDATE, a row of a foreign writer after the backfill of its bucket).

        The comparison runs over the counting bucket (`norm_identifier`). It folds more coarsely than NOCASE, with which
        `get_user_by_name`/`get_user_by_email` search — every collision that the sign-in finds
        is therefore also noticed here. Until 2026-09-26 NOCASE stood here; `Ärmel`/`ärmel` or a
        Unicode against the A-label domain of the same address were missing. A row without a bucket (file
        read-only, backfill not possible) does not count.
        Rows: `(name_id, kennung, mail_id, address)`. An account that carries the same string in
        BOTH its own columns is no collision (email mode, intended path).
        """
        self._backfill_pots()     # rows of a foreign writer count too
        return self._all(
            "SELECT n.id AS name_id, n.username AS kennung, e.id AS mail_id, e.email AS adresse "
            "FROM users n JOIN users e ON e.id <> n.id "
            "  AND e.topf_mail <> '' AND e.topf_mail = n.topf_name "
            "ORDER BY n.id LIMIT ?", (int(limit),))

    def bucket_collisions(self, limit: int = 50) -> list:
        """All identifiers that belong to more than one account — as `[{"kennung", "ids"}, …]`.

        Counted in the counting bucket (`norm_identifier`) over names AND addresses: `Alice`/`alice`,
        name = foreign address, two spellings of the same address (`u@bücher.example` and
        `u@xn--bcher-kva.example`). An account whose name is its own address counts once
        (the `UNION` merges the row). New collisions are prevented by the database
        (`_trigger_sql`); this query reports those from existing data — for the start message, which
        previously saw only the cross direction (`identifier_collisions`). `ids` ascending, the
        identifiers by the oldest account involved. Rows of a foreign writer first get
        their bucket (`_backfill_pots`); if that cannot be written (file read-only),
        they do not count."""
        self._backfill_pots()
        lines = self._all(
            "SELECT topf, group_concat(id) AS ids FROM ("
            "  SELECT id, topf_name AS topf FROM users WHERE topf_name <> ''"
            "  UNION SELECT id, topf_mail FROM users WHERE topf_mail <> '') "
            "GROUP BY topf HAVING COUNT(*) > 1 ORDER BY MIN(id) LIMIT ?", (int(limit),))
        return [{"kennung": z["topf"], "ids": sorted(int(i) for i in str(z["ids"]).split(","))}
                for z in lines]

    def list_users(self):
        return self._all("SELECT * FROM users ORDER BY username")

    #: Values of `users.disabled` besides 0 (active): the lock of a pending confirmation and
    #: the lock by the operator. Separate because `/auth/verify/…` lifts the one and never the
    #: other (H-18, second attack round): if the confirmation token arose only AFTER a
    #: lock by the operator — for instance in the outbox of an embedding app to which
    #: `send_verify_email` pushes it —, the lock found nothing to discard, and the link
    #: afterwards set `disabled` unconditionally to 0.
    LOCKED_CONFIRMATION = 1
    LOCKED_OPERATOR = 2

    def set_disabled(self, user_id, disabled: bool, through_operator: bool = False):
        """Lock or unlock an account.

        `through_operator=True` is the operator's lock (admin panel): no confirmation link
        lifts it, only an explicit `set_disabled(uid, False)`. Without the marker it is
        the lock of a pending confirmation, which `confirmation_enable` lifts — and
        which does not downgrade an already existing operator lock.

        Locks from versions before this distinction carry 1 — and up to 0.19.x the lock
        in the panel did not discard the open one-time tokens, so a pending confirmation link would
        have lifted it after the upgrade. The migration to schema 10 (`_catch_up_inventory`)
        therefore raises every lock that the audit log knows as a panel lock to 2 and discards
        the open tokens in doing so. A lock whose row has already been deleted
        (`audit_retention_days`) stays 1; `POST <admin_path>/api/users/{id}/disable` with
        `{"disabled": true}` sets the marker without unlocking in between."""
        if disabled:
            # An owner cannot be locked — not even via the code path (owner model). Otherwise
            # `owner_count` would count an owner who cannot sign in.
            line = self._one("SELECT is_owner FROM users WHERE id=?", (user_id,))
            if line is not None and line["is_owner"]:
                from .errors import StateError
                raise StateError(f"Account {user_id} is an owner and cannot be locked — hand over the "
                                 "owner role first.")
        if not disabled:
            self._exec("UPDATE users SET disabled=0 WHERE id=?", (user_id,))
        elif through_operator:
            self._exec("UPDATE users SET disabled=? WHERE id=?", (self.LOCKED_OPERATOR, user_id))
        else:
            self._exec("UPDATE users SET disabled=max(disabled, ?) WHERE id=?",
                       (self.LOCKED_CONFIRMATION, user_id))

    def confirmation_enable(self, user_id) -> bool:
        """Lift the lock of a pending confirmation — never the operator's.

        True if the account is active afterwards (also: it was not locked at all). False if
        a lock remains; then the operator locked it, and only the operator lifts it again."""
        self._exec("UPDATE users SET disabled=0 WHERE id=? AND disabled=?",
                   (user_id, self.LOCKED_CONFIRMATION))
        line = self._one("SELECT disabled FROM users WHERE id=?", (user_id,))
        return bool(line) and not line["disabled"]

    def set_admin(self, user_id, is_admin: bool):
        self._exec("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))

    def set_owner(self, user_id, owner: bool):
        """Set the owner flag. An owner is always an admin — and by hand (1): no identity
        provider takes the admin right from an owner (H-5 removes only the 2). The rules (at least
        one, only owners assign) are checked by the manager."""
        if owner:
            self._exec("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (user_id,))
        else:
            self._exec("UPDATE users SET is_owner=0 WHERE id=?", (user_id,))

    def owner_count(self, without=None) -> int:
        """How many owners are there (excluding the account `without`)?"""
        line = self._one("SELECT COUNT(*) AS n FROM users WHERE is_owner=1 AND id <> ?",
                          (int(without) if without is not None else -1,))
        return int(line["n"])

    def set_admin_from_idp(self, user_id):
        """Admin flag with the mark "granted by the identity provider" (`is_admin=2`, H-5).

        Only this value may be withdrawn again at the next login if the provider no longer
        delivers the group. A 1 (panel, CLI, `admin_identifiers`, `/auth/claim-admin`)
        is never touched by a provider. Everywhere else the flag counts as a truth value — 2 is admin like 1."""
        self._exec("UPDATE users SET is_admin=2 WHERE id=? AND is_admin=0", (user_id,))

    def user_count(self) -> int:
        return self._one("SELECT COUNT(*) c FROM users")["c"]

    # ---------- Password ----------
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
    #: Encryption/decryption of the TOTP secrets (H-14/H-15, `vault.Vault`). Set by the manager;
    #: a store without a vault (CLI tools) does not touch the secrets.
    vault: Any = None

    def set_totp(self, user_id, secret, confirmed=False):
        # `last_step` belongs to the secret: a new one starts without a consumed step. Otherwise
        # the confirmation code of a discarded attempt would lock the first code of the new one
        # if both fall into the same 30-second window.
        if self.vault is None:
            raise RuntimeError("TOTP secrets are only stored encrypted — the store has "
                               "no key (vault.Vault).")
        self._exec("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?,?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, "
                   "confirmed=excluded.confirmed, last_step=NULL",
                   (user_id, self.vault.encrypt(secret), 1 if confirmed else 0, _now()))

    def confirm_totp(self, user_id):
        self._exec("UPDATE totp_cred SET confirmed=1 WHERE user_id=?", (user_id,))

    def get_totp(self, user_id) -> Optional[dict]:
        """The TOTP row of an account, with the secret decrypted (`secret`)."""
        line = self._one("SELECT * FROM totp_cred WHERE user_id=?", (user_id,))
        if line is None:
            return None
        d = dict(line)
        if self.vault is not None:
            d["secret"] = self.vault.decrypt(d["secret"])
        return d

    def extract_secrets(self) -> int:
        """Encrypt plaintext secrets from the time before encryption (silent upgrade)
        — and first check that the key matches the already encrypted ones. If it does not,
        `ConfigError`: a start with the wrong key would otherwise let every TOTP sign-in fail
        silently. Returns how many were upgraded."""
        from .errors import ConfigError
        if self.vault is None:
            return 0
        # Both tables with encrypted data: if there are only refresh tokens (OIDC instance without TOTP),
        # a wrong key would otherwise start — and every request with an old cookie ended in a 500.
        probe = self._one("SELECT secret AS wert FROM totp_cred WHERE secret LIKE 'v1:%' "
                          "UNION ALL SELECT refresh FROM oidc_sitzung WHERE refresh LIKE 'v1:%' LIMIT 1")
        if probe is not None:
            try:
                self.vault.decrypt(probe["wert"])
            except Exception:
                raise ConfigError(
                    "The key does not match the stored secrets (TOTP/OIDC; wrong "
                    "TINYSESAM_SECRETS_KEY/secrets_key_file, or the key file next to the "
                    "database is missing or a different one). Use the right key — without it "
                    "all accounts have to set up TOTP again.") from None
        clear = self._all("SELECT user_id, secret FROM totp_cred WHERE secret NOT LIKE 'v1:%'")
        for z in clear:
            self._exec("UPDATE totp_cred SET secret=? WHERE user_id=? AND secret=?",
                       (self.vault.encrypt(z["secret"]), z["user_id"], z["secret"]))
        if clear:
            logging.getLogger("tinysesam").info(
                "%d TOTP secret(s) encrypted (previously plaintext in the database).", len(clear))
        return len(clear)

    def delete_totp(self, user_id):
        self._exec("DELETE FROM totp_cred WHERE user_id=?", (user_id,))

    def has_confirmed_totp(self, user_id) -> bool:
        r = self.get_totp(user_id)
        return bool(r and r["confirmed"])

    # ---------- Recovery codes ----------
    def delete_recovery_codes(self, user_id):
        self._exec("DELETE FROM recovery_code WHERE user_id=?", (user_id,))

    def add_recovery_codes(self, user_id, hashes):
        now = _now()
        with self._writing():
            self.db.executemany("INSERT INTO recovery_code(user_id, code_hash, created_at) VALUES (?,?,?)",
                                [(user_id, h, now) for h in hashes])
            self.db.commit()

    def consume_recovery_code(self, user_id, code_hash) -> bool:
        """Invalidate an unused code atomically. True only on the first valid redemption."""
        with self._writing():
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

    # ---------- OIDC link ----------
    def link_oidc(self, issuer, subject, user_id):
        self._exec("INSERT OR REPLACE INTO oidc_identity(issuer, subject, user_id) VALUES (?,?,?)",
                   (issuer, subject, user_id))

    # ---------- First login and enrollment window (R3-1) ----------
    def mark_first_login(self, user_id: int, now: int) -> bool:
        """Record the first complete login — only the first time (idempotent).

        Return value: True if this call set it. The condition is in the SQL, not
        before it: two simultaneous sign-ins of the same account (two devices, two workers)
        would otherwise both read, both write, and the time would be the later one."""
        return self._exec("UPDATE users SET first_login_at=? WHERE id=? AND first_login_at IS NULL",
                          (now, user_id)).rowcount > 0

    def set_mfa_enroll_until(self, user_id: int, until: Optional[int]) -> None:
        """Open the enrollment window (timestamp) or close it (None)."""
        self._exec("UPDATE users SET mfa_enroll_until=? WHERE id=?", (until, user_id))

    def is_oidc_account(self, user_id) -> bool:
        """Is this account bound to an OIDC identity (finding 8)?"""
        return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? LIMIT 1", (user_id,)))

    def confirm_idp(self, user_id, asked_at: Optional[int] = None) -> bool:
        """The provider has confirmed the account (login via it, refresh exchange with yes).

        `asked_at` is the time at which the question to the provider WENT OUT. A no that was
        recorded after that stays: two exchanges run in parallel (two sessions,
        two clients), and a yes that was answered before the lock but applied after the no
        would otherwise wake the keys of a locked account (attack on the third round).
        Return value: whether anything was written."""
        now = _now()
        asked = int(asked_at if asked_at is not None else now)
        return self._exec(
            "UPDATE users SET idp_bestaetigt_at=? WHERE id=? AND (idp_bestaetigt_at IS NULL "
            "OR idp_bestaetigt_at > 0 OR -idp_bestaetigt_at < ?)", (now, user_id, asked)).rowcount > 0

    def idp_refused(self, user_id) -> None:
        """The provider said no: the API keys of the account are dormant until the next
        confirmation (finding 8). Stored as a NEGATIVE time of the no — NULL means "never
        confirmed", ≤ 0 "refused", and the time decides whether a later-applied yes
        is younger (`confirm_idp`)."""
        self._exec("UPDATE users SET idp_bestaetigt_at=? WHERE id=?", (-max(_now(), 1), user_id))

    def oidc_session_handle(self, client, old_encrypted) -> Optional[str]:
        """TODAY's handle of the session whose row carries this (encrypted) token."""
        r = self._one("SELECT token_hash FROM oidc_sitzung WHERE client=? AND refresh=?",
                      (client, old_encrypted))
        return r["token_hash"] if r else None

    def discard_oidc_session(self, handle, client) -> None:
        """Discard an OIDC row without a configured client — the session itself stays."""
        self._exec("DELETE FROM oidc_sitzung WHERE token_hash=? AND client=?", (self._handle(handle), client))

    def get_oidc_user(self, issuer, subject) -> Optional[int]:
        r = self._one("SELECT user_id FROM oidc_identity WHERE issuer=? AND subject=?", (issuer, subject))
        return r["user_id"] if r else None

    # ---------- Federated identities via a stable identifier (F-11) ----------
    def link_federated(self, source: str, identifier: str, user_id: int, now: int) -> None:
        """Bind a foreign identity to a local account (or renew the binding)."""
        self._exec("INSERT OR REPLACE INTO federated_identity(quelle, kennung, user_id, gebunden_at)"
                   " VALUES (?,?,?,?)", (source, identifier, user_id, now))

    def get_federated_user(self, source: str, identifier: str) -> Optional[int]:
        r = self._one("SELECT user_id FROM federated_identity WHERE quelle=? AND kennung=?",
                      (source, identifier))
        return r["user_id"] if r else None

    def get_federated_identifier(self, source: str, user_id: int) -> Optional[str]:
        """The identifier with which this account is bound for this source — None if none.

        The way back is the actual bolt: if an account already carries an identifier, it must
        **not** be bound to a second one. That is exactly what would happen if a deleted account
        were recreated under the same name in the directory."""
        r = self._one("SELECT kennung FROM federated_identity WHERE quelle=? AND user_id=?",
                      (source, user_id))
        return r["kennung"] if r else None

    def has_foreign_identity(self, user_id: int) -> bool:
        """Is this account bound to any foreign identity (OIDC, LDAP, SAML)?"""
        return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? "
                              "UNION ALL SELECT 1 FROM federated_identity WHERE user_id=? LIMIT 1",
                              (user_id, user_id)))

    def unlink_federated(self, source: str, user_id: int) -> int:
        """Release the binding of an account for a source (operator path after a move)."""
        return self._exec("DELETE FROM federated_identity WHERE quelle=? AND user_id=?",
                          (source, user_id)).rowcount

    #: Prefix of the origin placeholders in `federated_identity.kennung` (see `TinySesam._WITHOUT_IDENTIFIER`).
    WITHOUT_IDENTIFIER = "~ohne-kennung:"

    def rebind(self, source: str, identifier: str, user_id: int, now: int) -> bool:
        """Bind an account to an identifier that belongs to nobody yet — or do nothing (G1).

        For the binding of existing accounts (`TinySesam.federation_bind_existing`), which runs through a whole
        directory between check and write. `link_federated` replaces a row with
        the same identifier (`INSERT OR REPLACE`) — here that would take its binding away from an account that has
        meanwhile signed in. Hence in ONE transaction: if the identifier already belongs
        to an account or this account already carries a real identifier, everything stays as it is
        (`False`). Otherwise an origin placeholder yields, the binding is created, and an open
        name binding (`namensbindung`) is done."""
        with self._writing():
            occupied = self.db.execute(
                "SELECT 1 FROM federated_identity WHERE quelle=? AND (kennung=? OR "
                "(user_id=? AND substr(kennung, 1, ?) <> ?)) LIMIT 1",
                (source, identifier, user_id, len(self.WITHOUT_IDENTIFIER), self.WITHOUT_IDENTIFIER)).fetchone()
            if occupied is not None:
                return False
            self.db.execute("DELETE FROM federated_identity WHERE quelle=? AND user_id=?", (source, user_id))
            self.db.execute("INSERT INTO federated_identity(quelle, kennung, user_id, gebunden_at) "
                            "VALUES (?,?,?,?)", (source, identifier, user_id, now))
            self.db.execute("DELETE FROM namensbindung WHERE quelle=? AND user_id=?", (source, user_id))
            self.db.commit()
            self._written = time.monotonic()
            self._clock_record()
        return True

    def without_binding(self, source: str) -> list:
        """The accounts without a real identifier for this source — no row or only the
        origin placeholder —, excluding service accounts (G1). With `has_password` (local password)."""
        return self._all(
            "SELECT u.*, EXISTS (SELECT 1 FROM password_cred p WHERE p.user_id = u.id) AS has_password "
            "FROM users u WHERE u.is_service = 0 AND NOT EXISTS (SELECT 1 FROM federated_identity f "
            "WHERE f.quelle = ? AND f.user_id = u.id AND substr(f.kennung, 1, ?) <> ?) ORDER BY u.id",
            (source, len(self.WITHOUT_IDENTIFIER), self.WITHOUT_IDENTIFIER))

    def open_name_binding(self, source: str, user_id: int, until: int) -> None:
        """Open the binding via the name for this account until `bis` (G1, `federation_unbind`)."""
        self._exec("INSERT OR REPLACE INTO namensbindung(quelle, user_id, bis) VALUES (?,?,?)",
                   (source, user_id, int(until)))

    def name_binding_unclosed(self, source: str, user_id: int, now: int) -> bool:
        """Has the operator opened the binding via the name for this account (and is it still running)?"""
        return self._one("SELECT 1 AS x FROM namensbindung WHERE quelle=? AND user_id=? AND bis > ?",
                         (source, user_id, int(now))) is not None

    def name_binding_close(self, source: str, user_id: int) -> None:
        """The opened binding via the name is done (the binding stands)."""
        self._exec("DELETE FROM namensbindung WHERE quelle=? AND user_id=?", (source, user_id))

    def federation_since(self, source: str, now: int) -> int:
        """The marker of a federated source (`foederation_seit:<quelle>`): from when the deadline for
        the binding via the name runs (G1). Set to `now` on the first call, never
        again afterwards — a marker that were set anew on every start would give every restart a
        new deadline. `INSERT OR IGNORE`: if several workers start at the same time, the first wins, and
        all afterwards read the same value."""
        key_name = f"foederation_seit:{source}"
        z = self._one("SELECT value FROM setting WHERE key=?", (key_name,))
        if z is None:
            self._exec("INSERT OR IGNORE INTO setting(key, value) VALUES (?,?)", (key_name, str(int(now))))
            z = self._one("SELECT value FROM setting WHERE key=?", (key_name,))
        return int(z["value"])

    # ---------- Approvals per application (T-14) ----------
    # The key is the **hash** of the session, not the plaintext — the same rule as in
    # `session`: whoever reads the file thereby gets no session that can be taken over.
    def set_oidc_session(self, handle, client, sub, refresh, client_id: Optional[str] = None) -> None:
        """Store the refresh token of an OIDC session for THIS client — encrypted (4a).

        One row per client: with several applications, a later login via another
        client must not overwrite the re-check of the first — otherwise the user would choose
        which provider entry is still re-checked (attack on the second round, finding 7)."""
        if self.vault is None:
            raise RuntimeError("Refresh tokens are only stored encrypted (vault.Vault).")
        self._exec("INSERT INTO oidc_sitzung(token_hash, client, sub, refresh, geprueft_at, client_id, erfolg_at) "
                   "VALUES (?,?,?,?,?,?,?) ON CONFLICT(token_hash, client) DO UPDATE SET sub=excluded.sub, "
                   "refresh=excluded.refresh, geprueft_at=excluded.geprueft_at, client_id=excluded.client_id, "
                   "erfolg_at=excluded.erfolg_at",
                   (self._handle(handle), client, sub, self.vault.encrypt(refresh), _now(), client_id,
                    _now()))

    def get_oidc_sessions(self, handle) -> list:
        """The OIDC rows of a session — the refresh token ENCRYPTED (it is decrypted
        only when exchanging; a request before the deadline expires does not touch the key)."""
        return [dict(z) for z in self._all("SELECT * FROM oidc_sitzung WHERE token_hash=?",
                                          (self._handle(handle),))]

    def get_oidc_session(self, handle, client="*") -> Optional[dict]:
        """One OIDC row, with the refresh token decrypted, or None (for tools and tests)."""
        z = self._one("SELECT * FROM oidc_sitzung WHERE token_hash=? AND client=?", (self._handle(handle), client))
        if z is None:
            return None
        d = dict(z)
        if self.vault is not None:
            d["refresh"] = self.vault.decrypt(d["refresh"])
        return d

    def claim_oidc_session(self, handle, client, old: int, now: int) -> bool:
        """Claim the due exchange for EXACTLY one request: `geprueft_at` from `old` to
        `now`, only if it is still `old`. Several simultaneous requests (also across workers) —
        only one exchanges. Otherwise all would exchange the same refresh token, and a provider with
        token rotation rejected the second exchange: the session ended for no reason (finding 5)."""
        return self._exec("UPDATE oidc_sitzung SET geprueft_at=? WHERE token_hash=? AND client=? "
                          "AND geprueft_at=?", (int(now), self._handle(handle), client, int(old))).rowcount == 1

    def oidc_session_checked(self, handle, client, when: int, new_refresh=None,
                              old_encrypted: Optional[str] = None, success: bool = False) -> bool:
        """Record the exchange; a newly issued refresh token replaces the old one (rotation).
        Return value: whether the row was still there (the session may have ended meanwhile).

        With `old_encrypted` (the stored, encrypted token with which the exchange was
        made) the row is found through it instead of through the handle: if the session gets a new token
        during the exchange (step-up, completion of a factor), the row hangs on the new
        handle — the old one would hit nothing, and the refresh token rotated by the provider would be
        lost; the next exchange with the old one would be a no at PocketID. The ciphertext is
        unique through its nonce."""
        where, value = ("refresh=?", old_encrypted) if old_encrypted else ("token_hash=?", self._handle(handle))
        # `success`: the provider has just said yes — state for the upper limit without a re-check.
        # `geprueft_at` alone is not suitable for that: after an "error" it stands at "in a minute".
        extra = ", erfolg_at=?" if success else ""
        success_value = (int(when),) if success else ()
        if new_refresh and self.vault is not None:
            return self._exec(f"UPDATE oidc_sitzung SET geprueft_at=?, refresh=?{extra} WHERE {where} AND client=?",
                              (int(when), self.vault.encrypt(new_refresh), *success_value, value,
                               client)).rowcount > 0
        return self._exec(f"UPDATE oidc_sitzung SET geprueft_at=?{extra} WHERE {where} AND client=?",
                          (int(when), *success_value, value, client)).rowcount > 0

    def move_oidc_session(self, old, new) -> None:
        """Attach the OIDC rows to a new session (new token at the completion of the chain) —
        BEFORE deleting the old ones, otherwise the foreign key would take them along."""
        self._exec("UPDATE oidc_sitzung SET token_hash=? WHERE token_hash=?",
                   (self._handle(new), self._handle(old)))

    # ---------- Gate: signed out of one application only (T-22) ----------
    def gate_sign_out(self, handle, host: str) -> None:
        self._exec("INSERT OR REPLACE INTO gate_abgemeldet(token_hash, host, at) VALUES (?,?,?)",
                   (self._handle(handle), str(host).lower(), _now()))

    def gate_is_signed_out(self, handle, host: str) -> bool:
        return bool(self._one("SELECT 1 FROM gate_abgemeldet WHERE token_hash=? AND host=?",
                              (self._handle(handle), str(host).lower())))

    def gate_resume(self, handle, host: str) -> int:
        return self._exec("DELETE FROM gate_abgemeldet WHERE token_hash=? AND host=?",
                          (self._handle(handle), str(host).lower())).rowcount

    # ---------- Connection of an app host to the central session (T-26) ----------
    def create_gate_link(self, link_hash: str, handle, host: str) -> None:
        self._exec("INSERT INTO gate_link(link_hash, token_hash, host, created_at) VALUES (?,?,?,?)",
                   (link_hash, self._handle(handle), str(host).lower(), _now()))

    def gate_link_handle(self, link_hash: str, host: str) -> Optional[str]:
        """The session handle behind this connection — only for ITS host, otherwise None."""
        r = self._one("SELECT token_hash FROM gate_link WHERE link_hash=? AND host=?", (link_hash, str(host).lower()))
        return r["token_hash"] if r else None

    def remove_gate_link(self, link_hash: str) -> int:
        return self._exec("DELETE FROM gate_link WHERE link_hash=?", (link_hash,)).rowcount

    # ---------- ID token as a sign-out hint (T-22) ----------
    def set_oidc_id_token(self, handle, client: str, id_token: str) -> None:
        if self.vault is None:
            raise RuntimeError("ID tokens are only stored encrypted (vault.Vault).")
        self._exec("INSERT OR REPLACE INTO oidc_id_token(token_hash, client, id_token) VALUES (?,?,?)",
                   (self._handle(handle), client, self.vault.encrypt(id_token)))

    def get_oidc_id_token(self, handle) -> Optional[tuple]:
        """(client, id_token) of this session's sign-in, decrypted — or None."""
        r = self._one("SELECT client, id_token FROM oidc_id_token WHERE token_hash=?", (self._handle(handle),))
        if not r or self.vault is None:
            return None
        return r["client"], self.vault.decrypt(r["id_token"])

    def put_oidc_grant(self, token_hash: str, client: str, now: int, roles=None) -> None:
        """Enter or confirm an approval. `granted_at` stays on a confirmation —
        otherwise nobody could answer the question "since when may this session enter this application"."""
        self._exec(
            "INSERT INTO oidc_grant(token_hash, client, granted_at, checked_at, roles) VALUES (?,?,?,?,?)"
            " ON CONFLICT(token_hash, client) DO UPDATE SET checked_at=excluded.checked_at,"
            " roles=excluded.roles",
            (token_hash, client, now, now, json.dumps(list(roles or []))))

    def get_oidc_grant(self, token_hash: str, client: str) -> Optional[dict]:
        r = self._one("SELECT * FROM oidc_grant WHERE token_hash=? AND client=?", (token_hash, client))
        if not r:
            return None
        d = dict(r)
        try:
            d["roles"] = json.loads(d.get("roles") or "[]")
        except Exception:
            d["roles"] = []
        return d

    def list_oidc_grants(self, token_hash: str) -> list:
        return [dict(r) for r in self._all(
            "SELECT client, granted_at, checked_at FROM oidc_grant WHERE token_hash=?"
            " ORDER BY granted_at", (token_hash,))]

    def drop_oidc_grant(self, token_hash: str, client: str) -> int:
        """Withdraw an approval. Exactly one — the session and the other applications stay;
        that is the difference between "the provider says no to this app" and "sign out"."""
        return self._exec("DELETE FROM oidc_grant WHERE token_hash=? AND client=?",
                          (token_hash, client)).rowcount

    def drop_oidc_grants_for_user(self, user_id: int, client: Optional[str] = None) -> int:
        """Withdraw all approvals of an account (optionally only for one application). The way for
        the operator when the provider has excluded someone and it should take effect immediately,
        without ending the session itself."""
        if client is None:
            return self._exec(
                "DELETE FROM oidc_grant WHERE token_hash IN (SELECT token_hash FROM session WHERE user_id=?)",
                (user_id,)).rowcount
        return self._exec(
            "DELETE FROM oidc_grant WHERE client=? AND token_hash IN"
            " (SELECT token_hash FROM session WHERE user_id=?)", (client, user_id)).rowcount

    # ---------- Sessions ----------
    # What is stored is the sha256 of the token, never the token itself. Everything that comes from a
    # session row (`row["token_hash"]`) is therefore a handle: it names a session
    # and is no good for signing in. The plaintext lives between `create_session()` and the cookie.
    @staticmethod
    def session_hash(token: str) -> str:
        return hashlib.sha256((token or "").encode()).hexdigest()

    def create_session(self, user_id, ttl_seconds, mfa_ok, method, ip=None, ua=None, remember=True,
                       factors=None) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        self._exec("INSERT INTO session(token_hash, user_id, created_at, expires_at, mfa_ok, mfa_at, "
                   "method, factors_done, remember, ip, user_agent, zuletzt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (self.session_hash(token), user_id, now, now + ttl_seconds, 1 if mfa_ok else 0,
                    (now if mfa_ok else None), method, json.dumps(list(factors or [])),
                    1 if remember else 0, ip, ua, now))
        return token

    #: Inactivity limits in seconds (without / with "stay signed in"), 0 = off. Set by the
    #: manager from the configuration (F-05); the store alone knows none.
    idle_sec = (0, 0)
    #: How often `zuletzt` is written at most: writing on every request would mean that every
    #: forward-auth call locks the file. A minute of fuzziness is nothing for limits of hours.
    IDLE_STEP_SEC = 60

    @staticmethod
    def _handle(value) -> str:
        """A handle is a sha256 hex digest. Whoever passes in a plaintext token by mistake
        gets an error — otherwise the UPDATE would hit nothing and the session
        would silently keep its old state (a second factor that does not arrive is noticed by nobody
        until it is missing)."""
        h = str(value or "")
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError("Session handle expected (token_hash from the session row), "
                             f"not a plaintext token: {h[:12]!r}…")
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
        return self.get_session_by_handle(self.session_hash(token))

    def get_session_by_handle(self, handle) -> Optional[sqlite3.Row]:
        """Like `get_session`, but via the handle (`token_hash`) — for paths that do not know the session
        from their own cookie (the connection of an app host, T-26). The same checks:
        expiry, inactivity, updating `zuletzt`."""
        h = str(handle or "")
        if len(h) != 64:
            return None
        r = self._one("SELECT * FROM session WHERE token_hash=?", (h,))
        if not r:
            return None
        now = _now()
        if r["expires_at"] < now:
            self.delete_session_by_handle(h)
            return None
        # Inactivity (F-05): in addition to the absolute lifetime. An expired session is
        # deleted, not only rejected — otherwise it would come back to life with the next access.
        # The long limit only if someone EXPLICITLY chose "stay signed in". A
        # session that is permanent only because the path knows no choice (OIDC, passkey,
        # sign-in link) or the checkbox is switched off would otherwise never get an idle end
        # (attack on the second round, finding 9).
        limit = self.idle_sec[1 if (r["remember"] and r["bleiben_gewaehlt"]) else 0]
        last = r["zuletzt"] if r["zuletzt"] is not None else r["created_at"]
        if limit and now - int(last) > limit:
            self.delete_session_by_handle(h)
            return None
        if now - int(last) >= self.IDLE_STEP_SEC:
            self._exec("UPDATE session SET zuletzt=? WHERE token_hash=?", (now, r["token_hash"]))
        return r

    def set_session_stay(self, handle):
        """Record: "stay signed in" was explicitly chosen (F-05)."""
        self._exec("UPDATE session SET bleiben_gewaehlt=1 WHERE token_hash=?", (self._handle(handle),))

    def set_session_end_others(self, handle):
        """Record: if this (half) session becomes full, the account's other ones end (limit d)."""
        self._exec("UPDATE session SET andere_beenden=1 WHERE token_hash=?", (self._handle(handle),))

    def set_session_mfa(self, handle, ok=True):
        self._exec("UPDATE session SET mfa_ok=?, mfa_at=? WHERE token_hash=?",
                   (1 if ok else 0, (_now() if ok else None), self._handle(handle)))

    def delete_session(self, token):
        """Plaintext token (from the cookie) — for logout."""
        self._exec("DELETE FROM session WHERE token_hash=?", (self.session_hash(token),))

    def delete_session_by_handle(self, handle):
        """Handle from a session row — for the admin panel and "end other sessions"."""
        h = self._handle(handle)
        # A superseded token in the grace period (A-6) belongs to this session and goes with it.
        self._exec("DELETE FROM session WHERE token_hash=? OR nachfolger=?", (h, h))

    def rotate_session(self, handle, mercy_sec: int = 0) -> Optional[str]:
        """Give the session a new token without otherwise changing it (F-06).

        Lifetime, factors and `created_at` stay — a step-up is meant to renew the token, not
        extend the absolute lifetime. The OIDC approvals hang on the handle by foreign key
        and move along; hence a new row, re-attach the approvals, delete the old row, all
        in one transaction. Returns the new plaintext token, or None if the
        session does not (any longer) exist.

        `mercy_sec` (A-6, PO decision 2026-09-25): the old token then remains valid for that many
        seconds — a request that was already under way at the moment of the step-up (second tab,
        background loading) would otherwise fail once. It then applies WITHOUT step-up freshness (`mfa_at`
        empty): whoever read along the old token gets no freshly confirmed rights, only
        the deadline. It points to its successor and ends with it (`delete_session_by_handle`).
        An already superseded token is not rotated again."""
        old = self._handle(handle)
        token = secrets.token_urlsafe(32)
        new = self.session_hash(token)
        columns = ("user_id, created_at, expires_at, mfa_ok, mfa_at, method, factors_done, "
                   "remember, ip, user_agent, zuletzt, bleiben_gewaehlt")
        with self._lock:
            try:
                cur = self.db.execute(
                    f"INSERT INTO session(token_hash, {columns}) SELECT ?, {columns} FROM session "
                    "WHERE token_hash=? AND nachfolger IS NULL", (new, old))
                if cur.rowcount != 1:
                    self.db.rollback()
                    return None
                self.db.execute("UPDATE oidc_grant SET token_hash=? WHERE token_hash=?", (new, old))
                self.db.execute("UPDATE oidc_sitzung SET token_hash=? WHERE token_hash=?", (new, old))
                self.db.execute("UPDATE gate_abgemeldet SET token_hash=? WHERE token_hash=?", (new, old))
                self.db.execute("UPDATE oidc_id_token SET token_hash=? WHERE token_hash=?", (new, old))
                self.db.execute("UPDATE gate_link SET token_hash=? WHERE token_hash=?", (new, old))
                if mercy_sec > 0:
                    self.db.execute("UPDATE session SET expires_at=MIN(expires_at, ?), mfa_at=NULL, "
                                    "nachfolger=? WHERE token_hash=?", (_now() + int(mercy_sec), new, old))
                    # An earlier predecessor that points to the old token now points to the new one —
                    # otherwise it would survive a sign-out of the new session.
                    self.db.execute("UPDATE session SET nachfolger=? WHERE nachfolger=?", (new, old))
                else:
                    self.db.execute("DELETE FROM session WHERE token_hash=?", (old,))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        return token

    def delete_user_sessions(self, user_id):
        self._exec("DELETE FROM session WHERE user_id=?", (user_id,))

    def delete_user_sessions_except(self, user_id, keep_handle):
        """End all sessions of a user EXCEPT one (e.g. the current one on a self password change).

        `keep_handle` is the `token_hash` from the session row, not the cookie."""
        self._exec("DELETE FROM session WHERE user_id=? AND token_hash!=?", (user_id, keep_handle or ""))

    def consume_totp_step(self, user_id, step: int) -> bool:
        """Book a TOTP time step as consumed. True if it was still free.

        The comparison and the write sit in ONE `UPDATE … WHERE`: two simultaneous
        requests with the same code cannot both win this way — SQLite serialises the
        writers, and the second hits no row any more.
        """
        cur = self._exec(
            "UPDATE totp_cred SET last_step=? WHERE user_id=? AND (last_step IS NULL OR last_step < ?)",
            (int(step), user_id, int(step)))
        return cur.rowcount == 1

    def gc_sessions(self) -> int:
        return self._exec("DELETE FROM session WHERE expires_at < ?", (_now(),)).rowcount

    @classmethod
    def secure_file(cls, source: str, destination: str) -> str:
        """Back up a database file WITHOUT touching it — the path for `tinysesam backup`.

        Why not simply `Store(quelle).backup(destination)`: the constructor sets
        `PRAGMA journal_mode=WAL`, creates missing tables and runs `_migrate()`. It
        **writes**, and does so before anything has been copied. Whoever does the
        only right thing before an update and makes a backup would thereby have lifted the running installation to the new
        schema while the old code is still running — the way back would be closed, and a file
        in the old schema would then exist nowhere. The safety net would have destroyed what it is meant to
        protect.

        That is why there is a separate connection in `ro` mode here: it does not migrate, creates nothing
        and needs no writable directory. The online backup API still reads
        a consistent state including WAL through it.
        """
        if not os.path.exists(source):
            raise FileNotFoundError(source)
        if not os.path.exists(destination):
            try:
                os.close(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, cls.FILE_PERMISSIONS))
            except OSError:
                pass  # created meanwhile or cannot be created — chmod below sets the permissions
        source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        destination_db = sqlite3.connect(destination)
        try:
            source_db.backup(destination_db)
        finally:
            destination_db.close()
            source_db.close()
        for attachment in ("", "-wal", "-shm"):
            try:
                if os.path.exists(destination + attachment):
                    os.chmod(destination + attachment, cls.FILE_PERMISSIONS)
            except OSError:
                pass  # permissions cannot be set (foreign file system) — the copy itself is complete
        return destination

    def backup(self, destination: str) -> str:
        """Write a consistent copy of the database, during operation.

        **A file copy is no good.** The database runs in WAL mode: everything since the
        last checkpoint is in `…-wal`, not in the `.db`. Whoever copies only the `.db` (cp,
        rsync, a backup agent that knows patterns) gets a torso — measured: a fresh
        instance with five accounts yielded a copy without even the table `users`. The error
        is noticed only on restoring.

        Here SQLite's online backup runs: it takes the locks it needs, pulls in the WAL and
        delivers a file that is correct on its own. The copy gets the same narrow permissions
        as the original — a backup with password hashes deserves as much protection as the source.
        """
        if not os.path.exists(destination):
            try:
                os.close(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.FILE_PERMISSIONS))
            except OSError:
                pass  # created meanwhile or cannot be created — chmod below sets the permissions
        destination_db = sqlite3.connect(destination)
        try:
            with self._lock:
                self.db.backup(destination_db)
        finally:
            destination_db.close()
        for attachment in ("", "-wal", "-shm"):
            try:
                if os.path.exists(destination + attachment):
                    os.chmod(destination + attachment, self.FILE_PERMISSIONS)
            except OSError:
                pass  # permissions cannot be set (foreign file system) — the copy itself is complete
        return destination

    def gc_flow(self) -> int:
        return self._exec("DELETE FROM flow WHERE expires_at < ?", (_now(),)).rowcount

    def list_sessions(self, user_id=None):
        # Superseded tokens in the grace period (A-6) are not a session of their own.
        if user_id is not None:
            return self._all("SELECT * FROM session WHERE user_id=? AND nachfolger IS NULL "
                             "ORDER BY created_at DESC", (user_id,))
        return self._all("SELECT * FROM session WHERE nachfolger IS NULL ORDER BY created_at DESC")

    # ---------- Flow state (OIDC / WebAuthn, short-lived, one-shot) ----------
    def put_flow(self, key, data: dict, ttl=600):
        self._exec("INSERT OR REPLACE INTO flow(key, data, expires_at) VALUES (?,?,?)",
                   (key, json.dumps(data), _now() + ttl))

    def pop_flow(self, key) -> Optional[dict]:
        """Hand out flow state exactly ONCE (WebAuthn challenge, OIDC `state`/`nonce`).

        Reading and deleting were two separate steps, each with its own lock (R3-8): two
        simultaneous callbacks with the same `state` — two threads, or two workers on
        the same file — both read the row before one deleted it, and both got the
        challenge. Now the `DELETE` decides: only whoever actually removed the row
        (`rowcount == 1`) gets the content. SQLite serialises the writers, also across
        process boundaries — `RETURNING` would be more elegant but requires SQLite ≥ 3.35."""
        with self._writing():
            r = self.db.execute("SELECT data, expires_at FROM flow WHERE key=?", (key,)).fetchone()
            if not r:
                return None
            away = self.db.execute("DELETE FROM flow WHERE key=?", (key,)).rowcount
            self.db.commit()
        if away != 1:
            return None                 # another caller consumed it first
        if r["expires_at"] < _now():
            return None
        try:
            return json.loads(r["data"])
        except Exception:
            return None

    def count_argon2_hashes(self) -> int:
        """How many stored password/PIN/scope hashes are argon2? (B6-8)"""
        n = 0
        for table in ("password_cred", "pin_cred", "resource_secret"):
            r = self._one(f"SELECT COUNT(*) AS n FROM {table} WHERE hash LIKE '$argon2%'")
            n += int(r["n"] or 0) if r else 0
        return n

    #: How long a successful commit counts as proof that the database is writable
    #: (seconds). Within this period `write_probe()` only checks the connection.
    WRITE_PROBE_SEC = 5

    def write_probe(self) -> None:
        """A real write transaction — the core of the health check (B6-4).

        A `SELECT 1` also succeeds on a database that has become read-only (read-only
        mount, wrong permissions after a restore, `SQLITE_READONLY`) or whose volume is full
        (`SQLITE_FULL`) — exactly where every sign-in fails at its first `INSERT INTO
        session`. Healthy is therefore only reported once a commit goes through.
        Raises the sqlite3 exception unchanged; what of it reaches the outside is decided by the
        caller.

        What is written is the clock state (`uhr_stand`) — so the health check also saves it
        on the side, in times when nothing else is written. But at most every
        `WRITE_PROBE_SEC`: `/healthz` is reachable without sign-in, and one commit
        with fsync under `_lock` per call would mean that whoever floods it occupies the write lock that
        sign-ins wait for, and wears out SD cards. If the last successful commit (also
        a foreign one via `_exec`) is more recent than that, a read access suffices — a closed or
        vanished connection is still noticed immediately, a change to "read-only" at the latest
        after `WRITE_PROBE_SEC`."""
        with self._writing():
            m = time.monotonic()
            if self._fresh(self._written, m, self.WRITE_PROBE_SEC):
                self.db.execute("SELECT 1").fetchone()
                return
            self._write_clock_state()
            self.db.commit()
            self._written = self._clock_secured = m

    # ---------- Runtime settings (editable in the panel) ----------
    def get_setting(self, key) -> Optional[str]:
        r = self._one("SELECT value FROM setting WHERE key=?", (key,))
        return r["value"] if r else None

    def set_setting(self, key, value):
        self._exec("INSERT OR REPLACE INTO setting(key, value) VALUES (?,?)", (key, str(value)))

    def all_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self._all("SELECT key, value FROM setting")}

    # ---------- Brute-force regulation ----------
    def record_attempt(self, username, ip, success, method):
        self._exec("INSERT INTO login_attempt(ts, username, ip, success, method) VALUES (?,?,?,?,?)",
                   (_now(), username, ip, 1 if success else 0, method))

    #: How long a pre-booking with an open outcome (`reserve_attempt(hover=True)`) counts as
    #: pending, not as a failed attempt (seconds, G9). Longer than any directory query up to
    #: its timeout (`ldap_.CONNECTION_TIMEOUT`, connection setup and bind once each) including
    #: compute time. An older open row has been completed by nobody — the process has died
    #: or is hanging; it then counts as a failed attempt, when in doubt the stricter reading.
    PREBOOKING_PENDING_SEC = 30

    def _fails_query(self, since, username=None, ip=None, method=None, exclude_methods=None,
                       from_id=None, only_confirmed=False, except_username=None):
        """The counting query for `count_fails` and `reserve_attempt` — one rule, two callers.
        `from_id`: only rows with a larger id (watermark of an identifier, G2).
        `only_confirmed`: without the pending pre-bookings (G9, `PREBOOKING_PENDING_SEC`)."""
        q = "SELECT COUNT(*) c FROM login_attempt WHERE success=0 AND ts>=?"
        args = [since]
        if only_confirmed:
            q += " AND (offen=0 OR ts<?)"
            args.append(_now() - self.PREBOOKING_PENDING_SEC)
        if from_id is not None:
            q += " AND id>?"
            args.append(int(from_id))
        if username:
            q += " AND username=? COLLATE NOCASE"
            args.append(username)
        if ip:
            q += " AND ip=?"
            args.append(ip)
        if except_username:
            q += " AND username<>? COLLATE NOCASE"
            args.append(except_username)
        if method:
            q += " AND method=?"
            args.append(method)
        if exclude_methods:
            place = ",".join("?" for _ in exclude_methods)
            q += f" AND (method IS NULL OR method NOT IN ({place}))"
            args.extend(exclude_methods)
        return q, args

    def count_fails(self, since, username=None, ip=None, method=None, exclude_methods=None,
                    from_id=None, only_confirmed=False, except_username=None) -> int:
        """Count failed attempts in the window — optionally only ONE method, or all EXCEPT some.

        `exclude_methods` is the counterpart of `method`: the login lockout wants to count everything
        that was a sign-in attempt — but not the old-password query of the account page, which lies in
        the same table (see `security.NOT_LOGIN_METHODS`). A row without a method
        (`NULL`, conceivable from old data) still counts: when in doubt, lock more strictly.

        Default: a pending pre-booking (`reserve_attempt(hover=True)`) counts — it
        CAN become a failed attempt. `only_confirmed=True` leaves it out (G9).
        """
        if not username and not ip:
            return 0
        q, args = self._fails_query(since, username, ip, method, exclude_methods, from_id,
                                      only_confirmed, except_username)
        return self._one(q, args)["c"]

    def reserve_attempt(self, username, ip, method, rules, series=None, hover=False) -> tuple:
        """Check lockouts and pre-book the attempt **in the same transaction** as a failed attempt.

        `rules` is a list `(grund, limit, filter)`; `filter` are the keywords of
        `count_fails`. Returns `(id, None)` — the attempt may proceed and already stands as a
        failed attempt in the table — or `(None, grund)` if a rule applies.

        Why in advance and why in one transaction (R3-2, R3-7, R7-2): previously the entire password
        check (argon2, dozens of milliseconds) lay between `_is_locked()` and `record_attempt()`.
        A parallel burst of N requests read the same counter state N times,
        "not locked yet", and could guess N times — the limit applied only to attackers who
        politely ask one after another. Now every attempt reserves its place before it checks,
        and `BEGIN IMMEDIATE` turns counting and booking into one step, also across several
        processes (`uvicorn --workers N`): the file's write lock orders them.
        If the attempt succeeds, `finish_attempt` turns the row into a success; a process
        that dies in between leaves a failed attempt — when in doubt, stricter.

        `series=(topf, art, limit)` also pre-books the series of consecutive failed attempts (B2-6) —
        in the SAME transaction. The first version read the series beforehand and counted it only after
        the check: a parallel burst at the limit read "not full yet" N times and could guess
        N times (measured: 15 instead of 1). Returns then `(id, series state)` after the booking —
        the SETTLED state (`_series_confirmed`, without pending pre-bookings). If it reaches
        the limit, exactly this booking triggered the lockout; a pending one never reaches it here,
        only at its completion (`finish_attempt`, audit round 2026-09-27, p2 F3).

        **Pending (G9).** `hover=True` books the attempt with an open outcome (`offen=1`): it
        can become a failed attempt or none at all (directory outage, F-23 — withdrawn
        only once the outage is reported, with a directory that drops packets, hence after
        the timeout). If a rule or the series applies **only** because of such rows, the
        answer is `(None, "pending")`: not decided yet, no lockout. The caller asks
        again after a short pause (`_begin_attempt`). Previously every rejection in this
        window was a lockout with `failed login` for fail2ban and a lockout notice to the holder — even
        if not a single failed attempt remained afterwards. The burst (R7-2) stays slowed down: it
        waits until the pre-bookings are decided and then gets the real lockout. If
        a rule applies with the confirmed rows alone, its reason applies as before; an open
        row older than `PREBOOKING_PENDING_SEC` counts as a failed attempt.
        """
        with self._lock:
            self._begin_immediate()
            try:
                state = None
                pending = False
                bucket_s, kind_s, limit_s = series if series is not None else (None, None, 0)
                if bucket_s and self._series_sum(bucket_s) >= limit_s:
                    if self._series_confirmed(bucket_s) >= limit_s:
                        self.db.execute("ROLLBACK")
                        return None, "lockout_series"
                    pending = True
                for reason, limit, filt in rules:
                    if not filt.get("username") and not filt.get("ip"):
                        continue
                    q, args = self._fails_query(**filt)
                    if self.db.execute(q, args).fetchone()["c"] < limit:
                        continue
                    # Does the rule apply — even without the pending pre-bookings? Then it is a
                    # lockout. Otherwise continue: a later rule may apply confirmed and takes precedence.
                    q, args = self._fails_query(**filt, only_confirmed=True)
                    if self.db.execute(q, args).fetchone()["c"] >= limit:
                        self.db.execute("ROLLBACK")
                        return None, reason
                    pending = True
                if pending:
                    self.db.execute("ROLLBACK")
                    return None, "pending"
                cur = self.db.execute(
                    "INSERT INTO login_attempt(ts, username, ip, success, method, offen) VALUES (?,?,?,0,?,?)",
                    (_now(), username, ip, method, 1 if hover else 0))
                if bucket_s:
                    self._series_plus(bucket_s, kind_s)
                    state = self._series_confirmed(bucket_s)
                self.db.execute("COMMIT")
                return cur.lastrowid, state
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def finish_attempt(self, attempt_id, success: bool, series=None) -> Optional[tuple]:
        """Complete an attempt pre-booked with `reserve_attempt`: success or failed attempt.

        Both end the pending state (`offen=0`, G9): a failed attempt counts from here also for
        `count_fails(only_confirmed=True)` — until then completing a failed attempt was a
        no-op. `series=(topf, art)` withdraws the pre-booking in the series on a success in the SAME
        transaction: separately it would stand in between neither as open nor as withdrawn,
        and whoever is waiting right now (`_begin_attempt`) would read the series one too high — at the
        limit a lockout with a lockout notice for nothing.

        With `series` it returns `(before, after)`: the settled state of the series
        (`_series_confirmed`) before and after the completion, both in one transaction
        (`BEGIN IMMEDIATE`, also across several processes). From that `_record_login` sees whether EXACTLY
        this completion crossed the limit (p2 F3). Until 2026-09-27 the state counted at
        booking: if in the meantime a full sign-in had ended the series, `lockout_series`
        stood in the log although nothing was locked. Without `series` None."""
        with self._writing():
            before = None
            if series:
                self._begin_immediate()
                before = self._series_confirmed(series[0])
            self.db.execute("UPDATE login_attempt SET success=?, offen=0 WHERE id=?",
                            (1 if success else 0, attempt_id))
            if success and series:
                self._series_minus(*series)
            state = (before, self._series_confirmed(series[0])) if series else None
            self.db.commit()
            self._written = time.monotonic()
            self._clock_record()
        return state

    def cancel_attempt(self, attempt_id, series=None):
        """Withdraw a pre-booked attempt — it was none (e.g. directory outage, F-23).

        `series=(topf, art)` withdraws its pre-booking in the series in the same transaction —
        for the same reason as in `finish_attempt` (G9)."""
        with self._writing():
            self.db.execute("DELETE FROM login_attempt WHERE id=? AND success=0", (attempt_id,))
            if series:
                self._series_minus(*series)
            self.db.commit()
            self._written = time.monotonic()
            self._clock_record()

    def clear_fails(self, username=None, ip=None, method=None, exclude_methods=None, since=None,
                    from_id=None):
        """Delete failed attempts — optionally only those of ONE method, or all EXCEPT some.

        `method` is not a nicety but the core: without it a successful
        password login also cleared the TOTP and PIN failed attempts. Whoever knew the password (leak,
        reuse, phishing) signed in correctly once before every guess and
        thereby reset the lockout for the SECOND factor — as often as they liked. The regulation
        that the panel advertises as hardening never applied to the second factor.

        `exclude_methods` clears everything except those named — the path after a COMPLETE
        sign-in, which does not concern the own buckets (account page, step-up, scope).

        `from_id` clears only rows from the watermark of the identifier (`identifier_limits`, G2): what
        arose only when the identifier already belonged to the account. `seit` is the fallback for
        existing data without a watermark (Unix seconds, the creation of the account, inclusive).
        """
        where: str = ""
        args_m: tuple = ()
        if method is not None:
            where, args_m = " AND method=?", (method,)
        elif exclude_methods:
            place = ",".join("?" for _ in exclude_methods)
            where, args_m = f" AND (method IS NULL OR method NOT IN ({place}))", tuple(exclude_methods)
        if since is not None:
            # Only from a point in time (limit a): a complete sign-in clears what applied to THIS
            # account — not the failed attempts under its name or address from before
            # its creation (those applied to nobody or to someone else).
            where, args_m = where + " AND ts >= ?", args_m + (int(since),)
        if from_id is not None:
            # More precise than `seit` (G2): from the joining of the identifier, not from creation — and to
            # the exact row, also in the second of joining.
            where, args_m = where + " AND id > ?", args_m + (int(from_id),)
        if username:
            self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE" + where,
                       (username,) + args_m)
        if ip:
            self._exec("DELETE FROM login_attempt WHERE ip=?" + where, (ip,) + args_m)

    def gc_attempts(self, older_than) -> int:
        return self._exec("DELETE FROM login_attempt WHERE ts < ?", (older_than,)).rowcount

    # ---------- Consecutive failed attempts (B2-6) ----------
    # The table `login_attempt` knows only windows: `gc()` clears it after a day, and every
    # threshold there counts from `lockout_window_sec`. Whoever guesses slowly — four attempts per window,
    # around the clock —, stayed below every threshold, for as long as they liked. NIST SP 800-63B
    # therefore demands a limit for CONSECUTIVE failed attempts that does not expire with time. It stands
    # here, separate and without a time window, per identifier AND method: locking happens on the sum,
    # what gets cleared is what the way back proves (a self-service reset only the password part,
    # R4-13). The booking lies in `reserve_attempt`, atomic with the attempt itself.
    def _series_sum(self, bucket) -> int:
        line = self.db.execute("SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie WHERE topf=?",
                                (bucket,)).fetchone()
        return int(line["n"])

    def _series_confirmed(self, bucket) -> int:
        """The series without the pending pre-bookings (G9) — under `_lock`, without commit.

        Every open row in `login_attempt` has exactly one booking in the series under the same
        bucket (`reserve_attempt(hover=True)` books both in one transaction); a row that is
        older than `PREBOOKING_PENDING_SEC` counts as a failed attempt and is not subtracted."""
        unclosed = self.db.execute(
            "SELECT COUNT(*) AS n FROM login_attempt WHERE username=? COLLATE NOCASE AND offen=1 "
            "AND ts>=?", (bucket, _now() - self.PREBOOKING_PENDING_SEC)).fetchone()
        return max(0, self._series_sum(bucket) - int(unclosed["n"]))

    def _series_minus(self, bucket, kind):
        self.db.execute("UPDATE fehlserie SET anzahl = anzahl - 1 WHERE topf=? AND art=? AND anzahl > 0",
                        (bucket, kind or ""))

    def _series_plus(self, bucket, kind):
        now = _now()
        self.db.execute("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES (?, ?, 1, ?, ?) "
                        "ON CONFLICT(topf, art) DO UPDATE SET anzahl = anzahl + 1, "
                        "zuletzt = excluded.zuletzt", (bucket, kind or "", now, now))

    def failure_series(self, bucket) -> int:
        """How many consecutive failed attempts stand for this (folded) identifier, across all methods?"""
        if not bucket:
            return 0
        with self._lock:
            return self._series_sum(bucket)

    def failure_series_confirmed(self, bucket) -> int:
        """Like `fehlserie`, without the pending pre-bookings (G9): the consecutive failed attempts that
        are settled. The series lockout hangs on it; the sum alone can still fall."""
        if not bucket:
            return 0
        with self._lock:
            return self._series_confirmed(bucket)

    def failure_series_without(self, bucket, kinds) -> int:
        """The series of this identifier WITHOUT the named kinds — what clearing only these kinds
        would leave standing (e.g. the self-service reset, which does not clear TOTP and `pin_chain`)."""
        if not bucket:
            return 0
        kinds = [str(a) for a in kinds]
        place = ",".join("?" for _ in kinds)
        with self._lock:
            line = self.db.execute(f"SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie "
                                    f"WHERE topf=? AND art NOT IN ({place})", [bucket, *kinds]).fetchone()
        return int(line["n"])

    def increase_failure_series(self, bucket, kind="password") -> int:
        """Attach a failed attempt to the series (paths without pre-booking); returns the new sum."""
        if not bucket:
            return 0
        now = _now()
        self._exec("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES (?, ?, 1, ?, ?) "
                   "ON CONFLICT(topf, art) DO UPDATE SET anzahl = anzahl + 1, zuletzt = excluded.zuletzt",
                   (bucket, kind or "", now, now))
        return self.failure_series(bucket)

    def lower_failure_series(self, bucket, kind) -> None:
        """Withdraw a pre-booking: the attempt was correct (or none at all — directory outage).

        Do not delete: a correct password with an open second factor is not a complete
        sign-in. The series before it stays, only this attempt does not count."""
        if not bucket:
            return
        self._exec("UPDATE fehlserie SET anzahl = anzahl - 1 WHERE topf=? AND art=? AND anzahl > 0",
                   (bucket, kind or ""))

    def delete_failure_series(self, bucket, kinds=None) -> int:
        """End the series (`kinds=None`: entirely, otherwise only these methods); returns how many there were."""
        if not bucket:
            return 0
        if kinds is None:
            away = self.failure_series(bucket)
            self._exec("DELETE FROM fehlserie WHERE topf=?", (bucket,))
            return away
        kinds = [str(a) for a in kinds]
        place = ",".join("?" for _ in kinds)
        line = self._one(f"SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie WHERE topf=? AND art IN ({place})",
                          [bucket, *kinds])
        self._exec(f"DELETE FROM fehlserie WHERE topf=? AND art IN ({place})", [bucket, *kinds])
        return int(line["n"])

    def gc_failure_series(self, older_than, limit) -> int:
        """Clear old, NOT triggered series (`zuletzt` before `older_than`, sum below `limit`).

        A triggered series stays: it is a lockout, and only a sign-in, a reset
        or the operator lifts it — not waiting. Without a limit the table would fill up with
        invented names; with it each remaining row costs an attacker `limit`
        failed attempts, each slowed down by the window thresholds."""
        return self._exec(
            "DELETE FROM fehlserie WHERE topf IN (SELECT topf FROM fehlserie GROUP BY topf "
            "HAVING MAX(zuletzt) < ? AND SUM(anzahl) < ?)", (int(older_than), int(limit))).rowcount

    # ---------- Magic / one-time tokens ----------
    def add_magic_token(self, token_hash, purpose, expires_at, user_id=None, email=None, payload=None):
        self._exec("INSERT INTO magic_token(token_hash, purpose, user_id, email, payload, created_at, expires_at) "
                   "VALUES (?,?,?,?,?,?,?)",
                   (token_hash, purpose, user_id, email, json.dumps(payload) if payload is not None else None,
                    _now(), expires_at))

    def get_magic_token(self, token_hash):
        return self._one("SELECT * FROM magic_token WHERE token_hash=?", (token_hash,))

    def use_magic_token(self, token_hash) -> bool:
        """Mark as used atomically. True only on the FIRST valid redemption (one-shot)."""
        with self._writing():
            cur = self.db.execute(
                "UPDATE magic_token SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
                (_now(), token_hash, _now()))
            self.db.commit()
            return cur.rowcount == 1

    def expire_magic_token(self, token_hash) -> bool:
        """Let a still unused token expire immediately (sending failed, B6-12).

        Deliberately "expired" and not "used": `used_at` means "redeemed" — for a
        confirmation token that is "address proven". A never delivered link proved nothing,
        and the cleanup of unconfirmed accounts (`unconfirmed_accounts`) must see it as
        expired.
        """
        return self._exec("UPDATE magic_token SET expires_at=? WHERE token_hash=? AND used_at IS NULL",
                          (_now() - 1, token_hash)).rowcount == 1

    def unconfirmed_accounts(self) -> list:
        """Accounts from a registration whose confirmation link has expired without them ever
        having been confirmed (R4-09). Only this combination counts — locked, never signed in,
        an unused and expired `verify_email` token, and NO valid or already
        redeemed one beside it. An existing account locked by the admin carries no such token
        and therefore stays untouched — and one with the operator mark (`disabled=2`) also
        when an app has sent it a confirmation link afterwards."""
        now = _now()
        return [r["id"] for r in self._all(
            "SELECT DISTINCT u.id FROM users u JOIN magic_token m ON m.user_id = u.id "
            "WHERE m.purpose = 'verify_email' AND m.used_at IS NULL AND m.expires_at < ? "
            "  AND u.is_owner = 0 "
            "  AND u.disabled = 1 AND u.first_login_at IS NULL "
            "  AND NOT EXISTS (SELECT 1 FROM magic_token m2 WHERE m2.user_id = u.id "
            "      AND m2.purpose = 'verify_email' AND (m2.used_at IS NOT NULL OR m2.expires_at >= ?))",
            (now, now))]

    def gc_unconfirmed_accounts(self) -> int:
        """Remove never-confirmed accounts (R4-09) — call BEFORE `gc_magic_tokens`.

        The mark "never confirmed" is the expired confirmation token; if
        `gc_magic_tokens` clears it first, the account can no longer be recognised. Without this
        step an address that a stranger had registered and never confirmed stayed taken
        forever: the real owner got "email taken". Here and not in the manager,
        so that `tinysesam gc` (works directly on the store) runs the same order."""
        ids = self.unconfirmed_accounts()
        for uid in ids:
            # Via the one deletion path (H-13, integration findings 12/18): the registration of the
            # stranger including IP and the failed attempts of the real address holder would otherwise
            # keep standing under name and address — and the closing line would carry the clear name.
            self.remove_account(uid)
            self.audit_log("signup_expired", replacement_name(uid), None, f"uid={uid}")
        return len(ids)

    def gc_magic_tokens(self) -> int:
        return self._exec("DELETE FROM magic_token WHERE expires_at < ? OR used_at IS NOT NULL", (_now(),)).rowcount

    # ---------- Shared resource secrets ----------
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

    # Only the hash here too. The token stood in plaintext in the file and was identical to the
    # cookie: whoever read the file put the value into the browser and was in every unlocked
    # scope for twelve hours — the same threat model that justifies the session switch,
    # only one table further. The token has 256 bits, so sha256 suffices.
    def add_resource_unlock(self, token, resource, expires_at):
        self._exec("INSERT OR REPLACE INTO resource_unlock(token, resource, expires_at) VALUES (?,?,?)",
                   (self.session_hash(token), resource, expires_at))

    def move_resource_unlocks(self, old_token, new_token) -> int:
        """Re-attach the approvals of a browser to a new token (F-01).

        Re-attach instead of copy: afterwards the old token holds nothing. If it was
        planted from outside, the planter comes away empty-handed; if it was the browser's own, the
        scopes this browser already had stay open."""
        if not old_token:
            return 0
        with self._writing():
            cur = self.db.execute("UPDATE OR REPLACE resource_unlock SET token=? WHERE token=?",
                                  (self.session_hash(new_token), self.session_hash(old_token)))
            self.db.commit()
            return cur.rowcount

    def delete_resource_unlocks(self, token) -> int:
        """End all approvals of this browser — on logout (F-08)."""
        if not token:
            return 0
        return self._exec("DELETE FROM resource_unlock WHERE token=?",
                          (self.session_hash(token),)).rowcount

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

    # ---------- Audit log ----------
    #: Truncate IPs in the audit log to their network (`TinySesamConfig.audit_ip_pseudonymize`, B5-11).
    #: Stands here and not in the manager because the login path also writes `audit_log` directly —
    #: a truncation that only some of the rows undergo protects nobody.
    audit_ip_pseudonym = False

    def audit_log(self, event, username=None, ip=None, detail=None):
        # The column is called `ip` — so an IP stands in it (B5-15). A real address in its
        # canonical form; everything else (a test peer, a Unix socket) only free of control characters
        # and capped, so that neither the panel nor `tinysesam audit` shows an invented row.
        if ip is not None:
            from . import security as _sec
            norm = _sec.ip_normalized(ip)
            if norm is None:
                ip = _sec.for_log(ip) or None
            else:
                ip = _sec.ip_pseudonym(norm) if self.audit_ip_pseudonym else norm
        self._exec("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                   (_now(), event, username, ip, detail))

    def delete_attempts_for(self, username, weitere=(), after=None, unlimited=(), from_ids=None) -> int:
        """Delete the sign-in attempts of an account (when deleting the account, H-13).

        `weitere` are additional identifiers under which it could sign in (the
        email address — `find_user` accepts it, and the attempt then stands under it).

        Counting happens under the bucket `norm_identifier` (NFKC, Python `lower()`, IDNA for addresses),
        so deleting happens there too — `lower()` in SQLite folds only ASCII and never hit the bucket
        `ärmel` of the account `Ärmel`, nor a name with compatibility characters (`ｂｅｒｔａ`) or an
        existing address in Unicode form (`u@bücher.example`). Rows from the time before
        `_bucket` stand under the raw input and are still found via SQLite `lower()`.

        Two limits (follow-up to integration findings 12/18):
        - `after` (Unix seconds): only attempts AFTER this second (the creation of the account) —
          before that they did not apply to it, and they count in the per-IP throttling of whoever
          made them. The second itself stays: whether an attempt in it came before or after creation
          cannot be decided, and a left-over attempt expires with the
          lockout window. Identifiers in `unlimited` apply without this limit.
          More precise is `from_ids` (`{bucket: versuch_ab}` from `identifier_limits`, G2): only attempts with
          a larger id than the watermark of the identifier — from its JOINING (rename,
          address change), not from creation, and to the exact row. Where an identifier has none
          (existing data), `after` applies.
        - If a REMAINING account carries the same bucket (a namesake such as `ｃｌａｒａ`/`clara`
          or `Émile`/`émile` from existing data, `account_by_bucket`), the bucket stays untouched.
          Otherwise removing an account, which an anonymous party can create and have cleared via `gc()`,
          would empty the account threshold of a stranger (R7-6/H-8)."""
        n = 0
        for value in (username, *[w for w in weitere if w]):
            bucket = norm_identifier(value)
            if not bucket or self.account_by_bucket(bucket) is not None:
                continue
            waterline = (from_ids or {}).get(bucket)
            if value in unlimited:
                limit, start_from = "ts > ?", -1
            elif waterline is not None:
                limit, start_from = "id > ?", int(waterline)
            else:
                limit, start_from = "ts > ?", (-1 if after is None else int(after))
            raw = str(value)
            n += self._exec(f"DELETE FROM login_attempt WHERE {limit} "
                            "AND (username = ? OR lower(username) = lower(?) "
                            "OR lower(username) = lower(?))",
                            (start_from, bucket, raw, raw.strip())).rowcount
        return n

    def gc_audit(self, older_than_ts: int) -> int:
        """Delete audit rows before a point in time (`audit_retention_days`, B5-11)."""
        return self._exec("DELETE FROM audit WHERE ts < ?", (int(older_than_ts),)).rowcount

    def anonymize_audit(self, username, replacement, weitere=(), since=None, since_id=0,
                            unlimited=(), from_ids=None) -> int:
        """Take an account out of the audit log without deleting the rows (H-13).

        The row "on the 3rd at 14:02 a password was reset, from this IP" stays for
        forensics; WHO it was then stands only as `replacement`. `weitere` are
        additional identifiers (the email address): under it, sign-in attempts stand in the
        column `username` (`find_user` accepts the address), and it occurs in the detail text.

        In the detail text the USERNAME is replaced only where one stands — `actor=<name>` (up to 0.24.x
        `akteur=<name>`, both are found) and the head of `user_create`. Freely replacing every identical word hit
        foreign rows: with the account `admin`, `admin=0->1` in the role change of an
        OTHER account became `deleted#2=0->1`, with `password` the method of every failed attempt. An
        identifier with `@`, on the other hand, is unmistakable and is replaced everywhere.

        `seit`/`since_id` restrict this to rows from the creation of the account (`setup_limit`,
        `remove_account`): what was written before under the name or with the address
        did not belong to this account. Identifiers in `unlimited` apply without the limit. Without
        `seit` every row applies. More precise is `from_ids` (`{bucket: audit_from}` from `identifier_limits`,
        G2): from the joining of the identifier instead of from creation — otherwise, when deleting an
        account that had taken over a freed name, the previous owner's row was
        rewritten too. Where an identifier has none (existing data), `seit` applies.

        **The search in the detail text is a scan** — a substring search (`instr`) that no
        B-tree index narrows down; `idx_audit_name_ts`/`idx_audit_ts` help only the column
        `username` and the period from `seit`. For an unrestricted address (deletion by
        an admin, `address_unlimited`) it reads the whole audit log, and that grows without
        `audit_retention_days` without limit. Until 2026-09-26 this scan ran in ONE
        write transaction, under the write lock (`_lock`) and with an open SQLite transaction:
        every sign-in, every audit entry, every other worker waited out the whole search (G4).
        Now it reads in blocks by `id` (`_ANONYMOUS_BLOCK` rows) WITHOUT a write transaction and
        writes only the hits, per block in a short transaction — the row read there fresh
        and re-checked, so that nothing is overwritten that has changed since reading.
        The search runs up to the most recent row at its start; what comes afterwards was written
        by someone after the deletion.

        **What the deletion promise left out until 2026-09-27** (lockouts/counters audit round, F4 — already
        so on main):

        * **Every spelling of the typed identifier** (4a): `login_fail` writes the RAW
          input (`Émile `, ` emile@example.com`, `ＥＭＩＬＥ@example.com`), counted in the
          bucket (`norm_identifier`). `lower(username)` hit only ASCII variants of these. The block scan
          therefore also compares the column `username` in the bucket (SQL function `tinysesam_kennung`,
          only for queries of this connection), with the same limits per identifier. If a
          REMAINING account shares the bucket (namesake from existing data, as with
          `delete_attempts_for`), it stays with `lower()` — otherwise it would hit its rows.
        * **Earlier names and addresses** (4b): from the own rows `username_changed old=…` and
          `email_changed old=…` (up to 0.24.x `alt=…`, `_earlier_identifiers`), each in the span in which the account
          carried them — the sign-in under the old name would otherwise keep standing with its IP.
        * **Values in the own rows** (4c): in every row whose `username` is afterwards
          the replacement name, the values of `old=`, `new=` and `to=` (up to 0.24.x `alt=`, `neu=`, `an=`) — the never redeemed address change,
          the address from LDAP/SAML, the old name.
        """
        if not username:
            return 0
        import re as _re
        without_deadline = {str(w) for w in unlimited if w}
        unclosed = self._WITHOUT_UPPER_LIMIT

        def start_from(value) -> tuple:
            if value in without_deadline:
                return (-1, -1, 0, -1, unclosed)
            waterline = (from_ids or {}).get(norm_identifier(value))
            if waterline is not None:
                return (-1, -1, 0, int(waterline), unclosed)
            if since is None:
                return (-1, -1, 0, -1, unclosed)
            return (int(since), int(since), int(since_id or 0), -1, unclosed)
        limit = "((ts > ? OR (ts = ? AND id >= ?)) AND id > ? AND id <= ?)"
        setup = (-1, -1, 0, -1) if since is None else (int(since), int(since), int(since_id or 0), -1)
        # Every identifier with its span: today's, then the earlier ones (4b) — read BEFORE
        # anything is rewritten; afterwards the rows they come from stand under `replacement`.
        identifiers = [(str(w), start_from(str(w))) for w in (username, *weitere) if w]
        identifiers += self._earlier_identifiers(identifiers, setup, limit)
        # Compared folded (4a) only where no remaining account shares the bucket.
        fold = {t for t in {norm_identifier(w) for w, _ in identifiers} - {""}
                  if self.account_by_bucket(t) is None}
        # The column `username`: via `idx_audit_name_ts`, short — one transaction.
        with self._writing():
            n = 0
            for value, limits in identifiers:
                n += self.db.execute(
                    f"UPDATE audit SET username=? WHERE lower(username)=lower(?) AND {limit}",
                    (replacement, value, *limits)).rowcount
            self.db.commit()
        above = int(self._one("SELECT max(id) AS m FROM audit")["m"] or 0)
        for value, limits in identifiers:
            w = _re.escape(value)
            end = r"(?![\w@.=-])"
            if "@" in value:
                pattern = _re.compile(r"(?<![\w@.-])" + w + end, _re.IGNORECASE)
            else:
                pattern = _re.compile(r"(?<![\w@.-])(akteur|actor)=" + w + end, _re.IGNORECASE)
            bucket = norm_identifier(value)
            folded = bucket in fold

            def rewrite(event, old, value=value, w=w, pattern=pattern) -> str:
                if "@" in value:
                    return pattern.sub(replacement, old)
                new = pattern.sub(lambda m: m.group(1) + "=" + replacement, old)
                if event == "user_create":   # detail: "<name> service=…"
                    new = _re.sub(r"^" + w + r"(?=\s|$)", replacement, new, count=1, flags=_re.IGNORECASE)
                return new

            def name_hits(name, bucket=bucket, folded=folded) -> bool:
                return folded and name is not None and name != replacement and norm_identifier(name) == bucket
            # Where the search begins: behind the watermark, or at the first row from `seit`
            # — before that no row satisfies the limit. `id + 0`, so that SQLite finds the minimum via
            # `idx_audit_ts` (only the rows from `seit`) and does not walk the table from the first
            # `id` until `ts` fits — for a young account that would be the whole log.
            below = max(limits[3], 0)
            if limits[0] >= 0:
                first = self._one("SELECT min(id + 0) AS m FROM audit WHERE ts >= ?",
                                  (limits[0],))["m"]
                below = max(below, int(first) - 1 if first is not None else above)
            finish = min(above, limits[4])
            # The column `username` in the bucket (4a) only where folding is done: the function costs a
            # Python call per row.
            also_name = "OR tinysesam_kennung(username) = ?" if folded else ""
            while below < finish:
                until = min(below + self._ANONYMOUS_BLOCK, finish)
                # The block via the primary key (`id > ? AND id <= ?`, so it stands in the plan) —
                # never via `idx_audit_ts`: otherwise each block would read all rows from `seit`, and the
                # search would become quadratic (tests/test_audit_round2.py checks the plan).
                candidates = {z["id"]: z for z in self._all(
                    "SELECT id, event, username, detail FROM audit WHERE id > ? AND id <= ? "
                    f"AND (instr(lower(detail), lower(?)) > 0 {also_name}) AND {limit}",
                    (below, until, value, *((bucket,) if folded else ()), *limits))
                    if rewrite(z["event"], z["detail"] or "") != (z["detail"] or "")
                    or name_hits(z["username"])}
                if candidates:
                    with self._writing():
                        for zid in candidates:
                            z = self.db.execute("SELECT event, username, detail FROM audit WHERE id=?",
                                                (zid,)).fetchone()
                            if z is None:
                                continue          # cleared away meanwhile (`gc_audit`)
                            old = z["detail"] or ""
                            new = rewrite(z["event"], old)
                            name = replacement if name_hits(z["username"]) else z["username"]
                            if new != old or name != z["username"]:
                                self.db.execute("UPDATE audit SET username=?, detail=? WHERE id=?",
                                                (name, new if new != old else z["detail"], zid))
                                n += name != z["username"]
                        self.db.commit()
                below = until
        self._replace_own_values(replacement, above)
        return n

    #: How many audit rows `anonymize_audit` searches in the detail text per block before it
    #: releases the write lock for others (G4).
    _ANONYMOUS_BLOCK = 5000
    #: Upper bound of the span of a TODAY identifier (`anonymize_audit`): none.
    _WITHOUT_UPPER_LIMIT = 2 ** 62
    #: How many earlier names or addresses `_earlier_identifiers` traces back at most.
    _EARLIER_MAX = 100
    #: The old name in `username_changed` (`old=<name>[ by=operator][ source=cli][ actor=…]`)
    #: and the old address in `email_changed` (`old=<address> new=<address>`). A name may
    #: carry spaces, an address may not (`valid_email`). Up to 0.24.x the keys were `alt=`, `durch=`,
    #: `quelle=`, `akteur=`, `neu=`: both spellings are read (a row of an older version after a rollback).
    _OLD_NAME = re.compile(r"^(?:alt|old)=(.*?)(?= (?:durch|by)=| (?:quelle|source)=| (?:akteur|actor)=|$)")
    _OLD_MAIL = re.compile(r"^(?:alt|old)=(\S*)")
    #: The values in the own rows that carry an identifier (4c): up to the next ` key=`.
    _OWN_VALUES = re.compile(r"(?<![\w@.-])(alt|old|neu|new|an|to)=(\S.*?)(?=\s[\w-]+=|$)")

    def _earlier_identifiers(self, current, setup, limit) -> list:
        """Earlier names and addresses of an account, each with the span in which it carried them —
        `[(kennung, limits)]` for `anonymize_audit` (H-13, audit round 2026-09-27, 4b).
        `current`: `[(name, limits), (address, limits)]`, `setup`: the limit of the creation
        without an upper bound.

        Read from the own rows: `username_changed` stands under the NEW name and names the
        old one (`old=`, up to 0.24.x `alt=`), `email_changed` under the name at the time of the change and
        names the old address. Backwards from today's name: the most recent rename in its span names the
        predecessor. It belonged to the account until that row, from the row that introduced IT — the
        most recent rename under it before that, not before creation —, otherwise from creation. Likewise the
        addresses, from the change rows under all names. Not covered: an address that came and went
        without `email_changed` (backfill from OIDC/LDAP) — there is no row for it. Via
        `idx_audit_name_ts`, no scan."""
        if not current:
            return []
        search = ("SELECT id, detail FROM audit WHERE lower(username) = lower(?) AND event = ? "
                 f"AND {limit} ORDER BY id DESC")
        names: list = []
        name, limits = current[0]
        z = self._one(search + " LIMIT 1", (name, "username_changed", *limits))
        for _ in range(self._EARLIER_MAX):
            m = self._OLD_NAME.match(str(z["detail"] or "")) if z is not None else None
            old = m.group(1).strip() if m else ""
            if z is None or not old:
                break
            until = int(z["id"])
            z = self._one(search + " LIMIT 1", (old, "username_changed", *setup, until - 1))
            names.append((old, (-1, -1, 0, int(z["id"]) - 1, until) if z is not None else (*setup, until)))
        change: dict = {}
        for name, limits in [current[0], *names]:
            for line in self._all(search + f" LIMIT {self._EARLIER_MAX}", (name, "email_changed", *limits)):
                change[int(line["id"])] = line
        row = [change[i] for i in sorted(change, reverse=True)][:self._EARLIER_MAX]
        addresses: list = []
        for i, line in enumerate(row):
            m = self._OLD_MAIL.match(str(line["detail"] or ""))
            old = m.group(1) if m else ""
            if not old:
                continue
            until = int(line["id"])
            prior = row[i + 1] if i + 1 < len(row) else None
            addresses.append((old, (-1, -1, 0, int(prior["id"]) - 1, until) if prior is not None else (*setup, until)))
        return names + addresses

    def _replace_own_values(self, replacement, above) -> None:
        """In the rows of the deleted account (`username` = replacement name, up to `above`) replace the values of
        `old=`, `new=` and `to=` (up to 0.24.x `alt=`, `neu=`, `an=`; H-13, audit round 2026-09-27, 4c): the
        requested, never redeemed address change (`email_change_requested new=…`), the address from LDAP/SAML
        (`federation_email_confirm to=…`), the old name (`username_changed old=…`). Empty values
        stay empty. Via `idx_audit_name_ts`; written per `_ANONYMOUS_BLOCK` rows, the row
        read fresh."""
        def replace(detail) -> str:
            return self._OWN_VALUES.sub(lambda m: f"{m.group(1)}={replacement}", detail)
        hit = [int(z["id"]) for z in self._all(
            "SELECT id, detail FROM audit WHERE lower(username) = lower(?) AND id <= ?", (replacement, above))
            if z["detail"] and replace(z["detail"]) != z["detail"]]
        for i in range(0, len(hit), self._ANONYMOUS_BLOCK):
            with self._writing():
                for zid in hit[i:i + self._ANONYMOUS_BLOCK]:
                    z = self.db.execute("SELECT username, detail FROM audit WHERE id=?", (zid,)).fetchone()
                    if z is None or z["username"] != replacement or not z["detail"]:
                        continue
                    self.db.execute("UPDATE audit SET detail=? WHERE id=?", (replace(z["detail"]), zid))
                self.db.commit()

    def recent_audit(self, limit=100, username: str | None = None, since: int | None = None,
                     since_id: int = 0, from_id: int | None = None, without_events=()):
        """The most recent audit entries, newest first.

        `username` filters in SQL, not in the caller. That is the difference between "the
        last N entries of this account" and "the entries of this account among the last N" —
        and exactly that counts in the motivating case: a brute-force wave pushes thousands of
        rows in within minutes, and the account being sought then lies far behind any window. For the same reason
        `seit` (Unix seconds, inclusive) also filters in SQL; from the second `seit`
        itself only rows from `since_id` (see `setup_limit`). `from_id`: only rows with a
        larger id — the watermark of an identifier (`identifier_limits`, G2). `without_events`
        leaves out these events (in the new and the old spelling, `_vocabulary.event_forms`), likewise in SQL: a display that discards rows only afterwards
        would show fewer than `limit` — and the gap would reveal that there had been one (G12b).
        """
        conditions: list[str] = []
        values: list[object] = []
        if without_events:
            # Both spellings: a row that an older version wrote after a rollback carries the old name.
            forms = _vocabulary.event_forms(*without_events)
            conditions.append(f"event NOT IN ({','.join('?' * len(forms))})")
            values.extend(forms)
        if username:
            # A replacement name in both spellings (`deleted#4`, up to 0.24.x `gelöscht#4`).
            names = _vocabulary.replacement_forms(username)
            conditions.append("lower(username) IN (" + ",".join("lower(?)" for _ in names) + ")")
            values.extend(names)
        if since:
            conditions.append("(ts > ? OR (ts = ? AND id >= ?))")
            values.extend((int(since), int(since), int(since_id or 0)))
        if from_id is not None:
            conditions.append("id > ?")
            values.append(int(from_id))
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return self._all(f"SELECT * FROM audit{where} ORDER BY id DESC LIMIT ?", (*values, limit))

    # ---------- API keys ----------
    def add_api_key(self, user_id, name, prefix, key_hash, roles=None, expires_at=None,
                    kind: str = "automation") -> int:
        cur = self._exec(
            "INSERT INTO api_key(user_id, name, prefix, key_hash, roles, kind, created_at, expires_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (user_id, name, prefix, key_hash, json.dumps(list(roles or [])), kind, _now(), expires_at))
        return cur.lastrowid

    def get_api_key_by_hash(self, key_hash):
        return self._one("SELECT * FROM api_key WHERE key_hash=?", (key_hash,))

    def list_api_keys(self, user_id):
        return self._all("SELECT * FROM api_key WHERE user_id=? ORDER BY created_at DESC", (user_id,))

    def touch_api_key(self, key_id):
        self._exec("UPDATE api_key SET last_used=? WHERE id=?", (_now(), key_id))

    #: What settles a confirmation request from LDAP/SAML for the day (`source_mail_since`): the
    #: delivered link and the rejection of a taken or reserved address.
    SOURCE_MAIL_DONE = ("federation_email_confirm", "email_change_taken", "email_change_reserved")

    def source_mail_since(self, user_id, since) -> bool:
        """Has a confirmation request for an address from LDAP/SAML on this account been settled
        since `seit` (Unix seconds)? Delivered (G12a: the row `federation_email_confirm`, which arises only AFTER
        the successful send) or rejected because the address is taken or
        reserved (`email_change_taken`/`_reserved` from this path, attack round 2026-09-26 —
        otherwise every worker wrote its own row, and the account page counted along). Recognised by the
        detail that begins with `account=<id> ` (up to 0.24.x `konto=<id> `, both are taken); self-service
        does not write it. Via
        `idx_audit_ts`, in the database and thus across all workers and every restart.
        The id instead of the name: a rename does not reset the daily quota."""
        return bool(self._one(
            "SELECT 1 FROM audit WHERE ts >= ? AND event IN (?, ?, ?) AND (detail LIKE ? OR detail LIKE ?) "
            "LIMIT 1",
            (int(since), *self.SOURCE_MAIL_DONE, f"account={int(user_id)} %", f"konto={int(user_id)} %")))

    def open_token(self, user_id, purpose, email=None) -> bool:
        """Is there already an open (unused, valid) link of this purpose for this account —
        to this address, or without `email` to any? So that not every sign-in sends a new
        confirmation link. The LDAP/SAML path asks without an address (p2 F2): with the
        filter on the address a second worker sent a link to a different one as long as the
        first was still in the outbox — and from whether it arrived, a user who maintains their own `mail`
        could read whether the first address is taken."""
        if email is None:
            return bool(self._one("SELECT 1 FROM magic_token WHERE user_id=? AND purpose=? "
                                  "AND used_at IS NULL AND expires_at >= ? LIMIT 1",
                                  (user_id, purpose, _now())))
        return bool(self._one("SELECT 1 FROM magic_token WHERE user_id=? AND purpose=? AND email=? "
                              "AND used_at IS NULL AND expires_at >= ? LIMIT 1",
                              (user_id, purpose, email, _now())))

    def revoke_user_magic_tokens(self, user_id, purposes=None) -> int:
        """Discard still open one-time tokens of an account — all, or only the named purposes.

        Lock by the operator: a confirmation link sent before the lock would otherwise unlock
        the account again (`/auth/verify/…` lifts `disabled` — for the registration
        that is right, for a lock by the operator it is not), a sign-in link would have created a
        session. Reset, password change, "end sessions": an open address change
        from a taken-over session would otherwise survive the defence (attack round, finding 1)."""
        if purposes:
            ph = ",".join("?" * len(purposes))
            return self._exec(f"DELETE FROM magic_token WHERE user_id=? AND used_at IS NULL "
                              f"AND purpose IN ({ph})", (user_id, *purposes)).rowcount
        return self._exec("DELETE FROM magic_token WHERE user_id=? AND used_at IS NULL",
                          (user_id,)).rowcount

    def revoke_user_api_keys(self, user_id) -> int:
        """Invalidate all still valid keys of an account. Returns how many there were —
        the number belongs in the log and in the response, otherwise nobody notices what silently
        dropped out (or keeps running)."""
        return self._exec("UPDATE api_key SET revoked=1 WHERE user_id=? AND revoked=0",
                          (user_id,)).rowcount

    def count_active_api_keys(self, user_id) -> int:
        r = self._one("SELECT COUNT(*) AS n FROM api_key WHERE user_id=? AND revoked=0", (user_id,))
        return r["n"] if r else 0

    def api_key_owner(self, key_id) -> Optional[int]:
        """The account ID for a key — for the audit row on revocation (B5-04)."""
        r = self._one("SELECT user_id FROM api_key WHERE id=?", (key_id,))
        return r["user_id"] if r else None

    def revoke_api_key(self, key_id, user_id=None):
        if user_id is not None:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=? AND user_id=?", (key_id, user_id))
        else:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=?", (key_id,))

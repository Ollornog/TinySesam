"""SQLite store for TinySesam: users, credentials (password/TOTP/WebAuthn/OIDC) and sessions.

Deliberately stdlib `sqlite3` (no ORM): lightweight, no extra dependency.
Thread-safe via a lock + `check_same_thread=False` (FastAPI workers share the instance).

What happens with a read-only, full or locked database and with a jump of the system clock
is described for operators in `docs/OPERATIONS.md` (failure behaviour).
"""
from __future__ import annotations
import contextlib, sqlite3, threading, time, secrets, json, logging, hashlib, os, re, stat, unicodedata
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    email         TEXT,
    -- Trägt die Adresse einen Beleg? 1 = ja (lokale Registrierung, sobald der Bestätigungslink
    -- eingelöst ist, oder über eine Einladung an genau diese Adresse; vom Admin/CLI gesetzt; ein
    -- IdP mit dem Claim), 0 = nein. Nein heisst NICHT „ungültig": Die
    -- Adresse wird ganz normal geführt und weitergereicht (`Remote-Email`), sie trägt nur keine
    -- Rechte — Erst-Admin/Allowlist verlangen den Beleg (`maybe_promote_admin`). Ein IdP, der
    -- `email_verified` nicht schickt (OIDC Core 5.1: optional; Entra ID), landet damit auf 0,
    -- statt die Adresse zu verlieren. Vorgabe 1: ein Bestand aus der Zeit vor dieser Spalte
    -- behält sein Verhalten (das ALTER TABLE füllt jede vorhandene Zeile damit).
    email_verified INTEGER NOT NULL DEFAULT 1,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    -- Owner (Entscheid 2026-09-24): immer Admin (von Hand, 1), nicht löschbar, nicht sperrbar, nicht
    -- entmachtbar; die Rolle lässt sich weitergeben, es gibt mindestens einen. Nur Owner vergeben sie.
    is_owner      INTEGER NOT NULL DEFAULT 0,
    roles         TEXT NOT NULL DEFAULT '[]',   -- JSON-Liste feingranularer Rollen (optional)
    is_service    INTEGER NOT NULL DEFAULT 0,   -- Service-/Daemon-Account: kein interaktiver Login, nur API-Key
    -- 0 = aktiv. 1 = gesperrt, weil die Bestätigung der Adresse aussteht (Registrierung, oder
    -- `set_disabled(uid, True)` einer einbettenden App) — die hebt der Bestätigungslink auf.
    -- 2 = gesperrt durch den Betreiber (Admin-Panel) — die hebt KEIN Link auf, nur der Betreiber.
    disabled      INTEGER NOT NULL DEFAULT 0,
    -- Wann war dieses Konto zum ERSTEN Mal vollständig angemeldet? NULL = noch nie (R3-1).
    -- Daran hängt das Selbst-Enrollment: Verlangt die Kette einen zweiten Faktor, darf ein
    -- Konto ihn selbst einrichten, solange es noch nie benutzt wurde — danach nicht mehr.
    -- Sonst genügt das Passwort eines BESTEHENDEN Kontos, um sich den zweiten Faktor selbst
    -- zu geben, und die Kette schützt genau die nicht, für die sie gedacht war.
    first_login_at INTEGER,
    -- Ein vom Betreiber geöffnetes Zeitfenster für die Einrichtung (Admin-Panel, Einladung).
    -- NULL/abgelaufen = zu. Der Weg für jedes Konto, dem die Betriebsart es sonst verwehrt.
    mfa_enroll_until INTEGER,
    created_at    INTEGER NOT NULL,
    -- Der Zähl-Topf des Sperrzählers (`norm_kennung`) von Name und Adresse, als Spalten mit Index
    -- (Schema 10). `konto_mit_topf` faltete vorher bei JEDEM Aufruf alle Konten in Python: Die
    -- Registrierung mit einer freien Adresse lief dadurch messbar länger als mit einer vergebenen
    -- (R4-03), und `gc()` wuchs mit offenen Konten × allen Konten. Gesetzt von `create_user` und
    -- `set_email`. NULL heisst „noch nicht gerechnet" — eine Zeile eines anderen Schreibers
    -- (ältere Fassung nach einem Rückschritt, rohes SQL, eine Umbenennung von Hand, s. die
    -- Trigger in `_migrate`) — und wird nachgetragen (`_toepfe_nachtragen`). '' = keine Adresse.
    -- Über die Töpfe erzwingt die Datenbank auch den gemeinsamen Kennungsraum (`_trigger_sql`).
    topf_name     TEXT,
    topf_mail     TEXT,
    idp_bestaetigt_at INTEGER, -- letzte Bestätigung durch den OIDC-Provider; 0 = Nein, NULL = nie (Fund 8)
    -- Ab wann gehört die Kennung diesem Konto? (Grenze a, G2) Die höchste `login_attempt.id`
    -- bzw. `audit.id` in dem Moment, in dem Name oder Adresse in ihren Zähl-Topf kamen — bei der
    -- Anlage, beim Umbenennen, beim Adresswechsel und beim Nachtrag einer Adresse. Was darunter
    -- liegt, galt niemandem oder jemand anderem. Eine Id statt einer Zeit: exakt auch innerhalb
    -- einer Sekunde, und unabhängig von der Uhr. NULL = Bestand von vor dieser Spalte, dann gilt
    -- die Anlage als Grenze (`created_at`, `anlage_grenze`). Gesetzt von `create_user` und
    -- `_kennung_setzen`, bei einem fremden Schreiber vom Nachrechnen-Trigger (`_trigger_sql`).
    name_versuch_ab INTEGER,
    mail_versuch_ab INTEGER,
    name_audit_ab   INTEGER,
    mail_audit_ab   INTEGER,
    -- Aus welcher föderierten Quelle stammt der Name ('oidc', 'saml', 'ldap')? Gesetzt, wenn die
    -- Quelle das Konto anlegt; NULL = vom Betreiber vergeben, selbst gewählt oder Bestand von vor
    -- dieser Spalte. Ein Name aus einer Quelle sagt nichts darüber, wer in einer ANDEREN so heisst:
    -- `preferred_username` oder `uid` wählt man bei einem IdP mit Selbstregistrierung selbst. Eine
    -- Anmeldung über eine andere Quelle bindet dieses Konto deshalb nie über den Namen
    -- (`_nachbindung_grund`, Angriffsrunde 2026-09-26); dieselbe Quelle darf ihren Platzhalter
    -- weiter durch die echte Kennung ersetzen. Ein Umbenennen setzt sie zurück.
    name_quelle     TEXT,
    -- Hat die Person den Namen selbst gewählt (Registrierung, Umbenennen in der Selbstbedienung)?
    -- 1 = ja: Dann sagt er nichts darüber, wer im Verzeichnis so heisst, und eine Anmeldung über
    -- LDAP/SAML bindet dieses Konto nie über den Namen (G2-N, `_nachbindung_grund`). 0 = vom
    -- Betreiber vergeben (Panel, API, Umbenennen mit `by_operator=True`) oder aus einer Quelle
    -- (dann sagt `name_quelle`, aus welcher).
    name_selbst_gewaehlt INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_key (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT,
    prefix     TEXT NOT NULL,                   -- Anzeige (tsk_xxxx…), NICHT der Key
    key_hash   TEXT UNIQUE NOT NULL,            -- sha256(vollständiger Key)
    roles      TEXT NOT NULL DEFAULT '[]',      -- Key-Scope; leer = erbt User-Rollen
    -- Welche Art Key ist das? (R6-5)
    --   'automation' (Vorgabe): arbeitet allein, trägt NIE das Admin-Flag seines Besitzers und
    --                           erfüllt keine Route, die Admin verlangt. Für Dienste und Skripte.
    --   'human'               : gilt nur ZUSAMMEN mit einer gültigen Sitzung desselben Kontos.
    --                           Dafür trägt er die vollen Rechte — der Weg für ein Werkzeug, das
    --                           ein Mensch selbst bedient (CLI am eigenen Rechner).
    -- Bis 0.21.x hiessen die Werte 'automat' und 'mensch' (Schema 12, `_werte_englisch`); gelesen
    -- werden sie weiter (`KEY_ARTEN_ALT`). Bis 0.18.x gab es die Unterscheidung nicht: Jeder Key
    -- eines Admins war eine vollständige Admin-Schreib-API, ohne zweiten Faktor und ohne
    -- CSRF-Schicht — ein abgeflossener CI-Key war die Instanz.
    kind       TEXT NOT NULL DEFAULT 'automation',
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
-- Fremde Identität → lokales Konto, über eine STABILE Kennung des Verzeichnisses (F-11).
-- OIDC hat dafür `oidc_identity` (issuer+sub); LDAP und SAML banden bis 0.19.0 allein über den
-- Benutzernamen. Ein Name ist aber nicht fälschungssicher: Wer im Verzeichnis umbenennt oder ein
-- gelöschtes Konto unter demselben Namen neu anlegt, bekommt dasselbe lokale Konto mitsamt
-- seinen Rollen. Die Kennung hier ist objectGUID/entryUUID (LDAP) bzw. die NameID (SAML) — sie
-- überlebt eine Umbenennung und wird nicht wiederverwendet.
CREATE TABLE IF NOT EXISTS federated_identity (
    quelle      TEXT NOT NULL,              -- 'ldap' | 'saml'
    kennung     TEXT NOT NULL,              -- die stabile Kennung aus dem Verzeichnis
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gebunden_at INTEGER NOT NULL,           -- wann die Bindung entstand (auch: nachgebunden)
    -- Der Name, unter dem sich das Konto zuletzt über diese Quelle angemeldet hat, im Zähl-Topf
    -- (`norm_kennung`) — nur wenn er weder Name noch Adresse des Kontos ist (G5). Nach einer
    -- Umbenennung im Verzeichnis tippt die Person den NEUEN Namen, und unter ihm zählt die Serie
    -- (B2-6); ohne diese Spalte räumte kein Rückweg sie. NULL = keiner (oder noch nie gesehen).
    -- Der Name gehört dem Konto, das sich zuletzt so angemeldet hat (`bindung_name_setzen` löscht
    -- ihn an fremden Bindungen), und kein anderes Konto kann ihn als Name oder Adresse annehmen
    -- (Kennungs-Trigger, `TinySesam.identifier_taken`; Prüfrunde Sperren/Zähler 2026-09-27).
    name_topf   TEXT,
    PRIMARY KEY (quelle, kennung)
);
-- Vom Betreiber geöffnete Bindung über den Namen (G1): Bis `bis` bindet die nächste Anmeldung über
-- LDAP/SAML dieses Konto über seinen Namen, auch nach der Frist (`federation_name_binding_days`)
-- und auch mit selbst gewähltem Namen. Geschrieben von `federation_unbind`, gelöscht, sobald
-- die Bindung steht. Ohne Zeile entscheidet die Frist.
CREATE TABLE IF NOT EXISTS namensbindung (
    quelle  TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bis     INTEGER NOT NULL,
    PRIMARY KEY (quelle, user_id)
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
    user_agent TEXT,
    zuletzt    INTEGER,                       -- letzte Anfrage mit dieser Sitzung (Inaktivitäts-Timeout, F-05)
    andere_beenden INTEGER NOT NULL DEFAULT 0, -- halbe Sitzung: bei Abschluss der Kette die übrigen beenden (Grenze d)
    bleiben_gewaehlt INTEGER NOT NULL DEFAULT 0, -- „Angemeldet bleiben" AUSDRÜCKLICH gewählt (F-05: dann gilt die zweite Leerlauf-Grenze)
    nachfolger TEXT                           -- abgelöst durch diese Sitzung (Gnadenfrist nach dem Drehen, A-6); NULL = aktuell
);
-- Welche Anwendung hat der Provider dieser Sitzung freigegeben? (T-14)
-- Eine Zeile je Sitzung UND Anwendung: Wer sich für app-a anmeldet, bekommt damit keinen
-- Zugang zu app-b — dort entscheidet der Provider erneut. Ohne diese Tabelle gäbe es nur die
-- Frage „angemeldet ja/nein", und die kann die Freigabe je Client nicht abbilden.
CREATE TABLE IF NOT EXISTS oidc_grant (
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client     TEXT NOT NULL,                 -- Schlüssel aus cfg.oidc_clients, "*" = Einzel-Client
    granted_at INTEGER NOT NULL,              -- erste Freigabe (bleibt stehen, auch über Nachprüfungen)
    checked_at INTEGER NOT NULL,              -- letzte Bestätigung durch den Provider
    roles      TEXT NOT NULL DEFAULT '[]',    -- Rollen, die der Provider FÜR DIESE Anwendung ergab
    PRIMARY KEY (token_hash, client)
);
CREATE TABLE IF NOT EXISTS oidc_sitzung (    -- Refresh-Token einer OIDC-Sitzung je Client (4a, Widerruf folgt dem IdP)
    token_hash  TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    client      TEXT NOT NULL,                -- Schlüssel aus cfg.oidc_clients, "*" = Einzel-Client
    sub         TEXT NOT NULL,                -- Subjekt beim Provider; ein anderes beendet die Sitzung
    refresh     TEXT NOT NULL,                -- verschlüsselt (vault.Vault), nie im Klartext
    geprueft_at INTEGER NOT NULL,             -- letzter Tausch (oder: beansprucht, s. Store)
    client_id   TEXT,                         -- an welche client_id das Token ging (NULL: vor dieser Spalte)
    erfolg_at   INTEGER,                      -- letzte ERFOLGREICHE Nachprüfung (Obergrenze ohne Nachprüfung); NULL: vor dieser Spalte
    PRIMARY KEY (token_hash, client)
);
-- Nur von DIESER Anwendung abgemeldet (T-22, `forward_logout="app"`): Die Sitzung bleibt, die
-- Forward-Auth lässt sie für diesen Host aber nicht mehr durch, bis der Mensch auf der Login-Seite
-- ausdrücklich „weiter“ wählt. Ohne die Zeile wäre „nur hier abmelden“ ein Neuladen der Seite.
CREATE TABLE IF NOT EXISTS gate_abgemeldet (
    token_hash TEXT NOT NULL REFERENCES session(token_hash) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    at         INTEGER NOT NULL,
    PRIMARY KEY (token_hash, host)
);
-- Das ID-Token der Anmeldung, verschlüsselt (vault.Vault) — nur als `id_token_hint` für den
-- Logout beim Provider (T-22). PocketID beendet seine Sitzung ohne den Hinweis nicht, sondern
-- zeigt eine Rückfrage und leitet danach nicht zurück.
-- Die Verbindung eines App-Hosts zur zentralen Sitzung (Code-Austausch, T-26): Die Sitzung bleibt
-- auf dem Host des Gateways; der App-Host bekommt nur ein eigenes Cookie, dessen Hash hier steht.
-- Es gilt NUR für seinen Host und endet mit der Sitzung (ON DELETE CASCADE).
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
    method   TEXT,
    offen    INTEGER NOT NULL DEFAULT 0      -- 1: vorgebucht, Ausgang noch offen (G9, `reserve_attempt`)
);
CREATE TABLE IF NOT EXISTS fehlserie (       -- Fehlversuche IN FOLGE je Kennung, ohne Zeitfenster (B2-6)
    topf    TEXT NOT NULL,                   -- gefaltete Kennung, derselbe Schlüssel wie login_attempt.username
    art     TEXT NOT NULL,                   -- Methode (password, pin, totp …): ein Reset räumt nur seine
    anzahl  INTEGER NOT NULL,
    seit    INTEGER NOT NULL,                -- erster Fehlversuch der laufenden Serie
    zuletzt INTEGER NOT NULL,
    PRIMARY KEY (topf, art)
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
-- Grenze c (Integrationsangriff): `anlage_grenze` und `audit_anonymisieren` suchen nach Name und
-- Zeit. Ohne Index lief das über das ganze Audit-Log — seine Grösse wächst mit der Aufbewahrung.
-- Nur Name und Zeit: Die Suche im DETAILTEXT (`audit_anonymisieren`) ist eine Teilstring-Suche,
-- die kein Index eingrenzt — sie bleibt ein Scan, läuft seit G4 aber blockweise ohne Schreibsperre.
CREATE INDEX IF NOT EXISTS idx_audit_name_ts ON audit(lower(username), ts);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_attempt_user ON login_attempt(username, ts);
CREATE INDEX IF NOT EXISTS idx_attempt_ip ON login_attempt(ip, ts);
CREATE INDEX IF NOT EXISTS idx_apikey_user ON api_key(user_id);
-- G1: „Welche Konten tragen für diese Quelle noch keine Kennung?" (Startmeldung, Bestandsbindung)
-- fragt je Konto nach seiner Zeile; ohne Index läse das je Konto alle Bindungen der Quelle.
CREATE INDEX IF NOT EXISTS idx_fed_quelle_user ON federated_identity(quelle, user_id);
"""


#: Characters where IDNA 2003 (stdlib codec) and IDNA 2008 differ: the stdlib codec
#: turns `straße.example` into `strasse.example` — a DIFFERENT domain. A domain containing one of them
#: stays in Unicode form instead of being rewritten incorrectly.
_IDNA_ABWEICHLER = frozenset("ßς\u200c\u200d")


def _domain_kanonisch(domain: str) -> str:
    """Bring a domain into A-label form (`xn--…`) when that is unambiguous (R4-06).

    Otherwise `bücher.example` and `xn--bcher-kva.example` are stored as two different addresses
    in the database although both mean the same mailbox — two accounts, two "taken" checks
    that cannot see each other. What cannot be rewritten safely stays unchanged."""
    if domain.isascii() or any(z in _IDNA_ABWEICHLER for z in domain):
        return domain
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain


def _email_unicode(email: str) -> str:
    """The address with its domain in Unicode form (`xn--bcher-kva.example` → `bücher.example`).

    Only for looking up existing addresses from before R4-06 that are still stored that way — never
    for storing. What cannot be decoded is returned unchanged."""
    lokal, at, domain = email.rpartition("@")
    if not at or "xn--" not in domain:
        return email
    try:
        return f"{lokal}@{domain.encode('ascii').decode('idna').lower()}"
    except UnicodeError:
        return email


def key_kind_of(row) -> str:
    """The kind of a key row with the English name (schema 12): `automation` or `human`.

    A value up to 0.21.x (`automat`, `mensch`) is mapped (`Store.KEY_ARTEN_ALT`) — an older
    version that ran on the file after a rollback writes it again. Empty or without the
    column (file before schema 7) means `automation`. Anything else stays as it is and, because
    it is not `human`, counts as an automation key (fail-closed, R6-6). Here and not on the manager, so that
    router and admin panel can read it without importing the manager (no import cycle)."""
    try:
        wert = str(row["kind"] or "automation")
    except (IndexError, KeyError, TypeError):
        return "automation"
    return Store.KEY_ARTEN_ALT.get(wert, wert)

def norm_email(email) -> Optional[str]:
    """Store an email canonically: NFKC, trimmed, lowercase, domain as A-label. `None` stays `None`.

    NFKC folds compatibility characters (R4-06): a full-width `ａｄｍｉｎ@example.com` is afterwards
    the same as `admin@example.com` — before, they were two identifiers that looked the same
    in the panel."""
    e = unicodedata.normalize("NFKC", str(email or "")).strip().lower()
    if not e:
        return None
    lokal, at, domain = e.rpartition("@")
    if at and domain:
        e = f"{lokal}@{_domain_kanonisch(domain)}"
    return e


def _schriften(text: str) -> set:
    """The scripts of the letters in `text` (first word of the Unicode name: LATIN,
    CYRILLIC, GREEK …). Digits and punctuation do not count."""
    return {unicodedata.name(z, "?").split(" ", 1)[0] for z in text if z.isalpha()}


#: Scripts that belong together in ONE language and may therefore be mixed (attack A6,
#: modelled on UTS #39 "Highly Restrictive"): Japanese writes kanji with hiragana and katakana
#: (`山田たろう`, `例え`), Korean hanja with hangul, Chinese han with bopomofo. Without this
#: exception the script check rejected ordinary Japanese addresses and IDN domains. Latin
#: deliberately belongs to no group — `аdmin` (Cyrillic/Latin) stays rejected.
_SCHRIFT_GRUPPEN = (
    frozenset({"CJK", "IDEOGRAPHIC", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"}),
    frozenset({"CJK", "IDEOGRAPHIC", "HANGUL"}),
    frozenset({"CJK", "IDEOGRAPHIC", "BOPOMOFO"}),
)


def _eine_schrift(teil: str) -> bool:
    """Do the letters come from one script — or from a group that belongs together?"""
    s = _schriften(teil)
    return len(s) <= 1 or any(s <= gruppe for gruppe in _SCHRIFT_GRUPPEN)


def name_ungueltig(name) -> bool:
    """Does a username contain control, format or separator characters (Cc/Cf/Zl/Zp)?

    Such characters separate two identifiers that look the same to a human and to an HTTP header:
    `chefin\\x01` is a different name from `chefin` for `identifier_taken`, but the forward-auth
    header sanitising strips the control character — the protected app received
    `Remote-User: chefin` from a foreign account (attack in the third round). The same rule
    as for addresses (`valid_email`)."""
    return any(unicodedata.category(z) in ("Cc", "Cf", "Zl", "Zp") for z in str(name or ""))


def norm_kennung(kennung) -> str:
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
    `Store.konto_mit_topf`), and `delete_attempts_for` leaves a shared bucket in place."""
    k = unicodedata.normalize("NFKC", str(kennung or "")).strip().lower()
    if "@" in k:
        return norm_email(k) or ""
    return k


def _kennung_sql(wert) -> Optional[str]:
    """`norm_kennung` for SQLite (`tinysesam_kennung`): NULL stays NULL, and an error becomes NULL
    instead of an exception in the middle of the query."""
    if wert is None:
        return None
    try:
        return norm_kennung(wert)
    except Exception:
        return None


def valid_email(email) -> bool:
    """Deliberately lenient: exactly one @, something on the left and right, a dot on the right, no spaces.
    Whether the address exists is answered only by the confirmation link (`signup_verify_email`).

    Also rejected is anything built to be confusable (R4-06): invisible characters
    (control and format characters such as zero-width joiner) and a part that mixes scripts —
    `аdmin@example.com` with a Cyrillic `а` looks like the admin mailbox in the panel. An
    address entirely in one script (`müller@…`, `иван@…`) stays allowed, as do the mixtures of one
    language from `_SCHRIFT_GRUPPEN` (`山田たろう@…`)."""
    e = (email or "").strip()
    if not e or " " in e or e.count("@") != 1:
        return False
    if any(unicodedata.category(z) in ("Cc", "Cf") for z in e):
        return False
    local, _, domain = e.partition("@")
    if not (bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")):
        return False
    return all(_eine_schrift(teil) for teil in [local, *domain.split(".")])


class _Uhr:
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
    `Store()` raises the clock to the most recent timestamp it finds (`mindestens()`) —
    including the state that `Store` writes at most once a minute (`uhr_stand`, on every
    write access and on every write probe of the health check). What expired in the last minute before
    a restart, or during a time in which nothing was written at all, can therefore
    remain valid for up to that interval longer — but not for its full remaining lifetime.

    The price: if the wall clock once jumped wrongly FORWARDS, the clock stays there until the wall clock
    catches up — deadlines are then internally consistent, just dated in the future. That is the
    safe direction, and it is logged as a warning.

    `wand`/`mono` are interchangeable so that a test can set up a jump without bending the clock of
    the whole process. Without them, `time.time`/`time.monotonic` are looked up on EVERY
    call rather than bound at import: an embedding app that patches `time.time` in its tests
    (`mock.patch`, `monkeypatch`, freezegun) thereby sets this clock too.
    It cannot be turned back this way — that is exactly the protection above.

    freezegun additionally replaces `time.monotonic`, namely with the frozen time on the
    epoch scale instead of the uptime. Carried forward, that would be a jump of decades
    (and one back when leaving `freeze_time`). A monotonic step that goes backwards
    or is larger than `MONO_SCHRITT_MAX_SEK` therefore does not count as elapsed time:
    under freezegun the clock follows the frozen wall clock forwards (including `tick()`/`move_to()`);
    after leaving, it continues from the advanced state with the real
    monotonic time — as after `mock.patch`. The lead therefore remains: for the lifetime
    of the process (real time does not catch up, both run at the same speed) and via
    `uhr_stand` in this database for every later opening, as long as the pause in between is shorter
    than the lead. That is the safe direction; a test that sets the clock far ahead
    therefore uses its own throwaway database. The price of the plausibility limit is paid only by
    a backwards jump of the wall clock that falls into a pause of more than a year without any call:
    then the wall clock that jumped back applies, but never less than the most recently issued
    state. The same rule applies to the monotonic stamps of the `Store` (`_frisch`): a negative
    distance is expired, not fresh.
    """

    #: Lag of the wall clock from which a warning is written (seconds). Below that
    #: it is normal NTP jitter.
    WARN_AB_SEK = 5

    #: Largest step of monotonic time between two calls that still counts as elapsed time
    #: (seconds). A real step is the pause between two requests; freezegun instead delivers
    #: the frozen time on the epoch scale (≈1.8e9 s) — a jump of decades.
    #: One year separates the two safely without giving up the protection after a long pause.
    MONO_SCHRITT_MAX_SEK = 365 * 86400

    def __init__(self, wand=None, mono=None):
        # Look up on EVERY call, do not bind at construction: whoever patches `time.time`
        # (`mock.patch`, `monkeypatch`, freezegun) sets this clock too (see docstring).
        def _wand():
            return time.time()

        def _mono():
            return time.monotonic()
        self.wand = wand or _wand
        self.mono = mono or _mono
        self._lock = threading.Lock()
        self._stand = 0.0          # last issued time (wall-clock scale)
        self._mono = None          # monotonic time at that issue
        self._gemeldet = False     # lag already reported? (one line per jump, not per request)

    def jetzt(self) -> int:
        with self._lock:
            wand, mono = float(self.wand()), float(self.mono())
            schritt = mono - self._mono if self._mono is not None else 0.0
            if not 0.0 <= schritt <= self.MONO_SCHRITT_MAX_SEK:
                # No real monotonic clock (backwards, or a jump of decades: freezegun
                # replaces `time.monotonic` with the epoch time). Do not advance — otherwise
                # the clock jumped ahead by ≈57 years and `uhr_stand` pinned every later opening of the
                # database there. The wall clock forwards still applies, backwards the clock stands —
                # even if the monotonic source itself jumps back (leaving freeze_time).
                schritt = 0.0
            self._stand, self._mono = max(wand, self._stand + schritt), mono
            self._rueckstand_pruefen(wand)
            return int(self._stand)

    def mindestens(self, ts) -> None:
        """Raise the clock to at least `ts` (most recent timestamp of the database when opening)."""
        if not ts:
            return
        with self._lock:
            if float(ts) > self._stand:
                self._stand, self._mono = float(ts), float(self.mono())
            self._rueckstand_pruefen(float(self.wand()))

    def _rueckstand_pruefen(self, wand: float) -> None:
        rueckstand = self._stand - wand
        if rueckstand > self.WARN_AB_SEK and not self._gemeldet:
            self._gemeldet = True
            logging.getLogger("tinysesam").warning(
                "Die Systemuhr steht %d s hinter der zuletzt benutzten Zeit (Rückwärtssprung "
                "oder falsches Datum nach dem Start). TinySesam zählt monoton weiter, damit "
                "abgelaufene Sitzungen und Einmal-Token nicht wieder gelten (nach einem "
                "Neustart ab dem zuletzt gesicherten Stand, höchstens eine Minute alt) — "
                "Uhrzeit (NTP) prüfen.", int(rueckstand))
        elif rueckstand <= self.WARN_AB_SEK:
            self._gemeldet = False


#: One clock per process: several `Store` instances in the same process must not
#: contradict each other, and a backwards jump hits the whole process, not one database.
_UHR = _Uhr()


def jetzt() -> int:
    """Current time (Unix seconds) that never runs backwards — see `_Uhr`."""
    return _UHR.jetzt()


#: Longest age after which `gc` deletes old login attempts (seconds): ten years like
#: `audit_retention_days`. The limit is not a recommendation for retention — the lockout sees
#: only its window anyway —, but keeps the number within the range SQLite can compute.
VERSUCHSFRIST_MAX_SEK = 3660 * 86400


def versuchsfrist(sekunden) -> int:
    """Check `attempts_older_than_sec` of `gc` — BEFORE anything is deleted.

    Without a limit, ±10**20 aborted with `OverflowError` after sessions, flows, tokens and unlocks
    were already gone; a negative value deleted every failed attempt, including those in the running
    lockout window, and thereby lifted every account lockout. 0 stays allowed: the documented way
    to clear all failed attempts. `True` is not an age (it would mean one second). `ValueError` if
    the value does not fit."""
    try:
        if isinstance(sekunden, bool):
            raise ValueError
        zahl = int(sekunden)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"attempts_older_than_sec={sekunden!r} ist keine ganze Zahl von Sekunden.") from None
    if not 0 <= zahl <= VERSUCHSFRIST_MAX_SEK:
        raise ValueError(f"attempts_older_than_sec={zahl} liegt ausserhalb von 0…{VERSUCHSFRIST_MAX_SEK} "
                         "(Sekunden). 0 räumt alle Fehlversuche.")
    return zahl


def _now() -> int:
    return _UHR.jetzt()


def ersatzname(user_id) -> str:
    """Who represents a deleted account in the audit log (H-13): `gelöscht#<id>`.

    One place for the format — every deletion path writes its closing line under it, even
    one that no longer finds the account (otherwise the clear name would appear there again)."""
    return f"gelöscht#{int(user_id)}"


#: Keys in the payload of an address-change link up to 0.21.x and their English replacement (schema 12).
_PAYLOAD_SCHLUESSEL_ALT = {"email_change": {"alt": "old"}}


def payload_lesen(purpose, text) -> Optional[dict]:
    """The payload of a one-time token as a dict — with English keys (schema 12).

    An address-change link carried `{"alt": <previous address>}` up to 0.21.x, and
    `{"old": …}` since 0.22.0. An old key is mapped, even if the migration has not
    reached it — an older version that issued a link after a rollback writes
    it that way again. A key that is already English wins. `None` without a payload."""
    if not text:
        return None
    daten = json.loads(text)
    for alt, neu in _PAYLOAD_SCHLUESSEL_ALT.get(purpose, {}).items():
        if isinstance(daten, dict) and alt in daten:
            wert = daten.pop(alt)
            daten.setdefault(neu, wert)
    return daten


class Store:
    #: Permissions for a NEWLY created database. It holds password hashes, TOTP secrets
    #: and email addresses; on a shared host anyone could read it up to 0.18.0 (0644,
    #: depending on umask). Nothing is changed on an existing file — whoever deliberately
    #: released a group should keep that —, but there is a warning.
    DATEIRECHTE = 0o600

    def __init__(self, db_path: str):
        neu = db_path not in (":memory:", "") and not os.path.exists(db_path)
        if neu:
            # The file is created directly with narrow permissions. A chmod AFTER connecting would have
            # a window in which it stands open — and that is exactly when
            # SQLite writes the schema into it.
            try:
                os.close(os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.DATEIRECHTE))
            except OSError:
                neu = False                      # directory missing or similar — sqlite3 reports it right away
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
        # The counting bucket as an SQL function — ONLY for queries of this connection (`audit_anonymisieren`),
        # never in schema, trigger or index: there it would break every writer without it (`_trigger_sql`).
        self.db.create_function("tinysesam_kennung", 1, _kennung_sql, deterministic=True)
        self._lock = threading.Lock()
        self._uhr_gesichert: Optional[float] = None   # monotonic time of the last saved clock state
        self._geschrieben: Optional[float] = None     # monotonic time of the last successful commit
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self._migrate()
        self._dateirechte_pruefen(db_path, neu)
        _UHR.mindestens(self._juengster_zeitstempel())

    #: How long a request waits for a locked database before giving up (ms).
    #: Twice Python's default: a checkpoint or a backup on slow
    #: storage (SD card, network drive) takes longer than 5 s, and an aborted login
    #: is more expensive than a slow one. No longer — the worker thread is stuck for that long.
    BUSY_TIMEOUT_MS = 10_000

    def _juengster_zeitstempel(self) -> int:
        """The most recent event timestamp of the database — the clock state across a restart.

        Only points in time at which something HAPPENED (created, logged), no deadlines: an
        `expires_at` is in the future by design and would set the clock ahead."""
        abfragen = ("SELECT MAX(created_at) AS t FROM session",
                    "SELECT MAX(created_at) AS t FROM magic_token",
                    "SELECT ts AS t FROM audit ORDER BY id DESC LIMIT 1",
                    "SELECT ts AS t FROM login_attempt ORDER BY id DESC LIMIT 1",
                    f"SELECT CAST(value AS INTEGER) AS t FROM setting WHERE key='{self.UHR_STAND}'")
        werte = []
        for sql in abfragen:
            try:
                r = self._one(sql)
            except sqlite3.Error:
                continue
            if r and r["t"]:
                werte.append(int(r["t"]))
        return max(werte, default=0)

    def _dateirechte_pruefen(self, db_path: str, neu: bool):
        """WAL and SHM carry the same data as the database — they get the same permissions.

        The main file itself is only assessed on an existing installation, not
        rewritten: a deliberate group release is a decision of the operator, not a
        gap. It still does not stay silent."""
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
                pass                              # file system without permissions (Windows, some mounts)
        if not neu and modus & 0o077:
            logging.getLogger("tinysesam").warning(
                "Die Datenbank %s ist für andere Konten lesbar (%o). Darin stehen Passwort-Hashes "
                "und TOTP-Geheimnisse. Enger stellen: chmod 600 %s", db_path, modus, db_path)

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
    #:      2026-09-27): `api_key.kind` `automat`/`mensch` → `automation`/`human` (on EVERY start —
    #:      for keys that an older version issued after a rollback), in the payload of
    #:      open address-change links `alt` → `old` (on the jump to 12; `_werte_englisch`).
    #:      An old value is still read correctly (`KEY_ARTEN_ALT`, `payload_lesen`). No
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
    SCHEMA_VERSION = 14

    #: The stored values up to 0.21.x and their English replacement (schema 12). The migration
    #: rewrites them, and whoever reads still maps an old value: an older version that ran
    #: on the same file after a rollback has left old values behind again.
    KEY_ARTEN_ALT = {"automat": "automation", "mensch": "human"}

    #: From this schema state on, `topf_name`/`topf_mail` are computed with today's `norm_kennung`.
    #: Whoever changes the folding in `norm_kennung` raises `SCHEMA_VERSION` and sets this
    #: value to match — otherwise the buckets of the existing data would stand in the old folding in the index, and
    #: `konto_mit_topf` would no longer find namesakes.
    TOPF_SCHEMA = 10

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
                      # 0 for existing data; who becomes owner is decided by `Store._owner_nachziehen`.
                      ("is_owner", "INTEGER NOT NULL DEFAULT 0"),
                      # Existing data: set to "now" below for OIDC accounts (finding 8).
                      ("idp_bestaetigt_at", "INTEGER"),
                      # NULL for existing data: the limit is then the creation, as until 2026-09-26 (G2).
                      # Do not backfill "now" — the account page would otherwise show nothing from before
                      # the update, and own failed attempts would remain until the end of the window.
                      ("name_versuch_ab", "INTEGER"), ("mail_versuch_ab", "INTEGER"),
                      ("name_audit_ab", "INTEGER"), ("mail_audit_ab", "INTEGER"),
                      # 0 for existing data; whoever registered or renamed themselves backfills
                      # it once below (`NAME_SELBST_NACHGETRAGEN`, G2-N).
                      ("name_selbst_gewaehlt", "INTEGER NOT NULL DEFAULT 0"),
                      # NULL for existing data; where the origin is proven, backfilled once below
                      # (`NAME_QUELLE_NACHGETRAGEN`, attack round 2026-09-26).
                      ("name_quelle", "TEXT")],
            # NULL: never logged in under a different name yet (G5); arises at the next login.
            "federated_identity": [("name_topf", "TEXT")],
            # 0 for existing data: every present row is a completed attempt (G9).
            "login_attempt": [("offen", "INTEGER NOT NULL DEFAULT 0")],
        }
        # `_schreibend`, not only `_lock`: the final commit below takes DELETE and stamp with it.
        # If something fails before that, without a rollback a transaction would stay open on the
        # connection (the AST guard in tests/test_hardening2.py demands this for every commit).
        with self._schreibend():
            # `fehlserie` initially came with schema 11 without a column `art` (a never published
            # intermediate state). Such a table is recreated — otherwise every login would end in
            # a 500. The series in it are lost; that is the lesser harm.
            _fs = {r["name"] for r in self.db.execute("PRAGMA table_info(fehlserie)")}
            if _fs and "art" not in _fs:
                ddl = re.search(r"CREATE TABLE IF NOT EXISTS fehlserie \(.*?\n\);", SCHEMA, re.S)
                if ddl is None:     # it is in SCHEMA; if it is missing there, that is an error here
                    raise RuntimeError("SCHEMA enthält keine Tabelle fehlserie")
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
            vorhanden_vorab = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if vorhanden_vorab < self.SCHEMA_VERSION:
                weg = self.db.execute(
                    "DELETE FROM resource_unlock WHERE length(token) <> 64"
                    " OR token GLOB '*[^0-9a-f]*'").rowcount
                if weg:
                    logging.getLogger("tinysesam").info(
                        "%d Ressourcen-Freigaben verworfen (Token werden jetzt gehasht abgelegt).", weg)

            # Schema 10. The steps run in the same transaction as the stamp below: if
            # the start aborts in between, the stamp is missing too, and the next start runs them again
            # (every step is repeatable). The existing-data steps run on EVERY start, not only
            # on the jump over the stamp — for what an older writer may have left behind
            # since then (`_bestand_nachziehen`).
            ohne_topf = self.db.execute(
                "SELECT * FROM users" + ("" if vorhanden_vorab < self.TOPF_SCHEMA else
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
                               (self.NAME_SELBST_NACHGETRAGEN,)).fetchone() is None:
                self._name_selbst_nachtragen()
            if self.db.execute("SELECT 1 FROM setting WHERE key=?",
                               (self.NAME_QUELLE_NACHGETRAGEN,)).fetchone() is None:
                self._name_quelle_nachtragen()
            self._owner_nachziehen()
            # Schema 12: the stored values in English (see `_werte_englisch`). Read-only and
            # values of an older version in it: that must not prevent a start that worked
            # before — the old values are read correctly anyway. An upgrade, on the other hand, writes,
            # like every migration.
            try:
                umgeschrieben = self._werte_englisch(links=vorhanden_vorab < 12)
            except sqlite3.OperationalError as e:
                if vorhanden_vorab < self.SCHEMA_VERSION:
                    raise
                umgeschrieben = 0
                logging.getLogger("tinysesam").warning(
                    "Werte einer älteren Fassung nicht auf die englischen Namen umgeschrieben (%s): "
                    "Die Datenbank ist nicht schreibbar. Gelesen werden sie trotzdem richtig.", e)
            if umgeschrieben:
                logging.getLogger("tinysesam").info(
                    "%d gespeicherte Werte auf die englischen Namen umgeschrieben (Schema 12: "
                    "API-Key-Arten, Adresswechsel-Links).", umgeschrieben)
            if vorhanden_vorab < 10:
                self._bestand_nachziehen(True, ohne_topf)
            else:
                try:
                    self._bestand_nachziehen(False, ohne_topf)
                except sqlite3.OperationalError as e:
                    # As with the bucket below: this must not prevent a start that worked before.
                    # With this stamp the transaction contains only this step.
                    self.db.rollback()
                    logging.getLogger("tinysesam").warning(
                        "Bestandsschritte nicht nachgezogen (%s): Sperren aus dem Panel einer älteren "
                        "Fassung tragen den Betreiber-Vermerk erst nach einem Start mit "
                        "Schreibzugriff.", e)
            try:
                self._toepfe_schreiben(ohne_topf)
            except sqlite3.OperationalError:
                # Read-only (volume mounted read-only) and rows of a foreign
                # writer without a bucket: this must not prevent the start, which worked before —
                # `konto_mit_topf` then checks such rows itself (`_toepfe_nachtragen`). An
                # upgrade, on the other hand, needs the buckets, like every other migration its columns.
                if vorhanden_vorab < self.TOPF_SCHEMA:
                    raise
                logging.getLogger("tinysesam").warning(
                    "Zähl-Töpfe von %d Konto(en) nicht nachgetragen: Die Datenbank ist nicht "
                    "schreibbar. Die Topf-Prüfung sieht sie trotzdem, nur langsamer.", len(ohne_topf))

            # A file from the future: this version does not fully know its tables
            # and would leave gaps when writing. That is no reason to crash —
            # but a very good one to say so loudly.
            vorhanden = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if vorhanden > self.SCHEMA_VERSION:
                logging.getLogger("tinysesam").warning(
                    "Die Datenbank trägt Schema-Version %d, diese TinySesam-Fassung kennt nur %d. "
                    "Sie stammt aus einer neueren Version — mit dieser hier zu schreiben kann "
                    "Daten unvollständig lassen. Passende Version installieren oder die Datei "
                    "aus einer Sicherung zurückspielen.", vorhanden, self.SCHEMA_VERSION)
            elif vorhanden != self.SCHEMA_VERSION:
                self.db.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            # Email unique (login identifier) — partial, so that accounts without an email stay allowed.
            # Existing data with duplicates: the index cannot be created → say so loudly, do not crash.
            try:
                self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email "
                                "ON users(lower(email)) WHERE email IS NOT NULL AND email <> ''")
            except sqlite3.IntegrityError:
                logging.getLogger("tinysesam").warning(
                    "users.email enthält Dubletten — Eindeutigkeits-Index nicht angelegt. "
                    "Doppelte Adressen bereinigen, sonst ist Login per E-Mail mehrdeutig.")
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
                self._trigger_setzen()
            except sqlite3.OperationalError as e:
                logging.getLogger("tinysesam").warning(
                    "Trigger über Benutzername und Adresse nicht angelegt (%s): Die Datenbank "
                    "erzwingt den gemeinsamen Kennungsraum erst nach einem Start mit "
                    "Schreibzugriff.", e)
            self.db.commit()

    #: Message of the identifier triggers (`sqlite3.IntegrityError`): name or address falls into the
    #: counting bucket of ANOTHER account. Callers recognise the case by `IntegrityError`, not by the text.
    KENNUNG_VERGEBEN = "tinysesam: kennung vergeben"

    #: The watermarks of an identifier (G2) as an SQL expression: the highest id that exists NOW.
    #: Everything created afterwards has a larger one (`AUTOINCREMENT` never issues an id twice).
    #: Only built-in functions — same reason as for the triggers.
    WL_VERSUCH = "(SELECT COALESCE(MAX(id), 0) FROM login_attempt)"
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
        (`_kennung_setzen`); otherwise even `B1` → `b1` would shift the limit.

        **Change with bucket** (`trg_users_wechsel_name`/`_mail`, audit round 2026-09-27): a foreign
        writer that carries the bucket ITSELF (`store.set_email` from 0.20.1 sets address and
        `topf_mail` in one statement) does not fire the recompute trigger — the bucket does
        change. Until then the watermark stayed at the state of the OLD identifier, and the first
        full sign-in cleared the failed attempts that a stranger had made under the new one before the change,
        also from the throttling of his IP. This trigger raises them when, in the same
        statement, the value AND the bucket change (to a bucket, not to NULL). The backfill
        (`_toepfe_schreiben`: only the bucket) does not fire it, nor does `B1` → `b1` in `_kennung_setzen`
        (there the bucket is at NULL in between); on a real change in
        `_kennung_setzen` it sets the same state that the statement has already written.

        **Identifier space** (`trg_users_kennung_insert`/`_update`, G12c): username and address
        are ONE space (`find_user` searches both), and the counting bucket folds more coarsely than NOCASE
        (`Alice`/`alice`, `Émile`/`émile`, full-width, Unicode and A-label domain). Until then the database
        knew only `UNIQUE(username)` (BINARY) and `ux_users_email` — check
        (`identifier_taken`) and write were separate, and two simultaneous registrations
        of the same identifier (one as name, one as address) both got through. Now the
        database rejects a NEWLY assigned bucket that is already the name or address of another account
        — in the same statement as the write, under SQLite's single writer.
        Why each part:

        * `UPDATE OF username, email`, not `OF topf_*`: the backfill (`_toepfe_schreiben`)
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
        def neu(spalte, alt, id_aus):
            andere = "id IS NOT NEW.id AND " if id_aus else ""
            fremd = "user_id IS NOT NEW.id AND " if id_aus else ""
            return (f"(NEW.{spalte} IS NOT {alt} AND NEW.{spalte} <> '' AND (EXISTS (SELECT 1 FROM users "
                    f"WHERE {andere}(topf_name = NEW.{spalte} OR topf_mail = NEW.{spalte})) "
                    f"OR EXISTS (SELECT 1 FROM federated_identity WHERE {fremd}name_topf = NEW.{spalte})))")
        abweisen = f"BEGIN SELECT RAISE(ABORT, '{cls.KENNUNG_VERGEBEN}'); END"
        arten = (("username", "topf_name", "name"), ("email", "topf_mail", "mail"))
        sql = [(f"trg_users_{topf}",
                f"CREATE TRIGGER IF NOT EXISTS trg_users_{topf} AFTER UPDATE OF {spalte} ON users "
                f"WHEN NEW.{topf} IS OLD.{topf} AND NEW.{spalte} IS NOT OLD.{spalte} "
                f"BEGIN UPDATE users SET {topf} = NULL, {art}_versuch_ab = {cls.WL_VERSUCH}, "
                f"{art}_audit_ab = {cls.WL_AUDIT} WHERE id = NEW.id; END")
               for spalte, topf, art in arten]
        sql += [(f"trg_users_wechsel_{art}",
                 f"CREATE TRIGGER IF NOT EXISTS trg_users_wechsel_{art} AFTER UPDATE OF {topf} ON users "
                 f"WHEN NEW.{topf} IS NOT NULL AND NEW.{topf} IS NOT OLD.{topf} "
                 f"AND NEW.{spalte} IS NOT OLD.{spalte} "
                 f"BEGIN UPDATE users SET {art}_versuch_ab = {cls.WL_VERSUCH}, "
                 f"{art}_audit_ab = {cls.WL_AUDIT} WHERE id = NEW.id; END")
                for spalte, topf, art in arten]
        sql.append(("trg_users_kennung_insert",
                    "CREATE TRIGGER IF NOT EXISTS trg_users_kennung_insert BEFORE INSERT ON users "
                    f"WHEN {neu('topf_name', 'NULL', False)} OR {neu('topf_mail', 'NULL', False)} "
                    + abweisen))
        sql.append(("trg_users_kennung_update",
                    "CREATE TRIGGER IF NOT EXISTS trg_users_kennung_update BEFORE UPDATE OF username, email "
                    f"ON users WHEN {neu('topf_name', 'OLD.topf_name', True)} "
                    f"OR {neu('topf_mail', 'OLD.topf_mail', True)} " + abweisen))
        return sql

    def _trigger_setzen(self) -> None:
        """Create the triggers from `_trigger_sql` — or replace them if an older version created them
        differently (without commit, under `_lock`, part of `_migrate`).

        `CREATE TRIGGER IF NOT EXISTS` alone would leave a trigger from schema 10 forever
        as it was back then. The comparison is made with the text in `sqlite_master` (SQLite stores it
        without `IF NOT EXISTS`; whitespace does not count). If it matches, nothing is written — not even
        on a read-only file."""
        for name, sql in self._trigger_sql():
            soll = " ".join(sql.replace(" IF NOT EXISTS", "", 1).split())
            steht = self.db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                                    (name,)).fetchone()
            if steht is not None and " ".join(str(steht[0] or "").split()) == soll:
                continue
            if steht is not None:
                self.db.execute(f"DROP TRIGGER IF EXISTS {name}")
            self.db.execute(sql)

    #: Setting key: has `users.name_selbst_gewaehlt` been backfilled for existing data (G2-N)?
    NAME_SELBST_NACHGETRAGEN = "name_selbst_nachgetragen"

    def _name_selbst_nachtragen(self) -> None:
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

        Exactly once, via the marker `NAME_SELBST_NACHGETRAGEN` in the same commit: if it ran on every
        start, the row of a later rename by the operator would make the account a
        self-named one again."""
        self.db.execute(
            "UPDATE users SET name_selbst_gewaehlt = 1 WHERE name_selbst_gewaehlt = 0 AND is_service = 0 "
            "AND EXISTS (SELECT 1 FROM audit a WHERE lower(a.username) = lower(users.username) "
            "AND a.ts >= users.created_at AND a.event IN ('signup', 'username_changed'))")
        self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                        (self.NAME_SELBST_NACHGETRAGEN, str(_now())))

    def _werte_englisch(self, links: bool = True) -> int:
        """Bring stored values of the public interface to their English names (schema
        12, PO decision 2026-09-27) — without commit, under `_lock`, part of `_migrate`.

        * `api_key.kind`: `automat` → `automation`, `mensch` → `human` (`KEY_ARTEN_ALT`) — the kind
          is seen by everyone who lists keys (`list_api_keys`, `api_key_kind`, `GET /auth/apikeys`,
          the panel). On EVERY start, not only on the jump over the stamp: an older version
          that ran on the file after a rollback has written old values again, and it
          does not lower the stamp. The table is small.
        * Payload of open address-change links (`magic_token`, `purpose='email_change'`): `alt` →
          `old` (`payload_lesen`) — visible via `peek_magic`/`redeem_magic`. Only with
          `links=True` (on the jump to 12): the search goes through all one-time tokens, and they grow
          until the next `gc` — on every start that would cost a run through the table
          (measured in `tests/test_legacy_data.py`, "Aufwand"). A link that an older version
          issues afterwards is mapped by `payload_lesen` on reading; it expires soon anyway.

        Idempotent; it writes only where there is something to rewrite — a read-only file
        without old values starts as before. Returns: the number of changed rows.

        Not translated is what is only read internally (the kind of a series `fehlserie.art`, the
        column names) and what is in the audit log — its rows stay as they are."""
        n = 0
        for alt, neu in self.KEY_ARTEN_ALT.items():
            if self.db.execute("SELECT 1 FROM api_key WHERE kind=? LIMIT 1", (alt,)).fetchone():
                n += self.db.execute("UPDATE api_key SET kind=? WHERE kind=?", (neu, alt)).rowcount
        for purpose, schluessel in (_PAYLOAD_SCHLUESSEL_ALT.items() if links else ()):
            for alt in schluessel:
                for z in self.db.execute(
                        "SELECT token_hash, payload FROM magic_token WHERE purpose=? AND payload LIKE ?",
                        (purpose, f'%"{alt}"%')).fetchall():
                    try:
                        neu_text = json.dumps(payload_lesen(purpose, z["payload"]))
                    except ValueError:
                        continue          # not JSON: not ours, do not touch
                    if neu_text != z["payload"]:
                        self.db.execute("UPDATE magic_token SET payload=? WHERE token_hash=?",
                                        (neu_text, z["token_hash"]))
                        n += 1
        return n

    #: Setting key: has `users.name_quelle` been backfilled for existing data (attack round 2026-09-26)?
    NAME_QUELLE_NACHGETRAGEN = "name_quelle_nachgetragen"

    #: How far apart creation and binding of a source may be for the binding to count as "the
    #: source created the account" (`_name_quelle_nachtragen`). On creation both happen in
    #: the same sign-in, without a directory call in between — fractions of a second.
    ANLAGE_TOLERANZ_SEC = 2

    def _name_quelle_nachtragen(self) -> None:
        """Backfill `users.name_quelle` once for existing data where the origin is proven (without
        commit, under `_lock`, part of `_migrate`).

        * **OIDC:** every row in `oidc_identity` has been written by the callback since v0.1 on CREATING
          the account — it never links an existing one. The account therefore carries the provider's name.
        * **LDAP/SAML:** a binding (also the placeholder) that arose with the creation of the account
          (`gebunden_at` at most `ANLAGE_TOLERANZ_SEC` before or after `created_at`). A later
          re-binding does not count — the account already existed then, and its name came from elsewhere.

        Excluded: service accounts and self-chosen names (the marker above already carries them).
        Accounts from before the identifiers (F-11, up to 0.19) have no binding from creation and stay
        NULL — the deadline applies to them (`federation_name_binding_days`). Limit in the safe
        direction: if the operator creates an account and binds it within two seconds, it counts as created by
        the source; another source binds it then only if the operator opens it
        (`federation_unbind`).

        Exactly once, via the marker `NAME_QUELLE_NACHGETRAGEN` in the same commit: if it ran on every start,
        an account renamed by the operator would get its source back."""
        self.db.execute(
            "UPDATE users SET name_quelle = 'oidc' WHERE name_quelle IS NULL AND is_service = 0 "
            "AND name_selbst_gewaehlt = 0 AND id IN (SELECT user_id FROM oidc_identity)")
        aus_anlage = ("FROM federated_identity f WHERE f.user_id = users.id "
                      "AND abs(f.gebunden_at - users.created_at) <= ?")
        self.db.execute(
            f"UPDATE users SET name_quelle = (SELECT f.quelle {aus_anlage} "
            "ORDER BY f.gebunden_at, f.quelle LIMIT 1) "
            "WHERE name_quelle IS NULL AND is_service = 0 AND name_selbst_gewaehlt = 0 "
            f"AND EXISTS (SELECT 1 {aus_anlage})",
            (self.ANLAGE_TOLERANZ_SEC, self.ANLAGE_TOLERANZ_SEC))
        self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                        (self.NAME_QUELLE_NACHGETRAGEN, str(_now())))

    #: Setting key: up to which `audit.id` the panel lockouts of older writers have already been
    #: caught up (`_bestand_nachziehen`). If it is missing, the next start reads the audit log
    #: in full once — that is only slower, not wrong (every step is repeatable).
    PANEL_WASSERLINIE = "panel_sperren_bis"

    #: How many identifiers at most in one `IN (…)` (SQLite up to 3.32: 999 parameters).
    IN_STUECK = 500

    @staticmethod
    def _uid_aus_detail(detail) -> Optional[int]:
        """The account id from the detail of a panel row: `uid=<id>` or `uid=<id> …`.

        The same form that the SQL version compared (`detail = 'uid=' || id` or
        `LIKE 'uid=' || id || ' %'`): only ASCII digits without a leading zero, then end or a
        space. The panel has written this form unchanged since 0.3.0."""
        kopf = str(detail or "").split(" ", 1)[0]
        if not kopf.startswith("uid="):
            return None
        zahl = kopf[4:]
        if not (zahl.isascii() and zahl.isdigit()) or zahl != str(int(zahl)):
            return None
        return int(zahl)

    def _owner_nachziehen(self) -> None:
        """If there are admins but no owner (existing data from before the owner model), the oldest admin
        becomes owner — preferably one that someone set by hand (`is_admin=1`), active and not a
        service account. Once, with a row in the audit log. Runs in the migration (under the
        write lock, directly on the connection) — BEFORE the watermark of the existing-data steps, so that
        its own row does not count as "new since the last start". Without an admin it stays with the
        first-admin path, which also assigns the first owner."""
        spalten = {r["name"] for r in self.db.execute("PRAGMA table_info(users)")}
        if "is_owner" not in spalten:
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
                    "Kein Owner: Es gibt Admins, aber keinen aktiven, von Hand gesetzten (nur vom "
                    "Identity Provider vergebene oder gesperrte). Einen Owner bestimmen: "
                    "`tinysesam owner --db <datei> <benutzer>`.")
            return
        self.db.execute("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (u["id"],))
        self.db.execute("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                        (_now(), "owner_grant", u["username"], None, "quelle=bestand aeltester_admin"))
        logging.getLogger("tinysesam").warning(
            "Owner-Modell: %s ist jetzt Owner (ältester Admin). Weitere Owner vergibt ein Owner im "
            "Admin-Panel.", u["username"])

    def _bestand_nachziehen(self, ab_anfang: bool, ohne_topf) -> None:
        """Bring existing data to schema 10 (without commit, under `_lock` — part of `_migrate`).

        On upgrade (`ab_anfang`) for all existing data, afterwards on **every** start for what
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
           after the watermark (`PANEL_WASSERLINIE`, on upgrade from 0): the first version searched
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
           (`konto_entfernen`) — even when a lock in the panel has discarded the tokens
           by which the account is otherwise recognisable as open. After the upgrade only for
           rows without a bucket (only a foreign writer creates them) and for the accounts from
           step 1. Step 2 runs before step 1, which discards exactly these tokens."""
        log = logging.getLogger("tinysesam")
        # Reading and writing under ONE write lock: a second worker that is just redeeming a
        # confirmation link sees the lock before or after, not in between. On
        # upgrade `_migrate` already holds the transaction (DELETE above).
        if not self.db.in_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        zeile = self.db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit'").fetchone()
        bis = int(zeile[0]) if zeile and zeile[0] else 0
        gespeichert = self.db.execute("SELECT value FROM setting WHERE key=?",
                                      (self.PANEL_WASSERLINIE,)).fetchone()
        gespeichert = gespeichert[0] if gespeichert else None
        ab = 0
        if not ab_anfang and gespeichert is not None and str(gespeichert).isdigit():
            ab = int(gespeichert)
        if ab > bis:
            ab = 0          # counter smaller than the watermark (table recreated): read everything
        juengstes = {}
        for ereignis, detail in self.db.execute(
                "SELECT event, detail FROM audit WHERE id > ? AND id <= ? "
                "AND event IN ('user_disable', 'user_enable') ORDER BY id", (ab, bis)):
            uid = self._uid_aus_detail(detail)
            if uid is not None:
                juengstes[uid] = ereignis
        kandidaten = sorted(uid for uid, ereignis in juengstes.items() if ereignis == "user_disable")

        def stuecke(ids):
            ids = list(ids)
            for i in range(0, len(ids), self.IN_STUECK):
                teil = ids[i:i + self.IN_STUECK]
                yield teil, ",".join("?" * len(teil))

        adressen = 0
        ziel = None if ab_anfang else {z["id"] for z in ohne_topf} | set(kandidaten)
        if ziel is None or ziel:
            offen = sorted(z[0] for z in self.db.execute(
                "SELECT user_id FROM magic_token WHERE purpose = 'verify_email' AND user_id IS NOT NULL "
                "GROUP BY user_id HAVING SUM(used_at IS NULL) > 0 AND SUM(used_at IS NOT NULL) = 0")
                if ziel is None or z[0] in ziel)
            for teil, ph in stuecke(offen):
                adressen += self.db.execute(
                    f"UPDATE users SET email_verified=0 WHERE id IN ({ph}) AND email_verified <> 0 "
                    "AND disabled <> 0 AND first_login_at IS NULL", teil).rowcount
        panel = []
        for teil, ph in stuecke(kandidaten):
            ids = [z[0] for z in self.db.execute(
                f"SELECT id FROM users WHERE id IN ({ph}) AND disabled = ?",
                (*teil, self.GESPERRT_BESTAETIGUNG))]
            if not ids:
                continue
            ph = ",".join("?" * len(ids))
            self.db.execute(f"UPDATE users SET disabled=? WHERE id IN ({ph}) AND disabled = ?",
                            (self.GESPERRT_BETREIBER, *ids, self.GESPERRT_BESTAETIGUNG))
            self.db.execute(f"DELETE FROM magic_token WHERE user_id IN ({ph}) AND used_at IS NULL", ids)
            panel += ids
        if gespeichert is None or str(gespeichert) != str(bis):
            self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                            (self.PANEL_WASSERLINIE, str(bis)))
        if ab_anfang and (adressen or panel):
            log.info("Schema 10: %d Sperre(n) aus dem Panel tragen jetzt den Betreiber-Vermerk (offene "
                     "Einmal-Token verworfen), %d Adresse(n) offener Registrierungen gelten bis zur "
                     "Bestätigung als unbelegt.", len(panel), adressen)
        elif adressen or panel:
            log.warning("Eine ältere TinySesam-Fassung hat in diese Datenbank geschrieben (Rückschritt "
                        "ohne Sicherung?): %d Sperre(n) aus ihrem Panel tragen jetzt den "
                        "Betreiber-Vermerk (offene Einmal-Token verworfen), %d Adresse(n) ihrer "
                        "offenen Registrierungen gelten bis zur Bestätigung als unbelegt.",
                        len(panel), adressen)

    def _toepfe_schreiben(self, zeilen) -> None:
        """Compute `topf_name`/`topf_mail` for these account rows (without commit, under `_lock`).

        Written only if name and address are still the ones read: if another
        writer changes them in between, its trigger sets the bucket to NULL, and the next call
        recomputes — instead of the bucket of the old name remaining here."""
        self.db.executemany(
            "UPDATE users SET topf_name=?, topf_mail=? WHERE id=? AND username IS ? AND email IS ?",
            [(norm_kennung(z["username"]), norm_kennung(z["email"]), z["id"], z["username"], z["email"])
             for z in zeilen])

    def _toepfe_nachtragen(self) -> list:
        """Backfill missing counting buckets — the rows of another writer (see `topf_name`).

        Returns the rows that could NOT be written (database read-only, locked);
        the caller checks those itself. Normally that is none, and it costs one query
        over the index — independent of which identifier is being looked up."""
        offen = self._all("SELECT * FROM users WHERE topf_name IS NULL OR topf_mail IS NULL")
        if not offen:
            return []
        try:
            with self._schreibend():
                self._toepfe_schreiben(offen)
                self.db.commit()
        except sqlite3.Error:
            return offen
        return []

    def _one(self, sql, args=()):
        with self._lock:
            cur = self.db.execute(sql, args)
            return cur.fetchone()

    def _all(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def _verwerfen(self) -> None:
        """Roll back an open transaction (under `_lock`) — after a failed write."""
        try:
            self.db.rollback()
        except sqlite3.Error:
            pass     # connection closed or similar — then nothing is left open either

    def _begin_immediate(self) -> None:
        """`BEGIN IMMEDIATE` for a self-managed transaction (under `_lock`) — counting and
        booking in one step, also across several processes (`reserve_attempt`, `finish_attempt`)."""
        if self.db.in_transaction:
            # The second lock behind `_schreibend`: if a transaction is lying around anyway (a
            # writer that did not roll back on failure), the BEGIN below would fail on it —
            # and with it every sign-in until someone else committed. Its content is the remainder
            # of a FAILED write; it is discarded, not booked along. Loud, because
            # it is an error elsewhere.
            logging.getLogger("tinysesam").warning(
                "Offene Transaktion auf der Datenbankverbindung vorgefunden (Rest eines "
                "gescheiterten Schreibzugriffs) — verworfen, bevor der Anmeldeversuch zählt.")
            self._verwerfen()
        self.db.execute("BEGIN IMMEDIATE")

    @contextlib.contextmanager
    def _schreibend(self):
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
        transaction themselves (`reserve_attempt`, `rotate_session`, `_uhr_mitschreiben`, the
        inner block of `_migrate`) puts each commit in a `try` whose broad `except`
        (without type, `Exception` or `BaseException` — `sqlite3.Error` does not catch a binding error such as
        OverflowError) or `finally` rolls back. tests/test_hardening2.py checks this via the
        syntax tree for every commit in this class — not merely whether `rollback()`
        appears somewhere in the function."""
        with self._lock:
            try:
                yield
            except BaseException:
                self._verwerfen()
                raise

    def _exec(self, sql, args=()):
        with self._schreibend():
            cur = self.db.execute(sql, args)
            self.db.commit()
            self._geschrieben = time.monotonic()
            self._uhr_mitschreiben()
            return cur

    #: Setting key of the saved clock state (see `_Uhr`) and how often it is written at most
    #: (seconds).
    UHR_STAND = "uhr_stand"
    UHR_SICHERN_SEK = 60

    def _uhr_stand_schreiben(self) -> None:
        """Raise `uhr_stand` to `jetzt()` — only UPWARDS (without commit, under `_lock`).

        `_migrate()` already writes before `Store()` has raised the clock from the database;
        there `jetzt()` is still the wrong wall clock of a boot with an old date. A blind
        overwrite would delete exactly the state that is about to raise the clock."""
        jetzt_s = _now()
        self.db.execute("INSERT OR IGNORE INTO setting(key, value) VALUES (?, ?)",
                        (self.UHR_STAND, str(jetzt_s)))
        self.db.execute("UPDATE setting SET value=? WHERE key=? AND CAST(value AS INTEGER) < ?",
                        (str(jetzt_s), self.UHR_STAND, jetzt_s))

    @staticmethod
    def _frisch(seit, m, frist) -> bool:
        """Is the monotonic stamp `seit` less than `frist` seconds before `m`?

        A NEGATIVE distance counts as expired, not as fresh: freezegun delivers
        `time.monotonic` on the epoch scale (≈1.8e9). A write under `freeze_time`
        left the stamps there, and afterwards every distance was negative, hence always "shorter than
        the deadline" — `uhr_stand` was no longer saved in the whole process, the write probe
        checked only the connection (second attack round, same class as in `_Uhr.jetzt`).
        A distance above any deadline is expired anyway."""
        return seit is not None and 0 <= m - seit < frist

    def _uhr_mitschreiben(self) -> None:
        """Save the clock state — at most once per `UHR_SICHERN_SEK` (under `_lock`).

        Without it a restart knew only the last event in the database: what expired afterwards
        applied again for its full remaining lifetime after a boot with an old date (B6-9). Own
        commit AFTER the actual write: if it fails (volume full), it must not drag down the
        already confirmed write — the state is a bonus."""
        m = time.monotonic()
        if self._frisch(self._uhr_gesichert, m, self.UHR_SICHERN_SEK):
            return
        try:
            self._uhr_stand_schreiben()
            self.db.commit()
            self._uhr_gesichert = m
        except Exception as fehler:
            # Rolled back on EVERY failure, only the database error is swallowed (the
            # clock state is a precaution). Until the final round, `except sqlite3.Error:` caught here —
            # a binding error such as OverflowError is not one and left the transaction open;
            # only the outer `_schreibend` of `_exec` saved it.
            self._verwerfen()
            if not isinstance(fehler, sqlite3.Error):
                raise

    # ---------- Users ----------
    def create_user(self, username, display_name=None, email=None, is_admin=False, roles=None,
                    is_service=False, email_verified=True, name_selbst_gewaehlt=False,
                    name_quelle=None) -> int:
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
            f"{self.WL_VERSUCH},{self.WL_VERSUCH},{self.WL_AUDIT},{self.WL_AUDIT},?,?)",
            (username, display_name or username, mail, 1 if email_verified else 0,
             1 if is_admin else 0,
             json.dumps(list(roles or [])), 1 if is_service else 0, _now(),
             norm_kennung(username), norm_kennung(mail), 1 if name_selbst_gewaehlt else 0,
             name_quelle or None))
        return cur.lastrowid

    def _kennung_setzen(self, user_id, spalte: str, wert, topf: str, beleg=None) -> list:
        """The statements that replace name (`spalte="username"`) or address (`"email"`, with `beleg`)
        together with the counting bucket — for `_umschreiben`.

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

        For the name a third is added at the front (`_verzeichnisname_merken`, audit round 2026-09-27):
        an account with an LDAP binding whose name was the name in the directory keeps the old one as
        directory name — otherwise it would drop out of `zaehl_kennungen` and out of the
        identifier space on renaming, until the next successful LDAP sign-in."""
        topf_spalte, art = ("topf_name", "name") if spalte == "username" else ("topf_mail", "mail")
        gleich = f"CASE WHEN {topf_spalte} IS ? THEN"
        setzen = (f"{topf_spalte} = {gleich} NULL ELSE ? END, "
                  f"{art}_versuch_ab = {gleich} {art}_versuch_ab ELSE {self.WL_VERSUCH} END, "
                  f"{art}_audit_ab = {gleich} {art}_audit_ab ELSE {self.WL_AUDIT} END")
        erste: tuple
        if beleg is None:
            erste = (f"UPDATE users SET {spalte}=?, {setzen} WHERE id=?",
                     (wert, topf, topf, topf, topf, user_id))
        else:
            erste = (f"UPDATE users SET {spalte}=?, email_verified=?, {setzen} WHERE id=?",
                     (wert, 1 if beleg else 0, topf, topf, topf, topf, user_id))
        vorab = [self._verzeichnisname_merken(user_id, topf)] if spalte == "username" else []
        return vorab + [erste, (f"UPDATE users SET {topf_spalte}=? WHERE id=?", (topf, user_id))]

    def _verzeichnisname_merken(self, user_id, neuer_topf) -> tuple:
        """The statement that, before a rename, records the previous name as the name in the directory
        on the LDAP binding (`federated_identity.name_topf`, G5) — for `_kennung_setzen`.

        Occasion (audit round 2026-09-27): if an account is named the same locally and in the directory, NULL stands there
        (`bindung_name_setzen` records only a differing name). If the operator
        (G13, panel, `tinysesam rename`) or the person themselves renamed the account, the
        directory name dropped out of `zaehl_kennungen`: if a stranger had filled the series beneath it before, the
        LDAP sign-in stayed locked — panel reset and full sign-in by another route did not
        clear it, only `tinysesam unlock <directory name>`. And the name was free locally: another
        account could take it and, with every sign-in, clear the counters against the LDAP
        password.

        Only a real identifier (not the origin placeholder `OHNE_KENNUNG`): without a stable
        identifier LDAP matches via the name — after renaming, the old name no longer
        belongs to this account. Only if NULL stands (a differing name is already recorded and
        the younger one) and only if the bucket really changes. The old bucket is read in
        the same transaction, before the new name is written."""
        alt = "(SELECT topf_name FROM users WHERE id = ?)"
        return (f"UPDATE federated_identity SET name_topf = {alt} WHERE quelle = 'ldap' AND user_id = ? "
                "AND name_topf IS NULL AND substr(kennung, 1, length(?)) <> ? "
                f"AND {alt} IS NOT NULL AND {alt} <> '' AND {alt} IS NOT ?",
                (user_id, user_id, self.OHNE_KENNUNG, self.OHNE_KENNUNG, user_id, user_id, user_id,
                 neuer_topf))

    def _umschreiben(self, schritte) -> None:
        """Several statements in ONE transaction, one commit (like `_exec`, only for a list).
        If one fails — also on an identifier trigger (`IntegrityError`) — `_schreibend` rolls
        all of them back."""
        with self._schreibend():
            for sql, args in schritte:
                self.db.execute(sql, args)
            self.db.commit()
            self._geschrieben = time.monotonic()
            self._uhr_mitschreiben()

    def set_username(self, user_id, username, selbst_gewaehlt: Optional[bool] = None) -> None:
        """Replace the username — together with the counting bucket (`topf_name`) in the same transaction.
        The check happens beforehand (`TinySesam.change_username`); this only writes. If the name is
        already the identifier of another account (name, address or namesake in the bucket), the
        database rejects it: `sqlite3.IntegrityError`, nothing changed.

        `selbst_gewaehlt` sets the marker `users.name_selbst_gewaehlt` (G2-N) in the same
        transaction and deletes the origin `users.name_quelle`: the new name comes from the person
        or the operator, no longer from the source that created the account. `None` leaves
        both as they are."""
        name = str(username or "").strip()
        schritte = self._kennung_setzen(user_id, "username", name, norm_kennung(name))
        if selbst_gewaehlt is not None:
            schritte.append(("UPDATE users SET name_selbst_gewaehlt=?, name_quelle=NULL WHERE id=?",
                             (1 if selbst_gewaehlt else 0, user_id)))
        self._umschreiben(schritte)

    def set_email(self, user_id, email, verified: bool = False):
        """Replace the address — **together with its proof**, by default "unconfirmed".

        The proof belongs to the address, not to the account: since `users.email_verified` decides
        on rights (`_maybe_promote_admin`, stage 2), a marker left standing would be
        the proof of the **old** address on the **new** one — exactly that was measured
        (B-umgehung-8 from T-13): `eve@example.com` (proven) → `set_email(uid, "boss@example.com")` →
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
        self._umschreiben(self._kennung_setzen(user_id, "email", mail, norm_kennung(mail), bool(verified)))

    def adresse_wechseln(self, user_id, email, name_folgt: bool = False) -> None:
        """Enter the confirmed new address (with proof) and, if `name_folgt`, set the name
        to the same address (email mode) — in ONE transaction.

        Written separately (`set_email`, then `set_username`), the second could fail
        after the first was already in place: new address, name still the old address — and the old
        address stayed occupied as the account's name. If one statement fails here (the new
        identifier has meanwhile been taken: `sqlite3.IntegrityError`), both stay as they were."""
        mail = norm_email(email)
        topf = norm_kennung(mail)
        schritte = self._kennung_setzen(user_id, "email", mail, topf, True)
        if name_folgt:
            schritte += self._kennung_setzen(user_id, "username", mail, topf)
        self._umschreiben(schritte)

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
        kanonisch = norm_email(email)
        if not kanonisch:
            return None
        # Also look for the form from before R4-06 (only trimmed and lowercase): a stored address
        # with an umlaut domain is still in Unicode form in existing data and would otherwise not be found.
        # And in BOTH directions (attack A5): the Unicode form is also recovered from the A-label
        # input — otherwise `user@xn--bcher-kva.example` did not find the existing entry
        # `user@bücher.example`, and the registration created a second account for the same
        # mailbox.
        alt = str(email or "").strip().lower()
        unicode_form = _email_unicode(kanonisch)
        return self._one("SELECT * FROM users WHERE email COLLATE NOCASE IN (?, ?, ?) ORDER BY id LIMIT 1",
                         (kanonisch, alt, unicode_form))

    def konto_entfernen(self, user_id, adresse_unbefristet: bool = False) -> Optional[tuple[str, int]]:
        """Delete an account — the ONE deletion path that every caller goes through (H-13).

        Account together with credentials and sessions, the sign-in attempts under name and address, and
        in the audit log the name becomes `gelöscht#<id>` (`audit_anonymisieren`). A deleted
        account whose name still stands in every row is not deleted.

        Why here and not in the manager: until the T-13 integration there were four deletion paths with two
        different promises. `TinySesam.delete_user` anonymised, `gc()`, `tinysesam gc` (which
        works directly on the store) and the rollback after a failed confirmation send
        called `delete_user` and left name, foreign IP and the victim's address standing — a
        later namesake saw the stranger's registration as their own event
        (integration findings 12/18). The store is the deepest place that all paths share.

        **Only what arose from the creation of the account** (`anlage_grenze` — the same limit as
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
        joining** (`kennung_grenzen`) — an account gets name and address later too
        (rename, address change). To the exact row, also in the second of joining. The
        creation remains the fallback for existing data without a watermark.

        `adresse_unbefristet=True` exempts a **proven** address (`adresse_belegt`):
        it demonstrably belongs to the account and is also replaced in older rows (the
        invitation that led to the account). That is the deliberate deletion by an admin
        (`TinySesam.delete_user`, H-13) — not a path that an anonymous party triggers. `gc()`, the
        rollback and `_purge_demo` clear accounts that never belonged to anyone; there the
        limit applies to the address too. And even for deletion by an admin only for a
        PROVEN address: that of an open account (registration, link never redeemed) or
        of a registration without confirmation requirement was typed in by a stranger — without this
        distinction, clearing such accounts in the panel would rewrite the admin's invitation
        and the failed attempts of the real holder from BEFORE creation to `gelöscht#<id>`.

        The sign-in attempts of a counting bucket (`norm_kennung`) that a REMAINING account
        shares stay in place (see `delete_attempts_for`).

        Returns `(replacement name, anonymised rows)` — under the replacement name the
        caller writes its own row (`user_delete`, `signup_expired`, `verify_send_error`) —,
        None if the account does not exist."""
        u = self.get_user(user_id)
        if u is None:
            return None
        name, mail = str(u["username"]), (u["email"] or "")
        seit, seit_id = self.anlage_grenze(u)
        # More precise than creation: from when each identifier belonged to the account (G2). Read before
        # deleting — afterwards the row no longer exists.
        grenzen = self.kennung_grenzen(u)
        unbefristet = (mail,) if (adresse_unbefristet and self.adresse_belegt(u)) else ()
        self.delete_user(user_id)
        self.delete_attempts_for(name, (mail,), nach=seit, unbefristet=unbefristet,
                                 ab_ids={t: g[0] for t, g in grenzen.items()})
        ersatz = ersatzname(user_id)
        return ersatz, self.audit_anonymisieren(name, ersatz, (mail,), seit=seit, seit_id=seit_id,
                                                unbefristet=unbefristet,
                                                ab_ids={t: g[1] for t, g in grenzen.items()})

    def adresse_belegt(self, user) -> bool:
        """Does the address of this account demonstrably belong to it? (`konto_entfernen`, H-13)

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
        offen = self._one(
            "SELECT 1 AS x FROM magic_token WHERE user_id=? AND purpose='verify_email' "
            "  AND used_at IS NULL "
            "  AND NOT EXISTS (SELECT 1 FROM magic_token WHERE user_id=? AND purpose='verify_email' "
            "      AND used_at IS NOT NULL) LIMIT 1", (user["id"], user["id"]))
        return offen is None

    def anlage_grenze(self, user) -> tuple[int, int]:
        """From where does an audit row belong to this account? `(seit, seit_id)` — the fallback.

        Since 2026-09-26 the watermark of the identifier applies first (`kennung_grenzen`, G2): an
        account that takes over a name that became free otherwise saw here the sign-ins of the
        previous owner including their IP. This limit now carries only the existing data whose accounts do not have the
        watermark.

        `seit` is `created_at` (Unix seconds). From the second of creation itself only rows
        from `seit_id` count: the registration row of the account (`signup`, for the placeholder
        `signup_taken`), which is written right after creation. Without it the limit would be
        accurate to the second only — and a stranger who registers in the same second in which
        the admin invites the address or a sprayer tries the free name would have their
        rows attributed. Exactly these paths (registration, `gc()`, B6-5) always have the row;
        an account without it (admin API, SSO, demo) falls back to `seit_id = 0` — then
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

        Filter for SQL: `ts > seit OR (ts = seit AND id >= seit_id)`."""
        seit = int(user["created_at"] or 0)
        platzhalter = not user["email"]
        for z in self._all(
                "SELECT id, event, username, detail FROM audit WHERE event IN ('signup', 'signup_taken') "
                "AND lower(username) = lower(?) AND ts BETWEEN ? AND ? ORDER BY id",
                (str(user["username"]), seit, seit + 1)):
            if z["event"] == "signup" or (
                    platzhalter and norm_email(z["username"]) != norm_email(z["detail"])):
                return seit, int(z["id"])
        return seit, 0

    def konto_mit_topf(self, kennung, ausser=None) -> Optional[sqlite3.Row]:
        """The first account whose name or address falls into the same counting bucket as `kennung`.

        The bucket is `norm_kennung` (Python `lower()`), whereas the database's name check is
        `COLLATE NOCASE` — and that folds only ASCII. `Émile` and `émile` are two
        names for SQLite, one for the lockout counter. That is why each account carries its bucket as a column
        (`topf_name`/`topf_mail`, computed in Python), and the lookup goes through its index.

        Up to schema 10 the lookup ran as a loop over ALL accounts in Python — on every
        registration, and for one with a free address twice as often as for one with a
        taken address: from a few thousand accounts on, the response time of a single request revealed
        whether an address has an account (R4-03), and `gc()` grew with open × all accounts.
        The work here now depends neither on the number of accounts nor on whether and where the
        identifier is found (tests/test_audit_round2.py counts the SQLite steps).
        `ausser` leaves out one account (the ID currently at issue)."""
        topf = norm_kennung(kennung)
        if not topf:
            return None
        # Rows whose bucket could not be backfilled (database read-only) are checked by Python —
        # normally none.
        treffer = [z for z in self._toepfe_nachtragen()
                   if z["id"] != ausser and topf in (norm_kennung(z["username"]), norm_kennung(z["email"]))]
        z = self._one("SELECT * FROM users WHERE (topf_name = ? OR topf_mail = ?) AND id IS NOT ? "
                      "ORDER BY id LIMIT 1", (topf, topf, ausser))
        if z is not None:
            treffer.append(z)
        return min(treffer, key=lambda t: t["id"]) if treffer else None

    def topf_eines_anderen(self, kennung, user_id) -> bool:
        """Is this identifier (in the counting bucket) the name or address of an account OTHER than `user_id`?

        The guard before every clearing under an identifier that the account does not itself carry as name or
        address (G5, G5-N1): under the name from the directory (`zaehl_kennungen`) and
        under the typed identifier of a directory sign-in (`TinySesam._record_login`). A
        directory filter on `mail` resolves `chefin@example.com` to a third party whose
        `mail` attribute reads that way; without this guard every sign-in of the third party cleared the
        counters of the local holder of this address — unlimited guessing against her account.
        It is checked when clearing, not when writing: an identifier can change owner."""
        return self.konto_mit_topf(kennung, ausser=user_id) is not None

    @staticmethod
    def _feld(zeile, name):
        """A column of the account row — None if it does not (yet) exist (dummy, old dict)."""
        try:
            return zeile[name]
        except (IndexError, KeyError):
            return None

    def kennung_grenzen(self, user) -> dict:
        """From where does a row under name or address belong to this account? (limit a, G2)

        `{bucket: (versuch_ab, audit_ab)}` for name and address in the counting bucket: rows in
        `login_attempt` or `audit` with a LARGER id belong to the account, the others belonged
        to nobody or to someone else. `None` means existing data (the columns only arrived with this
        state) — then, as until 2026-09-26, the creation applies (`created_at`, `anlage_grenze`).

        Until then the creation was the limit for EVERY identifier. But an account gets an identifier
        later too: on renaming, on address change, on backfilling an address from OIDC.
        The failed attempts that a stranger had made earlier under the then free name
        were cleared by the first full sign-in — also from the throttling of his IP —, and the
        account page showed the previous owner's sign-in including their IP.

        Name and address in the same bucket (email mode): the earlier of the two watermarks —
        the identifier belongs to the account since it was added by one of the two paths. If one
        of them is NULL, the fallback applies."""
        aus: dict = {}
        for spalte, art in (("username", "name"), ("email", "mail")):
            topf = norm_kennung(self._feld(user, spalte))
            if not topf:
                continue
            werte = tuple(None if w is None else int(w)
                          for w in (self._feld(user, f"{art}_versuch_ab"), self._feld(user, f"{art}_audit_ab")))
            if topf in aus:
                werte = tuple(None if a is None or b is None else min(a, b) for a, b in zip(aus[topf], werte))
            aus[topf] = werte
        return aus

    def konto_mit_verzeichnisname(self, kennung, ausser=None) -> Optional[sqlite3.Row]:
        """The account (not `ausser`) on whose binding this identifier stands as the name in the directory
        (`federated_identity.name_topf`, G5) — or None. For `TinySesam.identifier_taken` and
        `tinysesam rename`; the database checks the same in the identifier triggers (`_trigger_sql`).
        Via `ix_fed_name_topf`, no scan."""
        topf = norm_kennung(kennung)
        if not topf:
            return None
        z = self._one("SELECT user_id FROM federated_identity WHERE name_topf = ? AND user_id IS NOT ? "
                      "ORDER BY user_id LIMIT 1", (topf, ausser))
        return self.get_user(z["user_id"]) if z else None

    def zaehl_kennungen(self, user_id) -> set:
        """All identifiers (in the counting bucket) under which the series (B2-6) of this account can stand.

        Name and address — and the name under which the account signs in via a directory source
        (`federated_identity.name_topf`, G5), provided it is not the name or address of an
        OTHER account (`topf_eines_anderen`) and does not also stand on another account's binding
        (audit round 2026-09-27, p1-a: after renaming and reassignment in the directory,
        two accounts carried the same name, and every full sign-in of the previous owner ended the series
        under which the new holder was being guessed against). Since then `bindung_name_setzen` deletes the
        name on foreign bindings; if two exist in existing data, it counts for neither — until the next
        LDAP sign-in under it. The series counts under the TYPED identifier;
        after a rename in the directory (locally `alice`, there `alice.neu`), until
        2026-09-26 no way back cleared the series under `alice.neu` — one's own typos added up
        over the years, and a stranger permanently locked the person out with enough failed attempts.

        The one reader for every way back: `lift_lockout`, `_serie_beenden` (panel reset),
        `tinysesam passwd` and `tinysesam unlock`."""
        u = self.get_user(user_id)
        if u is None:
            return set()
        kennungen = {norm_kennung(u["username"]), norm_kennung(u["email"])} - {""}
        for z in self._all("SELECT DISTINCT name_topf FROM federated_identity WHERE user_id=? "
                           "AND name_topf IS NOT NULL AND name_topf <> ''", (user_id,)):
            topf = norm_kennung(z["name_topf"])
            if (topf and topf not in kennungen and not self.topf_eines_anderen(topf, user_id)
                    and self.konto_mit_verzeichnisname(topf, ausser=user_id) is None):
                kennungen.add(topf)
        return kennungen

    def bindung_name_setzen(self, quelle: str, user_id, name) -> bool:
        """Record the name under which the account has just signed in via `quelle` on its
        binding (`federated_identity.name_topf`, G5). Returns whether anything was written.

        Folded (`norm_kennung`) and only if it is neither name nor address of the account — the
        ways back know those anyway; then NULL stands. Only the most recent name: after two
        renames in the directory nobody signing in that way counts under the oldest any more.
        It writes only on a change, so at most one UPDATE per sign-in and normally
        none. Whether the name is the name or address of an OTHER account is checked by every reader
        (`zaehl_kennungen`), not by this writer.

        **The most recent sign-in under the name proves who it belongs to** (audit round 2026-09-27,
        p1-a): if the same name stands on the binding of an OTHER account, it is stale there — renamed
        in the directory and reassigned. It is deleted there, even if it stays NULL here as own
        name or own address. Until then both carried it, every full sign-in of the
        previous owner ended the new holder's series, and `tinysesam unlock` named the account
        with the younger binding instead of the one that had last signed in that way."""
        u = self.get_user(user_id)
        if u is None:
            return False
        topf = norm_kennung(name)
        if topf and self.konto_mit_verzeichnisname(topf, ausser=user_id) is not None:
            self._exec("UPDATE federated_identity SET name_topf=NULL WHERE name_topf=? AND user_id IS NOT ?",
                       (topf, user_id))
        wert = None if not topf or topf in {norm_kennung(u["username"]), norm_kennung(u["email"])} else topf
        if self._one("SELECT 1 AS x FROM federated_identity WHERE quelle=? AND user_id=? AND name_topf IS NOT ?",
                     (quelle, user_id, wert)) is None:
            return False
        self._exec("UPDATE federated_identity SET name_topf=? WHERE quelle=? AND user_id=?",
                   (wert, quelle, user_id))
        return True

    def verzeichnisname_freigeben(self, name) -> int:
        """Delete the name in the directory on ALL bindings — before creating an account that
        gets it as its name (`TinySesam._check_ldap`, audit round 2026-09-27). The directory has
        just signed in a different entry under this name; where it still stands, it is stale
        (see `bindung_name_setzen`) — and without this the database would reject the creation (identifier
        trigger). Returns the number of deleted marks."""
        topf = norm_kennung(name)
        if not topf or self.konto_mit_verzeichnisname(topf) is None:
            return 0
        return self._exec("UPDATE federated_identity SET name_topf=NULL WHERE name_topf=?", (topf,)).rowcount

    def konto_mit_bindungsname(self, kennung) -> Optional[sqlite3.Row]:
        """The account that last signed in under this identifier via a directory source
        (`federated_identity.name_topf`, G5) — for `tinysesam unlock <name as typed>`.
        None if none or if the identifier is the name or address of an account (then THAT
        account is meant, `konto_mit_topf`). Several hits (existing data, see `bindung_name_setzen`):
        None — which one signed in last that way is recorded nowhere. Until 2026-09-27 it was the
        most recently BOUND one, and `unlock` cleared its own series too (audit round, p1-a)."""
        topf = norm_kennung(kennung)
        if not topf or self.konto_mit_topf(topf) is not None:
            return None
        z = self._all("SELECT DISTINCT user_id FROM federated_identity WHERE name_topf=? LIMIT 2", (topf,))
        return self.get_user(z[0]["user_id"]) if len(z) == 1 else None

    def delete_user(self, user_id):
        """Remove the rows of an account — raw building block, only for `konto_entfernen`.

        Whoever deletes an account calls `konto_entfernen` (or `TinySesam.delete_user`): here
        the name stays in the audit log, and the sign-in attempts stay in place. A test ensures
        that there is no other caller."""
        with self._schreibend():
            for table in ("api_key", "password_cred", "pin_cred", "totp_cred", "recovery_code",
                          "webauthn_cred", "oidc_identity", "federated_identity", "namensbindung",
                          "session", "magic_token"):
                self.db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
            self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
            self.db.commit()

    def email_taken(self, email, exclude_id=None) -> bool:
        u = self.get_user_by_email(email)
        return bool(u and u["id"] != exclude_id)

    def kennungs_kollisionen(self, limit: int = 50) -> list:
        """Accounts whose **username** is the **email** of an OTHER account (finding R4-12).

        Only the cross direction; all collisions in the identifier space (also name against name, address
        against address) are reported by `topf_kollisionen`. New ones have been prevented by the database since 2026-09-26
        (`_trigger_sql`); what stands here comes from existing data (an older version, a raw
        UPDATE, a row of a foreign writer after the backfill of its bucket).

        The comparison runs over the counting bucket (`norm_kennung`). It folds more coarsely than NOCASE, with which
        `get_user_by_name`/`get_user_by_email` search — every collision that the sign-in finds
        is therefore also noticed here. Until 2026-09-26 NOCASE stood here; `Ärmel`/`ärmel` or a
        Unicode against the A-label domain of the same address were missing. A row without a bucket (file
        read-only, backfill not possible) does not count.
        Rows: `(name_id, kennung, mail_id, adresse)`. An account that carries the same string in
        BOTH its own columns is no collision (email mode, intended path).
        """
        self._toepfe_nachtragen()     # rows of a foreign writer count too
        return self._all(
            "SELECT n.id AS name_id, n.username AS kennung, e.id AS mail_id, e.email AS adresse "
            "FROM users n JOIN users e ON e.id <> n.id "
            "  AND e.topf_mail <> '' AND e.topf_mail = n.topf_name "
            "ORDER BY n.id LIMIT ?", (int(limit),))

    def topf_kollisionen(self, limit: int = 50) -> list:
        """All identifiers that belong to more than one account — as `[{"kennung", "ids"}, …]`.

        Counted in the counting bucket (`norm_kennung`) over names AND addresses: `Alice`/`alice`,
        name = foreign address, two spellings of the same address (`u@bücher.example` and
        `u@xn--bcher-kva.example`). An account whose name is its own address counts once
        (the `UNION` merges the row). New collisions are prevented by the database
        (`_trigger_sql`); this query reports those from existing data — for the start message, which
        previously saw only the cross direction (`kennungs_kollisionen`). `ids` ascending, the
        identifiers by the oldest account involved. Rows of a foreign writer first get
        their bucket (`_toepfe_nachtragen`); if that cannot be written (file read-only),
        they do not count."""
        self._toepfe_nachtragen()
        zeilen = self._all(
            "SELECT topf, group_concat(id) AS ids FROM ("
            "  SELECT id, topf_name AS topf FROM users WHERE topf_name <> ''"
            "  UNION SELECT id, topf_mail FROM users WHERE topf_mail <> '') "
            "GROUP BY topf HAVING COUNT(*) > 1 ORDER BY MIN(id) LIMIT ?", (int(limit),))
        return [{"kennung": z["topf"], "ids": sorted(int(i) for i in str(z["ids"]).split(","))}
                for z in zeilen]

    def list_users(self):
        return self._all("SELECT * FROM users ORDER BY username")

    #: Values of `users.disabled` besides 0 (active): the lock of a pending confirmation and
    #: the lock by the operator. Separate because `/auth/verify/…` lifts the one and never the
    #: other (H-18, second attack round): if the confirmation token arose only AFTER a
    #: lock by the operator — for instance in the outbox of an embedding app to which
    #: `send_verify_email` pushes it —, the lock found nothing to discard, and the link
    #: afterwards set `disabled` unconditionally to 0.
    GESPERRT_BESTAETIGUNG = 1
    GESPERRT_BETREIBER = 2

    def set_disabled(self, user_id, disabled: bool, durch_betreiber: bool = False):
        """Lock or unlock an account.

        `durch_betreiber=True` is the operator's lock (admin panel): no confirmation link
        lifts it, only an explicit `set_disabled(uid, False)`. Without the marker it is
        the lock of a pending confirmation, which `bestaetigung_freischalten` lifts — and
        which does not downgrade an already existing operator lock.

        Locks from versions before this distinction carry 1 — and up to 0.19.x the lock
        in the panel did not discard the open one-time tokens, so a pending confirmation link would
        have lifted it after the upgrade. The migration to schema 10 (`_bestand_nachziehen`)
        therefore raises every lock that the audit log knows as a panel lock to 2 and discards
        the open tokens in doing so. A lock whose row has already been deleted
        (`audit_retention_days`) stays 1; `POST <admin_path>/api/users/{id}/disable` with
        `{"disabled": true}` sets the marker without unlocking in between."""
        if disabled:
            # An owner cannot be locked — not even via the code path (owner model). Otherwise
            # `owner_count` would count an owner who cannot sign in.
            zeile = self._one("SELECT is_owner FROM users WHERE id=?", (user_id,))
            if zeile is not None and zeile["is_owner"]:
                from .errors import StateError
                raise StateError(f"Konto {user_id} ist Owner und lässt sich nicht sperren — erst die "
                                 "Owner-Rolle abgeben.")
        if not disabled:
            self._exec("UPDATE users SET disabled=0 WHERE id=?", (user_id,))
        elif durch_betreiber:
            self._exec("UPDATE users SET disabled=? WHERE id=?", (self.GESPERRT_BETREIBER, user_id))
        else:
            self._exec("UPDATE users SET disabled=max(disabled, ?) WHERE id=?",
                       (self.GESPERRT_BESTAETIGUNG, user_id))

    def bestaetigung_freischalten(self, user_id) -> bool:
        """Lift the lock of a pending confirmation — never the operator's.

        True if the account is active afterwards (also: it was not locked at all). False if
        a lock remains; then the operator locked it, and only the operator lifts it again."""
        self._exec("UPDATE users SET disabled=0 WHERE id=? AND disabled=?",
                   (user_id, self.GESPERRT_BESTAETIGUNG))
        zeile = self._one("SELECT disabled FROM users WHERE id=?", (user_id,))
        return bool(zeile) and not zeile["disabled"]

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

    def owner_count(self, ohne=None) -> int:
        """How many owners are there (excluding the account `ohne`)?"""
        zeile = self._one("SELECT COUNT(*) AS n FROM users WHERE is_owner=1 AND id <> ?",
                          (int(ohne) if ohne is not None else -1,))
        return int(zeile["n"])

    def set_admin_vom_idp(self, user_id):
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
    tresor: Any = None

    def set_totp(self, user_id, secret, confirmed=False):
        # `last_step` belongs to the secret: a new one starts without a consumed step. Otherwise
        # the confirmation code of a discarded attempt would lock the first code of the new one
        # if both fall into the same 30-second window.
        if self.tresor is None:
            raise RuntimeError("TOTP-Geheimnisse werden nur verschlüsselt abgelegt — der Store hat "
                               "keinen Schlüssel (vault.Vault).")
        self._exec("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?,?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, "
                   "confirmed=excluded.confirmed, last_step=NULL",
                   (user_id, self.tresor.encrypt(secret), 1 if confirmed else 0, _now()))

    def confirm_totp(self, user_id):
        self._exec("UPDATE totp_cred SET confirmed=1 WHERE user_id=?", (user_id,))

    def get_totp(self, user_id) -> Optional[dict]:
        """The TOTP row of an account, with the secret decrypted (`secret`)."""
        zeile = self._one("SELECT * FROM totp_cred WHERE user_id=?", (user_id,))
        if zeile is None:
            return None
        d = dict(zeile)
        if self.tresor is not None:
            d["secret"] = self.tresor.decrypt(d["secret"])
        return d

    def geheimnisse_heben(self) -> int:
        """Encrypt plaintext secrets from the time before encryption (silent upgrade)
        — and first check that the key matches the already encrypted ones. If it does not,
        `ConfigError`: a start with the wrong key would otherwise let every TOTP sign-in fail
        silently. Returns how many were upgraded."""
        from .errors import ConfigError
        if self.tresor is None:
            return 0
        # Both tables with encrypted data: if there are only refresh tokens (OIDC instance without TOTP),
        # a wrong key would otherwise start — and every request with an old cookie ended in a 500.
        probe = self._one("SELECT secret AS wert FROM totp_cred WHERE secret LIKE 'v1:%' "
                          "UNION ALL SELECT refresh FROM oidc_sitzung WHERE refresh LIKE 'v1:%' LIMIT 1")
        if probe is not None:
            try:
                self.tresor.decrypt(probe["wert"])
            except Exception:
                raise ConfigError(
                    "Der Schlüssel passt nicht zu den gespeicherten Geheimnissen (TOTP/OIDC; falsche "
                    "TINYSESAM_SECRETS_KEY/secrets_key_file, oder die Schlüsseldatei neben der "
                    "Datenbank fehlt bzw. ist eine andere). Den richtigen Schlüssel einsetzen — ohne ihn "
                    "müssen alle Konten TOTP neu einrichten.") from None
        klar = self._all("SELECT user_id, secret FROM totp_cred WHERE secret NOT LIKE 'v1:%'")
        for z in klar:
            self._exec("UPDATE totp_cred SET secret=? WHERE user_id=? AND secret=?",
                       (self.tresor.encrypt(z["secret"]), z["user_id"], z["secret"]))
        if klar:
            logging.getLogger("tinysesam").info(
                "%d TOTP-Geheimnis(se) verschlüsselt (bisher Klartext in der Datenbank).", len(klar))
        return len(klar)

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
        with self._schreibend():
            self.db.executemany("INSERT INTO recovery_code(user_id, code_hash, created_at) VALUES (?,?,?)",
                                [(user_id, h, now) for h in hashes])
            self.db.commit()

    def consume_recovery_code(self, user_id, code_hash) -> bool:
        """Invalidate an unused code atomically. True only on the first valid redemption."""
        with self._schreibend():
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
    def mark_first_login(self, user_id: int, jetzt: int) -> bool:
        """Record the first complete login — only the first time (idempotent).

        Return value: True if this call set it. The condition is in the SQL, not
        before it: two simultaneous sign-ins of the same account (two devices, two workers)
        would otherwise both read, both write, and the time would be the later one."""
        return self._exec("UPDATE users SET first_login_at=? WHERE id=? AND first_login_at IS NULL",
                          (jetzt, user_id)).rowcount > 0

    def set_mfa_enroll_until(self, user_id: int, bis: Optional[int]) -> None:
        """Open the enrollment window (timestamp) or close it (None)."""
        self._exec("UPDATE users SET mfa_enroll_until=? WHERE id=?", (bis, user_id))

    def ist_oidc_konto(self, user_id) -> bool:
        """Is this account bound to an OIDC identity (finding 8)?"""
        return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? LIMIT 1", (user_id,)))

    def idp_bestaetigen(self, user_id, gefragt_at: Optional[int] = None) -> bool:
        """The provider has confirmed the account (login via it, refresh exchange with yes).

        `gefragt_at` is the time at which the question to the provider WENT OUT. A no that was
        recorded after that stays: two exchanges run in parallel (two sessions,
        two clients), and a yes that was answered before the lock but applied after the no
        would otherwise wake the keys of a locked account (attack on the third round).
        Return value: whether anything was written."""
        jetzt = _now()
        gefragt = int(gefragt_at if gefragt_at is not None else jetzt)
        return self._exec(
            "UPDATE users SET idp_bestaetigt_at=? WHERE id=? AND (idp_bestaetigt_at IS NULL "
            "OR idp_bestaetigt_at > 0 OR -idp_bestaetigt_at < ?)", (jetzt, user_id, gefragt)).rowcount > 0

    def idp_verweigert(self, user_id) -> None:
        """The provider said no: the API keys of the account are dormant until the next
        confirmation (finding 8). Stored as a NEGATIVE time of the no — NULL means "never
        confirmed", ≤ 0 "refused", and the time decides whether a later-applied yes
        is younger (`idp_bestaetigen`)."""
        self._exec("UPDATE users SET idp_bestaetigt_at=? WHERE id=?", (-max(_now(), 1), user_id))

    def oidc_sitzung_handle(self, client, alt_verschluesselt) -> Optional[str]:
        """TODAY's handle of the session whose row carries this (encrypted) token."""
        r = self._one("SELECT token_hash FROM oidc_sitzung WHERE client=? AND refresh=?",
                      (client, alt_verschluesselt))
        return r["token_hash"] if r else None

    def oidc_sitzung_verwerfen(self, handle, client) -> None:
        """Discard an OIDC row without a configured client — the session itself stays."""
        self._exec("DELETE FROM oidc_sitzung WHERE token_hash=? AND client=?", (self._handle(handle), client))

    def get_oidc_user(self, issuer, subject) -> Optional[int]:
        r = self._one("SELECT user_id FROM oidc_identity WHERE issuer=? AND subject=?", (issuer, subject))
        return r["user_id"] if r else None

    # ---------- Federated identities via a stable identifier (F-11) ----------
    def link_federated(self, quelle: str, kennung: str, user_id: int, jetzt: int) -> None:
        """Bind a foreign identity to a local account (or renew the binding)."""
        self._exec("INSERT OR REPLACE INTO federated_identity(quelle, kennung, user_id, gebunden_at)"
                   " VALUES (?,?,?,?)", (quelle, kennung, user_id, jetzt))

    def get_federated_user(self, quelle: str, kennung: str) -> Optional[int]:
        r = self._one("SELECT user_id FROM federated_identity WHERE quelle=? AND kennung=?",
                      (quelle, kennung))
        return r["user_id"] if r else None

    def get_federated_kennung(self, quelle: str, user_id: int) -> Optional[str]:
        """The identifier with which this account is bound for this source — None if none.

        The way back is the actual bolt: if an account already carries an identifier, it must
        **not** be bound to a second one. That is exactly what would happen if a deleted account
        were recreated under the same name in the directory."""
        r = self._one("SELECT kennung FROM federated_identity WHERE quelle=? AND user_id=?",
                      (quelle, user_id))
        return r["kennung"] if r else None

    def has_foreign_identity(self, user_id: int) -> bool:
        """Is this account bound to any foreign identity (OIDC, LDAP, SAML)?"""
        return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? "
                              "UNION ALL SELECT 1 FROM federated_identity WHERE user_id=? LIMIT 1",
                              (user_id, user_id)))

    def unlink_federated(self, quelle: str, user_id: int) -> int:
        """Release the binding of an account for a source (operator path after a move)."""
        return self._exec("DELETE FROM federated_identity WHERE quelle=? AND user_id=?",
                          (quelle, user_id)).rowcount

    #: Prefix of the origin placeholders in `federated_identity.kennung` (see `TinySesam._OHNE_KENNUNG`).
    OHNE_KENNUNG = "~ohne-kennung:"

    def nachbinden(self, quelle: str, kennung: str, user_id: int, jetzt: int) -> bool:
        """Bind an account to an identifier that belongs to nobody yet — or do nothing (G1).

        For the binding of existing accounts (`TinySesam.federation_bind_existing`), which runs through a whole
        directory between check and write. `link_federated` replaces a row with
        the same identifier (`INSERT OR REPLACE`) — here that would take its binding away from an account that has
        meanwhile signed in. Hence in ONE transaction: if the identifier already belongs
        to an account or this account already carries a real identifier, everything stays as it is
        (`False`). Otherwise an origin placeholder yields, the binding is created, and an open
        name binding (`namensbindung`) is done."""
        with self._schreibend():
            besetzt = self.db.execute(
                "SELECT 1 FROM federated_identity WHERE quelle=? AND (kennung=? OR "
                "(user_id=? AND substr(kennung, 1, ?) <> ?)) LIMIT 1",
                (quelle, kennung, user_id, len(self.OHNE_KENNUNG), self.OHNE_KENNUNG)).fetchone()
            if besetzt is not None:
                return False
            self.db.execute("DELETE FROM federated_identity WHERE quelle=? AND user_id=?", (quelle, user_id))
            self.db.execute("INSERT INTO federated_identity(quelle, kennung, user_id, gebunden_at) "
                            "VALUES (?,?,?,?)", (quelle, kennung, user_id, jetzt))
            self.db.execute("DELETE FROM namensbindung WHERE quelle=? AND user_id=?", (quelle, user_id))
            self.db.commit()
            self._geschrieben = time.monotonic()
            self._uhr_mitschreiben()
        return True

    def ohne_bindung(self, quelle: str) -> list:
        """The accounts without a real identifier for this source — no row or only the
        origin placeholder —, excluding service accounts (G1). With `hat_passwort` (local password)."""
        return self._all(
            "SELECT u.*, EXISTS (SELECT 1 FROM password_cred p WHERE p.user_id = u.id) AS hat_passwort "
            "FROM users u WHERE u.is_service = 0 AND NOT EXISTS (SELECT 1 FROM federated_identity f "
            "WHERE f.quelle = ? AND f.user_id = u.id AND substr(f.kennung, 1, ?) <> ?) ORDER BY u.id",
            (quelle, len(self.OHNE_KENNUNG), self.OHNE_KENNUNG))

    def namensbindung_oeffnen(self, quelle: str, user_id: int, bis: int) -> None:
        """Open the binding via the name for this account until `bis` (G1, `federation_unbind`)."""
        self._exec("INSERT OR REPLACE INTO namensbindung(quelle, user_id, bis) VALUES (?,?,?)",
                   (quelle, user_id, int(bis)))

    def namensbindung_offen(self, quelle: str, user_id: int, jetzt: int) -> bool:
        """Has the operator opened the binding via the name for this account (and is it still running)?"""
        return self._one("SELECT 1 AS x FROM namensbindung WHERE quelle=? AND user_id=? AND bis > ?",
                         (quelle, user_id, int(jetzt))) is not None

    def namensbindung_schliessen(self, quelle: str, user_id: int) -> None:
        """The opened binding via the name is done (the binding stands)."""
        self._exec("DELETE FROM namensbindung WHERE quelle=? AND user_id=?", (quelle, user_id))

    def foederation_seit(self, quelle: str, jetzt: int) -> int:
        """The marker of a federated source (`foederation_seit:<quelle>`): from when the deadline for
        the binding via the name runs (G1). Set to `jetzt` on the first call, never
        again afterwards — a marker that were set anew on every start would give every restart a
        new deadline. `INSERT OR IGNORE`: if several workers start at the same time, the first wins, and
        all afterwards read the same value."""
        schluessel = f"foederation_seit:{quelle}"
        z = self._one("SELECT value FROM setting WHERE key=?", (schluessel,))
        if z is None:
            self._exec("INSERT OR IGNORE INTO setting(key, value) VALUES (?,?)", (schluessel, str(int(jetzt))))
            z = self._one("SELECT value FROM setting WHERE key=?", (schluessel,))
        return int(z["value"])

    # ---------- Approvals per application (T-14) ----------
    # The key is the **hash** of the session, not the plaintext — the same rule as in
    # `session`: whoever reads the file thereby gets no session that can be taken over.
    def set_oidc_sitzung(self, handle, client, sub, refresh, client_id: Optional[str] = None) -> None:
        """Store the refresh token of an OIDC session for THIS client — encrypted (4a).

        One row per client: with several applications, a later login via another
        client must not overwrite the re-check of the first — otherwise the user would choose
        which provider entry is still re-checked (attack on the second round, finding 7)."""
        if self.tresor is None:
            raise RuntimeError("Refresh-Tokens werden nur verschlüsselt abgelegt (vault.Vault).")
        self._exec("INSERT INTO oidc_sitzung(token_hash, client, sub, refresh, geprueft_at, client_id, erfolg_at) "
                   "VALUES (?,?,?,?,?,?,?) ON CONFLICT(token_hash, client) DO UPDATE SET sub=excluded.sub, "
                   "refresh=excluded.refresh, geprueft_at=excluded.geprueft_at, client_id=excluded.client_id, "
                   "erfolg_at=excluded.erfolg_at",
                   (self._handle(handle), client, sub, self.tresor.encrypt(refresh), _now(), client_id,
                    _now()))

    def get_oidc_sitzungen(self, handle) -> list:
        """The OIDC rows of a session — the refresh token ENCRYPTED (it is decrypted
        only when exchanging; a request before the deadline expires does not touch the key)."""
        return [dict(z) for z in self._all("SELECT * FROM oidc_sitzung WHERE token_hash=?",
                                          (self._handle(handle),))]

    def get_oidc_sitzung(self, handle, client="*") -> Optional[dict]:
        """One OIDC row, with the refresh token decrypted, or None (for tools and tests)."""
        z = self._one("SELECT * FROM oidc_sitzung WHERE token_hash=? AND client=?", (self._handle(handle), client))
        if z is None:
            return None
        d = dict(z)
        if self.tresor is not None:
            d["refresh"] = self.tresor.decrypt(d["refresh"])
        return d

    def oidc_sitzung_beanspruchen(self, handle, client, alt: int, jetzt: int) -> bool:
        """Claim the due exchange for EXACTLY one request: `geprueft_at` from `alt` to
        `jetzt`, only if it is still `alt`. Several simultaneous requests (also across workers) —
        only one exchanges. Otherwise all would exchange the same refresh token, and a provider with
        token rotation rejected the second exchange: the session ended for no reason (finding 5)."""
        return self._exec("UPDATE oidc_sitzung SET geprueft_at=? WHERE token_hash=? AND client=? "
                          "AND geprueft_at=?", (int(jetzt), self._handle(handle), client, int(alt))).rowcount == 1

    def oidc_sitzung_geprueft(self, handle, client, zeit: int, neuer_refresh=None,
                              alt_verschluesselt: Optional[str] = None, erfolg: bool = False) -> bool:
        """Record the exchange; a newly issued refresh token replaces the old one (rotation).
        Return value: whether the row was still there (the session may have ended meanwhile).

        With `alt_verschluesselt` (the stored, encrypted token with which the exchange was
        made) the row is found through it instead of through the handle: if the session gets a new token
        during the exchange (step-up, completion of a factor), the row hangs on the new
        handle — the old one would hit nothing, and the refresh token rotated by the provider would be
        lost; the next exchange with the old one would be a no at PocketID. The ciphertext is
        unique through its nonce."""
        wo, wert = ("refresh=?", alt_verschluesselt) if alt_verschluesselt else ("token_hash=?", self._handle(handle))
        # `erfolg`: the provider has just said yes — state for the upper limit without a re-check.
        # `geprueft_at` alone is not suitable for that: after an "fehler" it stands at "in a minute".
        extra = ", erfolg_at=?" if erfolg else ""
        erfolg_wert = (int(zeit),) if erfolg else ()
        if neuer_refresh and self.tresor is not None:
            return self._exec(f"UPDATE oidc_sitzung SET geprueft_at=?, refresh=?{extra} WHERE {wo} AND client=?",
                              (int(zeit), self.tresor.encrypt(neuer_refresh), *erfolg_wert, wert,
                               client)).rowcount > 0
        return self._exec(f"UPDATE oidc_sitzung SET geprueft_at=?{extra} WHERE {wo} AND client=?",
                          (int(zeit), *erfolg_wert, wert, client)).rowcount > 0

    def oidc_sitzung_umhaengen(self, alt, neu) -> None:
        """Attach the OIDC rows to a new session (new token at the completion of the chain) —
        BEFORE deleting the old ones, otherwise the foreign key would take them along."""
        self._exec("UPDATE oidc_sitzung SET token_hash=? WHERE token_hash=?",
                   (self._handle(neu), self._handle(alt)))

    # ---------- Gate: signed out of one application only (T-22) ----------
    def gate_abmelden(self, handle, host: str) -> None:
        self._exec("INSERT OR REPLACE INTO gate_abgemeldet(token_hash, host, at) VALUES (?,?,?)",
                   (self._handle(handle), str(host).lower(), _now()))

    def gate_ist_abgemeldet(self, handle, host: str) -> bool:
        return bool(self._one("SELECT 1 FROM gate_abgemeldet WHERE token_hash=? AND host=?",
                              (self._handle(handle), str(host).lower())))

    def gate_fortsetzen(self, handle, host: str) -> int:
        return self._exec("DELETE FROM gate_abgemeldet WHERE token_hash=? AND host=?",
                          (self._handle(handle), str(host).lower())).rowcount

    # ---------- Connection of an app host to the central session (T-26) ----------
    def gate_link_anlegen(self, link_hash: str, handle, host: str) -> None:
        self._exec("INSERT INTO gate_link(link_hash, token_hash, host, created_at) VALUES (?,?,?,?)",
                   (link_hash, self._handle(handle), str(host).lower(), _now()))

    def gate_link_handle(self, link_hash: str, host: str) -> Optional[str]:
        """The session handle behind this connection — only for ITS host, otherwise None."""
        r = self._one("SELECT token_hash FROM gate_link WHERE link_hash=? AND host=?", (link_hash, str(host).lower()))
        return r["token_hash"] if r else None

    def gate_link_entfernen(self, link_hash: str) -> int:
        return self._exec("DELETE FROM gate_link WHERE link_hash=?", (link_hash,)).rowcount

    # ---------- ID token as a sign-out hint (T-22) ----------
    def set_oidc_id_token(self, handle, client: str, id_token: str) -> None:
        if self.tresor is None:
            raise RuntimeError("ID-Tokens werden nur verschlüsselt abgelegt (vault.Vault).")
        self._exec("INSERT OR REPLACE INTO oidc_id_token(token_hash, client, id_token) VALUES (?,?,?)",
                   (self._handle(handle), client, self.tresor.encrypt(id_token)))

    def get_oidc_id_token(self, handle) -> Optional[tuple]:
        """(client, id_token) of this session's sign-in, decrypted — or None."""
        r = self._one("SELECT client, id_token FROM oidc_id_token WHERE token_hash=?", (self._handle(handle),))
        if not r or self.tresor is None:
            return None
        return r["client"], self.tresor.decrypt(r["id_token"])

    def put_oidc_grant(self, token_hash: str, client: str, jetzt: int, roles=None) -> None:
        """Enter or confirm an approval. `granted_at` stays on a confirmation —
        otherwise nobody could answer the question "since when may this session enter this application"."""
        self._exec(
            "INSERT INTO oidc_grant(token_hash, client, granted_at, checked_at, roles) VALUES (?,?,?,?,?)"
            " ON CONFLICT(token_hash, client) DO UPDATE SET checked_at=excluded.checked_at,"
            " roles=excluded.roles",
            (token_hash, client, jetzt, jetzt, json.dumps(list(roles or []))))

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
    leerlauf_sek = (0, 0)
    #: How often `zuletzt` is written at most: writing on every request would mean that every
    #: forward-auth call locks the file. A minute of fuzziness is nothing for limits of hours.
    LEERLAUF_SCHRITT_SEK = 60

    @staticmethod
    def _handle(wert) -> str:
        """A handle is a sha256 hex digest. Whoever passes in a plaintext token by mistake
        gets an error — otherwise the UPDATE would hit nothing and the session
        would silently keep its old state (a second factor that does not arrive is noticed by nobody
        until it is missing)."""
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
        jetzt = _now()
        if r["expires_at"] < jetzt:
            self.delete_session_by_handle(h)
            return None
        # Inactivity (F-05): in addition to the absolute lifetime. An expired session is
        # deleted, not only rejected — otherwise it would come back to life with the next access.
        # The long limit only if someone EXPLICITLY chose "stay signed in". A
        # session that is permanent only because the path knows no choice (OIDC, passkey,
        # sign-in link) or the checkbox is switched off would otherwise never get an idle end
        # (attack on the second round, finding 9).
        grenze = self.leerlauf_sek[1 if (r["remember"] and r["bleiben_gewaehlt"]) else 0]
        zuletzt = r["zuletzt"] if r["zuletzt"] is not None else r["created_at"]
        if grenze and jetzt - int(zuletzt) > grenze:
            self.delete_session_by_handle(h)
            return None
        if jetzt - int(zuletzt) >= self.LEERLAUF_SCHRITT_SEK:
            self._exec("UPDATE session SET zuletzt=? WHERE token_hash=?", (jetzt, r["token_hash"]))
        return r

    def set_session_bleiben(self, handle):
        """Record: "stay signed in" was explicitly chosen (F-05)."""
        self._exec("UPDATE session SET bleiben_gewaehlt=1 WHERE token_hash=?", (self._handle(handle),))

    def set_session_andere_beenden(self, handle):
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

    def rotate_session(self, handle, gnade_sek: int = 0) -> Optional[str]:
        """Give the session a new token without otherwise changing it (F-06).

        Lifetime, factors and `created_at` stay — a step-up is meant to renew the token, not
        extend the absolute lifetime. The OIDC approvals hang on the handle by foreign key
        and move along; hence a new row, re-attach the approvals, delete the old row, all
        in one transaction. Returns the new plaintext token, or None if the
        session does not (any longer) exist.

        `gnade_sek` (A-6, PO decision 2026-09-25): the old token then remains valid for that many
        seconds — a request that was already under way at the moment of the step-up (second tab,
        background loading) would otherwise fail once. It then applies WITHOUT step-up freshness (`mfa_at`
        empty): whoever read along the old token gets no freshly confirmed rights, only
        the deadline. It points to its successor and ends with it (`delete_session_by_handle`).
        An already superseded token is not rotated again."""
        alt = self._handle(handle)
        token = secrets.token_urlsafe(32)
        neu = self.session_hash(token)
        spalten = ("user_id, created_at, expires_at, mfa_ok, mfa_at, method, factors_done, "
                   "remember, ip, user_agent, zuletzt, bleiben_gewaehlt")
        with self._lock:
            try:
                cur = self.db.execute(
                    f"INSERT INTO session(token_hash, {spalten}) SELECT ?, {spalten} FROM session "
                    "WHERE token_hash=? AND nachfolger IS NULL", (neu, alt))
                if cur.rowcount != 1:
                    self.db.rollback()
                    return None
                self.db.execute("UPDATE oidc_grant SET token_hash=? WHERE token_hash=?", (neu, alt))
                self.db.execute("UPDATE oidc_sitzung SET token_hash=? WHERE token_hash=?", (neu, alt))
                self.db.execute("UPDATE gate_abgemeldet SET token_hash=? WHERE token_hash=?", (neu, alt))
                self.db.execute("UPDATE oidc_id_token SET token_hash=? WHERE token_hash=?", (neu, alt))
                self.db.execute("UPDATE gate_link SET token_hash=? WHERE token_hash=?", (neu, alt))
                if gnade_sek > 0:
                    self.db.execute("UPDATE session SET expires_at=MIN(expires_at, ?), mfa_at=NULL, "
                                    "nachfolger=? WHERE token_hash=?", (_now() + int(gnade_sek), neu, alt))
                    # An earlier predecessor that points to the old token now points to the new one —
                    # otherwise it would survive a sign-out of the new session.
                    self.db.execute("UPDATE session SET nachfolger=? WHERE nachfolger=?", (neu, alt))
                else:
                    self.db.execute("DELETE FROM session WHERE token_hash=?", (alt,))
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

    def totp_step_verbrauchen(self, user_id, step: int) -> bool:
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
    def sichere_datei(cls, quelle: str, ziel: str) -> str:
        """Back up a database file WITHOUT touching it — the path for `tinysesam backup`.

        Why not simply `Store(quelle).backup(ziel)`: the constructor sets
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
        if not os.path.exists(quelle):
            raise FileNotFoundError(quelle)
        if not os.path.exists(ziel):
            try:
                os.close(os.open(ziel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, cls.DATEIRECHTE))
            except OSError:
                pass  # created meanwhile or cannot be created — chmod below sets the permissions
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
                pass  # permissions cannot be set (foreign file system) — the copy itself is complete
        return ziel

    def backup(self, ziel: str) -> str:
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
        if not os.path.exists(ziel):
            try:
                os.close(os.open(ziel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.DATEIRECHTE))
            except OSError:
                pass  # created meanwhile or cannot be created — chmod below sets the permissions
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
                pass  # permissions cannot be set (foreign file system) — the copy itself is complete
        return ziel

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
        with self._schreibend():
            r = self.db.execute("SELECT data, expires_at FROM flow WHERE key=?", (key,)).fetchone()
            if not r:
                return None
            weg = self.db.execute("DELETE FROM flow WHERE key=?", (key,)).rowcount
            self.db.commit()
        if weg != 1:
            return None                 # another caller consumed it first
        if r["expires_at"] < _now():
            return None
        try:
            return json.loads(r["data"])
        except Exception:
            return None

    def zaehle_argon2_hashes(self) -> int:
        """How many stored password/PIN/scope hashes are argon2? (B6-8)"""
        n = 0
        for tabelle in ("password_cred", "pin_cred", "resource_secret"):
            r = self._one(f"SELECT COUNT(*) AS n FROM {tabelle} WHERE hash LIKE '$argon2%'")
            n += int(r["n"] or 0) if r else 0
        return n

    #: How long a successful commit counts as proof that the database is writable
    #: (seconds). Within this period `schreibprobe()` only checks the connection.
    SCHREIBPROBE_SEK = 5

    def schreibprobe(self) -> None:
        """A real write transaction — the core of the health check (B6-4).

        A `SELECT 1` also succeeds on a database that has become read-only (read-only
        mount, wrong permissions after a restore, `SQLITE_READONLY`) or whose volume is full
        (`SQLITE_FULL`) — exactly where every sign-in fails at its first `INSERT INTO
        session`. Healthy is therefore only reported once a commit goes through.
        Raises the sqlite3 exception unchanged; what of it reaches the outside is decided by the
        caller.

        What is written is the clock state (`uhr_stand`) — so the health check also saves it
        on the side, in times when nothing else is written. But at most every
        `SCHREIBPROBE_SEK`: `/healthz` is reachable without sign-in, and one commit
        with fsync under `_lock` per call would mean that whoever floods it occupies the write lock that
        sign-ins wait for, and wears out SD cards. If the last successful commit (also
        a foreign one via `_exec`) is more recent than that, a read access suffices — a closed or
        vanished connection is still noticed immediately, a change to "read-only" at the latest
        after `SCHREIBPROBE_SEK`."""
        with self._schreibend():
            m = time.monotonic()
            if self._frisch(self._geschrieben, m, self.SCHREIBPROBE_SEK):
                self.db.execute("SELECT 1").fetchone()
                return
            self._uhr_stand_schreiben()
            self.db.commit()
            self._geschrieben = self._uhr_gesichert = m

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

    #: How long a pre-booking with an open outcome (`reserve_attempt(schweben=True)`) counts as
    #: pending, not as a failed attempt (seconds, G9). Longer than any directory query up to
    #: its timeout (`ldap_.VERBINDUNGS_TIMEOUT`, connection setup and bind once each) including
    #: compute time. An older open row has been completed by nobody — the process has died
    #: or is hanging; it then counts as a failed attempt, when in doubt the stricter reading.
    VORBUCHUNG_SCHWEBE_SEK = 30

    def _fails_abfrage(self, since, username=None, ip=None, method=None, exclude_methods=None,
                       ab_id=None, nur_bestaetigt=False, ausser_username=None):
        """The counting query for `count_fails` and `reserve_attempt` — one rule, two callers.
        `ab_id`: only rows with a larger id (watermark of an identifier, G2).
        `nur_bestaetigt`: without the pending pre-bookings (G9, `VORBUCHUNG_SCHWEBE_SEK`)."""
        q = "SELECT COUNT(*) c FROM login_attempt WHERE success=0 AND ts>=?"
        args = [since]
        if nur_bestaetigt:
            q += " AND (offen=0 OR ts<?)"
            args.append(_now() - self.VORBUCHUNG_SCHWEBE_SEK)
        if ab_id is not None:
            q += " AND id>?"
            args.append(int(ab_id))
        if username:
            q += " AND username=? COLLATE NOCASE"
            args.append(username)
        if ip:
            q += " AND ip=?"
            args.append(ip)
        if ausser_username:
            q += " AND username<>? COLLATE NOCASE"
            args.append(ausser_username)
        if method:
            q += " AND method=?"
            args.append(method)
        if exclude_methods:
            platz = ",".join("?" for _ in exclude_methods)
            q += f" AND (method IS NULL OR method NOT IN ({platz}))"
            args.extend(exclude_methods)
        return q, args

    def count_fails(self, since, username=None, ip=None, method=None, exclude_methods=None,
                    ab_id=None, nur_bestaetigt=False, ausser_username=None) -> int:
        """Count failed attempts in the window — optionally only ONE method, or all EXCEPT some.

        `exclude_methods` is the counterpart of `method`: the login lockout wants to count everything
        that was a sign-in attempt — but not the old-password query of the account page, which lies in
        the same table (see `security.NICHT_LOGIN_METHODEN`). A row without a method
        (`NULL`, conceivable from old data) still counts: when in doubt, lock more strictly.

        Default: a pending pre-booking (`reserve_attempt(schweben=True)`) counts — it
        CAN become a failed attempt. `nur_bestaetigt=True` leaves it out (G9).
        """
        if not username and not ip:
            return 0
        q, args = self._fails_abfrage(since, username, ip, method, exclude_methods, ab_id,
                                      nur_bestaetigt, ausser_username)
        return self._one(q, args)["c"]

    def reserve_attempt(self, username, ip, method, regeln, serie=None, schweben=False) -> tuple:
        """Check lockouts and pre-book the attempt **in the same transaction** as a failed attempt.

        `regeln` is a list `(grund, grenze, filter)`; `filter` are the keywords of
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

        `serie=(topf, art, grenze)` also pre-books the series of consecutive failed attempts (B2-6) —
        in the SAME transaction. The first version read the series beforehand and counted it only after
        the check: a parallel burst at the limit read "not full yet" N times and could guess
        N times (measured: 15 instead of 1). Returns then `(id, series state)` after the booking —
        the SETTLED state (`_serie_bestaetigt`, without pending pre-bookings). If it reaches
        the limit, exactly this booking triggered the lockout; a pending one never reaches it here,
        only at its completion (`finish_attempt`, audit round 2026-09-27, p2 F3).

        **Pending (G9).** `schweben=True` books the attempt with an open outcome (`offen=1`): it
        can become a failed attempt or none at all (directory outage, F-23 — withdrawn
        only once the outage is reported, with a directory that drops packets, hence after
        the timeout). If a rule or the series applies **only** because of such rows, the
        answer is `(None, "schwebend")`: not decided yet, no lockout. The caller asks
        again after a short pause (`_begin_attempt`). Previously every rejection in this
        window was a lockout with `failed login` for fail2ban and a lockout notice to the holder — even
        if not a single failed attempt remained afterwards. The burst (R7-2) stays slowed down: it
        waits until the pre-bookings are decided and then gets the real lockout. If
        a rule applies with the confirmed rows alone, its reason applies as before; an open
        row older than `VORBUCHUNG_SCHWEBE_SEK` counts as a failed attempt.
        """
        with self._lock:
            self._begin_immediate()
            try:
                stand = None
                schwebend = False
                topf_s, art_s, grenze_s = serie if serie is not None else (None, None, 0)
                if topf_s and self._serie_summe(topf_s) >= grenze_s:
                    if self._serie_bestaetigt(topf_s) >= grenze_s:
                        self.db.execute("ROLLBACK")
                        return None, "lockout_serie"
                    schwebend = True
                for grund, grenze, filt in regeln:
                    if not filt.get("username") and not filt.get("ip"):
                        continue
                    q, args = self._fails_abfrage(**filt)
                    if self.db.execute(q, args).fetchone()["c"] < grenze:
                        continue
                    # Does the rule apply — even without the pending pre-bookings? Then it is a
                    # lockout. Otherwise continue: a later rule may apply confirmed and takes precedence.
                    q, args = self._fails_abfrage(**filt, nur_bestaetigt=True)
                    if self.db.execute(q, args).fetchone()["c"] >= grenze:
                        self.db.execute("ROLLBACK")
                        return None, grund
                    schwebend = True
                if schwebend:
                    self.db.execute("ROLLBACK")
                    return None, "schwebend"
                cur = self.db.execute(
                    "INSERT INTO login_attempt(ts, username, ip, success, method, offen) VALUES (?,?,?,0,?,?)",
                    (_now(), username, ip, method, 1 if schweben else 0))
                if topf_s:
                    self._serie_plus(topf_s, art_s)
                    stand = self._serie_bestaetigt(topf_s)
                self.db.execute("COMMIT")
                return cur.lastrowid, stand
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def finish_attempt(self, attempt_id, success: bool, serie=None) -> Optional[tuple]:
        """Complete an attempt pre-booked with `reserve_attempt`: success or failed attempt.

        Both end the pending state (`offen=0`, G9): a failed attempt counts from here also for
        `count_fails(nur_bestaetigt=True)` — until then completing a failed attempt was a
        no-op. `serie=(topf, art)` withdraws the pre-booking in the series on a success in the SAME
        transaction: separately it would stand in between neither as open nor as withdrawn,
        and whoever is waiting right now (`_begin_attempt`) would read the series one too high — at the
        limit a lockout with a lockout notice for nothing.

        With `serie` it returns `(before, after)`: the settled state of the series
        (`_serie_bestaetigt`) before and after the completion, both in one transaction
        (`BEGIN IMMEDIATE`, also across several processes). From that `_record_login` sees whether EXACTLY
        this completion crossed the limit (p2 F3). Until 2026-09-27 the state counted at
        booking: if in the meantime a full sign-in had ended the series, `lockout_serie`
        stood in the log although nothing was locked. Without `serie` None."""
        with self._schreibend():
            vorher = None
            if serie:
                self._begin_immediate()
                vorher = self._serie_bestaetigt(serie[0])
            self.db.execute("UPDATE login_attempt SET success=?, offen=0 WHERE id=?",
                            (1 if success else 0, attempt_id))
            if success and serie:
                self._serie_minus(*serie)
            stand = (vorher, self._serie_bestaetigt(serie[0])) if serie else None
            self.db.commit()
            self._geschrieben = time.monotonic()
            self._uhr_mitschreiben()
        return stand

    def cancel_attempt(self, attempt_id, serie=None):
        """Withdraw a pre-booked attempt — it was none (e.g. directory outage, F-23).

        `serie=(topf, art)` withdraws its pre-booking in the series in the same transaction —
        for the same reason as in `finish_attempt` (G9)."""
        with self._schreibend():
            self.db.execute("DELETE FROM login_attempt WHERE id=? AND success=0", (attempt_id,))
            if serie:
                self._serie_minus(*serie)
            self.db.commit()
            self._geschrieben = time.monotonic()
            self._uhr_mitschreiben()

    def clear_fails(self, username=None, ip=None, method=None, exclude_methods=None, seit=None,
                    ab_id=None):
        """Delete failed attempts — optionally only those of ONE method, or all EXCEPT some.

        `method` is not a nicety but the core: without it a successful
        password login also cleared the TOTP and PIN failed attempts. Whoever knew the password (leak,
        reuse, phishing) signed in correctly once before every guess and
        thereby reset the lockout for the SECOND factor — as often as they liked. The regulation
        that the panel advertises as hardening never applied to the second factor.

        `exclude_methods` clears everything except those named — the path after a COMPLETE
        sign-in, which does not concern the own buckets (account page, step-up, scope).

        `ab_id` clears only rows from the watermark of the identifier (`kennung_grenzen`, G2): what
        arose only when the identifier already belonged to the account. `seit` is the fallback for
        existing data without a watermark (Unix seconds, the creation of the account, inclusive).
        """
        wo: str = ""
        args_m: tuple = ()
        if method is not None:
            wo, args_m = " AND method=?", (method,)
        elif exclude_methods:
            platz = ",".join("?" for _ in exclude_methods)
            wo, args_m = f" AND (method IS NULL OR method NOT IN ({platz}))", tuple(exclude_methods)
        if seit is not None:
            # Only from a point in time (limit a): a complete sign-in clears what applied to THIS
            # account — not the failed attempts under its name or address from before
            # its creation (those applied to nobody or to someone else).
            wo, args_m = wo + " AND ts >= ?", args_m + (int(seit),)
        if ab_id is not None:
            # More precise than `seit` (G2): from the joining of the identifier, not from creation — and to
            # the exact row, also in the second of joining.
            wo, args_m = wo + " AND id > ?", args_m + (int(ab_id),)
        if username:
            self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE" + wo,
                       (username,) + args_m)
        if ip:
            self._exec("DELETE FROM login_attempt WHERE ip=?" + wo, (ip,) + args_m)

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
    def _serie_summe(self, topf) -> int:
        zeile = self.db.execute("SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie WHERE topf=?",
                                (topf,)).fetchone()
        return int(zeile["n"])

    def _serie_bestaetigt(self, topf) -> int:
        """The series without the pending pre-bookings (G9) — under `_lock`, without commit.

        Every open row in `login_attempt` has exactly one booking in the series under the same
        bucket (`reserve_attempt(schweben=True)` books both in one transaction); a row that is
        older than `VORBUCHUNG_SCHWEBE_SEK` counts as a failed attempt and is not subtracted."""
        offen = self.db.execute(
            "SELECT COUNT(*) AS n FROM login_attempt WHERE username=? COLLATE NOCASE AND offen=1 "
            "AND ts>=?", (topf, _now() - self.VORBUCHUNG_SCHWEBE_SEK)).fetchone()
        return max(0, self._serie_summe(topf) - int(offen["n"]))

    def _serie_minus(self, topf, art):
        self.db.execute("UPDATE fehlserie SET anzahl = anzahl - 1 WHERE topf=? AND art=? AND anzahl > 0",
                        (topf, art or ""))

    def _serie_plus(self, topf, art):
        jetzt = _now()
        self.db.execute("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES (?, ?, 1, ?, ?) "
                        "ON CONFLICT(topf, art) DO UPDATE SET anzahl = anzahl + 1, "
                        "zuletzt = excluded.zuletzt", (topf, art or "", jetzt, jetzt))

    def fehlserie(self, topf) -> int:
        """How many consecutive failed attempts stand for this (folded) identifier, across all methods?"""
        if not topf:
            return 0
        with self._lock:
            return self._serie_summe(topf)

    def fehlserie_bestaetigt(self, topf) -> int:
        """Like `fehlserie`, without the pending pre-bookings (G9): the consecutive failed attempts that
        are settled. The series lockout hangs on it; the sum alone can still fall."""
        if not topf:
            return 0
        with self._lock:
            return self._serie_bestaetigt(topf)

    def fehlserie_ohne(self, topf, arten) -> int:
        """The series of this identifier WITHOUT the named kinds — what clearing only these kinds
        would leave standing (e.g. the self-service reset, which does not clear TOTP and `pin_folge`)."""
        if not topf:
            return 0
        arten = [str(a) for a in arten]
        platz = ",".join("?" for _ in arten)
        with self._lock:
            zeile = self.db.execute(f"SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie "
                                    f"WHERE topf=? AND art NOT IN ({platz})", [topf, *arten]).fetchone()
        return int(zeile["n"])

    def fehlserie_erhoehen(self, topf, art="password") -> int:
        """Attach a failed attempt to the series (paths without pre-booking); returns the new sum."""
        if not topf:
            return 0
        jetzt = _now()
        self._exec("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES (?, ?, 1, ?, ?) "
                   "ON CONFLICT(topf, art) DO UPDATE SET anzahl = anzahl + 1, zuletzt = excluded.zuletzt",
                   (topf, art or "", jetzt, jetzt))
        return self.fehlserie(topf)

    def fehlserie_senken(self, topf, art) -> None:
        """Withdraw a pre-booking: the attempt was correct (or none at all — directory outage).

        Do not delete: a correct password with an open second factor is not a complete
        sign-in. The series before it stays, only this attempt does not count."""
        if not topf:
            return
        self._exec("UPDATE fehlserie SET anzahl = anzahl - 1 WHERE topf=? AND art=? AND anzahl > 0",
                   (topf, art or ""))

    def fehlserie_loeschen(self, topf, arten=None) -> int:
        """End the series (`arten=None`: entirely, otherwise only these methods); returns how many there were."""
        if not topf:
            return 0
        if arten is None:
            weg = self.fehlserie(topf)
            self._exec("DELETE FROM fehlserie WHERE topf=?", (topf,))
            return weg
        arten = [str(a) for a in arten]
        platz = ",".join("?" for _ in arten)
        zeile = self._one(f"SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie WHERE topf=? AND art IN ({platz})",
                          [topf, *arten])
        self._exec(f"DELETE FROM fehlserie WHERE topf=? AND art IN ({platz})", [topf, *arten])
        return int(zeile["n"])

    def gc_fehlserien(self, older_than, grenze) -> int:
        """Clear old, NOT triggered series (`zuletzt` before `older_than`, sum below `grenze`).

        A triggered series stays: it is a lockout, and only a sign-in, a reset
        or the operator lifts it — not waiting. Without a limit the table would fill up with
        invented names; with it each remaining row costs an attacker `grenze`
        failed attempts, each slowed down by the window thresholds."""
        return self._exec(
            "DELETE FROM fehlserie WHERE topf IN (SELECT topf FROM fehlserie GROUP BY topf "
            "HAVING MAX(zuletzt) < ? AND SUM(anzahl) < ?)", (int(older_than), int(grenze))).rowcount

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
        with self._schreibend():
            cur = self.db.execute(
                "UPDATE magic_token SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
                (_now(), token_hash, _now()))
            self.db.commit()
            return cur.rowcount == 1

    def expire_magic_token(self, token_hash) -> bool:
        """Let a still unused token expire immediately (sending failed, B6-12).

        Deliberately "expired" and not "used": `used_at` means "redeemed" — for a
        confirmation token that is "address proven". A never delivered link proved nothing,
        and the cleanup of unconfirmed accounts (`unbestaetigte_konten`) must see it as
        expired.
        """
        return self._exec("UPDATE magic_token SET expires_at=? WHERE token_hash=? AND used_at IS NULL",
                          (_now() - 1, token_hash)).rowcount == 1

    def unbestaetigte_konten(self) -> list:
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

    def gc_unbestaetigte_konten(self) -> int:
        """Remove never-confirmed accounts (R4-09) — call BEFORE `gc_magic_tokens`.

        The mark "never confirmed" is the expired confirmation token; if
        `gc_magic_tokens` clears it first, the account can no longer be recognised. Without this
        step an address that a stranger had registered and never confirmed stayed taken
        forever: the real owner got "email taken". Here and not in the manager,
        so that `tinysesam gc` (works directly on the store) runs the same order."""
        ids = self.unbestaetigte_konten()
        for uid in ids:
            # Via the one deletion path (H-13, integration findings 12/18): the registration of the
            # stranger including IP and the failed attempts of the real address holder would otherwise
            # keep standing under name and address — and the closing line would carry the clear name.
            self.konto_entfernen(uid)
            self.audit_log("signup_expired", ersatzname(uid), None, f"uid={uid}")
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
        with self._schreibend():
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
            norm = _sec.ip_normiert(ip)
            if norm is None:
                ip = _sec.fuer_log(ip) or None
            else:
                ip = _sec.ip_pseudonym(norm) if self.audit_ip_pseudonym else norm
        self._exec("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                   (_now(), event, username, ip, detail))

    def delete_attempts_for(self, username, weitere=(), nach=None, unbefristet=(), ab_ids=None) -> int:
        """Delete the sign-in attempts of an account (when deleting the account, H-13).

        `weitere` are additional identifiers under which it could sign in (the
        email address — `find_user` accepts it, and the attempt then stands under it).

        Counting happens under the bucket `norm_kennung` (NFKC, Python `lower()`, IDNA for addresses),
        so deleting happens there too — `lower()` in SQLite folds only ASCII and never hit the bucket
        `ärmel` of the account `Ärmel`, nor a name with compatibility characters (`ｂｅｒｔａ`) or an
        existing address in Unicode form (`u@bücher.example`). Rows from the time before
        `_topf` stand under the raw input and are still found via SQLite `lower()`.

        Two limits (follow-up to integration findings 12/18):
        - `nach` (Unix seconds): only attempts AFTER this second (the creation of the account) —
          before that they did not apply to it, and they count in the per-IP throttling of whoever
          made them. The second itself stays: whether an attempt in it came before or after creation
          cannot be decided, and a left-over attempt expires with the
          lockout window. Identifiers in `unbefristet` apply without this limit.
          More precise is `ab_ids` (`{bucket: versuch_ab}` from `kennung_grenzen`, G2): only attempts with
          a larger id than the watermark of the identifier — from its JOINING (rename,
          address change), not from creation, and to the exact row. Where an identifier has none
          (existing data), `nach` applies.
        - If a REMAINING account carries the same bucket (a namesake such as `ｃｌａｒａ`/`clara`
          or `Émile`/`émile` from existing data, `konto_mit_topf`), the bucket stays untouched.
          Otherwise removing an account, which an anonymous party can create and have cleared via `gc()`,
          would empty the account threshold of a stranger (R7-6/H-8)."""
        n = 0
        for wert in (username, *[w for w in weitere if w]):
            topf = norm_kennung(wert)
            if not topf or self.konto_mit_topf(topf) is not None:
                continue
            wasserlinie = (ab_ids or {}).get(topf)
            if wert in unbefristet:
                grenze, ab = "ts > ?", -1
            elif wasserlinie is not None:
                grenze, ab = "id > ?", int(wasserlinie)
            else:
                grenze, ab = "ts > ?", (-1 if nach is None else int(nach))
            roh = str(wert)
            n += self._exec(f"DELETE FROM login_attempt WHERE {grenze} "
                            "AND (username = ? OR lower(username) = lower(?) "
                            "OR lower(username) = lower(?))",
                            (ab, topf, roh, roh.strip())).rowcount
        return n

    def gc_audit(self, older_than_ts: int) -> int:
        """Delete audit rows before a point in time (`audit_retention_days`, B5-11)."""
        return self._exec("DELETE FROM audit WHERE ts < ?", (int(older_than_ts),)).rowcount

    def audit_anonymisieren(self, username, ersatz, weitere=(), seit=None, seit_id=0,
                            unbefristet=(), ab_ids=None) -> int:
        """Take an account out of the audit log without deleting the rows (H-13).

        The row "on the 3rd at 14:02 a password was reset, from this IP" stays for
        forensics; WHO it was then stands only as `ersatz`. `weitere` are
        additional identifiers (the email address): under it, sign-in attempts stand in the
        column `username` (`find_user` accepts the address), and it occurs in the detail text.

        In the detail text the USERNAME is replaced only where one stands — `akteur=<name>`
        and the head of `user_create`. Freely replacing every identical word hit
        foreign rows: with the account `admin`, `admin=0->1` in the role change of an
        OTHER account became `gelöscht#2=0->1`, with `password` the method of every failed attempt. An
        identifier with `@`, on the other hand, is unmistakable and is replaced everywhere.

        `seit`/`seit_id` restrict this to rows from the creation of the account (`anlage_grenze`,
        `konto_entfernen`): what was written before under the name or with the address
        did not belong to this account. Identifiers in `unbefristet` apply without the limit. Without
        `seit` every row applies. More precise is `ab_ids` (`{bucket: audit_ab}` from `kennung_grenzen`,
        G2): from the joining of the identifier instead of from creation — otherwise, when deleting an
        account that had taken over a freed name, the previous owner's row was
        rewritten too. Where an identifier has none (existing data), `seit` applies.

        **The search in the detail text is a scan** — a substring search (`instr`) that no
        B-tree index narrows down; `idx_audit_name_ts`/`idx_audit_ts` help only the column
        `username` and the period from `seit`. For an unrestricted address (deletion by
        an admin, `adresse_unbefristet`) it reads the whole audit log, and that grows without
        `audit_retention_days` without limit. Until 2026-09-26 this scan ran in ONE
        write transaction, under the write lock (`_lock`) and with an open SQLite transaction:
        every sign-in, every audit entry, every other worker waited out the whole search (G4).
        Now it reads in blocks by `id` (`_ANONYM_BLOCK` rows) WITHOUT a write transaction and
        writes only the hits, per block in a short transaction — the row read there fresh
        and re-checked, so that nothing is overwritten that has changed since reading.
        The search runs up to the most recent row at its start; what comes afterwards was written
        by someone after the deletion.

        **What the deletion promise left out until 2026-09-27** (lockouts/counters audit round, F4 — already
        so on main):

        * **Every spelling of the typed identifier** (4a): `login_fail` writes the RAW
          input (`Émile `, ` emile@example.com`, `ＥＭＩＬＥ@example.com`), counted in the
          bucket (`norm_kennung`). `lower(username)` hit only ASCII variants of these. The block scan
          therefore also compares the column `username` in the bucket (SQL function `tinysesam_kennung`,
          only for queries of this connection), with the same limits per identifier. If a
          REMAINING account shares the bucket (namesake from existing data, as with
          `delete_attempts_for`), it stays with `lower()` — otherwise it would hit its rows.
        * **Earlier names and addresses** (4b): from the own rows `username_changed alt=…` and
          `email_changed alt=…` (`_fruehere_kennungen`), each in the span in which the account
          carried them — the sign-in under the old name would otherwise keep standing with its IP.
        * **Values in the own rows** (4c): in every row whose `username` is afterwards
          the replacement name, the values of `alt=`, `neu=` and `an=` — the never redeemed address change,
          the address from LDAP/SAML, the old name.
        """
        if not username:
            return 0
        import re as _re
        ohne_frist = {str(w) for w in unbefristet if w}
        offen = self._OHNE_OBERGRENZE

        def ab(wert) -> tuple:
            if wert in ohne_frist:
                return (-1, -1, 0, -1, offen)
            wasserlinie = (ab_ids or {}).get(norm_kennung(wert))
            if wasserlinie is not None:
                return (-1, -1, 0, int(wasserlinie), offen)
            if seit is None:
                return (-1, -1, 0, -1, offen)
            return (int(seit), int(seit), int(seit_id or 0), -1, offen)
        grenze = "((ts > ? OR (ts = ? AND id >= ?)) AND id > ? AND id <= ?)"
        anlage = (-1, -1, 0, -1) if seit is None else (int(seit), int(seit), int(seit_id or 0), -1)
        # Every identifier with its span: today's, then the earlier ones (4b) — read BEFORE
        # anything is rewritten; afterwards the rows they come from stand under `ersatz`.
        kennungen = [(str(w), ab(str(w))) for w in (username, *weitere) if w]
        kennungen += self._fruehere_kennungen(kennungen, anlage, grenze)
        # Compared folded (4a) only where no remaining account shares the bucket.
        falten = {t for t in {norm_kennung(w) for w, _ in kennungen} - {""}
                  if self.konto_mit_topf(t) is None}
        # The column `username`: via `idx_audit_name_ts`, short — one transaction.
        with self._schreibend():
            n = 0
            for wert, grenzwerte in kennungen:
                n += self.db.execute(
                    f"UPDATE audit SET username=? WHERE lower(username)=lower(?) AND {grenze}",
                    (ersatz, wert, *grenzwerte)).rowcount
            self.db.commit()
        oben = int(self._one("SELECT max(id) AS m FROM audit")["m"] or 0)
        for wert, grenzwerte in kennungen:
            w = _re.escape(wert)
            ende = r"(?![\w@.=-])"
            if "@" in wert:
                muster = _re.compile(r"(?<![\w@.-])" + w + ende, _re.IGNORECASE)
            else:
                muster = _re.compile(r"(?<![\w@.-])akteur=" + w + ende, _re.IGNORECASE)
            topf = norm_kennung(wert)
            gefaltet = topf in falten

            def umschreiben(event, alt, wert=wert, w=w, muster=muster) -> str:
                if "@" in wert:
                    return muster.sub(ersatz, alt)
                neu = muster.sub("akteur=" + ersatz, alt)
                if event == "user_create":   # detail: "<name> service=…"
                    neu = _re.sub(r"^" + w + r"(?=\s|$)", ersatz, neu, count=1, flags=_re.IGNORECASE)
                return neu

            def name_trifft(name, topf=topf, gefaltet=gefaltet) -> bool:
                return gefaltet and name is not None and name != ersatz and norm_kennung(name) == topf
            # Where the search begins: behind the watermark, or at the first row from `seit`
            # — before that no row satisfies the limit. `id + 0`, so that SQLite finds the minimum via
            # `idx_audit_ts` (only the rows from `seit`) and does not walk the table from the first
            # `id` until `ts` fits — for a young account that would be the whole log.
            unten = max(grenzwerte[3], 0)
            if grenzwerte[0] >= 0:
                erste = self._one("SELECT min(id + 0) AS m FROM audit WHERE ts >= ?",
                                  (grenzwerte[0],))["m"]
                unten = max(unten, int(erste) - 1 if erste is not None else oben)
            schluss = min(oben, grenzwerte[4])
            # The column `username` in the bucket (4a) only where folding is done: the function costs a
            # Python call per row.
            auch_name = "OR tinysesam_kennung(username) = ?" if gefaltet else ""
            while unten < schluss:
                bis = min(unten + self._ANONYM_BLOCK, schluss)
                # The block via the primary key (`id > ? AND id <= ?`, so it stands in the plan) —
                # never via `idx_audit_ts`: otherwise each block would read all rows from `seit`, and the
                # search would become quadratic (tests/test_audit_round2.py checks the plan).
                kandidaten = {z["id"]: z for z in self._all(
                    "SELECT id, event, username, detail FROM audit WHERE id > ? AND id <= ? "
                    f"AND (instr(lower(detail), lower(?)) > 0 {auch_name}) AND {grenze}",
                    (unten, bis, wert, *((topf,) if gefaltet else ()), *grenzwerte))
                    if umschreiben(z["event"], z["detail"] or "") != (z["detail"] or "")
                    or name_trifft(z["username"])}
                if kandidaten:
                    with self._schreibend():
                        for zid in kandidaten:
                            z = self.db.execute("SELECT event, username, detail FROM audit WHERE id=?",
                                                (zid,)).fetchone()
                            if z is None:
                                continue          # cleared away meanwhile (`gc_audit`)
                            alt = z["detail"] or ""
                            neu = umschreiben(z["event"], alt)
                            name = ersatz if name_trifft(z["username"]) else z["username"]
                            if neu != alt or name != z["username"]:
                                self.db.execute("UPDATE audit SET username=?, detail=? WHERE id=?",
                                                (name, neu if neu != alt else z["detail"], zid))
                                n += name != z["username"]
                        self.db.commit()
                unten = bis
        self._eigene_werte_ersetzen(ersatz, oben)
        return n

    #: How many audit rows `audit_anonymisieren` searches in the detail text per block before it
    #: releases the write lock for others (G4).
    _ANONYM_BLOCK = 5000
    #: Upper bound of the span of a TODAY identifier (`audit_anonymisieren`): none.
    _OHNE_OBERGRENZE = 2 ** 62
    #: How many earlier names or addresses `_fruehere_kennungen` traces back at most.
    _FRUEHERE_MAX = 100
    #: The old name in `username_changed` (`alt=<name>[ durch=betreiber][ quelle=cli][ akteur=…]`)
    #: and the old address in `email_changed` (`alt=<adresse> neu=<adresse>`). A name may
    #: carry spaces, an address may not (`valid_email`).
    _ALT_NAME = re.compile(r"^alt=(.*?)(?= durch=| quelle=| akteur=|$)")
    _ALT_MAIL = re.compile(r"^alt=(\S*)")
    #: The values in the own rows that carry an identifier (4c): up to the next ` key=`.
    _EIGENE_WERTE = re.compile(r"(?<![\w@.-])(alt|neu|an)=(\S.*?)(?=\s[\w-]+=|$)")

    def _fruehere_kennungen(self, heutige, anlage, grenze) -> list:
        """Earlier names and addresses of an account, each with the span in which it carried them —
        `[(kennung, limits)]` for `audit_anonymisieren` (H-13, audit round 2026-09-27, 4b).
        `heutige`: `[(name, limits), (address, limits)]`, `anlage`: the limit of the creation
        without an upper bound.

        Read from the own rows: `username_changed` stands under the NEW name and names the
        old one (`alt=`), `email_changed` under the name at the time of the change and names the old
        address. Backwards from today's name: the most recent rename in its span names the
        predecessor. It belonged to the account until that row, from the row that introduced IT — the
        most recent rename under it before that, not before creation —, otherwise from creation. Likewise the
        addresses, from the change rows under all names. Not covered: an address that came and went
        without `email_changed` (backfill from OIDC/LDAP) — there is no row for it. Via
        `idx_audit_name_ts`, no scan."""
        if not heutige:
            return []
        suche = ("SELECT id, detail FROM audit WHERE lower(username) = lower(?) AND event = ? "
                 f"AND {grenze} ORDER BY id DESC")
        namen: list = []
        name, grenzwerte = heutige[0]
        z = self._one(suche + " LIMIT 1", (name, "username_changed", *grenzwerte))
        for _ in range(self._FRUEHERE_MAX):
            m = self._ALT_NAME.match(str(z["detail"] or "")) if z is not None else None
            alt = m.group(1).strip() if m else ""
            if z is None or not alt:
                break
            bis = int(z["id"])
            z = self._one(suche + " LIMIT 1", (alt, "username_changed", *anlage, bis - 1))
            namen.append((alt, (-1, -1, 0, int(z["id"]) - 1, bis) if z is not None else (*anlage, bis)))
        wechsel: dict = {}
        for name, grenzwerte in [heutige[0], *namen]:
            for zeile in self._all(suche + f" LIMIT {self._FRUEHERE_MAX}", (name, "email_changed", *grenzwerte)):
                wechsel[int(zeile["id"])] = zeile
        reihe = [wechsel[i] for i in sorted(wechsel, reverse=True)][:self._FRUEHERE_MAX]
        adressen: list = []
        for i, zeile in enumerate(reihe):
            m = self._ALT_MAIL.match(str(zeile["detail"] or ""))
            alt = m.group(1) if m else ""
            if not alt:
                continue
            bis = int(zeile["id"])
            vor = reihe[i + 1] if i + 1 < len(reihe) else None
            adressen.append((alt, (-1, -1, 0, int(vor["id"]) - 1, bis) if vor is not None else (*anlage, bis)))
        return namen + adressen

    def _eigene_werte_ersetzen(self, ersatz, oben) -> None:
        """In the rows of the deleted account (`username` = replacement name, up to `oben`) replace the values of
        `alt=`, `neu=` and `an=` (H-13, audit round 2026-09-27, 4c): the requested, never
        redeemed address change (`email_change_requested neu=…`), the address from LDAP/SAML
        (`federation_email_confirm an=…`), the old name (`username_changed alt=…`). Empty values
        stay empty. Via `idx_audit_name_ts`; written per `_ANONYM_BLOCK` rows, the row
        read fresh."""
        def ersetzen(detail) -> str:
            return self._EIGENE_WERTE.sub(lambda m: f"{m.group(1)}={ersatz}", detail)
        treffer = [int(z["id"]) for z in self._all(
            "SELECT id, detail FROM audit WHERE lower(username) = lower(?) AND id <= ?", (ersatz, oben))
            if z["detail"] and ersetzen(z["detail"]) != z["detail"]]
        for i in range(0, len(treffer), self._ANONYM_BLOCK):
            with self._schreibend():
                for zid in treffer[i:i + self._ANONYM_BLOCK]:
                    z = self.db.execute("SELECT username, detail FROM audit WHERE id=?", (zid,)).fetchone()
                    if z is None or z["username"] != ersatz or not z["detail"]:
                        continue
                    self.db.execute("UPDATE audit SET detail=? WHERE id=?", (ersetzen(z["detail"]), zid))
                self.db.commit()

    def recent_audit(self, limit=100, username: str | None = None, seit: int | None = None,
                     seit_id: int = 0, ab_id: int | None = None, ohne_events=()):
        """The most recent audit entries, newest first.

        `username` filters in SQL, not in the caller. That is the difference between "the
        last N entries of this account" and "the entries of this account among the last N" —
        and exactly that counts in the motivating case: a brute-force wave pushes thousands of
        rows in within minutes, and the account being sought then lies far behind any window. For the same reason
        `seit` (Unix seconds, inclusive) also filters in SQL; from the second `seit`
        itself only rows from `seit_id` (see `anlage_grenze`). `ab_id`: only rows with a
        larger id — the watermark of an identifier (`kennung_grenzen`, G2). `ohne_events`
        leaves out these events, likewise in SQL: a display that discards rows only afterwards
        would show fewer than `limit` — and the gap would reveal that there had been one (G12b).
        """
        bedingungen: list[str] = []
        werte: list[object] = []
        if ohne_events:
            bedingungen.append(f"event NOT IN ({','.join('?' * len(ohne_events))})")
            werte.extend(ohne_events)
        if username:
            bedingungen.append("lower(username)=lower(?)")
            werte.append(username)
        if seit:
            bedingungen.append("(ts > ? OR (ts = ? AND id >= ?))")
            werte.extend((int(seit), int(seit), int(seit_id or 0)))
        if ab_id is not None:
            bedingungen.append("id > ?")
            werte.append(int(ab_id))
        wo = (" WHERE " + " AND ".join(bedingungen)) if bedingungen else ""
        return self._all(f"SELECT * FROM audit{wo} ORDER BY id DESC LIMIT ?", (*werte, limit))

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

    #: What settles a confirmation request from LDAP/SAML for the day (`quellmail_seit`): the
    #: delivered link and the rejection of a taken or reserved address.
    QUELLMAIL_ERLEDIGT = ("federation_email_confirm", "email_change_taken", "email_change_reserved")

    def quellmail_seit(self, user_id, seit) -> bool:
        """Has a confirmation request for an address from LDAP/SAML on this account been settled
        since `seit` (Unix seconds)? Delivered (G12a: the row `federation_email_confirm`, which arises only AFTER
        the successful send) or rejected because the address is taken or
        reserved (`email_change_taken`/`_reserved` from this path, attack round 2026-09-26 —
        otherwise every worker wrote its own row, and the account page counted along). Recognised by the
        detail that begins with `konto=<id> `; self-service does not write it. Via
        `idx_audit_ts`, in the database and thus across all workers and every restart.
        The id instead of the name: a rename does not reset the daily quota."""
        return bool(self._one(
            "SELECT 1 FROM audit WHERE ts >= ? AND event IN (?, ?, ?) AND detail LIKE ? LIMIT 1",
            (int(seit), *self.QUELLMAIL_ERLEDIGT, f"konto={int(user_id)} %")))

    def offener_token(self, user_id, purpose, email=None) -> bool:
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

"""SQLite-Store für TinySesam: Nutzer, Credentials (Passwort/TOTP/WebAuthn/OIDC) und Sessions.

Bewusst stdlib-`sqlite3` (kein ORM): leichtgewichtig, keine zusätzliche Abhängigkeit.
Thread-safe über ein Lock + `check_same_thread=False` (FastAPI-Worker teilen sich die Instanz).

Was bei einer nur lesbaren, vollen oder gesperrten Datenbank und bei einem Sprung der Systemuhr
geschieht, steht für Betreiber in `docs/BETRIEB.md` (Ausfallverhalten).
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
    topf_name     TEXT,
    topf_mail     TEXT,
    idp_bestaetigt_at INTEGER  -- letzte Bestätigung durch den OIDC-Provider; 0 = Nein, NULL = nie (Fund 8)
);
CREATE TABLE IF NOT EXISTS api_key (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT,
    prefix     TEXT NOT NULL,                   -- Anzeige (tsk_xxxx…), NICHT der Key
    key_hash   TEXT UNIQUE NOT NULL,            -- sha256(vollständiger Key)
    roles      TEXT NOT NULL DEFAULT '[]',      -- Key-Scope; leer = erbt User-Rollen
    -- Welche Art Key ist das? (R6-5)
    --   'automat' (Vorgabe): arbeitet allein, trägt NIE das Admin-Flag seines Besitzers und
    --                        erfüllt keine Route, die Admin verlangt. Für Dienste und Skripte.
    --   'mensch'           : gilt nur ZUSAMMEN mit einer gültigen Sitzung desselben Kontos.
    --                        Dafür trägt er die vollen Rechte — der Weg für ein Werkzeug, das
    --                        ein Mensch selbst bedient (CLI am eigenen Rechner).
    -- Bis 0.18.x gab es die Unterscheidung nicht: Jeder Key eines Admins war eine vollständige
    -- Admin-Schreib-API, ohne zweiten Faktor und ohne CSRF-Schicht — ein abgeflossener CI-Key
    -- war die Instanz.
    kind       TEXT NOT NULL DEFAULT 'automat',
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
    PRIMARY KEY (quelle, kennung)
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
    bleiben_gewaehlt INTEGER NOT NULL DEFAULT 0 -- „Angemeldet bleiben" AUSDRÜCKLICH gewählt (F-05: dann gilt die zweite Leerlauf-Grenze)
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
    refresh     TEXT NOT NULL,                -- verschlüsselt (geheimnis.Tresor), nie im Klartext
    geprueft_at INTEGER NOT NULL,             -- letzter Tausch (oder: beansprucht, s. Store)
    PRIMARY KEY (token_hash, client)
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
CREATE INDEX IF NOT EXISTS idx_audit_name_ts ON audit(lower(username), ts);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_attempt_user ON login_attempt(username, ts);
CREATE INDEX IF NOT EXISTS idx_attempt_ip ON login_attempt(ip, ts);
CREATE INDEX IF NOT EXISTS idx_apikey_user ON api_key(user_id);
"""


#: Zeichen, in denen sich IDNA 2003 (stdlib-Codec) und IDNA 2008 unterscheiden: Der stdlib-Codec
#: macht aus `straße.example` ein `strasse.example` — eine ANDERE Domain. Enthält eine Domain eines davon,
#: bleibt sie in Unicode-Form statt falsch umgeschrieben zu werden.
_IDNA_ABWEICHLER = frozenset("ßς\u200c\u200d")


def _domain_kanonisch(domain: str) -> str:
    """Eine Domain in die A-Label-Form (`xn--…`) bringen, wenn das eindeutig geht (R4-06).

    Sonst stehen `bücher.example` und `xn--bcher-kva.example` als zwei verschiedene Adressen in der
    Datenbank, obwohl beide dasselbe Postfach meinen — zwei Konten, zwei „vergeben"-Prüfungen,
    die einander nicht sehen. Was sich nicht sicher umschreiben lässt, bleibt unverändert."""
    if domain.isascii() or any(z in _IDNA_ABWEICHLER for z in domain):
        return domain
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain


def _email_unicode(email: str) -> str:
    """Die Adresse mit der Domain in Unicode-Form (`xn--bcher-kva.example` → `bücher.example`).

    Nur für die Suche nach Bestandsadressen von vor R4-06, die noch so gespeichert sind — nie zum
    Speichern. Was sich nicht dekodieren lässt, kommt unverändert zurück."""
    lokal, at, domain = email.rpartition("@")
    if not at or "xn--" not in domain:
        return email
    try:
        return f"{lokal}@{domain.encode('ascii').decode('idna').lower()}"
    except UnicodeError:
        return email


def norm_email(email) -> Optional[str]:
    """E-Mail kanonisch speichern: NFKC, getrimmt, klein, Domain als A-Label. `None` bleibt `None`.

    NFKC faltet Kompatibilitätszeichen (R4-06): `ａｄｍｉｎ@example.com` in Vollbreite ist danach
    dasselbe wie `admin@example.com` — vorher waren es zwei Kennungen, die im Panel gleich
    aussahen."""
    e = unicodedata.normalize("NFKC", str(email or "")).strip().lower()
    if not e:
        return None
    lokal, at, domain = e.rpartition("@")
    if at and domain:
        e = f"{lokal}@{_domain_kanonisch(domain)}"
    return e


def _schriften(text: str) -> set:
    """Die Schriftsysteme der Buchstaben in `text` (erstes Wort des Unicode-Namens: LATIN,
    CYRILLIC, GREEK …). Ziffern und Satzzeichen zählen nicht."""
    return {unicodedata.name(z, "?").split(" ", 1)[0] for z in text if z.isalpha()}


#: Schriften, die in EINER Sprache zusammengehören und deshalb mischen dürfen (Angriff A6,
#: Vorbild UTS #39 „Highly Restrictive"): Japanisch schreibt Kanji mit Hiragana und Katakana
#: (`山田たろう`, `例え`), Koreanisch Hanja mit Hangul, Chinesisch Han mit Bopomofo. Ohne diese
#: Ausnahme wies die Schriftprüfung gewöhnliche japanische Adressen und IDN-Domains ab. Latein
#: gehört bewusst in keine Gruppe — `аdmin` (kyrillisch/lateinisch) bleibt abgewiesen.
_SCHRIFT_GRUPPEN = (
    frozenset({"CJK", "IDEOGRAPHIC", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"}),
    frozenset({"CJK", "IDEOGRAPHIC", "HANGUL"}),
    frozenset({"CJK", "IDEOGRAPHIC", "BOPOMOFO"}),
)


def _eine_schrift(teil: str) -> bool:
    """Stammen die Buchstaben aus einer Schrift — oder aus einer Gruppe, die zusammengehört?"""
    s = _schriften(teil)
    return len(s) <= 1 or any(s <= gruppe for gruppe in _SCHRIFT_GRUPPEN)


def norm_kennung(kennung) -> str:
    """Die Login-Kennung so, wie der Sperrzähler sie führt: NFKC, getrimmt, klein — und eine
    Adresse so kanonisch wie `norm_email` sie speichert.

    Muss mindestens so grob falten wie `TinySesam.find_user` (strip, `norm_email`, NOCASE):
    Jede Schreibweise, die dasselbe Konto trifft, gehört in denselben Zähl-Topf. Sonst stellt
    sich ein verteilter Angreifer mit `' opfer'`, `'opfer '`, `'\topfer'` … beliebig viele
    frische Töpfe auf, und die Konto-Schwelle über alle Adressen bindet nichts. `lower()`
    faltet gröber als NOCASE (auch ausserhalb von ASCII) — zwei Namen, die nur darin
    abweichen, teilen sich dann einen Topf. Das ist strenger, nie lockerer.

    Bis zur Integration von T-13 hiess das nur strip + lower. `norm_email` faltet seit R4-06
    aber auch NFKC und IDNA, und `find_user` fand damit `ｖｉｃｔｉｍ@example.com`,
    `victim＠example.com` (Vollbreiten-@) und jede Mischform — je mit eigenem Topf, allein für
    diese Adresse 2^16. Deshalb erst NFKC, DANN nach dem `@` sehen: Das Vollbreiten-@ U+FF20
    wird erst durch die Faltung zu einem. Gezählt wird bewusst unter der gefalteten EINGABE,
    nicht unter dem Konto, das sie trifft: So verhält sich die Sperre für vorhandene und
    erfundene Kennungen gleich und verrät nicht, welche Adresse zu welchem Benutzernamen
    gehört (Benutzername und Adresse eines Kontos sind deshalb zwei Töpfe; `sperre_aufheben`
    räumt beide). Namensvetter aus einem Bestand (`Émile`/`émile`) teilen einen Topf; neu
    anlegen lässt sich keiner mehr (`TinySesam.kennung_vergeben` fragt
    `Store.konto_mit_topf`), und `delete_attempts_for` lässt einen geteilten Topf stehen."""
    k = unicodedata.normalize("NFKC", str(kennung or "")).strip().lower()
    if "@" in k:
        return norm_email(k) or ""
    return k


def valid_email(email) -> bool:
    """Bewusst nachsichtig: genau ein @, links und rechts was dran, rechts ein Punkt, keine Leerzeichen.
    Ob die Adresse existiert, beantwortet nur der Bestätigungslink (`signup_verify_email`).

    Abgewiesen wird ausserdem, was zum Verwechseln gebaut ist (R4-06): unsichtbare Zeichen
    (Steuer- und Formatzeichen wie Zero-Width-Joiner) und ein Teil, der Schriften mischt —
    `аdmin@example.com` mit kyrillischem `а` sieht im Panel aus wie das Admin-Postfach. Eine
    Adresse ganz in einer Schrift (`müller@…`, `иван@…`) bleibt erlaubt, ebenso die Mischungen einer
    Sprache aus `_SCHRIFT_GRUPPEN` (`山田たろう@…`)."""
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
    """Die Zeitquelle für alles, was in der Datenbank mit einer Frist steht.

    Sitzungen, Einmal-Token, Step-up-Frische, Sperrfenster und Flow-State vergleichen einen
    gespeicherten Zeitstempel mit „jetzt". Mit der nackten Wanduhr (`time.time()`) belebte ein
    Rückwärtssprung all das wieder: NTP-Korrektur, ein Raspberry Pi, der ohne Pufferbatterie
    mit einem alten Datum bootet, ein VM-Snapshot — eine abgelaufene Sitzung galt erneut, ein
    verfallener Magic-Link liess sich einlösen, ein alter Step-up war wieder „frisch" (B6-9).

    Deshalb läuft diese Uhr nie rückwärts: Sie folgt der Wanduhr nach vorn, rückwärts aber nur
    mit der vergangenen **monotonen** Zeit (`time.monotonic()` kennt keine Sprünge). Nach einem
    Sprung um eine Stunde zurück zählt sie also normal weiter, statt eine Stunde stehenzubleiben
    — Fristen laufen weiter ab. Über einen Neustart trägt die Datenbank selbst den Stand:
    `Store()` hebt die Uhr auf den jüngsten Zeitstempel, den sie findet (`mindestens()`) —
    darunter den Stand, den `Store` höchstens jede Minute mitschreibt (`uhr_stand`, bei jedem
    Schreibzugriff und bei jeder Schreibprobe des Healthchecks). Was in der letzten Minute vor
    einem Neustart ablief oder in einer Zeit, in der gar nichts geschrieben wurde, kann danach
    also bis zu diesem Abstand länger gelten — nicht aber seine volle Restfrist.

    Der Preis: Sprang die Wanduhr einmal falsch nach VORN, bleibt die Uhr dort, bis die Wanduhr
    aufholt — Fristen sind dann intern stimmig, nur eben in der Zukunft datiert. Das ist die
    sichere Richtung, und es steht als Warnung im Log.

    `wand`/`mono` sind austauschbar, damit ein Test einen Sprung stellen kann, ohne die Uhr des
    ganzen Prozesses zu verbiegen. Ohne Angabe werden `time.time`/`time.monotonic` bei JEDEM
    Aufruf nachgeschlagen, nicht beim Import gebunden: Eine einbettende App, die in ihren Tests
    `time.time` patcht (`mock.patch`, `monkeypatch`, freezegun), stellt damit auch diese Uhr
    vor. Zurückdrehen lässt sie sich so nicht — das ist genau der Schutz oben.

    freezegun ersetzt zusätzlich `time.monotonic`, und zwar durch die eingefrorene Zeit auf der
    Epoch-Skala statt durch die Betriebszeit. Fortgeschrieben wäre das ein Sprung um Jahrzehnte
    (und beim Verlassen von `freeze_time` einer zurück). Ein Monotonie-Schritt, der rückwärts
    geht oder größer ist als `MONO_SCHRITT_MAX_SEK`, zählt deshalb nicht als vergangene Zeit:
    Unter freezegun folgt die Uhr der eingefrorenen Wanduhr nach vorn (`tick()`/`move_to()`
    eingeschlossen); nach dem Verlassen läuft sie vom vorgestellten Stand aus mit der echten
    monotonen Zeit weiter — wie nach `mock.patch`. Der Vorsprung bleibt also: für die Lebensdauer
    des Prozesses (die echte Zeit holt ihn nicht ein, beide laufen gleich schnell) und über
    `uhr_stand` in dieser Datenbank für jede spätere Öffnung, solange die Pause dazwischen kürzer
    ist als der Vorsprung. Das ist die sichere Richtung; ein Test, der die Uhr weit vorstellt,
    nimmt deshalb eine eigene Wegwerf-Datenbank. Den Preis der Plausibilitätsgrenze zahlt nur
    ein Rückwärtssprung der Wanduhr, der in eine Pause von mehr als einem Jahr ohne jeden Aufruf
    fällt: Dann gilt die zurückgesprungene Wanduhr, aber nie weniger als der zuletzt ausgegebene
    Stand. Dieselbe Regel gilt für die monotonen Stempel des `Store` (`_frisch`): Ein negativer
    Abstand ist abgelaufen, nicht frisch.
    """

    #: Ab welchem Rückstand der Wanduhr eine Warnung geschrieben wird (Sekunden). Darunter ist
    #: es normales NTP-Zittern.
    WARN_AB_SEK = 5

    #: Größter Schritt der monotonen Zeit zwischen zwei Aufrufen, der noch als vergangene Zeit
    #: gilt (Sekunden). Ein echter Schritt ist die Pause zwischen zwei Anfragen; freezegun liefert
    #: dagegen die eingefrorene Zeit auf der Epoch-Skala (≈1,8e9 s) — ein Sprung um Jahrzehnte.
    #: Ein Jahr trennt beides sicher, ohne den Schutz nach einer langen Pause aufzugeben.
    MONO_SCHRITT_MAX_SEK = 365 * 86400

    def __init__(self, wand=None, mono=None):
        # Bei JEDEM Aufruf nachschlagen, nicht beim Bau binden: Wer `time.time` patcht
        # (`mock.patch`, `monkeypatch`, freezegun), stellt damit auch diese Uhr (siehe Docstring).
        def _wand():
            return time.time()

        def _mono():
            return time.monotonic()
        self.wand = wand or _wand
        self.mono = mono or _mono
        self._lock = threading.Lock()
        self._stand = 0.0          # zuletzt ausgegebene Zeit (Wanduhr-Skala)
        self._mono = None          # monotone Zeit bei dieser Ausgabe
        self._gemeldet = False     # Rückstand schon gemeldet? (eine Zeile je Sprung, nicht je Anfrage)

    def jetzt(self) -> int:
        with self._lock:
            wand, mono = float(self.wand()), float(self.mono())
            schritt = mono - self._mono if self._mono is not None else 0.0
            if not 0.0 <= schritt <= self.MONO_SCHRITT_MAX_SEK:
                # Keine echte monotone Uhr (rückwärts oder ein Sprung um Jahrzehnte: freezegun
                # ersetzt `time.monotonic` durch die Epoch-Zeit). Nicht fortschreiben — sonst
                # sprang die Uhr um ≈57 Jahre vor und `uhr_stand` hielt jede spätere Öffnung der
                # Datenbank dort fest. Die Wanduhr nach vorn gilt weiter, rückwärts steht die Uhr —
                # auch wenn die monotone Quelle selbst zurückspringt (Verlassen von freeze_time).
                schritt = 0.0
            self._stand, self._mono = max(wand, self._stand + schritt), mono
            self._rueckstand_pruefen(wand)
            return int(self._stand)

    def mindestens(self, ts) -> None:
        """Die Uhr auf mindestens `ts` heben (jüngster Zeitstempel der Datenbank beim Öffnen)."""
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


#: Prozessweit eine Uhr: Mehrere `Store`-Instanzen im selben Prozess dürfen einander nicht
#: widersprechen, und ein Rückwärtssprung trifft den ganzen Prozess, nicht eine Datenbank.
_UHR = _Uhr()


def jetzt() -> int:
    """Aktuelle Zeit (Unix-Sekunden), die nie rückwärts läuft — s. `_Uhr`."""
    return _UHR.jetzt()


#: Längste Frist, nach der `gc` alte Login-Versuche löscht (Sekunden): zehn Jahre wie
#: `audit_retention_days`. Die Grenze ist kein Vorschlag für die Aufbewahrung — die Sperre sieht
#: ohnehin nur ihr Fenster —, sondern hält die Zahl im Bereich, den SQLite rechnen kann.
VERSUCHSFRIST_MAX_SEK = 3660 * 86400


def versuchsfrist(sekunden) -> int:
    """`attempts_older_than_sec` von `gc` prüfen — BEVOR irgendetwas gelöscht wird.

    Ohne Grenze brach ±10**20 mit `OverflowError` ab, als Sitzungen, Flows, Tokens und Unlocks
    schon weg waren; ein negativer Wert löschte jeden Fehlversuch, auch die im laufenden
    Sperrfenster, und hob damit jede Kontosperre auf. 0 bleibt erlaubt: der dokumentierte Weg,
    alle Fehlversuche zu räumen. `True` ist keine Frist (hiesse eine Sekunde). `ValueError`, wenn
    der Wert nicht passt."""
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
    """Wer ein gelöschtes Konto im Audit-Log vertritt (H-13): `gelöscht#<id>`.

    Eine Stelle für das Format — jeder Löschweg schreibt seine Schlusszeile darunter, auch
    einer, der das Konto schon nicht mehr vorfindet (sonst stünde dort wieder der Klarname)."""
    return f"gelöscht#{int(user_id)}"


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
        self.db = sqlite3.connect(db_path, check_same_thread=False,
                                  timeout=self.BUSY_TIMEOUT_MS / 1000)
        self.db.row_factory = sqlite3.Row
        # Ausdrücklich, nicht als stille Vorgabe von Pythons `sqlite3` (5 s): Der Wert entscheidet,
        # ob ein zweiter Schreiber — ein weiterer Worker, `tinysesam` auf der Kommandozeile, ein
        # WAL-Checkpoint, eine laufende Sicherung — wartet oder mit „database is locked" eine
        # Anmeldung als 500 abbricht (B6-11). Das PRAGMA wiederholt den Wert, damit er an der
        # Verbindung selbst ablesbar ist, egal wie sie geöffnet wurde.
        self.db.execute(f"PRAGMA busy_timeout={int(self.BUSY_TIMEOUT_MS)}")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        # Gelöschtes wird überschrieben, nicht nur freigegeben: Ein ersetztes Klartext-Geheimnis
        # (vor der Verschlüsselung, H-14/H-15) oder ein gelöschtes Konto bliebe sonst in freien
        # Seiten der Datei — und damit in jeder Sicherung — lesbar, je nach SQLite-Bau.
        self.db.execute("PRAGMA secure_delete=ON")
        self._lock = threading.Lock()
        self._uhr_gesichert: Optional[float] = None   # monotone Zeit des letzten gesicherten Uhrstands
        self._geschrieben: Optional[float] = None     # monotone Zeit des letzten erfolgreichen Commits
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.commit()
        self._migrate()
        self._dateirechte_pruefen(db_path, neu)
        _UHR.mindestens(self._juengster_zeitstempel())

    #: Wie lange eine Anfrage auf eine gesperrte Datenbank wartet, bevor sie aufgibt (ms).
    #: Doppelt so lang wie Pythons Vorgabe: Ein Checkpoint oder eine Sicherung auf langsamem
    #: Speicher (SD-Karte, Netzlaufwerk) dauert länger als 5 s, und ein abgebrochener Login
    #: ist teurer als ein langsamer. Länger nicht — der Worker-Thread hängt so lange fest.
    BUSY_TIMEOUT_MS = 10_000

    def _juengster_zeitstempel(self) -> int:
        """Der jüngste Ereignis-Zeitstempel der Datenbank — der Stand der Uhr über einen Neustart.

        Nur Zeitpunkte, zu denen etwas GESCHAH (angelegt, protokolliert), keine Fristen: ein
        `expires_at` liegt planmässig in der Zukunft und würde die Uhr vorstellen."""
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
    #: 5 — `users.email_verified`: der Beleg für die Adresse, getrennt von der Adresse selbst
    #: 6 — `oidc_grant`: Freigabe je Anwendung (T-14)
    #: 7 — `api_key.kind`: Automaten- und Menschen-Keys (R6-5)
    #: 8 — `users.first_login_at`, `users.mfa_enroll_until` (R3-1) — Stand von 0.19.0
    #: 9 — `federated_identity`: stabile Verzeichnis-Kennungen für LDAP/SAML (F-11)
    #: 10 — `users.topf_name`/`topf_mail` mit Index und Triggern, Indizes für die Suche nach Name
    #:      und Adresse (NOCASE); Bestand: Sperren aus dem Panel auf den Betreiber-Vermerk
    #:      (`disabled=2`), Adressen offener Registrierungen ohne Beleg (`_migrate`)
    #: 11 — `fehlserie`: Fehlversuche in Folge je Kennung (B2-6); `users.is_admin=2` heisst
    #:      „vom Identity Provider vergeben" (H-5) — die Spalte selbst bleibt, wie sie ist;
    #:      `users.is_owner` (Owner); `session.zuletzt` (Inaktivitäts-Timeout, F-05);
    #:      `session.andere_beenden` (Grenze d); `oidc_sitzung` (Refresh-Token, 4a);
    #:      `users.idp_bestaetigt_at` (API-Keys folgen dem IdP, Fund 8)
    SCHEMA_VERSION = 11

    #: Ab diesem Schema-Stand sind `topf_name`/`topf_mail` mit der heutigen `norm_kennung`
    #: gerechnet. Wer die Faltung in `norm_kennung` ändert, hebt `SCHEMA_VERSION` und setzt diesen
    #: Wert gleich — sonst stünden die Töpfe des Bestands in der alten Faltung im Index, und
    #: `konto_mit_topf` fände Namensvetter nicht mehr.
    TOPF_SCHEMA = 10

    def _migrate(self):
        """Additive Migrationen für bestehende DBs: fehlende Spalten nachrüsten (idempotent).

        Am Ende steht `PRAGMA user_version` auf `SCHEMA_VERSION`. Bis 0.18.0 gab es diesen
        Stempel nicht: Welchen Stand eine Datei hat, war nur an ihren Spaltennamen zu erraten —
        und eine Datei aus einer NEUEREN Fassung öffnete eine ältere TinySesam-Version
        stillschweigend, mit Tabellen, die sie nicht kennt. Der Stempel macht daraus eine
        Ansage statt eines rätselhaften Verhaltens."""
        adds = {
            "session": [("mfa_at", "INTEGER"), ("remember", "INTEGER NOT NULL DEFAULT 1"),
                        ("factors_done", "TEXT NOT NULL DEFAULT '[]'"),
                        # NULL für Bestandssitzungen: gilt als `created_at` (F-05).
                        ("zuletzt", "INTEGER"),
                        ("andere_beenden", "INTEGER NOT NULL DEFAULT 0"),
                        ("bleiben_gewaehlt", "INTEGER NOT NULL DEFAULT 0")],
            "totp_cred": [("last_step", "INTEGER")],
            # Bestandskeys gelten als Automaten-Keys: die engere Auslegung. Ein Key,
            # der bisher Admin-Routen bedienen konnte, verliert das — genau das ist
            # der Sinn von R6-5, und ein abgewiesener Aufruf hinterlässt eine Zeile.
            "api_key": [("kind", "TEXT NOT NULL DEFAULT 'automat'")],
            # `DEFAULT 1` füllt jede Bestandszeile: Adressen, die vor dieser Spalte entstanden
            # sind, behalten genau ihre bisherige Wirkung. Auf 0 kommt eine Adresse nur, wenn
            # ein Aufrufer sie ausdrücklich ohne Beleg einträgt (OIDC ohne `email_verified`).
            "users": [("email_verified", "INTEGER NOT NULL DEFAULT 1"),
                      # Beide NULL für Bestandskonten: Wer noch kein TOTP hat, soll es beim
                      # nächsten Login einrichten können — der Riegel greift ab da (R3-1).
                      ("first_login_at", "INTEGER"), ("mfa_enroll_until", "INTEGER"),
                      # NULL = noch nicht gerechnet; weiter unten für den Bestand nachgetragen.
                      # Ohne NOT NULL: Eine ältere Fassung (Rückschritt) legt Konten weiter an.
                      ("topf_name", "TEXT"), ("topf_mail", "TEXT"),
                      # 0 für den Bestand; wer Owner wird, entscheidet `Store._owner_nachziehen`.
                      ("is_owner", "INTEGER NOT NULL DEFAULT 0"),
                      # Bestand: unten für OIDC-Konten auf „jetzt" gesetzt (Fund 8).
                      ("idp_bestaetigt_at", "INTEGER")],
        }
        # `_schreibend`, nicht nur `_lock`: Der Schluss-Commit unten nimmt DELETE und Stempel mit.
        # Scheitert davor etwas, bliebe ohne Zurückrollen eine Transaktion auf der Verbindung
        # offen (der AST-Wächter in tests/test_hardening2.py verlangt das für jeden Commit).
        with self._schreibend():
            # `fehlserie` kam mit Schema 11 zunächst ohne Spalte `art` (nie veröffentlichter
            # Zwischenstand). Eine solche Tabelle wird neu angelegt — sonst liefe jede Anmeldung auf
            # einen 500. Die Serien darin gehen verloren; das ist der kleinere Schaden.
            _fs = {r["name"] for r in self.db.execute("PRAGMA table_info(fehlserie)")}
            if _fs and "art" not in _fs:
                ddl = re.search(r"CREATE TABLE IF NOT EXISTS fehlserie \(.*?\n\);", SCHEMA, re.S)
                if ddl is None:     # steht in SCHEMA; fehlt sie dort, ist das ein Fehler hier
                    raise RuntimeError("SCHEMA enthält keine Tabelle fehlserie")
                self.db.execute("DROP TABLE fehlserie")
                self.db.execute(ddl.group(0))
            neu_angelegt = set()
            for table, cols in adds.items():
                have = {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}
                for name, decl in cols:
                    if name not in have:
                        self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                        neu_angelegt.add((table, name))

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

            # Freischaltungen aus der Zeit vor der Umstellung lassen sich nicht umrechnen: Aus
            # dem Klartext wird der Hash, aus dem Hash nichts. Sie werden verworfen — betroffen
            # sind nur offene Ressourcen-Freigaben, und die holt man sich mit dem Geheimnis in
            # Sekunden zurück. Eine halb gehashte Tabelle wäre schlimmer.
            #
            # Erkannt wird das am WERT, nicht am Schema-Stempel. Die erste Fassung fragte
            # `0 < user_version < 4` — und traf damit genau den Fall nicht, für den sie
            # geschrieben war: `user_version` kam selbst erst mit 0.18.0, eine Bestandsdatei aus
            # 0.17.0 trägt dort die 0, und `0 < 0` ist falsch. Die Klartext-Einträge wären also
            # liegengeblieben; sie hätten nie wieder gematcht (gesucht wird seitdem der Hash)
            # und unbemerkt bis zu ihrem Ablauf Platz belegt. Der Test dazu steht in
            # tests/test_bestandsdaten.py.
            # Zwei Bedingungen, beide nötig: der Stempel sagt „diese Datei ist noch nicht durch"
            # (und hält den Scan aus jedem weiteren Start heraus), der WERT sagt, welche Zeile
            # wirklich Klartext ist. Der Stempel allein reichte nicht — siehe oben.
            vorhanden_vorab = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
            if vorhanden_vorab < self.SCHEMA_VERSION:
                weg = self.db.execute(
                    "DELETE FROM resource_unlock WHERE length(token) <> 64"
                    " OR token GLOB '*[^0-9a-f]*'").rowcount
                if weg:
                    logging.getLogger("tinysesam").info(
                        "%d Ressourcen-Freigaben verworfen (Token werden jetzt gehasht abgelegt).", weg)

            # Schema 10. Die Schritte laufen in derselben Transaktion wie der Stempel unten: Bricht
            # der Start dazwischen ab, fehlt auch der Stempel, und der nächste Start fährt sie erneut
            # (jeder Schritt ist wiederholbar). Die Bestandsschritte laufen bei JEDEM Start, nicht nur
            # beim Sprung über den Stempel — für das, was ein älterer Schreiber seitdem hinterlassen
            # haben kann (`_bestand_nachziehen`).
            ohne_topf = self.db.execute(
                "SELECT * FROM users" + ("" if vorhanden_vorab < self.TOPF_SCHEMA else
                                         " WHERE topf_name IS NULL OR topf_mail IS NULL")).fetchall()
            if ("users", "idp_bestaetigt_at") in neu_angelegt:
                # Die Frist für die API-Keys eines OIDC-Kontos (Fund 8) beginnt für den Bestand
                # mit dem Update — sonst ruhten nach dem Update sofort alle Keys, bis jeder sich
                # einmal über den Provider angemeldet hat. Genau einmal, beim Anlegen der Spalte:
                # Liefe es bei jedem Start, schenkte jeder Neustart einem Konto ohne Bestätigung
                # eine neue Frist. Hier und nicht direkt nach dem ALTER: Ein UPDATE öffnet in
                # Pythons sqlite3 eine Transaktion, und das `BEGIN IMMEDIATE` oben schlüge fehl.
                self.db.execute("UPDATE users SET idp_bestaetigt_at=? WHERE idp_bestaetigt_at IS NULL "
                                "AND id IN (SELECT user_id FROM oidc_identity)", (_now(),))
            self._owner_nachziehen()
            if vorhanden_vorab < 10:
                self._bestand_nachziehen(True, ohne_topf)
            else:
                try:
                    self._bestand_nachziehen(False, ohne_topf)
                except sqlite3.OperationalError as e:
                    # Wie beim Topf unten: Das darf einen Start nicht verhindern, der bisher ging.
                    # In der Transaktion liegt bei diesem Stempel nur dieser Schritt.
                    self.db.rollback()
                    logging.getLogger("tinysesam").warning(
                        "Bestandsschritte nicht nachgezogen (%s): Sperren aus dem Panel einer älteren "
                        "Fassung tragen den Betreiber-Vermerk erst nach einem Start mit "
                        "Schreibzugriff.", e)
            try:
                self._toepfe_schreiben(ohne_topf)
            except sqlite3.OperationalError:
                # Nur lesbar (Volume schreibgeschützt eingehängt) und Zeilen eines fremden
                # Schreibers ohne Topf: Das darf den Start nicht verhindern, der bisher auch ging —
                # `konto_mit_topf` prüft solche Zeilen dann selbst (`_toepfe_nachtragen`). Ein
                # Upgrade dagegen braucht die Töpfe, wie jede andere Migration ihre Spalten.
                if vorhanden_vorab < self.TOPF_SCHEMA:
                    raise
                logging.getLogger("tinysesam").warning(
                    "Zähl-Töpfe von %d Konto(en) nicht nachgetragen: Die Datenbank ist nicht "
                    "schreibbar. Die Topf-Prüfung sieht sie trotzdem, nur langsamer.", len(ohne_topf))

            # Eine Datei aus der Zukunft: Diese Fassung kennt ihre Tabellen nicht vollständig
            # und würde beim Schreiben Lücken hinterlassen. Das ist kein Grund abzustürzen —
            # aber ein sehr guter, es laut zu sagen.
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
            # Schema 10: Jede Suche nach einer Kennung läuft über einen Index, keine durch die ganze
            # Tabelle. Mit einem Scan hing die Laufzeit einer Registrierung davon ab, ob (und wie
            # früh) die Adresse gefunden wird — bei vielen Konten ein Orakel für vergebene Adressen
            # (R4-03). `get_user_by_name`/`get_user_by_email` vergleichen mit NOCASE; der
            # UNIQUE-Index auf `username` (BINARY) und `ux_users_email` (`lower(email)`) passen
            # dazu nicht, SQLite las deshalb jede Zeile.
            for sql in ("CREATE INDEX IF NOT EXISTS ix_users_topf_name ON users(topf_name)",
                        "CREATE INDEX IF NOT EXISTS ix_users_topf_mail ON users(topf_mail)",
                        "CREATE INDEX IF NOT EXISTS ix_users_name_nocase ON users(username COLLATE NOCASE)",
                        "CREATE INDEX IF NOT EXISTS ix_users_email_nocase ON users(email COLLATE NOCASE)"):
                self.db.execute(sql)
            # Ein anderer Schreiber ändert Name oder Adresse, ohne den Topf mitzuführen (eine
            # ältere Fassung nach einem Rückschritt, die Umbenennung von Hand, zu der der
            # Kollisions-Wächter beim Start rät): Dann ist der Topf veraltet — und NULL heisst
            # „nachrechnen". Nur eingebaute SQL-Funktionen: Auch das sqlite3-Werkzeug und ältere
            # Fassungen müssen weiter schreiben können (eine Python-Funktion im Trigger oder im
            # Index-Ausdruck bräche jeden Schreiber ohne sie mit „no such function").
            for spalte, topf in (("username", "topf_name"), ("email", "topf_mail")):
                self.db.execute(
                    f"CREATE TRIGGER IF NOT EXISTS trg_users_{topf} AFTER UPDATE OF {spalte} ON users "
                    f"WHEN NEW.{topf} IS OLD.{topf} "
                    f"BEGIN UPDATE users SET {topf} = NULL WHERE id = NEW.id; END")
            self.db.commit()

    #: Setting-Schlüssel: bis zu welcher `audit.id` die Panel-Sperren älterer Schreiber schon
    #: nachgezogen sind (`_bestand_nachziehen`). Fehlt er, liest der nächste Start das Audit-Log
    #: einmal ganz — das ist nur langsamer, nicht falsch (jeder Schritt ist wiederholbar).
    PANEL_WASSERLINIE = "panel_sperren_bis"

    #: Wie viele Kennungen höchstens in einem `IN (…)` stehen (SQLite bis 3.32: 999 Parameter).
    IN_STUECK = 500

    @staticmethod
    def _uid_aus_detail(detail) -> Optional[int]:
        """Die Konto-ID aus dem Detail einer Panel-Zeile: `uid=<id>` oder `uid=<id> …`.

        Dieselbe Form, die die SQL-Fassung verglich (`detail = 'uid=' || id` oder
        `LIKE 'uid=' || id || ' %'`): nur ASCII-Ziffern ohne führende Null, danach Ende oder ein
        Leerzeichen. Das Panel schreibt diese Form seit 0.3.0 unverändert."""
        kopf = str(detail or "").split(" ", 1)[0]
        if not kopf.startswith("uid="):
            return None
        zahl = kopf[4:]
        if not (zahl.isascii() and zahl.isdigit()) or zahl != str(int(zahl)):
            return None
        return int(zahl)

    def _owner_nachziehen(self) -> None:
        """Gibt es Admins, aber keinen Owner (Bestand vor dem Owner-Modell), wird der älteste Admin
        Owner — bevorzugt einer, den jemand von Hand gesetzt hat (`is_admin=1`), aktiv und kein
        Service-Konto. Einmal, mit Zeile im Audit-Log. Läuft in der Migration (unter der
        Schreibsperre, direkt auf der Verbindung) — VOR der Wasserlinie der Bestandsschritte, damit
        ihre eigene Zeile nicht als „neu seit dem letzten Start" gilt. Ohne Admin bleibt es beim
        Erst-Admin-Weg, der den ersten Owner mit vergibt."""
        spalten = {r["name"] for r in self.db.execute("PRAGMA table_info(users)")}
        if "is_owner" not in spalten:
            return
        if self.db.execute("SELECT 1 FROM users WHERE is_owner=1 LIMIT 1").fetchone():
            return
        # NUR ein aktiver, von Hand gesetzter Admin (`is_admin=1`). Ein vom Identity Provider
        # vergebenes Flag (2) machte ihn sonst beim nächsten Start dauerhaft zum Owner — und damit
        # zu einem Admin, den kein Provider mehr entzieht (Angriff auf die zweite Runde, Fund 1).
        # Ein gesperrter Admin wäre ein Owner, der sich nicht anmelden kann (Fund 2).
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
        """Bestandsdaten auf Schema 10 heben (ohne Commit, unter `_lock` — Teil von `_migrate`).

        Beim Upgrade (`ab_anfang`) für den ganzen Bestand, danach bei **jedem** Start für das, was
        ein älterer Schreiber seitdem hinterlassen haben kann. Eine ältere Fassung öffnet eine
        Schema-10-Datei, warnt und schreibt weiter; den Stempel lässt sie auf 10 (Rückschritt ohne
        Sicherung). Sperrt sie in diesem Fenster im Panel, steht wieder `disabled=1` mit offenem
        Bestätigungslink da, und hinge der Schritt am Stempel, liefe er nie wieder: Der alte Link
        höbe die Sperre auf und meldete an (H-18, gemessen mit 0.19.0). Die Spur des älteren
        Schreibers ist je Schritt eine andere — Audit-Zeilen seit der Wasserlinie für die Sperren,
        Zeilen ohne Topf (`topf_name`) für die Registrierungen.

        1. **Sperren aus dem Panel bekommen den Betreiber-Vermerk** (`disabled=2`). Bis zu dieser
           Fassung schrieb die Sperre im Panel `disabled=1` — denselben Wert wie eine ausstehende
           Bestätigung, und die hebt der Bestätigungslink auf. Bis 0.19.x verwarf die Sperre
           dabei nicht einmal die offenen Token. Erkannt wird die Panel-Sperre am Audit-Log: Der
           jüngste Eintrag `user_disable`/`user_enable` mit `uid=<id>` ist `user_disable`, und das
           Konto steht auf 1 (die heutige Sperre schreibt 2, eine 1 dahinter stammt also von einem
           älteren Schreiber). Solchen Konten werden zugleich die offenen Einmal-Token verworfen —
           wie bei einer Sperre von heute. Gelesen wird **einmal der Reihe nach**, nur die Zeilen
           nach der Wasserlinie (`PANEL_WASSERLINIE`, beim Upgrade ab 0): Die erste Fassung suchte
           je gesperrtem Konto im ganzen Audit-Log (gemessen 60 s bei 1 000 000 Zeilen × 1 000
           Konten, unter der Schreibsperre — ein zweiter Worker scheiterte am `busy_timeout`).
           Grenzen: Eine Sperre, deren Zeile `audit_retention_days` schon gelöscht hat, bleibt
           unerkannt; dafür sperrt `POST <admin_path>/api/users/{id}/disable` mit
           `{"disabled": true}` erneut, ohne zu entsperren. Und in die sichere Richtung: Hebt eine
           App eine Sperre von heute ohne Audit-Zeile auf und sperrt dann selbst (1), bevor der
           Dienst neu startet, gilt das beim nächsten Start als Sperre des Betreibers.
        2. **Adressen offener Registrierungen tragen keinen Beleg** (`email_verified=0`). Die
           Registrierung legte sie mit dem Vermerk 1 an, obwohl der Link noch ausstand; seit
           dieser Fassung setzt ihn erst der eingelöste Link. Offen heisst: gesperrt, nie
           angemeldet, ein unbenutzter `verify_email`-Token und kein eingelöster. Sonst nähme
           die Löschung durch einen Admin die fremd eingetippte Adresse auch aus älteren Zeilen
           (`konto_entfernen`) — auch dann noch, wenn eine Sperre im Panel die Token verworfen
           hat, an denen das Konto sonst als offen zu erkennen ist. Nach dem Upgrade nur für
           Zeilen ohne Topf (die legt nur ein fremder Schreiber an) und für die Konten aus
           Schritt 1. Schritt 2 läuft vor Schritt 1, der genau diese Token verwirft."""
        log = logging.getLogger("tinysesam")
        # Lesen und Schreiben unter EINER Schreibsperre: Ein zweiter Worker, der gerade einen
        # Bestätigungslink einlöst, sieht die Sperre davor oder danach, nicht dazwischen. Beim
        # Upgrade hält `_migrate` die Transaktion schon (DELETE oben).
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
            ab = 0          # Zähler kleiner als die Wasserlinie (Tabelle neu angelegt): alles lesen
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
        """`topf_name`/`topf_mail` für diese Kontozeilen rechnen (ohne Commit, unter `_lock`).

        Geschrieben wird nur, wenn Name und Adresse noch die gelesenen sind: Ändert ein anderer
        Schreiber sie dazwischen, setzt sein Trigger den Topf auf NULL, und der nächste Aufruf
        rechnet neu — statt dass hier der Topf des alten Namens stehen bliebe."""
        self.db.executemany(
            "UPDATE users SET topf_name=?, topf_mail=? WHERE id=? AND username IS ? AND email IS ?",
            [(norm_kennung(z["username"]), norm_kennung(z["email"]), z["id"], z["username"], z["email"])
             for z in zeilen])

    def _toepfe_nachtragen(self) -> list:
        """Fehlende Zähl-Töpfe nachtragen — die Zeilen eines anderen Schreibers (s. `topf_name`).

        Gibt die Zeilen zurück, die sich NICHT schreiben liessen (Datenbank nur lesbar, gesperrt);
        die prüft der Aufrufer selbst. Im Normalfall ist das nichts, und es kostet eine Abfrage
        über den Index — unabhängig davon, welche Kennung gerade gesucht wird."""
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
        """Eine offene Transaktion zurückrollen (unter `_lock`) — nach einem gescheiterten Schreiben."""
        try:
            self.db.rollback()
        except sqlite3.Error:
            pass     # Verbindung geschlossen o. ä. — dann liegt auch nichts mehr offen

    @contextlib.contextmanager
    def _schreibend(self):
        """`_lock` halten, schreiben — und bei einem Fehlschlag die Transaktion VERWERFEN.

        Pythons `sqlite3` öffnet vor jedem INSERT/UPDATE/DELETE still ein `BEGIN`. Scheiterte
        der Schreibzugriff (ein fremder Schreiber hielt die Sperre länger als `busy_timeout`,
        Volume voll, Datei nur lesbar), blieb diese Transaktion auf der GETEILTEN Verbindung
        offen. Gemessen: `reserve_attempt` beginnt mit einem ausdrücklichen `BEGIN IMMEDIATE`
        und scheiterte an „cannot start a transaction within a transaction" — jede Anmeldung
        endete mit 500, bis irgendein anderer Schreibzugriff zufällig committete. Ausgelöst hat
        es schon die Schreibprobe von `/healthz`, die ohne Anmeldung erreichbar ist. Dazu kommt:
        Dieser fremde Commit nähme mit, was ein mehrteiliger Schreiber (`delete_user`) vor dem
        Fehlschlag schon geschrieben hatte.

        Jeder Schreibweg läuft deshalb hierüber (oder über `_exec`, das es auch tut); wer die
        Transaktion selbst führt (`reserve_attempt`, `rotate_session`, `_uhr_mitschreiben`, der
        innere Block von `_migrate`), setzt jeden Commit in ein `try`, dessen breites `except`
        (ohne Typ, `Exception` oder `BaseException` — `sqlite3.Error` fängt einen Bindefehler wie
        OverflowError nicht) oder `finally` zurückrollt. tests/test_hardening2.py prüft das per
        Syntaxbaum für jeden Commit in dieser Klasse — nicht bloss, ob irgendwo in der Funktion
        `rollback()` steht."""
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

    #: Setting-Schlüssel des gesicherten Uhrstands (s. `_Uhr`) und wie oft er höchstens
    #: geschrieben wird (Sekunden).
    UHR_STAND = "uhr_stand"
    UHR_SICHERN_SEK = 60

    def _uhr_stand_schreiben(self) -> None:
        """`uhr_stand` auf `jetzt()` heben — nur nach OBEN (ohne Commit, unter `_lock`).

        Schon `_migrate()` schreibt, bevor `Store()` die Uhr aus der Datenbank gehoben hat;
        dort ist `jetzt()` noch die falsche Wanduhr eines Boots mit altem Datum. Ein blindes
        Überschreiben löschte damit genau den Stand, der die Uhr gleich heben soll."""
        jetzt_s = _now()
        self.db.execute("INSERT OR IGNORE INTO setting(key, value) VALUES (?, ?)",
                        (self.UHR_STAND, str(jetzt_s)))
        self.db.execute("UPDATE setting SET value=? WHERE key=? AND CAST(value AS INTEGER) < ?",
                        (str(jetzt_s), self.UHR_STAND, jetzt_s))

    @staticmethod
    def _frisch(seit, m, frist) -> bool:
        """Liegt der monotone Stempel `seit` weniger als `frist` Sekunden vor `m`?

        Ein NEGATIVER Abstand zählt als abgelaufen, nicht als frisch: freezegun liefert
        `time.monotonic` auf der Epoch-Skala (≈1,8e9). Ein Schreibzugriff unter `freeze_time`
        hinterliess die Stempel dort, und danach war jeder Abstand negativ, also immer „kürzer als
        die Frist“ — `uhr_stand` wurde im ganzen Prozess nicht mehr gesichert, die Schreibprobe
        prüfte nur noch die Verbindung (zweite Angriffsrunde, dieselbe Klasse wie in `_Uhr.jetzt`).
        Ein Abstand über jeder Frist ist ohnehin abgelaufen."""
        return seit is not None and 0 <= m - seit < frist

    def _uhr_mitschreiben(self) -> None:
        """Den Stand der Uhr sichern — höchstens einmal je `UHR_SICHERN_SEK` (unter `_lock`).

        Ohne ihn kannte ein Neustart nur das letzte Ereignis in der Datenbank: Was danach ablief,
        galt nach einem Boot mit altem Datum wieder für seine volle Restfrist (B6-9). Eigener
        Commit NACH dem eigentlichen Schreiben: Scheitert er (Volume voll), darf das den schon
        bestätigten Schreibzugriff nicht mitreissen — der Stand ist Beiwerk."""
        m = time.monotonic()
        if self._frisch(self._uhr_gesichert, m, self.UHR_SICHERN_SEK):
            return
        try:
            self._uhr_stand_schreiben()
            self.db.commit()
            self._uhr_gesichert = m
        except Exception as fehler:
            # Zurückgerollt wird bei JEDEM Fehlschlag, geschluckt nur der Datenbankfehler (der
            # Uhrstand ist Vorsorge). Bis zur Schlussrunde fing hier `except sqlite3.Error:` —
            # ein Bindefehler wie OverflowError ist keiner und liess die Transaktion offen;
            # gerettet hat es nur das äussere `_schreibend` von `_exec`.
            self._verwerfen()
            if not isinstance(fehler, sqlite3.Error):
                raise

    # ---------- Users ----------
    def create_user(self, username, display_name=None, email=None, is_admin=False, roles=None,
                    is_service=False, email_verified=True) -> int:
        mail = norm_email(email)
        cur = self._exec(
            "INSERT INTO users(username, display_name, email, email_verified, is_admin, roles, "
            "is_service, created_at, topf_name, topf_mail) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (username, display_name or username, mail, 1 if email_verified else 0,
             1 if is_admin else 0,
             json.dumps(list(roles or [])), 1 if is_service else 0, _now(),
             norm_kennung(username), norm_kennung(mail)))
        return cur.lastrowid

    def set_email(self, user_id, email, verified: bool = False):
        """Die Adresse ersetzen — **mitsamt ihrem Beleg**, vorgabegemäss „unbestätigt".

        Der Beleg gehört zur Adresse, nicht zum Konto: Seit `users.email_verified` über
        Rechte entscheidet (`maybe_promote_admin`, Stufe 2), wäre ein stehengelassener Vermerk
        der Beleg der **alten** Adresse auf der **neuen** — gemessen wurde genau das
        (B-umgehung-8 aus T-13): `eve@example.com` (belegt) → `set_email(uid, "boss@example.com")` →
        Erst-Admin über die Allowlist, ohne dass jemand etwas bestätigt hat.

        Bis dahin stand hier, der Vermerk bleibe „fail-closed" liegen. Das galt nur für die
        eine Richtung (unbestätigt bleibt unbestätigt); die andere war fail-**open**. Die
        Vorgabe ist deshalb `verified=False`: Wer einen Beleg für die NEUE Adresse hat — eine
        eingelöste Bestätigungsmail, ein IdP-Claim aus demselben Login —, sagt das
        ausdrücklich (`set_email(uid, mail, verified=True)`) oder setzt ihn danach mit
        `set_email_verified`. Adresse und Beleg gehen in EINER Anweisung in die Datenbank,
        damit zwischen beiden kein Zustand liegt, in dem die neue Adresse den alten Beleg
        trägt. Der Zähl-Topf der Adresse (`topf_mail`) geht in derselben Anweisung mit."""
        mail = norm_email(email)
        self._exec("UPDATE users SET email=?, email_verified=?, topf_mail=? WHERE id=?",
                   (mail, 1 if verified else 0, norm_kennung(mail), user_id))

    def set_email_verified(self, user_id, verified: bool):
        """Den Beleg für die Adresse vermerken (`users.email_verified`).

        Getrennt von der Adresse, weil beides getrennt bekannt ist: Ein IdP schickt `email` in
        jedem Login, den Claim `email_verified` aber nur manchmal. Und der Vermerk muss liegen
        bleiben, denn über ihn entscheidet auch ein Login, der selbst keinen Beleg mitbringt
        (lokales Passwort, Magic-Link) — sonst hinge der Schutz am Anmeldeweg."""
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
        # Auch die Form von vor R4-06 (nur getrimmt und klein) suchen: Eine gespeicherte Adresse
        # mit Umlaut-Domain steht im Bestand noch in Unicode-Form und würde sonst nicht gefunden.
        # Und zwar in BEIDE Richtungen (Angriff A5): Die Unicode-Form wird auch aus der A-Label-
        # Eingabe zurückgewonnen — sonst fand `user@xn--bcher-kva.example` den Bestand
        # `user@bücher.example` nicht, und die Registrierung legte ein zweites Konto für dasselbe
        # Postfach an.
        alt = str(email or "").strip().lower()
        unicode_form = _email_unicode(kanonisch)
        return self._one("SELECT * FROM users WHERE email COLLATE NOCASE IN (?, ?, ?) ORDER BY id LIMIT 1",
                         (kanonisch, alt, unicode_form))

    def konto_entfernen(self, user_id, adresse_unbefristet: bool = False) -> Optional[tuple[str, int]]:
        """Ein Konto löschen — der EINE Löschweg, über den jeder Aufrufer geht (H-13).

        Konto samt Zugangsdaten und Sitzungen, die Anmeldeversuche unter Name und Adresse, und
        im Audit-Log wird aus dem Namen `gelöscht#<id>` (`audit_anonymisieren`). Ein gelöschtes
        Konto, dessen Name weiter in jeder Zeile steht, ist nicht gelöscht.

        Warum hier und nicht im Manager: Bis zur T-13-Integration gab es vier Löschwege mit zwei
        verschiedenen Zusagen. `TinySesam.delete_user` anonymisierte, `gc()`, `tinysesam gc` (das
        direkt auf dem Store arbeitet) und die Rücknahme bei gescheitertem Bestätigungsversand
        riefen `delete_user` und liessen Name, fremde IP und die Adresse des Opfers stehen — ein
        späterer Namensvetter sah die Registrierung des Fremden als eigenes Ereignis
        (Integrationsfunde 12/18). Der Store ist die tiefste Stelle, die alle Wege teilen.

        **Nur was ab der Anlage des Kontos entstand** (`anlage_grenze` — dieselbe Grenze wie
        `TinySesam.own_events`). Seit `gc()` und die B6-5-Rücknahme hier durchgehen, löst diesen
        Weg auch ein Fremder ohne Konto aus: registrieren, nie bestätigen. Ohne Grenze schrieb
        er dabei Zeilen um, die VOR seinem Konto entstanden und anderen gehören — die Einladung
        des Admins mit der Adresse im Detail, den Fehlversuch eines Sprayers unter dem damals
        freien Namen, den der echten Adressinhaberin —, und deren Versuchszeilen verschwanden
        aus der Drosselung je IP. Ein Name oder eine eingetippte Adresse gehörte vor der Anlage
        niemandem oder jemand anderem. Anmeldeversuche aus der Sekunde der Anlage bleiben
        stehen: Ob sie davor oder danach kamen, lässt sich nicht entscheiden, und Stehenlassen
        ist hier die sichere Richtung (sie verfallen mit dem Sperrfenster).

        `adresse_unbefristet=True` nimmt eine **belegte** Adresse davon aus (`adresse_belegt`):
        Sie gehört nachweislich dem Konto und wird auch in älteren Zeilen ersetzt (die
        Einladung, die zu dem Konto führte). Das ist die bewusste Löschung durch einen Admin
        (`TinySesam.delete_user`, H-13) — kein Weg, den ein Anonymer auslöst. `gc()`, die
        Rücknahme und `purge_demo` räumen Konten ab, die nie jemandem gehörten; dort gilt die
        Grenze auch für die Adresse. Und auch bei der Löschung durch einen Admin nur für eine
        BELEGTE Adresse: Die eines offenen Kontos (Registrierung, Link nie eingelöst) oder
        einer Registrierung ohne Bestätigungspflicht hat ein Fremder eingetippt — ohne diese
        Unterscheidung schrieb das Aufräumen solcher Konten im Panel die Einladung des Admins
        und die Fehlversuche der echten Inhaberin von VOR der Anlage auf `gelöscht#<id>` um.

        Die Anmeldeversuche eines Zähl-Topfs (`norm_kennung`), den ein VERBLEIBENDES Konto
        teilt, bleiben stehen (s. `delete_attempts_for`).

        Gibt `(ersatzname, anonymisierte Zeilen)` zurück — unter dem Ersatznamen schreibt der
        Aufrufer seine eigene Zeile (`user_delete`, `signup_expired`, `verify_send_error`) —,
        None, wenn es das Konto nicht gibt."""
        u = self.get_user(user_id)
        if u is None:
            return None
        name, mail = str(u["username"]), (u["email"] or "")
        seit, seit_id = self.anlage_grenze(u)
        unbefristet = (mail,) if (adresse_unbefristet and self.adresse_belegt(u)) else ()
        self.delete_user(user_id)
        self.delete_attempts_for(name, (mail,), nach=seit, unbefristet=unbefristet)
        ersatz = ersatzname(user_id)
        return ersatz, self.audit_anonymisieren(name, ersatz, (mail,), seit=seit, seit_id=seit_id,
                                                unbefristet=unbefristet)

    def adresse_belegt(self, user) -> bool:
        """Gehört die Adresse dieses Kontos nachweislich ihm? (`konto_entfernen`, H-13)

        Der Vermerk `email_verified` UND keine ausstehende Bestätigung: Ein offenes Konto —
        gesperrt, ein unbenutzter `verify_email`-Token und kein eingelöster — trägt eine Adresse,
        die jemand eingetippt und nie bestätigt hat. Die Registrierung legt sie seit Schema 10
        ohne Vermerk an (den setzt erst der eingelöste Link), und `_migrate` holt das für
        offene Registrierungen aus dem Bestand nach. Die Token-Prüfung hier fängt zusätzlich
        eine App, die `create_user` mit der Vorgabe `email_verified=True` ruft und danach selbst
        einen Bestätigungslink verschickt."""
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
        """Ab wo gehört eine Audit-Zeile zu diesem Konto? `(seit, seit_id)`.

        `seit` ist `created_at` (Unix-Sekunden). Aus der Sekunde der Anlage selbst zählen nur
        Zeilen ab `seit_id`: der Registrierungszeile des Kontos (`signup`, beim Platzhalter
        `signup_taken`), die direkt nach dem Anlegen geschrieben wird. Ohne sie wäre die Grenze
        nur sekundengenau — und ein Fremder, der sich in derselben Sekunde registriert, in der
        der Admin die Adresse einlädt oder ein Sprayer den freien Namen probiert, bekäme deren
        Zeilen zugeschrieben. Genau diese Wege (Registrierung, `gc()`, B6-5) haben die Zeile
        immer; ein Konto ohne sie (Admin-API, SSO, Demo) fällt auf `seit_id = 0` zurück — dann
        zählt die ganze Sekunde.

        Gesucht wird die Zeile nur in der Sekunde der Anlage und der nächsten (das Passwort wird
        NACH dem Anlegen gehasht, die Zeile kann eine Sekunde später stehen). Eine
        `signup_taken`-Zeile zählt nur, wenn sie die Anlage eines **Platzhalters** war: Der
        Platzhalter trägt keine Adresse, und seine Zeile nennt im Detail die Adresse, die nicht
        sein Name ist. Die andere `signup_taken`-Zeile — jemand registriert sich mit einer
        Adresse, die schon einem Konto als Benutzername gehört (Name = Adresse), und dabei
        entsteht kein Konto — steht unter genau diesem Namen, auch in derselben oder der
        nächsten Sekunde. Sie ist nicht die Anlage und verschiebt nichts; als Anker genommen,
        fiele die `user_create`-Zeile des Admins aus der Anonymisierung.

        Filter für SQL: `ts > seit OR (ts = seit AND id >= seit_id)`."""
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
        """Das erste Konto, dessen Name oder Adresse in denselben Zähl-Topf fällt wie `kennung`.

        Der Topf ist `norm_kennung` (Python-`lower()`), die Namensprüfung der Datenbank dagegen
        `COLLATE NOCASE` — und das faltet nur ASCII. `Émile` und `émile` sind für SQLite zwei
        Namen, für den Sperrzähler einer. Deshalb führt jedes Konto seinen Topf als Spalte
        (`topf_name`/`topf_mail`, gerechnet in Python), und gesucht wird über deren Index.

        Bis Schema 10 lief die Suche als Schleife über ALLE Konten in Python — bei jeder
        Registrierung, und bei der mit einer freien Adresse zweimal öfter als bei der mit einer
        vergebenen: Ab einigen tausend Konten verriet die Antwortzeit einer einzigen Anfrage,
        ob eine Adresse ein Konto hat (R4-03), und `gc()` wuchs mit offenen × allen Konten.
        Die Arbeit hier hängt jetzt weder von der Zahl der Konten ab noch davon, ob und wo die
        Kennung gefunden wird (tests/test_audit_runde2.py zählt die SQLite-Schritte).
        `ausser` lässt ein Konto aus (die ID, um die es gerade geht)."""
        topf = norm_kennung(kennung)
        if not topf:
            return None
        # Zeilen, deren Topf sich nicht nachtragen liess (Datenbank nur lesbar), prüft Python —
        # im Normalfall keine.
        treffer = [z for z in self._toepfe_nachtragen()
                   if z["id"] != ausser and topf in (norm_kennung(z["username"]), norm_kennung(z["email"]))]
        z = self._one("SELECT * FROM users WHERE (topf_name = ? OR topf_mail = ?) AND id IS NOT ? "
                      "ORDER BY id LIMIT 1", (topf, topf, ausser))
        if z is not None:
            treffer.append(z)
        return min(treffer, key=lambda t: t["id"]) if treffer else None

    def delete_user(self, user_id):
        """Die Zeilen eines Kontos entfernen — Rohbaustein, nur für `konto_entfernen`.

        Wer ein Konto löscht, ruft `konto_entfernen` (oder `TinySesam.delete_user`): Hier bleibt
        der Name im Audit-Log stehen, und die Anmeldeversuche bleiben liegen. Ein Test hält fest,
        dass es keinen weiteren Aufrufer gibt."""
        with self._schreibend():
            for table in ("api_key", "password_cred", "pin_cred", "totp_cred", "recovery_code",
                          "webauthn_cred", "oidc_identity", "federated_identity", "session",
                          "magic_token"):
                self.db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
            self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
            self.db.commit()

    def email_taken(self, email, exclude_id=None) -> bool:
        u = self.get_user_by_email(email)
        return bool(u and u["id"] != exclude_id)

    def kennungs_kollisionen(self, limit: int = 50) -> list:
        """Konten, deren **Benutzername** die **E-Mail** eines ANDEREN Kontos ist (Fund R4-12).

        Warum das eine eigene Abfrage braucht: Die Tabelle kennt `UNIQUE(username)` und den
        Index `ux_users_email` auf `lower(email)` — aber **keinen Constraint über beide
        Spalten**. Eindeutig ist also jeder Namensraum für sich, während `find_user` im
        Vorgabe-Modus `both` in beiden sucht. `Manager.create_user` prüft kreuzweise, doch
        Prüfung und INSERT sind nicht atomar (zwei gleichzeitige Registrierungen derselben
        Kennung — eine als Name, eine als Adresse — kommen beide durch), und in einer Datenbank
        von VOR dem Fix steht die Kollision längst. Diese Abfrage ist deshalb der Wächter, den
        die Datenbank nicht stellen kann: Sie nennt, was da ist, statt es zu verhindern.

        Verglichen wird `COLLATE NOCASE`, also genauso wie `get_user_by_name`/`get_user_by_email`
        suchen — eine Kollision, die die Anmeldung findet, muss auch hier auffallen.
        Zeilen: `(name_id, kennung, mail_id, adresse)`. Ein Konto, das dieselbe Zeichenfolge in
        BEIDEN eigenen Spalten trägt, ist keine Kollision (E-Mail-Modus, vorgesehener Weg).
        """
        return self._all(
            "SELECT n.id AS name_id, n.username AS kennung, e.id AS mail_id, e.email AS adresse "
            "FROM users n JOIN users e ON e.id <> n.id "
            "  AND e.email IS NOT NULL AND e.email <> '' "
            "  AND e.email = n.username COLLATE NOCASE "
            "ORDER BY n.id LIMIT ?", (int(limit),))

    def list_users(self):
        return self._all("SELECT * FROM users ORDER BY username")

    #: Werte von `users.disabled` neben 0 (aktiv): die Sperre einer ausstehenden Bestätigung und
    #: die Sperre durch den Betreiber. Getrennt, weil `/auth/verify/…` die eine aufhebt und die
    #: andere nie (H-18, zweite Angriffsrunde): Entstand der Bestätigungstoken erst NACH einer
    #: Sperre durch den Betreiber — etwa im Postausgang einer einbettenden App, die
    #: `send_verify_email` dorthin schiebt —, fand die Sperre nichts zu verwerfen, und der Link
    #: setzte `disabled` danach bedingungslos auf 0.
    GESPERRT_BESTAETIGUNG = 1
    GESPERRT_BETREIBER = 2

    def set_disabled(self, user_id, disabled: bool, durch_betreiber: bool = False):
        """Konto sperren oder entsperren.

        `durch_betreiber=True` ist die Sperre des Betreibers (Admin-Panel): Kein Bestätigungslink
        hebt sie auf, nur ein ausdrückliches `set_disabled(uid, False)`. Ohne den Vermerk ist es
        die Sperre einer ausstehenden Bestätigung, die `bestaetigung_freischalten` aufhebt — und
        die stuft eine schon bestehende Sperre des Betreibers nicht herab.

        Sperren aus Fassungen vor dieser Unterscheidung tragen 1 — und bis 0.19.x verwarf die
        Sperre im Panel die offenen Einmal-Token nicht, ein ausstehender Bestätigungslink hätte
        sie nach dem Upgrade also aufgehoben. Die Migration auf Schema 10 (`_bestand_nachziehen`)
        hebt deshalb jede Sperre, die das Audit-Log als Panel-Sperre kennt, auf 2 und verwirft
        dabei die offenen Token. Eine Sperre, deren Zeile schon gelöscht ist
        (`audit_retention_days`), bleibt 1; `POST <admin_path>/api/users/{id}/disable` mit
        `{"disabled": true}` setzt den Vermerk, ohne dazwischen zu entsperren."""
        if disabled:
            # Ein Owner lässt sich nicht sperren — auch nicht über den Code-Weg (Owner-Modell). Sonst
            # zählte `owner_count` einen Owner, der sich nicht anmelden kann.
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
        """Die Sperre einer ausstehenden Bestätigung aufheben — nie die des Betreibers.

        True, wenn das Konto danach aktiv ist (auch: es war gar nicht gesperrt). False, wenn
        eine Sperre bleibt; dann hat der Betreiber gesperrt, und nur er hebt es wieder auf."""
        self._exec("UPDATE users SET disabled=0 WHERE id=? AND disabled=?",
                   (user_id, self.GESPERRT_BESTAETIGUNG))
        zeile = self._one("SELECT disabled FROM users WHERE id=?", (user_id,))
        return bool(zeile) and not zeile["disabled"]

    def set_admin(self, user_id, is_admin: bool):
        self._exec("UPDATE users SET is_admin=? WHERE id=?", (1 if is_admin else 0, user_id))

    def set_owner(self, user_id, owner: bool):
        """Owner-Kennzeichen setzen. Ein Owner ist immer Admin — und zwar von Hand (1): Kein Identity
        Provider nimmt einem Owner das Admin-Recht (H-5 entzieht nur die 2). Die Regeln (mindestens
        einer, nur Owner vergeben) prüft der Manager."""
        if owner:
            self._exec("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (user_id,))
        else:
            self._exec("UPDATE users SET is_owner=0 WHERE id=?", (user_id,))

    def owner_count(self, ohne=None) -> int:
        """Wie viele Owner gibt es (ohne das Konto `ohne`)?"""
        zeile = self._one("SELECT COUNT(*) AS n FROM users WHERE is_owner=1 AND id <> ?",
                          (int(ohne) if ohne is not None else -1,))
        return int(zeile["n"])

    def set_admin_vom_idp(self, user_id):
        """Admin-Flag mit dem Vermerk „vom Identity Provider vergeben" (`is_admin=2`, H-5).

        Nur dieser Wert darf beim nächsten Login wieder entzogen werden, wenn der Provider die
        Gruppe nicht mehr liefert. Eine 1 (Panel, CLI, `admin_identifiers`, `/auth/claim-admin`)
        rührt kein Provider an. Überall sonst gilt das Flag als Wahrheitswert — 2 ist Admin wie 1."""
        self._exec("UPDATE users SET is_admin=2 WHERE id=? AND is_admin=0", (user_id,))

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
    #: Ver-/Entschlüsselung der TOTP-Geheimnisse (H-14/H-15, `geheimnis.Tresor`). Setzt der Manager;
    #: ein Store ohne Tresor (CLI-Werkzeuge) fasst die Geheimnisse nicht an.
    tresor: Any = None

    def set_totp(self, user_id, secret, confirmed=False):
        # `last_step` gehört zum Geheimnis: Ein neues beginnt ohne verbrauchten Schritt. Sonst
        # sperrte der Bestätigungscode eines verworfenen Versuchs den ersten Code des neuen,
        # wenn beide in dasselbe 30-Sekunden-Fenster fallen.
        if self.tresor is None:
            raise RuntimeError("TOTP-Geheimnisse werden nur verschlüsselt abgelegt — der Store hat "
                               "keinen Schlüssel (geheimnis.Tresor).")
        self._exec("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?,?,?,?) "
                   "ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, "
                   "confirmed=excluded.confirmed, last_step=NULL",
                   (user_id, self.tresor.verschluesseln(secret), 1 if confirmed else 0, _now()))

    def confirm_totp(self, user_id):
        self._exec("UPDATE totp_cred SET confirmed=1 WHERE user_id=?", (user_id,))

    def get_totp(self, user_id) -> Optional[dict]:
        """Die TOTP-Zeile eines Kontos, das Geheimnis entschlüsselt (`secret`)."""
        zeile = self._one("SELECT * FROM totp_cred WHERE user_id=?", (user_id,))
        if zeile is None:
            return None
        d = dict(zeile)
        if self.tresor is not None:
            d["secret"] = self.tresor.entschluesseln(d["secret"])
        return d

    def geheimnisse_heben(self) -> int:
        """Klartext-Geheimnisse aus der Zeit vor der Verschlüsselung verschlüsseln (stilles Heben)
        — und vorher prüfen, dass der Schlüssel zu den schon verschlüsselten passt. Passt er nicht,
        `ConfigError`: Ein Start mit falschem Schlüssel liesse sonst jede TOTP-Anmeldung still
        scheitern. Gibt zurück, wie viele gehoben wurden."""
        from .errors import ConfigError
        if self.tresor is None:
            return 0
        # Beide Tabellen mit Verschlüsseltem: Gibt es nur Refresh-Tokens (OIDC-Instanz ohne TOTP),
        # startete ein falscher Schlüssel sonst — und jede Anfrage mit altem Cookie lief auf 500.
        probe = self._one("SELECT secret AS wert FROM totp_cred WHERE secret LIKE 'v1:%' "
                          "UNION ALL SELECT refresh FROM oidc_sitzung WHERE refresh LIKE 'v1:%' LIMIT 1")
        if probe is not None:
            try:
                self.tresor.entschluesseln(probe["wert"])
            except Exception:
                raise ConfigError(
                    "Der Schlüssel passt nicht zu den gespeicherten Geheimnissen (TOTP/OIDC; falsche "
                    "TINYSESAM_SECRETS_KEY/secrets_key_file, oder die Schlüsseldatei neben der "
                    "Datenbank fehlt bzw. ist eine andere). Den richtigen Schlüssel einsetzen — ohne ihn "
                    "müssen alle Konten TOTP neu einrichten.") from None
        klar = self._all("SELECT user_id, secret FROM totp_cred WHERE secret NOT LIKE 'v1:%'")
        for z in klar:
            self._exec("UPDATE totp_cred SET secret=? WHERE user_id=? AND secret=?",
                       (self.tresor.verschluesseln(z["secret"]), z["user_id"], z["secret"]))
        if klar:
            logging.getLogger("tinysesam").info(
                "%d TOTP-Geheimnis(se) verschlüsselt (bisher Klartext in der Datenbank).", len(klar))
        return len(klar)

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
        with self._schreibend():
            self.db.executemany("INSERT INTO recovery_code(user_id, code_hash, created_at) VALUES (?,?,?)",
                                [(user_id, h, now) for h in hashes])
            self.db.commit()

    def consume_recovery_code(self, user_id, code_hash) -> bool:
        """Einen ungenutzten Code atomar entwerten. True nur beim ersten gültigen Einlösen."""
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

    # ---------- OIDC-Link ----------
    def link_oidc(self, issuer, subject, user_id):
        self._exec("INSERT OR REPLACE INTO oidc_identity(issuer, subject, user_id) VALUES (?,?,?)",
                   (issuer, subject, user_id))

    # ---------- Erst-Login und Enrollment-Fenster (R3-1) ----------
    def mark_first_login(self, user_id: int, jetzt: int) -> bool:
        """Den ersten vollständigen Login festhalten — nur beim ersten Mal (idempotent).

        Rückgabe: True, wenn dieser Aufruf ihn gesetzt hat. Die Bedingung steht im SQL, nicht
        davor: Zwei gleichzeitige Anmeldungen desselben Kontos (zwei Geräte, zwei Worker)
        würden sonst beide lesen, beide schreiben, und der Zeitpunkt wäre der spätere."""
        return self._exec("UPDATE users SET first_login_at=? WHERE id=? AND first_login_at IS NULL",
                          (jetzt, user_id)).rowcount > 0

    def set_mfa_enroll_until(self, user_id: int, bis: Optional[int]) -> None:
        """Das Einrichtungsfenster öffnen (Zeitstempel) oder schliessen (None)."""
        self._exec("UPDATE users SET mfa_enroll_until=? WHERE id=?", (bis, user_id))

    def ist_oidc_konto(self, user_id) -> bool:
        """Ist dieses Konto an eine OIDC-Identität gebunden (Fund 8)?"""
        return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? LIMIT 1", (user_id,)))

    def idp_bestaetigen(self, user_id) -> None:
        """Der Provider hat das Konto eben bestätigt (Login über ihn, Refresh-Tausch mit Ja)."""
        self._exec("UPDATE users SET idp_bestaetigt_at=? WHERE id=?", (_now(), user_id))

    def idp_verweigert(self, user_id) -> None:
        """Der Provider hat Nein gesagt: Die API-Keys des Kontos ruhen bis zur nächsten
        Bestätigung (Fund 8). 0 statt NULL — NULL heisst „nie bestätigt", 0 heisst „verweigert"."""
        self._exec("UPDATE users SET idp_bestaetigt_at=0 WHERE id=?", (user_id,))

    def get_oidc_user(self, issuer, subject) -> Optional[int]:
        r = self._one("SELECT user_id FROM oidc_identity WHERE issuer=? AND subject=?", (issuer, subject))
        return r["user_id"] if r else None

    # ---------- Föderierte Identitäten über eine stabile Kennung (F-11) ----------
    def link_federated(self, quelle: str, kennung: str, user_id: int, jetzt: int) -> None:
        """Eine fremde Identität an ein lokales Konto binden (oder die Bindung erneuern)."""
        self._exec("INSERT OR REPLACE INTO federated_identity(quelle, kennung, user_id, gebunden_at)"
                   " VALUES (?,?,?,?)", (quelle, kennung, user_id, jetzt))

    def get_federated_user(self, quelle: str, kennung: str) -> Optional[int]:
        r = self._one("SELECT user_id FROM federated_identity WHERE quelle=? AND kennung=?",
                      (quelle, kennung))
        return r["user_id"] if r else None

    def get_federated_kennung(self, quelle: str, user_id: int) -> Optional[str]:
        """Die Kennung, mit der dieses Konto für diese Quelle gebunden ist — None, wenn keine.

        Der Rückweg ist der eigentliche Riegel: Trägt ein Konto schon eine Kennung, darf es
        **nicht** an eine zweite gebunden werden. Genau das wäre der Fall, wenn im Verzeichnis
        ein gelöschtes Konto unter demselben Namen neu entsteht."""
        r = self._one("SELECT kennung FROM federated_identity WHERE quelle=? AND user_id=?",
                      (quelle, user_id))
        return r["kennung"] if r else None

    def has_foreign_identity(self, user_id: int) -> bool:
        """Ist dieses Konto an irgendeine fremde Identität gebunden (OIDC, LDAP, SAML)?"""
        return bool(self._one("SELECT 1 FROM oidc_identity WHERE user_id=? "
                              "UNION ALL SELECT 1 FROM federated_identity WHERE user_id=? LIMIT 1",
                              (user_id, user_id)))

    def unlink_federated(self, quelle: str, user_id: int) -> int:
        """Die Bindung eines Kontos für eine Quelle lösen (Betreiber-Weg nach einem Umzug)."""
        return self._exec("DELETE FROM federated_identity WHERE quelle=? AND user_id=?",
                          (quelle, user_id)).rowcount

    # ---------- Freigaben je Anwendung (T-14) ----------
    # Der Schlüssel ist der **Hash** der Sitzung, nicht der Klartext — dieselbe Regel wie in
    # `session`: Wer die Datei liest, bekommt damit keine übernehmbare Sitzung.
    def set_oidc_sitzung(self, handle, client, sub, refresh) -> None:
        """Das Refresh-Token einer OIDC-Sitzung für DIESEN Client ablegen — verschlüsselt (4a).

        Je Client eine Zeile: Mit mehreren Anwendungen darf ein späterer Login über einen anderen
        Client die Nachprüfung des ersten nicht überschreiben — sonst suchte der Nutzer selbst aus,
        welcher Provider-Eintrag noch nachgeprüft wird (Angriff auf die zweite Runde, Fund 7)."""
        if self.tresor is None:
            raise RuntimeError("Refresh-Tokens werden nur verschlüsselt abgelegt (geheimnis.Tresor).")
        self._exec("INSERT INTO oidc_sitzung(token_hash, client, sub, refresh, geprueft_at) VALUES (?,?,?,?,?) "
                   "ON CONFLICT(token_hash, client) DO UPDATE SET sub=excluded.sub, "
                   "refresh=excluded.refresh, geprueft_at=excluded.geprueft_at",
                   (self._handle(handle), client, sub, self.tresor.verschluesseln(refresh), _now()))

    def get_oidc_sitzungen(self, handle) -> list:
        """Die OIDC-Zeilen einer Sitzung — das Refresh-Token VERSCHLÜSSELT (entschlüsselt wird
        erst, wenn getauscht wird; eine Anfrage vor Ablauf der Frist fasst den Schlüssel nicht an)."""
        return [dict(z) for z in self._all("SELECT * FROM oidc_sitzung WHERE token_hash=?",
                                          (self._handle(handle),))]

    def get_oidc_sitzung(self, handle, client="*") -> Optional[dict]:
        """Eine OIDC-Zeile, das Refresh-Token entschlüsselt, oder None (für Werkzeuge und Tests)."""
        z = self._one("SELECT * FROM oidc_sitzung WHERE token_hash=? AND client=?", (self._handle(handle), client))
        if z is None:
            return None
        d = dict(z)
        if self.tresor is not None:
            d["refresh"] = self.tresor.entschluesseln(d["refresh"])
        return d

    def oidc_sitzung_beanspruchen(self, handle, client, alt: int, jetzt: int) -> bool:
        """Den fälligen Tausch für GENAU eine Anfrage beanspruchen: `geprueft_at` von `alt` auf
        `jetzt`, nur wenn es noch `alt` ist. Mehrere gleichzeitige Anfragen (auch über Worker) —
        nur eine tauscht. Sonst tauschten alle dasselbe Refresh-Token, und ein Provider mit
        Token-Rotation lehnte den zweiten Tausch ab: Die Sitzung endete ohne Grund (Fund 5)."""
        return self._exec("UPDATE oidc_sitzung SET geprueft_at=? WHERE token_hash=? AND client=? "
                          "AND geprueft_at=?", (int(jetzt), self._handle(handle), client, int(alt))).rowcount == 1

    def oidc_sitzung_geprueft(self, handle, client, zeit: int, neuer_refresh=None) -> None:
        """Den Tausch vermerken; ein neu ausgegebenes Refresh-Token ersetzt das alte (Rotation)."""
        if neuer_refresh and self.tresor is not None:
            self._exec("UPDATE oidc_sitzung SET geprueft_at=?, refresh=? WHERE token_hash=? AND client=?",
                       (int(zeit), self.tresor.verschluesseln(neuer_refresh), self._handle(handle), client))
        else:
            self._exec("UPDATE oidc_sitzung SET geprueft_at=? WHERE token_hash=? AND client=?",
                       (int(zeit), self._handle(handle), client))

    def oidc_sitzung_umhaengen(self, alt, neu) -> None:
        """Die OIDC-Zeilen an eine neue Sitzung hängen (neues Token beim Abschluss der Kette) —
        VOR dem Löschen der alten, sonst nähme der Fremdschlüssel sie mit."""
        self._exec("UPDATE oidc_sitzung SET token_hash=? WHERE token_hash=?",
                   (self._handle(neu), self._handle(alt)))

    def put_oidc_grant(self, token_hash: str, client: str, jetzt: int, roles=None) -> None:
        """Freigabe eintragen oder bestätigen. `granted_at` bleibt bei einer Bestätigung stehen —
        die Frage „seit wann darf diese Sitzung in diese Anwendung" beantwortet sonst niemand mehr."""
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
        """Eine Freigabe entziehen. Genau eine — die Sitzung und die übrigen Anwendungen bleiben;
        das ist der Unterschied zwischen „der Provider sagt Nein zu dieser App" und „abmelden"."""
        return self._exec("DELETE FROM oidc_grant WHERE token_hash=? AND client=?",
                          (token_hash, client)).rowcount

    def drop_oidc_grants_for_user(self, user_id: int, client: Optional[str] = None) -> int:
        """Alle Freigaben eines Kontos entziehen (optional nur für eine Anwendung). Der Weg für
        den Betreiber, wenn der Provider jemanden ausgeschlossen hat und es sofort wirken soll,
        ohne die Sitzung selbst zu beenden."""
        if client is None:
            return self._exec(
                "DELETE FROM oidc_grant WHERE token_hash IN (SELECT token_hash FROM session WHERE user_id=?)",
                (user_id,)).rowcount
        return self._exec(
            "DELETE FROM oidc_grant WHERE client=? AND token_hash IN"
            " (SELECT token_hash FROM session WHERE user_id=?)", (client, user_id)).rowcount

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
                   "method, factors_done, remember, ip, user_agent, zuletzt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (self.session_hash(token), user_id, now, now + ttl_seconds, 1 if mfa_ok else 0,
                    (now if mfa_ok else None), method, json.dumps(list(factors or [])),
                    1 if remember else 0, ip, ua, now))
        return token

    #: Inaktivitäts-Grenzen in Sekunden (ohne / mit „Angemeldet bleiben"), 0 = aus. Setzt der
    #: Manager aus der Konfiguration (F-05); der Store allein kennt keine.
    leerlauf_sek = (0, 0)
    #: Wie oft `zuletzt` höchstens geschrieben wird: Jede Anfrage schreiben hiesse, dass jeder
    #: Forward-Auth-Abruf die Datei sperrt. Eine Minute Unschärfe ist für Stunden-Grenzen nichts.
    LEERLAUF_SCHRITT_SEK = 60

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
        if not r:
            return None
        jetzt = _now()
        if r["expires_at"] < jetzt:
            self.delete_session(token)
            return None
        # Inaktivität (F-05): zusätzlich zur absoluten Laufzeit. Eine abgelaufene Sitzung wird
        # gelöscht, nicht nur abgewiesen — sonst lebte sie mit dem nächsten Zugriff wieder auf.
        # Die lange Grenze nur, wenn jemand „Angemeldet bleiben" AUSDRÜCKLICH gewählt hat. Eine
        # Sitzung, die nur deshalb dauerhaft ist, weil der Weg keine Wahl kennt (OIDC, Passkey,
        # Anmelde-Link) oder die Checkbox abgeschaltet ist, bekäme sonst nie ein Leerlauf-Ende
        # (Angriff auf die zweite Runde, Fund 9).
        grenze = self.leerlauf_sek[1 if (r["remember"] and r["bleiben_gewaehlt"]) else 0]
        zuletzt = r["zuletzt"] if r["zuletzt"] is not None else r["created_at"]
        if grenze and jetzt - int(zuletzt) > grenze:
            self.delete_session(token)
            return None
        if jetzt - int(zuletzt) >= self.LEERLAUF_SCHRITT_SEK:
            self._exec("UPDATE session SET zuletzt=? WHERE token_hash=?", (jetzt, r["token_hash"]))
        return r

    def set_session_bleiben(self, handle):
        """Vermerken: „Angemeldet bleiben" wurde ausdrücklich gewählt (F-05)."""
        self._exec("UPDATE session SET bleiben_gewaehlt=1 WHERE token_hash=?", (self._handle(handle),))

    def set_session_andere_beenden(self, handle):
        """Vermerken: Wird diese (halbe) Sitzung voll, enden die übrigen des Kontos (Grenze d)."""
        self._exec("UPDATE session SET andere_beenden=1 WHERE token_hash=?", (self._handle(handle),))

    def set_session_mfa(self, handle, ok=True):
        self._exec("UPDATE session SET mfa_ok=?, mfa_at=? WHERE token_hash=?",
                   (1 if ok else 0, (_now() if ok else None), self._handle(handle)))

    def delete_session(self, token):
        """Klartext-Token (aus dem Cookie) — für Logout."""
        self._exec("DELETE FROM session WHERE token_hash=?", (self.session_hash(token),))

    def delete_session_by_handle(self, handle):
        """Handle aus einer Sitzungs-Zeile — für Admin-Panel und „andere Sitzungen beenden"."""
        self._exec("DELETE FROM session WHERE token_hash=?", (self._handle(handle),))

    def rotate_session(self, handle) -> Optional[str]:
        """Der Sitzung ein neues Token geben, ohne sonst etwas an ihr zu ändern (F-06).

        Laufzeit, Faktoren und `created_at` bleiben — ein Step-up soll das Token erneuern, nicht
        die absolute Lebensdauer verlängern. Die OIDC-Freigaben hängen per Fremdschlüssel am
        Handle und ziehen mit um; darum neue Zeile, Freigaben umhängen, alte Zeile löschen, alles
        in einer Transaktion. Gibt das neue Klartext-Token zurück, oder None, wenn es die
        Sitzung nicht (mehr) gibt."""
        alt = self._handle(handle)
        token = secrets.token_urlsafe(32)
        neu = self.session_hash(token)
        spalten = ("user_id, created_at, expires_at, mfa_ok, mfa_at, method, factors_done, "
                   "remember, ip, user_agent, zuletzt, bleiben_gewaehlt")
        with self._lock:
            try:
                cur = self.db.execute(
                    f"INSERT INTO session(token_hash, {spalten}) SELECT ?, {spalten} FROM session "
                    "WHERE token_hash=?", (neu, alt))
                if cur.rowcount != 1:
                    self.db.rollback()
                    return None
                self.db.execute("UPDATE oidc_grant SET token_hash=? WHERE token_hash=?", (neu, alt))
                self.db.execute("UPDATE oidc_sitzung SET token_hash=? WHERE token_hash=?", (neu, alt))
                self.db.execute("DELETE FROM session WHERE token_hash=?", (alt,))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
        return token

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
        if not os.path.exists(ziel):
            try:
                os.close(os.open(ziel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, cls.DATEIRECHTE))
            except OSError:
                pass  # inzwischen angelegt oder nicht anlegbar — die Rechte setzt der chmod unten
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
                pass  # Rechte nicht setzbar (fremdes Dateisystem) — die Kopie selbst ist vollständig
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
        if not os.path.exists(ziel):
            try:
                os.close(os.open(ziel, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.DATEIRECHTE))
            except OSError:
                pass  # inzwischen angelegt oder nicht anlegbar — die Rechte setzt der chmod unten
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
                pass  # Rechte nicht setzbar (fremdes Dateisystem) — die Kopie selbst ist vollständig
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
        """Flow-State genau EINMAL herausgeben (WebAuthn-Challenge, OIDC-`state`/`nonce`).

        Lesen und Löschen waren zwei getrennte Schritte, jeder mit eigenem Lock (R3-8): Zwei
        gleichzeitige Callbacks mit demselben `state` — zwei Threads, oder zwei Worker auf
        derselben Datei — lasen beide die Zeile, bevor einer sie löschte, und beide bekamen die
        Challenge. Jetzt entscheidet das `DELETE`: Nur wer die Zeile tatsächlich entfernt hat
        (`rowcount == 1`), bekommt den Inhalt. SQLite serialisiert die Schreiber, auch über
        Prozessgrenzen — `RETURNING` wäre eleganter, verlangt aber SQLite ≥ 3.35."""
        with self._schreibend():
            r = self.db.execute("SELECT data, expires_at FROM flow WHERE key=?", (key,)).fetchone()
            if not r:
                return None
            weg = self.db.execute("DELETE FROM flow WHERE key=?", (key,)).rowcount
            self.db.commit()
        if weg != 1:
            return None                 # ein anderer Aufrufer hat ihn zuerst verbraucht
        if r["expires_at"] < _now():
            return None
        try:
            return json.loads(r["data"])
        except Exception:
            return None

    def zaehle_argon2_hashes(self) -> int:
        """Wie viele gespeicherte Passwort-/PIN-/Bereichs-Hashes sind argon2? (B6-8)"""
        n = 0
        for tabelle in ("password_cred", "pin_cred", "resource_secret"):
            r = self._one(f"SELECT COUNT(*) AS n FROM {tabelle} WHERE hash LIKE '$argon2%'")
            n += int(r["n"] or 0) if r else 0
        return n

    #: So lange gilt ein erfolgreicher Commit als Beleg, dass die Datenbank beschreibbar ist
    #: (Sekunden). Innerhalb dieser Frist prüft `schreibprobe()` nur noch die Verbindung.
    SCHREIBPROBE_SEK = 5

    def schreibprobe(self) -> None:
        """Eine echte Schreibtransaktion — der Kern des Healthchecks (B6-4).

        Ein `SELECT 1` gelingt auch auf einer Datenbank, die nur noch lesbar ist (Read-only-
        Mount, falsche Rechte nach einem Rückspielen, `SQLITE_READONLY`) oder deren Volume voll
        ist (`SQLITE_FULL`) — genau dort, wo jede Anmeldung an ihrem ersten `INSERT INTO
        session` scheitert. Gemeldet wird deshalb erst gesund, wenn ein Commit durchgeht.
        Wirft die sqlite3-Ausnahme unverändert; was davon nach aussen dringt, entscheidet der
        Aufrufer.

        Geschrieben wird der Stand der Uhr (`uhr_stand`) — so sichert der Healthcheck ihn
        nebenbei auch in Zeiten, in denen sonst nichts geschrieben wird. Aber höchstens alle
        `SCHREIBPROBE_SEK`: `/healthz` ist ohne Anmeldung erreichbar, und je Aufruf ein Commit
        mit fsync unter `_lock` hiesse, wer ihn flutet, belegt die Schreibsperre, auf die
        Anmeldungen warten, und nutzt SD-Karten ab. Liegt der letzte erfolgreiche Commit (auch
        ein fremder über `_exec`) kürzer zurück, genügt ein Lesezugriff — eine geschlossene oder
        verschwundene Verbindung fällt dabei weiterhin sofort auf, ein Wechsel auf „nur lesbar"
        spätestens nach `SCHREIBPROBE_SEK`."""
        with self._schreibend():
            m = time.monotonic()
            if self._frisch(self._geschrieben, m, self.SCHREIBPROBE_SEK):
                self.db.execute("SELECT 1").fetchone()
                return
            self._uhr_stand_schreiben()
            self.db.commit()
            self._geschrieben = self._uhr_gesichert = m

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

    @staticmethod
    def _fails_abfrage(since, username=None, ip=None, method=None, exclude_methods=None):
        """Die Zählabfrage für `count_fails` und `reserve_attempt` — eine Regel, zwei Aufrufer."""
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
        if exclude_methods:
            platz = ",".join("?" for _ in exclude_methods)
            q += f" AND (method IS NULL OR method NOT IN ({platz}))"
            args.extend(exclude_methods)
        return q, args

    def count_fails(self, since, username=None, ip=None, method=None, exclude_methods=None) -> int:
        """Fehlversuche im Fenster zählen — optional nur EINE Methode, oder alle AUSSER einigen.

        `exclude_methods` ist das Gegenstück zu `method`: Der Login-Lockout will alles zählen,
        was ein Anmeldeversuch war — aber nicht die Alt-Passwort-Abfrage der Kontoseite, die in
        derselben Tabelle liegt (siehe `security.NICHT_LOGIN_METHODEN`). Eine Zeile ohne Methode
        (`NULL`, denkbar aus einem Altbestand) zählt weiter mit: Im Zweifel strenger sperren.
        """
        if not username and not ip:
            return 0
        q, args = self._fails_abfrage(since, username, ip, method, exclude_methods)
        return self._one(q, args)["c"]

    def reserve_attempt(self, username, ip, method, regeln, serie=None) -> tuple:
        """Sperren prüfen und den Versuch **in derselben Transaktion** vorab als Fehlversuch buchen.

        `regeln` ist eine Liste `(grund, grenze, filter)`; `filter` sind die Schlüsselwörter von
        `count_fails`. Rückgabe `(id, None)` — der Versuch darf laufen und steht schon als
        Fehlversuch in der Tabelle — oder `(None, grund)`, wenn eine Regel greift.

        Warum vorab und warum in einer Transaktion (R3-2, R3-7, R7-2): Vorher stand zwischen
        `is_locked()` und `record_attempt()` die ganze Passwortprüfung (argon2, zig
        Millisekunden). Eine parallele Salve von N Anfragen las N-mal denselben Zählerstand
        „noch nicht gesperrt" und durfte N-mal raten — die Grenze galt nur für Angreifer, die
        brav nacheinander fragen. Jetzt reserviert jeder Versuch seinen Platz, bevor er prüft,
        und `BEGIN IMMEDIATE` macht Zählen und Buchen zu einem Schritt, auch über mehrere
        Prozesse (`uvicorn --workers N`) hinweg: Die Schreibsperre der Datei ordnet sie.
        Gelingt der Versuch, macht `finish_attempt` aus der Zeile einen Erfolg; ein Prozess,
        der dazwischen stirbt, hinterlässt einen Fehlversuch — im Zweifel strenger.

        `serie=(topf, art, grenze)` bucht dazu die Serie der Fehlversuche in Folge (B2-6) vor —
        in DERSELBEN Transaktion. Die erste Fassung las die Serie davor und zählte sie erst nach
        der Prüfung: Eine parallele Salve an der Grenze las N-mal „noch nicht voll" und durfte
        N-mal raten (gemessen: 15 statt 1). Rückgabe dann `(id, serienstand)` nach der Buchung.
        """
        with self._lock:
            if self.db.in_transaction:
                # Das zweite Schloss hinter `_schreibend`: Liegt doch eine Transaktion herum
                # (ein Schreiber, der beim Fehlschlag nicht zurückrollt), scheiterte das BEGIN
                # unten an ihr — und mit ihm jede Anmeldung, bis jemand anderes committete. Ihr
                # Inhalt ist der Rest eines GESCHEITERTEN Schreibzugriffs; er wird verworfen,
                # nicht mitgebucht. Laut, weil es ein Fehler an anderer Stelle ist.
                logging.getLogger("tinysesam").warning(
                    "Offene Transaktion auf der Datenbankverbindung vorgefunden (Rest eines "
                    "gescheiterten Schreibzugriffs) — verworfen, bevor der Anmeldeversuch zählt.")
                self._verwerfen()
            self.db.execute("BEGIN IMMEDIATE")
            try:
                stand = None
                topf_s, art_s, grenze_s = serie if serie is not None else (None, None, 0)
                if topf_s:
                    if self._serie_summe(topf_s) >= grenze_s:
                        self.db.execute("ROLLBACK")
                        return None, "lockout_serie"
                for grund, grenze, filt in regeln:
                    if not filt.get("username") and not filt.get("ip"):
                        continue
                    q, args = self._fails_abfrage(**filt)
                    if self.db.execute(q, args).fetchone()["c"] >= grenze:
                        self.db.execute("ROLLBACK")
                        return None, grund
                cur = self.db.execute(
                    "INSERT INTO login_attempt(ts, username, ip, success, method) VALUES (?,?,?,0,?)",
                    (_now(), username, ip, method))
                if topf_s:
                    self._serie_plus(topf_s, art_s)
                    stand = self._serie_summe(topf_s)
                self.db.execute("COMMIT")
                return cur.lastrowid, stand
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def finish_attempt(self, attempt_id, success: bool):
        """Einen mit `reserve_attempt` vorgebuchten Versuch abschliessen (Fehlversuch bleibt stehen)."""
        if success:
            self._exec("UPDATE login_attempt SET success=1 WHERE id=?", (attempt_id,))

    def cancel_attempt(self, attempt_id):
        """Einen vorgebuchten Versuch zurücknehmen — er war keiner (etwa: Verzeichnis-Ausfall, F-23)."""
        self._exec("DELETE FROM login_attempt WHERE id=? AND success=0", (attempt_id,))

    def clear_fails(self, username=None, ip=None, method=None, exclude_methods=None, seit=None):
        """Fehlversuche loeschen — optional nur die EINER Methode, oder alle AUSSER einigen.

        `method` ist keine Feinheit, sondern der Kern: Ohne sie raeumte ein erfolgreicher
        Passwort-Login auch die TOTP- und PIN-Fehlversuche weg. Wer das Passwort kannte (Leak,
        Wiederverwendung, Phishing), meldete sich vor jedem Rateversuch einmal korrekt an und
        setzte damit die Sperre fuer den ZWEITEN Faktor zurueck — beliebig oft. Die Regulierung,
        die das Panel als Haertung ausweist, griff fuer den zweiten Faktor nie.

        `exclude_methods` räumt alles ausser den genannten — der Weg nach einer VOLLSTÄNDIGEN
        Anmeldung, die die eigenen Töpfe (Kontoseite, Step-up, Bereich) nicht betrifft.
        """
        wo: str = ""
        args_m: tuple = ()
        if method is not None:
            wo, args_m = " AND method=?", (method,)
        elif exclude_methods:
            platz = ",".join("?" for _ in exclude_methods)
            wo, args_m = f" AND (method IS NULL OR method NOT IN ({platz}))", tuple(exclude_methods)
        if seit is not None:
            # Nur ab einem Zeitpunkt (Grenze a): Eine vollständige Anmeldung räumt, was DIESEM
            # Konto galt — nicht die Fehlversuche unter seinem Namen oder seiner Adresse von vor
            # seiner Anlage (die galten niemandem oder jemand anderem).
            wo, args_m = wo + " AND ts >= ?", args_m + (int(seit),)
        if username:
            self._exec("DELETE FROM login_attempt WHERE username=? COLLATE NOCASE" + wo,
                       (username,) + args_m)
        if ip:
            self._exec("DELETE FROM login_attempt WHERE ip=?" + wo, (ip,) + args_m)

    def gc_attempts(self, older_than) -> int:
        return self._exec("DELETE FROM login_attempt WHERE ts < ?", (older_than,)).rowcount

    # ---------- Fehlversuche in Folge (B2-6) ----------
    # Die Tabelle `login_attempt` kennt nur Fenster: `gc()` räumt sie nach einem Tag, und jede
    # Schwelle dort zählt ab `lockout_window_sec`. Wer langsam rät — vier Versuche je Fenster,
    # rund um die Uhr —, blieb unter jeder Schwelle, beliebig lange. NIST SP 800-63B verlangt
    # deshalb eine Grenze für Fehlversuche IN FOLGE, die mit der Zeit nicht verfällt. Sie steht
    # hier, eigens und ohne Zeitfenster, je Kennung UND Methode: Gesperrt wird auf der Summe,
    # geräumt wird, was der Rückweg belegt (ein Selbstbedienungs-Reset nur den Passwort-Anteil,
    # R4-13). Das Buchen liegt in `reserve_attempt`, atomar mit dem Versuch selbst.
    def _serie_summe(self, topf) -> int:
        zeile = self.db.execute("SELECT COALESCE(SUM(anzahl), 0) AS n FROM fehlserie WHERE topf=?",
                                (topf,)).fetchone()
        return int(zeile["n"])

    def _serie_plus(self, topf, art):
        jetzt = _now()
        self.db.execute("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES (?, ?, 1, ?, ?) "
                        "ON CONFLICT(topf, art) DO UPDATE SET anzahl = anzahl + 1, "
                        "zuletzt = excluded.zuletzt", (topf, art or "", jetzt, jetzt))

    def fehlserie(self, topf) -> int:
        """Wie viele Fehlversuche in Folge stehen für diese (gefaltete) Kennung, über alle Methoden?"""
        if not topf:
            return 0
        with self._lock:
            return self._serie_summe(topf)

    def fehlserie_erhoehen(self, topf, art="password") -> int:
        """Einen Fehlversuch an die Serie hängen (Wege ohne Vorbuchung); gibt die neue Summe zurück."""
        if not topf:
            return 0
        jetzt = _now()
        self._exec("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES (?, ?, 1, ?, ?) "
                   "ON CONFLICT(topf, art) DO UPDATE SET anzahl = anzahl + 1, zuletzt = excluded.zuletzt",
                   (topf, art or "", jetzt, jetzt))
        return self.fehlserie(topf)

    def fehlserie_senken(self, topf, art) -> None:
        """Eine Vorbuchung zurücknehmen: Der Versuch war richtig (oder gar keiner — Verzeichnis-Ausfall).

        Nicht löschen: Ein richtiges Passwort bei offenem zweiten Faktor ist keine vollständige
        Anmeldung. Die Serie davor bleibt, nur dieser Versuch zählt nicht."""
        if not topf:
            return
        self._exec("UPDATE fehlserie SET anzahl = anzahl - 1 WHERE topf=? AND art=? AND anzahl > 0",
                   (topf, art or ""))

    def fehlserie_loeschen(self, topf, arten=None) -> int:
        """Die Serie beenden (`arten=None`: ganz, sonst nur diese Methoden); gibt zurück, wie viele es waren."""
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
        """Alte, NICHT ausgelöste Serien räumen (`zuletzt` vor `older_than`, Summe unter `grenze`).

        Eine ausgelöste Serie bleibt: Sie ist eine Sperre, und die hebt nur eine Anmeldung, ein
        Reset oder der Betreiber auf — nicht das Warten. Ohne Grenze liefe die Tabelle mit
        erfundenen Namen voll; mit ihr kostet jede bleibende Zeile einen Angreifer `grenze`
        Fehlversuche, jeder durch die Fenster-Schwellen gebremst."""
        return self._exec(
            "DELETE FROM fehlserie WHERE topf IN (SELECT topf FROM fehlserie GROUP BY topf "
            "HAVING MAX(zuletzt) < ? AND SUM(anzahl) < ?)", (int(older_than), int(grenze))).rowcount

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
        with self._schreibend():
            cur = self.db.execute(
                "UPDATE magic_token SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?",
                (_now(), token_hash, _now()))
            self.db.commit()
            return cur.rowcount == 1

    def expire_magic_token(self, token_hash) -> bool:
        """Einen noch unbenutzten Token sofort ablaufen lassen (Versand gescheitert, B6-12).

        Bewusst „abgelaufen" und nicht „benutzt": `used_at` heisst „eingelöst" — bei einem
        Bestätigungstoken also „Adresse belegt". Ein nie zugestellter Link hat nichts belegt,
        und die Bereinigung unbestätigter Konten (`unbestaetigte_konten`) muss ihn als
        abgelaufen sehen.
        """
        return self._exec("UPDATE magic_token SET expires_at=? WHERE token_hash=? AND used_at IS NULL",
                          (_now() - 1, token_hash)).rowcount == 1

    def unbestaetigte_konten(self) -> list:
        """Konten aus einer Registrierung, deren Bestätigungslink abgelaufen ist, ohne dass sie je
        bestätigt wurden (R4-09). Nur diese Kombination zählt — gesperrt, noch nie angemeldet,
        ein unbenutzter und abgelaufener `verify_email`-Token, und KEIN gültiger oder schon
        eingelöster daneben. Ein vom Admin gesperrtes Bestandskonto trägt keinen solchen Token
        und bleibt deshalb unberührt — und eines mit dem Betreiber-Vermerk (`disabled=2`) auch
        dann, wenn ihm eine App danach noch einen Bestätigungslink geschickt hat."""
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
        """Nie bestätigte Konten entfernen (R4-09) — VOR `gc_magic_tokens` rufen.

        Das Merkmal „nie bestätigt" ist der abgelaufene Bestätigungstoken; räumt
        `gc_magic_tokens` ihn zuerst weg, ist das Konto nicht mehr zu erkennen. Ohne diesen
        Schritt blieb eine Adresse, die jemand Fremdes registriert und nie bestätigt hatte, für
        immer belegt: Der echte Inhaber bekam „E-Mail vergeben". Hier und nicht im Manager,
        damit `tinysesam gc` (arbeitet direkt auf dem Store) dieselbe Reihenfolge fährt."""
        ids = self.unbestaetigte_konten()
        for uid in ids:
            # Über den einen Löschweg (H-13, Integrationsfunde 12/18): Die Registrierung des
            # Fremden samt IP und die Fehlversuche des echten Adressinhabers stünden sonst
            # weiter unter Name und Adresse — und die Schlusszeile trüge den Klarnamen.
            self.konto_entfernen(uid)
            self.audit_log("signup_expired", ersatzname(uid), None, f"uid={uid}")
        return len(ids)

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

    def move_resource_unlocks(self, old_token, new_token) -> int:
        """Die Freigaben eines Browsers auf ein neues Token umhängen (F-01).

        Umhängen statt kopieren: Danach hält das alte Token nichts mehr. War es von aussen
        untergeschoben, geht der Unterschieber leer aus; war es das eigene, bleiben die
        Bereiche offen, die dieser Browser schon hatte."""
        if not old_token:
            return 0
        with self._schreibend():
            cur = self.db.execute("UPDATE OR REPLACE resource_unlock SET token=? WHERE token=?",
                                  (self.session_hash(new_token), self.session_hash(old_token)))
            self.db.commit()
            return cur.rowcount

    def delete_resource_unlocks(self, token) -> int:
        """Alle Freigaben dieses Browsers beenden — beim Logout (F-08)."""
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

    # ---------- Audit-Log ----------
    #: IPs im Audit-Log auf ihr Netz kürzen (`TinySesamConfig.audit_ip_pseudonymize`, B5-11).
    #: Steht hier und nicht im Manager, weil auch der Login-Pfad direkt `audit_log` schreibt —
    #: eine Kürzung, die nur ein Teil der Zeilen erfährt, schützt niemanden.
    audit_ip_pseudonym = False

    def audit_log(self, event, username=None, ip=None, detail=None):
        # Die Spalte heisst `ip` — also steht darin eine (B5-15). Eine echte Adresse in ihrer
        # kanonischen Form; alles andere (ein Test-Peer, ein Unix-Socket) nur steuerzeichenfrei
        # und gedeckelt, damit weder das Panel noch `tinysesam audit` eine erfundene Zeile zeigt.
        if ip is not None:
            from . import security as _sec
            norm = _sec.ip_normiert(ip)
            if norm is None:
                ip = _sec.fuer_log(ip) or None
            else:
                ip = _sec.ip_pseudonym(norm) if self.audit_ip_pseudonym else norm
        self._exec("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                   (_now(), event, username, ip, detail))

    def delete_attempts_for(self, username, weitere=(), nach=None, unbefristet=()) -> int:
        """Die Anmeldeversuche eines Kontos löschen (beim Löschen des Kontos, H-13).

        `weitere` sind zusätzliche Kennungen, unter denen es angemeldet werden konnte (die
        E-Mail-Adresse — `find_user` nimmt sie an, und der Versuch steht dann unter ihr).

        Gezählt wird unter dem Topf `norm_kennung` (NFKC, Python-`lower()`, IDNA für Adressen),
        gelöscht wird deshalb auch dort — `lower()` in SQLite faltet nur ASCII und traf den Topf
        `ärmel` des Kontos `Ärmel` nie, ein Name mit Kompatibilitätszeichen (`ｂｅｒｔａ`) und eine
        Bestandsadresse in Unicode-Form (`u@bücher.example`) ebenso wenig. Zeilen aus der Zeit vor
        `_topf` stehen unter der rohen Eingabe und werden weiter über SQLite-`lower()` gefunden.

        Zwei Grenzen (Nachbesserung zu den Integrationsfunden 12/18):
        - `nach` (Unix-Sekunden): nur Versuche NACH dieser Sekunde (der Anlage des Kontos) —
          davor galten sie nicht ihm, und sie zählen in der Drosselung je IP dessen, der sie
          machte. Die Sekunde selbst bleibt: Ob ein Versuch darin vor oder nach der Anlage kam,
          ist nicht zu entscheiden, und ein stehengebliebener Versuch verfällt mit dem
          Sperrfenster. Kennungen in `unbefristet` gelten ohne diese Grenze.
        - Führt ein VERBLEIBENDES Konto denselben Topf (ein Namensvetter wie `ｃｌａｒａ`/`clara`
          oder `Émile`/`émile` aus einem Bestand, `konto_mit_topf`), bleibt der Topf unberührt.
          Sonst leerte das Entfernen eines Kontos, das ein Anonymer anlegen und per `gc()`
          abräumen lassen kann, die Konto-Schwelle eines fremden (R7-6/H-8)."""
        n = 0
        for wert in (username, *[w for w in weitere if w]):
            topf = norm_kennung(wert)
            if not topf or self.konto_mit_topf(topf) is not None:
                continue
            ab = -1 if (nach is None or wert in unbefristet) else int(nach)
            roh = str(wert)
            n += self._exec("DELETE FROM login_attempt WHERE ts > ? "
                            "AND (username = ? OR lower(username) = lower(?) "
                            "OR lower(username) = lower(?))",
                            (ab, topf, roh, roh.strip())).rowcount
        return n

    def gc_audit(self, older_than_ts: int) -> int:
        """Audit-Zeilen vor einem Zeitpunkt löschen (`audit_retention_days`, B5-11)."""
        return self._exec("DELETE FROM audit WHERE ts < ?", (int(older_than_ts),)).rowcount

    def audit_anonymisieren(self, username, ersatz, weitere=(), seit=None, seit_id=0,
                            unbefristet=()) -> int:
        """Ein Konto aus dem Audit-Log herausnehmen, ohne die Zeilen zu löschen (H-13).

        Die Zeile „am 3. um 14:02 wurde ein Passwort zurückgesetzt, von dieser IP" bleibt für
        die Forensik stehen; WER es war, steht danach nur noch als `ersatz` da. `weitere` sind
        zusätzliche Kennungen (die E-Mail-Adresse): Unter ihr stehen Anmeldeversuche in der
        Spalte `username` (`find_user` nimmt die Adresse an), und im Detailtext kommt sie vor.

        Im Detailtext wird der BENUTZERNAME nur dort ersetzt, wo einer steht — `akteur=<name>`
        und der Kopf von `user_create`. Ein freies Ersetzen jedes gleichlautenden Wortes traf
        fremde Zeilen: Mit dem Konto `admin` wurde aus `admin=0->1` in der Rollenänderung eines
        ANDEREN Kontos `gelöscht#2=0->1`, mit `password` die Methode jedes Fehlversuchs. Eine
        Kennung mit `@` ist dagegen unverwechselbar und wird überall ersetzt.

        `seit`/`seit_id` beschränken das auf Zeilen ab der Anlage des Kontos (`anlage_grenze`,
        `konto_entfernen`): Was davor unter dem Namen oder mit der Adresse geschrieben wurde,
        gehörte nicht diesem Konto. Kennungen in `unbefristet` gelten ohne die Grenze. Ohne
        `seit` gilt jede Zeile.
        """
        if not username:
            return 0
        import re as _re
        kennungen = [str(w) for w in (username, *weitere) if w]
        ohne_frist = {str(w) for w in unbefristet if w}

        def ab(wert) -> tuple:
            if seit is None or wert in ohne_frist:
                return (-1, -1, 0)
            return (int(seit), int(seit), int(seit_id or 0))
        grenze = "(ts > ? OR (ts = ? AND id >= ?))"
        with self._schreibend():
            n = 0
            for wert in kennungen:
                n += self.db.execute(
                    f"UPDATE audit SET username=? WHERE lower(username)=lower(?) AND {grenze}",
                    (ersatz, wert, *ab(wert))).rowcount
            for wert in kennungen:
                w = _re.escape(wert)
                ende = r"(?![\w@.=-])"
                if "@" in wert:
                    muster = _re.compile(r"(?<![\w@.-])" + w + ende, _re.IGNORECASE)
                else:
                    muster = _re.compile(r"(?<![\w@.-])akteur=" + w + ende, _re.IGNORECASE)
                zeilen = self.db.execute(
                    "SELECT id, event, detail FROM audit "
                    f"WHERE instr(lower(detail), lower(?)) > 0 AND {grenze}",
                    (wert, *ab(wert))).fetchall()
                for z in zeilen:
                    alt = z["detail"] or ""
                    if "@" in wert:
                        neu = muster.sub(ersatz, alt)
                    else:
                        neu = muster.sub("akteur=" + ersatz, alt)
                        if z["event"] == "user_create":   # Detail: „<name> service=…"
                            neu = _re.sub(r"^" + w + r"(?=\s|$)", ersatz, neu, count=1,
                                          flags=_re.IGNORECASE)
                    if neu != alt:
                        self.db.execute("UPDATE audit SET detail=? WHERE id=?", (neu, z["id"]))
            self.db.commit()
        return n

    def recent_audit(self, limit=100, username: str | None = None, seit: int | None = None,
                     seit_id: int = 0):
        """Die jüngsten Audit-Einträge, neueste zuerst.

        `username` filtert in SQL, nicht im Aufrufer. Das ist der Unterschied zwischen „die
        letzten N Einträge dieses Kontos" und „die Einträge dieses Kontos unter den letzten N" —
        und genau der zählt im Anlassfall: Eine Brute-Force-Welle schiebt in Minuten Tausende
        Zeilen nach, das gesuchte Konto liegt dann weit hinter jedem Fenster. Aus demselben Grund
        filtert `seit` (Unix-Sekunden, einschliesslich) ebenfalls in SQL; aus der Sekunde `seit`
        selbst nur Zeilen ab `seit_id` (s. `anlage_grenze`).
        """
        bedingungen: list[str] = []
        werte: list[object] = []
        if username:
            bedingungen.append("lower(username)=lower(?)")
            werte.append(username)
        if seit:
            bedingungen.append("(ts > ? OR (ts = ? AND id >= ?))")
            werte.extend((int(seit), int(seit), int(seit_id or 0)))
        wo = (" WHERE " + " AND ".join(bedingungen)) if bedingungen else ""
        return self._all(f"SELECT * FROM audit{wo} ORDER BY id DESC LIMIT ?", (*werte, limit))

    # ---------- API-Keys ----------
    def add_api_key(self, user_id, name, prefix, key_hash, roles=None, expires_at=None,
                    kind: str = "automat") -> int:
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

    def revoke_user_magic_tokens(self, user_id) -> int:
        """Alle noch offenen Einmal-Token eines Kontos verwerfen (Sperre durch den Betreiber).

        Ein vor der Sperre verschickter Bestätigungslink schaltete das Konto sonst wieder frei
        (`/auth/verify/…` hebt `disabled` auf — für die Registrierung ist das richtig, für eine
        Sperre durch den Betreiber nicht), ein Anmelde-Link hätte eine Sitzung angelegt."""
        return self._exec("DELETE FROM magic_token WHERE user_id=? AND used_at IS NULL",
                          (user_id,)).rowcount

    def revoke_user_api_keys(self, user_id) -> int:
        """Alle noch gültigen Keys eines Kontos entwerten. Gibt zurück, wie viele es waren —
        die Zahl gehört ins Protokoll und in die Antwort, sonst merkt niemand, was still
        weggefallen ist (oder eben weiterläuft)."""
        return self._exec("UPDATE api_key SET revoked=1 WHERE user_id=? AND revoked=0",
                          (user_id,)).rowcount

    def count_active_api_keys(self, user_id) -> int:
        r = self._one("SELECT COUNT(*) AS n FROM api_key WHERE user_id=? AND revoked=0", (user_id,))
        return r["n"] if r else 0

    def api_key_owner(self, key_id) -> Optional[int]:
        """Die Konto-ID zu einem Key — für die Audit-Zeile beim Widerruf (B5-04)."""
        r = self._one("SELECT user_id FROM api_key WHERE id=?", (key_id,))
        return r["user_id"] if r else None

    def revoke_api_key(self, key_id, user_id=None):
        if user_id is not None:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=? AND user_id=?", (key_id, user_id))
        else:
            self._exec("UPDATE api_key SET revoked=1 WHERE id=?", (key_id,))

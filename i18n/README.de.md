<p align="center"><img src="../docs/wizard.png" alt="TinySesam" width="250" height="250"></p>

<h1 align="center">TinySesam</h1>

<p align="center"><a href="../README.md">English</a> · <b>Deutsch</b></p>

<p align="right">
<a href="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python">
</p>

### Der Login-Mechanismus für deine selbstgebauten Apps.

Ein **super-leichtes Auth für FastAPI**, bei dem du **nur nutzt, was du brauchst** — und das mit dir mitwächst.
Eine Klasse davorhängen, fertig: Login-Seite, Sessions und Route-Guards inklusive.

- **Nur eine Seite mit einer PIN sichern?** → geht. (`require_resource("fotos")`, ganz ohne Benutzerkonto)
- **Forward-Auth vor fremde Apps hängen, wie TinyAuth?** → kann er. (`/auth/forward` bzw. OIDC-Gateway)
- **Ein Admin-Panel?** → eingebaut. **Lieber in dein eigenes einbauen?** → auch das (nur JSON-API).
- **Von „Passwort reicht" bis „OIDC → Passwort → TOTP"?** → wächst mit — jedes Stück **optional, an/aus per Config**.
- **Eigenes Look & Feel?** → das komplette **Frontend ist austauschbar** (`auth.set_template(...)`), inkl. Sprache (en/de).

> **Kurz zur Einordnung:** TinySesam sichert **deine eigenen (selbstgebauten) Apps** und **nutzt** dabei vorhandene
> IdProvider (OIDC, SAML, LDAP/AD) als *Client / Relying Party*. Es ist **selbst kein Identity Provider** — also
> **kein Ersatz** für Keycloak/Authentik/PocketID, sondern die schlanke Auth-Schicht **davor bzw. in** deiner App.

**Anmelde-Methoden — beliebig kombinierbar:**
- 🔑 **Passkey / WebAuthn** (passwortlos, phishing-resistent)
- 🔐 **Passwort** (argon2, mit stdlib-scrypt-Fallback)
- 🔢 **PIN** (persönliche PIN pro User, eigener strenger Lockout)
- 🌐 **OIDC** (generischer IdProvider: PocketID, Keycloak, Entra/Azure AD, …)
- 🪪 **SAML 2.0** (SP-Login gegen ADFS, Okta, Keycloak, …)
- 🗂️ **LDAP / Active Directory** (Passwort gegen Verzeichnis-Bind)
- ✉️ **Magic-Link** (Einmal-Login per E-Mail)
- 📱 **TOTP** als 2. Faktor *on-top* (+ **Recovery-Codes**; Passkeys gelten schon als vollwertig)

**Kombinierbar in Reihenfolge:**
beliebige **Faktor-Ketten** (`login_chain=["oidc","password"]`),
global oder per Route (`Depends(auth.require(factors=[...], strict=...))`).

**Rollen sind optional:**
die meisten Apps brauchen nur „eingeloggt / nicht" (`require_user`).
Wer differenzieren will: `is_admin` + frei definierbare `roles` (`require_admin`, `require_role("editor")`).

**Mehr:**
„Angemeldet bleiben",
**Step-up** pro Route (`require(mfa=True)`),
**Selbst-Registrierung** + **Einladungen**,
**Passwort-vergessen**,
geteiltes **Ressourcen-Geheimnis** (PIN/Passphrase ohne Konto),
eingebaute **Konto-Seite** (inkl. eigener Sitzungen + Recovery-Codes),
**Forward-Auth** für fremde Apps

jedes Feature optional, per Config an/aus,
und das komplette **Frontend austauschbar** (`auth.set_template(...)`).

---

## Installation

TinySesam wird über seinen **Git-Tag** installiert — auf PyPI liegt es noch nicht (siehe unten):

```bash
pip install "tinysesam @ git+https://github.com/Ollornog/TinySesam.git@v0.18.0"
# Kern: Passwort + TOTP. Alles: [all] — + argon2, QR, OIDC, Passkey
pip install "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@v0.18.0"
# gezielt: [argon2] [qr] [oidc] [saml] [ldap] [passkey] [redis] [gateway]
```

Ohne `@v…` kommt statt einer freigegebenen Fassung der bewegliche Hauptzweig — das gehört in ein
Experiment, nicht in einen Betrieb.

> **Noch nicht auf PyPI.** `pip install tinysesam` funktioniert **nicht**: Der Name ist dort nicht
> registriert. Das Packaging steht (Metadaten, Trusted Publishing, ein Packaging-Test);
> veröffentlicht wird mit **1.0**, bis dahin gilt der gepinnte Git-Tag oben. Bis 2026-09-21 stand
> hier das Gegenteil — der allererste Befehl, den jemand ausprobierte, endete mit
> `No matching distribution found for tinysesam`.

## Quickstart

```python
from fastapi import FastAPI, Depends
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    rp_id="app.example.com",           # Domain (WebAuthn), ohne Schema/Port
    origin="https://app.example.com",  # exaktes Browser-Origin
    passkey_enabled=True,
    oidc_enabled=True,
    oidc_issuer="https://id.example.com",
    oidc_client_id="…", oidc_client_secret="…",
))
auth.ensure_admin("admin", "startpasswort")   # legt Admin an, NUR wenn der Store leer ist

app = FastAPI()
app.include_router(auth.router())              # /auth/* + Login-UI

@app.get("/")
def home(user = Depends(auth.require_user)):    # geschützt: eingeloggt (inkl. 2FA)
    return {"hi": user["username"]}
```

Nicht-eingeloggte Browser werden auf `/auth/login` umgeleitet; API-Clients (Accept ≠ HTML) bekommen `401`.

## Login-Kennung

Womit man sich anmeldet, ist ein Config-Feld — `login_identifier`:

```python
TinySesamConfig(login_identifier="both")      # Benutzername ODER E-Mail im selben Feld (Default)
TinySesamConfig(login_identifier="username")  # nur Benutzername
TinySesamConfig(login_identifier="email")     # nur E-Mail
```

Die Beschriftung des Feldes zieht automatisch nach, Passwort- **und** PIN-Login halten sich daran.
Weil die E-Mail eine Login-Kennung ist, wird sie kanonisch gespeichert (getrimmt, klein) und ist
**eindeutig** (partieller UNIQUE-Index; Konten ohne Adresse bleiben erlaubt). Bei der Registrierung
ist sie standardmäßig Pflicht — `signup_require_email=False` schaltet das ab. Im Modus `"email"`
fällt das Benutzernamen-Feld ganz weg: die Adresse *ist* die Kennung. `signup_verify_email=True`
aktiviert das Konto erst nach Klick auf den Bestätigungslink; das braucht einen Mailer (`set_mailer`
oder SMTP-Config) und verweigert sonst die Registrierung, statt die Prüfung still zu überspringen.

## Guards

```python
Depends(auth.require_user)             # eingeloggt — mehr braucht der einfachste Fall nicht
Depends(auth.require_admin)            # eingeloggt + is_admin
Depends(auth.require_role("editor"))   # eingeloggt + Rolle (Admin hat implizit alle)
Depends(auth.require_role("a", "b"))   # eine der beiden genügt
```

## Rollen & Gruppen

**Rollen sind die Gruppen** — pro User eine Liste (`roles`) + `is_admin`; Guard `require_role("…")`.
Mehrere nennen und **eine davon genügt** — `require_role("redaktion", "lektorat")`, oder aus der Config
`require_role(cfg.erlaubte_rollen)`. Das ist dasselbe ODER wie `?roles=a,b` im Forward-Auth; die Frage
„wer darf durch?" bedeutet damit in beiden Betriebsmodi dasselbe. Wer **alle** verlangt, stapelt die
Guards: `@app.get(…, dependencies=[Depends(auth.require_role("a")), Depends(auth.require_role("b"))])`.
Ein Admin erfüllt dabei **jede** Rolle. Wer das nicht will (z.B. weil die Rechte an einer IdP-Gruppe
hängen): `admin_implies_roles=False` global oder `require_role("editor", admin_implies=False)` je Route.
- **Lokale User/Passwort:** Rollen im **Admin-Panel** je User zuweisen. `available_roles=[…]` definiert bekannte
  Rollen → das Panel zeigt sie als **Checkboxen** (leer = Freitext-Eingabe).
- **IdP-User (OIDC/SAML/LDAP/AD):** externe Gruppen automatisch auf lokale Rollen mappen —
  `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`, z.B.
  `{"editors": "editor", "cn=admins,ou=g": "__admin__"}` (Ziel `__admin__` = Admin-Flag). Beim Login gesetzt;
  gemappte Rollen werden synchronisiert, manuell vergebene bleiben. Überall dieselben `require_role(...)`-Guards.

## Routen (vom Router bereitgestellt)

| Route | Zweck |
|---|---|
| `GET/POST /auth/login` | Passwort-Login + Login-Seite (zeigt aktive Methoden) |
| `GET/POST /auth/totp` | 2. Faktor nach Passwort/OIDC |
| `GET/POST /auth/totp/setup` · `POST /auth/totp/disable` | TOTP einrichten/abschalten |
| `GET /auth/oidc/start` · `/auth/oidc/callback` | OIDC-Flow *(wenn aktiviert)* |
| `POST /auth/passkey/{register,login}/{begin,finish}` | WebAuthn *(wenn aktiviert)* |
| `GET /auth/passkey/list` · `POST /auth/passkey/delete` | Passkeys verwalten |
| `GET /auth/magic/{token}` | Anmelde-Link einlösen *(wenn Magic-Link aktiv)* |
| `GET /auth/verify/{token}` · `GET /auth/invite/{token}` | Adresse bestätigen · Einladung annehmen |
| `GET /auth/logout` · `GET /auth/me` | Abmelden · aktueller User (JSON) |

## Konfiguration (`TinySesamConfig`, Auszug)

| Feld | Default | |
|---|---|---|
| `db_path` | `tinysesam.db` | SQLite-Store |
| `password_enabled` / `passkey_enabled` / `oidc_enabled` | `True/False/False` | aktive Methoden (Passkey ab Werk aus: `webauthn` steckt im Extra `[passkey]`) |
| `totp_enabled` | `True` | 2FA erlauben (verlangt, sobald ein Nutzer es eingerichtet hat) |
| `login_chain` · `stepup_strict` | `[]` · `False` | `["password","totp"]` **erzwingt** 2FA über die Faktor-Kette. Leer = klassisch: ein Erstfaktor, dazu TOTP, wo eingerichtet |
| `session_ttl_hours` · `cookie_secure` · `cookie_samesite` | `168` · `True` · `lax` | Sessions/Cookie |
| `rp_id` · `origin` | `localhost` · … | WebAuthn (echte Domain nötig, HTTPS) |
| `oidc_issuer/_client_id/_client_secret/_scopes` | – | OIDC-Provider |
| `oidc_auto_create` · `oidc_allowed_groups` · `oidc_group_claim` | `True` · `[]` · `groups` | Auto-Anlage + Gruppen-Gate |
| `base_url` · `login_redirect` · `logout_redirect` | – · `/` · … | App-Integration |
| `cookie_domain` · `trusted_redirect_hosts` | `""` · `[]` | SSO über Subdomains · erlaubte absolute `?next=`-Ziele |
| `security_log` | `""` | Datei für den fail2ban-Logger (leer = nur an den Logger) |
| `forward_auth_enabled` · `forward_headers` | `False` · `{}` | Forward-Auth-Endpunkt · welche Header er setzt (leer = `Remote-*`) |

## Sprache (i18n)

Die eingebauten Texte sind **standardmäßig Englisch** (`lang="en"`); mitgeliefert ist auch **Deutsch**:

```python
TinySesamConfig(lang="de")                       # eingebaute Seiten + Meldungen auf Deutsch
auth.add_messages("fr", {"login.submit": "Se connecter", ...})   # eigene Sprache/Überschreibung
```
Einzelne Texte oder ganze Seiten lassen sich zusätzlich per `auth.set_template(...)` frei ersetzen.

## Eigene Login-Seite

TinySesam als reines Backend nutzen (eigene UI) — die Bausteine sind öffentlich:

```python
user = auth.check_password(username, password)
token, fertig = auth.start_session(user["id"], "password")   # Tupel, nicht nur ein Token
auth.set_cookie(resp, token)
if not fertig:                    # es fehlt noch ein zweiter Faktor
    ...                           # auth.verify_totp(user["id"], code) → auth.complete_totp(token)
```

`start_session` gibt `(token, session_ok)` zurück. Auspacken — wer das Tupel direkt in
`set_cookie` reicht, schreibt den String `"('abc…', True)"` ins Cookie, und es fliegt keine
Ausnahme: Die Anmeldung ist still kaputt. `session_ok=False` heisst: Die Sitzung existiert, ist
aber noch nicht vollständig.

## Look & Feel

Jede eingebaute Seite (Login, PIN, TOTP, Konto, Admin-Panel, Fehlerseiten) stylt sich über **einen Satz
CSS-Variablen** — kein Selektor muss je Seite nachgebaut werden. In `brand_css` überschreiben, fertig:

```python
TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-surface:#fbf8f4;--ts-ink:#2b2a3a;--ts-accent:#b0566f}")
```

Die Tokens (und ihre Defaults) stehen in [`tinysesam/theme.py`](../tinysesam/theme.py); `brand_head` hängt
zusätzliches `<head>`-Markup ein, `brand_icon` setzt das Favicon auf jeder eingebauten Seite.

**Eigene Navigation und Fußzeile drumherum?** `brand_header` und `brand_footer` umschließen *jede*
eingebaute Seite — Login, PIN, TOTP, Konto, Admin-Panel und die Fehlerseiten. Beide nehmen HTML oder
`fn(auth) -> str`, wenn der Rumpf vom Request abhängt (Login-Status, Sprache). `auth.install_error_pages(app)` liefert Browsern gebrandete 403/404/500-Seiten,
API-Clients weiterhin JSON. Mehr als Farben nötig? Ganze Seite per `auth.set_template(...)` ersetzen.

## PIN und Step-up für sensible Routen

Eine PIN muss kein Weg hinein sein. `pin_login=False` hält sie von der Login-Seite fern und lässt sie
als *zusätzlichen* Faktor stehen:

```python
TinySesamConfig.local_accounts(          # nur Benutzername + Passwort, nirgends eine E-Mail
    pin_enabled=True, pin_login=False,   # eine PIN gibt es, anmelden kann man sich damit nicht
    stepup_methods=["pin"],              # sensible Routen fragen danach, auch wenn man schon drin ist
)
```

- `Depends(auth.require(mfa=True))` → die Route verlangt eine *frische* Bestätigung. `/auth/reauth`
  bietet TOTP, PIN oder Passwort an — eingeschränkt durch `stepup_methods`, sonst das, was der Nutzer
  eingerichtet hat (`auth.stepup_options(user)`). Die Frische verfällt nach `stepup_max_age_sec`.
- `Depends(auth.require(factors=["password", "pin"]))` → eine geordnete Kette pro Route. Wer schon
  eingeloggt ist, bekommt nur das fehlende Feld, nicht noch einmal die ganze Login-Seite.

## Den ersten Admin bestimmen

Offene Registrierung plus „der erste Account wird Admin" ist ein Wettlauf: wer die frische Instanz
zuerst findet, gewinnt sie. TinySesam bietet deshalb zwei ausdrückliche Wege, **beide nur, solange es
keinen Admin gibt**:

```python
TinySesamConfig(admin_identifiers=["ich@example.com"])   # Allowlist, jede Login-Methode
```

- **Allowlist** — der genannte Benutzername bzw. die E-Mail wird beim nächsten erfolgreichen Login
  befördert, egal über welche Methode (auch OIDC/SAML/LDAP, wo die Adresse meist die stabile Kennung
  ist). Danach nie wieder.
- **Einmal-Token** — gibt es keinen Admin, schreibt TinySesam beim Start eine Claim-URL ins Log.
  Anmelden, `/auth/claim-admin?token=…` öffnen, fertig. Das Token gilt einmal und läuft nach
  `admin_claim_ttl_min` ab; sobald ein Admin existiert, antwortet die Route mit 404.

Die Allowlist sagt, **welcher Name** Admin wird — nicht, **wer** diesen Namen bekommt. Mit
`allow_signup=True` registriert sich ein Fremder einfach darunter und ist beim ersten Login Admin;
diese Kombination weist der Konstruktor deshalb ab. Erlaubt ist sie wieder, sobald die Identität
aus der Registrierung selbst belegt ist: eine E-Mail-Adresse (kein blosser Benutzername, den
niemand bestätigt), Pflicht und bestätigt (`signup_require_email=True`,
`signup_verify_email=True`). Sonst die Registrierung **geschlossen lassen** — oder den
Einmal-Token nehmen, der verlässt das Server-Log nie.

Dasselbe gilt, wenn ein IdP die Konten anlegt (`oidc_auto_create`, `saml_auto_create`,
`ldap_auto_create`): Auch dort kommt der Benutzername aus fremder Hand, ein Allowlist-**Name**
wird in dieser Lage abgewiesen. Eine Allowlist-**Adresse** bleibt erlaubt, zählt bei OIDC aber
nur mit dem Claim `email_verified` — fehlt er, gilt die Adresse als unbestätigt und wird (mit
`oidc_require_verified_email=True`, Vorgabe) gar nicht erst ins Konto übernommen. Für IdPs ohne
diesen Claim ist der Einmal-Token der belegte Weg.

Alternativ legt `auth.ensure_admin("admin", os.environ["INITIAL_PW"])` den Admin an, bevor die App
den ersten Request beantwortet — am saubersten, wenn du per Skript deployst.

### Admin-Passwort weg, und kein Mailer da?

Ein Preset für interne Werkzeuge (`local_accounts()`) hat bewusst kein „Passwort vergessen" und keinen
Magic-Link — beides bräuchte einen Mailserver. Und die beiden Bootstrap-Wege oben greifen nur,
**solange kein Admin existiert**. Mit genau einem Admin-Konto und ohne zweites, das aushelfen könnte,
ist das eine Sackgasse. Der Weg zurück führt über die Datenbankdatei, die dir ohnehin gehört:

```bash
python -m tinysesam passwd --db auth.db admin     # fragt zweimal, dann ist es gesetzt
```

Das Kommando beendet die offenen Sitzungen des Kontos (`--keep-sessions` lässt sie stehen) und
schreibt einen Audit-Eintrag. `--stdin` liest das Passwort von der Standardeingabe, für Skripte.
Dasselbe aus Python:

```python
auth = TinySesam(TinySesamConfig(db_path="auth.db"))
auth.set_password(auth.store.get_user_by_name("admin")["id"], "neues-passwort")
```

## Sicherungen und Aufräumen

```bash
python -m tinysesam backup --db auth.db auth-2026-09-21.db   # konsistente Kopie, im Betrieb
python -m tinysesam gc     --db auth.db                      # Abgelaufenes wegräumen
```

> **Die Datenbank nicht durch Kopieren der Datei sichern.** Sie läuft im WAL-Modus: Alles seit
> dem letzten Checkpoint steht in `auth.db-wal`, nicht in `auth.db`. Ein `cp`/`rsync` der `.db`
> allein liefert einen Torso — gemessen an einer frischen Instanz mit fünf Konten enthielt die
> Kopie nicht einmal die Tabelle `users`, und das merkt man erst beim Zurückspielen. `backup`
> nutzt SQLites Online-Backup: Es nimmt die nötigen Sperren, zieht das WAL mit und schreibt eine
> Datei, die für sich allein stimmt — mit denselben engen Rechten wie die Quelle. Aus Python:
> `auth.store.backup(pfad)`.

`gc` löscht abgelaufene Sitzungen, Flows, Einmal-Token und alte Login-Versuche; das Audit-Log
bleibt bewusst unangetastet. **Von selbst läuft das nicht** — fertige Unit-Dateien liegen in
[`deploy/systemd/`](../deploy/systemd/). Aus Python: `auth.gc()` liefert dieselben Zahlen als
Dict. `gc` gibt allerdings keinen Plattenplatz an das Dateisystem zurück; nach einem grossen
Aufräumen einmalig `sqlite3 auth.db 'VACUUM;'` bei gestopptem Dienst.

### Eine Sicherung zurückspielen

```bash
systemctl stop tinysesam                                  # der Dienst muss stehen
python -m tinysesam restore --db auth.db sicherung-2026-09-21.db
systemctl start tinysesam
```

> **Auch zurück nicht einfach kopieren.** Nach einem Absturz liegen `auth.db-wal` und
> `auth.db-shm` neben der Datenbank. SQLite spielt sie beim Start auf die eben zurückgespielte
> Datei — der alte Stand ist wieder da, ohne Fehlermeldung, und `PRAGMA integrity_check` sagt
> `ok`. `restore` räumt beide vorher weg, prüft die Sicherung, bevor es irgendetwas überschreibt
> (Integrität, Kontenzahl, Schema-Version), und setzt danach `0600`.

> **Ein Rückschritt auf ≤ 0.17.x braucht eine Sicherung im alten Schema.** 0.18.0 migriert die
> Datenbank beim ersten Start. Älterer Code öffnet die Datei danach klaglos, `/healthz` bleibt
> grün und Konten sind lesbar — aber jede Sitzungsoperation wirft. Die Sicherung also **vor** dem
> Update ziehen (`tinysesam backup` lässt die Quelle unangetastet) und im Ernstfall die
> zurückspielen.

### „Ich komme nicht rein" — nachsehen

```bash
python -m tinysesam audit  --db auth.db --user alice    # ins Protokoll, von der Kommandozeile
python -m tinysesam unlock --db auth.db alice           # eine Brute-Force-Sperre aufheben
```

Das Audit-Log hält fest, *warum* eine Anmeldung scheiterte (`kein_konto`, `konto_gesperrt`,
`falsches_geheimnis`) — die HTTP-Antwort tut das bewusst nicht, sonst liesse sich damit nach
Konten suchen. Im Protokoll liest nur der Betreiber mit.

## Demo-Modus

`demo_mode=True` legt die Konten `demo` und `demoadmin` an, zeigt ihre Zugangsdaten auf der
Anmeldeseite (und die PIN auf der PIN-Seite) und sagt unmissverständlich, dass er produktiv aus
gehört. Beim Abschalten werden genau diese Konten beim nächsten Start gelöscht. Niemals auf einer
öffentlichen Instanz einschalten.

## Sicherheit

- Passwörter: **argon2id** (Fallback **scrypt**, n=2¹⁵). Sessions **server-side** (in SQLite, jederzeit revozierbar).
- Session-Cookie: `HttpOnly`, `Secure` (Default), `SameSite=Lax`.
- OIDC: `state` + `nonce` im Store (nicht im Client), ID-Token gegen **JWKS** + `iss`/`aud`/`exp` verifiziert.
- WebAuthn: Challenge im Store, an httponly-Cookie gebunden; `sign_count`-Klon-Erkennung.
- **Produktiv immer hinter HTTPS.** `rp_id`/`origin` müssen exakt zur Domain passen.

## Härtung

Nach dem Vorbild von Authelia/Fail2Ban — die Schwellen sind **im Admin-Panel / zur Laufzeit** änderbar
(`auth.set_security(key, wert)`, Defaults in `security.SECURITY_DEFAULTS`):

- **Brute-Force-Regulation:** Fehlversuche pro **User *und* IP** werden gezählt; nach `max_login_attempts`
  im `lockout_window_sec`-Fenster ist der Login gesperrt — blockt auch das *korrekte* Passwort.
  Gilt für Passwort- und TOTP-Login (IP-Schwelle höher wg. NAT: `ip_attempt_factor`).
- **Rate-Limiting:** Token-Bucket pro IP auf Login-/2FA-Endpoints (`rate_limit_max` / `rate_limit_window_sec`).
- **fail2ban:** jeder Fehlversuch wird über den Logger `tinysesam.security` mit echter Client-IP geloggt
  (`failed login … ip=…`). Filter + Jail in [`deploy/fail2ban/`](../deploy/fail2ban/) → IP-Ban auf Firewall-Ebene.
  Mit `security_log="/var/log/tinysesam/security.log"` schreibt TinySesam die Datei selbst — die
  mitgelieferte Jail zeigt darauf und bewachte sonst eine Datei, die nie entsteht. Leer lassen, wer sein
  Logging selbst einrichtet; ein nicht schreibbarer Pfad warnt beim Start, statt ihn zu verhindern.
- **Echte Client-IP hinter Proxy:** `X-Forwarded-For` gilt nur, wenn der direkte Peer in
  `trusted_proxies` steht — sonst ist die IP fälschbar. **uvicorn ohne `--proxy-headers` starten.**
  Mit dem Flag ersetzt uvicorn `request.client.host` bereits durch die geforwardete IP; TinySesams
  Prüfung läuft ins Leere und Rate-Limit, Lockout und fail2ban lassen sich umgehen.
- **Rollen und Admins:** standardmäßig erfüllt ein Admin **jede** `require_role(...)`-Prüfung. Hängen
  die Rechte einer App allein an einer IdP-Gruppe, ist das eine stille Rechteausweitung — dann
  `admin_implies_roles=False` setzen (oder je Guard `require_role(..., admin_implies=False)`).
- **IdP-Gruppen** werden **exakt** gegen die Schlüssel von `*_group_role_map` verglichen
  (`group_match="exact"`). Teilstring-Vergleich (nötig für LDAP-`memberOf`-DNs, dort automatisch)
  würde den Schlüssel `admin` auch auf eine Gruppe `nicht-admin` passen lassen.
- **Audit-Log:** Login / Logout / Fehlversuche in der DB (`store.recent_audit()`), fürs Admin-Panel.
- **CSRF:** Double-Submit-Token (`csrf_enabled`, Default an) auf allen state-ändernden POSTs — die
  eingebauten Formulare/JS erledigen das automatisch (`_csrf`-Feld bzw. `X-CSRF-Token`-Header).
  Wer eigene Templates rendert: `token = auth.issue_csrf(response)` setzt das Cookie und liefert den Wert;
  API-Key-Requests sind ausgenommen (kein Cookie-Risiko). Zusätzlich zu `SameSite=Lax`.
- **Rate-Limit prozessübergreifend:** optional Redis (`redis_url`, Extra `[redis]`) für Multi-Worker; sonst In-Memory.
- **User-Enumeration:** Login/PIN prüfen auch bei unbekanntem Benutzer gegen einen Dummy-Hash (kein Timing-Leak).
- **Nach Passwortwechsel** werden die übrigen Sitzungen des Users beendet (Admin-Reset: alle).
- **Housekeeping:** `auth.gc()` löscht abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte
  Login-Versuche (Audit-Log bleibt). Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen.

## Installation und Updates

**TinySesam aktualisiert sich nicht selbst.** Die Version bestimmst du, und zwar an genau einer
Stelle: dort, wo du die Bibliothek installierst. Ein Auth-Modul, das zur Laufzeit Code aus dem
Internet nachlädt, ist eine Hintertür mit Bedienungsanleitung — wer das Admin-Panel übernimmt,
könnte auf eine alte Version mit bekannter Lücke zurückschalten. Etablierte Auth-Projekte haben
so einen Knopf nicht, und seit `v0.12.0` hat TinySesam ihn auch nicht mehr.

### Als Bibliothek (in deiner eigenen App)

Schreibe eine **feste Version** in die Abhängigkeiten deiner App — nie einen Branch:

```
tinysesam[oidc]==0.18.0
```

Eine veröffentlichte Version auf PyPI ändert sich nicht mehr: Dieselbe Zeile installiert morgen
denselben Code. Aktualisieren heißt dann: Version in der Zeile hochziehen, neu installieren,
Dienst neu starten. Python lädt Code nicht zur Laufzeit nach.

Derselbe Pin über Git, wenn du so installierst — beachte, dass sich ein **Tag umhängen lässt**;
für echte Unveränderlichkeit pinne den Commit (`@a1b2c3d…`):

```
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.18.0
```

Jedes Release hängt zusätzlich ein **Wheel** und ein **sdist** an, mit `SHA256SUMS`. Wer ohne Git
und ohne Paketindex installieren will, nimmt die Datei direkt:

```
pip install https://github.com/Ollornog/TinySesam/releases/download/v0.18.0/tinysesam-0.18.0-py3-none-any.whl
```

### Als Gateway (eigener Container)

Jedes Release baut ein Abbild für `linux/amd64` und `linux/arm64`:

```
ghcr.io/ollornog/tinysesam:v0.18.0
```

**Prüfen, woher es kommt.** Ein Digest belegt, dass sich ein Artefakt seit dem Bau nicht verändert
hat — nicht, wer es gebaut hat. Jedes Release trägt deshalb eine über Sigstore signierte
Herkunfts-Attestation und eine SBOM; beide liegen auch neben dem Abbild in der Registry:

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.18.0 --owner Ollornog
gh attestation verify tinysesam-0.18.0-py3-none-any.whl --owner Ollornog   # auch Wheel und sdist
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.18.0 --owner Ollornog \
    --predicate-type https://spdx.dev/Document                             # die SBOM
```

Geht das durch, heisst das: gebaut vom Release-Workflow dieses Repos, aus dem Commit, den die
Attestation nennt. Kein Schlüssel, den man herausgeben — und keiner, den man verlieren kann: Die
Signatur hängt an der Identität des Workflows.

Es läuft als **Nicht-root** (uid 1000), enthält weder `pip` noch `git`, bringt einen
`HEALTHCHECK` auf `/healthz` mit und startet direkt das Gateway — kein `command:` nötig.
Ein vollständiges Beispiel mit Caddy liegt in `deploy/forward-auth/docker-compose.yml`.

Update: Tag hochziehen, `docker compose pull && docker compose up -d`. Rollback: alten Tag
zurückschreiben. **Ein `latest` gibt es bewusst nicht** — ein wandernder Tag macht jeden
Neustart zum Glücksspiel. Wer es ernst meint, pinnt den Digest
(`ghcr.io/ollornog/tinysesam@sha256:…`, steht im Log des Release-Workflows): ein Tag lässt
sich umhängen, ein Digest nicht.

### Woher weißt du, dass es etwas Neues gibt?

Aus dem [Releases-Feed](https://github.com/Ollornog/TinySesam/releases) — per Watch, RSS
(`releases.atom`) oder einem Bot wie Renovate/Dependabot, der den Pin in einem Pull Request
hochzieht. Dann läuft deine CI gegen die neue Version, und du entscheidest, ob du mergst.
Die laufende Version zeigt `python -m tinysesam version` und das Admin-Panel unter „Härtung".

## API-Keys & Service-/Daemon-Accounts

Für **maschinellen Zugang** (Skripte, andere Dienste, System-Daemons) — parallel zum interaktiven Login:

- Ein API-Key gehört einem User, liegt **gehasht** (sha256) in der DB, optional mit **Ablauf** und **Rollen-Scope**.
- Gesendet als `Authorization: Bearer tsk_…` **oder** `X-API-Key: tsk_…`.
- **`require_user` akzeptiert Session ODER gültigen Key** — geschützte Routen sind ohne Änderung auch per Key erreichbar; `require_role(...)` respektiert den Key-Scope.
- **System-Daemons** = **Service-Account** (`auth.create_service("backup-daemon", roles=["reader"])`, kein Login/MFA) + Key (`auth.create_api_key(uid, name=…, expires_days=…)` → Klartext **einmalig**). Least-Privilege über die Rollen.
- **Sperren statt löschen:** `auth.revoke_api_key(id)` (Key gesperrt, bleibt in der Liste). Self-Service-Routen: `GET/POST /auth/apikeys`, `POST /auth/apikeys/{id}/revoke`.
- **Ein Key ist eine zweite Haustür — Aussperren nimmt ihn mit.** Der Admin-Passwort-Reset und
  das Sperren eines Kontos widerrufen dessen Keys, ebenso „**alle** Sitzungen beenden"
  (`scope=all`) durch den Nutzer selbst. Der **eigene** Passwortwechsel tut es bewusst nicht —
  ein Routine-Wechsel soll die Automatiken nicht reihenweise stilllegen —, nennt aber in der
  Antwort und im Protokoll, wie viele Keys weiter gelten (`api_keys_active`). Keys eines
  deaktivierten Kontos haben ohnehin nie angemeldet.

## Admin-Panel

Eingebautes Panel unter **`/auth/admin`** (nur `is_admin`), einbindbar ohne Extra-Setup:

- **Benutzer & Service-Accounts:** anlegen, **explizit sperren/entsperren** (`disabled` — Konto bleibt, Login blockiert, Sitzungen enden sofort; Selbst-Sperr-Schutz), Passwort-Reset, Rollen/Admin setzen.
- **API-Keys** je User: erzeugen (einmalige Anzeige) / widerrufen.
- **Sitzungen:** aktive einsehen + beenden.
- **Härtung:** Schwellen (Versuche/Sperrzeit/Rate-Limit) live einstellen.
- **Version:** die laufende Version plus ein Hinweis, wie Updates laufen — es gibt **keinen
  „jetzt aktualisieren"-Knopf**, und zwar mit Absicht ([ADR-2](../backlog/ADR-2-kein-selbst-update.md)):
  Ein Auth-Modul, das zur Laufzeit Code nachlädt, ist eine Hintertür mit Bedienungsanleitung.
  Aktualisiert wird dort, wo installiert wurde. (Hier stand bis 0.18.0 ein Knopf, ein
  manual/auto-Modus und ein Version-Pin — nichts davon gibt es seit 0.12.0.)
- **Audit-Log** einsehen.

JSON-API unter `<mount>/api/*` (dieselben Aktionen — für eigene UIs / Automation).

**Montieren / einbetten / HTTPS:**
- **Standard:** automatisch unter `config.admin_path` (Default `/auth/admin`) — frei änderbar.
- **Woanders montieren:** `app.include_router(auth.admin_router(), prefix="/admin")` — beliebiger Pfad,
  Sub-App/**Subdomain** (Host-Routing der App) oder **eigener Port** (separate ASGI-App). Die UI ermittelt
  ihre Basis-URL selbst. `admin_enabled=False` schaltet den Auto-Mount ab.
- **In bestehendes Panel einbetten:** `admin_ui_enabled=False` → nur die JSON-API, eigene UI davor.
- **HTTPS** (`config.https_mode` + `auth.install_https(app)`): `force` = HTTP→HTTPS-Redirect;
  `warn` = läuft auch **ohne Zertifikat**, zeigt aber einen Warnhinweis im Panel; `off` = aus.
  Ein Tippfehler fliegt beim Bau auf — alles außer `force` heißt stillschweigend „kein Redirect",
  `https_mode="forse"` hätte den HTTPS-Zwang also wortlos abgeschaltet.
- **`https_mode="force"` verlangt `cookie_secure=True`.** Die Kombination mit `cookie_secure=False`
  wird beim Bau abgelehnt: Eine App, die jeden Request auf HTTPS umleitet, das Session-Cookie aber
  ohne `Secure`-Flag herausgibt, widerspricht sich — ein einziger HTTP-Aufruf reicht, damit es im
  Klartext mitgeht. `cookie_secure=False` bleibt für lokale Aufbauten ohne Zertifikat richtig
  (`https_mode="warn"`).
- **Content-Security-Policy** (`config.csp`): Die eingebauten Seiten (Login, Konto, TOTP-Einrichtung,
  Fehlerseiten) tragen eine **strikte, nonce-basierte CSP** — ohne `unsafe-inline`. Je Antwort
  entsteht ein frischer Nonce und wandert in jedes `<script>`/`<style>` und in den Header; die Seiten
  sind inline-frei gebaut (kein `onclick`/`onsubmit`, kein `style=`), deshalb deckt der Nonce alles
  ab. `"strict"` (Vorgabe), `"off"` (kein Header — z.B. weil ein Proxy die CSP setzt) oder eine
  eigene Policy (ein `{nonce}` darin wird je Antwort ersetzt). Ein Template-Override, das ein
  `Response` zurückgibt, bleibt unangetastet und bekommt `ctx["nonce"]` für seine eigene.

## Neu in 0.5 — Kurzreferenz

Alles optional (per Config an/aus), einzeln und kombiniert nutzbar, Frontend überall ersetzbar.

- **Frontend austauschbar:** `auth.set_template(name, fn)` — `fn(auth, ctx)` gibt HTML-String **oder**
  eine eigene `Response` zurück. Alle 13 Namen: `login`, `pin`, `totp`, `totp_setup`, `reauth`,
  `account`, `register`, `forgot`, `reset`, `magic_request`, `magic_invalid`, `resource_unlock`,
  `error`. Eingebaute Renderer sind Fallback; `tinysesam.templates.DEFAULTS` führt die aktuelle Liste.
- **Angemeldet bleiben:** `remember_me_enabled` — Checkbox → persistentes Cookie; ohne Haken reines
  Session-Cookie + kurze `session_ttl_transient_hours`.
- **Step-up / per-Route-MFA:** `Depends(auth.require(mfa=True))` (Sudo-Frische `stepup_max_age_sec`,
  → `/auth/reauth`). `admin_require_mfa=True` schützt das Panel zusätzlich mit frischer Bestätigung.
- **Faktor-Ketten (geordnet):** `login_chain=["oidc","password"]` + `login_chain_strict`; pro Route
  `require(factors=[...], strict=...)`. Faktoren: `password, pin, oidc, passkey, totp, magic`.
- **PIN pro User:** `pin_enabled` — Benutzer+PIN, eigener strenger Lockout, mit TOTP kombinierbar.
- **Geteiltes Ressourcen-Geheimnis:** `resource_locks_enabled` — `auth.set_resource_secret(name, secret,
  kind="pin"|"password")`, Guard `Depends(auth.require_resource(name))`, ganz ohne Benutzerkonto.
- **Magic-Link:** `magiclink_enabled` + SMTP-Config **oder** `auth.set_mailer(fn)`; `/auth/magic/request`,
  eingelöst unter `/auth/magic/{token}` — **dieser Endpunkt ist der Anmelde-Link und sonst nichts.**
- **Jeder verschickte Link braucht `base_url`.** Sie ist die einzige Quelle für die Adresse in
  Reset-, Magic-, Bestätigungs- und Einladungsmails. Ohne sie bliebe nur der `Host`-Header der
  Anfrage — den setzt der *Anfragende*, und wer einen Reset für ein fremdes Postfach anstößt,
  könnte den Link so auf seinen eigenen Server zeigen lassen. Ein abgeleiteter Host gilt deshalb
  nur, wenn er in `trusted_redirect_hosts` steht oder Loopback ist; sonst geht **keine Mail
  hinaus** (fail closed, mit Logzeile und Konfigurations-Warnung).
- **Registrierung + Einladung:** `allow_signup` (+ `signup_verify_email`, `signup_invite_only`);
  Admin-Einladung `auth.create_invite(email, base_url, roles=…)`.
  Jeder verschickte Link hat **seinen eigenen Endpunkt**: `/auth/verify/{token}` (Adresse bestätigen),
  `/auth/invite/{token}` (Einladung), `/auth/reset?token=…` (Passwort zurücksetzen). Sie hängen an
  ihrer eigenen Funktion, nicht am Magic-Link — `magiclink_enabled=False` nimmt Bestätigung und
  Einladung nicht mehr mit.
- **Konto-Seite:** eingebaut unter `/auth/account` (`account_enabled`) — Passwort/PIN/2FA/Passkeys/Keys.
- **Forward-Auth:** `forward_auth_enabled` → `GET /auth/forward` (200 + `Remote-User/Groups/Email` bzw.
  401 + `X-TinySesam-Location`). Beispiele: [`deploy/forward-auth/`](../deploy/forward-auth/) (Caddy/nginx/Traefik;
  `nginx-pfad.conf` deckt den anderen häufigen Zuschnitt ab — ein Host, nur einzelne Pfade geschützt,
  dahinter statische Dateien und PHP).
  **Rollen am Proxy:** der Proxy sagt, was er verlangt — `GET /auth/forward?roles=redaktion,admin` oder
  Header `X-TinySesam-Roles`. Eine der genannten Rollen genügt; angemeldet, aber Rolle fehlt → **403**
  (kein 401, der schickte den Benutzer zum Login und von dort sofort zurück). Ohne die Angabe bleibt
  der Endpunkt binär wie bisher. Mehrere Angaben werden UND-verknüpft: ein Client, der selbst eine
  anhängt, kann die Prüfung nur verschärfen, nie aufweichen.
  **Welche Header hinausgehen**, steuert `forward_headers` — Vorgabe `Remote-User/-Name/-Email/-Groups`
  (der Authelia-Satz). Eine Zuordnung benennt sie um oder lässt sie weg: `{"user": "X-WEBAUTH-USER"}`
  verschickt genau diesen einen Header (Grafana-Stil), eine Liste denselben Wert unter mehreren Namen.
  Die Zuordnung ist die **vollständige** Liste — `email` wegzulassen ist der Weg, der App die Adresse
  nicht mehr zu geben. Beim Umbenennen den neuen Namen in der Proxy-Konfiguration mitziehen.
- **Open-Redirect-Schutz:** alle `?next=` laufen über `safe_next` (nur relative Pfade bzw.
  `trusted_redirect_hosts`; der Host der eigenen `base_url` zählt immer mit und muss dort nicht
  wiederholt werden). **`cookie_domain` für SSO über Subdomains** — und ohne das Feld gilt: Das
  Session-Cookie ist host-only, deshalb wird die Login-Seite **auf dem angefragten Host** gebaut
  statt auf `base_url`. Sonst setzte TinySesam das Cookie auf Host A und schickte den Browser nach
  Host B, wo es nicht mitgeschickt wird — eine Endlosschleife ohne Fehlermeldung. Dafür kommen nur
  Hosts aus `trusted_redirect_hosts` infrage, ein gefälschter `X-Forwarded-Host` biegt also
  niemanden um. `base_url` selbst bleibt unangetastet: OIDC-/SAML-Callbacks behalten ihre feste Adresse.

Vollständige Demo: [`examples/showcase.py`](../examples/showcase.py) — `/` ist die Projekt-Website selbst,
`/demo` ein Frontend, dessen Login-/Konto-/Admin-Panels **read-only Live-Vorschauen** der echten Seiten sind (`uvicorn examples.showcase:app`).

**Die Live-Demo ist ein Beispiel-Frontend, das mitgeliefert wird** — kein Bestandteil der Bibliothek
und keine Vorgabe. Sie zeigt einen Weg, die eingebauten Seiten einzubinden; Aussehen und Aufbau sind
frei ersetzbar. Wer TinySesam einbaut, bringt sein eigenes Frontend mit oder nimmt dieses als Vorlage.

## LDAP / lldap

Passwort-Login kann gegen ein Verzeichnis (lldap, OpenLDAP, AD) geprüft werden — als Backend hinter dem
normalen Passwort-Formular (Faktor `password`). `pip install 'tinysesam[ldap]'`:

```python
TinySesamConfig(
    ldap_enabled=True, ldap_url="ldap://lldap:3890",
    ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com",   # Direkt-Bind (lldap)
    # ODER Search-then-Bind: ldap_bind_dn=…, ldap_bind_password=…, ldap_user_base=…, ldap_user_filter="(uid={username})"
    ldap_allowed_groups=["staff"],   # optionales Gate (memberOf), leer = alle
    ldap_auto_create=True,           # unbekannten LDAP-User lokal anlegen
)
```
Lokale Passwörter und LDAP koexistieren (erst lokal, dann LDAP). Rollen/2FA/Ketten gelten wie sonst.

## SAML 2.0

SP-Login gegen einen SAML-IdP (ADFS, Okta, Keycloak, …). `pip install 'tinysesam[saml]'` (braucht System-`libxmlsec1`):

```python
TinySesamConfig(
    saml_enabled=True, base_url="https://app.example.com",
    saml_idp_sso_url="https://idp.example.com/sso",
    saml_idp_x509cert="MIID…",                 # IdP-Signaturzertifikat (PEM-Body)
    saml_attr_email="email", saml_attr_groups="groups", saml_allowed_groups=["staff"],
)
```
Routen: `/auth/saml/login` (→ IdP), `/auth/saml/acs` (Assertion, signaturgeprüft — von CSRF ausgenommen),
`/auth/saml/metadata` (SP-Metadaten für den IdP). Faktor `saml`, in Ketten kombinierbar.


> **`saml_idp_entity_id` setzen**, solange nicht sicher ist, dass sie der SSO-URL entspricht.
> Leer nimmt TinySesam an, der IdP nenne sich bei seiner SSO-URL. Keycloak (und andere) tun das
> nicht: dort ist sie `https://…/realms/<realm>`, während die SSO-URL auf `/protocol/saml` endet.
> Passt es nicht, wird **jede** Assertion mit `Invalid issuer` abgelehnt. Aus den IdP-Metadaten
> abschreiben (`entityID=`). Der Grund einer Ablehnung geht immer an den Logger
> `tinysesam.security` — nie an den Browser.

> **Nur SP-initiiert, und dafür braucht es `cookie_secure=True`.** Jede Assertion muss einen
> `AuthnRequest` beantworten, den diese App auch geschickt hat: `/auth/saml/login` legt die
> Request-ID in ein kurzlebiges Cookie, die ACS weist alles ab, dessen `InResponseTo` nicht dazu
> passt. Das schliesst Login-CSRF — ohne die Bindung konnte jeder mit einer gültigen Assertion
> sie in den Browser eines Fremden POSTen. Zwei Folgen: **IdP-initiierte Logins gibt es nicht
> mehr** (Einstieg ist `/auth/saml/login`), und das Cookie übersteht den Cross-Site-POST des IdP
> nur als `SameSite=None; Secure`. Mit `cookie_secure=False` bleibt es beim Wert aus
> `cookie_samesite`, den ein Browser bei diesem POST nicht mitschickt — für lokale Läufe und den
> TestClient in Ordnung, gegen einen echten IdP nicht. Der Grund steht im Log
> `tinysesam.security`.

> **Alle Felder auf einen Blick:** [`KONFIGURATION.md`](../KONFIGURATION.md) führt alle 120
> Config-Felder mit Typ, Vorgabe und Bedeutung — erzeugt aus `config.py`, kann also nicht
> auseinanderlaufen. Diese README erklärt die *Wege*; jene Seite beantwortet *„es gibt da ein
> Feld — was tut es?"*

## Presets

Fertige Config-Presets für gängige Fälle (Rest via `**overrides`, z. B. `db_path=`):

```python
# Active Directory (on-prem, via LDAP) — Direkt-Bind per UPN oder Search-then-Bind
TinySesamConfig.active_directory(ldap_url="ldaps://dc.corp:636", upn_suffix="corp.example.com", db_path="app.db")

# Entra ID / Azure AD (Cloud-AD, via OIDC)
TinySesamConfig.entra_id(tenant_id="…", client_id="…", client_secret="…", db_path="app.db")

# Reines OIDC-Forward-Auth-Gateway (siehe unten)
TinySesamConfig.oidc_gateway(issuer="…", client_id="…", client_secret="…", base_url="…")
```

## Als reines OIDC-Gateway (Preset)

Wer nur **OIDC-SSO vor beliebige Apps** will (Authelia-/oauth2-proxy-Stil), betreibt TinySesam als
Forward-Auth-**Gateway** — ohne eigene App, nur `pip install 'tinysesam[gateway]'`:
(`[gateway]` = `[oidc]` **plus ASGI-Server**. Mit `[oidc]` allein endet der Startbefehl unten
in `ModuleNotFoundError: uvicorn` — genau diese Kombination stand hier vorher.)

```bash
export TINYSESAM_OIDC_ISSUER=https://id.example.com \
       TINYSESAM_OIDC_CLIENT_ID=gateway TINYSESAM_OIDC_CLIENT_SECRET=… \
       TINYSESAM_BASE_URL=https://auth.example.com \
       TINYSESAM_COOKIE_DOMAIN=.example.com \
       TINYSESAM_PROTECTED_HOSTS=app.example.com,wiki.example.com
python -m tinysesam.gateway          # oder: uvicorn tinysesam.gateway:app
```

Der Reverse-Proxy ruft je Request `GET /auth/forward`. Der Gateway hängt den vollen
`/auth/*`-Router ein — mit `password_enabled=False` und OIDC als einziger Methode bleiben davon
der OIDC-Login, der Forward-Auth-Endpunkt, Logout und `/me`. Eine schmale Konfiguration also,
keine Ein-Routen-App.
Programmatisch: `TinySesamConfig.oidc_gateway(issuer=…, client_id=…, client_secret=…, base_url=…)`.
Fertiges [`deploy/forward-auth/docker-compose.yml`](../deploy/forward-auth/) (Gateway + Caddy) liegt bei.

## Tests & CI

```bash
pip install -e '.[all]' setuptools         # + httpx für den FastAPI-TestClient (in [all] enthalten)
python tests/run_all.py                    # alle Suiten; Exit 0 = grün, 1 = Fehlschlag
python tests/run_all.py core pin chain     # gezielt einzelne
```

Die Suiten sind eigenständige assert-Skripte (kein pytest). Drei davon beantworten die Frage
„ist etwas kaputt?", ohne dass du hinschauen musst:

- **`tests/test_browser.py`** fährt einen headless Chrome über das DevTools-Protokoll gegen das laufende
  Showcase und prüft, was ein Nutzer wirklich sieht: keine Konsolenfehler, keine fehlschlagenden Anfragen,
  Kopf/Nav/Fußzeile auf jeder Seite, gleiche Breiten, `?lang=`-Umschaltung, Dunkelmodus bis in die
  Vorschau-iframes, den Login (samt simuliertem Passwort-Autofill) und dass ein leeres Formular eine
  Meldung liefert statt einer 422-JSON-Wand. Wird übersprungen, wenn Chrome oder `websockets` fehlen.
- **`tests/test_repo.py`** bewacht die Hygiene: Versionen in `pyproject.toml`, `__init__.py` und Changelog
  stimmen überein; kein generiertes HTML, keine Geheimnisse, kein vergessenes `print()` in der Bibliothek;
  Farbwerte nur in `theme.py`/`theme.css`; jede Suite läuft im Sammellauf mit.
- **`tests/test_site.py`** prüft die erzeugte Website: beide Sprachen je Datei, ein `?lang=`-Mechanismus,
  überall derselbe Rumpf, Impressum vollständig.
- **`tests/test_packaging.py`** baut Wheel und sdist und sieht hinein: Alles, was das Paket braucht,
  ist wirklich drin, die Metadaten sind die, die PyPI erwartet, und veröffentlicht wird ohne Geheimnis.
  (`setuptools` muss installiert sein — ohne Bau-Backend prüfte die Suite nichts.)

**Vor jedem Push** — ein Tor, lokal:

```bash
git config core.hooksPath .githooks   # einmal pro Klon: der pre-push-Hook fährt das Tor
scripts/check.sh                      # Suiten + Browser + Hygiene + Website-Build
scripts/check.sh --fast               # ohne Browser-Test (nur wenn es eilt)
gh run watch --exit-status            # nach dem Push: CI-Ergebnis abholen, Exit != 0 bei Rot
```

**GitHub Actions** fährt das bei **Push auf `main`, bei Pull Requests und auf Zuruf**
(`workflow_dispatch`) — ein Push auf einen Feature-Branch löst bewusst nichts aus; dafür ist
`scripts/check.sh` da. Die CI fährt den vollen Lauf (Python 3.10–3.14 mit `[all]`), einen
Minimal-Lauf ohne Extras (sichert den stdlib-scrypt-Fallback) und einen Browser-Job, der
zusätzlich die Website baut.

## Status

**46 Testdateien, alle grün** — eine je Funktion, dazu eine Kombinations-Matrix
(`tests/test_matrix.py`).

Gebaut und getestet: Passwort/TOTP/Sitzungen/Rollen, Remember-me, Step-up und per-Route-MFA,
Faktor-Ketten, persönliche PIN, geteilte Ressourcen-Geheimnisse, Magic-Links + Mailer-Hook,
Registrierung und Einladung, Konto-Seite, Passwort-vergessen und TOTP-Recovery-Codes,
Sitzungsverwaltung, API-Keys und Service-Konten, Admin-Panel (oder nur dessen JSON-API),
Forward-Auth samt OIDC-Gateway, eine nonce-basierte CSP und die Kommandozeile (`backup`,
`restore`, `gc`, `audit`, `unlock`).

Externe Identitätsanbieter — OIDC, SAML 2.0, LDAP/AD — und Passkeys sind gebaut und gegen einen
echten Provider auf einer Bühne geprüft (`tests/e2e_stage.py`); die mitgelieferten Tests decken
sie strukturell ab, weil sie nicht nach draussen telefonieren können.

Zwei Sicherheitsaudits sind im September 2026 durch den Code gegangen (siehe `CHANGELOG`). Die
Version ist bewusst noch **nicht** 1.0: Die API-Oberfläche muss dafür zwei Minor-Versionen
stillhalten.

MIT-Lizenz.

## Credits

Icon: <a href="https://www.flaticon.com/authors/maxicons" target="_blank" rel="noopener">Wizard PNG Image by max.icons - flaticon.com</a>

<p align="center"><img src="docs/wizard.png" alt="TinySesam" width="104" height="104"></p>

<h1 align="center">TinySesam</h1>

<p align="center"><a href="README.md">English</a> · <b>Deutsch</b></p>

[![tests](https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml/badge.svg)](https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)

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

Direkt von GitHub (nicht auf PyPI):

```bash
GH="git+https://github.com/Ollornog/TinySesam.git"
pip install "tinysesam @ $GH"          # Kern: Passwort + TOTP
pip install "tinysesam[all] @ $GH"     # alles: + argon2, QR, OIDC, Passkey
# gezielt: [argon2] [qr] [oidc] [passkey]  ·  Version pinnen: …@git+…@v0.5.0
```

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

## Guards

```python
Depends(auth.require_user)             # eingeloggt (das braucht paperlaiss)
Depends(auth.require_admin)            # eingeloggt + is_admin
Depends(auth.require_role("editor"))   # eingeloggt + Rolle (Admin hat implizit alle)
```

## Rollen & Gruppen

**Rollen sind die Gruppen** — pro User eine Liste (`roles`) + `is_admin`; Guard `require_role("…")`.
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
| `GET /auth/logout` · `GET /auth/me` | Abmelden · aktueller User (JSON) |

## Konfiguration (`TinySesamConfig`, Auszug)

| Feld | Default | |
|---|---|---|
| `db_path` | `tinysesam.db` | SQLite-Store |
| `password_enabled` / `passkey_enabled` / `oidc_enabled` | `True/True/False` | aktive Methoden |
| `totp_enabled` / `totp_required` | `True/False` | 2FA erlauben / erzwingen |
| `session_ttl_hours` · `cookie_secure` · `cookie_samesite` | `168` · `True` · `lax` | Sessions/Cookie |
| `rp_id` · `origin` | `localhost` · … | WebAuthn (echte Domain nötig, HTTPS) |
| `oidc_issuer/_client_id/_client_secret/_scopes` | – | OIDC-Provider |
| `oidc_auto_create` · `oidc_allowed_groups` · `oidc_group_claim` | `True` · `[]` · `groups` | Auto-Anlage + Gruppen-Gate |
| `base_url` · `login_redirect` · `logout_redirect` | – · `/` · … | App-Integration |

## Sprache (i18n)

Die eingebauten Texte sind **standardmäßig Englisch** (`lang="en"`); mitgeliefert ist auch **Deutsch**:

```python
TinySesamConfig(lang="de")                       # eingebaute Seiten + Meldungen auf Deutsch
auth.add_messages("fr", {"login.submit": "Se connecter", ...})   # eigene Sprache/Überschreibung
```
Einzelne Texte oder ganze Seiten lassen sich zusätzlich per `auth.set_template(...)` frei ersetzen.

## Eigene Login-Seite

TinySesam als reines Backend nutzen (eigene UI) — die Bausteine sind öffentlich:
`auth.check_password(u,p)`, `auth.start_session(uid, "password")`, `auth.set_cookie(resp, token)`,
`auth.verify_totp(uid, code)`, `auth.complete_mfa(token)`.

## Look & Feel

Jede eingebaute Seite (Login, PIN, TOTP, Konto, Admin-Panel, Fehlerseiten) stylt sich über **einen Satz
CSS-Variablen** — kein Selektor muss je Seite nachgebaut werden. In `brand_css` überschreiben, fertig:

```python
TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-surface:#fbf8f4;--ts-ink:#2b2a3a;--ts-accent:#b0566f}")
```

Die Tokens (und ihre Defaults) stehen in [`tinysesam/theme.py`](tinysesam/theme.py); `brand_head` hängt
zusätzliches `<head>`-Markup ein. `auth.install_error_pages(app)` liefert Browsern gebrandete 403/404/500-Seiten,
API-Clients weiterhin JSON. Mehr als Farben nötig? Ganze Seite per `auth.set_template(...)` ersetzen.

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
  (`failed login … ip=…`). Filter + Jail in [`deploy/fail2ban/`](deploy/fail2ban/) → IP-Ban auf Firewall-Ebene.
- **Echte Client-IP hinter Proxy:** `X-Forwarded-For` gilt nur, wenn der direkte Peer in `trusted_proxies`
  steht — sonst ist die IP fälschbar.
- **Audit-Log:** Login / Logout / Fehlversuche in der DB (`store.recent_audit()`), fürs Admin-Panel.
- **CSRF:** Double-Submit-Token (`csrf_enabled`, Default an) auf allen state-ändernden POSTs — die
  eingebauten Formulare/JS erledigen das automatisch (`_csrf`-Feld bzw. `X-CSRF-Token`-Header);
  API-Key-Requests sind ausgenommen (kein Cookie-Risiko). Zusätzlich zu `SameSite=Lax`.
- **Rate-Limit prozessübergreifend:** optional Redis (`redis_url`, Extra `[redis]`) für Multi-Worker; sonst In-Memory.
- **User-Enumeration:** Login/PIN prüfen auch bei unbekanntem Benutzer gegen einen Dummy-Hash (kein Timing-Leak).
- **Nach Passwortwechsel** werden die übrigen Sitzungen des Users beendet (Admin-Reset: alle).
- **Housekeeping:** `auth.gc()` löscht abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte
  Login-Versuche (Audit-Log bleibt). Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen.

## Update (von GitHub, versioniert)

Auch eingebettet in eine andere App kann TinySesam sich von GitHub aktualisieren:

- **Programmatisch** (fürs Admin-Panel): `tinysesam.update_available()` → `{current, latest, available}`;
  über den Manager `auth.update_status()` / `auth.run_update()`.
- **CLI:** `python -m tinysesam check` · `python -m tinysesam update [ref]` (nach Install auch `tinysesam …`).
- **In den Einstellungen** (Store, Panel-editierbar):
  - **Modus** `manual` | `auto` (`auth.set_update_setting("mode", …)`) — `auth.auto_update()` beim Start/per Cron
    zieht im Auto-Modus ein verfügbares Update.
  - **Version-Pin** (`auth.set_update_setting("pin", "v0.2.0")`) — hält exakt auf dieser Version; leer = neueste.
- Quelle: `git+https://github.com/Ollornog/TinySesam.git@<ref>` (öffentlich). Privat/SSH: `TINYSESAM_GIT_URL`
  bzw. `scheme="ssh"`. **Nach dem Update Host-App neu starten** (Python lädt Code nicht zur Laufzeit neu).

## API-Keys & Service-/Daemon-Accounts

Für **maschinellen Zugang** (Skripte, andere Dienste, System-Daemons) — parallel zum interaktiven Login:

- Ein API-Key gehört einem User, liegt **gehasht** (sha256) in der DB, optional mit **Ablauf** und **Rollen-Scope**.
- Gesendet als `Authorization: Bearer tsk_…` **oder** `X-API-Key: tsk_…`.
- **`require_user` akzeptiert Session ODER gültigen Key** — geschützte Routen sind ohne Änderung auch per Key erreichbar; `require_role(...)` respektiert den Key-Scope.
- **System-Daemons** = **Service-Account** (`auth.create_service("backup-daemon", roles=["reader"])`, kein Login/MFA) + Key (`auth.create_api_key(uid, name=…, expires_days=…)` → Klartext **einmalig**). Least-Privilege über die Rollen.
- **Sperren statt löschen:** `auth.revoke_api_key(id)` (Key gesperrt, bleibt in der Liste). Self-Service-Routen: `GET/POST /auth/apikeys`, `POST /auth/apikeys/{id}/revoke`.

## Admin-Panel

Eingebautes Panel unter **`/auth/admin`** (nur `is_admin`), einbindbar ohne Extra-Setup:

- **Benutzer & Service-Accounts:** anlegen, **explizit sperren/entsperren** (`disabled` — Konto bleibt, Login blockiert, Sitzungen enden sofort; Selbst-Sperr-Schutz), Passwort-Reset, Rollen/Admin setzen.
- **API-Keys** je User: erzeugen (einmalige Anzeige) / widerrufen.
- **Sitzungen:** aktive einsehen + beenden.
- **Härtung:** Schwellen (Versuche/Sperrzeit/Rate-Limit) live einstellen.
- **Update:** Version/Status, Modus manual/auto, Version-Pin, „jetzt aktualisieren".
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

## Neu in 0.5 — Kurzreferenz

Alles optional (per Config an/aus), einzeln und kombiniert nutzbar, Frontend überall ersetzbar.

- **Frontend austauschbar:** `auth.set_template(name, fn)` — `fn(auth, ctx)` gibt HTML-String **oder**
  eine eigene `Response` zurück; Namen: `login`, `totp`, `reauth`, `resource_unlock`, `magic_request`,
  `magic_invalid`, `register`, `account`, `totp_setup`. Eingebaute Renderer sind Fallback.
- **Angemeldet bleiben:** `remember_me_enabled` — Checkbox → persistentes Cookie; ohne Haken reines
  Session-Cookie + kurze `session_ttl_transient_hours`.
- **Step-up / per-Route-MFA:** `Depends(auth.require(mfa=True))` (Sudo-Frische `stepup_max_age_sec`,
  → `/auth/reauth`). `admin_require_mfa=True` schützt das Panel zusätzlich mit frischer Bestätigung.
- **Faktor-Ketten (geordnet):** `login_chain=["oidc","password"]` + `login_chain_strict`; pro Route
  `require(factors=[...], strict=...)`. Faktoren: `password, pin, oidc, passkey, totp, magic`.
- **PIN pro User:** `pin_enabled` — Benutzer+PIN, eigener strenger Lockout, mit TOTP kombinierbar.
- **Geteiltes Ressourcen-Geheimnis:** `resource_locks_enabled` — `auth.set_resource_secret(name, secret,
  kind="pin"|"password")`, Guard `Depends(auth.require_resource(name))`, ganz ohne Benutzerkonto.
- **Magic-Link:** `magiclink_enabled` + SMTP-Config **oder** `auth.set_mailer(fn)`; `/auth/magic/request`.
- **Registrierung + Einladung:** `allow_signup` (+ `signup_verify_email`, `signup_invite_only`);
  Admin-Einladung `auth.create_invite(email, base_url, roles=…)`.
- **Konto-Seite:** eingebaut unter `/auth/account` (`account_enabled`) — Passwort/PIN/2FA/Passkeys/Keys.
- **Forward-Auth:** `forward_auth_enabled` → `GET /auth/forward` (200 + `Remote-User/Groups/Email` bzw.
  401 + `X-TinySesam-Location`). Beispiele: [`deploy/forward-auth/`](deploy/forward-auth/) (Caddy/nginx/Traefik).
- **Open-Redirect-Schutz:** alle `?next=` laufen über `safe_next` (nur relative Pfade bzw.
  `trusted_redirect_hosts`). `cookie_domain` für SSO über Subdomains.

Vollständige Demo: [`examples/showcase.py`](examples/showcase.py) — `/` ist die Projekt-Website selbst,
`/demo` ein Frontend, dessen Login-/Konto-/Admin-Panels **read-only Live-Vorschauen** der echten Seiten sind (`uvicorn examples.showcase:app`).

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
Forward-Auth-**Gateway** — ohne eigene App, nur `pip install 'tinysesam[oidc]'`:

```bash
export TINYSESAM_OIDC_ISSUER=https://id.example.com \
       TINYSESAM_OIDC_CLIENT_ID=gateway TINYSESAM_OIDC_CLIENT_SECRET=… \
       TINYSESAM_BASE_URL=https://auth.example.com \
       TINYSESAM_COOKIE_DOMAIN=.example.com \
       TINYSESAM_PROTECTED_HOSTS=app.example.com,wiki.example.com
python -m tinysesam.gateway          # oder: uvicorn tinysesam.gateway:app
```

Der Reverse-Proxy ruft je Request `GET /auth/forward`; alle anderen Methoden/Routen sind aus.
Programmatisch: `TinySesamConfig.oidc_gateway(issuer=…, client_id=…, client_secret=…, base_url=…)`.
Fertiges [`deploy/forward-auth/docker-compose.yml`](deploy/forward-auth/) (Gateway + Caddy) liegt bei.

## Tests & CI

```bash
pip install -e '.[all]'        # + httpx wird für den FastAPI-TestClient gebraucht (in [all] enthalten)
python tests/run_all.py         # alle Suiten; Exit 0 = grün, 1 = Fehlschlag
python tests/run_all.py core pin chain   # gezielt einzelne
```

Die Suiten sind eigenständige assert-Skripte (kein pytest). **GitHub-Actions-CI**
(`.github/workflows/ci.yml`) fährt bei **jedem Push/PR** automatisch: den vollen Lauf über
Python 3.10–3.13 (`.[all]`) **und** einen Minimal-Lauf ohne Extras (sichert den stdlib-scrypt-Fallback;
Passkey/OIDC-abhängige Suiten werden dabei übersprungen). Fürs Update also einfach pushen — CI testet.

## Status

Kern (Passwort/TOTP/Sessions/Rollen), Härtung, API-Keys/Service-Accounts, Admin-Panel und
Update-Mechanismus: implementiert & getestet. **Neu in 0.5** — Remember-me, Step-up/per-Route-MFA,
Faktor-Ketten, persönliche PIN, geteiltes Ressourcen-Geheimnis, Magic-Link + Mailer-Hook,
Registrierung + Einladung, Konto-Seite, Forward-Auth: je mit eigenem Test (`tests/test_*.py`),
plus Kombinations-Matrix (`tests/test_matrix.py`). 17 Testdateien, alle grün.
OIDC + Passkey: implementiert, struktur-getestet; der Browser-/Provider-abhängige End-to-End-Pfad
ist gegen echte Domain/echten Provider zu prüfen. **0.6** ergänzt LDAP/lldap-Backend, TOTP-Recovery-Codes,
Passwort-vergessen, eigene Sitzungsverwaltung, optionalen OIDC-RP-Logout sowie Härtung (Session-Invalidierung
nach PW-Wechsel, Anti-Enumeration, `auth.gc()`, `py.typed`). Insgesamt **22 Testdateien, alle grün**.

MIT-Lizenz.

## Credits

Icon: <a href="https://www.flaticon.com/free-icons/wizard" title="wizard icons">Wizard icons created by max.icons - Flaticon</a>

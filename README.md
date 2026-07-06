# TinySesam

Kleines, wiederverwendbares **Multi-Methoden-Auth für FastAPI**. Eine Klasse davorhängen, fertig —
Login-Seite, Sessions und Guards inklusive. Gedacht als Baustein für eigene Apps (z.B. paperlaiss).

**Methoden — alle parallel aktivierbar:**
- 🔑 **Passkey / WebAuthn** (passwortlos, phishing-resistent)
- 🔐 **Passwort** (argon2, mit stdlib-scrypt-Fallback)
- 🌐 **OIDC** (generischer IdProvider: PocketID, Keycloak, …)
- 📱 **TOTP** als 2. Faktor *on-top* zu Passwort/OIDC (Passkeys gelten schon als vollwertig)

**Rollen sind optional:** die meisten Apps brauchen nur „eingeloggt / nicht" (`require_user`).
Wer differenzieren will: `is_admin` + frei definierbare `roles` (`require_admin`, `require_role("editor")`).

---

## Installation

```bash
pip install tinysesam                 # Kern: Passwort + TOTP
pip install 'tinysesam[all]'          # alles: + argon2, QR, OIDC, Passkey
# gezielt: [argon2] [qr] [oidc] [passkey]
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

## Eigene Login-Seite

TinySesam als reines Backend nutzen (eigene UI) — die Bausteine sind öffentlich:
`auth.check_password(u,p)`, `auth.start_session(uid, "password")`, `auth.set_cookie(resp, token)`,
`auth.verify_totp(uid, code)`, `auth.complete_mfa(token)`.

## Sicherheit

- Passwörter: **argon2id** (Fallback **scrypt**, n=2¹⁵). Sessions **server-side** (in SQLite, jederzeit revozierbar).
- Session-Cookie: `HttpOnly`, `Secure` (Default), `SameSite=Lax`.
- OIDC: `state` + `nonce` im Store (nicht im Client), ID-Token gegen **JWKS** + `iss`/`aud`/`exp` verifiziert.
- WebAuthn: Challenge im Store, an httponly-Cookie gebunden; `sign_count`-Klon-Erkennung.
- **Produktiv immer hinter HTTPS.** `rp_id`/`origin` müssen exakt zur Domain passen.

## Status

Passwort + TOTP + Sessions + Rollen: implementiert & getestet (`tests/test_core.py`).
OIDC + Passkey: implementiert, Routen/Options struktur-getestet (`tests/test_methods.py`); der
Browser-/Provider-abhängige End-to-End-Pfad ist gegen echte Domain/echten Provider zu prüfen.

MIT-Lizenz.

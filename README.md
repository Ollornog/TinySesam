<p align="center"><img src="docs/wizard.png" alt="TinySesam" width="104" height="104"></p>

<h1 align="center">TinySesam</h1>

<p align="center"><b>English</b> · <a href="README.de.md">Deutsch</a></p>

[![tests](https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml/badge.svg)](https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)

### The login layer for your self-built apps.

**Super-light auth for FastAPI** where you **use only what you need** — and that grows with you.
Hang one class in front of your app, done: login page, sessions and route guards included.

- **Just gate one page behind a PIN?** → yes. (`require_resource("fotos")`, no user account at all)
- **Forward-auth in front of other apps, like TinyAuth?** → it can. (`/auth/forward` or an OIDC gateway)
- **An admin panel?** → built in. **Prefer it inside your own?** → that too (JSON API only).
- **From “a password is enough” to “OIDC → password → TOTP”?** → grows with you — every piece **optional, on/off by config**.
- **Your own look & feel?** → the whole **front end is replaceable** (`auth.set_template(...)`), including language (en/de).

> **A quick word on positioning:** TinySesam secures **your own (self-built) apps** and **consumes** existing
> identity providers (OIDC, SAML, LDAP/AD) as a *client / relying party*. It is **not an identity provider itself** —
> so **no replacement** for Keycloak/Authentik/PocketID, but the lean auth layer **in front of or inside** your app.

**Sign-in methods — freely combinable:**
- 🔑 **Passkey / WebAuthn** (passwordless, phishing-resistant)
- 🔐 **Password** (argon2, with stdlib-scrypt fallback)
- 🔢 **PIN** (personal PIN per user, its own strict lockout)
- 🌐 **OIDC** (generic IdProvider: PocketID, Keycloak, Entra/Azure AD, …)
- 🪪 **SAML 2.0** (SP login against ADFS, Okta, Keycloak, …)
- 🗂️ **LDAP / Active Directory** (password against a directory bind)
- ✉️ **Magic-link** (one-time login by email)
- 📱 **TOTP** as a 2nd factor *on top* (+ **recovery codes**; passkeys already count as full-strength)

**Combinable in order:**
any **factor chains** (`login_chain=["oidc","password"]`),
global or per route (`Depends(auth.require(factors=[...], strict=...))`).

**Roles are optional:**
most apps only need “logged in / not” (`require_user`).
If you want to differentiate: `is_admin` + freely defined `roles` (`require_admin`, `require_role("editor")`).

**More:**
“stay signed in”,
**step-up** per route (`require(mfa=True)`),
**self-registration** + **invitations**,
**forgot password**,
shared **resource secret** (PIN/passphrase without an account),
built-in **account page** (including your own sessions + recovery codes),
**forward-auth** for other apps

every feature optional, on/off by config,
and the whole **front end replaceable** (`auth.set_template(...)`).

---

## Installation

Straight from GitHub (not on PyPI):

```bash
GH="git+https://github.com/Ollornog/TinySesam.git"
pip install "tinysesam @ $GH"          # core: password + TOTP
pip install "tinysesam[all] @ $GH"     # everything: + argon2, QR, OIDC, passkey
# selective: [argon2] [qr] [oidc] [passkey]  ·  pin a version: …@git+…@v0.5.0
```

## Quickstart

```python
from fastapi import FastAPI, Depends
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    rp_id="app.example.com",           # domain (WebAuthn), no scheme/port
    origin="https://app.example.com",  # exact browser origin
    passkey_enabled=True,
    oidc_enabled=True,
    oidc_issuer="https://id.example.com",
    oidc_client_id="…", oidc_client_secret="…",
))
auth.ensure_admin("admin", "initial-password")   # creates an admin, ONLY if the store is empty

app = FastAPI()
app.include_router(auth.router())              # /auth/* + login UI

@app.get("/")
def home(user = Depends(auth.require_user)):    # protected: logged in (incl. 2FA)
    return {"hi": user["username"]}
```

Non-logged-in browsers are redirected to `/auth/login`; API clients (Accept ≠ HTML) get a `401`.

## Sign-in identifier

Who signs in with what is one config field — `login_identifier`:

```python
TinySesamConfig(login_identifier="both")      # username OR email in the same field (default)
TinySesamConfig(login_identifier="username")  # username only
TinySesamConfig(login_identifier="email")     # email only
```

The label of the field follows automatically, and password *and* PIN login both honour it.
Because the email is a login identifier, it is stored canonically (trimmed, lower-cased) and is
**unique** (partial UNIQUE index; accounts without an email stay allowed). Registration requires it
by default — `signup_require_email=False` turns that off. In `"email"` mode the registration form
drops the username field entirely: the address *is* the identifier. `signup_verify_email=True` activates the
account only after the confirmation link is clicked; it needs a mailer (`set_mailer` or SMTP config)
and refuses to register otherwise instead of silently skipping the check.

## Guards

```python
Depends(auth.require_user)             # logged in (this is what paperlaiss needs)
Depends(auth.require_admin)            # logged in + is_admin
Depends(auth.require_role("editor"))   # logged in + role (admin implicitly has all)
```

## Roles & groups

**Roles are the groups** — a list per user (`roles`) + `is_admin`; guard `require_role("…")`.
An admin satisfies **every** role. If you don't want that (e.g. because permissions come from an IdP
group): `admin_implies_roles=False` globally, or `require_role("editor", admin_implies=False)` per route.
- **Local user/password:** assign roles per user in the **admin panel**. `available_roles=[…]` defines known
  roles → the panel shows them as **checkboxes** (empty = free-text entry).
- **IdP users (OIDC/SAML/LDAP/AD):** automatically map external groups onto local roles —
  `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`, e.g.
  `{"editors": "editor", "cn=admins,ou=g": "__admin__"}` (target `__admin__` = admin flag). Set at login;
  mapped roles are synchronized, manually assigned ones stay. The same `require_role(...)` guards everywhere.

## Routes (provided by the router)

| Route | Purpose |
|---|---|
| `GET/POST /auth/login` | password login + login page (shows active methods) |
| `GET/POST /auth/totp` | 2nd factor after password/OIDC |
| `GET/POST /auth/totp/setup` · `POST /auth/totp/disable` | set up / turn off TOTP |
| `GET /auth/oidc/start` · `/auth/oidc/callback` | OIDC flow *(when enabled)* |
| `POST /auth/passkey/{register,login}/{begin,finish}` | WebAuthn *(when enabled)* |
| `GET /auth/passkey/list` · `POST /auth/passkey/delete` | manage passkeys |
| `GET /auth/logout` · `GET /auth/me` | log out · current user (JSON) |

## Configuration (`TinySesamConfig`, excerpt)

| Field | Default | |
|---|---|---|
| `db_path` | `tinysesam.db` | SQLite store |
| `password_enabled` / `passkey_enabled` / `oidc_enabled` | `True/True/False` | active methods |
| `totp_enabled` / `totp_required` | `True/False` | allow / enforce 2FA |
| `session_ttl_hours` · `cookie_secure` · `cookie_samesite` | `168` · `True` · `lax` | sessions/cookie |
| `rp_id` · `origin` | `localhost` · … | WebAuthn (real domain required, HTTPS) |
| `oidc_issuer/_client_id/_client_secret/_scopes` | – | OIDC provider |
| `oidc_auto_create` · `oidc_allowed_groups` · `oidc_group_claim` | `True` · `[]` · `groups` | auto-create + group gate |
| `base_url` · `login_redirect` · `logout_redirect` | – · `/` · … | app integration |

## Language (i18n)

The built-in texts are **English by default** (`lang="en"`); **German** ships too:

```python
TinySesamConfig(lang="de")                       # built-in pages + messages in German
auth.add_messages("fr", {"login.submit": "Se connecter", ...})   # your own language/override
```
Individual texts or whole pages can additionally be freely replaced via `auth.set_template(...)`.

## Your own login page

Use TinySesam as a pure backend (your own UI) — the building blocks are public:
`auth.check_password(u,p)`, `auth.start_session(uid, "password")`, `auth.set_cookie(resp, token)`,
`auth.verify_totp(uid, code)`, `auth.complete_mfa(token)`.

## Look & feel

Every built-in page (login, PIN, TOTP, account, admin panel, error pages) is styled from **one set of
CSS variables** — no per-page selectors to rebuild. Override them in `brand_css` and all pages follow:

```python
TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-surface:#fbf8f4;--ts-ink:#2b2a3a;--ts-accent:#b0566f}")
```

The tokens (and their defaults) live in [`tinysesam/theme.py`](tinysesam/theme.py); `brand_head` injects
extra `<head>` markup and `brand_icon` sets the favicon on every built-in page. `auth.install_error_pages(app)` gives browsers themed 403/404/500 pages while API
clients keep getting JSON. Need more than colors? Replace a whole page with `auth.set_template(...)`.

## PIN, and step-up for sensitive routes

A PIN does not have to be a way in. `pin_login=False` keeps the PIN off the login page and leaves it
as an *extra* factor:

```python
TinySesamConfig.local_accounts(          # username + password only, no email anywhere
    pin_enabled=True, pin_login=False,   # a PIN exists, but you cannot sign in with it
    stepup_methods=["pin"],              # sensitive routes ask for it, even while signed in
)
```

- `Depends(auth.require(mfa=True))` → the route demands a *fresh* confirmation. `/auth/reauth` offers
  TOTP, PIN or password — restricted by `stepup_methods`, otherwise whatever the user has set up
  (`auth.stepup_options(user)`). Freshness expires after `stepup_max_age_sec`.
- `Depends(auth.require(factors=["password", "pin"]))` → an ordered chain per route. Someone already
  signed in only gets the missing field, not the whole login page again.

## Bootstrapping the first admin

Open registration plus “the first account becomes admin” is a race: whoever finds the fresh instance
first wins it. TinySesam therefore offers two explicit paths, **both only while no admin exists**:

```python
TinySesamConfig(admin_identifiers=["me@example.com"])   # allowlist, any sign-in method
```

- **Allowlist** — the named username or email is promoted on its next successful sign-in, whatever the
  method (also OIDC/SAML/LDAP, where the email is usually the stable handle). After that: never again.
- **One-time token** — if no admin exists, TinySesam logs a claim URL on startup. Sign in, open
  `/auth/claim-admin?token=…`, and that account becomes admin. The token is single-use and expires
  after `admin_claim_ttl_min`; once an admin exists the route answers 404.

Alternatively `auth.ensure_admin("admin", os.environ["INITIAL_PW"])` seeds an admin before the app
ever serves a request — best when you deploy from a script.

## Demo mode

`demo_mode=True` creates the accounts `demo` and `demoadmin`, shows their credentials on the sign-in
page (and the PIN on the PIN page) and states plainly that it must be off in production. Turning it
off deletes exactly those accounts on the next start. Never enable it on a public instance.

## Security

- Passwords: **argon2id** (fallback **scrypt**, n=2¹⁵). Sessions **server-side** (in SQLite, revocable at any time).
- Session cookie: `HttpOnly`, `Secure` (default), `SameSite=Lax`.
- OIDC: `state` + `nonce` in the store (not in the client), ID token verified against **JWKS** + `iss`/`aud`/`exp`.
- WebAuthn: challenge in the store, bound to an httponly cookie; `sign_count` clone detection.
- **Always run behind HTTPS in production.** `rp_id`/`origin` must match the domain exactly.

## Hardening

Modeled on Authelia/Fail2Ban — the thresholds are changeable **in the admin panel / at runtime**
(`auth.set_security(key, value)`, defaults in `security.SECURITY_DEFAULTS`):

- **Brute-force throttling:** failed attempts per **user *and* IP** are counted; after `max_login_attempts`
  within the `lockout_window_sec` window the login is locked — this also blocks the *correct* password.
  Applies to password and TOTP login (IP threshold higher because of NAT: `ip_attempt_factor`).
- **Rate limiting:** token bucket per IP on the login/2FA endpoints (`rate_limit_max` / `rate_limit_window_sec`).
- **fail2ban:** every failed attempt is logged via the `tinysesam.security` logger with the real client IP
  (`failed login … ip=…`). Filter + jail in [`deploy/fail2ban/`](deploy/fail2ban/) → IP ban at the firewall level.
- **Real client IP behind a proxy:** `X-Forwarded-For` is only trusted when the direct peer is listed
  in `trusted_proxies` — otherwise the IP is forgeable. **Start uvicorn without `--proxy-headers`.**
  With that flag uvicorn already rewrites `request.client.host` to the forwarded IP, so TinySesam's
  check has nothing left to verify and rate limiting, lockout and fail2ban can be bypassed.
- **Roles and admins:** by default an admin satisfies every `require_role(...)`. If an app derives its
  permissions purely from an IdP group, that is a silent privilege escalation — set
  `admin_implies_roles=False` (or `require_role(..., admin_implies=False)`).
- **IdP groups** are matched **exactly** against the keys of `*_group_role_map` (`group_match="exact"`).
  Substring matching (needed for LDAP `memberOf` DNs, and used there automatically) would let the key
  `admin` match a group called `not-admin`.
- **Audit log:** login / logout / failed attempts in the DB (`store.recent_audit()`), for the admin panel.
- **CSRF:** double-submit token (`csrf_enabled`, on by default) on all state-changing POSTs — the
  built-in forms/JS handle this automatically (`_csrf` field or `X-CSRF-Token` header);
  API-key requests are exempt (no cookie risk). In addition to `SameSite=Lax`.
  Rendering your own templates? `token = auth.issue_csrf(response)` sets the cookie and returns the value.
- **Rate limit across processes:** optional Redis (`redis_url`, extra `[redis]`) for multi-worker; otherwise in-memory.
- **User enumeration:** login/PIN check against a dummy hash even for an unknown user (no timing leak).
- **After a password change** the user’s remaining sessions are ended (admin reset: all).
- **Housekeeping:** `auth.gc()` deletes expired sessions/flows/magic tokens/resource unlocks + old
  login attempts (the audit log stays). Call it regularly (cron/startup/scheduler) — otherwise the tables grow.

## Update (from GitHub, versioned)

Even embedded in another app, TinySesam can update itself from GitHub:

- **Programmatically** (for the admin panel): `tinysesam.update_available()` → `{current, latest, available}`;
  via the manager `auth.update_status()` / `auth.run_update()`.
- **CLI:** `python -m tinysesam check` · `python -m tinysesam update [ref]` (after install also `tinysesam …`).
- **In the settings** (store, panel-editable):
  - **Mode** `manual` | `auto` (`auth.set_update_setting("mode", …)`) — `auth.auto_update()` at startup/via cron
    pulls an available update in auto mode.
  - **Version pin** (`auth.set_update_setting("pin", "v0.2.0")`) — stays exactly on this version; empty = latest.
- Source: `git+https://github.com/Ollornog/TinySesam.git@<ref>` (public). Private/SSH: `TINYSESAM_GIT_URL`
  or `scheme="ssh"`. **Restart the host app after an update** (Python does not reload code at runtime).

## API keys & service/daemon accounts

For **machine access** (scripts, other services, system daemons) — alongside the interactive login:

- An API key belongs to a user, sits **hashed** (sha256) in the DB, optionally with an **expiry** and **role scope**.
- Sent as `Authorization: Bearer tsk_…` **or** `X-API-Key: tsk_…`.
- **`require_user` accepts a session OR a valid key** — protected routes are reachable by key without any change; `require_role(...)` honors the key scope.
- **System daemons** = **service account** (`auth.create_service("backup-daemon", roles=["reader"])`, no login/MFA) + key (`auth.create_api_key(uid, name=…, expires_days=…)` → plaintext **once**). Least privilege via the roles.
- **Disable instead of delete:** `auth.revoke_api_key(id)` (key disabled, stays in the list). Self-service routes: `GET/POST /auth/apikeys`, `POST /auth/apikeys/{id}/revoke`.

## Admin panel

Built-in panel at **`/auth/admin`** (`is_admin` only), embeddable with no extra setup:

- **Users & service accounts:** create, **explicitly disable/enable** (`disabled` — account stays, login blocked, sessions end immediately; self-lockout protection), password reset, set roles/admin.
- **API keys** per user: generate (shown once) / revoke.
- **Sessions:** view active ones + end them.
- **Hardening:** tune the thresholds (attempts/lockout time/rate limit) live.
- **Update:** version/status, mode manual/auto, version pin, “update now”.
- **Audit log** view.

JSON API at `<mount>/api/*` (the same actions — for your own UIs / automation).

**Mount / embed / HTTPS:**
- **Default:** automatically under `config.admin_path` (default `/auth/admin`) — freely changeable.
- **Mount elsewhere:** `app.include_router(auth.admin_router(), prefix="/admin")` — any path,
  sub-app/**subdomain** (host routing of the app) or a **separate port** (standalone ASGI app). The UI figures
  out its base URL on its own. `admin_enabled=False` turns off the auto-mount.
- **Embed into an existing panel:** `admin_ui_enabled=False` → just the JSON API, your own UI in front.
- **HTTPS** (`config.https_mode` + `auth.install_https(app)`): `force` = HTTP→HTTPS redirect;
  `warn` = runs **even without a certificate**, but shows a warning in the panel; `off` = off.

## New in 0.5 — quick reference

All optional (on/off by config), usable individually and combined, front end replaceable everywhere.

- **Replaceable front end:** `auth.set_template(name, fn)` — `fn(auth, ctx)` returns an HTML string **or**
  its own `Response`; names: `login`, `totp`, `reauth`, `resource_unlock`, `magic_request`,
  `magic_invalid`, `register`, `account`, `totp_setup`. Built-in renderers are the fallback.
- **Stay signed in:** `remember_me_enabled` — checkbox → persistent cookie; unchecked = pure
  session cookie + short `session_ttl_transient_hours`.
- **Step-up / per-route MFA:** `Depends(auth.require(mfa=True))` (sudo freshness `stepup_max_age_sec`,
  → `/auth/reauth`). `admin_require_mfa=True` additionally protects the panel with a fresh confirmation.
- **Factor chains (ordered):** `login_chain=["oidc","password"]` + `login_chain_strict`; per route
  `require(factors=[...], strict=...)`. Factors: `password, pin, oidc, passkey, totp, magic`.
- **PIN per user:** `pin_enabled` — user+PIN, its own strict lockout, combinable with TOTP.
- **Shared resource secret:** `resource_locks_enabled` — `auth.set_resource_secret(name, secret,
  kind="pin"|"password")`, guard `Depends(auth.require_resource(name))`, with no user account at all.
- **Magic-link:** `magiclink_enabled` + SMTP config **or** `auth.set_mailer(fn)`; `/auth/magic/request`.
- **Registration + invitation:** `allow_signup` (+ `signup_verify_email`, `signup_invite_only`);
  admin invite `auth.create_invite(email, base_url, roles=…)`.
- **Account page:** built in at `/auth/account` (`account_enabled`) — password/PIN/2FA/passkeys/keys.
- **Forward-auth:** `forward_auth_enabled` → `GET /auth/forward` (200 + `Remote-User/Groups/Email` or
  401 + `X-TinySesam-Location`). Examples: [`deploy/forward-auth/`](deploy/forward-auth/) (Caddy/nginx/Traefik).
- **Open-redirect protection:** every `?next=` runs through `safe_next` (relative paths only, or
  `trusted_redirect_hosts`). `cookie_domain` for SSO across subdomains.

Full demo: [`examples/showcase.py`](examples/showcase.py) — `/` is the project website itself,
`/demo` a front end whose login/account/admin panels are **live read-only previews** of the real pages (`uvicorn examples.showcase:app`).

## LDAP / lldap

Password login can be checked against a directory (lldap, OpenLDAP, AD) — as a backend behind the
normal password form (factor `password`). `pip install 'tinysesam[ldap]'`:

```python
TinySesamConfig(
    ldap_enabled=True, ldap_url="ldap://lldap:3890",
    ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com",   # direct bind (lldap)
    # OR search-then-bind: ldap_bind_dn=…, ldap_bind_password=…, ldap_user_base=…, ldap_user_filter="(uid={username})"
    ldap_allowed_groups=["staff"],   # optional gate (memberOf), empty = all
    ldap_auto_create=True,           # create an unknown LDAP user locally
)
```
Local passwords and LDAP coexist (local first, then LDAP). Roles/2FA/chains apply as usual.

## SAML 2.0

SP login against a SAML IdP (ADFS, Okta, Keycloak, …). `pip install 'tinysesam[saml]'` (needs system `libxmlsec1`):

```python
TinySesamConfig(
    saml_enabled=True, base_url="https://app.example.com",
    saml_idp_sso_url="https://idp.example.com/sso",
    saml_idp_x509cert="MIID…",                 # IdP signing certificate (PEM body)
    saml_attr_email="email", saml_attr_groups="groups", saml_allowed_groups=["staff"],
)
```
Routes: `/auth/saml/login` (→ IdP), `/auth/saml/acs` (assertion, signature-checked — exempt from CSRF),
`/auth/saml/metadata` (SP metadata for the IdP). Factor `saml`, combinable in chains.

## Presets

Ready-made config presets for common cases (the rest via `**overrides`, e.g. `db_path=`):

```python
# Active Directory (on-prem, via LDAP) — direct bind by UPN or search-then-bind
TinySesamConfig.active_directory(ldap_url="ldaps://dc.corp:636", upn_suffix="corp.example.com", db_path="app.db")

# Entra ID / Azure AD (cloud AD, via OIDC)
TinySesamConfig.entra_id(tenant_id="…", client_id="…", client_secret="…", db_path="app.db")

# Pure OIDC forward-auth gateway (see below)
TinySesamConfig.oidc_gateway(issuer="…", client_id="…", client_secret="…", base_url="…")
```

## As a pure OIDC gateway (preset)

If you only want **OIDC SSO in front of arbitrary apps** (Authelia/oauth2-proxy style), run TinySesam as a
forward-auth **gateway** — no app of your own, just `pip install 'tinysesam[oidc]'`:

```bash
export TINYSESAM_OIDC_ISSUER=https://id.example.com \
       TINYSESAM_OIDC_CLIENT_ID=gateway TINYSESAM_OIDC_CLIENT_SECRET=… \
       TINYSESAM_BASE_URL=https://auth.example.com \
       TINYSESAM_COOKIE_DOMAIN=.example.com \
       TINYSESAM_PROTECTED_HOSTS=app.example.com,wiki.example.com
python -m tinysesam.gateway          # or: uvicorn tinysesam.gateway:app
```

The reverse proxy calls `GET /auth/forward` per request; all other methods/routes are off.
Programmatically: `TinySesamConfig.oidc_gateway(issuer=…, client_id=…, client_secret=…, base_url=…)`.
A ready-made [`deploy/forward-auth/docker-compose.yml`](deploy/forward-auth/) (gateway + Caddy) ships with it.

## Tests & CI

```bash
pip install -e '.[all]'        # + httpx is needed for the FastAPI TestClient (included in [all])
python tests/run_all.py         # all suites; exit 0 = green, 1 = failure
python tests/run_all.py core pin chain   # run individual ones
```

The suites are standalone assert scripts (no pytest). **GitHub Actions CI**
(`.github/workflows/ci.yml`) runs automatically on **every push/PR**: the full run across
Python 3.10–3.13 (`.[all]`) **and** a minimal run without extras (which secures the stdlib-scrypt fallback;
passkey/OIDC-dependent suites are skipped there). So to update, just push — CI tests it.

## Status

Core (password/TOTP/sessions/roles), hardening, API keys/service accounts, admin panel and
update mechanism: implemented & tested. **New in 0.5** — remember-me, step-up/per-route MFA,
factor chains, personal PIN, shared resource secret, magic-link + mailer hook,
registration + invitation, account page, forward-auth: each with its own test (`tests/test_*.py`),
plus a combination matrix (`tests/test_matrix.py`). 17 test files, all green.
OIDC + passkey: implemented, structurally tested; the browser-/provider-dependent end-to-end path
is to be verified against a real domain/real provider. **0.6** adds the LDAP/lldap backend, TOTP recovery codes,
forgot-password, your own session management, optional OIDC RP logout, plus hardening (session invalidation
after a password change, anti-enumeration, `auth.gc()`, `py.typed`). In total **22 test files, all green**.

MIT license.

## Credits

Icon: <a href="https://www.flaticon.com/free-icons/wizard" title="wizard icons">Wizard icons created by max.icons - Flaticon</a>
</content>
</invoke>

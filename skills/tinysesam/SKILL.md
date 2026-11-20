---
name: tinysesam
description: >-
  Protect a Python/FastAPI app or any web app behind a reverse proxy with TinySesam — sign-in (password,
  TOTP, passkey, PIN, OIDC, SAML, LDAP, sign-in links), guards and roles, step-up, admin-created accounts,
  API keys, forward auth in front of third-party apps (Caddy, nginx, Traefik), OAuth for MCP clients such as
  Claude Code, services with client_credentials and private_key_jwt, home network without a domain, same look as a C22 app. Use when adding login or 2FA to a
  FastAPI app, putting an app behind a sign-in gate, wiring `TinySesamConfig`, `auth.require_user`,
  `/auth/forward`, or answering "how do I do X with TinySesam".
---

# TinySesam for app builders

TinySesam is a FastAPI authentication library that also runs as a forward-auth gateway. This skill is a **signpost**:
it picks the right recipe and names the switches; the full explanation lives in the repo docs, which are the source of
truth. Every Python block below is executed by the repo's test suite, every name in it exists in the code.

**Docs to open for details** (all in the repository root of `Ollornog/TinySesam`):

| Question | Read |
|---|---|
| Every config field, default, meaning | `CONFIGURATION.md` (generated from `tinysesam/config.py`) |
| Every public method, its signature and tier | `API.md` (generated; tier A = stable, B = advanced, C = internal, never use C) |
| Concepts, recipes, security notes | `README.md` (section names below) |
| Failure behaviour, proxy contract, rollbacks | `docs/OPERATIONS.md` |
| Home network, bare IP, own CA | `docs/HOME-NETWORK.md` |
| Proxy templates | `deploy/quickstart/` (ready-made stack), `deploy/forward-auth/` (Caddy, nginx, Traefik), `deploy/home-network/` |

## Choose the shape first

1. **Your own FastAPI app** → library mode: `TinySesam(TinySesamConfig(...))`, `app.include_router(auth.router())`,
   guards as dependencies. Recipes 1–5.
2. **Someone else's app** (wiki, dashboard, static site, any language) → gateway mode: TinySesam answers the proxy's
   sub-request `GET /auth/forward`, the app sees `Remote-User`/`Remote-Groups`/`Remote-Email` headers. Recipe 6;
   clients without a browser (WebDAV, CalDAV, Git) get app passwords, recipe 6a.
3. **A tool on a person's computer** (Claude Code as MCP client) → OAuth authorization server on top of forward auth.
   Recipe 7.
4. **A service without a person** (daemon, backup job, script on a server) → the same OAuth server with
   client credentials, paired once by a code. Recipe 7a.

Install pinned (`pip install "tinysesam[all]==<version>"`, extras: `[argon2] [qr] [oidc] [saml] [ldap] [passkey]
[redis] [gateway] [services]`). Never install unpinned; the README's *Installation* section names the current version.

## Recipe 1 — FastAPI app, password plus mandatory TOTP

`login_chain` is the switch that makes a second factor mandatory (`totp_required` is a dead field that is rejected).
With the default `mfa_enrollment="first_login"` a new account sets up its authenticator on its first sign-in.

```python
from fastapi import Depends, FastAPI
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    base_url="https://app.example.com",     # the public address; links and redirects come only from here
    login_chain=["password", "totp"],       # every sign-in needs both
    allow_signup=False,                     # accounts come from the admin (recipe 3) or your code
))

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)   # no unauthenticated API docs in production
app.include_router(auth.router())           # /auth/login, /auth/totp, /auth/account, /auth/admin, ...
auth.install_error_pages(app)               # themed 403/404/500 for browsers, JSON for API clients


@app.get("/")
def home(user=Depends(auth.require_user)):  # browsers are redirected to /auth/login, API clients get 401
    return {"hi": user["username"]}


@app.get("/reports")
def reports(user=Depends(auth.require_role("editor", "auditor"))):   # one of the roles is enough
    return {"reports": []}
```

- First admin: with no admin in the store, TinySesam issues a one-time claim token (console, else the file
  `<db_path>.claim`, mode 0600) for `/auth/claim-admin`. Alternatives: `admin_identifiers=["me@example.com"]` or
  `auth.ensure_admin(name, password)` with the password from your secret store. README: *Bootstrapping the first admin*.
- Other guards: `auth.require_admin`, `auth.require(mfa=True)` (fresh confirmation, recipe 2),
  `auth.require(factors=["pin", "password"])` (a chain for one route). `auth.current_user(request)` returns the
  account or `None` without redirecting.
- Call `auth.gc()` regularly (startup, timer) or the tables grow. A systemd timer ships in `deploy/systemd/`.

## Recipe 2 — step-up for a dangerous route

```python
from fastapi import Depends, FastAPI
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig.local_accounts(   # username + password only, no email anywhere
    db_path="app.db",
    pin_enabled=True, pin_login=False,          # the PIN exists only as an extra factor
    stepup_methods=["pin"],                     # the step-up page asks for it
    stepup_max_age_sec=300,                     # a confirmation counts for five minutes
))
app = FastAPI()
app.include_router(auth.router())


@app.post("/payouts")
def payout(user=Depends(auth.require(mfa=True))):  # older confirmation: browsers go to /auth/reauth, API gets 403
    return {"ok": True}
```

API clients get `403` plus the header `X-TinySesam-Reauth: /auth/reauth`. An API key can never satisfy a step-up.
`admin_require_mfa=True` (default) does the same for the admin panel and `require_admin`. Your own confirm dialog:
`auth.confirm_password(...)`, `auth.confirm_pin(...)`, `auth.confirm_totp(...)` — README *Own step-up page*.

## Recipe 3 — the admin creates accounts, a sign-in link lets them in

No registration, no mailer. The person opens the link, sets up what `login_chain` demands, and is signed in.

```python
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    base_url="https://app.example.com",      # the link address comes only from here, never from the Host header
    allow_signup=False,
    magiclink_enabled=True,
    magiclink_self_request=False,             # links only from the admin or your code
    magiclink_first_login_only=True,          # a link opens the door once, later the chain applies
    login_chain=["password", "totp"],
))
uid = auth.create_user("dana", email="dana@example.com", roles=["editor"])   # no password
link = auth.create_signin_link(uid, ttl_min=60)    # {"url", "expires_at", "qr"}; hand it over once
assert link["url"].startswith("https://app.example.com/auth/magic/")
```

The admin panel (`/auth/admin`) has the same as a *Sign-in link* button per user. `auth.set_disabled(uid, True)`
locks an account (ends sessions, revokes keys, drops open links). Cross-device sign-in by QR code:
`qr_login_enabled=True` (extra `[qr]`). README: *Recipe: the admin creates accounts, a link signs them in*.

## Recipe 4 — API keys for scripts and services

```python
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db"))
svc = auth.create_service("backup-daemon", roles=["reader"])         # no sign-in, no MFA, roles only
key = auth.create_api_key(svc, name="nightly", expires_days=30)       # key["key"] is shown this once
assert key["key"].startswith("tsk_")
```

The client sends `Authorization: Bearer tsk_…` or `X-API-Key: tsk_…`; `require_user` and `require_role` accept it.
`kind="automation"` (default) never carries the admin flag; `kind="human"` only works next to a live session of the
same account. Keys expire after `apikey_default_days` unless `expires_days` says otherwise; revoke with
`auth.revoke_api_key(key_id)`. README: *API keys & service/daemon accounts*.

## Recipe 5 — same look as your app: tokens, C22, top bar

- Colours: override `--ts-*` CSS variables in `brand_css` (defaults in `tinysesam/theme.py`). Light/dark follows the
  class `dark` on `<html>` and `localStorage.themeMode`.
- App built on C22: `c22_stylesheet="/static/css/c22-vega.css"` — a path on your own origin, nothing from third
  parties. The mapping is `tinysesam/c22.css`.
- Your own pages get TinySesam's top bar (logo, name, `topbar_links`, account menu with sign-out):

```python
import secrets

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    base_url="https://app.example.com",
    c22_stylesheet="/static/css/c22-vega.css",
    topbar_links=[("Dashboard", "/dashboard"), ("Wiki", "/wiki")],
))
app = FastAPI()
app.include_router(auth.router())


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, response: Response):
    nonce = secrets.token_urlsafe(16)              # your page's CSP nonce
    auth.ensure_csrf(request, response)            # the menu's sign-out form needs the CSRF cookie
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'")
    return (f"<!doctype html><html><head>{auth.topbar_head(nonce=nonce)}</head><body>"
            f"{auth.topbar(request, nonce=nonce, current='/dashboard')}<main>…</main></body></html>")
```

Replace a whole built-in page with `auth.set_template(name, fn)`; `fn(auth, ctx)` gets `ctx["nonce"]` and
`ctx["dialog"]` (TinySesam's own dialog instead of `alert`/`confirm`/`prompt`). README: *Look & feel*.

## Recipe 6 — a gate in front of any app (forward auth)

TinySesam runs as its own service; the proxy asks `GET /auth/forward` for every request (alias `/auth/verify`):
`200` plus `Remote-User`, `Remote-Groups`, `Remote-Email`, `Remote-Name`, `Remote-Id` → pass; `401` plus
`X-TinySesam-Location` → redirect to sign-in; `403` with `X-TinySesam-Reason: role` → wrong role.

**Fastest way: the quickstart stack** `deploy/quickstart/` — gateway, Caddy with caddy-jwt (image
`ghcr.io/ollornog/tinysesam-caddy-gate:v<version>`) and an example app behind the gate, nothing to build:

```bash
cp deploy/quickstart/example.env deploy/quickstart/.env && chmod 600 deploy/quickstart/.env
$EDITOR deploy/quickstart/.env        # OIDC provider, TS_AUTH_HOST, TS_APP_HOST, TS_TLS (acme | dns | internal | ip)
docker compose -f deploy/quickstart/docker-compose.yml up -d
```

Register `https://<TS_AUTH_HOST>/auth/oidc/callback` at the provider, open `https://<TS_APP_HOST>`: the example app
shows the `Remote-*` headers; then put your service in place of `app` (`TS_APP_UPSTREAM`). Included: identity headers
from the browser stripped, HSTS, sign-out at the app, OAuth for MCP clients (`TS_OAUTH_RESOURCES`). Not included
(take them from `deploy/forward-auth/`): fail2ban feed, one OIDC client per app, share paths, gate token.
README: *Gateway and Caddy in 5 minutes*.

- Without Docker: `pip install "tinysesam[gateway]==<version>"`, set `TINYSESAM_OIDC_ISSUER`,
  `TINYSESAM_OIDC_CLIENT_ID`, `TINYSESAM_OIDC_CLIENT_SECRET`, `TINYSESAM_BASE_URL`, `TINYSESAM_COOKIE_DOMAIN`,
  `TINYSESAM_PROTECTED_HOSTS`, then `python -m tinysesam.gateway` (image `ghcr.io/ollornog/tinysesam:v<version>`).
  In Python: `TinySesamConfig.oidc_gateway(issuer=..., client_id=..., client_secret=..., base_url=...)`.
- Hand-written proxy config: `deploy/forward-auth/Caddyfile` (expanded `reverse_proxy` with `handle_response` —
  Caddy's `forward_auth` shortcut does not redirect), `deploy/forward-auth/nginx.conf`,
  `deploy/forward-auth/traefik.yml`. Roles per app: header `X-TinySesam-Roles: editors,admin` in the sub-request.
- Library mode can be a gate too: `forward_auth_enabled=True`, `cookie_domain=".example.com"`,
  `trusted_redirect_hosts=["app.example.com"]`, `trusted_proxies=["<proxy address>/32"]`.
- Fewer sub-requests: gate token (`gate_token_enabled=True`, `deploy/forward-auth/Caddyfile.gate`, the proxy fetches
  the keys from `/auth/gate/jwks.json`); one gateway for many apps without a shared cookie: `gate_link_enabled=True`;
  one OIDC client per app: `oidc_clients`. README: *As a pure OIDC gateway (preset)*, *Several apps, one TinySesam*;
  `docs/OPERATIONS.md`.

## Recipe 6a — app passwords for WebDAV, CalDAV/CardDAV, Git

Clients that cannot open a sign-in page speak Basic auth. Per protected app, an account then creates an **app
password** on its account page (fresh confirmation, shown once, bound to the chosen apps, never the admin flag, valid
only at `/auth/forward`). The account's own password never works there. Default off:

```python
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="gateway.db",
    base_url="https://auth.example.com",
    forward_auth_enabled=True,
    cookie_domain=".example.com",              # one sign-in for the browser across the subdomains
    trusted_redirect_hosts=["dav.example.com"],
    forward_apps={"dav.example.com": {"name": "Files", "app_passwords": True}},
    app_password_default_days=365,             # typed into a phone by hand: a year, not a quarter
))
assert [a["host"] for a in auth.app_password_hosts()] == ["dav.example.com"]

uid = auth.create_user("alice", email="alice@example.com")
pw = auth.create_app_password(uid, "Phone calendar", hosts=["dav.example.com"])   # what the account page does
assert pw["hosts"] == ["dav.example.com"] and pw["secret"]                          # `secret`: shown this once
```

- Gateway: `TINYSESAM_FORWARD_APPS='{"dav.example.com": {"name": "Files", "app_passwords": true}}'`; the quickstart
  has the full example (`COMPOSE_PROFILES=webdav`, see `deploy/quickstart/example.env`).
- **At the proxy** the forward-auth block needs the `@basic` branch **before** `@denied`: a `401` with
  `X-TinySesam-Reason: basic` is passed through with its `WWW-Authenticate: Basic …` (a redirect would break the
  sync), and `header_up -Authorization` towards the app. The templates in `deploy/` carry it.
- On the device: the sign-in user name plus the app password, e.g. `git clone https://alice@git.example.com/repo.git`.
  A browser on the same host still gets the sign-in page.
- In code (tier B): `auth.create_app_password(...)` as above, `auth.list_app_passwords(uid)`, `auth.revoke_app_password(pw_id)`. Never unlimited unless
  `app_password_allow_unlimited=True`. Samba and other non-HTTP protocols are not covered. README: *App passwords:
  WebDAV, CalDAV, Git behind TinySesam*.

## Recipe 7 — OAuth for MCP clients (Claude Code)

TinySesam becomes the OAuth 2.1 authorization server; the app behind the proxy contains no OAuth code.

```python
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="gateway.db",
    base_url="https://auth.example.com",              # the issuer, fixed
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/mcp"],  # tokens are valid only here and below
))
```

At the proxy, on the app's host: route `/.well-known/oauth-protected-resource*` to TinySesam and pass a `401` that
carries `X-TinySesam-Reason: oauth` through with its `WWW-Authenticate` (both in `deploy/forward-auth/Caddyfile`).
Then on the user's computer: `claude mcp add --transport http myapp https://app.example.com/mcp` and
`claude mcp login myapp` (or `/mcp` inside Claude Code). Own CA (home network): `export
NODE_EXTRA_CA_CERTS=/path/to/root.crt` for Claude Code; an IP must be a Subject Alternative Name of the certificate.
Tokens: `oauth_access_token_ttl_sec`, `oauth_refresh_idle_days`, `oauth_refresh_max_days`; pepper via
`TINYSESAM_OAUTH_PEPPER` or `oauth_pepper_file`. Claude Desktop and Claude on the web call from Anthropic's
network and cannot reach a LAN-only server. README: *OAuth for MCP clients*.

## Recipe 7a — a service calls a protected app (no person)

A daemon or script gets short-lived tokens from the same OAuth server with client credentials with a private-key JWT (RFC 7523):
it holds its own key pair, TinySesam stores only the public key. Prefer this over an API key for anything that runs
unattended on another machine — nothing copyable travels with the requests.

```python
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="gateway.db",
    base_url="https://auth.example.com",
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/api"],
    oauth_service_clients=True,                       # needs the extra [services] (joserfc)
))
svc = auth.create_service("backup", roles=["backup"])
pairing = auth.create_service_pairing(svc, name="nightly", resources=["https://app.example.com/api"])
assert len(pairing["code"]) == 19                     # one-time code, shown once, valid oauth_pairing_minutes
```

On the service's machine: `tinysesam-client pair https://auth.example.com <code>` (writes a key file with mode 0600),
then `curl -H "Authorization: Bearer $(tinysesam-client token)" …`, or in Python `ServiceClient(key_file).httpx_auth()`
/ `.requests_auth()` from `tinysesam.client`. The admin panel ("Pair a service") and the account page ("Services")
issue codes too. The proxy needs nothing new: forward auth passes `Remote-User` (the service account) and its roles,
never admin. Keys expire after `oauth_service_key_days` and the client rotates them itself; revoke with
`auth.revoke_service_client(client_id)`, list with `auth.list_service_clients()`. README: *A service calls a protected
app*.

## Recipe 8 — home network without a domain

Prefer a domain with a DNS-01 certificate (works even if the name resolves only at home). Bare IP: template
`deploy/home-network/` (Caddy with its own CA), trust the root on every device. Passkeys never work on an IP
address. Local development on `http://127.0.0.1` or `http://localhost` needs nothing. `docs/HOME-NETWORK.md`.

## Test your integration

Your app's tests do not need a sign-in round-trip: `auth.start_session` creates a session without checking anything
(tests only, never in a login route — there use `auth.login_password(...)`).

```python
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="test.db", login_chain=["password", "totp"]))
app = FastAPI()
app.include_router(auth.router())


@app.get("/")
def home(user=Depends(auth.require_user)):
    return {"hi": user["username"]}


client = TestClient(app, base_url="https://testserver")
assert client.get("/", headers={"Accept": "application/json"}).status_code == 401   # API client, not signed in

uid = auth.create_user("quentin", password="a long test password 4711")
token, _ = auth.start_session(uid, "password")   # first factor only: the chain still owes TOTP
client.cookies.set(auth.session_cookie_name, token)
assert client.get("/", headers={"Accept": "application/json"}).status_code == 401

plain = TinySesam(TinySesamConfig(db_path="plain.db"))   # no chain: one factor completes the sign-in
plain_app = FastAPI()
plain_app.include_router(plain.router())
plain_app.get("/")(lambda user=Depends(plain.require_user): {"hi": user["username"]})
plain_client = TestClient(plain_app, base_url="https://testserver")
token, _ = plain.start_session(plain.create_user("rita"), "password")
plain_client.cookies.set(plain.session_cookie_name, token)
assert plain_client.get("/").json() == {"hi": "rita"}
```

With a chain, test the guarded routes against an app built without `login_chain` (as above), or walk the real
sign-in with `auth.login_password(...)` and `auth.login_totp(...)` against a TOTP code from `pyotp`.

Cookie names carry the `__Host-` prefix where possible: read `auth.session_cookie_name` and `auth.csrf_cookie_name`,
never spell them out.

## Pitfalls

- **HTTPS and `base_url` are mandatory** outside `localhost`: cookies are `Secure`, and every link (mail, OIDC
  redirect, sign-in link, QR code) is built from `base_url`, never from the `Host` header. OIDC, SAML and mail paths
  refuse to start without it (`ConfigError`).
- **Behind a proxy**: list it in `trusted_proxies`; start uvicorn **without** `--proxy-headers`, otherwise
  rate limit, lockout and fail2ban see a forgeable address.
- **Passkeys** need a real domain: `rp_id="app.example.com"`, `origin="https://app.example.com"`, extra `[passkey]`.
- **CSP**: built-in pages run under a strict nonce CSP (`csp="strict"`). Your own pages set their own CSP; no inline
  handlers (`onclick=`), no `style=` attributes, every `<script>`/`<style>` with the nonce.
- **Own login route**: only through `auth.login_password(...)`, `auth.login_totp(...)`, `auth.login_pin(...)` — they
  throttle, count and lock. Building one from `start_session` lets anyone guess passwords.
- **Own forms** need the CSRF token: `auth.ensure_csrf(request, response)` → hidden field `_csrf` or header
  `X-CSRF-Token`; check with `auth.require_csrf(request, value)`.
- **Admin step-up**: `admin_require_mfa=True` (default) — an old admin session confirms again before acting. New
  access (passkey, TOTP, PIN, API key, QR approval, OAuth consent) always needs a fresh confirmation; an API key never
  counts.
- **PocketID and similar providers** send `groups` only when asked: `oidc_scopes="openid profile email groups"`.
- **Admins satisfy every role** unless `admin_implies_roles=False`.
- **Back up the keys, apart from the database.** Secrets at rest (TOTP, …) are encrypted with the vault key
  (`TINYSESAM_SECRETS_KEY`, `secrets_key_file`, else `<db>.key` next to the database); without it every TOTP
  enrollment is lost. Keys per purpose (`vault`, `gate`, `oauth-pepper`) rotate without signing anyone out:
  `python -m tinysesam keys list --db app.db`, `keys rotate --purpose vault`. `docs/OPERATIONS.md`, section *Keys*.
- **Nothing from third parties**: logos, fonts and stylesheets come from your own origin (`brand_icon`,
  `c22_stylesheet` are paths or `data:` addresses).
- **Read the start-up warnings.** The constructor checks the whole configuration at once: a contradiction is a
  `ConfigError` with every finding, a gap that may still be filled (a mailer set later) is logged as a warning on
  the `tinysesam.security` logger. `config.validate()` re-checks a configuration changed after setup.

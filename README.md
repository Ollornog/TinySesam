<!-- Links hier ABSOLUT: Diese Datei ist zugleich die Projektbeschreibung auf PyPI
     (pyproject.toml: readme = "README.md"), und dort löst nichts relative Repo-Pfade auf —
     Logo und sieben Verweise waren auf der Paketseite tot. tests/test_repo.py hält das fest.
     Die deutsche Fassung unter i18n/ wird nur auf GitHub gelesen und darf relativ bleiben. -->
<p align="center"><img src="https://raw.githubusercontent.com/Ollornog/TinySesam/main/docs/wizard.png" alt="TinySesam" width="250" height="250"></p>

<h1 align="center">TinySesam</h1>

<p align="center"><b>English</b> · <a href="https://github.com/Ollornog/TinySesam/blob/main/i18n/README.de.md">Deutsch</a></p>

<p align="right">
<a href="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="https://github.com/Ollornog/TinySesam/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/python-3.12%2B-blue.svg" alt="Python">
</p>

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
global or per route (`Depends(auth.require(factors=[...], strict=...))`) — a route chain only ever
adds to the global rule.

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

TinySesam is on **PyPI** (since 0.19.0). Pin the version:

```bash
pip install "tinysesam==0.24.9"
# core: password + TOTP. Everything: [all] — + argon2, QR, OIDC, passkey
pip install "tinysesam[all]==0.24.9"
# selective: [argon2] [qr] [oidc] [saml] [ldap] [passkey] [redis] [gateway]
```

Every release goes to PyPI from its git tag, via trusted publishing (no token), and each file
carries a PEP 740 attestation of the commit it was built from. The same version also installs
straight from the tag:

```bash
pip install "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@v0.24.9"
```

Drop the `@v…` when you want a **commit** rather than a released version — that pulls the moving
default branch, so it belongs in an experiment, not in a deployment.

## Quickstart

```python
from fastapi import FastAPI, Depends
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    # Public address of this app. Required as soon as a link leaves it — the
    # OIDC redirect URI below is one. Without it the only source would be the
    # request's Host header, which the caller sets: the constructor refuses to
    # start rather than guess.
    base_url="https://app.example.com",
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
**unique** — across usernames *and* emails (no identifier belongs to two accounts, not even as
`Alice`/`alice`), enforced by the database; accounts without an email stay allowed. Registration requires it
by default — `signup_require_email=False` turns that off. In `"email"` mode the registration form
drops the username field entirely: the address *is* the identifier. `signup_verify_email=True` activates the
account only after the confirmation link is clicked; it needs a mailer (`set_mailer` or SMTP config)
and refuses to register otherwise instead of silently skipping the check.

## Guards

```python
Depends(auth.require_user)             # logged in — all the simplest case needs
Depends(auth.require_admin)            # logged in + is_admin
Depends(auth.require_role("editor"))   # logged in + role (admin implicitly has all)
Depends(auth.require_role("a", "b"))   # one of the two is enough
```

Without a guard, `auth.current_user(request)` returns the signed-in account — from a session
**or** an API key — or `None`, and never redirects: for a page that merely looks different when
someone is signed in. A route that *acts on the session* (applies a factor, refreshes or ends it)
takes the account from `auth.session_user(request)` instead, which never answers for a key
([tier B](#public-api-three-tiers)).

## Roles & groups

**Roles are the groups** — a list per user (`roles`) + `is_admin`; guard `require_role("…")`.
Name several and **one of them is enough** — `require_role("editorial", "proofing")`, or from a list
of your own (`require_role(*ROLES_ALLOWED)`). That is the same OR as `?roles=a,b` in forward-auth, so the question
“who may pass?” means the same thing in both modes. Need **all** of them? Stack the guards:
`@app.get(…, dependencies=[Depends(auth.require_role("a")), Depends(auth.require_role("b"))])`.
An admin satisfies **every** role. If you don't want that (e.g. because permissions come from an IdP
group): `admin_implies_roles=False` globally, or `require_role("editor", admin_implies=False)` per route.
Inside a route, `auth.has_role(user, "editor")` asks the same question as a `bool` — same admin
rule, same `admin_implies=False` switch.
- **Local user/password:** assign roles per user in the **admin panel**. `available_roles=[…]` defines known
  roles → the panel shows them as **checkboxes** (empty = free-text entry).
- **IdP users (OIDC/SAML/LDAP/AD):** automatically map external groups onto local roles —
  `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`, e.g.
  `{"editors": "editor", "cn=admins,ou=g": "__admin__"}` (target `__admin__` = admin flag). Set at login;
  mapped roles are synchronized, manually assigned ones stay. The same `require_role(...)` guards everywhere.
  **PocketID** (and other providers that tie claims to scopes) only sends the `groups` claim when the
  scope `groups` is requested — add it: `oidc_scopes="openid profile email groups"` (gateway:
  `TINYSESAM_OIDC_SCOPES`). Without it `oidc_allowed_groups` turns everyone away and the role map
  assigns nothing; the start warns. TinySesam doesn't add the scope itself (Entra ID, for one,
  rejects it and sends groups as an optional claim).

## Accounts in code

`auth.create_user(…)` creates an account and returns its ID. It runs the same checks as every
other path — the identifier must be free across usernames *and* emails, otherwise `ConfigError`
(`e.field`, `e.owner_id` say what collided):

```python
uid = auth.create_user("alice", email="alice@example.com", roles=["editor"])  # no password: OIDC, link, …
auth.create_user("bob", password=os.environ["BOB_INITIAL"], display_name="Bob")
```

`ensure_admin(…)` is for the first admin, `create_service(…)` for machine accounts
([API keys](#api-keys--servicedaemon-accounts)).

**Locking an account as the operator** — the same as “disable” in the panel, which calls it:

```python
auth.set_disabled(uid, True)     # ends its sessions, revokes its API keys, drops open links
auth.set_disabled(uid, False)    # unlocks; revoked keys stay revoked
```

The lock carries the operator mark: no confirmation link lifts it, not even one issued afterwards.
An owner cannot be locked (`StateError`); an unknown ID returns `False`. Up to 0.21.x the docs
showed `auth.store.set_disabled(uid, True, durch_betreiber=True)` for this — that only set the mark
and left sessions, keys and links alive.

**In your app's tests** you want a signed-in client without a login round-trip.
`start_session` creates a session **without checking anything** — which is exactly why it
belongs in tests (or behind a factor you verified yourself), never in a login route (that one
takes [`login_password`](#your-own-login-page)):

```python
token, _ = auth.start_session(uid, "oidc")
client.cookies.set(auth.session_cookie_name, token)
```

`session_cookie_name`, `csrf_cookie_name` and `resource_cookie_name` carry the `__Host-` prefix
wherever the browser allows it — read them, don't spell the names out.

## Routes (provided by the router)

| Route | Purpose |
|---|---|
| `GET/POST /auth/login` | password login + login page (shows active methods) |
| `GET/POST /auth/totp` | 2nd factor after password/OIDC |
| `GET/POST /auth/totp/setup` · `POST /auth/totp/setup/start` · `POST /auth/totp/disable` | set up / turn off TOTP (the `…/start` POST is what creates the key) |
| `GET /auth/oidc/start` · `/auth/oidc/callback` | OIDC flow *(when enabled)* |
| `POST /auth/passkey/{register,login}/{begin,finish}` | WebAuthn *(when enabled)* |
| `GET /auth/passkey/list` · `POST /auth/passkey/delete` | manage passkeys |
| `GET /auth/magic/{token}` | redeem a sign-in link *(when magic links are on)* |
| `GET /auth/verify/{token}` · `GET /auth/invite/{token}` | confirm an address · accept an invitation |
| `GET /auth/logout` · `GET /auth/me` | log out · current user (JSON) |

**Managing a factor needs a fresh factor.** `POST /auth/totp/disable`, `/auth/totp/recovery`,
`/auth/pin/set`, `/auth/pin/disable` and `/auth/passkey/delete` require a step-up confirmation no
older than `stepup_max_age_sec` — otherwise 403 plus `X-TinySesam-Reauth: /auth/reauth` (browsers
are redirected there). An **API key can never satisfy it**: a machine credential never performs an
interactive factor, so it cannot take one away either. `/auth/reauth` itself answers a key with a
403 as well (`api.stepup_session`): there is nothing for it to confirm, and a key plus a password
must not stand in for the second factor of a half-finished sign-in (fixed in 0.20.1).

**Setting a factor up needs an interactive session.** `GET/POST /auth/totp/setup` and
`POST /auth/passkey/register/{begin,finish}` require a session as well — an API key gets a 403
(`auth.require_session()` is the guard). Otherwise a leaked CI key would enrol a factor **it**
controls: the TOTP secret is in the body of `GET /auth/totp/setup`, and a passkey it registered is
a full sign-in — which would have handed it a fresh interactive session and, through that, the
step-up routes above.

**A first factor is different.** An account with no password, no PIN and no TOTP (a purely
federated account) has nothing to confirm with — `stepup_options()` is empty and the reauth page
has no field at all. For that one case `POST /auth/pin/set` accepts a **fresh sign-in** instead
(no older than `stepup_max_age_sec`, measured from the login, `auth.login_fresh()`); *replacing*
a PIN and removing any factor stay behind `require_mfa()`.

**No API-key path to these routes, and no replacement over HTTP.** Automation that rotated a PIN
or turned TOTP off with its own key gets a 403 with a translated reason
(`api.needs_session` / `api.stepup_session`). There is no admin route and no CLI command for it:
do it in-process through the Python API (`auth.set_pin(uid, …)`, `auth.totp_disable(uid)`), which
is the same code path the routes use, minus the HTTP surface.

## Configuration (`TinySesamConfig`, excerpt)

| Field | Default | |
|---|---|---|
| `db_path` | `tinysesam.db` | SQLite store |
| `password_enabled` / `passkey_enabled` / `oidc_enabled` | `True/False/False` | active methods (passkey is off by default: `webauthn` lives in the extra `[passkey]`) |
| `totp_enabled` | `True` | allow 2FA (required as soon as a user has set it up) |
| `login_chain` · `stepup_strict` | `[]` · `False` | `["password","totp"]` **enforces** an ordered factor chain — this is how you make 2FA mandatory. Empty = classic: one first factor, plus TOTP where set up |
| `session_ttl_hours` · `cookie_secure` · `cookie_samesite` | `168` · `True` · `lax` | sessions/cookie |
| `rp_id` · `origin` | `localhost` · … | WebAuthn (real domain required, HTTPS) |
| `oidc_issuer/_client_id/_client_secret/_scopes` | – | OIDC provider |
| `oidc_auto_create` · `oidc_allowed_groups` · `oidc_group_claim` | `True` · `[]` · `groups` | auto-create + group gate |
| `base_url` · `login_redirect` · `logout_redirect` | – · `/` · … | app integration (`base_url` **mandatory** with mail paths/OIDC/SAML) |
| `cookie_domain` · `trusted_redirect_hosts` | `""` · `[]` | SSO across subdomains · allowed absolute `?next=` targets |
| `security_log` | `""` | file for the fail2ban logger (empty = logger only) |
| `forward_auth_enabled` · `forward_headers` | `False` · `{}` | forward-auth endpoint · which headers it sets (empty = `Remote-*`) |

`TinySesamConfig` is a dataclass, and that is part of the promise: `dataclasses.fields(TinySesamConfig)`
lists every field — handy for passing on only the keys it knows from your own settings. Every
field with its meaning: [`KONFIGURATION.md`](https://github.com/Ollornog/TinySesam/blob/main/KONFIGURATION.md) (German).

## Language (i18n)

The built-in texts are **English by default** (`lang="en"`); **German** ships too:

```python
TinySesamConfig(lang="de")                       # built-in pages + messages in German
auth.add_messages("fr", {"login.submit": "Se connecter", ...})   # your own language/override
```
Individual texts or whole pages can additionally be freely replaced via `auth.set_template(...)`.

## Your own login page

Two ways, depending on what you want to change:

- **Only the look** — replace the page and keep the route: `auth.set_template("login", fn)`
  ([Look & feel](#look--feel)). The form keeps posting to `POST /auth/login`, and every
  protection stays where it is. This is the first choice.
- **Your own route** (a single-page app, JSON, other fields) — call the building block the
  built-in route itself calls: `auth.login_password(…)`. It throttles, counts and locks
  exactly like `POST /auth/login`, because that route is nothing but this call: the CSRF check,
  the per-IP rate limit, the attempt booked up front (failures per identifier, per address and
  per pair, the series lock), the LDAP fallback ("one identifier, one account"; an outage is not
  a failure), audit and security log (the lines fail2ban reads), then the session.

```python
from html import escape

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db"))
app = FastAPI()
app.include_router(auth.router())


@app.post("/login")          # a plain `def`: FastAPI runs it in its thread pool
def login(request: Request, username: str = Form(""), password: str = Form(""),
          next: str = Form(""), csrf: str = Form("", alias="_csrf")):
    result = auth.login_password(request, username, password, next=next, csrf=csrf)
    if not result:           # wrong, locked, rate-limited, directory down …: no session, no cookie
        return HTMLResponse(f"<p>{escape(result.message)}</p>", status_code=result.status)  # your form
    return result.redirect()     # to the open factor (result.next_factor) or to next, cookie set
```

The result, a `tinysesam.LoginResult`, carries `ok` (also its truth value), `reason` (one of
`LoginResult.REASONS`: `ok`, `missing`, `invalid`, `locked`, `locked_series`, `ratelimit`,
`directory_down`, `method_disabled`, `no_session`), `status` (what the built-in page answers:
303, 400, 401, 404, 429, 503), `message` (the translated text), `next_url` (the checked target),
`next_factor` (the open factor, e.g. `"totp"`), `done` (session complete) and `user` (only on
success). `reason` is meant for programs; it is not the audit or security log, whose lines stay
as they are. A failure has no session and sets no cookie — ignoring the result signs no one in. A
JSON route that prefers to raise writes `if not result: raise HTTPException(result.status,
result.message)`, leaves `csrf` out (then the `X-CSRF-Token` header counts) and sets the cookie on
its own response with `result.set_cookie(response)`. The session token is deliberately not a
field. Only `HTTPException(403)` is raised (CSRF, or an account disabled in the meantime), plus
anything unexpected — the attempt then counts as a failure.

The steps after the first factor work the same way: `auth.login_totp(request, code, next=…)`
takes a TOTP code or a one-time recovery code, like `POST /auth/totp`, and
`auth.login_pin(request, pin, username, next=…)` works like `POST /auth/pin` (in a chain step
or on a signed-in session without `username`). `result.next_factor` tells your page which step
comes next. All three are synchronous (a password hash, maybe the directory): call them from a
`def` route, or through `run_in_threadpool` in an `async def` one.

> **Without these building blocks there is no protection against guessing.** The inner checks
> `check_password`, `check_pin`, `check_ldap`, `verify_totp` and `verify_recovery_code` only
> compare: no lockout, no counter, no series lock, no rate limit, no line for fail2ban. Until
> 0.21.0 this section showed `check_password` + `start_session` — a route built from that lets
> anyone guess passwords (or a four-digit PIN, or a six-digit code) as fast as the server
> answers. They are [tier C](#public-api-three-tiers) since 0.22.0, warn when called and go with
> 1.0; replace them with `login_password`, `login_pin` and `login_totp`.

`start_session` stays, for tests and for a factor you verified yourself — it checks nothing
([Accounts in code](#accounts-in-code)). It returns `(token, session_ok)`: unpack it — passing
the tuple straight into `set_cookie` writes the string `"('abc…', True)"` into the cookie, and
nothing raises. The token returned by `complete_totp` replaces the old one, also on step-up — put
it into the cookie, or the cookie holds a dead session. The `login_*` building blocks do both
for you.

The same pattern exists for a step-up of your own ([Own step-up page](#own-step-up-page),
`confirm_*`) and for changing the password ([Own password change page](#own-password-change-page),
`change_password`).

### CSRF in your own pages

Every form your app renders itself needs the token in a hidden `_csrf` field (or, for `fetch`,
in the `X-CSRF-Token` header), and the browser needs the matching cookie.
`auth.ensure_csrf(request, response)` does both: a valid token the browser already has is reused
— forms in other tabs stay valid and the response gets no `Set-Cookie` — otherwise it sets a new
one, with the same attributes as `issue_csrf()`. It returns the token for the form.

```python
@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request, response: Response, user=Depends(auth.require_user)):
    csrf = auth.ensure_csrf(request, response)          # FastAPI copies the cookie over
    return templates.get_template("settings.html").render(
        csrf=csrf, csrf_cookie=auth.csrf_cookie_name)
```

With a finished response (Jinja's `TemplateResponse`), get the token before rendering and hand
the cookie to the response afterwards — within one request both calls return the same token:

```python
csrf = auth.csrf_token(request)
resp = templates.TemplateResponse(request, "settings.html",
                                  {"csrf": csrf, "csrf_cookie": auth.csrf_cookie_name})
auth.ensure_csrf(request, resp)
return resp
```

In the template — JavaScript cannot read a Python property, so the page hands the cookie name
over (or the script takes the value from the `_csrf` field):

```html
<meta name="csrf-cookie" content="{{ csrf_cookie }}">
<form method="post" action="/settings">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
</form>
<script>
  function csrf() {            // read when sending: a sign-in in another tab changes the cookie
    const name = document.querySelector('meta[name="csrf-cookie"]').content;
    const pair = document.cookie.split("; ").find(c => c.startsWith(name + "="));
    return pair ? pair.slice(name.length + 1) : "";
  }
  fetch("/settings", {method: "POST", headers: {"X-CSRF-Token": csrf()}});
</script>
```

The receiving route checks with `auth.require_csrf(request, value)` — the form field or the
header: 403 if it does not match the cookie or the request comes from a foreign origin.

The cookie is called `__Host-tinysesam_csrf` wherever the browser allows the prefix, otherwise
`tinysesam_csrf` — never hard-code it. A cookie value that does not look like a token (wrong
characters, too short, too long) is replaced rather than copied into a form.
`issue_csrf(response)` always rolls a **new** token and invalidates the forms in every other
tab; it is for deliberate renewal, not for rendering a page.

**Signing in and out changes the token.** Every sign-in — each built-in path and your own route with
`login_*` (or `start_session` + `set_cookie`) — sets a fresh token in the same response, and
`auth.logout()` deletes it. A form rendered in that same response works only with the response
parameter (first example): it takes its token from `ensure_csrf(request, response)` *after*
`set_cookie`/`logout`. A finished response (second example) is rendered before `set_cookie`/`logout`
changes the token, so its form carries the old one and every submit gets a 403. A response that
signs in or out therefore renders no form that way — redirect (303) instead, and the next request
renders with the new cookie, as the built-in sign-ins do. A step-up (`/auth/reauth`,
`rotate_session`) keeps the token.

## Look & feel

Every built-in page (login, PIN, TOTP, account, admin panel, error pages) is styled from **one set of
CSS variables** — no per-page selectors to rebuild. Override them in `brand_css` and all pages follow:

```python
TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-surface:#fbf8f4;--ts-ink:#2b2a3a;--ts-accent:#b0566f}")
```

The tokens (and their defaults) live in [`tinysesam/theme.py`](https://github.com/Ollornog/TinySesam/blob/main/tinysesam/theme.py); `brand_head` injects
extra `<head>` markup and `brand_icon` sets the favicon on every built-in page.

**Want your own nav and footer around them?** `brand_header` and `brand_footer` wrap *every* built-in
page — login, PIN, TOTP, account, admin panel and the error pages. Both take HTML or `fn(auth) -> str`
when the shell depends on the request (sign-in state, language). `auth.install_error_pages(app)` gives browsers themed 403/404/500 pages while API
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
  signed in only gets the missing field, not the whole login page again. A route chain tightens the
  global rule and never undercuts it: a session that still owes the global sign-in a factor (TOTP of
  an account that has one, the next step of `login_chain`) is sent there first — even with
  `factors=["password"]`.

**A PIN as the way in is a deliberate option.** With `pin_enabled=True` the PIN is a first factor by
default (`pin_login=True`) — unless a strict `login_chain` asks for it after another factor, where it
only ever is the next step. Handy for a general page, while a detail page asks for more:

```python
@app.get("/overview")                                   # the PIN is enough
def overview(user=Depends(auth.require())): ...

@app.get("/details")                                    # PIN, then the password
def details(user=Depends(auth.require(factors=["pin", "password"]))): ...
```

A four-digit PIN has 10,000 values. What keeps guessing in check is its own counter
(`pin_max_attempts` per account, the IP threshold at `ip_attempt_factor` times that) and the
consecutive-failure lock (`account_max_consecutive_failures`, see *Hardening*) — both sit next to the
login lockout in the admin panel. Don't want it? `pin_login=False`.

## Own step-up page

`Depends(auth.require(mfa=True))` sends browsers to the built-in page `/auth/reauth` and answers
other clients with a 403 plus `X-TinySesam-Reauth` ([above](#pin-and-step-up-for-sensitive-routes)).
To change only its look, replace the page: `auth.set_template("reauth", fn)`. A page of your own —
the dialog of a single-page app, a form in front of a dangerous button — calls the building block
the built-in route itself calls: `auth.confirm_password(…)`, `auth.confirm_pin(…)` or
`auth.confirm_totp(…)`. They throttle, count and lock exactly like `POST /auth/reauth`, because
that route is nothing but this call: the CSRF check, a full session (an API key does not count),
only a method `stepup_options()` offers this account (`stepup_methods`, `stepup_strict`), the
per-IP rate limit, the attempt booked up front in its own pot (`reauth_max_attempts` — typos here
do not lock the sign-in), audit and security log, then the fresh confirmation with a new session
token.

```python
from html import escape

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db"))
app = FastAPI()
app.include_router(auth.router())


@app.get("/danger")              # a sensitive route: only with a fresh confirmation
def danger(user=Depends(auth.require(mfa=True))):
    return {"user": user["username"]}


@app.post("/confirm")            # a plain `def`: FastAPI runs it in its thread pool
def confirm(request: Request, password: str = Form(""), next: str = Form(""),
            csrf: str = Form("", alias="_csrf")):
    result = auth.confirm_password(request, password, next=next, csrf=csrf)
    if not result:               # wrong, locked, no session, not offered …: nothing became fresh
        return HTMLResponse(f"<p>{escape(result.message)}</p>", status_code=result.status)  # your form
    return result.redirect()     # to next, with the renewed session cookie
```

The result is the same `tinysesam.LoginResult` as for signing in: on success `done` is true and
`redirect()` or `set_cookie(response)` puts the renewed token into the cookie — the old one keeps
working for `session_rotation_grace_sec`, without the freshness. On failure nothing became fresh,
and `reason` says why: `missing` (empty, 400, not counted), `invalid` (401), `locked` or
`ratelimit` (429), `method_disabled` (403: not offered to this account; with an empty
`stepup_options()` it has nothing to confirm with), `no_session` (401 with the login page as
`next_url`; 403 when the request shows an API key instead of a session). `confirm_totp` takes a
TOTP code only, no one-time recovery code — like the built-in page. Synchronous, like `login_*`.

## Own password change page

The built-in route is `POST /auth/password` (JSON with `current` and `new`; the account page uses
it). A page of your own calls the building block that route calls:
`auth.change_password(request, current, new, csrf=…)`. The current password is a secret like at
sign-in, so the same three apply: the per-IP rate limit, the attempt booked up front in its own pot
(`password_change_max_attempts`, per account — a typo here does not lock the sign-in), audit and
security log. It is checked against the account of the session, never against a name that might
resolve to someone else; then the new one against the password rule (`password_policy_error`). On
success the other sessions of the account end (yours stays), open address-change links are
dropped, and API keys stay valid on purpose — `result.api_keys_active` says how many, so your page
can say so too.

```python
from html import escape

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db"))
app = FastAPI()
app.include_router(auth.router())


@app.post("/password")           # a plain `def`: FastAPI runs it in its thread pool
def password(request: Request, current: str = Form(""), new: str = Form(""),
             csrf: str = Form("", alias="_csrf")):
    result = auth.change_password(request, current, new, csrf=csrf)
    if not result:               # wrong, locked, too weak, no session …: nothing changed
        return HTMLResponse(f"<p>{escape(result.message)}</p>", status_code=result.status)  # your form
    keys = f" {result.api_keys_active} API key(s) still work." if result.api_keys_active else ""
    return HTMLResponse(f"<p>Password changed, your other sessions are signed out.{keys}</p>")
```

The result is a `tinysesam.PasswordChangeResult`: `ok` (also its truth value), `reason` (one of
`PasswordChangeResult.REASONS`: `ok`, `missing`, `invalid`, `locked`, `ratelimit`, `policy`,
`no_session`), `status` (what `POST /auth/password` answers: 200, 400, 401, 403, 429), `message`
(the translated text; for `policy` the rule that failed) and `api_keys_active`. It needs a full
session — an API key does not count (`no_session`, 403): a machine credential does not change a
person's password. An empty current password is `missing` (400) and does not count as a failure.
Synchronous, like `login_*`.

## Bootstrapping the first admin

Open registration plus “the first account becomes admin” is a race: whoever finds the fresh instance
first wins it. TinySesam therefore offers two explicit paths, **both only while no admin exists**:

```python
TinySesamConfig(admin_identifiers=["me@example.com"])   # allowlist, any sign-in method
```

- **Allowlist** — the named username or email is promoted on its next successful sign-in, whatever the
  method. An **address** only counts with proof that it belongs to whoever is signing in; SAML and
  LDAP offer no such proof, so it never promotes there (see below). After that: never again — and
  not once an identity provider has taken the flag from the instance's last admin either; TinySesam
  then prints the one-time token below right away (or use `tinysesam owner`).
- **One-time token** — if no admin exists, TinySesam prints a claim URL to **stderr** on startup
  when stderr is a console (the operator's terminal). Sign in, open `/auth/claim-admin?token=…`,
  and that account becomes admin. The token is single-use and expires after `admin_claim_ttl_min`;
  once an admin exists the route answers 404. The value is deliberately kept out of the security
  log — that file is what fail2ban reads and logrotate keeps. **Where stderr is not a console**
  (container, journal, a pipe — stderr *is* the log there), TinySesam writes the token to
  `<db_path>.claim` with mode `0600` instead and logs only that path (`docker exec … cat
  /data/app.db.claim`); the file is removed once the token is redeemed. Without a database file
  (`:memory:`) only stderr is left, and the log line says so. `admin_claim_token_file` picks the
  file yourself (it takes precedence, also at a console).
  **Known limit:** the token is redeemed through a URL (`?token=…`, mirrored into the login
  redirect's `Location` when you are not signed in yet), so it passes through proxy access logs,
  `Referer` and the browser history before it is spent — keep `admin_claim_ttl_min` short and
  redeem it right away. Where no token should appear in a URL at all, take the first admin over
  `auth.ensure_admin(...)` or the allowlist. See [SECURITY.md](https://github.com/Ollornog/TinySesam/blob/main/SECURITY.md).

The allowlist says **which name** becomes admin, not **who** gets that name. With
`allow_signup=True` a stranger can simply register under it and be admin on first sign-in — so that
combination is refused at construction time. It is allowed again once the identity is backed by the
signup itself: an email address (not a bare username, which nobody confirms), required and verified
(`signup_require_email=True`, `signup_verify_email=True`). Otherwise keep signup closed, or use the
one-time token — that one never leaves the operator's console.

The same applies when an IdP creates the accounts (`oidc_auto_create`, `saml_auto_create`,
`ldap_auto_create`): the username comes from someone else there too, so an allowlist **name** is
refused in that setup. An allowlist **address** stays allowed, but with OIDC it only counts when
the claim `email_verified` says so. Without it the address is still stored on the account and
still goes out as `Remote-Email` — it is merely noted as unconfirmed (`users.email_verified`) and
carries no rights, on any sign-in path that account uses later. For an IdP that never sends the
claim (Entra ID): use the one-time token, the path with proof — or, if you vouch for those
addresses yourself, set `oidc_email_verified_default=True`. A claim that explicitly says `false`
stays a no either way.

**SAML and LDAP have no such proof**: no standard attribute states that the address was verified,
and in many directories the `mail` entry is maintained by the user themselves. By default an
allowlist address over those two paths therefore **never** becomes the first admin — not even for
an existing account that already carries it. The configuration check says so at construction
time, and the refused attempt is logged to the security log and the audit trail
(`admin_bootstrap_denied`). With a mailer, the owner confirms such an address by link after
sign-in (`federation_email_confirm`) — an allowlist address never gets that link. Only where you
vouch for the source does the address count as proven, like `email_verified=true` with OIDC:
`ldap_email_trusted`/`saml_email_trusted` for a maintained directory or a company IdP without
self-registration, or a proof attribute (`ldap_attr_email_verified`/`saml_attr_email_verified`)
for an IdP that carries one. Otherwise the path with proof is the **one-time token**; to keep driving
rights from the IdP afterwards, use `saml_group_role_map`/`ldap_group_role_map` (target
`__admin__`) — that is the operator's decision in the configuration, not an attribute inside a
sign-in.

Alternatively `auth.ensure_admin("admin", os.environ["INITIAL_PW"])` seeds an admin before the app
ever serves a request — best when you deploy from a script.

### Lost the admin password, with no mailer?

A preset built for internal tools (`local_accounts()`) deliberately has no “forgot password” and no
magic link — both would need a mail server. And the two bootstrap paths above only work **while no
admin exists**. With a single admin account and no second one to help, that is a dead end. The way
back runs over the database file, which you own anyway:

```bash
python -m tinysesam passwd --db auth.db admin     # asks twice, then sets it
```

It ends that account's open sessions (`--keep-sessions` keeps them) and writes an audit entry.
`--stdin` reads the password from standard input for scripted use. Same thing from Python:

```python
auth = TinySesam(TinySesamConfig(db_path="auth.db"))
auth.set_password(auth.find_user("admin")["id"], "new-password")
```

## Backups and housekeeping

```bash
python -m tinysesam backup --db auth.db auth-2026-09-21.db   # consistent copy, while running
python -m tinysesam gc     --db auth.db                      # expired sessions/flows/tokens
```

> **Do not back up the database by copying the file.** It runs in WAL mode: everything since the
> last checkpoint lives in `auth.db-wal`, not in `auth.db`. A `cp`/`rsync` of the `.db` alone
> gives you a torso — measured on a fresh instance with five accounts, the copy did not even
> contain the `users` table, and you only find out when you restore it. `backup` uses SQLite's
> online backup: it takes the locks it needs, pulls the WAL in, and writes a file that stands on
> its own, with the same tight permissions as the source. The supported way is this command;
> `auth.store.backup(path)` does the same from Python, but `auth.store` is internal (tier C, no
> promise — see [Public API](#public-api-three-tiers)).

`gc` deletes expired sessions, flows, one-time tokens and old login attempts; the audit log is
left alone on purpose. **Nothing runs it for you** — ready-made unit files are in
[`deploy/systemd/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/systemd). From Python:
`auth.gc()` returns the same counts as a dict. Note that `gc` does not hand disk space back to the
filesystem; after a large cleanup, run `sqlite3 auth.db 'VACUUM;'` once with the service stopped.

### Restoring a backup

```bash
systemctl stop tinysesam                                  # the service must be down
python -m tinysesam restore --db auth.db backup-2026-09-21.db
systemctl start tinysesam
```

> **Do not just copy the file back either.** After a crash, `auth.db-wal` and `auth.db-shm` are
> still lying next to the database. SQLite replays them onto the file you just restored — the old
> state is back, with no error, and `PRAGMA integrity_check` says `ok`. `restore` removes both
> first, checks the backup before overwriting anything (integrity, account count, schema version),
> and sets `0600` afterwards.

> **Rolling back needs a backup in the old schema.** Each release that adds columns migrates the
> database on first start — 0.18.0 did it once (schema 5), 0.19.0 took it to **schema 8**
> (per-app OIDC grants, key kind, first login and enrollment window), 0.20.0 takes it to
> **schema 10** (9: stable directory keys for LDAP/SAML; 10: indexed lockout buckets and
> name/address lookups, and panel locks from earlier releases become operator locks). Older code then opens the
> file without complaining, `/healthz` stays green and accounts are readable — but every session
> operation raises. Take a backup *before* the update (`tinysesam backup` leaves the source
> untouched) and restore that one. If older code did run on the new file, the next start of the
> new release catches up on two things: locks set in the older panel become operator locks
> (recognised by their audit rows), and addresses of its pending sign-ups count as unverified until
> confirmed; the log carries a warning. Nothing else is reconciled — the safe way back is the backup.

**Coming from 0.17.x or older?** `tinysesam backup` only exists since 0.18.0, and the first start
of the new release already migrates. So take the backup with the *new* version before it starts —
`backup` opens the source read-only and leaves it in the old schema:

```bash
# Container: pull the new tag, back up, only then start it (service name as in your compose file)
docker compose pull
docker compose run --rm --no-deps --entrypoint tinysesam tinysesam \
    backup --db /data/gateway.db /data/gateway-before-update.db
docker compose up -d

# Library: after installing the new version, before restarting the service
python -m tinysesam backup --db auth.db auth-before-update.db
```

Or stop the service and copy `auth.db` together with `auth.db-wal` and `auth.db-shm` (where they
exist) into a separate directory; to go back, put all three back with the service stopped.

### Diagnosing "I can't get in"

```bash
python -m tinysesam audit  --db auth.db --user alice    # the audit log, from the command line
python -m tinysesam unlock --db auth.db alice           # lift a brute-force lockout
```

The audit log records *why* a sign-in failed (`kein_konto`, `konto_gesperrt`,
`falsches_geheimnis`) — the HTTP response deliberately does not, so it cannot be used to probe for
accounts. The log is only read by the operator.

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
- **Owners, idle timeout, encrypted TOTP secrets, IdP revocation:** owners are admins that cannot be
  deleted, disabled or demoted (at least one, hand-overable, `tinysesam owner` as the emergency
  path); sessions without "stay signed in" end after 8 h of inactivity (`session_idle_minutes`); TOTP
  secrets are stored AES-256-GCM-encrypted — **back up the key** (`TINYSESAM_SECRETS_KEY`,
  `secrets_key_file` or `<db>.key`) separately; an OIDC session re-checks its refresh token every
  `oidc_session_refresh_minutes` and ends when the provider says no. Details: `docs/BETRIEB.md`.
- **Lockout notice** (ASVS 6.3.5): with a mailer configured, the verified address of a locked-out
  account gets one notice per lockout window (opt-out `notify_login_failures=False`).
- **Consecutive failures, no window** (`account_max_consecutive_failures`, default 100): every
  failed sign-in attempt under a name extends a series; at the limit sign-in is locked — and unlike
  the window thresholds this lock does not expire. It ends with a successful full sign-in over
  another path (passkey, sign-in link, OIDC), a password reset (only the first-factor share — failed
  TOTP codes and a PIN entered after another factor stay), a new password from the admin panel
  or `tinysesam unlock`. Counted per name whether the account exists or not, so the lock reveals
  nothing. NIST SP 800-63B caps consecutive failures at 100: slow guessing below every window
  threshold no longer runs forever.
- **Password length by factor situation:** a new password needs `password_min_length_single_factor`
  (default 15, NIST SP 800-63B) when it can sign in on its own — no `login_chain`, one with
  nothing but `password`, or a chain whose second factor accounts may enrol themselves
  (`mfa_enrollment` `first_login`/`grace`) — and `password_min_length` (default 8) only when the
  chain enforces a second factor that the operator hands out (`mfa_enrollment="strict"`). Existing passwords stay valid; the rule applies wherever one is set. The CLI
  (`tinysesam passwd`) doesn't read the configuration and takes the stricter one.
- **Method-scoped counters next to the login lockout:** the PIN (short keyspace,
  `pin_max_attempts`), the account page's current-password prompt
  (`password_change_max_attempts`), the step-up confirmation (`reauth_max_attempts`) and the
  area PIN (`resource_max_attempts`) each get their **own** pot. All of them are throttled and
  logged, but a wrong guess there does not lock the **login**: otherwise a few typos on your own
  account page would lock you out — behind NAT, colleagues who had nothing to do with it, and at
  the area PIN even passing visitors who have no account at all. Which method is not a sign-in
  attempt is listed in `security.NICHT_LOGIN_METHODEN` — derived from `security.EIGENE_SPERRE`,
  so no method can end up without a brake. The pots of the **signed-in** paths (password change,
  step-up) deliberately count per account only, not per IP: guessing there requires a valid
  session for that very account. The area PIN keeps the IP threshold — there the guesser is
  anonymous.
- **Rate limiting:** token bucket per IP on the login/2FA endpoints (`rate_limit_max` / `rate_limit_window_sec`).
- **fail2ban:** every failed attempt is logged via the `tinysesam.security` logger with the real client IP
  (`failed login … ip=…`). Filter + jail in [`deploy/fail2ban/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/fail2ban/) → IP ban at the firewall level.
  **Only real sign-in attempts carry `failed login`.** A wrong guess that was not a sign-in
  (password change, step-up confirmation, area PIN) is logged as `failed verification …` and is
  deliberately **not** banned by the shipped jail: those lines come from someone who is already
  signed in — with `maxretry = 6` a legitimate user locked themselves out after a few typos on
  their own account page, for the whole instance. To ban them anyway (say, for publicly offered
  area PINs), add `tinysesam-verify-filter.conf` and the second, milder `[tinysesam-verify]`
  jail; it ships disabled.
  Set `security_log="/var/log/tinysesam/security.log"` and TinySesam writes that file itself — the shipped
  jail points at it and would otherwise watch a file that never appears. Leave it empty if you wire up
  logging yourself; an unwritable path warns at startup instead of stopping it. The file is created
  with mode **0640** (usernames and IP addresses are in it), and so is the one created after a
  rotation; an already existing world-readable file is reported, not rewritten. If a **third** user
  has to read along (log shipping, neither owner nor in the group), grant it through the group:
  logrotate line `create 0640 tinysesam adm` — without it the next rotation puts the file back on
  the group of the TinySesam process and the shipper loses read access, not at update time but at
  the next rotation.
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
  Every sign-in issues a fresh token, signing out deletes it; a step-up keeps it.
  Rendering your own pages? `csrf = auth.ensure_csrf(request, response)` reuses the browser's
  token or sets one — see "CSRF in your own pages" above.
- **Rate limit across processes:** optional Redis (`redis_url`, extra `[redis]`) for multi-worker; otherwise in-memory.
- **User enumeration:** login/PIN check against a dummy hash even for an unknown user (no timing leak).
- **After a password change** the user’s remaining sessions are ended (admin reset: all).
- **Housekeeping:** `auth.gc()` deletes expired sessions/flows/magic tokens/resource unlocks + old
  login attempts (the audit log stays). Call it regularly (cron/startup/scheduler) — otherwise the tables grow.

## Installing and updating

**TinySesam does not update itself.** You decide the version, in exactly one place: where you
install the library. An auth module that pulls code from the internet at runtime is a backdoor
with a manual — whoever takes over the admin panel could roll back to an old version with a known
hole. Established auth projects don't ship such a button, and as of `v0.12.0` neither does TinySesam.

### As a library (inside your own app)

Put a **fixed version** in your app's dependencies — never a branch:

```
tinysesam[oidc]==0.24.9
```

A released version on PyPI never changes: the same line installs the same code tomorrow. Updating
means: bump the line, reinstall, restart the service. Python does not reload code at runtime.

The same pin via git, if you install that way — note that a **tag can be moved**; for real
immutability pin the commit (`@a1b2c3d…`):

```
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.24.9
```

Every release also attaches a **wheel** and an **sdist**, with `SHA256SUMS`. To install without
git and without an index, take the file directly:

```
pip install https://github.com/Ollornog/TinySesam/releases/download/v0.24.9/tinysesam-0.24.9-py3-none-any.whl
```

### As a gateway (its own container)

Every release builds an image for `linux/amd64` and `linux/arm64`:

```
ghcr.io/ollornog/tinysesam:v0.24.9
```

It runs as **non-root** (uid 1000), contains neither `pip` nor `git`, ships a `HEALTHCHECK` on
`/healthz` and starts the gateway directly — no `command:` needed.

**Check where it came from.** A digest proves an artifact hasn't changed since it was built — not
who built it. Every release therefore carries a Sigstore-signed provenance attestation and an SBOM,
both also stored next to the image in the registry:

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.24.9 --owner Ollornog
gh attestation verify tinysesam-0.24.9-py3-none-any.whl --owner Ollornog   # wheel and sdist too
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.24.9 --owner Ollornog \
    --predicate-type https://spdx.dev/Document                             # the SBOM
```

A pass means: built by this repository's release workflow, from the commit the attestation names.
No key to hand out and none to lose — the signature is tied to the workflow's own identity. A full example with Caddy
lives in `deploy/forward-auth/docker-compose.yml`.

Update: bump the tag, `docker compose pull && docker compose up -d` — if the release migrates
the database, take the backup in between (see "Restoring a backup"; from 0.17.x or older with
the new image). Rollback: put the old tag back, after a migration together with that backup.
**There is deliberately no `latest`** — a moving tag turns every restart into a gamble.
If you're serious, pin the digest (`ghcr.io/ollornog/tinysesam@sha256:…`, printed in the release
workflow log): a tag can be moved, a digest cannot.

### How do you learn there is something new?

From the [releases feed](https://github.com/Ollornog/TinySesam/releases) — via watch, RSS
(`releases.atom`), or a bot like Renovate/Dependabot that bumps the pin in a pull request. Then your
CI runs against the new version and you decide whether to merge. The running version is shown by
`python -m tinysesam version` and in the admin panel under "Hardening".

## Several apps, one TinySesam

One installation can protect several apps — and **the identity provider decides who gets into
which one**. That matters because with PocketID (and every provider that works this way) the
release is attached to the *OIDC client*, not to the user. With a single client there is only
one answer for every app: whoever is allowed into one is allowed into all of them.

Give each app its own client at the provider, then map host → client:

```python
cfg = TinySesamConfig.oidc_gateway(
    issuer="https://id.example.com",
    client_id="gateway", client_secret=os.environ["GATEWAY_SECRET"],   # fallback for unlisted hosts
    base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com", "wiki.example.com"],
    clients={
        "app.example.com":  {"client_id": "app",  "client_secret": os.environ["APP_SECRET"]},
        "wiki.example.com": {"client_id": "wiki", "client_secret": os.environ["WIKI_SECRET"],
                             "group_role_map": {"editors": "editor"}},
    },
    revalidate_minutes=60,
)
```

All clients point at **one** redirect URI (`base_url` + `/auth/oidc/callback`) — which client a
run belongs to is kept server-side, not in the URL. At the provider you therefore enter the same
address for each one.

**A release follows the provider.** `revalidate_minutes` says how long a release is trusted
before TinySesam asks again. When the time is up the next request takes a trip through the
provider; its session is usually still alive, so people see a flicker rather than a login. If the
group was taken away in the meantime, the provider says no — and shows **its own** message,
because that is where the release is maintained. The session itself stays: the other apps keep
working. `0` turns the check off, and a withdrawal then only takes effect when the session
expires (seven days by default).

As environment variables (gateway container):

```
TINYSESAM_OIDC_CLIENTS='{"app.example.com": {"client_id": "app", "client_secret": "..."}}'
TINYSESAM_OIDC_REVALIDATE_MINUTES=60
```

A config with a single client behaves exactly as before — no host mapping, no release to expire.

## API keys & service/daemon accounts

For **machine access** (scripts, other services, system daemons) — alongside the interactive login:

- An API key belongs to a user, sits **hashed** (sha256) in the DB, optionally with an **expiry** and **role scope**.
- Sent as `Authorization: Bearer tsk_…` **or** `X-API-Key: tsk_…`.
- **`require_user` accepts a session OR a valid key** — protected routes are reachable by key without any change; `require_role(...)` honors the key scope.
- **System daemons** = **service account** (`auth.create_service("backup-daemon", roles=["reader"])`, no login/MFA) + key (`auth.create_api_key(uid, name=…, expires_days=…)` → plaintext **once**). Least privilege via the roles.
- **Disable instead of delete:** `auth.revoke_api_key(id)` (key disabled, stays in the list). Self-service routes: `GET/POST /auth/apikeys`, `POST /auth/apikeys/{id}/revoke`.
- **Two kinds of key, and neither one is an admin API.** `kind="automation"` (the default) works
  on its own but **never carries its owner's admin flag** and satisfies no route that requires
  admin — the way for services, scripts and CI. `kind="human"` is only valid **together with a
  live session of the same account**, and in return carries full rights — the way for a tool a
  human drives themselves. On its own, a leaked one is worthless. Until 0.18.x there was one kind,
  and an admin's key was a complete write API: create users, set `is_admin`, reset passwords — no
  second factor, no CSRF layer. A leaked CI key was the instance. (Up to 0.21.x the kinds were
  called `automat` and `mensch`; since 0.22.0 those names are an input error that names the new
  one, and the migration rewrites stored keys — rolling back: `docs/BETRIEB.md`.)
- **Keys expire by themselves.** Without `expires_days` a key used to live forever, and that was
  the common case. `apikey_default_days` (90) now applies; `expires_days=0` still means
  "unlimited" but needs `apikey_allow_unlimited=True` and lands in the audit entry.
- **A key is a second front door, so locking an account out takes it along.** An admin password
  reset and disabling an account revoke that user's keys; so does the user's own "end **all**
  sessions" (`scope=all`). A user's own password change deliberately does **not** — a routine
  change shouldn't silently kill their integrations — but the response and the audit entry say
  how many keys are still live (`api_keys_active`). Keys of a disabled account never
  authenticated in the first place.

## Admin panel

Built-in panel at **`/auth/admin`** (`is_admin` only), embeddable with no extra setup:

- **Users & service accounts:** create, **explicitly disable/enable** (`disabled` — account stays, login blocked, sessions end immediately; self-lockout protection; in code: `auth.set_disabled`), password reset, set roles/admin.
- **API keys** per user: generate (shown once) / revoke.
- **Sessions:** view active ones + end them.
- **Hardening:** tune the thresholds (attempts/lockout time/rate limit) live.
- **Version:** the running version plus a note on how updates work — there is **no “update
  now” button**, and deliberately so ([ADR-2](https://github.com/Ollornog/TinySesam/blob/main/backlog/ADR-2-kein-selbst-update.md)):
  an auth module that loads code at runtime is a back door with a manual. You update where you
  installed it. (This line used to promise a button, a manual/auto mode and a version pin —
  none of which has existed since 0.12.0.)
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
  A typo is rejected at construction — anything other than `force` silently means „no redirect",
  so `https_mode="forse"` would have turned the HTTPS requirement off without a word.
- **`https_mode="force"` requires `cookie_secure=True`.** The combination with `cookie_secure=False`
  is refused at construction: an app that redirects every request to HTTPS but hands out its session
  cookie without the `Secure` flag contradicts itself — one plain HTTP call is enough to leak it.
  `cookie_secure=False` stays valid for local setups without a certificate (`https_mode="warn"`).
- **Content-Security-Policy** (`config.csp`): the built-in pages (login, account, TOTP setup, error)
  ship a **strict, nonce-based CSP** — no `unsafe-inline`. A fresh nonce per response goes into every
  `<script>`/`<style>` and the header; the pages are built inline-free (no `onclick`/`onsubmit`, no
  `style=`) so the nonce covers everything. `"strict"` (default), `"off"` (no header — e.g. a proxy
  sets the CSP), or your own policy string (a `{nonce}` in it is substituted per response). A template
  override returning a `Response` is left untouched and gets `ctx["nonce"]` to build its own.

## New in 0.5 — quick reference

All optional (on/off by config), usable individually and combined, front end replaceable everywhere.

- **Replaceable front end:** `auth.set_template(name, fn)` — `fn(auth, ctx)` returns an HTML string **or**
  its own `Response`. All 13 names: `login`, `pin`, `totp`, `totp_setup`, `reauth`, `account`,
  `register`, `forgot`, `reset`, `magic_request`, `magic_invalid`, `resource_unlock`, `error`.
  Built-in renderers are the fallback; `tinysesam.templates.DEFAULTS` holds the current list.
- **Stay signed in:** `remember_me_enabled` — checkbox → persistent cookie; unchecked = pure
  session cookie + short `session_ttl_transient_hours`.
- **Step-up / per-route MFA:** `Depends(auth.require(mfa=True))` (sudo freshness `stepup_max_age_sec`,
  → `/auth/reauth`). `admin_require_mfa=True` additionally protects the panel with a fresh confirmation.
- **Factor chains (ordered):** `login_chain=["oidc","password"]` + `login_chain_strict`; per route
  `require(factors=[...], strict=...)` on top of the global rule. Factors: `password, pin, oidc,
  passkey, totp, magic`.
- **PIN per user:** `pin_enabled` — user+PIN, its own strict lockout, combinable with TOTP.
- **Shared resource secret:** `resource_locks_enabled` — `auth.set_resource_secret(name, secret,
  kind="pin"|"password")`, guard `Depends(auth.require_resource(name))`, with no user account at all.
- **Magic-link:** `magiclink_enabled` + SMTP config **or** `auth.set_mailer(fn)`; `/auth/magic/request`,
  redeemed at `/auth/magic/{token}` — **that endpoint is the sign-in link and nothing else.**
- **`base_url` is mandatory** as soon as a mail path (`magiclink_enabled`,
  `password_reset_enabled`, `signup_verify_email`), `oidc_enabled` or `saml_enabled` is on —
  otherwise the constructor raises `ConfigError` and says what to put in. It is the only source
  for the address in reset, magic, confirmation and invitation mails, for the OIDC redirect URI
  and for the SAML entity ID. Without it TinySesam would have to fall back to the request's
  `Host` header — which the *requester* sets, so an attacker triggering a reset for someone else's
  mailbox could point the link at their own server. `trusted_redirect_hosts` is no substitute:
  with more than one host listed, the `Host` header would still pick which one ends up in the
  link. **Mounted under a sub-path** (`root_path`), the prefix belongs in `base_url`:
  `base_url="https://example.com/sso"` — and it applies to the **mailed links**, which carry it
  exactly once. The built-in pages and their redirects take the same prefix from the path of
  `base_url` (without `base_url`: from the request's `root_path` — `uvicorn --root-path /sso` behind
  a proxy that strips `/sso`, or a Starlette `Mount("/sso", app)`). `login_path`, `login_redirect`,
  `logout_redirect` and `admin_path` are paths of the app *without* the prefix. (Not `FastAPI(root_path=...)` on the app
  itself: that setting leaves the request path without the prefix, and `next=` targets built from
  it would point outside the mount.) The same one rule holds for the methods
  themselves, not just for the built-in routes: `magic_url`, `send_password_reset`,
  `send_login_link`, `send_verify_email` and `create_invite` all go through `public_base()`. With
  `base_url` set it wins — even over a second host of your own listed in `trusted_redirect_hosts`.
  Without it, a foreign base is rejected with `ConfigError` (no token, no mail). Building your own
  form? Take the base from `auth.public_base(request)` — empty means "no trusted address, abort" —
  never from `str(request.base_url)`.
- **Registration + invitation:** `allow_signup` (+ `signup_verify_email`, `signup_invite_only`);
  admin invite `auth.create_invite(email, base_url, roles=…)`. Each mailed link has **its own
  endpoint**: `/auth/verify/{token}` (address confirmation), `/auth/invite/{token}` (invitation),
  `/auth/reset?token=…` (password reset). They depend on their own feature, not on the magic link —
  turning `magiclink_enabled` off no longer takes confirmation and invitation with it.
- **Account page:** built in at `/auth/account` (`account_enabled`) — password/PIN/2FA/passkeys/keys.
- **Forward-auth:** `forward_auth_enabled` → `GET /auth/forward` (200 + `Remote-User/Groups/Email` or
  401 + `X-TinySesam-Location`). Examples: [`deploy/forward-auth/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/forward-auth/) (Caddy/nginx/Traefik;
  `nginx-pfad.conf` covers the other common shape — one host, individual paths protected, static files + PHP behind it).
  **Roles at the proxy:** have the proxy ask for them — `GET /auth/forward?roles=editor,admin` or the header
  `X-TinySesam-Roles`. One of the listed roles is enough; signed in but missing the role answers **403**
  (not 401 — that would bounce the user to the login and straight back). Without the parameter the endpoint
  stays binary, exactly as before. Several specifications are AND-ed, so a client that adds one itself can
  only tighten the check, never loosen it.
  **Which headers go out** is `forward_headers` — default `Remote-User/-Name/-Email/-Groups` (the
  Authelia set) plus `Remote-Id`, the account ID: users can change their username and email
  themselves, so an app should key users by `Remote-Id`. **Never tie rights to `Remote-User` or
  `Remote-Email`:** a name or address that becomes free (account deleted or renamed) can be taken by
  another account, which then carries it into the app. Your proxy must set every one of these
  headers itself (the examples in `deploy/forward-auth/` do), or it passes a forged one through. Give it a mapping to rename or drop them: `{"user": "X-WEBAUTH-USER"}` sends that one
  header and nothing else (Grafana style), a list sends the same value under several names. The mapping
  is the complete list, so leaving `email` out is how you stop handing the address to the app. Rename
  something? Pull the new name through in your proxy config too.
- **Open-redirect protection:** every `?next=` runs through `safe_next` (relative paths only, or
  `trusted_redirect_hosts`; the host of your own `base_url` always counts and needs no repeating).
  **`cookie_domain` for SSO across subdomains** — and note what happens without it: the session cookie
  is host-only, so the login page is built **on the host that was requested** rather than on `base_url`.
  Otherwise TinySesam would set the cookie on host A and send the browser to host B, where it is not
  sent back — a redirect loop with no error message anywhere. Hosts other than those in
  `trusted_redirect_hosts` are never used for this, so a forged `X-Forwarded-Host` cannot redirect
  anyone. `base_url` itself stays untouched; OIDC/SAML callbacks keep the one fixed address.

Full demo: [`examples/showcase.py`](https://github.com/Ollornog/TinySesam/blob/main/examples/showcase.py) — `/` is the project website itself,
`/demo` a front end whose login/account/admin panels are **live read-only previews** of the real pages (`uvicorn examples.showcase:app`).

**The live demo is an example front end that ships with the project** — not part of the library and
not a prescription. It shows one way to wire up the built-in pages; look and structure are yours to
replace. Bring your own front end, or take this one as a starting point.

## LDAP / lldap

Password login can be checked against a directory (lldap, OpenLDAP, AD) — as a backend behind the
normal password form (factor `password`). `pip install 'tinysesam[ldap]'`:

```python
TinySesamConfig(
    ldap_enabled=True, ldap_url="ldaps://lldap:6360",   # or ldap:// + ldap_start_tls=True
    ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com",   # direct bind (lldap)
    # OR search-then-bind: ldap_bind_dn=…, ldap_bind_password=…, ldap_user_base=…, ldap_user_filter="(uid={username})"
    ldap_allowed_groups=["staff"],   # optional gate (memberOf), empty = all
    ldap_auto_create=True,           # create an unknown LDAP user locally
    # ldap_tls_ca_file="/etc/ssl/own-ca.pem",   # internal CA; empty = system store
)
```
Local passwords and LDAP coexist (local first, then LDAP). Roles/2FA/chains apply as usual.

> **Plain text needs saying so.** `ldap://` without StartTLS sends the service account's password
> *and* every user password over the wire on every sign-in. Since 0.20.0 that is a **startup
> error**; `ldap_allow_plaintext=True` says out loud that this is what you want (a directory on
> the same host). The certificate is checked by default (`ldap_tls_verify`), and the service
> account binds **after** the TLS upgrade, not before it.

> **Identities are bound by a stable key, not by a name.** A username isn't forgery-proof:
> rename someone in the directory, or recreate a deleted account under the same name, and until
> 0.19.0 you'd land in the same local account with its roles. LDAP now binds `entryUUID` /
> `objectGUID` (`ldap_attr_id`), SAML the `NameID` (`saml_attr_id` for IdPs that issue transient
> ones). An account already bound to a *different* key is never taken over — that case is
> refused and audited. Accounts from before this version bind themselves by name on their next
> sign-in, once, also audited — but only within `federation_name_binding_days` (default 30) of the
> first start with the source enabled or of the account's creation; after that a dormant account
> would fall to the next person who gets the same name in the directory. Bind the rest explicitly:
> `auth.federation_bind_existing("ldap")` (dry run by default, `apply=True` writes; SAML takes
> `mapping={name: nameid}`), or open a single account with `auth.federation_unbind(source,
> user_id)`. A self-chosen name (sign-up, self-service rename) never binds by name, and neither
> does a name another source brought along when it created the account (an account created via
> OIDC never binds to LDAP or SAML by name — the name may have been self-chosen at the IdP). If the
> directory supplies no stable key, the name still decides and a log line says so;
> `federation_require_stable_id=True` turns that into a refusal.

> **Referrals are never followed** — and that is visible in the log. ldap3 follows a
> `SearchResultDone resultCode=10` on its own and binds on the host named by the *answer*, with the
> same credentials (that was finding F-28: the service account's DN and cleartext password arrived
> at a foreign server). TinySesam therefore sets `auto_referrals=False` on every connection, with
> no switch to turn it back on. The price: a search a directory answers by referral ends with no
> result, so the sign-in fails and looks like a wrong password. That case now writes a line to the
> `tinysesam.security` logger naming the referred host — **if you see it for every user of a
> domain, query the Global Catalog** (port 3268/3269) and point `ldap_user_base` at the forest
> root, instead of searching a single domain controller that refers you onward.

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

> **Set `saml_idp_entity_id` unless you know it equals the SSO URL.** Left empty, TinySesam assumes
> the IdP calls itself by its SSO URL. Keycloak (and others) don't: it is
> `https://…/realms/<realm>`, while the SSO URL ends in `/protocol/saml`. Get it wrong and **every**
> assertion is rejected with `Invalid issuer`. Copy it from the IdP's metadata (`entityID=`).
> Whenever an assertion is rejected, the reason goes to the `tinysesam.security` logger — never to
> the browser.

> **SP-initiated only, and it needs `cookie_secure=True`.** Every assertion must answer an
> `AuthnRequest` this app actually sent: `/auth/saml/login` stores the request ID in a short-lived
> cookie and the ACS rejects anything whose `InResponseTo` doesn't match. That closes login-CSRF —
> without it, anyone holding a valid assertion could post it into someone else's browser. Two
> consequences: **IdP-initiated logins no longer work** (start at `/auth/saml/login`), and the
> cookie only survives the IdP's cross-site POST as `SameSite=None; Secure`. With
> `cookie_secure=False` it falls back to `cookie_samesite`, which a browser won't send on that
> POST — fine for local runs and the test client, broken against a real IdP. The reason is in the
> `tinysesam.security` log.

> **Every field, in one place:** [`KONFIGURATION.md`](https://github.com/Ollornog/TinySesam/blob/main/KONFIGURATION.md)
> lists all 120 config fields with type, default and meaning — generated from `config.py`, so it
> cannot drift. This README explains the *ways*; that page answers *“there's a field — what does
> it do?”*

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
forward-auth **gateway** — no app of your own, just `pip install 'tinysesam[gateway]'`:
(`[gateway]` = `[oidc]` **plus an ASGI server**. With `[oidc]` alone the start command below
ends in `ModuleNotFoundError: uvicorn` — that combination used to be what this page told you
to run.)

```bash
export TINYSESAM_OIDC_ISSUER=https://id.example.com \
       TINYSESAM_OIDC_CLIENT_ID=gateway TINYSESAM_OIDC_CLIENT_SECRET=… \
       TINYSESAM_BASE_URL=https://auth.example.com \
       TINYSESAM_COOKIE_DOMAIN=.example.com \
       TINYSESAM_PROTECTED_HOSTS=app.example.com,wiki.example.com
python -m tinysesam.gateway          # or: uvicorn tinysesam.gateway:app
```

The reverse proxy calls `GET /auth/forward` per request. The gateway mounts the full `/auth/*`
router — with `password_enabled=False` and OIDC as the only method, what remains is the OIDC
sign-in, the forward-auth endpoint, logout and `/me`. It is a narrow configuration, not a
single-route app.
Programmatically: `TinySesamConfig.oidc_gateway(issuer=…, client_id=…, client_secret=…, base_url=…)`.
A ready-made [`deploy/forward-auth/docker-compose.yml`](https://github.com/Ollornog/TinySesam/tree/main/deploy/forward-auth/) (gateway + Caddy) ships with it.

### Gate token: the proxy checks for itself (ADR-9)

In front of a third-party app the proxy otherwise asks `/auth/forward` for **every** request —
every script, stylesheet and icon included. With `gate_token_enabled=True` (gateway:
`TINYSESAM_GATE=1`) a successful check also returns a short-lived token signed with Ed25519. The
proxy stores it as the cookie `__Host-tinysesam_gate` on the app's host and from then on checks it
**itself**; TinySesam is only asked again when it is missing or expired. The way back is the
existing forward auth, so a request and its body are not lost.

- **Proxy:** Caddy with the [caddy-jwt](https://github.com/ggicci/caddy-jwt) plugin — template
  [`deploy/forward-auth/Caddyfile.gate`](https://github.com/Ollornog/TinySesam/blob/main/deploy/forward-auth/Caddyfile.gate),
  build [`deploy/forward-auth/caddy-gate/Dockerfile`](https://github.com/Ollornog/TinySesam/blob/main/deploy/forward-auth/caddy-gate/Dockerfile).
- **Key:** derived from the installation's base key (`TINYSESAM_SECRETS_KEY`) — no second secret.
  `tinysesam gate-key --db …` prints the public half for the proxy.
- **Roles:** if the proxy requires roles (`X-TinySesam-Roles`), they are part of the token's
  audience (`app.example.com|roles=admin`); a token issued without roles does not count there.
- **Cost:** signing out, locking an account or a withdrawn grant only takes effect at the proxy
  once the token expires — `gate_token_ttl_sec`, default 300 seconds.

### Signing in at the gate: invisible or with a page (T-21)

`forward_login="direct"` — **the gateway's default** — sends someone who is not signed in straight to
the identity provider on a page load and back to the address they asked for; with an existing
session there, all they see is a redirect. `"page"` (the library default) shows the sign-in page
first. Per app, including a name on the sign-in page:

```python
forward_apps={"wiki.example.com": {"name": "Wiki", "login": "page"}}   # "Sign in to Wiki"
```

Gateway: `TINYSESAM_FORWARD_LOGIN`, `TINYSESAM_FORWARD_APPS` (JSON). `direct` requires OIDC to be the only
method. Background requests (XHR, scripts) still go to the sign-in page: they could not show the
provider's page, and each would start an OIDC flow of its own.

### One gateway for many apps, without a shared session cookie (T-26)

With `gate_link_enabled=True` (gateway: `TINYSESAM_GATE_LINK=1`) the session stays on the gateway's host
(`base_url`, no `cookie_domain`). An app host gets, through a code exchange, only a connection cookie of its
own that is valid for that host alone: `/.tinysesam/start` (app host) → `/auth/gate/authorize` (gateway,
sign-in if needed) → `/.tinysesam/callback` (app host, one-time code bound to the browser). No app ever sees
the session that would get you into the others. Signing out “everywhere” at an app ends the session at the
gateway and with it every connection — also after the app was signed out “here only” before (then via
`/auth/gate/logout` on the gateway). `TINYSESAM_LANG` (`en`, `de`) picks the language of the gateway's pages.

### Public paths: share links (T-20)

With `TS_SHARE_PRAEFIX='^/(s|public/share)/'` both Caddy templates let paths through without sign-in
and without an identity. The raw path is checked; the rule rejects `..`, `;`, backslash, NUL and
their encoded forms (Tomcat and Spring read `/s/..;/admin` as `/admin`). Off by default. How to
measure an app's paths: `docs/BETRIEB.md`.

### Signing out at the app: here only or everywhere (T-22)

The app's sign-out link points to `https://app.example.com/.tinysesam/logout` — the proxy hands
`/.tinysesam/*` to TinySesam, past the gate (both Caddy templates do). What happens there is set by
`forward_logout` or `forward_apps[host].logout` (or `?scope=app|all` in the link):

- **`all`** (default): the session ends — it carries every app behind the same sign-in — and with
  `oidc_rp_logout` (on in the gateway) the one at the provider too, with the ID token as
  `id_token_hint`. The way back is `https://app.example.com/.tinysesam/after-logout`: register that
  address at the provider as a **logout callback URL**.
- **`app`**: this app only. The session stays; the app lets it through again once you choose
  “Continue as …” on the sign-in page or sign in anew.
- **`ask`**: a page asks “Sign out of Wiki only, or everywhere?”.

If the app signs out at the provider itself (its own RP logout), register `…/.tinysesam/after-logout`
as its logout callback URL as well: the provider then sends you here and the TinySesam session ends
too. Other apps in the same browser keep their gate token for at most `gate_token_ttl_sec`.

## Public API: three tiers

Not everything without a leading underscore is a promise. Since 0.22.0 every public name has a
**tier**, recorded in `tests/api_surface.json` and listed with signature and description in
[`API.md`](https://github.com/Ollornog/TinySesam/blob/main/API.md):

| Tier | What | Promise |
|---|---|---|
| **A — public, stable from 1.0** | what this README shows, and what embedding apps use | No breaking change across two minor releases — the condition for 1.0. The count starts with 0.22.0. |
| **B — for advanced use** | building blocks for your own account and admin pages (below) | Stays. Removed or reshaped only after a `DeprecationWarning` across two minor releases. |
| **C — internal** | the wiring of the built-in routes | None. Since 0.22.0 the implementation carries a leading underscore; the old name stays until 1.0 as an alias that warns when called, then goes. Don't start using them. |

A new public name has no tier until someone decides; the guard `tests/test_api_surface.py` stays
red until then, so nothing becomes a promise by accident. The config fields are tier A (except
one tombstone, marked in `KONFIGURATION.md`), and so are the error types (`TinySesamError`,
`ConfigError`, `StateError`, `MissingExtra`, `MailNotConfigured`).

**Tiers A and B are in English.** Up to 0.21.x some of these names were German
(`foederation_nachbinden`, `kennung_vergeben`, `SICHERHEITSEREIGNISSE`, parameters such as
`durch_betreiber`, `ConfigError.besitzer_id` …). 0.22.0 renames them **without an alias** — the
tier promises only start with this release; the full list old → new is in the
[CHANGELOG](https://github.com/Ollornog/TinySesam/blob/main/CHANGELOG.md). The guard fails on a
German word in any tier-A/B name, parameter, config field or error attribute.

**So are the keys and values** (0.22.0, also without an alias): what the tier-A/B methods return or
accept (the report of `federation_bind_existing`, `gc()`, `create_api_key`, the reason codes), the
`details` passed to `on_security_event`, the context of your own pages (`ctx["prefix"]`,
`ctx["purpose"]`), the JSON of the account and admin routes, and the API key kinds `automation`/
`human`. The two values that live in the database (the key kind, the `old` address in a pending
address-change link) are migrated on start (schema 12) and still read correctly in their old form;
rolling back to 0.21.x takes one SQL block from `docs/BETRIEB.md`. The same guard measures them on a
probe instance and in the source. **Audit and log lines stay as they are** — fail2ban filters and
your own filters depend on them (`apikey_create … art=automat` keeps its wording).

**`auth.store` is internal (tier C).** It is the storage layer the built-in routes use; its methods
have no tier, no promise and no deprecation period, and they may change in any release. Everything
an app needs has a public method (`set_disabled`, `find_user`, `list_api_keys`, `lift_lockout` …);
where the docs still mention an `auth.store` call (a health probe, dropping OIDC grants), they say
so.

**Tier C warns.** Calling an old tier-C name (reading one, for the constants) raises a
`DeprecationWarning` that names the replacement; [`API.md`](https://github.com/Ollornog/TinySesam/blob/main/API.md)
lists each one. Python hides these warnings outside `__main__` — to find them in your app, run its
tests once with `python -W error::DeprecationWarning`. A subclass that overrides one of these names
gets a `RuntimeWarning` when it is defined: the built-in routes call `_name` since 0.22.0, so the
override no longer takes effect. The same goes for a **test fake** on an old name —
`auth.check_password = fake` or `mock.patch.object(auth, "rate_ok", …)` is never called; the
assignment raises a `RuntimeWarning` naming the target. Put the fake on the new name
(`auth._check_password = fake`). Patching the class (`mock.patch.object(TinySesam, …)`) doesn't
warn and doesn't work either.

### For advanced use (tier B)

Building blocks for pages you build yourself — signatures and descriptions in
[`API.md`](https://github.com/Ollornog/TinySesam/blob/main/API.md), the “B” sections.

- **Your own account page:** `count_other_sessions` (other sessions to end?), `own_events`,
  `has_pin`, `disable_pin`, `generate_recovery_codes`, `recovery_codes_remaining`,
  `remove_passkey`, `totp_begin` → `totp_confirm`, `totp_enrollment_user`, `mfa_enrollment_allowed`,
  `federated_only` (SSO-only account: no password to change), `password_policy_error` (the rule for a
  new password; the change itself is `change_password`, tier A), `identifier_taken` and `NAME_MAX`
  (is a name or address free, how long may it be), `request_email_change` (hand its result to
  `after_response`) → `confirm_email_change`, `stepup_fresh` (the step-up itself: `confirm_*`,
  tier A), `pending_user`, `session_user`.
- **Your own admin panel or operator tools:** `get_user`, `find_user`, `user_roles`, `set_roles`,
  `delete_user`, `lift_lockout` (like `tinysesam unlock`), `list_api_keys`, `api_key_kind`,
  `verify_api_key`, `revoke_mfa_enrollment`, `list_resource_secrets`, `remove_resource_secret`,
  `resource_unlocked`, `all_security`, `admin_exists`, `admin_claim_token`, `audit`,
  `FEDERATED_SOURCES`, `NAME_BINDING_REFUSALS`.
- **Mail and token flows:** `mail_configured`, `send_mail`, `create_magic_token` → `magic_url` →
  `peek_magic` / `redeem_magic`, `TOKEN_PATHS`, `require_public_base`.
- **Proxy configuration for the gate token:** `gate_public_key` (`sign_key` for caddy-jwt, same as
  `tinysesam gate-key`), `gate_issuer` (`issuer_whitelist`).
- **Your own routes and extension points:** `client_ip` (the real client address behind
  `trusted_proxies`), `json_body` (JSON body with the CSRF check for cookie clients), `browser_path`
  (links to TinySesam pages under a mount prefix), `flow_cookie_name`, `t` (translated text in
  `config.lang`), `set_rate_limiter`, `apply_idp_groups`, `version` and
  `tinysesam.current_version()`, `PAGES` (the page names `set_template` accepts),
  `MFA_ENROLLMENT_MODES`, `TinySesamConfig.validate()` (re-check after changing `auth.cfg` at
  runtime), `TinySesamConfig.enabled_methods()`, `TinySesamConfig.pin_as_first_factor()`.
- **`apply_factor`** attaches a factor to the session **without checking it**. Call it only after
  you verified that factor yourself, with the account from `session_user()` — it is the most
  powerful block here, and a mistake in front of it is a way in. Not needed for password, PIN and
  TOTP: the building blocks `login_*` ([Your own login page](#your-own-login-page), tier A)
  check, throttle and then call it themselves.

## Tests & CI

```bash
pip install -e '.[all]' setuptools         # + httpx for the FastAPI TestClient (included in [all])
python tests/run_all.py                    # every suite; exit 0 = green, 1 = failure
python tests/run_all.py core pin chain     # only some
CI_TEST_JOBS=1 python tests/run_all.py   # one suite after the other
```

The suites run **in parallel**: `CI_TEST_JOBS` sets how many at once (otherwise `CI_KERNE`, which
the CI runner sets; otherwise 2 — no core detection; anything but a whole number ≥ 1 is an error). Each suite gets its own
throwaway directory, and the log lists the suites in file order, not in the order they finish —
`CI_TEST_JOBS=1` is the serial run. The runner starts every suite through `tests/_starter.py`,
which lowers the password-hash cost **inside that test process only**. A suite started directly
(`python tests/test_core.py`) and the package itself always hash with the production parameters —
there is no setting and no environment variable for them.

The suites are standalone assert scripts (no pytest). Three of them answer the question
"is anything broken?" without you having to look:

- **`tests/test_browser.py`** drives a headless Chrome over the DevTools protocol against the running
  showcase and checks what a user actually sees: no console errors, no failing requests, header/nav/footer
  on every page, equal widths, `?lang=` switching, dark mode down into the preview iframes, the login
  (including a simulated password autofill) and that an empty form yields a message, not a 422 JSON wall.
  Skipped when Chrome or `websockets` are missing.
- **`tests/test_repo.py`** guards the housekeeping: versions in `pyproject.toml`, `__init__.py` and the
  changelog agree; no generated HTML, no secrets, no stray `print()` in the library; colour values only in
  `theme.py`/`theme.css`; every suite is picked up by the runner.
- **`tests/test_site.py`** checks the generated site: both languages per file, one `?lang=` mechanism,
  the shell identical everywhere, imprint complete.
- **`tests/test_packaging.py`** builds the wheel and the sdist and looks inside: everything the package
  needs is really in there, the metadata is the one PyPI expects, and publishing needs no secret.
  (`setuptools` must be installed — without a build backend the suite would check nothing.)

**Before every push** — one gate, locally:

```bash
git config core.hooksPath .githooks   # once per clone: the pre-push hook runs the gate
scripts/check.sh                      # suites + browser + hygiene + website build
scripts/check.sh --fast               # without the browser test (only when in a hurry)
gh run watch --exit-status            # after pushing: fetch the CI result, exit != 0 when red
```

**GitHub Actions** runs all of it on **pushes to `main`, on pull requests and on demand**
(`workflow_dispatch`) — a push to a feature branch deliberately triggers nothing; that is what
`scripts/check.sh` is for. CI runs the full matrix (Python 3.12–3.14 with `[all]`), a minimal run
without extras (guards the stdlib-scrypt fallback), and a browser job that also builds the website.

## Status

**72 test files, all green** — one per feature, plus a combination matrix (`tests/test_matrix.py`).

Implemented and tested: password/TOTP/sessions/roles, remember-me, step-up and per-route MFA,
factor chains, personal PIN, shared resource secrets, magic links + mailer hook, registration and
invitation, the account page, forgot-password and TOTP recovery codes, session management,
API keys and service accounts, the admin panel (or just its JSON API), forward-auth plus the
OIDC gateway, a nonce-based CSP, and the command line (`backup`, `restore`, `gc`, `audit`,
`unlock`).

External identity providers — OIDC, SAML 2.0, LDAP/AD — and passkeys are implemented and tested
against a real provider on a staging host (`tests/e2e_stage.py`); the tests that ship with the
package cover them structurally, because they cannot dial out.

Two security audits went through the code in 2026-09 (see the `CHANGELOG`). The version is
deliberately **not** 1.0 yet: the tier-A surface ([Public API](#public-api-three-tiers)) has to
hold still for two minor releases first, counted from 0.22.0.

MIT license.

## Credits

Icon: <a href="https://www.flaticon.com/authors/maxicons" target="_blank" rel="noopener">Wizard PNG Image by max.icons - flaticon.com</a>
</content>
</invoke>

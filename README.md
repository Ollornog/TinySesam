<!-- Links here are ABSOLUTE: this file is also the project description on PyPI
     (pyproject.toml: readme = "README.md"), and nothing resolves relative repo paths there —
     the logo and seven links were dead on the package page. tests/test_repo.py enforces this.
     The German version under i18n/ is only read on GitHub and may stay relative. -->
<p align="center"><img src="https://raw.githubusercontent.com/Ollornog/TinySesam/main/docs/wizard.png" alt="TinySesam" width="250" height="250"></p>

<h1 align="center">TinySesam</h1>

<p align="center"><b>English</b> · <a href="https://github.com/Ollornog/TinySesam/blob/main/i18n/README.de.md">Deutsch</a></p>

<p align="right">
<a href="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="https://github.com/Ollornog/TinySesam/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/python-3.13%2B-blue.svg" alt="Python">
</p>

### The login layer for your self-built apps.

**Super-light auth for FastAPI** where you **use only what you need** — and that grows with you.
Hang one class in front of your app, done: login page, sessions and route guards included.

- **Just gate one page behind a PIN?** → yes. (`require_resource("photos")`, no user account at all)
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
- ✉️ **Magic-link** (one-time login by email — or handed out by the admin, without a mailer)
- 📱 **Cross-device sign-in** (QR code or short code, approved on a device that is already signed in)
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
pip install "tinysesam==0.31.0"
# core: password + TOTP. Everything: [all] — + argon2, QR, OIDC, passkey
pip install "tinysesam[all]==0.31.0"
# selective: [argon2] [qr] [oidc] [saml] [ldap] [passkey] [redis] [gateway]
```

Every release goes to PyPI from its git tag, via trusted publishing (no token), and each file
carries a PEP 740 attestation of the commit it was built from. The same version also installs
straight from the tag:

```bash
pip install "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@v0.31.0"
```

The Go gate client is a module in a subdirectory, so Go needs a tag with that prefix: release.yml sets
`clients/go/vX.Y.Z` on the same commit as `vX.Y.Z`, as its last step once everything else is green (the Go module
proxy keeps a version forever; the tag is never moved).

Drop the `@v…` when you want a **commit** rather than a released version — that pulls the moving
default branch, so it belongs in an experiment, not in a deployment.

**Testing a commit between releases** (`@<sha>`): it carries the version of the last release, so pip reports
"already satisfied" and keeps the installed code. Force it — with the dependencies, so a commit that adds or
changes an extra or a dependency (or a switch to `[all]`) brings what it needs:

```bash
pip install --force-reinstall "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@<sha>"
```

Quicker, when neither the extras nor the dependencies change: add `--no-deps` (only the package is replaced).

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

app = FastAPI(lifespan=auth.lifespan)           # orderly shutdown, see below
app.include_router(auth.router())              # /auth/* + login UI

@app.get("/")
def home(user = Depends(auth.require_user)):    # protected: logged in (incl. 2FA)
    return {"hi": user["username"]}
```

Non-logged-in browsers are redirected to `/auth/login`; API clients (Accept ≠ HTML) get a `401`.

**Shutdown.** TinySesam sends mails and notices from background workers that write to its database. `auth.close()`
refuses new background jobs, lets the queued ones finish (deadline `timeout`, 10 s) and then closes the database —
idempotent, `False` if a job was still running at the deadline (the database then stays open). `auth.lifespan` calls
it at FastAPI's shutdown; with a lifespan of your own, nest it (`async with auth.lifespan(app): yield`); in a script
or test, `with TinySesam(cfg) as auth:`. Never close `auth.store.db` yourself: a worker still inside SQLite crashes
the process.

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
([tier B](#public-api-two-tiers)).

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
- **Role names** carry no comma, no control character and no surrounding spaces: `Remote-Groups` and the gate token
  join roles with `,` without an escape, so `staff,admin` would arrive as two roles. The configuration check refuses
  such a name in every field, `create_user`/`set_roles` raise `ConfigError` (`field="roles"`), and an account that
  still holds one from older data gets `403` at the forward check until the role is removed.

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
| `GET/POST /auth/magic/request` | request a sign-in link by email *(magic links on and `magiclink_self_request`)* |
| `POST /auth/qr/start` · `/auth/qr/status` · `/auth/qr/finish` | new device: open, poll and collect a cross-device sign-in *(`qr_login_enabled`)* |
| `GET/POST /auth/qr/approve` · `POST /auth/qr/deny` | signed-in device: approve or refuse it *(`qr_login_enabled`)* |
| `GET /auth/setup` | setup pass after a sign-in link: set up what the `login_chain` demands; also asks for an own password after a sign-in with a password the admin set (T-46) *(`magiclink_enabled`, `qr_login_enabled` or `password_enabled`)* |
| `GET /auth/verify/{token}` · `GET /auth/invite/{token}` | confirm an address · accept an invitation |
| `GET /auth/logout` · `GET /auth/me` | log out · current user (JSON) |

**Managing a factor needs a fresh factor.** `POST /auth/totp/disable`, `/auth/totp/recovery`,
`/auth/pin/set`, `/auth/pin/disable` and `/auth/passkey/delete` require a step-up confirmation no
older than `stepup_max_age_sec` — otherwise 403 plus `X-TinySesam-Reauth: /auth/reauth` (browsers
are redirected there). An **API key can never satisfy it**: a machine credential never performs an
interactive factor, so it cannot take one away either. `/auth/reauth` itself answers a key with a
403 as well (`api.stepup_session`): there is nothing for it to confirm, and a key plus a password
must not stand in for the second factor of a half-finished sign-in (fixed in 0.20.1).

**Setting up TOTP hands out the recovery codes.** The confirmation (`POST /auth/totp/setup`) creates
`recovery_code_count` codes and returns them once (`recovery_codes`) together with the target
(`next` — the given one, otherwise the account page); the built-in page shows them and leads on only
after *I have written them down*. `/auth/totp/recovery` replaces them later (with step-up).

**Recovery codes can be switched off** (`recovery_codes_enabled=False`, T-94) — for people who would only stumble
over a list of codes. The setup then shows no code page and creates no codes, `/auth/totp/recovery` answers `404`, the
account page offers no code action, and no code is accepted anywhere. Codes an account already holds stay in the
database untouched (switch back on, and they work again). The price: a lost authenticator app needs someone who resets
it — the admin panel (account page, "Authenticator app (TOTP)" → "Reset", with a step-up; "Allow setup for 1 hour"
opens the setup window `grant_mfa_enrollment` for an account that may not set up by itself), `tinysesam reset-totp`
on the database, an application's `reset_access` (scope `users:reset`, below) or your own code (`totp_disable`,
`grant_mfa_enrollment`, then `create_signin_link`). `config_check` warns when the panel is off and no application has
`users:reset`. **`totp_app_hint`** puts a short hint per language above the QR code — which app to
install: `{"en": "Install Example Authenticator.", "de": "…"}` (plain text, escaped,
at most 300 characters, the page's `lang`, else `en`, else the first entry).

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

## Sign-in by link and from another device

Three ways in without typing a password, all built on the same one-time sign-in token
(`magic_token`, purpose `login`) — so the same rules everywhere: single use, short validity, and
**the second factor is still demanded**: an account with TOTP or a passkey must pass it after the
link (`magiclink_require_second_factor`, default on). Sign-in by link counts as factor `magic`.

- **Link by email** (`magiclink_enabled=True`, `magiclink_self_request=True`, a mailer): the login
  page offers "email me a sign-in link". Unchanged.
- **Link from the admin, without mail** (`magiclink_enabled=True`): the admin panel has a
  *Sign-in link* button per user (JSON: `POST <admin>/api/users/{id}/signin-link`, body
  `{"ttl_min": 60}`, 1 minute to `signin_link_max_ttl_min` — default 24 h, NIST SP 800-63B-4 §4.2.2; a week at
  most, set on purpose —, default `magiclink_ttl_min`). The link is shown **once**,
  as a link and as a QR code (extra `[qr]`), to hand over by any channel; it works without a mailer.
  It is discarded with the account's other open links when the account is disabled or its password
  is reset. Audit `signin_link_issue` with the admin as `actor=`. In code:
  `auth.create_signin_link(user_id, ttl_min=None, next="/")` → `{url, expires_at, qr}`.
  The address comes **only** from `base_url`, never from the request's `Host` header.
- **Links only from the admin:** `magiclink_self_request=False`. Then `/auth/magic/request` answers
  404 and the login page has no "send me a link" button — links the admin or your code issued still
  redeem. No mailer needed (`config_check` asks for one only with the self-request).
- **Cross-device (QR code)** (`qr_login_enabled=True`): the new device shows a QR code and a short
  code (*Sign in with another device*). On a device where you are signed in, scan it or open
  `/auth/qr/approve` and type the code: the page names the asking device (user agent, IP, age)
  before you approve. The new device then gets **its own** session. Valid `qr_login_ttl_sec`
  (default 120 s), single use, rate-limited, audited (`qr_login_approve`, `qr_login_deny`,
  `qr_login`). Only a full interactive session approves — no API key, no half sign-in. Whoever only
  sees the code on the screen gets nothing: the session goes to the device that opened the
  request (it holds a secret that is never displayed). The QR code needs `base_url` and the extra
  `[qr]`; without them only the short code is shown. No mailer needed.
  **Against consent phishing (H2, T-44):** the new device also shows a two-digit number that the
  approving device has to type (a wrong one voids the request); the approval page warns, wants a fresh
  confirmation and — with `qr_login_require_second_factor=True` (default) — an account with TOTP or a
  passkey, which the new device then has to present as well. `/auth/qr/status` is throttled.

### Recipe: the admin creates accounts, a link signs them in

Registration off, the admin creates the account (no password), hands out a sign-in link, and on the
first sign-in the person sets up exactly what your chain demands — only then are they fully signed
in. Afterwards they sign in through the chain, the link was only the door.

```python
auth = TinySesam(TinySesamConfig(
    base_url="https://auth.example.com",
    allow_signup=False,                          # nobody registers themselves
    magiclink_enabled=True,
    magiclink_self_request=False,                # links only from the admin (or your code), no mailer
    magiclink_first_login_only=True,             # a link signs in only for the first sign-in
    login_chain=["password", "totp"],            # what every sign-in needs — and what gets set up
))
uid = auth.create_user("dana", email="dana@example.com")     # no password
link = auth.create_signin_link(uid)["url"]                    # or the panel button "Sign-in link"
```

Dana opens the link → `/auth/setup`: set a password → set up the authenticator app (recovery codes
shown once) → signed in. Later: password + TOTP, as the chain says.

**Alternatives per chain step** with `|`: `login_chain=["password|passkey"]` lets the setup pass offer
a password *or* a passkey; `["password|passkey", "totp|passkey"]` asks for two different factors (one
passkey never counts for two steps). Factor names: `password`, `pin`, `passkey`, `totp`, `oidc`,
`saml`, `magic`.

The rules of the setup pass:

- It opens only at a link sign-in (mail, admin, app code, cross-device) of an account that cannot
  satisfy the chain with what it has, only with a `login_chain`, and only where self-setup is allowed
  (`mfa_enrollment`; `"strict"` → the operator opens a window with `grant_mfa_enrollment`).
- The half session can do nothing but set up the factor the page offers right now — no protected
  route, no account page, no admin, no API key. It expires with `stepup_max_age_sec` (measured from
  the link); disabling the account or a password reset ends it.
- The link replaces no factor the account **has**: an existing password (or PIN, passkey, TOTP)
  is provided first, as at any sign-in; the pass offers only missing factors and never replaces one.
- An account with TOTP or a passkey shows it before anything is set up (the same rule as
  `magiclink_require_second_factor`), unless the operator opened a setup window.
- `magiclink_first_login_only=True`: a link signs in only an account that has never been fully signed
  in, or one that lacks a factor and may set it up. A complete account gets "only for the first
  sign-in" — also from the admin. Lost a factor? Remove it in the panel, open a setup window
  (`grant_mfa_enrollment`), then hand out a link: the person provides what they still have and sets up
  the rest. Cross-device sign-in is not affected (its approval comes from a full session).
- Inside the pass the order of the chain is not enforced (the server dictates the steps); the regular
  sign-in afterwards keeps `login_chain_strict`. Without a `login_chain` nothing changes: the link
  signs in as before.

## Configuration (`TinySesamConfig`, excerpt)

| Field | Default | |
|---|---|---|
| `db_path` | `tinysesam.db` | SQLite store |
| `password_enabled` / `passkey_enabled` / `oidc_enabled` | `True/False/False` | active methods (passkey is off by default: `webauthn` lives in the extra `[passkey]`) |
| `totp_enabled` | `True` | allow 2FA (required as soon as a user has set it up) |
| `totp_window` | `"previous"` | which 30-second steps a code may come from: current + previous (RFC 6238 §5.2); `"current"`; `"previous_and_next"` = up to 0.25.x |
| `login_chain` · `stepup_strict` | `[]` · `False` | `["password","totp"]` **enforces** an ordered factor chain — this is how you make 2FA mandatory; alternatives per step with `\|` (`["password\|passkey"]`). Empty = classic: one first factor, plus TOTP where set up |
| `session_ttl_hours` · `cookie_secure` · `cookie_samesite` | `168` · `True` · `lax` | sessions/cookie |
| `rp_id` · `origin` | `localhost` · … | WebAuthn (real domain required, HTTPS) |
| `oidc_issuer/_client_id/_client_secret/_scopes` | – | OIDC provider |
| `oidc_auto_create` · `oidc_allowed_groups` · `oidc_group_claim` | `True` · `[]` · `groups` | auto-create + group gate |
| `base_url` · `login_redirect` · `logout_redirect` | – · `/` · … | app integration (`base_url` **mandatory** with mail paths/OIDC/SAML) |
| `cookie_domain` · `trusted_redirect_hosts` | `""` · `[]` | SSO across subdomains · allowed absolute `?next=` targets |
| `security_log` | `""` | file for the fail2ban logger (empty = logger only) |
| `forward_auth_enabled` · `forward_headers` | `False` · `{}` | forward-auth endpoint · which headers it sets (empty = `Remote-*`) |
| `magiclink_enabled` · `magiclink_self_request` · `magiclink_ttl_min` | `False` · `True` · `10` | sign-in links redeem · anyone may request one by email (needs a mailer; `False` = links only from the admin or app code) · validity in minutes (also reset links; up to 0.25.x `15`) |
| `signin_link_max_ttl_min` | `1440` | upper bound for a sign-in link or an invitation the admin or app code issues (up to 0.25.x a week, `10080`) |
| `invite_ttl_min` | `1440` | validity of an invitation without an own `ttl_min` (up to 0.25.x `magiclink_ttl_min`) |
| `magiclink_first_login_only` | `False` | a link signs in only for the first sign-in (or to set up a missing factor) |
| `qr_login_enabled` · `qr_login_ttl_sec` | `False` · `120` | cross-device sign-in (QR code needs `base_url` and the extra `[qr]`) · validity of a request |

`TinySesamConfig` is a dataclass, and that is part of the promise: `dataclasses.fields(TinySesamConfig)`
lists every field — handy for passing on only the keys it knows from your own settings. Every
field with its meaning: [`CONFIGURATION.md`](https://github.com/Ollornog/TinySesam/blob/main/CONFIGURATION.md) (German).

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
success). `reason` is meant for programs; it is not the audit or security log (their event names, keys and
tokens are English as well, but a different vocabulary). A failure has no session and sets no cookie — ignoring the result signs no one in. A
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
> only compare: no lockout, no counter, no series lock, no rate limit, no line for fail2ban. They are
> internal (a leading underscore, no promise); their old public names (`check_password`, `check_pin`,
> `check_ldap`, `verify_totp`, `verify_recovery_code`, tier C up to 0.30.0) are gone. A route built
> from an inner check lets anyone guess passwords (or a four-digit PIN, or a six-digit code) as fast as
> the server answers — use `login_password`, `login_pin` and `login_totp`.

`start_session` stays, for tests and for a factor you verified yourself — it checks nothing
([Accounts in code](#accounts-in-code)). It returns `(token, session_ok)`: unpack it and put the
token into the session cookie with `auth.set_cookie(response, token, remember=None)` (`remember=None`
follows the session's own “stay signed in” choice) — passing the tuple straight into `set_cookie`
writes the string `"('abc…', True)"` into the cookie, and nothing raises. The token returned by
`complete_totp` replaces the old one, also on step-up — put it into the cookie, or the cookie holds a dead session. The `login_*` building blocks do both
for you.

The same pattern exists for a step-up of your own ([Own step-up page](#own-step-up-page),
`confirm_*`) and for changing the password ([Own password change page](#own-password-change-page),
`change_password`).

### CSRF in your own pages

Every form your app renders itself needs the token in a hidden `_csrf` field (or, for `fetch`,
in the `X-CSRF-Token` header), and the browser needs the matching cookie.
The CSRF cookie is deliberately **not** `HttpOnly` (double-submit: page JavaScript reads it to send `X-CSRF-Token`).
That is not a weakness: it is no credential, only a value an attacker on another origin cannot read; the session cookie
stays `HttpOnly`. A scanner finding "cookie without HttpOnly" on it is expected.
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
extra `<head>` markup and `brand_icon` sets the favicon (and the logo of the top bar) on every built-in page.

**Light and dark.** The pages come in a light and a dark set and switch with the class `dark` on `<html>` — the same
switch C22 uses: the choice is kept in `localStorage.themeMode` (`light`/`dark`; none = the system setting) and set in
`<head>` before the first paint, so nothing flashes. The defaults sit in the cascade layer `tinysesam`, so your
`brand_css` always wins: a plain `:root{…}` holds in both modes, `html.dark{…}` / `html:not(.dark){…}` give your brand
its own light and dark values.

**Top bar.** The account page, the admin panel and the setup, reauth and consent pages carry one bar: on the left the
application logo (`brand_icon` when it is a path on your origin or a `data:image/…` address, otherwise a built-in
mark in `--ts-accent`), the name (`gate_brand` or `rp_name`) and your links; on the right the account menu — account
name, your menu links, *Account*, *Admin panel* (admins only), *Light / Dark / System* and *Sign out* (a POST with the
CSRF field). Sign-in and error pages show logo and name only. On a phone (below 640 px) the links move into the menu
(before the menu links); every tap target is at least 44 px high; the menu answers the keyboard (Escape closes and
returns the focus, `aria-expanded`). `brand_icon_title` gives the logo image a tooltip (`title`, escaped, at most 200
characters) — e.g. a credit `"Logo: Example Icons, CC BY 4.0"`; it works only with an image in `brand_icon`. A tooltip is
no visible credit: when a licence asks for one, name it on a page of your application.

```python
TinySesamConfig(topbar_links=[("Wiki", "/wiki"), ("Files", "https://files.example.com/")],
                trusted_redirect_hosts=["files.example.com"])
```

A link is a path on your own origin or an https address on a host a `next=` may reach too (`base_url`,
`trusted_redirect_hosts`) — anything else is a `ConfigError`. `topbar_enabled=False` removes the bar (the account
page then carries its admin and sign-out links itself), e.g. when `brand_header` already frames the pages with your
navigation. Your own pages get the same bar from two calls:

```python
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, response: Response):
    nonce = secrets.token_urlsafe(16)          # the nonce of your page's CSP, if you use one
    auth.ensure_csrf(request, response)        # the menu's sign-out form needs the CSRF cookie
    return (f"<!doctype html><html><head>{auth.topbar_head(nonce=nonce)}</head><body>"
            f"{auth.topbar(request, nonce=nonce, current='/dashboard')}<main>…</main></body></html>")
```

`auth.topbar_head()` brings the light/dark restore, the `--ts-*` tokens (with `c22_stylesheet` also the C22 adapter
and stylesheet) and the bar's CSS — all scoped to `.tsbar`, nothing touches the rest of your page; `brand_css` is left
out, set your `--ts-*` values in your own stylesheet. `auth.topbar(request)` renders the bar for the session of this
request, with the mount prefix in every TinySesam path; `current` marks the entry of the page shown.

**Who sees a link.** A third element limits a link to administrators or to one role:

```python
TinySesamConfig(topbar_links=[("Docs", "/"),
                              ("Admin app", "https://app.example.com/admin", {"admin": True}),
                              ("Team", "/team", {"role": "teamadmin"})],
                trusted_redirect_hosts=["app.example.com"], available_roles=["teamadmin", "editors"])
```

`{"admin": True}` shows the link to accounts with the admin flag, `{"role": "…"}` to accounts with the role — decided
by `has_role`, so with `admin_implies_roles` (on by default) an administrator sees role links too, exactly as the
target's own `require(role=…)` lets them in. A plain pair is shown to everyone. The bar, the phone menu and
`auth.topbar(request)` apply the same filter; pages without the account menu (sign-in, errors) carry no link at all,
not even in the HTML source. A role missing from `available_roles` is a warning at the start (a typo would hide the
link from everyone), any other third element a `ConfigError`. Visibility is a convenience, not a protection: the
target checks access itself.

**Links in the account menu.** `topbar_menu_links` has the same shape, targets and visibility rules (one check, one
filter) and puts its entries into the account menu — after *Signed in as …*, before *Account*, with a separator of
their own:

```python
TinySesamConfig(topbar_menu_links=[("My collections", "/collections"),
                                   ("Moderation", "/mod", {"role": "moderators"}),
                                   ("App admin", "https://app.example.com/admin", {"admin": True})],
                trusted_redirect_hosts=["app.example.com"], available_roles=["moderators"])
```

Without a signed-in account there is no menu and so no menu link. More than 10 entries are a warning at the start (the
menu would run off the screen); the gateway reads them from `TINYSESAM_TOPBAR_MENU_LINKS` (the same JSON form as
`TINYSESAM_TOPBAR_LINKS`).

**The bar as data.** An application that draws its own bar (not Python, or its own design) asks
`GET /auth/topbar.json` with the request's session cookie and gets what the bar would show that account:

```json
{"brand": "Example", "signed_in": true, "name": "Tara Lead",
 "links": [{"title": "Docs", "href": "/"}, {"title": "Team", "href": "/team"}],
 "menu_links": [{"title": "My collections", "href": "/collections"}],
 "account": {"shown": true, "href": "https://auth.example.com/auth/account"},
 "admin_panel": {"shown": false, "href": null},
 "logout": {"href": "https://auth.example.com/auth/logout"}}
```

TinySesam's own paths are absolute on `base_url` (relative to the mount prefix without it). Without a session —
also with an API key, which gets no account menu — `signed_in` is false and there are no links (`menu_links` is always
there, `[]` then). The answer carries
`Cache-Control: no-store` and `Vary: Cookie` and no CORS header: another origin's page cannot read it. Behind the gate
the proxy templates strip TinySesam's cookies before the application, so an application there fetches it from its
own host, `GET /.tinysesam/topbar.json` (every proxy template passes `/.tinysesam/*` to TinySesam with the
browser's cookies) — from the page's script, same origin. The ready-made gateway reads the visibility from `TINYSESAM_TOPBAR_LINKS` too:
`[["Docs", "/"], ["Admin", "/admin", {"admin": true}]]`.

An application that uses TinySesam as a library but draws its interface elsewhere (a single-page app, a template
engine of another language) gets the same dict from `auth.topbar_data(account)` — for `session_user(request)` or for
the account behind `Remote-Id`; a locked or unknown account gets no menu. TinySesam's paths in it are absolute on
`base_url`; `base=` puts another prefix in front.

**Recipe: link your app's admin from TinySesam — and back.** TinySesam's admin panel gets no tabs of the application
(T-77 was rejected for this); the two administrations link to each other instead.
[`examples/app_admin.py`](https://github.com/Ollornog/TinySesam/blob/main/examples/app_admin.py) is the whole recipe
as a runnable app:

```python
TinySesamConfig(topbar_links=[("Home", "/"),
                              ("App admin", "/app-admin", {"admin": True}),          # there: administrators only
                              ("Team", "/team", {"role": "teamadmin"})],             # or the lead of one team
                available_roles=["teamadmin"])
```

1. **There:** the top bar of the admin panel, the account page and the application's own pages
   (`auth.topbar(request)`) shows *App admin* to administrators only.
2. **Back:** the application's admin page links to the panel with the address the bar data reports —
   `auth.topbar_data(user)["admin_panel"]["href"]`, absolute on `base_url`, so it works from another host too.
3. **Not drawn in Python:**
   - *Server side:* the host application hands `auth.topbar_data(auth.get_user(remote_id))` to its frontend over an
     internal endpoint — a separate app on 127.0.0.1 that the proxy never routes (`internal` in the example). A check of
     the client address is not enough: behind a proxy on the same host every request comes from 127.0.0.1.
   - *Browser side:* an application that sits only behind the gate (no TinySesam in its process) lets its page fetch
     `/.tinysesam/topbar.json` from its own host.

The targets check access themselves (`require(admin=True)`, `require(role=…)`): a hidden link is a convenience, not a
lock.

**Same look as your app (C22).** If your app is built on the [C22](https://github.com/Ollornog/C22) design system,
point TinySesam at the C22 stylesheet your app already serves — login, account page, admin panel and error pages
then derive their tokens from C22, follow its pack and its light/dark switch:

```python
TinySesamConfig(c22_stylesheet="/static/css/c22-vega.css")   # a path on your own origin, nothing from third parties
```

No C22 code runs on the auth pages and TinySesam does not depend on C22: the mapping is one optional CSS file
([`tinysesam/c22.css`](https://github.com/Ollornog/TinySesam/blob/main/tinysesam/c22.css)), every entry falls back to
TinySesam's own default, and the strict CSP stays as it is (the stylesheet carries the response nonce). Light/dark
follows C22's own mechanism: the class `dark` on `<html>`, taken from `localStorage.themeMode`, else the system setting.
Loading C22 another way? Paste the file into `brand_css` (`tinysesam.theme.C22_ADAPTER`).

**Want your own nav and footer around them?** `brand_header` and `brand_footer` wrap *every* built-in
page — login, PIN, TOTP, account, admin panel and the error pages. Both take HTML or `fn(auth) -> str`
when the shell depends on the request (sign-in state, language). `auth.install_error_pages(app)` gives browsers themed 403/404/500 pages while API
clients keep getting JSON. Need more than colors? Replace a whole page with `auth.set_template(...)`.

**Dialogs.** The built-in pages never open the browser's own `alert`/`confirm`/`prompt` boxes. Questions, notices
and secrets shown once (a new API key, new recovery codes) appear in one dialog of their own — a native `<dialog>`,
styled by the same tokens, keyboard-friendly (Escape cancels, Enter confirms, Tab stays inside, the focus returns to
the button that asked) and, for secrets, with a **Copy** button; where the clipboard API is missing (plain HTTP) the
text is pre-selected for Ctrl+C. A page of your own (`set_template`) gets the same building block as
`ctx["dialog"]` — put it into the page once and call it from your script:

```python
def my_account(auth, ctx):
    return f"""<!doctype html><title>Account</title>{ctx['dialog']}
<button id=go>Create key</button>
<script>document.getElementById('go').addEventListener('click', async () => {{
  if (await tsConfirm('Create a new key?')) await tsSecret('New API key', 'tsk_…', 'Shown only once.');
}});</script>"""

auth.set_template("account", my_account)
```

`tsAlert(text)`, `tsConfirm(text, {danger})` → `true`/`false`, `tsPrompt(text, value, {type})` → text or `null`,
`tsSecret(title, value, note)` and `tsCopy(value, field)` all return a Promise; the nonce of the strict CSP covers the
block like every other one ([`tinysesam/dialog.py`](https://github.com/Ollornog/TinySesam/blob/main/tinysesam/dialog.py)).

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
dropped, and API keys and app passwords stay valid on purpose — `result.api_keys_active` and
`result.app_passwords_active` say how many, so your page can say so too.

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
(the translated text; for `policy` the rule that failed), `api_keys_active` and `app_passwords_active`. It needs a full
session — an API key does not count (`no_session`, 403): a machine credential does not change a
person's password. An empty current password is `missing` (400) and does not count as a failure.
Synchronous, like `login_*`.

**An account without a password** (created by sign-in link, OIDC or passkey) has no current one to
type. The account page then offers *Set password* without that field; the route is
`POST /auth/password/set` (JSON with `new`), the building block `auth.set_initial_password(request,
new, csrf=…)`. Instead of the old password it asks for freshness — the same rule as for creating any
other factor: a fresh step-up if the account already has something to confirm with (TOTP, PIN;
otherwise `stepup`, 403 with `X-TinySesam-Reauth`), the age of the sign-in if it has nothing
(`stepup_max_age_sec`; otherwise `relogin`, 403 — sign in again). Plus CSRF, the per-IP rate limit,
the password rule and the audit line `password_set`. It refuses an account that already has a
password (`has_password`, 409 — that is `change_password`), a disabled password sign-in
(`method_disabled`, 404) and installations with `ldap_enabled` (`directory`, 409: a local password
next to the directory one would keep working after the directory disables the account). Other
sessions are not ended — the response carries `other_sessions`, the page offers it, as after a new
factor.

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
  `<db_path>.claim` with mode `0600` instead and logs only that path (`docker exec … python -c
  "print(open('/data/app.db.claim').read())"` — the gateway image has no `cat`); the file is removed once the token is
  redeemed. Without a database file
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

It ends that account's open sessions and revokes its API keys, app passwords, services and connected programs, like
an admin reset in the panel (`--keep-sessions` keeps all of that), and writes an audit entry with the counts.
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
> `auth.store.backup(path)` does the same from Python, but `auth.store` is internal (no
> promise — see [Public API](#public-api-two-tiers)).

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

> **Updating from before 0.30.0 takes two steps.** 0.30.0 is the last release with database migrations;
> this version opens schema 26 (the state of 0.30.0) and newer only and refuses an older database with a
> message, without writing to it. First update to 0.30.0 and start it once, check `tinysesam keys list`,
> then take this version — the steps are in `docs/OPERATIONS.md`, "Updating". Take a backup before each
> step (`tinysesam backup` leaves the source untouched); going back from this version to 0.30.0 needs
> no SQL (same schema). **From 0.30.x** follow the list "Upgrading from 0.30.x" there (API keys, open
> links and recovery codes end once), then "Upgrading from 0.31.x" when it exists; **from 0.31.x** only the
> latter. `tinysesam diagnose --db auth.db` names every point that blocks the start, with its command.

Instead of `tinysesam backup` you can also stop the service and copy `auth.db` together with `auth.db-wal` and `auth.db-shm` (where they
exist) into a separate directory; to go back, put all three back with the service stopped.

### Diagnosing "I can't get in"

```bash
python -m tinysesam audit  --db auth.db --user alice    # the audit log, from the command line
python -m tinysesam unlock --db auth.db alice           # lift a brute-force lockout
python -m tinysesam reset-totp --db auth.db alice       # lost authenticator app: TOTP and recovery codes go
python -m tinysesam oidc-link --db auth.db alice --issuer https://id.example.com --sub 2f9c…  # pre-register an OIDC identity
```

The audit log records *why* a sign-in failed (`no_account`, `account_locked`,
`wrong_secret`) — the HTTP response deliberately does not, so it cannot be used to probe for
accounts. The log is only read by the operator.

### Removing an account

```bash
python -m tinysesam delete --db auth.db alice           # asks first; --yes for scripts
```

For instances without an admin panel — for instance OIDC only, where an acceptance test with a
test account leaves a local account behind. It takes the same route and the same protection rules as
the panel's "Delete": credentials, sessions and identity links go, the sign-in attempts under name and
address go, and the name in the audit log becomes `deleted#<id>` (the rows themselves stay). An owner
and the last admin are not deleted. The command names what it removed (name, number of sessions and
identity links), never a secret. Without `--yes` it asks, and without a terminal it refuses; an
unknown account ends with exit 1. `#<id>` instead of the name works as in `rename`. A raw `DELETE`
in the database is the wrong way — it leaves the name in every audit row.

### Keys: list, rotate, re-encrypt, retire (T-48)

```bash
python -m tinysesam keys list      --db auth.db                    # every key: purpose, ID, state — never the key
python -m tinysesam keys rotate    --db auth.db --purpose vault    # or gate, oauth-pepper
python -m tinysesam keys reencrypt --db auth.db                    # stored secrets onto the active vault key
python -m tinysesam keys retire    --db auth.db --purpose vault    # refuses while anything still needs the old key
```

Three purposes, each a keyring (active key + older ones that still decrypt or verify): `vault` (the secrets at
rest), `gate` (the gate token's signature) and `oauth-pepper` (the OAuth token digests). Nothing is lost and nobody
is signed out by a rotation; the steps, the sources (environment, file, database) and the way back to an older
version are in `docs/OPERATIONS.md`, "Keys".

## Reporting a bug

TinySesam sends nothing home — no telemetry, not even as an opt-in: an authentication component that talks to the
outside on its own would lose the trust it lives on. Instead, a command writes a report that you read, check and send
yourself:

```bash
python -m tinysesam diagnose --config yourapp.settings:config --log /var/log/tinysesam/security.log   # library
docker exec <container> python -m tinysesam.gateway diagnose                                          # gateway image
```

- **What it holds:** version, Python, operating system family, mode, installed extras; the *shape* of the
  configuration (which fields differ from the default — switches and numbers as they are, everything else as a
  placeholder like `<url-1>` or `<host-2>`, secrets only as `<set>`); the built-in checks (`config_check` errors and
  warnings, proxy headers and uvicorn's `--no-proxy-headers`, the clock, the database schema, whether the vault key
  lies beside the database, gate token and JWKS); the latest warnings and errors of the security log, redacted.
- **What it does not do:** no network request, no write (the database is opened read-only, no key is created), no
  `TinySesam` instance. `--config` takes `module:attr` or `file.py:attr` — a `TinySesamConfig`, a `TinySesam` or a
  function returning one — and imports your module for it. `--db` and `--log` default to `db_path` and
  `security_log`; `--no-link` leaves the link out.
- **At the end** a link opens the [bug form](https://github.com/Ollornog/TinySesam/issues/new?template=bug.yml)
  prefilled. You check it and submit it. A report too long for a link leaves sections out and names them; paste them
  from the terminal.
- Host names, addresses, URLs, user names, paths and secrets are replaced, but you know your setup best: read the
  report before you share it. A **vulnerability** never goes into a public issue — see
  [`SECURITY.md`](https://github.com/Ollornog/TinySesam/blob/main/SECURITY.md).

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
  `secrets_key_file` or `<db>.key`) separately, rotate it with `tinysesam keys rotate` (below); an OIDC session
  re-checks its refresh token every
  `oidc_session_refresh_minutes` and ends when the provider says no. Details: `docs/OPERATIONS.md`.
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
  attempt is listed in `security.NOT_LOGIN_METHODS` — derived from `security.OWN_LOCK`,
  so no method can end up without a brake. The pots of the **signed-in** paths (password change,
  step-up) deliberately count per account only, not per IP: guessing there requires a valid
  session for that very account. The area PIN keeps the IP threshold — there the guesser is
  anonymous.
- **Rate limiting:** token bucket per IP on the login/2FA endpoints (`rate_limit_max` / `rate_limit_window_sec`); an
  IPv6 address counts as its /64, and a /48 shares five times the limit (`security.RATE_NET48_FACTOR`).
- **fail2ban:** every failed attempt is logged via the `tinysesam.security` logger with the real client IP
  (`failed login … ip=…`; the reason, if any, stands last as `reason=…` — since schema 15 on the OIDC and passkey
  lines too, so update the filter files from `deploy/fail2ban/` together with the release). Filter + jail in [`deploy/fail2ban/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/fail2ban/) → IP ban at the firewall level.
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
  in `trusted_proxies` — otherwise the IP is forgeable. **Start uvicorn with `--no-proxy-headers`**
  (`uvicorn.run(..., proxy_headers=False)`): uvicorn applies `X-Forwarded-For` **by default** and rewrites
  `request.client.host` to the forwarded IP, so TinySesam's check has nothing left to verify and rate limiting,
  lockout and fail2ban rest on uvicorn's `forwarded_allow_ips` instead of `trusted_proxies`. The gateway
  (`python -m tinysesam.gateway`) starts uvicorn that way itself; when the address arrives already rewritten,
  the security log says so and names the switch.
- **Roles and admins:** by default an admin satisfies every `require_role(...)`. If an app derives its
  permissions purely from an IdP group, that is a silent privilege escalation — set
  `admin_implies_roles=False` (or `require_role(..., admin_implies=False)`).
- **IdP groups** are matched **exactly** against the keys of `*_group_role_map` (`group_match="exact"`).
  Substring matching (needed for LDAP `memberOf` DNs, and used there automatically) would let the key
  `admin` match a group called `not-admin`.
- **Audit log:** login / logout / failed attempts in the DB (`store.recent_audit()`), for the admin panel.
- **Response headers:** every built-in page runs under a strict nonce CSP (`csp="strict"`) with `X-Frame-Options:
  SAMEORIGIN` and `Cross-Origin-Opener-Policy: same-origin`; every response carries `nosniff`, `Referrer-Policy:
  same-origin` and `no-store`; sign-out sends `Clear-Site-Data: "cache"`. `csp_report=True` lets browsers report
  violations to `/auth/csp-report`, one throttled line each in the security log — nothing goes to a third party.
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
tinysesam[oidc]==0.31.0
```

A released version on PyPI never changes: the same line installs the same code tomorrow. Updating
means: bump the line, reinstall, restart the service. Python does not reload code at runtime.

The same pin via git, if you install that way — note that a **tag can be moved**; for real
immutability pin the commit (`@a1b2c3d…`):

```
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.31.0
```

Every release also attaches a **wheel** and an **sdist**, with `SHA256SUMS`. To install without
git and without an index, take the file directly:

```
pip install https://github.com/Ollornog/TinySesam/releases/download/v0.31.0/tinysesam-0.31.0-py3-none-any.whl
```

### As a gateway (its own container)

Every release builds an image for `linux/amd64` and `linux/arm64`:

```
ghcr.io/ollornog/tinysesam:v0.31.0
```

It runs as **non-root** (uid 1000), ships a `HEALTHCHECK` on `/healthz` and starts the gateway directly — no
`command:` needed. The runtime base is **distroless** (`gcr.io/distroless/base-debian13`, pinned by digest) with the
Python interpreter of the `python:3.x-slim` build stage on top: no shell, no package manager, no `pip`, no `git` —
whoever gets code execution inside finds no tool to fetch more. The operator commands work as before
(`docker exec <c> tinysesam backup …`); for looking around there is `docker exec -it <c> python` or a side-car with a
shell in the container's namespaces — both in `docs/OPERATIONS.md`, "The gateway image: no shell inside".

**Check where it came from.** A digest proves an artifact hasn't changed since it was built — not
who built it. Every release therefore carries a Sigstore-signed provenance attestation and an SBOM,
both also stored next to the image in the registry:

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.31.0 --owner Ollornog
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.31.0 --owner Ollornog \
    --predicate-type https://spdx.dev/Document                             # the SBOM
# wheel and sdist (from PyPI or the release page): the isolated builder, the tag, and its SBOM
gh attestation verify tinysesam-0.31.0-py3-none-any.whl --owner Ollornog \
    --signer-workflow Ollornog/TinySesam/.github/workflows/build-provenance.yml --source-ref refs/tags/v0.31.0
gh attestation verify tinysesam-0.31.0.tar.gz --owner Ollornog \
    --signer-workflow Ollornog/TinySesam/.github/workflows/build-provenance.yml \
    --predicate-type https://spdx.dev/Document
```

A pass means: built by this repository's release workflow, from the commit the attestation names. Wheel and sdist
come from a builder of their own (SLSA Build L3, since 0.26.0): the reusable workflow
`build-provenance.yml` rebuilds the tag, checks its bytes against the ones the release ships and signs under its own
name — `--signer-workflow` pins it. Their SBOM (also attached to the GitHub release as `tinysesam-sbom.spdx.json`) lists
TinySesam and the dependencies pip resolved for it on the release day (Linux, Python 3.13, no extras).
No key to hand out and none to lose — the signature is tied to the workflow's own identity. The proxy comes along:
`ghcr.io/ollornog/tinysesam-caddy-gate:v0.31.0` is Caddy with the caddy-jwt plugin, built, scanned and attested by the
same release (verify it the same way). Running in five minutes: "Gateway and Caddy in 5 minutes" below; the reference
stack with every option lives in `deploy/forward-auth/docker-compose.yml`.

**Home network without a domain?** HTTPS is required outside `localhost`, so a bare IP address needs a CA of your own
on every device — and passkeys do not work on an IP at all. `docs/HOME-NETWORK.md` recommends
a domain (DNS-01 works even for names that resolve only at home) and describes the IP fallback with the template in
`deploy/home-network/`.

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

## Two ways to use TinySesam

There is no mode switch: every difference below already hangs on a field. The two names only say which side draws
which page.

| What | **TinySesam provides the pages** | **The app provides the UI** | Field |
|---|---|---|---|
| Sign-in, second factor, step-up | TinySesam | TinySesam, **in the app frame** | `forward_apps[host]` `home`, `links` |
| Change password, TOTP, passkeys, PIN, recovery codes | TinySesam's account page | TinySesam's account page, **in the app frame** | `account_enabled=True` |
| Approvals, OAuth consent | TinySesam | TinySesam, in the app frame | `approvals_enabled`, `oauth_enabled` |
| Show the security state | the account page | **the app's settings page**, data from TinySesam | `auth.account_overview`, `/.tinysesam/account.json` |
| Top bar on the app's pages | `auth.topbar()`, `auth.topbar_data()`, `/auth/topbar.json` | the app's own bar, a "Security" link to the account page | `topbar_links` |
| Top bar on TinySesam's pages | TinySesam's bar (`topbar_links`) | the app frame: "‹ name", the app's links, the account menu | `forward_apps[host]` |
| Colleagues' accounts | admin panel, delegated admins | **the app**, through the account API | `apps[id].provisioning` |
| Admin panel | admins and delegates | operators only (service accounts, adopt/release, gate) | no `admin_delegates` for the app's roles |
| Look | the instance's tokens or C22 | the same: **one** style for every app behind a gateway | `c22_stylesheet`, `brand_css` |

**The app frame.** Whoever comes from an application's host sees TinySesam's own pages as part of that application:
the top bar shows "‹ Example" back to `home` (with "via <gate_brand>" below it on a desktop), the application's links,
and an account menu with *Security* (the account page), *Approvals* (number and word), the admin panel for operators
only, light/dark/system and *Sign out* (TinySesam's sign-out: the session ends). `topbar_links` and
`topbar_menu_links` do not appear. A page without a signed-in account (sign-in, TOTP, errors) shows the name only — a
back link would lead straight back to the sign-in. The frame is chosen by `?app=<host>`, by the host of an absolute
`next`/`return_url`, or by `app=<host>` inside a relative `next` (so the step-up page keeps the frame of its target);
`forward_frame_default` names the frame for everything else. **Every target comes from the configuration** — an unknown
host changes nothing, and nothing of the request becomes a link. The account page's sections have stable anchors:
`#sessions`, `#totp`, `#passkeys`, `#devices`, `#app-passwords`, `#services`.

```python
TinySesamConfig(forward_apps={"team.example.com": {
    "name": "Example",                                    # the frame shows the name and nothing else on the left
    "home": "/",                                          # a path on this host or https://team.example.com/…
    "links": [("Spaces", "/spaces"), ("Team", "/team", {"role": "example-lead"})],   # like topbar_links, this host
}}, trusted_redirect_hosts=["team.example.com"], available_roles=["example-lead"])
```

**The security state as data.** `auth.account_overview(user, *, base=None, app_host=None, request=None)` (tier B) gives
what the account page shows: `account` (name, display name and `source` — where the account comes from: a list of
`local`, `oidc`, `saml`, `ldap`, two or more for a mixed account; shown only, no decision reads it), `sign_in` (password, TOTP with the recovery codes left, passkeys, PIN), `sessions` (when,
last seen, a coarse "browser · system", `current`), `programs` (OAuth programs, services, app passwords: name and last
use; the number of API keys), `approvals` and `links` (the account page and its anchors, with `app=<host>` for an
`app_host` with a frame). `null` means "not offered here", `[]` "offered, empty"; there is never an address, a hash, a
secret, a key prefix or another object's id in it. The account page reads the same function, so page and data cannot
drift apart. Over HTTP: `GET /auth/account.json` and, on an application's host through the proxy,
`GET /.tinysesam/account.json` — only for a full browser session (an API key, an OAuth token, an app password or a half
session gets 401), `no-store`, `Vary: Cookie`, no CORS, 60 reads per account and minute, read only. Ending a session,
revoking a program or an app password happens on the account page; the application links there with the anchors.

Recipes:

- **The app provides the UI, library, sign-in by OIDC only** (DashMyBoard does this): `admin_enabled=False`,
  `account_enabled=False`, only `oidc_enabled`. No TinySesam page remains but the sign-in.
- **The app provides the UI, library, local factors:** `account_enabled=True`. The pages already run on the
  application's origin: `rp_name`/`gate_brand` = the application's name, `topbar_links` = its navigation — or a
  `forward_apps` entry for the own host with `forward_frame_default` pointing to it. The settings page reads
  `auth.account_overview(auth.session_user(request), request=request)`.
- **The app provides the UI, behind the gateway** (also: TinySesam as a library in a thin wrapper of its own, as the
  gate in front of an application in another language on other origins): `forward_apps[host]` with `name`, `home`,
  `links` for every application host (each its own frame — a stable and a test host get their own); `apps[id]` with
  `provisioning` for the account API; `account_enabled=True`; no `admin_delegates` for the application's roles (the
  start warns when a delegate role overlaps an allowlist). The application draws its own bar (not from
  `topbar.json`) with a *Security* link to `/auth/account?app=<host>`, and its settings page shows the security state:
  - **preferred:** the settings page fetches `/.tinysesam/account.json` in the browser, same-origin — the proxy passes
    it to TinySesam with the browser's cookies, TinySesam itself checks "a person, by browser session", and the
    application never holds the session (spec §8a of `spec/gate-client.md`; `parse_account` and the helpers of the
    clients normalize the answer);
  - **or server-side** with the helpers (`fetch_account`, `FetchAccount`, …): they forward the session cookie, which
    the proxy templates strip before the application (spec §2.1, duty 4). Letting it through hands the application the
    person's browser session — only for an application you trust with that, with the commented variant in
    `deploy/forward-auth/Caddyfile.gate` (spec §8, "Server-side or in the browser");
  - **or inside the wrapper:** it calls `auth.account_overview(auth.get_user(remote_id), app_host=host)` and hands the
    dict to the application, the way it hands on `topbar_data`. Then the wrapper owns three duties TinySesam cannot
    enforce on this path: call it **only** for a checked `Remote-Kind: user` with `Remote-Auth: session`, **only** for
    the account of that request's `Remote-Id` (never an id from a parameter), and answer with
    `Cache-Control: no-store`. `current` stays `null` there: the gate token carries no session reference.

## Surfaces, origins, deployment

TinySesam is meant as a building block for other developers, so the ways to put it into an application are one grid,
not a list of special cases: four **surfaces** (what the person sees), three **origins** of an account (where it
lives) and two **modes of operation** (how TinySesam runs). This section is the map; the stages that build the missing
cells are the tasks of milestone M-2 in `backlog/`. What exists today is named in each table.

### The four surfaces

| Surface | Who draws the navigation | Where TinySesam's pages appear | Today |
|---|---|---|---|
| **Shell on top** | TinySesam's top bar above the application | The account and administration pages open from the bar | the top bar of spec §8 (`topbar.json`, `auth.topbar_data`), T-103 adds the layout switch |
| **Shell at the side** | the same component as a side bar | as above | T-103 |
| **Hybrid** | the application | one link "Account"; everything else in a TinySesam area, framed with the application's name and a way back | the app frame (T-91), T-104 adds the area |
| **Headless** | the application, completely | none inside the application: it reads data (`account.json`, `admin/*.json`) and sends the person to a TinySesam action page for every change | the account overview and the account API, T-105 and T-106 add the action pages and the reading side |

### The three origins of an account

**Local** (password, passkey, TOTP, PIN, sign-in link), **IdP** (OIDC, SAML or LDAP: TinySesam stores a mirror and the
role mapping) and **mixed** (both in one installation, an IdP account may be linked to a local one by a person with a
step-up on both sides, never silently by the same address). The account page links OIDC, SAML and LDAP identities and
unlinks them again — never the last way in.

### The two modes of operation

| | **Library** | **Server** |
|---|---|---|
| What runs | TinySesam inside your Python application | the gateway container, any language behind a proxy; configured by a TOML file with an environment overlay (`TINYSESAM_CONFIG`, T-97) or, for the OIDC-only preset, by environment variables |
| What the application gets | function calls (`get_user`, `has_role`, `topbar_data`, the account API) | the gate token, the `Remote-*` headers, `account.json`, `topbar.json`, the account API, through the clients (Go, Rust, JS/TS, PHP, Python) |
| Trust | one trust boundary: application and TinySesam share the process, the database and the secrets | two boundaries: the application holds no TinySesam secret and cannot read its database |

### Three rules that hold in every cell

1. **Ownership: reading is allowed everywhere, writing from another origin only by navigation.** An application may
   read what the person may see (`account.json`, `topbar.json`, the administrator's read data inside its own area).
   Anything that changes an account is done on a TinySesam action page the person is sent to, with a way back to the
   application. A secret (password, TOTP, passkey, recovery code) is typed only on TinySesam's own pages when the
   application lives on another origin; it never travels through the application. Hardening and configuration stay
   instance-wide and are not reachable from an application; the administrator flag is never set by a link.
2. **Equivalence: no decision depends on the origin of an account.** The same scenario (a role, an approval, an
   administrative action) has the same result for a local, an IdP and a mixed account. `source` is information shown in
   the panel and the account API, never a switch for behaviour.
3. **Parity: every function has a server route, or sits on the "library only" list with a reason.** A parity test
   reads `tests/api_surface.json` and fails when a stable name has neither. Library only: fully headless forms with own
   password fields, `set_template` and `page_layout` (they draw HTML inside your own process).

### Who builds which cell

| Function | Owner |
|---|---|
| The server can do everything: TOML configuration, parity test | T-97 |
| Reset a TOTP factor in the panel and the CLI | T-98 |
| Every origin is equal: `source`, step-up (SAML `ForceAuthn`, LDAP re-bind), linking local and IdP | T-99, T-70 |
| Permissions: registration by the application, assignment to roles, `has_permission` in server and clients | T-100, T-101 |
| IdP role sync, stage 1 (groups at sign-in) | T-102 |
| IdP role sync, stage 2 (SCIM) | T-109, optional |
| Shell on top and at the side | T-103 |
| Hybrid area and the library layout slot | T-104 |
| Headless writing: action pages with a way back | T-105 |
| Headless reading: events, keys, administrator data inside the application's area | T-106 |
| Acceptance: one example application per surface, each with local, IdP and mixed accounts, in CI | T-107 |
| Fully headless library (register, reset password, setup status) | T-108, optional |
| A rewrite of the core in another language | not planned: the core stays Python and the clients stay thin, see ADR-15 |
| An administrator interface inside the application's origin | not planned: an XSS of the application could post TinySesam forms |

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

Where the provider issues refresh tokens, most of these trips never happen: every successful
refresh exchange for an application (`oidc_session_refresh_minutes`, 15 by default) renews its
release, because that exchange is the provider's yes for exactly this client. The trip is left for
applications without a refresh token, an unreachable provider, and a client with `allowed_groups`
whose refresh answer lacks the groups claim. This matters when the provider's own session is
shorter than the release period — otherwise the trip would end on its login form.

As environment variables (gateway container):

```
TINYSESAM_OIDC_CLIENTS='{"app.example.com": {"client_id": "app", "client_secret": "..."}}'
TINYSESAM_OIDC_REVALIDATE_MINUTES=60
```

A config with a single client behaves exactly as before — no host mapping, no release to expire.

**Which application a request is for comes from the proxy alone.** `/auth/forward` reads the target from
`X-Forwarded-Host`/`-Proto`/`-Uri` (Caddy, Traefik) and from `X-Original-URL` only when no `X-Forwarded-Host` is there
(nginx). A request that carries both with different targets gets the sign-in page (`X-TinySesam-Reason:
forwarded-conflict`): one of the two came from the browser. Every per-application decision hangs on that target —
approval per client, app passwords, OAuth audience, "signed out here only" — so take the proxy templates in
`deploy/` as they are: they remove `X-Original-URL` (Caddy), set all four headers (nginx) or neither trust nor copy the
browser's forwarding headers (Traefik).

**`Remote-Groups: admin` is no fresh confirmation.** Forward auth answers for every valid session, however long ago
it was confirmed; `admin_require_mfa` and `stepup_max_age_sec` guard TinySesam's own admin panel and the routes that
create access, not the applications behind the proxy. An application that derives admin rights from the header should
not rest a sensitive action (delete everything, change who may enter) on it alone — ask for its own confirmation
there.

## API keys & service/daemon accounts

For **machine access** (scripts, other services, system daemons) — alongside the interactive login:

- An API key belongs to a user, sits in the DB only as an **HMAC with the pepper** (never the key, T-72), optionally with an **expiry** and **role scope**.
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
  one, and the migration rewrites stored keys — rolling back: `docs/OPERATIONS.md`.)
- **Keys expire by themselves.** Without `expires_days` a key used to live forever, and that was
  the common case. `apikey_default_days` (90) now applies; `expires_days=0` still means
  "unlimited" but needs `apikey_allow_unlimited=True` and lands in the audit entry.
- **A key is a second front door, so locking an account out takes it along.** An admin password
  reset and disabling an account revoke that user's keys; so does the user's own "end **all**
  sessions" (`scope=all`). A user's own password change deliberately does **not** — a routine
  change shouldn't silently kill their integrations — but the response and the audit entry say
  how many keys are still live (`api_keys_active`). Keys of a disabled account never
  authenticated in the first place.

## OAuth for MCP clients

TinySesam can be the **OAuth 2.1 authorization server** for tools a person runs on their own computer — first of
all **Claude Code** as an MCP client (T-36, ADR-11). The application behind the proxy (an MCP server, any HTTP
app) contains **no OAuth code**: forward auth accepts the access token and passes `Remote-*` on, exactly as for a
session. The sign-in is TinySesam's own — chain, TOTP, passkey, setup pass — followed by a consent page that names
the program, where the answer goes (`localhost:<port>`) and what it may do for how long.

```python
TinySesamConfig(
    base_url="https://auth.example.com",            # the issuer — fixed, never from the request
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/mcp"],  # tokens are valid only here and below
)
```

**TinySesam needs an origin of its own** — its own host (`auth.example.com`), or, when everything lives on one host,
at least its own port (`https://app.example.com:8443` next to the application on `:443`), never a path inside the
application. Three reasons: the issuer is the origin of `base_url`, and the client finds the server's metadata at
`/.well-known/oauth-authorization-server` on exactly that origin (RFC 8414) and checks `iss` against it (RFC 9207);
the sign-in and consent pages carry a strict CSP of their own, which on a shared origin would govern the application's
pages or be loosened by them; and forward auth guards the application's origin, while TinySesam's own routes (`/auth/*`,
the metadata) must answer without it. A port is enough for the issuer and the CSP — browsers treat it as another origin
— but **cookies do not separate by port** (RFC 6265, 8.5): the forward-auth templates strip every `tinysesam_*` cookie
before the application, and an application with its own cookies should not reuse those names.

At the proxy, two additions on the application's host (both in `deploy/forward-auth/Caddyfile`):
`/.well-known/oauth-protected-resource*` goes to TinySesam (RFC 9728 — the client learns where to sign in), and
a 401 that TinySesam marks with `X-TinySesam-Reason: oauth` is passed through with its `WWW-Authenticate: Bearer
resource_metadata=…` instead of being turned into a redirect to the login page. Then, on the computer with Claude
Code:

```bash
claude mcp add --transport http myapp https://app.example.com/mcp
claude mcp login myapp          # or /mcp inside Claude Code — the browser opens, sign in, allow
```

With a certificate from your own CA (home network, IP address — see `docs/HOME-NETWORK.md`) Claude Code needs the
root: `export NODE_EXTRA_CA_CERTS=/path/to/root.crt` (or the same key under `env` in Claude Code's `settings.json`);
an IP address must be in the certificate as a Subject Alternative Name.

What happens and what protects it:

- **Registration** (RFC 7591) is open, because Claude Code registers itself — and anew after every logout or port
  collision. Only public clients (`token_endpoint_auth_method=none`) with a loopback redirect
  (`http://localhost`, `127.0.0.1` or `[::1]`, any port); nothing the client names is fetched, its name is shown as
  "not verified", 20 registrations per address and hour (an IPv6 address counts as its /64), 100 per IPv6 /48.
  Registrations that never led to a connection go in `gc()`; at the cap of 1000 such registrations the longest-unused
  one older than ten minutes gives way, so a flood cannot lock everyone out of connecting until then.
- **Authorization code with PKCE S256 only**, the code lives 60 s and works once — a second use revokes what the
  first produced. The redirect URI is compared exactly, only a loopback port may differ (RFC 8252 §7.3). The answer
  carries `iss` (RFC 9207). CIMD is not advertised: it needs the AS to fetch a document from the internet.
- **Tokens are opaque** (`tsat_…` access, `tsrt_…` refresh; 256 random bits plus a checksum that secret scanners
  know), the database holds only an HMAC digest keyed with a **pepper** — `TINYSESAM_OAUTH_PEPPER` or
  `oauth_pepper_file`; without one it is derived from the master key (`config_check` says so).
- **Access token 1 h** (`oauth_access_token_ttl_sec`), checked against the database on every request: disconnecting
  a device, locking the account or removing a role takes effect at once. A token never carries the admin flag.
- **Refresh tokens rotate on every use.** A used one that comes back means it was copied: the whole connection is
  revoked, the audit log and `on_security_event` (`oauth_token_reuse`) say so. They expire after
  `oauth_refresh_idle_days` (90) without use and at the latest after `oauth_refresh_max_days` (180) — then the
  person signs in again. `0` switches the maximum off on purpose; `config_check` then points to ASVS 5.0 V10.4.8.
  `oauth_refresh_grace_sec` (0) can let two processes of one client refresh at once; Claude Code serialises.
- **Devices:** the account page lists the connected programs (name, client, connected, last used, address,
  resource) with "Disconnect"; the admin panel has a tab with all of them. `claude mcp logout` revokes at the server
  (RFC 7009, without a client secret). Locking the account, a password reset (self-service, by an administrator or
  `tinysesam passwd`) and "end all sessions" disconnect every program of the account, like its API keys.
- **Limits:** the connectors of Claude Desktop and Claude on the web call from Anthropic's network and cannot reach a server that
  is only in your LAN; Claude Code can. Claude Code has no DPoP — rotation is the protection for refresh tokens.
  Services without a person (`client_credentials`): next section.

### Without the consent page: the pairing code

For people who should not have to understand a consent page (ADR-14): the consent is given **in advance**, in the
person's own browser session, and a setup script spends it on the very next sign-in of the program. It stays OAuth
with PKCE and rotation; nothing long-lived lands on the computer.

```python
TinySesamConfig(
    base_url="https://auth.example.com",
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/mcp"],
    forward_apps={"app.example.com": {"name": "Doc Hub"}},  # the name the pages show
    oauth_pairing_consent_enabled=True,                     # off by default
    oauth_pairing_consent_minutes=15,                       # window from issuing, 1–60
)
```

1. The person fetches a code — on the account page (*Connect a program*), or the application does it in the browser
   on the same origin: `POST /auth/oauth/pairing` with the session cookie and `X-CSRF-Token`, body `{}` or
   `{"resource": "https://app.example.com/mcp"}`, answer `{code, expires_at, resource, redeem_url, issuer}`. Only the
   account itself, only with a **fresh** confirmation (else `403` with `X-TinySesam-Reauth`); never an API key, an
   access token, an administrator or an application on someone's behalf. One open code per account, 10 per hour.
2. The setup script redeems it right before the login: `POST /auth/oauth/pairing/redeem` with `{"code": "…"}` — no
   session, JSON only. `200 {"armed": true, …}` once; an unknown, used or expired code is always the same `400`.
3. `claude mcp login` opens the browser; the person is signed in, and the **next** authorization of that account goes
   straight back to Claude Code — if the browser opened it itself (`Sec-Fetch-Site: none`; a website's navigation
   never counts), the redirect is a loopback address, the resource matches and the window is open. Anything else shows
   the consent page and leaves the pairing for the right request.

The second login, an expired connection and `claude mcp logout` get the consent page again — one large *Allow*, the
application's name, the technical details folded. *Connected programs* lists such a program "via pairing code" and
disconnects it like every other.

A setup script, bash (Linux, macOS):

```bash
#!/usr/bin/env bash
set -euo pipefail
AUTH=https://auth.example.com
MCP=https://app.example.com/mcp
read -rp "Pairing code from 'Connect a program': " CODE
[[ $CODE =~ ^[A-Za-z0-9\ -]{16,24}$ ]] || { echo "That is not a pairing code." >&2; exit 1; }
claude mcp get example >/dev/null 2>&1 || claude mcp add --scope user --transport http example "$MCP"
curl -fsS -X POST "$AUTH/auth/oauth/pairing/redeem" -H 'Content-Type: application/json' \
     --data "{\"code\":\"$CODE\"}" >/dev/null \
  || { echo "Code unknown, used or expired — create a new one." >&2; exit 1; }
# Without a terminal `claude mcp login` waits silently after the browser: give it a console of its own.
if [ -t 1 ]; then claude mcp login example
elif command -v x-terminal-emulator >/dev/null; then x-terminal-emulator -e claude mcp login example
else osascript -e 'tell application "Terminal" to do script "claude mcp login example"'
fi
```

PowerShell (Windows):

```powershell
$Auth = "https://auth.example.com"; $Mcp = "https://app.example.com/mcp"
$Code = Read-Host "Pairing code from 'Connect a program'"
claude mcp get example *> $null
if ($LASTEXITCODE -ne 0) { claude mcp add --scope user --transport http example $Mcp }
Invoke-RestMethod -Method Post -Uri "$Auth/auth/oauth/pairing/redeem" -ContentType "application/json" `
  -Body (@{ code = $Code } | ConvertTo-Json) | Out-Null
# A console of its own: `claude mcp login` needs a terminal.
Start-Process powershell -ArgumentList "-NoExit", "-Command", "claude mcp login example"
```

`claude mcp login --no-browser` (SSH, no browser on that machine) works too: the URL pasted into the address bar is the
person's own navigation. What remains is a local program that starts its own authorization within the window — see
`SECURITY.md` and ADR-14.

The end-to-end check against the real Claude Code CLI is `tools/oauth-e2e/e2e.py` (manual: needs `claude`, Docker
and Chrome).

## A service calls a protected app

A daemon, a backup job or a script on a server — a **service without a person** — reaches an application behind
TinySesam with a short-lived access token from the same server (T-60, ADR-13). It authenticates with **its own key
pair**: the private key never leaves the service, TinySesam keeps only the public half. Nothing in the database,
the proxy log or a backup lets anyone else get a token — unlike an API key, which is a copyable string. Nobody
builds anything: the reference client `tinysesam-client` does pairing, tokens and key rotation.

```python
TinySesamConfig(
    base_url="https://auth.example.com",
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/api"],
    oauth_service_clients=True,              # needs: pip install 'tinysesam[services]'
)
```

**1. Pair once.** In the admin panel, open a service account's keys ("Pair a service", e.g. one made with
`auth.create_service("backup", roles=["backup"])`), or — for a script that acts as yourself — the section
"Services" on your account page. You get a one-time **pairing code** (`ABCD-EFGH-JKMN-PQRS`, valid
`oauth_pairing_minutes`, 10 min). From your own code: `auth.create_service_pairing(uid, name="backup",
resources=["https://app.example.com/api"], roles=["backup"])`. The ready-made gateway has neither panel nor account
page: there `TINYSESAM_OAUTH_SERVICE_CLIENTS=1` switches services on, and the code comes from the command line, with
the service's environment — `docker exec <gateway> python -m tinysesam.gateway pair backup --create-service`
(`--resource`, `--roles`, `--name` as above). On the service's machine:

```bash
pip install "tinysesam[services]==0.31.0"
tinysesam-client pair https://auth.example.com ABCD-EFGH-JKMN-PQRS
#   creates an Ed25519 key pair, sends the public key with a proof that it holds the private one,
#   writes $XDG_CONFIG_HOME/tinysesam/client.json (mode 0600; --key-file or TINYSESAM_CLIENT_KEY_FILE to choose)
```

**2. Call the app.** From the shell, or from Python with `httpx` or `requests`:

```bash
curl -H "Authorization: Bearer $(tinysesam-client token)" https://app.example.com/api/things
tinysesam-client request GET https://app.example.com/api/things
```

```python
from tinysesam.client import ServiceClient
sc = ServiceClient("/etc/backup/tinysesam.json")
httpx.get("https://app.example.com/api/things", auth=sc.httpx_auth())
requests.get("https://app.example.com/api/things", auth=sc.requests_auth())
```

The proxy needs nothing new: forward auth accepts the token and passes `Remote-User` (the service account),
`Remote-Groups` (its roles) and `Remote-Kind: service` on — the application sees a signed-in account and can tell it is
a service.

What happens and what protects it:

- **Token request** `grant_type=client_credentials` with `private_key_jwt` (RFC 7523): a JWT signed with the
  service's key, `iss` = `sub` = the client ID, **`aud` = the issuer** (`base_url`, as its only value — RFC 10070;
  the token endpoint URL is refused), `exp` at most 5 min ahead, a `jti` that works once. Algorithms `Ed25519`,
  `ES256` (and `EdDSA` for an Ed25519 key); never `none` or HMAC, and never a key the JWT brings along
  (`jwk`/`jku`/`x5u`). Any OAuth client library with `private_key_jwt` works the same way once paired.
- **Access token** opaque, `oauth_service_token_ttl_sec` (15 min), **no refresh token** — the service simply asks
  again (the client caches and renews it). Valid only for the resource(s) it was paired for (`invalid_target`
  otherwise), checked against the database on every request.
- **Never admin.** The service acts as its account without the admin flag, with an optional role scope (trimmed to
  the account's roles). A locked account, a revoked service or a removed role takes effect at the next request.
- **Pairing** happens only from an interactive, freshly confirmed session (never an API key); the code is stored
  as a digest, works once, 20 attempts per address and hour, and every refusal lands in the audit log.
- **Keys expire** after `oauth_service_key_days` (90); the client **rotates by itself** at half the lifetime:
  it writes the new key as *pending* first, registers it (signed with the old key, proven with the new one), then
  switches. The old key stays valid for an hour at the token endpoint — tokens in flight and other processes keep
  working — but it can never rotate again: only the current key may (a copied old key cannot take the service over).
  `tinysesam-client rotate` does it now.
- **Revocation:** the account page and the admin panel (tab "Connected programs") list every service with its last
  token request, address and key expiry, with "Revoke"; `auth.list_service_clients()`,
  `auth.revoke_service_client(client_id)`. Locking the account, an admin password reset and "end all sessions"
  revoke its services like its API keys. Events: `oauth_service_paired`, `oauth_service_revoked`.

Another language? Pairing is one JSON request — `POST /auth/oauth/pair` with `{"code", "jwk", "proof"}`, where
`proof` is a JWS of the new key with `typ: tinysesam-pairing+jwt`, `aud` = issuer, `nonce` = Base64url(SHA-256(the
code without dashes)) — and the answer (`client_id`, `token_endpoint`) is everything a standard `private_key_jwt`
client needs. Key rotation: `POST /auth/oauth/service/keys` (form: a client assertion, `jwk`, `proof` with
`typ: tinysesam-key+jwt` and `sub` = client ID).

## App passwords: WebDAV, CalDAV, Git behind TinySesam

Some clients cannot open a sign-in page: a file sync over **WebDAV**, the calendar and contacts of a phone
(**CalDAV/CardDAV**), **Git over HTTPS**, a backup script. They speak only Basic auth — a user name and a password in
every request. For them an account creates an **app password** on its account page (T-66): generated, shown once
with a copy button, valid only for the applications chosen, revocable on its own. The account's own password never
works this way, so the second factor cannot be skipped. (Samba and other non-HTTP protocols are not covered — they
never pass the proxy.)

Switch it on per application — default off:

```python
TinySesamConfig(
    forward_auth_enabled=True,
    base_url="https://auth.example.com",
    trusted_redirect_hosts=["dav.example.com"],
    forward_apps={"dav.example.com": {"name": "Files", "app_passwords": True}},
    # app_password_default_days=365, app_password_allow_unlimited=False
)
```

Gateway: the same key in `TINYSESAM_FORWARD_APPS='{"dav.example.com": {"name": "Files", "app_passwords": true}}'`;
`oidc_gateway()` then switches the account page on (otherwise off in a gateway), where the app passwords are made.
The quickstart stack has the whole example: `COMPOSE_PROFILES=webdav` adds a WebDAV server as the application
(`deploy/quickstart/example.env`, "WebDAV behind the gate").

**At the proxy** one branch more in the forward-auth block of the application (Caddy, as in
`deploy/forward-auth/Caddyfile`), **before** `@denied`: TinySesam answers a client without a browser with `401`,
`WWW-Authenticate: Basic realm="Files"` and `X-TinySesam-Reason: basic`, and the client needs exactly that 401 — a
redirect to the sign-in page would end its sync. And the application should not see the password:

```caddyfile
dav.example.com {
	route {
		reverse_proxy {$TS_AUTH_UPSTREAM:127.0.0.1:8000} {
			method GET
			rewrite /auth/forward
			header_up X-Forwarded-Method {method}
			header_up X-Forwarded-Uri {uri}
			header_up -X-Original-URL
			header_up -X-Original-URI
			@ok status 200
			handle_response @ok {
				request_header Remote-User {rp.header.Remote-User}
				request_header Remote-Groups {rp.header.Remote-Groups}
			}
			@basic {
				status 401
				header X-Tinysesam-Reason basic
			}
			handle_response @basic {
				header WWW-Authenticate {rp.header.Www-Authenticate}
				respond 401
			}
			@denied status 401
			handle_response @denied {
				redir {rp.header.X-Tinysesam-Location} 302
			}
		}
		# The application trusts Remote-User — it does not need the password (nor any other credential).
		reverse_proxy {$TS_APP_UPSTREAM:127.0.0.1:9000} {
			header_up -Authorization
			header_up -X-Api-Key
		}
	}
}
```

Then, on the device: user name as at sign-in, the app password as password — e.g.
`rclone lsf :webdav: --webdav-url https://dav.example.com/ --webdav-user alice --webdav-pass "$(rclone obscure …)"`,
`git clone https://alice@git.example.com/repo.git`, or the account settings of the phone's calendar. A browser that
opens the same application is still sent to the sign-in page (requests with `Sec-Fetch-*` or `Accept: text/html` get
no Basic challenge — it would pop up the browser's own password box). The templates in `deploy/` (`forward-auth`,
`quickstart`, `home-network`) carry the `@basic` branch; it does nothing at a host without app passwords.

What protects it:

- **Format:** five groups of five lowercase letters and digits without `0 o 1 l i` (`k7qm3-x9tfa-…`), ≈ 124 bits —
  easy to type on a phone, case and hyphens are ignored. Stored is only an HMAC digest keyed with the pepper keyring
  (ADR-12, `tinysesam keys rotate --purpose oauth-pepper` keeps them valid).
- **Bound:** to its account (the user name must match), to the applications chosen (default: one), and only at
  `/auth/forward` — never at TinySesam's own routes. It carries the account's roles but **never the admin flag**,
  like an automation key; no gate cookie is issued, so a revocation takes effect on the next request. An account
  from an identity provider keeps them only while the provider still confirms it (`oidc_apikey_confirm_days`, as
  for API keys).
- **Lifetime:** `app_password_default_days` (365 — typed into a phone by hand, it should not break every quarter);
  the holder chooses 30, 90 or 365 days, "never" only with `app_password_allow_unlimited=True`.
- **Created only with a fresh confirmation** (like a passkey or an API key); the holder gets the event
  `app_password_created` and, with a mailer, a notice. Revoked with the API keys when the account is locked, an
  administrator resets its password, or the holder signs out everywhere; the own password change keeps them and says
  how many (`app_passwords_active`).
- **Guessing:** a wrong one is a failed sign-in in a bucket of its own (pair, account, address — it does not lock the
  browser sign-in) and a `failed login … method=app_password` line for fail2ban. A known app password that was
  revoked or has expired is refused without counting — an old phone does not lock its owner out.
- **Visible:** the account page lists name, applications, created, last used and address; the admin panel has a tab
  with all of them. Audit `app_password_create`, `app_password_use` (once an hour per address), `app_password_denied`,
  `app_password_revoke`, `app_passwords_revoked`.

In code: `auth.create_app_password(user_id, name, hosts=[…], expires_days=…)` (the plain text once, under
`secret`), `auth.list_app_passwords(user_id)` (`None`: all accounts), `auth.revoke_app_password(id, user_id)`,
`auth.app_password_hosts()` (the applications that take them). The end-to-end check with a real WebDAV client
behind a real Caddy is `tests/e2e_app_passwords.py` (manual: needs Docker).

## Admin panel

Built-in panel at **`/auth/admin`** (administrators; delegated admins see their part — see
[Delegated administration](#delegated-administration)), embeddable with no extra setup:

- **Users & service accounts:** a slim list (name, type, roles, status) with search; a click opens the account's
  own page (address `#user/<id>`) with the sections *Profile*, *Access* (roles, [role levels](#role-levels), admin),
  *Sign-in* (password, passkeys, API keys, sign-in link) and *Danger zone* (lock/unlock — the account stays, login
  blocked, sessions end immediately; in code: `auth.set_disabled` —, owner, delete). The roles of `available_roles`
  are offered grouped by prefix (`app:`, `ops:` …) with a filter; a role an account holds that is not configured stays
  ticked under its own heading instead of being dropped on save.
- **API keys** per user: generate (shown once) / revoke.
- **Sign-in link** per user (with `magiclink_enabled`): one-time link plus QR code, shown once,
  works without a mailer — see [Sign-in by link and from another device](#sign-in-by-link-and-from-another-device).
- **Sessions:** view active ones + end them.
- **App passwords** (when an application takes them): every account's, with applications, last use and address;
  revoke — see [App passwords](#app-passwords-webdav-caldav-git-behind-tinysesam).
- **Hardening:** tune the thresholds (attempts/lockout time/rate limit) live.
- **Version:** the running version plus a note on how updates work — there is **no “update
  now” button**, and deliberately so ([ADR-2](https://github.com/Ollornog/TinySesam/blob/main/backlog/ADR-2-no-self-update.md)):
  an auth module that loads code at runtime is a back door with a manual. You update where you
  installed it. (This line used to promise a button, a manual/auto mode and a version pin —
  none of which has existed since 0.12.0.)
- **Audit log** view.

JSON API at `<mount>/api/*` (the same actions — for your own UIs / automation).

### Role levels

Some roles come in steps: `coll:photos-read` lets an account read a collection, `coll:photos` lets it write. Ticking
both boxes per collection is error-prone; `role_levels` turns such roles into **one choice per entry** —
"— / read / write" — in the panel:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    available_roles=["coll:photos", "coll:photos-read", "coll:recipes", "coll:recipes-read", "editor"],
    role_levels=[{
        "name": "collections",
        "label": "Collections",            # a text, or one per language: {"en": …, "de": …}
        "levels": [  # lowest first
            {"name": "read", "label": "read", "role": "coll:{1}-read"},
            {"name": "write", "label": "write", "role": "coll:{1}"},
        ],
    }],
)
```

- **Each level adds one role template** with `{1}`; a level stands for its role and every role below it. Choosing
  *write* for `photos` stores `coll:photos-read` **and** `coll:photos`; *—* stores neither.
- **The entries** (`photos`, `recipes`) come from the known roles: `available_roles` and the
  [role catalog](#role-catalog). When a role matches several templates, the most specific one wins: `coll:photos-read`
  is the read role of `photos`.
- **A way to pick roles, not a hierarchy.** An account holds plain roles as before: `Remote-Groups`, the gate token,
  key scopes and `has_role` carry exactly the stored roles — `coll:photos` alone does not imply `coll:photos-read`.
- **Existing accounts are never widened silently.** An account holding `coll:photos` without `coll:photos-read` is
  shown as *incomplete*; nothing is preselected, and saving keeps those roles until an administrator picks a level.
- **A level is offered only when all its roles are known**: in `available_roles` or the catalog for an administrator
  (otherwise it
  is struck through, with the missing role named), in their scope for a [delegated admin](#delegated-administration)
  (otherwise it is not shown; an entry without a grantable level is left out). The server checks the scope as before.
- **Checked at start:** at least two levels, every template with exactly one `{1}` and a literal part, no template
  twice, no comma, no two ladders whose templates can match the same role, no equally specific overlap inside one —
  errors; a delegate holding only part of a level — a warning. A ladder without entry and an entry missing the role of
  a level are start warnings over the known roles (the configuration check has no database and cannot see the catalog).

### Role catalog

Administrators add roles in the panel (**Accounts → Roles**) without touching the configuration; the panel then offers
them like `available_roles` — as checkboxes and as entries of the role levels. A convenience, nothing more:

- **It grants nothing.** Headers, the gate token, key scopes and `has_role` read only the roles an account holds; an
  administrator could set any role before. Fine-grained rights on an application's objects (a collection, its owners,
  moderators) belong in the application.
- **The configuration stays the truth.** A role the configuration names anywhere (`available_roles`, the group maps,
  `admin_delegates`, `signup_default_roles`, link visibility, `apps`), `admin` and `__admin__` cannot be added. A
  catalog role the configuration names later is redundant — the start says so, and it may be deleted. Whatever the
  configuration refers to (a delegate's roles, an application's allowlist) still has to stand in `available_roles`.
- **Names:** no comma, no control or invisible character, no surrounding spaces, at most 64 characters, no second
  spelling (`Editors` next to `editors`). No renaming: add the new one, move the accounts, delete the old one.
- **Deleting only what nobody uses:** refused while an account holds the role, an API key or OAuth service scope names
  it, an open invitation or pairing code carries it, or a pending approval would add it. The check and the delete are
  one transaction; nothing cascades. A role that is one level of a role level entry goes with its entry — the panel
  adds and deletes an entry with all its level roles at once.
- **Administrators only** (CSRF and the panel's step-up); delegated admins and applications do not change the catalog.
- **In code:** `auth.create_role("editor", actor=None)`, `auth.delete_role("editor")` (both raise `RoleError` with
  `e.code`: `invalid`, `exists`, `in_config`, `in_use`, `in_ladder`, `not_found`, `full`, `forbidden`),
  `auth.known_roles()`, `auth.role_catalog()`, `auth.role_usage("editor")`. On the command line:
  `tinysesam roles list|create|delete --db auth.db --config mod:attr [<role>]` (the configuration is required to
  change the catalog).

```python
import os
import tempfile

from tinysesam import RoleError, TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "roles.db"), available_roles=["staff"]))
auth.create_role("editor")
assert auth.known_roles() == ["editor", "staff"]
try:
    auth.create_role("staff")
except RoleError as e:
    assert e.code == "in_config"
uid = auth.create_user("lena", password="a long probe password 4711", roles=["editor"])
assert auth.role_usage("editor")["users"] == 1
auth.set_roles(uid, [])
assert auth.delete_role("editor") == {"name": "editor", "in_config": False}
```

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
- **HSTS** (`config.hsts`, ASVS 3.4.1): with `https_mode="force"`, `install_https` also sets
  `Strict-Transport-Security: max-age=31536000` on every HTTPS response of the app, your own routes included —
  never over plain HTTP. Without `includeSubDomains` by default: on a parent domain it would bind every subdomain
  to HTTPS; append `; includeSubDomains` once they all serve HTTPS (ASVS L2). `""` = no header (the proxy sets it;
  the templates under `deploy/` do).
- **No API docs in production:** FastAPI serves `/docs`, `/redoc` and `/openapi.json` without sign-in — the
  schema lists TinySesam's routes too, and Swagger loads from a third-party CDN. The gateway switches them off;
  in your own app use `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` (ASVS 13.4.5).
- **Content-Security-Policy** (`config.csp`): the built-in pages (login, account, TOTP setup, error)
  ship a **strict, nonce-based CSP** — no `unsafe-inline`. A fresh nonce per response goes into every
  `<script>`/`<style>` and the header; the pages are built inline-free (no `onclick`/`onsubmit`, no
  `style=`) so the nonce covers everything. `"strict"` (default), `"off"` (no header — e.g. a proxy
  sets the CSP), or your own policy string (a `{nonce}` in it is substituted per response). A template
  override returning a `Response` is left untouched and gets `ctx["nonce"]` to build its own.

## Delegated administration

Team leads manage the accounts of their team in the built-in panel without becoming administrators (T-74). The model
is role-based rights with a scope — like organisational units in a directory or administrative units in Entra ID: a
**delegate role** names the roles it manages, and its holders act only on accounts inside that scope. A delegate role
can manage other delegate roles below it (`manages`), so a two-level hierarchy looks like this:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    available_roles=["X", "A", "A-read", "B", "B-read", "area-admin", "team-a-admin", "team-b-admin"],
    admin_delegates={
        "area-admin":   {"roles": ["X"], "manages": ["team-a-admin", "team-b-admin"]},
        "team-a-admin": {"roles": ["A", "A-read"]},
        "team-b-admin": {"roles": ["B", "B-read"], "can": ["create", "disable", "roles"]},
    },
)
```

- **What a delegate does:** create accounts and invitations, issue a sign-in link, lock and unlock, set or remove the
  managed roles — only on accounts whose roles **all** lie within the managed roles (at least one). Never an admin,
  owner or service account, never their own. Strict on purpose: an account in two teams belongs to whoever is above
  both.
- **Managed roles:** a delegate role's own `roles`, the delegate roles below it (it appoints and removes them) and
  their roles. Above, `area-admin` manages X, A, A-read, B and B-read and appoints `team-a-admin` and `team-b-admin`;
  `team-a-admin` manages A and A-read. `manages` is a hierarchy without cycles; a role may have several parents.
- **Never sideways or upwards:** a `team-a-admin` sees neither team B, nor other `team-a-admin` accounts, nor the
  `area-admin`. A delegate never grants their own delegate role or one above it. An account with several delegate
  roles may do what one of them allows, on that role's accounts.
- **`can`** narrows the actions of one delegate role (`create`, `invite`, `disable`, `roles`, `signin_link`; without
  it, all of them). It is not inherited up or down.
- **The rest of the panel stays with administrators** — password reset, rename, delete, keys, passkeys, sessions,
  connected programs, app passwords, hardening, audit. Every limit is enforced on the server, route by route; the
  panel shows a delegate only their tab, their accounts, their roles and their buttons. The top bar and the account
  page offer them "Admin panel". `require_admin` and your own admin routes do not change: a delegate is no admin.
- **Only a browser session:** an API key, an OAuth token or an app password neither opens the panel nor carries a
  delegate role (not in `Remote-Groups` either) — like the admin flag. The session keeps it, so an application can
  show its own team page (`topbar_links` with `{"role": "team-a-admin"}`). An app that keeps profiles from
  `Remote-Groups` refreshes them only when `Remote-Auth` is `session` (empty counts as a token): a token request
  lacks `admin` and the delegate roles on purpose and must not downgrade the profile.
- **Step-up and audit:** the same confirmation as administrators (`admin_require_mfa`); creating, inviting and a
  sign-in link always ask for a fresh one. The audit log names the acting account (`actor=`), the panel's own lines
  also `as=<delegate role>`. Delegates have no audit view: the lines carry other people's addresses.
- **Checked at construction:** every role in `available_roles`, a delegate role never inside a `roles` list
  (appointing goes only through `manages`), `manages` names delegate roles, no cycle, `can` only known actions, no
  delegate role called `admin`.
- **Roles from an identity provider** (`*_group_role_map`) are set again at the next sign-in — a delegate's change to
  such a role does not last.

What a delegate can take over (a sign-in link signs into the account) is in
[`SECURITY.md`](https://github.com/Ollornog/TinySesam/blob/main/SECURITY.md#operating-notes-important).

## Approvals: a token asks, the person confirms

An API key never carries the admin flag or a delegate role (R6-5, T-74) — so a script or Claude with a key cannot set
roles, revoke someone's key or disable an account. With approvals it can **ask**, and the person confirms in their
browser with a step-up for exactly that action:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(approvals_enabled=True, base_url="https://auth.example.com")
```

```http
POST /auth/api/approvals
X-Api-Key: tsk_…

{"type": "tinysesam.account.set_roles", "fields": {"account": "17", "add": ["editors"], "remove": ["viewers"]}}
```

```json
{"id": "apv_q4m7…", "state": "pending", "match_code": "418 207",
 "approve_url": "https://auth.example.com/auth/approvals/apv_q4m7…", "expires_at": 1767226200}
```

- **Types (stage A):** `tinysesam.account.set_roles` (`account`, `add`, `remove` — roles only, never the admin flag),
  `tinysesam.apikey.revoke` (`key`), `tinysesam.account.disable` (`account`). Ids are decimal strings. Unknown,
  missing or wrongly typed fields are a `400`.
- **Show the link and the code** to the person (Claude prints both; with MCP it is a URL elicitation). The page shows
  the same code, what is asked (from TinySesam's own texts and the database, never free text of the requester), which
  key asked and the time left. In the account menu the entry **Approvals (n)** leads to the open ones;
  `topbar_data()` carries `"approvals": {"pending": n, "href": …}` for an application with its own bar.
- **The person decides** in a browser session of the same account — never with a token — and confirms once more for
  this approval: password, PIN or TOTP (as `stepup_methods` allows), a passkey bound to the approval, or a fresh
  sign-in at the provider. TinySesam then runs the action with the admin panel's code and the rights the session has
  at that moment: an administrator, a delegate within their scope, the holder for their own key.
- **The token reads the outcome:** `GET /auth/api/approvals/{id}` (`?wait=25` waits up to 25 s) gives `state` —
  `pending`, `consumed` with `result` (`ok`, `forbidden`, `not_found`, `invalid`, `conflict`), `rejected`, `expired`,
  `withdrawn`. `DELETE` withdraws a pending request. Only the asking key sees its requests.
- **Limits** (`approval_open_per_account`, `approval_open_per_token`, `approval_requests_per_hour`,
  `approval_reject_limit`) answer `429`; a request waits `approval_pending_sec` (default 10 min). `tinysesam gc`
  expires and later deletes the rows.

Why this keeps "admin and delegate rights never through tokens": [`SECURITY.md`, "Approvals"](https://github.com/Ollornog/TinySesam/blob/main/SECURITY.md#approvals-stage-a-a-token-proposes-the-person-confirms).

### Approvals for application actions: a signed one-time confirmation

An application can have its own sensitive actions confirmed the same way — "delete this collection permanently".
TinySesam does not carry them out: it hands the application **one signed confirmation** that exactly this person
confirmed exactly this action with a step-up, and the application checks it before it acts. Whether the action is
allowed (only the owner, typed the name) stays the application's rule, before it asks and again before it acts.

The operator registers the application's action types — the texts the person reads come from the operator, never from
the application, which only sends field values:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    approvals_enabled=True, base_url="https://auth.example.com",
    apps={"example": {
        "account": "svc-example",                      # its service account asks, with an automation key
        "name": {"en": "Example", "de": "Example"},
        "approvals": {
            "return_urls": ["https://app.example.com/approvals/return"],   # browser entry, compared exactly
            "types": {"example.collection.delete_permanently": {
                "fields": {"collection": {"type": "string", "max": 64, "pattern": "^[A-Za-z0-9_-]{1,64}$"},
                           "name": {"type": "string", "max": 120}},
                "title": {"en": "Delete collection permanently"},          # plus "de": … for German pages
                "summary": {"en": "Permanently delete the collection {name} ({collection})."},
                "irreversible": True}}}}})
```

- **Type names** begin with the application's id (`example.<thing>.<action>`, at least three segments); an
  application asks only for its own (`403 forbidden_type`). Fields are `string` (with `max` ≤ 500 and an optional
  `pattern`), `integer` (`min`/`max`) or `boolean`; unknown, missing or wrongly typed fields, control and bidi
  characters are a `400`. `types_file` names a JSON file with the same mapping; `types_from` lets a second channel
  (`example_test`, its own service account) ask for these types while its confirmations name only `example_test`.
  `config_check` refuses a placeholder that is no field, a text without `en`, a malformed name.
- **Ask** (back end): `POST /auth/api/approvals` with the service account's key, `{"type": …, "subject": "42",
  "fields": {…}}` — `subject` is the person who must confirm (for example `Remote-Id`). The answer carries
  `approve_url` and the six-digit `match_code`. Show both (a link, an MCP URL elicitation) — or, when the person is
  already in the application, add `return_url` (exactly a registered one) and `state` (random, kept in the session)
  and redirect the browser to `approve_url`.
- **The person confirms** on the approval page: the application's name, the operator's text with every value escaped
  and isolated (`<bdi>`), the field table, the code, a step-up for this approval. With `return_url` the browser goes
  back to `return_url?approval=<id>&state=<state>` (`&result=rejected|expired` when not confirmed) — never with the
  confirmation.
- **Pick up** (back end): `GET /auth/api/approvals/{id}?wait=25`. The first answer after the confirmation carries
  `"confirmation": "<JWS>"` — exactly once (`approved` → `consumed`); it lives `approval_token_ttl_sec` (default 120 s,
  at most 300). Not picked up within `approval_pickup_sec` (default 300 s) it expires.
- **Check** it with the keys of `/auth/approvals/jwks.json` (`TinySesam.approval_jwks()`; a key of its own, never the
  gate key), then remember its `jti` and act:

```python
from tinysesam.approval_token import verify


def may_delete(token, collection, name, person_id, keys, jti_store, state=None):
    """keys: /auth/approvals/jwks.json; jti_store(jti, until) -> True only the first time (a unique INSERT)."""
    return verify(token, keys=keys, issuer="https://auth.example.com", app_id="example",
                  expect_type="example.collection.delete_permanently",
                  expect_fields={"collection": collection, "name": name}, expect_sub=str(person_id),
                  jti_store=jti_store, expect_nonce=state)
```

The contract for other languages, with vectors: [`spec/approval-token.md`](https://github.com/Ollornog/TinySesam/blob/main/spec/approval-token.md). Why the
confirmation has its own key, type and audience: [`SECURITY.md`, "Approvals for application actions"](https://github.com/Ollornog/TinySesam/blob/main/SECURITY.md#approvals-for-application-actions-stage-b-a-signed-one-time-confirmation).

## Accounts for applications: the account API

An application behind TinySesam often needs its own accounts — a team admin in the application invites a colleague. With
the account API the application creates and manages **the accounts it creates itself**, through its service account,
inside narrow limits: no password, passkey or TOTP, no address change, no account it did not create, never an admin.

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    base_url="https://auth.example.com", magiclink_enabled=True,
    available_roles=["example-member", "example-editor", "staff"],
    apps={"example": {
        "account": "svc-example",                    # service account (is_service); its automation keys speak for the app
        "name": {"en": "Example", "de": "Example"},
        "provisioning": {
            "roles": ["example-member", "example-editor"],                       # allowlist
            "scopes": ["users:read", "users:invite", "users:update", "users:disable", "users:delete"],
            "link_ttl_min": 60, "max_accounts": 1000, "delete_grace_days": 7,
            "limits": {"create_per_hour": 60, "disable_per_hour": 60, "link_per_hour": 30, "taken_per_hour": 30,
                       "delete_per_hour": 20, "delete_per_day": 100},
        },
    }},
)
```

```http
POST /auth/api/users
X-Api-Key: tsk_…  (an automation key of svc-example)
TinySesam-On-Behalf-Of: 17

{"username": "lena", "display_name": "Lena M.", "email": "lena@example.org", "roles": ["example-member"]}
```

```json
{"id": 42, "username": "lena", "signin_url": "https://auth.example.com/auth/magic/…", "expires_at": 1767229800,
 "qr": "data:image/png;base64,…", "user": {"id": 42, "state": "active", "roles": ["example-member"], "…": "…"}}
```

| Route | Scope | What |
|---|---|---|
| `POST /auth/api/users` | `users:invite` | create a person with allowlist roles (at least one) and an optional `next`; the one-time link is only in this answer |
| `GET /auth/api/users/{id}`, `GET /auth/api/users` | `users:read` | one account, or a page (`?limit=` ≤ 200, `&after=<id>`, `?role=`, `?state=`) → `{"users": […], "next": <id>\|null}` |
| `PATCH /auth/api/users/{id}` | `users:update` | `display_name` and `roles` (the whole wanted set within the allowlist; other roles stay) |
| `POST /auth/api/users/{id}/disable`, `/enable` | `users:disable` | the application's own lock; `enable` lifts only that one |
| `POST /auth/api/users/{id}/signin-link` | `users:invite` | a new one-time link, only before the first sign-in; older links die; optional body `{"next": …}` |
| `DELETE /auth/api/users/{id}` | `users:delete` | never signed in: gone for good (`204`); otherwise locked and deleted after `delete_grace_days` (`202` `{"state": "deleting", "delete_after": …}`) |
| `POST /auth/api/users/{id}/restore` | `users:delete` | take a deletion back within the grace period; afterwards `404` |
| `GET /auth/api/provisioning` | — | what the key may do: app, scopes, roles, quota, grace period, limits and what is left |

- **Calls go to TinySesam directly**, with an automation key of the service account (`X-Api-Key` or
  `Authorization: Bearer tsk_…`). A session cookie does not count. Writes carry `TinySesam-On-Behalf-Of`: the id of the
  person the application acts for, or `-` for a job — the audit keeps it as a claim beside the service account.
- **An account is the application's** when it created it (`managed_by`). Every other account — and an administrator,
  owner, service account or delegate — answers `404`, like one that does not exist. If the operator gave an
  application account a role outside the allowlist, the application still reads it (`"other_roles": true`), but
  display name, lock and link answer `409 account_shared`.
- **What the application reads of an account:** `id`, `username`, `display_name`, `email`, `email_verified`, `roles`
  (only from the allowlist), `other_roles`, `state`, `created_at`, `first_login_at`, `last_login_at`, `delete_after`,
  `source` (`local`, `oidc`, `saml`, `ldap` — two or more for a mixed account); `state` is `active`, `disabled` (by the application), `disabled_operator` (only the operator lifts it) or `deleting`.
- **Errors** are `{"error": <code>, "error_description": …}`: `401 unauthenticated`, `403 not_a_provisioning_app`,
  `403 scope_missing`, `404 not_found`, `400 invalid|actor_required|actor_invalid|role_not_allowed|name_invalid|
  email_invalid|next_invalid`, `409 username_taken|email_taken|quota_reached|account_shared|already_signed_in|account_disabled|
  disabled_by_operator|account_deleting|not_deleting`, `429 limit` with `Retry-After`. Write routes may answer `202` later (approvals); treat it as
  "not done yet".
- **Where the link leads afterwards** (T-94): `next` in the body of create or `signin-link` — after the password, the
  TOTP and whatever else the setup pass asks, the browser goes there instead of the usual target. Without `next`,
  `provisioning.welcome_url` is the application's default. Both are checked the same way: a path (`/welcome`) or an
  `http(s)` address on the host of `base_url` or in `trusted_redirect_hosts` — printable ASCII, no user part, no `//`,
  no other scheme, at most 2048 characters (an international domain in its `xn--` form). Anything else is
  `400 next_invalid` before anything is written. The target is stored with the token, never in the link, so whoever
  holds the link cannot rewrite it; the door checks it once more, and the audit (`signin_link_issue`) names only its
  host. The confirmed `reset_access` link (below) leads to `welcome_url` as well.
- The first sign-in through the link leads an account without factors through the setup pass (`/auth/setup`). After
  that the person helps themselves (sign-in link to their address, password reset), the operator does — or the
  application's team admin resets the access (below).

### Resetting an account's access: new phone, forgotten password

After the first sign-in a key alone never resets anything (that would be a takeover). The application asks instead,
and a person confirms: its team admin, holding the role `approver_role` that only the operator (or a delegate allowed
to) grants. Configuration — `approvals_enabled=True`, the scope `users:reset` and the role:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    base_url="https://auth.example.com", magiclink_enabled=True, approvals_enabled=True,
    available_roles=["example-member", "example-editor", "teamadmin"],
    apps={"example": {"account": "svc-example", "name": "Example", "provisioning": {
        "roles": ["example-member", "example-editor"],
        "scopes": ["users:read", "users:invite", "users:reset"],
        "approver_role": "teamadmin",               # never in any application's allowlist (config_check refuses it)
    }}},
)
```

```http
POST /auth/api/approvals
X-Api-Key: tsk_…  (an automation key of svc-example)

{"type": "tinysesam.account.reset_access", "subject": "17", "fields": {"account": "42"}}
```

`subject` is the team admin's account id, `account` the account to reset (both as strings). The answer carries
`approve_url` and a `match_code`; the team admin opens the link, compares the code and confirms with a step-up. Then
password, PIN, TOTP and passkeys of account 42 are deleted, its sessions, keys and app passwords end — and the
application picks up the new one-time link **once**: `GET /auth/api/approvals/{id}?wait=25` answers
`{"state": "consumed", "result": "ok", "output": {"signin_url": …, "expires_at": …, "qr": …}}`, every later read
without `output`. Who lacks the role when confirming gets `result: "forbidden"` and nothing changes. Details and error
codes: [`spec/provisioning-api.md`](https://github.com/Ollornog/TinySesam/blob/main/spec/provisioning-api.md) §5; why the role never comes from the application:
`SECURITY.md`.

### Deleting, taking over, releasing

- **Deleting** (`users:delete`): an account that never signed in goes at once — nothing to protect, and a typo is taken
  back cleanly. Any other is locked like `disable` (sessions, keys, app passwords and open links end) and gets
  `delete_after` = now + `delete_grace_days` (default 7, 0 = at once, at most 30); its name stays taken. The regular
  cleanup (`auth.gc()` or `tinysesam gc`) then deletes it through the same path as the panel — its audit lines stay,
  anonymised. During the period the application may restore it (`POST …/restore`), everything else answers
  `409 account_deleting`; afterwards the account answers `404`. `delete_per_hour` (20) and `delete_per_day` (100) bound
  what a leaked key deletes. A deletion request under Art. 17 GDPR that must take effect at once goes through the
  operator (panel "Delete").
- **Taking over existing accounts:** an application owns only what it created, or what the **operator** hands it — in
  the panel ("Take over for …", administrators only, with a step-up) or by CLI:
  `tinysesam accounts adopt --db auth.db --config myapp:cfg --app example --with-role example-member --dry-run`.
  Only accounts whose roles all lie in the application's allowlist (at least one), never an administrator, owner,
  service account or delegate. `tinysesam accounts release --app example [--user …]` takes accounts back,
  `tinysesam accounts restore <user>` cancels a deletion (also in the panel: "Cancel deletion"),
  `tinysesam accounts list [--app example]` shows them with their state.
- **The panel** marks an application's account in the type column ("App: Example") and filters by application; the
  account page says "Managed by …" — "(not configured)" when the application is gone from `apps`, and the start log
  then names it with the number of its accounts. A delegate sees an application's account only when all its roles lie
  in the delegate's scope.
- **The application's link is only for the way in:** once an account holds a role outside the allowlist (the operator
  or a delegate gave it one, an `approver_role` for instance), becomes administrator or delegate, is released, or
  someone signs in to it after the link was issued, a sign-in link the application still holds signs nobody in.

What a leaked application key can do at most, and what not:
[`SECURITY.md`, "Account API"](https://github.com/Ollornog/TinySesam/blob/main/SECURITY.md#account-api-for-applications).

## New in 0.5 — quick reference

All optional (on/off by config), usable individually and combined, front end replaceable everywhere.

- **Replaceable front end:** `auth.set_template(name, fn)` — `fn(auth, ctx)` returns an HTML string **or**
  its own `Response`. All 13 names: `login`, `pin`, `totp`, `totp_setup`, `reauth`, `account`,
  `register`, `forgot`, `reset`, `magic_request`, `magic_invalid`, `resource_unlock`, `error`.
  Built-in renderers are the fallback; `tinysesam.templates.DEFAULTS` holds the current list.
  To show one of these pages from a route of your own, `auth.render_page(name, status=200, request=request,
  **ctx)` renders it — your replacement if one is set, otherwise the built-in page — with the CSP nonce, the CSRF
  token and the mount prefix in `ctx`, and returns the `Response`. Pass `request`: without it a new CSRF token
  is issued, and other forms the user has open expire.
- **Stay signed in:** `remember_me_enabled` — checkbox → persistent cookie; unchecked = pure
  session cookie + short `session_ttl_transient_hours`.
- **Step-up / per-route MFA:** `Depends(auth.require(mfa=True))` (sudo freshness `stepup_max_age_sec`,
  → `/auth/reauth`). `admin_require_mfa=True` (the default since H2) additionally protects the panel with a fresh
  confirmation. **New access always wants a fresh confirmation (H2, B-12):** registering a passkey, setting up
  TOTP or a PIN, creating an API key, approving a cross-device sign-in and allowing an OAuth program — a fresh
  sign-in counts, an older session goes over `/auth/reauth`; the setup pass after a link is not asked again.
- **Start secret from the admin (H2, T-46):** a password the admin sets in the panel (new account, reset) is
  valid for one sign-in only — `/auth/setup` then asks for an own one (`admin_password_must_change`).
- **The holder hears of new access (H2, T-47):** `on_security_event` plus, with a mailer, a mail without a link
  (`notify_new_access`) for a new factor, API key, QR-signed-in device, issued sign-in link, admin-set password,
  connected program and token reuse; the account page lists them under "Recent activity".
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
- **Forward-auth:** `forward_auth_enabled` → `GET /auth/forward` (200 + `Remote-User/Groups/Email/…/Kind` or
  401 + `X-TinySesam-Location`). Examples: [`deploy/forward-auth/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/forward-auth/) (Caddy/nginx/Traefik;
  `nginx-path.conf` covers the other common shape — one host, individual paths protected, static files + PHP behind it).
  **Which proxy:** Caddy is recommended — with the gate token (ADR-9) it checks most requests itself, without asking
  TinySesam. nginx (also with PHP over FastCGI) and Traefik are supported and tested against the real proxies
  (`tests/test_proxies.py`, like Caddy in `tests/test_gate_caddy.py`); with them every request goes through
  `/auth/forward`. Traefik needs `aliasHeadersStrategy: delete` in its static configuration, or a `Remote_User` sent by
  the browser reaches a CGI/WSGI/PHP backend as `HTTP_REMOTE_USER` (see the header of `traefik.yml`).
  **Roles at the proxy:** have the proxy ask for them — `GET /auth/forward?roles=editor,admin` or the header
  `X-TinySesam-Roles`. One of the listed roles is enough; signed in but missing the role answers **403**
  (not 401 — that would bounce the user to the login and straight back). Without the parameter the endpoint
  stays binary, exactly as before. Several specifications are AND-ed, so a client that adds one itself can
  only tighten the check, never loosen it.
  **Which headers go out** is `forward_headers` — default `Remote-User/-Name/-Email/-Groups` (the
  Authelia set) plus `Remote-Id`, the account ID: users can change their username and email
  themselves, so an app should key users by `Remote-Id`. `Remote-Auth` says how the request signed in —
  `session`, `oauth`, `apikey` or `app-password`; a request through a valid gate token is a `session` (the token
  carries it as a signed claim). It explains why `Remote-Groups` differ: a token, a key or an app password never
  carries `admin`. **The groups of a token request are incomplete on purpose:** whenever `Remote-Auth` is not
  `session`, `admin` and every delegate role are missing. An app that keeps a profile from `Remote-Groups` updates it
  only from a `session` request and never downgrades it on a token request — otherwise the account flips between
  admin and not with every API call. An empty or missing `Remote-Auth` counts as a token. `Remote-Kind` says what the
  account is — `service` for a service account, otherwise `user` — and is **always** sent (a gate token carries it as
  the claim `ts_kind`): `Remote-Auth` tells how a request came in, `Remote-Kind` whether a person or a service is
  behind it (a paired service acting as a person is `oauth` + `user`). An account whose `is_service` is neither 0 nor 1
  gets 403, never a guessed `user`. **Never tie rights to `Remote-User` or
  `Remote-Email`:** a name or address that becomes free (account deleted or renamed) can be taken by
  another account, which then carries it into the app. Your proxy must set every one of these
  headers itself (the examples in `deploy/forward-auth/` do), or it passes a forged one through. Give it a mapping to rename or drop them: `{"user": "X-WEBAUTH-USER"}` sends that one
  header and nothing else (Grafana style), a list sends the same value under several names. The mapping
  is the complete list, so leaving `email` out is how you stop handing the address to the app. The default
  mapping is `TinySesam.FORWARD_HEADERS_DEFAULT`; to change one header and keep the rest, start from a copy:
  `forward_headers={**TinySesam.FORWARD_HEADERS_DEFAULT, "user": ["Remote-User", "X-WEBAUTH-USER"]}`. Rename
  something? Pull the new name through in your proxy config too. **One exception to "complete":** the slots in
  `TinySesam.FORWARD_HEADERS_MANDATORY` (`kind`) are sent even when your mapping leaves them out — under their default
  name; `{"kind": "X-Account-Kind"}` renames, `{"kind": []}` is a `ConfigError`. Gate clients after spec v2 refuse a
  request without it, so update TinySesam and the proxy template before the applications (`SECURITY.md`).
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

> **Every field, in one place:** [`CONFIGURATION.md`](https://github.com/Ollornog/TinySesam/blob/main/CONFIGURATION.md)
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
python -m tinysesam.gateway          # or: uvicorn tinysesam.gateway:app --ws none --no-proxy-headers
```

With your own `uvicorn` invocation pass `--ws none`: if a WebSocket library is installed, uvicorn otherwise
answers the forward-auth check of a WebSocket app (it carries the client's `Upgrade: websocket`) with 403 (B-5).
`python -m tinysesam.gateway` sets this itself.

The reverse proxy calls `GET /auth/forward` per request. The gateway mounts the full `/auth/*`
router — with `password_enabled=False` and OIDC as the only method, what remains is the OIDC
sign-in, the forward-auth endpoint, logout and `/me`. It is a narrow configuration, not a
single-route app.
Programmatically: `TinySesamConfig.oidc_gateway(issuer=…, client_id=…, client_secret=…, base_url=…)`.
A ready-made [`deploy/forward-auth/docker-compose.yml`](https://github.com/Ollornog/TinySesam/tree/main/deploy/forward-auth/) (gateway + Caddy) ships with it.

### The server with a configuration file (T-97)

The environment variables above configure an OIDC-only preset. **`TINYSESAM_CONFIG`** naming a TOML file (say /etc/tinysesam.toml) makes the
same gateway the full TinySesam — local accounts, admin panel, account page, `apps`, SAML, LDAP, everything the library
has. The keys are the field names of `TinySesamConfig` ([`CONFIGURATION.md`](https://github.com/Ollornog/TinySesam/blob/main/CONFIGURATION.md)), read with the standard
library (`tomllib`); the file starts from the library's defaults, not from the preset:

```toml
base_url = "https://auth.example.com"
db_path = "/data/tinysesam.db"
trusted_redirect_hosts = ["app.example.com"]
oidc_enabled = true                          # local accounts stay on beside it (password_enabled)
oidc_issuer = "https://id.example.com"
oidc_client_id = "tinysesam"
oidc_client_secret = "env:OIDC_CLIENT_SECRET"   # or: oidc_client_secret_file = "/run/secrets/oidc"

[oidc_clients."wiki.example.com"]
client_id = "wiki"
client_secret_file = "/run/secrets/wiki"
```

- **Secrets never as a literal.** `oidc_client_secret`, `smtp_password`, `ldap_bind_password` and `client_secret` in an
  `oidc_clients` entry take `"env:NAME"` or the sibling key `<field>_file`; a literal ends the start. The file can be
  reviewed and kept in git.
- **A key that is no field ends the start** and names the nearest field (`password_enabeld` → `password_enabled`).
- **The environment overlays the file:** each gateway variable above that is set wins over the field it stands for
  (`TINYSESAM_BASE_URL` → `base_url`, `TINYSESAM_PROTECTED_HOSTS` → `trusted_redirect_hosts`, …;
  `python -m tinysesam.gateway --help`); an unset or empty one changes nothing. None of them is required with a file.
- **Without `TINYSESAM_CONFIG` nothing changes:** a running gateway keeps its variables and its preset.

### Gateway and Caddy in 5 minutes

[`deploy/quickstart/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/quickstart/) is one stack: the gateway,
Caddy with caddy-jwt and an example application behind the gate — nothing to build, every image from a release or pinned
by digest.

```bash
git clone https://github.com/Ollornog/TinySesam && cd TinySesam
cp deploy/quickstart/example.env deploy/quickstart/.env && chmod 600 deploy/quickstart/.env
$EDITOR deploy/quickstart/.env        # your OIDC provider, two host names, the TLS mode
docker compose -f deploy/quickstart/docker-compose.yml up -d
```

Register `https://<TS_AUTH_HOST>/auth/oidc/callback` as redirect URL at the provider, open `https://<TS_APP_HOST>`: after
the sign-in the example application shows the `Remote-*` headers TinySesam set. Then put your own service in place of
`app`.

- **TLS mode** `TS_TLS`: `acme` (public domain, Let's Encrypt), `dns` (a domain that resolves only at home, DNS-01 —
  needs a Caddy with your DNS provider's module: `docker build --build-arg
  CADDY_EXTRA_MODULES=github.com/caddy-dns/<provider> deploy/forward-auth/caddy-gate`), `internal` (domain names with
  Caddy's own CA) or `ip` (a bare IP address — read
  [`docs/HOME-NETWORK.md`](https://github.com/Ollornog/TinySesam/blob/main/docs/HOME-NETWORK.md) first).
- **Included:** identity headers from the browser are stripped, HSTS wherever there is a domain, sign-out at the
  application, OAuth for MCP clients (`TS_OAUTH_RESOURCES`). **Not included:** the fail2ban feed, several applications
  with a client each, share paths, the gate token — take them from
  [`deploy/forward-auth/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/forward-auth/).
- Every pull request runs this stack in the modes `ip` and `internal` (`tests/test_quickstart.py`).

### Gate token: the proxy checks for itself (ADR-9)

In front of a third-party app the proxy otherwise asks `/auth/forward` for **every** request —
every script, stylesheet and icon included. With `gate_token_enabled=True` (gateway:
`TINYSESAM_GATE=1`) a successful check also returns a short-lived token signed with Ed25519. The
proxy stores it as the cookie `__Host-tinysesam_gate` on the app's host and from then on checks it
**itself**; TinySesam is only asked again when it is missing or expired. The way back is the
existing forward auth, so a request and its body are not lost.

- **Proxy:** Caddy with the [caddy-jwt](https://github.com/ggicci/caddy-jwt) plugin — template
  [`deploy/forward-auth/Caddyfile.gate`](https://github.com/Ollornog/TinySesam/blob/main/deploy/forward-auth/Caddyfile.gate),
  image `ghcr.io/ollornog/tinysesam-caddy-gate:v0.31.0` (built from
  [`deploy/forward-auth/caddy-gate/`](https://github.com/Ollornog/TinySesam/tree/main/deploy/forward-auth/caddy-gate/)).
- **Key:** a random Ed25519 key of its own (since T-48, ADR-12 — up to 0.25.x it was derived from the vault key):
  `TINYSESAM_GATE_KEY`, `gate_key_file`, otherwise kept in the database encrypted with the vault key. The proxy
  fetches the public keys from `/auth/gate/jwks.json` (`jwk_url`, caddy-jwt 1.5.0 or later — with 1.4.0 one failed
  first fetch made every later request with a gate token hang); a gate rotation needs nothing at the proxy, the first
  tokens of the new key take the way back until Caddy has fetched the set again. Each token carries
  `typ: tinysesam-gate+jwt` and its `kid`. `Authorization` is never a token source for the proxy
  (`disable_authorization_fallback`): API keys and access tokens neither pass there nor reach its log.
- **`caddy reload` under systemd:** the reload adapts the Caddyfile in the *calling* process, so `{$TS_AUTH_UPSTREAM}`
  and every other `{$…}` placeholder (`{$CREDENTIALS_DIRECTORY}` too) are resolved there. An `ExecReload=` without the
  environment leaves them empty; the reload fails (e.g. `open /tls.crt`) and Caddy keeps running with the old
  configuration, without a word. Put the variables in `EnvironmentFile=` at unit level — it applies to `ExecReload=`
  as well — and set `CREDENTIALS_DIRECTORY=/run/credentials/<unit>` in `ExecReload=` explicitly. With Docker
  (`docker compose exec caddy caddy reload`) the reload inherits the container's environment; nothing to do there.
- **Roles:** if the proxy requires roles (`X-TinySesam-Roles`), they are part of the token's
  audience (`app.example.com|roles=admin`); a token issued without roles does not count there.
- **Cost:** signing out, locking an account or a withdrawn grant only takes effect at the proxy
  once the token expires — `gate_token_ttl_sec`, default 300 seconds.
- **Gate clients in other languages:** an application behind the gate that reads the `Remote-*` headers or checks the
  gate token itself follows the
  [gate client specification](https://github.com/Ollornog/TinySesam/blob/main/spec/gate-client.md) (token format,
  checking order, groups, JWKS rules that never hang). Its language-neutral test and attack vectors in
  [`spec/vectors/`](https://github.com/Ollornog/TinySesam/tree/main/spec/vectors) are generated from TinySesam's own
  code. The **Go client** is in
  [`clients/go/`](https://github.com/Ollornog/TinySesam/tree/main/clients/go) (`net/http` middleware, header and
  token mode, standard library only; every release tags it as `clients/go/vX.Y.Z`:
  `go get github.com/Ollornog/TinySesam/clients/go@v0.31.0`), the **Rust client** in
  [`clients/rust/`](https://github.com/Ollornog/TinySesam/tree/main/clients/rust) (crate `tinysesam-gate`: header and
  token mode, the key set fetch behind the feature `jwks`, framework-neutral via the `http` crate, an axum example; not
  published to the Rust crate registry, use it as a git dependency), the **JS/TS client** in
  [`clients/js/`](https://github.com/Ollornog/TinySesam/tree/main/clients/js) (TypeScript, ESM, no runtime dependency:
  WebCrypto `Ed25519` and `fetch`, so it runs on Node, Deno, Bun and edge runtimes; Node/Express middleware and a Fetch
  adapter for Hono and edge handlers; not published to npm, use it from the repository), the **PHP client** in
  [`clients/php/`](https://github.com/Ollornog/TinySesam/tree/main/clients/php) (package `tinysesam/gate`, PHP 8.4+:
  ext-sodium and PSR interfaces only, a PSR-15 middleware, `$_SERVER` for PHP-FPM, a file-backed key set cache shared by
  the processes of one host; not published on Packagist, use it from the repository). The **Python client** is part of
  the package: `tinysesam.gate_client` (WSGI/ASGI, no FastAPI), next section.

### Gate client for Flask, Django and other Python apps (T-86)

An application behind the gate that is not built on FastAPI uses `tinysesam.gate_client`: the
[gate client specification](https://github.com/Ollornog/TinySesam/blob/main/spec/gate-client.md) in Python, tested
against every vector of `spec/vectors/`. It checks; it never signs anyone in or issues a token. Importing it pulls in
neither FastAPI nor the rest of TinySesam — only the standard library and `cryptography`, which `pip install tinysesam`
brings anyway.

```python
from tinysesam import gate_client

gate = gate_client.GateClient(mode="header", trusted_proxies=["127.0.0.1"])
who = gate.identify({"Remote-User": "anna", "Remote-Groups": "editors", "Remote-Auth": "session", "Remote-Id": "7",
                     "Remote-Kind": "user"}, peer="127.0.0.1")
assert who.id == "7" and who.has_role("editors") and who.is_session() and not who.is_service()

try:
    gate.identify({"Remote-User": "anna"}, peer="192.0.2.10")        # not from the proxy
except gate_client.UntrustedPeer:
    pass
```

- **Header mode** (`GateClient(mode="header")`, the one the proxy templates support today) reads `Remote-User`, `-Name`, `-Email`,
  `-Groups`, `-Id`, `-Auth` and `-Kind` strictly: a repeated field, invalid UTF-8, a control character, a `Remote-Id`
  that is not ASCII digits, or a `Remote-Kind` that is missing, not exactly `user`/`service`, or `service` with
  `Remote-Auth: session` is refused, never cleaned or guessed (spec version 2 — it needs TinySesam and the proxy
  templates of the same release). It is safe only when the proxy removes these headers from every client
  request, on every path, and is the only way to the application (spec §2.1); `trusted_proxies` refuses requests from
  any other peer. `header_names` follows a renamed `forward_headers`.
- **Token mode** (`GateClient(mode="token", issuer=…, audience=…, gate_keys=[…])` or `jwks_url=…`) verifies the gate token itself
  in the order of spec §4.4 and ignores every `Remote-*` header. The algorithm is fixed to EdDSA; `alg`, `jwk`, `jku`,
  `x5u` and `x5c` in the token are never trusted. Keys: the output of `tinysesam gate-key`, or the JWKS URL — fetched
  with the standard library's `urllib` (no extra dependency) within 5 s and 64 KiB, at most once per 10 s, cached for
  `max-age` clamped to 60–3600 s, the last good set kept for an hour after a failure; requests share a running fetch
  and none waits past the deadline. The token comes from the gate cookie (`DEFAULT_GATE_COOKIE`, or `cookie_name`) or
  `token_header`. With today's
  `Caddyfile.gate` the application never sees the token (T-84), so this mode waits for a delivery path.
- `gate.verify(jws)` checks a token without a request and returns the identity and the claims.
- **The identity**: `Identity` with `user`, `name`, `email`, `groups`, `id`, `auth`, `kind`, `account_kind`. Key records
  by `id`. `has_role` compares exactly (`admin` implies nothing). `is_session()` is true only for `Remote-Auth: session`;
  an empty or unknown value is a token, whose groups are incomplete on purpose. `is_service()` is true only for a
  service account (`account_kind == "service"`, from `Remote-Kind` or `ts_kind`). Names may hold any character but
  controls: escape them.
- **Errors**: `gate.identify` raises a `GateError` whose `kind` is the class of the specification — `Unauthenticated`,
  `UntrustedPeer`, `HeaderError`, `InternalError`, and under `TokenError`: `MalformedToken`, `KidError`,
  `SignatureError`, `KeyUnavailable`, `ClaimsError`, `IssuerError`, `AudienceError`, `LifetimeError`, `NotYetValid`,
  `Expired`. Every one means *not authenticated*. A wrong configuration raises `ConfigError` at construction.
- **Middleware**: `WSGIMiddleware(app, gate)` (Flask: `app.wsgi_app = WSGIMiddleware(app.wsgi_app, gate)`; Django: wrap
  the application in `wsgi.py`) and `ASGIMiddleware(app, gate=gate)` (Starlette: `app.add_middleware(ASGIMiddleware,
  gate=gate)`) identify every request and let it through. The identity is in `environ["tinysesam.identity"]` /
  `scope["tinysesam.identity"]` and `current_identity()` returns it — also from a request object
  (`current_identity(request)` reads `.environ`, `.META` or `.scope`). A refusal is logged on `tinysesam.gate_client`
  with its class and `kid`, never with the token or a header value. With `jwks_url` the ASGI middleware checks in a
  worker thread, so a key fetch never blocks the event loop. WSGI servers join repeated header fields before the
  application sees them; the ASGI middleware refuses them.
- **Guards**: `require_auth(app)`, `require_role("editors")(app)`, `require_session(app)` and
  `require_account_kind("user")(app)` wrap a WSGI or ASGI application and answer 401/403 with `Cache-Control: no-store`
  and no reason. For view decorators in any framework, `guard_status(identity, role=…, session=…, account_kind=…)`
  returns `None`, 401 or 403.
- **Top bar** (optional): `parse_topbar(data)` reduces TinySesam's `/.tinysesam/topbar.json` to what may be rendered
  (`Topbar`, `TopbarLink`, with `links` and `menu_links`; unsafe links dropped, signed out on any doubt); `fetch_topbar(url, cookie_header)` fetches
  it server-side with only TinySesam's cookies; `Topbar.to_dict()` gives the normalized form of spec §8. With
  approvals switched on, `Topbar.approvals` is a `TopbarApprovals` (`pending`, `href`), otherwise `None`.
- **Server-side needs the session cookie**: the proxy templates strip TinySesam's cookies before the application (spec
  §2.1, duty 4), so `fetch_topbar` and `fetch_account` read *signed out* behind them. Prefer the browser way (the page
  fetches `/.tinysesam/topbar.json` or `/.tinysesam/account.json` itself, and the server never holds the session);
  server-side only for an application you trust with the session, with the commented variant in
  `deploy/forward-auth/Caddyfile.gate` (spec §8, "Server-side or in the browser").
- **Account overview** (optional, spec §8a): `fetch_account(url, cookie_header)` fetches `/auth/account.json` (or
  `/.tinysesam/account.json` on the application's host) server-side with only TinySesam's cookies;
  `parse_account(data)` normalizes an answer into a plain dict — `SIGNED_OUT_ACCOUNT` for anything but
  `signed_in: true`, unsafe links and members of the wrong type `None`.
- **Approval confirmations**: the check lives in `tinysesam.approval_token.verify` (also without FastAPI);
  `approval_token.JWKSKeys("https://auth.example.com/auth/approvals/jwks.json")` fetches the approval key set for it
  and refuses the gate key set. A complete application: `examples/approvals/app.py`.
- **Key sets**: every entry's `kid` must be the one derived from its key (the first 16 hex digits of SHA-256 over the
  32 key bytes, spec §4.3); an entry with a `kid` of your own choosing is skipped silently, and a fetched set without a
  single usable entry is a failed fetch — every token gets `KeyUnavailable` (with other usable entries: `KidError`).
  `jwks_url` refuses the approval key set (`…/approvals/jwks.json`), `JWKSKeys` the gate key set.

Flask, with a view decorator built on `guard_status`:

```python
import functools

from flask import Flask, abort
from tinysesam.gate_client import GateClient, WSGIMiddleware, current_identity, guard_status

app = Flask(__name__)
app.wsgi_app = WSGIMiddleware(app.wsgi_app, GateClient(mode="header", trusted_proxies=["127.0.0.1"]))


def require(role=None, session=False):
    def wrap(view):
        @functools.wraps(view)
        def guarded(*args, **kwargs):
            status = guard_status(current_identity(), role=role, session=session)
            if status:
                abort(status)
            return view(*args, **kwargs)
        return guarded
    return wrap


@app.get("/reports")
@require(role="editors")
def reports():
    return f"Hello {current_identity().name or current_identity().user}"
```

Complete programs for Flask and Django are in
[`examples/gate_client/`](https://github.com/Ollornog/TinySesam/tree/main/examples/gate_client).

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

With `TS_SHARE_PREFIX='^/(s|public/share)/'` both Caddy templates let paths through without sign-in
and without an identity. The raw path is checked; the rule rejects `.`/`..` segments (also with a path
parameter: `..;`), backslash, NUL and their encoded forms (Tomcat and Spring read `/s/..;/admin` as `/admin`); a `;` or `%3B`
elsewhere, such as in a file name, passes. Off by default. How to
measure an app's paths: `docs/OPERATIONS.md`.

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

After `all`, the page “Signed out” appears. With `forward_login="direct"` it leads back to the app by itself
after `forward_logged_out_sec` seconds (default 10, gateway `TINYSESAM_FORWARD_LOGGED_OUT_SEC`, 0 = stay):
the gate sends you on to the provider, which is signed out as well, so a **new** sign-in begins there. The
page uses a `meta refresh`, no script. In mode `page` the sign-in page itself says “You have been signed out”.

## Public API: two tiers

Not everything without a leading underscore is a promise. Since 0.22.0 every public name has a
**tier**, recorded in `tests/api_surface.json` and listed with signature and description in
[`API.md`](https://github.com/Ollornog/TinySesam/blob/main/API.md):

| Tier | What | Promise |
|---|---|---|
| **A — public, stable from 1.0** | what this README shows, and what embedding apps use | No breaking change across two minor releases — the condition for 1.0. The count starts with 0.22.0. |
| **B — for advanced use** | building blocks for your own account and admin pages (below) | Stays. Removed or reshaped only after a `DeprecationWarning` across two minor releases. A route has no warning: a path in tier B is announced in the CHANGELOG under “Deprecated” at least two minor releases before it goes. |

**Public is what the hand-written docs describe** (decided before 1.0): this README,
`CONFIGURATION.md`, `SECURITY.md` and `docs/OPERATIONS.md`. `API.md` is generated from the code and
lists every name with its tier; being listed there alone is no promise. The guard fails when a
tier-A or tier-B Python name (method, constant, property, preset, export, field of a result type) is
named in none of these documents.

A new public name has no tier until someone decides; the guard `tests/test_api_surface.py` stays
red until then, so nothing becomes a promise by accident. The config fields are tier A (except
one tombstone, marked in `CONFIGURATION.md`), and so are the error types (`TinySesamError`,
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
`human`. The same guard measures them on a probe instance and in the source. **Audit and log lines are
English too** (PO decision 2026-10-29): event names, keys, tokens, the replacement name of a deleted account
(`deleted#<id>`) and the message of the identifier triggers; the old → new lists are in the CHANGELOG of 0.22.0 and
0.25.0, and since the schema baseline only the English form is read.

**Beyond the Python names** (PO decision 2026-10-29). The tiers also cover what is not a Python name,
measured in `tests/api_surface.json` and listed in [`API.md`](https://github.com/Ollornog/TinySesam/blob/main/API.md):

- **Tier A:** `auth.cfg` — *reading* it (the attribute and its type; it is the instance you passed in).
  **Writing it is not promised:** it is a plain, mutable dataclass, and which field is read once and which
  per request is not part of the promise. And `auth.on_security_event` — the attribute, the call
  `hook(event, account, details)`, that it runs synchronously after the change is written, that a failing
  hook does not abort the operation, and the keys of `details` per event. The event names are
  `TinySesam.SECURITY_EVENTS` (the list with the keys of `details` is in `SECURITY.md`).
- **Tier A — the forward and gate contract** that reverse proxies depend on: `/auth/forward`, `/auth/verify`,
  `/.tinysesam/*`, `/auth/gate/*`, their status codes, the `X-TinySesam-*` headers and the values of
  `X-TinySesam-Reason`, the request headers a proxy sets or passes on (`X-Forwarded-Uri`, `X-Forwarded-Host`,
  `X-Forwarded-Proto`, `Cookie`, `Authorization` …) and `?roles=`, and the names of the cookies the gate sets.
  Tier A as well, because other systems have registered or poll them by hand: the OIDC callback, the SAML
  ACS and metadata paths and `/healthz`. The headers a browser sends on its own (`X-Csrf-Token`,
  `Sec-Fetch-Site`, `Referer`, …) are tier B.
- **Tier B — pages and API routes:** the HTML pages (sign-in, registration, account, admin panel …) and the
  JSON routes — **path and method** are promised, the HTML and the look are not. A path in tier B is announced
  in the CHANGELOG under “Deprecated” at least two minor releases before it is removed or renamed (a route cannot
  raise a `DeprecationWarning`).
- **Tier A — the security log** that fail2ban filters read: the logger names (`tinysesam.security`), the
  format of the log file, the event words (`failed login`, `failed verification`, `deferred login`,
  `repeated login`, `login ok`) and their keys in order (`user= ip= method= reason= unban=`). Free text
  after the keys is not promised. See `docs/OPERATIONS.md`, “Security log contract”.

For these new entries the tier-A clock starts with the release that introduces them (the one after 0.24.13),
not with 0.22.0; the names above keep theirs.

**`auth.store` is internal.** It is the storage layer the built-in routes use; its methods
have no tier, no promise and no deprecation period, and they may change in any release. Everything
an app needs has a public method (`set_disabled`, `find_user`, `list_api_keys`, `lift_lockout` …);
where the docs still mention an `auth.store` call (a health probe, dropping OIDC grants), they say
so.

**Internal is a leading underscore.** Up to 0.30.0 a third tier C kept the old public names of internal
methods as warning aliases (`check_password` → `_check_password` …); they are gone since the schema baseline
(the list is in the CHANGELOG, "Breaking"). A test fake belongs on the name the built-in routes call
(`auth._check_password = fake`); a fake on an old name is a plain attribute nobody reads.

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
  `verify_api_key`, `create_app_password`, `list_app_passwords`, `revoke_app_password`, `app_password_hosts`
  ([App passwords](#app-passwords-webdav-caldav-git-behind-tinysesam)), `create_service_pairing`,
  `list_service_clients`, `revoke_service_client` ([services](#a-service-calls-a-protected-app)), `revoke_mfa_enrollment`, `list_resource_secrets`, `remove_resource_secret`,
  `resource_unlocked`, `all_security`, `admin_exists`, `admin_claim_token`, `audit`,
  `FEDERATED_SOURCES`, `NAME_BINDING_REFUSALS`; the [role catalog](#role-catalog): `create_role`, `delete_role`,
  `known_roles`, `role_catalog`, `role_usage`, `RoleError`.
- **Mail and token flows:** `mail_configured`, `send_mail`, `create_magic_token` → `magic_url` →
  `peek_magic` / `redeem_magic`, `TOKEN_PATHS`, `require_public_base`, `create_signin_link` (one-time
  sign-in link without mail, address from `base_url`).
- **Proxy configuration for the gate token:** `gate_public_key` (`sign_key` for caddy-jwt, same as
  `tinysesam gate-key`), `gate_jwks` (the key set behind `/auth/gate/jwks.json` for `jwk_url`), `gate_issuer`
  (`issuer_whitelist`).
- **Approval confirmations of application actions:** `approval_jwks` (the key set behind `/auth/approvals/jwks.json`
  for the applications that check them — never the gate keys).
- **Your own routes and extension points:** `client_ip` (the real client address behind
  `trusted_proxies`), `json_body` (JSON body with the CSRF check for cookie clients), `browser_path`
  (links to TinySesam pages under a mount prefix), `flow_cookie_name`, `t` (translated text in
  `config.lang`), `set_rate_limiter`, `apply_idp_groups`, `version` and
  `tinysesam.current_version()`, `PAGES` (the page names `set_template` accepts),
  `MFA_ENROLLMENT_MODES`, `TinySesamConfig.validate()` (re-check after you changed a config object at
  runtime; writing `auth.cfg` itself is not promised), `TinySesamConfig.enabled_methods()`, `TinySesamConfig.pin_as_first_factor()`.
- **The top bar on your own pages:** `topbar_head` (tokens, bar CSS and the light/dark restore for `<head>`) and
  `topbar` (the bar with the account menu for this request's session); `topbar_data` (the same bar as data for an
  account, for an interface not drawn in Python) — see [Look & feel](#look--feel).
- **The security state on your own settings page:** `account_overview` (what the account page shows, as data; the
  same answer as `/auth/account.json`) — see [Two ways to use TinySesam](#two-ways-to-use-tinysesam).
- **The gate client for apps without FastAPI:** `tinysesam.gate_client` — every name in its own section,
  [Gate client for Flask, Django and other Python apps](#gate-client-for-flask-django-and-other-python-apps-t-86).
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
there is no setting and no environment variable for them. In the same process, closing a `sqlite3`
connection first waits for TinySesam's background notice jobs, which otherwise could still be using it.
A red suite is listed with how it ended (`exit 1`, `killed by signal SIGSEGV`); suites run unbuffered and
with faulthandler, so a crash leaves its output and the Python stack in the log.

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
`scripts/check.sh` is for. CI runs the full matrix (Python 3.13–3.15 with `[all]`), a minimal run
without extras (guards the stdlib-scrypt fallback), and a browser job that also builds the website.

## For AI coding assistants

Two entry points, so that an assistant finds its way without reading the whole README:

- **Building an app with TinySesam:** the skill
  [`skills/tinysesam/SKILL.md`](https://github.com/Ollornog/TinySesam/blob/main/skills/tinysesam/SKILL.md) —
  recipes (FastAPI with mandatory TOTP, step-up, admin-created accounts with a sign-in link, API keys, a gate in
  front of any app, OAuth for Claude Code, home network, C22 look), the switches and the pitfalls, with pointers into
  these docs. In Claude Code: `/plugin marketplace add Ollornog/TinySesam`, then `/plugin install tinysesam@tinysesam`
  (from Claude Code 2.1.275 in one step: `/plugin install tinysesam --marketplace Ollornog/TinySesam`). Other agents
  read the file directly; it uses the common `SKILL.md` format.
- **Working on TinySesam itself:** [`AGENTS.md`](https://github.com/Ollornog/TinySesam/blob/main/AGENTS.md) — layout,
  tests, generated files, backlog, security rules of the repository. `CLAUDE.md` imports it for Claude Code.

Every Python block in both files runs in the test suite, and every name they mention is checked against the code.

## Status

**148 test files, all green** — one per feature, plus a combination matrix (`tests/test_matrix.py`).

Implemented and tested: password/TOTP/sessions/roles, remember-me, step-up and per-route MFA,
factor chains, personal PIN, shared resource secrets, magic links + mailer hook, registration and
invitation, the account page, forgot-password and TOTP recovery codes, session management,
API keys and service accounts, the admin panel (or just its JSON API), forward-auth plus the
OIDC gateway, a nonce-based CSP, and the command line (`backup`, `restore`, `gc`, `audit`,
`unlock`, `diagnose`).

External identity providers — OIDC, SAML 2.0, LDAP/AD — and passkeys are implemented and tested
against a real provider on a staging host (`tests/e2e_stage.py`); the tests that ship with the
package cover them structurally, because they cannot dial out.

Two security audits went through the code in 2026-09 (see the `CHANGELOG`). The version is
deliberately **not** 1.0 yet: the tier-A surface ([Public API](#public-api-two-tiers)) has to
hold still for two minor releases first, counted from 0.22.0.

MIT license.

## Credits

Icon: <a href="https://www.flaticon.com/authors/maxicons" target="_blank" rel="noopener">Wizard PNG Image by max.icons - flaticon.com</a>
</content>
</invoke>

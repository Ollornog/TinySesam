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

TinySesam installs from its **git tag** — it is not on PyPI yet (see below):

```bash
pip install "tinysesam @ git+https://github.com/Ollornog/TinySesam.git@v0.18.0"
# core: password + TOTP. Everything: [all] — + argon2, QR, OIDC, passkey
pip install "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@v0.18.0"
# selective: [argon2] [qr] [oidc] [saml] [ldap] [passkey] [redis] [gateway]
```

Drop the `@v…` when you want a **commit** rather than a released version — that pulls the moving
default branch, so it belongs in an experiment, not in a deployment.

> **Not on PyPI yet.** `pip install tinysesam` does **not** work: the name is not registered there.
> The packaging is ready (metadata, trusted publishing, a packaging test) and publishing happens
> with **1.0** — until then the pinned git tag above is the way. This page said otherwise until
> 2026-09-21, which made the very first command anyone tried fail with
> `No matching distribution found for tinysesam`.

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
**unique** (partial UNIQUE index; accounts without an email stay allowed). Registration requires it
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

## Roles & groups

**Roles are the groups** — a list per user (`roles`) + `is_admin`; guard `require_role("…")`.
Name several and **one of them is enough** — `require_role("editorial", "proofing")`, or from a list
of your own (`require_role(*ROLES_ALLOWED)`). That is the same OR as `?roles=a,b` in forward-auth, so the question
“who may pass?” means the same thing in both modes. Need **all** of them? Stack the guards:
`@app.get(…, dependencies=[Depends(auth.require_role("a")), Depends(auth.require_role("b"))])`.
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
interactive factor, so it cannot take one away either.

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

## Language (i18n)

The built-in texts are **English by default** (`lang="en"`); **German** ships too:

```python
TinySesamConfig(lang="de")                       # built-in pages + messages in German
auth.add_messages("fr", {"login.submit": "Se connecter", ...})   # your own language/override
```
Individual texts or whole pages can additionally be freely replaced via `auth.set_template(...)`.

## Your own login page

Use TinySesam as a pure backend (your own UI) — the building blocks are public:

```python
user = auth.check_password(username, password)
token, done = auth.start_session(user["id"], "password")   # tuple, not just a token
auth.set_cookie(resp, token)
if not done:                      # a second factor is still missing
    ...                           # auth.verify_totp(user["id"], code) → auth.complete_totp(token)
```

`start_session` returns `(token, session_ok)`. Unpack it — passing the tuple straight into
`set_cookie` writes the string `"('abc…', True)"` into the cookie, and nothing raises: the sign-in
is quietly broken. `session_ok=False` means the session exists but is not complete yet.

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
  signed in only gets the missing field, not the whole login page again.

## Bootstrapping the first admin

Open registration plus “the first account becomes admin” is a race: whoever finds the fresh instance
first wins it. TinySesam therefore offers two explicit paths, **both only while no admin exists**:

```python
TinySesamConfig(admin_identifiers=["me@example.com"])   # allowlist, any sign-in method
```

- **Allowlist** — the named username or email is promoted on its next successful sign-in, whatever the
  method. An **address** only counts with proof that it belongs to whoever is signing in; SAML and
  LDAP offer no such proof, so it never promotes there (see below). After that: never again.
- **One-time token** — if no admin exists, TinySesam prints a claim URL to **stderr** on startup
  (the operator's console). Sign in, open `/auth/claim-admin?token=…`, and that account becomes
  admin. The token is single-use and expires after `admin_claim_ttl_min`; once an admin exists the
  route answers 404. The value is deliberately kept out of the security log — that file is what
  fail2ban reads and logrotate keeps. Where stderr itself is collected (journal, container logs),
  set `admin_claim_token_file` and TinySesam writes the token to that file with mode `0600`.
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
and in many directories the `mail` entry is maintained by the user themselves. Over those two
paths an allowlist address therefore **never** becomes the first admin — not even for an existing
account that already carries it. The configuration check says so at construction time, and the
refused attempt is logged to the security log and the audit trail
(`admin_bootstrap_denied`). There the path with proof is the **one-time token**; to keep driving
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
auth.set_password(auth.store.get_user_by_name("admin")["id"], "new-password")
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
> its own, with the same tight permissions as the source. From Python: `auth.store.backup(path)`.

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

> **Rolling back to ≤ 0.17.x needs a backup in the old schema.** 0.18.0 migrates the database on
> first start. Older code then opens the file without complaining, `/healthz` stays green and
> accounts are readable — but every session operation raises. Take a backup *before* the update
> (`tinysesam backup` leaves the source untouched) and restore that one.

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
  Rendering your own templates? `token = auth.issue_csrf(response)` sets the cookie and returns the value.
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
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.18.0
```

The same line installs the same code tomorrow, and updating means: bump the line, reinstall,
restart the service. Python does not reload code at runtime.

Note that a **tag can be moved**. For real immutability pin the commit instead (`@a1b2c3d…`) —
that one cannot be rewritten. Once TinySesam is on PyPI (with 1.0), `tinysesam[oidc]==1.0.0`
becomes the shorter way to the same guarantee: a released version there never changes at all.

Every release also attaches a **wheel** and an **sdist**, with `SHA256SUMS`. To install without
git and without an index, take the file directly:

```
pip install https://github.com/Ollornog/TinySesam/releases/download/v0.18.0/tinysesam-0.18.0-py3-none-any.whl
```

### As a gateway (its own container)

Every release builds an image for `linux/amd64` and `linux/arm64`:

```
ghcr.io/ollornog/tinysesam:v0.18.0
```

It runs as **non-root** (uid 1000), contains neither `pip` nor `git`, ships a `HEALTHCHECK` on
`/healthz` and starts the gateway directly — no `command:` needed.

**Check where it came from.** A digest proves an artifact hasn't changed since it was built — not
who built it. Every release therefore carries a Sigstore-signed provenance attestation and an SBOM,
both also stored next to the image in the registry:

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.18.0 --owner Ollornog
gh attestation verify tinysesam-0.18.0-py3-none-any.whl --owner Ollornog   # wheel and sdist too
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.18.0 --owner Ollornog \
    --predicate-type https://spdx.dev/Document                             # the SBOM
```

A pass means: built by this repository's release workflow, from the commit the attestation names.
No key to hand out and none to lose — the signature is tied to the workflow's own identity. A full example with Caddy
lives in `deploy/forward-auth/docker-compose.yml`.

Update: bump the tag, `docker compose pull && docker compose up -d`. Rollback: put the old tag
back. **There is deliberately no `latest`** — a moving tag turns every restart into a gamble.
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
    revalidate_minutes=15,
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
TINYSESAM_OIDC_REVALIDATE_MINUTES=15
```

A config with a single client behaves exactly as before — no host mapping, no release to expire.

## API keys & service/daemon accounts

For **machine access** (scripts, other services, system daemons) — alongside the interactive login:

- An API key belongs to a user, sits **hashed** (sha256) in the DB, optionally with an **expiry** and **role scope**.
- Sent as `Authorization: Bearer tsk_…` **or** `X-API-Key: tsk_…`.
- **`require_user` accepts a session OR a valid key** — protected routes are reachable by key without any change; `require_role(...)` honors the key scope.
- **System daemons** = **service account** (`auth.create_service("backup-daemon", roles=["reader"])`, no login/MFA) + key (`auth.create_api_key(uid, name=…, expires_days=…)` → plaintext **once**). Least privilege via the roles.
- **Disable instead of delete:** `auth.revoke_api_key(id)` (key disabled, stays in the list). Self-service routes: `GET/POST /auth/apikeys`, `POST /auth/apikeys/{id}/revoke`.
- **A key is a second front door, so locking an account out takes it along.** An admin password
  reset and disabling an account revoke that user's keys; so does the user's own "end **all**
  sessions" (`scope=all`). A user's own password change deliberately does **not** — a routine
  change shouldn't silently kill their integrations — but the response and the audit entry say
  how many keys are still live (`api_keys_active`). Keys of a disabled account never
  authenticated in the first place.

## Admin panel

Built-in panel at **`/auth/admin`** (`is_admin` only), embeddable with no extra setup:

- **Users & service accounts:** create, **explicitly disable/enable** (`disabled` — account stays, login blocked, sessions end immediately; self-lockout protection), password reset, set roles/admin.
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
  `require(factors=[...], strict=...)`. Factors: `password, pin, oidc, passkey, totp, magic`.
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
  exactly once. The built-in pages do *not* carry it: their form targets and links are
  root-absolute (`/auth/register`, `/auth/forgot`, …), so behind a proxy that strips `/sso` the
  sign-in itself ends up in a 404 while the mails work. See
  [T-15](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-15-unterpfad-montage.md). The same one rule holds for the methods
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
  Authelia set). Give it a mapping to rename or drop them: `{"user": "X-WEBAUTH-USER"}` sends that one
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
    ldap_enabled=True, ldap_url="ldap://lldap:3890",
    ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com",   # direct bind (lldap)
    # OR search-then-bind: ldap_bind_dn=…, ldap_bind_password=…, ldap_user_base=…, ldap_user_filter="(uid={username})"
    ldap_allowed_groups=["staff"],   # optional gate (memberOf), empty = all
    ldap_auto_create=True,           # create an unknown LDAP user locally
)
```
Local passwords and LDAP coexist (local first, then LDAP). Roles/2FA/chains apply as usual.

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

## Tests & CI

```bash
pip install -e '.[all]' setuptools         # + httpx for the FastAPI TestClient (included in [all])
python tests/run_all.py                    # every suite; exit 0 = green, 1 = failure
python tests/run_all.py core pin chain     # only some
```

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

**46 test files, all green** — one per feature, plus a combination matrix (`tests/test_matrix.py`).

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
deliberately **not** 1.0 yet: the API surface has to hold still for two minor releases first.

MIT license.

## Credits

Icon: <a href="https://www.flaticon.com/authors/maxicons" target="_blank" rel="noopener">Wizard PNG Image by max.icons - flaticon.com</a>
</content>
</invoke>

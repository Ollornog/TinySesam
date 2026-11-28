# Example Ex4: a single-page application behind the TinySesam server, surface "headless"

A Node application (`clients/js/examples/ex4`) behind the TinySesam server that **draws everything itself** — its
navigation, its documents and its own settings page. The settings page is a single-page app in the browser
(`examples/ex4/app.js`): it reads the account's state from `/.tinysesam/account.json` on the application's own host and
**writes nothing**. Every change — password, authenticator app, API keys, connected programs, ending a session — is a
link to one of TinySesam's **action pages** (`/auth/act/<name>`, T-105), which stands in the application's frame and
leads back with the result. No password, code or key ever passes through the application. The server is configured by
one file, `tinysesam.toml` (`TINYSESAM_CONFIG`, T-97).

| Service | What |
|---|---|
| `tinysesam` | the server, built from this checkout |
| `caddy` | the proxy with forward auth, built from `deploy/forward-auth/caddy-gate`, using `deploy/quickstart/Caddyfile` |
| `app` | the Node program: the identity from the `Remote-*` headers (header mode), the settings page as static script |

## Run it

1. Edit `tinysesam.toml`: the host names (`base_url`, `trusted_redirect_hosts`, `[forward_apps."…"]`,
   `apps.docs.hosts`, `oauth_resources`). Put into `.env` next to the compose file: `TS_AUTH_HOST=auth.example.com`,
   `TS_APP_HOST=app.example.com` (`TS_TLS=internal` is the default here: Caddy's own CA, for a test; `acme` for real
   names).
2. `docker compose up --build -d`, then claim the first administrator with the one-time token the server wrote:
   `docker compose exec tinysesam cat /data/ex4.db.claim` and open `https://<auth host>/auth/claim-admin`.
3. In the panel: create accounts with the role `docs-reader` and give that role `docs.read` (*Accounts → Permissions*);
   a team lead who administers them inside the application gets the role `docs-admin`.
4. Open `https://<app host>/settings`: TinySesam asks you to sign in, then the application shows your settings. Every
   *Change*, *Manage* or *End* opens TinySesam's action page in the application's frame; *Back to Documents* (or
   *Done — back to Documents*) returns to the settings, which say what happened and read the state again.

## With an identity provider (optional)

`tinysesam.toml` carries an OpenID Connect provider block, switched off (T-162): with it, the people of your provider
sign in beside the local accounts on the same sign-in page (mixed accounts), and the provider's group `docs` becomes
the role `docs-reader` at every sign-in — and goes at the next one when the provider withdraws the group.

1. At the provider: a confidential client (code flow) with the redirect URI `https://<auth host>/auth/oidc/callback`,
   sending the `groups` claim (for a scope `groups`), and a group `docs` (or change the key of `oidc_group_role_map`
   to the name your provider uses).
2. In `tinysesam.toml`: remove the `#` in front of each `oidc_` line and set `oidc_issuer` and `oidc_client_id` to
   your provider's. The secret never stands in the file (`oidc_client_secret = "env:EX4_OIDC_CLIENT_SECRET"`).
3. In `docker-compose.yml`: remove the `#` in front of `EX4_OIDC_CLIENT_SECRET` (service `tinysesam`), and put the
   secret into `.env`: `EX4_OIDC_CLIENT_SECRET=…`. Without it the server does not start.
4. `docker compose up -d tinysesam`: the sign-in page offers the provider's button beside the password. Once
   `docs-reader` holds `docs.read` (*Run it*, step 3), the provider's people get the application under the same
   rules as local readers.

## What it shows

- **Headless** (T-105): the application never shows a TinySesam page of its own accord and holds no secret. It reads
  `account.json` in the browser — same-origin through the proxy, never server-side with the person's cookie — and
  builds every link from its member `actions` (and `sessions.items[].end`), adding `return` (its settings page) and
  `state` (a value it issued and checks when the person comes back).
- **The way back**: `ts_action`, `ts_result` (`done`, `cancelled`, `unavailable`) and `state` in the query. The page
  shows a message only for a `state` it issued and reads `account.json` again — the result is a hint, not a proof.
- **Ending one session**: every other session of the account has an *End* link to the action page `session_end` with
  that session's handle; the page asks for confirmation (and, when the last one is too old, for a fresh sign-in
  confirmation first).
- **Every own action** (T-149): user name, address (offered once a mailer is configured, `smtp_host`), password, PIN,
  authenticator app with recovery codes, passkeys, API keys, app passwords for this host, services (pairing code),
  sessions and connected programs — each on its action page and back. `tests/test_headless_browser.py` drives every one.
- **Administration** (T-147, T-106): a person who administers accounts inside the application's area — an
  administrator, or a holder of the delegate role `docs-admin` (`[admin_delegates.docs-admin]`: the accounts with
  `docs-reader`, area `docs`) — sees an *Administration* section. `account.json` names TinySesam's administration data
  for exactly these people (`admin.accounts`); the page reads `/.tinysesam/admin/accounts.json` in the browser, like
  `account.json`, and draws every account with the links TinySesam offers for it: lock, unlock, roles, reset the
  authenticator app, revoke a key, disconnect a program, end a session, a sign-in link (a delegate gets lock, unlock,
  roles and the sign-in link). The application keeps no list of accounts and serves no data of its own. TinySesam
  names the account, asks for the administrator's password (or code) for that one action, and decides who may act;
  the sign-in link is shown on its page only. Give an administrator nothing more, a delegate the role `docs-admin`.
- **Own events and keys** (T-106): the settings page lists the account's recent events ("was that me?") and its API
  keys by name, from `account.json`.
- The pages carry a strict CSP with a fresh nonce (`connect-src 'self'`, `form-action 'none'`: the application posts no
  form at all) and colour themselves only with TinySesam's `--ts-*` tokens (`/.tinysesam/shell.css`).

`tests/test_headless_browser.py` runs the whole stack — this configuration, the Node program and a forward-auth proxy
doing what the Caddy template does — in Chrome at 375 and 1280 px, light and dark. Its cell X9 switches the provider block on (a real
provider on a loopback port, `tests/_test_idp.py`); `tests/test_server_config.py` builds the server from the
switched-on block.

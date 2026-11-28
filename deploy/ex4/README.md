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
3. In the panel: create accounts with the role `docs-reader` and give that role `docs.read` (*Accounts → Permissions*).
4. Open `https://<app host>/settings`: TinySesam asks you to sign in, then the application shows your settings. Every
   *Change*, *Manage* or *End* opens TinySesam's action page in the application's frame; *Back to Documents* (or
   *Done — back to Documents*) returns to the settings, which say what happened and read the state again.

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
- **Administration** (T-147): a holder of the application's permission `docs.admin` (role `docs-admin`) sees an
  *Administration* section — the accounts the application has seen through forward auth (its own list, served by
  `/admin/accounts.json`), each with links to TinySesam's administration action pages: lock, unlock, roles, reset the
  authenticator app, revoke a key, disconnect a program, end a session, a sign-in link. TinySesam names the account,
  asks for the administrator's password (or code) for that one action, and decides who may act; the sign-in link is
  shown on its page only. Give the role `docs-admin` the permission `docs.admin` and an administrator the role.
- The pages carry a strict CSP with a fresh nonce (`connect-src 'self'`, `form-action 'none'`: the application posts no
  form at all) and colour themselves only with TinySesam's `--ts-*` tokens (`/.tinysesam/shell.css`).

`tests/test_headless_browser.py` runs the whole stack — this configuration, the Node program and a forward-auth proxy
doing what the Caddy template does — in Chrome at 375 and 1280 px, light and dark.

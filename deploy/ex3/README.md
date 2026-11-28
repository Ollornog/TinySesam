# Example Ex3: a Node application behind the TinySesam server, surface "hybrid"

A Node application (`clients/js/examples/ex3`) behind the TinySesam server with **mixed accounts**: the people of an
OIDC identity provider (their `team-*` groups become roles, T-102) and local accounts of TinySesam, on the same
sign-in page. The application draws its **own navigation** — *Documents*, *About* and one link *Account* — and leaves
everything of the account to **TinySesam's area** (`/auth/area?app=docs`, T-104), framed with the application's name,
icon and links, with a way back. No line of Python in the application. The server is configured by one file,
`tinysesam.toml` (`TINYSESAM_CONFIG`, T-97).

| Service | What |
|---|---|
| `tinysesam` | the server, built from this checkout |
| `caddy` | the proxy with forward auth, built from `deploy/forward-auth/caddy-gate`, using `deploy/quickstart/Caddyfile` |
| `app` | the Node program: the identity and `Remote-Permissions` from the `Remote-*` headers (header mode) |

## Run it

1. Edit `tinysesam.toml`: the host names (`base_url`, `trusted_redirect_hosts`, `[forward_apps."…"]`,
   `apps.docs.hosts`) and the provider (`oidc_issuer`, `oidc_client_id`; the provider allows the redirect URI
   `https://<auth host>/auth/oidc/callback` and sends the `groups` claim). Put into `.env` next to the compose file:
   `TS_AUTH_HOST=auth.example.com`, `TS_APP_HOST=app.example.com`, `EX3_OIDC_CLIENT_SECRET=…` (`TS_TLS=internal` is
   the default here: Caddy's own CA, for a test; `acme` for real names).
2. `docker compose up --build -d`, then claim the first administrator with the one-time token the server wrote:
   `docker compose exec tinysesam cat /data/ex3.db.claim` and open `https://<auth host>/auth/claim-admin`.
3. In the panel (*Accounts → Permissions*): give `docs.read` to the role `team-docs` (it appears once a person of that
   group has signed in) and to the local role `docs-local`; create local accounts with `docs-local` as you like.
4. Open `https://<app host>/`: TinySesam asks you to sign in (*Sign in to Documents* with the application's icon), the
   application lists the documents for a holder of `docs.read`. *Account* opens the area.

## What it shows

- **Hybrid** (T-104): the application's own navigation, one link *Account* to `https://<auth host>/auth/area?app=docs`.
  The area shows the tiles of the own account — account, security, sessions, the panel for an administrator — in the
  frame of `[forward_apps."app.example.com"]` with the icon of `apps.docs.icon` (ADR-19) and "Back to Documents". Every
  tile opens TinySesam's account page in the same frame. The area lives on TinySesam's origin, never on the
  application's.
- **Mixed accounts and IdP role sync** (T-102): a group the provider sends becomes a role at sign-in and goes at the
  next sign-in or at the session's re-check against the provider (`oidc_session_refresh_minutes`); a local account holds
  the local role `docs-local`. Both read through the same permission `docs.read`.
- **The identity** comes from the `Remote-*` headers, accepted only from the compose network (`TS_TRUSTED_PROXY`), and
  checked by the JS gate client (spec section 2.1); the documents need `Remote-Permissions` to name `docs.read`.
- The pages carry a strict CSP with a fresh nonce and colour themselves only with TinySesam's `--ts-*` tokens
  (`/.tinysesam/shell.css`).

`tests/test_example_ex3.py` builds the server from this `tinysesam.toml` and runs the role sync story with a stubbed
provider; `tests/test_hybrid_browser.py` runs the whole stack — this configuration, the Node program and a forward-auth
proxy doing what the Caddy template does — in Chrome at 375 and 1280 px, light and dark.

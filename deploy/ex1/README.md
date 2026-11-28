# Example Ex1: a Go application behind the TinySesam server

A Go application (`clients/go/examples/ex1`) behind the TinySesam server with **local accounts**: TinySesam signs the
people in, its admin panel and account page manage them, and the application creates its own members through the
**account API** — without a line of Python in the application. The server is configured by one file,
`tinysesam.toml` (`TINYSESAM_CONFIG`, T-97).

| Service | What |
|---|---|
| `tinysesam` | the server, built from this checkout (the configuration file arrives with the release after 0.31.0) |
| `caddy` | the proxy with forward auth, built from `deploy/forward-auth/caddy-gate`, using `deploy/quickstart/Caddyfile` |
| `app` | the Go program: the identity from the `Remote-*` headers (header mode), the account API with a service key |

## Run it

1. Edit `tinysesam.toml`: the two host names (`base_url`, `trusted_redirect_hosts`, `[forward_apps."…"]`). Put the same
   names into `.env` next to the compose file: `TS_AUTH_HOST=auth.example.com`, `TS_APP_HOST=app.example.com`
   (`TS_TLS=internal` is the default here: Caddy's own CA, for a test; `acme` for real names).
2. `docker compose up --build -d`, then claim the first administrator with the one-time token the server wrote:
   `docker compose exec tinysesam cat /data/ex1.db.claim` and open `https://<auth host>/auth/claim-admin`.
3. In the panel: create the service account `svc-ex1` (a service account), issue it an **automation** API key, and
   give your own account the role `ex1-staff`. Put the key into `.env` as `TS_API_KEY=tsk_…` and run
   `docker compose up -d app`.
4. Open `https://<app host>/`: TinySesam asks you to sign in, the application greets you by name. `/members` lists the
   people the application created and invites a new one — the answer holds the one-time sign-in link to hand over.

## With an identity provider (optional)

`tinysesam.toml` carries an OpenID Connect provider block, switched off (T-162): with it, the people of your provider
sign in beside the local accounts on the same sign-in page (mixed accounts), and the provider's group `staff` becomes
the role `ex1-staff` at every sign-in — and goes at the next one when the provider withdraws the group.

1. At the provider: a confidential client (code flow) with the redirect URI `https://<auth host>/auth/oidc/callback`,
   sending the `groups` claim (for a scope `groups`), and a group `staff` (or change the key of `oidc_group_role_map`
   to the name your provider uses).
2. In `tinysesam.toml`: remove the `#` in front of each `oidc_` line and set `oidc_issuer` and `oidc_client_id` to
   your provider's. The secret never stands in the file (`oidc_client_secret = "env:EX1_OIDC_CLIENT_SECRET"`).
3. In `docker-compose.yml`: remove the `#` in front of `EX1_OIDC_CLIENT_SECRET` (service `tinysesam`), and put the
   secret into `.env`: `EX1_OIDC_CLIENT_SECRET=…`. Without it the server does not start.
4. `docker compose up -d tinysesam`: the sign-in page offers the provider's button beside the password. The
   application sees the provider's people like local ones: the role `ex1-staff` opens *Staff*, and the permissions
   an administrator assigns to it apply to them too.

## What it shows

- **Sign-in, panel, account page** are TinySesam's own pages; the application has no sign-in code.
- **The identity** comes from the `Remote-*` headers, accepted only from the compose network (`TS_TRUSTED_PROXY`), and
  checked by the Go gate client (spec section 2.1).
- **The account API** (`spec/provisioning-api.md`): `GET /auth/api/users`, `POST /auth/api/users` with
  `TinySesam-On-Behalf-Of` — the person who clicked "Invite". The application can only create people with the role of
  its allowlist (`ex1-member`) and never touches an account it did not create.
- **Shell on top** (T-103, surface "shell on top"): every page of the Go program loads TinySesam's shell component from
  its own host (`<script src="/.tinysesam/shell.js" nonce=…>`, the proxy passes `/.tinysesam/*` to TinySesam) and puts
  `<ts-shell layout="top" current="/…">` first in `<body>`. The bar carries the application's frame from
  `[forward_apps."…"]` (‹ Ex1 back home, *Members* for holders of `ex1.members.read`, *Staff* for the role
  `ex1-staff`); the element names its layout itself (the same as `apps.ex1.layout`, T-144: without the attribute the
  layout arrives with the data and a side layout shifts the page once); the account menu leads to TinySesam's account page in Ex1's frame. The pages carry a strict CSP
  with a fresh nonce (images also from TinySesam's origin, for a `brand_icon` given as a path, B-21) and colour
  themselves only with TinySesam's `--ts-*` tokens.

`tests/test_example_ex1.py` builds the server from this `tinysesam.toml` and makes the calls of the Go program; the
client-go workflow builds and vets the program. `tests/test_shell_browser.py` (part B) runs the whole stack — this
configuration, the Go program and a forward-auth proxy doing what the Caddy template does — in Chrome at 375 and
1280 px, light and dark. Its cell B5 switches the provider block on (a real provider on a loopback port,
`tests/_test_idp.py`); `tests/test_server_config.py` builds the server from the switched-on block.

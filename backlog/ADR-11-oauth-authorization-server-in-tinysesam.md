---
id: ADR-11
type: Decision
title: OAuth 2.1 authorization server for MCP clients — built into TinySesam with own thin handlers, not Ory Hydra as a sidecar
status: erledigt
tags: [architecture, oauth, mcp, forward-auth, tokens]
created: 2026-11-20
---

# ADR-11 — OAuth 2.1 authorization server: in TinySesam, own thin handlers

## Context

MCP clients (Claude Code first, own CLIs later) must reach applications that sit behind TinySesam. The MCP
authorization spec (2026-07-28) requires an OAuth 2.1 authorization server (AS): RFC 9728 metadata at the resource,
RFC 8414 discovery, PKCE S256, RFC 8707 `resource` with an audience check, client registration (pre-registered,
CIMD or — deprecated, but what an offline client uses — DCR), and refresh-token rotation for public clients
(RFC 9700 §2.2.2). The applications themselves must not contain OAuth code: forward auth (`/auth/forward`,
[ADR-5](ADR-5-roles-in-forward-auth.md)) stays the single check and additionally accepts an access token.

## What a spike measured (2026-11-20)

Two engines against the **real Claude Code CLI 2.1.329** (`claude mcp add/login/logout/get`, plus a local model
stand-in so that the CLI itself executes `tools/call`):

| | H — Ory Hydra v26.2.0 sidecar | L — AS inside TinySesam |
|---|---|---|
| Discovery 9728 → 8414, DCR, sign-in (password + TOTP), consent, token, tools | only with a TinySesam DCR facade: Hydra's registration answer (`contacts: null`, `client_uri: ""`) is rejected by the MCP TypeScript SDK (ory/hydra#4116 → #4044, open) | works out of the box |
| Loopback redirect | Claude Code registers `http://localhost:<random>/callback` and re-registers on a port collision. Hydra (fosite) frees the port only for IP literals (#4127 "not planned") | any port for a loopback host (RFC 8252 §7.3) |
| Rotation, reuse → family revoked | built in | own code, measured identical; 4 parallel CLI processes: no false reuse |
| Logout / RFC 7009 | public clients accepted | the MCP SDK 2.3 revoke handler demands `client_secret` → own route |
| Account locked | Hydra keeps refreshing unless TinySesam calls its admin API | immediate (same database) |
| RFC 8707 `resource` | ignored — the consent app has to map it to the audience | native |
| RFC 9207 `iss` | not sent | sent |
| Forward-auth check | introspection over the admin API, p50 1.07 ms | database lookup, p50 0.41 ms |
| Device list | consent sessions, also revoked ones | token families, exact |
| CIMD | open-source edition: no | not needed offline |

## Options

1. **H — Hydra sidecar.** Certified protocol core. But TinySesam would still own registration (facade), audience
   mapping, the account-state revocation, the device list and the CSP entry for the AS host — and operators would
   run, upgrade, migrate and back up a second service with its own database and secrets.
2. **L — in TinySesam on the MCP Python SDK's `mcp.server.auth` routes.** One process. But a large dependency with
   eight advisories in 2026, and two of its gaps (revoke for public clients, `none` missing from the advertised
   auth methods) need own routes anyway.
3. **L' — in TinySesam with own thin handlers**, no protocol framework: the five endpoints are small, the rules are
   what matters.

## Decision

**Option 3** (PO 2026-11-20: "Bau L freigegeben", own slim handlers). One process, one database
([ADR-3](ADR-3-in-app-instead-of-proxy.md)), no new dependency. `oauth_enabled` is off by default.

### Rules taken over, with their source

- **Token format** (GitHub): prefix `tsat_`/`tsrt_`/`tsac_` + 256 random bits (node-oidc-provider, fosite) in Base62
  + CRC32 — secret scanners recognise it, a typo is rejected before the database (not a security property).
- **Storage** (fosite-like): only HMAC-SHA-256 with a pepper from the environment or a file; without one the pepper is
  a subkey of the master key (like the gate key, [ADR-9](ADR-9-gate-token-at-the-proxy.md)), and `config_check`
  says so. PKCE compared with `compare_digest`. Never a token in a URL or a log (MCP).
- **Code** (node-oidc-provider; RFC 6749 §4.1.2, RFC 9700 §4.2.4, ASVS V10.4.2): 60 s, consumed atomically
  (`UPDATE … WHERE consumed_at IS NULL`), reuse checked before every other field and revoking the grant it produced;
  bound to client, redirect URI, challenge, resource, scope and account.
- **PKCE** (RFC 9700 §2.1.1): S256 only, `plain`/missing → `invalid_request`; downgrade in both directions refused;
  verifier 43–128 characters; a failed exchange consumes the code.
- **Redirect** (RFC 9700 §4.1.3, ASVS V10.4.1, RFC 8252 §7.3): exact comparison, only a loopback port free; no
  fragment, user info or wildcard; registration accepts only loopback `http` (no `javascript:`/`data:`, no https in
  this PR); an error never goes to an unknown client or unregistered redirect URI (RFC 6749 §4.1.2.1); `iss` always
  (RFC 9207).
- **Refresh** (MCP, RFC 9700 §4.14, ASVS V10.4.5; Auth0, node-oidc-provider): rotation on every use, grant model
  (`oauth_grant` + `oauth_token.grant_id`), reuse → the whole grant revoked + `invalid_grant` + audit + security
  event; optional grace window for the immediate predecessor only, returning the **same** successor (Auth0/Okta
  pattern; stored encrypted with the vault only while it lasts), default 0 s because Claude Code serialises its
  refreshes (measured); the rotation is one transaction; a refresh may only narrow the scope; the previous access
  token is revoked.
- **Expiry** (RFC 9700: inactivity SHOULD; ASVS V10.4.8 L2: absolute maximum): sliding 90 days without use **and** an
  absolute maximum of 180 days, both configurable (PO 2026-11-20). `oauth_refresh_max_days=0` switches the maximum
  off on purpose; `config_check` then names ASVS V10.4.8.
- **DCR** (RFC 7591 §5, ASVS V10.4.7): `token_endpoint_auth_method=none` only, grant and response types limited,
  lengths and counts capped, `logo_uri`/`client_uri`/… ignored (nothing is fetched — no SSRF), a rate limit per
  address, a cap on registrations without a grant, unused ones removed by `gc()`; the consent shows the name as
  "not verified". The answer contains no `null` or empty field (Claude Code's schema rejects them — measured with
  Hydra).
- **Consent** (ASVS V10.7.1–3): always for these clients; names program, redirect host (with a warning what
  `localhost` means), resource, scope and duration; the request is a server-side transaction bound to the browser
  that started it (flow cookie), the form confirms only its ID; CSRF token, `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`; `state` returned unchanged; `next` only relative. Account page and admin panel list and
  revoke grants (V10.4.9).
- **Resource** (RFC 8707): a fixed list `oauth_resources`, `aud` = resource, unknown → `invalid_target`; a token is
  valid only for its resource URL and below, never for a path with dot segments or encoded separators.
- **Account state**: every request and every refresh reads the account; locking revokes all grants; a token never
  carries the admin flag (as an automation key, R6-5); tokens are issued only after an interactive session, never
  for an API key.

### Deliberate deviations

- **`localhost` as a loopback redirect host** although RFC 8252 §8.3 recommends the IP literal: Claude Code registers
  `http://localhost:<port>/callback` (the 2.1.229 → 2.1.231 back-and-forth between `127.0.0.1` and `localhost` is
  documented upstream). Only `http`, only with PKCE, only for public clients, the host is shown on the consent page.
- **Revocation answers 200 also for a token of another client** (RFC 7009 §2.1 says "refused"): for public clients
  there is no client authentication that the refusal could protect, and a uniform answer reveals nothing about
  foreign tokens. The foreign token is not touched.
- **`resource` is required** at the authorization request (RFC 8707 makes it optional): there is no default audience
  that would be right for every installation, and MCP clients send it.
- **No CIMD** (MCP SHOULD): the AS would have to fetch the client's metadata from the internet — not possible in an
  offline home network. DCR (deprecated in MCP 2026-07-28) remains, because Claude Code uses it offline.
- **On `on_security_event`** come the events a person wants to hear about — a program connected, disconnected, a
  copied token detected; every refresh only goes to the audit log (hourly per device would be noise).

## Consequences

- No second service, no second database, no admin API to protect; latency of the check stays a local lookup.
- We own security-relevant code. It is pinned by a negative test per rule (`tests/test_oauth.py`), each proven by a
  mutation, a browser test of the consent page and the device list, and a manual end-to-end check with the real
  Claude Code CLI behind Caddy built from the repo template (`tools/oauth-e2e/e2e.py`).
- Registrations accumulate (every logout or port collision registers anew) → `gc()` and `tinysesam gc`.
- The connectors of Claude Desktop and Claude on the web cannot reach a LAN-only server (Anthropic's network); Claude Code can.
- Services without a person (`client_credentials` + `private_key_jwt`, pairing from T-32) follow in
  [T-59](T-59-oauth-for-services-client-credentials-private-key-jwt.md). Revisit H if certification, CIMD with
  internet access or a multi-tenant AS become requirements.

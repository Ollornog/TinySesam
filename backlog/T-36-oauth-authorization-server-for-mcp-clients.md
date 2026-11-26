---
id: T-36
type: Task
title: OAuth 2.1 authorization server for MCP clients (Claude Code) — human-operated tools
status: erledigt
milestone: M-5
tags: [oauth, mcp, forward-auth, tokens, claude-code]
created: 2026-11-20
---

# T-36 — OAuth 2.1 authorization server for MCP clients

Wish (PO 2026-11-20): Claude Code (and other tools a person runs on their own computer) reach applications behind
TinySesam as MCP clients, signing in with TinySesam's own sign-in — without the application containing OAuth code.
Decision: [ADR-11](ADR-11-oauth-authorization-server-in-tinysesam.md) (own thin handlers in TinySesam, not Hydra).

Done when: discovery, registration, authorization with consent, token, refresh rotation with reuse detection,
revocation and the resource side in forward auth work; the device list exists on the account page and in the panel;
every rule of ADR-11 is pinned by a negative test and proven by a mutation; the PO's acceptance list passes with the
real Claude Code CLI; README (de+en), CHANGELOG, CONFIGURATION.md, SECURITY.md and docs/OPERATIONS.md updated.

## Done (2026-11-20)

- `tinysesam/oauth.py` (rules, endpoints), tables in `tinysesam/store.py` (schema 17, additive), the bearer path and
  the RFC 9728 challenge in `/auth/forward`, consent page and device list (`templates.py`), panel tab (`admin.py`),
  `config_check` (forward auth, `base_url`, resources, CSRF required; warnings for no own pepper and for
  `oauth_refresh_max_days=0`), `gc()` and `tinysesam gc`.
- Proxy: `deploy/forward-auth/Caddyfile` and `Caddyfile.gate` route `/.well-known/oauth-protected-resource*` to
  TinySesam and pass the OAuth 401 through.
- Tests: `tests/test_oauth.py` (flow + every negative test), `tests/test_browser.py` (`oauth_consent`: consent at
  390/1280 px under the strict CSP, the POST reaching the loopback callback, device list, disconnect).
- End to end: `tools/oauth-e2e/e2e.py` with Claude Code 2.1.329, Caddy 2.11.8 from the repo template and headless
  Chrome — sign-in with password + TOTP, silent refresh after a restart, disconnect on the account page, refresh
  token reuse, account lock, `claude mcp logout`: all six green.

Follow-up: [T-60](T-60-oauth-for-services-client-credentials-private-key-jwt.md) (services). Not built here: device
flow (RFC 8628), CIMD, DPoP, https redirect URIs for hosted clients.

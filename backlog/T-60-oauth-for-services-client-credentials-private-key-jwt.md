---
id: T-60
type: Task
title: OAuth for services — client_credentials + private_key_jwt, pairing from T-32
status: offen
milestone: M-2
blocked_by: [T-36]
tags: [oauth, m2m, api-keys, pairing]
created: 2026-11-20
---

# T-60 — OAuth for services (client_credentials + private_key_jwt)

Second client kind of the connection concept (after [T-36](T-36-oauth-authorization-server-for-mcp-clients.md),
decision [ADR-11](ADR-11-oauth-authorization-server-in-tinysesam.md)): a service or daemon without a person gets
short-lived access tokens from the same authorization server.

- `grant_type=client_credentials` with client authentication `private_key_jwt` (RFC 7523). The service creates its
  key pair itself; only the public key lies at TinySesam.
- Registration by a **pairing code** from [T-32](T-32-api-key-pairing-negotiate-a-key-on-first-contact-o.md)
  (issued on the account page or in the panel, single use, short-lived, audited) instead of copying a secret. The
  RFC 9421 per-request signature from the T-32 draft is replaced by `private_key_jwt` + a short-lived token (same
  check as for human-operated tools, no own replay or proxy normalisation).
- Roles and scope like service accounts today; the token carries the service account, never an admin flag.
- A reference client (`tinysesam.client` + CLI): pairing, fetching and renewing tokens, key rotation — so that nobody
  builds it themselves.
- Optional: DPoP (RFC 9449) for own clients.

Done when: an ADR amends ADR-11 for this client kind; pairing, token, key rotation and revocation work and are pinned
by negative tests with mutations; README recipe, CHANGELOG, CONFIGURATION.md.

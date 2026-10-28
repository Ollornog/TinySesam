---
id: T-19
type: Task
title: Issue the gate token and prove it with a real Caddy running caddy-jwt
status: erledigt
milestone: M-3
tags: [gateway, jwt, caddy, cookies]
created: 2026-10-03
---

# T-19 — Gate token

Core of [ADR-9](ADR-9-gate-token-am-proxy.md).

**To do:**
- Key pair of the gateway (rotation with overlap), output as JWKS.
- `/.sesam/refresh` (on the app host, forwarded by the proxy to TinySesam) → gateway checks session,
  approval per app, roles → one-time code (short, redeemable once, bound to the host) →
  `/.sesam/callback` sets the gate cookie host-only. Return target checked against `trusted_redirect_hosts`.
- Claims: `iss`, `aud` = host, `sub`, `exp`, roles; adjustable lifetime (default 5 min).
- `deploy/forward-auth/`: Caddyfile example with `caddy-jwt` (`from_cookies`, whitelists,
  `handle_errors 401` → 307), remove the gate cookie via `header_up Cookie`, always remove `Remote-User`
  from the client, optionally set it from claims. Dockerfile line for `xcaddy --with`.
- `/auth/forward` stays unchanged as the route without a plugin.

**Done when:** browser test: first request → gateway → back with cookie; afterwards N asset requests
without a single call to TinySesam (counted); expired token → 307 → new token, POST
keeps the body; token for host A is rejected on host B; the app sees neither the gate cookie nor the
TinySesam session; mutation per check.

## Done 2026-10-07

The code exchange via `/.sesam/*` has been dropped: the token is created on the way back in
`/auth/forward` (reasoning in [ADR-9](ADR-9-gate-token-am-proxy.md)). JWKS likewise — `caddy-jwt`
takes the key directly with EdDSA, so there is no rotation with overlap.

- `tinysesam/gate.py`: derivation (HKDF), issuing, verifying as at the proxy, `zielgruppe()`.
  `_gate_cookie()` in `/auth/forward`; fields `gate_token_enabled`, `gate_token_ttl_sec`,
  `gate_cookie_name`, check in `konfigpruefung._gate`; `tinysesam gate-key`; gateway
  `TINYSESAM_GATE`, `TINYSESAM_GATE_TTL_SEC`.
- `deploy/forward-auth/Caddyfile.gate`, `deploy/forward-auth/caddy-gate/Dockerfile`.
- Tests: `tests/test_gate.py` (issuing, audience, claims, 12 tamperings, foreign
  JOSE implementation, keys, CLI, configuration check, guard over the template) and
  `tests/test_gate_caddy.py` (real Caddy, template from the repo: 10 asset requests without a call to
  TinySesam, POST including body on the way back, 7 tampered cookies, revocation delay, control run without
  gate). CI job `gate-caddy`.
- Mutation: ten interventions in code and template (token never issued, roles not in the audience,
  token for API key, any host, verifier without alg comparison, cookie without HttpOnly, Remote-Email not
  removed, no Set-Cookie on the way back, gate cookie reaches the app, without `sign_alg`) — each
  turns at least one of the two suites red.

---
id: T-119
type: Task
title: "caddy-jwt 1.5.0: back to jwk_url, disable_authorization_fallback instead of the Authorization detour; check the X-Forwarded-For warning"
status: erledigt
points: 2
milestone: M-5
tags: [gate, caddy, upstream, cleanup]
created: 2026-11-23
---
# T-119 — caddy-jwt 1.5.0: remove both workarounds

**Story points:** 2 · **Estimate:** 3–5 h · **Milestone:** [M-5](M-5-after-1-0.md)

**Trigger:** caddy-jwt 1.5.0 in `deploy/forward-auth/caddy-gate/go.mod` (released 2026-11-23; Dependabot raises it
after its cooldown). Both upstream issues that forced workarounds are fixed there.

## Content
- **jwk_url again** (ggicci/caddy-jwt#117, fixed by #118): with 1.4.0 a failed first fetch of
  `/auth/gate/jwks.json` (gateway still starting, 404) made every later request with a gate token hang — one fetch,
  no fallback, no deadline. Since 0.26.2 the templates use a fixed `sign_key` instead. Measure the fix in
  `tests/test_gate_caddy.py` (first fetch 404, then 200: no hang), then put `jwk_url` back into
  `deploy/forward-auth/Caddyfile.gate` and the quickstart; key rotation without a Caddy reload documented.
- **`disable_authorization_fallback`** (ggicci/caddy-jwt#90, fixed by #119): 1.4.0 always read `Authorization` as a
  token source and logged `token_string` (start and end of a Basic value or an API key) for a non-JWT. The templates
  route requests without a gate cookie or with `Authorization` away before `jwtauth` (`@no_gate_cookie` matcher).
  Replace that detour by the new option; a test proves that a Bearer and a Basic value are neither parsed nor logged
  (log lines checked, a mutation without the option turns it red).
- Check the warning "X-Forwarded-For from <ip> is ignored: the peer is not in trusted_proxies" (`security.py`): it
  was seen naming client addresses as the peer behind a server that already evaluates the header itself — a false
  alarm or a double evaluation; fix the cause or the advice in `docs/OPERATIONS.md`.

## Acceptance
- caddy-jwt 1.5.0 pinned; `jwk_url` in the templates with the hang measured away; the Authorization detour gone in
  favour of `disable_authorization_fallback`, with the no-parse/no-log test; CHANGELOG with the operator steps (both
  are changes to the Caddyfile an operator copied); the warning question answered with a test.

## Result (2026-11-25)
- caddy-jwt 1.5.0 pinned by hand (no Dependabot pull request existed yet; 1.5.0 already runs on the maintainer's gates).
- `jwk_url` back in `Caddyfile.gate`; measured with a key set that answers 404 at the first token: 1.4.0 times out
  (20 s, three of three requests), 1.5.0 answers at once and reaches the fast path after TinySesam comes up. A rotation
  is followed without a reload; a refetch started just before a rotation can put the old set back for a moment (the
  new key's token then takes the way back once more — never a wrong accept). The quickstart has no `jwtauth` block.
- `disable_authorization_fallback` replaces the `@no_gate_cookie`/`@has_authorization` detour; a valid gate token in
  `Authorization: Bearer` does not pass Caddy, the log holds no `token_string`.
- The X-Forwarded-For warning: a double evaluation, not a false alarm — the server in front had applied the header
  (uvicorn `proxy_headers=True`). The dedicated warning naming `--no-proxy-headers` (since #283) missed a client
  handed on in another notation and fell through to "is ignored"; fixed and tested in `tests/test_gateway.py`.

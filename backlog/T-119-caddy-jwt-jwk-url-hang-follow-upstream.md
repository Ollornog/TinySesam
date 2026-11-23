---
id: T-119
type: Task
title: "caddy-jwt jwk_url hang: follow upstream, then offer jwk_url again; check the X-Forwarded-For warning"
status: offen
milestone: M-2
tags: [gate, caddy, upstream]
created: 2026-11-23
---
# T-119 — caddy-jwt jwk_url hang: follow upstream, then offer jwk_url again; check the X-Forwarded-For warning

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-after-1-0.md)

Measured with Caddy 2.11 and caddy-jwt 1.4.0: if the first fetch of `/auth/gate/jwks.json` fails (gateway still
starting, 404), every request with a gate token on that site hangs afterwards — one fetch, no fallback, no deadline
(`jwk.Cache.Register` with `WithWaitReady` under a mutex). The templates went back to `sign_key` (0.26.2); the issue is
reported upstream (ggicci/caddy-jwt#117).

## Content
- When upstream ships a fix: measure it in `tests/test_gate_caddy.py` (first fetch 404, then 200), then offer `jwk_url`
  again in `deploy/forward-auth/Caddyfile.gate` and the quickstart, key rotation without a Caddy reload documented.
- Check the warning "X-Forwarded-For from <ip> is ignored: the peer is not in trusted_proxies" (`security.py`): it
  was seen naming client addresses as the peer behind a server that already evaluates the header itself — a false
  alarm or a double evaluation; fix the cause or the advice in `docs/OPERATIONS.md`.

## Acceptance
- Either `jwk_url` back in the templates with the hang measured away, or the entry stays open with the upstream
  state; the warning question answered with a test.

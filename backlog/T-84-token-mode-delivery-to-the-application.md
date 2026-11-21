---
id: T-84
type: Task
title: 'Token mode: deliver the gate token to the application'
status: offen
milestone: M-2
tags: [gate, clients, proxy]
created: '2026-11-22'
---
# T-84 — token mode: deliver the gate token to the application

Found while writing the gate client specification ([T-28](T-28-go-variant-small-gate-client.md)). In token mode
(`spec/gate-client.md` §4) the application checks the gate token itself instead of trusting `Remote-*`. With today's
`deploy/forward-auth/Caddyfile.gate` it never gets a valid one:

- the proxy strips every `tinysesam_*` cookie before the application, the gate cookie included (B-20);
- on the way back through `/auth/forward` the fresh token travels only in `X-TinySesam-Gate-Cookie` → `Set-Cookie` to
  the browser; the request that reaches the application carries the expired token or none.

## To decide and build

- How the proxy passes the token: keep the gate cookie for token-mode hosts, or a request header with the bare token
  (also on the way back, e.g. a second answer header of `/auth/forward` with the token alone).
- Templates for Caddy, nginx and Traefik, measured through the real proxies like `tests/test_gate_caddy.py`.
- The spec's §4.2 then names the source; the vectors stay as they are (they check the token, not its transport).

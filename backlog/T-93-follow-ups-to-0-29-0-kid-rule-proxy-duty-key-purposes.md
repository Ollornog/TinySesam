---
type: Task
title: 'Follow-ups to 0.29.0: kid rule, server-side top bar vs. proxy duty, key purposes both ways'
status: erledigt
id: T-93
milestone: M-5
tags: [gate-client, docs, approvals, proxy]
created: '2026-11-23'
---
# T-93 — Follow-ups to 0.29.0

Three findings from users of the 0.29.0 gate clients.

1. **kid rule.** A test fixture with a fixed `kid` got `key_unavailable` without a hint: a JWKS entry whose `kid` is not
   the one derived from its key is skipped (spec §4.3), and a set without a usable entry is a failed fetch. Now stated
   in spec §4.3, every client README and the Python section of the README.
2. **Server-side top bar and account vs. proxy duty 4.** The proxy templates strip TinySesam's cookies before the
   application, and the server-side helpers (`FetchTopbar`, `FetchAccount`, …) need exactly the session cookie. The
   recommended way is now the browser's (`/.tinysesam/topbar.json`, `/.tinysesam/account.json` same-origin); the
   server-side way is a deliberate exception that hands the application the session, with a commented variant in
   `deploy/forward-auth/Caddyfile.gate` that lets through only the session and the connection cookie — measured in
   `tests/test_gate_caddy.py`. Spec §2.1 duty 4, §8 and §8a say so.
3. **Key purposes both ways** (spec/approval-token.md §3). An approval verifier already refused `/gate/jwks.json`;
   now every gate client refuses a key set URL ending in `/approvals/jwks.json` at configuration (Go `New`, Rust
   `JwksVerifier::from_url`, JS `createGate`, PHP `Gate::tokenMode`, Python `GateClient`), each proved by mutation.

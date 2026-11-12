---
id: B-7
type: Bug
title: 'Gate token: iat in the future after a backward clock step — caddy-jwt rejects fresh tokens'
status: erledigt
milestone: M-2
tags: [gateway, forward-auth, gate, clock]
created: 2026-11-12
---

# B-7 — Gate token: `iat` in the future after a backward clock step

## Repro

Gateway (`gate_token_enabled`) on a VM whose clock boots about a second ahead. The container starts with the boot,
reads the clock, then NTP steps the wall clock back (measured on a production VM: −1.0 s to −1.3 s at every weekly
reboot, from the journal's realtime−monotonic offset). Sign in and open a protected app.

**Expected:** the proxy accepts the fresh gate token.
**Actual:** caddy-jwt logs `jwt.Validate: validation failed: "iat" not satisfied` for the requests in the first second
after each new token (a burst of parallel asset requests); a moment later the same token passes. Lasts until the
gateway restarts.

## Cause

`_gate_cookie` stamped `iat`/`nbf`/`exp` with `store.now()`. That clock never runs backwards (B6-9): after a step back
it keeps the lead for the whole process lifetime — on purpose, for deadlines stored in the database. The gate token,
however, is checked by the proxy against **its** system clock (jwx: fails if `now < iat`). With a lead of 1.3 s the
token's `iat` was up to one full second ahead of the proxy.

## Fix

The gate token takes its timestamps from the bare wall clock (`store.wall_now()`). The monotonic protection buys
nothing there: the proxy never sees TinySesam's clock. Everything stored in the database keeps using `store.now()`.

Test: `tests/test_gate.py` (B-7) sets up the step with a fake clock and checks `iat`/`nbf` ≤ wall clock; with
`store.now()` in `_gate_cookie` it fails with `iat` one second ahead.

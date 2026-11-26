---
id: B-15
type: Bug
title: 'Test flake: TOTP codes in the suites flip at a 30-second step boundary'
status: erledigt
milestone: M-5
tags: [ci, tests, flaky, totp]
created: '2026-11-21'
---
# B-15 — TOTP codes in the suites flip at a 30-second step boundary

**Seen:** `test_next_whatwg.py` red once in a local run of `scripts/check.sh` on a branch without product changes:
the TOTP setup answered `{"ok": false}`, the log said `failed verification … method=totp_setup`. The second run was
green.

## Cause
About forty places in twenty suites confirm a TOTP setup with the code of the previous step,
`pyotp.TOTP(secret).at(time.time() - 30)`, so that the running step stays free for a later sign-in with `.now()`.
Since T-57 the default window (`totp_window="previous"`) accepts the running and the previous step. The test computes
the code at one moment, the library checks it a little later: a step boundary in between makes the code two steps
old, and it is refused. The places that expect a code of the next step to be refused (`at(time.time() + 30)`) flip
the other way — across a boundary that code is the running one and passes.

## Fix
- `tests/_totp_clock.py`: `previous_code`, `next_code` and `code(secret, steps)` derive the code from ONE moment with
  at least `MARGIN` (5 s) left in its step; in the last seconds they sleep over the boundary first. The library keeps
  its own clock — nothing in the product is loosened.
- Every suite uses the helper; `tests/test_h4_auth_hardening.py` gave up its own `mid_step` arithmetic for it.
- `tests/test_totp_clock.py` replays the race against the library's `matching_step` with a fake clock 0.1 s before a
  boundary and 0.2 s of latency: the old way refuses the previous code and accepts the next one (self-probe), the
  helper gets both right. A guard keeps every suite on the helper (no `.at(time.time() ± 30)` any more).

## Proof
- Mutation `MARGIN = 0.0`: `test_totp_clock.py` red ("the helper waits out the end of the step").
- Mutation: one place in `test_core.py` back to `at(time.time() - 30)`: the guard is red.
- Real clock, 0.1 s before a boundary, 0.3 s until the check: the old way refused, the helper accepted.

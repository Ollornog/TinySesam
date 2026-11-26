---
id: T-57
type: Task
title: 'TOTP: accept at most one step back (switch totp_window)'
status: erledigt
milestone: M-5
tags: [security, totp]
created: '2026-11-20'
---
# T-57 — TOTP: accept at most one step back (switch totp_window)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N7 — ASVS 6.5.5 (L2), RFC 6238 §5.2.

**Is:** `valid_window=1` (`totp.py:26,31-51`) accepts ±1 step (90 s); replay protection is correct (`store.py:3157-3167`).

**Proposal:** switch `totp_window` (default: one step back, none ahead). Effort S.

## Done (H4)
- New `totp_window`: `"previous"` (default: current + previous step), `"current"`, `"previous_and_next"` (old
  behaviour). `TinySesam._totp_step` feeds `tinysesam.totp.matching_step(secret, code, back, ahead)` for the sign-in,
  the step-up and the setup confirmation; `tinysesam.totp.WINDOWS` holds the pairs. Replay protection unchanged.
- `config_check` rejects unknown values. Upgrade note in the CHANGELOG (authenticators with a fast clock, tests that
  used the next step's code).
- `"current"` would meet ASVS 6.5.5 to the letter (30 s); the default follows RFC 6238 instead, because a code typed
  in the last seconds of a step would otherwise fail regularly. Documented in `SECURITY.md`.
- Tests: `tests/test_h4_auth_hardening.py` (T-57 block); suites that signed in with the next step's code set
  `totp_window="previous_and_next"` for that instance.
- Sources: RFC 6238 §5.2 ("We RECOMMEND that at most one time step is allowed as the network delay"); ASVS 5.0.0
  6.5.5 ("for TOTP a maximum lifetime of 30 seconds"); NIST SP 800-63B-4 §3.1.4.2 ("accept a given OTP only once").

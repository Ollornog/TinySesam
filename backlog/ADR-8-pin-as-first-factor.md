---
id: ADR-8
type: Decision
title: A PIN may be the first factor — deliberate, configurable, with its own limit
status: erledigt
tags: [pin, factors, hardening]
created: 2026-09-24
---

# ADR-8 — A PIN may be the first factor

## Context

The third audit (T-13, finding **B2-8**) established: a four-digit PIN is a full,
centrally verified first factor in TinySesam. According to NIST SP 800-63B, a secret this short is weak as a
sole factor — it has 10,000 values.

## Decision

**The PIN stays allowed as a first factor** (PO decision 2026-09-24, "explicitly yes"). The
use case is real: a general page behind a PIN, a detail page behind more —
via a per-route chain (`auth.require(factors=["pin", "password"])`).

It stays **configurable**:

- `pin_login` (configuration, default `True`): with `False` the PIN is no way in, only
  a follow-up factor (chain step, route chain) and step-up factor. If a strict `login_chain` requires
  the PIN behind another factor, it is no way in even with `True`
  (`pin_als_erstfaktor()`, G7 — a PIN entered first never satisfies this chain).
- `pin_max_attempts` (panel, default 5): the PIN's own counter per account, per address the
  `ip_attempt_factor` multiple of it. It sits in the panel **directly next to the login lockout**, because
  it is set together with it there.
- `account_max_consecutive_failures` (panel, default 100, B2-6): PIN failures count towards the
  series. Nobody gets more than 99 guesses in a row, not even spread out. A
  password reset by the owner clears the failures of the PIN as first factor — otherwise a
  stranger with wrong PINs would lock the account beyond the reset (R2-2). It does not clear the failures of a PIN behind
  an already provided factor (kind `pin_folge`, G7), as with TOTP: only
  someone who has the first factor generates those. Whoever wants to rule out guessing entirely takes the PIN off the
  login page (`pin_login=False`).

## Consequences

- Whoever uses the PIN as a first factor accepts the strength of a short secret. The limits
  above make that at most 100 attempts out of 10,000 in a row, after which it must be re-bound.
- The docs call this by its name (README "PIN and step-up", `docs/OPERATIONS.md`, table of
  sign-in methods) and show the "general page / detail page" pattern.
- Measured in `tests/test_t13_decisions.py` (PIN alone → general page, detail page requires
  the password, `pin_login=False` takes the PIN off the login page, order in the panel).

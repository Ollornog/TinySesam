---
id: B-12
type: Bug
title: 'New sign-in factors, API keys and QR approval without fresh confirmation'
status: erledigt
milestone: M-2
tags: [security, stepup, asvs, priority-high]
created: '2026-11-20'
---
# B-12 — New sign-in factors, API keys and QR approval without fresh confirmation

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding H1 (severity high) — ASVS 7.5.1 (L2), NIST SP 800-63B-4 §4.1.2.1.

**Repro:** with only a session cookie (no step-up), `POST /auth/passkey/register/begin|finish`, `POST /auth/totp/setup/start`
+ `/auth/totp/setup`, `POST /auth/apikeys` and `POST /auth/qr/approve` succeed (`tinysesam/webauthn_.py:66-101`,
`tinysesam/router.py:204,220,617-640,1916-1945` at b1d166c).
**Expected:** full re-authentication before changing the MFA configuration. **Actual:** a stolen cookie becomes a
permanent passkey (signs in alone), a 90-day API key with the account's roles, or a TOTP that locks the holder out.

**Proposal:** `require_mfa()` before those routes (exceptions: the setup pass T-34 and the first factor under
`login_fresh`); an AST guard "every factor-creating route demands freshness" next to H-18; or an ADR if the PO wants
setup without freshness on purpose. Effort M.

## Fixed (H2)
- One bolt, `TinySesam._require_fresh()`: an interactive session (never an API key) whose last confirmation is younger
  than `stepup_max_age_sec` — or, for an account with nothing to confirm with, whose sign-in is (`login_fresh`).
  Refusal 403 + `X-TinySesam-Reauth`, or `api.stepup_relogin`. A fresh sign-in counts (`mfa_at` at sign-in).
- In front of: `passkey/register/begin|finish`, `totp/setup/start`, `totp/setup` (and the GET page goes over the
  reauth page and back), `pin/set`, `POST /auth/apikeys`, `qr/approve` (page and POST), OAuth consent (page and
  allow) — the identifier changes (`account/username|email`) use the same bolt now.
- Not asked again (no softening): the setup pass T-34 and the mandatory TOTP setup in a chain (half sessions, fresh
  from the sign-in, only the offered factor); `set_initial_password` (B-10) keeps its own, identical rule.
- OAuth consent (T-36): allowing a program issues a refresh token that lives for days — the same "new lasting access
  from a stolen session" as a passkey, so the same rule. Deny needs no freshness.
- Guard `tests/test_h2_hardening.py` (AST: every new-access route calls the bolt) and the H-18 table in
  `tests/test_stepup.py` (`/auth/apikeys` moved from OPEN to STEPUP; factor setup refuses a stale session).

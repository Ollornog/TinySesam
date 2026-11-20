---
id: B-12
type: Bug
title: 'New sign-in factors, API keys and QR approval without fresh confirmation'
status: offen
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

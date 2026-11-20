---
id: B-11
type: Bug
title: 'A SAML response could be replayed until NotOnOrAfter'
status: erledigt
milestone: M-2
tags: [saml, security, asvs]
created: '2026-11-20'
---
# B-11 — A SAML response could be replayed until NotOnOrAfter

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M1 — ASVS 6.8.3 (L2): assertions are processed only once within their validity.

**Repro (before H1):** sign in via SAML once, keep the `SAMLResponse`; in another browser set the cookie
`tinysesam_saml_flow` to the response's `InResponseTo` and POST the response to `/auth/saml/acs` → signed in again.
**Expected:** rejected. **Actual:** 303, a second session.

## Fixed (H1)
- `SAMLClient(cfg, store=…)`: every sent AuthnRequest ID is stored (`samlreq:`, 10 min) and consumed atomically
  (`pop_flow`) when its response arrives — the cookie alone no longer makes a request ID.
- Every accepted assertion ID is claimed (`Store.claim_flow`, `samlassert:`) until `NotOnOrAfter` + python3-saml's
  clock drift; a second use is refused, also under a fresh request. `gc` removes expired rows (flow table, no schema change).
- `tests/test_saml.py` with really signed assertions: replay with the forged cookie → 400; never-sent `InResponseTo`
  → 400; reused assertion ID → 400, new ID → 303; expiry and gc.

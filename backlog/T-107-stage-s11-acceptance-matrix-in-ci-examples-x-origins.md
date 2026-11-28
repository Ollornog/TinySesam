---
id: T-107
type: Task
title: "Stage S11 — acceptance matrix in CI: examples x origins"
status: erledigt
points: 8
milestone: M-2
blocked_by: [T-101, T-102, T-103, T-104, T-106]
tags: [ci, tests]
created: 2026-11-23
---
# T-107 — Stage S11 — acceptance matrix in CI: examples x origins

**Story points:** 8 · **Estimate:** 10–14 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Test IdP in CI (OIDC and SAML bases exist: `test_oidc_jwks.py`, `test_saml.py`, `test_ldap.py`); a matrix job runs Ex1 to Ex4 x (local, IdP, mixed) where it makes sense, and belongs to `nightly-repeat`.

## Acceptance
- Green matrix; every cell of the feature matrix is done or marked "deliberately not".

## Done (sprint S9, 2026-11-28)

- `tests/_test_idp.py`: a real OpenID provider on a loopback port (discovery, authorize with a page per account, PKCE
  S256, client secret, RS256 ID token, JWKS, userinfo); `_browser_stack.sign_in_with_provider` takes the browser
  through it.
- Cells (README "The acceptance matrix", en/de): Ex1 B1/B5, Ex2 A2/A4 (`tests/test_shell_browser.py`), Ex3 H1/H3
  (`tests/test_hybrid_browser.py`, the stubbed provider replaced), Ex4 X1/X9 (`tests/test_headless_browser.py`) — local,
  IdP (OIDC through the provider) and mixed (both in one installation, the same result for an equivalent role). All
  twelve done; deliberately not per example: SAML/LDAP as the provider and linking (own suites).
- CI: `browser-suite` matrix (pages, shell, hybrid, headless) side by side, aggregate `browser` (the required check);
  part of `nightly-repeat` through `ci.yml`; the sprint lane runs it on a change of the browser scope (now with
  `tests/_test_idp.py`). `tests/test_ci_aggregate.py` checks the aggregate, the extras and the matrix's cells.
- Estimate: about 8 SP as planned; follow-ups T-162 (deploy examples with a provider) and T-163 (top bar parity with
  `base_url`).

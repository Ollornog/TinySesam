---
id: T-107
type: Task
title: "Stage S11 — acceptance matrix in CI: examples x origins"
status: offen
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

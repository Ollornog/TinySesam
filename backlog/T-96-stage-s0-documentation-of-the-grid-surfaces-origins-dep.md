---
id: T-96
type: Task
title: "Stage S0 — documentation of the grid: surfaces, origins, deployment"
status: offen
milestone: M-4
tags: [docs]
created: 2026-11-23
---
# T-96 — Stage S0 — documentation of the grid: surfaces, origins, deployment

**Story points:** 3 · **Estimate:** 4–6 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Document the grid before building it.

## Content
- README and `i18n/README.de.md`: section "Surfaces, origins, deployment" with the grid (four surfaces x local / IdP / mixed x library / server), the ownership rule (reading is allowed everywhere, writing from another origin only by navigation), the equivalence rule (no decision depends on the origin of an account) and the parity rule (every function has a server route or sits on the "library only" list with a reason).
- `SECURITY.md` (en + de): the library is one trust boundary, server and application are two.

## Acceptance
- Hygiene green; every row of the feature matrix has an owner (a task of this milestone or "not planned" with a reason).

Concept: surfaces and rules in [ADR-15](ADR-15-python-core-stays-clients-stay-thin-no-go-rewrite.md) to [ADR-19](ADR-19-gate-look-like-a-provider-sign-in-heading-and-icon-of-t.md).

---
id: T-109
type: Task
title: Stage S13 (optional) — SCIM stage 2 for IdP role sync
status: offen
milestone: M-4
blocked_by: [T-102]
tags: [idp, scim, optional]
created: 2026-11-23
---
# T-109 — Stage S13 (optional) — SCIM stage 2 for IdP role sync

**Story points:** 21 · **Estimate:** 32–45 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

**Only on demand.** Build it when a real user with Entra or Okta asks. Until then this stays open as a note.

`/scim/v2/Users` and `/scim/v2/Groups` (RFC 7643/7644), one bearer token per IdP (key purpose per [ADR-12](ADR-12-key-purposes-keyrings-and-rotation.md)); create, lock, delete and group push without a sign-in; locked by SCIM equals locked in the panel; group push feeds `idp_role_membership`. Add 30 % risk margin (new ground).

## Acceptance
- **Ex3** with a SCIM test client: a withdrawal without a sign-in takes effect at once.

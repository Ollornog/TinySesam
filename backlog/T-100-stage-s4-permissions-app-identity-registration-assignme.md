---
id: T-100
type: Task
title: "Stage S4 — permissions: app identity, registration, assignment, has_permission"
status: offen
points: 13
milestone: M-4
blocked_by: [T-97]
tags: [permissions, roles, admin]
created: 2026-11-23
---
# T-100 — Stage S4 — permissions: app identity, registration, assignment, has_permission

**Story points:** 13 · **Estimate:** 26–32 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The permission layer of [ADR-17](ADR-17-permission-layer-and-admin-levels.md), library side.

## Content
- Unify the app identity: `apps[id]` with `hosts`, `layout`, `permissions`, name and icon; `forward_apps` stays as an alias translated by `config_check`.
- Schema 27 (additive): `app_permission`, `role_permission`; migration test with an old database; note in `docs/OPERATIONS.md`.
- Registration by config and `register_permissions` (idempotent, name rule, at most 200 per app). The application can only register, never assign.
- `has_permission(user, perm, app=…)` and `require_permission` dependency; effective permissions = union over roles, for this application only; services get the intersection with their scope.
- Panel matrix per application; `danger` permissions need a step-up (symbol and word, never colour only); area administrators assign only inside their area; audit per change; orphaned assignments shown, never silently re-granted.
- `admin_implies_permissions`, default false.

## Acceptance
- Example **Ex2** (Python library): `docs.read` / `docs.delete`, a role assigned locally, the delete button only with the permission.

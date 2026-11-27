---
id: T-100
type: Task
title: "Stage S4 — permissions: app identity, registration, assignment, has_permission"
status: erledigt
points: 12
milestone: M-2
blocked_by: [T-97]
tags: [permissions, roles, admin]
created: 2026-11-23
---
# T-100 — Stage S4 — permissions: app identity, registration, assignment, has_permission

**Story points:** 12 (13 before 2026-11-27: the app identity moved to T-101, T-103, T-104) · **Estimate:** 26–32 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The permission layer of [ADR-17](ADR-17-permission-layer-and-admin-levels.md), library side.

## Content
- ~~Unify the app identity~~ — moved (decision 2026-11-27, rule "no configuration field without a reader"): `hosts` and
  `forward_apps` as its alias to [T-101](T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md) (the first
  reader: `ts_perms`/`Remote-Permissions` need host → application id), `layout` to
  [T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md), `icon` to
  [T-104](T-104-stage-s8-hybrid-tinysesam-area-with-name-and-icon-libra.md). `apps[id]` carries `permissions` and `name`
  here; until T-101 `forward_apps` stays the view on the hosts.
- Schema 27 (additive): `app_permission`, `role_permission`; migration test with an old database; note in `docs/OPERATIONS.md`.
- Registration by config and `register_permissions` (idempotent, name rule, at most 200 per app). The application can only register, never assign.
- `has_permission(user, perm, app=…)` and `require_permission` dependency; effective permissions = union over roles, for this application only; services get the intersection with their scope.
- Panel matrix per application; `danger` permissions need a step-up (symbol and word, never colour only); area administrators assign only inside their area; audit per change; orphaned assignments shown, never silently re-granted.
- `admin_implies_permissions`, default false.

## Progress

- 2026-11-27: library core — schema 27 (`app_permission`, `role_permission`, additive; step tested on a database of
  the state before), `apps[id].permissions` and `register_permissions` (idempotent, name rule, at most 200, per source:
  the application's manifest never touches the configuration's names), `has_permission` / `permissions_of` /
  `require_permission`, `grant_permission` / `revoke_permission` / `delete_permission` / `app_permissions`,
  `admin_implies_permissions` (default false), orphaned permissions with suspended assignments (never re-granted
  silently), a role holding permissions counts as in use. Suite `tests/test_permissions.py`.
- 2026-11-27: panel matrix per application (`_admin_permissions.py`): `danger` → fresh confirmation for everyone
  (symbol and word), orphaned shown with suspended roles and deletable by administrators, area administrators by
  `admin_delegates[…]["apps"]` plus the action `permissions` (only their applications and managed roles), audit with
  the actor. Suite `tests/test_admin_permissions.py`.
- 2026-11-27: acceptance — example Ex2 (`examples/ex2/app.py`, `tests/test_example_ex2.py`): `docs.read` /
  `docs.delete`, the roles assigned locally in the panel, the delete button only with the permission, run through the
  real panel routes. Done; the app identity went to T-101/T-103/T-104 (see Content).

## Acceptance
- Example **Ex2** (Python library): `docs.read` / `docs.delete`, a role assigned locally, the delete button only with the permission.

---
id: B-19
type: Bug
title: "A role removed from available_roles keeps its permission assignments"
status: erledigt
points: 2
milestone: M-2
tags: [permissions, roles]
created: 2026-11-27
---
# B-19 — A removed role keeps its permission assignments

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

**Done (2026-11-27), without a schema step:** the existing `active` = 0 of `role_permission` ("suspended", re-activated
only by an administrator's assignment) carries it. `permissions_of` counts only roles of the configuration and the
catalog (`_known_roles`), so a removed role grants nothing at once; at start `_suspend_removed_role_permissions`
suspends the assignments of such roles in one transaction (audit `permissions_suspended reason=role_removed`, once)
and names every such row in a security-log warning at each start. The panel's matrix gives a removed role a column of
its own for administrators — "⊘ Role removed — grants nothing", cells "⏸ suspended" with "Withdraw"
(`removed_roles` in `GET <admin>/api/permissions`). `tests/test_admin_permissions.py` (f) runs remove → start →
re-create (configuration and catalog) → assign again → withdraw; the browser test checks the column and the button.
Mutations (all red): no suspension; no request-time filter; no `removed_roles`; `removed_roles` for area
administrators; no security-log line; the panel without the mark. Left open: a role removed AND added back while the
same instance runs (by changing `cfg.available_roles` in code, no start in between) keeps its active assignments.

Found in sprint S5 ([T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md)). When a role leaves
`available_roles`, its rows in `role_permission` stay. A role created later under the same name inherits them silently
— against the T-100 rule "orphaned assignments are shown, never silently re-granted".

## Content
- Treat assignments of a role that is no longer in the catalog like orphaned permissions: they grant nothing, the panel
  shows them, a re-created role does not take them over without an administrator's action.
- Start-check warning that names the orphaned rows.

## Acceptance
- A test: assign `docs.delete` to a role, remove the role, re-create it — the permission is not effective until an
  administrator assigns it again; the panel shows the orphaned row (symbol and word). Proven by mutation.

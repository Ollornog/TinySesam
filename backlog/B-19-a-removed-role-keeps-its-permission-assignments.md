---
id: B-19
type: Bug
title: "A role removed from available_roles keeps its permission assignments"
status: offen
points: 2
milestone: M-2
tags: [permissions, roles]
created: 2026-11-27
---
# B-19 — A removed role keeps its permission assignments

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

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

---
id: B-20
type: Bug
title: "A role removed and re-added at runtime keeps its permission assignments"
status: offen
points: 1
milestone: M-2
tags: [permissions, roles]
created: 2026-11-28
---
# B-20 — A role removed and re-added at runtime keeps its permission assignments

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Rest of [B-19](B-19-a-removed-role-keeps-its-permission-assignments.md) (S6 #416): assignments of a role that left the
catalog are suspended at start. When `cfg.available_roles` loses a role and gets it back without a start in between,
its assignments stay active.

## Content
- Suspend at the moment the role leaves the catalog (or check the catalog when a permission is evaluated), not only
  at start.

## Acceptance
- A test: assign, remove the role at runtime, re-add it — the permission is not effective until an administrator
  assigns it again. Proven by mutation.

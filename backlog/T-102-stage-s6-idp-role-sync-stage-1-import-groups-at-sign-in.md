---
id: T-102
type: Task
title: "Stage S6 — IdP role sync stage 1: import groups at sign-in"
status: offen
points: 8
milestone: M-2
blocked_by: [T-99, T-100]
tags: [idp, roles]
created: 2026-11-23
---
# T-102 — Stage S6 — IdP role sync stage 1: import groups at sign-in

**Story points:** 8 · **Estimate:** 14–20 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

[ADR-18](ADR-18-idp-role-sync-and-linking-local-and-idp-accounts.md), stage 1.

## Content
- `*_group_import` per source (OIDC, SAML, LDAP) with a filter (exact names or prefix `team-*`); without a filter at most 100 groups per sign-in, above that a security-log warning and no import.
- A group becomes a role of the same raw name; the catalog row carries `source` and `last_seen_at`, the panel shows "from IdP" (symbol and word).
- Collision with a config or local catalog role: skip, log, hint in the panel.
- `idp_role_membership(user_id, source, role)` (schema 27): what the source delivered last is replaced at sign-in; hand-assigned roles and other sources stay.
- A missing claim withdraws nothing (log and hint). Entra: app roles via `oidc_group_claim="roles"`, labels for GUIDs (display only).
- Start-check hint for stale IdP catalog rows.

## Acceptance
- Example **Ex3** IdP: a group arrives at sign-in, shows in the catalog as "from IdP", the administrator assigns `docs.read`, the application sees it; the group is withdrawn and the permission is gone after the revalidation.

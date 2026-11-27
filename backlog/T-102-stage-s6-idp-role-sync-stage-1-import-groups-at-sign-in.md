---
id: T-102
type: Task
title: "Stage S6 — IdP role sync stage 1: import groups at sign-in"
status: in-arbeit
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
- `idp_role_membership(user_id, source, role)` (schema 28; 27 went to T-100): what the source delivered last is replaced at sign-in; hand-assigned roles and other sources stay.
- A missing claim withdraws nothing (log and hint). Entra: app roles via `oidc_group_claim="roles"`, labels for GUIDs (display only).
- Start-check hint for stale IdP catalog rows.

## Acceptance
- Example **Ex3** IdP: a group arrives at sign-in, shows in the catalog as "from IdP", the administrator assigns `docs.read`, the application sees it; the group is withdrawn and the permission is gone after the revalidation.

## Progress

- 2026-11-27 (PR 1, library): `*_group_import`, `*_group_import_filter`, `idp_group_labels`; schema 28 (`idp_role`,
  `idp_role_membership`); OIDC sign-in and re-check, SAML, LDAP; collisions (configuration, map target, `admin`, local
  catalog, other case, hand-typed role, role level entry, invalid name) skipped, logged, noted; 100-group limit without
  a filter; start hint for imported roles unseen for 90 days. Decision on a missing claim: OIDC withdraws nothing (ADR);
  SAML and LDAP read an absent attribute as "no groups" (they carry no empty attribute; T-99 kept the same for the maps)
  — a missing attribute release costs access instead of keeping a withdrawn group's role. Suites
  `tests/test_group_import.py`, `tests/test_group_import_saml.py`; 29 mutations, all red.


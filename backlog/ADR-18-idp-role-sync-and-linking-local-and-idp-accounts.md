---
id: ADR-18
type: Decision
title: IdP role sync and linking local and IdP accounts
status: erledigt
tags: [architecture, idp, roles, accounts]
created: 2026-11-23
---
# ADR-18 — IdP role sync; linking local and IdP accounts

## Context
Group-to-role maps (`*_group_role_map`) are applied at every sign-in, but raw groups are not stored: a group without a map entry is invisible. A missing group claim counts as an empty list (`oidc.py`, `manager.py` `apply_idp_groups`), which silently withdraws mapped roles when an IdP drops the claim (for example Entra group overage). Local and IdP accounts cannot be linked by the person.

## Decision
**Role sync, stage 1 — at sign-in** ([T-102](T-102-stage-s6-idp-role-sync-stage-1-import-groups-at-sign-in.md))
- Per source a switch `*_group_import` with a filter; the group name becomes the role name raw; the origin is a note (`source`, `last_seen_at`), not a prefix.
- A group that collides with a config or local catalog role is skipped, logged and hinted — otherwise an IdP group `admin` would inherit the local role `admin`.
- A table `idp_role_membership` holds what a source delivered last; at sign-in exactly that set is replaced. Hand-assigned roles and other sources stay untouched.
- A missing claim is not an empty list: nothing is withdrawn, nothing granted, a log entry and a hint ([T-99](T-99-stage-s3-every-origin-is-equal-source-step-up-linking-l.md) pins the rule).
- Withdrawal takes effect at sign-in or revalidation (OIDC has it, SAML and LDAP at the next sign-in): documented honestly.

**Stage 2 — SCIM:** only on demand ([T-109](T-109-stage-s13-optional-scim-stage-2-for-idp-role-sync.md), "only when asked for").

**Linking local and IdP:** by the person with a step-up on both sides, or by an administrator through a sign-in link with the binding. Never silently by an equal address.

**Equivalence rule:** no decision depends on the origin of an account, only on account, roles and factor state; the origin is a visible attribute.

## Consequences
Extends [ADR-7](ADR-7-factors-not-from-the-idp.md) (factors stay local). Schema 27.

---
id: T-99
type: Task
title: "Stage S3 — every origin is equal: source, step-up, linking local and IdP"
status: offen
milestone: M-4
blocked_by: [T-97]
tags: [idp, oidc, saml, ldap, accounts]
created: 2026-11-23
---
# T-99 — Stage S3 — every origin is equal: source, step-up, linking local and IdP

**Story points:** 13 · **Estimate:** 24–32 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Make local, IdP and mixed accounts behave the same ([ADR-18](ADR-18-idp-role-sync-and-linking-local-and-idp-accounts.md)).

## Content
- `source` of an account shown in the panel, the account API and `account.json`.
- SAML step-up by `ForceAuthn` (and a check of `AuthnInstant`); LDAP step-up by a fresh bind.
- Pre-create an OIDC account and bind it at the first sign-in by `sub` or a verified address (opt-in).
- Link a local account and an IdP identity: by the person with a step-up on both sides, or by an administrator through a sign-in link with the binding — never silently by the same address.
- Fix and pin the rule "a missing group claim is not an empty list" (today `oidc.py` and `manager.py` `apply_idp_groups` treat it as empty and withdraw mapped roles).

## Acceptance
- Same scenario (role, approval, admin action) once local, once OIDC, once SAML (test IdP) with the same result.

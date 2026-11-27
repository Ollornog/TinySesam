---
id: T-99
type: Task
title: "Stage S3 — every origin is equal: source, step-up, linking local and IdP"
status: in-arbeit
points: 8
milestone: M-2
blocked_by: [T-97]
tags: [idp, oidc, saml, ldap, accounts]
created: 2026-11-23
---
# T-99 — Stage S3 — every origin is equal: source, step-up, linking local and IdP

**Story points:** 8 own + 5 in [T-70](T-70-saml-forceauthn-authninstant-for-re-authentication.md) (SAML step-up; frontmatter `points: 8`, so nothing is counted twice) · **Estimate:** 24–32 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Make local, IdP and mixed accounts behave the same ([ADR-18](ADR-18-idp-role-sync-and-linking-local-and-idp-accounts.md)).

## Content
- `source` of an account shown in the panel, the account API and `account.json`.
- SAML step-up by `ForceAuthn` (and a check of `AuthnInstant`); LDAP step-up by a fresh bind.
- Pre-create an OIDC account and bind it at the first sign-in by `sub` or a verified address (opt-in).
- Link a local account and an IdP identity: by the person with a step-up on both sides, or by an administrator through a sign-in link with the binding — never silently by the same address.
- Fix and pin the rule "a missing group claim is not an empty list" (today `oidc.py` and `manager.py` `apply_idp_groups` treat it as empty and withdraw mapped roles).

## Progress

- 2026-11-27: the rule "a missing group claim is not an empty list" is fixed and pinned for the OIDC sign-in
  (`oidc.py`; the re-check `_oidc_swap` already had it): a missing claim leaves the mapped roles and the provider's
  admin flag and logs a warning, an empty claim withdraws them, `allowed_groups` still refuses. Suite
  `tests/test_idp_group_claim.py`. SAML and LDAP keep reading an absent attribute as "no groups" (a directory omits
  an empty attribute). Open: `source` (panel, account API, `account.json` and the clients' spec), SAML/LDAP step-up,
  pre-created OIDC accounts, linking.

## Acceptance
- Same scenario (role, approval, admin action) once local, once OIDC, once SAML (test IdP) with the same result.

## Roadmap (2026-11-23)

The SAML step-up has its detailed design in [T-70](T-70-saml-forceauthn-authninstant-for-re-authentication.md)
(5 SP, 8–12 h, can run earlier); what remains here is about 8 SP, 16–20 h.

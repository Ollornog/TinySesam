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
  an empty attribute).
- 2026-11-27: `source` of an account (`Store.account_sources`: `local`, `oidc`, `saml`, `ldap`, mixed = two or more) in
  the panel, the account API, `account.json` (spec §8a, two vectors) and the gate clients of all five languages; suite
  `tests/test_account_source.py`.
- 2026-11-27: LDAP step-up by a fresh bind (`_directory_password`, `_verify_directory_password` through `_check_ldap`;
  the entry must lead to this account; outage 503 without a count); suite `tests/test_ldap_stepup.py`.
- 2026-11-27: SAML step-up done in T-70 (`ForceAuthn`, `AuthnInstant`).
- 2026-11-27: linking by the person (`POST /auth/oidc/link`: CSRF, `_require_fresh`, active provider sign-in, the
  starting session, never an identity of another account), pre-registration by `sub` (`tinysesam oidc-link`), opt-in
  `oidc_bind_precreated` (verified address, only an unused operator-created account); attack tests in
  `tests/test_oidc_link.py`. The administrator's path is a sign-in link plus the person's link (documented, no route
  of its own).
- 2026-11-27: acceptance suite `tests/test_origin_equal.py` — the same scenario (role granted in the panel, admin
  action from a stale session after the origin's own confirmation, approval confirmed with the origin's step-up) once
  local, once OIDC, once SAML (test identity provider `tests/_saml_idp.py`) with the same result. It found the gap: a
  pure SAML account could not confirm an approval at all — the per-approval provider step-up now exists for SAML too
  (`/auth/saml/login?approval=<id>`, `ForceAuthn`, `AuthnInstant`, `stepup_amr` `["saml"]`).

**Open (rest of T-99):** linking for SAML and LDAP identities (today OIDC only — SAML and LDAP bind by
their stable identifier at sign-in, an operator unbinds with `federation_unbind`); unlinking by the person.

## Acceptance
- Same scenario (role, approval, admin action) once local, once OIDC, once SAML (test IdP) with the same result.

## Roadmap (2026-11-23)

The SAML step-up has its detailed design in [T-70](T-70-saml-forceauthn-authninstant-for-re-authentication.md)
(5 SP, 8–12 h, can run earlier); what remains here is about 8 SP, 16–20 h.

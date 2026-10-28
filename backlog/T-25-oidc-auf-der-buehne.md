---
id: T-25
type: Task
title: E2E stage — the OIDC ceremony fails at the identity provider
status: erledigt
milestone: M-2
tags: [e2e, oidc, stage]
created: 2026-10-03
---

# T-25 — OIDC on the E2E stage green again

Since v0.20.1 `tests/e2e_stage.py` has run green on the stage ([T-6](T-6-stage-per-playbook.md)) for passkey and SAML,
**red for OIDC**. The provider (PocketID) rejects the sign-in with "You are not allowed to access this service".

**Cause:** The test account does not belong to a group that is approved for the stage's OIDC client. Since PocketID v2
a client without group approval is open to nobody. This is not a bug in TinySesam, but as long as OIDC is red,
the E2E run checks only two of the three routes from [T-1](T-1-e2e-gegen-echten-idp.md).

## The stage is rebuilt for each run

Decision of 2026-10-03: The stage is not permanent operation. It is set up, the run goes, afterwards it is
torn down. The approval must therefore live where it survives a rebuild: at the provider (group of the test account
or approved group of the client), not in the stage.

## Done when

- The test account belongs, at the provider, to a group that is approved for the stage's client, or the client
  approves a test group of its own.
- A run on a **freshly built** stage reports all three routes green.
- The control run holds: without the approval OIDC turns red and is not silently skipped.

Related: [T-14](T-14-mehrere-oidc-clients.md) — the approval per app lies with the identity provider.

## Done 2026-10-07

- A separate test group was created at the provider (PO approval 2026-10-07). Only the test account is a member,
  approved only for the stage's OIDC client. The other groups and clients are unchanged.
- Run on a **freshly built** stage (state of `main` after T-18): `passkey: grün · saml: grün · oidc: grün`,
  OIDC signed in as the test account.
- Control run: test account taken out of the group, same run → `oidc: ROT` ("You are not allowed to access
  this service"), exit 1 — red, not skipped. Afterwards membership restored, stage torn down.

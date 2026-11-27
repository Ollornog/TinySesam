---
id: B-18
type: Bug
title: "OIDC unlink leaves the refresh row of the running session"
status: erledigt
points: 2
milestone: M-2
tags: [oidc, accounts, linking]
created: 2026-11-27
---
# B-18 — OIDC unlink leaves the refresh row of the running session

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

**Done (2026-11-27):** `Store.unlink_oidc` deletes the account's `oidc_identity` rows and the `oidc_session` rows of
every session of the account in one transaction and returns both counts; `_unlink_identity` writes
`oidc_unlinked by=holder rechecks_dropped=<n>` and an INFO line in the security log. `tests/test_identity_link.py`
signs in through a stub provider on two devices, shows the provider reached before the unlink, then unlinks: both
rows gone, the next due re-check asks nobody, both sessions answer `/auth/me`. Mutations (all red): no delete of the
rows; only one session's rows; no security-log line; without the rows check the provider is asked twice.

Found in sprint S5 ([T-99](T-99-stage-s3-every-origin-is-equal-source-step-up-linking-l.md), #402). When a person
unlinks an OIDC identity, the refresh row of the running session stays: the re-check keeps asking the provider for an
identity that no longer belongs to the account, until the session ends.

## Content
- Unlinking an OIDC identity drops the refresh rows of that identity for every session of the account (or ends the
  re-check for it), in the same transaction as the unlink.
- Security log line for the dropped rows.

## Acceptance
- A test: link, sign in through the provider, unlink — the next re-check does not reach the provider for the unlinked
  identity, and the session stays valid through the remaining sign-in method. Proven by mutation.

---
id: B-18
type: Bug
title: "OIDC unlink leaves the refresh row of the running session"
status: offen
points: 2
milestone: M-2
tags: [oidc, accounts, linking]
created: 2026-11-27
---
# B-18 — OIDC unlink leaves the refresh row of the running session

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

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

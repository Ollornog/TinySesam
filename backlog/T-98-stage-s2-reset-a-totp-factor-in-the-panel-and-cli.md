---
id: T-98
type: Task
title: Stage S2 — reset a TOTP factor in the panel and CLI
status: offen
milestone: M-4
tags: [admin, totp]
created: 2026-11-23
---
# T-98 — Stage S2 — reset a TOTP factor in the panel and CLI

**Story points:** 2 · **Estimate:** 3–4 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

`PanelActions.reset_totp`, a button in the panel account page (step-up), a CLI command, audit entry. Lets an operator reset a lost TOTP without any application involved (the application route is the approval `tinysesam.account.reset_access` of [T-90](T-90-account-api-for-applications-stage-a-create-read-u.md)).

## Acceptance
- An operator resets a TOTP in the panel and from the CLI; every rule has a mutation proof; English and German texts.

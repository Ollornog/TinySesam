---
id: T-98
type: Task
title: Stage S2 — reset a TOTP factor in the panel and CLI
status: erledigt
points: 2
milestone: M-2
blocked_by: [T-112]
tags: [admin, totp]
created: 2026-11-23
---
# T-98 — Stage S2 — reset a TOTP factor in the panel and CLI

**Done (2026-11-27):** `PanelActions.reset_totp` behind `POST <admin>/api/users/{uid}/totp/reset` (administrators
only, owner model, `_require_fresh`; 409 without a TOTP) and `GET <admin>/api/users/{uid}/totp` for the state; the
panel's account page shows the line "Authenticator app (TOTP)" with "Reset" (own dialog, English and German); the CLI
`tinysesam reset-totp --db <file> <user>`. TOTP and recovery codes go, the TOTP share of the lockout ends, audit lines
`totp_reset_by_admin` (actor), `totp_disable` (holder), `totp_reset_cli`; the panel's reset sends `totp_disabled` to
the holder. The `recovery_codes_enabled=False` warning fires only when the panel is off too. Suite
`tests/test_totp_reset.py`; mutations in the pull request.

**Story points:** 2 · **Estimate:** 3–4 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

`PanelActions.reset_totp`, a button in the panel account page (step-up), a CLI command, audit entry. Lets an operator reset a lost TOTP without any application involved (the application route is the approval `tinysesam.account.reset_access` of [T-90](T-90-account-api-for-applications-stage-a-create-read-u.md)).

## Acceptance
- An operator resets a TOTP in the panel and from the CLI; every rule has a mutation proof; English and German texts.

## Roadmap (2026-11-23)

Waits for the module cut ([T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md)) only to avoid
editing the panel and the CLI while they move; it does not need the server stage.

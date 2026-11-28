---
type: Task
title: 'Administration actions on action pages: area admin, class each'
status: erledigt
points: 21
id: T-147
milestone: M-2
created: '2026-11-28'
---
# T-147 — Administration actions on action pages: area admin, class each

**Story points:** 21 (re-estimated in S8 from 13)

Rest of T-105 (estimated 44 SP, the part that carries Ex4 was built in sprint S7). The action register knows the class `each` but no action uses it yet. Build the administration actions as action pages in the application's name with a way back: TOTP reset, lock/unlock, roles, revoke a key, revoke a program, end another account's session, and a sign-in link instead of "set a password". Each opens with a fresh step-up per action (`each`). Acceptance: Ex4 (or Ex3) drives every one of them from the application and back; no secret in the application.

## Done (S8)

`tinysesam/_admin_actions.py`: the eight actions as entries of scope `admin` in `_actions.ACTIONS`, one page per action
(`GET /auth/act/<name>?target=<account id>`), the confirmed POST `/auth/act/<name>/<ticket>` with a ticket per page,
the step-up of that one action by password, TOTP code or PIN, the rights at the POST (`PanelActions.target`), the
panel's code. Ex4 drives every action from its administration section (`tests/test_headless_browser.py`, X6).
Not in this task: a passkey or a provider (OIDC, SAML) as the confirmation of an action — a person with only those
confirms in the panel.

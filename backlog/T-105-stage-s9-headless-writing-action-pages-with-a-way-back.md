---
id: T-105
type: Task
title: "Stage S9 — headless writing: action pages with a way back"
status: offen
milestone: M-4
blocked_by: [T-98, T-104]
tags: [headless, actions]
created: 2026-11-23
---
# T-105 — Stage S9 — headless writing: action pages with a way back

**Story points:** 21 · **Estimate:** 27–34 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The application draws everything, TinySesam only the pages for secrets and consents.

## Content
- One register of actions shared by administration and the own account, classes `window` / `each`, `return` plus `ts_result`.
- Session handle (single session ending), schema 27 or 28.
- Own action pages: password, TOTP, codes, passkey, PIN, sessions, programs, services, app passwords, keys, address, name. Secrets never travel through the application; writing from another origin only by navigation to an action page. Sign-in link instead of "set a password".

## Acceptance
- **Ex4** headless (JavaScript single-page app behind the server): every write action over an action page in the application's name and back; no secret in the application.

## Added 2026-11-23

From [T-91](T-91-app-frame-and-account-overview.md): ending a single session or program from the application uses
the session handle of this stage (A2).

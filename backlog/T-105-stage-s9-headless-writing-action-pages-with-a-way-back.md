---
id: T-105
type: Task
title: "Stage S9 — headless writing: action pages with a way back"
status: in-arbeit
points: 21
milestone: M-2
blocked_by: [T-98, T-104]
tags: [headless, actions]
created: 2026-11-23
---
# T-105 — Stage S9 — headless writing: action pages with a way back

**Story points:** 21 · **Estimate:** 27–34 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The application draws everything, TinySesam only the pages for secrets and consents.

## Content
- One register of actions shared by administration and the own account, classes `window` / `each`, `return` plus `ts_result`.
- Session handle (single session ending), schema 29 (the schema stood at 28 when the stage began).
- Own action pages: password, TOTP, codes, passkey, PIN, sessions, programs, services, app passwords, keys, address, name. Secrets never travel through the application; writing from another origin only by navigation to an action page. Sign-in link instead of "set a password".

## Acceptance
- **Ex4** headless (JavaScript single-page app behind the server): every write action over an action page in the application's name and back; no secret in the application.

## Added 2026-11-23

From [T-91](T-91-app-frame-and-account-overview.md): ending a single session or program from the application uses
the session handle of this stage (A2).

## Progress (sprint S7, 2026-11-28)

Re-estimated from the code: about 44 SP in all — own action pages with the register 13, session handle 5, Ex4 with its
browser test 8, the five clients normalizing `actions` and the handle 5, the administrator's actions (class `each`,
sign-in link instead of "set a password") 13. This stage carries the acceptance (Ex4) first:

- Part 1 (with part 2 in one pull request): the register (`tinysesam/_actions.py`: scope, class, sections, `fresh`), the route `/auth/act/<name>`, the
  way back with `ts_action`/`ts_result`/`state`, the own action pages from the account page's sections, `actions` in
  `account_overview`/`account.json`, spec §8c.
- Part 2: the session handle (schema 29: table `session_handle`, trigger, kept through a rotation), `POST
  /auth/sessions/end`, the action page `session_end`, `handle`/`end` per session in `account.json`.
- Part 3: example Ex4 and its browser test.

Proposed as follow-ups: the administrator's actions on action pages (scope `admin`, class `each`, sign-in link instead
of "set a password"); the five clients normalizing `actions` and the session handle (spec §8a, vectors).

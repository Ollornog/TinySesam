---
type: Task
title: 'Administration actions on action pages: area admin, class each'
status: offen
points: 13
id: T-147
milestone: M-2
created: '2026-11-28'
---
# T-147 — Administration actions on action pages: area admin, class each

**Story points:** 13

Rest of T-105 (estimated 44 SP, the part that carries Ex4 was built in sprint S7). The action register knows the class `each` but no action uses it yet. Build the administration actions as action pages in the application's name with a way back: TOTP reset, lock/unlock, roles, revoke a key, revoke a program, end another account's session, and a sign-in link instead of "set a password". Each opens with a fresh step-up per action (`each`). Acceptance: Ex4 (or Ex3) drives every one of them from the application and back; no secret in the application.

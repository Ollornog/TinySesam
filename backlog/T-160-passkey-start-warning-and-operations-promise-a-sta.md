---
type: Task
title: Passkey start warning and OPERATIONS promise a start that the router build refuses
status: erledigt
points: 1
id: T-160
milestone: M-5
created: '2026-11-28'
---
# T-160 — Passkey start warning and OPERATIONS promise a start that the router build refuses

**Story points:** 1

With passkey_enabled and without the extra [passkey] the start warning says 'sign-in via this method will fail' and docs/OPERATIONS.md says 'start remains possible', but build_router raises MissingExtra (intended fail-fast, see router.py and tests/test_repo.py). Make warning and table say that the router build stops without the extra. Acceptance: test pins the warning text against the behaviour.

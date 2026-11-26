---
id: T-128
type: Task
title: "Drop the branch for test kits before 0.65 in the release-automation check"
status: offen
milestone: M-2
tags: [ci, kit, cleanup]
created: 2026-11-26
---
# T-128 — Drop the pre-0.65 kit branch

**Story points:** 1 · **Estimate:** 1 h · **Milestone:** [M-2](M-2-after-1-0.md)

Waits for the kit sync to 0.65 or later on main (an open sync pull request). `tests/test_repo.py` accepts both shapes of the release automation's stop (kit before 0.65: rc 1 and `::error::`;
from 0.65: rc 0, `::notice::`, "Release automation skipped"), chosen by `tests/_kit/KIT_VERSION`. Once main runs a kit
of 0.65 or later, the old branch is dead code.

## Acceptance
- Only the 0.65+ shape is accepted; a stop with rc 1 turns the check red (mutation).

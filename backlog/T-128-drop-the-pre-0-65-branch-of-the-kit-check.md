---
id: T-128
type: Task
title: "Drop the branch for test kits before 0.65 in the release-automation check"
status: erledigt
milestone: M-5
tags: [ci, kit, cleanup]
created: 2026-11-26
---
# T-128 — Drop the pre-0.65 kit branch

**Done (2026-11-27):** with kit 0.69.0 on main the hygiene test accepts only the 0.65+ halt (rc 0, `::notice::`, "Release automation skipped"); a halt with rc 1 and `::error::` is red (mutation of the kit halt in a probe copy). The kit-version switch `_KIT` is gone, together with the dead pre-0.67 branch of the whole-line allowlist.

**Story points:** 1 · **Estimate:** 1 h · **Milestone:** [M-5](M-5-after-1-0.md)

Waits for the kit sync to 0.65 or later on main (an open sync pull request). `tests/test_repo.py` accepts both shapes of the release automation's stop (kit before 0.65: rc 1 and `::error::`;
from 0.65: rc 0, `::notice::`, "Release automation skipped"), chosen by `tests/_kit/KIT_VERSION`. Once main runs a kit
of 0.65 or later, the old branch is dead code.

## Acceptance
- Only the 0.65+ shape is accepted; a stop with rc 1 turns the check red (mutation).

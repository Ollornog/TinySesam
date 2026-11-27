---
id: T-132
type: Task
title: "Upgrade list for the breaks after 0.31.0"
status: offen
points: 2
milestone: M-2
tags: [release, changelog, hygiene]
created: 2026-11-27
---
# T-132 — Upgrade list for the breaks after 0.31.0

**Story points:** 2 · **Estimate:** 2–3 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Found in sprint S4 (2026-11-27): the upgrade-list check of `tests/test_repo.py` (T-126) compares the breaking commits
from `v0.30.0` up to the FIRST release tag after it — `v0.31.0` exists, so a breaking commit of M-2 is checked by no
list. "Upgrading from 0.30.x" belongs to the 0.31.0 section; whoever updates from 0.31.x to the M-2 release needs a
list of their own. Since T-129 a breaking commit after the latest tag at least needs a mark in `[Unreleased]`.

## Content
- `[Unreleased]` carries "#### Upgrading from 0.31.x" between the upgrade markers (the same text in
  `docs/OPERATIONS.md`) as soon as M-2 brings its first break; the 0.31.0 list keeps its own markers or moves out of
  the check.
- The check takes the range from the latest release tag to `HEAD` and the list of `[Unreleased]`.

## Acceptance
- A breaking commit after the latest tag not named in the new list turns the hygiene test red (mutation).

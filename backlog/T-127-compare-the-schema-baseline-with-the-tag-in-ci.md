---
id: T-127
type: Task
title: "CI compares the schema baseline with the tag v0.30.0, not only with the checked-in file"
status: erledigt
milestone: M-1
tags: [ci, schema, baseline]
created: 2026-11-26
---
# T-127 — Schema baseline against the tag in CI

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-1](M-1-clean-baseline-and-modules-before-shell-and-headless.md)

`tests/test_schema_baseline.py` compares a fresh database with `tests/fixtures/schema_baseline.json`. The fixture
is generated from the tag v0.30.0, but CI checks out shallow without tags, so CI only compares with the checked-in
file: a fixture edited by hand would go unnoticed.

## Content
- The job that runs the baseline test fetches the tag (`fetch-depth: 0` or a targeted `git fetch --depth=1 origin
  tag v0.30.0`) and regenerates the fixture from it before the comparison.

## Acceptance
- A hand-edited fixture turns CI red (mutation); without the tag the test fails loudly instead of skipping.

---
id: T-138
type: Task
title: "CodeQL findings before the closing PR of a sprint, not only in it"
status: offen
points: 2
milestone: M-5
tags: [ci, codeql, sprint]
created: 2026-11-27
---
# T-138 — CodeQL findings before the closing PR of a sprint

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

The sprint lane ([T-131](T-131-sprint-lane-for-the-heavy-ci-jobs.md)) skips CodeQL, so findings first show in the
closing PR to main and cost one full round (~45 min). It happened in two sprints in a row, both times
`py/side-effect-in-assert` in a new test (S4 #390, S5 #410).

## Content
- Either keep the Python CodeQL analysis in the sprint lane (measure its time first), or add a fast hygiene guard for
  calls with side effects inside `assert` in `tests/`, whichever is cheaper for the same catch.

## Acceptance
- A sprint PR with `assert client.post(...).status_code == 403` is red before the closing PR; the measured time of the
  sprint lane stays below ~6 min.

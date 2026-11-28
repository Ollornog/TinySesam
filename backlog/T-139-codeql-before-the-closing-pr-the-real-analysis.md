---
id: T-139
type: Task
title: "CodeQL before the closing PR of a sprint: the real analysis, not one mirrored rule"
status: offen
points: 2
milestone: M-5
tags: [ci, codeql, sprint]
created: 2026-11-28
---
# T-139 — CodeQL before the closing PR of a sprint: the real analysis, not one mirrored rule

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

Follows [T-138](T-138-codeql-findings-before-the-closing-pr-of-a-sprint.md). The closing PR was red on CodeQL for the
third sprint in a row (S4 #390, S5 #410, S6 #427). T-138's guard mirrors one rule (`py/side-effect-in-assert`); S6
brought three others (`js/polynomial-redos`, `py/bad-tag-filter`, `py/unused-import`). Each costs a full round of the
closing PR (~45 min).

## Content
- Run the real CodeQL analysis (Python and JavaScript) before the closing PR, compared against `main`: either in the
  sprint lane with `main` as the comparison base, or as a separate CodeQL-only check a sprint can start on demand.
- Measure the added time of the sprint lane.

## Acceptance
- A sprint PR that adds a `js/polynomial-redos` or `py/bad-tag-filter` finding is red before the closing PR; findings
  already on `main` do not turn it red.

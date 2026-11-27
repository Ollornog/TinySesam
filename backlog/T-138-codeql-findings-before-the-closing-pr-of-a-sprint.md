---
id: T-138
type: Task
title: "CodeQL findings before the closing PR of a sprint, not only in it"
status: erledigt
points: 2
milestone: M-5
tags: [ci, codeql, sprint]
created: 2026-11-27
---
# T-138 — CodeQL findings before the closing PR of a sprint

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

**Done (2026-11-27):** a hygiene guard, not CodeQL in the sprint lane. Measured: the Python CodeQL job on `main` took
1:52–2:31 min (four runs 2026-11-27), a sprint pull request's lane 1:51–2:24 min (`repeat`, pull requests #401–#407);
CodeQL in the lane would have fit below 6 min, but it needs a code-scanning analysis of the sprint branch to compare
against (the branch has none, CodeQL runs on `main` only) and costs a further runner job per push. `tests/test_repo.py`
now mirrors the query `Statements/SideEffectInAssert.ql` (the same names, `subprocess` calls and yields) over every
tracked Python file in about half a second, with a self-probe; it runs in the sprint lane (the hygiene test of
`repeat`) and in the pre-push hook, so the finding is red before the push. The rule is mirrored, not widened:
`assert client.post(...).status_code == 403` is no CodeQL finding (`post` is not among its names) and no finding here —
the acceptance below is met with the two real cases (`delete(...)`, S5; `write(...)`, S4). No finding in the
inventory. Proved by mutation in the pull request and by a sprint pull request turned red with such an assert.

The sprint lane ([T-131](T-131-sprint-lane-for-the-heavy-ci-jobs.md)) skips CodeQL, so findings first show in the
closing PR to main and cost one full round (~45 min). It happened in two sprints in a row, both times
`py/side-effect-in-assert` in a new test (S4 #390, S5 #410).

## Content
- Either keep the Python CodeQL analysis in the sprint lane (measure its time first), or add a fast hygiene guard for
  calls with side effects inside `assert` in `tests/`, whichever is cheaper for the same catch.

## Acceptance
- A sprint PR with `assert client.post(...).status_code == 403` is red before the closing PR; the measured time of the
  sprint lane stays below ~6 min.

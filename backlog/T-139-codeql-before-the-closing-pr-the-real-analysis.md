---
id: T-139
type: Task
title: "CodeQL before the closing PR of a sprint: the real analysis, not one mirrored rule"
status: erledigt
points: 2
milestone: M-5
tags: [ci, codeql, sprint]
created: 2026-11-28
---
# T-139 — CodeQL before the closing PR of a sprint: the real analysis, not one mirrored rule

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

**Done (2026-11-28):** CodeQL in the sprint lane, compared with `main` through the code-scanning API. A pull request
into `sprint/<name>` runs the job `sprint` of `codeql.yml` (Python and JavaScript, the scope and query suite of
`analyse` / `analyse-js`, read permission only) with `upload: never`; `scripts/_codeql_sprint.py` downloads the SARIF
of `main`'s newest analysis of the category and of the one at the merge base and compares by rule, file and CodeQL's
`primaryLocationLineHash` as a multiset. No upload, because the sprint branch has no analysis of its own for GitHub's
check to compare against. Go and Rust stay with the closing pull request. Measured on #429: CodeQL sprint (python)
2:26 min, (javascript-typescript) 1:06 min, beside `repeat` 1:57 min — the lane's wall time grows by about half a
minute. Acceptance probe #430 (closed, not merged): `py/bad-tag-filter` in a new script → python job red with 1 new
of 9 (26 on `main`, all silent); the S6 `js/polynomial-redos` back in `registerRequest` → JavaScript job red with 2 new
(plus the then unused helper). A finding only reachable from a function not exported through `index.ts` is no
`js/polynomial-redos` finding at all (CodeQL's "library input" is the package's entry), so the probe used the real S6
line. `tests/test_codeql_sprint.py` checks the comparison, the choice of analyses and the workflow; six mutations red.

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

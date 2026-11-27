---
id: T-131
type: Task
title: "Sprint lane for the heavy CI jobs (classifier in the workflows)"
status: erledigt
points: 3
milestone: M-5
tags: [ci, kit]
created: 2026-11-27
---
# T-131 — Sprint lane for the heavy CI jobs

**Story points:** 3 · **Estimate:** 3–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

**Done (2026-11-27):** a job `classify` in `ci.yml`, the four client workflows, `audit.yml` and `release.yml` runs
`scripts/_nur_text.sh` on the merge commit; `full`, `minimal`, `browser`, `gate-caddy`, the client legs, `audit`,
`verify`, `image-probe` and `rehearsal-targets` carry the kit's fail-safe gate, every job after them skips with them;
`repeat` stays ungated (its `scripts/check.sh` runs the fast checks). The aggregates count a skipped job green only
with `nur_text=ja`. CodeQL already ran only on pull requests into `main`. `tests/test_ci_aggregate.py` checks the
gating of every job and runs the classifier and the aggregate's script; mutations in the pull request. Like the
kit's docs fast lane, a pull request of text only skips the heavy jobs as well.

Found in sprint S4 (2026-11-27, pull request #378): a pull request into `sprint/<name>` takes the shared kit's sprint
lane (0.68) only where `scripts/check.sh` runs — the job `repeat` printed "SPRINT LANE" and ran the fast checks. Every
other job (`full` ×3, `minimal`, `browser`, `gate-caddy`, the client workflows, audit, release rehearsal, CodeQL) runs
in full, because none of TinySesam's workflows has a classifier job that asks `scripts/_nur_text.sh` and gates the
heavy jobs with `needs.<job>.outputs.nur_text != 'ja'`. A sprint pull request therefore costs as long as one into
`main` (about 45 minutes).

## Content
- A classifier job per workflow (or one reusable one) that runs `scripts/_nur_text.sh` on the pull request's merge
  commit and outputs `nur_text`; the heavy jobs get the kit's fail-safe `if:` form
  (`!cancelled() && needs.<job>.outputs.nur_text != 'ja'`), which `hygiene.pruefe_nur_text` checks.
- The aggregate jobs (`suite-ok`, `client-*-ok`) treat a skipped job of the sprint lane as green, a failed one as red.
- Main and the closing pull request run everything as before.

## Acceptance
- A pull request into `sprint/*` runs only the fast checks (job log "SPRINT LANE", heavy jobs skipped); a pull request
  into `main` runs the full suite; the hygiene test's check of the `if:` form is green and red on a mutated form.

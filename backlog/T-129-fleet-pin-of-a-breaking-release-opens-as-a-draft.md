---
id: T-129
type: Task
title: "The fleet pin of a breaking release opens as a draft"
status: offen
milestone: M-5
tags: [ci, release, rollout]
created: 2026-11-26
---
# T-129 — Fleet pin of a breaking release as a draft

**Story points:** 2 · **Estimate:** 2–3 h · **Milestone:** [M-5](M-5-after-1-0.md)

The job `fc-pin` of `release.yml` opens a pin pull request in the maintainer's deployment repository after every tag;
its auto-merge takes it once the checks are green. For 0.31.0, a breaking release, the pin was merged seven minutes
after it opened, before the maintainer could hold it, and had to be reverted: a breaking release changes what operators
must do (API keys issued anew), so its rollout is a decision, not an automatism.

## Content
- `scripts/_release_automatik.py fc-pin` opens the pull request as a draft when the release is breaking: the first line
  of its CHANGELOG section says "breaking", or the section has an "Upgrading from" list.
- The job summary says why it is a draft and what to do (mark it ready to roll out).

## Acceptance
- A rehearsal with a breaking CHANGELOG section produces a draft request, a normal one does not (test); dropping the
  condition turns the test red (mutation).

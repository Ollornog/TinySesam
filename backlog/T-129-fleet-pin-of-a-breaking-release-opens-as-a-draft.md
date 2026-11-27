---
id: T-129
type: Task
title: "The fleet pin of a breaking release opens as a draft"
status: erledigt
milestone: M-2
tags: [ci, release, rollout]
created: 2026-11-26
---
# T-129 — Fleet pin of a breaking release as a draft

**Story points:** 2 · **Estimate:** 2–3 h · **Milestone:** [M-5](M-5-after-1-0.md)

The job `fc-pin` of `release.yml` opens a pin pull request in the maintainer's deployment repository after every tag;
its auto-merge takes it once the checks are green. For 0.31.0, a breaking release, the pin was merged seven minutes
after it opened, before the maintainer could hold it, and had to be reverted: a breaking release changes what operators
must do (API keys issued anew), so its rollout is a decision, not an automatism.

## Content (rewritten 2026-11-27)

The hold belongs where the merge happens, not in the job that opens the pull request: since shared test kit 0.69.0
(the FleetCommander incident of 0.31.0) the deployment repository's auto-merge holds a pin pull request as a draft when
the release is breaking — the major differs (at 0.x the minor), or the source repository's CHANGELOG gains a line with
`breaking`, `Upgrading from` or `Upgrade-Hinweis` between the old and the new tag, or anything of it cannot be read
(fail safe). `fc-pin` lives in the kit (`scripts/_release_automatik.py`, not edited here), so a draft at the source
would be a second copy of the same rule in another place.

What TinySesam owes the kit's rule: a breaking release must carry the mark. `tests/test_repo.py` reads the marks from
the generated auto-merge (so they follow the kit) and is red when a breaking commit (`type!:`, `BREAKING CHANGE:`)
landed since the latest release tag while `## [Unreleased]` has no line with a mark — a breaking 1.x minor or patch
would otherwise reach the fleet unseen.

## Acceptance
- A breaking commit since the latest tag without a mark in `[Unreleased]` turns the hygiene test red (mutation: a
  `feat(x)!:` commit in a probe clone with the word removed); with the mark it is green.

**Done (2026-11-27):** as above; the job summary of `fc-pin` stays the kit's.

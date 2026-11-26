---
id: T-126
type: Task
title: "Breaking release after the baseline, with one upgrade list"
status: offen
milestone: M-5
tags: [release, upgrade, breaking]
created: 2026-11-26
---
# T-126 — Breaking release after the baseline

**Story points:** 3 · **Estimate:** 3–5 h · **Milestone:** [M-5](M-5-clean-baseline-and-modules-before-shell-and-headless.md)

M-5 changed what an operator must do on update in several places at once. The first release after it ships all of it
together, so that users re-issue credentials only once.

## Content
- One "Upgrading from 0.30.x" list in `CHANGELOG.md` and `docs/OPERATIONS.md` ("Updating"), collecting:
  - a database below schema 26 and non-v2 vault values are refused at start (T-111) — update through 0.30.0 first;
  - gate keys of kind `derived-v1` are refused — retire them with `tinysesam keys retire --purpose gate --kid …` on
    0.30.x before the update;
  - API keys, one-time tokens and QR secrets are keyed with the pepper (T-72): re-issue them;
  - recovery codes are keyed with the pepper: users generate new ones;
  - a gate code exchange running during the update (at most 10 minutes) fails once;
  - the removed tier-C aliases (T-111), with their replacements.
- A `tinysesam diagnose` check (or the start error) names each blocking item with its command, so an operator does not
  need the list to find out.
- The release itself is the maintainer's (`scripts/_release.py`).

## Acceptance
- A 0.30.0 database with a `derived-v1` gate key and an old API key: the new version refuses to start and names the
  retire command; after the retire it starts and the old key is rejected with a clear reason (test).
- The upgrade list names every breaking entry of `[Unreleased]` (a hygiene check compares the `!` commits since
  v0.30.0 with the list, or the list is reviewed in the release pull request).

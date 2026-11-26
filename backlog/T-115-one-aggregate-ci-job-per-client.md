---
id: T-115
type: Task
title: "One aggregate CI job per client, so required checks do not depend on matrix names"
status: erledigt
milestone: M-5
tags: [ci, branch-protection]
created: 2026-11-23
---
# T-115 — One aggregate CI job per client, so required checks do not depend on matrix names

**Story points:** 2 · **Estimate:** 2–3 h · **Milestone:** [M-5](M-5-after-1-0.md)

The required checks of the branch protection carry matrix names (`test (php 8.4)`, `client-go (stable)`,
`test (node lts/*)` …). Changing a matrix silently blocks every merge until someone updates the protection.

## Content
- A final job per client workflow (`client-go-ok`, `client-rust-ok`, `client-js-ok`, `client-php-ok`, and the same for
  the main suite matrix) that `needs` the matrix and fails if any leg failed or was cancelled; a skipped leg counts as
  not green.
- The required checks point at these jobs only; the maintainer switches the protection in the same change.

## Acceptance
- Adding or removing a matrix leg needs no change of the branch protection (shown once in a test pull request); a red
  leg turns the aggregate red.

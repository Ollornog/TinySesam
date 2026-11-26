---
id: B-17
type: Bug
title: "Scorecard red: the image of scorecard-action 2.6.0 cannot be pulled (upstream)"
status: offen
milestone: M-5
tags: [ci, supply-chain, upstream]
created: 2026-11-26
---
# B-17 — Scorecard red on main

**Story points:** 1 · **Estimate:** 1 h · **Milestone:** [M-5](M-5-after-1-0.md)

The `scorecard` workflow fails since scorecard-action 2.6.0: its image index on ghcr points at deleted manifests
(ossf/scorecard-action#1752).

## Content
- Wait for the upstream fix until 2026-11-27. Without one: pin v2.5.0 by SHA, ignore 2.6.0 in Dependabot, and undo
  both once upstream is fixed.

## Acceptance
- `scorecard` green on main; the Dependabot ignore (if set) carries the upstream issue as the reason to remove it.

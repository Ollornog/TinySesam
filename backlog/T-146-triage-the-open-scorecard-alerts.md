---
id: T-146
type: Task
title: "Triage the open Scorecard alerts"
status: offen
points: 2
milestone: M-5
tags: [ci, scorecard]
created: 2026-11-28
---
# T-146 — Triage the open Scorecard alerts

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

15 Scorecard alerts are open in code scanning: 11 × Pinned-Dependencies (workflows, Dockerfile), one each for
Code-Review, Fuzzing, Vulnerabilities and CII-Best-Practices. The hygiene test guards nine achieved criteria.

## Content
- Fix the Pinned-Dependencies findings that are real; record the others with a reason (or a backlog entry) instead of
  leaving them open.

## Acceptance
- No open Scorecard alert without a fix or a recorded reason.

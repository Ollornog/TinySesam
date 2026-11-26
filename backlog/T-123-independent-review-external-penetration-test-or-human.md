---
id: T-123
type: Task
title: "Independent review: an external penetration test or a human code review"
status: offen
points: 3
milestone: M-3
blocked_by: [T-122]
tags: [security, review, launch]
created: 2026-11-23
---
# T-123 — Independent review: an external penetration test or a human code review

**Story points:** 3 · **Estimate:** 6–10 h own work (preparation, fixes are entries of their own) · **Milestone:** [M-3](M-3-trust-hardening-and-launch.md)

Every audit so far was done by the project itself. Before TinySesam is promoted widely
([T-30](T-30-launch-plan.md)) a human outside the project should look at it.

## Content
- Scope at least: sign-in and step-up, sessions and tokens, the OAuth authorization server, the gate and forward auth,
  the account and approval API.
- Brief from the threat model ([T-122](T-122-public-threat-model.md)), a probe installation, the test kit.
- Findings become `B-` entries; the report (or its summary) is published with the fixes.

## Acceptance
- A review report exists, every finding is fixed or accepted with a reason, the README label changes from "hardened,
  not independently reviewed" to naming the review.

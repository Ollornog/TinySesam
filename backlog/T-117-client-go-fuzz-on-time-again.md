---
id: T-117
type: Task
title: "client-go: fuzz on time again once Go fixes the deadline report"
status: offen
points: 1
milestone: M-5
tags: [clients, go, fuzzing]
created: 2026-11-23
---
# T-117 — client-go: fuzz on time again once Go fixes the deadline report

**Story points:** 1 · **Estimate:** 0.5–1 h · **Milestone:** [M-5](M-5-after-1-0.md)

`.github/workflows/client-go.yml` fuzzes with a count (`-fuzztime=300000x`) because the coordinator reports its own
deadline as a failure (golang/go#75804). Fixed upstream for Go 1.26.12 and 1.27.5.

## Content
- When both supported Go lines carry the fix, go back to a duration and remove the comment.

## Acceptance
- Fuzz step on a duration, green on stable and oldstable; the backlog entry closes with the Go version.

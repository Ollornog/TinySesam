---
id: T-114
type: Task
title: "Proxy test image: nginx on the stable line instead of mainline"
status: erledigt
milestone: M-5
tags: [ci, proxies, dependencies]
created: 2026-11-23
---
# T-114 — Proxy test image: nginx on the stable line instead of mainline

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-5](M-5-after-1-0.md)

`tests/proxies/Dockerfile` follows nginx mainline (1.31.x) since a Dependabot bump; the project rule is the newest
**stable** release. Templates are measured against what operators run.

## Content
- Pin the stable line (`stable-alpine` with digest, 1.30.x at the time of writing).
- Limit Dependabot for this file to the stable line (an `ignore` for the mainline minor or a version rule).

## Acceptance
- The proxy suites run against nginx stable; a Dependabot run does not propose mainline again.

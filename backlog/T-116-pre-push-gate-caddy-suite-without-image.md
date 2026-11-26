---
id: T-116
type: Task
title: "Pre-push: the gate-Caddy suite without its image counts as red"
status: erledigt
milestone: M-5
tags: [tests, pre-push]
created: 2026-11-23
---
# T-116 — Pre-push: the gate-Caddy suite without its image counts as red

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-5](M-5-after-1-0.md)

`tests/test_gate_caddy.py` skips without `TINYSESAM_GATE_CADDY`, and the fast pre-push counts the skip as red (a
skip is not a green). Every change near the gate then needs the full gate or a manual image.

## Content
- Either the hook builds the Caddy-with-caddy-jwt test image once and caches it by digest (like the proxy test
  images), or the fast gate selects the suite only when the image is available and says so loudly; the full gate and
  CI always run it.
- Document the decision in `CONTRIBUTING.md`.

## Acceptance
- A change in `deploy/forward-auth/` runs the suite in the fast gate on a machine with Docker; without Docker the hook
  names the missing tool instead of reporting a red test.

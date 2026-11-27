---
id: T-137
type: Task
title: "Declare the optional imports: requests in client.py, websockets in tools/oauth-e2e"
status: offen
points: 1
milestone: M-5
tags: [dependencies, packaging]
created: 2026-11-27
---
# T-137 — Declare the optional imports

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-5](M-5-after-1-0.md)

The unused-dependency check notes two imports without a declaration: `requests` in `tinysesam/client.py` (optional,
imported only when used) and `websockets` in `tools/oauth-e2e`. Today they are notes, not findings.

## Content
- `requests` as an extra (or a documented optional import with the exception and its reason in
  `.github/abhaengigkeiten.json`); `websockets` declared for the tool.

## Acceptance
- The check lists neither import as a note any more.

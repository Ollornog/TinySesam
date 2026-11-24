---
id: T-103
type: Task
title: "Stage S7 — shell on top and at the side: one component, layout top or side"
status: offen
points: 13
milestone: M-4
blocked_by: [T-97]
tags: [shell, ui, topbar]
created: 2026-11-23
---
# T-103 — Stage S7 — shell on top and at the side: one component, layout top or side

**Story points:** 13 · **Estimate:** 24–32 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

One component for both shells: `<ts-shell layout="top|side" current="/docs">`, script and CSS under `/.tinysesam/` (server) or `/auth/` (library), shadow DOM and `--ts-*` tokens. Data from `topbar.json` plus a new `frame` part. The layout comes from `apps[id].layout` or an instance field. TinySesam's own pages (panel and account page included) get the side layout, too — the same markup source as `topbar.py`.

## Content
- `auth.topbar(layout=…)` in the library; proxy templates pass `/.tinysesam/*` through; spec section 8d.
- Replaces the planned "E8" shell component of the app frame ([T-91](T-91-app-frame-and-account-overview.md)).

## Acceptance
- **Ex1** as surface "shell on top" (Go, server) and **Ex2** as surface "shell at the side" (Python, library): browser test at 375 and 1280 px, light and dark, strict CSP, no console errors, role and permission links.

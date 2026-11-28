---
id: T-103
type: Task
title: "Stage S7 — shell on top and at the side: one component, layout top or side"
status: erledigt
points: 14
milestone: M-2
blocked_by: [T-97]
tags: [shell, ui, topbar]
created: 2026-11-23
---
# T-103 — Stage S7 — shell on top and at the side: one component, layout top or side

**Story points:** 14 · **Estimate:** 24–32 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

One component for both shells: `<ts-shell layout="top|side" current="/docs">`, script and CSS under `/.tinysesam/` (server) or `/auth/` (library), shadow DOM and `--ts-*` tokens. Data from `topbar.json` plus a new `frame` part. The layout comes from `apps[id].layout` or an instance field. TinySesam's own pages (panel and account page included) get the side layout, too — the same markup source as `topbar.py`.

## Content
- `apps[id].layout` (`top` | `side`), taken over from [T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md)
  on 2026-11-27: it enters the configuration together with its reader, the shell component (no own SP: the layout
  switch is this task's content already).
- `auth.topbar(layout=…)` in the library; proxy templates pass `/.tinysesam/*` through; spec section 8d.
- Browser test of the permission matrix of [T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md)
  (danger step-up, area administrator sees only the own area): T-100 checked it by screenshot only; added 2026-11-27,
  +1 SP.
- Replaces the planned "E8" shell component of the app frame ([T-91](T-91-app-frame-and-account-overview.md)).

## Acceptance
- **Ex1** as surface "shell on top" (Go, server) and **Ex2** as surface "shell at the side" (Python, library): browser test at 375 and 1280 px, light and dark, strict CSP, no console errors, role and permission links.

## Closed 2026-11-28

Done in three pull requests into the sprint branch of S6:

- **Part 1** (#422): `shell_layout`, `apps[id].layout` (with its reader), `auth.topbar(layout=…)`, the side layout of
  TinySesam's own pages (panel and account page included) from `topbar.py`; the component `<ts-shell>`
  (`/.tinysesam/shell.js`, `/auth/shell.js`, `shell.css`) with the part `frame` of `topbar.json` (spec §8d); links by
  permission; Ex2 as "shell at the side". The browser test proves that the component draws exactly the markup of
  `topbar.py` (sign-out by design a link).
- **Part 2** (#423): Ex1 as "shell on top" — the Go pages load the component; the whole stack (server from
  `deploy/ex1/tinysesam.toml`, Go program, forward-auth proxy) in Chrome at 375 and 1280 px, light and dark.
- **Part 3**: the browser test of the permission matrix of T-100 (a dangerous permission asks for a step-up, an area
  administrator sees only the own area).

The planned shell component "E8" of T-91 is this component. `apps[id].icon` stays with
[T-104](T-104-stage-s8-hybrid-tinysesam-area-with-name-and-icon-libra.md).

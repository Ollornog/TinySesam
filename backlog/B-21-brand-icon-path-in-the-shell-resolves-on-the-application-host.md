---
id: B-21
type: Bug
title: "A brand_icon path in the shell logo resolves on the application's host"
status: offen
points: 2
milestone: M-2
tags: [shell, branding]
created: 2026-11-28
---
# B-21 — A brand_icon path in the shell logo resolves on the application's host

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Found in [T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md): the shell component runs on the
application's page, so a relative `brand_icon` loads from the application's host, not from TinySesam's.

## Content
- `topbar.json` gives the icon as an absolute URL on TinySesam's base (or under `/.tinysesam/`).

## Acceptance
- Browser test: Ex1 with a relative `brand_icon` shows the logo, no broken request. Proven by mutation.

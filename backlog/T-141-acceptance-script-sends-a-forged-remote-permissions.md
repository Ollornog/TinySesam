---
id: T-141
type: Task
title: "Proxy acceptance script sends a forged Remote-Permissions"
status: erledigt
points: 1
milestone: M-2
tags: [forward-auth, deploy, permissions]
created: 2026-11-28
---
# T-141 — Proxy acceptance script sends a forged Remote-Permissions

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

`deploy/forward-auth/acceptance.sh` checks forged `Remote-*` headers against a running proxy; `Remote-Permissions`
([T-101](T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md)) is only checked by the text test of the
templates.

## Content
- The acceptance script sends a forged `Remote-Permissions` without and with a session and expects the proxy to
  overwrite or drop it.

## Acceptance
- Against a template without the header line the script is red.

## Done (S9)

`acceptance.sh`: a self-sent `Remote-Permissions` opens nothing; with `ECHO=1` a forged one never reaches the
application on the share path or with a session. `tests/test_acceptance_script.py` runs the script against a stand-in
proxy — green when it strips, red when it passes the client's `Remote-Permissions` (or `Remote-Kind`) on;
`tests/test_gate_caddy.py` counts the three checks against Caddy and its counter-check (no stripping proxy) names both
red lines. Mutation: the gate template without its two strip lines turns `test_gate_caddy.py` red.

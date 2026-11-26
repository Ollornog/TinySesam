---
id: T-108
type: Task
title: "Stage S12 (optional) — fully headless library: register, reset password, setup status"
status: offen
points: 5
milestone: M-2
blocked_by: [T-96, T-112]
tags: [library, headless, optional]
created: 2026-11-23
---
# T-108 — Stage S12 (optional) — fully headless library: register, reset password, setup status

**Story points:** 5 · **Estimate:** 8–10 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Building blocks `register`, `reset_password`, `setup_status`; JSON for TOTP start, magic-link request, QR start. Only for the library (one trust boundary); a server application never types a secret itself.

## Acceptance
- A variant of Ex2 with no built-in page except the consent pages.

## Roadmap (2026-11-23)

Waits for the module cut ([T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md)): the new
building blocks go into their feature module.

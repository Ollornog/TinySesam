---
id: T-110
type: Task
title: "Dependency diet: joserfc instead of authlib.jose, QR as SVG without Pillow, SAML as its own image variant"
status: offen
milestone: M-4
tags: [dependencies, supply-chain]
created: 2026-11-23
---
# T-110 — Dependency diet: joserfc instead of authlib.jose, QR as SVG without Pillow, SAML as its own image variant

**Story points:** 5 · **Estimate:** 8–12 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Cheap supply-chain gains found by the Python-versus-Go analysis ([ADR-15](ADR-15-python-core-stays-clients-stay-thin-no-go-rewrite.md)); independent of the stages.

## Content
- Replace `authlib.jose` by `joserfc` (already a dependency of `[services]`). Check that the ID token validation keeps every rule: fixed algorithm, `exp` required, `azp`.
- Draw the QR code as SVG through `qrcode` without Pillow (drops a large C library).
- SAML (`python3-saml`, lxml, xmlsec, libxmlsec1) only in its own image variant; check that it builds on the distroless base.

## Acceptance
- Gateway image without Authlib and Pillow, all tests green, pip-audit and image scan show the smaller surface; mutation proof for the token rules.

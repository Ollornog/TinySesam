---
id: T-110
type: Task
title: "Dependency diet: joserfc instead of authlib.jose, QR as SVG without Pillow, SAML as its own image variant"
status: offen
points: 5
milestone: M-3
blocked_by: [T-112]
tags: [dependencies, supply-chain]
created: 2026-11-23
---
# T-110 — Dependency diet: joserfc instead of authlib.jose, QR as SVG without Pillow, SAML as its own image variant

**Story points:** 5 · **Estimate:** 8–12 h (from the concept, not measured) · **Milestone:** [M-3](M-3-trust-hardening-and-launch.md)

Cheap supply-chain gains found by the Python-versus-Go analysis ([ADR-15](ADR-15-python-core-stays-clients-stay-thin-no-go-rewrite.md)); independent of the stages.

## Content
- Replace `authlib.jose` by `joserfc` (already a dependency of `[services]`). Check that the ID token validation keeps every rule: fixed algorithm, `exp` required, `azp`.
- Draw the QR code as SVG through `qrcode` without Pillow (drops a large C library).
- ~~SAML only in its own image variant~~ — moved to T-97 (see below).

## Acceptance
- Gateway image without Authlib and Pillow, all tests green, pip-audit and image scan show the smaller surface; mutation proof for the token rules.

## Roadmap (2026-11-23)

Moved to [M-3](M-3-trust-hardening-and-launch.md) (later, not on the critical path). The SAML image variant is part of
[T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md) (the server builds both images); this entry
keeps joserfc and the QR code without Pillow.

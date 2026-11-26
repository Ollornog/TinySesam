---
id: ADR-19
type: Decision
title: "Gate look like a provider sign-in: heading and icon of the application, no look per host"
status: erledigt
tags: [architecture, gateway, ui]
created: 2026-11-23
---
# ADR-19 — Gate look: "Sign in to <application>" with the application's icon

## Context
The concept had a stage "look per host": validated tokens and a logo per application on TinySesam's pages. [T-91](T-91-app-frame-and-account-overview.md) decided "one style for the gateway; no per-application CSS". When TinySesam is built into an application (library), it takes the look of the application. As a gate in front of applications it may look like itself.

## Decision
- **Library:** the look of the application (as today, [T-61](T-61-c22-adapter-same-look-as-a-c22-app.md)).
- **Gate:** one independent look per instance, like a hosted sign-in of an identity provider: a heading "Sign in to <application>" and the application's icon. Per application only a **name and an icon** (`apps[id].name`, `apps[id].icon`, served from TinySesam's own origin, no external resource).
- **No look per host**, no tokens or CSS per application. The planned stage shrinks to name and icon.
- The T-91 decision "one style for the gateway" stays valid; this adds name and icon. The icon wish noted in [M-6](M-6-gate-in-front-of-third-party-apps.md) (icon on the login page) is fulfilled here.
- The side shell also applies to panel and account page ([T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md)).

## Consequences
[T-104](T-104-stage-s8-hybrid-tinysesam-area-with-name-and-icon-libra.md) carries name and icon instead of the look per host; the cost is smaller than first estimated.

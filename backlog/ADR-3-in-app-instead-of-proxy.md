---
id: ADR-3
type: Decision
title: Protection in the app per route, not at proxy level
status: erledigt
tags: [architecture, auth, forward-auth]
created: 2026-07-06
---

# ADR-3 — Protection in the app, not at proxy level

## Context

Two common patterns: forward auth at the reverse proxy (like Authelia, oauth2-proxy) or a
dependency on the individual route in the application.

## Decision

**In the app, per route** (dependency on the route or on a sub-router). The web server
only terminates TLS and passes all paths through.

## Rationale

For **your own** applications this is the right seam: public previews stay open
while individual areas require sign-in — both in the same deployment, without a
proxy having to replicate the path patterns. A proxy solution lags behind with every new route.

## Consequences

- For **third-party** applications that cannot be touched, there is additionally the forward-auth mode
  (`/auth/forward`, `/auth/verify`, gateway preset). That is a **separate operating mode**, not a
  replacement for the basic model.
- OIDC `state`/`nonce` and the WebAuthn challenge live server-side in the store, not in the client.

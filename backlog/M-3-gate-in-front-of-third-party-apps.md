---
id: M-3
type: Milestone
title: Gate in front of third-party apps — fast, sign in once, sign out cleanly
status: erledigt
tags: [gateway, forward-auth, sso]
created: 2026-10-03
---

# M-3 — Gate in front of third-party apps

**Done when:** a third-party app behind the gate loads its assets without a TinySesam hop, a person signs in
exactly once (at the provider), optionally signs out of only the app or of everything, and share paths work without
sign-in — all configurable per app and proven with an acceptance test.

Decision: [ADR-9](ADR-9-gate-token-at-the-proxy.md). Tasks T-19 to T-24.

## Done 2026-10-07

T-19 to T-24 and B-2. Open as a wish, without a task: an icon of the application on the login page (T-21),
nginx and Traefik counterparts to `Caddyfile.gate` (ADR-9).

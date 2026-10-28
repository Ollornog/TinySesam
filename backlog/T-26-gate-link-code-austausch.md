---
id: T-26
type: Task
title: Central gateway with code exchange — session stays on the gateway, app hosts only get a connection of their own
status: erledigt
milestone: M-3
tags: [gateway, cookies, sicherheit]
created: 2026-10-07
---

# T-26 — Code exchange for a central gateway

**Occasion (PO 2026-10-07):** One TinySesam is to protect many apps centrally. With `cookie_domain` on the
parent domain the session cookie reached every app below it — also via a route past the proxy (mesh,
split DNS) —, and an app that is not trusted would thereby have the door to all the others. PO decision: the
secure route, not the shared cookie. This brings back the code exchange from the first draft of
[ADR-9](ADR-9-gate-token-am-proxy.md), which T-19 had struck as "not needed" — for a gateway
per app host that was right, for a central one it was not.

## Done 2026-10-07

- `gate_link_enabled`, table `gate_link` (schema 14), routes `/.tinysesam/start`, `/auth/gate/authorize`,
  `/.tinysesam/callback`; `/auth/forward`, sign-out and "Continue as …" read the connection.
- Test `tests/test_gate_link.py` with two separate cookie stores per host (17 checks), 10 mutations
  red (host binding of the connection, binding and host of the code, single use, `rd`, "signed out here only",
  sign out everywhere, rotation, link mode of the sign-in URL, configuration check).
- Not run through a real Caddy: the new routes lie under `/.tinysesam/*`, which the templates already pass
  to TinySesam (measured there through Caddy); the flow across two hosts follows at the first rollout
  (acceptance with `deploy/forward-auth/abnahme.sh`).

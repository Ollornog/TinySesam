---
id: T-22
type: Task
title: "Logout mode per app: app, all, ask — chain via the provider back to the gate"
status: erledigt
milestone: M-3
tags: [gateway, oidc, logout]
created: 2026-10-03
---

# T-22 — Logout modes

The provider finding is in [ADR-9](ADR-9-gate-token-at-the-proxy.md) (consequences).

**To do:**
- `/.sesam/logout?scope=app` — delete the gate cookie of this host, discard the approval of this app in the
  session; provider and other apps stay signed in. For this the app redirects **directly** here,
  without calling the provider (whose end-session always ends the provider session).
- `/.sesam/logout?scope=all` — target of the chain app → provider end-session → **Logout Callback URL** →
  here: end **all** TinySesam sessions of the user, delete the gate cookie; if the gate itself is
  called, additionally RP logout at the provider. Check `state`, target only from `trusted_redirect_hosts`.
- `fragen` (ask) — page with "Only *App X*" and "Sign out everywhere" (for apps that only know one logout URL).
- `oidc_rp_logout=True` as default in the gateway preset.
- Docs: checklist per app (logout target in the app, Logout Callback URL at the provider, mode in the gate).

**Done when:** browser test: `app` → this app demands login, a second app stays open; `alle` (all) →
provider signed out, both gates closed after ≤ one token lifetime (its own immediately); no open
redirect via `scope`/target; mutation per branch.

## Done 2026-10-07

Values in English: `forward_logout = "all" | "app" | "ask"` (default `all`), per host in `forward_apps`.

- `all` ends **this** session (it carries every application behind the same sign-in), not all
  sessions of the account on other devices. "Everywhere" here means: in all applications of this
  browser. Other gate cookies of this browser expire after `gate_token_ttl_sec`.
  *The plan said "all TinySesam sessions of the user". That is a different step ("sign out on all
  devices") and stays with the account panel.*
- `app` needs a lock on the session (`gate_abgemeldet`, schema 13). Without it the forward auth
  would have let the session through again on the next click. It is lifted with "Continue
  as …" (`POST /auth/gate/resume`) or a new sign-in targeting this application. The
  forward auth then always sends to the login page, never directly to the provider (which would
  silently sign in again).
- **`id_token_hint`:** Without it PocketID (v2.17.0) does not end its session. TinySesam stores
  the ID token encrypted (`oidc_id_token`) and sends it together with the `client_id` of the client of the sign-in.
- Routes on the app host: `/.tinysesam/logout` (GET/POST), `/.tinysesam/after-logout` (return path from the
  provider, ends a still living session — chain starting from the application). Cross-site: ask first.
- Docs: checklist per application in `docs/OPERATIONS.md`.
- Test: `tests/test_logout_modes.py`, `tests/test_gate_caddy.py` (sign-out through Caddy). 9 mutations red.

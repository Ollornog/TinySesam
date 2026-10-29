---
id: ADR-9
type: Decision
title: Gate in front of third-party apps — the proxy verifies a short-lived gate token itself, TinySesam only when issuing
status: erledigt
tags: [architektur, forward-auth, gateway, oidc, sso, logout]
created: 2026-10-03
---

# ADR-9 — Gate token at the proxy instead of a subrequest per request

## Context

For **third-party** applications whose security you do not want to trust, TinySesam stands in front as a gate
(forward-auth mode, [ADR-3](ADR-3-in-app-instead-of-proxy.md) consequences). Today the proxy asks `/auth/forward` for
**every** request — also for every script, stylesheet and icon. In doing so TinySesam looks up the
session in the store, checks the approval per application ([T-14](T-14-multiple-oidc-clients.md)) and the
roles ([ADR-5](ADR-5-roles-in-forward-auth.md)). From operation in front of a third-party app (previously with
another forward-auth service): **the check itself** was the noticeable price, not the network path.

A second annoyance: gate and app each demand their own login.

## Options

1. **Forward auth as before, with a cache in TinySesam** (session hash → result, ~30 s). Cheaper,
   but every request remains a hop through Python.
2. **Path exceptions for assets** (`*.js`, `/static/*`). Rejected: extension matchers are the classic
   hole — app routers serve dynamic content under `/admin/x.css`.
3. **Short-lived, signed gate token that the proxy verifies itself.** TinySesam is only asked
   when the token is missing or expired.

## Decision

**Option 3.**

- **Gate token:** JWT, lifetime 5–10 min (configurable), `aud` = host of the application, `iss` = gateway.
  Ed25519 (`EdDSA`), the proxy knows only the public key. Derived from the installation's base key
  (HKDF), no second secret; `tinysesam gate-key` prints the public part. When
  **issuing**, TinySesam checks everything that `/auth/forward` checks today (session, approval per app, roles) — the token
  is its cached result.
- **Cookie:** host-only on the app host, `HttpOnly`, `Secure`, `SameSite=Lax`, own name.
  The proxy **removes it from the request** before passing it to the app.
- **Issuing on the way back, not via separate routes** (as of 2026-10-07, built with T-19): if
  the token is missing or invalid, the proxy falls back to the existing forward auth
  (`handle_errors 401` → `/auth/forward`). Its 200 carries the new token in the header
  `X-TinySesam-Gate-Cookie`, and the proxy attaches it as `Set-Cookie` to the application's response.
  TinySesam sees the session as before (cookie via `cookie_domain`, which the templates remove before the
  application, B-20).
  *Until 2026-10-07 this contained a separate code exchange (`/.sesam/refresh` → one-time code →
  `/.sesam/callback`) with 307 redirects.* It would have kept the session only on the gateway host,
  but would have needed a second sign-in path next to the existing one, and a POST with an expired token
  would have turned into a GET after several hops anyway. The way back via `/auth/forward` passes the request
  on to the application with method and body — measured with Caddy 2.11.7 (`tests/test_gate_caddy.py`).
  The question of whether the session cookie may sit on the parent domain is thus not new, but that
  of the existing forward auth.
- **Proxy side:** Caddy with the plugin `ggicci/caddy-jwt` (v1.4.0), `sign_alg EdDSA` with the
  public key as Base64 — then the plugin ignores the `alg` in the header (checked in the
  source code). Template `deploy/forward-auth/Caddyfile.gate`. nginx/Traefik counterparts do not
  exist yet.
- **Login once, at the provider:** gate and app are each their own OIDC client at the same provider,
  both restricted to the same group. No shared client: its secret would otherwise sit in the
  third-party app. The app then signs in silently (provider session exists).
- **Login mode per app:** `unsichtbar` (invisible; **default in the gateway**, PO 2026-10-03) redirects directly to the
  provider and back to the start address; `fenster` (window) shows "Sign in to *App X*".
- **Logout mode per app:** `app` · `alle` · `fragen` ([T-22](T-22-logout-modes.md)).
- **Share paths:** exact prefixes per app, before the gate, never by file extension ([T-20](T-20-share-exceptions.md)).

## Consequences

- **Delayed revocation:** a block or logout takes effect at the proxy only when the token expires. The own
  logout path (`/.sesam/logout`) deletes the cookie immediately; other apps follow after ≤ one lifetime.
- **Dependency on the proxy plugin.** Whoever cannot build a plugin stays with `/auth/forward` (it remains
  unchanged).
- **Header auth** (`Remote-User` from the claims) becomes possible, but only for apps that offer it as a mode;
  the proxy **always** removes a `Remote-User` sent along, also on share paths.
- The share exception remains real attack surface of the third-party app — unavoidable, hence narrow.
- Provider finding (PocketID v2.17.0, code `backend/internal/oidc/end_session_*.go`): RP-initiated
  logout with `id_token_hint`, target from the **Logout Callback URLs** stored per client, `state` is
  appended; the provider ends **its own session** in the process; no back-/front-channel logout.

---
type: Task
title: 'Two ways to use TinySesam: app frame on TinySesam''s pages and the own account as data'
status: in-arbeit
id: T-91
milestone: M-2
tags: [topbar, account, frame, gateway, self-service, docs]
created: '2026-11-23'
---
# T-91 — App frame and the own account as data

A team server runs TinySesam as a library in a thin wrapper of its own (OAuth) and as the gate in front of a Go
application on other origins, with local accounts (password, TOTP, passkeys) and its own account management through the
account API (T-90). People land on TinySesam's security pages regularly, and the application wants to show the
security state on its own settings page. The draft (2026-11-23, accepted by the PO with all six recommendations) found
that "the app provides the UI" needs no switch: two building blocks and documentation.

## Decisions (PO 2026-11-23)

- The frame hangs on `forward_apps[host]` (keyed by host, `name` exists), not on `apps[id]`.
- One style for the gateway; no per-application CSS.
- Reading only with a browser session, not by OAuth or API key.
- Ending sessions and revoking programs stay on the account page (anchors), no writing route under `/.tinysesam/`.
- Sign-out in the frame is TinySesam's sign-out (the session ends).
- English names instead of "mode 1/2"; no mode switch.

## Stage E0 — documentation (this pull request)

- [x] README / `i18n/README.de.md` *Two ways to use TinySesam*: the rule table and three recipes; the recipe "behind
      the gateway" covers the wrapper in front of an application in another language (gate client preferred,
      `account_overview` with the three duties of the wrapper).
- [x] `SECURITY.md` / `i18n/SECURITY.de.md`: frame (no open redirect, no oracle) and reading (browser session only,
      CSRF, no CORS, rate, log, the wrapper's duties).
- [x] Skill recipe 5a, CHANGELOG.

## Stage E1 — app frame (this pull request)

- [x] `forward_apps[host]` `home`, `links`; `forward_frame_default`; `config_check` (host-bound targets, name required,
      at most 8 links as a warning, default must name a frame, `topbar_enabled=False` warns).
- [x] `_frame(request, ctx)`: `?app=`, absolute `next`/`return_url`, `app=` inside a relative `next`, default; targets
      only from the configuration; unknown host byte-equal.
- [x] `topbar.render_frame`, shared account menu; pages without an account show the name only.
- [x] `app=` through account → TOTP setup → step-up → back; anchors on the account page.
- [x] `config_check` warning: delegate roles overlapping an application's allowlist (draft §5).
- [x] Browser test: sign-in, step-up, account page framed at 375/1280 px, light/dark, strict CSP.

## Stage E2 — the own account as data (this pull request)

- [x] `auth.account_overview(user, *, base, app_host, request)` (tier B); the account page and `/auth/sessions` read
      it.
- [x] `GET /auth/account.json`, `GET /.tinysesam/account.json`: full browser session only, `no-store`,
      `Vary: Cookie`, no CORS, 60 per account and minute, GET only.
- [x] Format in `spec/gate-client.md` §8a (optional helper).
- [x] Proxy templates: `/.tinysesam/*` already passes through Caddy (plain, gate, quickstart, home network), nginx
      (both) and Traefik; the template comments and the proxy suites name `account.json`.

## Open

- [ ] clients: `FetchAccount` in every gate client (Go, Rust, JS/TS, PHP, `tinysesam.gate_client`) with vectors, like
      `FetchTopbar`/`parse_topbar` — next pull request, together with the approval helpers.
- [ ] `current` for the wrapper path: the gate token carries no session reference; a claim for it needs a spec change
      of its own.
- [ ] Ending a single session or program from the application (needs a session handle, schema, own draft).

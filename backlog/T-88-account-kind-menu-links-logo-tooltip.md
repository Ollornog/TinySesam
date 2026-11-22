---
id: T-88
type: Task
title: 'Account kind (Remote-Kind, spec v2), account menu links and the logo tooltip'
status: erledigt
milestone: M-2
tags: [forward-auth, gate, gate-client, topbar]
created: '2026-11-22'
---
# T-88 — account kind, account menu links, logo tooltip

Source: an application behind the gate must tell a person from a service account (`Remote-Auth` says how a request
came in, not what the account is), wants its own entries in TinySesam's account menu, and has to credit its logo.

## Done

- **`Remote-Kind: user | service`** from `users.is_service`, sent on every 200 of `/auth/forward`; claim `ts_kind` in
  every gate token. A value of `is_service` other than exactly 0/1 is a 403 (`api.kind_invalid`) with a security log
  line, never a guessed `user`. `forward_headers["kind"]` is a mandatory slot (`FORWARD_HEADERS_MANDATORY`): left out it
  is sent under its default name, it can be renamed, `{"kind": []}` is a `ConfigError`. A service account never gets a
  gate token (bolt in `_gate_cookie`).
- Every proxy template strips a client's `Remote-Kind` on every path and sets TinySesam's value (Caddy ×4 incl. the gate
  fast path with `ts_kind` in `meta_claims`, nginx, nginx/FastCGI, Traefik); measured through the real proxies with a
  forged value. Measured: a gate token without `ts_kind` takes caddy-jwt's fast path and the application gets an empty
  `Remote-Kind` (no placeholder text, no fallback to `/auth/forward`). `acceptance.sh` probes a forged `Remote-Kind`.
- **Spec v2** (`spec/gate-client.md`, vectors format 2, attack class `remote-kind`), no transition rule. Clients Go,
  Rust, JS/TS and Python on v2: `account_kind`, fail closed when missing or malformed, `service` with `session` refused.
- **`topbar_menu_links`** (account menu, before *Account*; one check and one filter with `topbar_links`; `menu_links` in
  `topbar_data` and both JSON routes) and **`brand_icon_title`** (`title` on the logo image, escaped, ≤ 200 characters).

## Open

- The FleetCommander role `caddy` follows after the release (strip `Remote-Kind`, `ts_kind` in `meta_claims`, fast path
  `header_up Remote-Kind {http.auth.user.ts_kind}`); only then do applications switch to clients after spec v2.
- PHP client (T-83) directly against spec v2.

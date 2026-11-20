---
id: T-58
type: Task
title: 'Caddy templates: a header missing from the auth answer reaches the app as placeholder text'
status: offen
milestone: M-2
tags: [deploy, forward-auth]
created: '2026-11-20'
---
# T-58 — Caddy templates: a header missing from the auth answer reaches the app as placeholder text

Source: measurement in T-43 (H1, Caddy 2.11.9).

**Is:** `request_header Remote-Email {rp.header.Remote-Email}` — if the auth response carries no such header at all
(e.g. `forward_headers` renamed or reduced, template lines kept), the app receives the literal text
`{http.reverse_proxy.header.Remote-Email}`. Not a leak (the client's value is replaced too), but a wrong value.

**Proposal:** strip `Remote-*` up front in `deploy/forward-auth/Caddyfile` and `deploy/home-network/Caddyfile` like
`Caddyfile.gate`, and set each header only via a matcher on its presence — or document in the template that its
lines must follow `forward_headers` exactly. Effort S.

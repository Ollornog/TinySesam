---
id: T-75
type: Task
title: 'Sign-in kind in forward auth: a Remote-Auth header'
status: erledigt
milestone: M-2
tags: [forward-auth, gate]
created: '2026-11-21'
---
# T-75 — sign-in kind in forward auth

Source: an application behind the gate gets different `Remote-Groups` depending on how the request signed in — a
token never carries the admin flag — and flips between profiles. It could not tell why.

## Done

- `/auth/forward` answers `Remote-Auth: session | oauth | apikey | app-password` (`TinySesam.FORWARD_HEADERS_DEFAULT`,
  slot `auth`). An unknown way in gives an empty value, never a guessed kind.
- `forward_headers` renames or drops it like every other slot (`{"auth": "X-Auth-Kind"}`, or leave `auth` out).
- Caddy (plain, gate, quickstart, home network), nginx, nginx/FastCGI and Traefik strip a client's `Remote-Auth` and set
  TinySesam's. `nginx-path.conf` also gained `Remote-Id`, which it had not passed or emptied before.

## Decision: a signed claim in the gate token, not a constant in the template

The gate token carries `ts_auth = "session"`, and `Caddyfile.gate` maps it with `header_up Remote-Auth
{http.auth.user.ts_auth}` like the other claims. Reasons:

- **One source.** The claims come from the same `_forward_values` as the headers and follow `forward_headers`: renamed
  or dropped, the fast path does the same as the way back. A constant in the template would keep saying `session`
  after an operator dropped the slot.
- **Signed.** The value is covered by the token's Ed25519 signature; the proxy cannot be fed another one.
- **Always true.** A gate token is issued only for a full session (`_gate_cookie` checks the session row), so the claim
  is set to `session` from that row, whatever way the account dict came in.

A token issued before the upgrade has no `ts_auth`: until it expires (at most `gate_token_ttl_sec`), the fast path
sends an empty `Remote-Auth`.

## Proof

- `tests/test_remote_auth.py`: A1–A7 of the acceptance list (session, OAuth token at its resource without `admin` even
  for an admin, API key as Bearer and `X-Api-Key`, app password, gate claim signed and equal to the header, renamed and
  dropped slot) plus a guard over every template with self-probes.
- `tests/test_gate_caddy.py` against a real Caddy with caddy-jwt: a browser-sent `Remote-Auth` is overwritten on the way
  back (`session`), with an API key alone (`apikey`) and on the fast path (`session` from the claim).
- Mutations: kind always empty (A1 red), the claim from the account dict instead of the session row (A5 red),
  `request_header -Remote-Auth` removed (guard red), `ts_auth` out of `meta_claims` (real Caddy red).

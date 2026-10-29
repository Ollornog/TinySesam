---
id: ADR-5
type: Decision
title: Roles in forward auth come from the proxy, not from a rules table
status: erledigt
tags: [architektur, forward-auth, rollen]
created: 2026-09-19
---

# ADR-5 — Roles in forward auth come from the proxy

## Context

`/auth/forward` was binary: signed in or not. Roles only travelled along as a `Remote-Groups` header,
and a reverse proxy cannot do anything with that — nginx because of the phase order, and
Caddy and Traefik face the same problem. In practice `require_role` therefore existed only in
in-app mode ([ADR-3](ADR-3-in-app-instead-of-proxy.md)), while the README promises forward auth in front of third-party
applications. Reported from practice (third-party deployment, 2026-09).

## Options

1. **Rules table in the configuration** (Authelia model): path pattern → roles, evaluated against
   the `X-Original-URL` that is transmitted anyway. Centrally visible, editable in the panel.
2. **The proxy states what it requires**: `?roles=a,b` on the sub-request or header
   `X-TinySesam-Roles`.

## Decision

**Option 2.** The specification sits where the proxy configures the route anyway.

## Rationale

Option 1 makes TinySesam depend on the path structure of third-party applications: it would have to
know patterns, sort them and match them against the URL — exactly the double maintenance because of which ADR-3 made
in-app protection the basic model, just the other way round. Option 2 keeps the library
stateless with respect to third-party paths and changes nothing for existing users: without the specification,
`/auth/forward` stays binary as before.

## Consequences

- Multiple specifications are combined with **AND**, commas within one specification are OR. This makes the
  evaluation fail-closed: if a client attaches a `roles=` or the header itself, it can
  only tighten the check, never loosen it.
- If the role is missing, TinySesam answers **403, not 401**. A 401 would send the already
  signed-in user to the login, which sends them back with the same missing role — a loop.
- The rejection goes into the audit log (`forward_role_denied`): a 403 in the proxy log does not say who
  failed at what.
- `admin_implies_roles` applies as with `require_role` — an admin also satisfies the role, unless
  disabled globally.

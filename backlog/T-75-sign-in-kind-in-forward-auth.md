---
id: T-75
type: Task
title: 'Sign-in kind in forward auth: a Remote-Auth header'
status: offen
milestone: M-2
tags: [proposal, forward-auth, gate]
created: '2026-11-21'
---
# T-75 — sign-in kind in forward auth

**Status: proposal.** The maintainer sets the priority; nothing is decided.

Source: an application behind the gate gets different `Remote-Groups` depending on how the request signed in — a
token never carries the admin flag — and flips between profiles. It cannot tell why.

## What it would mean

- A header `Remote-Auth: session | oauth | apikey | app-password` in the forward-auth answer; a request through a
  valid gate token counts as `session`.
- The proxy templates pass it on to the application like the other `Remote-*` headers, and strip a client header of
  the same name first.

## Open questions

- Whether the gate token carries the kind as a signed claim (it is issued only for sessions today).
- The header name and whether it belongs to `forward_headers` (configurable like the others).

---
id: T-140
type: Task
title: "HTTP test for Permissions::register() in the PHP client"
status: erledigt
points: 1
milestone: M-2
tags: [clients, php, permissions]
created: 2026-11-28
---
# T-140 — HTTP test for Permissions::register() in the PHP client

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

[T-101](T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md) covered the request the PHP client builds by
the vectors, not the sending over curl.

## Content
- A test against a local HTTP endpoint: method, path, `X-Api-Key`, body, deadline, and the error on an answer other
  than 200 (the key never in the error).

## Acceptance
- The test is red when the key goes into the error text or the deadline is missing (mutation).

## Done (sprint S9, 2026-11-28)

- `clients/php/tests/RegisterHttpTest.php` against PHP's built-in server (`tests/Support/router.php`): method, path,
  `X-Api-Key`, content type and body as sent; `403`, a `200` that is no JSON object and an unreachable server each a
  `RegistrationFailed` with its `status` and without the key (whole and its prefix); a server that never answers ends
  after the 5-second deadline (between 4.5 and 6.5 s).
- Mutations: the key in the error text, the deadline removed, the key in another header — each red.

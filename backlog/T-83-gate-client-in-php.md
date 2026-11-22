---
id: T-83
type: Task
title: 'Gate client in PHP'
status: offen
milestone: M-2
tags: [gate, clients, php]
created: '2026-11-22'
---
# T-83 — gate client in PHP

A small PHP library for applications behind TinySesam's gate, built on the specification and the vectors of
[T-28](T-28-go-variant-small-gate-client.md). It checks; it never issues tokens or signs anyone in.

`sodium_crypto_sign_verify_detached` (ext-sodium); `json_decode` keeps the last duplicate, so a check runs first. A PSR-15 middleware as the first integration.

## Done when

- `clients/php/` follows [`clients/README.md`](../clients/README.md): both modes of
  [`spec/gate-client.md`](../spec/gate-client.md) (header mode; token mode with fixed keys and with JWKS), guards for
  signed in, role and session only.
- Its test suite loads `spec/vectors/*.json` from the repository and passes every token, header, key-set and
  cache-scenario vector; plus the tests the vectors cannot carry (a JWKS server that never answers, a body above
  64 KiB, concurrent requests sharing one fetch).
- Mutation proof: relaxing one rule (algorithm from the header, no duplicate check, stripping instead of refusing)
  turns the vector suite red.
- A workflow `client-php.yml` on `ubuntu-latest` (actions pinned by SHA, `permissions: contents: read`, no path filter),
  the Dependabot entry `composer` for `/clients/php`, a README in English.
- No publication to Packagist without a decision of the product owner.

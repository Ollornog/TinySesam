---
id: T-82
type: Task
title: 'Gate client in JavaScript and TypeScript'
status: offen
milestone: M-2
tags: [gate, clients, js]
created: '2026-11-22'
---
# T-82 — gate client in JS/TS

A small JS/TS library for applications behind TinySesam's gate, built on the specification and the vectors of
[T-28](T-28-go-variant-small-gate-client.md). It checks; it never issues tokens or signs anyone in.

WebCrypto Ed25519 or `jose` pinned to `EdDSA`; `JSON.parse` keeps the last duplicate, so a scanner runs first. ESM with types; the core without Node-only APIs so it runs on edge runtimes; an Express/Fastify middleware as the first integration. Includes the top bar helper (spec §8) for browser apps.

## Done when

- `clients/js/` follows [`clients/README.md`](../clients/README.md): both modes of
  [`spec/gate-client.md`](../spec/gate-client.md) (header mode; token mode with fixed keys and with JWKS), guards for
  signed in, role and session only.
- Its test suite loads `spec/vectors/*.json` from the repository and passes every token, header, key-set and
  cache-scenario vector, and the top-bar vectors; plus the tests the vectors cannot carry (a JWKS server that never answers, a body above
  64 KiB, concurrent requests sharing one fetch).
- Mutation proof: relaxing one rule (algorithm from the header, no duplicate check, stripping instead of refusing)
  turns the vector suite red.
- A workflow `client-js.yml` on `ubuntu-latest` (actions pinned by SHA, `permissions: contents: read`, no path filter),
  the Dependabot entry `npm` for `/clients/js`, a README in English.
- No publication to npm without a decision of the product owner.

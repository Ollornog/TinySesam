---
id: T-80
type: Task
title: 'Gate client in Go'
status: offen
milestone: M-2
tags: [gate, clients, go]
created: '2026-11-22'
---
# T-80 — gate client in Go

A small Go library for applications behind TinySesam's gate, built on the specification and the vectors of
[T-28](T-28-go-variant-small-gate-client.md). It checks; it never issues tokens or signs anyone in.

The standard library carries Ed25519 (`crypto/ed25519`); duplicate members need a walk over `encoding/json`'s tokens. Middleware for `net/http` first; adapters for other routers only on demand.

## Done when

- `clients/go/` follows [`clients/README.md`](../clients/README.md): both modes of
  [`spec/gate-client.md`](../spec/gate-client.md) (header mode; token mode with fixed keys and with JWKS), guards for
  signed in, role and session only.
- Its test suite loads `spec/vectors/*.json` from the repository and passes every token, header, key-set and
  cache-scenario vector; plus the tests the vectors cannot carry (a JWKS server that never answers, a body above
  64 KiB, concurrent requests sharing one fetch).
- Mutation proof: relaxing one rule (algorithm from the header, no duplicate check, stripping instead of refusing)
  turns the vector suite red.
- A workflow `client-go.yml` on `ubuntu-latest` (actions pinned by SHA, `permissions: contents: read`, no path filter),
  the Dependabot entry `gomod` for `/clients/go`, a README in English.
- No publication to the Go module proxy without a decision of the product owner.

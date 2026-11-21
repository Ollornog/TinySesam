---
id: T-81
type: Task
title: 'Gate client in Rust'
status: offen
milestone: M-2
tags: [gate, clients, rust]
created: '2026-11-22'
---
# T-81 — gate client in Rust

A small Rust library for applications behind TinySesam's gate, built on the specification and the vectors of
[T-28](T-28-go-variant-small-gate-client.md). It checks; it never issues tokens or signs anyone in.

`ed25519-dalek` with `verify_strict`; a `serde_json` visitor that refuses repeated keys. A `tower` layer or an `axum` extractor as the first integration.

## Done when

- `clients/rust/` follows [`clients/README.md`](../clients/README.md): both modes of
  [`spec/gate-client.md`](../spec/gate-client.md) (header mode; token mode with fixed keys and with JWKS), guards for
  signed in, role and session only.
- Its test suite loads `spec/vectors/*.json` from the repository and passes every token, header, key-set and
  cache-scenario vector; plus the tests the vectors cannot carry (a JWKS server that never answers, a body above
  64 KiB, concurrent requests sharing one fetch).
- Mutation proof: relaxing one rule (algorithm from the header, no duplicate check, stripping instead of refusing)
  turns the vector suite red.
- A workflow `client-rust.yml` on `ubuntu-latest` (actions pinned by SHA, `permissions: contents: read`, no path filter),
  the Dependabot entry `cargo` for `/clients/rust`, a README in English.
- No publication to the Rust crate registry without a decision of the product owner.

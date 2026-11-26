---
id: T-81
type: Task
title: 'Gate client in Rust'
status: erledigt
milestone: M-5
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

## Done

- Crate `tinysesam-gate` 0.1.0 in [`clients/rust/`](../clients/rust/README.md): header mode (explicit opt-in,
  trusted peers, renamed headers), token mode with fixed keys and — feature `jwks`, `reqwest` with rustls — a fetched
  key set (deadline, body limit, freshness, rate limit, stale limit, shared fetch, monotonic cache clock), guards,
  top bar helper, axum example. Framework-neutral through the `http` crate; no `tower` layer of its own (the example
  shows the axum middleware; a layer can follow when an application needs one).
- Every vector passes (token, headers also through `http::HeaderMap`, key sets, the cache scenarios through the
  synchronous cache and through the async client, top bar, test keys); never-answering server, body above 64 KiB,
  32 concurrent requests sharing one fetch, no redirects; property tests.
- Mutation proof: one hand mutation per rule, each red; see the CHANGELOG entry. Finding: the vectors cannot tell a
  malformed but hex-like `kid` (upper case, wrong length) from an unknown one in fixed-key mode — both are `kid`; only
  the JWKS scenario `invalid-kid-no-fetch` (`../keys`) sees the difference. The crate pins the format with unit tests
  of its own; a vector with an upper-case `kid` in that scenario would close the gap for every client.
- `client-rust.yml`, Dependabot `cargo`, auto-merge with `client-rust.yml` among the mandatory workflows.

---
id: T-80
type: Task
title: 'Gate client in Go'
status: erledigt
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

## Done (2026-11-22)

- `clients/go/` — module `github.com/Ollornog/TinySesam/clients/go`, package `tinysesam`, Go 1.26+, **standard
  library only** (`crypto/ed25519`, `encoding/json` behind a token walk that refuses repeated members, `encoding/base64`
  behind the strict pre-checks). No JOSE library: none enforces the pre-checks of spec §4.4, and the algorithm is a
  constant, so a library would add surface without taking work away.
- Header mode (`TrustedProxies`, renamable headers) and token mode (fixed keys or JWKS with the §5 rules: 5 s
  deadline, 64 KiB, cache, 10 s rate, stale limit, shared running fetch); `Gate.Middleware`, `RequireAuth`,
  `RequireRole`, `RequireSession`; typed errors per class; `ParseTopbar`/`FetchTopbar` (§8).
- The test suite reads `spec/vectors/*.json` from the repository and passes all of them (114 token, 33 header, 19 key
  set, 10 cache scenarios with 38 steps, 6 top bar); plus a JWKS server that never answers, a body above 64 KiB, 32
  concurrent requests sharing one fetch, a redirect to another host, configuration errors, guards; five fuzz targets.
- Mutation proof: 57 hand mutations, one per checking step, 54 red. The three that stay green are guarded twice (the
  base64 alphabet check by the canonical re-encoding, the BOM check by `json.Valid`, a second fetch in one request by
  the 10 s rate). The vector `attack-payload-invalid-utf8` also repeats a member, so a client without a UTF-8 check
  still passes it; the Go suite has a test of its own for that.
- `.github/workflows/client-go.yml` (no path filter, ends early when a pull request touches neither `clients/go/` nor
  `spec/`), Dependabot `gomod` for `/clients/go` and `/.github/audit` (the tools), CodeQL for Go, a step in `scripts/check.sh`.
- Not published: no tag `clients/go/v…`, no announcement to the module proxy (decision of the product owner open).
- Published since 2026-11-23 (product owner): `clients/go/v0.29.0` set by hand; from the next release on
  `.github/workflows/release.yml` tags `clients/go/vX.Y.Z` on the commit of every `vX.Y.Z` itself (`clients/README.md`,
  "Publishing").

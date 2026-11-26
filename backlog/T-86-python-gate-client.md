---
id: T-86
type: Task
title: 'Python gate client'
status: erledigt
milestone: M-5
tags: [gate, clients, python]
created: '2026-11-22'
---
# T-86 — Python gate client

A slim gate client for Python applications that do not use TinySesam as a FastAPI module — Flask, Django or any other
WSGI/ASGI application behind the gate. Built on the specification and the vectors of
[T-28](T-28-go-variant-small-gate-client.md); phase 2 together with Go ([T-80](T-80-gate-client-in-go.md)) and Rust
([T-81](T-81-gate-client-in-rust.md)). It checks; it never issues tokens or signs anyone in.

## Done when

- The module `tinysesam.gate_client` in the package, importable without FastAPI (standard library and `cryptography`,
  which the package requires anyway); the import of `tinysesam` itself must then not pull in FastAPI for it either.
- Both modes of [`spec/gate-client.md`](../spec/gate-client.md) (header mode; token mode with fixed keys and with
  JWKS), guards for signed in, role and session only; a WSGI and an ASGI middleware; examples for Flask and Django.
- It grows out of the reference client `tests/_gate_reference.py`; the vector suite `tests/test_gate_vectors.py` then
  runs against the module, the relaxation self-probes stay in the tests.
- The vectors pass, plus the tests the vectors cannot carry (a JWKS server that never answers, a body above 64 KiB,
  concurrent requests sharing one fetch); mutation proof.
- New public names get their API tier (`tests/api_surface.json`) and their place in the README; the CHANGELOG says
  who needs it.

## Done (2026-11-22)

- `tinysesam/gate_client.py`, importable without FastAPI (standard library + `cryptography`); `tinysesam/__init__.py`
  imports `TinySesam` on first use. `GateClient` (header mode with `trusted_proxies` and `header_names`; token mode
  with `gate_keys` or `jwks_url`), `Identity`, one exception per error class, `WSGIMiddleware`, `ASGIMiddleware`,
  `current_identity`, `require_auth`, `require_role`, `require_session`, `guard_status`, `parse_topbar`,
  `fetch_topbar`. Tier B; README section in English and German; examples for Flask and Django in
  `examples/gate_client/`.
- JWKS with `urllib` (no extra dependency): the deadline is enforced by the cache and per body chunk, redirects only
  to the same host. With `jwks_url` the ASGI middleware checks in a worker thread.
- One Python implementation: `tests/_gate_reference.py` removed; `tests/test_gate_vectors.py` runs every vector
  against the client, `tests/_gate_relax.py` relaxes one check function at a time, and every check function needs a
  relaxation. `tests/test_gate_client.py` holds the tests the vectors cannot carry.
- Mutation proof: 83 hand mutations of the client, one per checking step, restored from a saved copy with a hash
  check: 79 red. Green stay four that are guarded twice: an empty header segment (the empty JSON fails too), the
  base64 alphabet check (the canonical re-encoding), the signature length when shorter than 64 (the verification), the
  body limit while reading (the size check of the result). The first run found gaps that are closed now: two vectors
  (`attack-claim-sub-empty`, `skip-x-short` with only its length wrong; in #304), the `kid` form in the cache scenario
  (#304), and tests for a fetch that outlives its deadline, a hanging fetcher, a valid body with a status other than
  200, an empty issuer or audience, and a mode that is not exactly `header` or `token`.

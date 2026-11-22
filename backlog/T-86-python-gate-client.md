---
id: T-86
type: Task
title: 'Python gate client'
status: offen
milestone: M-2
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

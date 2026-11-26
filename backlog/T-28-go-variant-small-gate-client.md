---
id: T-28
type: Task
title: 'Gate client specification with language-neutral test and attack vectors'
status: erledigt
milestone: M-5
tags: [gate, spec, clients]
created: 2026-10-28
---

# T-28 — gate client specification with language-neutral test and attack vectors

**Scope (product owner, 2026-11-22):** the foundation for gate clients in Go, Rust, JS/TS and PHP — a normative
specification and language-neutral test and attack vectors generated from the real code. The clients themselves are
separate tasks: [T-80](T-80-gate-client-in-go.md) (Go), [T-81](T-81-gate-client-in-rust.md) (Rust),
[T-82](T-82-gate-client-in-javascript-and-typescript.md) (JS/TS), [T-83](T-83-gate-client-in-php.md) (PHP) and
[T-86](T-86-python-gate-client.md) (Python, as `tinysesam.gate_client` in the package, without FastAPI). Go, Rust and
Python come first (phase 2). The server stays Python; no client issues tokens or signs anyone in.

## Done

- **[`spec/gate-client.md`](../spec/gate-client.md)** (normative, MUST/SHOULD): header mode with the duties of the
  proxy, token mode, the token format (`EdDSA`, `typ: tinysesam-gate+jwt`, `kid` = SHA-256 prefix of the key, `iss`,
  `aud` with roles, `ts_*` claims, lifetime ≤ 3600 s), a fixed checking order with error classes, clock leeway 0 by
  default and 60 s at most, a size limit of 4096 bytes, the groups format (comma, trimmed spaces, no escapes),
  `Remote-Auth` (empty counts as a token), the JWKS rules (5 s deadline, 64 KiB, freshness 60–3600 s, one attempt per
  10 s, stale for at most 3600 s — never the hang of caddy-jwt #117), fail closed, a list of what a client must never
  do, and the optional top bar helper.
- **`spec/vectors/*.json`** from `scripts/_gate_vectors.py`: valid tokens from TinySesam's own issuing path
  (`_gate_cookie`, `gate.issue`) with fixed test keys and a fixed clock, header inputs from
  `_forward_response_headers`, top bar data from `topbar_data`. 114 token, 33 header, 19 key-set, 10 cache-scenario and
  6 top-bar vectors; 40 attack classes, among them `alg: none`, HS256 with the public key, `crit`, embedded
  `jwk`/`jku`/`x5u`, manipulated `kid`, duplicate members, base64url padding/alphabet/non-canonical bits, JWS JSON,
  oversize, control characters and homoglyphs.
- **`tests/test_gate_vectors.py`** with the reference client `tests/_gate_reference.py`: the files are current to the
  generator, every vector has a reason and a known attack class, every class occurs and is named in the spec, the
  reference passes all of them, `gate.check` agrees where it checks the same, and each of 23 relaxations of the
  reference (algorithm from the header, embedded key trusted, no duplicate check, …) fails at least one vector.
- **[`clients/README.md`](../clients/README.md)**: path, vector runner, libraries, CI job pattern, Dependabot ecosystem
  per language; no publication to a registry without a decision of the product owner.

## Findings while writing it

- `gate.check` (the proxy-side check) accepts padded or standard-alphabet base64, duplicate members (last one wins),
  `crit` and embedded keys (ignored), and any lifetime. Harmless at the proxy — only the key holder can mint such a
  token, and the key is fixed — but a client is stricter; the suite documents the split.
- Role names are not checked for commas, so a role `a,b` would be read as two groups by every consumer of
  `Remote-Groups` — [T-85](T-85-role-names-without-comma.md).
- With `Caddyfile.gate` an application never sees a valid gate token: the proxy strips the cookie, and on the way back
  the fresh token only reaches the browser — [T-84](T-84-token-mode-delivery-to-the-application.md).

## History

A complete rewrite in Go was rejected on 2026-10-29: about 26k lines of code, about 40k lines of tests and grown
hardening; TinySesam is a mountable FastAPI module, and Go has no counterpart for that. The part that runs on every
request is already Go (caddy-jwt in the proxy, ADR-9); Python is involved only at sign-in. No permanent parallel Python
and Go gateway (two security-critical implementations of one contract drift apart). A complete port only once few
Python apps remain, as a migration with a time-boxed parallel phase. The specification and its vectors are what keeps
the small clients from drifting: they are generated from the server and checked against it.

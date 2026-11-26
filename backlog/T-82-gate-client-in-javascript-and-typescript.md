---
id: T-82
type: Task
title: 'Gate client in JavaScript and TypeScript'
status: erledigt
milestone: M-5
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

## Done

- Package `@tinysesam/gate` 0.1.0 in [`clients/js/`](../clients/js/README.md), `"private": true`: header mode
  (explicit `mode: 'header'`, trusted proxies, renamed headers), token mode with fixed keys or a key set URL
  (deadline, body limit, freshness, rate limit, stale limit, shared fetch, monotonic cache clock), guards, the top bar
  helper, a Node/Express adapter (`./node`) and a Fetch adapter (Hono, edge runtimes), two examples. No runtime
  dependency: WebCrypto `Ed25519` instead of `jose` (the pre-checks are needed either way, and `jose` verifies through
  the same WebCrypto call). An Express middleware rather than a Fastify plugin: Fastify can mount it through its
  Express compatibility, and the Fetch adapter covers the rest.
- Every vector passes (token, headers also through `Gate.identify` and through a real Node HTTP server, key sets, cache
  scenarios, top bar, test keys); never-answering server, stalled body, body above 64 KiB, 32 concurrent requests
  sharing one fetch, no redirects; minted tokens with one defect each; fast-check properties. Run on Node 22, 24 and
  26; the core also on Deno 2.9 and Bun 1.4 (local smoke test).
- Mutation proof: 104 hand mutations, 97 red. Equivalent (a second guard holds the rule): the base64url alphabet (the
  canonical re-encoding refuses every foreign character), the byte order mark as bytes (refused again as U+FEFF after
  decoding), an empty header or payload segment (fails as empty JSON, same class `malformed`), the JWK `x` length
  (the import checks it again), a key set that is not an object (no `keys` array, same class), a second fetch in one
  request (the rate limit stops it), the wait deadline and the fetch deadline (each holds the 5 s alone).
- Findings for the vectors (not changed here; the generator belongs to the vector work): the first mutation run left
  ten rules green that no vector isolates — a signature of the wrong length together with an unknown `kid` (step 5
  must come before step 6), a control character in `sub` without `ts_id` (an empty `sub` has a vector since #304), a fetch answer with a
  status other than 200 but a valid key set body, a fetch body above 64 KiB in a cache scenario, a group padded with
  non-space whitespace (U+00A0), a gate cookie name in another case, a top bar slot with `shown: false` and a safe
  `href`. The client pins each with a test of its own; vectors for them would close the gap for every client.
- `client-js.yml`, Dependabot `npm`, auto-merge with `client-js.yml` among the mandatory workflows; CodeQL analyses
  `javascript-typescript` and `rust`.

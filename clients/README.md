# Gate clients

Small libraries for applications behind TinySesam's gate, one per language (Python lives in the package itself). Built so far: **Go** ([`clients/go/`](go/README.md)). This
directory holds the conventions every client follows. The contract is [`spec/gate-client.md`](../spec/gate-client.md); the
proof is that a client passes every vector in [`spec/vectors/`](../spec/vectors/).

| Path | Language | Backlog |
|---|---|---|
| [`clients/go/`](go/README.md) | Go | [T-80](../backlog/T-80-gate-client-in-go.md) — built |
| `clients/rust/` | Rust | [T-81](../backlog/T-81-gate-client-in-rust.md) |
| `clients/js/` | JavaScript / TypeScript | [T-82](../backlog/T-82-gate-client-in-javascript-and-typescript.md) |
| `clients/php/` | PHP | [T-83](../backlog/T-83-gate-client-in-php.md) |
| `tinysesam/gate_client.py` (module `tinysesam.gate_client`) | Python | [T-86](../backlog/T-86-python-gate-client.md) |

The Python client is part of the `tinysesam` package, not of this directory: no FastAPI dependency (only the standard
library and `cryptography`, which the package requires anyway), a WSGI and an ASGI middleware, examples for Flask and
Django. Its vector runner is a suite in `tests/`; it grows out of the reference client `tests/_gate_reference.py`.
Order: Go, Rust and Python first (phase 2), then JS/TS and PHP.

TinySesam itself stays Python; a client never issues tokens and never signs anyone in (ADR-9, T-28).

## What every client contains

- **Both modes** of the specification (header mode, token mode with fixed keys and with JWKS), chosen explicitly by
  configuration; the optional top bar helper of §8 only when someone needs it.
- **Guards** in the idiom of the language (middleware, extractor, attribute): signed in, `has_role`, session only.
  They answer 401/403 and never reveal why (spec §6).
- **A vector runner in its own test suite** that loads `spec/vectors/*.json` **from this repository** (relative path
  `../../spec/vectors/`, never a copy) and checks every vector:
  - `token.json` — `ok`, `error` class, `claims`, `identity`, `has_role`;
  - `headers.json` — convert each header value to bytes with Latin-1, a list means a repeated field;
  - `jwks.json` — `sets` against the key set parser, `scenarios` against the cache with a fake fetcher and a fake
    clock (a fetch where the step gives no `fetch` answer fails the step);
  - `topbar.json` — if the helper exists.
  Plus the tests the vectors cannot carry (spec §5): a JWKS server that accepts and never answers (the request returns
  within the deadline), a body above 64 KiB, concurrent requests sharing one fetch.
- **Mutation as proof**: relax one rule (take `alg` from the header, skip the duplicate check, strip instead of refuse)
  and show that the vector suite turns red; restore from a saved copy.
- A `README.md` in English with installation, the two modes, the proxy duties of spec §2.1 and the configuration
  errors that stop the start.
- No private infrastructure, English everywhere; the repository's hygiene test reads these directories too.

## Libraries: no cryptography of our own

Ed25519 verification, base64url and JSON come from maintained libraries; the structural pre-checks of spec §4.4
(segments, alphabet, canonical encoding, header members, duplicates, sizes) are the client's own code, because no JOSE
library enforces all of them. Starting points — check the current stable release and its advisories when building:

| Language | Signature | JSON with duplicate detection | Note |
|---|---|---|---|
| Go | `crypto/ed25519` (standard library) | `encoding/json` `Decoder.Token` walk | a JOSE library (`go-jose/v4`) is optional; never let it choose the algorithm |
| Rust | `ed25519-dalek` (with `verify_strict`) | `serde_json` with a visitor that rejects repeated keys | `jsonwebtoken` takes the algorithm from a `Validation` you pin — still do the pre-checks |
| JS/TS | WebCrypto `Ed25519` (Node ≥ 22, browsers) or `jose` (panva) with `algorithms: ['EdDSA']` | a small scanner before `JSON.parse` (it keeps the last duplicate) | ESM, typed; no Node-only APIs in the core so it runs on edge runtimes |
| PHP | `sodium_crypto_sign_verify_detached` (ext-sodium, bundled) | a check before `json_decode` (it keeps the last duplicate) | `web-token/jwt-framework` only if it can be pinned to EdDSA |
| Python | `cryptography` (`Ed25519PublicKey.verify`) | `json.loads` with an `object_pairs_hook` that refuses repeats and a `parse_constant` that refuses `NaN` | no JOSE library needed; see `tests/_gate_reference.py` |

Every parser in this table keeps the **last** of two equal member names by default — the duplicate check is a MUST of
the specification and has its own vectors.

## CI per client

The Python client runs in the existing suites (`tests/run_all.py`, `ci.yml`) and needs no workflow of its own. For the
others: one workflow per client, `.github/workflows/client-<lang>.yml`, on `pull_request` and on `push` to `main` — no path
filter (a required check that is skipped blocks the merge forever); a job that finds no change in its directory may end
early and green.

```yaml
name: client-go
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read            # nothing else; never write at the top level
jobs:
  test:
    runs-on: ubuntu-latest  # public repository: GitHub-hosted runners only
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@<full commit SHA>  # vX.Y.Z — every action pinned by SHA, version as comment
        with:
          persist-credentials: false
      - uses: actions/setup-go@<full commit SHA>  # vX.Y.Z
        with:
          go-version-file: clients/go/go.mod
      - run: go test ./...
        working-directory: clients/go
```

- Actions pinned by full commit SHA with the version as a comment (the hygiene test checks it), the same SHAs the other
  workflows use where the action is the same.
- `permissions: contents: read` at the top; a job that needs more says so on the job.
- The language's own linters (`go vet`, `cargo clippy -D warnings`, `tsc --strict` + ESLint, `phpstan`) and its
  vulnerability check (`govulncheck`, `cargo audit`, `npm audit --omit=dev`, `composer audit`) run in the same job.
- A matrix only over supported releases of the language (the current stable and the oldest still maintained).

## Dependabot

Each client adds its ecosystem to `.github/dependabot.yml` with the same cooldown and schedule as the existing entries:

| Client | `package-ecosystem` | `directory` |
|---|---|---|
| Go | `gomod` | `/clients/go` |
| Rust | `cargo` | `/clients/rust` |
| JS/TS | `npm` | `/clients/js` |
| PHP | `composer` | `/clients/php` |

Lock files (`go.sum`, `Cargo.lock`, `package-lock.json`, `composer.lock`) are committed.

## Publishing

**No client is published to a registry** (the Go module proxy, the Rust crate registry, npm, Packagist) without a decision
of the product owner. Until then the clients are used from this repository by path or commit. Version numbers of the
clients are independent of TinySesam's and start below 1.0.

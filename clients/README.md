# Gate clients

Small libraries for applications behind TinySesam's gate, one per language (Python lives in the package itself). Built so far:
**Go** ([`clients/go/`](go/README.md)), **Rust** ([`clients/rust/`](rust/README.md)), **JS/TS**
([`clients/js/`](js/README.md)), **PHP** ([`clients/php/`](php/README.md)) and **Python** (`tinysesam.gate_client`, in the package). This directory holds the
conventions every client follows. The contract is [`spec/gate-client.md`](../spec/gate-client.md); the
proof is that a client passes every vector in [`spec/vectors/`](../spec/vectors/).

| Path | Language | Backlog |
|---|---|---|
| [`clients/go/`](go/README.md) | Go | [T-80](../backlog/T-80-gate-client-in-go.md) — built |
| [`clients/rust/`](rust/README.md) | Rust | [T-81](../backlog/T-81-gate-client-in-rust.md) — built (crate `tinysesam-gate`) |
| [`clients/js/`](js/README.md) | JavaScript / TypeScript | [T-82](../backlog/T-82-gate-client-in-javascript-and-typescript.md) — built (package `@tinysesam/gate`, private) |
| [`clients/php/`](php/README.md) | PHP | [T-83](../backlog/T-83-gate-client-in-php.md) — built (package `tinysesam/gate`, not on Packagist) |
| `tinysesam/gate_client.py` (module `tinysesam.gate_client`) | Python | [T-86](../backlog/T-86-python-gate-client.md) — built |

The Python client is part of the `tinysesam` package, not of this directory: no FastAPI dependency (only the standard
library and `cryptography`, which the package requires anyway), a WSGI and an ASGI middleware, examples for Flask and
Django (`examples/gate_client/`). Its vector runner is `tests/test_gate_vectors.py`, which also holds the relaxation
self-probes (`tests/_gate_relax.py` switches off one check of the client at a time); `tests/test_gate_client.py` covers
the JWKS server tests, the middleware and the configuration errors. Documented in the README, section "Gate client for
Flask, Django and other Python apps".
Order: Go, Rust and Python first (phase 2), then JS/TS and PHP.

TinySesam itself stays Python; a client never issues tokens and never signs anyone in (ADR-9, T-28).

## What every client contains

- **Both modes** of the specification (header mode, token mode with fixed keys and with JWKS), chosen explicitly by
  configuration; the optional helpers — the top bar of §8 (with its `approvals` member), the account overview of §8a
  (with `actions`, the session handle and the address of an action page of §8c) and the approval check of [`spec/approval-token.md`](../spec/approval-token.md) — in every client.
- **Guards** in the idiom of the language (middleware, extractor, attribute): signed in, `has_role`, session only,
  account kind (`user`/`service`, spec v2). They answer 401/403 and never reveal why (spec §6).
- **Spec version 2:** the identity carries `account_kind` from `Remote-Kind`/`ts_kind`, and a request or token without
  it is refused — no switch that takes a missing value as `user`. The README names the TinySesam release it needs.
- **A vector runner in its own test suite** that loads `spec/vectors/*.json` **from this repository** (relative path
  `../../spec/vectors/`, never a copy), checks that every file says `"format": 2`, and checks every vector:
  - `token.json` — `ok`, `error` class, `claims`, `identity`, `has_role`;
  - `headers.json` — convert each header value to bytes with Latin-1, a list means a repeated field;
  - `jwks.json` — `sets` against the key set parser, `scenarios` against the cache with a fake fetcher and a fake
    clock (a fetch where the step gives no `fetch` answer fails the step);
  - `topbar.json` and `account.json` — the normalized result, exactly; the list `action_urls` of `account.json`
    against the client's call that builds the address of an action page (the URL, or a refusal for `invalid`);
  - `approval.json` (`"format": 1`, its own specification) — every vector against the approval helper with a fixed
    key set, a fixed clock and `input.seen` as the `jti` store: the claims or the error class. That every attack vector
    carries one defect is measured once, against the Python reference (`tests/test_approval_vectors.py`); a client
    proves its own rules by mutation.
  Plus the tests the vectors cannot carry (spec §5): a JWKS server that accepts and never answers (the request returns
  within the deadline), a body above 64 KiB, concurrent requests sharing one fetch.
- **Mutation as proof**: relax one rule (take `alg` from the header, skip the duplicate check, strip instead of refuse)
  and show that the vector suite turns red; restore from a saved copy.
- A `README.md` in English with installation, the two modes, the proxy duties of spec §2.1 and the configuration
  errors that stop the start — including the price of a server-side top bar or account helper (it needs the session
  cookie the proxy strips, spec §8 "Server-side or in the browser") and the key set rule of spec §4.3 (an entry's
  `kid` must be derived from its key, else it is skipped: a set with no usable entry gives `key_unavailable`).
- **Key purposes kept apart** (spec/approval-token.md §3): the gate client refuses a key set URL ending in
  `/approvals/jwks.json`, the approval helper one ending in `/gate/jwks.json` — both at configuration.
- No private infrastructure, English everywhere; the repository's hygiene test reads these directories too.

## Libraries: no cryptography of our own

Ed25519 verification, base64url and JSON come from maintained libraries; the structural pre-checks of spec §4.4
(segments, alphabet, canonical encoding, header members, duplicates, sizes) are the client's own code, because no JOSE
library enforces all of them. Starting points — check the current stable release and its advisories when building:

| Language | Signature | JSON with duplicate detection | Note |
|---|---|---|---|
| Go | `crypto/ed25519` (standard library) | `encoding/json` `Decoder.Token` walk | a JOSE library (`go-jose/v4`) is optional; never let it choose the algorithm |
| Rust | `ed25519-dalek` (with `verify_strict`) | `serde_json` with a visitor that rejects repeated keys | `jsonwebtoken` takes the algorithm from a `Validation` you pin — still do the pre-checks |
| JS/TS | WebCrypto `Ed25519` (Node ≥ 22, Deno, Bun, edge runtimes, browsers) — chosen, no runtime dependency; `jose` (panva) with `algorithms: ['EdDSA']` was the alternative | `JSON.parse`, then a scan of the accepted text (it keeps the last duplicate, accepts lone surrogates and loses `1.0` vs `1`) | ESM, typed; no Node-only APIs in the core so it runs on edge runtimes |
| PHP | `sodium_crypto_sign_verify_detached` (ext-sodium, bundled) — chosen, no library | `json_decode` into `\stdClass`, then a scan of the accepted text (it keeps the last duplicate) | `web-token/jwt-framework` was the alternative; the key set fetch uses ext-curl (one deadline over the whole transfer) |
| Python | `cryptography` (`Ed25519PublicKey.verify`) | `json.loads` with an `object_pairs_hook` that refuses repeats and a `parse_constant` that refuses `NaN` | no JOSE library needed; see `tinysesam/gate_client.py` |

Every parser in this table keeps the **last** of two equal member names by default — the duplicate check is a MUST of
the specification and has its own vectors.

## CI per client

The Python client runs in the existing suites (`tests/run_all.py`, `ci.yml`) and needs no workflow of its own. For the
others: one workflow per client, `.github/workflows/client-<lang>.yml`, on `pull_request` and on `push` to `main` — no path
filter (a required check that is skipped blocks the merge forever); a job that finds no change in its directory may end
early and green.

The branch protection names one aggregate job per workflow (`client-<lang>-ok`, and `suite-ok` for the Python matrix), never
the legs of a matrix: the job `needs` all others, runs `always()` and is red unless each one succeeded (a skipped leg
counts as not green). A leg added or dropped then needs no change of the protection (`tests/test_ci_aggregate.py`).

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

**No client is published to a registry** (the Rust crate registry, npm, Packagist) without a decision of the product
owner. Until then those clients are used from this repository by path or commit, and their version numbers are
independent of TinySesam's and start below 1.0.

**Go is the exception (product owner, 2026-11-23):** a Go module needs no registry, only a tag. Every release tags
`clients/go/vX.Y.Z` on the same commit as `vX.Y.Z`, so the Go client carries TinySesam's version (first `v0.29.0`):
`go get github.com/Ollornog/TinySesam/clients/go@vX.Y.Z`. `.github/workflows/release.yml` sets the tag itself, as its
last step — after the GitHub release, PyPI, both images and their attestations — in three jobs: `go-module-plan` (read
only: `go.mod` at the tag commit names the module; tag already on that commit → done, on another → red; no tag for a
pre-release), `go-module-tag` (`contents: write`, no checkout, two `gh api` calls: annotated tag object with the
maintainer as tagger, then the ref) and `go-module-verify` (annotated, tagger, commit; then a probe of
proxy.golang.org that only warns, the proxy can lag). The module proxy and the checksum database keep a version
forever: a module tag is never moved and never set by hand. The logic is `scripts/_go_module_tag.py`, tested against
a throwaway git repository in `tests/test_go_module_tag.py`.

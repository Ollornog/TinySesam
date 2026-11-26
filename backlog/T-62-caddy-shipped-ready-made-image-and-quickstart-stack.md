---
id: T-62
type: Task
title: 'Caddy shipped ready-made: image tinysesam-caddy-gate and a quickstart stack'
status: erledigt
milestone: M-5
tags: [deploy, forward-auth, caddy, release, supply-chain, quickstart]
created: '2026-11-20'
---
# T-62 — Caddy shipped ready-made: image tinysesam-caddy-gate and a quickstart stack

Wish (PO 2026-11-20): "should we bake Caddy in as a template, so that it does not have to be built every time?"
Decision: **not into the gateway image** — a proxy with its own release cadence, its own CVEs and port 443 does not
belong in the auth service's container — but as an image of its own, published with every release, plus one stack that
runs without building anything.

## Done

- **Image `ghcr.io/ollornog/tinysesam-caddy-gate:vX.Y.Z`** (release.yml): same version as the release (the templates
  belong to the release, `gate-caddy` measures exactly that pair), multi-arch, pushed only for the tag, provenance and
  SBOM attested (`image-attest`), Grype-scanned before the push (`image-probe`, also on every PR), push and SBOM in the
  dress rehearsal (the SBOM must name caddy-jwt and Caddy). Extended the existing jobs instead of adding new ones, so the
  required checks cover it. A Caddy bump cuts a patch release (`ABBILD_PFADE`).
- **Build without xcaddy:** `main.go` + `go.mod` + `go.sum` — Caddy and caddy-jwt are ordinary Go dependencies, hashes
  verified, compiled for the target platform without emulation. **Dependabot `gomod`** watches both (before: an
  invisible `ARG CADDY_JWT`); `go_modules` in `AUTO_OEKO`. Found on the way: the official `caddy:2.11.9-alpine` digest
  carried fixable high/critical OpenSSL and zlib findings, Caddy 2.11.9 pinned the Go modules `x/net` and
  `klauspost/compress` with high findings — `apk upgrade` in the final stage and both modules raised in go.mod; Grype
  clean (≥ high). `CADDY_EXTRA_MODULES` builds a variant with a DNS provider (measured with caddy-dns/cloudflare).
- **`deploy/quickstart/`**: gateway + Caddy + example application (traefik/whoami, pinned by digest), hardened like the
  reference stack, `.env` from `example.env`. TLS mode `TS_TLS` = `acme` | `dns` | `internal` | `ip` through Caddyfile
  snippets; HSTS only with a domain; header strip, sign-out path, OAuth metadata and Bearer 401 (T-36). Name: the entry
  point, while `deploy/forward-auth/` stays the reference with every option.
- **Gateway:** `TINYSESAM_OAUTH_RESOURCES` — until now the gateway could not switch on OAuth at all.
- **T-58 solved** in all four Caddy templates (strip up front, each header only when the answer carries it — Caddy's own
  `copy_headers` pattern). `deploy/home-network/Caddyfile` got the T-36 additions.
- **Acceptance:** `tests/test_quickstart.py` runs the stack with both images of the commit (CI job `gate-caddy`) in the
  modes `ip` and `internal`: TLS chain (without SNI for the IP), redirect to the sign-in, forged `Remote-*` gone,
  TinySesam's values arrive, no placeholder, no TinySesam cookie, HSTS exactly with a domain, OAuth metadata + Bearer
  401, then `acceptance.sh`. `tests/test_gate_caddy.py` measures the quickstart Caddyfile alongside the other templates
  (H1, T-58, OAuth route). `tests/test_repo.py`: own images by version, others by digest, hardening, `gomod` entry,
  both images scanned and attested.

Done when: one release ships the Caddy image with the gateway image, the quickstart starts without building, and a
Caddy or caddy-jwt release arrives as a tested Dependabot PR. ✅ (The first published image comes with the next release.)

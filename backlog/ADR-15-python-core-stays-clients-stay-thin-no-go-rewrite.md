---
id: ADR-15
type: Decision
title: Python core stays, clients stay thin — no Go rewrite
status: erledigt
tags: [architecture, python, go, supply-chain]
created: 2026-11-23
---
# ADR-15 — The Python core stays; clients stay thin

## Context
For a project meant to be reused by other developers, the question came up whether to rewrite the core in Go (single binary, fast start). An analysis (2026-11-23, `main` at 0.29.1) measured the current state and estimated both paths.

Measured: 27,760 lines of code in the core; about 164 routes; 134 test files with about 7,500 assertion lines (105 of them in process); 275 vector cases in the spec; clients in Go, Rust, JavaScript and PHP (the Go client without third-party modules); 437 commits since 2026-07-06; 277 entries in the `### Security` sections of the changelog. Dependencies: 16 packages for the core, 25 for the gateway image, 39 for `[all]`; an equivalent Go build would link about 37 modules — the same order of magnitude.

## Options
1. **Rewrite the core in Go.** Estimate (not measured): 1,160–1,670 h or 670 SP, three to six months with two cores in parallel, and a new hardening phase. Of 293 counted security and defect entries in the history, Go would have prevented 2 and partly caught 10 (about 4 %); about 96 % are logic, protocol and configuration errors that a rewrite repeats. SAML libraries in Go had several signature bypasses between 2022 and 2026.
2. **Keep Python, one core for library and server, thin clients per language** (chosen). 218–286 h or 133 SP to the goal of [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md) — about a fifth.
3. Python core plus a Go sidecar for the proxy check: only on demand; the gate-token check at the proxy already runs in the clients, not in Python.

## Decision
Option 2 (maintainer, 2026-11-23). Clients stay thin: they verify the gate token, normalise the account and permission data and offer `has_permission`; they hold no policy. The spec and its vectors are the contract.

Cheap supply-chain gains without a rewrite are their own task: [T-110](T-110-dependency-diet-joserfc-instead-of-authlib-jose-qr-as-s.md) (joserfc instead of `authlib.jose`, QR as SVG without Pillow, SAML as its own image variant; about 8–12 h).

## Reversal conditions
- A single binary or small footprint becomes a product feature (embedded devices, "no Python in the container" customers, edge instances under 30 MB RAM): then a strangler migration with the vectors as the contract.
- The Python library has no users (all applications use the server): then the library mode disappears and a Go core loses nothing.
- Python or FastAPI become a repeated supply-chain or maintenance problem.
- A rewrite is due anyway (schema restart, 2.0).

## Consequences
One core serves both modes, so parity ([ADR-16](ADR-16-server-configuration-by-toml-file-with-an-environment-o.md)) is cheap. Image size and start time stay Python's.

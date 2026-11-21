---
id: T-79
type: Task
title: 'Diagnostics report and bug form instead of telemetry'
status: offen
milestone: M-2
tags: [cli, support, privacy]
created: '2026-11-21'
---
# T-79 — diagnostics report and bug form instead of telemetry

Queued after T-74.

## Decision: no telemetry

No automatic telemetry, no phone-home — not even as an opt-in. Reasons:

- **Trust:** an authentication component that talks to the outside on its own loses the trust it lives on.
- **Personal data:** errors carry user names, addresses, IPs and tokens; even a scrubbed stream leaks some.
- **No receiver:** GitHub offers no endpoint for it; we would have to run one.
- **Abuse:** a token shipped for reporting would be extracted and misused.

## `tinysesam diagnose` (CLI, also in the gateway image)

A report the operator reads, checks and sends themselves. The command makes no network request.

- Version, Python, mode (library or gateway), the shape of the configuration — which switches are set, never a value
  or a secret — with host names redacted.
- Results of the built-in checks: `config_check`, proxy headers and uvicorn (`--proxy-headers`, `trusted_proxies`),
  the clock, the database schema, reachability of the own JWKS (locally, not over the network).
- The latest errors from the security log, redacted (IPs, user names, tokens).
- At the end a prefilled link `https://github.com/Ollornog/TinySesam/issues/new?template=bug.yml&…` that the user
  checks and submits.
- Test: no secret and no configuration value ever appears in the report (canary values in every secret and free-text
  field of the configuration).

## `.github/ISSUE_TEMPLATE/bug.yml`

The same fields as the report. Vulnerabilities keep the private reporting path (`SECURITY.md`); the form says so.

## Usage: observe passively

pypistats, ghcr pulls, repository traffic, dependents. No collection of our own.

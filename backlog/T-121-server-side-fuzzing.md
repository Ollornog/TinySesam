---
id: T-121
type: Task
title: "Fuzz the server side: gate token, forward headers, OAuth endpoints, JSON APIs, template escaping"
status: offen
points: 5
milestone: M-3
blocked_by: [T-112]
tags: [security, fuzzing, hardening]
created: 2026-11-23
---
# T-121 — Fuzz the server side: gate token, forward headers, OAuth endpoints, JSON APIs, template escaping

**Story points:** 5 · **Estimate:** 8–12 h (not measured) · **Milestone:** [M-3](M-3-trust-hardening-and-launch.md)

The Go client has five fuzz targets; the Python server has none. Fuzzing finds the parser and boundary errors the
example-based tests do not think of.

## Content
- Targets (Atheris or Hypothesis, decided in the entry's first step): gate token and approval token parsing, the
  `/auth/forward` header handling (`X-Forwarded-*`, `X-Original-*`, `Remote-*`), the OAuth endpoints (authorize,
  token, DCR, pairing), the account and approval API JSON, `next`/`return_url` checks, and the escaping of the
  built-in templates.
- A short corpus in the repository, longer runs in `nightly`, every crash becomes a regression test.

## Acceptance
- At least eight targets run in `nightly`; a planted parser bug (mutation) is found within the configured run time;
  findings fixed with tests or recorded as accepted with a reason.

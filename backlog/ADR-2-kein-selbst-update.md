---
id: ADR-2
type: Decision
title: No self-update — whoever installs decides the version
status: erledigt
tags: [sicherheit, release]
created: 2026-07-09
---

# ADR-2 — No self-update

## Context

Up to 0.11, TinySesam could update itself through a panel route (`updater.py`,
`update_mode`, `update_pin`).

## Decision

**Removed without replacement in 0.12.0.** A hygiene test keeps the button out.

## Rationale

An auth service that fetches code for itself undermines exactly the control it exists for:
whoever takes over the panel takes over the next version. Updating is the job of whoever
installs — through the package manager or the container image.

## Consequences

- `update_mode` and `update_pin` are gone and must not come back; a test enforces that.
- Whoever updates swaps the tag or image digest.
- The CLI stays lean — but **lean does not mean empty**. Extended in 2026-09 by
  `tinysesam passwd --db <file> <user>`: the command fetches nothing and talks to no
  running service, but opens a database file that one needs file access to anyway. It is the
  way out of the dead end that a preset without a mailer leads to (no
  "forgot password", no magic link, first-admin paths only while no admin exists).
  The boundary of this decision is **fetching code**, not **maintaining offline**.

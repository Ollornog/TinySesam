---
id: ADR-4
type: Decision
title: CI stays on hosted runners — self-hosted ruled out
status: erledigt
tags: [ci, security]
created: 2026-07-10
---

# ADR-4 — CI stays on hosted runners

## Context

For private projects it is natural to run your own runners. For this **public** repo,
we checked whether that would make sense here too.

## Decision

**Ruled out, not postponed.** CI runs on `ubuntu-latest`.

## Rationale

In a public repo anyone can open a fork PR, whose workflow would then run on your own
hardware. Non-ephemeral runners can therefore be compromised permanently — GitHub explicitly
advises against it.

**Cost is no counter-argument:** public repos have unlimited minutes.

## Consequences

- `runs-on: ubuntu-latest` is a security decision here, not an incidental detail.
- The line must not switch to `self-hosted`.

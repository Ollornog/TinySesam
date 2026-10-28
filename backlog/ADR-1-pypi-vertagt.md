---
id: ADR-1
type: Decision
title: PyPI release deferred until 1.0
status: verworfen
superseded_by: ADR-6
tags: [release, supply-chain]
created: 2026-07-10
---

# ADR-1 — PyPI release deferred until 1.0

> **Superseded by [ADR-6](ADR-6-pypi-veroeffentlichen.md) (2026-09-21).** What follows was
> right as long as the condition was not met: the decision was "wait until 1.0", and
> with 1.0 exactly that point has been reached. The text stays because the reasons have not
> become obsolete — they have been answered, and ADR-6 says how.

## Context

An auth package would be much easier to include via `pip install` than via a pinned
Git tag. The names are free.

## Options

1. **Publish now** — most convenient installation, widest reach.
2. **Wait until 1.0** — installation via pinned Git tag.

## Decision

**Wait (2).**

## Rationale

- **Every PyPI version is irrevocable.** The API is still moving — 0.12.0 removed the
  self-update without replacement ([ADR-2](ADR-2-kein-selbst-update.md)). A package whose
  surface changes at monthly intervals does not belong in an immutable index.
- **An auth package is a supply-chain target.** Whoever takes over the account pushes code into other
  people's sign-in flows. The pinned tag shifts the trust onto a commit hash.

## Consequences

- Until 1.0, installation goes through `pip install git+…@<tag>`.
- If it is published, then with **Trusted Publishing** (PyPI trusts the workflow via OIDC),
  no token in the repo.
- To be checked at [M-1](M-1-api-stabil-1-0.md).

## Addendum (2026-09-21)

Both conditions set out here have been met: publishing happens via **Trusted Publishing**,
and the point in time is 1.0. As for the rationale, only the first point is outdated — the API
has been measured rather than asserted since 0.16.0. The second (auth package as a supply-chain target) still holds
unchanged; ADR-6 answers it instead of discarding it.

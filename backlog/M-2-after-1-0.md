---
id: M-2
type: Milestone
title: After 1.0 — keeping the published package maintained
status: offen
tags: [release, maintenance]
created: 2026-09-21
---

# M-2 — After 1.0: keeping the published package maintained

**Done when:** nothing is open any more that a user of the published package would notice —
neither when installing nor when operating.

With [M-1](M-1-api-stable-1-0.md) the library **is to** go to PyPI
([ADR-6](ADR-6-publish-to-pypi.md)) — it is not yet published, and M-1 is back at `offen`
after the maturity review. 0.18.0 was delivered via the pinned Git tag. The
yardstick of this milestone therefore applies from the day of publication: until 1.0 it means "works
in the repo", afterwards "arrives correctly at a stranger's". This is where the points collect that follow from this shift — deadlines of the
build tooling, gaps noticed while preparing for publication, and everything
that would cost a major version if noticed too late.

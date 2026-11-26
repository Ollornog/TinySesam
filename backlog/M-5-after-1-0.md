---
id: M-5
type: Milestone
title: After 1.0 — keeping the published package maintained
status: offen
rank: 5
tags: [release, maintenance]
created: 2026-09-21
---

# M-5 — After 1.0: keeping the published package maintained

**Done when:** nothing is open any more that a user of the published package would notice —
neither when installing nor when operating.

With [M-4](M-4-api-stable-1-0.md) the library **is to** go to PyPI
([ADR-6](ADR-6-publish-to-pypi.md)) — it is not yet published, and M-4 is back at `offen`
after the maturity review. 0.18.0 was delivered via the pinned Git tag. The
yardstick of this milestone therefore applies from the day of publication: until 1.0 it means "works
in the repo", afterwards "arrives correctly at a stranger's". This is where the points collect that follow from this shift — deadlines of the
build tooling, gaps noticed while preparing for publication, and everything
that would cost a major version if noticed too late.

## Roadmap 2026-11-23

This milestone stays the maintenance lane, worked in between the sprints of
[M-1](M-1-clean-baseline-and-modules-before-shell-and-headless.md), [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)
and [M-3](M-3-trust-hardening-and-launch.md). Measurable done line for a release: no open `B-` entry in M-5, no expired
scanner exception, and every remaining open entry is tagged `idea`, `maybe` or `on-demand` or waits for an upstream
release. Moved out on 2026-11-23: B-16 and T-72 (M-1), T-70 (M-2), T-30 (M-3); closed: T-89, T-90, T-91 (rest in
[T-120](T-120-leftovers-of-approvals-account-api-and-app-frame.md)).

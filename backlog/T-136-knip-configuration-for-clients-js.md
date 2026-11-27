---
id: T-136
type: Task
title: "knip configuration for clients/js, so the unused-dependency check covers it"
status: offen
points: 2
milestone: M-5
tags: [ci, dependencies, clients]
created: 2026-11-27
---
# T-136 — knip configuration for clients/js

**Story points:** 2 · **Estimate:** 2–3 h · **Milestone:** [M-5](M-5-after-1-0.md)

The unused-dependency check of the shared kit (0.73.0) reports `clients/js/package.json: NOT checked — no knip
config`. Without a configuration with the entry files knip would guess.

## Content
- `clients/js/knip.json` with the entry files of the gate client; the check runs it in the `audit` workflow.

## Acceptance
- `scripts/_abhaengigkeiten.py` checks `clients/js` and reports it clean; a probe dependency that nothing imports turns
  it red.

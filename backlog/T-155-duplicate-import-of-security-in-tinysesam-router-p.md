---
type: Task
title: Duplicate import of security in tinysesam/router.py
status: offen
points: 1
id: T-155
milestone: M-5
created: '2026-11-28'
---
# T-155 — Duplicate import of security in tinysesam/router.py

**Story points:** 1

ruff F811: `security` is imported twice in `tinysesam/router.py`. Remove the duplicate and let the lint stage catch the next one.

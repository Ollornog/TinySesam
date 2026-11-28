---
type: Bug
title: Role removed and re-added between two permission checks stays unnoticed
status: offen
points: 2
id: B-22
milestone: M-5
created: '2026-11-28'
---
# B-22 — Role removed and re-added between two permission checks stays unnoticed

**Story points:** 2

Limit of B-20: _known_roles notices a removed role only when a permission is checked. If a role is removed and re-added with no check in between, its old assignments stay active. Fix: compare the role set in validate() or on configuration reload. Acceptance: test removes and re-adds a role without a check in between and the assignment is suspended.

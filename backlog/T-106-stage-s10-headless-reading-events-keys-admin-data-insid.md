---
id: T-106
type: Task
title: "Stage S10 — headless reading: events, keys, admin data inside the application"s area"
status: offen
points: 13
milestone: M-4
blocked_by: [T-105]
tags: [headless, admin, spec]
created: 2026-11-23
---
# T-106 — Stage S10 — headless reading: events, keys, admin data inside the application's area

**Story points:** 13 · **Estimate:** 26–32 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

## Content
- `account.json`: `events`, `api_keys`, error format `error`, Fetch Metadata.
- Admin read inside the area of the application only (`/.tinysesam/admin/*.json`, spec section 8b); the panel link stays a link, nothing is switched off. The administrator flag is never settable by link.
- Hardening and configuration remain instance-wide and are not reachable from an application.

## Acceptance
- **Ex4**: the application's own admin page from `admin/*.json` plus the account API plus action pages; panel and full account page are never opened.

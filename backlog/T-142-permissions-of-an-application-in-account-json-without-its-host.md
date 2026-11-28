---
id: T-142
type: Task
title: "Permissions of an application in account.json without its host"
status: erledigt
points: 2
milestone: M-2
tags: [permissions, account]
created: 2026-11-28
---
# T-142 — Permissions of an application in account.json without its host

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

`/auth/account.json` gives `permissions: null` outside an application's host; there is no way to ask for one
application by a parameter. Open whether a front end needs it (account page, headless UIs of
[T-106](T-106-stage-s10-headless-reading-events-keys-admin-data-insid.md)).

## Content
- Decide (ADR-17 addendum): `?app=<id>` for the signed-in person's own permissions, or deliberately not.

## Acceptance
- The decision is written down; if yes, a test that `?app=` never shows another person's permissions.

## Done (S9)

Decided yes (ADR-17 addendum 2026-11-28): `/auth/account.json?app=<id>` and `account_overview(user, app=<id>)` name the
signed-in person's own permissions for that application on TinySesam's origin; on an application's host the host
decides. `tests/test_permissions_server.py` (c): another account's permissions never, whatever the query says; an
unknown id `null`.

---
id: T-135
type: Task
title: "Account page in the panel: the roles each source delivers"
status: erledigt
points: 2
milestone: M-2
tags: [idp, roles, admin]
created: 2026-11-27
---
# T-135 — Account page: the roles each source delivers

**Story points:** 2 · **Estimate:** 2–4 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Follow-up of [T-102](T-102-stage-s6-idp-role-sync-stage-1-import-groups-at-sign-in.md). `idp_role_sources` exists; the
account page in the panel does not show yet which roles come from which source (OIDC, SAML, LDAP) and which are
assigned by hand.

## Content
- The account page lists the roles grouped by source, the IdP ones marked "from IdP" (symbol and word), with the time
  of the last delivery.

## Acceptance
- Browser test at 390 px, light and dark, strict CSP: an account with a hand-assigned and an imported role shows both
  with their source.

## Done (S9)

The panel's account page (*Accounts → <account>*, section Access) lists each held role with its source: "⇄ from IdP
(<source>) — last delivered <date>" per delivering source, "✋ assigned by hand" for a role no source delivers, both for
a role the account held by hand before a source delivered it. `/api/users` carries `role_sources`
(`Store.idp_role_deliveries`, one query). `tests/test_browser.py` (group import part, 1280 and 390 px, light and dark,
strict CSP), `tests/test_group_import.py`.

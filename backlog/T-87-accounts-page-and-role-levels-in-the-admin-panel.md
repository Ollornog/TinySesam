---
id: T-87
type: Task
title: 'Accounts page and role levels in the admin panel'
status: erledigt
milestone: M-2
tags: [admin, roles, ui, delegates]
created: '2026-11-22'
---
# T-87 — accounts page and role levels in the admin panel

Reported in use: every account row carried up to nine buttons that wrapped into tall rows, the roles editor opened
below the row, and roles that come in steps (`coll:a-read` to read, `coll:a` to write) had to be ticked one by one in a
flat checkbox wall.

## Done

- **Slim list** (name, type, role chips, status) with search; a click opens the account's own page (`#user/<id>`,
  back/forward work) with *Profile*, *Access*, *Sign-in* and *Danger zone*. The new-account form uses the same role
  picker.
- **`role_levels`** (config): ladders of role templates with `{1}`; the panel offers one choice per entry ("— / read /
  write") and stores the full set. No implication anywhere else — headers, gate token, key scopes and `has_role` carry
  exactly the stored roles. An incomplete entry is shown and kept until a level is chosen. Pure functions in
  `tinysesam/_role_levels.py`, so a role catalog (database) can feed them later.
- **Delegated admins:** only the levels whose roles all lie in their scope; an entry without one is not shown. The
  roles route checks the scope as before.
- **Other roles** grouped by prefix with a filter; roles an account holds outside the configuration stay ticked — the
  old editor dropped them on every save (fixed).
- `config_check`: shape, two levels at least, templates usable and unique, no comma or control character, no overlap
  between ladders, no equally specific overlap in one, no role claimed by two entries (errors); ladder without entry,
  entry missing a level role, delegate holding a part of a level (warnings).
- Tests: `tests/test_role_levels.py` (functions, config check, server, panel JS in node), `tests/test_browser.py`
  (accounts panel as administrator and as delegate, 390 px, light and dark, strict CSP).

## Later

- The role catalog (roles in the database) feeds `_role_levels.entries` with `available_roles` plus the catalog.
- Role names without comma and control characters everywhere: [T-85](T-85-role-names-without-comma.md).

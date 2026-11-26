---
id: T-92
type: Task
title: 'Role catalog: roles in the database, so administrators add them in the panel'
status: erledigt
milestone: M-5
tags: [roles, admin, ui, cli]
created: '2026-11-23'
---
# T-92 — role catalog

Requested in use: administrators should add a role in the panel and assign it, without a change of the configuration
and a restart. Decided by the maintainer on 2026-11-22: a convenience for administrators only. Identity versus
resources — fine-grained rights on an application's objects (collections, owners, moderators) stay in the
application; no moderator scopes from templates, no workflow.

## Done

- [x] Schema 25: table `role_catalog` (`name`, `name_compare`, `created_at`, `created_by`), additive; rollback in
      `docs/OPERATIONS.md`.
- [x] Rules in `tinysesam/_role_catalog.py` (shared by the panel, the methods and the CLI): the name (T-85 plus C1 and
      format characters, at most 64), no second spelling (casefold), the configuration owns every role it names
      (`config_check.configured_roles`, plus `admin` and `__admin__`), no ambiguous role level entry, at most 1000 rows.
- [x] Delete only what nobody uses — accounts, API key scopes (not revoked, not expired), OAuth service scopes, open
      invitations and pairing codes, pending approvals that add the role — checked and deleted in one transaction
      (`BEGIN IMMEDIATE`); a role that is one level of a role level entry goes with its entry. A catalog row the
      configuration names too may be deleted (the role stays known).
- [x] The panel offers `available_roles` ∪ catalog (checkboxes, role levels, free text only when both are empty).
      *Accounts → Roles* (`#roles`): add, delete with the reason when it cannot, "add to catalog" for roles only accounts
      hold, the account count as a link to the list filtered by exactly that role (`#role/<name>`), and per role level
      ladder "add entry"/"delete entry" with all its level roles at once. English and German.
- [x] Routes `<admin>/api/roles` (GET, POST), `…/roles/delete`, `…/roles/entry`, `…/roles/entry/delete`:
      administrators only (CSRF, step-up of the panel), errors in words.
- [x] `TinySesam.create_role`, `delete_role`, `known_roles`, `role_catalog`, `role_usage`, `RoleError` (tier B).
- [x] CLI `tinysesam roles list|create|delete` (changing needs `--config`).
- [x] Start: catalog rows breaking T-85, catalog roles the configuration names too, and the role level coverage over
      the known roles (moved from `config_check`, which has no database and would report catalog entries as missing).
- [x] Audit `role_created`, `role_deleted`, `role_delete_refused`.
- [x] Tests `tests/test_role_catalog.py` (with the race of delete and assignment) and the browser test of the page.

## Not built, on purpose

- Delegated admins adding roles in an area (`coll:*`): drafted (area prefixes in `admin_delegates`, the scope from the
  catalog minus every configured role, the check inside the delegate's write transaction), not built — rights per
  collection belong in the application. Reopen with a concrete need.
- Applications adding roles through the account API: their allowlist is checked statically; a leaked key could flood
  the catalog. If ever needed, a `provisioning.role_prefix` with its own quota.
- Renaming, descriptions, labels per catalog role, cascading deletes, a server rule "only known roles may be set".

---
id: ADR-17
type: Decision
title: Permission layer and admin levels
status: erledigt
tags: [architecture, permissions, roles, admin]
created: 2026-11-23
---
# ADR-17 — Permission layer and admin levels

## Context
Applications have only roles (`has_role`). Fine-grained rights ("may delete documents") end up as invented role names. The application should declare what it can do; the operator decides who may.

## Decision
**Permissions**
- The application registers its permissions (`docs.read`, `docs.delete`; label in en and de, description, flag `danger`). Names are free but unique per application; TinySesam keeps them apart per application internally (app id plus name). Name rule `^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}$`, at most 200 per application.
- The administrator assigns permissions to roles (catalog, config or IdP role), per application, individually, no wildcards; a button "all" exists.
- `has_permission(user, perm, app=…)` in the library, in the gate token (`ts_perms`), in a header (`Remote-Permissions`), in `account.json` and in every client.
- Effective permissions are the union over the account's roles, for that application only; services get the intersection with their scope.
- **The application cannot grant itself anything:** registering is the only thing the service path allows. A registered permission grants nothing until assigned; `suggested_roles` is a hint in the panel only.
- `admin_implies_permissions` defaults to false (`admin_implies_roles=True` is already a known trap).
- A permission that vanishes from the manifest stays as "orphaned" and does nothing; it is shown and can be deleted, never silently re-granted.
- Object-level rights ("folder X") stay in the application.
- Changes at the proxy path take effect after the gate-token TTL (default 300 s); library and service path at once. An oversized set is rejected at the header, never cut.

**Admin levels** (names fixed here)
- **Superadmin (owner)**: instance-wide, including hardening and configuration.
- **Admin**: accounts, roles, permissions, approvals.
- **Area administrator** (formerly "delegate", [T-74](T-74-delegated-admins.md)): manages accounts and assigns permissions only for applications in their area; `danger` permissions only with a step-up. The area administration stays a matter of the panel.

## Addendum 2026-11-28 (T-142): one application's permissions without its host

`/auth/account.json?app=<id>` (and `account_overview(user, app=<id>)`) names the signed-in person's OWN permissions
for one application of `apps` on TinySesam's origin — for a front end there (a library application, the headless pages
of a library) that has no application host to ask from. Decided yes, because it shows nothing the person could not
see at that application's host anyway, and limited so it stays that way: no parameter chooses an account; an unknown
id gives `null`; on an application's host (`/.tinysesam/account.json`) the host decides and the parameter is ignored,
so an application's page never learns the person's permissions in another application. Another account's permissions
stay with the account API (`GET /auth/api/users/{id}/permissions?app=`, the application's own service account).

## Consequences
Schema 27 (additive: `app_permission`, `role_permission`), see [T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md) and [T-101](T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md). App identity is unified: `apps[id]` carries `hosts`, `layout`, `permissions`, name and icon; `forward_apps` stays as an alias. Extends [ADR-5](ADR-5-roles-in-forward-auth.md).

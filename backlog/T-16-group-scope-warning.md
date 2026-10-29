---
id: T-16
type: Task
title: Warn when a group rule runs through the groups claim and the groups scope is missing
status: erledigt
milestone: M-2
tags: [oidc, gruppen, konfiguration, pocketid, betrieb]
created: 2026-09-27
---

# T-16 — Groups scope: warn instead of silently rejecting

**Finding from operation (2026-09-27, integration into an app with PocketID):** `oidc_allowed_groups` was
set, `oidc_group_claim` was on the default `groups`, `oidc_scopes` on the default
`openid profile email`. PocketID sends the `groups` claim only with the `groups` scope — everyone
was rejected ("no matching group", audit `oidc_group_denied`), and nothing at startup
pointed to the cause. With `oidc_group_role_map` it would have been quieter: no role, no error.

**Done when:** the configuration check warns as soon as a group rule (`oidc_allowed_groups`
or `oidc_group_role_map`) runs through the `groups` claim and the `groups` scope is not requested
— per client, also for `oidc_clients` with their own `scopes`; a warning, not an error, and
no automatic requesting (other providers deliver the claim through a mapper without a scope,
some reject an unknown scope); the gateway can set the scope at all; test and
mutation.

## Done 2026-09-27

- `config_check._groups_scope()`: one warning that names the affected clients and the way
  (`oidc_scopes`, gateway `TINYSESAM_OIDC_SCOPES`, `scopes` on the entry). Silent for Entra ID
  (`login.microsoftonline.com`): there `groups` is not a scope, the advice would break the sign-in
  (AADSTS650053); groups arrive as an "optional claim".
- Gateway: new variable `TINYSESAM_OIDC_SCOPES` (default `openid profile email`). Without it the
  preset always took the default — the warning's advice would not have been actionable in the gateway.
- **SAML and LDAP:** no counterpart in the configuration. There are no scopes there; whether the IdP
  releases the group attribute or the directory delivers `memberOf` (OpenLDAP: memberof overlay)
  is determined on the other side. `docs/OPERATIONS.md` names the symptom (audit `saml_denied
  grund=gruppe` or `ldap_group_denied` for everyone).
- Test: `tests/test_operations_findings.py` (a) — warning with allowed_groups and with the role mapping,
  none with scope, without rule, with a different claim, without OIDC, with Entra ID; per application; gateway
  with and without `TINYSESAM_OIDC_SCOPES`. Docs: README EN/DE (Roles & groups), `docs/OPERATIONS.md`,
  compose example, CHANGELOG.

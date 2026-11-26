---
id: T-85
type: Task
title: 'Role names without comma and control characters'
status: erledigt
milestone: M-5
tags: [roles, forward-auth, gate]
created: '2026-11-22'
---
# T-85 — role names without comma and control characters

Found while writing the gate client specification ([T-28](T-28-go-variant-small-gate-client.md)). `Remote-Groups` and
the claim `ts_groups` join the roles with `,` and have no escape mechanism (`spec/gate-client.md` §3.3). Nothing stops a
role named `a,b` (`set_roles`, `available_roles`, `ldap_group_role_map`, `oidc_group_role_map`, the admin panel): every
consumer would read it as the two groups `a` and `b` — a role `staff,admin` becomes `admin` at the application. A role
with a control character loses it on the way out (`_header_value` and the claims strip C0/DEL): `ad\x01min` arrives as
`admin`. An account name with a control character is refused at that point (403), a role name is not. Role names come
from the operator's configuration or an admin (delegates only grant roles listed in `admin_delegates`), so this is no
path for an outsider — but it turns a typo or a pasted value into another role.

## Done

- [x] One rule, `store.role_invalid`: not a string, empty, a comma, C0/DEL or surrounding spaces (gate clients trim
      the spaces around an entry, spec §3.3, so ` admin` would arrive as `admin`).
- [x] `config_check`: an error in every field that names a role (`config_check.configured_roles`): `available_roles`,
      `signup_default_roles`, the three group maps and the map per OIDC client, `admin_delegates` (role, `roles`,
      `manages`), the role of a top bar or menu link; the provisioning allowlist, `approver_role` and the `role_levels`
      templates keep their own findings, now on the same rule. English and German.
- [x] Writing: `create_user`, `set_roles` and `create_invite` raise `ConfigError` (`field="roles"`) before anything is
      written; the admin panel answers `400` naming the role (`PanelActions.roles_from`, also for approvals of
      `tinysesam.account.set_roles`). API key and service scopes are a subset of the account's roles and need no
      check of their own.
- [x] Identity provider: a map target changed at runtime is skipped with a security line, the other roles apply.
- [x] Existing data: a start warning names the roles, nothing is rewritten; the forward check refuses such an account
      (`403`, so no gate token) instead of stripping or splitting the role.
- [x] Tests `tests/test_role_names.py` with a mutation per check (PR description).

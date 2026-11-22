---
id: T-85
type: Task
title: 'Role names without comma and control characters'
status: offen
milestone: M-2
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

## To do

- Refuse a comma and C0/DEL in role names wherever roles are set or configured (`config_check` for the maps and
  `available_roles`, `set_roles`, `apply_idp_groups`, the panel's API); an IdP group mapped to such a role is a
  configuration error, a role arriving from an IdP is skipped with a security log line.
- Existing accounts with such a role: a startup warning naming the role, no silent rewrite; on the way out refuse
  rather than strip (like the account name).
- A test that fails without the check.

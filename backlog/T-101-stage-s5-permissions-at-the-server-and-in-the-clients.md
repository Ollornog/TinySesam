---
id: T-101
type: Task
title: Stage S5 — permissions at the server and in the clients
status: erledigt
points: 14
milestone: M-2
blocked_by: [T-100]
tags: [permissions, clients, spec]
created: 2026-11-23
---
# T-101 — Stage S5 — permissions at the server and in the clients

**Story points:** 14 (13 + 1 for `apps[id].hosts`, taken over from T-100 on 2026-11-27) · **Estimate:** 22–30 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Server and client side of [ADR-17](ADR-17-permission-layer-and-admin-levels.md).

**Done (2026-11-28), in four pull requests into the sprint branch:** the server core (`apps[id].hosts`,
`permission_scopes`, `Remote-Permissions` / `ts_perms` in the default header set and every proxy template, a set above
`PERMISSIONS_VALUE_MAX` refused with 403, `account.json.permissions` on an application's host, the permission API
`PUT /auth/api/apps/{id}/permissions` and `GET /auth/api/users/{id}/permissions?app=`); spec §3.4 and §8a with
`spec/vectors/permissions.json`; `has_permission` and `register_permissions` in the Python, Go, JavaScript, Rust and
PHP clients against the same vectors; example Ex1 registers at start and checks by the Go client. Breaks: upgrade list
"Upgrading from 0.31.x" items 3 and 4.

## Content
- App identity, taken over from [T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md): `apps[id].hosts`
  (each host in at most one application) as the host → application id the proxy path needs for `ts_perms` and
  `Remote-Permissions`; `forward_apps` stays as the per-host alias, translated by `config_check` (name falls back to
  `apps[id].name`). The reason it moved: before this task nothing reads `hosts`.
- `PUT /auth/api/apps/{id}/permissions` (register only; automation key, scope `permissions:register`), `GET /auth/api/users/{id}/permissions?app=`.
- Gate token claim `ts_perms` and header `Remote-Permissions` (new slot in `forward_headers`; an oversized set is rejected, not cut); `account.json.permissions`.
- `spec/gate-client.md` section 3 and 8a, vectors `permissions.json`; `has_permission` and `register_permissions` in the Go, Rust, JavaScript, PHP and Python clients against the same vectors.
- Effect: at the proxy path after the gate token TTL (default 300 s), immediately in the library and the service path; written in the spec.

## Acceptance
- Example **Ex1** (Go) registers at start and checks by the client; the vectors are green in all five clients.

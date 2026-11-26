---
id: T-101
type: Task
title: Stage S5 — permissions at the server and in the clients
status: offen
points: 13
milestone: M-2
blocked_by: [T-100]
tags: [permissions, clients, spec]
created: 2026-11-23
---
# T-101 — Stage S5 — permissions at the server and in the clients

**Story points:** 13 · **Estimate:** 22–30 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Server and client side of [ADR-17](ADR-17-permission-layer-and-admin-levels.md).

## Content
- `PUT /auth/api/apps/{id}/permissions` (register only; automation key, scope `permissions:register`), `GET /auth/api/users/{id}/permissions?app=`.
- Gate token claim `ts_perms` and header `Remote-Permissions` (new slot in `forward_headers`; an oversized set is rejected, not cut); `account.json.permissions`.
- `spec/gate-client.md` section 3 and 8a, vectors `permissions.json`; `has_permission` and `register_permissions` in the Go, Rust, JavaScript, PHP and Python clients against the same vectors.
- Effect: at the proxy path after the gate token TTL (default 300 s), immediately in the library and the service path; written in the spec.

## Acceptance
- Example **Ex1** (Go) registers at start and checks by the client; the vectors are green in all five clients.

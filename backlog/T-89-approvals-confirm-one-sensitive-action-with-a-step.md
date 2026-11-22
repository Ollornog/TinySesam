---
type: Task
title: 'Approvals: confirm one sensitive action with a step-up (stage A: TinySesam actions; stage B: application
  actions)'
status: in-arbeit
id: T-89
milestone: M-2
tags: [approvals, step-up, admin, delegates, mcp]
created: '2026-11-22'
---
# T-89 — Approvals: confirm one sensitive action with a step-up

A token proposes one sensitive action; the person confirms it in a browser session of the same account with a step-up
of THAT approval. TinySesam delivers only the evidence "this account has just confirmed, bound to exactly this action"
— no workflow, no second person, no deadlines of the application. Rule E4 (delegate and admin rights never through
tokens) stays: the token only writes a row, the session decides with its rights at confirmation time.

## Stage A — TinySesam actions (done in this pull request)

- [x] Table `approval` and migration (schema 22) with the columns stage B needs (`app_id`, `return_url`, `issued_at`).
- [x] States `pending → consumed | rejected | expired | withdrawn`, every transition one `UPDATE … WHERE state = <old>`.
- [x] `POST/GET/DELETE /auth/api/approvals` (API keys only; a session, an OAuth or MCP token and an app password are
      refused), `?wait=` long poll up to 25 s.
- [x] Pages `/auth/approvals` and `/auth/approvals/{id}`: a GET never decides; `frame-ancestors 'none'` whatever `csp`.
- [x] Step-up per approval: password/PIN/TOTP (`stepup_options`), passkey with a challenge bound to id and payload hash,
      provider with `max_age=0` and `auth_time` later than the request.
- [x] Types `tinysesam.account.set_roles` (roles only — never the admin flag, PO 2026-11-22), `tinysesam.apikey.revoke`,
      `tinysesam.account.disable`, executed with the admin panel's code (`admin.PanelActions`).
- [x] Badge "Approvals (n)" in the account menu, `topbar_data.approvals` (optional member of spec §8), limits,
      rejection lock, audit without values, `approval_approved` security event, gc.

## Stage B — application actions (open)

- [ ] Keyring `approval` (ADR-12) and JWKS `/auth/approvals/jwks.json`.
- [ ] `approval_apps`, `approval_types` (+ `approval_types_file`) with `config_check`; requests by the application's
      service account for an account (`subject`), own prefix only.
- [ ] Signed one-time confirmation (`typ=tinysesam-approval+jwt`, RFC 9396 `authorization_details`), picked up once.
- [ ] Browser entry with `return_url`/`state`; optional `POST …/executed`.
- [ ] `spec/approval-token.md`, `vectors/approval.json`; client helpers in Go, Rust, JS, Python and PHP.
- [ ] Clients normalize the topbar member `approvals` (spec §8); stage A only names it as optional.
- [ ] `Idempotency-Key` for requests.

Design: the accepted draft of 2026-11-22 (sections 0–12).

---
type: Task
title: 'Approvals: confirm one sensitive action with a step-up (stage A: TinySesam actions; stage B: application
  actions)'
status: erledigt
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

## Stage B — application actions

Part 1, the server side (done):

- [x] Keyring `approval` (ADR-12, `TINYSESAM_APPROVAL_KEY`, `approval_key_file`, `keys rotate|retire --purpose
      approval`) and JWKS `/auth/approvals/jwks.json` — never the gate key.
- [x] Types in the one application register: `apps[…].approvals.types` (or `types_file`), `return_urls`, `types_from`
      for a second channel — instead of the draft's own `approval_apps`/`approval_types`; `config_check` with English
      and German findings. Requests by the application's service account for a `subject`, own prefix only (`403
      forbidden_type`), schema checked (`400`), `approval_app_requests_per_hour`.
- [x] Signed one-time confirmation (`tinysesam.approval_token`, `typ=tinysesam-approval+jwt`, RFC 9396
      `authorization_details`, `ts_payload_sha256` over RFC 8785), signed at the pickup, handed out once (the pickup of
      the access reset generalized), never in the audit, a log or a URL.
- [x] Browser entry with `return_url`/`state` (back with `approval`, `state`, `result`; `state` as `nonce`), schema 24
      (`approval.nonce`).
- [x] `spec/approval-token.md`, `spec/vectors/approval.json` from the real issuing path, Python reference with the
      one-defect guard (`tests/test_approval_vectors.py`).

Part 2, the client helpers (done):

- [x] Approval helpers in Go (`ApprovalVerifier.Verify`), Rust (`approval::ApprovalVerifier`, `ApprovalJwksVerifier`
      behind `jwks`), JS/TS (`createApprovalVerifier`) and PHP (`ApprovalVerifier::create`), each with a fixed approval
      key set or the JWKS URL of §3 (a `…/gate/jwks.json` refused at start-up) and the `jti` store as an interface
      (callback, Go interface, Rust trait or two-step `check`/`accept`, PHP interface or callable; examples with one
      `INSERT`); every client runs every vector of `vectors/approval.json`, the "runner follows" entry of the vector
      guards is gone. Python: `tinysesam.approval_token.verify` stays the reference, plus `JWKSKeys` for the fetched
      key set (still importable without FastAPI).
- [x] An example application: `examples/approvals/app.py` (ask, browser entry, pickup, check, `jti` with one `INSERT`,
      the own rule again), `--demo` with a real TinySesam on loopback; `tests/test_example_approvals.py` drives it
      against TinySesam's real approval page.
- [x] Clients normalize the topbar member `approvals` (spec §8): first the evidence that all five tolerate it (the
      vector `approvals-pending` passed every client unchanged), then `{pending, href}` or `null` in all five.

Later, on demand:

- [ ] Optional `POST /auth/api/approvals/{id}/executed` (audit only, draft §4.2).
- [ ] `Idempotency-Key` for requests.
- [ ] A CLI import of an application's type snippet (an operator's action).

Design: the accepted draft of 2026-11-22 (sections 0–12).

## Closed 2026-11-23

Stages A and B are done. The "later, on demand" items moved to
[T-120](T-120-leftovers-of-approvals-account-api-and-app-frame.md).

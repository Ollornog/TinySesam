---
type: Task
title: 'Account API for applications (stage A: create, read, update, lock, link; stage B: delete, panel,
  CLI)'
status: in-arbeit
id: T-90
milestone: M-2
tags: [provisioning, accounts, service-accounts, delegates, api]
created: '2026-11-22'
---
# T-90 — Account API for applications

An application manages the accounts it creates itself, through its service account, inside narrow limits: ownership
only by `users.managed_by`, roles only from its allowlist, no access to sign-in methods, the one-time link only until
the first sign-in. TinySesam delivers identity, roles and approvals; team admins, collections and the like stay in the
application.

## Stage A — core (done in this pull request)

- [x] Register `apps` with the block `provisioning` (allowlist, scopes, link lifetime, quota, hourly limits) and
      `config_check` (never `admin`, a delegate role or a group-mapped role; one service account per application;
      `users:invite` needs the sign-in link and `base_url`; `admin_path='/auth'` refused; prefix warning).
- [x] Schema 23: `users.managed_by` (indexed), `users.last_login_at`, `users.delete_after`, lock value `disabled=3`.
- [x] `/auth/api/users`: create with a one-time link, read one or a page, `PATCH` display name and allowlist roles
      (`(current − allowlist) ∪ wanted` in one transaction), `disable`/`enable` with the application's own lock,
      `signin-link` before the first sign-in; `GET /auth/api/provisioning`.
- [x] Caller only through `verify_api_key` (automation key, `is_service == 1`, named as the application's account);
      404 for everything the application does not own, before any field; `409 account_shared` for whole-account
      actions; `config_check.may_manage` shared with the panel's delegates (T-74).
- [x] Limits per application and hour in the `flow` table (shared by workers), audit with the panel's event names plus
      `app=… actor_claimed=…`, start check of the service account.

## Stage B — delete, panel, CLI (open)

- [ ] `DELETE /auth/api/users/{id}`: never signed in → at once; otherwise `disabled=3` + `delete_after`, `restore`,
      `gc_provisioning` through `delete_user`; `users:delete`, `delete_grace_days`, `delete_per_hour`/`per_day`.
- [ ] Panel: mark "managed by", filter, adopt/release with step-up, "cancel deletion"; account page names the
      application as the origin of a link ("by Example").
- [ ] CLI `tinysesam accounts adopt|release|restore|list`.
- [ ] Browser test of the panel marks.

## Access reset (done in its own pull request)

- [x] Approval type `tinysesam.account.reset_access` (draft section 13, released by the PO on 2026-11-22): asked by the
      application's service account (scope `users:reset`) with `subject` = its team admin, confirmed with a step-up by
      a holder of `provisioning.approver_role` at confirmation time; target and right checked at the request and the
      confirmation; every factor deleted, sessions and standing credentials revoked, the new link picked up exactly
      once (`approved` → `consumed`, `output`). `config_check`: the role never in any allowlist (error), grantable by a
      delegate (warning). Tests `tests/test_reset_access.py` (six rows of the table with mutations, the straw-account
      attack end to end), browser test of the page.

## Later

- [ ] Gateway variable `TINYSESAM_APPS` — together with the switches the gateway preset turns off (API keys, sign-in
      link, a way to set up a factor); alone it could never pass `config_check`.
- [ ] `require_approval` per action (stage C), joining existing accounts with their consent.

Design: the accepted draft of 2026-11-22 (sections 0–13).

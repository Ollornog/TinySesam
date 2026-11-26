---
type: Task
title: 'Account API for applications (stage A: create, read, update, lock, link; stage B: delete, panel,
  CLI)'
status: erledigt
id: T-90
milestone: M-5
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

## Stage B — delete, panel, CLI (done in its own pull request)

- [x] `DELETE /auth/api/users/{id}`: never signed in → at once (`204`, `delete_user`); otherwise `disabled=3` +
      `delete_after` (`202`), `restore` within the period (afterwards `404`), the cleanup (`Store.gc_provisioning` in
      `TinySesam.gc()` and `tinysesam gc`) through the one deletion path; `users:delete`, `delete_grace_days`,
      `delete_per_hour`/`delete_per_day`; during the period every other write `409 account_deleting`; the operator's
      unlock ends a deletion. No schema change.
- [x] Panel: "App: Example" in the type column, filter by application, "Managed by …" (also "(not configured)") on the
      account page, "Take over for …"/"Release" (administrators, step-up), "Cancel deletion"; a delegate sees an
      application's account only in scope. English and German.
- [x] CLI `tinysesam accounts adopt|release|restore|list`; one rule for adopting (`provisioning.adopt_refusal`); start
      warning for accounts of an application that is not configured.
- [x] Follow-up of the access reset: a sign-in link the application obtained names it and dies at the door once the
      account is no longer wholly the application's (foreign role, admin, delegate, released) or someone signed in
      after it was issued (`TinySesam._app_link_refused`).
- [x] Tests `tests/test_accounts_stage_b.py` (every row of the stage-B table with its mutation), browser test of the
      panel marks (light/dark, 375/390 px, strict CSP).

## Access reset (done in its own pull request)

- [x] Approval type `tinysesam.account.reset_access` (draft section 13, released by the PO on 2026-11-22): asked by the
      application's service account (scope `users:reset`) with `subject` = its team admin, confirmed with a step-up by
      a holder of `provisioning.approver_role` at confirmation time; target and right checked at the request and the
      confirmation; every factor deleted, sessions and standing credentials revoked, the new link picked up exactly
      once (`approved` → `consumed`, `output`). `config_check`: the role never in any allowlist (error), grantable by a
      delegate (warning). Tests `tests/test_reset_access.py` (six rows of the table with mutations, the straw-account
      attack end to end), browser test of the page.

## Follow-up — panel hint

- [x] The account page notes an unmanaged account that no application could take over (no role, or roles outside
      every allowlist): `provisioning.no_app_can_adopt` over `adopt_refusal`, administrators only, no block.
- [x] `--config` of the CLI documented for a `TinySesam` object as well (`accounts`, `roles`, `diagnose`).

## Later

- [ ] Gateway variable `TINYSESAM_APPS` (now part of [T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md), M-2) — together with the switches the gateway preset turns off (API keys, sign-in
      link, a way to set up a factor); alone it could never pass `config_check`.
- [ ] `require_approval` per action (stage C), joining existing accounts with their consent.
- [ ] The holder's account page names the application as the origin of a link or lock ("by Example", draft §8).

Design: the accepted draft of 2026-11-22 (sections 0–13).

## Closed 2026-11-23

Stages A and B, the access reset and the panel hint are done. `TINYSESAM_APPS` is part of
[T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md); the other "later" items moved to
[T-120](T-120-leftovers-of-approvals-account-api-and-app-frame.md).

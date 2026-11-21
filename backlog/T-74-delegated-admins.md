---
id: T-74
type: Task
title: Delegated admins — a team admin who manages accounts within listed roles
status: erledigt
milestone: M-2
tags: [admin, roles]
created: '2026-11-21'
---
# T-74 — delegated admins

**Status: done** (decisions below; hierarchy added at the maintainer's request).

Source: a deployment where a team lead should manage the accounts of their team without becoming an administrator of
the whole installation.

## What it would mean

- A delegate role in the configuration, e.g. `admin_delegates={"teamadmin": {"roles": ["editors", "viewers"]}}`.
- A delegate **may**: create accounts, issue a sign-in link, lock and unlock, set or remove only the listed roles.
- A delegate **may not**: touch admin or delegate accounts, set the admin flag, change settings, see or revoke other
  people's API keys, read the audit log of everyone.
- The same fresh confirmation as an administrator (`admin_require_mfa`, `_require_fresh`).
- The delegate role never appears in tokens (gate token, OAuth, API keys), like `is_admin`.
- The admin panel shows a filtered view; every limit is enforced on the server, not only hidden in the page.

## Open questions

- One delegate role per team, or a list of role scopes per account.
- What a delegate sees of accounts outside their roles (nothing, or name only).
- Audit: their own actions and those on their accounts.

## Decisions (2026-11-21)

- **Scope strict:** a delegate acts only on accounts whose roles all lie within the managed roles (at least one) —
  never admin, owner, service or own account. Locking or a sign-in link acts on the whole account.
- **Hierarchy:** `manages` (DAG, several parents) — `eff(D) = roles(D) ∪ desc(D) ∪ ⋃ roles(K), K ∈ desc(D)`. Never
  sideways or upwards; never the own delegate role or one above it. `can` narrows one role's actions, not inherited.
- **Audit:** no audit view for delegates (the lines carry other people's addresses; the actor is only a text in the
  detail). Every action is logged with `actor=`, the panel's lines with `as=<delegate role>`.
- **Invitations** follow the rules of creating. Removing every role is allowed (the account leaves the scope).
- **Machine credentials** (automation keys, OAuth tokens, app passwords) carry no delegate role, at the same places
  that drop the admin flag; the panel demands a browser session.
- **Unlocking** an account an administrator locked stays possible (the lock records no author) — documented.
- The computation is pure (`config_check.delegation_graph`, `delegate_scopes`, `delegate_may_manage`) so a tenant
  (T-73) can later call it with its own delegation.

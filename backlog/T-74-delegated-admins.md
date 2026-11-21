---
id: T-74
type: Task
title: Delegated admins — a team admin who manages accounts within listed roles
status: offen
milestone: M-2
tags: [proposal, admin, roles]
created: '2026-11-21'
---
# T-74 — delegated admins

**Status: proposal.** The maintainer sets the priority; nothing is decided.

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

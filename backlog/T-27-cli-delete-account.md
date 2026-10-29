---
id: T-27
type: Task
title: CLI command to delete an account (maintenance without the admin panel)
status: erledigt
milestone: M-2
tags: [cli, wartung, konten, datenschutz]
created: 2026-10-11
---

# T-27 — `python -m tinysesam delete --db <file> <user>`

**Occasion (PO 2026-10-11):** An acceptance test with a test account against a production instance created a local
account there at the first OIDC login (a row in `users` plus `oidc_identity`). The instance runs with OIDC only,
without an admin panel and without an account page. Afterwards there was **no** supported way to remove the account
again: the CLI knows `passwd`, `backup`, `restore`, `gc`, `audit`, `unlock`, `owner`, `rename` and `gate-key`,
but no delete. A raw `DELETE` in the database would be the wrong way (audit anonymisation,
sign-in attempts, name binding — see `konto_entfernen`). The account therefore stayed; it just can no longer
sign in, because the IdP client no longer admits it.

The library has long been able to do it (B5-08 from [T-13](T-13-audit-2026-09-22-round-3.md): `TinySesam.delete_user` →
`Store.konto_entfernen`). Only the operator route on the command line is missing, just like `unlock`/`rename` for
their cases.

## To do

- New command `delete --db <file> <user>` in `tinysesam/__main__.py`, which deletes through the **same** route as
  the panel (`konto_entfernen`, not `Store.delete_user` directly — a test records that the raw building block
  has no further caller).
- The same protection rules as when deleting via the panel (check how it treats the owner, and do not
  make it looser here); unknown user → exit ≠ 0 with a clear message.
- Confirmation: ask interactively, `--ja` for scripts. The output names what was removed (name, number
  of sessions/identities), never secrets.
- Update help text, README section "Maintenance" and CHANGELOG.

## Done when

- A test creates an OIDC account with a session, deletes it via the CLI and checks: rows in `users`, `oidc_identity`,
  `session` gone, audit entry anonymised as when deleting via the panel, second call → exit ≠ 0.
- Mutation: command bent to `Store.delete_user` → the audit test turns red; protection rule removed → red.

## Done 2026-10-29

- `delete --db <file> <user>` (also `#<id>`) in `tinysesam/__main__.py`; goes through `Store.konto_entfernen` like the
  panel. The protection rule (owner, last admin) was moved into `Store.loeschsperre` and is used by
  `TinySesam.delete_user` and the command — one rule, not a copy. Asks on a terminal, `--ja` for scripts, no terminal
  and no `--ja` refuses.
- Test `tests/test_cli_delete.py` (OIDC account with sessions: rows gone, audit anonymised like the panel's, second
  call exit 1, owner / last admin, confirmation paths). Mutations red: command bent to `Store.delete_user`, protection
  rule removed, `--ja` / terminal check removed.
- Docs: README (en/de) "Removing an account", `docs/OPERATIONS.md`, CHANGELOG. API.md does not list CLI commands.

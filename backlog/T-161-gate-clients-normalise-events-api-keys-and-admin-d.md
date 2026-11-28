---
type: Task
title: Gate clients normalise events, API keys and admin data of account.json
status: erledigt
points: 5
id: T-161
milestone: M-2
created: '2026-11-28'
---
# T-161 — Gate clients normalise events, API keys and admin data of account.json

**Story points:** 5

Since T-106 account.json carries events (time, event, by_admin), programs.api_keys (name, kind, times) and admin.accounts (the path of GET /.tinysesam/admin/accounts.json, spec section 8b, only for administrators of the area). All five clients drop these members today: the vectors signed-in and offered-less in spec/vectors/account.json carry them in input, not in expected. Normalise them in Python, Go, Rust, JS and PHP (safe types; an href that fails the rule of section 8 becomes null, as for actions), move them into expected, and add a helper that reads and normalises the answer of section 8b (the accounts with the addresses of the administration action pages), with its own vectors. The HTTP tests of the clients (JS approval.test.ts, Rust tests/remote.rs, PHP ApprovalTest) follow expected; their stale comment goes (T-159). Acceptance: signed-in and offered-less expect the members; vectors for wrong types, unsafe hrefs and missing members of the three and of the section 8b answer; all five clients pass them; mutation per client.

## Done (sprint S9, 2026-11-28)

- Spec §8a: `events` (always a list), `programs.api_keys` (a list or `null`) and `admin` (`{accounts}` with a safe
  href, else `null`) are normalized; signed out both new members are `null`. §8b: the client's helper and its
  normalized form; attack classes `account-href`/`account-types` cover the administration data too.
- Vectors: `signed-in` and `offered-less` expect the members; new `events-keys-wrong-types`, `events-keys-not-list`,
  `events-keys-admin-missing`, `admin-accounts`, `admin-javascript`, `admin-protocol-relative`, `admin-not-text`,
  `admin-not-object`; the list `admin_accounts` (9, from TinySesam's own `admin_overview` for an administrator and a
  delegate).
- Python `parse_admin_accounts`, Go `ParseAdminAccounts`, Rust `account::normalize_admin`/`normalize_admin_json`, JS
  `parseAdminAccounts`, PHP `Account::parseAdminAccounts`. Upgrade list item 8 (additive members).
- T-159 closed with it (the stale comment in the three HTTP tests).
- Not part of it: Ex4 keeps reading `account.json` and the administration data itself — the JS helpers import the
  client's other modules, and a page without a bundler cannot carry them as source like the parser of the way back.

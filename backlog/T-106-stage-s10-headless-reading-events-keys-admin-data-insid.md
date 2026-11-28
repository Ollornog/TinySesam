---
id: T-106
type: Task
title: "Stage S10 — headless reading: events, keys, admin data inside the application"s area"
status: erledigt
points: 13
milestone: M-2
blocked_by: [T-105]
tags: [headless, admin, spec]
created: 2026-11-23
---
# T-106 — Stage S10 — headless reading: events, keys, admin data inside the application's area

**Story points:** 13 · **Estimate:** 26–32 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

## Content
- `account.json`: `events`, `api_keys`, error format `error`, Fetch Metadata.
- Admin read inside the area of the application only (`/.tinysesam/admin/*.json`, spec section 8b); the panel link stays a link, nothing is switched off. The administrator flag is never settable by link.
- Hardening and configuration remain instance-wide and are not reachable from an application.

## Acceptance
- **Ex4**: the application's own admin page from `admin/*.json` plus the account API plus action pages; panel and full account page are never opened.

## Done (S9)

- `account.json` (`account_overview`): `events` (the account page's own events: `at`, `event`, `by_admin`, never an
  address), `programs.api_keys` (the keys `api_keys_active` counts: name, kind, times, never the prefix), `admin`
  (`{accounts: "/.tinysesam/admin/accounts.json"}` for a person who administers accounts inside the application's
  area). Every refusal carries `error` (`signed_out`, `cross_site`, `not_found`, `rate_limited`); Fetch Metadata:
  `Sec-Fetch-Site: cross-site`/`same-site` → 403 first (`tinysesam/_routes_data.py`, split out of the router).
- Admin read (spec §8b): `GET /.tinysesam/admin/accounts.json` on an application's host with the panel on, and
  `auth.admin_overview(user, app_host)` (tier B): administrators and the delegates whose role names the application in
  `admin_delegates[role].apps`; the panel's list (delegate scopes), per account id, names, source, roles, lock state,
  TOTP, the application's permissions and the addresses of the administration action pages offered now. No email,
  hash, key prefix, address, admin or owner flag; hardening and configuration not reachable.
- A confirmed address change asked for in a frame leads back to the frame's home, not to the full account page.
- Acceptance: Ex4's administration section is drawn from the admin data (its own `/admin/accounts.json` and the
  permission `docs.admin` are gone; `docs-admin` is a delegate of the area); `tests/test_headless_browser.py` X6
  (administrator), X8 (delegate; no page view of the panel, the area or the full account page), X1/X3 (own events and
  keys); `tests/test_headless_reading.py` R1–R6.

Proposed follow-ups: the five clients normalise `events`, `programs.api_keys`, `admin` and offer a helper for the
administration data (§8b, vectors); `api_keys_active` counts expired keys; a program's revocation on an action page
fetches the full account page through the redirect it follows.

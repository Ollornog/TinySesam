---
id: T-76
type: Task
title: 'Top bar: visibility per link, and the bar as JSON'
status: erledigt
milestone: M-5
tags: [topbar, ui]
created: '2026-11-21'
---
# T-76 — top bar link visibility

Source: a deployment whose top bar links lead to areas that only administrators or one role can open; everyone else
saw links that end in "access denied". Its applications are not all Python, so they also need the bar as data.

## Done

- `topbar_links` entries take an optional third element, `{"admin": True}` or `{"role": "…"}` (exactly one).
  A `(title, target)` pair stays visible to everyone.
- One filter (`topbar.visible_links`) serves the bar, the phone menu (`tsbar-mlinks`), `auth.topbar(request)` and the
  JSON. Pages without the account menu (sign-in, errors) render no link at all, so no restricted target is in their
  source.
- `config_check`: a visibility role outside `available_roles` is a warning, a malformed third element an error.
- `GET /auth/topbar.json` (tier B) and, on a protected application's host, `GET /.tinysesam/topbar.json` (tier A, a
  proxy path): links, display name, whether *Account* and *Admin panel* appear and their absolute addresses, the
  sign-out address. `Cache-Control: no-store`, `Vary: Cookie`, no CORS header.
- `TINYSESAM_TOPBAR_LINKS` (gateway) takes `[title, target, {visibility}]`.

## Decisions

- **`admin_implies_roles` includes role links.** A role link follows `has_role`, which lets an administrator satisfy
  every role while `admin_implies_roles` is on (the default). The link then appears exactly where the target's own
  `require(role=…)` lets the account in. Who switches the setting off hides role links from administrators without the
  role, too.
- **Visibility is a convenience, not a protection.** The target checks access itself; a hidden link is not a lock.
- **An unknown rule hides the link.** `link_visible` is fail-closed; `config_check` refuses such a rule at the start so
  it never gets there silently.
- **The JSON follows the HTML bar.** Without a session — an API key included, it gets no account menu — no links and
  no menu.
- **Two addresses for the JSON.** Behind the gate the proxy templates strip TinySesam's cookies before the application
  (B-20), so the application's server cannot forward them. `/.tinysesam/*` reaches TinySesam with the browser's cookies;
  the page's script fetches `/.tinysesam/topbar.json` from its own origin, no CORS needed. Folding the data into the
  forward-auth answer was left out: unbounded header size for every request.

## Not done

- Own entries in the account menu (the second idea of the proposal) — no deployment asked for it yet.

## Proof

- `tests/test_topbar_visibility.py`: B1–B7 of the acceptance list, the JSON (headers, anonymous, API key, without
  `base_url`, on the application's host), the gateway variable.
- Mutations, all red: rule ignored, role link by the role list alone (admin_implies_roles ignored), warning removed,
  JSON unfiltered.

---
type: Task
title: The five clients normalise actions and the session handle
status: erledigt
points: 5
id: T-148
milestone: M-2
created: '2026-11-28'
---
# T-148 — The five clients normalise actions and the session handle

**Story points:** 5

Since T-105 (sprint S7) `account.json` carries `actions` and `sessions.items[].handle`/`end`; spec §8a lists them as not normalised and the Go, Rust, JS, PHP and Python clients drop them (the vector `signed-in` carries them in `input`, not in `expected`). Normalise them in all five clients, move them into `expected`, and give the clients a call to end a session by its handle.

## Done (sprint S8, 2026-11-28)

- Spec §8a: `actions` is a member of the table; `handle` (text) and `end` (href) per session are normalized; §8c names
  the client's call that builds the address of an action page (`action_url` and its peers), with the escaping rule.
- Vectors: `signed-in` expects `actions`, `handle` and `end`; new `actions-unsafe-hrefs`, `actions-wrong-types`,
  `actions-missing`; the list `action_urls` (23 vectors, attack class `action-request`).
- Python, Go, Rust, JavaScript and PHP normalize them and offer the call; `tests/test_action_pages.py` drives the action
  page through the address the Python client built.
- Not part of it: a parser of the way back (`ts_action` incl. the eight `admin_*` names, `ts_result`, `state`) in the
  clients — the application reads its own query today.

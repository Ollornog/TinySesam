---
type: Task
title: The five clients normalise actions and the session handle
status: offen
points: 5
id: T-148
milestone: M-2
created: '2026-11-28'
---
# T-148 — The five clients normalise actions and the session handle

**Story points:** 5

Since T-105 (sprint S7) `account.json` carries `actions` and `sessions.items[].handle`/`end`; spec §8a lists them as not normalised and the Go, Rust, JS, PHP and Python clients drop them (the vector `signed-in` carries them in `input`, not in `expected`). Normalise them in all five clients, move them into `expected`, and give the clients a call to end a session by its handle.

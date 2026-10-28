---
id: T-24
type: Task
title: Acceptance — before/after measurement and acceptance test per app
status: erledigt
milestone: M-3
tags: [gateway, messung, test]
created: 2026-10-03
---

# T-24 — Acceptance

- Measurement with an asset-heavy sample page: load time and number of TinySesam calls with
  `/auth/forward` versus gate token. Result in `docs/BETRIEB.md`.
- Acceptance test pattern per app (script/test template): unprotected path → login; share path open;
  path next to the share prefix closed; logout `app`/`alle` as in T-22; header spoofing (`Remote-User`)
  ineffective.

**Done when:** measured values are in the docs, the acceptance pattern lies under `deploy/forward-auth/`.

## Done 2026-10-07

- Measurement `scripts/gate_messung.py`, values in `docs/BETRIEB.md`. Honestly: for single requests
  the gate saves only about 0.3 ms; the gain (factor 12–13) arises under concurrency. The first attempt
  with a Python client gave the opposite (gate slower) — it measured the client. With `hey` and a
  static application the picture is right; the Python client is discarded.
- Acceptance pattern `deploy/forward-auth/abnahme.sh` (bash + curl, `--path-as-is`), run in the Caddy test against
  the test setup, with a control run; 3 mutations on the script red.
- Header spoofing can be checked from outside only as "opens nothing". That the application does not see a
  foreign `Remote-User` is checked by `tests/test_gate_caddy.py` against the dummy.

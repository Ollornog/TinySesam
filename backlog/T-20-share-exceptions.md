---
id: T-20
type: Task
title: Share exceptions per app — exact path prefixes before the gate, with a control test
status: erledigt
milestone: M-3
tags: [gateway, caddy, share]
created: 2026-10-03
---

# T-20 — Share exceptions

Apps with share links need public paths. The exception sits in the proxy **before** the gate.

**To do:** docs + example (Caddy `handle @share`), patterns for known apps as a starting point (measure
each app yourself: share pages load their own assets and API calls). Never extension matchers.
Remove `Remote-User` here too. Small check tool or test pattern: a path **outside** the
list (also with `..`, `%2e`, double slash) must return 401 or 307.

**Done when:** example and control test in the repo, configuration check (T-23) warns about extensions.

## Done 2026-10-07

- `@share` in both Caddy templates, off until `TS_SHARE_PRAEFIX` is set.
- **Measurement before the rule** (Caddy 2.11.7): The `path` matcher compares the cleaned path and
  does not distinguish upper/lower case, but passes the raw one on to the application.
  `/s/..;/admin`, `/s/..%5cadmin` and `/s/abc%00` got through, `/x/../s/abc` and `/S/abc` likewise.
  That is why the rule checks `orig_uri.path` with an expression and rejects tricks separately.
- No "check tool" in the package: the control test against a real application is its share page in the
  browser (instructions `docs/OPERATIONS.md`). For the template itself `tests/test_gate_caddy.py` measures
  16 tricks and neighbouring paths as well as 5 open paths.
- The point from T-23 ("configuration check warns about extensions") is dropped: the list sits in the proxy,
  TinySesam does not see it. The guard in `tests/test_gate.py` holds the shape of the templates.
- Mutation: 5 interventions in the templates, all red.

---
id: T-12
type: Task
title: Assess the CodeQL backlog and track the open alerts in the backlog
status: erledigt
milestone: M-1
tags: [codeql, ci, hygiene, security]
created: 2026-09-22
---

# T-12 — CodeQL backlog

On 2026-09-22 `main` held **61 open CodeQL alerts** that nobody had ever assessed. They do
nothing — until a pull request touches one of their lines: then CodeQL posts each one as a review
thread, and `main` requires resolved conversations. A `note` alert then blocks the merge just like
a critical one (as happened in #52).

## What was done

- **One real finding:** `examples/showcase.py` put the username unescaped into the HTML of the
  demo pages `/app` and `/sensibel` (`py/reflective-xss`). Fixed with `html.escape`.
- **Nine false alarms dismissed in GitHub with a reason** — not struck here, otherwise they would
  come back on the next run:
  - `py/url-redirection` (2×, `router.py`): the target is a fixed relative path, the token is
    inserted URL-encoded. No open redirect.
  - `py/clear-text-logging-sensitive-data` (4× in `security.py`, `manager.py`, `__main__.py`):
    what is logged are proxy IPs, hostnames and "password too short" without the value.
  - `py/clear-text-logging-sensitive-data` (2×, `tests/_kit/report.py`): the test reporter
    prints check names.
  - `py/weak-sensitive-data-hashing` (`manager.py`): API keys are random tokens with 256 bits of
    entropy, not a password — a fast hash is the standard there (as for session tokens).
  - `py/overly-permissive-file` (`tests/test_security_findings.py`): the test deliberately
    creates a 0644 file to check the warning about it.
- **Rest cleaned up mechanically:** unclosed files in tests, four URL substring checks
  in tests, unused imports and variables, empty `except` blocks with a reason, mixed
  returns, duplicate imports.
- **`scripts/_codeql_backlog.py`** fetches the open list through the API and writes it below,
  between the markers. New alerts thus land here — in the repo, in the diff — instead of only in
  the inbox. The email itself can only be switched off at GitHub: repo → Watch → Custom →
  deselect "Security alerts".

**Done when:** the table below is empty or every remaining entry carries an assessment here, and
the suite is green after the cleanup.

## Done 2026-09-25

On `main` no CodeQL alert is open any more (table below, freshly generated). The others were
fixed or dismissed with a reason in GitHub (among them the test apps in `test_csrf.py` and the
script splitter in `test_admin.py`, "used in tests"). CodeQL reports new alerts on every PR as a
review thread; `scripts/_codeql_backlog.py` remains the way to bring the state on `main` here.

## Open alerts (generated)

<!-- CODEQL:START -->
_Keine offenen Alerts._
<!-- CODEQL:END -->

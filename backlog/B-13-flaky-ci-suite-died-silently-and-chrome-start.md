---
id: B-13
type: Bug
title: 'CI flakes: a suite died from a segfault without a word, Chrome hung at startup'
status: erledigt
milestone: M-2
tags: [ci, tests, flaky]
created: '2026-11-20'
---
# B-13 — CI flakes: a suite died from a segfault without a word, Chrome hung at startup

**Seen:** `test_values_english.py` red three times in CI (on `main` and in a PR, Python 3.13 and 3.15), locally
green. Under `FAIL test_values_english.py` stood nothing of its own — only the warnings in its stderr. Separately,
the browser test in the job `repeat`: “Chrome wrote no DevTools port (after 30s)”, Chrome alive, its log empty.

## Cause 1 — why nothing was in the log
The suite was killed by a signal. Its stdout went into a pipe, block-buffered, and was lost with the process; the
runner did not show the exit code or signal. Reproduced with a dummy suite that segfaults: the old runner prints
`FAIL test_crash_probe.py` and nothing else — exactly the CI picture.

**Fix:** `tests/run_all.py` runs every suite with `PYTHONUNBUFFERED=1` and `PYTHONFAULTHANDLER=1`, names the end
under `FAIL` (`(exit 1)` or `(killed by signal SIGSEGV)`), says `no output on stdout` when there is none, and
shows stderr from the start of a crash report or traceback instead of only the last 2000 characters.

## Cause 2 — the segfault
Since H2 (T-47, `notify_new_access`) `create_api_key` and other access events queue a notice in the background
outbox (`tinysesam.mailer.Outbox`); the job reads the account and writes an `audit` row over the store's
connection. The suite closes that connection itself (`a.store.db.close()`) right after creating keys, to start
the library again on the same file. If the worker was still inside SQLite, `sqlite3` freed the connection under
it. Reproduced: 200–300 rounds of “create key → close” crash in 5 of 5 runs (3.13 and 3.15) with
`Fatal Python error: Segmentation fault` in `Store._exec` ← `audit_log` in the worker thread.

Production never closes the connection under a running worker — only the tests do (13 suites call
`store.db.close()`).

**Fix:** `tests/_starter.py` creates every `sqlite3` connection in the test process with a subclass whose
`close()` first waits until every outbox has run its queued jobs (`Outbox.wait`). After it: 0 crashes in
5 × 300 rounds (3.13) and 3 × 300 (3.15); the suite 100× green (12 in parallel, 3.13) and 60× (3.15).

## Chrome
Measured locally: Chrome writes the DevTools port after 0.2 s, under full CPU load (16 busy loops, four Chromes
at once) after at most 1.3 s. 30 s is therefore not a slow start but a hang — the timeout stays. A hanging
session or system D-Bus was ruled out (Chrome writes the port after 0.1 s even then). The cause could not be
reproduced locally; the failure message now names where Chrome stands (time since start, load, free memory,
profile content, state and `wchan` of every Chrome process and thread of the main process), and Chrome logs its
own INFO lines (`--enable-logging=stderr`). The next occurrence will show the place.

**Guards:** `tests/test_runner.py` section K (signal name, stdout before the crash, faulthandler stack, crash
excerpt, close waits for the outbox — and does not without the starter). Mutation probes: each of the five
changes removed individually turns exactly its check red.

---
id: B-13
type: Bug
title: 'CI flakes: a suite died from a segfault without a word, a dialog wait raced, Chrome hung at startup'
status: erledigt
milestone: M-5
tags: [ci, tests, flaky]
created: '2026-11-20'
---
# B-13 — CI flakes: a suite died from a segfault without a word, a dialog wait raced, Chrome hung at startup

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

**Production is not affected — measured.** The library never closes the shared connection (`auth.store` is tier C,
there is no close method); at the end of the process `concurrent.futures` joins the outbox workers before the
interpreter tears anything down. 150 processes that queue five notices each and end right away: 0 crashes, all
750 `access_notice` rows written. Only code that closes `auth.store.db` itself (the tests) can hit the race.
A public, safe way to shut down came with [T-67](T-67-orderly-shutdown-close.md) (`TinySesam.close()`, 2026-11-21).

## Cause 3 — a dialog wait in the browser test raced
Seen on this fix's own PR (job `repeat`): “the dialog did not close (at …/auth/account)”. `Page.answer()` clicked
OK and then waited for “no `dialog.tsdlg` at all”. The recovery-code flow opens the next dialog (the codes) right
after the confirmation; when the request was quick it was open before the first poll, and the wait ran out
although everything worked.

**Fix:** `answer()` waits until the dialog it answered has left the document. A new check in the dialog section
answers a `tsConfirm` that opens a `tsAlert` in the same microtask — deterministic: with the old wait it is red
with exactly the CI message, with the new one green.

## Chrome
Measured locally: Chrome writes the DevTools port after 0.2 s, under full CPU load (16 busy loops, four Chromes
at once) after at most 1.3 s. 30 s is therefore not a slow start but a hang — the timeout stays. A hanging
session or system D-Bus was ruled out (Chrome writes the port after 0.1 s even then), and so was a second suite
running beside it: the same hang hit PR #244 in the job `browser`, where the browser test runs alone. The cause could not be
reproduced locally; the failure message now names where Chrome stands (time since start, load, free memory,
profile content, state and `wchan` of every Chrome process and thread of the main process), and Chrome logs its
own INFO lines (`--enable-logging=stderr`). The next occurrence will show the place.

**Guards:** the dialog check above; `tests/test_runner.py` section K (signal name, stdout before the crash, faulthandler stack, crash
excerpt, close waits for the outbox — and does not without the starter). Mutation probes: each of the five
changes removed individually turns exactly its check red.

## Chrome — cause found (2026-11-21)
A cold disk, not D-Bus. The suites looked up the runner image's **preinstalled** `google-chrome` before the `chrome`
that `setup-chrome` unpacked; on a fresh runner nothing had read its ~400 MB, and Chrome faulted its binary in page by
page. The state dump from #273 showed it: main process `state=D wchan=folio_wait_bit_common`. Reproduced in
DashMyBoard (page cache dropped, disk throttled to 30 read IOPS): no port within 30 s; after reading the files first
the same start passes.

**Fix:** CI sets `CHROME=<setup-chrome's chrome-path>` for the browser suites; `find_chrome()` (`tests/voraussetzung.py`)
honours it first and stops on a wrong path; `prewarm_chrome()` reads Chrome's files once before the timed start. The
30 s limit stays. **Guards:** `tests/test_chrome_choice.py` (`CHROME` goes first; the read covers the executed binary
and not only the wrapper) and a check in `tests/test_repo.py` that CI passes `CHROME`; each mutated red.

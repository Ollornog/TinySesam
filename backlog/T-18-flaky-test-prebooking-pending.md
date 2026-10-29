---
id: T-18
type: Task
title: Flaky test test_prebooking_pending — red once in the CI job repeat, cause open
status: erledigt
milestone: M-2
tags: [tests, wackeltest, ci, parallel]
created: 2026-09-28
---

# T-18 — `test_prebooking_pending.py` was red once, without it being visible why

**Finding.** In the CI job `repeat` of PR #108 (run 36360175849, commit 4c7ba7e, `ubuntu-latest`,
2 test jobs, FastAPI 0.141.1) `test_prebooking_pending.py` was red once: `42 ok, 1 Fehler`.
Which check failed was not in the log. `tests/run_all.py` showed only the last
2000 characters of the output, and the `FEHL` line stood before that. This has been fixed since PR #108: under
`FAIL` all `FEHL` lines are now shown (`tests/test_runner.py` I).

**Narrowed down.** The visible excerpt began at the check "is_locked at the series limit …
as deferral", and from there on everything was green. So the failed check is **before** that, in
sections (a) first window, R7-2 burst, orphaned pre-bookings, (d) parallel login at
the limit or (d3) deferral at the series limit. Three of them wait with a fixed
`time.sleep(HANGS * 0.4)` for the parallel sign-ins to have arrived in the hanging directory.
Under load that can be too short.

**Cannot be reproduced.** Locally 20× without load and 30× under full load (12 busy loops on 12
threads) green, and in two further CI runs of the same PR `repeat` was green as well.

## Open

- [ ] On the next red run, fetch the `FEHL` line from the log; the display is there now.
- [ ] If it is down to a wait point: do not lengthen the time, but wait for the state
      (`Verzeichnis.fragen` or the number of pending pre-bookings, with a deadline) and hold the hanging
      of the directory until the test releases it.

## Done 2026-10-07

Not seen red again since PR #108 (the `FEHL` line would have been in the log since then). The
second point is implemented, without waiting for the next red run:

- All six fixed wait points (`time.sleep(HANGS * 0.4)`, `* 0.3`, `0.15`) now wait with
  `wait_until()` for the state that the check reads afterwards: the number of attempts that have
  arrived in the directory (`Verzeichnis.fragen`), with a deadline and a named error.
- **Not** implemented: letting the directory "hang until the test releases". In (d), (d3) and (h)
  the parallel sign-ins themselves go into the directory. A release only after their result would have
  blocked them against each other, and the timing checks in (a) and (e) depend on the hang duration. Waiting
  for the arrival removes the suspected cause (read before everyone had arrived) without this
  rebuild.
- Evidence: 3 runs without load, 15 runs under full load (12 busy loops on 12 threads), all green. If
  the suite turns red again anyway, the `FEHL` line is in the log — then a new bug entry with
  it.

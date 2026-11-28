---
id: T-145
type: Task
title: "Panel browser tests: account-switch race and the shared CDP helper"
status: offen
points: 3
milestone: M-5
tags: [tests, browser]
created: 2026-11-28
---
# T-145 — Panel browser tests: account-switch race and the shared CDP helper

**Story points:** 3 · **Estimate:** 4–6 h · **Milestone:** [M-5](M-5-after-1-0.md)

S6 #425: part C of `tests/test_shell_browser.py` deleted the cookies while the panel still reloaded its matrix (a 401
on a correct request). The panel tests in `tests/test_browser.py` switch accounts the same way and do not yet use the new
`tests/_cdp.py`.

## Content
- Check every account switch in `tests/test_browser.py` for a pending panel request (leave the page first, wait for the
  redraw); move the file onto `tests/_cdp.py`.

## Acceptance
- A mutation that removes the wait turns a test red; no test lost.

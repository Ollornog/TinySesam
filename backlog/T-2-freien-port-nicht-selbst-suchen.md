---
id: T-2
type: Task
title: Browser test should not look for a free port itself
status: erledigt
milestone: M-1
tags: [testing, browser, flaky]
created: 2026-07-10
---

# T-2 — Do not look for a free port yourself

`tests/test_browser.py: free_port()` binds a port, closes it and returns the number.
**In between, another process can take it** — a classic race condition that makes the test fail
rarely and inexplicably.

## Solution

Start Chrome with `--remote-debugging-port=0` and read the actual number from `DevToolsActivePort`
in the profile directory. Proven in a sibling project.

**Done when:** `free_port()` is gone and the suite stays green even with parallel runs.

## Done (2026-09-19)

The Chrome half was already built (`--remote-debugging-port=0` + `DevToolsActivePort`); what
remained was the **uvicorn test server**, which had the same bug.

Solved not by searching better, but by making the gap disappear: the socket is bound and **kept
bound**, then handed to `uvicorn.Server.run(sockets=[...])`. There is no longer a moment between
"port determined" and "port taken" in which anyone else could grab it. `free_port()` is gone
without replacement.

Verified with four parallel runs of the browser suite on the same machine — all green. A direct
negative test cannot sensibly be constructed: race conditions show up rarely, the evidence is the
structural disappearance of the window.

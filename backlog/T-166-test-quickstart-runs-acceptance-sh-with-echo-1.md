---
type: Task
title: test_quickstart runs acceptance.sh with ECHO=1
status: offen
points: 1
id: T-166
milestone: M-5
created: '2026-11-28'
---
# T-166 — test_quickstart runs acceptance.sh with ECHO=1

**Story points:** 1

Follow-up of T-141. The forgery checks of deploy/forward-auth/acceptance.sh run against a stand-in proxy and real Caddy, not against the quickstart stack. Let test_quickstart run acceptance.sh with ECHO=1. Acceptance: a quickstart template without the strip line turns the test red.

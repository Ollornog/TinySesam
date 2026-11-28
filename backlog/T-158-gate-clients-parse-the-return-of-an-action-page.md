---
type: Task
title: Gate clients parse the return of an action page
status: offen
points: 3
id: T-158
milestone: M-2
created: '2026-11-28'
---
# T-158 — Gate clients parse the return of an action page

**Story points:** 3

Follow-up of T-148. The clients build the action URL (action_url) but leave reading the way back to the app: ts_action (own action names and the eight admin_* names), ts_result and state. Add a checked parser in all five clients (unknown action or result is rejected, state compared in constant time against the caller's value), spec section 8c and vectors. Acceptance: vectors for every action name, unknown values and a wrong state; Ex4 uses the JS parser.

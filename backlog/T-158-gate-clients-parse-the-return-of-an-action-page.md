---
type: Task
title: Gate clients parse the return of an action page
status: erledigt
points: 3
id: T-158
milestone: M-2
created: '2026-11-28'
---
# T-158 — Gate clients parse the return of an action page

**Story points:** 3

Follow-up of T-148. The clients build the action URL (action_url) but leave reading the way back to the app: ts_action (own action names and the eight admin_* names), ts_result and state. Add a checked parser in all five clients (unknown action or result is rejected, state compared in constant time against the caller's value), spec section 8c and vectors. Acceptance: vectors for every action name, unknown values and a wrong state; Ex4 uses the JS parser.

## Done (sprint S9, 2026-11-28)

- Spec §8c "Reading the way back": the query between the first `?` and the first `#`, only the three names as written,
  nothing for an ordinary visit, `invalid` (an unknown action or result, a name twice or missing, a broken escape, a
  value outside printable ASCII, a `state` outside the rule), `state` (not the one issued, constant time).
- Vectors: the list `action_returns` in `spec/vectors/account.json` (59: every one of the 21 action names and every
  result from TinySesam's own way back, odd addresses, refusals), attack class `action-return`.
- Python `parse_action_return`/`ActionReturnRefused`, Go `ParseActionReturn` (`ErrActionReturnInvalid`,
  `ErrActionReturnState`, a fuzz target), Rust `account::parse_action_return`, JS `parseActionReturn` (self-contained;
  the vector test runs its source copy in an empty context too), PHP `Account::parseActionReturn`.
- Ex4 reads its results with the JS parser (carried into the page as source); `tests/test_headless_browser.py` X4
  shows an unknown action refused and an ordinary visit silent; `tests/test_action_pages.py` reads the page's own way
  back with the Python parser.

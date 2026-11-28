---
type: Task
title: Ex4 uses the JS client helpers of T-158 and T-161
status: offen
points: 2
id: T-168
milestone: M-5
created: '2026-11-28'
---
# T-168 — Ex4 uses the JS client helpers of T-158 and T-161

**Story points:** 2

Ex4 runs without a bundler and inlines only the return parser; the helpers for account data and the admin overview (T-161) are not used. Find a way without a bundler (module script from the client's build) and use them. Acceptance: Ex4 contains no own normalisation of account.json.

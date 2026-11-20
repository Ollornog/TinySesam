---
id: B-8
type: Bug
title: Voluntary TOTP setup does not lead on — the page stays on "2FA active"
status: erledigt
milestone: M-2
tags: [totp, account, ui]
created: 2026-11-20
---

# B-8 — Voluntary TOTP setup does not lead on

## Repro

Fully signed in, classic mode (no `login_chain`), e.g. `examples/demo.py`. Open
`/auth/totp/setup?next=/auth/account`, start the setup, enter a valid code.

**Expected:** after activation the page leads on to the target (here the account page).
**Actual:** `POST /auth/totp/setup` answers `{"ok": true, "other_sessions": 0}` without `next`. The page script only
navigates on `j.ok && j.next`, so it stays on "2FA active".

## Cause

Only the mandatory setup under `login_chain` (A-1) returned `next`; the voluntary branch returned early without it.

## Fix

The voluntary branch also returns `next`: the given target through `safe_next`; without one the account page when
`account_enabled`, otherwise `login_redirect` (`_setup_next` in the router; the setup page carries the same default in
`data-next`). The page leads on only after the session offer (`offer()`) and after the recovery codes are noted (B-9a).

Tests: `tests/test_account_setup.py` (target given, no target, foreign target, account page off) and
`tests/test_browser.py` (`account_setup`: the click on "I have written them down" lands on the account page).

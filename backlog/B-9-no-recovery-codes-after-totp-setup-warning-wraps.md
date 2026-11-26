---
id: B-9
type: Bug
title: No recovery codes after the TOTP setup, and the warning on the account page wraps into the buttons
status: erledigt
milestone: M-5
tags: [totp, recovery, account, ui]
created: 2026-11-20
---

# B-9 — No recovery codes after the TOTP setup; the warning wraps

## Repro

**a)** Set up TOTP (voluntarily or as the mandatory step under `login_chain`), then open the account page.
**Expected:** the account has recovery codes, shown once during the setup.
**Actual:** the setup creates none; the account page says "Only 0 recovery codes left — generate new ones".

**b)** Account page with TOTP, 1280 px wide.
**Expected:** the remainder line sits on its own, readable, and shows the current number.
**Actual:** `#rc_left` is an inline `<small class=err>` next to the buttons; it wraps over two lines and overlaps the
button row. After "Generate recovery codes" it still shows the old number (the script never touched it).

## Cause

a) Recovery codes came only from the button (`POST /auth/totp/recovery`, 0.6.0 "self-service regeneration"). Nothing
in code, CHANGELOG or backlog argued against creating them with the factor — it was simply never done.
b) Inline badge in the button row; no update in `recovery()`.

## Fix

a) `POST /auth/totp/setup` creates `recovery_code_count` codes on a successful confirmation and returns them once
(`recovery_codes`), on both paths. No step-up as at `/auth/totp/recovery` (R3-3): there the codes replace a factor
somebody else may hold; here the session has just proven the new factor itself, and whoever holds the secret needs no
codes. `totp_begin` already clears orphaned codes; an API key never reaches the confirmation (`require_session`). The
setup page shows the codes and leads on only after "I have written them down". The account page tells "No recovery
codes" (0) apart from "Only n left".
b) `#rc_left` is a block (`.rcleft`) below the buttons; `recovery()` sets text and class from the new count.

Tests: `tests/test_account_setup.py` (codes on both paths, none on a wrong code, the three texts, block after the
buttons), `tests/test_browser.py` (`account_setup`: codes shown once, line below the buttons and on one line at
1280/390 px, updated after "generate"). Screenshots before/after in the PR.

---
id: B-10
type: Bug
title: An account without a password cannot set one — the account page demands the current password
status: erledigt
milestone: M-5
tags: [password, account, self-service]
created: 2026-11-20
---

# B-10 — An account without a password cannot set one

## Repro

Account created without a password (sign-in link, OIDC, passkey). Open the account page, section "Password".

**Expected:** the account can set a first password.
**Actual:** the page asks for the "current password"; `change_password` refuses an empty one with `missing` (400).
There is no way to get a password at all.

## Fix

- Building block `set_initial_password(request, new, *, csrf=None) -> PasswordChangeResult` (tier A) and route
  `POST /auth/password/set` (JSON `new`). Instead of the old password: freshness, the rule that already applies to
  creating the FIRST factor (`config.stepup_max_age_sec`, `/auth/pin/set`) — a fresh step-up if the account has a
  factor (`stepup_options()`, reason `stepup`, 403 with `X-TinySesam-Reauth`), otherwise the age of the sign-in
  (`login_fresh()`, reason `relogin`, 403). Plus CSRF, a full session (no API key), per-IP rate limit, password rule,
  audit `password_set`, event `password_changed`.
- Refused: existing password (`has_password`, 409 — the old one stays required, `change_password`), password sign-in
  off (`method_disabled`, 404), `ldap_enabled` (`directory`, 409 — a local password next to the directory one would
  keep working after the directory disables the account; the same caution as the username self-service, which is off
  with LDAP).
- Other sessions are not ended; the response carries `other_sessions` and the page offers it (B1-7), as after a new
  factor.
- Account page: without a password "Set password" without the current-password field (`password_initial`); after
  setting, the regular change form.

The follow-up T-34 (first sign-in by link, then forced setup of password/TOTP/passkey) reuses `set_initial_password`:
right after a link sign-in the session is fresh and the account has no factor, so `login_fresh()` lets it through.

Tests: `tests/test_account_setup.py` (page, CSRF, rule, success + audit + offer, 409 afterwards, stale sign-in, stale
step-up, API key, LDAP, password sign-in off), `tests/test_stepup.py` (route classified, API key and existing password
refused), `tests/test_browser.py` (`account_setup`: set in a real browser).

---
id: T-63
type: Task
title: 'Notify the holder of a successful sign-in after failed attempts'
status: erledigt
milestone: M-5
tags: [security, notification]
created: '2026-11-20'
---
# T-63 — Notify the holder of a successful sign-in after failed attempts

Source: rest of T-47 (security review 2026-11-20, finding N2 — ASVS 6.3.5/6.3.7 L3). H2 built the events for new
access; this third one was left out of the H2 scope.

**Is:** failed attempts and the later sign-in appear in the account page's "Recent activity", but no event and no
mail says "someone signed in after N failed attempts".

**Proposal:** count the account's failed attempts before `lift_lockout` clears them at a complete sign-in (careful:
`_record_login` already clears those of the same method on success — count before that), event
`signed_in_after_failures` (`failures`, `ip`), mail via `notify_new_access` (or its own switch). Effort S.

## Done (H4)
- `TinySesam._lift_after_sign_in(uid, ip)` replaces `lift_lockout(uid)` at the five places where a sign-in becomes
  complete. It reads the streak (B2-6, `failure_series_confirmed` over `count_identifiers`) BEFORE `lift_lockout`
  clears it — the window in `login_attempt` would not do, `_record_login` already cleared the succeeding method.
- From `_AFTER_FAILURES_MIN = 3`: audit `login_after_failures failures=N` (account page "Recent activity"), event
  `signed_in_after_failures` (`failures`, `ip`; `SECURITY_EVENTS`, tier A), mail under `notify_login_failures`
  (own list `_FAILURE_MAIL_EVENTS` — it belongs to the failed attempts, not to new access).
- One or two typos stay quiet; a repeated identical wrong password counts once (existing rule).
- Tests: `tests/test_h4_auth_hardening.py` (T-63 block); browser test checks the account page line.
- Sources: ASVS 5.0.0 6.3.5 ("a successful authentication after several unsuccessful attempts").

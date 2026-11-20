---
id: T-44
type: Task
title: 'QR / cross-device sign-in: harden against consent phishing'
status: erledigt
milestone: M-2
tags: [security, qr-login, cross-device]
created: '2026-11-20'
---
# T-44 — QR / cross-device sign-in: harden against consent phishing

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M6 — RFC 10027 (BCP 247) §6.1, ASVS 6.6.2/6.6.3, 7.6.2.

**Is:** the approval page is a GET link that can be sent to a victim; it shows the attacker's User-Agent/IP; no
proximity check, no freshness (→ B-12), no security event; `/auth/qr/status` polls without `_rate_ok`. An account
without a second factor is taken over with one click (`tinysesam/manager.py:4525-4610`, `router.py:549-640`).

**Proposal:** approval only from the own session or by typing the code (number matching); `require_mfa()`; warning
text "only approve if YOU stand in front of the other device"; event `device_signed_in`; rate limit on status; optional
same public IP (§6.1.8). Effort M.

## Done (H2)
- Number matching: the new device shows a two-digit number (`qr.match_hint`), the approval wants it typed
  (`POST /auth/qr/approve` field `match`); a wrong or missing number voids the request (audit `qr_login_mismatch`).
  The number is not in the approval link, so a forwarded link alone approves nothing.
- Warning on the approval page (`qr.warning`); fresh confirmation (B-12) — a stale page goes over the reauth page
  and comes back with its code.
- Accounts without a second factor: refused by default (`qr_login_require_second_factor=True`). Reason: for them
  one approval is the whole sign-in; with TOTP/passkey the new device has to present the factor as well
  (`magiclink_require_second_factor`), so a phished approval gives a half sign-in at most. Switch off → allowed,
  number and freshness still apply.
- `/auth/qr/status`: own throttle, 120 polls per address and minute (`router._QR_STATUS_PER_MINUTE`), then 429.
- Event `device_signed_in` (T-47). Same public IP (§6.1.8) not built: behind mobile networks and NAT it refuses the
  legitimate case more often than it stops an attacker; number matching covers the proximity question.

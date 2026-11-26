---
id: T-47
type: Task
title: 'Notify the account holder about new access (link issued, new device, success after failures)'
status: erledigt
milestone: M-5
tags: [security, notification]
created: '2026-11-20'
---
# T-47 — Notify the account holder about new access (link issued, new device, success after failures)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N2 — NIST SP 800-63B-4 §4.1.2.1, ASVS 6.3.5/6.3.7 (L3).

**Is:** `SECURITY_EVENTS` (`tinysesam/manager.py:1210-1215`) lacks `signin_link_issued` (audit only), QR approval /
new device and "successful sign-in after failed attempts".

**Proposal:** three events; optional mail like `notify_login_failures`. Effort S.

## Done (H2)
- `on_security_event` (extended, not new): `signin_link_issued` (`ttl_min`, `by_operator`), `device_signed_in`
  (`method`, `ip`, `agent`); `password_changed` carries `by_operator`. Existing: `passkey_added`, `totp_enabled`,
  `pin_set`, `api_key_created`, `oauth_device_connected`, `oauth_token_reuse`.
- Mail only with a mailer (`notify_new_access`, default on): verified address, no link, at most one per account and
  event a minute, background outbox. The holder's own password change mails nothing.
- Account page "Recent activity" (reused): the admin's reset now also lands under the holder
  (`password_set_by_admin`, "by an administrator"), next to `signin_link_issue`, `qr_login` and the factor lines.
- "Successful sign-in after failed attempts" (in the title) moved to T-63 — the master scope for H2 named the six
  kinds above; the failed attempts are already visible in "Recent activity".

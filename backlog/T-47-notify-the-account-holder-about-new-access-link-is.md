---
id: T-47
type: Task
title: 'Notify the account holder about new access (link issued, new device, success after failures)'
status: offen
milestone: M-2
tags: [security, notification]
created: '2026-11-20'
---
# T-47 — Notify the account holder about new access (link issued, new device, success after failures)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N2 — NIST SP 800-63B-4 §4.1.2.1, ASVS 6.3.5/6.3.7 (L3).

**Is:** `SECURITY_EVENTS` (`tinysesam/manager.py:1210-1215`) lacks `signin_link_issued` (audit only), QR approval /
new device and "successful sign-in after failed attempts".

**Proposal:** three events; optional mail like `notify_login_failures`. Effort S.

---
id: T-57
type: Task
title: 'TOTP: accept at most one step back (switch totp_window)'
status: offen
milestone: M-2
tags: [security, totp]
created: '2026-11-20'
---
# T-57 — TOTP: accept at most one step back (switch totp_window)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N7 — ASVS 6.5.5 (L2), RFC 6238 §5.2.

**Is:** `valid_window=1` (`totp.py:26,31-51`) accepts ±1 step (90 s); replay protection is correct (`store.py:3157-3167`).

**Proposal:** switch `totp_window` (default: one step back, none ahead). Effort S.

---
id: T-46
type: Task
title: 'Admin-set password must not become the permanent password'
status: offen
milestone: M-2
tags: [security, admin, password]
created: '2026-11-20'
---
# T-46 — Admin-set password must not become the permanent password

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M8 — ASVS 6.4.1 (L1), 6.4.6 (L3).

**Is:** `POST /api/users/{uid}/password` (`tinysesam/admin.py:181-205`) sets the chosen password for good; no
"change at next sign-in" marker.

**Proposal:** move the panel's password reset to the existing sign-in link + setup pass (T-33/T-34), or set a
must-change marker; keep the old way only behind a switch. Effort M.

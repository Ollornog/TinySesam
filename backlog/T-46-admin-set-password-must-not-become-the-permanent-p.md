---
id: T-46
type: Task
title: 'Admin-set password must not become the permanent password'
status: erledigt
milestone: M-5
tags: [security, admin, password]
created: '2026-11-20'
---
# T-46 — Admin-set password must not become the permanent password

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M8 — ASVS 6.4.1 (L1), 6.4.6 (L3).

**Is:** `POST /api/users/{uid}/password` (`tinysesam/admin.py:181-205`) sets the chosen password for good; no
"change at next sign-in" marker.

**Proposal:** move the panel's password reset to the existing sign-in link + setup pass (T-33/T-34), or set a
must-change marker; keep the old way only behind a switch. Effort M.

## Done (H2)
- Marker `users.password_must_change` (schema 18, additive), set by the panel (new account with password, reset)
  via `set_password(…, by_operator=True)` while `admin_password_must_change=True` (default).
- A sign-in that USED that password stays half (`_password_change_owed` in `_session_ok`); the next step is
  `password_change` → `/auth/setup` (the T-34 page, one password card); `POST /auth/password/set` from that half
  session sets an own password (rule; not the admin's one), clears the marker and completes the sign-in under a new
  token. The half session expires with the step-up window. Any own password clears the marker.
- The old way only behind the switch (`admin_password_must_change=False`).

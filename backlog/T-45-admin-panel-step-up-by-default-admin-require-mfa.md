---
id: T-45
type: Task
title: 'Admin panel: step-up by default (admin_require_mfa)'
status: erledigt
milestone: M-5
tags: [security, admin, stepup]
created: '2026-11-20'
---
# T-45 — Admin panel: step-up by default (admin_require_mfa)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M7 — ASVS 7.5.3, 8.4.2 (L3), NIST SP 800-63B-4 §2.2.3.

**Is:** `admin_require_mfa=False` (`tinysesam/config.py:316`); an old admin session sets passwords, issues sign-in links
for any account (up to 7 days) and grants roles/admin without a step-up.

**Proposal:** default `True`, at least for writing panel routes; `config_check` warns on `False`. Behaviour change →
CHANGELOG. Effort S.

## Done (H2)
- `admin_require_mfa` default `True` (CHANGELOG "Changed", way back `False`); `config_check` warns on `False` (de+en).
- Admin without a second factor: the step-up asks the password (`stepup_options`). Purely federated admin: the
  sign-in time counts; a stale one is told "sign out and sign in again" (`err.stepup_relogin`) instead of "set up a
  method" — nobody is locked out. The panel script follows `X-TinySesam-Reauth` to the reauth page and back.

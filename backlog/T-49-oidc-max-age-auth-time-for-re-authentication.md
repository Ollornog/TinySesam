---
id: T-49
type: Task
title: 'OIDC: max_age / auth_time for re-authentication'
status: offen
milestone: M-2
tags: [security, oidc, stepup]
created: '2026-11-20'
---
# T-49 — OIDC: max_age / auth_time for re-authentication

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N5 — ASVS 6.8.4 (L2).

**Is:** freshness of federated accounts counts from TinySesam's own sign-in; a silent re-login through the running IdP
session counts as fresh (`oidc.py` sends no `prompt`/`max_age`, checks no `auth_time`).

**Proposal:** for step-up send `prompt=login` / `max_age=0` and check `auth_time`. Effort M.

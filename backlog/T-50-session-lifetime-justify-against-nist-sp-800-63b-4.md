---
id: T-50
type: Task
title: 'Session lifetime: justify against NIST SP 800-63B-4, document parallel sessions'
status: offen
milestone: M-2
tags: [security, sessions, docs]
created: '2026-11-20'
---
# T-50 — Session lifetime: justify against NIST SP 800-63B-4, document parallel sessions

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N3 — ASVS 7.1.1, 7.1.2 (L2); NIST SP 800-63B-4 §2.2.3 (AAL2: ≤ 24 h total, ≤ 1 h inactivity, SHOULD).

**Is:** 168 h with "stay signed in", inactivity timeout off there (`config.py:320-328`, `docs/OPERATIONS.md:136-160`);
no reference to 800-63; no limit and no documentation for parallel sessions.

**Proposal:** a documented justification (re-read the exact AAL2 wording first); optional `session_max_per_account`. Effort S.

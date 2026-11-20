---
id: T-51
type: Task
title: 'Sign-in link lifetimes: magic link 10 min, admin link at most 24–72 h'
status: offen
milestone: M-2
tags: [security, magic-link, admin]
created: '2026-11-20'
---
# T-51 — Sign-in link lifetimes: magic link 10 min, admin link at most 24–72 h

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N4 — ASVS 6.5.5 (L2: out-of-band ≤ 10 min), NIST SP 800-63B-4 §4.2.2 (by mail ≤ 24 h).

**Is:** `magiclink_ttl_min=15` (`config.py:203`), `_SIGNIN_LINK_MAX_TTL_MIN` = 7 days (`manager.py:4465`).

**Proposal:** default 10 min; admin link at most 24 h, or 72 h with a written reason. Effort S.

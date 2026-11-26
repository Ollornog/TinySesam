---
id: T-51
type: Task
title: 'Sign-in link lifetimes: magic link 10 min, admin link at most 24–72 h'
status: erledigt
milestone: M-5
tags: [security, magic-link, admin]
created: '2026-11-20'
---
# T-51 — Sign-in link lifetimes: magic link 10 min, admin link at most 24–72 h

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N4 — ASVS 6.5.5 (L2: out-of-band ≤ 10 min), NIST SP 800-63B-4 §4.2.2 (by mail ≤ 24 h).

**Is:** `magiclink_ttl_min=15` (`config.py:203`), `_SIGNIN_LINK_MAX_TTL_MIN` = 7 days (`manager.py:4465`).

**Proposal:** default 10 min; admin link at most 24 h, or 72 h with a written reason. Effort S.

## Done (H4)
- `magiclink_ttl_min` default 15 → **10** (mailed sign-in link, reset link, invitation without own `ttl_min`).
- New `signin_link_max_ttl_min` (default **1440** = 24 h, allowed 1–10080) replaces the fixed week
  `_SIGNIN_LINK_MAX_TTL_MIN`; above it `create_signin_link` raises `ValueError` with the bound (`api.signin_link_ttl`,
  400 in the panel). `config_check`: range, and an error when the bound is below `magiclink_ttl_min`.
- Upgrade path: `magiclink_ttl_min=15`, `signin_link_max_ttl_min=10080` restore the old values (CHANGELOG).
- 72 h with a written reason was not taken: NIST names 24 h for a code sent by mail, and a hand-over link by any
  channel is no less a key; a week stays possible on purpose.
- Tests: `tests/test_h4_auth_hardening.py` (T-51 block), `tests/test_sign_in_alternatives.py` adjusted to the bound.
- Sources: ASVS 5.0.0 6.5.5 ("Out of band requests must have a maximum lifetime of 10 minutes"); NIST SP 800-63B-4
  §4.2.2 (issued recovery codes "24 hours when sent to an email address"), §3.1.3.2 (out-of-band: "invalid unless
  completed within 10 minutes").

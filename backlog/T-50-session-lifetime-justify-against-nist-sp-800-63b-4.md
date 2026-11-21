---
id: T-50
type: Task
title: 'Session lifetime: justify against NIST SP 800-63B-4, document parallel sessions'
status: erledigt
milestone: M-2
tags: [security, sessions, docs]
created: '2026-11-20'
---
# T-50 — Session lifetime: justify against NIST SP 800-63B-4, document parallel sessions

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N3 — ASVS 7.1.1, 7.1.2 (L2); NIST SP 800-63B-4 §2.2.3 (AAL2: ≤ 24 h total, ≤ 1 h inactivity, SHOULD).

**Is:** 168 h with "stay signed in", inactivity timeout off there (`config.py:320-328`, `docs/OPERATIONS.md:136-160`);
no reference to 800-63; no limit and no documentation for parallel sessions.

**Proposal:** a documented justification (re-read the exact AAL2 wording first); optional `session_max_per_account`. Effort S.

## Done (H4)
- `docs/OPERATIONS.md`, new section "Lifetimes against NIST SP 800-63B-4, parallel sessions": the re-read limits
  (AAL1 overall SHOULD ≤ 30 days, inactivity MAY; AAL2 overall SHOULD ≤ 24 h, inactivity SHOULD ≤ 1 h; AAL3 SHALL
  ≤ 12 h / SHOULD ≤ 15 min), a table of the four session settings against AAL1/AAL2, the three reasons for the AAL2
  deviations (new access wants a 15-minute confirmation; "stay signed in" is a per-sign-in choice; sessions are
  server-side, visible and revocable, OIDC re-checked, notifications), and the settings that meet AAL2 to the letter.
- Defaults unchanged on purpose: password-only sign-ins are AAL1, and the defaults meet AAL1.
- Parallel sessions (ASVS 7.1.2): documented as unlimited, with the reason (a limit lets a thief push the holder
  out) and how they are seen and ended. `session_max_per_account` not built — documentation is what 7.1.2 demands;
  open for whoever needs a limit.
- Sources: NIST SP 800-63B-4 §2.1.3, §2.2.3, §2.3.3 (Reauthentication), §5.2; ASVS 5.0.0 7.1.1, 7.1.2.

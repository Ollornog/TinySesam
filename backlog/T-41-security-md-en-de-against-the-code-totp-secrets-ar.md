---
id: T-41
type: Task
title: 'SECURITY.md (en/de) against the code: TOTP secrets are encrypted since 0.21.0'
status: erledigt
milestone: M-2
tags: [docs, security]
created: '2026-11-20'
---
# T-41 — SECURITY.md (en/de) against the code: TOTP secrets are encrypted since 0.21.0

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N1.

**Was:** both SECURITY.md said TOTP secrets were stored unencrypted, "planned (H-14/H-15)" — encrypted with
AES-256-GCM since 0.21.0. Operators were advised against the wrong risk.

## Done (H1)
- Section replaced: what is encrypted (TOTP secrets, OIDC refresh and ID tokens), where the key comes from, that the
  default `<db>.key` beside the database also derives the gate-token signing key (mint tokens for every app) — keep it
  outside the data directory, back it up separately; no rotation yet (→ T-48).
- New section "Vulnerable dependencies": deadlines (critical 7, high 30 days) and how they are kept (→ T-42).
- The rest read against the code: event list = `SECURITY_EVENTS`, first-admin token, `__Host-` limit still accurate.

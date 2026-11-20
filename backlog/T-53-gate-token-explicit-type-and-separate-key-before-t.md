---
id: T-53
type: Task
title: 'Gate token: explicit type and separate key before the OAuth AS signs JWTs'
status: offen
milestone: M-2
tags: [security, gate, jwt]
created: '2026-11-20'
---
# T-53 — Gate token: explicit type and separate key before the OAuth AS signs JWTs

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N9 — RFC 8725 §3.11, ASVS 9.2.2 (L2).

**Is:** `"typ": "JWT"` (`tinysesam/gate.py:100`). Relevant as soon as the OAuth authorization server (T-36) signs JWTs
too: type confusion between gate and OAuth tokens.

**Proposal:** `typ: tinysesam-gate+jwt` (checked by the templates via caddy-jwt where possible) and an own HKDF `info`
per token kind. Effort S.

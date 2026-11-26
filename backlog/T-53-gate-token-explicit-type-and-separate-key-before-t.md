---
id: T-53
type: Task
title: 'Gate token: explicit type and separate key before the OAuth AS signs JWTs'
status: erledigt
milestone: M-5
tags: [security, gate, jwt]
created: '2026-11-20'
---
# T-53 — Gate token: explicit type and separate key before the OAuth AS signs JWTs

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N9 — RFC 8725 §3.11, ASVS 9.2.2 (L2).

**Is:** `"typ": "JWT"` (`tinysesam/gate.py:100`). Relevant as soon as the OAuth authorization server (T-36) signs JWTs
too: type confusion between gate and OAuth tokens.

**Proposal:** `typ: tinysesam-gate+jwt` (checked by the templates via caddy-jwt where possible) and an own HKDF `info`
per token kind. Effort S.

## Done (2026-11-20, ADR-12)

Header `typ: tinysesam-gate+jwt` and `kid`; `gate.check` refuses any other type. The gate key is a key of its own
(T-48). caddy-jwt 1.4.0 cannot check `typ` (no option; measured: `JWT` and `at+jwt` pass) — at the proxy the
separation rests on the dedicated key and on `aud` (a bare host, never an RFC 8707 URL audience); a claim-based matcher in
the template was weighed and left out (ADR-12).

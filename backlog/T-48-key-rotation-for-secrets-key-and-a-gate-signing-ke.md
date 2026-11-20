---
id: T-48
type: Task
title: 'Key rotation for secrets_key, and a gate signing key of its own'
status: offen
milestone: M-2
tags: [security, crypto, gate]
created: '2026-11-20'
---
# T-48 — Key rotation for secrets_key, and a gate signing key of its own

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M5 — ASVS 11.1.1, 11.1.2 (L2), 13.3.4 (L3).

**Is:** one base key encrypts TOTP secrets and refresh/ID tokens and derives the Ed25519 gate key
(`tinysesam/gate.py:55`); default location `<db>.key` beside the database; no rotation (`docs/OPERATIONS.md:311`).
After a leak: lose every TOTP setup or keep a compromised gate key.

**Proposal:** `tinysesam rekey` (prefix `v2:`, old key reads, new key writes), re-encrypt, new `gate-key` output
(`kid` exists); crypto inventory in OPERATIONS.md; `config_check` hint for the gateway without
`TINYSESAM_SECRETS_KEY`/`secrets_key_file`. With T-54 (AAD) in the same `v2:`. Effort M.

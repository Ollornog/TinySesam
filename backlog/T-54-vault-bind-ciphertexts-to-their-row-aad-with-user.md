---
id: T-54
type: Task
title: 'Vault: bind ciphertexts to their row (AAD with user_id and column)'
status: offen
milestone: M-2
tags: [security, crypto]
created: '2026-11-20'
---
# T-54 — Vault: bind ciphertexts to their row (AAD with user_id and column)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N10.

**Is:** the AAD of AES-GCM is only the prefix `v1:` (`tinysesam/vault.py:121`); with WRITE access to the database the
encrypted TOTP secret of one account can be copied to another.

**Proposal:** `user_id` and column into the AAD — together with T-48 under `v2:`. Effort S.

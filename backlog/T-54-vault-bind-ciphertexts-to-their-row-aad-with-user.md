---
id: T-54
type: Task
title: 'Vault: bind ciphertexts to their row (AAD with user_id and column)'
status: erledigt
milestone: M-5
tags: [security, crypto]
created: '2026-11-20'
---
# T-54 — Vault: bind ciphertexts to their row (AAD with user_id and column)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N10.

**Is:** the AAD of AES-GCM is only the prefix `v1:` (`tinysesam/vault.py:121`); with WRITE access to the database the
encrypted TOTP secret of one account can be copied to another.

**Proposal:** `user_id` and column into the AAD — together with T-48 under `v2:`. Effort S.

## Done (2026-11-20, ADR-12)

Format `v2:<kid>:…`, AAD = key ID + table/column + the row's lasting identity (account; client and subject; client and
account; token row; purpose and kid). `v1:` values are read with every key and rewritten at the start. A value moved to
another row or column, or with an edited key ID, no longer decrypts (`tests/test_keys.py`).

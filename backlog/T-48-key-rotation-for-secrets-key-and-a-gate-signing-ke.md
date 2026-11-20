---
id: T-48
type: Task
title: 'Key rotation for secrets_key, and a gate signing key of its own'
status: erledigt
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

## Done (2026-11-20, ADR-12)

One key per purpose (`vault`, `gate`, `oauth-pepper`), each a keyring with key IDs (`tinysesam/keys.py`). The gate key
and the pepper are random keys of their own — `TINYSESAM_GATE_KEY`/`gate_key_file`, `TINYSESAM_OAUTH_PEPPER`/
`oauth_pepper_file`, otherwise in the table `key_material` encrypted with the vault key — never derived from it.
`tinysesam keys list|rotate|reencrypt|retire`; `retire` refuses while anything still needs a key. `/auth/gate/jwks.json`
for caddy-jwt `jwk_url` (previous gate key published for 3600 s). Migration: the base key is vault version 1, the
derived gate key and pepper stay previous keys; way back `keys reencrypt --to v1`. Crypto inventory and steps:
docs/OPERATIONS.md "Keys". `config_check`: key file readable by others, key file beside the database, gate key reachable
through the data directory alone. Tests: `tests/test_keys.py`.

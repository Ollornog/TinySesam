---
id: T-124
type: Task
title: "Crypto inventory and post-quantum readiness (harvest now, decrypt later)"
status: offen
milestone: M-6
blocked_by: [T-112]
tags: [security, crypto, pq]
created: 2026-11-23
---
# T-124 — Crypto inventory and post-quantum readiness (harvest now, decrypt later)

**Story points:** 5 · **Estimate:** 8–12 h (not measured) · **Milestone:** [M-6](M-6-trust-hardening-and-launch.md)

Know every place that uses cryptography and keep the algorithms exchangeable, so the move to post-quantum
algorithms is a configuration change, not a rewrite.

## Content
- Inventory: every key, signature, MAC, hash and cipher in the core, the gate and approval tokens, the vault, the
  OAuth server and the clients — algorithm, key size, where the key lives, how it rotates (ADR-12).
- Transport: measure which TLS groups the shipped templates and the gateway image offer (hybrid X25519MLKEM768 in
  Caddy and Go; OpenSSL 3.5 or later in the image for outgoing connections).
- Agility: `alg` and `kid` exchangeable for every signed token (gate, approval, OAuth); a test that a second
  algorithm can be added without a format break.
- A plan (not a build) for ML-DSA in JOSE once the IETF drafts are final; passkeys are watched, not changed.

## Acceptance
- `docs/crypto.md` with the inventory; a test fails when a new cryptographic call appears outside the inventory;
  measured TLS groups recorded; the agility test green.

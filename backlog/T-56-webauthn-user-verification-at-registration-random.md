---
id: T-56
type: Task
title: 'WebAuthn: user verification at registration, random user handle'
status: offen
milestone: M-2
tags: [security, passkey, webauthn]
created: '2026-11-20'
---
# T-56 — WebAuthn: user verification at registration, random user handle

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N6 — WebAuthn Level 3 §7.1, §14.6.1.

**Is:** registration does not check UV (`webauthn_.py:112`) while sign-in demands it; the user handle is the sequential
account ID (`webauthn_.py:83`) — reveals the account count, correlatable across RPs.

**Proposal:** `require_user_verification=True` at registration; 64 random bytes as user handle for new passkeys
(existing ones keep theirs). Effort S.

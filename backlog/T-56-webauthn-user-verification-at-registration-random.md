---
id: T-56
type: Task
title: 'WebAuthn: user verification at registration, random user handle'
status: erledigt
milestone: M-5
tags: [security, passkey, webauthn]
created: '2026-11-20'
---
# T-56 — WebAuthn: user verification at registration, random user handle

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N6 — WebAuthn Level 3 §7.1, §14.6.1.

**Is:** registration does not check UV (`webauthn_.py:112`) while sign-in demands it; the user handle is the sequential
account ID (`webauthn_.py:83`) — reveals the account count, correlatable across RPs.

**Proposal:** `require_user_verification=True` at registration; 64 random bytes as user handle for new passkeys
(existing ones keep theirs). Effort S.

## Done (H4)
- `reg_finish` passes `require_user_verification=(passkey_user_verification == "required")` to
  `verify_registration_response` — the same rule as the sign-in. A refused answer is a 400 (`api.passkey_reg_failed`,
  audit `passkey_create_failed reason=<exception type>`) instead of an unhandled 500.
- User handle of new passkeys: `TinySesam._webauthn_user_handle(uid)` = HMAC-SHA-512(instance salt, account ID),
  64 bytes, the same for every passkey of one account, different per account and per instance. The salt is created
  on first use in the setting `webauthn_handle_salt` (`Store.webauthn_handle_salt`, race-safe). No schema change: TinySesam
  never looks an account up by handle (sign-in by credential ID), so existing passkeys keep their old handle and work.
- Deviation from the proposal: not "64 random bytes stored per account" but an HMAC with a random instance salt —
  indistinguishable from random to anyone outside, no column, no migration, no rollback note needed.
- Tests: `tests/test_h4_auth_hardening.py` (T-56 block) with a software authenticator (real attestation "none",
  P-256, the library's real verification).
- Sources: W3C WebAuthn Level 3 §7.1 (registration step "If user verification is required for this registration,
  verify that the UV bit of the flags in authData is set"), §14.6.1 ("It is RECOMMENDED to let the user handle be
  64 random bytes").

---
type: Task
title: Administration action confirmed by passkey or provider sign-in
status: offen
points: 5
id: T-156
milestone: M-3
created: '2026-11-28'
---
# T-156 — Administration action confirmed by passkey or provider sign-in

**Story points:** 5

Follow-up of T-147. An administration action page confirms the one action by password, TOTP or PIN today. Add passkey (WebAuthn assertion bound to the ticket) and a fresh provider sign-in (OIDC/SAML with max_age/prompt=login) as confirmation, for accounts without a local secret. Acceptance: Ex4 runs one admin action confirmed by passkey and one by provider in the browser; the ticket stays single-use and bound to person, action and account.

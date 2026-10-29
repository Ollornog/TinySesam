---
id: T-4
type: Task
title: Email verification and invitation without the magic-link endpoint
status: erledigt
milestone: M-1
tags: [mail, registration]
created: 2026-07-10
---

# T-4 — Decouple verification/invitation from the magic link

Email verification and invitation currently use the same endpoint as the magic link
(`/auth/magic/{token}`). Anyone who turns off magic link thereby also loses verification and
invitation — two things that have nothing to do with each other.

**Done when:** both paths have their own endpoint and magic link can be turned off independently.

## Done (2026-09-19)

Three paths instead of the expected two — during the rework it turned out that **password reset**
had the same flaw: its route required `password_reset_enabled AND magiclink_enabled`, although it
had long had its own endpoint. It now depends only on its own switch.

| Purpose | before | now |
|---|---|---|
| Sign-in link | `/auth/magic/{token}` | unchanged |
| Confirm address | `/auth/magic/{token}` | `/auth/verify/{token}` (tied to `signup_verify_email`) |
| Invitation | `/auth/magic/{token}` → redirect | `/auth/invite/{token}` (tied to `allow_signup`) |
| Password reset | `/auth/magic/{token}` → redirect | `/auth/reset?token=…` directly in the link |

The links are built per purpose from `TinySesam.TOKEN_PATHS` (`magic_url(raw, base, purpose)`).
`/auth/magic/{token}` now only accepts `login` tokens and rejects others **without consuming
them** — a wrongly guessed endpoint does not make the token worthless.

**Hard cut, deliberate** (PO decision): confirmation and invitation links already sent as
`/auth/magic/…` are invalid. The dispatcher `_magic_dispatch` is gone; what remains is a shared
sign-in helper for the two paths that really prove the same thing (access to the mailbox).

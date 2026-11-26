---
type: Task
title: 'First sign-in by one-time link: recovery codes switchable, TOTP app hint, target after the setup'
status: erledigt
id: T-94
milestone: M-5
tags: [onboarding, totp, account-api, redirect]
created: '2026-11-23'
---
# T-94 — First sign-in by one-time link, shorter

An operator walked a colleague without technical knowledge through the first sign-in (link → password → TOTP →
recovery codes → the application's home page) and it took too long. Three general changes, none for one application.

1. **Recovery codes switchable** — `recovery_codes_enabled` (default `True`). A switch of its own rather than
   `recovery_code_count=0`: the count has been bounded 1–100 since B3-12 precisely because `0` once issued nothing and
   still reported success, and `generate_recovery_codes(n=0)` falls back to the count; a separate switch reads as what
   it does and keeps the count meaningful. Off: the setup goes straight on (no code page, no codes), `/auth/totp/recovery`
   is `404`, the account page has no code action (the panel never had one), `generate_recovery_codes` raises
   `ConfigError`, and `_verify_recovery_code` looks at no code — every way that took a code (`login_totp`, the step-up)
   goes through it. Existing codes are **kept, not deleted**: switching back on is the way back, and a refused code is
   not used up. `config_check` warns when TOTP is on and no application has `users:reset` — the only configured way that
   resets a lost authenticator; the admin panel removes no TOTP (finding while checking, see below).
2. **`totp_app_hint`** — `{lang: text}` above the QR code (and on the start step), `lang` → `en` → first entry; escaped,
   1–300 characters, no control/format characters or line breaks, at most 20 languages; a runtime value past the check
   is not shown.
3. **Target after the setup** — optional `next` on `POST /auth/api/users` and `POST /auth/api/users/{id}/signin-link`,
   default `apps[…].provisioning.welcome_url`, also for the link of a confirmed `reset_access`.
   `config_check.link_next_ok` is the one rule (and `create_signin_link` uses it too): a path or an http(s) address on the
   host of `base_url` or in `trusted_redirect_hosts`, printable ASCII, no user part, `//`, other scheme, backslash or
   placeholder, ≤ 2048 characters. Wrong → `400 next_invalid` before anything is written. `apps[…]` carries no host of
   its own, so the circle is that of every redirect. Stored in the token payload (no schema change), re-checked at the
   door; audit `next_host=`. Not for the panel's link and invitation (no application context, no field in the UI) and
   not for the CLI (it issues no links).

Open, not part of this task: the README told operators to "remove a lost factor in the panel" — the panel removes
passkeys, not TOTP. A panel action "reset second factor" would give operators without an application a way back
when codes are off.

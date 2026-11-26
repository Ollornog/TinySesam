---
type: Task
title: 'Sign-in alternatives: QR/cross-device login, admin-issued link without mail, self-request switchable'
status: erledigt
id: T-33
milestone: M-5
tags: [login, magic-link, qr, admin]
created: '2026-11-20'
---
# T-33 — Sign-in alternatives: QR/cross-device login, admin-issued link without mail, self-request switchable

Wish (PO 2026-11-20), modelled on PocketID's login alternatives. Builds on the existing magic link (`magiclink_enabled`, `/auth/magic/request`, confirm page + POST redeem, `magiclink_require_second_factor`, `create_magic_token`/`magic_url`) — extend it, no second token system.

**1. QR code / cross-device sign-in.** A new device shows a QR code plus a short code on the login page. A device where the user is already signed in scans it (or types the code) and approves; the new device then gets its own session. Short TTL, single use, the approving side shows which device/IP asks (against phishing a code onto someone else's screen), rate-limited, audited. The second-factor rules apply as for the magic link.

**2. Magic link by mail** — exists. Keep as is.

**3. Admin-issued sign-in link without mail.** Admin panel (and JSON API) gets "create sign-in link" per user: shown **once**, as a link and as a QR code, to hand over by any channel. Works without a mailer configured. TTL settable, single use, revoked with the account's other links on disable / password reset, audited with the admin as actor.

**4. Magic link without self-service.** New switch `magiclink_self_request` (default true = today's behaviour). False: `/auth/magic/request` is gone (404) and the login page shows no "send me a link" button, but links issued by the admin (3) or by app code still redeem. So "sign-in by link only when the admin hands one out" is a configuration, not a fork.

Open questions (decide before building):
- Does an admin-issued link count as first factor only (`magiclink_require_second_factor` applies) or may it be marked as a recovery path for a user who lost the second factor? Default: same rule as every magic link.
- `base_url` is mandatory for mail paths today; an admin link needs an absolute address too — reuse `base_url`, never the request's Host header (R4-01).
- QR rendering uses the existing `[qr]` extra; without it, only the short code.
- `magiclink_enabled` currently implies "needs a mailer" (`config_check`): split into "links on" and "self-request by mail on".

Done when: 1, 3 and 4 work, are switchable per config, show up in the admin panel, `config_check` and the audit log, are documented in the README (sign-in section + config table), and tests cover: QR approval from a foreign session is refused, admin link single-use and revoked on disable, self-request off ⇒ request route 404 while issued links still redeem.

## Done (2026-11-20)

Built as asked; the open questions were decided with the defaults named above:

- **Admin link and second factor:** same rule as every magic link — `magiclink_require_second_factor` applies, no
  recovery path. Whoever lost the second factor needs the operator's reset path, not a link that skips it.
- **Address:** only `base_url`, never the Host header (R4-01). `create_signin_link` raises `ConfigError` without it
  (panel: 503); the cross-device page shows the short code alone and `config_check` warns.
- **QR rendering:** the existing extra `[qr]`; without it link or short code only.
- **Switches:** `magiclink_enabled` = links redeem (mail, admin, app code); `magiclink_self_request` = request by mail,
  and only that part needs a mailer in `config_check`.
- **Cross-device as a factor:** counts as `magic` (no new factor name, no change to chains), so the second-factor rule
  is the link's. The request lives in `magic_token` (purpose `qr_login`): key = hash of the short code, the new device
  holds a secret (hash in the payload) that is never displayed — knowing the code is not enough to collect the session.

Tests: `tests/test_sign_in_alternatives.py`, `tests/test_security_findings.py` (base of `create_signin_link`),
browser test (cross-device round trip and panel button under strict CSP).

---
id: T-66
type: Task
title: 'App passwords for WebDAV, CalDAV/CardDAV and Git at the gate'
status: erledigt
milestone: M-2
tags: [security, gate, forward-auth, webdav]
created: '2026-11-20'
---
# T-66 — App passwords for WebDAV, CalDAV/CardDAV and Git at the gate

Source: PO wish 2026-11-20 — HTTP clients without a browser (WebDAV, CalDAV/CardDAV, Git over HTTPS, scrapers) speak
only Basic auth and cannot pass a sign-in page. The established answer is the app password (Nextcloud, Google,
Fastmail, GitHub fine-grained tokens). Samba is explicitly out of scope (no HTTP; stays in the application).

**Done:**

- **App password** per account and device/purpose (`create_app_password`, account page, `POST /auth/app-passwords`):
  five groups of five from 31 symbols (lowercase letters and digits without `0 o 1 l i`), ≈ 124 bits — above the 112
  bits NIST SP 800-63B §5.1.2.1 asks of a look-up secret that is not rate-limited; lowercase so a phone needs no shift
  key; case, hyphens and spaces ignored on input. Shown once in the dialog with a copy button (`tsSecret`). Stored
  only as HMAC-SHA-256 with the existing pepper keyring of ADR-12 (`oauth-pepper`, own label) plus its key ID; a use
  with a previous pepper rewrites the digest, and `keys retire` refuses while an unused one still needs the old pepper.
  Name, applications, created, last used, address, optional expiry, revocable.
- **Lifetime:** `app_password_default_days` = 365. Not the 90 days of an automation key: an app password is typed into
  a phone by hand, and a calendar that breaks every quarter teaches people to work around it; a year still ends what
  nobody remembers, and the list shows the last use. 30/90/365 to choose; no expiry only with
  `app_password_allow_unlimited` (default off, as for API keys).
- **Creation only with a fresh confirmation** (`_require_fresh`, B-12) and never by an API key; event
  `app_password_created` with a mail notice (`notify_new_access`, T-47), `app_password_revoked`,
  `app_passwords_revoked`.
- **Bound to applications:** `forward_apps[host]["app_passwords"] = True` switches a host on (default off,
  `config_check` refuses anything but a bool); each app password names its hosts (the account page ticks one by
  default). It carries the account's roles, never the admin flag (like an automation key).
- **Gate:** `/auth/forward` accepts `Authorization: Basic` only at such a host, only with an app password of that
  account for that host — the account's own password is never compared (it does not have the format), so TOTP cannot
  be skipped. Success → `Remote-*` as for a session; no gate token (ADR-9) is issued, so a revocation takes effect on
  the next request. Failure or no credentials from a client without a browser → `401` with
  `WWW-Authenticate: Basic realm="<app name>", charset="UTF-8"` and `X-TinySesam-Reason: basic` (and still
  `X-TinySesam-Location` for an old template); a browser (`Sec-Fetch-*`, `Accept: text/html`) keeps the redirect —
  a Basic challenge would open its password box. Other hosts: unchanged.
- **Lockout:** a new kind in `security`: `SIGN_IN_OWN_LOCK` — a sign-in attempt (`failed login … method=app_password`,
  the shipped fail2ban jail) with a bucket of its own (pair, account, address at the login thresholds), outside the
  login lockout, the streak (B2-6) and the clean-up of a complete sign-in. A known app password that is revoked or
  expired is refused without being booked (a device that still has it is no guesser). Audit `app_password_use`
  (throttled), `app_password_denied`, `app_password_create`, `app_password_revoke`, `app_passwords_revoked`.
- **Revocation with the API keys** (`_keys_revoked`): account locked, password reset by an administrator or by the
  holder ("forgot"), "sign out everywhere". The own password change and "end other sessions" keep them and say how
  many (`PasswordChangeResult.app_passwords_active`, the JSON of `POST /auth/password` and `/auth/sessions/revoke`).
- **Admin panel:** tab "App passwords" (every account's, revoke; owner protection). No creation for someone else — an
  app password is the holder's own.
- Schema 20: table `app_password` (additive).
- Tests: `tests/test_app_passwords.py` (every protection rule with its mutation); end to end
  `tests/e2e_app_passwords.py` — rclone 1.76.0 as WebDAV client against `rclone serve webdav` behind Caddy 2.11.9 with
  the recipe's `basic` branch, in throwaway containers on 127.0.0.1.

**Left open:**

- The `basic` branch in the templates of `deploy/` (Caddyfile, Caddyfile.gate, the quickstart stack) — after T-62
  (PR #253) is merged, into its structure; until then the recipe in the README.
- nginx `auth_request` cannot pass a `WWW-Authenticate` from the auth sub-request through (it answers 401 with its
  own headers); a recipe with `auth_request_set` + `add_header` is to be measured. Traefik's `forwardAuth` passes the
  401 with its headers through as is.

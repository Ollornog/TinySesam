# Security

<b>English</b> · <a href="i18n/SECURITY.de.md">Deutsch</a>
<br /><br />

## Reporting a vulnerability

Please do **not** report security issues via public issues. Report them privately through this repo's
**GitHub Security Advisories** (the *Security* tab → *Report a vulnerability*).
I aim to give a first response within a few days.

## Status / scope

TinySesam is a self-built auth module and **not externally audited**. It deliberately relies on
established building blocks (argon2id/scrypt for passwords & PINs, server-side revocable sessions,
`SameSite`/`HttpOnly`/`Secure` cookies, OIDC ID tokens against JWKS + `iss`/`aud`/`exp`/`nonce`,
WebAuthn with `sign_count` clone detection, sha256-hashed one-time/API tokens, brute-force lockout +
rate limit, open-redirect protection via `safe_next`). Even so: review it yourself before production use.

## Operating notes (important)

- **Always run behind HTTPS**; `rp_id`/`origin` must match the domain exactly.
- Trust the real client IP only behind a trusted proxy (`trusted_proxies`), otherwise `X-Forwarded-For` is forgeable.
- Set `trusted_redirect_hosts` only to hosts you actually own (open redirect / forward auth).
- Keep secrets (OIDC client secret, SMTP password) in the environment / a secret store, not in code.
- **Known limit — the first-admin one-time token travels in a URL.** It is redeemed with
  `GET /auth/claim-admin?token=…`, and when you are not signed in yet the login redirect mirrors it
  into the `Location` header. A URL is not a confidential channel: it lands in the access log of any
  proxy in front, in `Referer`, and in the browser history — before the token is spent. By default
  the value is also printed to **stderr**, which journald, `docker logs` and any log shipping
  collect. Neither is a leak of a long-lived credential (single use, expires after
  `admin_claim_ttl_min`, route 404s once an admin exists), but treat it as short-lived and handle it
  accordingly: keep `admin_claim_ttl_min` small, prefer `admin_claim_token_file` (mode `0600`) over
  stderr where stderr is collected, redeem it right away, and take the first admin over
  `auth.ensure_admin(...)` or `admin_identifiers` where you do not want a token in a URL at all.

## Supported versions

Security fixes land on the latest released minor version — see the top of
[CHANGELOG.md](CHANGELOG.md). Older lines get no backports: pin a tag, and move the pin
when a release fixes something. (This used to name a fixed version here, and it was
thirteen minors out of date — a promise nobody was measuring.)

<br /><br />
<p align="right"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>

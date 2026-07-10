# Security

<p align="left"><b>English</b> · <a href="i18n/SECURITY.de.md">Deutsch</a></p>

<p align="right"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>

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

## Supported versions

Security fixes land on the latest minor version (currently `0.5.x`).

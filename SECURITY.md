# Security

<b>English</b> · <a href="i18n/SECURITY.de.md">Deutsch</a>
<br /><br />

## Reporting a vulnerability

Please do **not** report security issues via public issues. Two private channels:

1. **GitHub private vulnerability reporting** — the *Security* tab → *Report a vulnerability*
   (<https://github.com/Ollornog/TinySesam/security/advisories/new>). Preferred: the report,
   the discussion and the later advisory stay in one place.
2. **E-mail** to <tinysesam-github@ollornog.de> with the subject `[security] TinySesam` — for
   anyone without a GitHub account, or when the form is unavailable.

What you can rely on (calendar days, counted from your report):

| Step | Deadline |
| --- | --- |
| Acknowledgement of receipt | **7 days** |
| First assessment (confirmed / not reproducible / out of scope) | **14 days** |
| Fixed release, or a published advisory with a workaround | **90 days** |

Coordinated disclosure: please keep the details private until a fix is released or the 90 days
have passed, whichever comes first. If a deadline slips, you get a message saying so and why —
silence is not an answer. Credit in the advisory and the CHANGELOG, unless you prefer otherwise.

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
- **Known limit — TOTP secrets are stored unencrypted in the database.** Passwords, PINs, recovery
  codes and API keys are stored only as hashes; a TOTP secret cannot be, because the server has to
  compute every code from it. Anyone who can read the SQLite file (or a backup of it) can generate
  valid codes for every account — the second factor then rests on the password alone. Encrypting
  it with a key kept outside the database is planned (T-13, H-14/H-15). Until then, treat the
  database and its backups as a secret (mode `0600`, encrypted backups), and if you need the second
  factor to survive a database leak, use passkeys — only a public key is stored for them.
- **Known limit — without the `__Host-` prefix on the session cookie, every host under the
  parent domain is trusted.** The session cookie carries `__Host-` only with `cookie_secure=True`,
  an empty `cookie_domain`, `cookie_path="/"` and `cookie_host_prefix=True` — the defaults. SSO
  across subdomains needs `cookie_domain`, and a cookie valid for the whole domain cannot carry the
  prefix; `cookie_host_prefix=False`, any other `cookie_path` and `cookie_secure=False` drop it as
  well. Without it the cookie is plain `tinysesam_session`, and any host under the parent domain —
  a protected app behind forward auth included — can set its own cookie of that name for the whole
  domain (cookie tossing), with or without `cookie_domain`: a signed-out visitor is then signed in
  as the account whose token that host holds, and a signed-in one usually as well, because the
  newer cookie wins. No request to TinySesam is needed, so neither the CSRF token nor the origin
  check can stop it; they only close the form route (login CSRF via a POST to TinySesam), and over
  plain HTTP not even that, because browsers send no `Sec-Fetch-Site` there. Set `cookie_domain`
  only when every host under it is yours and trusted as much as TinySesam itself. Otherwise leave
  it empty and keep the other three at their defaults: the session then stays host-only with
  `__Host-`, and no other host can set it. (Apps served from TinySesam's own host, as in the
  path-based forward-auth setup, share its origin and are trusted either way.)
- **Notify account holders about factor changes — `auth.on_security_event`.** Opt-in hook,
  called as `hook(event, account, details)` with `account = {id, username, email, display_name}`
  whenever a sign-in factor is created, changed, removed or consumed: `password_changed`,
  `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled`, `recovery_codes_generated`,
  `recovery_code_used` (`details={"verbleibend": n}`), `passkey_added`, `passkey_removed`,
  `api_key_created`, `api_key_revoked` (`details={"key_id": n}`) and `api_keys_revoked`
  (`details={"anzahl": n, "grund": …}` — in bulk on a reset, a block, an admin password reset or
  `sessions/revoke` with `scope=all`). That includes changes an administrator makes to someone
  else's account in the panel (password reset, issuing an API key, revoking a passkey) — write the
  mail so it does not assume the holder did it. Apart from the hook, TinySesam sends one mail itself
  when a mailer is configured: a notice to the (verified) address of an account that got locked by
  failed sign-in attempts (ASVS 6.3.5; opt-out `notify_login_failures=False`). Send your mails from
  the hook (ideally via a queue — it runs synchronously in the request). An exception in the hook
  never undoes the change, but lands in the security log.
- **A TOTP code is valid exactly once — including the setup code.** The code that confirms the
  setup is consumed. Under `login_chain=["password","totp"]` that confirmation completes the TOTP
  step of the sign-in; everywhere else the *next* code is needed to sign in. Integration tests that
  call `totp_confirm(uid, now())` and then `verify_totp(uid, now())` with the same code fail since
  T-13 — confirm with the previous time step's code instead.

## Supported versions

Security fixes land on the latest released minor version — see the top of
[CHANGELOG.md](CHANGELOG.md). Older lines get no backports: pin a tag, and move the pin
when a release fixes something. (This used to name a fixed version here, and it was
thirteen minors out of date — a promise nobody was measuring.)

<br /><br />
<p align="right"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>

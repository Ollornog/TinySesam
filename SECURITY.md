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
WebAuthn with `sign_count` clone detection, sha256-hashed one-time/API tokens, session handles as an HMAC with a pepper kept outside the database file, brute-force lockout +
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
- **Reversible secrets are encrypted at rest — the key is the thing to guard.** Passwords, PINs,
  recovery codes and API keys are stored only as hashes. What the server must read back — TOTP
  secrets, OIDC refresh and ID tokens — is encrypted with AES-256-GCM (mandatory since 0.21.0; a
  value from before is encrypted at startup). The key comes from `TINYSESAM_SECRETS_KEY`, else
  `secrets_key_file`, else a file `<db>.key` (mode `0600`) created next to the database. That
  default protects against a database file that leaks on its own, **not** against a copy of the
  whole directory. Since T-48 (ADR-12) every key has one purpose and its own material: the signing
  key of the gate tokens (ADR-9) and the OAuth pepper are random keys, **never derived** from the
  vault key — the vault key alone (a leaked environment, a key backup) mints no gate token. Without an
  own source (`TINYSESAM_GATE_KEY`, `gate_key_file`) the gate key is kept in the database, encrypted
  with the vault key, so `<db>.key` beside the database still gives both to whoever reads the whole
  directory; `config_check` says so when the gate is on. In production, and always for the gateway
  with gate tokens, keep the vault key outside the data directory (`TINYSESAM_SECRETS_KEY` as a
  container secret, or `secrets_key_file`) and back it up separately from the database: without it
  every TOTP setup is lost. Each value carries its key ID and is bound to its row (AES-GCM associated
  data, T-54), and every key can be rotated without loss (`tinysesam keys rotate|reencrypt|retire`,
  docs/OPERATIONS.md "Keys"). Passkeys remain the factor that survives a database leak — only a
  public key is stored for them.
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
  `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled` (`details={"recovery_codes_deleted": n}`),
  `recovery_codes_generated` (`details={"count": n}`), `recovery_code_used`
  (`details={"remaining": n}`), `passkey_added` (`details={"name": …}`), `passkey_removed`
  (`details={"passkey_id": n}`), `api_key_created` (`details={"key_id": n, "name": …}`),
  `api_key_revoked` (`details={"key_id": n}`), `email_changed` and `username_changed`
  (`details={"old": …, "new": …}` — self-service, 2026-09-25) and `api_keys_revoked`
  (`details={"count": n, "reason": …}`, `reason` one of `password_reset`, `account_disabled`,
  `admin_password_reset`, `sessions_revoked` — in bulk on a reset, a block, an admin password reset
  or `sessions/revoke` with `scope=all`). Connected programs (OAuth, T-36): `oauth_device_connected`
  (`details={"grant_id": n, "client_id": …, "client_name": …, "resource": …}` — a program got its first
  tokens after the consent), `oauth_device_revoked` (`details={"grant_id": n, "client_id": …, "reason": …}`,
  `reason` one of `user`, `admin`, `client` and the reasons of `api_keys_revoked` — since the attack round of
  2026-11-21 (A-1) a reset, an admin password reset and "sign out everywhere" end the connected programs too, not
  only a block) and `oauth_token_reuse`
  (`details={"grant_id": n, "client_id": …, "kind": "code"|"refresh"}` — a used code or refresh token came
  back, the connection was revoked: the token has probably been copied). New ways in that are no factor
  of their own (H2, T-47): `signin_link_issued` (`details={"ttl_min": n, "by_operator": bool}` — a
  sign-in link was issued for the account) and `device_signed_in` (`details={"method": "qr_login",
  "ip": …, "agent": …}` — a device signed in through a cross-device approval); `password_changed`
  carries `details={"by_operator": bool}` (`True`: an administrator set it). App passwords (T-66):
  `app_password_created` (`details={"app_password_id": n, "name": …, "hosts": [...]}`), `app_password_revoked`
  (`details={"app_password_id": n}`) and `app_passwords_revoked` (`details={"count": n, "reason": …}`, the same
  reasons as `api_keys_revoked`). Services (T-60): `oauth_service_paired` (`details={"client_id": …, "client_name":
  …, "resources": [...]}` — a service was paired to act as the account) and `oauth_service_revoked`
  (`details={"client_id": …, "client_name": …, "reason": …}`, `reason` one of `user`, `admin`, and the reasons of
  `api_keys_revoked`). A complete sign-in after at least three consecutive failed attempts (T-63, ASVS 6.3.5):
  `signed_in_after_failures` (`details={"failures": n, "ip": …}` — the streak counts every failed sign-in under
  the account's names since the last complete sign-in, across methods; also the audit event `login_after_failures`).
  The full list of event names is `TinySesam.SECURITY_EVENTS`.
  The `details` keys and the reasons are English since
  0.22.0 (up to 0.21.x `verbleibend`, `alt`/`neu`, `anzahl`/`grund` with German reasons). That includes changes an administrator makes to someone
  else's account in the panel (password reset, issuing an API key, revoking a passkey) — write the
  mail so it does not assume the holder did it. Apart from the hook, TinySesam sends two kinds of
  mail itself when a mailer is configured, both only to a verified address and without a link: a
  notice to an account that got locked by failed sign-in attempts and, since T-63, one about a sign-in after
  failed attempts (ASVS 6.3.5; opt-out `notify_login_failures=False` for both), and since H2 a notice about **new access** (T-47, NIST SP 800-63B-4
  §4.1.2.1; opt-out `notify_new_access=False`) for `passkey_added`, `totp_enabled`, `pin_set`,
  `api_key_created`, `device_signed_in`, `signin_link_issued`, `password_changed` by an administrator,
  `oauth_device_connected`, `oauth_token_reuse`, `app_password_created` and `oauth_service_paired` — at most one per
  account and event a minute. The
  same events appear on the account page under "Recent activity". Send your other mails from
  the hook (ideally via a queue — it runs synchronously in the request). An exception in the hook
  never undoes the change, but lands in the security log.
- **Known limit — Basic auth has no second factor; that is why only app passwords take it (T-66).** WebDAV,
  CalDAV/CardDAV and Git clients send a user name and a password with every request and cannot answer a TOTP prompt
  or hold a passkey. With `forward_apps[host]["app_passwords"] = True` the gate accepts `Authorization: Basic` for that
  host — but **only** with an app password: a generated secret of ≈ 124 bits (NIST SP 800-63B §5.1.2.1 asks 112 for
  a look-up secret that is not rate-limited), stored as an HMAC digest with the pepper keyring, bound to its account
  and to the applications chosen at creation, without admin rights, created only after a fresh confirmation, and
  revoked with the API keys on lock, admin password reset and "sign out everywhere". The account's own password is
  never compared there (it does not even have the format), so the second factor cannot be skipped by Basic auth. What
  remains: an app password is a bearer secret — whoever copies it from the device (or reads it in transit without
  HTTPS) can use it at its applications until it expires or is revoked; it is sent with every request, so the proxy
  in front must not log `Authorization`, and the templates drop the header before the application (next point).
  Misses are `failed login … method=app_password` in the security log (fail2ban) and
  count in a bucket of their own, so guessing at the gate does not lock the browser sign-in. Samba and other
  non-HTTP protocols are out of scope.
- **Credentials at the application — the templates drop them.** Every proxy template in `deploy/` (Caddy, nginx,
  Traefik) removes `Authorization` and `X-Api-Key` on the way to the application, AFTER forward auth has decided:
  Caddy `header_up -Authorization` / `header_up -X-Api-Key` in every application `reverse_proxy`, nginx
  `proxy_set_header Authorization ""` (FastCGI `fastcgi_param HTTP_AUTHORIZATION ""`, which also keeps
  `PHP_AUTH_USER`/`PHP_AUTH_PW` empty), Traefik the middleware `tinysesam-strip-credentials` after `tinysesam-auth`.
  The application learns who is signed in from `Remote-*`; it never needs the secret. Up to the attack round of
  2026-11-21 (A-3) the templates only mentioned this in a comment, and an application's header log, debug page or
  error report received app passwords, OAuth access tokens and — worst — API keys (`tsk_…`, valid at every host and
  at TinySesam's own API, with roles, up to 90 days). **Your application checks `Authorization` itself** (its own
  Basic auth or token check behind the gate)? Then delete those lines for that one host or location, deliberately —
  and accept that whatever it logs then holds the credential. The quickstart's `webdav` profile does not need it
  (the WebDAV server there has no sign-in of its own). `tests/test_attack_round_a.py` checks every template under
  `deploy/` for this, a new one included; `tests/test_gate_caddy.py` measures it through a real Caddy.
- **Credentials do not reach the proxy log either.** The gate plugin caddy-jwt (v1.4.0) takes `Authorization` as a
  token candidate whatever its configuration says, and logs a candidate that is no JWT at level error with a third of
  its beginning and end. Up to 0.26.0 `deploy/forward-auth/Caddyfile.gate` therefore wrote half an API key, OAuth token
  or app password of every API and MCP call into Caddy's log. Since 0.26.1 a request with `Authorization`, or without
  the gate cookie, goes straight to `/auth/forward`; jwtauth only sees the gate cookie. Caddy still logs that one,
  shortened (a JWT of at most `gate_token_ttl_sec`), on every request it lets through.
- **Services authenticate with their own key, not with a secret (T-60, ADR-13).** With `oauth_service_clients` a
  service gets short-lived access tokens by `client_credentials` with `private_key_jwt` (RFC 7523): TinySesam stores
  only its public key, so a copied database, a proxy log or a backup yields nothing that gets a token. The assertion
  is checked by joserfc (extra `[services]`) with an algorithm list (`Ed25519`, `ES256`, `EdDSA` for an Ed25519 key)
  bound to the stored key's type — no `none`, no HMAC, no key taken from the JWT header; `aud` must be the issuer
  as its only value (RFC 10070 — the token endpoint URL is refused against audience injection), `exp` at most 5
  minutes ahead, `jti` single use until then. A refusal answers a generic `invalid_client`; the reason is in the audit
  log (`oauth_client_auth_failed`). Pairing needs a one-time code from a freshly confirmed session or the admin
  panel and a proof that the service holds the private key. The token never carries the admin flag; a lock, a
  revocation or a removed role takes effect at the next request. What remains: **the key file is the service** —
  whoever copies it (mode 0600 by default) can get tokens until the key is rotated (`oauth_service_key_days`, the
  client rotates at half of it) or the service is revoked. An access token itself is a bearer token for its
  lifetime (15 min) at its resource; binding it to the key (DPoP, RFC 9449) is open as T-68.
- **A TOTP code is valid exactly once — including the setup code.** The code that confirms the
  setup is consumed. Under `login_chain=["password","totp"]` that confirmation completes the TOTP
  step of the sign-in; everywhere else the *next* code is needed to sign in. Integration tests that
  call `totp_confirm(uid, now())` and then sign in (`POST /auth/totp`) with the same code fail
  since T-13 — confirm with the previous time step's code instead. **Which steps count** is `totp_window`
  (T-57, RFC 6238 §5.2): by default the current and the previous one; up to 0.25.x the next one counted as well
  (`"previous_and_next"` keeps that). A test that signs in with the *next* step's code needs that switch now.
  `"current"` accepts only the running step — the 30 seconds ASVS 6.5.5 names, at the price of codes typed just
  as the step changes.
- **Re-authentication at an OIDC provider is checked by `auth_time` (T-49, ASVS 6.8.4).** A round through the
  provider's running session is silent — no password, no factor. With `oidc_reauth_check` (default on) the
  confirmation page offers "Confirm with <provider>" to an account linked to it; that round asks for an active
  sign-in (`prompt=login`, `max_age=0`, OIDC Core §3.1.2.1) and confirms only with an `auth_time` from after the
  request (60 s clock tolerance) — otherwise the page says so and nothing is confirmed (audit `oidc_reauth_stale`).
  Any other round on a full session (the approval for another application) no longer refreshes the confirmation
  (`stepup_not_counted reason=no_fresh_auth_time`), and a new session counts as confirmed from the provider's
  `auth_time`, not from the round: a silent sign-in an hour after the last password is an hour old for
  `stepup_max_age_sec`. **Fallback without `auth_time`** (the provider does not send the claim): a new session
  counts from TinySesam's own sign-in, as before — the provider is trusted to have authenticated at least with
  its weakest method; the provider button then never confirms, the account confirms with its own factors or by
  signing in again. Providers that ignore `prompt=login` are caught the same way. `oidc_reauth_check=False`
  restores the behaviour up to 0.25.x. SAML has no such check yet (`ForceAuthn` is not sent, `AuthnInstant` is
  not read; backlog T-70): a SAML round through the provider's running session still counts as a fresh
  confirmation.
- **Your own sign-in, step-up or password-change page: build it on the building blocks.**
  `login_password`, `login_pin`, `login_totp`, `confirm_password`, `confirm_pin`, `confirm_totp`
  and `change_password` (tier A, since 0.22.0) throttle, count, lock and log exactly like the
  built-in routes — those routes call them. The inner checks (`_check_password`,
  `_verify_user_password`, `_verify_user_pin`, `_verify_totp` and their old tier-C names) do none
  of that: a page built on them lets passwords, PINs and codes be guessed as fast as the server
  answers, with no line for fail2ban. An API key never counts for these building
  blocks — it confirms no person and changes no password (`POST /auth/password` refuses it with a
  403 since 0.22.0).

## Vulnerable dependencies

Deadlines for fixing a known vulnerability in a dependency of the package or the gateway image
(ASVS 15.1.1), counted from the day a fixed version is available:

| Severity (CVSS) | Deadline |
| --- | --- |
| Critical | **7 days** |
| High | **30 days** |
| Medium / low | with the next regular release |

How they are kept: `pip-audit` checks every resolution of the package and the image's lock list on
every pull request and nightly, and a finding fails the run; the built gateway image is scanned
with Grype on every pull request, and a fixable finding of severity *high* or above fails it;
Dependabot proposes the updates. A finding that cannot be fixed in time (for example, the fixed
OS package is not yet in the pinned base image) may be excepted only in `.grype.yaml`, with a
reason and an `until` date within these deadlines — the scan fails again once that date has passed.

## Supported versions

Security fixes land on the latest released minor version — see the top of
[CHANGELOG.md](CHANGELOG.md). Older lines get no backports: pin a tag, and move the pin
when a release fixes something. (This used to name a fixed version here, and it was
thirteen minors out of date — a promise nobody was measuring.)

<br /><br />
<p align="right"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>

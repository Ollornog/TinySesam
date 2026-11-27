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
WebAuthn with `sign_count` clone detection, one-time/API tokens and session handles as an HMAC with a pepper kept outside the database file, brute-force lockout +
rate limit, open-redirect protection via `safe_next`). Even so: review it yourself before production use.

## Operating notes (important)

- **Always run behind HTTPS**; `rp_id`/`origin` must match the domain exactly.
- Trust the real client IP only behind a trusted proxy (`trusted_proxies`), otherwise `X-Forwarded-For` is forgeable.
- Set `trusted_redirect_hosts` only to hosts you actually own (open redirect / forward auth).
- **Switching recovery codes off (`recovery_codes_enabled=False`, T-94) removes the self-service way back.** Whoever
  loses the authenticator app then gets in again only when someone resets the access: an application's
  `reset_access` (scope `users:reset`, confirmed by a person holding `approver_role`) or your own code with
  `totp_disable`, `grant_mfa_enrollment` and a new sign-in link. The admin panel removes no TOTP. `config_check` warns
  when no application has `users:reset`. With the switch off no code is accepted, and none is used up; codes an account
  holds stay in the database (hashed) and are valid again once the switch is back on — delete them per account with
  `totp_disable` if that way back is not wanted.
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
  `admin_password_reset`, `sessions_revoked`, `access_reset` — in bulk on a reset, a block, an admin password reset,
  `sessions/revoke` with `scope=all` or an access reset by an application's approver). Connected programs (OAuth, T-36): `oauth_device_connected`
  (`details={"grant_id": n, "client_id": …, "client_name": …, "resource": …, "via": "page"|"pairing"}` — `pairing`
  when a pairing code gave the consent, ADR-14 — a program got its first tokens after the consent), `oauth_device_revoked` (`details={"grant_id": n, "client_id": …, "reason": …}`,
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
  Approvals (stage A): `approval_approved` (`details={"approval_id": …, "type": …, "result": …}` — the holder
  confirmed an action a token had asked for and TinySesam carried it out; TinySesam itself mails nothing for it) and
  `access_reset` (`details={"app": …, "approved_by": …, "password": n, "pin": n, "totp": n, "recovery_codes": n,
  "passkeys": n, "api_keys": n}` — an application's approver reset the account's access; mailed with
  `notify_new_access`).
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
- **Delegated admins can take over the accounts in their scope — on purpose (T-74).** A delegate role
  (`admin_delegates`) lets its holders issue a sign-in link for every account in their scope; whoever redeems it is
  signed into that account. A delegate therefore holds, in effect, every managed role: they can also create an account
  with those roles and sign into it. In a hierarchy this goes downwards: `area-admin` can take over every account of
  the teams below it and every `team-*-admin` it manages, a `team-a-admin` only plain accounts of team A — never a
  peer, an account above, another branch, an administrator, an owner or a service account, never by an API key, an
  OAuth token or an app password. It sits behind the same step-up as an administrator, a sign-in link always behind a
  fresh confirmation, and every action is in the audit log with the acting account. Grant a delegate role only to
  someone you would trust with every account it manages; take `signin_link` (and `invite`, `create`) out of `can`
  where that is too much. A delegate can also unlock an account an administrator locked (the lock does not record who
  set it): to take an account out of a delegate's reach, take the managed roles from it.
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
- **`Remote-Kind` fails closed — update the proxy before the applications.** `/auth/forward` always sends
  `Remote-Kind: user|service` (from `users.is_service`; a value of the column that is neither 0 nor 1 is refused with
  403, never guessed as `user`), and every gate token carries `ts_kind`. Gate clients after spec version 2
  (`spec/gate-client.md`) refuse a request without it, with an unknown value, or with `service` together with
  `Remote-Auth: session`. The client cannot see where a header came from: a proxy template **older** than this release
  does not strip `Remote-Kind` and passes a value the browser sent straight to the application. **Order:** first
  TinySesam and the proxy templates (or your own proxy rules: strip `Remote-Kind` on every path, set it only from
  TinySesam's answer or the claim `ts_kind`), then wait `gate_token_ttl_sec` (default 300 s, so no gate token without
  `ts_kind` is left), then the applications on clients after spec v2. `deploy/forward-auth/acceptance.sh` checks a
  forged `Remote-Kind` from outside (with `ECHO=1` also that it never arrives); `tests/test_gate_caddy.py` and
  `tests/test_proxies.py` measure every template through the real proxy.
- **Credentials do not reach the proxy log either.** Without `disable_authorization_fallback` the gate plugin
  caddy-jwt takes `Authorization` as a token candidate whatever its configuration says, and up to 1.4.0 it logged a
  candidate that is no JWT at level error with a third of its beginning and end. Up to 0.26.0
  `deploy/forward-auth/Caddyfile.gate` therefore wrote half an API key, OAuth token or app password of every API and
  MCP call into Caddy's log; 0.26.1 to 0.30.0 routed such requests around jwtauth. Since T-119 the template (with
  caddy-jwt 1.5.0) sets `disable_authorization_fallback`: jwtauth reads only the gate cookie, never `Authorization` —
  not even a valid gate token sent there — and caddy-jwt no longer logs token text (`token_string`) at all.
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
- **A pairing code gives the consent in advance (ADR-14, off by default).** With `oauth_pairing_consent_enabled` the
  account fetches a one-time code in its own freshly confirmed browser session (CSRF; never an API key, an access
  token, an administrator or an application on someone's behalf), and a setup script redeems it without a session.
  Then exactly one authorization of that account skips the consent page — only when the person's browser opened it
  itself (`Sec-Fetch-Site: none` at `/authorize`; a website's navigation carries `cross-site` and neither uses nor
  spends it), the redirect is a loopback address, the client is a person's client, the resource matches the code's
  and the window (`oauth_pairing_consent_minutes`, 15) is open, after the same sign-in and freshness checks as the
  page. Anything else shows the page and spends nothing. The code has 80 bits, only its digest is stored, it is never
  logged, works once (atomically), 20 redemptions per address and hour, each failure a fail2ban line. What remains: a
  local program that starts its own authorization within the window gets that one connection — malware level; it is
  listed "via pairing code" under *Connected programs* and in `oauth_device_connected` (`via: "pairing"`).
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
  confirmation. **LDAP** (T-99): an account whose password lives in the directory confirms with it on the
  confirmation page — a fresh bind through the same directory check as the sign-in (group gate, one identifier one
  account), which must lead to this account; counted in the confirmation's own bucket, a directory outage is a 503
  and no failed attempt.
- **Your own sign-in, step-up or password-change page: build it on the building blocks.**
  `login_password`, `login_pin`, `login_totp`, `confirm_password`, `confirm_pin`, `confirm_totp`
  and `change_password` (tier A, since 0.22.0) throttle, count, lock and log exactly like the
  built-in routes — those routes call them. The inner checks (`_check_password`,
  `_verify_user_password`, `_verify_user_pin`, `_verify_totp`) do none
  of that: a page built on them lets passwords, PINs and codes be guessed as fast as the server
  answers, with no line for fail2ban. An API key never counts for these building
  blocks — it confirms no person and changes no password (`POST /auth/password` refuses it with a
  403 since 0.22.0).

## Approvals (stage A): a token proposes, the person confirms

With `approvals_enabled=True` an API key of an account can **ask** for one of three TinySesam actions it may not do
on its own — `tinysesam.account.set_roles` (add and remove roles), `tinysesam.apikey.revoke`,
`tinysesam.account.disable`. TinySesam stores the request and answers with a link and a six-digit match code; the
person opens the link in their browser session, confirms once more and decides. The design rests on these rules:

- **The token only proposes.** `POST /auth/api/approvals` writes a row; it grants nothing. Only an API key may ask
  (a `human` key only beside a session of its account, as everywhere); a session has the panel, an OAuth or MCP token
  is refused until TinySesam is an MCP resource itself, an app password never. A service account's key gets
  `no_approver`: nobody could confirm.
- **Only a browser session of the same account decides** (`POST /auth/approvals/{id}`). A request that carries
  `Authorization` or `X-Api-Key` is refused with 403 — also a `human` key beside its session. Another account sees a
  neutral page ("does not exist or belongs to another account"), the same answer as for an unknown id; the id itself is
  128 random bits.
- **A step-up per approval, never a time window.** Password, PIN or TOTP (what `stepup_options()` offers, so
  `stepup_methods` narrows it), a passkey whose WebAuthn challenge is SHA-256(`"tinysesam-approval:"` ‖ server
  nonce ‖ id ‖ payload hash) — single use, bound to exactly this action, so an agent driving the browser cannot replay
  a gesture —, or a fresh sign-in at the provider (`prompt=login`, `max_age=0`) whose `auth_time` must be later than
  the request (without `auth_time`: no approval, fail-closed). A fresh session does not count, and confirming an
  approval does not make the session fresh. The secret checks run through the reauth page's lock, counter and
  fail2ban lines.
- **The rights at confirmation time decide (E4).** TinySesam executes with the admin panel's own code
  (`admin.PanelActions`) as the confirming session: an administrator, a delegate within their scope (T-74), the holder
  for their own key. A delegation that ended in between gives `result=forbidden`. **Admin rights never travel this
  way:** `set_roles` takes only `add`/`remove` of roles, never the admin flag — and a type that grants it needs a
  decision of the maintainer of its own, not just code.
- **Nothing lasting.** One action, once, for minutes (`approval_pending_sec`, 120–1800 s). Every state change is one
  `UPDATE … WHERE state = <old>`: a double or parallel confirmation has exactly one winner, and only the winner
  executes. A GET never decides anything; the POST carries CSRF and the `payload_hash` the page showed — a request that
  changed in between is refused.
- **No free text from the requester.** Title and summary come from TinySesam's own texts, filled from the stored
  payload and the database at page time; every value is escaped and bidi-isolated, control characters and commas in
  role names are refused, not stripped. A target account or key the viewer may not manage right now is named by its id
  only. The page is never framed: `frame-ancestors 'none'` and `X-Frame-Options: DENY` whatever `csp` says.
- **Fatigue and spam.** No bulk confirmation; open requests per account (`approval_open_per_account`, 5) and per key
  (`approval_open_per_token`, 3), new ones per account and hour (`approval_requests_per_hour`, 20), and
  `approval_reject_limit` (3) rejections of one type from one key within an hour block that key for that type for an
  hour — `429` each, audited as `approval_throttled`.
- **Audit without values:** `approval_requested`, `approval_approved` (with `amr`), `approval_rejected`,
  `approval_withdrawn`, `approval_expired`, `approval_executed` (with `result`), `approval_throttled`,
  `approval_denied` (`reason=token|other_account|stepup|payload_changed|no_approver`) carry id, type, key and payload
  hash — the values stay in the row. `approval_approved` reaches `on_security_event`.

Remaining risk: a person who confirms without reading. The match code, the step-up per approval and the limits make
that harder, not impossible — the page is deliberately plain: who asks (key name and date), what (one sentence and the
values), the code, the time left. Revoking the asking key ends a flood of requests.

## Approvals for application actions (stage B): a signed one-time confirmation

An application registered in `apps` with an `approvals` block asks for one of ITS action types; the person confirms on
the same page with the same rules as above (session of the subject only, step-up per approval, CSRF, `payload_hash`,
match code, never framed, never a GET); TinySesam carries nothing out and hands the application one signed
confirmation instead. The rules that are new:

- **The operator's text, the application's values.** Types come only from the configuration (`apps[…].approvals.types`
  or the operator's `types_file`), never from an API of the application: the text is the protection against phishing —
  an application that could register "open the view" as the text of a deletion would have the person confirm the
  deletion. `config_check` demands `en`, plain `{field}` placeholders that name fields, and type names that begin with
  the application's id. The application sends only values; they are checked against the schema (unknown, missing,
  wrongly typed, too long, off-pattern → `400`; control characters, C1, the bidi controls and the line separators are
  refused, never removed) and shown escaped, each in its own `<bdi>`, with the raw field table below.
- **Only its own prefix.** An application asks only for types that begin with its id (or with the id of `types_from`,
  a second channel of the same product): `403 forbidden_type` otherwise, audited. `tinysesam.` stays TinySesam's.
  `subject` may be any active person (§12 of the design: a binding to grants does not carry over the gate path); every
  request counts against `approval_app_requests_per_hour` (120) — `invalid_subject` included, so the answer cannot map
  the active persons — and the limits per account apply as in stage A.
- **A key of its own.** The confirmation is signed with the keyring of purpose `approval` (`TINYSESAM_APPROVAL_KEY`,
  `approval_key_file`, else the database encrypted with the vault key; `tinysesam keys rotate --purpose approval`),
  published at `/auth/approvals/jwks.json` — never the gate key. The proxy checks gate tokens by the key alone (caddy-jwt
  cannot check `typ`): with one key a confirmation could pass as a gate cookie, and a gate token as a confirmation at an
  application with a weak check. Own key, own `typ` (`tinysesam-approval+jwt`), own `aud` (RFC 8725 §3.11/§3.12).
- **Bound to one action, one application, one person.** `aud` is one string (the application's id — a test channel's
  confirmation never counts in the stable one), `sub` the confirming account, exactly one `authorization_details` entry
  (RFC 9396) with `ts_payload_sha256` over its RFC 8785 form, `auth_time` and `amr` of the step-up, `act` the asking
  application, `jti` the approval id, at most 300 s (`approval_token_ttl_sec`, default 120).
- **Exactly once, nowhere else.** The first status read after the confirmation moves `approved` → `consumed` and signs
  the confirmation then — it exists in that one answer only: not stored, not in the audit (`approval_issued` names id,
  type, application and hash), not in a log, never in the return address. Not picked up within `approval_pickup_sec`
  (300 s) the row expires. The application remembers the `jti` until `exp` (spec step 12), so a copy taken between
  pickup and execution is worthless. The application, the type and the person are checked again at confirmation and
  at pickup; one gone in between gives `consumed` with `result=forbidden` and no confirmation.
- **Browser entry without forgeable links.** The application creates the request in its back end (like RFC 9126) with
  a `return_url` that must equal one of `apps[…].approvals.return_urls` exactly (absolute https, no query or fragment)
  and a `state`; the browser carries only the id. Back to the application goes `?approval=<id>&state=<state>` (and
  `&result=rejected|expired`); `state` comes back inside the confirmation as `nonce`, which the application compares
  with its session. The page adds exactly that origin to its `form-action` (Chrome checks the redirect after the POST
  against it) and nothing else.

Remaining risk: a compromised application asks for its own types for any person — bothersome, not more: confirming
takes that person's step-up on TinySesam's page with the operator's text. Revoking the application's key ends it. What
the application does with a valid confirmation is its own code: the check order of
[`spec/approval-token.md`](spec/approval-token.md) and its own rules again before it acts.

## Account API for applications

With an application in `apps` that has a `provisioning` block, the application manages the accounts **it creates
itself** (or the operator handed it) through `/auth/api/users`: create (with a one-time link until the first sign-in),
read, change the display name and the roles of its allowlist, lock and unlock, delete with a grace period and restore. It calls TinySesam directly with an automation key of its service
account.

**What a leaked application key can do at most:** create accounts with the roles of the allowlist (`create_per_hour`,
`max_accounts`) and receive their one-time links — so: own ways in with the application's roles, which is why those
roles should belong to the application alone (`config_check` warns about a role without the `<app>-` prefix); change
allowlist roles on the application's accounts; lock and unlock them (only its own lock, `disable_per_hour`); read the
names, addresses, roles of the allowlist and sign-in times of the application's accounts; delete the application's
accounts — at once only those that never signed in, every other one locked with a grace period (`delete_grace_days`,
default 7) during which the application or the operator restores it, bounded by `delete_per_hour` and
`delete_per_day`.

**What it cannot do:** become administrator or delegate, see or change any other account, take over an account that
has been used (no link after the first sign-in, no address change, no password, no factor), issue keys or app passwords,
create service accounts, lift a lock of the operator. The rules behind that:

- **Only the key counts.** The caller is resolved through `verify_api_key` alone, never `current_user()` — a session
  cookie neither authenticates nor changes anything (401 without a key). Demanded: an automation key, an account with
  `is_service == 1`, named as `account` of an application with `provisioning` (403 `not_a_provisioning_app` otherwise).
  Rule E4 stays: the key carries neither admin flag nor delegate role; the account API is a narrow door of its own and
  opens no panel route.
- **Ownership only by `users.managed_by`** — set when the application creates the account, never derived from roles.
  An account the application did not create, an administrator, owner, service account or delegate answers **404**
  like an account that does not exist, on every route, decided before any field of the request is read. Whole-account
  actions (display name, lock, link) additionally need all roles of the account in the allowlist (`409
  account_shared` otherwise — the application sees the account, so that is no oracle); the rule is
  `config_check.may_manage`, the same as for the panel's delegates.
- **Roles only from the allowlist,** never `admin`, a delegate role or a role a group map assigns (`config_check`
  errors). A role outside it is refused (400 `role_not_allowed`), never dropped silently. `PATCH` writes
  `(current − allowlist) ∪ wanted` in one transaction, so roles the operator granted stay. `is_admin`, `is_service` and
  `password` are refused; a name or address from `admin_identifiers` answers like a taken one.
- **No access to sign-in methods.** No password, passkey or TOTP is set or reset; the address is accepted only on
  creation (`email_verified=0`), never by `PATCH` — otherwise a key would set its own address and take over the account
  through "forgot password".
- **The one-time link only before the first sign-in** (`409 already_signed_in` afterwards — after it a link from a key
  would be a takeover). A new link discards the open ones. The link exists only in the answer: the database stores the
  hash, the audit names `ttl_min`, no log line carries it. The holder learns of it (`signin_link_issued`).
- **Where the link leads afterwards is checked where it is given** (`next`, `provisioning.welcome_url`, T-94): only the
  circle of every redirect — a path, or an `http(s)` address on the host of `base_url` or in `trusted_redirect_hosts`,
  never one from the `Host` header (`config_check.link_next_ok`). Printable ASCII only, so a homograph (`аpp` with a
  Cyrillic `а`), a control character, a backslash or a user part (`https://app.example.com@evil.example`) is refused
  outright rather than read differently by the browser; `//host` and other schemes (`javascript:`) as well. A bad
  target is `400 next_invalid` before anything is written — not dropped in silence. It is stored with the token (the
  payload), never in the link, and the door re-checks it against the configuration of the moment; the audit names the
  host (`next_host=`), not the address. A leaked key thus sends a new person only where TinySesam already redirects.
- **The application's own lock** (`disabled=3`): it never downgrades another lock (`UPDATE … WHERE disabled=0`), and
  `enable` lifts only `3` (`409 disabled_by_operator` otherwise). Every check reads `disabled <> 0`, so `3` signs in
  nowhere — not by password, passkey, sign-in link, OIDC, SAML, LDAP or key. Locking ends sessions, keys, devices, app
  passwords and open links like every lock.
- **The person behind the call is claimed, not proven.** Writes carry `TinySesam-On-Behalf-Of` (an active person's id,
  or `-` for a job; 400 without it). The audit names the service account as actor and the claim as
  `actor_claimed=<name>#<id>`. Answers `actor_invalid` count against `taken_per_hour`, like answers "taken": they would
  otherwise enumerate accounts.
- **Limits per application** in the database (shared by every worker): creations, locks, links, deletions and
  "taken" answers per hour, deletions also per day (`429` with `Retry-After`, a security-log warning and
  `provision_throttled`); `max_accounts`.
- **Mass deletion stays reversible.** An account that has signed in is never deleted by the key at once: `DELETE`
  locks it (the effect of every lock) and sets `delete_after`; its name stays taken, so nobody re-creates it under the
  same name meanwhile. During the period the application may only restore it (every other write answers
  `409 account_deleting`, `enable` cannot lift the lock); the operator cancels in the panel or by
  `tinysesam accounts restore`, and the operator's unlock ends the deletion as well. Only the cleanup deletes — through
  the one deletion path, its audit lines anonymised (H-13), and only while the account is still the application's
  (released or made administrator meanwhile: the mark goes, the account stays). After the deadline the account answers
  `404` to the application.
- **Ownership changes only by the operator.** Taking an existing account over for an application (panel, administrators
  with a step-up; `tinysesam accounts adopt`) needs every role of the account in the allowlist and at least one, and
  never takes an administrator, owner, service account or delegate (`provisioning.adopt_refusal`) — "holds one of the
  application's roles" is not enough, the application could then lock or delete the part of another. Releasing
  (`managed_by = NULL`) ends a pending deletion. Both are in the audit (`account_adopted`, `account_released`).
- **The application's link dies when the account stops being wholly its own.** A sign-in link the application obtained
  (creation, `signin-link`, an access reset) names the application; the door (`/auth/magic/…`) refuses it once the
  account holds a role outside the allowlist, has become administrator or delegate, is no longer the application's —
  or someone signed in to it after the link was issued. Otherwise a key that still held the creation link of an account
  the operator then made an approver would sign in as that approver. Checked at redemption, so no path that changes an
  account (panel, delegate, approval, CLI, an embedding application, the identity provider) is missed; audit
  `magic_app_link_refused`. A link the operator issues is not affected.

Remaining risk: whoever holds the key can create accounts with the application's roles until a limit stops them,
lock the application's accounts, and schedule the deletion of up to `delete_per_day` of them a day (restorable within
the grace period). Revoking the service account's key in the panel shuts the API at once; the audit
(`provision_*`, `apikey_use`) shows what happened.

### Resetting an account's access: an approval, never the key alone

After the first sign-in the key cannot reset anything — that would be a takeover. With the scope `users:reset` and
`provisioning.approver_role` the application may **ask** for the approval `tinysesam.account.reset_access`: `subject`
is the TinySesam account of the application's team admin, the field `account` one of the application's own accounts.
What it does once confirmed: every sign-in factor of the account is deleted in one transaction (password, PIN, TOTP
with its recovery codes, passkeys), its sessions end, its API keys, app passwords, services and connected programs are
revoked (reason `access_reset`), open links die, and the application picks up **one** new one-time link. Federated
sign-ins (OIDC, SAML, LDAP) stay — they live at the provider. The approval page says all of this in words before the
approver confirms: the summary names every kind that goes, the row "Signs in now with" lists the account's factors,
the row "Also ends" counts its sessions, API keys, app passwords, services and connected programs — the API keys and
app passwords a device of the holder still uses stop working too.

- **The approver role is never the application's.** Confirming needs `approver_role` at the moment of confirming —
  checked in the confirming session, not at the request; an administrator without it is no approver either. The role
  may be any role (also an existing one such as `teamadmin`), but `config_check` refuses it when it stands in the
  allowlist of **any** application with provisioning: otherwise a leaked key creates a straw account, gives it every
  allowlist role, signs in with that account's one-time link, confirms its own request and takes over every account of
  the application. At runtime such a role counts as none, and `users:reset` with it. Only the operator grants the role
  — or a delegate whose `roles` hold it, which `config_check` names as a warning: then the delegates appoint the
  approvers.
- **The target is checked twice,** at the request and again at the confirmation: an account the application created
  (`managed_by`), no administrator, owner, service account or delegate (`404 not_found`), all its roles in the
  allowlist (`409 account_shared`), not disabled (`409 account_disabled`), and never the approver's own account
  (`403 forbidden`). A change in between gives the result `not_found`, `conflict` or `forbidden` and changes nothing.
- **Everything else is an approval of stage A:** only a browser session of `subject` decides, with a step-up of THIS
  approval, the match code, one atomic transition, the limits (`approval_open_per_token` counts the application's open
  requests, the rejection lock blocks the application for this type). Whether `subject` holds the role is not told to
  the key; a person without it sees "your right: missing" on the page.
- **The link exists exactly once.** Confirmed and executed, the row waits in `approved` (for `approval_pending_sec`);
  the first status read moves it atomically to `consumed` and only then issues the link — two parallel reads get one
  link. It is in that answer only: never in the audit (`account_access_reset` names the application, the approver,
  the counts and the approval id), never in a log, never in a URL; the database holds its hash. A setup window opens
  for the link's lifetime plus an hour, so the person can set up what the chain demands although `first_login_at`
  stays.
- **The holder learns of it:** the security event `access_reset` (`app`, `approved_by`, the counts) — mailed with
  `notify_new_access`. A reset nobody asked for is how a misused approver right shows.

Remaining risk: an approver who confirms for the wrong person, or a colluding approver together with the key. The
approver is a person the operator chose, confirms each reset with a step-up, and is named in the audit; the holder is
notified.

## App frame and the own account as data

**App frame** (`forward_apps[host]` `home`, `links`): the request only *chooses* a frame (`?app=<host>`, the host of
an absolute `next`/`return_url`, `app=<host>` inside a relative `next`); its name, back link and links come from the
configuration alone, checked at the start to lie on exactly that host (a path or `https://` on it — no `//`, no user
part, no quotes). So the frame is no open redirect, and an unknown host answers byte-equal to the page without it (no
oracle of the configured hosts). Pages without a signed-in account carry no frame link at all. Sign-out in the frame is
TinySesam's (the session ends), not the application's `forward_logout`.

**Reading the own account** (`GET /auth/account.json`, `GET /.tinysesam/account.json`, `auth.account_overview`):

- **Only a full browser session.** An API key, an OAuth access token, an app password and a half session get 401: the
  addresses and devices of sessions are a person's view (F-09, like `/auth/sessions`), and the factor state would tell
  a leaked token which factor is missing. A locked account with a valid cookie gets 401. No parameter chooses an
  account; the account API never reads another account's security state.
- **Never in the answer:** addresses, session hashes, secrets, key hashes or prefixes, raw browser strings, ids of
  other objects. A session shows a coarse "browser · system".
- **CSRF and other origins:** GET only, nothing changes (POST/DELETE → 405), so no CSRF token; no CORS header, so a
  foreign origin's page cannot read it; `no-store` and `Vary: Cookie` keep it out of shared caches. There is no writing
  route under `/.tinysesam/`: there the application's host counts as an own origin (`_origin_ok`), and an XSS in the
  application could otherwise end sessions after a fresh step-up. Ending sessions, revoking programs and app passwords
  stay on the account page, behind the existing audited and step-up-guarded routes.
- **Rate and log:** 60 reads per account and minute; a refusal (429, `Retry-After`) writes a
  `failed verification … reason=ratelimit_account_json` line, never `failed login` (the fail2ban jail stays quiet).
  Reads are not audited (own data; every change is).
- **In a wrapper** that hands `account_overview` to an application in another language, the three duties of the recipe
  are the wrapper's: only for a checked `Remote-Kind: user` with `Remote-Auth: session`, only for that request's
  `Remote-Id`, answered with `no-store`. TinySesam cannot enforce them on that path; the gate client's fetch of
  `/.tinysesam/account.json` (spec §8a) keeps the check with TinySesam.

## Role names and the role catalog

**Role names** (T-85): `Remote-Groups` and `ts_groups` join roles with `,` without an escape, and gate clients trim
the spaces around an entry. A comma, a control character or surrounding spaces in a role name are therefore refused
everywhere roles are configured or written (`config_check`, `create_user`, `set_roles`, `create_invite`, the panel); a
group map changed at runtime skips such a target with a security line. An account that still holds one from older
data gets `403` at the forward check (no gate token) — never the stripped or split role — until an administrator
removes it; the start names such roles.

**The role catalog** (`auth.create_role`, the panel's *Roles*, `tinysesam roles`) is a list the panel offers, not a
grant: headers, the gate token, key scopes and `has_role` read only the roles an account holds. Only administrators
change it (CSRF and `admin_require_mfa` as every panel route; delegated admins, API keys and applications cannot). A
role the configuration names, `admin` and `__admin__` are refused, so the catalog never touches what `config_check`
guards (delegate roles, allowlists, `approver_role`); new names also refuse format characters (bidi, zero-width), so
two roles cannot look alike in the panel. A role is deleted only when nothing holds or waits for it — accounts, key
and service scopes, open invitations and pairing codes, pending approvals — checked and deleted in one transaction:
an assignment running at the same time lands before (the delete is refused) or after (the account keeps a role the
catalog no longer lists, shown as "only on accounts"), never in between. Nothing cascades.

## Trust boundaries: library, server, application

As a **library** TinySesam runs inside your application's process: one trust boundary. A flaw in any other code of the
application (an injection, a vulnerable dependency, a debug endpoint) reaches the database, the session pepper, the
signing keys and every secret TinySesam holds, because they are in the same memory and the same file system. The
library cannot defend against its own host process.

As a **server** (the gateway container) TinySesam and the application are two boundaries: the application sees only
what the proxy hands it (the gate token or the `Remote-*` headers, `account.json`, `topbar.json`, the account API with
its own key) and holds no TinySesam secret, so a compromise of the application does not hand over the accounts. The
application can still misuse what it is given, so give it the narrowest scopes and permissions, and keep the proxy
duties of spec section 2.1 (strip every `Remote-*` and the gate cookie a client sends). Choose the server for an
application you do not fully trust, or whose code you did not write.

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

**Current exceptions (2026-11-22):** CVE-2026-19499 and CVE-2026-5435 (high) in `libc6 2.41-12+deb13u4`, only for that
package and version, until 2026-11-28 (red from 2026-11-29). Debian fixed both in `2.41-12+deb13u5`, but neither
`python:3.15-slim` nor `gcr.io/distroless/base-debian13:nonroot` has been rebuilt with it; the pinned digests are the
current ones of their tags (checked 2026-11-22). Once Dependabot bumps a rebuilt base, the rules match nothing and the
check after the scans turns red until they are removed.

## Supported versions

Security fixes land on the latest released minor version — see the top of
[CHANGELOG.md](CHANGELOG.md). Older lines get no backports: pin a tag, and move the pin
when a release fixes something. (This used to name a fixed version here, and it was
thirteen minors out of date — a promise nobody was measuring.)

<br /><br />
<p align="right"><img src="docs/wizard.png" alt="TinySesam" width="60" height="60"></p>

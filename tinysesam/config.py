"""Configuration for TinySesam. The embedding app fills TinySesamConfig and passes it to TinySesam()."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class TinySesamConfig:
    # --- Store ---
    db_path: str = "tinysesam.db"

    # --- Language of the built-in texts (en|de; add your own via auth.add_messages) ---
    lang: str = "en"

    # --- Branding/theme: set once → re-skins ALL built-in pages (+ error pages) ---
    brand_css: str = ""                   # additional CSS (after the default → overrides it)
    brand_head: str = ""                  # additional <head> HTML (e.g. logo font, meta)
    brand_icon: str = ""                  # favicon URL for ALL built-in pages (empty = built-in default
                                          # icon, "none" = none; since 0.24.8 — before, empty meant "none")
    #: Background images of all built-in pages (since 0.24.8): paths, data: or https addresses. Several fade
    #: slowly into one another, with a very dark overlay on top; with "reduce motion" the first one stays
    #: still. An https address opens the strict CSP for exactly that origin (img-src). Loading images from
    #: third parties means: every visitor's browser contacts them — only on purpose and with a suitable licence.
    brand_backgrounds: list = field(default_factory=list)
    brand_background_seconds: int = 12          # how long each image stays before the cross-fade
    brand_background_credit_text: str = ""      # discreet note at the bottom right, e.g. "Photos: Unsplash"
    brand_background_credit_url: str = ""      # target of the note (http/https only)
    # Shell of the host app around EVERY built-in page (login/PIN/TOTP/account/admin/error): your own
    # navigation on top, footer at the bottom. Either an HTML string or `fn(auth) -> str` if the
    # content depends on the request (login state, language) — then evaluated on every call.
    brand_header: object = ""
    brand_footer: object = ""         # footer below every built-in page; HTML string or `fn(auth) -> str`

    # --- Roles/groups ---
    # Does an admin satisfy EVERY require_role(...) check? Default True (classic behaviour).
    # CAUTION: if an app's permissions hang solely on an IdP group, this is a silent
    # privilege escalation — set False then, or use `require_role(..., admin_implies=False)` per guard.
    admin_implies_roles: bool = True
    # How are IdP groups compared with the keys of *_group_role_map?
    # "exact" (default, safe) or "substring" (the old substring comparison, on request only).
    # With "exact", LDAP compares a memberOf DN by its parts: the whole DN, "cn=staff" or "staff".
    group_match: str = "exact"
    # Known roles/groups: the admin panel offers them as checkboxes (empty = free-text fallback).
    available_roles: list[str] = field(default_factory=list)
    # IdP group → local role (set on OIDC/SAML/LDAP login). Target "__admin__" = admin flag (grant only).
    # Compared according to `group_match` (default exact). Managed roles are synchronised on each login.
    oidc_group_role_map: dict = field(default_factory=dict)
    saml_group_role_map: dict = field(default_factory=dict) # SAML group → local role, e.g. `{"staff": "editors"}`
    ldap_group_role_map: dict = field(default_factory=dict) # LDAP group (DN or name) → local role

    # --- Active login methods (all can run in parallel) ---
    password_enabled: bool = True     # offer password login at all (off = SSO/passkey/PIN only)
    # Own blocklist for new passwords: path to a text file, one password per line
    # (UTF-8, lines in another encoding count as Latin-1; `#` at the start of a line = comment).
    # Complements the small built-in list — if you want to check against the common leak lists (e.g. the
    # 100,000 most frequent), put them here. Offline: TinySesam asks no third-party
    # service. Empty = built-in list only. `tinysesam passwd` reads it with `--blocklist-file`.
    password_blocklist_file: str = ""
    # Default OFF, because `webauthn` is not part of the core but of the extra [passkey].
    # Until 2026-09-21 this was True — so `pip install tinysesam` with the
    # default configuration crashed while building the router (ModuleNotFoundError: webauthn).
    # The very first step of every new user, and the test suite could not see it.
    passkey_enabled: bool = False         # WebAuthn / passkeys (passwordless) — needs [passkey]
    #: Must the authenticator verify the human (PIN, fingerprint, face) before it
    #: signs? `"required"` (default) demands it, `"preferred"` asks for it and also accepts
    #: a no (B2-10).
    #:
    #: Why it matters: A passkey signs in **on its own** in TinySesam — it is not a second
    #: factor but a complete login. Without user verification it only proves **possession**
    #: of the key: the unlocked computer, the plugged-in stick, the phone briefly put down
    #: are enough then. With it, it proves possession **and** something only the person
    #: can do. Up to 0.18.x this was "preferred" and the answer was not even checked — an
    #: authenticator could say no and still count.
    #:
    #: `"preferred"` is a deliberate decision for a stock of old authenticators and
    #: announces itself at startup. Whoever starts fresh leaves it at `"required"`.
    passkey_user_verification: str = "required"
    pin_enabled: bool = False             # personal PIN per user (username + PIN)
    pin_login: bool = True                # offer the PIN as first factor on the login page.
                                          # False = the PIN exists but serves ONLY as an additional factor
                                          # (chain step, route chain) or as step-up for sensitive
                                          # areas. If a strict login_chain demands the PIN
                                          # behind another factor, it is never a first factor there.
    pin_min_length: int = 4               # minimum length when setting a PIN
    # What confirms a step-up (require(mfa=True))? Empty = everything the user has set up
    # (order totp → pin → password). E.g. ["pin"] = PIN for sensitive areas.
    # If the user has none of the listed methods, their best available method applies.
    stepup_methods: list[str] = field(default_factory=list)
    # Turn the wish into a barrier: True = whoever has none of the listed methods set up
    # does NOT get in (instead of confirming with the password they just signed in
    # with — that is no step-up). Default False, because otherwise the area would be locked for
    # existing accounts overnight; whoever sets `stepup_methods` to enforce something
    # usually wants True as well.
    stepup_strict: bool = False
    oidc_enabled: bool = False            # external IdProvider (PocketID …)
    # Path of the callback. Must be registered with the IdP as redirect URI (base_url + this path).
    # At startup TinySesam logs the expected URI — otherwise typos only show up after the login.
    oidc_callback_path: str = "/auth/oidc/callback"
    apikey_enabled: bool = True           # access via API key (machines/daemons, bound to a user/service account)
    #: Lifetime of an automation key in days if the caller names none. A key without
    #: expiry is a secret nobody takes back: it outlives the person who
    #: issued it, the project it was meant for, and the machine it sits on.
    apikey_default_days: int = 90
    #: May an automation key be created without expiry (`expires_days=0`)? Default no. True is
    #: a deliberate decision of the operator and is logged on creation — there are
    #: cases for it (a device nobody can touch), they are just rare.
    apikey_allow_unlimited: bool = False
    admin_enabled: bool = True            # mount the admin panel automatically at admin_path
    admin_path: str = "/auth/admin"       # default mount point; auth.admin_router() also lets you mount it elsewhere
    admin_ui_enabled: bool = True         # built-in HTML UI; False = JSON API only (for embedding in your own panel)
    account_enabled: bool = True          # built-in self-service page /auth/account (overridable)
    forward_auth_enabled: bool = False    # /auth/forward + /auth/verify for reverse proxy (Caddy/nginx/Traefik)
    # Which headers the forward-auth response sets. Empty = the Authelia-style set
    # Remote-User/-Name/-Email/-Groups and Remote-Id (the account ID — stable across renames and
    # mail changes, since 2026-09-25). Otherwise **field → header name** (or list of names); what is not
    # listed here is NOT set. Fields: user · name · email · groups · id.
    # The proxy must set EVERY configured header itself (overwrite) — otherwise it passes on one
    # of the same name sent by the browser (deploy/forward-auth/*).
    #   {"user": "X-WEBAUTH-USER"}                     → Grafana style, and nothing else
    #   {"user": ["Remote-User", "X-Auth-Request-User"], "groups": "X-Auth-Request-Groups"}
    # With the Traefik/Caddy example, keep the forwarded headers in sync (authResponseHeaders).
    forward_headers: dict = field(default_factory=dict)
    # Gate token (ADR-9, T-19): A successful forward-auth check additionally returns a
    # short-lived, signed token (Ed25519) in the header X-TinySesam-Gate-Cookie. The proxy sets
    # it as a cookie on the application's host and verifies it itself from then on (Caddy + caddy-jwt) —
    # TinySesam is only asked again when it is missing or expired. Only with
    # forward_auth_enabled, only for sessions (not for API keys) and only for hosts from
    # trusted_redirect_hosts or oidc_clients. Template: deploy/forward-auth/Caddyfile.gate.
    gate_token_enabled: bool = False
    gate_token_ttl_sec: int = 300          # lifetime = revocation delay at the proxy; 30–3600
    # How the gate signs in someone who is not signed in (T-21): "page" = TinySesam's login page
    # (with the application's name from forward_apps), "direct" = on page load straight to the
    # identity provider and back to the requested address. "direct" only if OIDC is the only
    # sign-in method; background requests (XHR, assets) go to the login page even then —
    # otherwise each of them would start a flow of its own. oidc_gateway() sets "direct".
    forward_login: str = "page"
    # What "sign out" means at the application (T-22), path: https://<app>/.tinysesam/logout.
    # "all" = end this session (applies to all applications behind the same sign-in) and, with
    # oidc_rp_logout, at the provider too; "app" = this application only: the session stays, the host
    # lets it through again only after "Continue as …" on the login page; "ask" = ask.
    forward_logout: str = "all"
    # "Signed out" page in "direct" mode (PO 2026-10-10): leave it up for this many seconds, then go back
    # to the application on its own — the gate forwards to the provider, where a NEW sign-in begins
    # (the provider is already signed out with oidc_rp_logout). 0 = leave it up, button only. 0–300.
    forward_logged_out_sec: int = 10
    # Settings per protected application: {"app.example.com": {"name": "Wiki", "login": "direct",
    # "logout": "ask"}}. name = display name on the login and sign-out pages; login/logout override
    # forward_login/forward_logout for this host.
    forward_apps: dict = field(default_factory=dict)
    gate_cookie_name: str = "__Host-tinysesam_gate"  # form __Host-tinysesam_<name>: host-only, and the templates strip it before the app
    # Central gateway, session stays on its host (T-26): An app host gets, via a
    # code exchange (/.tinysesam/start → /auth/gate/authorize → /.tinysesam/callback), only a connection
    # cookie of its own that is valid for it alone. Without this, the session cookie would have to sit on
    # the parent domain and would reach every app below it. Requires gate_token_enabled and base_url,
    # does not combine with cookie_domain.
    gate_link_enabled: bool = False
    https_mode: str = "warn"              # off | warn | force  — force = HTTP→HTTPS redirect;
                                          # warn = also runs WITHOUT a certificate (with a warning in the panel)
    # What do people sign in with? "username" | "email" | "both" (both allowed in the same field)
    login_identifier: str = "both"
    # --- First admin (bootstrap) — deliberately NOT "the first registered user becomes admin" ---
    admin_identifiers: list[str] = field(default_factory=list)  # username/email promoted to admin
                                          # at login AS LONG AS there is no admin —
                                          # and never again after the identity provider of the instance
                                          # has revoked its last admin (G6; then one-time token
                                          # or `tinysesam owner`).
                                          # Also works with OIDC/SAML/LDAP (usually the email there).
    admin_claim_ttl_min: int = 60         # validity of the one-time token for /auth/claim-admin (0 = off)
    # Where the value of the one-time token is written. A path here: TinySesam creates the file
    # with mode 0600 and writes the token into it. Empty = to stderr if stderr is a
    # console; otherwise (container, journal, pipe) since 0.22.0 to `<db_path>.claim` (0600,
    # removed after redemption) — until then it showed up in `docker logs` (T-17). Without a
    # database file (`:memory:`) only stderr remains, and the log says so.
    # The token is NEVER in the security_log (fail2ban reads that, and logrotate keeps it).
    admin_claim_token_file: str = ""      # 0600 file for the one-time token, e.g. /run/tinysesam/admin-claim.token; empty: stderr if it is a console, otherwise `<db_path>.claim`

    # --- Demo mode: creates sample accounts and shows the credentials. NEVER in production. ---
    demo_mode: bool = False           # create sample accounts and show the credentials — NEVER in production
    demo_password: str = "demo1234"   # password of the demo accounts (only with demo_mode)
    demo_pin: str = "1234"            # PIN of the demo accounts (only with demo_mode)

    allow_signup: bool = False            # self-registration (local user+password); not alongside ldap_enabled
    signup_require_email: bool = True     # email mandatory at registration (unique, see login_identifier)
    signup_verify_email: bool = False     # account active only after email confirmation (magic link) — needs a mailer
    signup_invite_only: bool = False      # registration only with a valid invitation token
    signup_default_roles: list[str] = field(default_factory=list)  # roles for new self-registered users

    # --- Shared resource secrets (without a user account: one PIN/passphrase protects an area) ---
    resource_locks_enabled: bool = False # additionally lock individual routes/resources with a PIN
    resource_unlock_ttl_hours: int = 12   # how long an unlocked resource stays open
    resource_cookie: str = "tinysesam_runlock" # cookie name for unlocked resources

    # --- Magic link (one-time login/access by email) ---
    magiclink_enabled: bool = False   # sign-in by one-time link — needs a mailer
    magiclink_ttl_min: int = 15           # validity of a one-time link
    #: ASVS 6.3.6 (PO decision 2026-09-24): If an account has a second factor (TOTP or
    #: passkey), the sign-in link alone does not sign in fully — the factor is demanded afterwards.
    #: Otherwise the mailbox would be the only key, even for an account that protected itself with an
    #: authenticator. Accounts without a second factor are still signed in by the link alone.
    #: Applies to the global chain and every route chain (`require(factors=["magic"])`, G10).
    #: `False` = the link always suffices (behaviour up to 0.20.x in chains like `["magic"]`).
    magiclink_require_second_factor: bool = True

    # --- Self-service: address and username (PO decision 2026-09-25) ---
    #: Everyone changes their own email address (account page, fresh step-up). The new one counts only
    #: after the click on the confirmation link sent to it; the old one gets a notice. Needs a
    #: mailer — without one this path does not exist.
    self_service_email_change: bool = True
    #: Everyone changes their own username (account page, fresh step-up) — not in the mode
    #: `login_identifier="email"`, where the name follows the address, and not alongside LDAP
    #: (`ldap_enabled`), where the names come from the directory and only the operator renames.
    #: Apps behind forward auth then see a different `Remote-User`; `Remote-Id` is stable.
    self_service_username_change: bool = True
    email_change_ttl_min: int = 60        # validity of the confirmation link for a new address

    # --- Email delivery (SMTP; fully overridable via auth.set_mailer(fn)) ---
    smtp_host: str = ""                   # empty + no set_mailer → delivery disabled
    smtp_port: int = 587              # 587 = STARTTLS, 465 = SMTPS (then smtp_ssl=True)
    smtp_user: str = ""               # SMTP username; empty = send without authentication
    smtp_password: str = ""           # SMTP password — belongs in an environment variable, not in the source code
    smtp_from: str = ""                   # sender; empty = smtp_user
    smtp_starttls: bool = True            # 587 = STARTTLS; for 465 set smtp_ssl=True
    smtp_ssl: bool = False            # SMTPS from connection setup (port 465) instead of STARTTLS
    smtp_timeout: int = 15            # seconds until a hanging mail server is given up on
    smtp_ca_file: str = ""            # own CA (PEM) for the relay; empty = system CAs. Verification always happens
    mail_subject_prefix: str = ""         # optional subject prefix, e.g. "[MyApp] "
    #: Notify the owner when their account is locked because of failed attempts (ASVS 6.3.5,
    #: B1-12). Only works with delivery configured and only to an ASSIGNED address; at most one
    #: notice per account and lock window. Opt-out: False.
    notify_login_failures: bool = True

    # --- TOTP (2FA on top of password/OIDC; passkeys are already phishing-resistant) ---
    totp_enabled: bool = True             # users may set up TOTP
    #: Key file for encrypting the TOTP secrets (H-14/H-15; 32 bytes, Base64).
    #: The environment variable TINYSESAM_SECRETS_KEY takes precedence; with neither, TinySesam creates
    #: `<db_path>.key` (0600). Without the key all TOTP setups are lost — back it up separately
    #: from the database (docs/OPERATIONS.md).
    secrets_key_file: str = ""
    # CAUTION: ineffective and therefore REJECTED since 0.18.0 — the switch was never
    # read. Making TOTP mandatory works through the factor chain:
    #   login_chain=['password', 'totp']  (+ login_chain_strict=True)
    # The field only stays so that an existing call gets a clear error
    # instead of a TypeError about an unknown argument.
    totp_required: bool = False
    recovery_code_count: int = 10         # number of one-time recovery codes per generation (lost authenticator)

    # --- Password reset (forgot password by email; needs magiclink_enabled + mailer) ---
    password_reset_enabled: bool = False

    # --- Factor chains (ordered combinations) ---
    # Global default chain of satisfied factors that make a session complete, e.g.
    # ["oidc", "password"] or ["password", "totp"]. Empty = classic (one first factor + TOTP if
    # set up). Can be tightened per route: Depends(auth.require(factors=[...], strict=...)) —
    # in addition, never instead of this chain (since 2026-09-27). Factor names: password, pin, oidc, passkey,
    # totp, magic. The first factor identifies the user.
    login_chain: list[str] = field(default_factory=list)
    #: Who may set up a second factor demanded by the chain **themselves**? (R3-1)
    #:
    #: `login_chain=["password", "totp"]` reads like "nobody gets in without a second factor".
    #: Up to 0.18.x that was not true: An account without TOTP could set it up at exactly this
    #: point itself — so whoever had only the password bound their own authenticator
    #: and was fully in. The chain thus protected everyone except those it was meant for.
    #:
    #: * ``"first_login"`` (default): allowed as long as the account has **never** been fully
    #:   signed in. A freshly created account sets itself up the first time — never again
    #:   afterwards. Without a deadline: Whoever uses their new account only in three weeks should not stand in front of
    #:   a locked door.
    #: * ``"grace"``: allowed within `mfa_enrollment_grace_days` after account creation.
    #: * ``"strict"``: never. The setup then comes from the operator
    #:   (`auth.grant_mfa_enrollment(uid)`, admin panel or invitation).
    #:
    #: If the chain demands no second factor at all, none of this applies — a voluntary TOTP
    #: can be set up by any signed-in user at any time, as before.
    mfa_enrollment: str = "first_login"
    #: Only for `mfa_enrollment="grace"`: days since account creation.
    mfa_enrollment_grace_days: int = 7
    login_chain_strict: bool = True       # enforce the order (True) or any order (False)

    # --- Step-up / per-route MFA (sudo freshness) ---
    # Guards with mfa=True demand a "fresh" factor confirmation. A session is fresh for
    # stepup_max_age_sec after login/reauth; after that → /auth/reauth. 0 = never expire (only "has passed 2FA").
    # The same span limits creating the FIRST factor: An account without password, PIN and TOTP
    # cannot perform a step-up (`stepup_options()` empty, the reauth page has no field), so
    # the age of the SIGN-IN (`login_fresh()`) counts there — after that only a new login helps.
    stepup_max_age_sec: int = 900         # 15 min; also limits creating the FIRST factor (measured from login there)
    admin_require_mfa: bool = False        # admin panel + require_admin additionally demand step-up MFA

    # --- Sessions (server-side, revocable) ---
    session_cookie: str = "tinysesam_session" # name of the session cookie (tell them apart when several apps share a domain)
    session_ttl_hours: int = 24 * 7       # TTL with "stay signed in" (persistent cookie)
    session_ttl_transient_hours: int = 12 # TTL without "stay signed in" (session cookie, ends when the browser closes)
    remember_me_enabled: bool = True      # offer the "stay signed in" checkbox (off → always persistent)
    #: Inactivity timeout in minutes (F-05, ASVS 7.3.1): Whoever has made no request with this
    #: session for that long is signed out — in addition to the absolute lifetime above. 0 = off.
    #: Default 8 h for sessions WITHOUT "stay signed in"; with it the second number applies (default off:
    #: whoever picks "stay signed in" explicitly wanted the long session).
    session_idle_minutes: int = 8 * 60        # inactivity without "stay signed in" (minutes, 0 = off)
    session_idle_minutes_remember: int = 0    # inactivity WITH "stay signed in" (minutes, 0 = off)
    #: Grace period after rotating the token (A-6, PO decision 2026-09-25): A step-up gives the
    #: session a new token (F-06). A request that was already in flight at that moment (second
    #: tab, background loading) still carries the old one and failed once. For this many seconds
    #: the old token keeps working — without step-up freshness, and it ends with the new session. 0 = off.
    session_rotation_grace_sec: int = 10
    cookie_secure: bool = True            # send over HTTPS only
    cookie_samesite: str = "lax"          # lax|strict|none
    cookie_path: str = "/"            # path the cookies apply to
    #: Empty = host-only. For SSO across subdomains e.g. ".example.com" — then TinySesam trusts
    #: every host under this domain: Anyone can set a session cookie for the whole domain
    #: and so push the browser into someone else's account (known limitation, SECURITY.md).
    #: Empty protects against that only as long as the session cookie carries `__Host-` (`cookie_host_prefix`).
    cookie_domain: str = ""
    #: `__Host-` prefix for session, CSRF and unlock cookie (H-1). Only takes effect where the
    #: browser allows it: `cookie_secure=True`, `cookie_domain` empty, `cookie_path="/"`. The
    #: CSRF cookie is always host-only and carries the prefix even with `cookie_domain` set.
    #: A cookie named like this cannot be set or shadowed by a neighbouring subdomain (cookie
    #: tossing). If the prefix is missing on the session cookie (`cookie_domain` set, this switch
    #: off, `cookie_path` ≠ "/" or `cookie_secure=False`), it carries only its bare name
    #: (`tinysesam_session`), and every host under the domain can plant one (known
    #: limitation, SECURITY.md).
    #: The cookie name changes with this — sign in once more after the update; the
    #: cookies under the old names are deleted by TinySesam on the next sign-in, step-up or
    #: sign-out via the built-in routes, `auth.logout()` or `auth.rotate_session()`.
    #: Your own code takes the name from `auth.csrf_cookie_name`, not from `csrf_cookie`; your own
    #: JS gets it from the page (template variable or `<meta>`) or reads the token from the
    #: form field that `auth.ensure_csrf()` returns.
    cookie_host_prefix: bool = True
    #: Prefix of THIS installation's cookies (session, CSRF, unlock, OIDC/SAML/passkey flow):
    #: Every name that starts with `tinysesam_` then starts with this prefix. For an app with
    #: its own TinySesam BEHIND a TinySesam gateway: Its proxy templates strip every
    #: `tinysesam_*` cookie before the app — including its OIDC flow cookie, and the way back from the provider
    #: failed ("without matching flow cookie"). With e.g. `"myapp_"` its cookies get through.
    #: A gateway itself (`forward_auth_enabled`) stays at `tinysesam_`: otherwise the
    #: templates no longer strip its session (the config check reports this). Explicitly set names
    #: (`session_cookie="x"`) stay as they are; so do the gateway's cookies (`__Host-tinysesam_gate`
    #: etc.). Changing it = new cookie names: sign in once more.
    cookie_prefix: str = "tinysesam_"

    # --- Content Security Policy for the OWN pages (login/account/TOTP/…) ---
    # The built-in pages are built nonce-proof (no inline handler, no style=);
    # a nonce is generated per response and injected into every <script>/<style>.
    #   "strict" (default) → default-src 'self'; script-src/style-src by nonce only
    #   "off"              → no CSP header (e.g. if a proxy/an app sets the CSP centrally)
    #   custom string      → used 1:1 as the header; a contained {nonce} is replaced. Without a
    #                        single known directive ('Strict', 'stirct') the setup aborts
    #                        instead of silently switching the CSP off; an unknown one next to
    #                        known ones ('scirpt-src', 'require-sri-for') gives a warning
    # Applies to the pages rendered by TinySesam and the admin panel, not to your own
    # response overrides (they set their CSP themselves). With 'strict', X-Frame-Options:
    # SAMEORIGIN is added; nosniff, Referrer-Policy, no-store and Vary: Cookie are carried by all
    # TinySesam responses regardless of this switch.
    csp: str = "strict"

    # --- CSRF (double-submit cookie; in addition to SameSite=Lax) ---
    csrf_enabled: bool = True             # state-changing POSTs demand a token (form field _csrf / header X-CSRF-Token)
    csrf_cookie: str = "tinysesam_csrf" # name of the CSRF cookie
    #: Check the origin before the token comparison (H-2): `Sec-Fetch-Site: same-origin` suffices,
    #: otherwise `Origin` must be one of our own hosts (Host header, X-Forwarded-Host, base_url —
    #: NOT trusted_redirect_hosts: those are redirect targets, in the forward-auth setup the
    #: protected apps); `Sec-Fetch-Site: same-site` or `cross-site` without an own origin
    #: (also `Origin: null`) is rejected. If no usable origin exists and `Sec-Fetch-Site`
    #: says `none` or is missing, the token alone decides. `Sec-Fetch-Site` is missing
    #: not only with old browsers and scripts but with every browser over HTTP (except
    #: localhost): Browsers send `Sec-Fetch-*` to HTTPS only. With `cookie_secure=False`
    #: an `Origin: null` from a neighbouring subdomain therefore also gets through to the token, and the
    #: CSRF cookie carries no `__Host-` then — over HTTP the check does not protect against
    #: login CSRF from the neighbourhood (there the session cookie can be planted anyway,
    #: known limitation in SECURITY.md).
    #: Behind a proxy that rewrites the host without setting X-Forwarded-Host, browsers
    #: without `Sec-Fetch-Site` fail (Safari before 16.4, every browser over HTTP) — set
    #: base_url for that.
    csrf_origin_check: bool = True

    # --- LDAP / lldap (password against directory bind; counts as factor 'password') ---
    #: Must a foreign identity (LDAP, SAML) bring a stable identifier? Default **no**:
    #: A directory that provides none should not suddenly sign in nobody after the update.
    #: If it is missing, the mapping falls back to the username — the unprotected
    #: state from before 0.20.0 — and says so once per source in the security log. True turns
    #: this into a rejection; that is the safe setting as soon as the directory can.
    federation_require_stable_id: bool = False
    #: How long may a sign-in via LDAP/SAML bind a still unbound account by its
    #: **name** (days)? Counted per source from the first start with the source enabled
    #: (for existing data: from the update) or from the account's creation, whichever is later. After that
    #: the name no longer binds — otherwise a dormant account (someone has left) would fall to
    #: the next person who gets the same name in the directory, along with roles and admin rights
    #: (G1). Rejection comes with a log line naming the identifier and the remedy; the operator
    #: then binds explicitly: `auth.federation_bind_existing(source)` (existing data, dry run as
    #: default) or `auth.federation_unbind(source, user_id)` (opens the binding for this
    #: account). `0` = explicit only (even a freshly created pre-provisioned account does not bind
    #: itself), `-1` = unlimited, the behaviour up to 0.20.x (the config check warns).
    federation_name_binding_days: int = 30
    ldap_enabled: bool = False       # check passwords against an LDAP/AD instead of locally — needs [ldap]
    ldap_url: str = ""                    # ldap://host:389 or ldaps://host:636
    ldap_start_tls: bool = False      # upgrade to TLS after connecting (port 389); for 636 use `ldaps://` in the URL
    #: Verify the directory's certificate? Default **yes** (F-12). Without verification,
    #: encrypted only means "not readable by someone who is not in between": Whoever redirects the
    #: traffic presents a certificate of their own, gets the password of the service account
    #: and of every user password, and passes the response on — nobody notices.
    #: Until 0.19.0 the verification did not exist at all.
    ldap_tls_verify: bool = True
    #: Own CA file (PEM) for the directory certificate. Empty = the system store.
    #: The usual way for an internal directory with its own CA.
    ldap_tls_ca_file: str = ""
    #: May the connection use no TLS at all (`ldap://` without StartTLS)? Default **no**. Then
    #: the password of the service account and every user password would cross the network in clear text.
    #: True is a deliberate decision for a directory on the same host (loopback) and
    #: announces itself at startup.
    ldap_allow_plaintext: bool = False
    ldap_user_dn_template: str = ""       # direct bind, e.g. "uid={username},ou=people,dc=example,dc=com" (lldap)
    ldap_bind_dn: str = ""                # OR service account for search-then-bind
    ldap_bind_password: str = ""      # password of the service account — belongs in an environment variable
    ldap_user_base: str = ""              # search base (for search-then-bind)
    ldap_user_filter: str = "(uid={username})" # search filter for the account; `{username}` is substituted
    #: The attribute with the directory entry's **stable** identifier (F-11). Empty = try
    #: `entryUUID` (OpenLDAP, lldap) and `objectGUID` (Active Directory) in that
    #: order. The mapping to the local account hangs on it — a username is no good for that: Whoever renames
    #: in the directory or recreates a deleted account under the same name would otherwise get
    #: the same local account along with its roles.
    ldap_attr_id: str = ""
    ldap_attr_email: str = "mail"     # LDAP attribute with the email address
    #: Trust addresses from the directory across the board? LDAP delivers no proof like OIDC
    #: `email_verified`. `False` (default since PO decision 2026-09-25): The address is not
    #: used directly — with `federation_email_confirm` the owner confirms it by link, or
    #: `ldap_attr_email_verified` names a proof. `True`: The directory is maintained, nobody
    #: changes their own `mail` attribute — the address counts as proven and carries rights (first admin
    #: via `admin_identifiers`).
    ldap_email_trusted: bool = False
    #: LDAP attribute whose true value ("TRUE", "1", "yes") proves THIS entry's address —
    #: for directories that keep it. Empty = none.
    ldap_attr_email_verified: str = ""
    ldap_attr_name: str = "cn"        # LDAP attribute with the display name
    ldap_group_attr: str = "memberOf"     # attribute with the group membership
    ldap_allowed_groups: list[str] = field(default_factory=list)  # empty = all; otherwise gate (DN, "cn=x" or "x" — no substring)
    ldap_auto_create: bool = True         # create an unknown LDAP user locally (without a local password)

    # --- OIDC ---
    oidc_name: str = "SSO"                # display name of the button
    oidc_issuer: str = ""                 # e.g. https://id.example.com  (…/.well-known/openid-configuration)
    oidc_client_id: str = ""          # client ID at the provider
    oidc_client_secret: str = ""      # client secret — belongs in an environment variable, not in the source code
    oidc_scopes: str = "openid profile email" # requested scopes; `openid` is mandatory, `email`/`profile` fill the account
    oidc_auto_create: bool = True         # create an unknown OIDC user automatically
    # What applies if the provider does NOT send `email_verified`? The claim is optional in
    # OIDC Core 5.1 (Entra ID, for one, omits it). Default False = the address counts as unconfirmed:
    # It is taken into the account as usual and passed on (`Remote-Email`), but carries
    # no rights — first admin via `admin_identifiers` demands the proof (recorded as
    # `users.email_verified=0`, then applies to EVERY sign-in method of this account). True only for IdPs
    # that do not send the claim AND whose addresses the operator vouches for themselves (own
    # directory, one tenant): then an address without the claim counts as proven and can carry the
    # first admin. A claim that explicitly says `false` stays a no in both cases.
    oidc_email_verified_default: bool = False
    oidc_rp_logout: bool = False          # on sign-out also sign out of the OIDC provider (end_session), optional
    oidc_group_claim: str = "groups"      # claim with the groups
    oidc_allowed_groups: list[str] = field(default_factory=list)  # empty = all allowed

    # --- Several applications behind ONE installation (T-14) ---
    #: Protected host → own OIDC client at the same provider. Empty = one application, the
    #: single client above applies to everything (behaviour up to 0.18.0, unchanged).
    #:
    #: Why at all: Who may enter which application is decided by the **provider** — with PocketID
    #: through the group approval per OIDC client. This approval hangs on the client, not on the user.
    #: With a single client there is therefore only one answer for all applications: Whoever is in
    #: at one is in at all. The previous remedy was a TinySesam instance of its own per application —
    #: three containers, three databases, three audit logs for
    #: the same people.
    #:
    #: Structure per entry: ``{"app.example.com": {"client_id": "...", "client_secret": "...",
    #: "scopes": "openid profile email", "allowed_groups": [...], "group_role_map": {...}}}``.
    #: If an optional key is missing, the single client's value applies. The **issuer is the same
    #: for all clients** — several providers in one instance are not intended, and the
    #: config check says so too.
    oidc_clients: dict = field(default_factory=dict)
    #: After how many minutes an approval already granted is re-checked at the provider. 0 = never
    #: (behaviour up to 0.18.0). The provider decides on the approval, so a revocation
    #: must arrive there too: Without re-checking it applies until the session ends — by
    #: default seven days. The re-check is a hop via the provider; its session normally
    #: persists, so the human sees only a short redirect. If the provider refuses,
    #: the approval is gone **for this one application**, the session stays for the others.
    #: ``oidc_gateway()`` sets 60; whoever builds it by hand decides for themselves. Allowed are
    #: 0 to 43200 (30 days) — above that it is no longer a re-check. A period of one day
    #: or more written in seconds is therefore an error; above one day (1440) the
    #: check warns and asks for the unit (3600 for an hour). Shorter periods in seconds
    #: (300 instead of 5) go unnoticed — the unit is in the field name.
    oidc_revalidate_minutes: int = 0
    #: Revocation follows the provider (4a): Every so many minutes, on the next request, TinySesam
    #: exchanges the refresh token of the OIDC session. If the provider refuses (blocked, deleted, revoked
    #: for the application), the session ends; groups and the admin flag granted by the provider
    #: are re-evaluated in the process. An unreachable provider signs nobody out. Needs a
    #: provider that issues refresh tokens (if necessary scope `offline_access`). 0 = off.
    oidc_session_refresh_minutes: int = 15
    #: Upper limit without a successful re-check (PO decision 2026-09-25): If 4a fails permanently
    #: because of a client error (secret renewed at the provider, client deleted) or the provider
    #: itself, nobody re-checks any more — whoever is blocked at the provider in the meantime would stay
    #: signed in until the session expires. After this many hours without a yes the session ends; the
    #: next sign-in then shows whether the way to the provider works again. Price: If the provider is
    #: gone for longer, all OIDC sessions are signed out afterwards. 0 = no limit.
    oidc_session_max_unverified_hours: int = 25
    #: API keys of an OIDC account follow the provider (finding 8). If it says no on the re-check (4a),
    #: the account's keys go dormant immediately — fixed, cannot be switched off. In addition they apply only
    #: as long as the provider has confirmed the account within the last so many days (login via it
    #: or a refresh exchange with yes): Whoever works by script only has no session that 4a
    #: could re-check. Nothing is deleted — the next sign-in via the provider wakes the
    #: keys up again. Accounts without an OIDC binding (including service accounts) are not affected. 0 = no
    #: deadline (only the no counts).
    oidc_apikey_confirm_days: int = 30

    # --- SAML 2.0 (SP login against an IdP: ADFS, Keycloak, Okta, Entra …) ---
    saml_enabled: bool = False        # SAML 2.0 sign-in against an IdP — needs [saml] and libxmlsec1
    saml_name: str = "SAML"               # display name of the button
    saml_sp_entity_id: str = ""           # own SP entity ID; empty = base_url + /auth/saml/metadata
    saml_acs_url: str = ""                # Assertion Consumer Service; empty = base_url + /auth/saml/acs
    # IdP entity ID. Empty = the SSO URL is assumed — that is right for some IdPs, for
    # others it is NOT: Keycloak, for example, calls itself `https://…/realms/<realm>`, while the SSO URL ends
    # in `/protocol/saml`. If it does not match, every assertion is rejected ("Invalid issuer");
    # the reason is then in the logger `tinysesam.security`. When in doubt, copy it from the IdP descriptor
    # (`entityID=` in the metadata XML).
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""            # IdP single-sign-on URL (redirect binding)
    saml_idp_x509cert: str = ""           # IdP signing certificate (PEM body, without BEGIN/END)
    saml_attr_username: str = ""          # attribute with the username; empty = NameID
    saml_attr_email: str = "email"    # SAML attribute with the email address
    #: Trust addresses from the assertion across the board? SAML has no proof. `False` (default):
    #: The address is not used directly — no account attribute, no `Remote-Email`, an
    #: account name with `@` yields to a substitute name (like H-3 for OIDC); with
    #: `federation_email_confirm` the owner confirms it by link, or `saml_attr_email_verified`
    #: names a proof. `True`: The IdP verifies every address (corporate IdP without self-registration).
    saml_email_trusted: bool = False
    #: Attribute of the assertion whose true value proves the address (e.g. a Keycloak mapper for
    #: `emailVerified`). Empty = none.
    saml_attr_email_verified: str = ""
    #: Have addresses from LDAP/SAML that are not trusted confirmed by link (PO decision
    #: 2026-09-25): After sign-in a confirmation link goes to the address from the source —
    #: at most one delivered per account and day (across all workers; if a link lives longer,
    #: `email_change_ttl_min`, that long), none while one is open; a throttle or a
    #: failed delivery is retried after `mail_per_address_window_sec`. An address already taken
    #: or reserved gets none, its rejection counts like a delivery. Only the click
    #: makes it the account's address, with proof. Needs mailer and `base_url`.
    federation_email_confirm: bool = True
    saml_attr_name: str = "displayName" # SAML attribute with the display name
    #: The attribute with the **stable** identifier (F-11). Empty = the assertion's `NameID`.
    #: It is only suitable if its format is permanent: `persistent` or an own identifier from
    #: the directory. A **transient** NameID format changes with every sign-in and is
    #: worthless as a binding — then an attribute the IdP reliably sends belongs here.
    saml_attr_id: str = ""
    saml_attr_groups: str = "groups"  # SAML attribute with the groups (for saml_group_role_map)
    saml_allowed_groups: list[str] = field(default_factory=list)  # empty = all
    saml_auto_create: bool = True     # create unknown users on their first successful SAML login

    # --- WebAuthn / passkey ---
    rp_id: str = "localhost"              # registrable domain (e.g. app.example.com) — WITHOUT scheme/port
    rp_name: str = "TinySesam"            # display name of the relying party
    #: Brand shown in front of a gateway's applications (e.g. a company name). If set, the sign-in page is called
    #: "Sign in to <brand>" and names the application below ("App: <name>"); if empty it stays at
    #: "Sign in to <application>". Display text only.
    gate_brand: str = ""
    origin: str = "http://localhost:8000" # exact origin (scheme+host+port) of the browser; several as a list

    # --- App integration ---
    # Public base URL — the one address under which the app is reachable from outside.
    # Source for EVERY absolute address: links in mails (reset, magic, confirmation, invitation),
    # OIDC redirect URI and post-logout, SAML entity ID/ACS, forward-auth redirect.
    # MANDATORY as soon as a mail path (magiclink_enabled, password_reset_enabled,
    # signup_verify_email), oidc_enabled or saml_enabled is on — otherwise the setup fails
    # with ConfigError. Reason: The Host header would remain as the source, and that is input from the
    # requester; without base_url an attacker could redirect the reset link in the victim's mail to
    # their own server. trusted_redirect_hosts is no substitute for it — if more than
    # one host is listed there, the requester chooses via the Host header.
    # If mounted under a subpath (root_path), the prefix belongs HERE:
    # "https://example.com/sso" — it applies to the LINKS SENT OUT, which carry it exactly once.
    # The built-in pages and their redirects take the same prefix since T-15 from the path
    # of this base_url (without base_url from the request's root_path). login_path, login_redirect,
    # logout_redirect and admin_path are therefore paths of the app WITHOUT the prefix.
    # Where base_url may stay empty (password/passkey/PIN/LDAP only,
    # forward_auth_enabled at most), a derived base is checked: only a host from
    # trusted_redirect_hosts or loopback counts, and the server's root_path comes along.
    # If base_url is set, it ALWAYS wins — even against a base passed in from outside on a
    # second own host from trusted_redirect_hosts (otherwise the Host header chooses which
    # of our own names ends up in the reset link).
    base_url: str = ""
    login_path: str = "/auth/login"       # login page
    login_redirect: str = "/"             # target after a successful login
    logout_redirect: str = "/auth/login"  # target after logout

    # --- Hardening ---
    # Reverse proxies whose X-Forwarded-For may be trusted (otherwise the real client IP can be forged).
    # X-Forwarded-For is believed only from these peers — otherwise the client IP can be forged
    # (rate limit, lockout, fail2ban). IMPORTANT: start uvicorn **without** `--proxy-headers`. Otherwise
    # uvicorn already replaces `request.client.host` with the forwarded IP and this check
    # comes to nothing.
    trusted_proxies: list[str] = field(default_factory=lambda: ["127.0.0.1/32", "::1/128"])
    # Rate limit across processes via Redis (multi-worker); empty = in-memory per process. Extra [redis].
    redis_url: str = ""                   # e.g. redis://localhost:6379/0
    # Hosts that ?next= may point to absolutely (open-redirect protection; empty = relative paths only).
    # The host of your own base_url always counts and need not be repeated here.
    trusted_redirect_hosts: list[str] = field(default_factory=list)
    # File the logger "tinysesam.security" additionally writes to — the feed for
    # fail2ban (deploy/fail2ban/), e.g. /var/log/tinysesam/security.log. Empty = to the
    # logger only; whoever sets up logging themselves leaves it empty. If the file is not writable,
    # TinySesam warns and carries on. When NEWLY created it gets 0640 instead of the umask (also
    # after a rotation), because it contains usernames and IP addresses; an already
    # existing world-readable file is reported but not rewritten. If a THIRD
    # user is to read along (log shipping, neither owner nor in the group), the way leads through
    # the group: logrotate line `create 0640 tinysesam adm` (stands that way in
    # deploy/fail2ban/tinysesam-jail.conf). Without it the file is created again at the next
    # rotation with the group of the TinySesam process, and the shipping loses
    # read access — not at the update, but only at the rotation.
    security_log: str = ""
    # Retention of the audit log in days: `auth.gc()` deletes older lines (B5-11). 0 = no
    # deadline, the log grows without limit as before. The audit log contains usernames and IPs,
    # i.e. personal data — a deadline is the operator's business (purpose and duration belong
    # in their record of processing activities). The default therefore deletes nothing on its own. The
    # command `tinysesam gc --audit-days N` does the same from the command line. Allowed are
    # 0 to 3660 (ten years) — a value in seconds instead of days is rejected, not
    # silently accepted.
    audit_retention_days: int = 0
    # Truncate IPs in the audit log to their network (IPv4 /24, IPv6 /48). Applies to new lines; lock,
    # rate limit and security_log (fail2ban) still see the full address, otherwise a
    # lock would hit the whole network.
    audit_ip_pseudonymize: bool = False
    # Fine-tuning (attempts/lock time/rate limit) lives in the store and can be changed in the admin panel
    # (defaults: tinysesam.security.SECURITY_DEFAULTS).

    @classmethod
    def local_accounts(cls, **overrides):
        """Preset: **username + password only**, entirely without email.

        Switches off everything that presupposes an address (magic link, forgot password,
        email confirmation) and lets the login accept only the username. Ideal for internal
        tools without a mail server. With `pin_enabled=True` a PIN can be added —
        e.g. `stepup_methods=["pin"]` for sensitive areas.
        """
        base = dict(login_identifier="username", signup_require_email=False,
                    signup_verify_email=False, magiclink_enabled=False, password_reset_enabled=False)
        base.update(overrides)
        # `base` is a dict of mixed values; the dataclass checks the field types at runtime.
        return cls(**base)   # type: ignore[arg-type]

    @classmethod
    def oidc_gateway(cls, *, issuer, client_id, client_secret, base_url,
                     cookie_domain="", trusted_redirect_hosts=None, allowed_groups=None,
                     group_claim="groups", oidc_name="SSO", oidc_scopes="openid profile email",
                     db_path="tinysesam-gateway.db", https_mode="warn", session_ttl_hours=24 * 7,
                     trusted_proxies=None, clients=None, revalidate_minutes=60, **overrides):
        """Preset: TinySesam as a pure **OIDC forward-auth gateway** (Authelia/oauth2-proxy style).
        All other methods/features off, OIDC + forward auth on. Runs with `pip install 'tinysesam[oidc]'`.
        Individual fields can be overridden via **overrides.

        `clients` protects **several applications** with one installation: host → own client
        at the same provider (T-14). Without it the single client applies to everything, exactly as
        before.

        `revalidate_minutes` is **60** here, not 0 as in the base setup: A gateway
        is the place where the provider's approval is the only authorisation. If it stayed
        valid until the end of the session, a group revocation would not take effect there for up to `session_ttl_hours`
        — by default seven days.

        Why one hour and not less: Every re-check is a hop via the provider.
        For a human at the browser that is a flicker, for anything else a break — an
        open form, a running upload, a background XHR request. The shorter the
        period, the more often it hits one of them. Compared with seven days, one hour is the
        order of magnitude that matters; the difference between 15 and 60 minutes is rarely decisive
        for a revocation, but certainly for operation. Whoever needs it tighter
        sets it tighter."""
        base = dict(
            db_path=db_path,
            password_enabled=False, passkey_enabled=False, pin_enabled=False,
            oidc_enabled=True, magiclink_enabled=False, apikey_enabled=False,
            allow_signup=False, admin_enabled=False, account_enabled=False,
            totp_enabled=False, resource_locks_enabled=False,
            forward_auth_enabled=True,
            oidc_issuer=issuer, oidc_client_id=client_id, oidc_client_secret=client_secret,
            oidc_name=oidc_name, oidc_scopes=oidc_scopes,
            oidc_allowed_groups=list(allowed_groups or []), oidc_group_claim=group_claim,
            oidc_auto_create=True,
            oidc_clients=dict(clients or {}), oidc_revalidate_minutes=revalidate_minutes,
            base_url=base_url, cookie_domain=cookie_domain,
            trusted_redirect_hosts=list(trusted_redirect_hosts or []),
            session_ttl_hours=session_ttl_hours, https_mode=https_mode,
            trusted_proxies=list(trusted_proxies or ["127.0.0.1/32", "::1/128"]),
            # In front of foreign applications the gate signs in invisibly (PO decision 2026-10-03):
            # page load → provider → back. A window "Sign in to TinySesam" with a
            # single button would be just one more click.
            forward_login="direct",
            # Signing out also ends the session at the provider (T-22) — otherwise `direct` would silently sign in
            # again on the next page load, and "sign out" would be a reload.
            oidc_rp_logout=True,
        )
        base.update(overrides)
        # `base` is a dict of mixed values; the dataclass checks the field types at runtime.
        return cls(**base)   # type: ignore[arg-type]

    @classmethod
    def active_directory(cls, *, ldap_url, upn_suffix=None, base_dn=None, bind_dn="", bind_password="",
                         allowed_groups=None, **overrides):
        """Preset: password login against **Active Directory** (via LDAP). Either direct bind by UPN
        (`upn_suffix="corp.example.com"` → user@corp.example.com) OR search-then-bind via
        sAMAccountName (`bind_dn`/`bind_password`/`base_dn`). Remaining fields via **overrides (db_path …)."""
        base = dict(
            ldap_enabled=True, ldap_url=ldap_url, ldap_group_attr="memberOf",
            ldap_allowed_groups=list(allowed_groups or []), ldap_auto_create=True,
            ldap_attr_email="mail", ldap_attr_name="displayName",
        )
        if upn_suffix:
            base["ldap_user_dn_template"] = "{username}@" + upn_suffix.lstrip("@")
        else:
            base.update(ldap_bind_dn=bind_dn, ldap_bind_password=bind_password,
                        ldap_user_base=base_dn or "", ldap_user_filter="(sAMAccountName={username})")
        base.update(overrides)
        # `base` is a dict of mixed values; the dataclass checks the field types at runtime.
        return cls(**base)   # type: ignore[arg-type]

    @classmethod
    def entra_id(cls, *, tenant_id, client_id, client_secret, oidc_name="Microsoft", **overrides):
        """Preset: **Entra ID / Azure AD** via OIDC (cloud AD). tenant_id = directory (tenant) ID."""
        base = dict(
            oidc_enabled=True,
            oidc_issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            oidc_client_id=client_id, oidc_client_secret=client_secret,
            oidc_name=oidc_name, oidc_scopes="openid profile email",
        )
        base.update(overrides)
        # `base` is a dict of mixed values; the dataclass checks the field types at runtime.
        return cls(**base)   # type: ignore[arg-type]

    def validate(self) -> list[str]:
        """Check the configuration again — for the case that it was changed after setup.

        `TinySesam` checks in the constructor and afterwards keeps a **reference** to this object:
        Whoever sets fields later (`auth.cfg.cookie_samesite = "Strict"`) bypasses every
        guard that way, and the values are read at request time. That is not a theoretical case —
        `examples/showcase.py` changes `auth.cfg` after setup, and for language or branding
        that is perfectly fine.

        Only the fields from which cookies and headers are made are delicate. Whoever turns
        the configuration at runtime calls this method afterwards and gets a list of findings
        (empty = fine). Freezing the dataclass would be the harder solution — but it would
        also forbid what is allowed.
        """
        fehler, warnungen = self._befunde()
        return fehler + warnungen

    def _befunde(self) -> tuple[list[str], list[str]]:
        """(errors, warnings) kept apart — `validate()` returns both in one list, and from
        that one could no longer read what would have made the setup fail. `TinySesam.router()`
        needs exactly this distinction (B3-14)."""
        from .config_check import _t, check_config
        fehler, warnungen = check_config(self)
        if self.cookie_samesite not in ("lax", "strict", "none"):
            fehler.append(_t(
                self, "cookie_samesite={value!r} — allowed are 'lax', 'strict', 'none' (lower case)",
                value=self.cookie_samesite))
        if self.cookie_samesite == "none" and not self.cookie_secure:
            fehler.append(_t(
                self, "cookie_samesite='none' without cookie_secure=True — the browser discards "
                "such a cookie"))
        if self.https_mode not in ("off", "warn", "force"):
            fehler.append(_t(
                self, "https_mode={value!r} — allowed are 'off', 'warn', 'force'",
                value=self.https_mode))
        if not isinstance(self.csp, str):
            fehler.append(_t(self, "csp must be a string, is {type}", type=type(self.csp).__name__))
        if not self.cookie_secure and self.https_mode == "force":
            fehler.append(_t(
                self, "https_mode='force' with cookie_secure=False — the session cookie would go "
                "out without the Secure flag"))
        return fehler, warnungen

    def enabled_methods(self) -> list[str]:
        """First factors that the login page offers. A PIN that cannot be a first factor
        (`pin_as_first_factor()`) is deliberately NOT listed here — it stays usable as an additional
        factor/step-up."""
        m = []
        if self.password_enabled:
            m.append("password")
        if self.pin_as_first_factor():
            m.append("pin")
        if self.passkey_enabled:
            m.append("passkey")
        if self.oidc_enabled and self.oidc_issuer and self.oidc_client_id:
            m.append("oidc")
        if self.saml_enabled and self.saml_idp_sso_url and self.saml_idp_x509cert:
            m.append("saml")
        if self.magiclink_enabled:
            m.append("magic")
        return m

    def pin_as_first_factor(self) -> bool:
        """Does a PIN sign in as the FIRST factor — on the login page and via `/auth/pin` without a
        session?

        Yes with `pin_enabled` and `pin_login` — unless a strict `login_chain` demands the PIN
        behind another factor (G7). There a PIN entered first never satisfies the chain
        any more, the order is wrong afterwards (`_chain_satisfied`). The guest path was thus useful
        only to guessers: Without the password it answered a wrong PIN with 401, the right one
        with 303. And through it someone with mailbox and password evaded the kind of series
        that a self-service reset clears. The PIN step AFTER the first factor (half session)
        hangs on none of these switches.

        In a NON-strict chain the PIN stays a first factor with `pin_login`, even if it comes
        last — the config check warns about this."""
        if not (self.pin_enabled and self.pin_login):
            return False
        kette = list(self.login_chain or [])
        return not (self.login_chain_strict and "pin" in kette and kette[0] != "pin")

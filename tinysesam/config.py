"""Configuration for TinySesam. The embedding app fills TinySesamConfig and passes it to TinySesam()."""
from __future__ import annotations
from dataclasses import dataclass, field

from . import _chain


@dataclass
class TinySesamConfig:
    # --- Store ---
    db_path: str = "tinysesam.db"

    # --- Language of the built-in texts (en|de; add your own via auth.add_messages) ---
    lang: str = "en"

    # --- Branding/theme: set once → re-skins ALL built-in pages (+ error pages) ---
    brand_css: str = ""                   # additional CSS (after the default → overrides it)
    brand_head: str = ""                  # additional <head> HTML (e.g. logo font, meta)
    #: Same look as an app built on the C22 design system: the address PATH of the app's compiled C22
    #: stylesheet (e.g. "/static/c22-vega.css", same origin only). Set → every built-in page loads it and
    #: derives its --ts-* tokens from C22 (tinysesam/c22.css, own defaults as fallback); light/dark follows
    #: C22. No C22 code runs on the pages. Empty (default) = TinySesam's own look.
    c22_stylesheet: str = ""
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
    #: Top bar of the built-in pages (T-64): logo (`brand_icon`, else a built-in mark), name, `topbar_links` and,
    #: on the account, setup, reauth and consent pages, the account menu (account, admin panel, light/dark/system,
    #: sign out). Sign-in and error pages show logo and name only. False = no bar (the account page then carries
    #: its admin and sign-out links itself) — e.g. when `brand_header` already frames the pages with an own navigation.
    topbar_enabled: bool = True
    #: Links in the top bar, as (title, target) pairs: `[("Wiki", "/wiki"), ("Files", "https://files.example.com/")]`.
    #: A target is a path on the own origin (`/…`, as the browser sees it) or an https address on a host that a
    #: `next=` may reach too (`base_url`, `trusted_redirect_hosts`). Shown next to the name, on a phone in the menu.
    #: An optional third element limits who sees the link (T-76): `("Admin", "/admin", {"admin": True})` for accounts
    #: with the admin flag, `("Team", "/team", {"role": "teamadmin"})` for accounts with the role — decided by
    #: `has_role`, so with `admin_implies_roles` (default) an admin sees role links too. A pair stays visible to
    #: everyone. Visibility is a convenience, not a protection: the target checks access itself. Pages without the
    #: account menu (sign-in, errors) show no links at all. The same filter answers `GET /auth/topbar.json`.
    topbar_links: list = field(default_factory=list)
    #: Links in the account menu of the top bar, after "Signed in as …" and before "Account", with a separator of
    #: their own: `[("My collections", "/collections"), ("Moderation", "/mod", {"role": "moderators"})]`. The same
    #: shape, targets and visibility rules as `topbar_links` (one check, one filter); at most 10 are recommended (a
    #: warning above, the menu would run off the screen). Without a signed-in account there is no menu and so no
    #: menu link. `GET /auth/topbar.json` answers them as `menu_links`. Visibility is a convenience, not a protection.
    topbar_menu_links: list = field(default_factory=list)
    #: Tooltip of the logo image (`title` on the `<img>` of `brand_icon`), e.g. a credit "Logo: Example Icons,
    #: CC BY 4.0". At most 200 characters, no control characters; escaped. Empty (default) = no attribute. Works only
    #: with an image in `brand_icon` (not with the built-in mark or "none"). A tooltip is no visible credit: when a
    #: licence asks for one, name it on a page of the application.
    brand_icon_title: str = ""

    # --- Roles/groups ---
    # Does an admin satisfy EVERY require_role(...) check? Default True (classic behaviour).
    # CAUTION: if an app's permissions hang solely on an IdP group, this is a silent
    # privilege escalation — set False then, or use `require_role(..., admin_implies=False)` per guard.
    admin_implies_roles: bool = True
    # How are IdP groups compared with the keys of *_group_role_map?
    # "exact" (default, safe) or "substring" (the old substring comparison, on request only).
    # With "exact", LDAP compares a memberOf DN by its parts: the whole DN, "cn=staff" or "staff".
    group_match: str = "exact"
    # Known roles/groups: the admin panel offers them as checkboxes, together with the role catalog administrators fill
    # in the panel (README "Role catalog"); both empty = free-text fallback. Every role the configuration refers to
    # elsewhere (delegates, allowlists) belongs here. No comma, control character or surrounding spaces (T-85).
    available_roles: list[str] = field(default_factory=list)
    # Role levels: ladders the admin panel offers as ONE choice per entry instead of single checkboxes, e.g.
    # `[{"name": "collections", "label": "Collections", "levels": [
    #   {"name": "read", "role": "coll:{1}-read"}, {"name": "write", "role": "coll:{1}"}]}]`.
    # Levels lowest first, each adds one role template with `{1}`; a level stores its role and every role below it.
    # The entries (`{1}`) come from `available_roles` and the role catalog. A way to pick roles, not a role hierarchy:
    # headers, gate token and key scopes carry exactly the stored roles. See README, "Role levels".
    role_levels: list = field(default_factory=list)
    # IdP group → local role (set on OIDC/SAML/LDAP login). Target "__admin__" = admin flag (grant only).
    # Compared according to `group_match` (default exact). Managed roles are synchronised on each login.
    oidc_group_role_map: dict = field(default_factory=dict)
    saml_group_role_map: dict = field(default_factory=dict) # SAML group → local role, e.g. `{"staff": "editors"}`
    ldap_group_role_map: dict = field(default_factory=dict) # LDAP group (DN or name) → local role

    # --- Active login methods (all can run in parallel) ---
    password_enabled: bool = True     # offer password login at all (off = SSO/passkey/PIN only)
    # Own blocklist for new passwords: path to a text file, one password per line
    # (UTF-8, lines in another encoding count as Latin-1; `#` at the start of a line = comment).
    # Complements the built-in list (the 10,000 most frequent passwords of 8+ characters, since H1) — for a
    # bigger leak list (e.g. the 100,000 most frequent), put it here. Offline: TinySesam asks no third-party
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
    # The same list decides which factor on the sign-in pages refreshes a session that is already
    # signed in (passkey, OIDC and SAML always do; a sign-in link or QR approval never does).
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
    #: Lifetime of an app password in days if the holder names none (T-66). App passwords are switched on per
    #: application with `forward_apps[host]["app_passwords"] = True`; they are for HTTP clients that speak only
    #: Basic auth (WebDAV, CalDAV/CardDAV, Git over HTTPS) and are valid only at the gate (`/auth/forward`) of
    #: the applications chosen at creation. A year, not 90 days: an app password is typed into a phone by hand,
    #: and breaking the calendar sync every quarter teaches people to work around it. 1–3650.
    app_password_default_days: int = 365
    #: May an app password be created without expiry? Default no — the same reasoning as for API keys: a secret
    #: without an end outlives the device it was typed into.
    app_password_allow_unlimited: bool = False
    admin_enabled: bool = True            # mount the admin panel automatically at admin_path
    admin_path: str = "/auth/admin"       # default mount point; auth.admin_router() also lets you mount it elsewhere
    admin_ui_enabled: bool = True         # built-in HTML UI; False = JSON API only (for embedding in your own panel)
    account_enabled: bool = True          # built-in self-service page /auth/account (overridable)
    forward_auth_enabled: bool = False    # /auth/forward + /auth/verify for reverse proxy (Caddy/nginx/Traefik)
    # Which headers the forward-auth response sets. Empty = the Authelia-style set
    # Remote-User/-Name/-Email/-Groups, Remote-Id (the account ID — stable across renames and
    # mail changes, since 2026-09-25) and Remote-Auth (how the request signed in: `session`, `oauth`, `apikey`
    # or `app-password`; a valid gate token counts as `session` — T-75) and Remote-Kind (what the account is: `user`,
    # or `service` for a service account). Otherwise **field → header name** (or list of names); what is not listed
    # here is NOT set — except `kind`, which is always sent: left out, it goes under `Remote-Kind`; it can be renamed
    # (`{"kind": "X-Account-Kind"}`) but not dropped (gate clients after spec v2 refuse a request without it).
    # Fields: user · name · email · groups · id · auth · kind.
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
    # Keyring file of the gate signing key (T-48, ADR-12): Base64 of a 32-byte Ed25519 seed, further lines are
    # older keys the proxy still accepts. The environment variable TINYSESAM_GATE_KEY (+ `_PREVIOUS`) takes
    # precedence; without both the key is random and kept in the database, encrypted with the vault key. Never
    # derived from the vault key. The proxy learns it from /auth/gate/jwks.json (`jwk_url`) or `tinysesam gate-key`.
    gate_key_file: str = ""
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
    # "logout": "ask", "app_passwords": True}}. name = display name on the login and sign-out pages; login/logout
    # override forward_login/forward_logout for this host; app_passwords = this host accepts app passwords by
    # Basic auth (T-66, default off — WebDAV, CalDAV/CardDAV, Git over HTTPS; never the account's own password).
    # The app frame (T-91): home and links make TinySesam's own pages (sign-in, step-up, account, approvals) look
    # like part of the application whenever a person comes from this host — the top bar shows "‹ name" back to home
    # and the application's links instead of topbar_links and topbar_menu_links. home = a path or an https address on
    # exactly this host (default https://<host>/); links = the shape of topbar_links, every target on this host (a
    # path means a path on this host), at most 8. A frame needs a name. The frame is chosen by ?app=<host>, by the
    # host of an absolute next/return_url, or by app=<host> inside a relative next; the targets always come from here,
    # never from the request. Read by the library as well, with or without forward auth.
    forward_apps: dict = field(default_factory=dict)
    # The frame of the pages when no request names one (T-91): a host of forward_apps whose entry has home or links,
    # e.g. a TinySesam that serves exactly one application. Empty (default) = TinySesam's own top bar then.
    forward_frame_default: str = ""
    gate_cookie_name: str = "__Host-tinysesam_gate"  # form __Host-tinysesam_<name>: host-only, and the templates strip it before the app
    # Central gateway, session stays on its host (T-26): An app host gets, via a
    # code exchange (/.tinysesam/start → /auth/gate/authorize → /.tinysesam/callback), only a connection
    # cookie of its own that is valid for it alone. Without this, the session cookie would have to sit on
    # the parent domain and would reach every app below it. Requires gate_token_enabled and base_url,
    # does not combine with cookie_domain.
    gate_link_enabled: bool = False

    # --- OAuth 2.1 for MCP clients and other human-operated tools (T-36, ADR-11) ---
    # TinySesam becomes an authorization server: a tool such as Claude Code registers itself (dynamic
    # registration, loopback redirect only), the person signs in here as always (chain, TOTP, passkey) and
    # allows the access on a consent page. The protected application contains no OAuth code: forward auth
    # accepts the access token and sets Remote-* as for a session. Needs forward_auth_enabled, base_url (the
    # issuer) and at least one entry in oauth_resources. Recipe: README "OAuth for MCP clients".
    oauth_enabled: bool = False
    # The protected resources tokens are issued for — absolute URLs, e.g. ["https://app.example.com/mcp"].
    # The token is valid only for this URL and the paths below it (audience, RFC 8707); the proxy routes
    # /.well-known/oauth-protected-resource* of the application's host to TinySesam.
    oauth_resources: list[str] = field(default_factory=list)
    oauth_access_token_ttl_sec: int = 3600   # lifetime of an access token; checked against the database per request
    # A refresh token expires after this many days without use (sliding: each use renews it).
    oauth_refresh_idle_days: int = 90
    # Absolute maximum of a connection in days, regardless of use — then the person signs in again
    # (ASVS 5.0 V10.4.8). 0 = no maximum (only on purpose: config_check reports it).
    oauth_refresh_max_days: int = 180
    # Grace window in seconds: a refresh token used again within it returns the SAME successor instead of
    # counting as reuse (two processes of one client refreshing at once). 0 = every second use revokes the
    # connection; Claude Code serialises its refreshes, so 0 is enough there. 0–60.
    oauth_refresh_grace_sec: int = 0
    # Keyring file with the pepper of the token digests (Base64, at least 32 bytes; further lines: older peppers,
    # docs/OPERATIONS.md "Keys"). The environment variable TINYSESAM_OAUTH_PEPPER takes precedence; without both
    # the pepper is a random key of its own, stored in the database encrypted with the vault key (ADR-12).
    # Rotation: `tinysesam keys rotate --purpose oauth-pepper` — connected devices stay connected.
    oauth_pepper_file: str = ""
    # Services: client_credentials + private_key_jwt (T-60, ADR-13).
    # A service or daemon without a person gets short-lived access tokens from the same server. It is paired once
    # with a one-time code from the account page or the admin panel, creates its key pair itself and proves
    # every token request with a signed assertion (RFC 7523) — TinySesam keeps only the public key. Needs
    # oauth_enabled and the extra [services] (joserfc). Recipe: README "A service calls a protected app".
    oauth_service_clients: bool = False
    oauth_service_token_ttl_sec: int = 900   # lifetime of a service's access token; no refresh token, it asks anew
    # Lifetime of a service key in days: the reference client rotates it on its own at half of it; 0 = no
    # expiry (only on purpose: config_check reports it).
    oauth_service_key_days: int = 90
    oauth_pairing_minutes: int = 10          # how long a pairing code can be redeemed
    # Pairing code for people's programs (ADR-14): the consent given in advance. The account fetches a one-time code
    # in its own fresh browser session (account page "Connect a program", or the application in the browser through
    # POST /auth/oauth/pairing); a setup script redeems it right before `claude mcp login`. Then exactly ONE following
    # authorization of that account — dynamically registered client, loopback redirect, matching resource, opened by
    # the person's own browser (`Sec-Fetch-Site: none`), the same account signed in — goes through without the consent
    # page. Without a code, after expiry or after `claude mcp logout` the consent page asks as always. Needs
    # oauth_enabled. Recipe: README "OAuth for MCP clients".
    oauth_pairing_consent_enabled: bool = False
    # How long the code and the consent it arms last, counted from issuing (1–60 minutes).
    oauth_pairing_consent_minutes: int = 15
    https_mode: str = "warn"              # off | warn | force  — force = HTTP→HTTPS redirect;
                                          # warn = also runs WITHOUT a certificate (with a warning in the panel)
    # Strict-Transport-Security on every HTTPS response while https_mode='force' (ASVS 3.4.1). The default is
    # one year, the minimum ASVS asks for. Without includeSubDomains: TinySesam often runs inside an app on a
    # domain that has other subdomains, and the flag binds EVERY one of them to HTTPS — a decision about
    # the whole domain tree that belongs to its owner (ASVS L2 wants it: append "; includeSubDomains").
    # No preload as a default: the browsers' preload list is hard to leave again.
    # "" = no header (e.g. the proxy in front sets it).
    hsts: str = "max-age=31536000"
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
    #: Sign-in links redeem (`/auth/magic/{token}`) — sent by mail on request, issued by an admin
    #: in the panel, or created by app code (`create_signin_link`). Whether anyone may request one by
    #: mail on the login page is the separate switch `magiclink_self_request` (T-33).
    magiclink_enabled: bool = False   # sign-in by one-time link (mailed, admin-issued or app-issued)
    #: With `magiclink_enabled`: the login page offers "email me a sign-in link" and
    #: `/auth/magic/request` exists — this part needs a mailer. `False` = links only from the admin
    #: panel or app code: the request route is gone (404), the button too, issued links still redeem.
    magiclink_self_request: bool = True
    #: Validity of a one-time link in minutes — the mailed sign-in link and the reset link (T-51). Default 10 (up to
    #: 0.25.x: 15): ASVS 5.0 6.5.5 limits out-of-band requests to 10 minutes, and a link that waits in a mailbox is a
    #: key lying about. The person asked for the link a moment ago, so ten minutes suffice; the reset link stays at
    #: this value on purpose (OWASP Forgot Password Cheat Sheet: short-lived). Invitations have their own
    #: `invite_ttl_min`. 1–1440.
    magiclink_ttl_min: int = 10
    #: Validity in minutes of an invitation without an own `ttl_min` (`create_invite`, the panel's invitation). Default
    #: 24 h: unlike a sign-in or reset link nobody asked for it, and the invitee rarely opens the mail within minutes.
    #: Bounded by `signin_link_max_ttl_min` like an issued sign-in link (an invitation is a hand-over link that may
    #: even carry admin rights); `config_check` refuses a larger value with `allow_signup`. Up to 0.25.x an
    #: invitation took `magiclink_ttl_min` (15) — set that value to keep it. 1–10080.
    invite_ttl_min: int = 24 * 60
    #: Upper bound in minutes for a sign-in link an administrator or app code issues (`create_signin_link`, the panel's
    #: "Sign-in link"), T-51. Default 24 h: NIST SP 800-63B-4 §4.2.2 lets a recovery code sent by mail live at most
    #: 24 hours, and a hand-over link is the same kind of key. Up to 0.25.x the bound was 7 days (10080) — set that
    #: value to keep it. 1–10080.
    signin_link_max_ttl_min: int = 24 * 60
    #: ASVS 6.3.6 (PO decision 2026-09-24): If an account has a second factor (TOTP or
    #: passkey), the sign-in link alone does not sign in fully — the factor is demanded afterwards.
    #: Otherwise the mailbox would be the only key, even for an account that protected itself with an
    #: authenticator. Accounts without a second factor are still signed in by the link alone.
    #: Applies to the global chain and every route chain (`require(factors=["magic"])`, G10).
    #: `False` = the link always suffices (behaviour up to 0.20.x in chains like `["magic"]`).
    magiclink_require_second_factor: bool = True
    #: A sign-in link only for the FIRST sign-in (T-34), not as a regular way in: it signs in an
    #: account that has never been fully signed in, or one that lacks a factor of `login_chain` and
    #: may set it up itself (the setup pass opens). Any other account gets "this link is only for
    #: the first sign-in" — whoever issued it, the admin included. Use it with "the admin creates
    #: accounts and hands out a link": afterwards the account signs in through the chain only.
    #: Not for the cross-device sign-in (QR): its approval comes from a full session of the same
    #: account. `False` (default) = links sign in as before.
    magiclink_first_login_only: bool = False

    # --- Cross-device sign-in (QR code, T-33) ---
    #: A device without a session shows a QR code and a short code on the login page; a device on
    #: which the user is already signed in scans it (or types the code), sees which device and IP ask,
    #: and approves. The new device then gets its own session. Counts as factor `magic`: the
    #: second-factor rule of the sign-in link applies (`magiclink_require_second_factor`). No mailer
    #: needed. The QR code needs `base_url` (absolute address) and the extra `[qr]`; without
    #: either, only the short code is shown.
    qr_login_enabled: bool = False
    qr_login_ttl_sec: int = 120           # validity of a cross-device request (single use)
    #: Hardening against consent phishing (T-44, RFC 10027 §6.1): the approval of a cross-device
    #: request is allowed only for an account that has a second factor (TOTP or passkey) — then the
    #: new device has to present it as well (`magiclink_require_second_factor`), and an approval that
    #: was talked out of the account holder gives a half sign-in at most. An account without one
    #: would be taken over completely by one approved request. `False` = accounts without a second
    #: factor may approve as well (number matching and a fresh confirmation still apply).
    qr_login_require_second_factor: bool = True

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
    #: Notify the owner by mail about NEW access to their account (T-47, NIST SP 800-63B-4
    #: §4.1.2.1): a new factor (passkey, TOTP, PIN), a new API key, a device signed in by QR
    #: approval, a sign-in link issued for the account, a password set by an administrator, a
    #: connected OAuth program and a refresh token caught being reused. Only with delivery configured
    #: and only to a verified address; at most one mail per account and event a minute. The same
    #: events always reach `on_security_event` and the account page's "Recent activity". Opt-out: False.
    notify_new_access: bool = True

    # --- TOTP (2FA on top of password/OIDC; passkeys are already phishing-resistant) ---
    totp_enabled: bool = True             # users may set up TOTP
    #: Which time steps a TOTP code may come from (T-57, RFC 6238 §5.2, ASVS 5.0 6.5.5): "previous" (default) =
    #: the current 30-second step and the one before it, for a code typed just before the change; "current" =
    #: only the running step; "previous_and_next" = also the next step (behaviour up to 0.25.x, for authenticators
    #: whose clock runs fast). Every code still counts only once.
    totp_window: str = "previous"
    #: Keyring file of the vault (H-14/H-15, T-48): it encrypts the TOTP secrets, OIDC refresh/ID tokens and the
    #: keys kept in the database (32 bytes, Base64; the first line is active, further lines are older keys that
    #: only decrypt). The environment variable TINYSESAM_SECRETS_KEY (+ `_PREVIOUS`) takes precedence; with
    #: neither, TinySesam creates `<db_path>.key` (0600). Without the key all TOTP setups are lost — back it
    #: up separately from the database (docs/OPERATIONS.md "Keys"). Rotation: `tinysesam keys rotate`.
    secrets_key_file: str = ""
    # CAUTION: ineffective and therefore REJECTED since 0.18.0 — the switch was never
    # read. Making TOTP mandatory works through the factor chain:
    #   login_chain=['password', 'totp']  (+ login_chain_strict=True)
    # The field only stays so that an existing call gets a clear error
    # instead of a TypeError about an unknown argument.
    totp_required: bool = False
    recovery_code_count: int = 10         # number of one-time recovery codes per generation (lost authenticator)
    #: One-time recovery codes at all (T-94). `False`: the TOTP setup shows no code page and creates no codes, the
    #: account page offers none, and a code is no longer accepted anywhere — codes an account already holds stay in
    #: the database untouched (switching back on makes them valid again) and are deleted as before when TOTP is
    #: removed. A lost authenticator then needs someone who resets the access: an application's `reset_access`
    #: (`apps[…].provisioning`, scope `users:reset`) or the application's own code (`totp_disable`,
    #: `grant_mfa_enrollment`, `create_signin_link`); `config_check` warns when no application has `users:reset`.
    recovery_codes_enabled: bool = True
    #: A short hint per language above the QR code of the TOTP setup (T-94), e.g. which authenticator app to install:
    #: `{"en": "Use the app Example Authenticator.", "de": "…"}`. The page takes the
    #: entry of `lang`, else `en`, else the first one. Plain text only — shown escaped, at most 300 characters, no
    #: control characters (`config_check`). Empty = no hint.
    totp_app_hint: dict = field(default_factory=dict)

    # --- Password reset (forgot password by email; needs magiclink_enabled + mailer) ---
    password_reset_enabled: bool = False

    # --- Factor chains (ordered combinations) ---
    # Global default chain of satisfied factors that make a session complete, e.g.
    # ["oidc", "password"] or ["password", "totp"]. Empty = classic (one first factor + TOTP if
    # set up). Can be tightened per route: Depends(auth.require(factors=[...], strict=...)) —
    # in addition, never instead of this chain (since 2026-09-27). Factor names: password, pin, oidc, passkey,
    # totp, magic, saml. The first factor identifies the user.
    # Alternatives per step with "|" (T-34): ["password|passkey", "totp|passkey"] — any one of
    # them satisfies the step, and one factor never satisfies two steps (a passkey alone is not
    # both). After a sign-in link, an account that lacks factors for the chain sets them up in a
    # setup pass (`/auth/setup`) before it is fully signed in — see `magiclink_first_login_only`.
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
    #: The admin panel and `require_admin` additionally demand a fresh confirmation (T-45, ASVS
    #: 7.5.3/8.4.2): an old admin session cannot set passwords, issue sign-in links or grant rights
    #: without confirming again. Default `True` since H2 (before: `False`). An admin without a second
    #: factor confirms with the password; an account that has nothing to confirm with (purely
    #: federated) signs in again. `False` = the old behaviour (`config_check` warns).
    admin_require_mfa: bool = True
    #: A password set by an administrator (panel: new account or reset) is a start secret, not the
    #: account's password (T-46, ASVS 6.4.1): the next password sign-in stays half until the holder
    #: has chosen an own one (the page `/auth/setup`). `False` = the admin's password stays.
    admin_password_must_change: bool = True
    #: Delegated admins (T-74): a role whose holders manage the accounts of their team in the admin panel without
    #: being administrators — `{"teamadmin": {"roles": ["editors", "viewers"]}}`. A delegate creates accounts and
    #: invitations, issues sign-in links, locks and unlocks, and sets or removes the listed roles — only on accounts
    #: whose roles all stand in the list (no admin, owner or service account, never their own). Optional per role:
    #: `"manages": ["team-a-admin", …]` — delegate roles below it (a hierarchy without cycles; it appoints and
    #: removes them and manages their roles too), `"can": ["create", "invite", "disable", "roles", "signin_link"]` —
    #: a part of the actions (default all). The rest of the panel stays with administrators. Only a browser session
    #: counts: API keys, OAuth tokens and app passwords carry neither the panel nor the delegate role. The same
    #: step-up as administrators (`admin_require_mfa`). Every role must stand in `available_roles`; a delegate role
    #: stands in no `roles` list, only in `manages`. See README, "Delegated administration".
    admin_delegates: dict = field(default_factory=dict)

    # --- Approvals: confirm one sensitive action with a step-up (stage A: TinySesam actions) ---
    # A token (an API key of the account) asks TinySesam for an action it may not do on its own — set the roles of an
    # account, revoke an API key, disable an account. TinySesam stores the request and returns a link and a six-digit
    # match code; the person opens the link in their browser session, confirms once more (password, PIN, TOTP,
    # passkey or the provider, per approval — never a time window) and TinySesam executes the action with the same
    # code as the admin panel, checking the rights the SESSION has at that moment. A token never gains a right: it
    # only proposes. Off by default; without it nothing changes. See SECURITY.md "Approvals".
    approvals_enabled: bool = False
    # How long a request waits for its decision, in seconds (120–1800); afterwards it is `expired`.
    approval_pending_sec: int = 600
    # Open (pending) requests at the same time per account (1–50); more give 429.
    approval_open_per_account: int = 5
    # Open (pending) requests at the same time per asking API key (1–50); more give 429.
    approval_open_per_token: int = 3
    # New requests per account and hour (1–500); more give 429.
    approval_requests_per_hour: int = 20
    # Rejections of the same type from the same token within an hour that block that token for that type for an hour
    # (1–20). The answer to a token that keeps asking for something the person keeps refusing.
    approval_reject_limit: int = 3
    # --- Approvals, stage B: actions of an application ---
    # An application registered in `apps` with an `approvals` block asks for one of ITS action types (a type the
    # operator lists there, with a fixed text in English and German and a field schema) for a person; the person
    # confirms on the same page with a step-up, and the application picks up ONE signed confirmation — a short JWT
    # (`typ: tinysesam-approval+jwt`, `aud` = the application's id, one `authorization_details` entry, RFC 9396) that
    # it checks against `/auth/approvals/jwks.json` before it carries the action out. See SECURITY.md "Approvals".
    # How long a confirmed action waits for the application to pick up its confirmation, in seconds (60–900);
    # afterwards it is `expired`.
    approval_pickup_sec: int = 300
    # Lifetime of a confirmation from its pickup, in seconds (30–300). Short on purpose: it carries one action, once.
    approval_token_ttl_sec: int = 120
    # New requests per application and hour (1–10000), whatever the outcome; more give 429. It also bounds what an
    # application can learn from the answer `invalid_subject` about which ids are active persons.
    approval_app_requests_per_hour: int = 120
    # Keyring file with the Ed25519 seed that signs the confirmations (Base64 of 32 bytes; further lines: older keys,
    # docs/OPERATIONS.md "Keys"). The environment variable TINYSESAM_APPROVAL_KEY takes precedence; without both the
    # key is a random key of its own, stored in the database encrypted with the vault key (ADR-12). Never the gate
    # key. Rotation: `tinysesam keys rotate --purpose approval` — the applications follow through the key set.
    approval_key_file: str = ""

    # --- Applications: the account API (provisioning, stages A and B) ---
    # The register of applications that speak to TinySesam through a service account — one entry per product:
    # `{"example": {"account": "svc-example", "name": {"en": "Example"}, "provisioning": {…}}}`. The id (lower-case
    # letters, digits, `_`, at most 32) is what `users.managed_by` stores. `account` names the service account
    # (`is_service`) whose automation keys speak for the application — a key of any other account, a `human` key or
    # a session is refused. With `provisioning` the application manages the accounts it creates itself through
    # `/auth/api/users`: create (with a one-time link until the first sign-in), read, change the display name and the
    # roles of its allowlist, lock and unlock, delete and restore. Members of `provisioning`: `roles` (the allowlist —
    # listed in `available_roles`, never `admin`, a delegate role or a role a group map assigns), `scopes`
    # (`users:read`, `users:invite`, `users:update`, `users:disable`, `users:delete`), `link_ttl_min` (default 60, at
    # most `signin_link_max_ttl_min`), `max_accounts` (default 1000), `delete_grace_days` (default 7, 0–30: an account
    # that has signed in is locked and deleted by the cleanup only after this many days, restorable until then; one that
    # never signed in goes at once) and `limits` (per hour: `create_per_hour` 60, `disable_per_hour` 60,
    # `link_per_hour` 30, `taken_per_hour` 30, `delete_per_hour` 20; per day: `delete_per_day` 100) and `welcome_url`
    # (T-94: where the application's one-time links lead once the first sign-in and its setup are complete, when the
    # request names no `next` of its own — a path or an http(s) address on the host of `base_url` or in
    # `trusted_redirect_hosts`, checked like `next`; default: the usual target). It never touches
    # passwords, passkeys, TOTP, the address after creation, an account it does not own, an administrator or a
    # delegate. The operator hands existing accounts to an application or takes them back (panel, `tinysesam accounts
    # adopt|release`). Empty = no account API. See README "Accounts for applications" and SECURITY.md "Account API".
    # Resetting the access of an account that has signed in before (new phone, forgotten password) is no key action:
    # with the scope `users:reset` and `approver_role` (one role name) the application asks for the approval
    # `tinysesam.account.reset_access` (needs `approvals_enabled`), and a person holding `approver_role` at that moment
    # confirms it with a step-up — then every factor of the account is deleted and the application picks up a new
    # one-time link once. `approver_role` must never stand in the allowlist of any application (a leaked key would give
    # it to a straw account it created); only the operator, or a delegate whose `roles` hold it, grants it.
    # With an `approvals` block (needs `approvals_enabled`) the application asks people to confirm ITS OWN sensitive
    # actions (stage B): `types` maps a type name — ASCII, at least three dot-separated segments, the first one the
    # application's id, e.g. `example.collection.delete_permanently` — to `{"fields": {name: {"type": "string",
    # "max": 120, "pattern": "^…$"} | {"type": "integer", "min": 0, "max": 99} | {"type": "boolean"}}, "title":
    # {"en": …, "de": …}, "summary": {"en": "… {name} …", "de": …}, "irreversible": true}`; or `types_file` names a
    # JSON file with the same mapping (read at the start). The texts are the operator's: the application only sends
    # field values, which the page shows escaped and isolated. `return_urls` lists the exact addresses the browser may
    # be sent back to when the person started in the application (no prefix match); `types_from` lets a second channel
    # of the same product (its own id, its own service account) ask for the types of another entry, while its
    # confirmations name only its own id. See README "Approvals for application actions".
    apps: dict = field(default_factory=dict)

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
    # SAMEORIGIN and Cross-Origin-Opener-Policy: same-origin are added to HTML responses; nosniff, Referrer-Policy, no-store and Vary: Cookie are carried by all
    # TinySesam responses regardless of this switch.
    csp: str = "strict"
    # Report CSP violations to TinySesam itself (ASVS 3.4.7). Off by default. With csp='strict' the policy gets
    # `report-uri` and `report-to` pointing to <prefix>/auth/csp-report, the pages a `Reporting-Endpoints`
    # header, and the endpoint (POST, without sign-in — browsers send reports without cookies) writes one
    # `CSP violation directive=… page=… blocked=… ip=…` line per report to the `tinysesam.security` log. Only the
    # directive, the path of the page (never its query: sign-in and reset links carry tokens there) and the
    # origin of the blocked resource; at most 10 reports per minute and IP, 60 log lines per minute in total,
    # 8 KiB per body. No third party receives anything, and the policy itself stays as strict as without it.
    # Without csp='strict' (own policy, 'off') the switch does nothing: name your own report target there.
    csp_report: bool = False

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
    #: A successful refresh exchange for the application's client (`oidc_session_refresh_minutes`)
    #: renews the approval as well — the hop is then only needed without a refresh token (B-6).
    #: ``oidc_gateway()`` sets 60; whoever builds it by hand decides for themselves. Allowed are
    #: 0 to 43200 (30 days) — above that it is no longer a re-check. A period of one day
    #: or more written in seconds is therefore an error; above one day (1440) the
    #: check warns and asks for the unit (3600 for an hour). Shorter periods in seconds
    #: (300 instead of 5) go unnoticed — the unit is in the field name.
    oidc_revalidate_minutes: int = 0
    #: Re-authentication at the provider is checked (T-49, ASVS 5.0 6.8.4, OIDC Core §3.1.2.1): the confirmation
    #: page offers "Confirm with <provider>" to an account linked to it, which asks the provider for an active
    #: sign-in (`prompt=login`, `max_age=0`) and counts only with an `auth_time` from after the request; a round
    #: through a provider session that was already running no longer refreshes a full session (approval for
    #: another application), and a new session counts as confirmed from the provider's `auth_time`, not from
    #: the round. Without `auth_time` in the ID token a new session counts from TinySesam's own sign-in (the
    #: documented fallback), and the provider button does not confirm. `False` = the behaviour up to 0.25.x.
    oidc_reauth_check: bool = True
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
    #: Re-authentication at the SAML provider is checked (T-70, ASVS 5.0 6.8.4, SAML 2.0 Core §3.4.1, §2.7.2): the
    #: confirmation page offers "Confirm with <provider>" to an account bound to it, which sends the AuthnRequest with
    #: `ForceAuthn="true"` and confirms only with an `AuthnInstant` from after the request (60 s clock tolerance); a
    #: round through a provider session that was already running no longer refreshes a full session, and a new
    #: session counts as confirmed from the assertion's `AuthnInstant`, not from the round. An identity provider that
    #: ignores `ForceAuthn` answers with an old `AuthnInstant` and is caught the same way. `False` = the behaviour up to
    #: 0.31.x: every SAML round counts as a fresh confirmation.
    saml_reauth_check: bool = True
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
    # An IP address other than loopback gives a startup warning (T-37): HTTPS on it needs a
    # CA of your own on every device, and passkeys do not work on an IP — see
    # docs/HOME-NETWORK.md.
    base_url: str = ""
    login_path: str = "/auth/login"       # login page
    login_redirect: str = "/"             # target after a successful login
    logout_redirect: str = "/auth/login"  # target after logout

    # --- Hardening ---
    # Reverse proxies whose X-Forwarded-For may be trusted (otherwise the real client IP can be forged).
    # X-Forwarded-For is believed only from these peers — otherwise the client IP can be forged
    # (rate limit, lockout, fail2ban). IMPORTANT: start uvicorn with `--no-proxy-headers` (`proxy_headers=False`):
    # uvicorn applies X-Forwarded-For by DEFAULT, replaces `request.client.host` with the forwarded IP, and this
    # check comes to nothing. `python -m tinysesam.gateway` does so itself.
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
        # App passwords (T-66) are created on the account page: an application that takes them switches the page
        # on, unless the caller decided about it explicitly. (The page shows nothing else a gateway would hide —
        # sessions, recent activity, connected programs.)
        apps = base.get("forward_apps")
        if "account_enabled" not in overrides and isinstance(apps, dict) and any(
                isinstance(e, dict) and e.get("app_passwords") is True for e in apps.values()):
            base["account_enabled"] = True
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
        error, warnings = self._findings()
        return error + warnings

    def _findings(self) -> tuple[list[str], list[str]]:
        """(errors, warnings) kept apart — `validate()` returns both in one list, and from
        that one could no longer read what would have made the setup fail. `TinySesam.router()`
        needs exactly this distinction (B3-14)."""
        from .config_check import _t, check_config
        error, warnings = check_config(self)
        if self.cookie_samesite not in ("lax", "strict", "none"):
            error.append(_t(
                self, "cookie_samesite={value!r} — allowed are 'lax', 'strict', 'none' (lower case)",
                value=self.cookie_samesite))
        if self.cookie_samesite == "none" and not self.cookie_secure:
            error.append(_t(
                self, "cookie_samesite='none' without cookie_secure=True — the browser discards "
                "such a cookie"))
        if self.https_mode not in ("off", "warn", "force"):
            error.append(_t(
                self, "https_mode={value!r} — allowed are 'off', 'warn', 'force'",
                value=self.https_mode))
        if not isinstance(self.csp, str):
            error.append(_t(self, "csp must be a string, is {type}", type=type(self.csp).__name__))
        if not self.cookie_secure and self.https_mode == "force":
            error.append(_t(
                self, "https_mode='force' with cookie_secure=False — the session cookie would go "
                "out without the Secure flag"))
        return error, warnings

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
        chain = list(self.login_chain or [])
        return not (self.login_chain_strict and "pin" in _chain.factors(chain)
                    and "pin" not in _chain.first_step(chain))

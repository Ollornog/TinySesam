# Changelog

All notable changes. Format loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security — authlib floor 1.9.1, setuptools 84.2.1, log filter for CodeQL

- Lower bound `authlib>=1.9.1` (extras `oidc`, `gateway`, `all`; previously 1.6.12): The lowest permitted resolution
  pulled in a version with seven known vulnerabilities (CVE-2026-96760, CVE-2026-114614 to -114618, CVE-2026-114620;
  fixed in 1.8.0, 1.9.0 and 1.9.1). The nightly `audit` had therefore been red for days. `tests/test_packaging.py`
  pins the new floor.
- setuptools 84.2.1 in the gateway image (`deploy/gateway/requirements.txt`) and in the build tools
  (`.github/bau/requirements.txt`), GHSA-xmj3-9gf7-h52w.
- `security.fuer_log` additionally removes line breaks via `.replace("\n", "")`. This changes nothing in effect but is
  the form CodeQL recognises as a filter against log injection (#266, `deferred login`). New test: a line break in
  name or address does not produce a second line in the deferral line.

### Changed — repository language is English (T-29)

- Documentation (`API.md`, `KONFIGURATION.md`, `docs/BETRIEB.md`, `TODO.md`), this CHANGELOG (now with the English Keep a
  Changelog categories), the backlog, and the comments and docstrings of the library, the tests, the scripts and the
  deployment files are written in English. The German user interface stays available (`lang="de"`), the German
  READMEs and policy files stay under `i18n/`. Default language of the interface was already English.
- Not yet translated (runtime texts, tests depend on their wording): log lines, `ConfigError`/`StateError` messages,
  CLI output, the hints of `konfigpruefung.py`, the replacement texts of the deprecated aliases, SQL schema comments,
  and the German website texts.

### Changed — Python 3.13–3.15 (test kit 0.37.0)

- The matrix runs 3.13/3.14/3.15, `requires-python` is `>=3.13` (the last three stable Python series; 3.15.0 was released on 2026-10-09).
- CI: Where xmlsec has no wheel (3.15), lxml is built from source against the same libxml2 — otherwise SAML fails with "libxml2 library version mismatch". The nightly prerelease is now 3.16.

### Changed — Test kit 0.36.3: text fast path, text check, pins of the auto-merge template

- If a revision changes only text on the kit's allowlist (`*.md` in the root, `docs/`, `backlog/`,
  `changelog.d/`), `scripts/check.sh` runs only `tests/test_repo.py` (hygiene, links, anchors, frontmatter) instead of
  the full suite; the required checks still run and report green. Decision: `scripts/_nur_text.sh`, when in doubt the
  full suite.
- New check for dead links and anchors as well as broken frontmatter in Markdown.
- Dependabot no longer bumps `actions/create-github-app-token` here (`ignore`): The template owns the pin, it
  arrives with `repokit sync`. Before, every such PR never went green.
- Audit tools: certifi 2026.10.19 and uv 0.13.4 (PYSEC-2026-4320/-4321). The Dependabot PRs each bumped only one
  of the two, so the required check `audit` stayed red on every one.
- certifi 2026.10.19 in the gateway image as well (`deploy/gateway/requirements.txt`, PYSEC-2026-4320).

### Changed — Auto-merge with a GitHub App (kit 0.34.0)

- The auto-merge rebases stale Dependabot branches using an app token; merging is done with the app token,
  and the push starts the workflows on main by itself. In the `workflow_run` workflow, `tests/test_repo.py` allows exactly
  `actions/create-github-app-token` (by SHA) and `gh pr update-branch` in the job with write permission.

### Changed — Pages actions merge by themselves, acceptance after the merge (kit 0.32.0)

- `actions/configure-pages`, `upload-pages-artifact` and `deploy-pages` run only on main; there is no
  public probe for `deploy-pages`. Their updates now merge by themselves (`NACH_MERGE_ABGENOMMEN`),
  the follow-up run of `pages.yml` accepts them. If it fails, the old site stays online, and the red run
  is reported.

### Changed
- **The gateway lock list may carry a higher lower bound than the package** (`tests/test_repo.py`): Until now the test
  required equality between `deploy/gateway/requirements.in` and `pyproject.toml`. As a result, every uv PR from
  Dependabot stayed red (#159), because it bumps only `requirements.in`. Now the same packages apply, with no bound below
  that of the package. This way gateway updates merge by themselves, and the package's minimum version stays unchanged.
- **Dress rehearsal on every PR** (PO 2026-10-11, "automate everything without breaking anything"): The jobs
  `generalprobe*` in `release.yml` run the actions that so far ran only on the tag against throwaway targets on the
  runner (`.github/generalprobe/`). Login and push go to a local registry, the SBOM comes from the image pushed
  there, wheel and sdist go to a local package server, and only a probe file is attested.
  This way their updates merge by themselves too. `tests/test_repo.py` requires that every action of the tag runs in the same
  version in the rehearsal and that the rehearsal attestation never attests an artifact.
- **Auto-merge from the repokit template** (kit 0.30.2): The exception for this repo is now the rule for all
  repos. Merging happens as soon as every required workflow is green for exactly this head.
- **Dependabot merges everything the required checks accept, majors included** (PO 2026-10-11, deliberate exception for this
  repo). Only PRs with foreign commits, red required checks and actions that run only on the tag remain manual. Such a
  PR stays open and reaches the PO as a notification. The waiting period of three days stays.
- **`docker-compose` (deploy/forward-auth) is now accepted**: New step in the job `gate-caddy`. It resolves the
  compose file, pulls every image by tag and digest and checks the Caddyfile with exactly the Caddy from the
  compose file. This way these PRs merge by themselves too.
- **`gate-caddy` is a required check.** It was previously missing from the branch protection. A Dependabot PR for the
  `caddy-gate` image could therefore merge before the job had finished.

## [0.24.13] — 2026-10-11

**Who needs it:** everyone with `csp='strict'` (default). No API break, no new schema.
**Behavior change:** The CSP of the built-in pages carries `form-action`. Forms may now only submit to the own
site and to the targets from the own configuration, or be redirected there.

### Security
- **CSP: `form-action`** (DAST 2026-10-11, ZAP 10055-13 "Failure to Define Directive with No Fallback"): The directive
  does not fall back to `default-src` — an injected form was previously allowed to submit anywhere. Now
  `form-action 'self'` plus the targets TinySesam itself redirects to: `base_url`, the OIDC issuer and its
  logout endpoint (once loaded), the SAML IdP as well as `trusted_redirect_hosts` and client hosts as `name:*`
  (`safe_next` allows any port there). Only `'self'` would have broken, in Chrome, every redirect after submitting to a
  protected host (signing in with `next`, signing out at the provider, "Continue as …") — Chrome checks
  `form-action` there too, Firefox does not. Browser test `tests/test_csp_form_action.py`: A redirect to an
  allowed host arrives, a form to a foreign origin is blocked; two mutations red.

## [0.24.12] — 2026-10-11

**Who needs it:** apps with their own TinySesam behind a TinySesam gateway. No API break, no new schema;
without `cookie_prefix` everything stays as it was.

### Added
- **`cookie_prefix`** (default `tinysesam_`): Prefix of the cookies of this installation — session, CSRF, approval and the
  flow cookies of OIDC, SAML and passkey. For an app with its own TinySesam **behind** a TinySesam gateway:
  Its proxy templates strip every `tinysesam_*` cookie before the app (B-20), including its OIDC flow cookie — the
  return from the provider was rejected ("without matching flow cookie"), and one landed back at the login. With e.g.
  `cookie_prefix="myapp_"` its cookies get through. Explicitly set names and the gateway's cookies
  (`__Host-tinysesam_gate|link|linkflow`) stay. The config check rejects a broken prefix and a gateway
  (`forward_auth_enabled`) with a foreign prefix — the templates would otherwise no longer strip its session.
  Test `tests/test_cookie_praefix.py` plays through start → proxy rule from `Caddyfile.gate` → return.

### Changed
- **Lock list of the gateway image: Dependabot regenerates it completely (uv instead of pip).** New input
  `deploy/gateway/requirements.in` (= `dependencies` + extra `gateway` + setuptools, replaces `bau.in`), header with the
  `uv pip compile` command line. The pip ecosystem bumped the list line by line and did not carry over new transitive
  dependencies (#126). `tests/test_repo.py` keeps input and pyproject equal, checks the command line and that no
  folder belongs to pip AND uv at the same time; auto-merge accepts `uv`.
- Dependencies of the gateway image (fastapi 0.142.2, cryptography 50.0.2) and of the audit tools (uv 0.12.23 among others)
  bumped, hash lists regenerated. fastapi 0.142 newly needs `opentelemetry-api`; Dependabot's line update (#126)
  did not pick up the new dependency, image build and audit went red.

## [0.24.11] — 2026-10-10

**Who needs it:** gateways in `direct` mode. No API break, no new schema.
**Behavior change:** In `direct` mode, the "Signed out" page returns to the application by itself after 10 seconds.
Whoever wants to leave it standing sets `forward_logged_out_sec` to 0.

### Added

- **"Signed out" continues on** (`forward_logged_out_sec`, default 10, 0–300; gateway
  `TINYSESAM_FORWARD_LOGGED_OUT_SEC`):
  - After "sign out everywhere" the page stays that long, with a running-down bar, then it goes to the application.
    The gate forwards on to the provider, and a new sign-in begins there.
  - A `meta refresh` in the head, no script. The bar is pure CSS and is dropped under `prefers-reduced-motion`.
  - Applies on the app host (`/.tinysesam/after-logout`) and on the gateway (`/auth/gate/logged-out`), only in
    `direct` mode. In `page` mode the login page itself shows the sign-out.
  - Tests in `tests/test_gate_link.py` and `tests/test_logout_modi.py`. The mutations "never continue" and
    "continue in `page` mode too" are red.

## [0.24.10] — 2026-10-09

**Who needs it:** everyone who lifts the fail2ban ban of an IP after a successful sign-in. No API break.

### Added

- **`login ok … unban=ja|nein`** in the security log:
  - `ja` appears only if there is no failed attempt against a **different** account from this IP within the lockout window. Own
    typos beforehand do not interfere.
  - This way an attacker with an own account cannot lift their ban by signing in between two volleys.
  - Test in `tests/test_passwort_wiederholung.py`. The mutation "always ja" is red.

## [0.24.9] — 2026-10-09

**Who needs it:** everyone with password sign-in whose users have devices with an old password, and everyone with
background images. No API break, no new schema.
**Behavior change:** The same wrong password from the same IP to the same account now counts only once. Whoever wants the
old behavior sets `password_repeat_memory` to 0.

### Added

- **Repeated passwords count once** (`password_repeat_memory`, default 5; `password_repeat_window_sec`, default
  24 h; both adjustable in the panel):
  - A phone that keeps asking at regular intervals with the old password locks neither account nor IP, and fail2ban does not ban it.
  - The repetition gets the same 401 and appears as `login_repeat` in the audit and as `INFO repeated login …`
    in the security log.
  - Only 8 bytes of PBKDF2 (20,000 rounds, salt from a derived subkey) are remembered, in memory only.
  - Every other wrong password counts in full.
  - `tests/test_passwort_wiederholung.py`. The mutation without fingerprint is red (429 from the sixth attempt).
- **`INFO login ok user=… ip=… method=…`** in the security log for every complete sign-in.

### Changed

- **Background images brighter and there faster:**
  - New tokens `--ts-bild-staerke` (.6) and `--ts-bild-hell` (.8), the darkening is lighter.
  - The first image appears after 0.5 s instead of 3 s.
- The logger `tinysesam.security` now writes to the file from INFO instead of WARNING.

## [0.24.8] — 2026-10-09

**Who needs it:** everyone whose pages should get their own look. No API break, no new schema.
**Behavior change:** Without `brand_icon`, the built-in pages now carry a built-in favicon. Whoever wants none
sets `brand_icon="none"`.

### Added

- **Background images** (`brand_backgrounds`, `brand_background_seconds`, `brand_background_credit_text/_url`; gateway
  `TINYSESAM_BRAND_BACKGROUNDS…`):
  - Several images cross-fade slowly, with a very dark darkening layer over them. With "reduce motion" the
    first one stands still. A discreet source credit appears at the bottom right.
  - The images are in the nonce-protected page `<style>`, never in `style=`. The strict CSP stays in place and releases
    for images exactly the origins of the https addresses entered.
  - The configuration check (already in the constructor) rejects addresses with quotation marks, parentheses, backslash or
    spaces (CSS breakout), as well as `javascript:` and `//`.
  - In the gateway, foreign addresses are allowed only with `TINYSESAM_BRAND_BACKGROUNDS_EXTERN=1`, otherwise startup aborts.
  - `tests/test_hintergrund.py`. Two mutations are red: without character check and without CSP extension.
- **Built-in favicon:** a plain key as a `data:` URI that switches between light and dark. Without a
  favicon the browser requests `/favicon.ico`, which in front of a gate is a protected path.

## [0.24.7] — 2026-10-08

**Who needs it:** gateways in front of several applications of a company or brand. No API break, no new schema. Without
the new setting nobody sees anything new.

### Added

- **Brand in front of the applications** (`gate_brand`, in the gateway `TINYSESAM_GATE_BRAND`): If set, the
  login page is titled "Sign in to <brand>" and names the application below it ("App: <name>", from `forward_apps`). Without a brand
  it stays at "Sign in to <application>". `tests/test_gate_marke.py` covers both cases, the application without a name and
  the escaping (mutation: brand ignored → red).
  With a brand the page title is "<brand> Login".
- **Favicon in the gateway** (`TINYSESAM_BRAND_ICON` → `brand_icon`, so it applies to all built-in pages). Only
  values from the own origin are allowed: a path `/…` or a `data:image/…` URI. A foreign URL, `//…`, `javascript:` or
  `data:text/…` aborts startup, because otherwise every visitor of the login page would contact third parties. Tested,
  the mutation without the check is red.

### Changed

- **CI: `release.yml` does not load buildx from the Actions cache** (`cache-binary: false` on
  `setup-buildx-action`, zizmor `cache-poisoning`, hardening baseline M6/B1). PR runs fill the cache too;
  in the workflow that publishes, the tool should not come from it.
  `tests/test_repo.py` requires the setting (mutation: line removed → red). No release needed.

## [0.24.6] — 2026-10-08

**Who needs it:** everyone with the built-in pages. No API break, no new schema. **Whoever has custom CSS**
(`brand_css`) and styled `.err`, `.ok` or the gray hint line of the login page there: These messages
are now `.meldungen > .meldung.{info|ok|warn|fehler}`.

### Changed

- **Messages as separate boxes below the card, each with an icon.** Until now every page put its message into the
  card itself: errors as a red line (`class=err`), success as `class=ok`, the hint after signing out as a gray line.
  Now there are four kinds: hint ⓘ, success ✓, warning ⚠ and error ⊗. Each is a separate box below the card,
  equally wide, with `role=status` or `role=alert`. The icons are inline SVG in `currentColor` (nothing is
  loaded), the colors come from the existing tokens `--ts-{info,ok,warn,err}-*`. Converted are sign-in,
  TOTP, registration, login link, forgot and reset password, step-up, PIN, resource unlock and "Link
  invalid". The admin panel (wide layout without card) keeps its warning bar.
- `_page`/`_doc` have a slot below the card (`unten`).

## [0.24.5] — 2026-10-08

**Who needs it:** operators of the central gateway with login mode `page`. No API break, no new schema.

### Changed

- **After signing out, straight to the login page** with the hint "You have been signed out." instead of an intermediate page
  "Signed out → Sign in again" whose only button led exactly there. This applies to the return from the provider
  (`/.tinysesam/after-logout`) and to `/auth/gate/logged-out`, in the code exchange with login mode `page`. The
  hint travels along in the flow (`/.tinysesam/start?abgemeldet=1` → login page). In `direct` mode the
  "Signed out" page remains, because there would be no login page of its own there.
- The login page can show a hint without error character (`info`).

## [0.24.4] — 2026-10-08

**Who needs it:** operators of the central gateway with login mode `page`. No API break.

### Changed

- **The login page in the code exchange shows the app** ("Sign in to <app>" instead of the installation name): The
  path from the gateway to the sign-in now carries `gate_host`, the name is supplied by `forward_apps`.

## [0.24.3] — 2026-10-08

**Who needs it:** operators of the central gateway with app hosts that are also reachable bypassing it (e.g. directly
in the VPN). No API break, no new schema.

### Added

- **`/auth/gate/logged-out?host=…`** on the gateway: "Signed out" with "Sign in again" to exactly this app. For
  paths on which the app host has no TinySesam in front of it. There the app's proxy can pass `/.tinysesam/logout`
  on to the gateway and ends up here.
- **`TINYSESAM_OIDC_NAME`** in the gateway: label of the sign-in button (default "SSO").

### Changed

- Signing out at the gateway without a session (`/auth/gate/logout`) now leads to this page instead of to
  `/.tinysesam/after-logout` of the app host, which a path bypassing the gate does not know.
- **CI: every job with `timeout-minutes`** (measured maximum duration × ~3, e.g. `repeat` 30, `full` 15, `image` 30)
  and `apt-get` with `Acquire::Retries=3` and `Acquire::http::Timeout=30`. Before, GitHub's default of 360 min applied,
  and a hanging Ubuntu mirror blocked PR #135. `tests/test_repo.py` requires the limit in all 20 jobs.

## [0.24.2] — 2026-10-07

**Who needs it:** operators of the gateway (`tinysesam.gateway`). No API break, no new schema.

### Added

- **Start page of the gateway:** `/` shows signed-in users "Signed in as …" with sign-out (POST, CSRF), otherwise it goes
  to the sign-in. Until now the gateway's address answered with `{"detail":"Not Found"}` in the browser.
  New page `gateway_home` (replaceable via `set_template`).
- **Error pages in the gateway:** Browsers get the error page in the branding (`install_error_pages`), API clients
  still get JSON.

### Changed

- Instead of Starlette's English default text ("Not Found"), error pages show the text of the configured language,
  where there is one (`error.404`, `error.405`). Custom messages stay unchanged.

## [0.24.1] — 2026-10-07

**Who needs it:** everyone who runs 0.24.0 as a central gateway (`gate_link_enabled`). No API break,
no new schema.

First operation of the central gateway (0.24.0) in the browser over the public path — three findings.

### Fixed

- **Signing out "everywhere" left the session on the gateway in place** if the app had already been signed out "only here"
  beforehand: Without a link, the app host did not know the session. Now it forwards to
  `/auth/gate/logout?host=…` on the gateway, where it ends (with provider logout). From a foreign site,
  the confirmation prompt comes first on the app host (logout CSRF); without a session, also at the gateway back to
  `after-logout` instead of in circles.
- **False alarm at startup:** "Forward auth without cookie_domain … separate sign-in per host" also appeared with
  `gate_link_enabled`, where host-only is intended.

### Added

- **`TINYSESAM_LANG`** (`en`, `de`) in the gateway — until now its pages were always English. Unknown values
  are a startup error.

## [0.24.0] — 2026-10-07

**No break** of the public API — an extension: a central gateway for many apps, without the
session ever reaching an app.

**What stands out on update:**

- **Schema 14:** The first start creates the table `gate_link`. An older version opens the file with the
  warning "newer schema version" and leaves the table in place.
- Without `gate_link_enabled` nothing changes.

### Added — Central gateway with code exchange (T-26)

- **`gate_link_enabled`** (gateway: `TINYSESAM_GATE_LINK=1`): One TinySesam protects many app hosts without
  the session cookie being on the parent domain. An app host gets only its own link cookie (`__Host-tinysesam_link`) via `/.tinysesam/start` →
  `/auth/gate/authorize` → `/.tinysesam/callback`,
  valid exclusively for it. The one-time code is valid for 120 s, exactly once, only for its host and only in
  the browser that began the flow (binding cookie). `rd` accepts only paths of the app host.
- `/auth/forward`, sign-out (`/.tinysesam/logout`, `after-logout`) and "Continue as …" understand the
  link; signing out "everywhere" at one app ends the session at the gateway. "Sign out only here" releases the
  link and lets the next exchange run via "Continue as …".
- Configuration check: not together with `cookie_domain`, not without gate token and `base_url`.
- **Schema 14:** table `gate_link` (additive).

## [0.23.0] — 2026-10-07

**No break** of the public API — extensions only (`tests/api_surface.json`). New is the gate in front of
third-party applications ([M-3](backlog/M-3-gate-vor-fremden-apps.md)): gate token, login and logout modes,
share exceptions, measurement and acceptance.

**What stands out on update:**

- **Schema 13:** The first start creates two tables (`gate_abgemeldet`, `oidc_id_token`). An older
  version then opens the file with the warning "newer schema version" and leaves both in place.
- **Gateway (`oidc_gateway()`, image):** Whoever is not signed in now goes **directly
  to the provider** when requesting a page (`forward_login="direct"`), instead of first seeing the login page. Back to the previous
  behavior: `TINYSESAM_FORWARD_LOGIN=page`.
- **Gateway:** `oidc_rp_logout` is now on — signing out also ends the session at the provider, with
  `id_token_hint`. For the return at the provider, enter `https://<app>/.tinysesam/after-logout` as the Logout
  Callback URL (`docs/BETRIEB.md`, checklist).
- **Several OIDC clients:** A session without approval for an application now goes to the provider instead of
  into a loop (B-2) — whoever worked around this so far can remove the detour.
- The Caddy templates pass `/.tinysesam/*` to TinySesam and have a (switched-off)
  share block. Whoever maintains their own version: adopt both blocks, otherwise signing out at the
  application leads nowhere.

### Added — Measurement and acceptance of the gate (T-24)

- `scripts/gate_messung.py` (with `hey`): With 20 simultaneous requests, the path via
  `/auth/forward` manages about 3,200 requests per second at 6 ms median, the gate token about 40,000 at 0.4 ms.
  Result and setup in `docs/BETRIEB.md`.
- `deploy/forward-auth/abnahme.sh`: acceptance of a real deployment from the outside (sign-in,
  remote user, `/.tinysesam/*`, share path and path tricks, gate token, sign-out). The Caddy test runs
  it against the test setup.

### Added — Configuration check for gate operation (T-23)

Warnings, startup succeeds: `gate_token_ttl_sec` above 900 (revocation delay); gate without a protected
host (no token would be issued); `forward_apps` without forward auth; `forward_login="direct"` with sign-out
`all`/`ask`, but without `oidc_rp_logout` — the next page request would silently sign in again.

### Added — Share exceptions in the Caddy templates (T-20)

- Block `@share` in `Caddyfile` and `Caddyfile.gate`: public paths (share links) without
  sign-in, without identity, without TinySesam cookies. Off until `TS_SHARE_PRAEFIX` is set.
- The **raw** path is checked: With Caddy's `path` matcher, `/s/..;/admin` got through (Tomcat/Spring:
  `/admin`), and `/x/../s/a` was compared as `/s/a` but passed on raw. The rule rejects `.`-
  and `..` segments, `;`, backslash, NUL and their encoded forms; `tests/test_gate_caddy.py`
  measures 16 such paths against Caddy.
- On this path, the normal template also strips the browser's `Remote-*` headers.

### Added — Signing out at the application (T-22)

- **`/.tinysesam/logout`** on the application's host (both Caddy templates pass `/.tinysesam/*` past the
  gate to TinySesam). **`forward_logout`** (default `all`) or `forward_apps[host].logout`,
  overridable in the link with `?scope=app|all`:
  - `all` ends the session and, with `oidc_rp_logout`, the one at the provider. Back via
    `/.tinysesam/after-logout` (enter at the provider as Logout Callback URL), a "Signed out"
    page.
  - `app` ends only this application: The session stays, the host lets it through again only after "Continue as …"
    on the login page (`POST /auth/gate/resume`) or a new sign-in.
  - `ask` asks.
  From a foreign site (`Sec-Fetch-Site: cross-site`) the user is asked first, as with `/auth/logout`.
- **`id_token_hint` on logout at the provider.** TinySesam stores the sign-in's ID token encrypted
  and sends it along — together with the `client_id` of the client through which the sign-in ran. PocketID does not end
  its session without the hint, but stops at a confirmation prompt. Also applies to
  `/auth/logout`.
- `oidc_gateway()` now sets `oidc_rp_logout=True`. Gateway: `TINYSESAM_FORWARD_LOGOUT`, `logout` in
  `TINYSESAM_FORWARD_APPS`.
- New pages `gate_logout` and `gate_logged_out` (replaceable via `set_template`).
- **Schema 13:** tables `gate_abgemeldet` and `oidc_id_token`, additive. An older version opens the
  file with the warning "newer schema version" and leaves both tables in place.

### Added — Login modes in front of the gate (T-21)

- **`forward_login`**: `"page"` (library default) sends someone not signed in to the
  login page, `"direct"` sends a page request straight to the identity provider and back to the
  requested address. **`oidc_gateway()` sets `"direct"`** (PO decision 2026-10-03). A page request is recognized
  by `Sec-Fetch-Mode: navigate` (otherwise `Accept: text/html`); background requests
  continue to the login page and thus do not begin an OIDC flow of their own. `direct` requires OIDC as the
  only method, otherwise startup aborts.
- **`forward_apps`** per host: `name` (login page "Sign in to Wiki") and `login` (overrides
  `forward_login`). An unknown key or value aborts startup. Gateway:
  `TINYSESAM_FORWARD_LOGIN`, `TINYSESAM_FORWARD_APPS` (JSON).

### Fixed

- **B-2 — endless loop with several OIDC clients.** If someone was signed in but had no (valid) approval
  for THIS application, `/auth/forward` sent them to the login page, and that sent
  them — signed in — back to the application. In addition, the login page's OIDC button lost the parameter
  `app=`, the round ran via the default client, and the approval for the application never came into being. Now:
  The re-check leads directly to `/auth/oidc/start?app=…`, the login page sends a session without
  approval to the provider instead of back, the button carries `app=`, and `/auth/oidc/start` without `app` takes the
  client for the host of `next`.

### Added — Gate token: the proxy checks by itself ([ADR-9](backlog/ADR-9-gate-token-am-proxy.md), T-19)

- **`gate_token_enabled`** (default off; gateway: `TINYSESAM_GATE=1`): A successful check on
  `/auth/forward` additionally returns the header `X-TinySesam-Gate-Cookie` with a short-lived token
  signed with Ed25519. The proxy sets it as cookie `__Host-tinysesam_gate` on the application's host and
  then checks it itself — measured through a real Caddy: ten asset requests,
  zero calls to TinySesam. If the token is missing or expired, the previous path via
  `/auth/forward` applies, with the request's method and body preserved.
- Issued only for a full session (no API key), only for protected hosts
  (`trusted_redirect_hosts`, `oidc_clients`, `base_url`) and only after a passed check. Required
  roles are in the target group (`app.example.com|roles=admin`), a token without role information does not apply
  on a path with roles. The claims follow `forward_headers`.
- **No second secret:** The signing key is derived via HKDF from the installation's base key
  (`TINYSESAM_SECRETS_KEY` or `<db>.key`). New: `tinysesam gate-key --db …`
  prints the public key for the proxy; `auth.gate_public_key()` and `auth.gate_issuer()`
  (tier B) provide the same in code.
- New fields `gate_token_ttl_sec` (default 300, allowed 30–3600 — that is how long a revocation does not take effect
  at the proxy) and `gate_cookie_name` (form `__Host-tinysesam_<name>`, otherwise startup aborts).
  Gateway: `TINYSESAM_GATE_TTL_SEC`.
- Template `deploy/forward-auth/Caddyfile.gate`, build of a Caddy with the plugin caddy-jwt in
  `deploy/forward-auth/caddy-gate/Dockerfile` (version and digest pinned, Dependabot bumps the
  image). New CI job `gate-caddy` builds exactly this image and runs `tests/test_gate_caddy.py`
  against it.

### Changed — CI and release (for developers; nothing changes in the package)

- E2E stage: OIDC green again (T-25). The test account now belongs at the provider to a group that is approved only for
  the stage's client. On a freshly built stage all three paths run green; without the
  approval OIDC goes red.
- `tests/test_vorbuchung_schwebe.py` no longer waits a fixed time until the parallel sign-ins
  have arrived in the pending directory, but for the state itself (T-18). The suite was once
  red under load, the cause presumably exactly these wait points.
- **The number of parallel test jobs comes from the runner, not from detection.** `tests/run_all.py`
  took half of `os.cpu_count()` without `CI_TEST_JOBS`. In a container that reports all cores of the
  host, not the CPU quota: A runner with two cores on a host with twelve started six
  jobs. Now `CI_TEST_JOBS` (by hand) applies, otherwise `CI_KERNE` (set by the CI runner), otherwise 2. An
  invalid value in either of the two variables aborts. For this, `tests/test_repo.py` calls the
  kit check `pruefe_parallel_worker` (kit 0.27.1).
- `tests/test_testlauf.py` now checks that every suite has its own throwaway directory
  (TMPDIR, HOME, XDG_*) and that it is deleted afterwards. Until now nothing guarded that: a
  shared, never-deleted directory for all suites stayed green.
- **After a Dependabot auto-merge, CI runs on main.** With `gh pr merge --auto`, GitHub merged
  on behalf of the workflow token, and such a merge starts no workflow. After #114, neither CI nor audit, CodeQL or Pages ran on
  main. Now `dependabot-auto-merge.yml` starts via
  `workflow_run` as soon as a required workflow has finished. It waits with a deadline until GitHub reports the PR
  as mergeable, merges itself (without `--auto`, with `--match-head-commit`) and then triggers
  `ci.yml`, `audit.yml`, `codeql.yml` and `pages.yml` via `workflow_dispatch`. If a
  required check is red, the PR gets a comment instead of silently hanging.
- `tests/test_repo.py`:
  - The trigger must name exactly the required workflows, and exactly what a push to main would start is
    triggered.
  - `workflow_run` is allowed, but only without any action. Scorecard objects to it anyway only in
    combination with a checkout of the PR code.
  - 10 mutations red.
- **CodeQL is a required check** (`CodeQL (python)` and the result `CodeQL`), so codeql-action updates
  merge by themselves too. The parts of an action (`github/codeql-action/init` and
  `/analyze`) are now bumped together by Dependabot: Bumped individually they ran in different versions,
  and CodeQL aborted (#110/#111). `tests/test_repo.py` requires a shared group for every
  action with several subpaths and checks that every workflow in `PFLICHT_WORKFLOWS` runs on every
  PR.
- **Dependabot no longer bumps `pydantic-core` on its own.** pydantic pins it exactly; a
  single bump broke `pip check` in the image build and in the audit (#81, #112). The new required checks
  stopped the auto-merge of #112, as intended.
- **Dependabot updates merge by themselves if a required check accepts them** (patch and minor,
  after a 3-day waiting period). Majors and everything no required check examines remain manual; the PR
  then gets a comment saying why. Automatic are `pip` (build tools, gateway lock list,
  audit tools), `docker` (base image) and only the actions that run in a required workflow
  on the PR. Login, attestation, SBOM and PyPI upload run only on the tag and therefore
  remain manual, as does the compose example.
  `.github/workflows/dependabot-auto-merge.yml` has two jobs: The check logic runs without
  write permission. The job with write permission calls only `gh pr merge --auto --match-head-commit` or
  `gh pr comment`. `tests/test_repo.py` allows exactly these two commands, not `gh pr`
  across the board. The positive list now compares up to three words.
- **The release dry run runs on every pull request.** Until now no required check accepted the pinned
  build tools (`.github/bau`), the image's lock list (`deploy/gateway`), the
  base image in the `Dockerfile` and the build's actions. An update that breaks the sdist or the
  image was noticed only at the next tag. Now every PR builds wheel, sdist and the image
  for both platforms, but publishes nothing. The PR skips the suite in `pruefen`
  because `ci.yml` runs it on the same commit.
- **New `abbild-probe`:** The image must start before it is pushed. `scripts/_abbild_probe.sh`
  builds it, starts it without network and with placeholder values, waits for the HEALTHCHECK from the
  `Dockerfile` and requires `/healthz` 200 with the version from `pyproject.toml`. The job has no
  write permission; `image` depends on it.
- **New `pruefsummen`:** Wheel and sdist are downloaded the way `release` and `pypi` receive them,
  and checked with `sha256sum -c` against `SHA256SUMS`. `release` depends on it.
- The dry run from a branch whose name contains a slash (and from every PR:
  `108/merge`) previously aborted at the image tag. Outside a tag the image is now called
  `trockenlauf`; it is never pushed anyway.
- `tests/test_repo.py` pins down all points.

### Changed — Test run (for developers; nothing changes in the package)

- **Under `FAIL` every failed check is listed.** `tests/run_all.py` showed of a red
  suite only the last 2000 characters. If an early check failed, its `FEHL` line was missing from the
  log, as seen in the CI job `repeat`. Now all `FEHL` lines are listed up front above the
  excerpt, and the excerpt begins at a line boundary.
- **The suites run in parallel.** `tests/run_all.py` runs them simultaneously; how many
  is set by `CI_TEST_JOBS` (default: half the cores, at least one; a value
  other than an integer ≥ 1 aborts with exit 2). The first line names the number
  (`▸ Test-Jobs: N`), the log still follows the order of the files, and
  `CI_TEST_JOBS=1` is the serial run of before. Measured on 12 threads (6 jobs, without
  browser test): full run 237 s → 40 s, slim run (without extras) 466 s → 42 s; serial with
  the cheap hashes 179 s and 177 s respectively.
- **Cheap password hashes only in the test run.** The collective run starts every suite via
  `tests/_starter.py`, which lowers scrypt and argon2 **in the test process**. In the slim run,
  about two thirds of the suite time previously went into scrypt. The package has **no** switch for this —
  no environment variable, no setting; `tests/test_testlauf.py` pins that down. Suites that check
  hash parameters or runtimes themselves keep computing with the real values, as does every
  directly started suite.
- **No suite writes into the tree or shares anything with another one anymore:** mypy puts
  its cache into the suite's sandbox (before: `.mypy_cache/` in the tree), `scripts/check.sh` builds
  the website into a throwaway directory (before: `_site/`, which was deleted afterwards — including an
  own one), `tests/test_ratelimit.py` no longer talks to a real Redis on `localhost:6379`, and
  `tests/test_ldap.py` keeps its "dead" port occupied until the probe is finished.
- **A check that went red under load:** `tests/test_werte_englisch.py` compared the order
  of `list_api_keys` (sorted by seconds) — if the keys were created in two different seconds,
  it was red although every kind was right. Now per key via its name.

## [0.22.0] — 2026-09-27

> **Breaks the interface — read before updating.** German names, parameters, keys and values
> of tiers A and B are now English, **without alias**; internal names (tier C) warn; `POST
> /auth/password` no longer accepts an API key. Schema 12 (stored key kinds in English) — **back up the database
> before updating**; going back to 0.21.x needs the SQL from `docs/BETRIEB.md`.
> Whoever uses TinySesam only via the documented tier A paths (router, guards, `create_user`,
> configuration) will not notice any of this — cross-checked with three consumers.

**Classification of the public API (tiers A/B/C) — plus the secure login building block
(`login_password`, `login_pin`, `login_totp`) for custom login pages and the same building blocks for
custom step-up and password-change pages (`confirm_password`, `confirm_pin`, `confirm_totp`,
`change_password`); the internal names (tier C) warn and are dropped with 1.0, the German
names of tiers A and B are now English (without alias) — likewise their keys and values, including the
stored ones (schema 12); the lock by the operator has a public method
(`auth.set_disabled`), `auth.store` is internals without a promise. And two findings from operation: the
first-admin token no longer appears in the log in the container, a group rule without scope `groups` is
reported.** What stands out on update:

- **The public API has tiers** (PO decision 2026-09-26): **A** public and stable from
  1.0, **B** for advanced users (building blocks for custom account and admin pages), **C** internal.
  Only A carries the promise from M-1 — two minor versions without a break, counted from this release. B
  stays, but is reworked or removed after a `DeprecationWarning` has pointed to it for two
  minor versions. C is not part of the promise and is dropped with 1.0.
  **Whoever embeds TinySesam checks `API.md` for the tier of their calls** — there
  every name now stands under its tier, the C names as a table with their replacement (including
  `check_password`, `check_pin`, `verify_totp`, `record_login`, `is_locked`, `sec`). The READMEs
  explain the tiers ("Public API: three tiers" / "Öffentliche API: drei Stufen").
- **German names of tiers A and B are now English — without alias** (PO decision 2026-09-27).
  Methods, constants, parameters and the attributes of `ConfigError` are renamed, like the rest
  of the tier A interface. **There is no alias:** The promises of the tiers begin only with
  this release, and none of the consumers we know uses any of the old names. Whoever calls one
  of them gets an `AttributeError` or, for a keyword parameter, a
  `TypeError` — **switch over according to the table**; positional calls with a renamed parameter
  keep working. No configuration field is affected (those were already English), nor
  is any database column.

  | up to 0.21.x | from 0.22.0 | Tier |
  |---|---|---|
  | `foederation_nachbinden(quelle, *, zuordnung=None, ausfuehren=False)` | `federation_bind_existing(source, *, mapping=None, apply=False)` | A |
  | `loese_fremde_bindung(quelle, user_id)` | `federation_unbind(source, user_id)` | A |
  | `SICHERHEITSEREIGNISSE` | `SECURITY_EVENTS` | A |
  | `change_username(user_id, neu, ip=None, *, durch_betreiber=False)` | `change_username(user_id, new_username, ip=None, *, by_operator=False)` | A |
  | `create_user(…, *, name_selbst_gewaehlt=False)` | `create_user(…, *, self_chosen_name=False)` | A |
  | `public_base(request=None, kandidat="")` | `public_base(request=None, candidate="")` | A |
  | `ConfigError.feld`, `ConfigError.besitzer_id` | `ConfigError.field`, `ConfigError.owner_id` | A |
  | `MissingExtra(nachricht, extra="")` | `MissingExtra(message, extra="")` | A |
  | `andere_sitzungen(request, user, token=None)` | `count_other_sessions(request, user, token=None)` | B |
  | `api_key_art(key)` | `api_key_kind(key)` | B |
  | `darf_mfa_einrichten(user_id, jetzt=None)` | `mfa_enrollment_allowed(user_id, now=None)` | B |
  | `kennung_vergeben(kennung, exclude_id=None)` | `identifier_taken(identifier, exclude_id=None)` | B |
  | `nach_der_antwort(resp, auftrag, bei_ueberlauf=None)` | `after_response(resp, task, on_overflow=None)` | B |
  | `nur_foederiert(user_id)` | `federated_only(user_id)` | B |
  | `passwort_mangel(password, *, …)` | `password_policy_error(password, *, …)` | B |
  | `pfad(request, pfad)` | `browser_path(request, path)` | B |
  | `sperre_aufheben(user_id, methoden=None)` | `lift_lockout(user_id, methods=None)` | B |
  | `apply_factor(…, email_bestaetigt=None)` | `apply_factor(…, email_verified=None)` | B |
  | `flow_cookie_name(basis)` | `flow_cookie_name(base)` | B |
  | `request_email_change(user_id, neu, base_url)` | `request_email_change(user_id, new_email, base_url)` | B |
  | `require_public_base(request=None, kandidat="")` | `require_public_base(request=None, candidate="")` | B |
  | `FOEDERIERTE_QUELLEN` | `FEDERATED_SOURCES` | B |
  | `MFA_ENROLLMENT_ARTEN` | `MFA_ENROLLMENT_MODES` | B |
  | `NACHBINDUNG_GRUENDE` | `NAME_BINDING_REFUSALS` | B |
  | `SEITEN` | `PAGES` | B |
  | `TinySesamConfig.pin_als_erstfaktor()` | `TinySesamConfig.pin_as_first_factor()` | B |
  | `TinySesamConfig.pruefen()` | `TinySesamConfig.validate()` | B |

  The keys and values that these names return or accept have been English since the second
  PO decision of the same day as well — next item. Audit events and their details
  (`ldap_kennung_gebunden`, `durch=betreiber`), the lines for fail2ban and all columns of the
  database stay. Only log lines that name a call have changed: the hints to
  `auth.federation_unbind(…)`, `auth.federation_bind_existing(…, mapping=…)` and
  `auth.change_username(…, by_operator=True)`, and the summary line of the existing-account binding in the
  security log begins with `federation_bind_existing(<quelle>)`.
- **The keys and values are English too — without alias, and the database follows**
  (PO decision 2026-09-27, "translate everything, DB values too"): what tiers A and B
  return or accept, what goes to `on_security_event`, the context of custom pages and the
  JSON responses of the routes. **Whoever reads one of these keys or compares one of the values
  switches over according to the table** — an old key is a `KeyError`, an old value compares
  silently unequal; `create_api_key(kind="automat"|"mensch")` and `POST /auth/apikeys` with an old
  `kind` are an input error (`ConfigError` or 400), whose text names the new name.

  | Where | up to 0.21.x | from 0.22.0 |
  |---|---|---|
  | `federation_bind_existing()` — report | `quelle`, `ausgefuehrt`, `gebunden`, `konflikt`, `mehrdeutig`, `nicht_im_verzeichnis`, `ohne_kennung`, `abgewiesen`, `lokal` | `source`, `applied`, `bound`, `conflict`, `ambiguous`, `not_in_directory`, `no_identifier`, `refused`, `local_password` |
  | … per entry | `lokal`, `verzeichnis`, `kennung`, `grund`, `gebunden_an`, `treffer` | `local`, `directory`, `identifier`, `reason`, `bound_to`, `matches` |
  | … reasons (`reason`) outside of `NAME_BINDING_REFUSALS` | `kein_konto`, `dienstkonto`, `gesperrt`, `schon_gebunden` | `no_account`, `service_account`, `disabled`, `already_bound` |
  | `NAME_BINDING_REFUSALS` — keys (the explanations now in English) | `adresse_als_name`, `kennung_ungueltig`, `konflikt`, `anders_gebunden`, `name_selbst_gewaehlt`, `name_aus_quelle`, `frist` | `address_as_name`, `invalid_identifier`, `conflict`, `bound_elsewhere`, `self_chosen_name`, `name_from_other_source`, `binding_window_expired` |
  | `gc()` | `fehlserien` | `failure_series` |
  | `create_api_key()`, `POST /auth/apikeys` | `verworfene_rollen` | `dropped_roles` |
  | Kind of an API key: `create_api_key(kind=…)` (also the default), `api_key_kind()`, `list_api_keys()`, `GET /auth/apikeys`, `GET <admin_path>/api/users/{id}/keys` | `automat`, `mensch` | `automation`, `human` |
  | `current_user()` via an API key | `_key_art` | `_key_kind` |
  | `confirm_email_change()` | `"vergeben"` | `"taken"` |
  | `peek_magic()`/`redeem_magic()` of an address-change link — `payload` | `alt` | `old` |
  | `on_security_event`: `username_changed`, `email_changed` | `alt`, `neu` | `old`, `new` |
  | … `recovery_code_used` | `verbleibend` | `remaining` |
  | … `recovery_codes_generated` | `anzahl` | `count` |
  | … `totp_disabled` | `recovery_codes_geloescht` | `recovery_codes_deleted` |
  | … `api_keys_revoked` | `anzahl`, `grund`: `sperre`, `admin_passwort`, `passwort_reset`, `sitzungen_beendet` | `count`, `reason`: `account_disabled`, `admin_password_reset`, `password_reset`, `sessions_revoked` |
  | Context of custom pages (`set_template`) | `ctx["praefix"]`; `ctx["zweck"]` (page `magic_confirm`) | `ctx["prefix"]`; `ctx["purpose"]` |

  The event names (`SECURITY_EVENTS`), the remaining reasons (`LoginResult.REASONS` …), the
  page names (`PAGES`) and the keys of the other JSON responses were already English.
  `own_events()` still names the names of the audit events (including German ones such as
  `ldap_kennung_gebunden`) — those are audit values, and they stay.

  **Stored values, schema 12.** Two of them are in the database: the kind of each API key
  (`api_key.kind`) and, in the open address-change link, the previous address (`magic_token.payload`).
  The first start of 0.22.0 rewrites them, raises the stamp to 12 and says so in the log (`…
  gespeicherte Werte auf die englischen Namen umgeschrieben`); no column changes. An old value
  is still read correctly (a `mensch` key counts as `human`, i.e. only with a session),
  and every start catches up keys that an older version has issued in the meantime.
  **Going back to 0.21.x** (measured with 0.21.0): It opens the file and warns at startup
  ("Die Datenbank trägt Schema-Version 12, diese TinySesam-Fassung kennt nur 11 …"), but treats a
  `human` key as an automation key — **there it works without a session**, with the rights of the
  account without admin flag. Before starting a 0.21.x version, therefore run the SQL from `docs/BETRIEB.md`
  ("Rückschritt auf 0.21.x"): `UPDATE api_key SET kind='mensch' WHERE kind='human'` etc.,
  then set the stamp back to 11.

  **Audit and log lines stay as they were** — operators' filters depend on them. They
  still contain the old names: `apikey_create`/`apikey_use` `art=automat|mensch`,
  `<quelle>_namensbindung_zu grund=<abbreviation up to 0.21.x>` (e.g. `grund=name_aus_quelle`),
  `totp_disable … recovery_codes_geloescht=`, `recovery_used … verbleibend=`, the lines in the
  security log (`API-Key der Art 'mensch' ohne passende Sitzung …`, the reason for a name binding
  that was not made). Whoever infers an audit line from an interface value
  therefore still reads the old spelling there.
- **Account dicts carry only the account's fields now.** `get_user`, `find_user`,
  `identifier_taken`, `current_user`, `session_user`, `pending_user`, `verify_api_key`,
  `LoginResult.user` and the `require_*` guards return `id`, `username`, `display_name`, `email`,
  `email_verified`, `is_admin`, `is_owner`, `roles`, `is_service`, `disabled`, `first_login_at`,
  `mfa_enroll_until`, `created_at` (plus `_via`, `_key_kind` depending on the path). Up to 0.21.x the whole
  database row went out, including the store's bookkeeping under German column names (`topf_name`,
  `topf_mail`, `name_quelle`, `name_selbst_gewaehlt`, `idp_bestaetigt_at`, `name_versuch_ab`,
  `mail_versuch_ab`, `name_audit_ab`, `mail_audit_ab`) — internals that should carry no promise.
  `verify_api_key` now returns a dict instead of a `sqlite3.Row` as the account, `list_api_keys`
  a list of dicts (columns of `api_key`, `kind` in English).
- **An operator locks an account in code with `auth.set_disabled(user_id, True)`** (new, tier A,
  PO decision 2026-09-27) — same effect as "Lock" in the panel, which calls the method:
  operator note, end sessions, revoke API keys, discard open one-time tokens, audit.
  Up to 0.21.x `docs/BETRIEB.md` showed `auth.store.set_disabled(uid, True,
  durch_betreiber=True)` for this — **that set only the note**; sessions, keys and links stayed valid.
  Whoever adopted that switches over. **`auth.store` is internals** (tier C): no tier,
  no promise, no transition period. Where the docs still name a call (the write probe for a
  custom health check, `drop_oidc_grants_for_user`, `backup` from Python), it says so there. The
  panel now answers `POST <admin_path>/api/users/{id}/disable` for an account that does not exist
  with 404 instead of 200 (before: "ok" plus audit line, without anything happening).
- **The internal names (tier C) warn.** 42 methods and 7 constants are now internally called `_name`
  (`check_password` → `_check_password`, `record_login` → `_record_login` …, list under
  "Deprecated"), `complete_mfa` is an alias of `complete_totp`. The old name does the same as
  before until 1.0, but triggers a `DeprecationWarning` with the replacement on every call (constants: on read).
  Python does not show it outside `__main__` — **whoever embeds TinySesam runs
  their tests once with `python -W error::DeprecationWarning`**. A subclass of
  `TinySesam` that overrides one of these names gets a `RuntimeWarning` on definition:
  The built-in routes now call `_name`, the override no longer takes effect.
- **Test fakes on an old name no longer take effect.** `auth.check_password = fake` or
  `mock.patch.object(auth, "rate_ok", …)` replaced what the built-in routes called up to 0.21.x.
  Since this release they call the `_` names (`_check_password`, `_rate_ok` …) — such a fake
  is never called, and the test silently checks something else (measured: 0 calls, the login succeeds
  with 303). **Set fakes on the new name** (`auth._check_password = fake`). Assigning to
  an old name on the object now triggers a `RuntimeWarning` (visible without a filter) that names the
  target; a patch on the class (`mock.patch.object(TinySesam, "check_password", …)`) replaces
  the alias itself, goes unnoticed and takes no effect either.
- **Custom login pages use `login_password`** (PO finding 2026-09-26). Whoever followed the pattern "Your
  own login page" of the README up to 0.21.0 (`check_password` + `start_session`) has **no protection
  against password guessing** on their own route — no lockout, no counter, no
  series, no throttle, no line for fail2ban. Switch to `auth.login_password(request,
  username, password, next=…, csrf=…)` (for the second step `login_totp`, for the PIN
  `login_pin`): It returns a `LoginResult` (`if not result: …`, otherwise
  `result.redirect()`), and it protects exactly like `POST /auth/login`, because that route calls it.
  Whoever only wanted to change the look replaces just the page (`set_template("login", …)`).
  The old checkers warn since this release and name the replacement.
- **Custom step-up and password-change pages use `confirm_*` or `change_password`**
  (PO decision 2026-09-27). Whoever asks again themselves before a sensitive action and calls
  `verify_user_password`, `verify_user_pin` or `verify_totp` for it has **no lockout,
  no counter and no line in the security log** there — the same applies to a custom account page that
  checks the old password this way and then calls `set_password`. Switch to
  `auth.confirm_password(request, password, next=…, csrf=…)` (or `confirm_pin`,
  `confirm_totp`; result a `LoginResult`, on success `result.redirect()`) and
  `auth.change_password(request, current, new, csrf=…)` (result a `PasswordChangeResult`).
  Both protect exactly like `/auth/reauth` and `POST /auth/password`, because those routes call them.
- **`POST /auth/password` no longer accepts an API key** — 403 with the text "Ein Passwort ändert ein
  Mensch: angemeldete Sitzung nötig, ein API-Key genügt hier nicht" (`api.password_needs_session`).
  Up to 0.21.x a key together with the old password changed the account's password and ended
  **all** of its sessions in the process (it had none of its own, after all). Whoever sets a password by machine
  does so as an operator (panel, `set_password`). Without a session, the 401 now carries a
  text ("nicht eingeloggt") instead of a bare `Unauthorized`.
- **An empty field is no longer a failed attempt — and neither is a method that is not offered.**
  `/auth/reauth` without a filled-in field answers 400 ("Bitte alle Felder ausfüllen.") instead of 401,
  `POST /auth/password` with an empty `current` 400 instead of 403; neither counts toward the lockout anymore
  (as at login). If a form sends `/auth/reauth` a method that is not
  offered to the account (`stepup_options()`; the built-in page shows only the offered ones — affected
  are custom templates and crafted requests), that is 403 without a failed attempt instead of 401 with one. Which
  field counts is still determined by the order code, PIN, password; what is new is only that a
  filled-in but not offered field is no longer silently passed over.
- **The first-admin one-time token goes into a file without a console** (T-17). If there is no admin and
  stderr is not a terminal (container, journal, pipe), the token for `/auth/claim-admin` is now
  in `<db_path>.claim` (permissions 0600), and the log names only the path — in the container thus
  `docker exec … cat /data/app.db.claim` instead of `docker logs`. After redeeming, the
  file disappears. On a console it stays with stderr; `admin_claim_token_file` takes precedence as before. Whoever
  waited for the line with `?token=` in the logs (script, instructions) now reads the file.
- **New startup warning: group rule without scope `groups`** (T-16). Whoever uses `oidc_allowed_groups` or
  `oidc_group_role_map` via the claim `groups` and does not request the scope `groups`
  sees a warning at startup. With PocketID (and other providers that bind claims to scopes)
  this situation means: everyone is rejected or gets no role. Remedy
  `oidc_scopes="openid profile email groups"`, in the gateway the new variable
  `TINYSESAM_OIDC_SCOPES`. TinySesam does not request the scope itself; if the provider supplies the
  claim without a scope (mapper), the warning is moot.

### Added

- **`auth.set_disabled(user_id, disabled)`** (tier A, PO decision 2026-09-27): lock or unlock an account as
  operator, with the panel's effect — operator note (no
  confirmation link lifts the lock, not even one that only comes into being afterwards, H-18), end all
  sessions, revoke API keys (event `api_keys_revoked` with
  `reason="account_disabled"`; on unlocking they stay revoked), discard open one-time tokens, audit `user_disable`/`user_enable` with `uid=…` (and `api_keys_revoked=…`). In a
  request the line names the signed-in account — exactly the line the panel itself wrote up to 0.21.x —,
  without a request the affected one. An owner cannot be locked
  (`StateError`, nothing happens), an unknown ID returns `False`. What depends on the caller
  (not locking oneself, only an owner changes an owner account) is still checked by the panel. The
  route `POST <admin_path>/api/users/{id}/disable` calls the method (one source).
- **Value check in the name guard** (`tests/test_api_surface.py`, `pruefe_werte`): Besides the names,
  it now measures the keys and values of tiers A and B — on a sample instance (result dicts
  of `gc`, `create_api_key`, `list_api_keys`, `federation_bind_existing` with all parts and
  reasons, `peek_magic`, `confirm_email_change`, the account dicts, `ConfigError.field`; the
  payload of every event on a hook; the context of custom pages via recording templates;
  the JSON of `/auth/me`, `/auth/apikeys` and `<admin_path>/api/users` including `disabled_by`; the
  stored values in the file), on the constants and configuration defaults and in the source code
  (every call of `_sicherheitsereignis` and `render_page`, every key a renderer reads from
  `ctx`, every JSON response of the route modules) — currently 790 entries. Red on a German word (the same
  list, extended by the words and stems of the values) and on every name up to 0.21.x (`ALTE_WERTE`,
  also `alt`, which as an English word is not in the list); plus a minimum set per path,
  self-tests (an old key in `gc()` of a subclass, in an event, in the context,
  in a JSON response) and the wiring.
- **Tests:** `tests/test_werte_englisch.py` — a file from 0.21.x (old values, stamp 11)
  migrates at startup, the keys work as before (human key only with a session), a second
  start changes nothing; mixed values after a rollback (stamp 12, `mensch`/`automat` and
  a link with `alt`) work correctly, even without a restart; the SQL from `docs/BETRIEB.md` restores
  the state of 0.21.x and a later start migrates again; a file with
  old values (stamp 12) starts read-only, an upgrade without write permission aborts; the old kinds are an
  input error with a hint; `set_disabled` with every effect, owner protection, unknown ID,
  the same audit line via the panel and an AST guard that the panel route only
  calls the method.

- **Warning for a group rule without scope `groups`** (T-16, finding from operation 2026-09-27):
  `konfigpruefung` checks per client — the single client with `oidc_scopes`, each application from
  `oidc_clients` with its `scopes` and its group rule (otherwise the global one) — whether a
  group rule runs via the claim `groups` without the scope `groups` being requested. A
  warning, not an error, no requesting on its behalf. For Entra ID (`login.microsoftonline.com`) it stays silent:
  There `groups` is not a scope (AADSTS650053), groups come as an "optional claim". SAML and LDAP
  have no counterpart in the configuration (no scopes; the IdP or the directory releases the attribute
  or not) — `docs/BETRIEB.md` names the symptom. Gateway: new variable
  `TINYSESAM_OIDC_SCOPES` (default `openid profile email`), before, the scope could not
  be set there at all. Test: `tests/test_betriebsfunde.py` (a).
- **Secure login building block for custom pages: `login_password`, `login_pin`,
  `login_totp`** (tier A, PO finding 2026-09-26). Each method does what the built-in route
  does — and the built-in route calls it (one source, no drift): check CSRF (`csrf=`, otherwise
  header `X-CSRF-Token`; 403), throttle per IP, book the attempt in advance atomically (failed attempts per
  identifier, address and pair, series; for the PIN login and PIN bucket, behind a supplied
  factor under its own series kind), with LDAP the fallback to the directory including pending state and
  rollback on an outage ("one identifier, one account" included), audit and security log
  (the same fail2ban lines), then the session or the next factor. `login_totp` accepts
  TOTP and one-time codes, like `POST /auth/totp`. Expected outcomes are results, not
  exceptions; only what the route also throws is thrown (403 on CSRF, the unexpected).
- **`tinysesam.LoginResult`** (export, tier A): the result — `ok` (also `bool(result)`),
  `reason` (`LoginResult.REASONS`: `ok`, `missing`, `invalid`, `locked`, `locked_series`,
  `ratelimit`, `directory_down`, `method_disabled`, `no_session`), `status` (the status of the
  built-in page), `message` (translated), `next_url` (checked target), `next_factor` (open
  factor), `done`, `user` (only on success); `set_cookie(response)` and `redirect()`. A
  frozen dataclass; the session token is deliberately not a field (no `repr`, no `asdict`) —
  fail-closed: A failure carries none, whoever ignores the result signs nobody in.
  `locked` includes the deferral behind a pending directory sign-in (G9), otherwise the
  reason would reveal that someone else is currently signing in under the identifier. The names of the building block are
  English like the rest of tier A (PO decision 2026-09-27); `reason` is an abbreviation for
  programs — the audit and log lines (including those for fail2ban) stay as they are. The guard
  measures the type too (area `LoginResult` in `tests/api_surface.json`: fields with type and default,
  methods, `REASONS`), `API.md` describes it in a section of its own. The
  step-up building blocks `confirm_*` return it too (see below); there `method_disabled` means 403 and
  `no_session` means 403 if the request shows an API key instead of a session.
- **Secure building blocks for custom step-up pages: `confirm_password`, `confirm_pin`,
  `confirm_totp`** (tier A, PO decision 2026-09-27). The same pattern as `login_*`, for the
  confirmation before sensitive actions: check CSRF (`csrf=`, otherwise header `X-CSRF-Token`), require a full
  session (an API key does not count: `no_session`, 403 — not even next to a half
  session), allow only a method that `stepup_options()` offers the account (`stepup_methods`,
  `stepup_strict`; otherwise `method_disabled`, 403, without a failed attempt), throttle per IP, book the attempt
  in advance atomically in its own bucket (`reauth_max_attempts`; if the page offers the PIN, the
  PIN bucket counts too, C-3), audit and security log (`failed verification`, `stepup`), then
  freshness (`mfa_at`) with a new session token (F-06) — the old one remains valid for `session_rotation_grace_sec`
  without freshness (A-6). An empty field is `missing` (400) and does not count.
  `confirm_totp` accepts no one-time code, like the built-in page. **The result is `LoginResult`**
  and not a type of its own: A confirmation is a renewed sign-in on the running session, the
  fields fit without remainder (on success `done=True`, `next_factor=None`), and `redirect()`/
  `set_cookie()` set the renewed token — a type of its own would have repeated every field. Three
  names instead of one `confirm(…, password=…, pin=…, code=…)`: like `login_*` exactly one secret per
  call, no order that silently passes over a field. `POST /auth/reauth` calls them.
- **Secure building block for a custom password-change page: `change_password`** (tier A):
  the same logic as `POST /auth/password`, which calls it — CSRF, full session (no API key),
  throttle per IP, advance booking in its own bucket (`password_change_max_attempts`, per account; a
  typo here does not lock the sign-in, R4-10), the old password checked against the session's ID
  (R4-12), the password rule, on success end the other sessions (the own one stays), discard open
  address-change links, audit `password_change` including `api_keys_active=n`. The result is the
  new export **`tinysesam.PasswordChangeResult`** (tier A): `ok` (also `bool(result)`), `reason`
  (`PasswordChangeResult.REASONS`: `ok`, `missing`, `invalid`, `locked`, `ratelimit`, `policy`,
  `no_session`), `status` (what the route answers: 200, 400, 401, 403, 429), `message` (translated;
  for `policy` the violated rule), `api_keys_active` (that many API keys survive the change —
  deliberately, and it is not concealed). A type of its own, because a password change signs nobody in
  and rotates no token: `next_url`, `next_factor`, `done`, `redirect()` would have no
  meaning, `api_keys_active` only it has. The guard measures it like `LoginResult` (own
  area in `tests/api_surface.json`), `API.md` describes it in a section of its own.
- **Tests:** `tests/test_bestaetigen.py` — a custom step-up page via `confirm_*` locks after N
  failed attempts in the `reauth` bucket (even the correct password then makes nothing fresh, the
  sign-in stays open), throttles per IP and on success makes fresh, with a new token and
  grace period of the old one; without a session, with a half session and with an API key (also next to a half
  session) no effect and no attempt; only offered methods, empty does not count, PIN bucket,
  no one-time code. A custom password-change page via `change_password` locks, checks the
  rule, ends the other sessions, discards the open address change and names the API keys;
  CSRF via field and header, the result type. The same sequence via `/auth/reauth` or
  `POST /auth/password` and via a custom route yields the same statuses, texts, audit,
  security-log and attempt lines. An AST guard pins down that both routes call their building block
  and not an inner checker themselves; the README examples run verbatim and must
  lock; the names are English and tier A. The guard in `tests/test_stepup.py` now
  also sees a sink that is merely passed along (`run_in_threadpool(auth.change_password, …)`), helpers
  that are called as a method (`self._nur_mit_sitzung`), and checks the body of a sink itself.
- **Tests:** `tests/test_anmelden.py` — a custom login page via the building block locks after N
  failed attempts (429 `locked`), throttles per IP (`ratelimit`) and locks the series
  (`locked_series`); LDAP fallback, outage with and without a local password, "one identifier, one
  account"; PIN in the guest path and in the chain step, TOTP with one-time code and without a session; CSRF,
  fail-closed, the result type. The same sequence via the built-in route and via a custom one
  yields the same statuses, audit, security-log, attempt and series lines (password, LDAP,
  PIN, TOTP). An AST guard pins down that `login_submit`, `pin_submit` and `totp_submit` call their
  building block and not an inner checker themselves; the README example runs verbatim and
  must lock. The guard in `tests/test_stepup.py` counts `login_*` among the places with
  session effect. A fake on the old name (`auth.check_password = fake`,
  `mock.patch.object(auth, "rate_ok", …)`) is never called and warns, the same on the new one
  (`auth._check_password`) takes effect. A name guard measures the building block's interface on the object
  (every method that returns a `LoginResult`, including parameters; type, module, fields, methods,
  `REASONS`): no German word, every name in tier A.
- **Name guard over the whole interface of tiers A and B** (`tests/test_api_surface.py`,
  `pruefe_namen`): every name in the store in A or B, the parameters of every method and function on the
  live object, all configuration fields, the public attributes and constructor parameters
  of the exported error types — currently 596 entries. Red on a German word: whole words from
  a list, word stems even in the middle of a word (`SICHERHEITSEREIGNISSE` is only one
  after splitting) and umlauts. Plus a minimum set (one mandatory entry per kind, number of parameters and
  fields) against a measurement that silently sees less, and self-tests on a sample class: every
  old name stands out, English lookalikes (`series`, `start`, `binding`, `base`) do not, tier C
  stays outside. Section (k) in `tests/test_anmelden.py` uses the same list.

- **Tier per public name, and the guard requires it** (PO decision 2026-09-26).
  `tests/api_surface.json` keeps every entry as an object: the measured value (`sig`, for
  constants `wert`, for configuration fields `feld`) plus `stufe` (`"A"`, `"B"` or `"C"`);
  the exports are an object instead of a list. `tests/test_api_surface.py` is red as soon as a
  public name carries no or an unknown tier, and names it. `--update` measures anew,
  carries over the tiers (and all other decisions on the entry) from the same name, but
  never assigns one itself: A new name comes in without a tier and keeps the guard red until
  someone decides — a silent "A" would have promised every helper method without an underscore
  forever. A reported break carries the name's tier (`[A] …`). Currently: A 252 (including
  `login_*`, `confirm_*`, `change_password`, `set_disabled`, the 11 names on the result type
  `LoginResult` and the 6 on `PasswordChangeResult`), B 64, C 50 of 366 names.
- **Tier C as a warning alias** (`tinysesam/_veraltet.py`). Every C name is a
  `Veraltet("_name", "<replacement>")`: a descriptor that passes through unchanged to the implementation
  and triggers exactly one `DeprecationWarning` in the process — on call, not already on
  lookup (`hasattr`, `getmembers`), for constants on read; the warning points to the
  caller and names the replacement. Signature and docstring come from the target. An assignment on the object
  (test fake) is stored as before and read via the old name, **but no longer takes effect** —
  the routes call `_name` —, which is why it triggers a `RuntimeWarning` with the target (see "What stands out on
  update"); `del` restores the alias. `tests/test_api_surface.py` pins down:
  C entry in the store
  (with `ziel`, `seit`, `bis`) exactly if the class carries an alias; the target is called `_name`
  (only exception `complete_mfa` → `complete_totp`, tier A); every alias warns exactly once, with
  replacement and "is dropped with 1.0", at the caller, and passes arguments through unchanged; an
  assignment on the object warns exactly once (RuntimeWarning, with target, at the assignment); no
  code in `tinysesam/`, `examples/`, `scripts/` and `web/` uses an old name (AST, in the package
  also as a string for `getattr`); from version 1.0 on every remaining alias is red; `seit`
  matches the CHANGELOG — if the alias stands under "Deprecated" only in `[Unreleased]`, `seit` must be
  greater than the most recent release, otherwise exactly the release that introduces it (the classification
  was built with `seit: 0.21.0`, then 0.21.0 went out without it, and only the field was
  checked, not its value). In addition,
  `tests/run_all.py` sets a warning filter for every suite that turns such a warning from a module of the
  package into an error — so a dynamic access stands out too as soon as a suite runs through the path;
  the guard measures the filter's effect in a process of its own.
- **README: the tiers and a section for advanced users** (EN/DE). The B building blocks are listed
  grouped by purpose — custom account page, custom admin panel, mail and token flows,
  custom routes and extension points —, `apply_factor` with a warning of its own (attaches a factor
  to the session unchecked). `tests/test_repo.py` checks that every B name from the store appears there in
  both languages.
- **Documented after the fact what consumers use but no README showed** (all tier A):
  `create_user` (section "Accounts in code" / "Konten im Code"), `has_role` (roles),
  `current_user` including its distinction from `session_user` (guards), `session_cookie_name` with
  `start_session` for the tests of one's own app — explicitly as a session **without checking**, not
  as a login path —, and that `TinySesamConfig` is and remains a dataclass
  (`dataclasses.fields(TinySesamConfig)`).

### Security

- **The first-admin one-time token was in the log in the container** (T-17, finding from operation
  2026-09-27). Without `admin_claim_token_file` it went to stderr — and directly after it the line "The
  value is deliberately NOT in the log". In a container stderr is the log (`docker logs`, any
  log shipping): Whoever could read it and had an account on the instance became admin with the token,
  as long as there was none yet. Now: If stderr is not a console (`sys.stderr.isatty()` false),
  TinySesam writes the token to `<db_path>.claim` (0600) and names only the path; after
  redeeming, the file is deleted, a start with an admin clears away a leftover, after expiry
  its content is invalid. Without a database file (`:memory:`) or if the file is not created, only
  stderr remains — and the log line then says that the value is in the service's log, instead of claiming
  the opposite. Also applies to the output at the moment of an IdP withdrawal (G6). Test:
  `tests/test_betriebsfunde.py` (b).
- **The pattern "Your own login page" of the README was unprotected against password guessing**
  (PO finding 2026-09-26). It showed `check_password` + `start_session` as building blocks; but the inner
  checkers `check_password`, `check_pin`, `check_ldap` and `check_saml` do not throttle by themselves —
  lockout, failed-attempt counter and series lockout are set only by the built-in routes. Whoever followed the pattern
  up to 0.21.0 has no protection against guessing on their own login route. The
  README now shows two secure paths: for a custom look, replace only the page
  (`set_template("login", …)`, the form still goes to the built-in route), for a custom
  route the building block `login_password` (or `login_totp`, `login_pin`), which the
  built-in routes call themselves; its example runs verbatim in the test and must lock. The
  checkers are in tier C, their warning names the building block. Also unthrottled was `verify_totp`
  from the same example — a six-digit code; its replacement is `login_totp`.
- **Custom step-up and password-change pages had only unthrottled checkers** (PO decision
  2026-09-27). For the confirmation before sensitive actions and the password change there were only the
  built-in routes; whoever built a page of their own was left with `verify_user_password`,
  `verify_user_pin`, `verify_totp` and `set_password` — without lockout, counter and log line, an
  unlimited oracle for the password (and the short PIN) of an account whose session one
  already has. Now there are `confirm_*` and `change_password` (tier A), the built-in routes
  call them; the warnings of the old checkers name them.
- **`POST /auth/password` accepted an API key.** The account came from `current_user()`, and that
  falls back to the key without a session: An automation key together with the old password changed
  a human's password and ended all of their sessions in the process. `/auth/reauth` has rejected keys
  since 0.20.1; the password change now does too (403, `api.password_needs_session`). A key is
  a machine sign-in, knowing the old password does not make it a human.

### Changed

- **Keys and values of tiers A and B in English, schema 12** (PO decision 2026-09-27): the
  table is under "What stands out on update". `Store.SCHEMA_VERSION` is 12 — a
  data migration without a new column, but with values that 0.21.x reads differently (a `human` key would count
  there without a session); the stamp is exactly the place where an older version warns about it.
  `api_key.kind` is rewritten on every start, the payload of an address-change link only by the jump to
  12 — on every start the search through all one-time tokens would run (measured in
  `tests/test_bestandsdaten.py`, "Aufwand": 540 SQLite steps more with 20,000 tokens); old values
  are read correctly in both places. A file with old values at stamp 12 starts read-only
  and keeps going (warning in the log). The reason for the collective key revocation comes from a fixed
  list (`_KEYS_WIDERRUFEN_GRUENDE`); any other value is a programming error (`ValueError`),
  not a silent new abbreviation.
- **Account dicts only with the account's fields** (`_KONTO_FELDER` — a list of the allowed columns
  instead of the forbidden ones: A new column of the store does not silently become a promise).
- **The panel route "Lock" calls `auth.set_disabled`**; the steps are now only there.

- **The German names of tiers A and B are now English, without alias** (PO decision
  2026-09-27): 11 methods, 5 constants, 2 methods of `TinySesamConfig`, 18 parameters in 14
  methods, the attributes `ConfigError.field`/`.owner_id` and the first parameter of
  `MissingExtra` — the table is above under "What stands out on update". Package, routes,
  examples, tests and docs now call only the new names; `API.md` and `KONFIGURATION.md` are regenerated.
- **`POST /auth/login`, `/auth/pin` and `/auth/totp` are thin wrappers around `login_*`.** The
  whole flow moved from `router.py` into the building blocks; the routes now only render the result.
  Responses, texts, audit and log lines stay the same (measured against a custom route over
  the same building block). Three small things change: An unexpected exception in the PIN or
  TOTP check now closes the pre-booked attempt immediately as a failed attempt (before, only for the
  password; previously its series pre-booking stayed in memory). `/auth/pin` answers 404
  if `pin_enabled` was switched off at runtime (the route had existed since startup, but on
  a full session it kept confirming PINs). And the replacement texts of the C aliases (`check_password`,
  `check_pin`, `check_ldap`, `verify_totp`, `verify_recovery_code`, `is_locked`, `is_pin_locked`,
  `rate_ok`, `record_login`, `versuch_beginnen`, `login_redirect_after`) now name the
  building block instead of the route.
- **`/auth/reauth` (submit) and `POST /auth/password` are thin wrappers around `confirm_*` and
  `change_password`.** The flow moved from `router.py` into the building blocks; the routes now only choose
  the filled-in field or read the JSON and output the result. Responses, texts, audit and
  log lines stay the same (measured against custom routes over the same building blocks) except for the
  points under "What stands out on update". `POST /auth/password` now checks the old password in the
  thread pool — before, argon2 ran in the event loop and held up every
  other request of the worker for the duration of the check. The replacement texts of the C aliases `verify_user_password`,
  `verify_user_pin`, `verify_totp`, `is_reauth_locked` and `is_password_change_locked` name the
  new building blocks.
- **`API.md` is organized by tier** (A "public, stable from 1.0", B "for
  advanced users", C as a table "Deprecated — dropped with 1.0" with replacement instead of explanation) and
  explains up front what each tier promises. New
  in it: the constants of tiers A and B (explanation from the `#:` comment, plus the value) and
  `tinysesam.current_version()`; the hygiene check requires an explanation for them too.
  `KONFIGURATION.md` names the tier of the fields — all A except the tombstone `totp_required` (B).
  Until now it said "measured, not selected": what was frozen was whatever carried no underscore.

### Deprecated

- **50 internal names (tier C) — dropped with 1.0.** Since this release the
  implementation is called `_name`; the old name passes through unchanged until 1.0 and triggers a
  `DeprecationWarning` on call (constants: on read) that names the replacement. The replacement per name
  is listed in `API.md` ("C · Veraltet — fällt mit 1.0 weg"). **With 1.0 all old names are dropped.**
  - **Sign-in checkers without their own throttle — replacement: `login_password`, `login_pin`,
    `login_totp`, for step-up `confirm_password`, `confirm_pin`, `confirm_totp`, for the
    password change `change_password` or the built-in routes (`/auth/resource/{name}`,
    `/auth/saml/acs`), custom look via `set_template`:** `check_password` → `_check_password`,
    `check_pin` → `_check_pin`, `check_ldap` → `_check_ldap`, `check_saml` → `_check_saml`,
    `check_resource` → `_check_resource`, `verify_totp` → `_verify_totp`, `verify_recovery_code` →
    `_verify_recovery_code`, `verify_user_password` → `_verify_user_password`, `verify_user_pin` →
    `_verify_user_pin`.
  - **Lockouts and bookkeeping — replacement: `login_*`, `confirm_*`, `change_password` or the
    built-in routes, which check and book atomically:** `is_locked` → `_is_locked`, `is_pin_locked` → `_is_pin_locked`,
    `is_password_change_locked` → `_is_password_change_locked`, `is_reauth_locked` →
    `_is_reauth_locked`, `is_resource_locked` → `_is_resource_locked`, `is_totp_setup_locked` →
    `_is_totp_setup_locked`, `rate_ok` → `_rate_ok`, `record_login` → `_record_login`,
    `versuch_beginnen` → `_versuch_beginnen`.
  - **Session, sign-in chain, CSRF:** `session_from_request` → `_session_from_request` (replacement
    `current_user`/`session_user`), `next_login_step` → `_next_login_step`, `factor_entry` →
    `_factor_entry`, `login_redirect_after` → `_login_redirect_after` (replacement `next_url` on the result
    of `login_*`), `csrf_rotieren` → `_csrf_rotieren` (replacement `set_cookie`/`issue_csrf`),
    `verify_csrf` → `_verify_csrf` (replacement `require_csrf`), `unlock_resource` → `_unlock_resource`,
    `mfa_pending` → `_mfa_pending`.
  - **First admin, demo, log:** `maybe_promote_admin` → `_maybe_promote_admin` (replacement
    `admin_identifiers`/`ensure_admin`), `consume_admin_claim` → `_consume_admin_claim`,
    `admin_claim_fehlgriff` → `_admin_claim_fehlgriff`, `seed_demo` → `_seed_demo` (replacement
    `demo_mode=True`), `purge_demo` → `_purge_demo` (replacement `demo_mode=False`), `send_signup_notice`
    → `_send_signup_notice`, `sicherheitsereignis` → `_sicherheitsereignis`, `token_abgewiesen` →
    `_token_abgewiesen`.
  - **Forward auth and several OIDC applications:** `forwarded_url` → `_forwarded_url`,
    `forward_login_url` → `_forward_login_url`, `forward_response_headers` →
    `_forward_response_headers`, `oidc_anwendung` → `_oidc_anwendung`, `oidc_freigabe_gueltig` →
    `_oidc_freigabe_gueltig`, `vermerke_oidc_freigabe` → `_vermerke_oidc_freigabe`, `is_secure` →
    `_is_secure`.
  - **Hardening values:** `sec` → `_sec` (replacement `all_security()`).
  - **Constants (warn on read):** `APIKEY_AUDIT_FENSTER` → `_APIKEY_AUDIT_FENSTER`,
    `DEMO_USERS` → `_DEMO_USERS`, `FOEDERIERTE_FAKTOREN` → `_FOEDERIERTE_FAKTOREN`, `IDENTIFYING` →
    `_IDENTIFYING`, `RECOVERY_BYTES` → `_RECOVERY_BYTES`, `RECOVERY_WARNSCHWELLE` →
    `_RECOVERY_WARNSCHWELLE`, `SERIE_PIN_FOLGE` → `_SERIE_PIN_FOLGE` (replacement `login_pin`; came with
    0.21.0, whose CHANGELOG named it for custom PIN pages — hence an alias and not merely
    renamed).
  - **`complete_mfa` → `complete_totp`** (same behavior; not an underscore name, the alias points
    to the public method). In the guard its return type is now measured too
    (`-> Optional[str]`), before there was none.

### Fixed

- **The API guard lost `*` and `/` in signatures.** `signatur()` in
  `tests/test_api_surface.py` assembled the parameters one by one; the markers for
  keyword-only (`*`) and positional-only parameters (`/`) were dropped in the process, although the docstring
  promised to measure exactly that. A `*` inserted later — every positional call
  breaks — looked like no change. Now the markers are in the store (10 signatures re-measured:
  `login_*`, `change_username`, `create_user`, `federation_bind_existing`,
  `password_policy_error` and the presets `active_directory`, `entra_id`, `oidc_gateway` — none of them
  has changed), an inserted `*` or `/` is a break, a keyword-only parameter with a default
  appended at the end remains an extension. A store from before 0.22.0
  (`git show v0.21.0:tests/api_surface.json`) can still be compared: Its signatures
  are read in as "measured without markers" and compared without markers. The same bug was
  in `scripts/_api_doku.py` — `API.md` showed e.g. `login_password(…, password, next=…)`, as if
  `next` could be passed positionally too; the guard keeps both versions equal.

## [0.21.0] — 2026-09-27

**Big release — back up the database and read the list below before updating.** It fully closes
the third audit (T-13): all findings, all remainders named as limits, two review rounds against the
fixes. Who needs it: **every app under a subpath** (T-15 — up to 0.20.1 the built-in pages pointed
out of the mount), **anyone using LDAP or SAML** (addresses, binding via the stable identifier,
"one identifier, one account"), and everyone affected by the security fixes. New: owners, username
and address in self-service with `Remote-Id`, revocation via the identity provider, encrypted TOTP
secrets, renaming by the operator (panel, `tinysesam rename`), `foederation_nachbinden`. Schema 11
(additive; 0.20.x opens the file afterwards only with a warning).

**When updating:** `login_path`, `login_redirect`, `logout_redirect` and `admin_path` are paths of the
app **without** the subpath prefix — that comes from the path of `base_url` (T-15, see "Changed").
What else you will notice:

- **New passwords need 15 characters** as long as the password alone can sign in (default).
  Existing ones stay valid.
- **New required dependency `cryptography`**; TOTP secrets are now stored encrypted. Without
  `TINYSESAM_SECRETS_KEY`/`secrets_key_file`, TinySesam creates `<db>.key` next to the database —
  **back this key up separately**; without it, all accounts have to set up TOTP again.
- **Sessions without an explicitly chosen "stay signed in" end after 8 hours of inactivity**
  (`session_idle_minutes`) — OIDC and link sessions too.
- **Owners exist**: The oldest active admin that was set by hand becomes owner on the first start.
- **Addresses from SAML and LDAP no longer go straight into the account** (`saml_email_trusted`,
  `ldap_email_trusted`, both default off): If mail is set up, the holder confirms them via a
  link; new SAML accounts with `@` in the name get a substitute name. **If you maintain your directory
  (nobody changes their own `mail` attribute), set `ldap_email_trusted=True`** — otherwise
  LDAP users get a confirmation link on their next login.
- **API keys of OIDC accounts go dormant** when the provider says no or the account has gone 30 days
  without confirmation — a sign-in via the provider wakes them.
- **The database enforces the shared identifier space** (G12c): `store.create_user`,
  `store.set_username` and `store.set_email` raise `sqlite3.IntegrityError` if the name or address
  is already the identifier of another account — **even for look-alike names such as `Alice`/`alice`**. Anyone
  calling the store directly must catch this. `auth.create_user` raises the same `ConfigError` in a race as
  for a taken identifier; `e.besitzer_id` can then be `None`. The startup message now names
  every collision in the existing data, not just "name = someone else's address".
- **`tinysesam unlock` takes the identifier as typed** — name, address or the name in the
  directory — and clears the counters under it even without an account; it returns 1 only if nothing
  was there (G5). Failed attempts that were counted under the new identifier before a rename or address change
  are no longer wiped by the next sign-in; they expire with the lockout window (G2).
- **PIN behind another factor** (G7): If a strict `login_chain` requires the PIN behind another
  factor (`["password", "pin"]`), the login page no longer shows a PIN field, and `/auth/pin`
  answers 404 without a session — that path never led to a full session. **`pin_login=False` with such a
  chain now works** (previously a dead end). Failed attempts in the PIN step after the first factor are no longer cleared
  by "forgot password" (as with TOTP); the operator still can (panel reset, `tinysesam
  unlock`). An app that uses a route chain with the PIN first for guests under such a chain
  loses that entry point.
- **LDAP: sign-ins wait briefly instead of being locked** (G9): In the first window of a
  directory outage, a sign-in can take up to 12 s instead of getting 429 right away. New in the
  security log: `deferred login user=… ip=… reason=pending` — a deferral, not a lockout; the
  bundled fail2ban filters deliberately do not match the line.
- **LDAP/SAML bind an unbound account via the name for only 30 days** (G1): counted per
  source from the first start after the update or from the creation of the account
  (`federation_name_binding_days`). After that the sign-in is rejected (`<source>_namensbindung_zu`,
  the log line names the identifier and the remedy). **Bind the existing accounts once:**
  read `auth.foederation_nachbinden("ldap")` as a dry run, then run it with `ausfuehren=True`; SAML with
  `zuordnung={name: nameid}`. The startup message names, per source, how many accounts are affected.
  `federation_name_binding_days=-1` restores the old behavior. **Self-registered or
  self-renamed accounts never bind via the name** (G2-N), **nor do accounts that another
  source created** (attack round 2026-09-26): An account created via OIDC does not bind
  via the name to LDAP or SAML, one created via LDAP not to SAML and vice versa — also in the
  existing data, as far as the origin is documented. If you run several sources from the same directory,
  you will notice this from `<source>_namensbindung_zu grund=name_aus_quelle`; a single account is opened
  with `auth.loese_fremde_bindung(quelle, user_id)`.
- **If the identity provider takes the right from the last admin, `admin_identifiers` stays closed** (G6):
  The allowlist then promotes nobody. Back into the panel via the one-time token that
  TinySesam writes to the console at that moment (or to `admin_claim_token_file`), or
  `tinysesam owner`. **Keep at least one owner by hand.**
- **Route chains with the sign-in link require the second factor** (G10): If an account has TOTP or
  a passkey, `require(factors=["magic"])` lets it through after the link only with this factor —
  like the global policy (`magiclink_require_second_factor=False` turns off both).
- **Changing the address to a taken address now looks like any other** (G12b): In that case too,
  the notice goes to the previous confirmed address, and the request consumes the account's quota
  (`mail_per_address_max` per `mail_per_address_window_sec`). **`request_email_change()` then still
  returns a send function** — whether a link went out is told by its return value
  (`senden() -> bool`). An app that read `request_email_change(…) is not None` as "link sent"
  is wrong. The account page shows `email_change_taken`/`_reserved` (older
  rows too) as `email_change_requested` and no longer shows `federation_email_confirm` at all; the operator's audit log
  keeps the real names.
- **Confirmation links for addresses from LDAP/SAML count sends** (G12a): at most one
  delivered per account and day (if a link lives longer, `email_change_ttl_min`, as long as that), now
  across all workers; a throttled target address or a failed send is retried after
  `mail_per_address_window_sec` instead of the next day. The rejection of a
  taken or reserved address counts the same way. The audit line `federation_email_confirm`
  is only created after sending; its detail begins with `konto=<id>`, that of the lines
  `email_change_requested`/`_taken`/`_reserved` from this path with `konto=<id> quelle=<source>` —
  if you read the log by machine, adapt your reader.
- **One identifier, one account (review round 2026-09-27):** If the identifier typed belongs locally to an
  account (name or address) but the LDAP entry for it belongs to another — a local account has the same name as
  someone in the directory, or a filter on `mail` hits the address of a local account —,
  **the sign-in via LDAP is rejected** (failed attempt, audit `ldap_kennung_abgewiesen
  grund=kennung_zweier_konten lokal=<id> verzeichnis=<id|neu>`, log line with remedy: rename the local
  account). Until then it signed the directory entry in or created an account `ldap-…`.
  **The name under which another account signs in via LDAP counts as taken**
  (registration 409, rename rejected, `store.create_user`/`set_username` raise
  `IntegrityError`), and a renamed LDAP account keeps its old name as the directory name.
- **No open registration and no self-rename next to LDAP** (PO decision 2026-09-27):
  `allow_signup=True` together with `ldap_enabled=True` is a setup error, and
  `change_username` rejects everyone who is not an operator next to LDAP (the account page does not
  offer it). Anyone who registered in advance with the name or directory address of a person who has never signed in,
  or renamed themselves that way, would otherwise lock that person out under this
  identifier (consequence of "one identifier, one account"). There, the operator creates accounts (panel,
  `create_user`) and renames them (panel, `tinysesam rename`).
- **Route chains only tighten the global rule** (PO decision 2026-09-27): `require(factors=[…])`
  lets a session that the global sign-in still owes a factor (TOTP of an account that has
  one; the next step of the `login_chain`) through only after that step — even with
  `factors=["password"]`. Until then the route chain overrode the global rule; if you used it
  as your own, weaker sign-in (route `["password"]` without TOTP, route `["magic"]` under
  `login_chain=["password", "totp"]`), you now get the missing step.
- **LDAP: a sign-in queries the directory for at most 25 s in total** (review round 2026-09-27,
  `ldap_.GESAMT_FRIST_SEK`). Each response gets its share: with search-then-bind and StartTLS,
  2 s per response of the service account (with `ldaps://` 3 s, without TLS 4 s), then the user connection
  gets the rest, at most 10 s per response. **A directory that answers more slowly now counts as unreachable**
  (503, no failed attempt, pause of the outage marker) — previously each response waited up
  to 10 s, so a sign-in took up to 100 s.
- **Serial lockout: texts per way out** (review round 2026-09-27). The login page (`err.locked_serie`)
  names the operator first, the password reset only conditionally — the same for every kind. The lockout notice and
  the security log (`Anmeldung für user=… gesperrt: … Aufheben: …`) name the reset only if it
  lifts the lockout (not for failed attempts after the password: TOTP, PIN in the chain step). If you read
  the log line by machine, mind the text after `Aufheben:`.
- **`/auth/pin` with a half session** checks the PIN only if it is the open step of the
  `login_chain` (review round 2026-09-27); otherwise guest path or 404. In classic mode with
  `pin_login=False` this is again the behavior of 0.20.x.
- **New CLI commands:** `tinysesam rename --db <file> <name|#id> <new>` (rename as operator,
  G13) and `tinysesam owner --db <file> <name>` (emergency route to owner).
- **Back up the database before updating** — schema 11; 0.20.x opens it afterwards with a warning.

### Added

- **Renaming accounts as operator (G13).** Until then this was possible only for the holder themselves or from
  the embedding service — even an identifier collision reported by the startup could be resolved neither in the
  panel nor in the CLI. Now: panel "Rename", `POST <admin_path>/api/users/{id}/username`
  (same rules as self-service via `change_username`, plus the owner protection; an
  audit line `username_changed … durch=betreiber akteur=<admin>`) and `tinysesam rename --db <file>
  <name|#id> <new-name>` (length, control characters, mutually free, no other person's address as name; if the
  database rejects it, a clear message; audit `quelle=cli`). Both rename as operator: The "chosen
  by themselves" marker (G2-N) is dropped. The startup messages about collisions and control characters name both ways.
- **Binding existing accounts to LDAP/SAML: `auth.foederation_nachbinden(quelle, *, zuordnung=None,
  ausfuehren=False)`** (G1). LDAP searches the directory for each account without an identifier
  (`LDAPClient.eintrag_suchen`, service account or anonymous, exactly one hit); SAML and individual
  accounts take `zuordnung={name: identifier}`. Default is a dry run; the report names for each account
  `gebunden`, `konflikt`, `mehrdeutig`, `nicht_im_verzeichnis`, `ohne_kennung`, `abgewiesen` (with
  reason, `TinySesam.NACHBINDUNG_GRUENDE`) and `lokal` (accounts with a local password, only reported),
  with display name and address here and in the directory side by side. Also
  `federation_name_binding_days`, `create_user(…, name_selbst_gewaehlt=False)` for own
  registrations and for accounts from an own identity provider, and
  `change_username(…, durch_betreiber=False)` for renaming by the operator (G2-N).
- **Changing username and email address yourself (PO decision 2026-09-25).** On the account page,
  with a fresh step-up. The address counts only after a click on the link sent to the new one (with proof),
  the old one gets a notice, open links to it expire; a taken address gets
  no link with the same response, and neither does an address from `admin_identifiers` (otherwise
  another account, after the holder clicked in good faith, would carry the confirmed allowlist address and, on an
  instance without an admin, be the first admin). The name follows the same rules as on creation, plus: no
  other person's address as name, no name from `admin_identifiers`; in mail mode it follows the address.
  Switches `self_service_email_change`, `self_service_username_change` (both on),
  `email_change_ttl_min`. API: `change_username`, `request_email_change`, `confirm_email_change`;
  events `username_changed`, `email_changed`.
- **Confirming addresses from SAML and LDAP by link (PO decision 2026-09-25).** If the
  operator does not trust the source, a confirmation link goes after sign-in to the address from the
  source — the same way as for the address change in self-service; only the click makes it the
  address of the account, with proof. Only for accounts without a confirmed address, at most one delivered per
  account and day (across all workers, G12a), none while an address-change link of the account is open
  (to whichever address, since the review round 2026-09-27); a taken address
  gets none, and its rejection counts like a send. Switch
  `federation_email_confirm` (default on; needs a mailer and `base_url`). Also, per source an
  optional proof attribute for IdPs that maintain it: `ldap_attr_email_verified`,
  `saml_attr_email_verified` — a true value (`true`, `1`, `yes`) confirms the address of this
  login and, like the switch, also carries the first admin via an allowlist address (the
  configuration check says so at setup).
- **`Remote-Id` in the forward-auth default** — the account ID, stable across renaming and
  mail changes. **When updating:** Set the header in the proxy too (the examples under
  `deploy/forward-auth/` do) — a proxy that does not set it itself passes through one sent by the
  browser.

- **Grace period after step-up (A-6).** A step-up gives the session a new token (F-06); a
  request from a second tab that was in flight at that moment failed once as a result. The old
  token now stays valid for `session_rotation_grace_sec` (default 10) seconds — without step-up freshness,
  not as a session of its own, and it ends with the new one. `0` = the old behavior.
- **Upper limit without a successful re-check (4a).** If the re-check at the provider
  fails permanently because of an error of the client or of the provider itself, an OIDC session ends after
  `oidc_session_max_unverified_hours` (default 25) hours without a yes (`oidc_unbestaetigt`). Not a
  no from the provider — the API keys do not go dormant because of it. `0` = no limit.

- **Owner.** Owners are admins who cannot be deleted, locked or stripped of their rights; the role
  can be passed on, several can be owners, there is always at least one. Only an owner
  grants it — and only an owner changes an owner account (password, keys, passkeys, sessions,
  lock, roles); the protection also applies in code (`set_disabled`, `delete_user`). **The
  hardening values in the panel are saved only by an owner** — otherwise an admin could tighten the lockout and
  lock the owner out with a few failed attempts; all admins may read them, and without an owner
  (existing data with only IdP admins) it stays as before. The first admin
  of an instance is its first owner; in existing data the oldest active admin set by hand becomes
  owner (not a service account, not locked; line `owner_grant` in the audit log) — if there is none,
  the log names the emergency route. An owner is always an admin "by hand" — no
  identity provider takes the right from them (H-5). Emergency route: `tinysesam owner --db … <name>`.
  Panel: column and button "Make owner / Give up owner". API: `auth.set_owner(uid, bool)`.
- **Inactivity timeout (F-05, ASVS 7.3.1).** `session_idle_minutes` (default 8 h) for every
  session for which "stay signed in" was not explicitly chosen (also persistent ones from OIDC
  or a sign-in link), `session_idle_minutes_remember` (default off) for the chosen ones. The last request
  is stored on the session (`session.zuletzt`, written at most once per minute).
- **Revocation follows the identity provider (4a).** The refresh token of an OIDC session is stored
  encrypted on it, one row per client; every `oidc_session_refresh_minutes` (default 15)
  the next request triggers the exchange at the provider — in the background, without waiting for it,
  and of many parallel requests exactly one (rotation). Nobody queries locked accounts. If it refuses (locked, deleted, removed from the group, withdrawn from the application),
  the session ends (`oidc_widerruf` in the audit log); groups, allowed groups and the admin flag
  granted by the provider are re-evaluated — H-5 thus takes effect within minutes. A provider that
  is unreachable signs nobody out (new attempt after a minute). Needs a provider that issues
  refresh tokens.
- **Notice to the holder when their account is locked because of failed attempts (ASVS 6.3.5).** With
  sending configured to the confirmed address, at most one per lockout window (counted in the
  audit log, so across all workers), without a link.
  Opt-out: `notify_login_failures=False`. Lookup and sending happen in the background, via
  a separate outbox — the response reveals neither existence nor runtime.
- **Security events for the revocation of API keys**: `api_key_revoked`, `api_keys_revoked`
  (limit e).
- **API keys follow the identity provider (finding 8).** Until now a no from the provider (4a) ended only
  the session; the account's automation keys kept running up to `apikey_default_days` — the same
  class of error as PocketID CVE-2026-43983. Now they go dormant immediately (`api_keys_ruhen` in the audit log),
  and likewise without confirmation by the provider within `oidc_apikey_confirm_days` (default 30, 0 = no
  deadline) — this also hits someone who now works only by script. Nothing is deleted,
  because `invalid_grant` does not distinguish "locked" from "expired": The next sign-in via
  the provider wakes the keys. Only accounts with an OIDC binding; column `users.idp_bestaetigt_at`, for
  existing data the deadline starts with the update.
- **The sign-in link requires the second factor if there is one (ASVS 6.3.6, option C).** If
  an account has TOTP or a passkey, the link alone no longer signs in fully — not even in a chain
  like `["magic"]`, not in a route chain `require(factors=["magic"])` (G10) and not for
  an account with only a passkey (the classic policy always required
  a set-up TOTP). Accounts without a second factor are still signed in by the link alone.
  Configurable: `magiclink_require_second_factor` (default on). An account with a passkey sets
  up a further factor (TOTP self-setup in a chain) only if the passkey was presented in
  the same session or the operator opened a window — otherwise it would go
  around the passkey via the sign-in link or "forgot password".
- **SAML and LDAP addresses: the operator says per source whether to trust them** (point 5, option B;
  defaults after PO decision 2026-09-25). `ldap_email_trusted` and `saml_email_trusted`, both
  default off. Trusted: The address counts as confirmed, goes on as `Remote-Email` and carries
  rights (first admin). Not trusted: like H-3 for OIDC — no address in the account, no
  `Remote-Email`, and with SAML an account name with `@` (also `＠`) yields to a substitute name; the
  normal path is then the confirmation link (below). The protection from F-14 thus applies again by default to LDAP
  too.
  With a source that is not trusted, an unconfirmed name is never assigned via the name to an existing account
  (otherwise `bob@example.com` from an IdP with self-registration would take over the local
  account `bob@example.com`); without a stable identifier it is rejected. Unconfirmed means: for SAML a
  name with `@` or one taken from the address attribute itself, for LDAP an input that equals the
  `mail` value of the entry (also `chefin` without `@`; a UPN as bind identifier stays).
  Substitute names `saml-…`/`ldap-…`. An identifier with surrounding whitespace or control characters is
  rejected instead of trimmed.
- **Account names with control or format characters no longer exist** (pre-existing, attack on the
  third round). `chefin\x01` was a different name from `chefin` for TinySesam, but the header sanitizing
  of forward-auth turned it into `Remote-User: chefin` — the protected app saw someone else's account. `create_user`
  rejects such names (registration and panel with 400), federated paths
  fall back to a substitute name. Existing data with C0 control characters in the name gets no approval
  from `/auth/forward` any more (403); names with other format characters (such as ZWNJ) do not collide
  and continue to pass. The startup names such existing accounts.
- **4a: An error of the client is not a no to the account.** `invalid_client` (e.g. after a
  secret rotation), `unauthorized_client`, `unsupported_grant_type` and every 401 used to end
  sessions — and since finding 8 would have shut down the keys of everyone affected. They now count like
  an unreachable provider (as do 5xx). Every other 4xx remains a no — including Dex'
  `invalid_request` for a revoked token. A row of a client that was removed from `oidc_clients`
  or recreated at the provider (different `client_id`, now on the row) is
  discarded instead of exchanged. A yes whose question went out before a no does not overwrite the no
  (race of two exchanges). If the session gets a new token during the exchange, the rotated
  refresh token still ends up on its row (previously it was lost, and the next
  exchange was a no with PocketID).

### Security

- **After a revocation by the identity provider, the allowlist does not reopen (G6).**
  Measured: `admin_identifiers=[chef@…]` and an admin group at the provider; when the group is dropped,
  H-5 took the flag — and in the same login `maybe_promote_admin` (via `apply_factor`, there
  was no admin) promoted the person again: as admin "by hand" (1) AND first owner, a right that no
  provider takes away any more and that can be neither deleted nor locked; likewise every other account from
  the list. Now the revocation of the last admin sets the marker `allowlist_nach_idp_entzug`
  (setting, no schema), after which the allowlist refuses (`admin_bootstrap_denied nach_idp_entzug`).
  The one-time token for `/auth/claim-admin` goes to the operator immediately (until then only at startup),
  `tinysesam owner` remains. Test: `tests/test_t13_entscheide.py`.
- **Route chains require the second factor after the sign-in link (G10).** `_link_braucht` ran
  only for the global policy; `require(factors=["magic"])` let an account with TOTP or passkey through with
  the mailbox alone (measured: global route 401, this one 200). Now the same rule in both
  places; a chain that itself contains `totp`/`passkey` gets no double step. Test:
  `tests/test_t13_entscheide.py` (3c).
- **Binding via the name with a deadline (G1).** An account without an identifier from LDAP/SAML (existing data from before
  F-11, advance creation) bound the next sign-in under its name — without a limit on time or
  origin, also replacing an origin placeholder, and `federation_require_stable_id`
  changed nothing about it. Measured: a dormant account `jsmith` with admin right, two years old; a
  new directory entry `jsmith` with a foreign identifier took it over including admin. Now only
  `federation_name_binding_days` (default 30, `0` = only explicitly, `-1` = unlimited, anything below
  a setup error) from the source's marker (`foederation_seit:<source>`, set once at the
  first start with the source switched on) or the creation of the account; afterwards rejection as in case 3.
  The same applies without a stable identifier to the first assignment of an existing account.
  `loese_fremde_bindung` opens the binding for one account (table `namensbindung`), the new
  `foederation_nachbinden` binds the existing data explicitly — with the same decision as
  the sign-in (`_nachbindung_grund`). Test: `tests/test_foederation_bestand.py`.
- **A self-chosen name does not bind via LDAP/SAML (G2-N).** A local account `eve` renamed
  itself to `chefin` on the account page, a name that existed only in the directory; the
  sign-in of the real chefin bound her identifier to eve's account, the role from
  `ldap_group_role_map` came with it — and eve kept signing in with her password (pre-existing
  also via `allow_signup`). Now an account from registration (also with invitation) or
  from renaming in self-service carries the marker `users.name_selbst_gewaehlt` and is never bound via
  the name (audit `<source>_namensbindung_zu grund=name_selbst_gewaehlt`); one created by the
  operator or renamed with `durch_betreiber=True` is not. Existing data gets the
  marker once on the first start from the audit log (`signup`/`username_changed` under the current
  name since creation).
- **A name from another source does not bind either (attack round 2026-09-26).** G2-N
  covered only registration and renaming. But an account that OIDC, SAML or LDAP creates carries
  the name the person has THERE — with an IdP that allows self-registration, a self-chosen one
  (`preferred_username`, NameID, `uid`). Measured: `chefin` via OIDC, then the real chefin via
  LDAP — her identifier and the role from `ldap_group_role_map` ended up in the OIDC account, and the
  attacker kept signing in via OIDC; via SAML likewise, with `__admin__` up to the admin flag.
  Conversely, a SAML self-registrant with `uid=chefin` took over the account that LDAP had created.
  Now the creation records the source (`users.name_quelle`), and a DIFFERENT source never binds the
  account via the name (`grund=name_aus_quelle`); the same source still replaces its placeholder
  with the real identifier. A "chosen by themselves" marker for every federated creation (the form
  recommended in the finding) would have broken exactly that: After `ldap_attr_id`, every LDAP account without an
  identifier would have been rejected. Renaming resets the origin. Existing data gets it on the
  first start, once, where it is documented: OIDC (the callback creates every linked account itself)
  and an LDAP/SAML binding from the second of creation; accounts from before the identifiers (up to 0.19)
  stay without and are subject to the deadline. Test: `tests/test_foederation_bestand.py`.
- **`objectGUID` from the raw bytes** (side finding to G1): Without a schema, ldap3 decodes a value
  that happens to be valid UTF-8 to text — a GUID made of bytes below 0x80 arrived as text with
  control characters, the format check rejected it as tampered, and the person never got
  in via LDAP again. `objectGUID` is now always read raw and stored as hex, any other
  `ldap_attr_id` only if its text carries control characters.
- **Identifier space enforced in the database (G12c).** Username and address are one space
  (`find_user` searches both, the lockout counter folds `Alice`/`alice`, `Émile`/`émile`, full-width
  and Unicode/A-label domains together), but the database knew only `UNIQUE(username)` (BINARY)
  and the index on the address. The check happened before writing (`kennung_vergeben`), separately from
  writing: Two simultaneous requests for the same identifier — one as name, one as address, also
  an address change against a registration — both got through, or one ended with a 500.
  Now two triggers over the counting buckets (`trg_users_kennung_insert`/`_update`, only
  built-in SQL functions, via the existing indexes) reject every newly assigned identifier that already
  belongs to another account — in the same statement as the write. The loser of a
  race gets the same answer as for a taken identifier: `ConfigError` from
  `create_user` (`e.besitzer_id` can then be `None`), 409 or the neutral page for
  registration, 409 in the admin API and when confirming an address change (audit
  `email_change_taken … wettlauf=1`), 400 when renaming; an address from OIDC/LDAP/SAML is
  not filled in (audit `<source>_email_taken … wettlauf=1`). The address change in mail mode
  writes address and name in one transaction (`store.adresse_wechseln`). Existing
  collisions stay and can be resolved; new: `store.topf_kollisionen()`, and
  `kennungs_kollisionen()` compares via the counting bucket instead of NOCASE. Anyone who sets the same address again
  keeps their counting bucket (previously it was NULL until the next backfill).
  ⚠️ **For direct store callers:** `store.create_user`/`set_username`/`set_email` raise
  `sqlite3.IntegrityError` ("tinysesam: kennung vergeben") instead of creating a collision.
  **Way back:** The triggers stay in the file and keep working under 0.20.x; remove them with
  `DROP TRIGGER trg_users_kennung_insert; DROP TRIGGER trg_users_kennung_update;`
  (docs/BETRIEB.md, "Kennungsraum"). Test: `tests/test_kennungsraum.py`.
- **No oracle for taken addresses on address change (G12b).** The response was identical,
  but three channels revealed whether an address is already the identifier of another account (measured): The
  notice to the own, confirmed address came only for a free one; the request for a taken one
  returned before the per-account throttle — after three probes of taken addresses the link to
  an own control address still went out, after three of free ones it no longer did; and the account page
  named `email_change_taken` or `_reserved`. Plus the runtime: taken is one row written
  and 417 SQLite steps, free two and 450, plus the send after the response (median in
  one process 2.3 versus 3.9 ms). Now one branch for every target: first the throttles, then in every
  case a token (for "taken"/"reserved" a throwaway token, already expired when
  created, following the pattern of R4-03) and an audit line, then always a sender that sends the
  notice to the own address. The account page maps the event names
  (`own_events`); a rejection on confirming (409) keeps its name. Identical are thus
  response, mails to the requester, quota, display and the sequence of SQL statements.
  **Remaining:** no index hit against a non-hit (microseconds), and the throttle per
  target (`wechsel:<address>`) still reveals whether an address received three
  change requests in the last 15 minutes — regardless of whether it is taken. Test:
  `tests/test_selbstbedienung.py` (G12b), `tests/test_quellenadresse.py` (account page LDAP).
- **Confirmation links from LDAP/SAML: count sends, dampen attempts (G12a).** The daily quota
  (`quellmail:<id>`, in memory per process) was consumed before the attempt: A throttled
  target address or a failed send cost the link for a whole day, and two workers
  on one database sent two on the same day. Now the database counts the send — the
  line `federation_email_confirm … konto=<id>` is created in the outbox and only if the mail
  went out (`Store.quellmail_seit`, via `idx_audit_ts`) —, and likewise the rejection of a
  taken or reserved address (its line `email_change_taken`/`_reserved` begins on
  this path with `konto=<id> quelle=<source>`): at most one completed request per account and day,
  for as long as a link is valid, if that is longer. Dampening the rejection only in memory at first
  was an oracle (attack round 2026-09-26): one more row per worker and until restart, the
  account page of an LDAP user who maintains their own `mail` showed one request for a free address,
  for a taken one one more with each worker. The memory now dampens only the
  transient in the window of the mail throttle. `_token_mail` reports whether the mail went out.
  **Remaining:** If the send to a free address fails, the next sign-in may try again after the
  window — a taken one has no send that could fail. Test:
  `tests/test_quellenadresse.py` (G12a, a1-02).
- **Open one-time links fall with every defense** (self-service attack round, finding 1): The
  password reset (also by the admin) and "end all sessions" discard all open links of the
  account, the password change on the account page and "end other sessions" open
  address changes. Before, an address change that an intruder had
  requested from their session survived the defense — one click on their link afterwards, and the next reset went to them.
  The request itself now goes as a notice to the previous confirmed address, and the mail names the
  account for which confirmation is being made.
- **SAML proof attribute confirms the address, not the name** (finding 1 of the LDAP/SAML round): An
  account name with `@` stays only if it is exactly the confirmed address. Otherwise an IdP with
  self-registration (NameID `bob@example.com`, own address confirmed) would have taken over the local account
  `bob@example.com` via the name.
- **Address change: throttled per account, checked folded.** An account no longer scatters change mails to
  any number of foreign addresses (quota as per target address); the address is first
  folded, then checked (`x＠…@example.com` otherwise produced an address with two `@`). A
  proof attribute consisting of whitespace counts as not set everywhere (before: check "never", runtime "yes").
- **Change requests have their own mail quota** (bucket `wechsel`, like the
  registration notice after attack A2): Anyone with an account requests the change to a still-free address. In the
  shared bucket of sign-in link and reset it would have used up the quota with which the later holder
  of that address sends themselves a sign-in link.
- **TOTP secrets encrypted at rest, mandatory (H-14/H-15).** AES-256-GCM (`cryptography`); the
  key comes from `TINYSESAM_SECRETS_KEY`, `secrets_key_file` or `<db>.key` (0600, next to the
  database — then loudly warned). Existing data is encrypted at startup; a key that does not
  fit aborts startup instead of letting every TOTP sign-in fail silently (also checked against
  the refresh tokens). The key file is created atomically, also with several workers. `tinysesam
  backup` reminds you to back up the key separately. SQLite overwrites deleted data
  (`secure_delete`) so that replaced plaintext does not remain in free pages of the file.
- **Registration without a runtime oracle (ASVS 6.3.8).** With confirmation and name = address, the
  "address taken" branch wrote only an audit line, the free branch account, lock and token —
  measurable in the response time. Now the same work (placeholder with random name, cleared
  by `gc()`). Without confirmation, registration necessarily reveals taken addresses; the
  configuration check warns about it.
- **An identifier belongs to the account only from its joining** (limit a, complete with G2). A
  sign-in clears only failed attempts counted from then on under name or address — not those a
  stranger made earlier under the then-free identifier (they count in the throttling of their
  IP). Until 2026-09-26 the limit was the creation of the account: After a rename, an address change
  or the backfill of an address from OIDC, the first sign-in also cleared the foreign attempts,
  the account page showed the previous owner's sign-in including IP, and deletion rewrote their
  audit lines. This now applies to the full sign-in, the success of the first factor
  (`record_login`), the account page and deletion. The limit is an id watermark per identifier
  (`users.name_versuch_ab`, `mail_versuch_ab`, `name_audit_ab`, `mail_audit_ab`, set in the same
  UPDATE as the identifier): exact even in the second of creation, independent of the clock; merely
  changing the spelling (`B1` → `b1`) does not move it. A raw UPDATE of name or address
  raises it (recalculation trigger, the stricter direction). Existing data: NULL, then as before the creation.
  The series (B2-6) still ends only with the first full sign-in — it has no IP and protects
  only the one to whom the identifier now belongs. Schema stays 11 (additive). Test:
  `tests/test_kennung_beitritt.py`.
- **LDAP: the series under the name in the directory (G5).** After a rename in the directory
  (locally `alice`, bound via the stable identifier, there `alice.neu`) the series (B2-6) counts under
  `alice.neu`, but clearing happened only under `alice` and the address: Own typos added up
  over the years, a stranger locked the person out permanently with enough failed attempts, and the
  documented way out `tinysesam unlock alice.neu` aborted with "no account". Now every
  successful sign-in records the directory name on the binding (`federated_identity.name_topf`), and
  full sign-in, panel reset, `tinysesam passwd` and `unlock` clear it too
  (`store.zaehl_kennungen`) — not if it belongs locally to another account. `unlock` takes the
  identifier as typed and clears even without an account (existing data in which the name is not yet recorded).
- **The PIN behind another factor is a follow-up factor (G7).** The series (B2-6) counts per kind,
  and a self-service reset clears the shares of the first factors (R2-2). The kind was the
  method — it did not know the position: In a chain `password → pin`, the failed attempts of the
  PIN step were booked like those of a first factor, and whoever had mailbox and password got a
  fresh series against the PIN with each reset. Now the path decides: A PIN behind an already provided
  factor — half session in the chain step, full session in a route chain — books under `pin_folge` and
  stays after the reset like TOTP; a PIN as first factor (without a session) still books under
  `pin`, which the reset clears. The full sign-in, the panel reset and `tinysesam unlock` clear
  both. Window and PIN bucket still count as `pin`. Plus two findings on the same path:
  **N1** — with `pin_login=False` a chain `password → pin` was a dead end: The PIN step ran
  via the guest path, and that answered 404. Now `/auth/pin` recognizes the half session like
  `/auth/totp` and asks only for the PIN (without a name field); `pin_login` applies only to the guest path — since
  the review round 2026-09-27 only if the PIN is its chain step (p2 F1, below).
  **N2** — in a strict chain `password → pin`, the guest path without a password answered a
  wrong PIN with 401, the right one with 303: an oracle, and a PIN entered first
  never satisfies the strict chain anyway. The PIN is no longer a first factor there
  (`TinySesamConfig.pin_als_erstfaktor()`, read by login page and `/auth/pin`). In a NON-strict
  chain it remains one; the configuration check then warns and advises `pin_login=False`.
  If the form in the chain step names a different account, it remains an identity switch via the
  guest path (404 if closed). The account page still shows its PIN section where the login page
  no longer offers the PIN, and also with `pin_login=False` if the chain requires a PIN. New
  for own PIN pages: `versuch_beginnen(…, serie_art=auth.SERIE_PIN_FOLGE)`. The lockout notice by
  mail also names the operator as a way out for the series (since the review round 2026-09-27 the reset
  only if it clears the series, below). **Way back:** An older version counts
  `pin_folge` too and clears it only with a full sign-in or by the operator — stricter.
  Test: `tests/test_pin_folge.py`.
- **LDAP: a directory sign-in no longer clears foreign counters (G5-N1).** A filter on
  `mail` also resolves the address of a local account to a third party whose `mail` attribute is that value.
  Every sign-in of the third party reset the account window of the holder — distributed guessing
  without a limit except series and IP limit. `record_login` has `konto=` for this (appended, default
  `None`); the bundled login route passes it through on a directory sign-in.
- **An identifier never checks the secrets of two accounts (review round 2026-09-27, p1-d).** G5-N1
  protected only one direction. Under one identifier, the login route checked the local password of the
  account AND the LDAP password of the entry that can be bound via the stable identifier to ANOTHER account.
  If a local account had the same name as another person in the directory (after a
  rename there, in the panel, in the CLI or in self-service, by registration) or carried
  their directory address (filter on `mail`, `ldap_email_trusted=False`), each of its
  sign-ins cleared window and series under this identifier. Measured with all defaults: 120 failed attempts
  against the LDAP password from one IP, no 429, after which the right password opened the session
  of the person. Now `check_ldap` rejects if the entry leads to a different account than
  `find_user` — bound, via the name or newly created —, before anything is written
  (account, binding, roles, address); the route books a failed attempt. And the name on the
  binding of another account (`federated_identity.name_topf`) is taken: `kennung_vergeben`,
  the identifier triggers of the database (index `ix_fed_name_topf`) and `tinysesam rename`. Test:
  `tests/test_t13_entscheide.py`.
- **After renaming an LDAP account, its old name remains the name in the directory (p1-b).**
  If the account had the same name locally as in the directory, nothing was recorded on the binding; after renaming,
  panel reset and full sign-in no longer cleared the series under the directory name (429 until
  `tinysesam unlock`), and the name was free locally. Now every rename records the old name
  in the same transaction (only with a real identifier, not with the origin placeholder).
- **A stale directory name does not clear a foreign series (p1-a).** After rename and
  reassignment in the directory, two accounts carried the same name; every full sign-in of the
  previous holder ended the series under which the new holder was being guessed against, and `tinysesam
  unlock` named the account with the younger binding. Now the sign-in under the name deletes it
  from foreign bindings, `zaehl_kennungen` also checks foreign bindings, and `unlock` names no account
  when there are two holders (existing data).
- **A writer that carries the counting bucket along raises the watermark (p1-c).** `store.set_email` from
  0.20.1 (after a downgrade) sets address and bucket in one statement — the recalculation trigger
  did not fire, and the first full sign-in cleared the stranger's failed attempts under the new
  address. New triggers `trg_users_wechsel_name`/`_mail`. Test: `tests/test_kennung_beitritt.py`.
- **Route chains no longer fall below the global rule (PO decision 2026-09-27, "align").**
  `require(factors=["password"])` let an account with TOTP onto the route with the password alone,
  `["pin", "password"]` likewise, and under `login_chain=["password", "totp"]` the password sufficed.
  Now the session must first be full for the global rule (`mfa_ok`); a half one goes to its
  missing step (`next_login_step`). No new parameter. Test: `tests/test_t13_entscheide.py`.
- **The deletion promise (H-13) covers spellings, earlier identifiers and the own values (p2 F4,
  already on main).** After deletion, these remained: `login_fail` lines with the RAW input
  (`Émile `, ` emile@…`, full-width), the sign-in under the earlier name including IP, `alt=` in
  `username_changed`/`email_changed` and `neu=`/`an=` of a never-redeemed address change or from
  LDAP/SAML. Now the block scan compares the column `username` in the counting bucket (not if a
  remaining account shares the bucket), earlier names and addresses come from the own
  change lines and apply in their span, and in the own lines `alt=`, `neu=` and
  `an=` are replaced. Test: `tests/test_audit_runde2.py`.
- **The half session checks the PIN only as its chain step (review round 2026-09-27, p2 F1).** Since
  G7-N1, `/auth/pin` accepted any half session. In classic mode with `pin_login=False` and an
  account with TOTP and PIN, whoever had only the password got 401 for a wrong PIN and 303 for the
  right one (0.20.x: 404) — an oracle. In a strict chain `password → totp → pin`, a
  PIN was in the session before the TOTP; its order could never be satisfied afterwards, and every further
  sign-in in the same browser got stuck on it until sign-out. Now the half session (GET
  and POST) counts only if the global `login_chain` requires the PIN, it is still missing and — strictly —
  it is the next step; otherwise guest path or 404. Test: `tests/test_pin_folge.py` (j);
  `tests/test_stepup.py` had pinned the 401 for the classic case and expects 404 again.
- **No oracle via the in-flight window of the outbox (p2 F2).** The line
  `federation_email_confirm` is created only after the send, a rejection immediately, and
  `offener_token` asked only for a link to the SAME address. If the link to `target@` was still in the
  outbox (slow relay), a second worker after a change of the own
  `mail` attribute sent one to `probe@` — if it arrived, `target@` was free; plus two links on one day.
  Now every open address-change link of the account holds it back (`store.offener_token(…, email=None)`).
  Test: `tests/test_quellenadresse.py`.
- **`lockout_serie` exactly at the transition (p2 F3, already on main).** What was logged was the
  series state at booking, including pending pre-bookings: If the holder (right
  password) and an attacker were pending at limit−2 simultaneously and her full sign-in ended the series,
  `lockout_serie` stood in the audit log and "locked" in the security log, although nothing was locked.
  Now the settled state counts: `store.reserve_attempt` returns it after booking (an
  immediately settled booking exceeds the limit there — reported if the series is
  still standing at completion), `store.finish_attempt(…, serie=)` returns it before and after
  completion, both in one transaction (`BEGIN IMMEDIATE`; a pending one exceeds the limit only there). Test:
  `tests/test_vorbuchung_schwebe.py` (real burst with and without pending: exactly one line).
- **LDAP: total deadline so that a running sign-in never counts as a confirmed failed attempt (p2 V1).**
  An open pre-booking counts after `Store.VORBUCHUNG_SCHWEBE_SEK` (30 s) as the failed attempt of a
  dead process. ldap3 knows only a deadline per response (10 s), and a search-then-bind with
  StartTLS waits up to ten times — a slow but answering directory let a still-running
  sign-in count as a confirmed failed attempt: real lockout, lockout mail and `failed login`
  for third parties. Now `ldap_.GESAMT_FRIST_SEK = 25`, distributed over the wait points (the service account
  at most half of the rest); if the rest does not suffice, the directory counts as unreachable
  before it is queried — never as "wrong password". Test: same place (ldap3 dummy with its own clock).
- **The way out of the series depending on kind.** The self-service reset does not clear TOTP and the PIN in the
  chain step (G7); if these alone reached the limit, lockout notice and
  security log still named the reset — the holder reset their password and stayed locked.
  Now they name it only if it lifts the lockout (`store.fehlserie_ohne`), otherwise the operator.
  The login page shows everyone the same text, which names the operator first — a text per kind
  would reveal that someone is guessing at the second factor and the account therefore exists. Test:
  `tests/test_pin_folge.py`.
- **A full queue discards the confirmation link.** If the notice outbox returned the send
  (queue full), the token of the never-delivered link stayed open and held back, via
  `offener_token`, every new one until its expiry. Now it expires immediately; the same applies to
  the address change in self-service (`request_email_change` passes along `senden.verwerfen`, the route
  passes it through as `bei_ueberlauf`). Test: `tests/test_quellenadresse.py`,
  `tests/test_selbstbedienung.py`.
- **LDAP: the first window of an outage no longer locks anyone (G9).** The login route books every
  attempt in advance as a failed attempt (R7-2) and takes it back on a directory outage (F-23) —
  only once the outage is reported, for a directory that drops packets, that is after the
  timeout (up to 10 s; since the total deadline, p2 V1 above, the share of the wait point). Before the
  first timeout the outage marker knows nothing yet: Anyone who
  knocked in those seconds saw the pending pre-bookings as failed attempts. Measured with 15 hanging sign-ins
  behind a NAT address: Alice and the emergency admin with the right password got 429, the
  security log `failed login … reason=lockout_user|lockout_ip` (fail2ban banned the address), Alice
  a mail "Locked sign-in" — afterwards not a single failed attempt was in the table. Now
  the pre-booking of an LDAP sign-in is pending in the database (`login_attempt.offen`, schema stays
  11, additive) until the directory has answered. If a sign-in would fail **only** on pending
  pre-bookings, it waits until they are decided — at most 12 s
  (`ldap_.VERBINDUNGS_TIMEOUT` + 2), at most 8 waiters per process —, and then continues normally.
  Anyone who gets no waiting slot or exceeds the deadline gets 429 as with a lockout (no
  new oracle), but in the security log `deferred login user=… ip=… reason=pending`: no lockout,
  no hit for the fail2ban filters, no lockout notice, and never the text of the series lockout. A
  rule that applies even with the confirmed failed attempts alone locks as before — a burst of
  wrong passwords waits along and then gets the real lockout (R7-2 remains). An open
  pre-booking that nobody completed after 30 s (`Store.VORBUCHUNG_SCHWEBE_SEK`, process
  died) counts as a failed attempt; an unexpected exception in the check turns the attempt immediately
  into one. Also: completion or withdrawal of an attempt and its pre-booking in the series now run
  in one transaction — separately, a waiter read the series in between one too high. New:
  `versuch_beginnen(…, schweben=)`, `store.count_fails(…, nur_bestaetigt=)`,
  `store.reserve_attempt(…, schweben=)` (response `(None, "schwebend")`), `store.finish_attempt(…,
  serie=)`, `store.cancel_attempt(…, serie=)`, `store.fehlserie_bestaetigt()` — all appended, with
  default. `is_locked()` reports a deferral as `True` (with `deferred login`, without mail). Without LDAP
  nothing is pending, behavior is unchanged. **Way back:** An older version does not know the column
  and counts open rows as failed attempts as before. Test: `tests/test_vorbuchung_schwebe.py`.

- **Sign-in locked after 100 failed attempts in a row (B2-6).** The previous thresholds count only
  within the window (`lockout_window_sec`) — anyone who guesses more slowly than the threshold could guess indefinitely. Now
  every failed sign-in attempt under a name extends a series; at the limit
  (`account_max_consecutive_failures`, panel, 10…100000) the sign-in is locked, even with the
  right password, and the lockout **does not expire**. It ends with a full sign-in
  (also via passkey, sign-in link or OIDC), a password reset, a new password from the
  panel or `tinysesam unlock`. Counting is per name, whether the account exists or not — the message
  ("Zu viele Fehlversuche in Folge …") reveals nothing. A wrong attempt that is not a sign-in
  (password change, step-up, area PIN) does not count. `gc()` clears untriggered series after
  90 days of rest, triggered ones never. The series is checked and pre-booked **in the same transaction**
  as the attempt (a parallel burst at the limit gets one attempt, not one per request);
  a correct first factor takes back only its own pre-booking, a directory outage
  does not count. The **self-service reset clears the shares of the first factors** (password, PIN
  as first factor — which anyone can produce, even a stranger without a secret); **TOTP failures
  remain**, as do those of a PIN behind an already provided factor (G7) — the same reason
  as R4-13: The mailbox does not prove the second factor, and these failures are produced only by someone who already has the
  first. The operator clears everything: password reset in the panel, `tinysesam unlock`.
- **Password minimum length 15 if the password alone can sign in (B2-4, NIST SP 800-63B).** New
  passwords (registration, reset, change, panel, CLI) need at least
  `password_min_length_single_factor` (panel, default 15). It applies as long as the global
  chain enforces no second factor — i.e. by default — **and also when accounts may set up the
  required second factor themselves** (`mfa_enrollment` `first_login`/`grace`):
  Whoever knows only the initial password binds their own authenticator there. Only with
  `login_chain=[…second factor…]` AND `mfa_enrollment="strict"` does `password_min_length` (8) apply.
  If you do not want the stricter rule, set the new threshold to 8. The CLI does not know the
  configuration and takes the stricter one.
- **An admin flag granted by the identity provider goes away again when it no longer delivers the group
  (H-5).** Mapped roles were already revoked, the admin flag was "grant only". It now
  carries a mark (`users.is_admin=2`, still a truth value); only this flag is taken back by the
  provider at the next login, with line `idp_admin_revoke`. An admin from panel, CLI,
  `admin_identifiers` or `/auth/claim-admin` stays untouched. Flags from before do not carry the
  mark and also stay. The panel writes the admin flag only on a
  real change — before, every saving of the roles silently turned the 2 into a 1.
- **An IdP address without proof is not used (H-3).** Until now OIDC took over an address without
  `email_verified=true` into the account and passed it on as `Remote-Email`, just without rights in
  TinySesam — a protected app that assigns users by address never saw the mark. Now:
  no account name from it (not even via a `preferred_username` that is an address — Keycloak
  "Email as username", Entra UPN —, checked after Unicode folding, so `＠` too), no address
  in the account, no `Remote-Email`. If the provider delivers the proof
  later, it is backfilled, provided it is free. A provider that never sends the claim (Entra
  ID) needs `oidc_email_verified_default=True`. SAML and LDAP deliver no proof; for them
  the operator decides per source ("SAML and LDAP addresses" under Added).
- **Email collision at OIDC login (F-27)** was already caught (409, `oidc_ident_taken`) and
  now has a test; an unconfirmed foreign address no longer collides at all since H-3.

### Changed

- **The installation guide leads with PyPI.** TinySesam has been there since 0.19.0 (every tag goes
  to PyPI via Trusted Publishing, ADR-6), but both READMEs still said "not on PyPI" and
  sent everyone via Git. Now `pip install "tinysesam==X.Y.Z"`, the Git tag as an alternative; the
  guard in `tests/test_repo.py` that pinned the wrong statement now checks the opposite.

- **The built-in pages carry the subpath (T-15).** Under `uvicorn --root-path /sso` behind
  a proxy that strips `/sso`, or as `Mount("/sso", app)`, forms, links,
  fetch calls and redirects pointed out of the mount until now (`/auth/login` → 404), only the
  links that were sent were right. Now the prefix comes from **one** source: the path of
  `base_url` (where it belongs according to the docs anyway), without `base_url` from the `root_path` of the
  request. This also makes guards of a host app outside the TinySesam mount and the
  forward-auth login URL correct. New: `auth.pfad(request, pfad)` for own redirects to pages of
  TinySesam, `safe_next(next, request)`, `ctx["praefix"]` for own templates (whose output
  otherwise remains unchanged). **When updating:** `login_path`, `login_redirect`, `logout_redirect`
  and `admin_path` are paths of the app **without** prefix — if you entered it by hand until now
  (`/sso/auth/login`), remove it; the configuration check warns about it.
- **Without `next` a sign-in leads to `login_redirect`.** The routes had `next="/"` as
  default, `login_redirect` applied only to an invalid target — different from how the configuration
  describes it ("target after successful login"). With the default `"/"` nothing changes.

- **License as SPDX expression (PEP 639, T-7):** `license = "MIT"` with `license-files`, the
  license classifier is dropped. Building thus needs setuptools ≥ 77 (`build-system.requires`); the
  old table form is no longer accepted by setuptools from 2027-02-18.

- **PIN as first factor remains allowed — recorded as a decision (B2-8, ADR-8).** Nothing
  changes in behavior; the PIN attempts (`pin_max_attempts`) now sit in the panel right next to the
  login lockout, PIN failures count in the series (B2-6). README and `docs/BETRIEB.md` show the
  pattern "general page with PIN, detail page with `require(factors=["pin", "password"])`".
- Order of the hardening values in the panel: what is set together is placed together.
- **The panel names the reason for a lockout** (limit b): "locked (confirmation / app)" (lifted by the
  confirmation link) instead of just "locked" (operator). Until 2026-09-26 the text did not reach the
  panel (the list of panel texts did not know it, the badge stayed empty), nor did the texts of the
  owner buttons — and "Make owner / Give up owner" was never wired, the click did nothing
  (G3). A test now checks every text the panel script reads and every action a button
  names (`tests/test_admin_konto.py`); the browser test clicks the owner button and "Rename".
- **Indexes on the audit log** (limit c) for search by name and time. The search in the detail text
  on deleting an account is narrowed by no index (substring) — it remains a scan, but ran in
  ONE write transaction: With a large log, every sign-in and every other worker waited out the
  whole search. Since G4 it reads in blocks by `id` (5000 rows) without a write lock and writes
  only the hits in short transactions, the row read fresh there (`tests/test_audit_runde2.py`,
  120,000 rows).
- **Chain with mandatory setup (password → totp → pin): the offer to end the other sessions
  returns** (limit d, ASVS 7.4.3). The page asks after the setup; the consent is
  redeemed as soon as the last factor is confirmed (`/auth/sessions/revoke-after-login`,
  response field `other_sessions_after`).


- **The button in the release workflow is a dry run.** Triggered by hand (`workflow_dispatch`),
  `release.yml` checks and builds everything, including the image for both platforms, but publishes
  nothing — no release, no PyPI, no image in the registry, no attestation. Before, the button would
  have failed at the tag comparison (a branch name is not a tag). Without a tag,
  `scripts/_release.py --pruefen` checks the version states; `tests/test_repo.py` pins that every
  publishing job depends on the tag.

- **Test base on kit 0.21.8:** The kit check that looks for `splitlines()` closes its files again
  (CodeQL `file-not-closed`, rejected as a kit finding in 0.20.1 and fixed at the source). Newly
  wired: `pruefe_veroeffentlichen_am_tag` — in a tag-triggered workflow with a button,
  nothing publishes without a tag (the general version of the guard from the release dry run).

## [0.20.1] — 2026-09-24

**Security follow-up — apply promptly if you use a second factor or API keys.** Via
`/auth/reauth`, API key and password replaced the second factor; via `/auth/pin`, automation key and PIN
became a full admin session (both pre-existing, see "Security").

Follow-up to 0.20.0. Two consumers reported findings **in** TinySesam while lifting:
Both had to rebuild TinySesam for the CSRF cookie of their own pages, and the promise "fresh
CSRF token on login" held only at the end of a TOTP step. The attack on these changes
also found a pre-existing hole in step-up (`/auth/reauth`, see "Security"), and a second round
the same class in `/auth/pin`: Automation key and PIN became a full admin session. No
schema change, no new configuration.

**Before updating:** nothing to set. Good to know:

1. **After a sign-in, the CSRF token from before is no longer valid.** A form opened in
   another tab before the sign-in answers once with 403. Tests that keep sending a token read before
   the sign-in afterwards do likewise — read the token from the cookie again after the sign-in.
2. **Anyone who combines `csrf_cookie_name` + `issue_csrf()` + a copied Set-Cookie line for own
   pages** can replace that with `auth.ensure_csrf(request, response)`. Anyone who, after an
   own sign-in, renders a form in the **same** response, gets its token with
   `ensure_csrf()` **after** `set_cookie()` — via the FastAPI response parameter. A finished
   response (Jinja's `TemplateResponse`) is then already rendered, its form would carry the old
   token (403): A response that signs in or out redirects instead of delivering a form.
3. **`/auth/reauth` answers an API key with 403** (`api.stepup_session`). A key could never
   confirm anything there — it does not reach step-up freshness —, but the route accepted it and
   could be abused with it (see "Security"). Anyone calling it from an automation
   now gets the rejection instead of an ineffective 303.
4. **For `/auth/pin` an API key is a guest.** Without a full session, the POST answers with 404 for
   `pin_login=False` and the GET redirects to the sign-in; with `pin_login=True` the
   PIN needs the user field as with any guest. As an additional factor without a user field, the PIN applies only
   to a session. The same applies to the TOTP step, the TOTP setup and
   sign-out: They see only the account from the cookie. **Own routes** that call `apply_factor()` for
   "the signed-in account" or refresh the session take the account from the new
   `auth.session_user(request)` instead of `current_user()` (see "Security").

### Added

- **`auth.session_user(request) -> Optional[dict]`** — the account of the full session of this
  request, never from an API key; a half session returns None (that is read by `pending_user()`).
  Without a full session `current_user()` falls back to the key and is thus the wrong source
  for every place that applies a factor to the session (`apply_factor`, `complete_totp`),
  refreshes it or ends it (see "Security"). The built-in routes have taken the account there
  from here since; the rule is in the docstring of both methods.
- **`auth.ensure_csrf(request, response) -> str`** — ensure a valid CSRF cookie and
  fetch the token for the form, without rebuilding TinySesam. An existing, valid token
  stays (no Set-Cookie line, the forms of other tabs remain valid); otherwise it sets a
  new one, with the same attributes as `issue_csrf()`. If the response has already rotated the token
  (sign-in) or deleted it (sign-out), it returns the new one or sets a fresh one — never the old one
  from the request. For finished responses (Jinja's `TemplateResponse`): `csrf_token(request)` before
  rendering, `ensure_csrf(request, response)` after; both return the same token in the same request
  — not in a response that signs in or out: The page is rendered before the token
  changes, its form would carry the old one. Redirect there (added after the attack on the
  change: the promise "same token" had silently not held at this point, fail-closed
  with 403; `tests/test_csrf.py` pins the limit and the way out). Examples for template and
  JS in both READMEs ("CSRF on own pages"). Before, there was only `issue_csrf()` (always rolls
  anew — the "form expired" trap in the other tabs) and `csrf_token()` (sets
  no cookie).
- **The properties are in the frozen API surface** — `session_cookie_name`,
  `csrf_cookie_name`, `resource_cookie_name` (`tests/api_surface.json`, new section
  `TinySesam.eigenschaften`; `API.md` with its own section). The guard explicitly excluded properties until
  now: Precisely the names to which section 0.20.0 sends every embedding
  app could be silently renamed. A self-check in the test requires the three and
  measures that a rename is reported as a break — even before `--update`.

### Changed

- **Test base on kit 0.21.6:** The hygiene checks give line numbers like the editor
  (before, `splitlines()` shifted them past U+2028 and relatives).

- **A CSRF cookie that does not look like a token is replaced** instead of adopted — in
  `render_page()`, `csrf_token()`, `ensure_csrf()` and in the admin panel alike: only `A–Z a–z 0–9 _ -`,
  32 to 128 characters. Before, any cookie value landed unexamined in the form field. The comparison
  of the double submit (`verify_csrf`) is unchanged.
- **The admin panel sets its CSRF cookie via `ensure_csrf()`** and thus with the same
  attributes as every other setter.
- **`issue_csrf()` and `csrf_rotieren()` replace a CSRF line** that the response already carries,
  instead of appending a second one.

### Security

- **Every sign-in rotates the CSRF token, sign-out deletes it** — as the docstring of
  `csrf_rotieren()` promises ("on login"; OWASP CSRF Prevention Cheat Sheet: "changes with each
  login"). It was called only at the end of a TOTP step. Password, PIN, sign-in link,
  registration, OIDC, SAML and passkey left the token standing, and `auth.logout()` did not delete the
  cookie: The token survived sign-out and re-sign-in until the browser was closed.
  Now centrally instead of per route: Every session row is created in `_sitzung_anlegen()`, one that is
  already fully signed in there is noted, and `set_cookie()` rotates the token in the same response.
  This applies to every built-in path and to an app's own sign-in route (`start_session` +
  `set_cookie`). A step-up (`/auth/reauth`, TOTP on a full session, `rotate_session`) and the
  first step of a chain do not rotate. `logout()` — thus also `POST /auth/logout` and
  sign-out via GET from the own page — deletes the CSRF cookie with Secure and path; the next
  page sets a fresh one. `tests/test_csrf.py` runs through every sign-in path individually (old token
  403, new one valid, the follow-up page renders with the new one), a guard over the source code pins
  that sessions are created only in `_sitzung_anlegen()` and the session cookie is set only in
  `set_cookie()`.
- **`/auth/reauth` confirms only a session now, never an API key — key and password replaced
  the second factor there** (pre-existing, reproduced on 0.20.0; found in the attack on the
  CSRF changes). The route checked the factor of the account from `current_user()` and then made
  the session from the cookie full. With a **half** session (first factor provided, TOTP
  open), `current_user()` falls back to the API key, so check and effect hit
  different things: With the session cookie of a half-signed-in other person, one's own
  automation key and one's own password, their session was fully signed in without their TOTP ever
  being asked. In one's own account, automation key and password replaced the TOTP and brought back the
  admin flag that an automation key alone does not carry (R6-5). Prerequisites were a
  valid API key (`apikey_enabled`) and — for the other account — its half session cookie.
  Now `GET` and `POST /auth/reauth` answer an account that does not come from the session with
  403 (`api.stepup_session`) before any factor is checked; a key can never reach step-up freshness
  anyway (`stepup_fresh()`). `tests/test_stepup.py` reproduces both paths and
  checks that the step-up of a full session continues to work via TOTP.
- **`/auth/pin` turned automation key and PIN into a full admin session — even with
  `pin_login=False`** (pre-existing, reproduced on 0.20.0; second attack round against 0.20.1,
  the same class as `/auth/reauth` above). `pin_submit` read "already signed in" from
  `current_user()`, and without a full session that falls back to the API key. A pure
  key request without a cookie thus counted as signed in: The bolt `pin_login=False` ("the PIN is
  not a first factor") did not engage, the PIN of the key account was checked, and `apply_factor()` created
  a new, full session for lack of one — including the admin flag that an automation key never carries
  (R6-5), and thus admin panel, key management and factor setup. With the half session
  of another person in the cookie, the same request replaced their cookie. Prerequisites were a
  valid key (`apikey_enabled`), `pin_enabled` and the PIN of the key account; with `pin_login=True`
  the PIN is a first factor anyway, the key gained nothing there. **Now centrally instead of per
  route:** The account of a place with session effect comes from `auth.session_user()` (new, see
  "Added"), for which a key is "not signed in" — in `/auth/pin` (GET and POST),
  `/auth/reauth` (the bolt from above now runs through it), the TOTP step, the
  TOTP setup and sign-out. Going through the class, two more harmless places
  turned up: The TOTP step checked the code of the key account on the full session of a locked account,
  and sign-out logged the key's account for a key without a session. A guard in
  `tests/test_stepup.py` reads every function of the package: Whoever creates a session, attaches a
  factor to it, refreshes it or ends it must not take its account either directly or via a
  local helper from `current_user()`, `require_user()`, `require_role()` or `require_admin()`;
  self-probes pin that it sees every promised form. The behavior probe
  next to it reproduces the path (key + PIN → 404, no session, no admin; half foreign session
  stays unchanged; the PIN as additional factor of a full session continues to work).

### Fixed

- **Docs: backup before the update if the installation is at 0.17.x or older.** The
  note "before the update `tinysesam backup`" did not work out there: The subcommand exists only
  since 0.18.0, and the first start of the new image already migrates. Both READMEs and the
  0.20.0 section now name the way: take the backup with the new version before it starts
  (`docker compose run --rm --no-deps --entrypoint tinysesam <service> backup …`, for the
  library after installing and before the restart), or, with the service stopped, copy the `.db`
  together with `-wal`/`-shm`. Reproduced on a file created with 0.16.0: The backup
  carries the old schema, the source stays unchanged.
- **Docs: the CSRF cookie name in own JS.** "Own JS reads the CSRF name from
  `auth.csrf_cookie_name`" (0.20.0) was shortened: JavaScript cannot read a Python property. The
  page passes the name on via a template variable or `<meta>`, or the script takes the
  token from the form field of `ensure_csrf()`. Clarified in the 0.20.0 section, in both
  READMEs and in `KONFIGURATION.md` (`cookie_host_prefix`).
- **Docs: 0.19.0 promised too much for factor setup.** Behavior change no. 3 said that the setup
  too (`totp/setup`, `passkey/register/*`) requires a freshly confirmed session. The code
  requires an interactive session there (`require_session()`, no API key), not a fresh
  confirmation — that is also what the finding further below says. The sentence is corrected with a date, the code
  stays.

## [0.20.0] — 2026-09-24

**Security release, with breaking changes — every installation should apply it, but not blindly.**
It closes the remaining three 1.0 blockers of the third audit (F-11 stable identifier for LDAP and
SAML, F-12 LDAP transport, F-16 SP identity) and the remaining findings from T-13; afterwards
the merge itself was attacked and hardened.

**Before updating:**

1. **Take a backup** (`tinysesam backup`). The database moves from schema 8 to **10**; a
   downgrade to 0.19.x needs the backup. **From 0.17.x or older** (added in 0.20.1):
   The subcommand exists only since 0.18.0, and the first start of the new image already migrates.
   So take the backup with the new version before it starts — `docker compose pull`,
   then `docker compose run --rm --no-deps --entrypoint tinysesam <service> backup --db
   /data/gateway.db /data/vor-update.db`, only afterwards `docker compose up -d`; for the library
   `python -m tinysesam backup --db … <target>` after installing, before the restart. `backup`
   opens the source read-only. Or stop the service and copy the `.db` together with `-wal` and `-shm`.
2. **Everyone is signed out once after the update** (`__Host-` cookies).
3. **Check own JS and own routes:** read the CSRF cookie name from `auth.csrf_cookie_name`
   (not from `cfg.csrf_cookie`, not hard-coded `tinysesam_csrf`); own JS gets it from
   the page, via a template variable or `<meta>` — a Python property cannot read it
   (clarified in 0.20.1; since 0.20.1 `auth.ensure_csrf()` sets cookie and token for own
   pages). Set the token returned by `complete_totp()` into the cookie; sign out via
   `POST /auth/logout`.
4. **Check the configuration:** `ldap://` without StartTLS is a setup error, as is text instead of a number
   in number fields (`smtp_port="587"`). Set `base_url` if mail or SSO is involved.
5. **If you adopted the nginx template**, pull in the `map` lines.

The details follow — first the points from the blockers, then "T-13: the remaining findings" and
"T-13: attack on the integration".

**Behavior change.** `ldap://` without StartTLS is now a **setup error**. Anyone who talks to a
directory in plaintext has to say so explicitly with `ldap_allow_plaintext=True`.
→ **To do:** either `ldaps://` in the URL, or `ldap_start_tls=True`, or set the switch
(only sensible if the traffic never leaves the machine).

### Changed

- **The release script now replaces only pins** (`scripts/_release.py`): Before, it rewrote every
  occurrence of the old version, including narrative text like "0.19.0 raised to schema 8". It
  now also recognizes the German section `[Unveröffentlicht]`.
- **Test base on kit 0.21.5** (from 0.18.0). Newly wired: `pruefe_testdateien_gerufen` asks
  from outside whether every test file has a runner — an unwired test passes its own
  call check by staying silent. The secrets fence knows `pat` assignments and the
  `nbp_` format; the name fence also checks word components. The CI records the state of the tree
  before the suite and checks against it afterwards: Since kit 0.20.1, the backlog check without a
  before-state reports only "not decidable" (exit 2) instead of a documented backlog. Since
  0.21.2 a collector (`tests/run_all.py`) counts only if a runner also calls it.

- **The container image builds on Python 3.14** instead of 3.12 (`python:3.14-slim`, pinned
  by digest). 3.14 is the upper bound of the supported matrix; before the switch it was checked that all
  extras install and import in the target image.

### Security

- **Every `actions/checkout` sets `persist-credentials: false`** (nine places, no exception).
  **Level of this rule: own hardening, not a documented standard** — GitHub recommends it nowhere
  explicitly. What it brings: By default, checkout stores the token in a way that **any
  later step in the same job** can read it. Since v6 it lies under `$RUNNER_TEMP` instead of
  `.git/config`, so the risk is smaller than the often-cited reasoning suggests — but it
  does not disappear, and after checkout foreign code runs here (`pip install -e`,
  third-party actions). No exception needed, because no job of this repo pushes or tags via git;
  measured, not assumed.

- **Dependabot bundles only patch and minor now** (`update-types`). A major would otherwise land in the
  monthly group PR and be waved through with it: The same check that suffices for three harmless
  patches would then also decide on a version jump with a break. Majors come individually
  — there the package's CHANGELOG is the work, not the green tick of the CI.

- **LDAP and SAML bind to a stable identifier, not to the username** (F-11, schema 9).
  A name is not forgery-proof: Anyone who renames in the directory or recreates a deleted account
  under the same name got, up to 0.19.0, **the same local account including its
  roles** — without knowing the local password. Together with the unchecked SP identity
  (F-16) this was the account takeover that the audit report rated critical. OIDC had its own
  mapping from the start with `issuer`+`sub`; LDAP and SAML had none.

  Mapping is now done via `objectGUID`/`entryUUID` (LDAP, `ldap_attr_id`) or the
  `NameID` (SAML, `saml_attr_id` for IdPs with transient NameIDs). Four cases, and the third
  is the bolt: Identifier known → this account, **even if the name changed**. Identifier
  unknown and name free → create and bind. Identifier unknown, but the account of this name
  already carries a **different** identifier → **reject**, with an audit line. Identifier unknown and the
  account still unbound → **rebind**, once, also logged.

  The rebinding is the path for existing data: Accounts from before this version have no
  identifier, and at some point each one has to go through it. It relies one last time on the
  name — and never again afterwards. Anyone who has really moved in the directory releases the binding
  explicitly (`auth.loese_fremde_bindung("ldap", uid)`); that this is a deliberate step
  and not a side effect of a sign-in is the point.

  **If the directory delivers no stable identifier**, it stays with the name — the unprotected
  state —, and one line per source in the security log says so.
  `federation_require_stable_id=True` turns that into a rejection. The default is the soft
  version, so that nobody is left standing at a locked door after the update.

- **The SAML self-description no longer listens to the requester** (F-16). python3-saml builds from
  `https`, `http_host` and `script_name` the address it considers its own, and uses it to compare
  the `Destination` of the assertion. These three values came from `X-Forwarded-Proto` and the
  `Host` header — so the requester helped determine the comparison: They presented an assertion
  whose `Destination` names their host, and set the header to match. The check
  succeeded although the assertion was never meant for us. Together with binding via the
  bare username (F-11) this was an account takeover without knowing the local password.

  The `req` set now comes from `saml_.request_kontext()` and thus from the **checked
  base** — the same one from which entity ID and ACS URL are built. All three values say
  the same thing, and none listens to the requester. The path part of an app mounted under a subpath
  travels along, but not twice.

- **The service account's password went over the wire in plaintext** (F-12). With
  search-then-bind, `auto_bind=True` was in the connection and `start_tls()` one line later:
  The bind was thus done before the line was encrypted. An eavesdropper needed
  no attack, only patience — and on **every** sign-in, because the search runs every time.
  Now `AUTO_BIND_TLS_BEFORE_BIND` switches to TLS first; the user connection did it
  right from the start.

- **The directory's certificate is checked** (F-12, `ldap_tls_verify`, default on).
  `ldap3.Server(...)` without `tls=` checks nothing at all — encrypted thus meant only "not
  readable by someone who is not sitting in between". Anyone who redirects the traffic holds out their own
  certificate, gets both passwords and passes the response on to the real directory;
  for both sides the process looks normal. An internal CA belongs in
  `ldap_tls_ca_file`; `ldap_tls_verify=False` remains possible and reports itself at setup.

- **Plaintext is no longer a default** (F-12, `ldap_allow_plaintext`, default off). Up to 0.19.0
  `ldap://` without StartTLS was the delivery state, and the configuration check said nothing
  about it. Now setup fails with a text that names both ways out.

### Security — T-13: the remaining findings of the audit report

Ten areas, **161 items fixed**, 2 were already done, 6 stay open with justification
(backlog T-13). Every fix was then specifically attacked and improved.

**Behavior changes — read before updating:**

- **Everyone is signed out once after the update.** Session, CSRF and unlock cookies are now called
  `__Host-tinysesam_*` (where the browser allows it). Own code takes the CSRF name from
  `auth.csrf_cookie_name`; own JS gets it from the page (template variable or `<meta>`,
  clarified in 0.20.1 — which also brought `ensure_csrf()`). Turn off: `cookie_host_prefix=False`.
- **Signing out is a POST** (`POST /auth/logout` with CSRF). A `GET` from a foreign page asks first.
- **Sign-in and confirmation links redeem only by button** (POST), no longer on opening —
  mail scanners no longer consume them that way.
- **Login lockout counts per account+IP**; a stranger no longer locks an account out. New threshold
  `account_attempt_factor` per account across all IPs.
- **LDAP groups compare by DN components**, not by substring. A key that would now match only
  as a substring reports itself once in the security log.
- **Password reset by mail revokes the API keys**; pure SSO accounts get no reset link.
- **`set_security()` checks limits** and raises `ConfigError` instead of silently accepting.
- **New blocklist for passwords** at every setting place (offline, extensible).
- **SMTP checks the certificate** (`smtp_ca_file` for own CA).
- **Never-confirmed accounts** are cleared by `gc()` after the link expires.
- **Schema 10** (first start migrates): indexed counting buckets, operator mark on panel locks.
  Back up first (`tinysesam backup`) — a downgrade needs the backup.
- **The CSRF cookie is called `__Host-tinysesam_csrf` even with `cookie_domain`.** Anyone who sets it themselves
  or reads it in JS takes the name from `auth.csrf_cookie_name` (not from `cfg.csrf_cookie`); it reaches
  JS via the page, via a template variable or `<meta>` (clarified in 0.20.1).
- **Break: `complete_totp()`/`complete_mfa()` rotate the token on step-up too** — the
  returned token belongs in the cookie, otherwise the user is signed out.
- **Text instead of a number in number fields of the config is a setup error** (e.g. `smtp_port="587"`
  straight from an environment variable) — convert with `int()` yourself beforehand.
- **Self-registration creates the address as unconfirmed** until the link is redeemed
  (exception: invitation to exactly this address).
- **`trusted_redirect_hosts` no longer count as own origin** in the CSRF origin check;
  behind a proxy that rewrites the host, set `base_url`.

#### Session, cookies, CSRF

**Security**
- Session, CSRF and unlock cookies are now called `__Host-tinysesam_session`, `__Host-tinysesam_csrf` and `__Host-tinysesam_runlock`, where the browser allows it (Secure, no `cookie_domain`, `cookie_path="/"`). The CSRF cookie and the flow cookies of OIDC, SAML and passkey are always host-only and carry the prefix even with `cookie_domain` set. Where the prefix applies, a neighboring subdomain can no longer plant cookies (cookie tossing, login CSRF). Without `__Host-` on the session cookie, i.e. with `cookie_domain`, `cookie_host_prefix=False`, a different `cookie_path` or `cookie_secure=False`, it can still set the session cookie (known limit, SECURITY.md). Turn off with `cookie_host_prefix=False`. **Break:** After the update everyone is signed out once. Own code takes the name from `auth.csrf_cookie_name` instead of from `csrf_cookie`; own JS gets it from the page, via a template variable or `<meta>` (clarified in 0.20.1). (H-1, F-02, A-1, A-7)
- The CSRF check examines the origin before the token comparison: With `Sec-Fetch-Site: same-origin` it is passed, otherwise a set `Origin` must be an own host. Foreign origin and neighboring subdomains get 403. **Limit:** If a usable `Origin` is missing (absent or `null`) and `Sec-Fetch-Site` is missing too, the token alone decides. This applies to every browser over HTTP (`cookie_secure=False`, except `localhost`), because browsers send `Sec-Fetch-Site` only to HTTPS. There, a neighboring subdomain with `Origin: null` gets as far as the token, and without `Secure` the CSRF cookie carries no `__Host-`. Over HTTP the origin check therefore does not protect against login CSRF from the neighborhood. Behind a proxy that rewrites the host without setting `X-Forwarded-Host`, browsers without `Sec-Fetch-Site` fail (Safari before 16.4, every browser over HTTP). For that, set `base_url` or, if need be, `csrf_origin_check=False`. (H-2, A-3)
- An area unlock issues a new unlock token every time, a planted token holds nothing afterwards (F-01). Logout also ends the area unlocks of this browser (F-08).
- A step-up (reauth or renewed factor) gives the session a new token. Lifetime, sign-in time and cookie kind ("stay signed in" yes or no) are retained. (F-06, A-2)
- `GET /auth/logout` from a foreign page no longer signs out but asks. New is `POST /auth/logout` with CSRF check. (F-07)
- `POST /auth/sessions/revoke` requires a fresh confirmation (`X-TinySesam-Reauth`). `GET /auth/sessions` requires a real session, an API key is not enough. (F-09)
- `csrf_enabled=False` together with `cookie_samesite='none'` aborts setup. (F-03)
- `cookie_secure=False` on a request over HTTPS (also behind a TLS proxy) appears once per instance in the security log. (F-04)

**Changed**
- Factor changes (TOTP, PIN, passkey) report `other_sessions` in the response. The account page and the TOTP setup then offer to end the other sessions. With mandatory TOTP setup during sign-in, the offer comes only if the confirmation completes the sign-in (TOTP is the last step of the chain). **Known limit:** If another step follows (`password → totp → pin`), the setup reports `other_sessions: 0`, and the PIN step afterwards offers nothing either. The offer is then dropped entirely, the way to the other sessions is the session list on the account page. If the confirmation is too old, the path leads via reauth back to the account page (`?revoke_others=1`), where it is asked once more. (B1-7, A-5)
- `set_cookie(response, token)` now aligns the cookie kind without `remember` with the session to which the token belongs. Before, the default was always "persistent". With an explicit `remember` everything stays as before. (A-2)
- New: `auth.session_cookie_name`, `auth.csrf_cookie_name`, `auth.resource_cookie_name`, `auth.flow_cookie_name(base)` as well as the config fields `cookie_host_prefix` and `csrf_origin_check`.

#### Headers and injection in pages

**Security**
- Every response of a TinySesam route now carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` and `Vary: Cookie`. This also applies to raised errors (401/403/redirects via `exc.headers`), to the 422 of input validation and to the error pages and the JSON 500 from `install_error_pages`. The 422 is still built by the handler the app registered for it. Routes of the host remain untouched (route class instead of middleware). With `csp='strict'`, `X-Frame-Options: SAMEORIGIN` is added. (R8-5, R4-08, R5-2, A2)
- The admin panel runs under the same nonce CSP as the other pages, without inline handlers and without `style=`. (R8-1)
- Escaping: `rp_name` in the admin panel (R8-3), key, passkey and session fields on the account page (`esc0` replaces all five HTML special characters, R8-6), username in the showcase on `/demo` (R8-2).
- `csp`: A typo like `'Strict'` or a policy without a single known directive aborts setup instead of silently turning off the CSP. `pruefen()` also reports this afterwards. An unknown directive next to known ones (e.g. `require-sri-for`, `disown-opener`) produces only a warning, because the browser applies the rest of the policy. (B3-2, A3)

**Fixed**
- The hardening headers in `exc.headers` no longer lowercase existing keys. An exception handler of the host that reads `exc.headers["Location"]` redirects correctly again for the admin panel without a session. (A1)

#### OIDC, SAML, LDAP (incl. proxy templates)

**Security**
- **OIDC: PKCE (S256) is always on** (F-20, H-12). The verifier stays on the server, an intercepted code cannot be redeemed without it.
- **OIDC: ID token without `exp` is rejected** (F-25). A few seconds of clock lead at the IdP are tolerated (`leeway=60`, F-26).
- **OIDC: An error response from the IdP on discovery or JWKS is no longer cached** (F-24).
- **SAML: SHA-1 in signature or digest is rejected** (F-21).
- **SAML: The ACS is rate-limited, and every substantive rejection (group, no account, locked) appears with reason and IP in the audit log** (F-22).
- **LDAP: Groups are no longer compared by substring** (F-19). `group_match` now also applies to LDAP. A `memberOf` DN matches as a whole DN, as a partial DN from the front (`cn=admins,ou=groups`) or via the CN (`admins`), each only with whole components. So `admin` no longer matches `cn=nicht-admin,…`. This also applies to `ldap_allowed_groups`. **Behavior change:** A key that matched only as a substring (e.g. `ou=groups` or `staff` for `cn=staffextern`) no longer matches. The security log reports it once on the first affected login. `group_match="substring"` brings back the old comparison.
- **LDAP: A directory outage is not a failed attempt** (F-23). The login route answers with 503 and writes an audit line `ldap_unavailable`. Neither a lockout nor a `failed login` for fail2ban is booked against LDAP users. A wrong **local** password counts as a failed attempt even during the outage, otherwise the local emergency account could be guessed without limit (A-1). Connection timeout 10 s.
- **No reset link for pure SSO accounts** (H-4): Accounts bound to OIDC, LDAP or SAML that have no local password get no reset link. The outward response stays the same. If an account comes from a directory without a stable identifier, TinySesam still remembers the origin at login (A-4). If a real identifier comes later, it replaces this mark.
- **Proxy templates: The TinySesam cookies no longer go to the protected app** (B-20, A-2, A-5). Caddy and both nginx templates remove all `tinysesam_*` cookies (session, unlock, CSRF, also with `__Host-`/`__Secure-`) before the app or before PHP and leave other cookies alone. Traefik cannot remove individual cookies. `traefik.yml` names the gap and brings the middleware `tinysesam-cookies-weg` for apps without their own cookies. **Existing installations: update your own proxy configuration.** Anyone who has renamed cookies enters the names into the pattern.
- **nginx templates set `X-Forwarded-For` in the sub-request themselves** (NEU-1). Before, the value sent by the client arrived at TinySesam and determined rate limit, IP lockout and fail2ban.

**Changed**
- LDAP sign-ins and local sign-ins are separated in the audit log (`login_ldap` / `login_lokal`), `login_fail` names `quelle=` (F-29).
- The configuration check no longer names `ldap_enabled` as a remedy for "no method" and warns on LDAP without `password_enabled` (F-30).
- Caddy template: comment and test on the Go-canonical spelling in `{rp.header.…}` (H-16).

#### Mail paths and registration

**Security**
- **One-time links no longer redeem via GET (R4-02).** `GET /auth/magic/{token}` and `GET /auth/verify/{token}` now show only a confirmation page (new page `magic_confirm`). Redeeming is done via `POST` with a CSRF token. Mail scanners and preview bots thus no longer consume the link and sign nobody in. **To do:** Anyone who replaces the page `magic_confirm` via `set_template` or redeems the link via GET themselves switches to POST.
- **No account probing via registration (R4-03, improvement A1).** With `signup_verify_email`, a taken address answers like a free one, and the holder gets a notice without a token. The username is now checked before the address. With a taken address, a locked placeholder without an address occupies the name, and `gc()` removes it after expiry. A username must not be someone else's email address (new message `err.username_is_address`). Without confirmation it stays at 409.
- **Throttle per target address (R4-04, improvement A2):** `mail_per_address_max` / `mail_per_address_window_sec` (3 per 15 min) for sign-in link and reset. Rejection is invisible, the audit log shows `mail_ratelimit`. The registration notice has its own bucket so that strangers cannot lock the holder out of their own links.
- **Sending after the response (R4-05, B6-6).** The built-in routes send via their own mail worker (`mailer.Postausgang`) with a capped queue. This removes the timing oracle, and a hanging mail server no longer occupies the thread pool.
- **Email normalization (R4-06, improvements A5/A6).** `norm_email` folds via NFKC and writes umlaut domains as A-labels. `valid_email` rejects invisible characters and script mixing, but allows the scripts of one language together (kanji with kana, hanja with hangul, Han with Bopomofo). Existing addresses in Unicode form are still found by the search, even if the input comes as an A-label.
- **Never-confirmed accounts are cleaned up (R4-09).** `gc()` and `tinysesam gc` remove them as soon as the confirmation link has expired (counter `unverified_accounts`).
- **Links go to the stored address (R4-11)**, not to the input.
- **Failed send (B6-5, B6-12).** The token expires immediately. If the confirmation mail of a registration fails, the account is rolled back instead of lying around as a corpse with HTTP 500.
- **Invalid one-time tokens leave a trace (B5-18, improvement A3).** They appear in the audit log as `token_invalid`, globally capped at 20 per minute plus a line `token_invalid_throttled`. In the security log each appears as `failed verification` (not the login jail). `GET /auth/reset` without a token does not count.
- **SMTP TLS checks certificate and hostname (B3-1, improvement A4).** An own CA is given via `smtp_ca_file`. **BREAK – To do:** A relay with a self-signed certificate now needs `smtp_ca_file`, and a relay via IP address needs as `smtp_host` the name from the certificate. Otherwise no mail goes out any more. A missing `smtp_ca_file` path is a setup error. `smtp_host` as an IP address triggers a warning at startup. A certificate error on sending names the remedy in the log.

#### Lockouts and throttling

- **Atomic lockouts (R7-2, R3-2, R3-7):** Login, TOTP, PIN, area PIN, step-up and password change now check and book an attempt in one step (`versuch_beginnen()`, `Store.reserve_attempt` with `BEGIN IMMEDIATE`). A parallel burst no longer gets over the lockout limit.
- **No more foreign lockouts (R7-6/H-8):** The first threshold of the login lockout applies per pair of account and IP (`max_login_attempts`). Per account, a higher threshold applies across all IPs (new: `account_attempt_factor`, default 3). A single stranger no longer locks the holder out, distributed guessing remains limited. **Behavior change.**
- **Account threshold counts under the folded identifier (R7-6/H-8, re-check):** Counting happened under the raw typed identifier. Variants like `' opfer'` or `'OPFER\t'` hit the same account but each filled a counter of its own, so the account threshold bound nothing. Now all paths count, clear and unlock (`tinysesam unlock`) under the same identifier, trimmed and lowercased (`norm_kennung`).
- **Area PIN (R7-3):** per IP `resource_max_attempts`, per area `account_attempt_factor` times that. A stranger no longer locks an area for everyone. **Behavior change.**
- **Full sign-in clears all sign-in failed attempts (R7-1):** new `sperre_aufheben()`, for username and email. The own buckets of account page, step-up and area stay.
- **Reset lifts the password lockout (R4-13/H-10):** The number appears in the audit log, TOTP and PIN failed attempts stay.
- **Redis outage (B6-1, B6-2):** Fallback to an in-memory limiter instead of "allow everything", ping at startup, one message each for outage and return, pause after an error, short socket timeouts.
- **In-memory RateLimiter capped (R7-5):** at most `max_keys` keys (LRU).
- **`/auth/claim-admin` throttled (B5-16):** Failed attempts land in the audit log (`admin_claim_fail`) and in the security log as `failed verification`.
- `is_pin_locked` reports its rejection. The area PIN writes `grund=falsches_bereichsgeheimnis` instead of `kein_konto`.

#### Password and factors

**Changed — password rule at every setting place (T-13: B2-5/H-17, R4-07, B2-13; follow-up A-3, A-5, A-6, A-7)**
- **New passwords are checked everywhere against an offline blocklist.** This applies to registration, reset, account page, admin panel and `tinysesam passwd`. Rejected are known passwords (even dressed up, e.g. `Passwort2026!`) and trivial patterns: repetitions, counting and keyboard sequences, also descending, wrapped or composed (`0987654321`, `12341234`, `asdfasdf`, `11112222`, `qwerasdf`). Likewise context words: `rp_name`, username and name part of the email, **also in their parts** (`Mustermann1990!` for `max.mustermann@…`). There are no composition rules (NIST SP 800-63B). **Behavior change:** Weak passwords accepted until now are now rejected with 400. The admin panel did not check at all until then.
- **Maximum length 256 characters** for new passwords at all setting places (R4-07).
- **New: `password_blocklist_file`**, an own blocklist (one password per line, `#` = comment). Lines that are not UTF-8 are read as Latin-1. Mixed leak lists like `rockyou.txt` thus load instead of aborting startup. A missing or unreadable file aborts startup with `ConfigError`.
- **`tinysesam passwd` follows the same rule:** New are `--blocklist-file` and `--rp-name`, because the CLI reads no config.

**Added — notification on factor changes (T-13: B2-2/H-6)**
- **`auth.on_security_event = hook`**, called as `hook(event, account, details)` for `password_changed`, `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled`, `recovery_codes_generated`, `recovery_code_used` (with remainder), `passkey_added`, `passkey_removed` and `api_key_created`. Opt-in, TinySesam sends nothing itself. An error in the hook does not undo the change but lands in the security log. Described in SECURITY.md.

**Changed — TOTP setup (T-13: B2-3, B2-12/R3-6; follow-up A-1, A-4)**
- **The setup code is valid exactly once.** After confirmation it no longer signs in at `/auth/totp`. **Behavior change for integrators:** Tests that call `totp_confirm(uid, now())` and then `verify_totp(uid, now())` with the same code turn red. There, confirm with the code of the previous time step.
- **Mandatory setup under `login_chain=["password","totp"]`:** The confirmation immediately completes the TOTP step of the sign-in too (new session token, JSON `{"ok": true, "next": …}`), and the page redirects to the target. `next` travels through the setup. Before, the consumed code at `/auth/totp` would have fed the login lockout and the fail2ban jail.
- **`POST /auth/totp/setup`** is throttled, has its own lockout bucket (`totp_setup_max_attempts`, separate from the login lockout) and logs (audit `totp_enable`). If TOTP is already confirmed it answers with **409** like GET and `/start`. `totp_confirm` rejects a confirmed TOTP: no false `totp_enabled`, no second code checker.

**Changed — recovery codes and reset (T-13: B2-7, R4-14; follow-up A-8)**
- A consumed recovery code produces the audit line `recovery_used` with remainder, a security-log line and the event `recovery_code_used`. The account page shows the remainder and warns from three.
- **The password reset by mail revokes the API keys** like the admin reset (behavior change).
- `POST /auth/reset` checks the link before the password rule. An invalid or expired link immediately reports "Link invalid" instead of "Password too weak".

**Security — known limit (T-13: H-14/H-15)**
- TOTP secrets are stored unencrypted in the database. This is now described in SECURITY.md as a limit, with an operations recommendation. The encryption itself is deferred.

#### Audit and forensics

- **Audit log: who, from where, what exactly (T-13).** `audit()` adds IP and signed-in account from the running request. TOTP, recovery, PIN, key, reset and verify lines therefore name account and IP, and `tinysesam audit --user X` finds them (B5-02). When an admin creates or revokes a key or sends an invitation in the panel, `akteur=<admin>` with IP appears in the log (B5-04, R6-3). If a key is used, `apikey_use` is created (throttled per key, IP and hour); if it is rejected, `apikey_denied` with reason and a seclog line is created. This also applies on POST routes with a CSRF exemption (B5-05). `totp_enable` is written on confirmation, `recovery_used` with the remaining count on redemption (B5-07). `user_roles` and `security_update` log the state before → after (R6-7). Anyone who reads the audit log or session list in the panel leaves a line themselves (B5-12).
- **Log injection closed (B5-06, B5-14).** `tinysesam audit` and the logger `tinysesam.security` neutralize control characters in every argument. This covers C0, DEL, C1 (NEL, CSI), U+2028/U+2029 and bidi control characters.
- **The ip column contains an IP (B5-15).** `X-Forwarded-For` is adopted only as a valid, canonical address, an IPv6 zone specification (`%…`) is dropped. Anyone who changes the zone per request via a pass-through proxy thus escapes neither rate limit nor IP lockout.
- **Rejected forward-auth (B5-17).** A 401 with invalid proof produces, throttled, `forward_denied`. `forward_denied` and `forward_role_denied` write the URL without query and fragment (`?…`) so that unlock tokens and codes do not land in the log.
- **Retention and deletion (B5-11, H-13).** New are `audit_retention_days` (takes effect via `gc()` and `tinysesam gc --audit-days N`) and `audit_ip_pseudonymize` (truncates to /24 or /48). `delete_user` replaces the account in the audit log with `gelöscht#<id>`: in the column `username`, also for sign-in attempts under the email address (whose attempt lines are deleted), also for `akteur=` and for the address in the detail text. Same-named words in foreign lines, such as `admin=0->1`, stay.
- **Panel: revoke foreign passkeys, delete accounts (B5-08).** The own account and the last admin cannot be deleted.
- **Account page: latest events (H-7).** The list shows time, event and IP, but no detail text. If an admin triggered the event, "by an administrator" appears there instead of their IP.

#### Admin and configuration check

**Security**

- **Admin panel: The last active admin can no longer be stripped of their rights** (R6-1). The request gets 400. Locked accounts and service accounts do not count as "another admin".
- **No admin service account via the panel any more** (R6-2). On creation and via the roles route there is 400, before it was silently discarded or silently set.
- **Hardening thresholds have limits** (R6-4, B2-9, `security.SECURITY_GRENZEN`). Until now a typo could shut down the instance permanently, e.g. `rate_limit_max=0` (every sign-in rejected, including the one to turn it back) or `max_login_attempts=0`. The panel now checks on the all-or-nothing principle. The limits forbid shutting down, not tightening: attempt counters from 1, `lockout_window_sec` 60 s to 30 days, `rate_limit_max` from 3, `rate_limit_window_sec` up to 1 day, `password_min_length` 8 to 128.
  **Behavior change:** `set_security()` raises `ConfigError` on an unknown key or a value outside the limits. Up to 0.19.x an unknown key silently dropped out, and every value was accepted. An old value in the database beyond the limits is **pulled to the nearest limit**, not set to the default. This way an upgrade does not loosen a stricter setting, only an unreadable value falls back to the default. On the first read there is a line in the security log. `Infinity` in the panel yields 400 instead of 500.
- **An API key no longer mints a key** (R6-6). The panel key route requires a session. The admin flag is dropped for every key kind except `mensch` (fail-closed), before only for `automat`.
- **An unusable scope or expiry when creating a key yields 400 with a reason instead of HTTP 500** (R6-8), in the panel as under `/auth/apikeys`.
- **Login URL at forward-auth** (R5-1): With `cookie_secure=True`, `X-Forwarded-Proto: http` no longer downgrades the scheme (except loopback). A user part from `X-Original-URL` (`https://fremd.example@app.example.com`) no longer lands in front of the host.
- **`trusted_proxies`: One invalid entry no longer invalidates the whole list** (B3-3). Each entry is checked individually, and the configuration check rejects hostnames and typos.
- **Later config changes are checked before the routes are built** (B3-14, A2). `router()` and `admin_router()` re-check everything that would have made the constructor fail: `konfigpruefung`, cookie fields and the bolts of the constructor (`admin_identifiers` next to open registration/auto-create, `login_identifier`, `forward_headers`, `totp_required`). Before, for example, `auth.cfg.allow_signup = True` after the constructor next to `admin_identifiers=["chef"]` built a router in which the first visitor registered as first admin. `pruefen()` still returns a list.

**Changed**

- **New configuration errors that can make existing configs fail at startup. Check before upgrading:**
  - `stepup_methods` with an unknown method (`"topt"`) or a disabled one (`"pin"` without `pin_enabled`) (B3-6). Before, the confirmation silently fell back to the password.
  - `trusted_proxies` with an entry that is not an IP network (B3-3).
  - `passkey_enabled`: `origin` is not an origin (path, trailing slash) or `rp_id` does not fit it (B3-10). If `origin` differs from `base_url` or the developer values are still there, there is a warning. `origin` may, as with py_webauthn, be a **list**, each entry is checked.
  - Number fields outside their limits (B3-12, `konfigpruefung.ZAHLENGRENZEN`), for example `session_ttl_hours=0`, `magiclink_ttl_min=0`, `recovery_code_count=0` or a negative `stepup_max_age_sec`. `True` instead of a number is also an error, and **text instead of a number as well**: `smtp_port="587"`, say straight from an environment variable, now aborts setup with "is not an integer". In 0.19.0, text in these fields still built, so these newly break: `pin_min_length`, `apikey_default_days`, `resource_unlock_ttl_hours`, `magiclink_ttl_min`, `smtp_port`, `smtp_timeout`, `recovery_code_count`, `mfa_enrollment_grace_days`, `stepup_max_age_sec`, `session_ttl_hours`, `session_ttl_transient_hours` and `oidc_revalidate_minutes`, i.e. every field in `ZAHLENGRENZEN` but two. `admin_claim_ttl_min` already failed in 0.19.0 with a `TypeError` instead of a message (except with `admin_enabled=False`), and `audit_retention_days` is new. → **To do:** convert beforehand yourself, `smtp_port=int(os.environ["SMTP_PORT"])`. The bundled gateway already converts its environment variables.
  - `signup_verify_email=True` without `signup_require_email=True` (B3-16). Anyone who gave no address was active immediately without confirmation. Also errors: `cookie_domain` that does not cover the host of `base_url`, and `admin_path`/`login_path`/`oidc_callback_path` without a leading `/`. Warnings exist for swapped session durations and for `signup_invite_only` without `allow_signup`.
  - `demo_mode=True` next to OIDC/SAML/LDAP/forward-auth and on a database with existing accounts that never was a demo (B3-8). A real demo still starts, even with registered visitors.
- **Warning on an open forward-auth gate** (H-11, B3-9): auto-create without `*_allowed_groups` or without `oidc_clients`, or open self-registration in front of forward-auth. The bundled compose and the gateway docs say where the circle is limited.
- **If `base_url` is emptied after the constructor, the mail routes and the admin invitation answer with HTTP 503 instead of an uncaught 500.** The 503 comes from the route (`router._mail_basis`). → **Integrator:** Correct the paragraph "**The 500 stays.** … and the 500 as what comes out today" in the entry on `require_public_base()` (CHANGELOG.md around lines 495-500) accordingly to 503.

**Docs**

- **KONFIGURATION.md: descriptions no longer slip** (B3-15). The generator attaches indented continuation lines to the right field and removes the `#:` colon. The file is regenerated, as is API.md.

#### Operations and runtime

**Changed**
- **`/healthz` now writes instead of only reading** (B6-4): A read-only database or a dead connection reports **503** `{"status": "degraded"}` instead of a permanent 200. Anyone who embeds TinySesam as a library builds the same check with the new `auth.store.schreibprobe()`. A real write happens at most every 5 s (`Store.SCHREIBPROBE_SEK`), in between the probe only checks the connection. A flood on the open path thus does not occupy the write lock and does not wear out an SD card. A database that has just become read-only is noticed after 5 s at the latest.
- **HEALTHCHECK in the image waits 12 s/15 s instead of 4 s/5 s**: longer than the wait for a locked database, so that a short lock (checkpoint, backup) does not mark the container unhealthy.
- **`busy_timeout` explicitly 10 s** (`Store.BUSY_TIMEOUT_MS`, B6-11) instead of Python's silent 5 s: A second writer makes a sign-in wait and does not abort it with `database is locked`.
- **Locked accounts get `403 api.account_disabled` instead of a session** (H-18): Sign-in link, passkey and every other factor no longer create a session for a locked account. TOTP no longer makes a half session full after the lock. The lock in the panel discards open one-time tokens (new: `Store.revoke_user_magic_tokens()`), so an old confirmation link no longer lifts it.
- **Monotonic time source for all deadlines in the database** (B6-9, new: `tinysesam.store.jetzt()`): If the system clock jumps back (NTP, Pi without a backup battery, VM snapshot), expired sessions, one-time tokens and step-ups no longer revive. Across a restart the database carries the state: It saves it at most every minute in the setting `uhr_stand`. Limit: What expired in the last minute before the restart or during an idle period entirely without writes counts again after a boot with an old date, until the clock has caught up. If the clock jumped forward wrongly, timestamps stay there until the wall clock catches up.
- **For tests of embedding apps:** `time.time` is looked up on every call and not bound at import. `mock.patch`, `monkeypatch` and freezegun therefore also advance TinySesam's clock. It cannot be turned back that way: After unpatching it continues counting from the advanced state, under freezegun it stays there until real time catches up (the protection from B6-9).
- **If `[argon2]` is missing at runtime** (B6-8), startup names the number of affected hashes along with `pip install 'tinysesam[argon2]'`. In operation, the remedy appears once per process in the log (new: `Store.zaehle_argon2_hashes()`).

**Fixed**
- `pop_flow()` hands out WebAuthn challenge and OIDC `state` exactly once, even with two simultaneous callbacks and across process boundaries (R3-8).

**Docs**
- New: `docs/BETRIEB.md` with failure behavior (B6-13), session and federation management (F-10), sign-in paths and their strength (B1-11) and the open ASVS L3 items (B1-12). `test_repo` checks the page's numbers against the code, including the ratio of HEALTHCHECK to `busy_timeout`.

#### Supply chain and publishing

**Security**

- **Vulnerability gate in the CI** (B4-2). The new workflow `audit.yml` runs `pip-audit --strict` over the newest and over the lowest allowed resolution (`lowest-direct`) of all extras. Every hashed lock list is added. It runs on every PR, on `main` and nightly. Up to 0.19.0 a PR with a vulnerable resolution went green, because a Dependabot alert is not a gate. The gate gets its own tools from a pinned, hashed list.
- **The image's lock list is checked for completeness** (B4-7, re-check). The image installs with `--no-deps`. If a Dependabot bump brings a new dependency along, it is missing in the list, and pip does not notice. The image would then abort only at startup. Now `pip check` and the import run in the Dockerfile. `audit.yml` runs the same steps on every PR on Python 3.14.
- **No pip in the final image, true again.** Since the switch to 3.14 the deletion paths still pointed to `python3.12`, so pip was in the image again. The paths are now given as patterns, and a test requires the Python series from the `FROM`.
- **Whoever holds an identity does not run foreign code** (B4-4). `release.yml` is split. Checking and building run only with read permission. Release, PyPI and the attestation of the image run without checkout and without pip. Up to 0.19.0 `pip install ".[all]"` ran in the same job that attested with `id-token: write`. Every dependency could thus have issued an attestation on the identity of the workflow. `tests/test_repo.py` reads the permissions in every spelling: block, flow map, `write-all` and inherited from the workflow level. Such jobs may start only a short list of commands in `run:`, and local actions are forbidden there.
- **Tools of the actions in a fixed version** (B4-6). `setup-qemu` and `setup-buildx` pulled `tonistiigi/binfmt:latest` (runs privileged), `buildkit:buildx-stable-1` and the runner's buildx. Now each of these tools is pinned with version and digest. `build` and `setuptools` come from a hashed list, and building is done without isolation.
- **The gateway image is reproducible** (B4-7). It installs from `deploy/gateway/requirements.txt`, pinned with hashes and universal for amd64 and arm64. TinySesam itself is installed without network. There is no `pip install --upgrade pip` any more, and the build runs with `SOURCE_DATE_EPOCH` and `rewrite-timestamp`.
- **Scorecard criteria guarded** (B4-14). Dangerous-Workflow, Token-Permissions, Pinned-Dependencies (partly), SAST, Security-Policy, License, Dependency-Update-Tool, CI-Tests and Binary-Artifacts are checked offline. The injection guard checks every `${{ … }}` expression that touches `github.event` or `github.head_ref`. This also applies inside `toJSON()` or `format()` and in the `script:` of `actions/github-script`.

**Changed**

- **Behavior change: The reference stack is hardened** (B4-11). `deploy/forward-auth/docker-compose.yml` pins Caddy to a version and digest instead of `caddy:2`. Both services run `read_only`, with `cap_drop: [ALL]` and `no-new-privileges`. Caddy gets back only `NET_BIND_SERVICE`. → **To do**, if you adopted the compose: Everything a service writes at runtime needs a volume or a `tmpfs`. Own additions that need further capabilities must explicitly bring them back.
- **Wheel and sdist are bit-reproducible** (B4-8). Both artifacts are built with `SOURCE_DATE_EPOCH` = timestamp of the commit and then normalized with `scripts/_artefakte_normalisieren.py`. The sdist gets fixed timestamps, order, owner, permissions and a fixed gzip header. In the wheel the file permissions are fixed, because setuptools otherwise adopts the umask of the checkout (0002 on Ubuntu/Mint, 0022 on the runner). Rebuilding works like this: run the same steps on the tag, then `sha256sum -c SHA256SUMS`.
- **Dependabot raises what is pinned** (B4-3, B4-12). The pip entry for `/` was ineffective because Dependabot never raises open `>=` floors. It is replaced by entries for the hashed lock lists and for the compose stack. The floors are now checked by the audit gate.
- **The sdist contains nothing gitignored any more** (B4-13). `MANIFEST.in` mirrors `.gitignore`. Before, `python -m build` from a used working tree put, for example, an `examples/app.db` or a `.env` into the package.
- **`SECURITY.md` names reachable reporting paths and deadlines** (B4-10). There are two paths: the private advisory and an email for everyone without a GitHub account. The deadlines are 7, 14 and 90 days, the same in both languages.

### Security — T-13: attack on the integration

The ten branches were merged and then attacked themselves: 18 findings at the seams,
each reproduced twice, fixed; the fixes were attacked again and improved. What
of it matters for the update:

- **Lockouts:** The account lockout counts Unicode spellings of an address together (NFKC, IDNA —
  before, there were 2^16 buckets for `victim@example.com`). The TOTP setup checks and books in
  one step. A directory outage is not queried again for 30 s
  (`ldap_.AUSFALL_PAUSE_SEK`), after which exactly one sign-in checks again; this way pre-booked
  attempts no longer hang until the timeout. LDAP inputs over 256 (name) or 1024 characters
  (password) no longer go to the directory. A failed write access (such as the
  write probe of `/healthz`) no longer leaves an open transaction behind that answered every sign-in with
  500.
- **One deletion path:** `gc()`, `tinysesam gc`, the rollback of a registration and `delete_user`
  run via `Store.konto_entfernen`: audit log anonymized, sign-in attempts gone — but only
  what arose from the creation of the account on. Look-alike names such as `Émile`/`émile` count as taken.
  The bucket check for this is indexed (schema 10); in the first version it made
  registration a runtime oracle for taken addresses.
- **Admin:** Revoking a foreign passkey reports `passkey_removed`
  (`auth.remove_passkey`). Roles are checked before writing (`roles=[1]` gave an admin flag
  without an audit line). The panel shows the reason for a rejection instead of reporting "saved".
  Locks in the panel carry the operator mark (`disabled=2`); no confirmation link lifts them,
  not even one that arises only afterwards, and the migration lifts locks from 0.19.x with an
  open link on them (as far as the audit log still knows them).
- **Traces:** Invalid tokens at `POST /auth/reset` and `GET /auth/register?invite=` write
  `token_invalid` / `failed verification` again.
- **Session:** The step-up via `POST /auth/totp` rotates the token (F-06). The origin check
  rejects `Origin: null` from the neighborhood over HTTPS; over HTTP browsers send no
  `Sec-Fetch-Site`, there the token alone decides. Cookies under the old names from before
  `__Host-` are deleted by every built-in route that writes the session, plus `auth.logout()` and
  `auth.rotate_session()`. The nginx templates filter twelve TinySesam cookies and pass on no cookie
  at all if there are more (fail closed) — **To do:** update adopted `map` lines.
- **Configuration:** Limits for `audit_retention_days` (0–3660) and `oidc_revalidate_minutes`
  (0–43200, warning above 1440); `tinysesam gc` checks deadlines before the first deletion step;
  `tinysesam passwd` reads the minimum length by the same route as the web
  (`security.haertung_lesen`). The confirmation token is created in the request, only the send
  waits.
- **Known limits** (SECURITY.md, BETRIEB.md, backlog T-13): With `cookie_domain`,
  `cookie_host_prefix=False`, a different `cookie_path` or over HTTP, any host under the
  domain can plant a session cookie. In a chain `password → totp → pin` the
  offer to end the other sessions is dropped. In the first window of an LDAP outage, attempts
  still hang until the timeout. API keys report `on_security_event` only on creation.
- **Tests:** If `node` is missing, it is red instead of silently skipped (`TINYSESAM_OHNE_NODE=1` as a
  visible opt-out). The guards over transactions, settings access, number fields and
  deletion paths recognize the class instead of one spelling and each carry a self-probe.

## [0.19.0] — 2026-09-22

**Security release.** The third audit (red/blue, 139 confirmed findings) named 16 items as
blockers for 1.0; this version closes them except for the three that concern LDAP and SAML
(F-11, F-12, F-16 — they are tracked in T-13 and need a migration of the identity binding). It also
brings T-14: several applications behind **one** installation, with one approval per application
that follows the identity provider.

**The database moves from schema 5 to 8.** Take a backup before the update — a rollback
to 0.18.x needs it (`tinysesam backup`).


**Behavior changes in this round.** Six items change what an existing installation
does — each item says what to do; the rationale is given further down at the finding
the item comes from.

1. **`base_url` is mandatory** as soon as a mail path (`magiclink_enabled`, `password_reset_enabled`,
   `signup_verify_email`), `oidc_enabled` or `saml_enabled` is on. The warning became an
   **error**: the instance no longer starts otherwise. → **To do:** enter the public
   address of this app (`base_url="https://auth.example.com"`, locally
   `"http://127.0.0.1:8000"`, under a subpath with prefix `"https://example.com/sso"`). The
   error message at startup says exactly that. Anyone who passes the base themselves now takes it from
   `auth.public_base(request)`, not from the request.
2. **An email address only supports a permissions decision with proof** (new column
   `users.email_verified`, schema 5). Via OIDC the claim `email_verified` counts; SAML and
   LDAP have none — there, an address from `admin_identifiers` never promotes anymore.
   → **To do:** existing accounts are not affected (`ALTER TABLE … DEFAULT 1`). Anyone who
   previously set the first admin via `admin_identifiers` + SAML/LDAP uses `/auth/claim-admin` and
   then the group mapping. Anyone running an IdP that never sends the optional claim (Entra ID)
   and vouches for its addresses themselves sets `oidc_email_verified_default=True`.
3. **Self-service management of factors is behind step-up.** `totp/disable`, `totp/recovery`,
   `pin/set`, `pin/disable`, `passkey/delete` require a freshly confirmed session.
   (Correction 0.20.1: this text used to say that, since the lookup, the **setup**
   (`totp/setup`, `passkey/register/*`) also required a freshly confirmed session. That was never true — the code
   requires an interactive session there (`require_session()`, no API key), but no fresh
   confirmation; that is also how the finding on factor setup further down has it.)
   → **To do:** configure nothing; anyone building their **own** account page evaluates the hint header
   `X-TinySesam-Reauth` and redirects to `/auth/reauth`, otherwise the buttons fail silently with 403.
4. **An API key no longer gets onto these routes** — it is a machine credential and never provides
   an interactive factor; the response is **403**. → **To do:** move automation that
   previously set or removed factors via a key to another path (admin API or database). In return, a
   leaked CI key can no longer do anything there.
5. **The lower bounds of the dependencies are raised** — `fastapi>=0.133.0`,
   `python-multipart>=0.0.31`, `authlib>=1.6.12`, without upper bounds. → **To do:** anyone who pins versions
   (lockfile, constraints, distribution package) updates them; with `authlib 1.3.0` a
   forged ID token was possible.
6. **Failed attempts count in their own buckets instead of the login bucket.** A password change,
   step-up confirmation and area PIN have their own thresholds (`password_change_max_attempts`,
   `reauth_max_attempts`, `resource_max_attempts`, 5 each); their log lines carry the distinct words
   `failed verification` and no longer hit the bundled fail2ban jail.
   → **To do:** anyone using the jail takes over the updated
   `deploy/fail2ban/tinysesam-filter.conf`; anyone who also wants to ban these failed attempts additionally takes
   `tinysesam-verify-filter.conf` together with the milder jail, which is disabled by default.

⚠️ **For embedding apps** there are two more changes to documented methods: `create_user()`
now raises `ConfigError` on a duplicate **username** instead of `sqlite3.IntegrityError`, and
`store.set_email()` also writes the confirmation flag, **unconfirmed** by default
(`verified=True` for the proven case). Both are described below at their finding.

**Docs reconciliation: 70 places where the docs said something different from the code.** Seven surfaces
were measured against reality — both READMEs, CHANGELOG, docstrings, `deploy/`, `web/`,
backlog. The finding was not that sentences sounded outdated: **Ten of the places were defects
in the code or in a shipped template**, which only became visible because someone read the
promise next to it. They are listed under "Fixed" and "Security".

### Fixed — 0.18.0 would have locked out every scrypt installation

**Anyone running TinySesam without the `[argon2]` extra could no longer sign in after updating to
0.18.0.** The hash format `scrypt$salt$dk` did not carry its parameters, and 0.18.0 raised
`p` from 1 to 3 (OWASP): `verify_password` recomputed every existing hash with the new value and
arrived at a different result. No error, no message — just "password does not match", for every
account at once. The new format `scrypt$n$r$p$salt$dk` states the parameters; the old one is recomputed with
the values of back then and silently raised to today's at the next login.
It would have hit exactly the installations the fallback was built for.

### Fixed

- **`login_chain=["password","totp"]` was a dead end for accounts without TOTP.** The correct
  password led to `/auth/totp`, which, for lack of a secret, redirected back to the login page — and
  the setup page required a fully signed-in user, which can never exist under this chain. Neither in nor to
  the setup; the operator had to go to the database. Now
  the path leads to the setup (new: `auth.totp_enrollment_user(request)`). Whoever stands there has
  already provided their first factor; they are signed in only after a code from the new secret.
- **The migration left plaintext approvals behind.** The cleanup of `resource_unlock` hung on
  `0 < PRAGMA user_version < 4` — the stamp itself only arrived with 0.18.0, an existing file carries
  0 there. So the condition was wrong in exactly the case it was written for. Detection
  now works on the value, not on the stamp.
- **`tinysesam audit --user NAME` often did not find the entries.** Filtering was not done in SQL,
  but by sifting through the most recent rows afterwards: a brute-force wave pushed the sought entry out of the
  window, and the command reported "No entries for 'X'." with exit 0 — in the very case it was needed.
- **The bundled Caddy template protected nothing.** `reverse_proxy /auth/forward <upstream>`
  is a **path matcher** in Caddy, not a rewrite: the auth check only ran for requests to
  `/auth/forward`, every other path fell straight through to the app. Now `rewrite /auth/forward`
  in the block, as in Caddy's own expansion of `forward_auth`.
- **The login redirect of the Caddy template pointed nowhere.** `{rp.header.X-TinySesam-Location}`
  found nothing: Caddy stores response headers under the Go-canonical name
  (`X-Tinysesam-Location`), and the placeholder is looked up character for character. The result was a
  302 with an empty `Location`.
- **`deploy/forward-auth/docker-compose.yml` produced a stack that does not run.** The mounted
  Caddyfile pointed to `127.0.0.1:8000` — nothing listens there in the Caddy container. The upstreams
  now come from the environment; the compose file sets the service names.
- **The image's `HEALTHCHECK` followed redirects**, although the comment next to it claimed the opposite:
  `urlopen` brings the redirect handler in the default opener and reported the status
  of the redirect target. Now via `http.client`, which never redirects on its own.
- **systemd silently discarded `Documentation=` in `tinysesam-gc.service`** — the umlaut in the URL anchor
  made the line invalid.
- **The quickstart of both READMEs no longer built.** The first block a new user
  copies turns on `oidc_enabled=True` and set no `base_url` — since the tightening
  further down, that is exactly a `ConfigError` in the constructor. The rule arrived, the example stayed:
  the same class of error as `pip install tinysesam`, the first line anyone tries
  was the first one to fail. `base_url` is now in both examples, with the sentence explaining why.
  So that this does not happen again, **the hygiene check builds every config example of both READMEs** and
  runs the complete blocks in a throwaway directory (`tests/test_repo.py`) — until now
  it only measured numbers in the text, not whether an example runs.
- **Two operator messages named paths that do not exist.** The new collision guard at
  startup advised "Change one of the two identifiers (admin panel or CLI)" — neither can
  do that: the admin API offers create, lock, roles, password and keys, but no rename, and
  the CLI does not create accounts at all. It now names what exists
  (`store.set_email(…)`, otherwise the database) — together with the side effect this path has since the
  item on `set_email()` further down: the new address is stored **unconfirmed**
  (`users.email_verified=0`); anyone who has proof for it passes `verified=True`. Likewise in
  the configuration check: "The
  first admin then only comes about via `admin_identifiers` or the CLI" → `ensure_admin()`
  in your own service. It is the same false CLI promise that this entry has
  already retracted once elsewhere.

### Security

- **A passkey must verify the human, not just the key** (`passkey_user_verification`,
  default `"required"`, B2-10). In TinySesam a passkey signs in **on its own** — it is not a second
  factor but a complete login. Without user verification it only proves **possession**: the
  unlocked computer, the plugged-in stick, the phone briefly set down are then enough.

  Up to 0.18.x the request said `preferred` **and** the response was not even checked
  (`require_user_verification=False`) — so an authenticator could say no and still be accepted.
  The request was non-binding in both directions. Now it is required and checked.
  `"preferred"` remains possible for a stock of old authenticators, but is flagged at
  startup and in the configuration check.

- **The passkey path is throttled and leaves traces** (B2-10, B5-01). It was the only
  sign-in route without a brake, and every call to `login/begin` created a `flow` row that
  only expired after five minutes — a convenient way to make the database grow. Nothing was
  logged at all: neither the creation of a passkey (a new full login path on the account),
  nor its deletion, nor a failed sign-in. Anyone probing here did so unobserved.
  Now the rate-limit bucket counts too, and creation, deletion and failed attempt appear in the audit log;
  the failed attempt additionally carries the event word the fail2ban jail matches on — it **is**
  one.

- **Two kinds of API key, and neither is an admin API anymore** (`kind`, R6-5). A key was
  previously a complete write interface in the name of its owner. For an admin, that
  meant: create users, set `is_admin`, reset passwords, change thresholds — without a second
  factor and without the CSRF layer, because neither applies to a key. A leaked
  CI key was the instance. The existing role scope did not help: it narrows the **roles**, the
  admin flag comes from the account row and remained untouched.

  Now a key says what it is. `kind="automat"` (default) works alone, but **never carries
  the admin flag** of its owner and satisfies no route that requires admin — the path for
  services, scripts and CI. `kind="mensch"` is valid **only together with a valid session
  of the same account** and carries the full rights for that — the path for a tool that a human
  operates themselves. Leaked on its own, such a key is worthless. The session must belong to the key's account;
  any sign-in is not enough.

- **An API key now expires on its own** (`apikey_default_days`, default 90;
  `apikey_allow_unlimited`, default off). Without a value, a key was **unlimited** until now, and
  that was the most common case — a secret that nobody revokes anymore, which outlives the person
  who issued it and the project it was meant for. `expires_days=0` still explicitly means
  "unlimited", but needs the permission and then appears in the audit entry. A
  negative value remains an expiry in the past, i.e. a key that is dead from the start.

  **Existing files:** schema 7 backfills the kind, as `automat` — the narrower interpretation.
  A key that could previously serve admin routes loses that; that is exactly the point. A
  rejected call leaves a line in the security log.

- **A disabled account gets nothing at all on SSO login anymore** (F-17). The OIDC callback ran
  completely through for a `disabled=1` account: groups were adopted, the admin flag could be
  set, a login entry was created — only the session was missing at the end. Disabling an account
  is the answer to "this person should not be able to do anything anymore"; that its roles still change
  in the process is the opposite of that, and in the log the process looked like
  a successful sign-in. The check now sits **before** any write access, with an audit line and
  a line in the security log. Local password login and panel always checked this; the
  federated side was the gap.

- **The UserInfo response must belong to the ID token** (F-18). In the callback it is laid
  over the claims and supplies groups, email and thus indirectly roles and the admin flag — but unlike
  the ID token it is **not signed**, but an ordinary response to a
  bearer token. OIDC Core 5.3.2 therefore explicitly requires checking its `sub` against that of the ID token
  and otherwise **not using** the response. Exactly that was missing: anyone who presented an access token
  of another account pushed the attributes of a different person into their own session.
  If the `sub` does not match, the response is now discarded entirely — not partially adopted —,
  and the claims of the signed token remain the only source.

- **An ID token for another application is rejected** (F-15, OIDC Core 3.1.3.7). Only
  that the own `client_id` **appears** in `aud` was checked. A token may however name several
  recipients, and then only `azp` says for whom it was issued. Without this check,
  a token made for another application of the same provider and merely naming us as well
  was enough (token substitution): anyone who got a token at any client of this provider got
  in here with it too. Three rules now apply — several `aud` require an `azp`, an
  existing `azp` must be the own `client_id`, and that must be in `aud`. Since
  `oidc_clients` (T-14) this weighs doubly: otherwise the token of app A would also be good for app B and
  the approval per client would be bypassed.

- **A made-up `Host` can no longer switch off a warning.** `security.einmal_melden()` records
  what already has a hint line in the security log, so that a page load with twenty
  subresources does not write twenty identical lines. The key is the **host from the
  request**, and the cap of 512 entries applied for the lifetime of the process: anyone who tried 512
  different `Host` values silenced the spot until restart — after that the notice about the **real**
  operational error was missing too. Noise thus turned into targeted switching off.
  The cap now applies per time window (`_GEMELDET_FENSTER_SEK`, one hour), and reaching
  the cap writes **one** line — an invisible suppression would be the same hole
  again. Found when attacking this round's own fixes (C-4).

- **`base_url` is checked by the same rule as a derived base.** The form check
  now sits in `security.normalisiere_basis()`; `security.sichere_basis()` merely puts the
  question "is this an own host?" in front of it. Before, only the **derived** branch went through the
  check, while a configured `base_url` merely saw `strip().rstrip("/")` and the
  configuration check accepted it with a coarse scheme-and-host pattern. That let through what fails in the
  other branch: userinfo in the host (`https://wer:was@auth.example` — it would appear
  in every reset link and every redirect URI), a fragment or a query (the appended
  token ended up behind the `#` and never reached the server), an invalid port, a path with
  `..`. The configuration check now rejects this at construction and additionally reports when a
  usable address would be **changed** along the way — with the value that should be entered
  instead. `public_base()` normalizes as a floor underneath (a config can still be changed after the
  constructor). (C-7)

- **The promise "a replaced base reports itself" also holds with the same host.** Only
  the hostname was compared, so only a change of the name was reported. An app mounted under `/sso`
  that passes `https://auth.example.com/falsch` to its own form got no line — although
  exactly this wrong prefix arrives as a 404 at the recipient. The whole
  normalized base is now compared. (C-5)

- **The ID token no longer decides itself how it is verified.** `authlib.jose.jwt` is a
  decoder with a default set, and that set contains HS256: if no algorithm is
  named when decoding, the **header of the token** decides — that is, the sender. Up to authlib 1.3.0 this
  allowed forging an ID token using the public key from the JWKS as the HMAC secret
  (GHSA-5357-c2jx-v7qh, algorithm confusion); the public key is public by definition,
  the attacker would have picked the `sub`. The declared floor fit that:
  `authlib>=1.3` allowed exactly this version, and anyone who pins a version (lockfile,
  constraints, distribution package) got it too. Now both — `OIDCClient.ID_TOKEN_ALGS`
  names exclusively asymmetric algorithms (RS/PS/ES/EdDSA) and is set when decoding,
  independent of version; a later extension by HS\* or `none` is rejected by the client with
  `ConfigError`. And the lower bounds are raised, to the measured gap-free floor
  (OSV, as of 2026-09-22): `fastapi>=0.133.0` (only from there is starlette >= 1.3.1 allowed),
  `python-multipart>=0.0.31`, `authlib>=1.6.12`. **No** upper bounds — a cap in a library
  blocks exactly the update that brings the next fix.
  `tests/test_packaging.py` also measures the bounds against a frozen table, so that the floor
  does not age again. Found in the third audit (B4-1 from [T-13](backlog/T-13-audit-2026-09-22-runde-3.md)).
- **An unconfirmed IdP address could determine the first admin.** `admin_identifiers` is the
  documented bootstrap path. For open registration, TinySesam requires a confirmed
  address for it — the OIDC path, however, read `email` unconditionally and overlooked the standard claim
  `email_verified` (OIDC Core 5.1). Anyone who entered the admin address at an IdP with self-registration or in a
  second tenant was first admin at the first login. Now a
  missing claim counts as *unconfirmed* (fail-closed, with log and audit line), and this
  address never supports the first-admin decision — not even for an existing account
  that already carries it, and not via a later login that brings no proof
  itself (`maybe_promote_admin(user, email_bestaetigt=…)`, passed through by `apply_factor`;
  without this parameter the flag on the account decides). **The address is still kept:**
  Only the proof is remembered separately, in the new column `users.email_verified`
  (schema version 5; an `ALTER TABLE` with `DEFAULT 1` makes every existing account behave exactly as
  before). *Discarding* the address was the first version of this fix, and it
  cost more than it protected: an IdP that never sends the optional claim (Entra ID)
  made every newly created account be named `oidc-<sub>` instead of like the address, and
  `Remote-Email` went out empty to the protected app — the same person ended up after the update in
  a *different* account of the app, and reset as well as magic link were closed to them. Because the claim is
  optional, `oidc_email_verified_default` (default `False`) now decides what the
  **silence** of a provider means; anyone who vouches for their addresses themselves sets it to
  `True` and can use `admin_identifiers` even with such an IdP. A claim that explicitly
  says `false` remains a no in both cases — and `_flag_wahr` reads it in the forms that
  real providers send (`True`, `"true"`, `"True"`, `1`, `"1"`; everything else, including the
  string `"false"`, is no — a truthiness check on the raw value would have
  let it through, and no test held that down). Address and
  proof are always taken from the SAME document: the callback merges ID token and
  userinfo document, and when mixing, an `email_verified=true` from one could end up attached to the
  address from the other. Second, the guard that forbids allowlist **usernames**
  hung on `allow_signup` alone — for auto-creation by an IdP (`oidc_auto_create`,
  `saml_auto_create`, `ldap_auto_create`) it did not apply, although the name comes from foreign
  hands there too (`preferred_username`); it now covers all four doors.
  **Via SAML and LDAP there is no such proof at all — there an allowlist address
  never promotes.** The bolt initially hung on the OIDC callback alone: SAML ACS and LDAP login called
  `apply_factor` without the argument, and `None` means "no foreign IdP involved" — it ran past the
  bolt, so an IdP with self-registration or a directory in which the user maintains their own
  `mail` attribute continued to determine the first admin. Now both
  paths explicitly pass "no proof", and the rule itself is **fail-closed**:
  `maybe_promote_admin` receives the **factor**, and for a federated factor (new:
  `TinySesam.FOEDERIERTE_FAKTOREN`) an address only counts with an explicit `True` —
  a future federated path that forgets to pass the proof thereby refuses instead of
  promoting. LDAP needs the explicit pass-through in addition, because it deliberately writes the factor
  `password` and cannot be recognized by the factor name. The configuration check names
  the combination allowlist **address** + `saml_auto_create`/`ldap_auto_create` and the proven
  path (`/auth/claim-admin`, then the group mapping). The address itself stays
  in the account — it is the attribute that directory or IdP supplies; it merely no longer carries a
  permissions decision.
  **That at first only closed the first login, and the attack then needed exactly one
  click more.** Without explicit proof, the **flag on the account**
  (`users.email_verified`) decides — and `check_ldap`/`check_saml` created that with the default "proven"
  although by definition nothing is proven via these paths. The attacker thus signed in
  once via the directory (promotion correctly refused), set up a PIN or a passkey in their
  freshly signed-in session — self-service, intended in one's own session — and was first admin
  at the second login: this factor is not federated, passes no proof, and the flag said "proven". Measured with a
  directory in which the user maintains their `mail` attribute themselves. **Now both paths create
  with `email_verified=False`**: the address is in the account, the flag claims nothing.
  The rule is thus the same across all sign-in paths — an address supports a
  permissions decision only if *this* login proves it (OIDC claim) or a dedicated
  confirmation path has proven it. The two bolts for SAML (pass-through of the ACS route,
  `FOEDERIERTE_FAKTOREN`) and the one for LDAP are now measured **individually**: before, each
  covered the other, a refactoring could have lost the remaining one unnoticed.
  Evidence in `tests/test_saml.py`, `tests/test_ldap.py` and `tests/test_audit_runde2.py`.
  Found in the third audit (F-14 from T-13; the two follow-up findings B-umgehung-1 and
  B-umgehung-10 of the second attack round).
- **⚠️ `store.set_email()` now carries the confirmation flag along — behavior change for
  embedders.** Since `users.email_verified` decides about permissions, a leftover
  flag was the proof of the **old** address applied to the **new** one: an account with a confirmed
  `eve@example.com` whose address was rewritten to the allowlist address was first
  admin at the next login, without anyone confirming anything. The docstring explicitly called
  leaving it in place "fail-closed" and justified it with the *other* direction
  (unconfirmed stays unconfirmed) — this one was fail-**open**. Address and flag now go
  into the database in ONE statement, by default as **unconfirmed**; anyone who has proof
  for the new address says so (`set_email(uid, mail, verified=True)`). Within the package itself
  the method has no caller — the trap was set for embedders. Evidence in
  `tests/test_audit_runde2.py`. Found in the third audit (B-umgehung-8 from
  [T-13](backlog/T-13-audit-2026-09-22-runde-3.md)).
- **LDAP no longer follows a referral — it cost the service account's password.** ldap3
  follows a `SearchResultDone resultCode=10` on its own and builds a new connection
  to the host that the **response** names — with the same credentials. TinySesam set the
  parameter nowhere. Reproduced with two LDAP servers on loopback: server A answered the
  search with a referral, and at the foreign server B the complete BindRequest arrived with the DN and
  cleartext password of the service account — on the user connection it would have been the password of the
  person signing in. A referral does not need a taken-over directory for this: on a
  cleartext connection any eavesdropper in between injects it. Now `auto_referrals=False` on
  **every** connection and `allowed_referral_hosts=[]` on the server (second lock, in case
  a connection is ever created without the parameter); without following, the search ends empty and
  the sign-in fails, instead of giving away credentials. Deliberately hard and without a switch —
  anyone searching across several AD domains queries the Global Catalog. So that this price does not
  accrue **silently** (without following, every sign-in looks like a wrong password, and
  for every user of the domain at the same time), the discarded referral now writes a
  line via `tinysesam.security` and names the referred host — through the same sanitization
  as the username, so a line break from a foreign response does not create a second,
  made-up log line. The Global Catalog hint (port 3268/3269) is now in the
  LDAP section of **both READMEs** instead of only in the source. Finding **F-28** from
  [T-13](backlog/T-13-audit-2026-09-22-runde-3.md). Side finding at the same spot: ldap3 rejects `ldap_bind_dn`
  without `ldap_bind_password`, the error was swallowed in the login and looked like a wrong password
  for every user — the configuration check now reports the combination at construction.
- **The `Host` header poisoned the reset, sign-in and confirmation link.** In ten places
  TinySesam derived the public address from the request itself — six times as
  `cfg.base_url or str(request.base_url)` (magic link, reset, confirmation, OIDC post-logout,
  OIDC redirect URI, admin invitation), three times for SAML, once in the forward-auth redirect.
  The derived part is the raw `Host` header, i.e. an input of the requester (no proxy
  and no ASGI server checks it). Anyone who triggered "forgot password" for a **foreign** mailbox
  and set `Host:` in the process made the real app send a real mail with a **valid reset token** whose link pointed to the attacker's server; the same for magic link, email confirmation and admin invitation.
  `trusted_redirect_hosts` only protected `?next=`, not this path (CWE-644). Now
  `TinySesam.public_base()` decides everywhere: `base_url` wins, otherwise a derived host only counts
  if it is in `trusted_redirect_hosts` or is loopback. The same check covers
  OIDC redirect URI and post-logout, SAML entity ID/ACS and the forward-auth redirect; each
  of these places is measured individually (`tests/test_sicherheit_befunde.py`), after in a
  mutation trial all four could be reverted to the old form without a single check turning red.

  **The documented methods now follow the same rule too** — `magic_url()`, where all four
  mail paths converge, and before it `send_password_reset`, `send_login_link`, `send_verify_email`
  and `create_invite`. Before, the check sat only in the route: an app with its own "forgot
  password" form that followed the obvious pattern `str(request.base_url)` stayed fully
  vulnerable, while the built-in route had long been sealed. It is **one** rule, not a
  second rulebook: `_gepruefte_basis()` calls `public_base()` and turns the empty result
  into an error. If `base_url` is set, **it wins unconditionally here too** — the passed address does not
  come into play at all. That is more than "a foreign host is rejected": if several own
  names are in `trusted_redirect_hosts` (the normal case with SSO), the `Host` header could otherwise still
  *select* which of them ends up in the reset link. Without `base_url` — the only setup in which
  anything is derived at all — a foreign base is rejected with `ConfigError`, **before**
  the token is issued (no unusable token is left lying around) and before the account lookup (the exception
  does not reveal whether the address exists). The check is **idempotent**: the senders check before
  the token is issued, `magic_url()` checks once more afterwards — the path portion no longer grows in the process
  (an intermediate version appended it again on every pass and sent out links with a fourfold
  prefix, i.e. 404). A test counts the occurrences instead of checking `startswith`.

  **`base_url` is now mandatory — a deliberate behavior change, and the first version of this
  fix was too soft.** The paragraph here promised "visible error instead of guessed address";
  for the two most common paths only the first half held. `/auth/forgot` and
  `/auth/magic/request` wrote an audit line when the base was missing and rendered
  **the success page unchanged**: HTTP 200, "mail is on its way", no mail. The same generic
  response that prevents user enumeration concealed a total outage here — anyone who updated without
  `base_url` lost password reset and magic link for **all** users, visible only
  in one log line. The other paths (OIDC start, registration with confirmation, admin invitation,
  SAML) answered with **500** in the middle of the sign-in attempt, although it was already clear at construction that
  it cannot work. And `konfigpruefung` called it only a **warning**: if `base_url` stayed empty
  and — the normal case with forward-auth/SSO — several names were in
  `trusted_redirect_hosts`, the runtime check was satisfied by any of them; the attacker triggered the
  reset for a foreign mailbox, set `Host:` to a **different** co-trusted host and
  the token went out there.

  Both are closed: `konfigpruefung` reports an empty `base_url` as an **error** as soon as a
  mail path (`magiclink_enabled`, `password_reset_enabled`, `signup_verify_email`),
  `oidc_enabled` or `saml_enabled` is on — construction then fails with `ConfigError`, instead of
  permitting an operation that silently does the wrong thing. Thus `base_url` wins everywhere an absolute
  address goes **into foreign hands** — mail link, OIDC redirect URI, post-logout, SAML entity ID/ACS —,
  and the `Host` header has no say there anymore. **One exception, and it is named:** without
  `cookie_domain`, `forward_login_url()` builds the login page on the requested host if that is in
  `trusted_redirect_hosts`. The session cookie is then host-only; if the login URL
  pointed elsewhere, the sign-in silently went in circles. `konfigpruefung` announces this case at
  startup, and it reaches no further than `trusted_redirect_hosts`.

  At runtime there is no silent success: the new method
  `TinySesam.require_public_base()` raises `ConfigError` with a clear message, where before a
  success page stood ("mail is on its way", HTTP 200, no mail — the same response that prevents
  user enumeration, thereby concealing the total outage). `forward_auth_enabled`
  remains a warning — its redirect stays relative without a base and hits the same browser;
  where the `Host` header previously wrote an absolute address into `X-TinySesam-Location`, a path now stands.
  **The 500 remains.** This used to say "where before a success page or a 500
  stood"; that promised more than is measured. No route catches the `ConfigError`, an
  ASGI server turns it into a server error — for the regular setup that is meaningless,
  because `konfigpruefung` no longer lets it arise at all, it only affects a config that was changed AFTER the
  constructor. Both are measured (`tests/test_sicherheit_befunde.py`): no 200,
  no mail sent, and the 500 as what comes out today. The hint about the missing base
  appears **once per process and host** in the security log, not per request: forward-auth asks
  on every anonymous request, one page load is twenty subresources — exactly the file
  the fail2ban jail points to would otherwise have filled up.

  Additionally the **`root_path`** is included — **for the sent links**:
  `base_url="https://example.com/sso"` keeps its prefix, a derived base takes over the
  subpath from the request, and both carry it in the link exactly **once**; before, an app
  mounted under a subpath sent links into a 404. **The built-in pages do not carry the subpath:**
  Their form targets and links are root-absolute (`/auth/register`, `/auth/forgot`,
  …), and `login_path`/`login_redirect`/`logout_redirect` go out unchanged. Anyone mounting under
  `--root-path /sso` behind a proxy that strips `/sso` gets working
  mails and a sign-in into a 404. The limit is measured (`tests/test_sicherheit_befunde.py`
  on a real mount) and tracked as a task: [`backlog/T-15`](backlog/T-15-unterpfad-montage.md).

  **For operators — what to enter:** Anyone who previously ran without `base_url` and uses a mail path,
  OIDC or SAML must set `base_url` to the public address of this app, otherwise the instance
  no longer starts: `base_url="https://auth.example.com"` (locally
  `base_url="http://127.0.0.1:8000"`, mounted under a subpath with prefix,
  `"https://example.com/sso"` — for the mail links, see above). The error message at startup
  says exactly that.

  **For embedders:** Anyone who passes the base themselves takes it not from the request but from
  `auth.public_base(request)` (empty = abort). If `base_url` is set, it replaces a differing
  value — that also lifts an `http://` from a TLS-terminating proxy to the configured
  address, instead of letting it silently wander into the mail link; once per host a line
  about it appears in the security log. Without `base_url`, a foreign host gets `ConfigError` instead of a link.
  Found in the third audit (R4-01 = R8-4 from [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md)),
  sharpened further in the follow-up rounds N1 and N6.
- **A foreign registration could occupy the login identifier of an existing account.** The two
  namespaces were only checked separately — the address against `users.email`, the username
  against `users.username`. In the default mode `login_identifier="both"`, however, the sign-in searches
  **both** columns and, for an identifier with `@`, lets the email win: anyone who entered the email of an
  existing account as a *username* — or its username as an email — occupied
  its identifier. The owner, even an admin, got 401 from then on despite the correct password, and
  `/auth/password` checked its secret for the stranger's session instead of their own: a
  password oracle without throttle, lockout and log line. Both identifiers must now be free **crosswise**;
  the check sits in `create_user` and thus applies to every path that creates an
  account — registration, invitation, admin API, `ensure_admin`/`create_service` and the
  automatic creation from OIDC/LDAP/SAML, which fails closed instead of overwriting a foreign
  identifier. (The CLI was initially in this list too — it cannot create any accounts at all.) What this promise means on the **federated** paths is now also
  stated in tests: OIDC falls back to a free name (both namespaces are checked), an address that cannot
  be sidestepped ends with **409**, LDAP with **401**, SAML with **403** — each a clean
  rejection with an audit line (`oidc_ident_taken`, `ldap_ident_taken`, `saml_ident_taken`), no
  500 in the middle of the sign-in process. `/auth/password` additionally checks against the
  **ID** of the own session instead of via the identifier, so that a collision from legacy data there
  no longer takes effect. New: `auth.kennung_vergeben(kennung, exclude_id=None)`.
  **For embedding apps — ⚠️ behavior changes here:** With a duplicate **email**
  everything stays as in 0.18.x (`ConfigError`, wording "E-Mail-Adresse ist bereits vergeben").
  A duplicate **username**, by contrast, ran into the database up to 0.18.x and came back as
  `sqlite3.IntegrityError` ("UNIQUE constraint failed: users.username"); now
  `create_user()` catches it beforehand and likewise raises `ConfigError`, with the text "Benutzername
  ist bereits vergeben". Anyone who catches `IntegrityError` no longer catches this case — the
  signature is unchanged, so `api_surface.json` does not see the change; it is therefore stated
  here and in the docstring (→ API.md). Likewise the **wording depends on the field**: the new trigger
  (username equal to a foreign email and vice versa) carries the text of the field that collides,
  not always that of the email. An earlier draft of this entry claimed the opposite.
  The case is anyway better distinguished **without** text comparison: `e.feld` is
  `"username"` or `"email"`, `e.besitzer_id` names the account the identifier belongs to. And because the database has no UNIQUE index across BOTH
  namespaces — check and INSERT in `create_user` are not atomic, and a database
  from before the fix long carries the collision —, **startup now reports existing
  cross collisions** with both account IDs, instead of silently carrying them along
  (`store.kennungs_kollisionen()`). Cleanup is by hand: which account keeps the name
  cannot be decided by a library. Found in the third audit (R4-12 from T-13).
- **`/auth/password` was a silent password oracle — and it did not even check the own account.**
  The query of the old password was the only secret check running without the triad of the
  login path: no throttle, no lockout, no recorded failed attempt — any number of attempts,
  never a 429, no line for the security log or fail2ban, while the same slip at the login
  locks after a few tries. In addition it resolved the account via the **login identifier**
  (`check_password(u["username"], …)` → `find_user`) instead of via the ID of the own session: anyone who owned an
  account whose username equals the email of another guessed the password
  **of this foreign account** through it — and a hit silently set their own password, so it stayed invisible even on success. Now: `verify_user_password(u["id"], …)` plus `rate_ok` →
  `is_password_change_locked` → `record_login(…, "password_change")`; the dedicated method
  ensures that a hit here does not clear the failed attempts of the login path.
  The lockout is a **separate, method-bound bucket** with its own threshold
  (`password_change_max_attempts`, default 5) — the same design as the PIN counter. The first
  attempt attached the route to the login lockout, and that counts method-blind: five typos on
  the own account page thereby locked the **sign-in** for `lockout_window_sec`, including the
  route through which the lockout could have been worked off — and behind NAT, three
  mistyping colleagues locked, via `ip_attempt_factor`, the login of a completely uninvolved fourth.
  Therefore `is_locked` now only counts what was a **sign-in attempt**
  (`security.NICHT_LOGIN_METHODEN` as an exception list, so that a new sign-in method
  counts on its own). Guessing is still throttled, locked and logged
  unchanged — just where the guessing took place. **The price, stated openly:** instead of one bucket there are, at the end of this
  round, **five** — sign-in, PIN sign-in, password change, step-up confirmation and area PIN,
  5 attempts each within the window (the last three were added with the follow-up work below). The step-up page
  also checks the PIN lockout of the sign-in, otherwise a PIN locked there could
  be guessed on here. Anyone who exhausts all buckets has
  more attempts than before; in return, a typo on the account page locks nobody's
  sign-in anymore, and each bucket hits exactly the one who guessed.
  New: `auth.is_password_change_locked(username, ip)` and
  `store.count_fails(..., exclude_methods=…)`. Evidence in `tests/test_hardening.py`.
  Found in the third audit (R4-10 from [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md)).
  **Reworked (second attack round) — the fix fell short in three places:**
  1. **The exception list named only `password_change`.** `record_login()` is called in the router with
     five methods; `reauth` (step-up confirmation) and `resource` (area PIN without
     account) continued to count into the login bucket. Five typos on the reauth page
     thereby locked the **sign-in** of the same account, and with the area PIN — which every visitor
     may try — three areas of five slips each were enough to lock, via `ip_attempt_factor`,
     the sign-in of completely unrelated accounts from the same address. Both now have
     their own bucket (`auth.is_reauth_locked`, `auth.is_resource_locked`, thresholds
     `reauth_max_attempts`/`resource_max_attempts`); `NICHT_LOGIN_METHODEN` is **derived** from the
     mapping `security.EIGENE_SPERRE`, so a method without its own brake can no longer be
     entered at all. A test holds the list against the methods the router really calls
     with, via AST — exactly that was missing, otherwise the gap would have been noticed.
  2. **The non-login line hit the bundled fail2ban jail.** `failed login user=…
     ip=… method=password_change` matched the shipped `failregex` character for character
     (`maxretry = 6`): eight typos of a **signed-in** user at their own old password
     produced eight bannable lines, and from the app lockout on, every further click accelerated the
     ban. Non-sign-ins now carry their own event word **`failed verification`**
     (`security.log_ereignis`) and pass the jail by; anyone who wants to ban them anyway
     adds the new filter `deploy/fail2ban/tinysesam-verify-filter.conf` together with the milder,
     **disabled-by-default** second jail (useful above all for publicly
     offered area PINs). Everything is still logged unchanged.
  3. **The separate bucket brought along the NAT amplification it was meant to abolish.** It initially
     also counted per IP (`limit * ip_attempt_factor`): three mistyping colleagues locked the
     fourth's **own** password change — a lockout that did not exist at all on 0.18.x.
     `is_password_change_locked` and `is_reauth_locked` now count **per account only**; anyone
     guessing there already needs a valid session of exactly this account, so the victim is
     always the signed-in user themselves. Against knocking from outside, `rate_ok(ip)` still stands.
     `is_resource_locked` keeps the IP threshold: there an unauthenticated person guesses, and without it
     guessing could continue endlessly via ever new area names.
- **A `GET` on `/auth/totp/setup` could remove the confirmed second factor.** The page
  called `totp_begin()` unconditionally and wrote a fresh, unconfirmed secret over the old one:
  TOTP dropped to "unconfirmed", the ten recovery codes stayed behind orphaned, no
  audit line was created — and after that the password alone sufficed for a full session. CSRF did not help
  here: a GET carries no token, and `SameSite=Lax` (default) sends the
  session cookie on a top-level navigation; a click on a foreign link was enough.
  Now `totp_begin()` refuses to start as long as a **confirmed** TOTP exists (new
  error type `StateError`, exported), the route answers with `409`, the repelled attempt goes
  into the audit log as `totp_setup_denied`, and a new setup clears orphaned recovery codes.
  The path to switching authenticators leads through the regular disabling
  (`POST /auth/totp/disable`, CSRF-protected and logged); the setup for accounts
  **without** TOTP — also from a `login_chain` — remains open unchanged.
  **Reworked:** The finding text demanded two things — refuse when TOTP is confirmed *and*
  begin the setup only on explicit request. The second was missing: for every account
  without confirmed TOTP, **every** GET still generated a fresh secret and thereby replaced
  a running setup attempt — a foreign link invalidated the QR image that had just been scanned
  (the confirmation then failed inexplicably) and triggered audit lines from outside.
  The secret is now created exclusively in the new, CSRF-protected route
  **`POST /auth/totp/setup/start`**; the GET only shows the button that triggers it (new
  texts `setup.start`/`setup.start_hint`, de/en). **For embedding apps with their own TOTP page:**
  `totp_begin()` now **raises**, namely `StateError` — which inherits from
  `TinySesamError`/`RuntimeError` and **not** from `ConfigError`; anyone who catches the
  documented type otherwise gets a 500 in their own route. Because `api_surface.json` freezes signatures
  and does not see raised types at all, [API.md](API.md) from now on lists the
  error types together with the hierarchy (generated from the docstrings).
  Finding **B2-1** from [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md).
- **The first-admin one-time token was in plaintext in `security.log`.** As long as there is no admin,
  TinySesam writes a hint to `/auth/claim-admin?token=…` at startup — up to 0.18.x
  including the value, via `security.seclog`. With `security_log` set, that is exactly the
  file the bundled fail2ban jail points to: it was created without a permission setting (measured
  `-rw-rw-r--`), logrotate keeps it for weeks, every log shipping takes it along. Anyone who could
  read it and had any account on the instance redeemed the token and was admin. Now
  the value goes to **stderr** — the operator's console, the only recipient the docstring ever
  meant — or, new, into a dedicated file: `admin_claim_token_file` (created with **0600**,
  permissions set before writing even for an existing file). The log only says
  *where* the token lies. In addition, `attach_security_log()` creates the log file itself with **0640**
  instead of with the umask — also the one newly created after a rotation —, because it contains
  usernames and IP addresses; an already existing world-readable file is reported but not
  rewritten. A configuration check rejects `admin_claim_token_file == security_log`.
  **For operators:** 0640 means owner and group. A log shipper that runs as a *third*
  user (neither owner nor in the group) loses read access — and not
  at the update, but only at the next rotation, when the handler recreates the file. Anyone who
  needs it grants access via the group: logrotate line `create 0640 tinysesam adm`. That
  used to be only in the fail2ban template and is now also in the `security_log` section of
  KONFIGURATION.md and both READMEs. What the fix does **not** solve and which is therefore listed as a known limit
  in SECURITY.md and both READMEs: the token is redeemed via a **URL**
  (`GET /auth/claim-admin?token=…`, and for a non-signed-in call additionally in the `Location` of the
  login redirect) and thus passes through proxy access logs, `Referer` and browser history; by
  default it also goes to **stderr**, which journald, `docker logs` and any log shipping
  collect. Neither yields a permanent secret (redeemable exactly once, expiry via
  `admin_claim_ttl_min`, route 404 as soon as an admin exists) — set a short expiry, where stderr
  is collected use `admin_claim_token_file`, redeem immediately.
  Found in the third audit (B5-03 from [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md)).
- **The OIDC discovery document is now checked against the configured issuer.** Until now
  TinySesam took `issuer`, `token_endpoint` and `jwks_uri` from the document unchecked and on retrieval also
  followed redirects — a 3xx on the well-known path would have sufficed to replace all three, and the
  ID token check would have verified against the issuer *from the document* (RFC 8414 §3.3, OIDC Discovery §4.3
  require the comparison). Now: no redirect, only 200, and `issuer` must match `oidc_issuer` —
  otherwise `ConfigError` with both values. The key under which accounts are stored in the database remains
  the issuer from the document; through the comparison it is now the same as in the configuration.
  Found in the third audit (PocketID symbiosis, RB-03).
- **CodeQL backlog cleaned up.** 61 open alerts lay on `main`, unassessed. They do nothing — until a pull request touches one
  of their lines and the merge hangs on a `note` thread. Reviewed ([T-12](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-12-codeql-bestand.md)):
  **one real finding** — `examples/showcase.py` put the username unescaped into the demo pages
  `/app` and `/sensibel` (fixed with `html.escape`); **nine false alarms** rejected with reasons
  (fixed redirect paths, logged IPs instead of secrets, sha256 for random API keys, a
  deliberately 0644 file in the test); the rest cleaned up mechanically (unclosed files in tests,
  URL substring checks, unused imports, empty `except` with a justification). New:
  `scripts/_codeql_backlog.py` writes the open list into the backlog, so that new alerts
  land in the repo and not only in the mailbox.
- **`auth.seed_demo()` now checks itself whether `demo_mode` is on.** The docstring promised that
  all along, the body did not hold to it: a direct call created `demo` and `demoadmin` — the latter
  with `is_admin=1` and the documented default password, both immediately able to sign in, without the
  warning in the log that demo mode otherwise emits.
- **`deploy/forward-auth/nginx.conf` passed a client header through to the app.** `Remote-Name`
  was missing in the template, and an unset header is not omitted by nginx but passed on
  unchanged: anyone who sent `Remote-Name: chef` had it delivered behind the
  auth check, as if it came from TinySesam. All four headers are now set.
- **The fail2ban filter promised a protection it does not deliver.** The anchoring `^…$` keeps
  fragments out, but an injected line from a manipulated username is
  complete and well-formed — it matches just the same. The protection is solely the sanitization in
  0.18.0; the comment now says so.
- **The second factor could be dismantled without fresh confirmation — and via API key.**
  `POST /auth/totp/disable`, `/auth/totp/recovery`, `/auth/pin/set`, `/auth/pin/disable` and
  `/auth/passkey/delete` hung on `current_user()` alone. A session whose step-up had long
  expired — a 403 on every `require(mfa=True)` guard — could thereby delete TOTP, issue itself
  ten fresh recovery codes and remove PIN as well as passkey: of all things, the
  management of the factors stood behind no barrier. Added to that was the second half: `current_user()`
  also accepts an **API key**, and a machine credential never provides an interactive
  factor — a leaked CI key silently dismantled the second factor of its owner. All
  five routes now require `require_mfa()`: interactive session with fresh confirmation, constructively
  unreachable for an API key (403, "Step-up-MFA nötig — nur per interaktiver Sitzung").
  For `/auth/pin/set` this applies to **replacing** a PIN; that the same route also creates the first one
  is the special case in the item below. The account page now evaluates the hint header
  `X-TinySesam-Reauth` itself and redirects to the reauth page instead of failing silently —
  this is now measured where it takes place: in the browser test (expired freshness, click on
  "turn off 2FA", landing on `/auth/reauth`, the factor is still there afterwards). In the process it turned out that
  the two delete buttons of the account page reported success **unconditionally** ("✓ entfernt") and reloaded
  — even on 403 or 500. They now check the response. Finding **R3-3** from
  [T-13](backlog/T-13-audit-2026-09-22-runde-3.md).
- **The bolt against the dismantling API key could be bypassed via factor SETUP.** `require_mfa()`
  only covered the dismantling; `GET/POST /auth/totp/setup` and `POST /auth/passkey/register/{begin,finish}`
  still hung on `current_user()` alone — and that accepts an API key, for which the
  CSRF check does not apply anyway (`_csrf_entbehrlich`). That left two paths open: the key reads
  the TOTP secret in plaintext from the response of the setup page and confirms it (afterwards
  the **key holder** controls the second factor — the real user is locked out, and with a
  known password it is the full takeover), or it registers its own passkey. A
  passkey is a full login: through it the key got a fresh interactive session and
  thus stood after all in front of exactly the routes that were meant to lock it out. The setup now requires
  the same as the dismantling — a session, no machine credential (new:
  **`auth.require_session()`**, 403 "Einen Anmeldefaktor richtet ein Mensch ein …"). `register/finish`
  additionally binds the new passkey to the signed-in account instead of only to the flow cookie.
  Attack against the R3-3 fix, reproduced in the third audit.
- **The first PIN of a purely federated account was unreachable behind `require_mfa()`.**
  `/auth/pin/set` replaces a PIN — and is at the same time the only way to **create** one. An account
  without password, PIN and TOTP (OIDC/SAML/LDAP) has nothing with which it could perform a step-up:
  `stepup_options()` is empty, and after `stepup_max_age_sec` (default 900 s from login) had elapsed
  the route answered 403 — the reauth page offered a **password field** for it, which this account
  does not have, and every hopeless attempt counted into the same brute-force lockout. For an account that has **no** factor at all, **creating** now hangs on the age of the sign-in (new: **`auth.login_fresh()`**, the same span,
  measured from login instead of from factor confirmation); **replacing, dismantling — and creating for
  every account that has anything to confirm at all — remain behind `require_mfa()`**. The
  restriction is deliberate: with `pin_login`, a PIN is a full first factor, a
  stolen fresh session cookie would otherwise set up its own access that outlives the theft. For an account with a password that means: confirm first (the
  account page leads there on its own via `X-TinySesam-Reauth`), then the first PIN. An
  earlier draft of this entry read as if a fresh sign-in sufficed everywhere — the
  rule is now measured in `tests/test_pin_stepup.py`, instead of merely described. If the sign-in is too old as well, the response says what helps ("melde dich neu
  an") and **no longer** refers to the reauth page. With an empty list of methods the page now shows
  no form at all, and a POST there is not logged as a failed attempt.

### Added

- **Several applications behind one installation** (`oidc_clients`, T-14). Who may enter which
  application is decided by the identity provider — with PocketID via the group approval per
  OIDC client. This approval hangs on the **client**, not on the user: with a single client
  there is only one answer for all applications, and whoever may enter one may enter all. The previous
  workaround was a separate instance per application — three containers, three databases, three
  audit logs for the same people.

  Now `oidc_clients` assigns each protected host its own client at the **same** provider
  (`client_id`, `client_secret`, optional `scopes`, `allowed_groups`, `group_role_map`). All
  point to **one** redirect URI: which client is meant is stated in the process on the server,
  not in the address — so at the provider the same one is entered everywhere. `/auth/forward`
  now asks two things instead of one: signed in, **and** approved for this application.
  If the approval is missing, it does not go with 403 against the human, but with 401 via the provider
  — it decides, it shows its own refusal.

  The approval is stored in the new table `oidc_grant` (schema 6), per session and application, with
  the roles the provider yielded **for this application**. A configuration without
  `oidc_clients` behaves not one byte differently from 0.18.0.

- **Revocation follows the provider** (`oidc_revalidate_minutes`, default 0 = off; the preset
  `oidc_gateway()` sets 60). Without revalidation, an approval once granted held until the expiry
  of the session — by default **seven days**. A group removal in the provider took no effect for that long,
  and that is exactly the case for which the approval is maintained there. When the period expires,
  the next request takes the detour via the provider; its session in all likelihood
  persists, the human sees a flicker instead of a sign-in form. If the provider says no, the
  approval is gone **for this one application** — the session and the other applications remain.

  Deliberately **without a refresh token in the file**: the silent path via a refresh grant would have placed
  a usable secret per session in the database. The detour via the provider needs
  none and answers the same question.

  The hour is a trade-off, not a formula: every revalidation is a detour via the provider,
  and for a human at the browser that is a flicker, but for an open form or a
  running XHR request a break. Compared with seven days, the order of magnitude is what
  matters; between 15 and 60 minutes a removal is rarely decided, but how
  often it hits someone in the middle of work is.

- **Gateway environment variables** for this: `TINYSESAM_OIDC_CLIENTS` as JSON or per host
  `TINYSESAM_OIDC_CLIENT_<HOST>_ID`/`_SECRET`. The hostname from the variable name is matched against
  `TINYSESAM_PROTECTED_HOSTS`, because a `_` in the name can stand for a dot **or** a
  hyphen — without the matching, an entry would silently arise for a host
  that does not exist, and the assignment would never apply. If nothing matches, a log line says so.

- **`stepup_strict`** (default `False`): turns `stepup_methods` into a barrier. Until now the
  list was only a wish — anyone who had set up none of the named methods confirmed with
  whatever they had, including the password they had just signed in with. That is
  no step-up. With `True` the area stays locked until the method is set up;
  the page now says so too, instead of showing a form without fields.
- **`auth.require_session(request)`** and **`auth.login_fresh(request)`** — the two barriers
  from the items above, also for custom account pages: "signed in, but not via API key" and
  "the sign-in is at most `stepup_max_age_sec` old". Pure extension, not a break.
- **`auth.is_reauth_locked(username, ip)` and `auth.is_resource_locked(username, ip)`** together with
  the thresholds **`reauth_max_attempts`** and **`resource_max_attempts`** (5 each, changeable in the
  panel like the others): the dedicated buckets for step-up confirmation and area PIN. In addition
  `security.EIGENE_SPERRE` (method → bolt; `NICHT_LOGIN_METHODEN` is derived from it) and
  `security.log_ereignis(method)` for the event word of the log line.
- **`deploy/fail2ban/tinysesam-verify-filter.conf`** plus the jail `[tinysesam-verify]` in the
  template — the milder, disabled-by-default second jail for `failed verification`.
- **`recent_audit(limit, username=…)`** filters in SQL (see `audit --user` above).
- **Three guards in `tests/test_repo.py`**: The number of test files named in both READMEs and
  the Python range are measured against reality, and as long as the version is below 1.0,
  no README may show a PyPI installation. Exactly these three numbers were wrong — numbers
  that nobody re-measures go stale with the next commit.
- **`tests/test_bestandsdaten.py`** — 28 checks on what an upgrade must survive.
- **Promises of this cycle that nobody had measured now have a test** — each
  proven by a mutation trial (revert → red, otherwise green), after all of them could be reverted with the full suite 46/46:
  `ConfigError.feld`/`.besitzer_id` **and** the unchanged message text
  "… ist bereits vergeben" (`tests/test_identifier.py`); the **PIN** delete button of the account page,
  which reports success only after `r.ok` — only the 2FA button was covered, and that in the browser test,
  which never gets to see the PIN section (`tests/test_account.py`); the binding of
  `passkey/register/finish` to the signed-in account, against a foreign flow planted
  (`tests/test_methods.py`); and that the two operator messages only name paths that exist
  (`tests/test_security_log.py`, `tests/test_sicherheit_befunde.py`).

### Changed — Python 3.12 is the new lower bound (matrix 3.12 / 3.13 / 3.14)

**`requires-python` rises from `>=3.10` to `>=3.12`.** Anyone running TinySesam on 3.10 or 3.11
will no longer get a new package at the next pip update — that is the purpose of the
declaration, and it is the only place that can say so honestly.

Behind it stands not a number but a window: **the last three stable minors**. Python 3.10
goes EOL on 2026-10-31. The promise "runs from 3.10" had been thin lately anyway — it stood in
pyproject, but the lower bound never moved along, and every library underneath
follows sooner or later.

The matrix thus runs **3.12, 3.13, 3.14** instead of 3.10–3.14 as before; the classifiers for 3.10 and
3.11 are dropped (an unmeasured promise is an assertion — the suite enforces that). The
upper bound deliberately stays at 3.14: **3.15 appears on 2026-10-01**, but still runs only in the
nightly job with `continue-on-error` and moves into the gate only once it has actually been green there.

The matrix is now maintained in **one** place instead of three.

### Changed

- **The installation instructions lead with the git tag.** Both READMEs began with
  `pip install tinysesam` — the name is not registered on PyPI, the command ends with
  `No matching distribution found`. The first line anyone tries was the first one to
  fail. Publication happens with 1.0 ([ADR-6](backlog/ADR-6-pypi-veroeffentlichen.md)).
- **The status section of both READMEs** described the state of 0.5/0.6 ("17 and 22 test files respectively")
  for a package with two security audits, SAML, gateway and command line behind it.
- **`web/flows.py` names `ldap_enabled`** in the section "External IdProvider". The page
  promises in its preamble that the config that turns it on stands next to each heading — for
  one of the three named methods it was not there.
- **Docstrings** that were no longer correct: `mailer` (there is no `send()`, the mailer is
  called), `gateway` (`[gateway]`, not `[oidc]` — that is the library without a server),
  `router` (14 conditional blocks, not two), `mfa_pending` (no longer "enforced globally"),
  `create_api_key` (raises on an empty scope).

## [0.18.0] — 2026-09-21

**Security release. Anyone running TinySesam should update** — six vulnerabilities, each proven with
its own reproduction script, including role escalation and account substitution.
The details are under "Fixed"; the tests for them pin down every reproduced attack
so that it does not come back.

**This version is deliberately NOT 1.0.** The jump had been prepared and was rolled back:
a maturity review from four independent angles found 47 findings, 12 of which were
reproduced individually — **12 held up, 11 of them blockers**. A package with role escalation does not carry a
"Production/Stable" label, and a PyPI release is irrevocable. The maturity level therefore remains
at `4 - Beta`.

**Why nobody noticed is the real finding:** `tests/run_all.py` booked real
failures as "skipped". The suite was green because it did not measure. That was
repaired first — everything else would have been built on sand.

**The PyPI preparation stays in** (metadata, Trusted Publishing, packaging test,
`MANIFEST.in`) — it will only be published with 1.0. Until then, installation continues
via the pinned Git tag.

### Added — supply-chain hygiene (CodeQL, Dependabot for pip, digest pin)

From research into what an open-source auth package should have before 1.0:

- **Static analysis** did not run at all so far. New: `.github/workflows/codeql.yml`
  (`security-and-quality`, weekly and on every PR). For an auth package this was the
  most glaring gap — the OpenSSF Scorecard check `SAST` would have scored 0.
- **Dependabot only covered `github-actions`**, not `pip`: there were no regular version PRs for `fastapi`, `authlib`,
  `python3-saml` & co. Dependabot reports security vulnerabilities
  repo-wide anyway — but an auth package should not stay on yesterday's version
  until someone finds one. Grouped into one PR per month so that a solo project does not drown
  in noise. The base image is watched as well.
- **The Docker base image is pinned by digest** instead of by tag. `python:3.12-slim` points
  here today and elsewhere tomorrow; two builds of the same commit produced different
  images.

Already fulfilled and therefore mentioned only for completeness: **Private Vulnerability Reporting**
is enabled in the repo (checked, not assumed) — SECURITY.md promises the channel, and
it exists.

### Security — second audit: repairing the repairs

Four independent angles, this time aimed at the fresh code itself. **43 findings, 5
blockers** — and three of them were holes that appeared while closing the first six.
That is the real yield of this round: whoever closes a hole does not check their own
closure. Evidence in `tests/test_audit_runde2.py` ([T-9](backlog/T-9-audit-2026-09-21-runde-2.md)).

**The first admin could still be hijacked — via the username.** The new guard
requires an *email* in `admin_identifiers` when signup is open, on the grounds that "whoever has the
mailbox has the name". But `maybe_promote_admin` still compared *name OR email*,
and a username is a free text field: whoever registered as `username="chef@example.com"`
and confirmed their own mailbox became the first admin. The hole had merely moved.
Now the rule is: an entry with `@` is matched only against the email, one without `@` only against the name.

**An API key scope that shrank to nothing became "inherits everything".** `["lagre"]` — a
typo — was trimmed to `[]`, and `[]` means "no scope" in the database. The trimming
that was supposed to limit made the key **more powerful**. Such a key is no longer created at all;
what was meant is known only to the caller.

**The CSRF check had a switch chosen by the client.** `require_csrf` skipped itself
as soon as any `X-API-Key` header was present — unchecked, even with `apikey_enabled=False`, and
afterwards authentication continued via the session cookie. It is now skipped only for a
**real** key without a session.

**A scoped key issued itself a more powerful one.** Key management
now requires an interactive session: keys are issued by a human, not by a key.

**A TOTP code was valid any number of times for 90 seconds** — two separate clients could fully sign in with
the same code. NIST SP 800-63B is unambiguous: "Verifiers SHALL accept a given OTP
only once while it is valid." The consumed time step is now recorded (schema 3).

**The unlock token for locked resources was stored in plaintext** in the database and was
identical to the cookie — the same threat model that justifies the session migration, just
one table further (schema 4).

**The migration was not atomic.** `ALTER TABLE` commits on its own; an abort before it
left plaintext tokens in the `token_hash` column — permanently, because detection never
kicks in again afterwards. Now everything runs in one transaction (`BEGIN IMMEDIATE`), and detection
looks for rows that do not look like a hash: this **heals** an already damaged file.
Solved along the way: with several workers, one died at startup with `no such column: "token"`.

**The first-admin guard, `POST /auth/magic/request`** (the only state-changing route without
CSRF) and **[B-1](backlog/B-1-admin-panel-rotiert-csrf.md)** (the panel rolled a new CSRF token on every
call) are also closed — B-1 was filed as "after 1.0" and, through the new
CSRF checks, now affected more paths.

**Further:** recovery codes 64 → **112 bits** (the NIST threshold for unsalted hashing);
scrypt fallback moved to an approved OWASP combination; scrypt hashes now upgrade to argon2
when the extra is installed later (before, existing accounts stayed on the
weaker scheme forever); the session token is renewed on a change of privileges and the CSRF token
rotated at login (both OWASP); `/auth/oidc/start` is rate-limited (before, the only
flow-creating route without it).

### Fixed — `tinysesam backup` modified the file it was supposed to back up

`_oeffne()` used the full `Store` constructor — which sets `journal_mode=WAL`, creates tables
and **migrates**, all before a copy exists. Anyone who did the one right thing before an update
and made a backup thereby lifted the running installation to the new schema while the old code
was still running. The way back was closed, and afterwards a file in the old schema existed nowhere.

`Store.sichere_datei()` now opens read-only. Measured against a real 0.17.0 file: source
unchanged, copy complete and in the old schema.

**And restoring was not documented** — with the same WAL trap, mirrored: after
a crash, `-wal`/`-shm` lie next to the file, SQLite replays them onto the freshly restored
file, the old state is back, and `integrity_check` says `ok`. New: **`tinysesam restore`**,
which enforces the order and verifies the backup before it overwrites anything.

### Added — tools for incident response

**`tinysesam audit`** and **`tinysesam unlock`**. The audit log was readable only via the admin panel,
that is, only as a signed-in admin — unreachable precisely when sign-in
is the problem. And a brute-force lock could not be lifted selectively at all; what remained was
`gc --attempts-older-than 0`, which clears the failed attempts of **all** accounts.

In addition, the log now records **why** a sign-in failed (`kein_konto`,
`konto_gesperrt`, `falsches_geheimnis`). The HTTP response deliberately still does not — only the operator reads along in the
log, and there the three most common causes were previously
byte-identical.

**The healthcheck queries the database** (`SELECT 1`, 503 on failure). Before, it only reported that
the process was alive: after a rollback or with a full volume, the service returned 500 to all
signed-in users while Docker kept the container as `healthy` indefinitely.

**`deploy/systemd/`** ships a timer and service for `gc` — the README pointed to it without
a template being included — along with a word on retaining the audit log (it stores
IP addresses) and on the `VACUUM` without which `gc` does not give back disk space.

**The shipped Compose file and the shipped fail2ban jail did not fit together:** the
Compose file set no `TINYSESAM_SECURITY_LOG` and mounted no log directory, so the jail
pointed to a file that never existed. Two building blocks that each looked right and together
did nothing.

### Fixed — fail2ban could be turned against third parties

The username went **unfiltered** into the log line that fail2ban reads. A `\n` in it creates an
extra line; with a line break at the front and the back, the real `ip=` entry is pushed onto
a following line that the filter no longer matches, leaving a freely invented one
in between. fail2ban then counts the failed attempts of an IP **chosen by the attacker**, while the
real one produces zero hits — with `maxretry = 6`, six requests suffice to lock out
any address. Proven against real fail2ban 1.1.1.

Control characters are now dropped, the length is capped, and the shipped filter is anchored to
the whole line (`^…$`) — anyone running an older version should adopt the filter.

### Fixed — the project's own checks claimed more than they measure

Every promise was cross-checked by mutation; seven did not hold:

- **In the git worktree, the entire repo hygiene check evaded itself** — there `.git` is a *file*, and
  the check asked `.is_dir()`. Private infrastructure, secrets, SHA pins: all gone, run
  green.
- **`run_all.py` had no floor:** exit 0 even with "0 green, everything skipped".
- The **PyPI secret check** could be defeated with a `name:` above the step.
- **`test_repo`** caught `import subprocess`, but not `from subprocess import run` and not
  `os.system` — right next to a security claim. It now runs over the syntax tree, including
  alias resolution.
- **`test_api_surface`** did not freeze class attributes (`FORWARD_HEADERS_DEFAULT` is a
  promise in the docs and could have been changed silently).
- **`test_kern_install`** measured text occurrences instead of behavior in two places.
- **`test_typen`** ran mypy without `--check-untyped-defs`: 120 of 410 functions unchecked,
  including all four presets. With the depth, six real errors turned up immediately.

Two suites had also **cemented the TOTP replay** (the same code twice). A
test that secures a broken behavior is itself a finding.

### Changed — ⚠️ note when updating: what changes in behavior

**The public surface almost does not break:** no method was removed or renamed, no
parameter dropped, no config field changed its type. The seven signatures that
`tests/api_surface.json` records as changed are exclusively `x: bool = None` →
`x: Optional[bool] = None` — identical at runtime, just annotated more honestly.

**One exception: `passkey_enabled` is now `False`** (before `True`) — the only
default that changed. It was `True` even though `webauthn` is not in the core
but in the `[passkey]` extra: the very first step of an installation without extras crashed with
`ModuleNotFoundError: webauthn`. Anyone who uses passkeys and **never set** the switch
must set it now (`passkey_enabled=True` plus the extra) — otherwise the passkey routes and the button
on the login page disappear after the update. Stored credentials remain in the
database and are immediately usable again as soon as the switch is set.

**Behavior changes nonetheless**, and exactly where a security fix demands it. No
API guard sees that. The list, sorted by impact:

**Startup aborts when the configuration contradicts itself** (new; before, it ran):

| Configuration | Why `ConfigError` now |
|---|---|
| `totp_required=True` | The switch was never read — it promised 2FA and delivered none. Replacement: `login_chain=['password','totp']` |
| `admin_identifiers=[…]` + `allow_signup=True` | Whoever guesses the address registers under it and becomes admin. Allowed with a confirmed email |
| `cookie_samesite` outside `lax/strict/none` | Starlette only checked at the first cookie — and under `python -O` not at all |
| `cookie_samesite='none'` without `cookie_secure` | The browser discards such a cookie; sign-in would never arrive |
| no active sign-in method | Nobody can sign in, and nothing said so |
| `login_chain` with a disabled or unknown step | The chain is unfulfillable, the user ends up in a loop |

**Anyone using the Store API directly** reads `row["token_hash"]` instead of `row["token"]` —
session tokens are now stored in the database only as sha256. The write paths
(`set_session_mfa`, `set_session_factors`, `delete_session_by_handle`) take this handle and
**throw** on a plaintext token instead of silently running into the void. The database migrates itself
on first start; **existing sign-ins stay valid**.

**Six user-facing methods now return a `dict`** instead of a `sqlite3.Row` (`get_user`,
`find_user`, `check_password`, `check_ldap`, `check_saml`, `pending_user`). Access via
`u["name"]` works unchanged; `.get()` now works in addition. Anyone type-checking
against `sqlite3.Row` must adjust.

**Four routes now require a CSRF token** — `POST /auth/totp/disable`, `/auth/totp/recovery`,
`/auth/pin/disable`, `/auth/apikeys/{id}/revoke` —, and in the admin panel it applies to **every** non-read
method. A custom UI that calls these endpoints without `X-CSRF-Token` gets 403.

**Further behavior changes:**

- **SAML is now exclusively SP-initiated.** IdP-initiated logins no longer work
  (the entry point is `/auth/saml/login`), and the flow cookie survives the IdP's cross-site POST
  only with `cookie_secure=True`.
- **Forward-auth headers always go over the wire as UTF-8.** A downstream app that
  reads `Remote-Name` as Latin-1 sees garbled characters for umlauts — in return, names
  like "Иван" work at all for the first time.
- **API keys are taken along when locking out:** admin password reset, locking an account and
  "end **all** sessions" (`scope=all`) revoke them. Your own password change does not.
- **An API key can never have more roles than its owner.** Keys that previously
  carried invented roles lose them on next use.
- **A successful login now clears only the failed attempts of the same method.** Anyone who relied on the
  earlier behavior will see locks on other factors persist longer.
- **HTTP error texts are translated.** Anyone who checked for the German wording of a `detail` message
  must switch to the status code.
- **A newly created database gets `0600`.** Existing files are not changed —
  but a second process running under a different identity can no longer read a new file.

**The second audit added further behavior changes:**

- **A TOTP code is valid exactly once.** Anyone who submits the same code twice — an automation, a
  test, a double-click on "Submit" — gets a rejection the second time. Two of our own
  suites had done exactly that.
- **API keys are issued from a session, not with an API key.**
  `POST /auth/apikeys` and `…/revoke` respond with 403 if the caller is signed in via key.
- **An API key scope that matches no role of the owner is rejected** instead of trimmed
  (`ConfigError`). Before, this produced a key that inherited *all* roles.
- **The CSRF exception applies only to a real API key without a session.** Anyone who previously sent an
  arbitrary `X-API-Key` header and signed in via cookie now gets 403.
- **`POST /auth/magic/request` requires a CSRF token.**
- **The session token is renewed at the second factor.** Anyone who holds on to the token itself (instead of
  following the cookie) must adopt the new value; `complete_totp()` returns it.
- **`admin_identifiers` now distinguishes:** an entry with `@` applies only to the email, one
  without only to the username. Anyone who meant both enters both.
- **Unlocks for locked resources from before the update are discarded** — they
  cannot be converted. Affected users reopen the resource with their secret.
- **`forward_headers` requires strings or lists of them**; `None` and numbers are now rejected at
  construction instead of producing a 500 later.

**Not affected:** `complete_mfa()` remains as an alias of `complete_totp()`, all
previous exports remain, and the four new error types inherit from the built-in type they
replace — `except ValueError` and `except RuntimeError` still catch.

### Security — six holes closed, each with its attack recorded

Found in the maturity review before the planned 1.0. Each of the six was reproduced
individually before it was repaired, and each now has a check in
`tests/test_sicherheit_befunde.py` — named after the **attack**, not the function: anyone
who sees one of them red knows immediately what has become possible again. Every fix was additionally cross-checked by
switching it off (mutation): without it the check goes red, with it green.

**Role escalation via self-issued API keys.** A user could give their own key
any roles — including `admin`. `create_api_key` now trims them to the roles
of the owner and reports the discarded ones back. And because a key outlives its owner: on
verification it is trimmed again with the owner's current roles, a revoked right does not live on
in the key.

**The OIDC callback was bound to no sign-in attempt.** Whoever held a valid authorization code
could redeem it in a stranger's browser (login CSRF). The flow is now tied to a
short-lived, httponly cookie; the callback requires it, compares in constant time,
and deletes it afterwards.

**SAML accepted assertions that were never requested.** `InResponseTo` bound the response to
nothing — python3-saml checks the field only if it is present at all; a response without it
passed. The ID of the AuthnRequest is now kept and strictly required on redemption.
This version is thereby explicitly **SP-initiated**: IdP-initiated logins no longer exist.
Note: the flow cookie must survive the IdP's cross-site POST, which works only with
`SameSite=None; Secure` — with `cookie_secure=False` the config value stays as it is and a
real IdP login fails (the reason is then in the `tinysesam.security` log).

**Four state-changing routes without CSRF protection.** Disabling TOTP, reissuing the
recovery codes, disabling the PIN and revoking API keys could be triggered
from foreign pages — the second factor could be disabled via a form. All four
now require a token; in the admin panel this applies to **every** non-read method. In addition,
disabling TOTP and PIN appeared in no log: anyone who loses the second factor should be able
to read up on it.

**A successful password cleared the lock on the second factor.** `record_login` cleared
*all* failed attempts of an account on success, including those of TOTP — whoever had the password
thereby reset the counter and could keep guessing the second factor. Now only the method
that actually succeeded is cleared.

**The first admin could be hijacked via registration.** `admin_identifiers` vouches for which
*name* becomes admin — not who gets it. Together with open self-registration, the first
person to guess the address signed in under exactly that one. The constructor now rejects this
combination and names the viable ways (a confirmed email address, or the
one-time token under `/auth/claim-admin`).

### Added — two reference works, both generated

**[`KONFIGURATION.md`](KONFIGURATION.md)** lists all **119** config fields with type, default and
meaning. 39 of them appeared in no documentation before. Generated from the comments in `config.py`
(`scripts/_config_doku.py`) so that it cannot drift apart again — and 32 fields that had no
comment at all now have one. A check demands both: dump up to date, no
field without an explanation.

**[`API.md`](API.md)** lists the frozen surface with signature and first sentence: **106
methods** of `TinySesam` plus the 6 presets of `TinySesamConfig`, 112 entries in total.
68 of them appeared in no documentation before: anyone embedding TinySesam saw the promise "this surface
stays stable" without a place stating what it contains. All now have a docstring.
(Generated like `KONFIGURATION.md` — the number in this paragraph is the state of this release, the
current one is in the file itself.)

**Open and deliberately not decided in passing:** *which* of these methods should be public
in the long run. The surface was measured (everything without a leading underscore), not selected —
that is a product decision and is tracked in [M-1](backlog/M-1-api-stabil-1-0.md).

### Fixed — contradictions in the configuration were noticed only at login

An app **without a single active sign-in method** started without complaint. A `login_chain` that
names a disabled method is unfulfillable and sends the user in circles. OIDC without
`issuer` failed only at the click on "Sign in". `tinysesam/konfigpruefung.py` now checks this
at construction and reports **all** findings together — anyone with three things wrong should read them once
and not start three times.

The line between error and warning is not strictness but repairability: what is
inherently unfulfillable aborts construction; what may still come later — a mailer is
typically set after the constructor — is logged. In addition a guard for
`cookie_samesite`, which Starlette previously checked only at the first cookie (and under `python -O`
not at all).

### Changed — `complete_totp()` instead of `complete_mfa()`

The old name promised more than the method does: MFA is the whole chain, here it is about exactly
one factor — and the docstring itself called it "backward compatible", without there having been
any other. `complete_mfa` remains as an alias and is not removed.

### Changed — the API guard captures more

It recorded the name and type of config fields, but **not the defaults**: `session_ttl_hours`
could be silently changed from 168 to 1 — a behavior break for anyone who never touched the field.
Likewise the **return types** of the methods were missing; `-> dict` to `-> str` would have gone through
unnoticed. Both are now measured as well.

### Changed — the source package carries the test suite, in full

Until 0.18.0, `MANIFEST.in` contained `prune tests`, with this reasoning: setuptools pulls in only
`tests/test_*.py` by an old heuristic (without `run_all.py`, without `_kit/`), and two
suites need something a sdist never contains anyway. That reasoning no longer holds. Since this
version, a suite **cancels itself** when a prerequisite is missing (`tests/voraussetzung.py`,
exit 77) — the repo-bound ones thus skip themselves cleanly in the source package and name the reason.

Anyone repackaging TinySesam (a distribution, conda, an internal wheel) can verify the build with it,
and that is the point of a source package. Measured in the unpacked sdist of this release
(the numbers grow with every new suite, the sentence behind them stays: nothing falls over, and what
cancels, cancels):

```
41/45 grün, 4 übersprungen, 0 fehlgeschlagen
```

`examples/showcase.py` and `deploy/` are now included as well — both are linked in the README,
and a dead link is more annoying in a tarball than on the web, where GitHub sits next to it.
`web/` stays out: the generator of the project page is a repo matter, not part of the library's source.

### Fixed — error types, schema stamp, recovery codes

**There were no error types one could react to.** What was thrown was `ValueError`
(configuration) and `RuntimeError` (missing extra); anyone who wanted to tell at startup whether
the configuration is wrong or a package is missing had to read the message text — and that is
translated as of this version. New and exported: `TinySesamError`, `ConfigError`, `MissingExtra`
(carries the name of the extra as a field), `MailNotConfigured`. Each additionally inherits from the
built-in type it replaces — `except ValueError` still catches, nothing breaks.

**A missing extra reported itself differently depending on the method**: understandable for passkey, otherwise as a
`ModuleNotFoundError` from deep inside the library or only at the first login as a 500. Now
in two stages:

* **At construction** TinySesam warns if a fully configured method cannot find its module
  — in the log, with the missing install line.
* **On the first real use** a readable `MissingExtra` is raised (with the extra's name as a
  field) instead of a bare `ModuleNotFoundError`.

Why not simply abort at construction: a client is replaceable — `auth.ldap = own_client`
is a legitimate path, and four of our own suites take it. A guard that trips already at the switch
forbids it. The first version did exactly that and paralyzed the `minimal` job of the CI;
now it raises only where it can never be wrong.

**The database carried no schema stamp.** Which state a file is in could only be guessed from its
column names, and a file from a *newer* version was silently opened by an older one. Now
`PRAGMA user_version` is set, and a file from the future announces itself.

**Recovery codes carried 48 bits.** They replace the second factor and stay valid until they are
used — unlike a TOTP code, which is worthless after 30 seconds. Newly generated ones carry
**112 bits** (`RECOVERY_BYTES = 7`, two halves per code); existing ones stay valid (only the hash
is stored anyway). Above in the same section the value is stated correctly — here, until
2026-09-21, the 64 from an intermediate state stood.

### Fixed — the responses spoke German, even in English

**32 HTTP responses carried hard-coded German text** — CSRF errors, "admin rights required", OIDC and
passkey messages —, even in an installation with `lang="en"`. The UI was bilingual, the
responses to machines and proxies were not. They now go through the translation table
(prefix `api.*`, separate from the `err.*` of the UI pages). A hygiene check forbids hard-coded
text in an `HTTPException` so that the gap does not grow back on its own.

For this, `OIDCClient.exchange()` accepts the caller's translation function (`t=auth.t`).
The client itself knows no language — it speaks the protocol, not to the user; without `t`
its two messages stay English, instead of slipping German to a caller with `lang="en"`.

### Fixed — the gateway did not start by its own instructions

The README named `pip install 'tinysesam[oidc]'` and `python -m tinysesam.gateway` in the same
breath. But `[oidc]` brings no ASGI server: the start command ended in a
`ModuleNotFoundError: uvicorn`, which looked like a defect instead of a missing line in the
install command. That the Docker image ran was due to a patch in the `Dockerfile` that installed `uvicorn`
by hand on the side — it hid the gap in the extra.

New: **`pip install 'tinysesam[gateway]'`** (= `[oidc]` plus server). If the server is missing anyway,
the gateway says which line is missing instead of showing a stack trace. `--help` now prints a
help text and exits with 0 — before, the question landed in the uvicorn import and afterwards in a server
on `0.0.0.0:8000`: anyone who wanted to know what the thing is called had it running. An unknown
argument ends with 2.

### Fixed — the PyPI page showed a dead logo and seven dead links

`README.md` is also the project description on PyPI, and there nothing resolves relative
repo paths. All links in this file are now absolute; a check pins it down. The
German version under `i18n/` is read only on GitHub and may stay relative.

In the same go: both READMEs advertised an **update button** in the admin panel ("mode manual/auto,
version pin, update now"). It has deliberately not existed since 0.12.0
([ADR-2](backlog/ADR-2-kein-selbst-update.md)) — the panel shows the version and a notice.

### Fixed — `Typing :: Typed` was a promise nobody had measured

The package carries the classifier and a `py.typed`: the promise to every user that the
annotations are correct and their type checker may rely on them. At the first measurement
there were **30 errors in 6 files**.

The most tangible of them: six user-facing methods were annotated `-> Optional[dict]` and
returned a `sqlite3.Row`. Anyone who believed the promise and wrote `user.get("email")` got
an `AttributeError` from a line that, according to the type, could not be wrong. `get_user`,
`find_user`, `check_password`, `check_ldap`, `check_saml` and `pending_user` now
really return a `dict` — at the store level the Row remains, where it is documented and intended.

The remaining 24 were annotation errors without runtime effect (mostly `x: bool = None` instead of
`Optional[bool]`), plus two places where an abort path was not annotated as such
(`_deny`, `_redirect_factor` are now `NoReturn`).

**A real bug turned up in the process:** `cookie_samesite` was never checked. Starlette rejects
a wrong value with an `assert` — so only at the first cookie, and under `python -O` not at all;
the typo would then end up in the `Set-Cookie` header. The constructor now checks it, including
the combination `samesite='none'` without `cookie_secure` (which a browser discards).

So that the promise stays **measured**: `tests/test_typen.py` runs mypy over the library and
additionally checks against the actual return value what the signatures promise. mypy runs in CI and
is included in the `ci-python-web` image — without that, the suite skipped itself, and the
run still looked green.

**On the API surface:** `tests/api_surface.json` records the new annotations as a "break".
It is not one: `x: bool = None` and `x: Optional[bool] = None` behave the same at runtime,
the signature has merely become more honest. No caller has to change anything.

### Fixed — a security switch that never did anything, and a page list that was wrong

**`totp_required` had no wiring.** The switch was in the config, in both READMEs
("enforce 2FA") and on the website — and was read nowhere. Anyone who set it
believed the second factor enforced and did not have it. A security switch without effect is more dangerous
than none at all, because it ends the search for the right way. The constructor now rejects it and names
the path that works: `login_chain=['password', 'totp']`. The docs name it as well.

**`set_template` accepted names that did not exist.** The docstring listed `'magic_sent'` and
`'resource_pin'` — neither ever existed — and left out seven real pages. A
typo had silently no consequence: the custom page was registered and never served. The
list is now `TinySesam.SEITEN` in the code, an unknown name is an error, and a
check compares it against the pages that `render_page()` actually serves.

**SECURITY.md named `0.5.x`** as the series that receives security fixes — thirteen
minor versions old. It now points to the CHANGELOG head instead of a number that goes stale.

### Fixed — behind a proxy, all users appeared under one IP

Four findings, one theme. Common consequence: lockout, rate limit and fail2ban acted **collectively**
instead of per user — and in the worst case fail2ban bans the proxy, that is, everyone. None of it looked like
an error.

**SSO and passkey logins wrote the raw peer IP.** `oidc.py` and `webauthn_.py` accessed
`request.client.host` directly and thereby bypassed `trusted_proxies`; behind a proxy, its
address ended up in the session list, in the log and in the IP lock. Both now use
`client_ip()`. An unused helper in `router.py` that pretended to do the same wrongly
is gone.

**The default does not fit in a container — and that stayed silent.** `trusted_proxies` is set to
`127.0.0.1/32`; in a container, however, the proxy is a different container. X-Forwarded-For is then
discarded without anything reporting it. `client_ip()` now notifies once per peer,
with concrete advice (`trusted_proxies=['<network of the proxy>']`).

**`0.0.0.0/0` devalues X-Forwarded-For instead of trusting it.** If every address counts as a proxy,
none remains as the client — `client_ip()` falls back to the peer IP. That sounds generous
and is the opposite. This case now reports itself as well.

**The shipped Compose file made exactly this mistake.** `TINYSESAM_TRUSTED_PROXIES: "0.0.0.0/0"`
is replaced: the example brings its own network with a fixed subnet and enters that —
a bridge address assigned by the Docker daemon could not be entered at all. A check
pins this down.

### Fixed — promised Python versions are now measured

The classifiers promised 3.10 to 3.14, the CI matrix ran **3.10, 3.12 and 3.14** — 3.11 and
3.13 were a claim. The matrix now runs all five, and a hygiene check compares
classifiers against the matrix: whoever promises a version in future must also run it (or remove the
classifier).

The trigger was a failure of our own: `tests/test_kern_install.py` imported `tomllib`, which exists
only from 3.11 — on 3.10 the test died. Because `ci-local` runs only **one** Python version, this
was noticed only in the GitHub matrix; the gate did what it is there for. The test now reads the
core dependencies from the **package metadata** (`importlib.metadata.requires`) instead of from
`pyproject.toml` — that runs on every version and also measures closer to the subject: what is
really there after `pip install tinysesam`. A second hygiene check catches standard-library
names that are younger than the oldest promised version.

### Fixed — operations: backup, cleanup, log ([T-8](backlog/T-8-reifepruefung-restbefunde.md))

**A file copy of the database was worthless.** It runs in WAL mode; anyone who backs up only the `.db`
gets a torso — measured, the copy of an instance with five accounts did not even contain the
table `users`, and you only notice when restoring. New: `tinysesam backup --db … <target>`
and `store.backup(path)` via SQLite's online backup, during operation, with the same narrow
permissions as the source.

**Cleanup had no way in from outside.** `auth.gc()` existed, but nothing called it, and in the
gateway image one could not get at it. New: `tinysesam gc --db …` for cron or a systemd timer.
Incidentally: `python -m tinysesam --help` now exits with 0 instead of 2 — a question is not a typo.

**From the first log rotation on, the guard no longer watched.** The security log ran through a
`FileHandler`, which keeps the inode open: logrotate renames, creates anew, and from then on TinySesam
wrote into the *renamed* file. The fail2ban jail read the empty new one — without error, without
message. Now a `WatchedFileHandler`, which checks inode and device before every line.

**The app lockout blinded fail2ban.** As long as an account was locked, the app answered 429
without logging an attempt — the log fell silent at exactly the moment the IP
should have been banned. Rejections due to lockout or rate limit now write a line,
**in the same format as a real failed attempt**, so that the shipped filter takes effect immediately,
even in installations that never touched their filter file. The reason is attached as `reason=`
(`lockout_user`, `lockout_ip`, `ratelimit`).

**Admin actions appeared in the log without actor and without IP.** It recorded *that* an account
was locked, not by whom — with several admins exactly the question asked afterwards.
All eight panel actions now run through a common path that records both.

### Security — four findings from the second round ([T-8](backlog/T-8-reifepruefung-restbefunde.md))

The maturity review reported 35 further findings that nobody had reproduced individually. They are
examined in turn — confirmed, refuted or filed as a matter of taste. These four were
confirmed:

**Session tokens were stored in plaintext in the database.** Now only their sha256 is stored there; the
plaintext lives between `create_session()` and the cookie. Everything that comes out of a session row
(`token_hash`) is thereby a handle: it names a session for ending and is useless
for signing in. The pattern already existed in the same house — `magic_token` has kept it that way from the start.
**Existing sign-ins survive the migration:** the hash can be computed from the plaintext,
the migration computes it on first start. Anyone using the Store API directly reads
`row["token_hash"]` instead of `row["token"]`; the write paths (`set_session_mfa`,
`set_session_factors`, `delete_session_by_handle`) take this handle and **throw** on a
plaintext token instead of silently running into the void.

**The admin panel handed out the session tokens of all users.** `GET /admin/api/sessions` returned
the real token of every foreign session to the browser — meant for ending, suitable for taking over.
It now returns the handle.

**The database was created world-readable (0644).** It holds password hashes,
TOTP secrets and email addresses. A new file is now created directly with `0600` — not
via `chmod` afterwards, which would have a window in which it stands open, and exactly in that window
SQLite writes the schema into it. WAL and SHM hold the same data and get the same permissions. An
**existing** database is not rewritten (a deliberate group share is the
operator's decision), but it is named in the log together with the necessary command.

**API keys survived lockout.** A key hangs on no session; whoever reset an account
only closed the front door. Now: the **admin reset** and **locking** an account
revoke the keys (the intent is unambiguous there). Your **own** password change deliberately leaves
them in place — a routine change should not shut down automations —, but names their
number in the response (`api_keys_active`) and in the log. "End all sessions" (`scope=all`)
takes them along, "end others" does not. (The key of a **deactivated** account was never valid —
`verify_api_key` checks the flag; the reported finding reached further here than it held.)

### Added — publishing to PyPI is prepared (not yet carried out)

Metadata, `MANIFEST.in`, a packaging test and the release workflow are ready. **Installation
continues via the pinned Git tag** — the upload happens only with 1.0, and 1.0 comes only
once the findings from the maturity review are worked off.

The packaging test paid off immediately: the sdist contained **half a test suite**
(setuptools pulled in `tests/test_*.py` by an old heuristic, without `run_all.py` and without
`_kit/`) — what would have shipped is a suite that fails at import.

**Publishing happens without a secret.** The release workflow identifies itself to PyPI via its
own OIDC identity (Trusted Publishing) — no token in the repo, none to rotate, none that
could be extracted from a run. Each file additionally carries a PEP 740 attestation:
verifiable which commit it was built from. It is triggered solely by a tag that a
human sets. Rationale and the one-time setup: [ADR-6](backlog/ADR-6-pypi-veroeffentlichen.md),
fields in the head of `.github/workflows/release.yml`.

[ADR-1](backlog/ADR-1-pypi-vertagt.md) ("deferred until 1.0") is thereby set to `verworfen` — with
a pointer to its successor and unchanged text. The decision was not wrong, it has been fulfilled.

**On the API surface.** Measured for the window `v0.16.0` → `v0.17.0`: **zero breaks, zero
extensions** — there the surface is the same character for character. That was the third
condition for 1.0 and is proven for this period. **For 0.18.0 this no longer holds**: this
release brings new methods (`complete_totp`, `csrf_rotieren`), new exports (`TinySesamError`,
`ConfigError`, `MissingExtra`, `MailNotConfigured`) and the changed default of
`passkey_enabled` — the clock for "two minor versions without a break" thereby restarts.

It does not carry 1.0 anyway: the promise never had to hold under changes, because 0.17.0 did not touch
the library at all. And the security fixes of this version change **behavior**
that users could (wrongly) assume until now — a measured surface says nothing about that.
[M-1](backlog/M-1-api-stabil-1-0.md) remains open.

### Added — `tests/test_packaging.py`: the package as it arrives

Up to here, what lies in the repo was checked. On PyPI, what lies in the wheel counts — and those are
two different lists. A wheel missing a file installs cleanly and is noticed only
on a stranger's machine; a version in the index cannot be taken back.

The suite therefore **builds** wheel and sdist (offline, from the versioned files, outside the
working tree) and looks inside: every versioned file under `tinysesam/` is in the wheel — today
that is only `py.typed`, but the first template someone adds is silently missing without an entry under
`[tool.setuptools.package-data]`. Plus the metadata the index depends on:
no more `Private :: Do Not Upload`, maturity level matching the version, every Python version run by CI
also declared as a classifier, lower bound equal to `requires-python`, all five
project links set, README as Markdown in the package. And that the release workflow
publishes without a secret.

`setuptools` thereby becomes part of the test environment — since Python 3.12 a fresh environment no longer
ships it. The CI jobs and `scripts/check.sh` install it explicitly; if it is missing, the suite is
red instead of skipped. A test without prerequisites must not look green.

### Fixed — the sdist contained a test suite that could not be started

Found by the new packaging test, on the first run. setuptools pulls `tests/test_*.py`
into the source package by an old heuristic — but neither `tests/run_all.py` nor `tests/_kit/` nor
`tests/api_surface.json`. Anyone who unpacked the sdist found a suite that fails at import.
That is worse than none: it claims a testability that does not exist.

A `MANIFEST.in` now decides the question explicitly. The first answer to it was
`prune tests` — the sdist as the **source of the library**, without a test suite, because two suites
need something a source package never contains anyway. That answer **did not hold within the
same release** and was replaced: since this version, a suite cancels itself when a prerequisite
is missing (exit 77), and so the sdist carries the **complete** suite (`graft tests`, plus
`examples/` and `deploy/`). The section further above — "the source package carries the test suite,
in full" — is the state that ships.

### Changed — package metadata completed

`Development Status` to `4 - Beta` (in the first attempt this said `5 - Production/Stable` — reverted with
the withdrawal of 1.0, the rationale is in the head of this release), the supported
Python versions (3.10–3.14)
as classifiers, plus `Typing :: Typed`, `Topic :: Security` and the audience of administrators.
`[project.urls]` now names all five targets a visitor to the index page looks for: website,
docs, repo, CHANGELOG, issues. The short description is English like the README and website, instead of
German and three times as long.

Deliberately **not** switched: `license` stays the table form instead of the SPDX expression from
PEP 639. That requires setuptools ≥ 77, and builds also happen with older ones — the reason is in
`pyproject.toml` right next to it, so that it does not have to be worked out anew next time.

## [0.17.0] — 2026-09-20

A release **with no change to the library**: anyone who embeds TinySesam gets the same code
as with 0.16.0 — the wheel differs only in its version number. It is still worthwhile, because
the image is built with updated tooling and because the **clock for 1.0 starts running** here:
`tests/test_api_surface.py` pins down the public surface, and M-1 requires two minor versions
without a break. 0.17.0 is the first of them.

If you are on 0.16.0 and need none of this, you can skip it.


### Changed — all GitHub Actions brought up to date

Eight actions updated, including one major (`setup-python` 6 → 7: removes the `pip-install` input,
which we never used). For each one the **runtime at the new SHA** was checked — all eight
run on `node24`. That is the point a SHA pin alone does not cover: it freezes the action,
not the Node version it runs on; an outdated runtime goes unnoticed until GitHub
switches it off.

Five of the updates arrived as individual proposals, three had not been reported by anyone yet. Combined,
because `main` is required to be "up to date": every single merge would have made the other four
stale and triggered six CI runs.

### Added — the public API is measured, not asserted

Both of the last two releases broke the API, and both times it was only noticed while writing the
CHANGELOG. `tests/test_api_surface.py` now pins down the surface (manager methods,
config fields, presets, exports — 231 names) and reports every deviation. It forbids nothing, it
forces a deliberate decision: `python tests/test_api_surface.py --update`, then commit.

The distinction matters here: a **break** (removed, renamed, incompatible signature) is
something different from an **extension** (parameter with a default value appended — existing calls keep
working). A guard that cries wolf over harmless changes gets clicked away, and then the
real one is missed. Counter-check with the two real cases: `require_role` (keyword-only) is reported
as a break, `magic_url` (new parameter with a default value) as an extension.

### Added — `scripts/_release.py`: the manual steps before a release

The version appears in six places and in the CHANGELOG. Maintaining that by hand worked,
because a test complains when you forget one — but "works because a test complains" is
a loop of error and correction, not a procedure. `python3 scripts/_release.py 0.17.0` sets
everything and closes the CHANGELOG section; `--pruefen` only checks.

Deliberately **not** included: tagging and pushing. A human presses the button — the same separation as
with rollout. Both feed into [M-1](backlog/M-1-api-stabil-1-0.md).

## [0.16.0] — 2026-09-19

> ⚠️ **Breaking change.** `/auth/magic/…` confirmation and invitation links that have already been sent
> become invalid — anyone with such emails in circulation has to resend them after the update.

The release from real-world use. Anyone who hangs TinySesam in front of third-party apps as **forward auth** should
install it: there was a silent redirect loop there, roles could not be checked at the proxy at all,
and which headers go out was not configurable. Anyone who embeds it **in** their app
gets dedicated endpoints for email confirmation, invitation and password reset (until
now they all hung on the magic link), `require_role()` with multiple roles, and a maintenance command for
the case where the admin password is gone.

On top of that, two things you cannot see but that count: the three sign-in ceremonies
(passkey, OIDC, SAML) ran **against real counterparties** for the first time — and found
a bug right away. And every artifact of this release carries a signed provenance attestation
plus an SBOM.


### Changed — the E2E stage is built by playbook, no longer by hand

`tests/e2e_stage.py` needs an instance with a real domain, a real certificate and an
identity provider next to it. Until now that existed only because someone had set it up — what exactly
was running was known only to whoever was there. Now a run builds it from a fresh throwaway container,
and the second run changes nothing. The playbook lives in the deploy repo: addresses and
credentials do not belong in a public repo; only the call leads from here. Closes
[T-6](backlog/T-6-stage-per-playbook.md).

### Added — provenance and contents of the artifacts are now attested

A digest proves that an artifact has not changed since it was built — **not who
built it**. Anyone who gains access to the registry can push their own image under the same tag;
anyone who only pulls the tag notices nothing.

Every release therefore now carries a provenance attestation signed via **Sigstore** and an
**SBOM** — for the gateway image as well as for the wheel and sdist. Signing uses the OIDC identity
of the release workflow: no key that has to be handed out, and none that can be lost.
The image attestation is additionally stored in the registry and can therefore be verified even without this repo.

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:vX.Y.Z --owner Ollornog
```

The SBOM is generated from the **pushed** image, not from the build directory — otherwise it would describe
something other than what was delivered. Closes
[T-5](backlog/T-5-abbild-signatur-pruefen.md).

### Fixed — a rejected SAML assertion could not be diagnosed

`SAMLClient.process()` threw away `get_errors()` and `get_last_error_reason()` and returned only `None`;
the ACS then showed the **magic-link** error page ("this link is invalid,
expired or already used"). Anyone debugging a SAML sign-in therefore saw a message about
a link that never existed, and nothing appeared in the log.

The reason now goes to the `tinysesam.security` logger — and only there: whoever sends the response
should not learn why it failed. The ACS answers with 400 and a message
that talks about the identity provider.

Found on the first run against a **real** IdP: Keycloak's entity ID is `…/realms/<realm>`,
not the SSO URL. Without `saml_idp_entity_id` the check therefore rejects every assertion — previously
silently. The field already existed; the config and both READMEs now state when it has to be
set.

### Added — `tests/e2e_stage.py`: the ceremony against a real instance

Passkey, SAML and OIDC had so far only been tested for **structure**: what was checked was that the right
fields are set and the right switches are flipped — never the ceremony itself against a
real provider on a real HTTPS domain.

The new run does exactly that, in a real browser via the DevTools protocol: register a passkey
and then sign in passwordless (virtual authenticator, but real `rp_id`), SAML against
a real IdP, OIDC against a real provider. It drives the **built-in** UI,
not rebuilt JS — otherwise the test would be checking its own code.

Deliberately **not** a CI test and deliberately not named `test_*.py` (otherwise `run_all.py` picks it
up): CI has no domain, no certificate and no IdP; a test that reproduces those checks
the dummy. Intended as a smoke test after deploy. Addresses and credentials come from the
environment, never from the repo; every part without configuration is **skipped** and reported as such,
never silently counted as passed.

Two things the run learned while it was being built: it waits for **states** instead of for the
clock (fixed wait times made it moody), and it **cleans up after itself** — otherwise the
account accumulates another passkey on every pass. It reports a rate limit or lockout as
such, instead of saying "sign-in failed" and sending the search in the wrong direction. All three paths run through against real counterparties, and the run turns red when
it is broken (wrong password at the IdP, unknown credential: exit 1). Closes
[T-1](backlog/T-1-e2e-gegen-echten-idp.md).

### Changed — shared test base on repokit 0.9.0

`repokit sync`. Two fixes, both reported from a fresh bootstrap: the hygiene test fired
on `runs-on: ubuntu-latest  # niemals self-hosted` — that is, on a line that
follows the rule and gives the reason for it (it now reads the code without the comment behind it, and only
that). And `_backlog.py index` wrote "— — done" for a milestone without tasks, where
checkbox and text contradicted each other.

### Changed — email confirmation, invitation and password reset have their own endpoints

> ⚠️ **Breaking change.** `/auth/magic/…` confirmation and invitation links that have already been sent
> become invalid.

All four token purposes ran through `/auth/magic/{token}`, and this route existed only with
`magiclink_enabled=True`. Anyone who switched off the sign-in link by email — an obvious step as soon as you use
passwords or SSO — thereby lost **email confirmation and invitation as well**, two things
that have nothing to do with it. During the rework a third case turned up: the reset route required
`password_reset_enabled AND magiclink_enabled`, although it had long had its own endpoint.

| Purpose | before | now |
|---|---|---|
| Sign-in link | `/auth/magic/{token}` | unchanged |
| Confirm address | `/auth/magic/{token}` | `/auth/verify/{token}` (tied to `signup_verify_email`) |
| Invitation | `/auth/magic/{token}` | `/auth/invite/{token}` (tied to `allow_signup`) |
| Password reset | `/auth/magic/{token}` → detour | `/auth/reset?token=…` directly (tied to `password_reset_enabled`) |

**Breaking:** Confirmation and invitation links already sent to `/auth/magic/…` are
invalid. Anyone with such emails in circulation resends them after the update. `/auth/magic/{token}`
now accepts only `login` tokens and rejects others **without consuming them**.

Anyone who builds the links themselves: `auth.magic_url(raw, base_url, purpose)` picks the path per purpose
(`TinySesam.TOKEN_PATHS`). Closes
[T-4](backlog/T-4-verifikation-ohne-magic-endpoint.md).

### Fixed — browser test: the test server port was a race

`tests/test_browser.py` found the port for the uvicorn test server by binding a socket,
closing it again and passing on the number. In between, another process could take it —
on a runner with parallel jobs not a thought experiment, and the test then turns red rarely and
inexplicably. The socket now stays bound and is passed to `uvicorn.Server.run(sockets=[...])`;
the window no longer exists. Chrome had already solved the same problem on its side for a while
(`--remote-debugging-port=0` + `DevToolsActivePort`). Closes
[T-2](backlog/T-2-freien-port-nicht-selbst-suchen.md).

### Added — `forward_headers`: which headers the forward-auth response sets

The set was fixed: `Remote-User/-Name/-Email/-Groups`, the Authelia convention. Not every
downstream app understands these names (Grafana wants `X-WEBAUTH-USER`, applications shaped by oauth2-proxy
want `X-Auth-Request-*`), and not every operator wants to hand out all four — the
email address, for example. Both were previously possible only by bending it in the proxy.

`forward_headers` maps **field → header name** (`user` · `name` · `email` · `groups`), one field
may point to several names. The mapping is the **complete** list, not an addition:
`{"user": "X-WEBAUTH-USER"}` sends exactly this one header. Leaving something out is therefore the way
not to hand it out. Empty = unchanged, the previous set.

It is validated at startup: a typo in the field name would otherwise silently drop the header, and a
header name with a line break would be header injection. Closes
[T-3](backlog/T-3-forward-auth-header-feinsteuerung.md).

## [0.15.0] — 2026-09-19

Forward auth from real-world use — four findings from a third-party deployment that hung TinySesam in front of
a grown site, plus the follow-up in the app. Anyone who embeds TinySesam **in** their app
gets `require_role()` with multiple roles (see the breaking point below) and, with
`security_log`, a fail2ban jail that works without manual effort. Anyone who hangs it in front of third-party apps as **forward auth**
should install this release: there was a silent redirect loop there.

In addition, as begun in the previous cycle, the work on the safety net (backlog in the repo,
nonce-based CSP) — these are invisible to anyone embedding it.

### Fixed — forward auth sent users into a silent endless loop

Without `cookie_domain` the session cookie is **host-only**. The login URL was nevertheless always built on
`base_url`: TinySesam set the cookie on host A and sent the browser to host B, where
it is not sent along — the proxy asked again, it went back to the login. No error message,
no log line, just a loop. Reported from a third-party deployment.

Without `cookie_domain` the login URL is now built **on the requested host**, provided it is listed in
`trusted_redirect_hosts` — the same whitelist prevents a forged
`X-Forwarded-Host` from redirecting anyone. `base_url` remains untouched: OIDC/SAML callbacks still need
the one fixed address. At startup TinySesam also says that multiple hosts without
`cookie_domain` yield **no** shared SSO — that is provable in advance, the hosts are in the
own configuration.

In addition: the host of the own `base_url` now always counts as an allowed `?next=` target and no longer has to
be repeated in `trusted_redirect_hosts`. If you forgot that in single-host operation, the
absolute `next=` was silently discarded and you landed on `login_redirect` after login.

### Changed — `require_role()` accepts multiple roles, one of them suffices

Follow-up to the role check in forward auth: there, since the previous entry, you could say
`?roles=redaktion,lektorat`, but not in the app — `require_role()` took exactly one role,
for an OR you had to write your own dependency. The same question ("who gets through?")
thus meant something different depending on the operating mode, at the expense of the basic model
([ADR-3](backlog/ADR-3-in-app-statt-proxy.md)).

Now: `require_role("redaktion", "lektorat")` or `require_role(list_from_the_config)`, likewise
`require(role=[...])`. Anyone who requires **all** roles stacks two guards — `Depends` dependencies
all run anyway. The 403 message now names all the roles checked.

The call with one role remains unchanged. **The only breaking point:** `mfa` and `admin_implies`
have become keyword-only. A positional `require_role("editor", True)` used to mean
`mfa=True` and would now be a second role named `True` — this breaks loudly with an explanation
instead of silently checking something else.

### Added — roles in forward auth (`?roles=` / `X-TinySesam-Roles`)

`/auth/forward` was binary: signed in or not. Roles only travelled along as a `Remote-Groups` header,
which a reverse proxy cannot do anything with — `require_role` effectively existed only in in-app mode.

Now the proxy says what it requires: `GET /auth/forward?roles=redaktion,admin` or the header
`X-TinySesam-Roles`. One of the named roles suffices, `admin_implies_roles` applies as usual.
If it is missing, TinySesam answers **403** — not 401, which would send the signed-in user to the login and from
there back with the same missing role. The rejection appears as `forward_role_denied` in the
audit log; a 403 in the proxy log does not say who failed at what. Without the specification everything stays
as before. Multiple specifications are ANDed, so that a parameter appended by someone
can only tighten the check. Rationale and the rejected alternative (rule table in the Authelia style):
[ADR-5](backlog/ADR-5-rollen-im-forward-auth.md).

### Added — `security_log`: the fail2ban jail works without manual effort

`deploy/fail2ban/tinysesam-jail.conf` pointed to `/var/log/tinysesam/security.log`, but nothing
wrote there — the wiring was a commented-out Python snippet in the jail file.
Anyone who adopted it got a jail that silently watched a file that never came into existence.
`TinySesamConfig(security_log="…")` now attaches the handler itself (idempotent, with timestamp
in the format fail2ban dates). A path that is not writable warns at startup — a log file is
no reason to shut down the sign-in.

### Added — `tinysesam passwd`: the way back without a mail server

With `local_accounts()`, "forgot password" and magic link are off (there is no mailer), and the
first-admin paths only apply as long as no admin exists. Anyone who lost their admin password had
no documented way back. New: `python -m tinysesam passwd --db auth.db admin` — offline on
the database file, ends the account's open sessions and writes an audit entry.
This does not contradict "no self-update"; the line there is *loading code*, not *maintaining
offline* ([ADR-2](backlog/ADR-2-kein-selbst-update.md)).

### Added — `deploy/forward-auth/nginx-pfad.conf`

A second nginx example for the other common layout: one host, only individual paths
protected, static files and PHP behind it. It exposes three traps, all of which were
reproduced: `location ^~` switches off the regex locations (`.env` ends up being served from the protected
folder), `proxy_set_header Remote-User` does not reach PHP-FPM (it needs
`fastcgi_param HTTP_REMOTE_USER`), and the `Remote-*` headers must be cleared in the open
locations, otherwise a client simply sends them along itself.

### Added — backlog in the repo (`backlog/`)

Milestones, tasks and **architecture decisions (ADR)** now live as Markdown with
frontmatter under `backlog/` — one file per item, checked by the test suite
(`python3 scripts/_backlog.py list|check|index`).

GitHub Issues remain the inbox; whatever is accepted gets an entry here. The
advantage: a task closes **in the PR that completes it** — visible in the diff. And the
hygiene test reads the backlog too, which makes the difference for a public repo.

Four decisions already made have been added as ADRs: PyPI deferred until 1.0,
no self-update, protection in the app instead of at the proxy, no self-hosted runners.
Rejected decisions are not deleted, but get `status: verworfen` **and**
`superseded_by` — a guard enforces the reference.

`TODO.md` keeps the history of the completed versions and points to the backlog.

### Added — nonce-based Content Security Policy for the built-in pages

The built-in pages (login, account, TOTP setup, error) now deliver a **strict,
nonce-based CSP** — without `unsafe-inline`. A nonce is generated per response; it is centrally placed into
every `<script>`/`<style>` and into the `Content-Security-Policy` header. This became possible because the
pages were rebuilt **inline-free**: no more `onclick`/`onsubmit` (one delegated click listener
instead of inline handlers, `data-act` attributes), no `style=` attributes (moved out into classes). A
CSP nonce covers exactly `<script>`/`<style>` blocks — inline handlers and `style=` **not**, which is why
they had to go.

The switch is **`config.csp`**: `"strict"` (default), `"off"` (no header — e.g. when a proxy
or the app sets the CSP centrally) or a **custom policy** (a contained `{nonce}` is replaced per
response). A template override that returns a `Response` is left untouched — it sets its own
CSP; `ctx["nonce"]` is available to it.

Why this matters: anyone embedding TinySesam can now put their app under a strict CSP without
the login/account page breaking — it brings its own, matching CSP. Proven in the browser
(`test_browser.py`): under the strict CSP **no** `securitypolicyviolation` fires; with a deliberately
wrong nonce Chrome blocks every script/style (negative test). Functional test: `test_csp.py`.

### Changed — contradictory HTTPS configuration is rejected at build time

Two holes, both silent:

`https_mode` was **not validated at all**. Only `== "force"` is evaluated — anything else means
"no redirect". A typo (`"forse"`) therefore switched off the HTTPS enforcement without a word, without an error,
without a hint. Now only `off`/`warn`/`force` are allowed, as already with `login_identifier`.

`https_mode="force"` together with `cookie_secure=False` contradicts itself: the app redirects every
request to HTTPS and still hands out the session cookie without the `Secure` flag — a single HTTP request
is enough for it to travel in plaintext. This combination is rejected.
`cookie_secure=False` remains correct and allowed for local setups without a certificate.

Only **what the app says about its own behavior** is checked, not what it
claims about the outside world. A first version also fired on `base_url="https://…"` + `cookie_secure=False`. That
sounded like the same error, but was not: `base_url` is the public address from which SAML
and OIDC build their callbacks — it says nothing about the transport between browser and app. Four
of our own suites need exactly this combination (public HTTPS URL, `TestClient` on `http://`),
and a guard that fires wrongly four times in its own house will do so all the more for users. The
rule is therefore out again.

### Added — the cookie flags are now under supervision

The flags were right in the code, but no test pinned them down: `grep -rln "httponly" tests/`
came back empty. A refactor that drops `httponly=True` from the session cookie would have gone green through
the suite — an auth library that hands its session to any XSS without anything
turning red anywhere. `tests/test_cookies.py` nails that down: HttpOnly, Secure, SameSite,
Path, Max-Age, for each cookie individually, on the raw `Set-Cookie` header rather than on the client's
cookie jar (which swallows attributes and does not even store Secure cookies over `http://`).

The expectation is **per cookie**, not one rule for all. `tinysesam_csrf` must specifically
**not** be HttpOnly — double submit needs JS read access. A blanket "all cookies
HttpOnly" would have complained about precisely the right cookie, and anyone who then weakens the test
loses it for the cookies that matter. A cookie that is set and missing from the
expectation list counts as a violation: whoever introduces one has to explain its flags.

In the process it turned out that there are **three** CSRF setters. `issue_csrf()` — the public API for
third-party templates — is now checked too; if it were not, the third-party
integration would be the weakest point. The third setter sits in the admin panel and belongs to
`test_adminmount.py`; that is stated as a gap in the header of the suite, not silently passed over.

Parser and check rule come from the shared kit (`_kit/headers.py`, from repokit 0.7.0) — they
are not TinySesam-specific, and every app with cookies needs them. Here only the question remains of which
cookies exist and what each one must carry.

### Changed — the docs speak both languages throughout

The language switcher was patchwork. The README carried it centered in the header (current language bold,
the other as a link); `CONTRIBUTING` referred to the counterpart in italics, left-aligned; the
`CODE_OF_CONDUCT` existed in both languages but did not link them to each other at all.
Now `CODE_OF_CONDUCT` and `CONTRIBUTING` carry the same header as the README — centered
heading, centered switcher.

`SECURITY` existed only in German. The German version is now called `SECURITY.de.md`, next to it
stands `SECURITY.md` in English; both are connected via the same header. The in-app footer
links the file matching the display language, `tests/test_repo.py` enforces the pair. `CHANGELOG`
and `TODO` deliberately remained single-language German at the time (since T-29 they are English as well).

For polish: the README badges (tests, license, Python) are now right-aligned, and the
docs subpages carry the wizard icon right-aligned at the foot — the same image as the README
(250 px), small (60 px) on the subpages.

### Changed — image credit links directly to the author page

The Flaticon link in the README footer pointed to the search page. It now leads directly to the
author page (max.icons) and opens in a new tab; the format is aligned with the other
repos: `Icon: … PNG Image by … - flaticon.com`.

The translations now live under `i18n/` (`i18n/README.de.md`, `i18n/CODE_OF_CONDUCT.de.md`,
`i18n/CONTRIBUTING.de.md`, `i18n/SECURITY.de.md`), only the English versions remain in the root.
Reason: GitHub's health-file detector looks for `CODE_OF_CONDUCT`/`SECURITY`/… in root, `.github/` and
`docs/` and, with several hits, picks the alphabetically first — that is, `CODE_OF_CONDUCT.de.md` before
`.md`. The community profile thus showed the German version as "Other" instead of the English one as
Contributor Covenant. From `i18n/`, the detector sees only the English root files.
The in-app footer and `tests/test_repo.py` follow the new location; the language switcher remains.

The subpages now carry a standard Markdown heading instead of a centered HTML header.
For the *Contributor Covenant* something else matters more, though: GitHub's template matching tolerates **no**
foreign content in the file — not even at the end. The English `CODE_OF_CONDUCT.md` therefore stays
**pure** (only heading and template text), so that GitHub recognizes it as Contributor Covenant and
not as "Other". The remaining subpages (German CoC version, `CONTRIBUTING`, `SECURITY`, each
bilingual) carry the language switcher directly under the heading and the logo right-aligned at the
foot of the page — the same pattern in all our own repos.

The contact addresses (code of conduct, contributing, imprint) now uniformly go through
`tinysesam-github@ollornog.de` instead of `admin@`/`tinysesam@` — one repo-specific address per project.

### Changed — the test base is shared, no longer copied

The general hygiene checks, the blocklists and the residue check were in every
project as their own copy — and drifted apart. This suite knew seven forbidden names,
the sister project thirteen; the patterns for private networks had the exception for CIDR masks
in the docs in only one of the two. Same intent, different effect.

Now they live under `tests/_kit/` as a **checked-in, shared base**: the rules as pure
data (`hygiene_policy.json`), the checks as stdlib-only functions (`hygiene.py`). They are
generated, not written by hand.

Important for everyone who clones the project: **nothing is added that would have to be loaded.**
No pip package, no submodule, no network at test time. `tests/_kit/` is in every `git clone`,
every ZIP and every release tarball. If the guard that enforces "no private infrastructure"
itself came from the network, it would be the leak it is meant to prevent.

The check functions return lists of violations instead of raising. That is why this suite
keeps its `assert` style, while the sister project reports by collecting — the same code, two
idioms.

### Fixed — CI ignored `.ci-allow-dirty`

The residue check existed in five copies. The `pre-push` hook and `ci-local` read `.ci-allow-dirty`;
the two CI versions checked raw `git status --porcelain` and did not know the file. The
binding gate thus contradicted the local safety net — on the stricter side, which made the error
look harmless for a long time. Hook and CI now run the same file, `scripts/_residue_check.sh`.

### Fixed — the own name was on the blocklist

The unified name blocklist contained the GitHub owner. That is explicitly allowed, though:
repo URL, copyright line, imprint address and Pages address must be allowed to name it. In the
sister project this never showed up, because its identity masking happened to hit the URL lines;
here, with imprint and Pages URL, it fired immediately. The entry is removed. The actual
danger remains caught: a service subdomain still hits the subdomain pattern, the bare
domain does not.

### Added — community files

- **`CODE_OF_CONDUCT.md`** (+ German version): the Contributor Covenant 2.1, contact
  `admin@ollornog.de`. It applies to the people who open issues and PRs — not to the code.
- **`CONTRIBUTING.md`** (+ German version): ground rules (tests belong to the change,
  repeatable suite, security changes are not cosmetic, no private infrastructure,
  optional stays optional) and the feature-branch workflow.

Both appear on GitHub's *community profile checklist*; they had been missing.

### Added — documented standards are now enforced by machine

Four rules from a standards survey (with primary sources) are now checked by the hygiene suite itself:

- **Actions pinned by full commit SHA**, not by tag. GitHub calls the SHA "the only way to
  use an action as an immutable release" — a tag can be moved. The version appears as a
  comment behind it, and `.github/dependabot.yml` keeps it current so that the pin does not silently go stale.
- **`permissions:` at the top level of every workflow.** There is no safe default.
- **CHANGELOG categories from Keep a Changelog** (one language per repo).
- **`README.de.md` follows the heading structure of `README.md`** — GitHub picks the README by
  location, not by language, so a translation goes stale unnoticed.

Also enabled: private vulnerability reporting and Dependabot security updates.

### Fixed — the `pre-push` hook recommended the wrong command

When Docker was not reachable, the hook named `docker info` as the check and `git push --no-verify`
as the way out. But `docker info` answers three different causes the same way: the group `docker`
really is missing; the shell is older than the `usermod`, so the membership was long granted and
is only unknown to this process; or the daemon is not running. Anyone who concludes "the group
is missing" from the second case grants a root-equivalent right a second time, although `sg docker -c '…'`
helps immediately — and advice that leads to switching off the check is no safety net.

The hook now queries the group database (`id -nG "$benutzer"`) and the process credentials
(`id -nG`) separately and names, for each case, the command that fixes it. As a *functional test*
`docker info` remains right: there the only question is "can a container be started, yes or no".

### Added — generated artifacts must not be in the repo

`pip install -e .` rewrites `<paket>.egg-info/` on every run. If the directory is versioned,
every test run leaves a changed file behind, and the suite is no longer repeatable. The
error stays invisible for a long time: `PKG-INFO` changes only when metadata changes — version,
description, dependencies. Until then the tree is clean *by chance*. In a sister project
it survived six green runs this way and tipped over only at the version jump; no test suite found it.

`tests/test_repo.py` now forbids `*.egg-info`, `*.dist-info`, `build/`, `dist/`, `__pycache__`
and `*.pyc` under `git ls-files`. The `.gitignore` alone is not enough: it protects only what has not yet been
checked in.

## [0.14.0] — 2026-07-10

The project website, the demo frontend — and the last page that had not yet been translated.
No change to guards, sessions or sign-in paths; anyone who only embeds the library notices
from this release only the new `admin.*` keys in `messages.py`.

### Added — the admin panel speaks both languages
- **`/auth/admin` follows `cfg.lang`**, like the login, account and error pages. Previously
  `tinysesam/admin.py` had its German hard-coded in the template: `<html lang=de>`, the tabs
  "Benutzer / Sitzungen / Härtung / Audit", every field label, every confirmation prompt. A TinySesam
  configured for English showed its administrators a German panel.
- The panel builds its UI in the browser, so the texts travel along as JSON
  (`const L`) instead of being substituted into the template text. They come from the same
  table as all other pages (`messages.py`, prefix `admin.`) and can therefore be overridden
  like all the others — `auth.add_messages("fr", {"admin.tab.users": …})`.
  `new language` now means: one table, not a fork of the panel.
- **`admin.locale`** (`en-GB` / `de-DE`) controls `toLocaleString()` — otherwise English
  dates would appear in the German panel.
- Two safeguards: `json.dumps(..., ensure_ascii=False)`, so that "Härtung" also appears as
  "Härtung" in the UTF-8 page, and `<` is masked as `<` — a custom
  translation containing `</script>` would otherwise have ended the script block.
- `tests/test_i18n.py` now checks that **both tables carry the same keys** (170).
  A missing entry would silently fall back to English: the page looks translated, individual
  words are not. That is exactly how the panel went unnoticed as German. The browser test
  drives `?lang=` through the preview iframes down into the tab.

### Added — the demo page is now also available built
- **`demo.html` on the website.** GitHub Pages only serves files, no server process —
  the live demo could never run there, and a link to it was therefore missing. Now
  **`web/demo.py`** renders the three previews (login, account, admin panel) **at build time from the
  library itself** to `demo/*.html`; `demo.html` embeds them as before as locked
  iframes. They are the same pages as live, just already rendered.
  - It is built against an **in-memory database** (`db_path=":memory:"`): no temporary
    file, nothing to clean up, no account created. What the admin panel shows is the
    hard-coded sample data from `MOCK` — which it fetches via `fetch` from JSON
    files placed next to it, exactly as live from the dummy route.
  - Each panel is generated **once per language** (`login.de.html`, `admin.en.html`, …); the
    page shows the matching frame via `l-en`/`l-de` — the same language system as
    everywhere, no language file names in the URL.
  - **`web/demo.py` is the single source** for config, sample data, panel texts and
    frame CSS. `examples/showcase.py` uses it too, instead of duplicating it.
    Previously the same sentences and the same config were in two places — and drifted
    apart: the dummy API reported a hard-coded version `0.12.0`.
  - For this, `pages.yml` installs the library (`pip install .`) and rebuilds the site even
    when `tinysesam/**` changes — the panels are, after all, its image.

### Changed
- **The copy button sits in its own row in the code block**, top right, instead of
  floating above the code. Border and background now sit on `.cw` rather than on `.code`;
  `overflow-x` stays with the code, so that a long line does not scroll the button away with it.
- **The extras list has a uniform font size.** `code` shrinks globally to `.86em`,
  the description next to it does not — side by side that looked uneven. Both are now set to
  the smaller size, like the sentences above and below.
- **The live demo also starts in English.** `lang_of()` fell back to `"de"`, the website
  had long since stopped doing so.

### Fixed
- **The website was offline (404).** The build job was not to blame, but the target: the
  repo's Pages source was set to *"Deploy from a branch"* (`main`, path `/docs`). But `docs/`
  contains only `theme.css` and `wizard.png` — the pages are generated from `web/site.py` and
  uploaded as an artifact by `pages.yml`. Pages therefore served a folder without
  `index.html`. The same automatic build additionally occupied the deployment, which made
  `actions/deploy-pages` fail with *"in progress deployment"*. The workflow says so in its
  header comment: source must be **GitHub Actions**. No code fix, a setting:
  `gh api -X PUT repos/<owner>/<repo>/pages -f build_type=workflow`.

### Changed
- **English is the website default.** `LANG_JS` used to evaluate `navigator.language`,
  so a German browser got the German version unasked. Now `?lang=` takes precedence over
  cookie over `LANGS[0]` (= `en`); the active choice is kept in `ts_lang`. `tests/test_site.py`
  freezes this — the test explicitly forbids `navigator.language`.
- **The extras appear as a list**, no longer as running text with middle dots: `[argon2]`,
  `[oidc]`, `[saml]`, `[ldap]`, `[passkey]`, `[qr]`, `[redis]`, each on one line with its
  effect. They are now **data** (`extras` as a list of pairs, `extras_intro`/`extras_outro`), the
  layout exists once in the renderer. The grid sits on the `<ul>`, the `<li>` are
  `display:contents` — if it sat on the `li`, every row would be its own grid and the
  descriptions would not line up.

## [0.13.1] — 2026-07-10

### Fixed
- **The image was never built.** `${{ github.repository_owner }}` yields the spelling of the
  GitHub account; container registries require lowercase names, and `buildx` aborted with
  *"invalid tag …: repository name must be lowercase"*. The `release` job was green, only the
  image was missing — visible only in the job log. The owner is now lowercased beforehand,
  and a hygiene test forbids `repository_owner` in the `tags:` line.

## [0.13.0] — 2026-07-10

### Added — gateway as a container image
- **`Dockerfile`** for the OIDC forward-auth gateway. Multi-stage: the build stage installs
  `.[oidc]` **from the build context** (not from the network) into a venv, the runtime stage copies
  only this venv. Final image **without `pip` and without `git`**, runs as **non-root** (uid 1000),
  `HEALTHCHECK` on `/healthz`, data under `/data`.
  Only the `[oidc]` extra: `[all]` would pull in `python3-saml` and thus `libxmlsec1`, which would have to be
  compiled for arm64 under emulation — for an extra the gateway does not use.
- **`release.yml` builds and pushes the image** to `ghcr.io/ollornog/tinysesam:<tag>`, for
  `linux/amd64` and `linux/arm64`, and prints the **digest**. Deliberately **no `latest`**: a
  moving tag turns every restart into a gamble.
- **`GET /healthz`** in the gateway — without sign-in, reports status and running version. With
  `https_mode=force` it is exempt from the HTTPS redirect: the health check talks to the
  process from inside over HTTP, and a check that gets a redirect back checks nothing.

### Changed
- **`deploy/forward-auth/docker-compose.yml` uses the image** instead of installing at runtime.
  No more `pip install` at container start, no `command:`. Update via `docker compose pull`.
- The browser test lets Chrome choose its debug port itself and reads it from
  `DevToolsActivePort`. A port reserved in advance was a race: between closing the
  probe socket and starting Chrome, another process could take it —
  on a runner with parallel jobs not a thought experiment.

## [0.12.0] — 2026-07-10

### Removed — self-update (break of the public API)
- **`tinysesam/updater.py` is gone**, along with `self_update()`, `update_available()`, `latest_version()`
  and `pip_url()`. Likewise the manager methods `update_settings/set_update_setting/update_status/
  run_update/auto_update`, the panel routes `/api/update*`, the "Update" tab and the
  store settings `update_mode`/`update_pin`.
  **Reason:** the target version could be set freely via the admin panel. Anyone who takes over
  an admin session could switch back to an old version with a known vulnerability and thereby make the instance
  permanently vulnerable — in the very component that protects everything else. In a container
  a self-update is pointless anyway: the next restart discards it. No
  established auth project has such a button.
  **Replacement:** whoever installs determines the version — pinned Git tag or wheel from the release.
  `python -m tinysesam version` and the panel under "Härtung" show the running version.
  A hygiene test keeps the button out.
- **CLI slimmed down:** `python -m tinysesam version` stays, `check` and `update` are gone.

### Added — delivery
- **`.github/workflows/release.yml`** — a tag `vX.Y.Z` builds wheel + sdist, first checks that the
  tag matches the version in `pyproject.toml`, runs the suite and attaches the files together with
  `SHA256SUMS` to the GitHub release.
- **README: "Installation and updates"** (both languages) — the two operating modes, the pin for each
  mode and how to learn about a new version.
- **`deploy/forward-auth/docker-compose.yml` pins the version.** Previously a
  `pip install …@main` ran there at container start: every restart pulled the current main branch, two
  containers from the same file could run different versions, nothing started without network,
  and there was no rollback.

### Changed — hygiene
- **No more private infrastructure in the repo.** The dividing line is identity versus infrastructure:
  author, imprint, license and repo URL are allowed (and partly legally required) — service subdomains,
  internal hostnames, private IPs, container numbers, home directories, customer names and
  API token identifiers are not. `admin@example.de` is harmless, `paperless.example.de` reveals where a
  Paperless runs.
  The patterns are **generic**, the remaining proper names appear in the test only as a **SHA256 prefix**:
  a literal blocklist in a public repo would publish exactly what it is
  meant to protect. Eleven decoy lines prove that the guard works.
- Sample data of the showcase now use **RFC 5737 addresses** (`203.0.113.7`) instead of an
  invented address from a real private range. Such an address makes the own hygiene test
  fire and tempts you to weaken it.
- The showcase's dummy API still served `/api/update`, although the route no longer exists.
- **README:** the live demo is explicitly a **bundled sample frontend**, not
  part of the library and not a requirement.
- **`.githooks/pre-push` also works without `ci-local`.** The hook required a container wrapper
  that only the author's machine knows, and aborted for everyone else on feature branches.
  Now: native run as the default; only those who have set up `ci-local` must also have Docker running.
  The path to a private directory is gone.
- **`scripts/ci-status.sh` and `scripts/ci_status.py` removed** — a stopgap for machines without `gh`.
  With `gh` installed, `gh run watch --exit-status` does the same, knows the repo from the
  remote and, unlike the anonymous API route, also delivers the logs.
- The hygiene test additionally guards: no `self-hosted` runner in the workflows (in a
  public repo a fork PR would otherwise run on foreign hardware) and no `pip` call at runtime.

### Added — safeguards
- **`tests/test_browser.py`** — headless Chrome via the DevTools protocol against the running showcase:
  console errors, failing requests, body on every page, equal widths, icon sizes,
  `?lang=` switching, dark mode down into the preview iframes, empty form without a JSON wall and the
  login with simulated password autofill. Skipped without Chrome/`websockets`.
- **`tests/test_repo.py`** — versions consistent, required files present, no generated HTML, no
  secrets, no `print()` in the library, color values only in `theme.py`, every suite in the collective run.
- CI: new job **`browser`**, which additionally builds the website.
- **`scripts/check.sh`** — one gate before every push (suites + browser + hygiene + website build),
  run by the **`.githooks/pre-push`** hook (`git config core.hooksPath .githooks`).
  After the push the CI result is actively fetched (`gh run watch --exit-status`) — a push
  without feedback counts as not verified.
- `tests/run_all.py --no-browser` for intermediate runs; `tests/test_repo.py` now also guards that
  gate, hook and CI jobs exist and that both READMEs explain the tests.

### Changed — CI and local checking
- **`pre-push`: shellcheck directive repaired.** `# shellcheck disable=SC2053  -- Grund` is not a
  valid directive — the parser breaks on it (`SC1072/SC1073`) and **no longer checks the rest of the
  file**. The hook therefore counted as checked but was not. The reason is now on its own
  line above; shellcheck now reports the hook clean (0 findings).
- **`pre-push` also checks natively for residue.** The residue check is otherwise done only by `ci-local`,
  not by `check.sh` — so anyone pushing without a container did not get the repeatability check.
  The hook now compares `git status --porcelain` before and after the run and aborts if the
  suite left something behind. An already dirty working tree does not count as residue;
  exceptions go into `.ci-allow-dirty`, as with `ci-local`.
- **Browser test was flaky** — on cold CI runners Chrome sometimes started slower than the 10 s
  the test waited, and its output went to `DEVNULL`: the message was always
  "Chrome antwortet nicht", without a reason. Now 30 s (overridable via `CHROME_START_TIMEOUT`),
  Chrome's output is captured and printed on failure, and an already dead
  Chrome aborts **immediately** instead of waiting for the cap. The log file is cleaned up too.
- **Tests are repeatable** — `tests/run_all.py` gives every suite its **own throwaway directory**
  (`TMPDIR`, `HOME`, `XDG_*` point there, deleted afterwards). No state from one run can affect the
  next, no suite can disturb another.
- **New CI job `repeat`**: runs `scripts/check.sh` twice in a row and then checks
  that the tree is unchanged. A test that turns red on the second run is broken — not the code.
  Deliberately not in the `pre-push` hook, as it doubled the wait on every push.
  Local equivalent: `ci-local --full`.
- **Version matrix on `3.10 / 3.12 / 3.14`** (min + prod + max) instead of `3.10`–`3.13`. The old matrix
  left **3.14 untested**, although it has been the current stable version since October 2025. What is tested
  now are the edges that `requires-python` promises, plus the version that runs in production.
- **Prerelease separated:** new workflow `.github/workflows/nightly.yml` runs Python 3.15
  (`allow-prereleases`) nightly with `continue-on-error` — an RC bug no longer blocks a push.
- **Feature branches no longer trigger CI** (`on.push.branches: [main]` instead of `["**"]`).
  Full CI runs on the pull request and on `main`; in between the local container run checks.
  Escape hatch for WIP on `main`: `[skip ci]` in the commit message.
- **`.githooks/pre-push` uses the container if there is one.** If a `ci-local` is in the `PATH`,
  the suite runs there — the same toolchain as CI. Anyone who has set it up but whose Docker
  does not respond gets an **abort** on feature branches (no GitHub CI runs there, a
  silent fallback would be a hole in the net); on `main` the native run suffices, because CI follows.
  Without `ci-local` the suite simply runs natively — otherwise nobody but the author could push.

### Changed
- **Code blocks follow the theme** — previously they were dark in both themes, because `--code-bg` was
  a dark tone in the light set too. Now a light sheet on light paper, dark in the dark theme;
  the syntax colors are their own tokens (`--code-com/-key/-str`) in `docs/theme.css` and are
  contrast-checked for both backgrounds.
- **Copy button on every code block** (`web/ui.py: codeblock()`). What is copied is `innerText`, i.e. the
  plain command without markup. Where `navigator.clipboard` is missing — the showcase runs on the LAN over
  `http://`, hence without a secure context — an `execCommand` fallback kicks in.

### Fixed
- The **account preview** loaded via `fetch`, ran into the `401` and threw `TypeError: ks.map is not a
  function` into the console. `render_page("account", static=True)` loads nothing afterwards; in addition,
  `loadkeys`/`loadsess` now check whether a list came back at all. (Found by the new browser test.)
- Code blocks lacked `white-space:pre` — the multi-line usage block collapsed into **one** long
  line. Only noticed when the copy button was supposed to put it on the clipboard.

### Added
- **Imprint & privacy** (`legal.html`, `/legal` in the demo) — details per § 5 DDG, note on
  GitHub Pages as host (server logs, USA, EU-US Data Privacy Framework), what the browser stores
  (`ts_lang`, `ts-theme` — both requested, no tracking, no cookie banner) and the rights under
  Art. 15–21 GDPR. The own data lives in `OWNER` in `web/site.py`; unfilled placeholders
  are shown in red. Linked from the footer of every page.

### Changed — UI rebuilt
- **One language system, not a second one.** `?lang=xx` switches, the cookie `ts_lang` remembers — on the website
  as in the app. The language file names (`index.de.html`, `flows.de.html`) are gone without replacement: because
  GitHub Pages has no server, each file carries **both** languages and hides one via CSS.
  Four files become two, two mechanisms become one.
- **`web/ui.py`**: the complete page body in one place — header (title row + two nav rows in
  *one* container), footer, disclosure widget, switch pills, icons, CSS and JS. Website, demo **and**
  the built-in TinySesam pages use the same functions; `Nav` describes the app once,
  `Ctx` the request. `web/site.py` now contains only texts and page content.
- The only special case remains the home page: there the title area replaces the brand row.
- The GitHub/docs icons are as tall as the switch pills (22 px frame, 20 px symbol). For that,
  `nav.row a` has to leave out the padding via `:not(.ilink)` — otherwise it wins against `.ilink` (higher
  specificity), 4 px of content width remain and the symbol is squeezed into a line.

### Fixed
- **An empty login form produced a 422 JSON wall** instead of the page with an error message.
  Affected were login, PIN, TOTP, signup, resource PIN, magic link and password reset:
  all used `Form(...)`, whose validation errors FastAPI outputs as JSON. Now `Form("")` plus
  a custom check → 400 with "Bitte alle Felder ausfüllen."; the fields additionally carry `required`.
- The demo hint also appeared in the login **preview** on `/demo`, where it has no business being.
  `render_page("login", demo_hint=False)` suppresses it.
- **The admin panel never got `brand_head`** — which is why it stayed light in dark mode (the early
  theme script was missing). New placeholder `__BRANDHEAD__`.
- **The language switcher was dead on the website pages** (`flows.de.html`, `index.de.html`): it
  pointed to `…?lang=en`, but there the language is in the **file name** and overrides the parameter.
  Now it points to the other file. The demo pages (`/demo`, `/demo/flows`) keep using
  `?lang=`, because they have no language variants as files.
- **The built-in CSS bled onto the body of the host app.** `_CSS` styled bare
  `button`/`input`/`h1` selectors; as soon as `brand_header`/`brand_footer` were set, that wrecked
  the foreign navigation (pills became full-width buttons). Everything is now encapsulated
  under `.tsmain`, the admin panel under `.tsadmin`.
- **The demo login failed because of browser autofill.** The password field was prefilled with a saved
  password; anyone who typed only the username above it got "wrong credentials" (in the
  server log: `demo FAIL password`). Now: `autocomplete=new-password`, a script discards a
  prefilled password (retrying several times, but never after the user's own input), and the names in the
  demo hint are **buttons that fill the form**. Cross-checked in real Chrome via the DevTools protocol:
  autofill is discarded, click fills, login goes through, self-typed input stays.
- Showcase: the language/context middleware is pure ASGI. `BaseHTTPMiddleware` runs the app in
  its own task, where the `ContextVar` set there was no longer visible.
- **Sign-in failed with 403 if another page was loaded in between.**
  `render_page()` rolled a new CSRF token on *every* render and overwrote the cookie —
  making every open form (including a second tab or an error page) immediately
  invalid, without an error message. The token is now reused as long as the cookie exists;
  `render_page(..., request=request)` passes it through, new `auth.csrf_token(request)`.
  The protection remains just as sharp: wrong or missing token → 403.

### Changed
- **Demo hint is outside the login card** — it does not belong in the form. `_page(..., top=…)`
  and `_doc(..., top=…)` respectively render content above the card (body is now a centered column).

### Added
- **`brand_header` / `brand_footer`** — custom navigation and footer around **every** built-in page
  (login, PIN, TOTP, account, admin panel, error pages). String or `fn(auth) -> str` if the body
  depends on the request. The content sits centered in `.tsmain` in between; if the body raises an exception,
  it is silently omitted instead of dragging the page down with it.

### Changed (website & showcase)
- Order of the bars: **title/brand → nav2 → toolbar** (the narrow one with GitHub/docs on the left
  and the two switchers on the right). The divider sits under nav2; the fade-in on load now applies
  to all three bars and lives in `NAV_CSS` — previously it was missing entirely on the flow page.
- The example-pages disclosure widget no longer opens by itself when you are on one of these pages —
  it is only marked.
- Home page: under "Installation" there are now the **extras** and what they bring (`[oidc]`, `[saml]`,
  `[ldap]`, `[passkey]`, `[qr]`, `[redis]`, `[argon2]`) — you do not have to take `[all]`.
- Showcase: `stepup_methods=["totp", "pin"]` — the sensitive area asks for the PIN, and as soon as 2FA
  is set up, the one-time code is additionally available as a choice.
- **Third, narrow bar at the very top**: GitHub and docs as icon links on the left, the two
  switchers (language, light/dark) on the right. The brand bar below carries only the logo now; on the
  home page it is omitted, because the title area shows it.
- Identifier fields with `autocapitalize=none autocorrect=off spellcheck=false` — keyboards
  otherwise capitalized the username.
- **Language and light/dark as switch pills** in the first bar (instead of dropdown or button) —
  compact (18 px high); brand and title in the first bar are larger in return.
- **Profile disclosure widget** instead of an account button: icon + username, below that account, admin panel, sign out.
- Disclosure widgets now close on a click elsewhere and with `Escape` (`<details>` does not do this by itself).
- Footer: the divider sits at the content, not at the window edge — same width as the bars (`--nav-w`).
- Typography: noticeably more air before headings and around the second bar; headings larger
  (h1 50 px, section label 18 px, flow headings 31 px), section spacing 112 px; the bars use **one** font size (`--nav-fs`) instead of three.
- Dark theme (`docs/theme.css`): background, surfaces and dividers a touch lighter —
  pure near-black looked flat, the cards barely stood out.

## [0.11.0] — 2026-07-09

Large collective release: login identifier, PIN as an additional factor, first-admin bootstrap, demo mode,
bilingual website — plus the permission traps from the first production use.

### Security
- **`has_role()` granted admins every role.** This remains the default (`admin_implies_roles=True`),
  but can now be switched off — globally or per guard: `require_role("editor", admin_implies=False)`.
  Anyone who derives permissions solely from an IdP group should do so; otherwise every local admin
  is silently also "editor".
- **IdP groups are compared exactly** (`group_match="exact"`, new default). Previously a substring
  match applied — the key `admin` thus also matched a group `nicht-admin`. For LDAP
  the substring match stays active (whole `memberOf` DNs arrive there), otherwise via config/parameter.
- **First-admin token only if local admins are intended.** With `admin_enabled=False` (pure
  OIDC app without a panel) no token is generated or redeemed any more — previously one appeared in the
  log, although the app knew no local admin at all.
- Docs: **start uvicorn without `--proxy-headers`.** Otherwise uvicorn replaces `request.client.host` with
  the forwarded IP, `trusted_proxies` checks nothing and rate limit/lockout/fail2ban can be bypassed.

### Added
- **`auth.issue_csrf(response) -> str`** — set the CSRF cookie and get the token, for custom templates
  (Jinja & co.) that do not go through `render_page()`. No-op if CSRF is off.
- **`oidc_callback_path`** — the callback was hard-wired. At startup TinySesam now additionally
  logs the expected redirect URI, so that a typo is not first reported by the IdP.
- New suite `tests/test_authz_hardening.py`.

- **First admin without "first come, first served"** — two explicit paths, both effective only while there is
  no admin: `admin_identifiers=[…]` (allowlist on name/email, applies to **every**
  login method, including OIDC/SAML/LDAP) and a **one-time token** in the log →
  `GET /auth/claim-admin?token=…` (`admin_claim_ttl_min`, after which the route is 404).
- **Demo mode** (`demo_mode=True`) — creates `demo` + `demoadmin`, shows the credentials on the
  login page (and the PIN on the PIN page) and warns visibly. When switched off, **exactly
  these** accounts are deleted again (`seed_demo`/`purge_demo`, `store.delete_user`).
- Showcase: consistent language switching (`?lang=` + cookie) for demo pages **and** the
  built-in TinySesam pages (`cfg.lang` via middleware).
- **Login identifier selectable** — `login_identifier="username" | "email" | "both"` (default **`both`**).
  Password and PIN login go through `auth.find_user(...)`; the identifier field labels itself
  accordingly ("Benutzer" / "E-Mail" / "Benutzer oder E-Mail"). The timing protection against
  user enumeration (dummy hash) is retained in all modes.
- **Email as a full-fledged identifier** — `signup_require_email` (default **on**), format validation,
  canonical storage (trimmed/lowercase) and **uniqueness** via a partial UNIQUE index
  (`users(lower(email))`, accounts without an address remain allowed). `store.norm_email`/`valid_email`/`email_taken`.
- **Signup follows `login_identifier`:** in `"email"` mode the username field is dropped,
  the address is the identifier; otherwise as before. The admin panel may also omit the name there.
- Admin panel: email on creation (requirement follows the config) + its own column in the user table.
- **`brand_icon`** — favicon for **all** built-in pages from a single config value (login/PIN/TOTP/
  account/signup/magic/admin panel/error pages). Previously none of them had one.
- Showcase: **demo mailbox** (`/demo/postfach`) — the demo sends nothing, `set_mailer` stores the
  mails there. Login link and forgot-password can thus really be tried out.
- **PIN without login role** — `pin_login=False`: the PIN exists, but does **not** appear on the
  login page. It then serves only as an additional factor (`require(factors=[…, "pin"])`) or as step-up.
- **Step-up with PIN** — `stepup_methods=["pin"]` (empty = everything the user has: TOTP → PIN → password).
  `/auth/reauth` could previously do only TOTP or password; now PIN too, and `auth.stepup_options(user)`
  says what is an option for the respective user (fallback if the desired method is missing).
- **`/auth/pin` for signed-in users** — GET renders a real PIN page (previously: redirect to the login page),
  without a user field when a session is running; POST derives the identity from the session.
  New template `pin`, `auth.verify_user_pin` / `verify_user_password` check against a known identity.
- **Preset `TinySesamConfig.local_accounts(...)`** — username + password only, entirely without email
  (no magic link, no forgot-password, no confirmation). The signup form shows
  **no email field any more** if the app has no use for the address anyway.
- **Website bilingual and generated** — source `web/site.py` + `web/flows.py`, output
  `index.html` / `index.de.html` / `flows.html` / `flows.de.html` with a language switcher.
  `python -m web.build` builds them, the action `.github/workflows/pages.yml` deploys them on every
  push. The HTML files are **no longer in the repo** (only `theme.css` + `wizard.png`).
  *Needed once: Settings → Pages → Source = "GitHub Actions".*
- **Login flows as a diagram** — nine paths, bilingual, from one source. On the website, next to
  each one stands the config switch that turns it on; in the demo (`/demo/flows`) instead
  "active/off", read from the running config.
- **Header, second bar and footer from one source** (`web/site.py`) — the same on every page,
  in website and demo alike. `nav_top` = brand + tools (language switch, **dark-mode toggle**),
  `nav_sub` = pages + example-pages disclosure widget on the left, sign in/out or account/admin on the right,
  `footer(lang)` = one function. Language in the bar as an abbreviation (DE/EN), spelled out in the menu.
  The only special case remains the home page: `nav_top(brand_href=None)` omits the brand,
  because the title area shows it large.
- **Dark-mode toggle** — sets `data-theme` on `<html>` (which `docs/theme.css` already knows) and
  remembers the choice; an inline script in the `<head>` prevents the flash of the wrong theme.
  New suites `tests/test_pin_stepup.py`, `tests/test_site.py`.

### Fixed
- Showcase: the second bar did not fade in (the `rise` animation applied only to hero and sections).
- The open dropdown looked transparent: the animated sections form their own stacking contexts and
  painted over it. `nav.sub` now gets its own context (`position:relative;z-index:30`) and
  a background; the menu sits at `z-index:40`.
- Header, nav and footer now follow the page's content width via `--nav-w`
  (home page 720 px, otherwise 900 px) — previously they were 900 px wide everywhere.
- Showcase: the admin preview was regularly cut off at the bottom — its table arrives via `fetch`
  **after** the `load` event. The frame now re-measures via `ResizeObserver` (plus straggler timer).
- Showcase: on the flow page the first bar was **below** the second — the demo glued its
  bar behind `<body>`, the page brought its own nav. Both now come from `web/site.py`.
- `signup_verify_email` is now robust: confirmation on, but **no mailer** configured →
  clear error instead of silently waving it through; **no half-finished account** is created either.
  New suite `tests/test_identifier.py`.

### Added (showcase & design)
- **Showcase frontend** (`examples/showcase.py`): `/` is the project website (`docs/index.html`)
  **one to one**, supplemented with a demo button. `/demo` is the demo frontend — nav with logo and title,
  sign in/sign up, below that login, account and admin panel as a **read-only live preview**.
  The previews render the **real** building blocks (`auth.render_page(...)`, `admin.render_panel(...)`),
  so they are never stale; the admin preview runs against a read-only dummy API.
- `tinysesam.admin.render_panel(auth, base, warn="")` — public, so that the panel HTML is generated in exactly
  one place (panel and demo preview cannot drift apart).
- Showcase: second nav bar with the test pages; account and admin panel appear only when you are
  signed in or have admin rights. GitHub/docs buttons with icon.

### Changed
- **All built-in pages now style themselves via CSS variables** (new: `tinysesam/theme.py`).
  Login, account and admin panel each had their own hard-coded colors — a `brand_css` could not
  fully override them (account/panel stayed dark). One set of tokens now re-skins everything.
  Appearance of the defaults unchanged (dark theme).
- Website and showcase share the palette `docs/theme.css` (the website loads it via `<link>`,
  the app passes it on as `brand_css`).
- **README bilingual**: `README.md` (English, default) + `README.de.md` (German), with a language switcher.

### Fixed
- Showcase: "Sign in"/"Create account" seemed dead when signed in (`/auth/login` → `303 /`).
  The demo frontend now knows the login state and shows account/sign out instead.

## [0.10.0] — 2026-07-09

### Added
- **Central theming hook:** `brand_css` / `brand_head` re-skin ALL built-in pages
  (login/PIN/TOTP/reauth/magic/signup/account/admin panel) with one config value — no per-page rebuild.
- **Themed error pages:** `auth.install_error_pages(app)` — 403/404/429/500 as a branded HTML page
  for browsers, JSON for API clients; redirects (login/reauth/factor) remain redirects. `error` template
  replaceable via `set_template('error')`.
- Admin panel: **"Update now"** always available (not only when an update is detected).
- Showcase: fully branded example (a single `brand_css`) including 404/500 demo.

## [0.9.0] — 2026-07-09

### Added
- **Role/group management:** `available_roles` (known roles) → the admin panel offers them as
  **checkboxes** per user (fallback free text). `auth.apply_idp_groups(...)`.
- **IdP groups → local roles:** `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`
  (substring match, target `__admin__` sets the admin flag). Set at login; mapped roles are
  synchronized, manual ones remain. Consistent `require_role(...)` authorization across all login paths.

### Fixed
- CI: the `[all]` job installs `libxmlsec1-dev` (SAML/xmlsec); test runner skips suites with
  missing extras (onelogin/ldap3/redis/xmlsec) instead of failing (minimal job green again).

## [0.8.0] — 2026-07-09

### Added
- **SAML 2.0 SP login** (extra `[saml]`, python3-saml) — `/auth/saml/login|acs|metadata`, signature-
  verified assertion (ACS exempt from CSRF), attributes→user, group gate, factor `saml`.
- **Presets** — `TinySesamConfig.active_directory(...)` (AD via LDAP, UPN or sAMAccountName bind)
  and `TinySesamConfig.entra_id(...)` (Azure AD/Entra via OIDC).
- README/website: problem-oriented pitch (login layer for self-built apps).

**Note:** Kerberos/NTLM/GSSAPI SSO is deliberately left out (LAN/domain-bound, heavy ops coupling,
redundant to OIDC/SAML for AD).

## [0.7.0] — 2026-07-08

### Added
- **i18n** — built-in texts in **English (new default)** and **German**; `config.lang`,
  `auth.t(key)`, `auth.add_messages(lang, {...})`. **Note:** the default is now English —
  German-speaking integrations set `lang="de"`.
- **CSRF protection** (double-submit cookie, `csrf_enabled`, default on) on all state-changing POSTs;
  built-in forms/JS handle it automatically, API-key requests are exempt.
- **Cross-process rate limit** via Redis (`redis_url`, extra `[redis]`) for multi-worker;
  `auth.set_rate_limiter()` for custom backends. Fallback in-memory, fail-open on Redis outage.
- Project **icon** + minimal **GitHub Pages website** (`docs/`).

## [0.6.0] — 2026-07-08

### Added
- **LDAP/lldap backend** (extra `[ldap]`) — password against directory bind (direct or search-then-bind),
  auto-create local user, optional group gate. Coexists with local passwords.
- **TOTP recovery codes** — one-time codes as a 2FA substitute (redeemable in the TOTP step, self-service regeneration).
- **Forgot password** — self-service reset by email (`password_reset_enabled`, uses magic link/mailer).
- **Manage own sessions** — `/auth/sessions` (masked) + "sign out others/everywhere"; on the account page.
- **Optional OIDC RP logout** (`oidc_rp_logout`) — sign out at the provider too (`end_session`).
- `auth.gc()` (DB housekeeping), `py.typed` (type info is shipped).

### Security
- Sessions are invalidated after a password change (self: except the current one; admin reset: all).
- Dummy-hash verify against **user enumeration** via timing (login & PIN).
- Invalid JSON body → **400** instead of 500. Test runner `tests/run_all.py` + CI (Py 3.10–3.13).

## [0.5.0] — 2026-07-08

Large feature expansion; everything **optional** (on/off via config), usable individually and combined,
frontend fully replaceable via a template registry. The classic path (one first factor +
TOTP if set up) remains unchanged.

### Added
- **Template override registry** (`auth.set_template(name, fn)`) — every page replaceable (string or response).
- **Remember me** — persistent vs. pure session cookie (`remember_me_enabled`, `session_ttl_transient_hours`).
- **Step-up / per-route MFA** — `auth.require(mfa=True)`, sudo freshness `stepup_max_age_sec`, `/auth/reauth`, `admin_require_mfa`.
- **Factor chains** (ordered) — global `login_chain` + per route `require(factors=[...], strict=...)`; e.g. OIDC→password.
- **Personal PIN** per user (`pin_enabled`), its own strict lockout, combinable with TOTP.
- **Shared resource secret** (PIN/passphrase, without an account) — `require_resource(name)`.
- **Magic link** (one-time login by email) + **mailer hook** (`set_mailer`) / SMTP.
- **Signup + invitation** — `allow_signup`, `signup_verify_email`, `signup_invite_only`, `create_invite`.
- Built-in **account page** `/auth/account` + self-service password change `/auth/password`.
- **Forward auth** (`/auth/forward` + `/auth/verify`) for reverse proxies; examples Caddy/nginx/Traefik.
- **OIDC gateway preset** — `TinySesamConfig.oidc_gateway(...)`, `python -m tinysesam.gateway`, docker-compose.
- **Test runner** `tests/run_all.py` + **GitHub Actions CI** (Py 3.10–3.13, full + minimal run).

### Changed
- Central **open-redirect protection** `safe_next` on all `?next=` targets; `cookie_domain` for subdomain SSO.
- Invalid JSON body → **400** instead of 500 (`TinySesam.json_body`).
- Store auto-migration (`session.mfa_at`/`remember`/`factors_done`), new module `mailer.py`.

## [0.4.0] — 2026-07-06
Admin panel as a standalone, freely mountable router (prefix/subdomain/port) + JSON-only API mode;
HTTPS modes `off`/`warn`/`force`.

## [0.3.0] — 2026-07-06
API keys + service/daemon accounts (hashed, expiry, role scope) + built-in admin panel.

## [0.2.0] — 2026-07-06
Hardening (brute-force lockout, rate limit, fail2ban log, audit, trusted proxy) + self-update from GitHub.

## [0.1.0] — 2026-07-06
Initial version: password + TOTP + passkey/WebAuthn + OIDC, server-side sessions, optional roles.

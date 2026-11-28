# Backlog

<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: `python3 scripts/_backlog.py index` -->

Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.
Konventionen: [README-KONVENTION.md](README-KONVENTION.md).

## Meilensteine

* ☑ **[M-1](M-1-clean-baseline-and-modules-before-shell-and-headless.md)** Clean baseline and modules — before shell and headless continue — 6/6 erledigt
* ☐ **[M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)** Shell and headless: every UI mode, local/IdP/mixed users, library and server alike — 31/37 erledigt
* ☐ **[M-3](M-3-trust-hardening-and-launch.md)** Trust, hardening and launch — before TinySesam is promoted widely — 0/7 erledigt
* ☐ **[M-4](M-4-api-stable-1-0.md)** 1.0 — API stable enough for PyPI — 14/14 erledigt
* ☐ **[M-5](M-5-after-1-0.md)** After 1.0 — keeping the published package maintained — 92/110 erledigt
* ☑ **[M-6](M-6-gate-in-front-of-third-party-apps.md)** Gate in front of third-party apps — fast, sign in once, sign out cleanly — 8/8 erledigt

## Aufgaben

* ☑ **[T-1](T-1-e2e-against-real-idp.md)** End-to-end test against a real identity provider · M-4
* ☑ **[T-2](T-2-do-not-search-free-port-yourself.md)** Browser test should not look for a free port itself · M-4
* ☑ **[T-3](T-3-forward-auth-header-fine-tuning.md)** Forward auth — make the remote headers that are set configurable · M-4
* ☑ **[T-4](T-4-verification-without-magic-endpoint.md)** Email verification and invitation without the magic-link endpoint · M-4
* ☑ **[T-5](T-5-verify-image-signature.md)** Consider image signature and SBOM · M-4
* ☑ **[T-6](T-6-stage-via-playbook.md)** Build the E2E stage with a playbook instead of by hand · M-4
* ☑ **[T-7](T-7-spdx-license-expression.md)** Switch the license declaration to the SPDX expression (deadline: 2027-02-18) · M-5
* ☑ **[T-8](T-8-maturity-review-remaining-findings.md)** Work through the 35 maturity-review findings that were not reproduced individually · M-4
* ☑ **[T-9](T-9-audit-2026-09-21-round-2.md)** Work through the findings of the second audit (four perspectives) · M-4
* ☑ **[T-10](T-10-docs-comparison-2026-09-21.md)** Docs measured against the code — 70 places, 10 real defects · M-4
* ☑ **[T-11](T-11-zizmor-excessive-permissions.md)** zizmor excessive-permissions — already fixed when filed, entry stays as a lesson · M-4
* ☑ **[T-12](T-12-codeql-backlog.md)** Assess the CodeQL backlog and track the open alerts in the backlog · M-4
* ☑ **[T-13](T-13-audit-2026-09-22-round-3.md)** Work through the findings of the third audit (red team, blue team, online research) · M-4
* ☑ **[T-14](T-14-multiple-oidc-clients.md)** Multiple OIDC clients in one instance — per-app approval lives at the identity provider · M-4
* ☑ **[T-15](T-15-subpath-mounting.md)** Make built-in pages mountable under a subpath · M-5
* ☑ **[T-16](T-16-group-scope-warning.md)** Warn when a group rule runs through the groups claim and the groups scope is missing · M-5
* ☑ **[T-17](T-17-claim-token-not-in-container-log.md)** Do not write the first-admin one-time token to the container log · M-5
* ☑ **[T-18](T-18-flaky-test-prebooking-pending.md)** Flaky test test_prebooking_pending — red once in the CI job repeat, cause open · M-5
* ☑ **[T-19](T-19-gate-token.md)** Issue the gate token and prove it with a real Caddy running caddy-jwt · M-6
* ☑ **[T-20](T-20-share-exceptions.md)** Share exceptions per app — exact path prefixes before the gate, with a control test · M-6
* ☑ **[T-21](T-21-login-modes.md)** Login mode per app: invisible (gateway default) or window · M-6
* ☑ **[T-22](T-22-logout-modes.md)** Logout mode per app: app, all, ask — chain via the provider back to the gate · M-6
* ☑ **[T-23](T-23-config-check-gate.md)** Configuration check for gate operation · M-6
* ☑ **[T-24](T-24-gate-acceptance-measurement.md)** Acceptance — before/after measurement and acceptance test per app · M-6
* ☑ **[T-25](T-25-oidc-on-the-stage.md)** E2E stage — the OIDC ceremony fails at the identity provider · M-5
* ☑ **[T-26](T-26-gate-link-code-exchange.md)** Central gateway with code exchange — session stays on the gateway, app hosts only get a connection of their own · M-6
* ☑ **[T-27](T-27-cli-delete-account.md)** CLI command to delete an account (maintenance without the admin panel) · M-5
* ☑ **[T-28](T-28-go-variant-small-gate-client.md)** Gate client specification with language-neutral test and attack vectors · M-5
* ☑ **[T-29](T-29-translate-everything-to-english.md)** Translate everything to English (code texts, docs, messages) · M-5
* ☐ **[T-30](T-30-launch-plan.md)** Launch plan — make TinySesam publicly known · M-3
* ☐ **[T-31](T-31-maybe-recommend-a-provider-session-at-least-as-lon.md)** Maybe: recommend a provider session at least as long as the gateway session · M-5
* ☑ **[T-32](T-32-api-key-pairing-negotiate-a-key-on-first-contact-o.md)** API key pairing: negotiate a key on first contact, optional renew and rotate on login · M-5
* ☑ **[T-33](T-33-sign-in-alternatives-qr-cross-device-login-admin-i.md)** Sign-in alternatives: QR/cross-device login, admin-issued link without mail, self-request switchable · M-5
* ☑ **[T-34](T-34-admin-creates-accounts-link-sign-in-sets-up-the-chain.md)** Admin creates accounts, a link signs them in: setup pass and alternatives in the factor chain · M-5
* ☑ **[T-35](T-35-own-dialogs-instead-of-browser-system-dialogs.md)** Own dialogs instead of the browser's system dialogs, with a copy button · M-5
* ☑ **[T-36](T-36-oauth-authorization-server-for-mcp-clients.md)** OAuth 2.1 authorization server for MCP clients (Claude Code) — human-operated tools · M-5
* ☑ **[T-37](T-37-home-network-ip-only-template.md)** Home network: template for IP only, with a clear recommendation for a domain · M-5
* ☑ **[T-38](T-38-gateway-no-docs-redoc-openapi-json-without-sign-in.md)** Gateway: no /docs, /redoc, /openapi.json without sign-in · M-5
* ☑ **[T-39](T-39-hsts-in-the-library-https-mode-force-and-in-every.md)** HSTS in the library (https_mode=force) and in every proxy template · M-5
* ☑ **[T-40](T-40-password-blocklist-the-10-000-most-common-password.md)** Password blocklist: the 10,000 most common passwords shipped (ASVS 6.2.4) · M-5
* ☑ **[T-41](T-41-security-md-en-de-against-the-code-totp-secrets-ar.md)** SECURITY.md (en/de) against the code: TOTP secrets are encrypted since 0.21.0 · M-5
* ☑ **[T-42](T-42-supply-chain-image-cve-scan-openssf-scorecard-zizm.md)** Supply chain: image CVE scan, OpenSSF Scorecard, zizmor as a gate, CVE deadlines · M-5
* ☑ **[T-43](T-43-home-network-and-plain-caddy-template-client-remot.md)** Home-network and plain Caddy template: client Remote-* headers measured · M-5
* ☑ **[T-44](T-44-qr-cross-device-sign-in-harden-against-consent-phi.md)** QR / cross-device sign-in: harden against consent phishing · M-5
* ☑ **[T-45](T-45-admin-panel-step-up-by-default-admin-require-mfa.md)** Admin panel: step-up by default (admin_require_mfa) · M-5
* ☑ **[T-46](T-46-admin-set-password-must-not-become-the-permanent-p.md)** Admin-set password must not become the permanent password · M-5
* ☑ **[T-47](T-47-notify-the-account-holder-about-new-access-link-is.md)** Notify the account holder about new access (link issued, new device, success after failures) · M-5
* ☑ **[T-48](T-48-key-rotation-for-secrets-key-and-a-gate-signing-ke.md)** Key rotation for secrets_key, and a gate signing key of its own · M-5
* ☑ **[T-49](T-49-oidc-max-age-auth-time-for-re-authentication.md)** OIDC: max_age / auth_time for re-authentication · M-5
* ☑ **[T-50](T-50-session-lifetime-justify-against-nist-sp-800-63b-4.md)** Session lifetime: justify against NIST SP 800-63B-4, document parallel sessions · M-5
* ☑ **[T-51](T-51-sign-in-link-lifetimes-magic-link-10-min-admin-lin.md)** Sign-in link lifetimes: magic link 10 min, admin link at most 24–72 h · M-5
* ☑ **[T-52](T-52-response-hardening-for-l3-coop-csp-reporting-clear.md)** Response hardening for L3: COOP, CSP reporting, Clear-Site-Data, textContent, /healthz version · M-5
* ☑ **[T-53](T-53-gate-token-explicit-type-and-separate-key-before-t.md)** Gate token: explicit type and separate key before the OAuth AS signs JWTs · M-5
* ☑ **[T-54](T-54-vault-bind-ciphertexts-to-their-row-aad-with-user.md)** Vault: bind ciphertexts to their row (AAD with user_id and column) · M-5
* ☑ **[T-55](T-55-slsa-build-l3-and-an-sbom-for-wheel-and-sdist.md)** SLSA Build L3 and an SBOM for wheel and sdist · M-5
* ☑ **[T-56](T-56-webauthn-user-verification-at-registration-random.md)** WebAuthn: user verification at registration, random user handle · M-5
* ☑ **[T-57](T-57-totp-accept-at-most-one-step-back-switch-totp-wind.md)** TOTP: accept at most one step back (switch totp_window) · M-5
* ☑ **[T-58](T-58-caddy-templates-a-header-missing-from-the-auth-answer.md)** Caddy templates: a header missing from the auth answer reaches the app as placeholder text · M-5
* ☑ **[T-59](T-59-gateway-image-on-a-slimmer-or-distroless-base.md)** Gateway image on a slimmer or distroless base, with only the dependencies it needs · M-5
* ☑ **[T-60](T-60-oauth-for-services-client-credentials-private-key-jwt.md)** OAuth for services — client_credentials + private_key_jwt, pairing from T-32 · M-5
* ☑ **[T-61](T-61-c22-adapter-same-look-as-a-c22-app.md)** C22 adapter: the built-in pages in the look of an app built on C22 · M-5
* ☑ **[T-62](T-62-caddy-shipped-ready-made-image-and-quickstart-stack.md)** Caddy shipped ready-made: image tinysesam-caddy-gate and a quickstart stack · M-5
* ☑ **[T-63](T-63-notify-the-holder-of-a-successful-sign-in-after-failed-attempts.md)** Notify the holder of a successful sign-in after failed attempts · M-5
* ☑ **[T-64](T-64-top-bar-and-favicon-refresh.md)** Top bar and favicon refresh: logo, name, links, account menu, light/dark, phone · M-5
* ☑ **[T-65](T-65-ai-guide-agents-md-and-a-skill-for-app-builders.md)** AI guide: AGENTS.md for contributors and a skill for app builders · M-5
* ☑ **[T-66](T-66-app-passwords-for-webdav-caldav-and-git-at-the-gate.md)** App passwords for WebDAV, CalDAV/CardDAV and Git at the gate · M-5
* ☑ **[T-67](T-67-orderly-shutdown-close.md)** Orderly shutdown: a public close() that drains the outboxes and refuses new jobs · M-5
* ☐ **[T-68](T-68-dpop-for-service-tokens.md)** DPoP for service tokens — bind a service's access token to its key (RFC 9449) · M-5
* ☑ **[T-69](T-69-attack-round-a-oauth-services-app-passwords-keys.md)** Attack round A (2026-11-21) — OAuth, services, app passwords, keys · M-5
* ☑ **[T-70](T-70-saml-forceauthn-authninstant-for-re-authentication.md)** SAML: ForceAuthn / AuthnInstant for re-authentication (the T-49 gap) · M-2
* ☑ **[T-71](T-71-session-handles-keyed-with-the-pepper.md)** Session handles keyed with the pepper instead of a plain sha256 · M-5
* ☑ **[T-72](T-72-pepper-for-the-remaining-token-digests.md)** Pepper for the remaining token digests, then drop the session-handle rewrite · M-1
* ☐ **[T-73](T-73-tenants-multiple-hostnames-each-with-its-own-sign-in-choice.md)** Tenants — multiple hostnames, each with its own sign-in choice · M-5
* ☑ **[T-74](T-74-delegated-admins.md)** Delegated admins — a team admin who manages accounts within listed roles · M-5
* ☑ **[T-75](T-75-sign-in-kind-in-forward-auth.md)** Sign-in kind in forward auth: a Remote-Auth header · M-5
* ☑ **[T-76](T-76-top-bar-link-visibility.md)** Top bar: visibility per link, and the bar as JSON · M-5
* ✗ **[T-77](T-77-admin-panel-extra-tabs.md)** Admin panel: extra tabs that link to the application''s own administration · M-5
* ☑ **[T-78](T-78-nginx-and-traefik-templates-through-the-real-proxies.md)** nginx and Traefik templates measured through the real proxies in the CI · M-5
* ☑ **[T-79](T-79-diagnostics-report-and-bug-form-instead-of-telemetry.md)** Diagnostics report and bug form instead of telemetry · M-5
* ☑ **[T-80](T-80-gate-client-in-go.md)** Gate client in Go · M-5
* ☑ **[T-81](T-81-gate-client-in-rust.md)** Gate client in Rust · M-5
* ☑ **[T-82](T-82-gate-client-in-javascript-and-typescript.md)** Gate client in JavaScript and TypeScript · M-5
* ☑ **[T-83](T-83-gate-client-in-php.md)** Gate client in PHP · M-5
* ☐ **[T-84](T-84-token-mode-delivery-to-the-application.md)** Token mode: deliver the gate token to the application · M-5
* ☑ **[T-85](T-85-role-names-without-comma.md)** Role names without comma and control characters · M-5
* ☑ **[T-86](T-86-python-gate-client.md)** Python gate client · M-5
* ☑ **[T-87](T-87-accounts-page-and-role-levels-in-the-admin-panel.md)** Accounts page and role levels in the admin panel · M-5
* ☑ **[T-88](T-88-account-kind-menu-links-logo-tooltip.md)** Account kind (Remote-Kind, spec v2), account menu links and the logo tooltip · M-5
* ☑ **[T-89](T-89-approvals-confirm-one-sensitive-action-with-a-step.md)** 'Approvals: confirm one sensitive action with a step-up (stage A: TinySesam actions; stage B: application · M-5
* ☑ **[T-90](T-90-account-api-for-applications-stage-a-create-read-u.md)** 'Account API for applications (stage A: create, read, update, lock, link; stage B: delete, panel, · M-5
* ☑ **[T-91](T-91-app-frame-and-account-overview.md)** Two ways to use TinySesam: app frame on TinySesam''s pages and the own account as data · M-5
* ☑ **[T-92](T-92-role-catalog-roles-in-the-database-for-the-admin-panel.md)** Role catalog: roles in the database, so administrators add them in the panel · M-5
* ☑ **[T-93](T-93-follow-ups-to-0-29-0-kid-rule-proxy-duty-key-purposes.md)** Follow-ups to 0.29.0: kid rule, server-side top bar vs. proxy duty, key purposes both ways · M-5
* ☑ **[T-94](T-94-first-sign-in-by-link-recovery-codes-off-totp-hint-target.md)** First sign-in by one-time link: recovery codes switchable, TOTP app hint, target after the setup · M-5
* ☑ **[T-95](T-95-pairing-code-for-people-s-programs-and-a-simpler-consent-page.md)** Pairing code for people's programs (consent given in advance) and a consent page for laypeople · M-5
* ☑ **[T-96](T-96-stage-s0-documentation-of-the-grid-surfaces-origins-dep.md)** Stage S0 — documentation of the grid: surfaces, origins, deployment · M-2
* ☑ **[T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md)** Stage S1 — the server can do everything: TOML configuration, parity test · M-2
* ☑ **[T-98](T-98-stage-s2-reset-a-totp-factor-in-the-panel-and-cli.md)** Stage S2 — reset a TOTP factor in the panel and CLI · M-2
* ☑ **[T-99](T-99-stage-s3-every-origin-is-equal-source-step-up-linking-l.md)** Stage S3 — every origin is equal: source, step-up, linking local and IdP · M-2
* ☑ **[T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md)** Stage S4 — permissions: app identity, registration, assignment, has_permission · M-2
* ☑ **[T-101](T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md)** Stage S5 — permissions at the server and in the clients · M-2
* ☑ **[T-102](T-102-stage-s6-idp-role-sync-stage-1-import-groups-at-sign-in.md)** Stage S6 — IdP role sync stage 1: import groups at sign-in · M-2
* ☑ **[T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md)** Stage S7 — shell on top and at the side: one component, layout top or side · M-2
* ☑ **[T-104](T-104-stage-s8-hybrid-tinysesam-area-with-name-and-icon-libra.md)** Stage S8 — hybrid: TinySesam area with name and icon, library layout slot · M-2
* ☑ **[T-105](T-105-stage-s9-headless-writing-action-pages-with-a-way-back.md)** Stage S9 — headless writing: action pages with a way back · M-2
* ☑ **[T-106](T-106-stage-s10-headless-reading-events-keys-admin-data-insid.md)** Stage S10 — headless reading: events, keys, admin data inside the application"s area · M-2
* ☐ **[T-107](T-107-stage-s11-acceptance-matrix-in-ci-examples-x-origins.md)** Stage S11 — acceptance matrix in CI: examples x origins · M-2
* ☐ **[T-108](T-108-stage-s12-optional-fully-headless-library-register-rese.md)** Stage S12 (optional) — fully headless library: register, reset password, setup status · M-2
* ☐ **[T-109](T-109-stage-s13-optional-scim-stage-2-for-idp-role-sync.md)** Stage S13 (optional) — SCIM stage 2 for IdP role sync · M-2
* ☐ **[T-110](T-110-dependency-diet-joserfc-instead-of-authlib-jose-qr-as-s.md)** Dependency diet: joserfc instead of authlib.jose, QR as SVG without Pillow, SAML as its own image variant · M-3
* ☑ **[T-111](T-111-schema-baseline-and-ballast-removal-the-current-state-is.md)** Schema baseline and ballast removal: the current state is the starting line · M-1
* ☑ **[T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md)** Modules: split manager.py and store.py into one building block per feature; a feature that is off loads nothing · M-1
* ☑ **[T-113](T-113-topbar-fetch-in-rust-and-php.md)** Topbar fetch in the Rust and PHP clients · M-5
* ☑ **[T-114](T-114-test-image-nginx-on-the-stable-line.md)** Proxy test image: nginx on the stable line instead of mainline · M-5
* ☑ **[T-115](T-115-one-aggregate-ci-job-per-client.md)** One aggregate CI job per client, so required checks do not depend on matrix names · M-5
* ☑ **[T-116](T-116-pre-push-gate-caddy-suite-without-image.md)** Pre-push: the gate-Caddy suite without its image counts as red · M-5
* ☐ **[T-117](T-117-client-go-fuzz-on-time-again.md)** client-go: fuzz on time again once Go fixes the deadline report · M-5
* ☑ **[T-118](T-118-grype-exception-libc6-expires.md)** Grype exception for libc6 expires on 2026-11-28 — rebuild the base images or drop it · M-5
* ☑ **[T-119](T-119-caddy-jwt-jwk-url-hang-follow-upstream.md)** caddy-jwt 1.5.0: back to jwk_url, disable_authorization_fallback instead of the Authorization detour; check the X-Forwarded-For warning · M-5
* ☐ **[T-120](T-120-leftovers-of-approvals-account-api-and-app-frame.md)** On demand: leftovers of approvals, account API and app frame · M-5
* ☐ **[T-121](T-121-server-side-fuzzing.md)** Fuzz the server side: gate token, forward headers, OAuth endpoints, JSON APIs, template escaping · M-3
* ☐ **[T-122](T-122-public-threat-model.md)** A short public threat model · M-3
* ☐ **[T-123](T-123-independent-review-external-penetration-test-or-human.md)** Independent review: an external penetration test or a human code review · M-3
* ☐ **[T-124](T-124-crypto-inventory-and-post-quantum-readiness.md)** Crypto inventory and post-quantum readiness (harvest now, decrypt later) · M-3
* ☑ **[T-125](T-125-attestation-retry-in-the-tag-jobs.md)** Attestation retry in the tag jobs of release.yml (image, SBOM) · M-5
* ☑ **[T-126](T-126-breaking-release-after-the-baseline-with-an-upgrade-list.md)** Breaking release after the baseline, with one upgrade list · M-1
* ☑ **[T-127](T-127-compare-the-schema-baseline-with-the-tag-in-ci.md)** CI compares the schema baseline with the tag v0.30.0, not only with the checked-in file · M-1
* ☑ **[T-128](T-128-drop-the-pre-0-65-branch-of-the-kit-check.md)** Drop the branch for test kits before 0.65 in the release-automation check · M-5
* ☑ **[T-129](T-129-fleet-pin-of-a-breaking-release-opens-as-a-draft.md)** The fleet pin of a breaking release opens as a draft · M-2
* ☑ **[T-130](T-130-server-path-for-the-mfa-enrollment-pass.md)** Server path for the MFA enrollment pass (grant and revoke) · M-2
* ☑ **[T-131](T-131-sprint-lane-for-the-heavy-ci-jobs.md)** Sprint lane for the heavy CI jobs (classifier in the workflows) · M-5
* ☑ **[T-132](T-132-upgrade-list-for-breaks-after-0-31-0.md)** Upgrade list for the breaks after 0.31.0 · M-2
* ☐ **[T-133](T-133-quickstart-with-a-configuration-file.md)** deploy/quickstart with a configuration file · M-2
* ☑ **[T-134](T-134-docs-recipe-for-an-own-server-image-with-saml.md)** Docs: recipe for an own server image with the [saml] extra · M-2
* ☑ **[T-135](T-135-account-page-shows-the-roles-each-source-delivers.md)** Account page in the panel: the roles each source delivers · M-2
* ☐ **[T-136](T-136-knip-configuration-for-clients-js.md)** knip configuration for clients/js, so the unused-dependency check covers it · M-5
* ☐ **[T-137](T-137-declare-optional-imports-requests-and-websockets.md)** Declare the optional imports: requests in client.py, websockets in tools/oauth-e2e · M-5
* ☑ **[T-138](T-138-codeql-findings-before-the-closing-pr-of-a-sprint.md)** CodeQL findings before the closing PR of a sprint, not only in it · M-5
* ☑ **[T-139](T-139-codeql-before-the-closing-pr-the-real-analysis.md)** CodeQL before the closing PR of a sprint: the real analysis, not one mirrored rule · M-5
* ☐ **[T-140](T-140-http-test-for-register-in-the-php-client.md)** HTTP test for Permissions::register() in the PHP client · M-2
* ☑ **[T-141](T-141-acceptance-script-sends-a-forged-remote-permissions.md)** Proxy acceptance script sends a forged Remote-Permissions · M-2
* ☑ **[T-142](T-142-permissions-of-an-application-in-account-json-without-its-host.md)** Permissions of an application in account.json without its host · M-2
* ☑ **[T-143](T-143-frame-normalised-in-the-five-clients.md)** The topbar frame part normalised in the five clients · M-2
* ☑ **[T-144](T-144-side-layout-without-the-layout-attribute-jumps.md)** Side layout without the layout attribute: the page jumps when the data arrive · M-2
* ☐ **[T-145](T-145-panel-browser-tests-account-switch-race-and-cdp-helper.md)** Panel browser tests: account-switch race and the shared CDP helper · M-5
* ☐ **[T-146](T-146-triage-the-open-scorecard-alerts.md)** Triage the open Scorecard alerts · M-5
* ☑ **[T-147](T-147-administration-actions-on-action-pages-area-admin.md)** Administration actions on action pages: area admin, class each · M-2
* ☑ **[T-148](T-148-the-five-clients-normalise-actions-and-the-session.md)** The five clients normalise actions and the session handle · M-2
* ☑ **[T-149](T-149-browser-coverage-of-the-remaining-action-pages-in.md)** Browser coverage of the remaining action pages in Ex4 · M-2
* ☑ **[T-150](T-150-sprint-lane-runs-a-client-s-tests-when-spec-or-tha.md)** Sprint lane runs a client's tests when spec/ or that client changes · M-2
* ☑ **[T-151](T-151-frame-icon-in-topbar-json-so-the-shell-shows-the-a.md)** frame.icon in topbar.json, so the shell shows the application's icon in the frame · M-2
* ☑ **[T-152](T-152-the-frame-travels-in-the-token-of-address-change-e.md)** The frame travels in the token of address change, e-mail confirmation and invitation · M-2
* ☐ **[T-153](T-153-test-shell-browser-py-on-the-shared-tests-browser.md)** test_shell_browser.py on the shared tests/_browser_stack.py · M-5
* ☐ **[T-154](T-154-codeql-py-unused-global-variable-on-urls-and-hashe.md)** CodeQL py/unused-global-variable on _URLS_AND_HASHES in test_english_code.py · M-5
* ☐ **[T-155](T-155-duplicate-import-of-security-in-tinysesam-router-p.md)** Duplicate import of security in tinysesam/router.py · M-5
* ☐ **[T-156](T-156-administration-action-confirmed-by-passkey-or-prov.md)** Administration action confirmed by passkey or provider sign-in · M-3
* ☐ **[T-157](T-157-panel-field-for-the-app-of-an-invitation.md)** Panel field for the app of an invitation · M-5
* ☐ **[T-158](T-158-gate-clients-parse-the-return-of-an-action-page.md)** Gate clients parse the return of an action page · M-2
* ☐ **[T-159](T-159-client-http-tests-stale-comment-about-dropped-memb.md)** Client HTTP tests: stale comment about dropped members · M-5
* ☐ **[T-160](T-160-passkey-start-warning-and-operations-promise-a-sta.md)** Passkey start warning and OPERATIONS promise a start that the router build refuses · M-5

## Fehler

* ☑ **[B-1](B-1-admin-panel-rotates-csrf.md)** The admin panel rolls a new CSRF token on every request · M-4
* ☑ **[B-2](B-2-loop-without-app-approval.md)** Endless loop between application and login page when the approval for the application is missing · M-6
* ☑ **[B-3](B-3-gate-semicolon-redirect.md)** Gate: paths containing ; or %3B are redirected to /.tinysesam/start · M-5
* ☑ **[B-4](B-4-login-next-not-percent-encoded.md)** Login page: next is HTML-escaped but not percent-encoded in its links · M-5
* ☑ **[B-5](B-5-gateway-websocket-upgrade.md)** Gateway: forward auth of a WebSocket app answers 403 when a WebSocket library is installed · M-5
* ☑ **[B-6](B-6-gate-refresh-exchange-does-not-renew-the-applicati.md)** Gate: refresh exchange does not renew the application approval — hourly login once the provider session has ended · M-5
* ☑ **[B-7](B-7-gate-token-iat-in-the-future-after-a-clock-step.md)** Gate token: iat in the future after a backward clock step — caddy-jwt rejects fresh tokens · M-5
* ☑ **[B-8](B-8-voluntary-totp-setup-does-not-lead-on.md)** Voluntary TOTP setup does not lead on — the page stays on "2FA active" · M-5
* ☑ **[B-9](B-9-no-recovery-codes-after-totp-setup-warning-wraps.md)** No recovery codes after the TOTP setup, and the warning on the account page wraps into the buttons · M-5
* ☑ **[B-10](B-10-account-without-password-cannot-set-one.md)** An account without a password cannot set one — the account page demands the current password · M-5
* ☑ **[B-11](B-11-a-saml-response-could-be-replayed-until-notonoraft.md)** A SAML response could be replayed until NotOnOrAfter · M-5
* ☑ **[B-12](B-12-new-sign-in-factors-api-keys-and-qr-approval-witho.md)** New sign-in factors, API keys and QR approval without fresh confirmation · M-5
* ☑ **[B-13](B-13-flaky-ci-suite-died-silently-and-chrome-start.md)** CI flakes: a suite died from a segfault without a word, a dialog wait raced, Chrome hung at startup · M-5
* ☑ **[B-14](B-14-late-key-list-overwrites-the-sign-in-link-browser-test-reauth-flakes.md)** Admin panel: a late key list overwrote the sign-in link; browser test ran out after a dialog that navigates · M-5
* ☑ **[B-15](B-15-totp-codes-in-the-suites-flip-at-a-step-boundary.md)** Test flake: TOTP codes in the suites flip at a 30-second step boundary · M-5
* ☑ **[B-16](B-16-the-sql-check-of-test-english-code-goes-blind-afte.md)** The SQL check of test_english_code goes blind after an apostrophe in a SCHEMA comment · M-1
* ☑ **[B-17](B-17-scorecard-red-upstream-image-of-scorecard-action-2-6-0.md)** Scorecard red: the image of scorecard-action 2.6.0 cannot be pulled (upstream) · M-5
* ☑ **[B-18](B-18-oidc-unlink-leaves-the-refresh-row-of-the-running-session.md)** OIDC unlink leaves the refresh row of the running session · M-2
* ☑ **[B-19](B-19-a-removed-role-keeps-its-permission-assignments.md)** A role removed from available_roles keeps its permission assignments · M-2
* ☑ **[B-20](B-20-a-role-removed-and-re-added-at-runtime-keeps-its-assignments.md)** A role removed and re-added at runtime keeps its permission assignments · M-2
* ☑ **[B-21](B-21-brand-icon-path-in-the-shell-resolves-on-the-application-host.md)** A brand_icon path in the shell logo resolves on the application's host · M-2
* ☐ **[B-22](B-22-role-removed-and-re-added-between-two-permission-c.md)** Role removed and re-added between two permission checks stays unnoticed · M-5

## Entscheidungen (ADR)

* ✗ **[ADR-1](ADR-1-pypi-deferred.md)** PyPI release deferred until 1.0 · abgelöst durch ADR-6
* ☑ **[ADR-2](ADR-2-no-self-update.md)** No self-update — whoever installs decides the version
* ☑ **[ADR-3](ADR-3-in-app-instead-of-proxy.md)** Protection in the app per route, not at proxy level
* ☑ **[ADR-4](ADR-4-no-self-hosted-runners.md)** CI stays on hosted runners — self-hosted ruled out
* ☑ **[ADR-5](ADR-5-roles-in-forward-auth.md)** Roles in forward auth come from the proxy, not from a rules table
* ☑ **[ADR-6](ADR-6-publish-to-pypi.md)** TinySesam is published on PyPI from 1.0
* ☑ **[ADR-7](ADR-7-factors-not-from-the-idp.md)** TOTP secrets and PINs never come from the identity provider
* ☑ **[ADR-8](ADR-8-pin-as-first-factor.md)** A PIN may be the first factor — deliberate, configurable, with its own limit
* ☑ **[ADR-9](ADR-9-gate-token-at-the-proxy.md)** Gate in front of third-party apps — the proxy verifies a short-lived gate token itself, TinySesam only when issuing
* ☑ **[ADR-11](ADR-11-oauth-authorization-server-in-tinysesam.md)** OAuth 2.1 authorization server for MCP clients — built into TinySesam with own thin handlers, not Ory Hydra as a sidecar
* ☑ **[ADR-12](ADR-12-key-purposes-keyrings-and-rotation.md)** One key per purpose, each a keyring with key IDs — vault, gate signature, OAuth pepper; rotation without loss
* ☑ **[ADR-13](ADR-13-oauth-for-services-private-key-jwt.md)** Services get tokens with client_credentials and private_key_jwt, paired by a one-time code — amends ADR-11
* ☑ **[ADR-14](ADR-14-pairing-code-as-consent-given-in-advance.md)** A pairing code is a consent given in advance — one authorization of the account without the consent page, amends ADR-11
* ☑ **[ADR-15](ADR-15-python-core-stays-clients-stay-thin-no-go-rewrite.md)** Python core stays, clients stay thin — no Go rewrite
* ☑ **[ADR-16](ADR-16-server-configuration-by-toml-file-with-an-environment-o.md)** Server configuration by TOML file with an environment overlay, and library–server parity
* ☑ **[ADR-17](ADR-17-permission-layer-and-admin-levels.md)** Permission layer and admin levels
* ☑ **[ADR-18](ADR-18-idp-role-sync-and-linking-local-and-idp-accounts.md)** IdP role sync and linking local and IdP accounts
* ☑ **[ADR-19](ADR-19-gate-look-like-a-provider-sign-in-heading-and-icon-of-t.md)** Gate look like a provider sign-in: heading and icon of the application, no look per host

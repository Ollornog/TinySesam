# Backlog

<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: `python3 scripts/_backlog.py index` -->

Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.
Konventionen: [README-KONVENTION.md](README-KONVENTION.md).

## Meilensteine

* ☐ **[M-1](M-1-api-stable-1-0.md)** 1.0 — API stable enough for PyPI — 14/14 erledigt
* ☐ **[M-2](M-2-after-1-0.md)** After 1.0 — keeping the published package maintained — 9/12 erledigt
* ☑ **[M-3](M-3-gate-in-front-of-third-party-apps.md)** Gate in front of third-party apps — fast, sign in once, sign out cleanly — 8/8 erledigt

## Aufgaben

* ☑ **[T-1](T-1-e2e-against-real-idp.md)** End-to-end test against a real identity provider · M-1
* ☑ **[T-2](T-2-do-not-search-free-port-yourself.md)** Browser test should not look for a free port itself · M-1
* ☑ **[T-3](T-3-forward-auth-header-fine-tuning.md)** Forward auth — make the remote headers that are set configurable · M-1
* ☑ **[T-4](T-4-verification-without-magic-endpoint.md)** Email verification and invitation without the magic-link endpoint · M-1
* ☑ **[T-5](T-5-verify-image-signature.md)** Consider image signature and SBOM · M-1
* ☑ **[T-6](T-6-stage-via-playbook.md)** Build the E2E stage with a playbook instead of by hand · M-1
* ☑ **[T-7](T-7-spdx-license-expression.md)** Switch the license declaration to the SPDX expression (deadline: 2027-02-18) · M-2
* ☑ **[T-8](T-8-maturity-review-remaining-findings.md)** Work through the 35 maturity-review findings that were not reproduced individually · M-1
* ☑ **[T-9](T-9-audit-2026-09-21-round-2.md)** Work through the findings of the second audit (four perspectives) · M-1
* ☑ **[T-10](T-10-docs-comparison-2026-09-21.md)** Docs measured against the code — 70 places, 10 real defects · M-1
* ☑ **[T-11](T-11-zizmor-excessive-permissions.md)** zizmor excessive-permissions — already fixed when filed, entry stays as a lesson · M-1
* ☑ **[T-12](T-12-codeql-backlog.md)** Assess the CodeQL backlog and track the open alerts in the backlog · M-1
* ☑ **[T-13](T-13-audit-2026-09-22-round-3.md)** Work through the findings of the third audit (red team, blue team, online research) · M-1
* ☑ **[T-14](T-14-multiple-oidc-clients.md)** Multiple OIDC clients in one instance — per-app approval lives at the identity provider · M-1
* ☑ **[T-15](T-15-subpath-mounting.md)** Make built-in pages mountable under a subpath · M-2
* ☑ **[T-16](T-16-group-scope-warning.md)** Warn when a group rule runs through the groups claim and the groups scope is missing · M-2
* ☑ **[T-17](T-17-claim-token-not-in-container-log.md)** Do not write the first-admin one-time token to the container log · M-2
* ☑ **[T-18](T-18-flaky-test-prebooking-pending.md)** Flaky test test_prebooking_pending — red once in the CI job repeat, cause open · M-2
* ☑ **[T-19](T-19-gate-token.md)** Issue the gate token and prove it with a real Caddy running caddy-jwt · M-3
* ☑ **[T-20](T-20-share-exceptions.md)** Share exceptions per app — exact path prefixes before the gate, with a control test · M-3
* ☑ **[T-21](T-21-login-modes.md)** Login mode per app: invisible (gateway default) or window · M-3
* ☑ **[T-22](T-22-logout-modes.md)** Logout mode per app: app, all, ask — chain via the provider back to the gate · M-3
* ☑ **[T-23](T-23-config-check-gate.md)** Configuration check for gate operation · M-3
* ☑ **[T-24](T-24-gate-acceptance-measurement.md)** Acceptance — before/after measurement and acceptance test per app · M-3
* ☑ **[T-25](T-25-oidc-on-the-stage.md)** E2E stage — the OIDC ceremony fails at the identity provider · M-2
* ☑ **[T-26](T-26-gate-link-code-exchange.md)** Central gateway with code exchange — session stays on the gateway, app hosts only get a connection of their own · M-3
* ☐ **[T-27](T-27-cli-delete-account.md)** CLI command to delete an account (maintenance without the admin panel) · M-2
* ☐ **[T-28](T-28-go-variant-small-gate-client.md)** Examine a Go variant — a small gate client instead of a complete rewrite · M-2
* ☑ **[T-29](T-29-translate-everything-to-english.md)** Translate everything to English (code texts, docs, messages) · M-2
* ☐ **[T-30](T-30-launch-plan.md)** Launch plan — make TinySesam publicly known · M-2

## Fehler

* ☑ **[B-1](B-1-admin-panel-rotates-csrf.md)** The admin panel rolls a new CSRF token on every request · M-1
* ☑ **[B-2](B-2-loop-without-app-approval.md)** Endless loop between application and login page when the approval for the application is missing · M-3
* ☑ **[B-3](B-3-gate-semicolon-redirect.md)** Gate: paths containing ; or %3B are redirected to /.tinysesam/start · M-2
* ☑ **[B-4](B-4-login-next-not-percent-encoded.md)** Login page: next is HTML-escaped but not percent-encoded in its links · M-2

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

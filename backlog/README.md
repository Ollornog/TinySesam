# Backlog

<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: `python3 scripts/_backlog.py index` -->

Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.
Konventionen: [README-KONVENTION.md](README-KONVENTION.md).

## Meilensteine

* ☐ **[M-1](M-1-api-stabil-1-0.md)** 1.0 — API stable enough for PyPI — 14/14 erledigt
* ☐ **[M-2](M-2-nach-1-0.md)** After 1.0 — keeping the published package maintained — 6/7 erledigt
* ☑ **[M-3](M-3-gate-vor-fremden-apps.md)** Gate in front of third-party apps — fast, sign in once, sign out cleanly — 8/8 erledigt

## Aufgaben

* ☑ **[T-1](T-1-e2e-gegen-echten-idp.md)** End-to-end test against a real identity provider · M-1
* ☑ **[T-2](T-2-freien-port-nicht-selbst-suchen.md)** Browser test should not look for a free port itself · M-1
* ☑ **[T-3](T-3-forward-auth-header-feinsteuerung.md)** Forward auth — make the remote headers that are set configurable · M-1
* ☑ **[T-4](T-4-verifikation-ohne-magic-endpoint.md)** Email verification and invitation without the magic-link endpoint · M-1
* ☑ **[T-5](T-5-abbild-signatur-pruefen.md)** Consider image signature and SBOM · M-1
* ☑ **[T-6](T-6-stage-per-playbook.md)** Build the E2E stage with a playbook instead of by hand · M-1
* ☑ **[T-7](T-7-spdx-lizenzausdruck.md)** Switch the license declaration to the SPDX expression (deadline: 2027-02-18) · M-2
* ☑ **[T-8](T-8-reifepruefung-restbefunde.md)** Work through the 35 maturity-review findings that were not reproduced individually · M-1
* ☑ **[T-9](T-9-audit-2026-09-21-runde-2.md)** Work through the findings of the second audit (four perspectives) · M-1
* ☑ **[T-10](T-10-doku-abgleich-2026-09-21.md)** Docs measured against the code — 70 places, 10 real defects · M-1
* ☑ **[T-11](T-11-zizmor-excessive-permissions.md)** zizmor excessive-permissions — already fixed when filed, entry stays as a lesson · M-1
* ☑ **[T-12](T-12-codeql-bestand.md)** Assess the CodeQL backlog and track the open alerts in the backlog · M-1
* ☑ **[T-13](T-13-audit-2026-09-22-runde-3.md)** Work through the findings of the third audit (red team, blue team, online research) · M-1
* ☑ **[T-14](T-14-mehrere-oidc-clients.md)** Multiple OIDC clients in one instance — per-app approval lives at the identity provider · M-1
* ☑ **[T-15](T-15-unterpfad-montage.md)** Make built-in pages mountable under a subpath · M-2
* ☑ **[T-16](T-16-gruppen-scope-warnung.md)** Warn when a group rule runs through the groups claim and the groups scope is missing · M-2
* ☑ **[T-17](T-17-claim-token-nicht-ins-container-log.md)** Do not write the first-admin one-time token to the container log · M-2
* ☑ **[T-18](T-18-wackeltest-vorbuchung-schwebe.md)** Flaky test test_vorbuchung_schwebe — red once in the CI job repeat, cause open · M-2
* ☑ **[T-19](T-19-gate-token.md)** Issue the gate token and prove it with a real Caddy running caddy-jwt · M-3
* ☑ **[T-20](T-20-share-ausnahmen.md)** Share exceptions per app — exact path prefixes before the gate, with a control test · M-3
* ☑ **[T-21](T-21-login-modi.md)** Login mode per app: invisible (gateway default) or window · M-3
* ☑ **[T-22](T-22-logout-modi.md)** Logout mode per app: app, all, ask — chain via the provider back to the gate · M-3
* ☑ **[T-23](T-23-konfigpruefung-gate.md)** Configuration check for gate operation · M-3
* ☑ **[T-24](T-24-gate-abnahme-messung.md)** Acceptance — before/after measurement and acceptance test per app · M-3
* ☑ **[T-25](T-25-oidc-auf-der-buehne.md)** E2E stage — the OIDC ceremony fails at the identity provider · M-2
* ☑ **[T-26](T-26-gate-link-code-austausch.md)** Central gateway with code exchange — session stays on the gateway, app hosts only get a connection of their own · M-3
* ☐ **[T-27](T-27-cli-konto-loeschen.md)** CLI command to delete an account (maintenance without the admin panel) · M-2

## Fehler

* ☑ **[B-1](B-1-admin-panel-rotiert-csrf.md)** The admin panel rolls a new CSRF token on every request · M-1
* ☑ **[B-2](B-2-schleife-ohne-app-freigabe.md)** Endless loop between application and login page when the approval for the application is missing · M-3

## Entscheidungen (ADR)

* ✗ **[ADR-1](ADR-1-pypi-vertagt.md)** PyPI release deferred until 1.0 · abgelöst durch ADR-6
* ☑ **[ADR-2](ADR-2-kein-selbst-update.md)** No self-update — whoever installs decides the version
* ☑ **[ADR-3](ADR-3-in-app-statt-proxy.md)** Protection in the app per route, not at proxy level
* ☑ **[ADR-4](ADR-4-keine-self-hosted-runner.md)** CI stays on hosted runners — self-hosted ruled out
* ☑ **[ADR-5](ADR-5-rollen-im-forward-auth.md)** Roles in forward auth come from the proxy, not from a rules table
* ☑ **[ADR-6](ADR-6-pypi-veroeffentlichen.md)** TinySesam is published on PyPI from 1.0
* ☑ **[ADR-7](ADR-7-faktoren-nicht-aus-dem-idp.md)** TOTP secrets and PINs never come from the identity provider
* ☑ **[ADR-8](ADR-8-pin-als-erstfaktor.md)** A PIN may be the first factor — deliberate, configurable, with its own limit
* ☑ **[ADR-9](ADR-9-gate-token-am-proxy.md)** Gate in front of third-party apps — the proxy verifies a short-lived gate token itself, TinySesam only when issuing

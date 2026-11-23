---
id: M-4
type: Milestone
title: "Shell and headless: every UI mode, local/IdP/mixed users, library and server alike"
status: offen
tags: [shell, headless, server, permissions]
created: 2026-11-23
---
# M-4 — Shell and headless

**Done when:** a developer who does not know this project can put TinySesam into an application in any of the four surfaces — shell on top, shell at the side, hybrid (a TinySesam area, the rest belongs to the application), headless — with local, IdP or mixed users, once as a library and once as a server, and gets the same behaviour. Applications register their own permissions; administrators assign them to roles; the application asks `has_permission`.

Goal (maintainer, 2026-11-23): TinySesam as an open-source building block for other developers. Decisions: [ADR-15](ADR-15-python-core-stays-clients-stay-thin-no-go-rewrite.md) (Python core, thin clients), [ADR-16](ADR-16-server-configuration-by-toml-file-with-an-environment-o.md) (server file and parity), [ADR-17](ADR-17-permission-layer-and-admin-levels.md) (permissions and admin levels), [ADR-18](ADR-18-idp-role-sync-and-linking-local-and-idp-accounts.md) (IdP role sync and linking), [ADR-19](ADR-19-gate-look-like-a-provider-sign-in-heading-and-icon-of-t.md) (gate look).

## The grid

Four surfaces (shell on top, shell at the side, hybrid, headless) x three origins (local, IdP, mixed) x two modes of operation (library, server). Limits that hold for every cell: secrets are typed only on TinySesam pages when the application is on another origin; writing from the application only by navigation to an action page with a way back; area administrators stay a matter of the panel; admin read inside the application's area only; the administrator flag is never set by link; hardening and configuration only instance-wide; "sign-in link" instead of "set a password"; the panel is linked, nothing is switched off.

## Order: server first

T-96 -> T-97 -> T-98 -> T-100 -> T-101 -> T-99 -> T-102 -> T-103 -> T-104 -> T-105 -> T-106 -> T-107 (T-108, T-109 on demand; T-110 any time)

## Acceptance

- One example application per surface, all with the same business logic ("documents" with `docs.read` / `docs.delete`): **Ex1** shell on top (Go, server, local and mixed), **Ex2** shell at the side (Python, library, local and IdP), **Ex3** hybrid (PHP or Node, server, IdP and mixed), **Ex4** headless (JavaScript single-page app, server, mixed).
- Parity test between library and server green ([T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md)); acceptance matrix in CI ([T-107](T-107-stage-s11-acceptance-matrix-in-ci-examples-x-origins.md)).

## Tasks

| Stage | Task | Title | SP | Hours |
|---|---|---|---|---|
| S0 | [T-96](T-96-stage-s0-documentation-of-the-grid-surfaces-origins-dep.md) | documentation of the grid: surfaces, origins, deployment | 3 | 4–6 |
| S1 | [T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md) | the server can do everything: TOML configuration, parity test | 13 | 20–26 |
| S2 | [T-98](T-98-stage-s2-reset-a-totp-factor-in-the-panel-and-cli.md) | reset a TOTP factor in the panel and CLI | 2 | 3–4 |
| S3 | [T-99](T-99-stage-s3-every-origin-is-equal-source-step-up-linking-l.md) | every origin is equal: source, step-up, linking local and IdP | 13 | 24–32 |
| S4 | [T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md) | permissions: app identity, registration, assignment, has_permission | 13 | 26–32 |
| S5 | [T-101](T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md) | permissions at the server and in the clients | 13 | 22–30 |
| S6 | [T-102](T-102-stage-s6-idp-role-sync-stage-1-import-groups-at-sign-in.md) | IdP role sync stage 1: import groups at sign-in | 8 | 14–20 |
| S7 | [T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md) | shell on top and at the side: one component, layout top or side | 13 | 24–32 |
| S8 | [T-104](T-104-stage-s8-hybrid-tinysesam-area-with-name-and-icon-libra.md) | hybrid: TinySesam area with name and icon, library layout slot | 13 | 18–24 |
| S9 | [T-105](T-105-stage-s9-headless-writing-action-pages-with-a-way-back.md) | headless writing: action pages with a way back | 21 | 27–34 |
| S10 | [T-106](T-106-stage-s10-headless-reading-events-keys-admin-data-insid.md) | headless reading: events, keys, admin data inside the application's area | 13 | 26–32 |
| S11 | [T-107](T-107-stage-s11-acceptance-matrix-in-ci-examples-x-origins.md) | acceptance matrix in CI: examples x origins | 8 | 10–14 |
| S12 (optional) | [T-108](T-108-stage-s12-optional-fully-headless-library-register-rese.md) | fully headless library: register, reset password, setup status | 5 | 8–10 |
| S13 (optional) | [T-109](T-109-stage-s13-optional-scim-stage-2-for-idp-role-sync.md) | SCIM stage 2 for IdP role sync | 21 | 32–45 |
| Diet | [T-110](T-110-dependency-diet-joserfc-instead-of-authlib-jose-qr-as-s.md) | Dependency diet: joserfc instead of authlib.jose, QR as SVG without Pillow, SAML as its own image variant | 5 | 8–12 |

Stages S0 to S11: 133 SP, 218–286 h (estimate, not measured; 1 SP is about one pull request of 2–3 h). With S12 and S13: 159 SP, 258–341 h. The dependency diet comes on top (5 SP).

## Existing entries

- [T-90](T-90-account-api-for-applications-stage-a-create-read-u.md) "Later: gateway variable `TINYSESAM_APPS`" is part of T-97.
- [T-91](T-91-app-frame-and-account-overview.md) "one style for the gateway" stays valid for the gate; ADR-19 adds name and icon per application and replaces the planned "look per host".
- [T-73](T-73-tenants-multiple-hostnames-each-with-its-own-sign-in-choice.md) (tenants) stays an idea and is not part of this milestone.
- [T-74](T-74-delegated-admins.md): "delegates" are renamed "area administrators" by ADR-17.

## Out of scope

A mode switch, CORS, write routes under `/.tinysesam/`, iframes, bar injection by the proxy, a TinySesam area on the application's origin behind a proxy, fully headless server applications, wildcard permissions, permission hierarchies, object-level permissions inside TinySesam, an application granting itself rights.

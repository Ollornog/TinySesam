---
id: T-97
type: Task
title: "Stage S1 — the server can do everything: TOML configuration, parity test"
status: offen
milestone: M-4
blocked_by: [T-96]
tags: [gateway, server, config]
created: 2026-11-23
---
# T-97 — Stage S1 — the server can do everything: TOML configuration, parity test

**Story points:** 13 · **Estimate:** 20–26 h (from the concept, not measured) · **Milestone:** [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The gateway is today an OIDC-only preset configured by environment variables (no local accounts, panel, account page, `apps`, SAML or LDAP). Make the server the same core as the library, configured by a file ([ADR-16](ADR-16-server-configuration-by-toml-file-with-an-environment-o.md)).

## Content
- `TINYSESAM_CONFIG=/etc/tinysesam.toml` (stdlib `tomllib`) builds the full `TinySesamConfig`; the environment overlays the file. Secrets only as `*_file` or `env:NAME`; `config_check` refuses a literal at a secret field.
- The gateway mounts panel, account page, approvals and the account API when switched on.
- Image variant with the `[saml]` extra (libxmlsec1) kept apart from the slim image.
- Parity test over `tests/api_surface.json` (extended, no new guard): every tier A/B name has a server route or an entry on the "library only" list with a reason.
- `deploy/quickstart` with a configuration file.
- Includes the open item "Gateway variable `TINYSESAM_APPS`" of [T-90](T-90-account-api-for-applications-stage-a-create-read-u.md) (Later): `apps` come from the file, with the switches the gateway preset turns off.
- Related idea: [T-73](T-73-tenants-multiple-hostnames-each-with-its-own-sign-in-choice.md) (tenants) stays separate; the file format must not block it.

## Acceptance
- Example **Ex1** (a Go application behind the server, local accounts): sign-in, panel and account API without a line of Python in the application.
- Parity test green; a mutation (remove a server route) turns it red.

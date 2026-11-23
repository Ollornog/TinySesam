---
id: ADR-16
type: Decision
title: Server configuration by TOML file with an environment overlay, and library–server parity
status: erledigt
tags: [architecture, gateway, config]
created: 2026-11-23
---
# ADR-16 — Server configuration by TOML file; parity with the library

## Context
The gateway is a preset configured by environment variables, covering only OIDC (`gateway.py`, `config.py` with `admin_enabled=False`, `account_enabled=False`). It has no local accounts, panel, account page, `apps`, SAML or LDAP. For other developers the server must be able to do what the library does.

## Options
1. More environment variables: hundreds of names, no review or git path.
2. Everything in the panel: the configuration would have no review path and no reproducibility.
3. **A TOML file, the environment as an overlay, runtime data in the panel** (chosen).

## Decision
- `TINYSESAM_CONFIG=/etc/tinysesam.toml`, read with the standard library (`tomllib`), builds the full `TinySesamConfig`. The environment overlays the file (container habit).
- Secrets only as `*_file` or `env:NAME`; `config_check` refuses a literal at a secret field.
- Runtime data (role catalog, permissions assignments, accounts) live in the database and are maintained in the panel.
- The server is `tinysesam.gateway` with the full configuration, not a second code base. The SAML extras ship as their own image variant.
- **Parity rule:** every function has a server route (and, where the application reads something, a spec section and a vector) or sits on a "library only" list with a reason. A parity test reads `tests/api_surface.json` (extended) and fails when a tier A/B name has neither. Library only: fully headless forms with own password fields, `set_template` and `page_layout`.
- Server first: [T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md) precedes every other stage of [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md).

## Consequences
Every later feature ships its HTTP or spec path in the same pull request. The environment variable `TINYSESAM_APPS` of [T-90](T-90-account-api-for-applications-stage-a-create-read-u.md) becomes part of the file.

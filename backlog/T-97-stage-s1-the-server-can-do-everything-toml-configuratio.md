---
id: T-97
type: Task
title: "Stage S1 — the server can do everything: TOML configuration, parity test"
status: in-arbeit
points: 13
milestone: M-2
blocked_by: [T-96, T-112]
tags: [gateway, server, config]
created: 2026-11-23
---
# T-97 — Stage S1 — the server can do everything: TOML configuration, parity test

**Story points:** 13 · **Estimate:** 20–26 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The gateway is today an OIDC-only preset configured by environment variables (no local accounts, panel, account page, `apps`, SAML or LDAP). Make the server the same core as the library, configured by a file ([ADR-16](ADR-16-server-configuration-by-toml-file-with-an-environment-o.md)).

## Content
- `TINYSESAM_CONFIG=/etc/tinysesam.toml` (stdlib `tomllib`) builds the full `TinySesamConfig`; the environment overlays the file. Secrets only as `*_file` or `env:NAME`; `config_check` refuses a literal at a secret field.
- The gateway mounts panel, account page, approvals and the account API when switched on.
- Image variant with the `[saml]` extra (libxmlsec1) kept apart from the slim image.
- Parity test over `tests/api_surface.json` (extended, no new guard): every tier A/B name has a server route or an entry on the "library only" list with a reason.
- `deploy/quickstart` with a configuration file.
- Includes the open item "Gateway variable `TINYSESAM_APPS`" of [T-90](T-90-account-api-for-applications-stage-a-create-read-u.md) (Later): `apps` come from the file, with the switches the gateway preset turns off.
- Related idea: [T-73](T-73-tenants-multiple-hostnames-each-with-its-own-sign-in-choice.md) (tenants) stays separate; the file format must not block it.

## Progress

- 2026-11-27, part 1: `TINYSESAM_CONFIG` file (`tinysesam/_server_config.py`), secrets only `env:NAME` / `<field>_file`
  (checked in the loader, where the source of a value is still visible — `config_check` sees only the resolved value),
  unknown keys refused, the gateway variables as overlay (`gateway.ENVIRONMENT_FIELDS`, held to the preset path per
  variable), panel, account page and approvals mount through `auth.router()` when the file switches them on.
  Suite `tests/test_server_config.py`.
- 2026-11-27, part 2: parity test in `tests/test_api_surface.py` (no new guard): `server` on 168 tier A/B entries of
  `tests/api_surface.json` (route or `library: <reason>`), areas decided as a whole (`PARITY_AREA_REASONS`), the
  server built from a configuration file with every feature on (`server_routes`), routes behind a missing extra
  checked against the static scan. Gaps: `grant_mfa_enrollment`, `revoke_mfa_enrollment` → [T-130](T-130-server-path-for-the-mfa-enrollment-pass.md).

- 2026-11-27, part 3: example **Ex1** — `clients/go/examples/ex1` (header mode, account API with the service
  account's automation key), `deploy/ex1` (`tinysesam.toml`, compose built from the checkout, Dockerfile with
  digest-pinned bases in Dependabot), `tests/test_example_ex1.py` (the server from that file serves sign-in, panel,
  account page and forward auth; list and invite through the account API).

**Open (rest of T-97):**
- Image variant with the `[saml]` extra: a second published image (libxmlsec1 and its libraries in the distroless
  runtime, its own release jobs, attestation, image probe and Dependabot entry) — an architecture decision for the
  maintainer before it is built (named in the S4 report).
- `deploy/quickstart` with a configuration file: waits for the next release (release stop until the end of M-2), as
  the published images before it cannot read `TINYSESAM_CONFIG`.

## Acceptance
- Example **Ex1** (a Go application behind the server, local accounts): sign-in, panel and account API without a line of Python in the application.
- Parity test green; a mutation (remove a server route) turns it red.

## Roadmap (2026-11-23)

Comes after the module cut ([T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md)): the file
fills `TinySesamConfig`, and the feature registry of T-112 loads only what it switches on. Run it in the same sprint
right after T-112, by the same hands.

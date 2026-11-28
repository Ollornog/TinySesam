---
id: T-133
type: Task
title: "deploy/quickstart with a configuration file"
status: erledigt
points: 2
milestone: M-2
tags: [deploy, server, config]
created: 2026-11-27
---
# T-133 — Quickstart with a configuration file

**Story points:** 2 · **Estimate:** 2–3 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Rest of [T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md). `deploy/quickstart` pins the published
image, and the images up to 0.31.0 cannot read `TINYSESAM_CONFIG`. Releases wait until the end of M-2, so this goes in
with the release that closes M-2.

## Content
- `deploy/quickstart` ships a `tinysesam.toml` next to the compose file (secrets as `<field>_file` or `env:NAME`) and
  sets `TINYSESAM_CONFIG`; the environment variables keep working as an overlay.
- README and `docs/` quickstart sections show the file.

## Acceptance
- The quickstart test starts the stack from the file with the image of the new release: sign-in, panel and forward
  auth answer.

## Done (S9)

`deploy/quickstart/tinysesam.toml` (the OIDC gateway's switches, network, database path; the client secret as `env:`),
mounted read-only with `TINYSESAM_CONFIG`; `.env` overlays it. `tests/test_quickstart_config.py`: the file with
example.env's variables equals the preset field by field, the overlay, no secret in the file.
`tests/test_quickstart.py` asserts inside the stack that the gateway runs from the file (measured locally with images
built from this checkout). Upgrade note: WebDAV profile needs `account_enabled = true` in the file. The quickstart
still pins the 0.31.0 images until the release bumps them (`scripts/_release.py`) — the file needs that release.

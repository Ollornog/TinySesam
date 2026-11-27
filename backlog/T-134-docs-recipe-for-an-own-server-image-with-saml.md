---
id: T-134
type: Task
title: "Docs: recipe for an own server image with the [saml] extra"
status: offen
points: 1
milestone: M-2
tags: [docs, saml, deploy]
created: 2026-11-27
---
# T-134 — Recipe for an own server image with SAML

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The published server image stays slim and has no SAML (decision 2026-11-27 in
[T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md): no second published image). Operators who want
SAML at the server build their own image.

## Content
- A short section in `docs/` with a Dockerfile: the server image's base, `tinysesam[saml]` with libxmlsec1 and its
  libraries, the configuration file from T-97.
- Points out that the operator then owns updates and scanning of that image.

## Acceptance
- A test builds the recipe's image in a throwaway container (own label) and the server signs in through the SAML test
  provider of the suite; without Docker it skips with a reason (a skip is not a green: it runs in CI).

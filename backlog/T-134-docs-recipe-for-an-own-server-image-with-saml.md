---
id: T-134
type: Task
title: "Docs: recipe for an own server image with the [saml] extra"
status: erledigt
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

## Progress

- 2026-11-27: done. Recipe `deploy/saml-server/Dockerfile` and the section "A server image with SAML" in
  `docs/OPERATIONS.md`. Deviation from the content above: no libxmlsec1 from apt — the `xmlsec` and `lxml` wheels
  (amd64, arm64) bring libxmlsec1 and libxml2 built against each other, and mixing a wheel with Debian's library is what
  breaks `import xmlsec`; `--only-binary` keeps it so (measured: the runtime stage without any apt package signs in).
  `tests/test_saml_image.py` (label `tinysesam.test=saml-image`, only its own container and image are removed), required
  in the CI job `gate-caddy`.


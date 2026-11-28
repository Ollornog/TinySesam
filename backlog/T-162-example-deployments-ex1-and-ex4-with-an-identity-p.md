---
type: Task
title: Example deployments Ex1 and Ex4 with an identity provider
status: offen
points: 3
id: T-162
milestone: M-2
created: '2026-11-28'
---
# T-162 — Example deployments Ex1 and Ex4 with an identity provider

**Story points:** 3

The acceptance matrix (T-107) adds the provider to the configurations of Ex1, Ex2 and Ex4 only inside the browser suites; deploy/ex1, deploy/ex4 and the demo of Ex2 run with local accounts. For M-2's promise (any surface with local, IdP or mixed accounts) the deployments should show the mixed case too: an optional provider block in deploy/ex1/tinysesam.toml and deploy/ex4/tinysesam.toml (oidc_* with env secrets, a group mapped to the example's role), the compose files and READMEs (en/de) saying how to point it at a provider, and Ex2's --demo with an optional provider. Acceptance: the suites read the provider block from the deploy files instead of appending it; docs name the steps.

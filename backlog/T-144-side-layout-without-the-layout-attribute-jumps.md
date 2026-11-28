---
id: T-144
type: Task
title: "Side layout without the layout attribute: the page jumps when the data arrive"
status: erledigt
points: 1
milestone: M-2
tags: [shell, docs]
created: 2026-11-28
---
# T-144 — Side layout without the layout attribute: the page jumps when the data arrive

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Found in [T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md): `<ts-shell>` without `layout`
learns the side layout from `topbar.json`, and the page shifts once.

## Content
- Recommend the attribute in the docs and the examples; optionally a hint in the console in dev mode.

## Acceptance
- Both examples set the attribute; the docs say why.

## Done (S9)

Spec §8d (SHOULD set the attribute, and why), README and `README.de.md` ("The shell component"), the snippet in both
with `layout="top"`; example Ex1 sets `layout="top"` (Go test and `tests/test_shell_browser.py`). Ex2 uses the
library's server-side bar (`auth.topbar(…)`), which knows the layout before the first paint — no jump there. No
console hint: the component has no dev mode to tell it apart from production.

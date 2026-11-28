---
id: T-143
type: Task
title: "The topbar frame part normalised in the five clients"
status: erledigt
points: 3
milestone: M-2
tags: [clients, shell, topbar]
created: 2026-11-28
---
# T-143 — The topbar frame part normalised in the five clients

**Story points:** 3 · **Estimate:** 4–6 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

[T-103](T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md) added the part `frame` to `topbar.json`
(spec §8d). The clients pass it through raw.

## Content
- Go, Rust, JavaScript, PHP and Python read `frame` into their typed form, against shared vectors.

## Acceptance
- The vectors are green in all five clients.

## Done (sprint S8, 2026-11-28)

Spec §8d says how `frame` is normalized; every top-bar vector expects it, eight new `frame-*` vectors come from the
probe's host as an application with an app frame (side layout, a link for administrators). Python (`TopbarFrame`), Go,
Rust, JavaScript and PHP read it into their typed form.

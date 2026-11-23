---
id: T-113
type: Task
title: "Topbar fetch in the Rust and PHP clients"
status: offen
milestone: M-2
tags: [clients, topbar]
created: 2026-11-23
---
# T-113 — Topbar fetch in the Rust and PHP clients

**Story points:** 3 · **Estimate:** 4–6 h (not measured) · **Milestone:** [M-2](M-2-after-1-0.md)

Rest of the client helpers of [T-89](T-89-approvals-confirm-one-sensitive-action-with-a-step.md) and
[T-93](T-93-follow-ups-to-0-29-0-kid-rule-proxy-duty-key-purposes.md): Go, JS/TS and Python can fetch the topbar data
(`/.tinysesam/topbar.json`, spec §8) for a server-side render; Rust and PHP only normalize a document the application
fetched itself.

## Content
- `FetchTopbar` equivalent in Rust (behind the `jwks`/HTTP feature, like `AccountFetcher`) and PHP (`Topbar::fetch`),
  same limits as the account fetch: only TinySesam's cookies, 5 s, 64 KiB, anything but `200` is "no bar".
- The browser way stays the recommendation (spec §8); the docs of both clients say so.

## Acceptance
- Every topbar vector passes in Rust and PHP through the fetch path; mutation per limit (cookie filter, size, time).

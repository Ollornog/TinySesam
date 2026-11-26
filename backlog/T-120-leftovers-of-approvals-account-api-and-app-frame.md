---
id: T-120
type: Task
title: "On demand: leftovers of approvals, account API and app frame"
status: offen
points: 3
milestone: M-5
tags: [approvals, provisioning, frame, on-demand]
created: 2026-11-23
---
# T-120 — On demand: leftovers of approvals, account API and app frame

**Story points:** 3 (a collection; each leftover becomes its own entry with its own estimate when an application asks) · **Milestone:** [M-5](M-5-after-1-0.md)

Collected from [T-89](T-89-approvals-confirm-one-sensitive-action-with-a-step.md),
[T-90](T-90-account-api-for-applications-stage-a-create-read-u.md) and
[T-91](T-91-app-frame-and-account-overview.md), closed with their core done. Nothing here is planned until an
application asks for it.

- Approvals: optional `POST /auth/api/approvals/{id}/executed` (audit only); `Idempotency-Key` for requests; a CLI
  import of an application's type snippet.
- Account API: `require_approval` per action (stage C), joining existing accounts with their consent; the holder's
  account page names the application as the origin of a link or lock ("by Example").
- App frame: `current` for the wrapper path (the gate token carries no session reference; needs a spec change).
- Ending a single session or program from the application moved to
  [T-105](T-105-stage-s9-headless-writing-action-pages-with-a-way-back.md) (session handle, stage S9).

Each item becomes its own entry when it is picked up.

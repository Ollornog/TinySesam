---
id: T-77
type: Task
title: 'Admin panel: extra tabs that link to the application''s own administration'
status: offen
milestone: M-2
tags: [proposal, admin, ui]
created: '2026-11-21'
---
# T-77 — extra tabs in the admin panel

**Status: proposal.** The maintainer sets the priority; nothing is decided.

Source: a deployment where the application has administration pages of its own; administrators switch between the
panel and those pages by hand.

## What it would mean

- `admin_tabs=[("Projects", "/admin/projects"), …]`: extra tabs in the admin panel that are plain links to the
  application's own administration — on the own origin or a host from `trusted_redirect_hosts`, checked like
  `topbar_links`.
- No embedding (no iframe): the link opens the application's page, which checks access itself.

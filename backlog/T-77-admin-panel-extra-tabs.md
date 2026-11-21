---
id: T-77
type: Task
title: 'Admin panel: extra tabs that link to the application''s own administration'
status: verworfen
milestone: M-2
tags: [admin, ui]
created: '2026-11-21'
---
# T-77 — extra tabs in the admin panel

**Rejected (2026-11-21, product owner).** No extra tabs as a configuration field: the panel stays TinySesam's own, and
another field would be one more surface to check and keep. Instead the two administrations link to each other — the
top bar link visible to administrators or one role only (T-76) and a link back from the application's admin page.
The recipe is in the README ("Recipe: link your app's admin from TinySesam — and back") and runs as
`examples/app_admin.py`; applications not drawn in Python take the bar as data (`auth.topbar_data`,
`/auth/topbar.json`, `/.tinysesam/topbar.json`).

The original proposal, kept for the record:

Source: a deployment where the application has administration pages of its own; administrators switch between the
panel and those pages by hand.

## What it would mean

- `admin_tabs=[("Projects", "/admin/projects"), …]`: extra tabs in the admin panel that are plain links to the
  application's own administration — on the own origin or a host from `trusted_redirect_hosts`, checked like
  `topbar_links`.
- No embedding (no iframe): the link opens the application's page, which checks access itself.

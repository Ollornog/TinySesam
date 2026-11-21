---
id: T-76
type: Task
title: 'Top bar: visibility per link and own entries in the account menu'
status: offen
milestone: M-2
tags: [proposal, topbar, ui]
created: '2026-11-21'
---
# T-76 — top bar link visibility

**Status: proposal.** The maintainer sets the priority; nothing is decided.

Source: a deployment whose top bar links lead to areas that only administrators or one role can open; everyone else
sees links that end in "access denied".

## What it would mean

- `topbar_links` entries with an optional visibility: `("Admin", "/admin", {"admin": True})`,
  `("Reports", "/reports", {"role": "editors"})`. Without it, the link is shown to everyone, as today.
- Optionally own entries in the account menu of the top bar (next to account, admin panel, theme, sign out).
- Visibility is a convenience, not a protection: the target checks access itself.

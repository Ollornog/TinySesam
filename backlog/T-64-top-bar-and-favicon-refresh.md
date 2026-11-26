---
id: T-64
type: Task
title: 'Top bar and favicon refresh: logo, name, links, account menu, light/dark, phone'
status: erledigt
milestone: M-5
tags: [ui, theme, accessibility]
created: '2026-11-20'
---
# T-64 — Top bar and favicon refresh

Source: PO wish 2026-11-20 — favicon and title bar should look newer: account, dropdown, light/dark, sign-out, admin;
clean, minimal; on the left always the application logo, next to it the name, then the links; phone support.

**Done:**

- One top bar (`tinysesam/topbar.py`) for account page, admin panel, setup/reauth/consent/QR-approval/gateway pages;
  sign-in and error pages show logo and name only. Account menu as a disclosure (`aria-expanded`, Escape, outside
  click), admin entry only for admins, sign-out as a POST with CSRF, Light/Dark/System with `aria-pressed` and a
  check mark (never colour alone). Below 640 px the links move into the menu, tap targets ≥ 44 px.
- Light and dark for the default tokens, switched like C22 (class `dark`, `localStorage.themeMode`), restored in
  `<head>` before the first paint; defaults in the cascade layer `tinysesam` so `brand_css` keeps winning.
- Logo = `brand_icon` (own origin / `data:image`), else a built-in mark — no separate `brand_logo` field: one asset
  serves tab and bar, and an app that needs a wordmark replaces the bar via `topbar_enabled=False` + `brand_header`.
- Links: `topbar_links`, checked like `next=` targets (own paths, https on `base_url`/`trusted_redirect_hosts`).
- For apps: `auth.topbar_head()` + `auth.topbar(request)`.
- New favicon: tile with a keyhole, light/dark via `prefers-color-scheme`.

**Left open:** the showcase/website keeps its own shell (`topbar_enabled=False` in `web/demo.py`) with its own
light/dark key (`ts-theme`, `data-theme`); moving it onto the bar and C22's switch is a follow-up.

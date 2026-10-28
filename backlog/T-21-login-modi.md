---
id: T-21
type: Task
title: "Login mode per app: invisible (gateway default) or window"
status: erledigt
milestone: M-3
tags: [gateway, oidc, login]
created: 2026-10-03
---

# T-21 — Login modes

Today the gate sends to the TinySesam login page on 401, where the OIDC button is
(`/auth/oidc/start?next=…`). That is the mode `fenster` (window) without any reference to the app.

**To do:**
- `unsichtbar` (invisible): the login URL of the gate points directly to `/auth/oidc/start?next=<start address>` (or the
  client of the app, T-14). **Default in the gateway preset** (PO 2026-10-03); in the library the
  default stays the login page. Only permitted if OIDC is the only method.
- `fenster` (window): login page with the name and icon of the app ("Sign in to *App X*"), appearance via the theme.
- Configurable per app (`oidc_clients` entry / gateway variable).
- An error case at the provider (refusal, group missing) must not run into a redirect loop:
  visible error page.

**Done when:** browser test of both modes, loop test on refusal, docs EN/DE, mutation.

## Done 2026-10-07

The values are named in English (rule of stages A/B): `forward_login = "page" | "direct"`, per host in
`forward_apps` (`name`, `login`) instead of in the entry of `oidc_clients` — the setting also applies to
an installation with only one client.

- `direct` only for **page requests** (`Sec-Fetch-Mode: navigate`, otherwise `Accept: text/html`); every
  other request goes to the login page. Without that, every XHR of an expired session would have started
  its own OIDC flow (database row, rate limit of `/auth/oidc/start`).
- `direct` only with OIDC as the only method — checked at startup and once more at runtime.
- Refusal by the provider: the callback answers with an error page, not with a redirect —
  no loop.
- **Icon** of the application on the login page: not built. It would need an image file that TinySesam
  delivers itself (no foreign source) — open as a wish, not a task.
- Found and fixed during the build: [B-2](B-2-schleife-ohne-app-freigabe.md).
- Test: `tests/test_login_modi.py`, 9 mutations red.

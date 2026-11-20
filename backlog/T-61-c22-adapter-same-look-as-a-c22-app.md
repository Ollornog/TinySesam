---
id: T-61
type: Task
title: 'C22 adapter: the built-in pages in the look of an app built on C22'
status: erledigt
milestone: M-2
tags: [ui, theme]
created: '2026-11-20'
---
# T-61 — C22 adapter: the built-in pages in the look of an app built on C22

**Goal:** an app that uses the C22 design system as its shell shows login, account page, admin panel and error
pages in the same look — and a C22 theme change (pack, light/dark) carries over. TinySesam keeps working without
C22: no package dependency, no C22 JavaScript on the auth pages, strict CSP unchanged.

**Done:**
- `tinysesam/c22.css` — pure CSS, one entry per `--ts-*` token: `var(<C22 token>, <TinySesam default>)`. Derived
  values (tinted message boxes, link colour) go through `--ts-c22-*` helpers without a fallback, so without C22 they
  drop out and the default applies.
- New field `c22_stylesheet` (a same-origin path, checked by `config_check`): the pages load the app's C22
  stylesheet (with the response nonce), inline the adapter between the tokens and `brand_css`, and restore
  light/dark the way C22 does (`localStorage.themeMode`, else the system setting; class `dark` on `<html>`).
- `<link rel=stylesheet>` gets the response nonce like `<script>`/`<style>` — under the strict CSP a same-origin
  stylesheet in `brand_head` did not load before.
- New tokens `--ts-danger-ink`, `--ts-success-ink` (default `#fff`, so nothing changes without the adapter): C22's
  destructive colour is light in dark mode and needs dark text.
- Test `tests/test_c22_adapter.py`: completeness, fallbacks equal the defaults, every C22 name in the pinned list
  `tests/fixtures/c22_tokens.txt` (refresh: `tools/c22_tokens.py`), wiring, CSP, and in a browser: adapter without C22
  computes every token exactly as without it.

**Not mapped (no C22 counterpart):** the five `--ts-image-*` tokens of the background images keep TinySesam's values.

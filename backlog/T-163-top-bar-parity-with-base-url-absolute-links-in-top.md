---
type: Task
title: 'Top bar parity with base_url: absolute links in topbar.json, paths in topbar()'
status: offen
points: 2
id: T-163
milestone: M-5
created: '2026-11-28'
---
# T-163 — Top bar parity with base_url: absolute links in topbar.json, paths in topbar()

**Story points:** 2

Found by T-107: with base_url set, the shell component (/auth/shell.js drawing /auth/topbar.json) names the account page as an absolute address while auth.topbar() names the path; tests/test_shell_browser.py A1 compares both only without base_url. Decide whether the difference is intended (topbar.json is read from other origins too) and either document it in spec section 8d and the README or align the library's markup; extend A1 to a configuration with base_url. Acceptance: A1 green with and without base_url, or the difference named in the docs and asserted.

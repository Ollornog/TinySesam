---
type: Task
title: Browser coverage of the remaining action pages in Ex4
status: offen
points: 3
id: T-149
milestone: M-2
created: '2026-11-28'
---
# T-149 — Browser coverage of the remaining action pages in Ex4

**Story points:** 3

`tests/test_headless_browser.py` drives password, API key and sessions through action pages. TOTP, PIN, passkey, address, name, recovery codes, app passwords and services are covered by the Python tests only. Drive each through Ex4 and back, three runs in a row green.

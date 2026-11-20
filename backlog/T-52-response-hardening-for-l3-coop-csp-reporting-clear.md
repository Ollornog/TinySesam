---
id: T-52
type: Task
title: 'Response hardening for L3: COOP, CSP reporting, Clear-Site-Data, textContent, /healthz version'
status: offen
milestone: M-2
tags: [security, headers, asvs]
created: '2026-11-20'
---
# T-52 — Response hardening for L3: COOP, CSP reporting, Clear-Site-Data, textContent, /healthz version

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), findings N8 and M2 (part) — ASVS 3.4.7, 3.4.8, 14.3.1, 3.2.2, 13.4.6.

**Is:** no `Cross-Origin-Opener-Policy`, no CSP report endpoint, no `Clear-Site-Data` on sign-out (TinySesam stores
nothing in browser storage — rather ➖); app JS writes via `innerHTML` with own escaping (`templates.py:681-699`,
`admin.py:715-794`); `/healthz` names the version without sign-in (`gateway.py`) — `scripts/_image_probe.sh` relies on it.

**Proposal:** COOP `same-origin` on own pages; optional `report-to`; `textContent` where possible; version in `/healthz`
only behind a switch, with the image probe reading it differently. Effort S.

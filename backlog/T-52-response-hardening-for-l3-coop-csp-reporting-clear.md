---
id: T-52
type: Task
title: 'Response hardening for L3: COOP, CSP reporting, Clear-Site-Data, textContent, /healthz version'
status: erledigt
milestone: M-5
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

## Done (2026-11-21)

- **COOP** `same-origin` on every HTML response while `csp='strict'` (like `X-Frame-Options`); not on JSON, not with
  an own policy or `off`. No built-in flow uses a popup — OIDC, SAML and the gate redirect in the same tab.
- **CSP reporting** without third parties: `csp_report` (off by default) adds `report-uri`/`report-to` for the own
  endpoint `POST /auth/csp-report` and `Reporting-Endpoints`; one filtered line per report in `tinysesam.security`
  (page path without query, only origin/keyword of the blocked resource), 10 reports/min per IP, 60 lines/min in
  total, 8 KiB per body. The policy itself is unchanged.
- **Clear-Site-Data** `"cache"` from `auth.logout()` — not `"storage"`/`"cookies"` (app data, theme choice, sibling
  apps under the registrable domain).
- **`/healthz` without the version**; `TINYSESAM_HEALTH_VERSION=1` brings it back; `scripts/_image_probe.sh` reads the
  version from the package in the image.
- **`textContent`: not done, on purpose.** The `innerHTML` sites render markup (rows with buttons, badges) and every
  API value goes through `esc`/`esc0` (R8-6); the strict nonce CSP blocks script and inline style even if an escape
  were missed. Rebuilding the admin panel and the account lists on DOM calls is a refactor of its own with UI risk and
  little gain over that; the stronger follow-up would be Trusted Types (`require-trusted-types-for 'script'`), which
  needs a policy for every sink — a separate task if wanted.

Tests: `tests/test_response_hardening.py`, `tests/test_gateway.py` (`/healthz`).

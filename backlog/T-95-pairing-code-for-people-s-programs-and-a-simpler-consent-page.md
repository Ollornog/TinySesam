---
type: Task
title: Pairing code for people's programs (consent given in advance) and a consent page for laypeople
status: erledigt
id: T-95
milestone: M-2
tags: [oauth, mcp, consent, pairing, laypeople]
created: '2026-11-23'
---
# T-95 — Pairing code for people's programs, simpler consent page

Laypeople set up an MCP client (Claude Code: `claude mcp add`, `claude mcp login`) against TinySesam's OAuth server
(ADR-11) and should not have to understand a consent page. Decision and threat model:
[ADR-14](ADR-14-pairing-code-as-consent-given-in-advance.md) (PO 2026-11-23: pairing code, only the account itself,
the page again on re-login, the page simplified).

## Done

- [x] `oauth_pairing_consent_enabled` (default off), `oauth_pairing_consent_minutes` (15, 1–60); `config_check` refuses
      the switch without `oauth_enabled`.
- [x] `POST /auth/oauth/pairing` (own fresh session, CSRF; optional `resource`) → `{code, expires_at, resource,
      redeem_url, issuer}`; one open code per account, 10 per hour.
- [x] `POST /auth/oauth/pairing/redeem {code}` without a session, atomic, generic answer, 20 per address and hour,
      fail2ban line per failure, the code never logged.
- [x] The consent page spends the armed consent for exactly one authorization: same account, `Sec-Fetch-Site: none`
      at `/authorize` (measured in headed Chrome 158 and Firefox 160, see ADR-14), loopback redirect, person's client,
      matching resource, within the window — after the sign-in and freshness checks. Nothing else spends it.
- [x] Schema 26: `consent_via` on `oauth_code` and `oauth_grant`; audit `via=pairing fetch_site=…`, security event
      `via`, account page and panel "via pairing code".
- [x] Account page section "Connect a program" (code in the own dialog, shown once).
- [x] Consent page for laypeople: one sentence with the application's name in its app frame (T-91), one large
      "Allow", details folded; en/de.
- [x] Tests: `tests/test_oauth_pairing.py` (rules and attacks A-1…A-6, switch, schema), freshness guard, browser test
      (account page → code → redemption → straight back to the program; consent page light/dark at 390 px).
- [x] Return to the program by a page with meta refresh, not a `303` (a sign-in form earlier in the chain would stop
      the redirect by its `form-action` — found with the real Claude Code).
- [x] `tools/oauth-e2e/e2e.py` steps 7 and 8 with the real Claude Code CLI.
- [x] Docs: README / `i18n/README.de.md` recipe with setup scripts (bash, PowerShell), SECURITY, OPERATIONS (schema 26),
      skill, CHANGELOG.

## Open

- [ ] Measure `Sec-Fetch-Site` on macOS (`open`) and Windows (`start`).
- [ ] A per-application logo in the app frame (`forward_apps[host]` has a name, no logo yet).

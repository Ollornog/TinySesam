---
id: ADR-14
type: Decision
title: A pairing code is a consent given in advance — one authorization of the account without the consent page, amends ADR-11
status: erledigt
tags: [architecture, oauth, mcp, consent, pairing]
created: 2026-11-23
---

# ADR-14 — Pairing code: the consent given in advance

Amends [ADR-11](ADR-11-oauth-authorization-server-in-tinysesam.md) "Consent: always for these clients". Task:
[T-95](T-95-pairing-code-for-people-s-programs-and-a-simpler-consent-page.md).

## Context

A person without technical knowledge sets up an MCP client (Claude Code: `claude mcp add`, then `claude mcp login`)
against TinySesam's OAuth server. The browser opens, the person is signed in — and then has to understand a consent
page and press "Allow". The application around it already asked the person, in its own words, whether the program may
connect: the second question is the one laypeople stumble over. The connection must stay OAuth (PKCE, rotation, revoke
per device); no long-lived key may land on the computer.

Claude Code 2.1.330 sends `prompt=consent`, `scope=mcp offline_access`, `resource=<MCP URL>`, `redirect_uri
http://localhost:<port>/callback`, PKCE S256, and registers itself dynamically (RFC 7591) on every login.

## What the consent page protects against (and what it is worth today)

| Threat | Today | With the pairing code |
|---|---|---|
| A website starts an authorization through the victim's browser (consent phishing) | the code goes to the victim's loopback, the site cannot read it; without a click nothing is issued | the site's navigation carries `Sec-Fetch-Site: cross-site` through the whole redirect chain: it neither uses nor spends the armed consent |
| A local process starts its own authorization (RFC 8252 §8.6) | the person sees an unexpected request | **open within the window**: the first matching authorization of the account gets the code. Residual risk, below |
| The client's name is a claim (RFC 7591 §5) | shown as "not verified" | the consent was given on TinySesam's own page in the own session, not to a name |
| Clickjacking (RFC 9700 §4.16) | `frame-ancestors 'none'` | unchanged for the page; the code itself is fetched by a JSON route with CSRF and a fresh session |
| Freshness (B-12) | the page asks for a fresh confirmation | unchanged: issuing the code needs a fresh session, and the authorization that spends it passes the same freshness check as the page |
| Later non-loopback clients | none today | the pairing never covers a redirect that leaves the computer (rule with a test) |

## Options

1. **Prepared connection with a fixed `client_id`** (the draft's recommendation): TinySesam creates the client, the
   person types `claude mcp add --client-id …`. Narrower binding, no redemption step — but it depends on Claude Code
   honouring `--client-id` without a secret (reported broken in 2.1.172 and 2.1.178, unmeasured since) and puts a
   command with an ID in front of a layperson.
2. **Pairing code** (PO choice): the application or account page fetches a one-time code in the person's session, a
   setup script redeems it right before `claude mcp login`, and the next matching authorization goes through. Works
   with every dynamically registering client as it is, no client option needed.
3. **Remember the consent per (account, client software, resource)**: refused — the software can only be recognised by
   the name it claims, and RFC 8252 §8.6 asks to treat an unproven client as never approved.
4. **Trusted first-party clients (CIMD, `software_id`)**: refused — the identifier is public, every local process could
   use it for ever.
5. **Service pairing** (ADR-13): refused as the way — it leaves a long-lived private key on the computer, and Claude
   Code speaks no `client_credentials` for MCP. Its building blocks are reused (code format, digest, single use).

## Decision

**Option 2** (PO 2026-11-23), with every narrowing of the draft that does not change the flow:

- **Issuing** only by the account itself, from its own browser session with a fresh confirmation
  (`_require_fresh`, CSRF): `POST /auth/oauth/pairing` (account page "Connect a program", or the application in the
  browser on the same origin). No API key, no access token, no administrator, no "on behalf of" through the account
  API — a code is a consent, and only the person can give it. One open code per account (a new one replaces it), at
  most 10 per hour.
- **The code:** 16 characters from 32 (80 bits, the service pairing format), only its SHA-256 digest is stored
  (`magic_token`, purpose `oauth_consent_pairing`), never logged, valid `oauth_pairing_consent_minutes` (default 15,
  1–60) from issuing, bound to the account and optionally to one resource of `oauth_resources`.
- **Redeeming** without a session (the script has none): `POST /auth/oauth/pairing/redeem {code}`, JSON only. Atomic
  (`UPDATE … WHERE purpose='oauth_consent_pairing'`): one redemption wins, the second gets the same answer as an unknown
  code. 20 attempts per address (IPv6 /64) and 100 per /48 and hour; every failure is a security-log line for fail2ban.
  It arms the consent (`oauth_consent_armed`) for the rest of the window.
- **Spending:** the consent page, after the sign-in and the freshness check it always had, spends the armed consent for
  exactly one authorization request when **all** hold — otherwise it shows the page and spends nothing:
  - the account signed in in this browser is the code's account;
  - the request was opened by the person's browser itself: `Sec-Fetch-Site: none` at `/authorize`, stored with the
    request (the sign-in and reauth round trips in between are same-origin);
  - the redirect URI is a loopback address;
  - the client is a person's client (dynamically registered), not a service;
  - the resource is the code's resource, if the code names one;
  - still within the window.
  The spending is atomic; a request that does not match leaves the consent for the right one. The answer to the client
  (code, `state`, `iss`) is the one the page would have produced, handed over by a short return page with a meta
  refresh and a link — not a `303`: when the person was not signed in yet, the chain starts at the sign-in or reauth
  FORM, and Chrome checks every redirect after a form submission against that page's `form-action`, which names no
  loopback address. Measured with the real Claude Code: the `303` ended on `chrome-error`, the return page reaches the
  callback (browser test and `tools/oauth-e2e/` step 7 pin it). The code, the grant and the device list carry
  `consent_via='pairing'` (schema 26); the audit says `oauth_consent … via=pairing fetch_site=none`, the security event
  `oauth_device_connected` carries `via: "pairing"`.
- **`prompt=consent`** from the client is overruled in exactly this one case: the pairing code IS the consent, given a
  few minutes earlier on TinySesam's page. TinySesam treats `prompt` as advisory everywhere else as well (it never
  answers `prompt=none` silently without a consent).
- **Afterwards** — a second login, expiry of the connection, `claude mcp logout` — the consent page asks again. It is
  simplified for laypeople (the draft's option e): one sentence with the application's name (`forward_apps[host].name`,
  in the app frame of T-91), one large "Allow", program, `client_id`, redirect host, scope and duration folded into
  `<details>`.
- **Off by default** (`oauth_pairing_consent_enabled`); `config_check` refuses it without `oauth_enabled`. Switched
  off, both routes are `404` and an armed row from before skips nothing.

### Measured: `Sec-Fetch-Site` when a program opens the browser

On Linux Mint 22.3 (X11), 2026-11-23, a local server logging the request headers:

| Browser | How opened | `/authorize` | after a 303 to the same origin |
|---|---|---|---|
| Chrome 158 (own profile, headed) | started with the URL (the `.desktop` `Exec` line `xdg-open` uses) | `none`, `?1` | `none` |
| Chrome 158 | URL handed to the running instance | `none` | `none` |
| Chrome 158 (the default browser) | `xdg-open <url>` into the running browser | `none` | `none` |
| Chrome 158 | script navigation from a page on another site | `cross-site` | `cross-site` |
| Firefox 160 (own profile, headed) | started with the URL / handed to the running instance | `none` | `none` |
| Firefox 160 | script navigation from a page on another site | `cross-site` | `cross-site` |

So the rule is a requirement, not only an audit field. A browser that sends no `Sec-Fetch-Site` (before Chrome 76,
Firefox 90, Safari 16.4) gets the consent page — fail-safe. Not measured: macOS `open` and Windows `start`; Claude Code
opens the browser through the `open` package, which calls exactly these.

## Residual risk

- **A local process within the window:** whoever runs as the person on the computer and starts an authorization
  (opening the person's browser, which sends `none`) before Claude Code does gets the code instead. That is
  malware level; such a process can also read Claude Code's stored tokens and the person's browser profile. The window
  is short (15 minutes, at most 60), the pairing works once, and the person sees the connection in "Connected programs"
  ("via pairing code") and in the security notice of `oauth_device_connected`.
- **A leaked code** (script output, shared screen): it arms only the consent of the account that fetched it, spendable
  only in that person's browser with that person's session. The worst case is a spent consent — the real program then
  lands on the page, and the script's redemption answers "unknown, used or expired".
- **A website in the window** can neither use nor spend the consent (`cross-site`); it can still start an
  authorization that shows the page — as before.

## Consequences

- One additive schema step (26: `consent_via` on `oauth_code` and `oauth_grant`); older versions ignore it.
- The code helpers moved from `oauth_services` to `oauth` (one format, one digest for both kinds of pairing).
- The end-to-end check with the real Claude Code stays manual: `tools/oauth-e2e/e2e.py` steps 7 (pairing code → login
  without the page) and 8 (after `mcp logout` the page again). The browser test drives the account page, the
  redemption and the return to the program in headless Chrome, signed in and through the sign-in form.

---
id: T-72
type: Task
title: Pepper for the remaining token digests, then drop the session-handle rewrite
status: offen
milestone: M-5
blocked_by: [T-111]
tags: [security, keys, api-keys]
created: '2026-11-21'
---
# T-72 — pepper for the remaining token digests

Source: [T-71](T-71-session-handles-keyed-with-the-pepper.md). After T-71 these digests are still a plain sha256, so
write access to the database file alone still mints access:

- `api_key.key_hash` — an inserted row is a working automation key of any account;
- `magic_token.token_hash` — sign-in links, invitations, address confirmations (`TinySesam._token_hash`) and the
  service pairing codes (`oauth_services.code_digest`);
- the QR sign-in approvals (`_token_hash("qr:" + code)` and the device secret).

## To do

- Key them with the pepper keyring like the app passwords (label per kind, `kid` or lookup over the keyring), with a
  migration that keeps valid keys and links working (HMAC over the stored sha256, as in T-71) and a `keys retire`
  check for what still needs a previous pepper.
- In the same release remove the session-handle rewrite of T-71 (`Store.pepper_session_handles`): once no plain digest
  is accepted anywhere, a rewrite that a deleted marker can trigger again is the last way in for a writer. Installations
  that skipped the release in between sign in again once — say so in the CHANGELOG.

## Greenfield (maintainer, 2026-11-23)

Moved to [M-5](M-5-clean-baseline-and-modules-before-shell-and-headless.md). With the schema baseline
([T-111](T-111-schema-baseline-and-ballast-removal-the-current-state-is.md)) there is no old data to carry: no
migration that keeps valid keys and links — existing API keys, sign-in links and QR approvals stop working once and
the CHANGELOG says so. The removal of the session-handle rewrite belongs to T-111.

---
id: T-71
type: Task
title: Session handles keyed with the pepper instead of a plain sha256
status: erledigt
milestone: M-5
tags: [security, sessions, keys]
created: '2026-11-21'
---
# T-71 — session handles keyed with the pepper

Source: [T-69](T-69-attack-round-a-oauth-services-app-passwords-keys.md), "not done here". A session row stored the
plain sha256 of the cookie. Whoever could **write** the database file (a backup put back, a shared volume, an injection
elsewhere) inserted the sha256 of a token of their own choosing and held a session of any account — without any key.

## Done

- The handle is `HMAC-SHA-256(pepper, label ‖ sha256(token))` with the pepper keyring of
  [ADR-12](ADR-12-key-purposes-keyrings-and-rotation.md) (`oauth-pepper`, never readable from the file alone). The same
  digest covers the app-host links (`gate_link.link_hash`) and the area unlocks (`resource_unlock.token`).
- **Nobody is signed out.** Because the HMAC runs over the old sha256, the first start rewrites every stored handle and
  every column that names one (`Store.SESSION_HANDLE_COLUMNS`) without knowing a token, in one transaction with the
  marker `setting.session_handles = hmac-v1`.
- Pepper rotation: a handle keeps the pepper it was made with until its session ends; the lookup takes the candidate
  that exists. `tinysesam keys retire --purpose oauth-pepper` refuses while a session or app-host link from before the
  rotation runs.
- A store without the pepper refuses to digest a session token instead of falling back to sha256.
- Tests: `tests/test_session_pepper.py` (planted row, a database of 0.26.0 with all hanging rows, rotation and retire,
  no fallback), six mutations each red.

## Known limit of the transition

The rewrite runs whenever the marker is missing. Whoever can write the file could delete the marker, plant a plain
sha256 row and wait for a restart — the same reach as the digests that are still unpeppered (API keys, sign-in links,
QR approvals). Both go together in [T-72](T-72-pepper-for-the-remaining-token-digests.md).

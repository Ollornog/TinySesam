---
id: T-17
type: Task
title: Do not write the first-admin one-time token to the container log
status: erledigt
milestone: M-2
tags: [sicherheit, erst-admin, container, betrieb, log]
created: 2026-09-27
---

# T-17 — Claim token: in a container, stderr is the log

**Finding from operation (2026-09-27, start in a container without an admin):** TinySesam wrote the
claim URL with the one-time token to stderr and directly after it the line "The value is deliberately NOT
in the log". In a container stderr IS the log (`docker logs`, every log shipping) — so the value stood
exactly there, two lines above the assurance. `admin_claim_token_file` would have prevented it, but
nothing pointed to it, and the default hit the most common operation.

**Done when:** without `admin_claim_token_file` and without a console (`sys.stderr.isatty()` false)
the token sits in a file with `0600` next to the database and stderr/the log only
name the path; the text says honestly where the token is (also in the fallback to stderr with `:memory:` or
a file that cannot be created); the same for the output at the moment of an IdP revocation (G6); the
file disappears after redemption or is invalid after expiry; tests for console and
no console, permissions, no token in the log text; mutation.

## Done 2026-09-27

- `TinySesam._admin_claim_bekanntgeben`: console → stderr as before; no console →
  `<db_path>.claim` (0600, opened without `O_TRUNC`, permissions set on the descriptor, then
  truncated — the same route as for `admin_claim_token_file`), only the path in the log. Fallback
  to stderr without a database file or if the file is not created, then with the sentence that the
  value is in the service's log. `admin_claim_token_file` takes precedence, even at a console.
- Cleanup: `_consume_admin_claim` deletes `<db_path>.claim` after redemption; a start with an
  admin removes a leftover. After expiry the content no longer counts, the next start
  writes a new token. A self-chosen file stays in place (content invalid).
- The output after an IdP revocation (G6) goes through the same method.
- Tests: `tests/test_betriebsfunde.py` (b) — console and container (stderr and security log in
  one buffer, like `docker logs`), permissions 0600, redemption from the file, cleanup, expiry,
  `:memory:`, file that cannot be created, own file at the console. Adapted:
  `tests/test_security_log.py` (console explicitly), `tests/test_t13_entscheide.py` (G6 without
  console: file). Docs: README EN/DE, `docs/BETRIEB.md` ("First-admin one-time token"),
  `KONFIGURATION.md`, fail2ban jail, CHANGELOG.

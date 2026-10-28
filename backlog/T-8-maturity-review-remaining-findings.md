---
id: T-8
type: Task
title: Work through the 35 maturity-review findings that were not reproduced individually
status: erledigt
milestone: M-1
tags: [sicherheit, betrieb, paket, api, doku]
created: 2026-09-21
---

# T-8 — the 35 remaining maturity-review findings

The maturity review of 2026-09-21 (four independent perspectives) found **47 findings**. 12 were
reproduced individually and are done — the six security holes including tests, the core install,
the blind test run. The remaining **35 are reported but not verified**: they come from the
reviewers' reports, not from a reproduction attempt of our own.

**That is the difference that matters.** A reported finding is a claim. Every item here is
therefore first checked against the code and then decided: confirmed → fix with a test;
refuted → strike here with a reason; matter of taste → ADR. No item is reworked "because it is
listed".

**Done when** every item carries one of these three marks and the confirmed ones are fixed.

## Status: worked through (2026-09-21)

**35 fixed, 1 handed over to [M-1](M-1-api-stable-1-0.md) as a product decision.** Every item was
first checked against the code. Three findings went further than reported (the file copy of the
database did not even contain the table `users`; a display name like "Иван" broke forward auth with
a 500, without any attacker; the app lockout blinded fail2ban). Two refuted themselves on
measurement:

* **"API keys survive deactivation"** — they do not. `verify_api_key` checks the flag; the first
  measurement was wrong because the method returns `(user, roles)` and a non-empty tuple is always
  truthy.
* **"`resource_locks_enabled` needs `pin_enabled`"** — a check built from this was a false alarm,
  which a suite of its own refuted immediately: a locked resource is unlocked with its own secret,
  not with the login PIN.

[M-1](M-1-api-stable-1-0.md) stays open — but now for a named reason and not because of a pile of
unverified reports.

## Security and hardening

- [x] The admin panel hands out the session tokens of all users in plain text
- [x] Session tokens are stored in plain text in the database — fixed: the sha256 is stored,
      existing sign-ins were migrated
- [x] Recovery codes carry only 48 bits — fixed: 64 bits, existing ones stay valid
- [x] The database is created world-readable (0644)
- [x] API keys survive password change and "end all sessions"
- [x] The `trusted_proxies` default is forgery-proof, but breaks behind a container proxy
      — fixed: `client_ip()` reports the misconfiguration once per peer
- [x] The shipped compose example makes every client IP the proxy IP — fixed: own network with a
      fixed subnet instead of `0.0.0.0/0`, plus a check
- [x] SSO and passkey logins write the proxy IP instead of the client IP — fixed: both use
      `client_ip()`
- [x] Forward auth: header *names* are checked, header *values* are not — fixed; in the process it
      turned out that a name like "Иван" broke forward auth with a 500, without any attacker
- [x] OIDC: the JWKS is fetched once and never refreshed — fixed: lifetime + one throttled
      re-fetch on signature error (`tests/test_oidc_jwks.py`)
- [x] There is no configuration check — fixed: `config_check.py` reports all contradictions
      together at construction; errors abort, repairable things warn

The CSRF rotation of the admin panel is already recorded as [B-1](B-1-admin-panel-rotates-csrf.md).

## Operations, protocol, data storage

- [x] A naive backup of the database yields an EMPTY database (WAL)
- [x] `_migrate()` only upgrades `session` columns — fixed: `PRAGMA user_version`, and
      a file from a newer version speaks up
- [x] Cleanup never runs by itself, and the gateway image has no way to trigger it
      — fixed: `tinysesam gc --db …` for cron/timer
- [x] After the first log rotation TinySesam writes to the renamed file — the fail2ban jail
      then runs blind — fixed: `WatchedFileHandler`
- [x] The security log names no reason and is silent on lockout — fixed: rejections
      report with `reason=`, in the format of the existing filter (so the rule did match after all,
      the lines were missing)
- [x] Admin actions are logged without actor and without IP

## Package and installation

- [x] `python -m tinysesam.gateway` does not run after the documented pip install — fixed:
      extra `[gateway]`, understandable message, docs and Dockerfile updated
- [x] `--help` on the gateway started a server on `0.0.0.0:8000` — fixed: help and
      exit 0; an unknown argument ends with 2
- [x] The classifiers promise Python 3.11 and 3.13, CI runs neither
      — fixed: matrix on all five, plus hygiene check classifier ↔ matrix
- [x] The sdist contains no tests — fixed: `graft tests`, in the unpacked sdist
      40/44 green with 4 clean skips; `examples/` and `deploy/` are included
- [x] SECURITY.md names 0.5.x as the series that gets security fixes — fixed: now refers
      to the CHANGELOG head instead of a number
- [x] A missing extra shows up as a 500 or not at all — fixed: one guard for all
      four methods, `MissingExtra` with a machine-readable `extra` field

## The API contract

- [x] `Typing :: Typed` and `py.typed` are a promise that was never checked — fixed:
      30 type errors cleaned up, mypy in CI and image, `tests/test_types.py`
- [x] `check_password` & co. are annotated as `Optional[dict]` but return `sqlite3.Row`
      — fixed: they now return dicts
- [x] There are no error types a user can react to — fixed: `tinysesam/errors.py`
- [x] `complete_mfa` calls itself "backwards-compatible name" in its own docstring — fixed:
      `complete_totp` is the clear name, `complete_mfa` stays as an alias
- [~] The public surface was measured, not decided — **made visible**:
      each of the 105 methods has a docstring, `API.md` lists them. The selection itself
      is a product decision and is in [M-1](M-1-api-stable-1-0.md)
- [x] The API guard freezes less than "231 names" suggests — fixed: defaults
      of the config fields and return types are now captured too
- [x] `set_template` names two page names in its docstring that do not exist — fixed:
      `TinySesam.SEITEN`, an unknown name raises, check against `render_page`

## Docs, website, language

- [x] 31 hard-coded German error texts in HTTP responses — fixed: 35 messages via `api.*`
      bilingual, a hygiene check forbids fixed text in `HTTPException`
      (reported three times in the review, counts as one finding)
- [x] `totp_required` is a dead switch — fixed: it is rejected, the docs name `login_chain`
- [x] Both READMEs advertise an update button that deliberately has not existed since 0.12.0 — fixed
- [x] No complete configuration reference — fixed: `CONFIGURATION.md`, generated,
      all 119 fields explained, with a check
- [x] The PyPI project page shows a broken logo and seven dead links — fixed
- [x] The README becomes the PyPI description but contains seven relative references — fixed:
      absolute URLs, plus a check in `test_repo.py`

## Provenance

The evidence for the reproduced findings is in `.befunde-2026-09-21/` (not checked in).
The titles here are the short version from the review report; the long versions went away with
the review agents. Where a title is terse, the code decides anyway.

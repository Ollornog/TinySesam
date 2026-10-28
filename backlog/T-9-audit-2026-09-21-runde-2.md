---
id: T-9
type: Task
title: Work through the findings of the second audit (four perspectives)
status: erledigt
milestone: M-1
tags: [sicherheit, betrieb, tests, audit]
created: 2026-09-21
---

# T-9 — second audit, 2026-09-21

After [T-8](T-8-reifepruefung-restbefunde.md) a second pass with four independent perspectives,
this time aimed **at the fresh code itself**: what is wrong with the fixes?
**43 findings, 5 of them blockers** — and several are regressions of the repairs from T-8. That is
the value of a second look: whoever closes a hole does not check their own seal.

As in T-8, every item is first reproduced against the code before it is touched.

## Blockers

- [x] **Hijack the first admin via the USERNAME.** The T-8 guard requires an *email* in
      `admin_identifiers` when registration is open — but `maybe_promote_admin` still compared
      "name OR email". Anyone who registers as `username="chef@example.com"` and confirms their
      own mailbox became first admin. The hole had only moved.
- [x] **`tinysesam backup` migrates the source database.** `_oeffne()` takes the full
      `Store` constructor, which runs `_migrate()` — **before** copying. Anyone who does the one
      right thing before the update and takes a backup thereby lifts the running installation to
      the new schema while the old code is running. The way back is closed afterwards, and a file
      in the old schema exists nowhere any more. Applies to `gc` just the same.
- [x] **Restoring is not documented and fails silently.** After a crash `-wal`/`-shm` are lying
      around; a `cp backup.db auth.db` is overwritten at startup by the leftover WAL — the old
      state is back, `integrity_check` says `ok`.
- [x] **`konfigpruefung.py` checks a field that does not exist** (`ldap_server` instead of
      `ldap_url`). Two errors in one line: the warning fires on **every** LDAP configuration, and
      the intended check **never** takes place. Our own presets trigger it.
- [x] **The PyPI secret check can be defeated with a `name:`**
      (`test_packaging.py:235`). A step written the usual way with
      `password: ${{ secrets.… }}` passes green. The most expensive one before a first publication.

## Permissions and access

- [x] **An empty API key scope became "inherits everything".** `["tippfehler"]` shrinks to `[]`,
      and `[]` means "no scope" in the schema. A scope that was meant to limit, extended.
- [x] A **scoped API key issues itself another one with all owner roles**
      (`create_api_key` intersects against the account roles, not against the effective roles).
- [x] **The CSRF check has an off switch chosen by the client:** any
      `X-API-Key` header skips it — even with `apikey_enabled=False`, even if the session is used
      afterwards.
- [x] `POST /auth/magic/request` without CSRF check (the only state-changing route without one).
- [x] **The admin panel rolls a new CSRF token on every call** (= [B-1](B-1-admin-panel-rotiert-csrf.md),
      was on M-2). Through the new CSRF checks it now hits more paths than at the time of the report.
- [x] `login_chain` accepts `ldap`/`apikey` as a step — neither can ever be fulfilled.
- [x] `pin_login=False` is not seen by the "no sign-in method" check → empty
      login page, no finding.

## Crypto and sessions

- [x] **The migration is not atomic.** `ALTER TABLE` commits on its own; an abort before it
      leaves plain-text tokens in the column `token_hash` — permanently, because the
      detection condition never becomes true again afterwards. All affected sign-ins are dead.
- [x] **The migration does not tolerate a second process** (`uvicorn --workers N`): `no such column:
      "token"`, the worker dies at startup.
- [x] **A TOTP code is valid for 90 seconds, any number of times** — two separate clients sign in
      fully with the same code. NIST SP 800-63B: "SHALL accept a given OTP only once".
- [x] `resource_unlock.token` is in the database in **plain text** (identical to the cookie) —
      the same threat model that justifies the session switch.
- [x] Recovery codes: 64 bit with unsalted sha256 — NIST requires a password hashing scheme below
      112 bit.
- [x] scrypt fallback below the OWASP parameters (`N=2^15, p=1` is not an approved combination).
- [x] scrypt hashes are **never** upgraded to argon2, even if the extra is installed later.
- [x] Session token is not renewed on a change of privileges (second factor).
- [x] CSRF token is not rotated at login (naive double submit).

## Operations

- [x] **fail2ban can be turned against third parties:** the username goes unfiltered into the log;
      a `\n` in it creates a forged line with a foreign IP, while the real one becomes invisible.
      Proven against real fail2ban 1.1.1.
- [x] The shipped **fail2ban jail cannot read anything in the shipped compose** — there neither
      `TINYSESAM_SECURITY_LOG` is set nor a log directory mounted.
- [x] `/auth/oidc/start` is the only flow-creating route **without a rate limit**; every abort
      leaves a row. `gc` does not give the space back (no `VACUUM`).
- [x] **Incident diagnosis:** wrong password, deactivated account and typo in the name are
      byte-identical in the log; an active lockout is not in the audit at all; OIDC rejections
      (group missing / no account) leave nothing. There is no CLI way to the audit log.
- [x] The **health check does not notice database damage** — `/healthz` stays 200 while
      every signed-in request returns 500.
- [x] **Rollback trap:** old code on a new file starts, `/healthz` green, accounts readable,
      every session operation throws. Not documented anywhere.
- [x] No timer/cron template for `gc`, although the README refers to it.
- [x] Not a word on retention of the audit log (it stores IP addresses).

## The checks themselves

- [x] **In a git worktree the entire hygiene suite skips itself** (`.git` is a file there, not a
      directory) — and `run_all` reports green.
- [x] **`run_all.py` has no floor:** exit 0 even for "0 green, everything skipped".
- [x] `test_repo.py` catches `import subprocess`, but not `from subprocess import run` or
      `os.system` — although a security statement sits next to it.
- [x] `test_api_surface.py` does not freeze class attributes — `FORWARD_HEADERS_DEFAULT` is a
      promise in the docs and could be changed silently.
- [x] `test_kern_install.py` measures **text occurrences instead of behaviour** in two places.
- [x] `test_typen.py` runs mypy without `--check-untyped-defs`: 120 of 410 functions are never
      checked, including all four presets (users see `Any` there).
- [x] The constructor guards can be bypassed by changing the config **after** construction — our
      own `examples/showcase.py` does exactly that.
- [x] `forward_headers={"user": None}` passes the guard and turns every forward-auth request
      into a 500; `{"user": 123}` kills the constructor with a raw `TypeError`.
- [x] `_fehlt_extra` in `webauthn_.py` is dead code; the passkey case raises `RuntimeError`
      instead of `MissingExtra`.
- [x] `ldap_.authenticate()` **swallows** the missing extra and answers as for a wrong
      password; `saml_.metadata()` imports unguarded → 500.

## Status: worked through (2026-09-21)

**All 43 findings handled.** Each was first reproduced against the code before it was touched;
the evidence is in `tests/test_audit_runde2.py` (36 checks) and in the existing
security suite.

The three regressions from this morning are the real yield of this round: the first-admin guard
checked the *configuration* and left the *comparison* unchanged; the API key trimming turned
"no matching role" into "inherits everything"; and `tinysesam backup` migrated the file it was
supposed to back up. All three arose while closing a hole — none of them would have been noticed
without a second, independent look.

## Refuted

- **"CSRF exception for API keys is not a bypass"** (crypto perspective) versus **"off switch
  chosen by the client"** (security-fix perspective): the second is right and proved it —
  the header is not validated, and afterwards the session takes effect. The first only looked at
  the CORS side.

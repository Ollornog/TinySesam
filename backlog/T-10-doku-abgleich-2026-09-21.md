---
id: T-10
type: Task
title: Docs measured against the code — 70 places, 10 real defects
status: erledigt
milestone: M-1
tags: [doku, sicherheit, betrieb, tests]
created: 2026-09-21
---

# T-10 — docs reconciliation, 2026-09-21

After [T-8](T-8-reifepruefung-restbefunde.md) and [T-9](T-9-audit-2026-09-21-runde-2.md) a third
pass, this time **starting from the docs**: every statement about behaviour was measured against
the code — both READMEs, CHANGELOG, docstrings, `deploy/`, `web/`, backlog, plus the maintainer's internal
docs. **70 places deviated.**

The yield was not in the outdated sentences. **Ten of the deviations were defects in the code or
in a shipped template** — visible only because next to them stood a promise that someone read. A
test checks what its author thought to check; a docstring records the intent, and where intent and
body diverge, one of the two is wrong.

## Blockers

- **0.18.0 would have locked out every scrypt installation.** The format `scrypt$salt$dk` did not
  carry its parameters, and 0.18.0 raised `p` from 1 to 3 (OWASP). `verify_password` recomputed
  every existing hash with the new value — without error, without message, just "password does
  not match", for every account without `[argon2]` at the same time. Exactly the installations the
  fallback is built for. The format now carries the parameters; the old one is recomputed with the
  values of back then and upgraded at the next login.
- **`login_chain=["password","totp"]` was a dead end** for every account without TOTP set up: the
  correct password led to `/auth/totp`, which for lack of a secret redirected back to the login
  page, and the setup page required a fully signed-in user, which under this chain can never
  exist. Neither in nor to the setup.
- **`nginx.conf` passed a client header through to the app.** `Remote-Name` was missing in the
  template — nginx does not omit a header that is not set, it passes it on.
- **The Caddy template protected nothing.** `reverse_proxy /auth/forward <upstream>` is a path
  matcher, not a rewrite: the check ran only for requests to `/auth/forward`, every other path
  fell through. In addition a login redirect that stayed empty because of Go header
  canonicalization.
- **`seed_demo()` did not check `demo_mode`** — the docstring had promised it all along. A direct
  call created `demoadmin` with `is_admin=1` and the documented default password.

## Further defects

- The migration left plain-text unlocks behind (`0 < user_version < 4` missed exactly the case it
  was written for — `user_version` itself only arrived with 0.18.0).
- `tinysesam audit --user` filtered the most recent rows afterwards instead of filtering in SQL:
  "No entries for 'X'." with exit 0 in the very case it was needed.
- The shipped compose produced a stack that does not run (`127.0.0.1` in the Caddy container).
- The `HEALTHCHECK` followed redirects, contrary to the comment next to it.
- `Documentation=` in `tinysesam-gc.service` was silently discarded by systemd (umlaut in the
  anchor).
- `stepup_methods` was only a wish: anyone who had set up none of the named methods confirmed with
  whatever they had — including the password they had just signed in with. New: `stepup_strict`.

## What prevents a relapse

- `tests/test_bestandsdaten.py` — 28 checks on what an upgrade must survive. Each was
  cross-checked against the mutation: fix reverted → check red.
- Three guards in `tests/test_repo.py`: the number of test files and the Python range named in both
  READMEs are measured against reality, and as long as the version is below 1.0 no README may show
  a PyPI install. Exactly these three numbers were wrong — "17 and 22 test files" for 46,
  "Python 3.10–3.13" for a matrix up to 3.14, and `pip install tinysesam` as the very first
  command, although the name is not registered there.

## Open

The READMEs name `v0.18.0` as tag, wheel URL and image tag. The tag does not exist yet — it comes
into being with the release, which a human triggers; `scripts/_release.py` updates all places.
Until then they point nowhere. Not a defect of this pass, but the state on `main`.

---
id: M-1
type: Milestone
title: 1.0 — API stable enough for PyPI
status: offen
tags: [release, api]
created: 2026-07-23
---

# M-1 — 1.0: API stable enough for PyPI

**Done when:** the public API has not broken across two minor versions,
the ceremony paths (passkey/OIDC/SAML) have run once against real counterparts, and a release
runs through without manual steps.

Only then is PyPI justifiable — see [ADR-1](ADR-1-pypi-deferred.md). Until then, the pinned
Git tag is the more honest artifact.

## Open: the surface is measured, not selected (2026-09-21)

`tests/api_surface.json` freezes **everything that has no leading underscore** — 105
methods. 68 of them appeared in no documentation; they are frozen because they look that way, not
because anyone decided that they belong to the public surface.

Since 0.18.0 the situation is at least visible: each of these methods has a docstring, and
[API.md](../API.md) lists them completely (generated, with a check). Since then the guard also covers
return types and the **default values** of the config fields — without that,
`session_ttl_hours` could be silently set from 168 to 1.

**What remains open and must be decided before 1.0:** which of these 105 names should be public
for good? Freezing everything is the safe but expensive answer — every internal
rename then becomes a breakage. The decision is one of substance (what does TinySesam promise?)
and does not belong in a repair run.

## Status: open again (2026-09-21, after the maturity review)

The milestone was closed for a day and is no longer. A maturity review from four
independent angles (security, package/installation, API contract, operations) found **47 findings**;
12 of them were reproduced individually — **12 held up, 11 confirmed as blockers**.

Among them six security holes, each proven with its own reproduction script: role escalation
via self-issued API keys, account injection via OIDC (`state` without browser binding)
and SAML (`InResponseTo` unchecked), six writing routes without a CSRF check (including
"disable 2FA", with no audit entry), a resettable brute-force lockout and an
admin bootstrap where whoever types in the address first wins.

**An auth package with role escalation does not carry "Production/Stable", and a PyPI version is
irrevocable.** Hence 0.18.0 instead of 1.0.0.

### Why nobody noticed — the finding behind the findings

`tests/run_all.py` booked real failures as **"skipped"**. The suite was green because
it did not measure. Even the worst case remained invisible as a result: `pip install tinysesam`
with default configuration does not start (`ModuleNotFoundError: webauthn`) — the very first step
of every new user, and CI could not see it.

That was repaired first. Everything else would have been built on sand.

### The conditions, as they stand now

| Condition | Status |
|---|---|
| Ceremonies against real counterparts | met |
| Release without manual steps | met |
| Two minor versions without API breakage | **clock restarts with 0.18.0** |
| **No open security findings** | **new — see M-2** |

The fourth condition was not there before because nobody had looked for it. It belongs here:
a stable surface on top of a package with role escalation measures the wrong thing.

## Status 2026-09-27: T-13 done, only the API classification remains open

[T-13](T-13-audit-2026-09-22-round-3.md) (third audit including addenda, boundaries and the review round
locks/counters) is complete: every point is fixed with a test, proven by mutation, or marked
"deliberately so, with reasons". What remains open for this milestone is only the **classification
of the public API into A/B/C** (PO decision 2026-09-26) — the question of substance above, which of the
frozen names should be public for good. It rests with the PO.

## Status 2026-09-27: classification built, the clock for A starts with 0.22.0

The PO decided on the tiers on 2026-09-26 ("sounds good — go"); step 1 is built:

- **Each of the 339 public names carries a tier** in `tests/api_surface.json` —
  A 225 (of which 158 configuration fields), B 64, C 50. `tests/test_api_surface.py` is red if
  one carries none or an unknown one; `--update` carries tiers over but never assigns one.
  That answers the question above ("measured, not selected"): what is selected is what is A.
- **The condition "two minor versions without breakage" applies only to A**, counted from 0.22.0 — the
  release that brings the classification. A breakage in B (only after a `DeprecationWarning` over two
  minor versions) or C (internal, falls with 1.0) does not reset the clock; the guard reports
  it anyway, with the previous tier.
- `API.md` is organized by tier, the READMEs explain the tiers and list the B building blocks in the
  section for advanced users.

| Condition | Status |
|---|---|
| Classification of the public API | **built** (tiers, guard, docs) |
| C names with underscore, old name as warning alias until 1.0 | **built** (50 aliases, guard, warning filter in `run_all.py`) |
| Safe building block for custom login pages (the inner verifiers do not throttle, PO finding) | **built** — step 3 (`login_*`, `LoginResult`, the routes call it; English since the addendum below) |
| The same for custom step-up and password-change pages (PO decision 2026-09-27) | **built** — `confirm_*` (→ `LoginResult`), `change_password` (→ `PasswordChangeResult`), `/auth/reauth` and `POST /auth/password` call them; addendum below |
| Two minor versions without breakage **in tier A** | clock starts with 0.22.0 |

**Step 2 (2026-09-27): tier C is a warning alias.** The implementation is called `_name`
(42 methods, 6 constants; `complete_mfa` points to `complete_totp`), the old name is a
`Deprecated` (deprecated) from `tinysesam/_deprecated.py` and warns on call exactly once with the replacement. Package, examples,
scripts and tests only call the new names. The guard holds storage and class
against each other, checks warning, target and forwarding of every alias, forbids old names in the own
code (AST) and turns red with 1.0 as long as an alias still stands; `tests/run_all.py` turns such a
warning from the package itself into an error. `PIN_CHAIN_SERIES` had never been published and is called `_PIN_CHAIN_SERIES` without
an alias — state after step 2: 338 names, C 49.

**Step 3 (2026-09-27): a safe login building block for custom pages.** (With the names of
that time — since the addendum "The login building block is named in English" below the English ones apply.) The
PO finding: the README sent custom login pages to `check_password` + `start_session`, and the
inner verifiers do not throttle. Now there are `anmelden_passwort`, `anmelden_pin` and
`anmelden_totp` (tier A) with the result type `tinysesam.Anmeldung` (export, tier A): they
throttle, count and lock like the built-in routes — because `POST /auth/login`, `/auth/pin` and `/auth/totp` call exactly them and only
render the result (one source; an AST guard in `tests/test_sign_in.py` forbids the
routes any inner verifier). Equality is measured line by line: the same sequence over the
built-in and over a custom route yields the same status, audit, log and counter lines. The
README shows both ways (looks only: `set_template`; custom route: `anmelden_passwort`), its
example runs verbatim in the test and must lock. The replacement texts of the C aliases name the building block.
The guard also measures the result type (area `Anmeldung`: fields, methods, `GRUENDE`) — state
353 names: A 240, B 64, C 49.

**Addendum 2026-09-27: 0.21.0 went out without the classification** (brought forward for a
production go-live). It appears with **0.22.0**: `seit` (since) of the aliases, the counter for A, the warning texts
and the docs name 0.22.0. Because only the *presence* of `seit` was checked, the guard now also checks
the value against the CHANGELOG (`seit_befunde`): if `[Unveröffentlicht]` introduces an alias, `seit` is above
the latest release, otherwise it is exactly the introducing release.
One consequence: `PIN_CHAIN_SERIES` was "never published" at step 2 and was called `_PIN_CHAIN_SERIES` without an alias
— with 0.21.0 it is published (G7; its CHANGELOG names it for custom
PIN pages). It is now an alias like every C name: state 354 names, A 240, B 64, C 50.

**Addendum 2026-09-27 (PO decision): The login building block is named in English** and stays tier A,
like the rest of the tier A surface: `login_password`, `login_pin`, `login_totp`; the result type
`tinysesam.LoginResult` (module `tinysesam/login_result.py`) with `ok`, `reason`, `status`,
`message`, `next_url`, `next_factor`, `done`, `user`, `set_cookie(response)` and `redirect()`;
the reasons in `REASONS`: `ok`, `missing`, `invalid`, `locked`, `locked_series`, `ratelimit`,
`directory_down`, `method_disabled`, `no_session`. Renamed before the release and therefore **without
an alias** — the names from step 3 (`anmelden_*`, `Anmeldung`, `GRUENDE`, `cookie_setzen` …)
were in no release (`git show v0.21.0:tinysesam/manager.py` does not know them). Only the
names of the building block are affected: audit and log lines (`login_fail … grund=…`, the lines for
fail2ban) stay as they are; `reason` is a short code for programs, not a log line. A
guard (`tests/test_sign_in.py`, section k) measures the surface of the building block on the object —
every method that returns a `LoginResult`, including parameters; type, module, fields, methods,
`REASONS` — and demands: no German word from a short list, every name tier A. State
unchanged at 354 names, A 240, B 64, C 50.

~~Open for this milestone, as a finding from step 3: the guard records signatures without the
star of keyword-only parameters.~~ **Fixed 2026-09-27:** `signatur()` measures `*` and
`/` too (10 signatures re-measured, none changed), an inserted `*` is a breakage; a
storage file from before 0.22.0 is read in without marks and compared without marks, the comparison with
`v0.21.0`/`v0.20.1` reports only real differences. `API.md` shows the marks as well.

Not measured and thus outside the classification: instance attributes (`auth.store`, `auth.cfg`,
`on_security_event` …), the HTTP routes and the logger names (`tinysesam.security`).
~~Whether they belong in the commitment is an open question with the PO.~~ **Decided:** `auth.store` is
internals, tier C, without commitment (addendum of 2026-09-27 below); `auth.cfg`, `on_security_event`, the routes
and the logger names are measured and tiered since the **addendum of 2026-10-29** at the end of this page.

**Addendum 2026-09-27 (PO decision): The whole surface of tiers A and B is named in English,
without alias.** After the login building block, now the rest: 11 methods, 5 constants, 2 methods of
`TinySesamConfig`, 18 parameters in 14 methods, `ConfigError.feld`/`.besitzer_id` →
`.field`/`.owner_id` and `MissingExtra(nachricht, …)` → `MissingExtra(message, …)` (table in the
CHANGELOG under "What stands out on update"). Unlike with the building block, these names were in
0.21.0 — they are dropped **without an alias** nonetheless, because the commitments of the tiers only begin with 0.22.0
and none of the known consumers uses any of them (checked: no call, no parameter, no configuration
field). The tiers stay as they were. No configuration field was affected —
they were already named in English. Values stay: reason codes, audit and log lines, the keys of the
report of `federation_bind_existing`, database columns.

The name guard from section (k) has been extended to the whole surface
(`tests/test_api_surface.py`, `pruefe_namen`): every name in A or B, every parameter on the live
object, every configuration field, the attributes and constructor parameters of the error types — 566
entries; words, stems (also in the middle of a word) and umlauts; minimum set and self-probes. State
unchanged at 354 names, A 240, B 64, C 50.

~~Open (not part of this decision, to be asked of the PO): return values and data still carry
German keys — the report of `federation_bind_existing` (`quelle`, `ausgefuehrt`,
`gebunden`, `konflikt`, `mehrdeutig`, `nicht_im_verzeichnis`, `ohne_kennung`, `abgewiesen`,
`lokal`, per entry `verzeichnis`, `kennung`, `grund`, `gebunden_an`, `treffer`), `gc()`
(`fehlserien`), the payload of `on_security_event` (`alt`, `neu`), the values of `api_key_kind`
(`automat`, `mensch`) and the context for custom pages (`ctx["praefix"]`, `ctx["zweck"]`). The
guard measures names, not values; whether these keys become English before 1.0 is a decision of its own
— any change there breaks code that reads them.~~ **Decided 2026-09-27**, see the
next addendum.

**Addendum 2026-09-27 (PO decision): Keys and values in English too — database included.**
"Translate everything, DB values too", without alias (the commitments begin with 0.22.0):

- The list from above is implemented, plus what the inventory found: the reasons in the report
  (`kein_konto` → `no_account` …), the keys of `NAME_BINDING_REFUSALS` (with an English
  explanation), `verworfene_rollen` → `dropped_roles`, `confirm_email_change` → `"taken"`, the
  payload of an email-change link (`alt` → `old`), the remaining payload of `on_security_event`
  (`verbleibend`, `anzahl`, `grund` with its values, `recovery_codes_geloescht`),
  `current_user()["_key_art"]` → `_key_kind`. Table in the CHANGELOG under "What stands out
  when updating". The account dicts now carry only the account's fields — the store's bookkeeping
  (German column names) went out with them up to 0.21.x.
- Two of these are **stored**: `api_key.kind` and the payload of open email-change links.
  A data migration raises `SCHEMA_VERSION` to **12** — no column, but 0.21.x reads the new
  value differently: a `human` key counts there as an automaton key and takes effect without a session (measured with
  the code from `v0.21.0`). The stamp is the place where an older version warns; 0.21.x
  opens the file with that warning. The way back is an SQL block in `docs/OPERATIONS.md` that
  `tests/test_values_english.py` executes. An old value continues to be read correctly; the keys
  are rewritten by every start, the payload only by the jump to 12 (otherwise a pass through all
  one-time tokens on every start).
- **Not translated:** audit and log lines (fail2ban, operators' filters) — the
  old names remain in them (`art=automat`, `grund=name_aus_quelle` …); the kind of a failure series
  (`fehlserie.art`, among them `pin_folge`), which is only read internally; the column names.
- **Guard:** `pruefe_werte` in `tests/test_api_surface.py` measures the keys and values on a probe
  instance, on the constants and in the source code (790 entries) against the word list and the
  names up to 0.21.x.
- **`auth.set_disabled(user_id, disabled)`** (tier A) instead of the advice to call `auth.store.set_disabled(…,
  durch_betreiber=True)`, which only set the note; the panel calls the method.
  **`auth.store` is internals** (tier C, no commitment) — the docs say so everywhere they still
  name a call. State 366 names: A 252, B 64, C 50.

**Addendum 2026-09-27 (PO decision): Building blocks for custom step-up and password-change pages**
(tier A, English). After the login building block, the same was missing for confirmation before sensitive
actions and for a custom password change: there were only the routes `/auth/reauth` and
`POST /auth/password`, and the inner verifiers (`_verify_user_password`, `_verify_user_pin`,
`_verify_totp`) do not throttle. Now:

- `confirm_password(request, password, *, next="", csrf=None)`, `confirm_pin(…, pin, …)`,
  `confirm_totp(…, code, …)` → **`LoginResult`**. Three names as with `login_*` instead of one
  `confirm(…)` with three optional fields: exactly one secret per call, no order that
  silently skips a field. `LoginResult` instead of a type of its own: a confirmation is a
  renewed sign-in on the running session, the fields fit without remainder, and `redirect()`/
  `set_cookie()` is needed for the renewed token. `next` was added relative to the assignment — as
  with `login_*`, so that `redirect()` has a checked target.
- `change_password(request, current, new, *, csrf=None)` → **`PasswordChangeResult`** (new
  export): `ok`, `reason`, `status`, `message`, `api_keys_active`. A type of its own, because a
  password change signs nobody in and does not rotate a token.
- The routes are wrappers around them; an AST guard (`tests/test_confirm.py`, h) forbids them
  any inner verifier, equality is measured line by line (g). Three behaviour changes
  to the routes are in the CHANGELOG under "What stands out on update": `POST /auth/password` takes
  no API key any more (403), an empty field no longer counts at either, a method not offered
  at `/auth/reauth` is 403 without a failed attempt.

State 365 names: A 251 (+ 4 methods, the export and 6 names on `PasswordChangeResult`), B 64,
C 50; the name guard measures 593 entries.

**Addendum 2026-10-29 (PO decision): the promise covers the hook, the HTTP contract and the security log.**
What was "not measured" is measured now (`tests/_contract.py`, `tests/_contract_probe.py`, wired into
`tests/test_api_surface.py`; 191 new entries in seven areas of `tests/api_surface.json`, **A 106, B 85**; no existing
entry or tier changed):

| What | Tier | Area in `api_surface.json` | How it is measured |
|---|---|---|---|
| `auth.cfg` — **reading** it | A | `TinySesam.attributes` | a probe instance: type, "is the instance that was passed in", not frozen |
| `auth.on_security_event` — attribute, call `hook(event, account, details)`, synchronous, after the change is written, a failing hook does not abort | A | `TinySesam.attributes` | declaration read from `__init__`; a probe hook observes arguments, thread, state and failure isolation |
| keys of `details` per event | A | `TinySesam.event_payload` | the keyword names of every `_security_event(...)` call; the events must equal `SECURITY_EVENTS` |
| forward/gate routes (`/auth/forward`, `/auth/verify`, `/.tinysesam/*`, `/auth/gate/*`) with their query/form parameters | A | `http.routes` | decorators of the route modules (static, independent of installed extras), compared with FastAPI's reading of a probe instance; `add_api_route`, `mount` and the like are refused |
| status codes, redirect paths, headers and cookie names of the forward endpoint and the gate paths | A | `http.forward` | 21 observed cases on probe instances, including the whole code exchange |
| `X-TinySesam-*` headers, values of `X-TinySesam-Reason`, request headers and parameters read, gate cookie names | A (the two account-page hints `X-TinySesam-Factor`, `-Reauth`: B) | `http.contract` | string constants and `.get("…")` reads in the forward/gate code |
| HTML pages, JSON/API routes, passkey/OIDC/SAML routes, `/healthz` — **path and method**, not the HTML | B | `http.routes` | as above |
| logger names | A | `log.loggers` | `getLogger("…")` literals; the security logger must be among them |
| log file format, event words, the keys of the lines in order, the literal `method=`/`reason=`/`unban=` values | A | `log.lines` | the AST reader of `tests/_seclog_ast.py`, shared with `tests/test_fail2ban_reason.py`; the event words the shipped filters name must still be produced |

* **`auth.cfg` is not immutable.** `TinySesamConfig` is a plain, mutable dataclass; `examples/showcase.py` and the
  README write to it, `router()` checks it once more, and `TinySesamConfig.validate()` re-checks. So the promise
  is **reading only**; writing is explicitly not promised (README, `API.md`).
* **The payload keys are not counted twice.** `pruefe_werte` keeps checking the *language* of the keys; the new area
  pins *which* keys exist. A key that goes away is a break, a key that is added is an extension.
* **Tier rules the guard holds:** everything in `TinySesam.attributes`, `.event_payload`, `http.forward`, `log.*` and
  `http.contract` (bar the two hints) and the forward/gate routes may not sit below A; every other route is B and may
  be promoted. `--update` still assigns no tier. A route the static scan cannot see turns the guard red.
* **Tier B for routes** reads as in the table of the first addendum, with one adaptation: a route cannot raise a
  `DeprecationWarning`, so a removal or rename must be announced in the CHANGELOG under "Deprecated" two minor
  versions ahead.
* **The clock.** The existing A entries keep their clock (counted from 0.22.0). The new A entries start theirs with
  the release that introduces them — the one after 0.24.13; nothing here was released yet. As the condition is
  worded ("the public API has not broken across two minor versions"), it can be met for these entries at the
  earliest two minor versions after that release.
* **Operator documentation:** `docs/OPERATIONS.md` ("Security log contract", "HTTP contract for proxies"), the READMEs
  ("Beyond the Python names"), `API.md` (generated: "Attributes of `TinySesam`", "HTTP contract", "Security log").

| Condition | Status |
|---|---|
| Classification of the Python names | built (0.22.0) |
| `auth.cfg` (reading), `on_security_event` | **built** — tier A, clock from the next release |
| HTTP: forward/gate contract A, pages and API routes B | **built** |
| Logger names, security-log lines for filters | **built** — tier A |
| Two minor versions without breakage **in tier A** | existing names: clock since 0.22.0; the entries above: from the release that introduces them |

**Open, found while measuring:**

* The query parameter `abgemeldet` is German and sits in a tier-A route (`GET /.tinysesam/start`, written by
  TinySesam's own redirects) and in a tier-B one (`GET /auth/login`). The guard for English names covers names, keys
  and values of the Python surface, not the parameters of routes; renaming it is a behaviour change (in-flight
  links, `tests/test_gate_link.py`) and is a decision for the PO.
* Routes the decision did not name are tier B: the JSON routes (`/auth/me`, `/auth/apikeys`, `/auth/sessions`, the
  admin API), the passkey routes and — worth a look — the paths other systems have registered by hand:
  `<oidc_callback_path>` and `/auth/oidc/start` (the identity provider), `/auth/saml/acs`, `/auth/saml/metadata`,
  `/healthz` (the image's health check) and the links in e-mails (`/auth/magic/{token}`, `/auth/verify/{token}`,
  `/auth/invite/{token}`, `/auth/reset`). A move would cost an operator a reconfiguration; promotion to A is a
  one-word change in `tests/api_surface.json`.
* `X-Csrf-Token`, `Sec-Fetch-Site` and `Referer` are in the request headers because the gate paths read them; they
  are tier A with the rest of `http.contract`. Say so if a narrower set is wanted.
* Still not measured: the shape of the JSON bodies of the routes, `Set-Cookie` attributes, `Location` targets beyond
  their path, the audit event names, the HTML.

<!-- What used to be here (closing with 1.0.0) is obsolete together with the milestone itself. -->

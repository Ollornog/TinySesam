# Operations — what TinySesam does when something fails

This page is for the operator: what happens when a component drops out, how to manage sessions and
foreign identities, and how strong the individual sign-in methods really are. The READMEs show how
to build TinySesam in; this page says what to expect afterwards.

Every statement here has been reproduced against the code. Where a behaviour is a known weakness, the
backlog ID is given ([T-13](../backlog/T-13-audit-2026-09-22-round-3.md)).

## Failure behaviour

Basic rule: **if a checking component fails, nobody is signed in** (fail-closed). Two deliberate
exceptions are listed explicitly below (Redis, security log): there a *throttle* becomes weaker or a
*log* is lost, not the check itself.

| What fails | What the user sees | What the operator sees |
|---|---|---|
| **Database read-only** (read-only mount, permissions after a restore) | Sign-in fails with 500 as soon as a session is written. Existing sessions keep reading. | Gateway: `/healthz` → **503** `degraded` (write probe, B6-4). Log: `Healthcheck: Datenbank nicht beschreibbar`. |
| **Database volume full** | as above, as soon as SQLite needs new space | `/healthz` → 503, **if** the write probe needs space. A probe that writes into pages that are already allocated does not see an almost full disk — disk space belongs in the host's monitoring as well. |
| **Database locked** (second writer: another worker, `tinysesam` on the command line, a backup) | The request waits up to **10 s** (`Store.BUSY_TIMEOUT_MS`, B6-11), then 500 (`database is locked`). The next request runs normally: a failed write rolls back and leaves no transaction open. | the 500 appears in the ASGI server's log. `/healthz` waits the same way and reports 503 only after 10 s — the image's HEALTHCHECK therefore waits 12 s. Until T-13 was integrated, such a failure (also of the write probe of `/healthz`) left a transaction open, and every following sign-in ended with 500 until some other write happened to commit. If the sign-in path finds one anyway, it discards it and writes `Offene Transaktion … verworfen` to the log — that then points to a bug elsewhere. |
| **Redis** (`redis_url`) unreachable | nothing: sign-ins continue | **throttled per process** — a built-in in-memory limiter takes over (with `--workers N` up to N times as generous, but still a limit; B6-1). The switch is reported, not every request: once `Redis-Rate-Limit nicht erreichbar …`, once on return (B6-2); the start already asks Redis with `ping`. After an error Redis rests for 30 s, then the next attempt follows. The account lockout (in the database) applies unchanged. |
| **SMTP / mailer** | Magic link and "forgot password": the same success page as always (no account enumeration), but no mail. Registration with confirmation mail: likewise the usual page ("Mail on its way"); the account just created is removed again and the registration can be repeated (B6-5). If no mailer is set up at all (no `smtp_host`, no `set_mailer`), registration with confirmation is rejected immediately with 500. | Audit: `magic_send_error`, `reset_send_error` or `verify_send_error` (with "account removed"). The token of the undelivered mail has expired immediately (B6-12) — a relay that delivers the mail after all carries a dead link. |
| **OIDC provider** | New sign-ins via OIDC fail (error page). Existing sessions keep running until `session_ttl_hours`. | With several applications and `oidc_revalidate_minutes`: after the period expires, forward-auth sends the user to the provider — if that is gone, access to **this** application ends (fail-closed). |
| **LDAP server** | 503 "directory not reachable" — the same answer for every account. Local accounts with their own password (the emergency admin) keep signing in. | An outage is not a failed attempt: no lockout, no `failed login` (F-23); a wrong **local** password still counts (A-1). Audit `ldap_unavailable`, in the security log `LDAP unreachable user=… ip=… reason=…`. After the first failure that affects the directory as a whole (connection setup, TLS, service account, or a question that hung until the timeout), TinySesam **does not ask the directory at all for 30 s** (`ldap_.AUSFALL_PAUSE_SEK`), after that a single sign-in probes again. If the directory aborts only **one** request quickly after its inputs were sent (e.g. slapd on a PDU above `sockbuf_max_incoming`), only that one gets 503 (`reason=LDAP: only this request aborted …` in the security log) — otherwise a crafted sign-in would switch LDAP off for everyone. User names above 256 and passwords above 1024 characters (`ldap_.LDAP_NAME_MAX`, `LDAP_PASSWORT_MAX`) never reach the directory and count like a wrong password (401, `failed login`); outage and return are logged once each (`LDAP-Verzeichnis nicht erreichbar (…)`, `… wieder erreichbar`). Without this pause, with a directory that drops packets, every attempt hung until the timeout (10 s, `ldap_.VERBINDUNGS_TIMEOUT`). **The first window** (until the first timeout, per outage and process) still hangs, but no longer locks anyone out (G9): the pre-booking of an LDAP sign-in stays pending (`login_attempt.offen`) until the directory has answered. Anyone who would fail only because of pending pre-bookings — the colleagues behind the same NAT address, the emergency admin — waits until they are decided: at most 12 s, at most 8 waiters per process. After that 503 or the sign-in; anyone who gets no waiting slot or exceeds the deadline gets 429 with `deferred login user=… ip=… reason=pending` in the security log — **no** lockout, no `failed login` (fail2ban does not ban), no lockout notice. A salvo of wrong passwords waits along and then gets the real lockout (R7-2). An open pre-booking that nobody has completed after 30 s (`Store.VORBUCHUNG_SCHWEBE_SEK`, process died) counts as a failed attempt. So that a sign-in that is still running never counts that way, every question to the directory has **at most 25 s in total** (`ldap_.GESAMT_FRIST_SEK`, since 2026-09-27): each answer gets its share — the service account at most half of the remainder, the user connection the rest, at most 10 s per answer. With search-then-bind and StartTLS that is 2 s per service-account answer (ldaps 3 s, without TLS 4 s), then up to 5 s for the user connection (ldaps 6 s, without TLS 8 s). A directory that answers more slowly counts as unreachable (503, no failed attempt). A directory on the same network needs milliseconds. |
| **Extra missing at runtime** (`[oidc]`, `[saml]`, `[ldap]`, `[passkey]`) | Sign-in via this method fails with a readable message | At start a warning line with `pip install 'tinysesam[…]'` (the start itself remains possible — a custom client can be set); on the first attempt `MissingExtra` with the package name instead of a 500 from deep inside. |
| **Extra `[argon2]` missing** (new image, venv rebuilt) | Every account with an argon2 hash: "wrong password". | At start a line with the number of affected hashes and `pip install 'tinysesam[argon2]'`; during operation the same remedy once per process (B6-8). Every installation verifies scrypt hashes. |
| **System clock jumps back** (NTP, Pi without backup battery, VM snapshot) | nothing — deadlines keep running normally | Warning line `Die Systemuhr steht … hinter der zuletzt benutzten Zeit`. TinySesam keeps counting monotonically; expired sessions, one-time tokens and step-ups do not come back to life (B6-9). Across a **restart** the database carries the state: it saves it at most once a minute (`uhr_stand`, on every write and on the write probe of `/healthz`). What expired in the time after that — the last minute, or the whole idle period of an instance without healthcheck and without sign-ins — is valid again after a boot with an old date, until the clock has caught up that gap. If the clock once jumped wrongly **forward**, timestamps stay there until the wall clock catches up. |
| **Security log** (`security_log`) not writable | nothing | At start: `security_log … not writable — fail2ban gets nothing to read`. Sign-in continues anyway — a missing log is no reason to shut the service down. |

**Healthcheck.** The gateway (`python -m tinysesam.gateway`) ships `/healthz`: reachable without
sign-in, also over HTTP with `https_mode="force"`, answer 200 `{"status": "ok"}` or 503
`{"status": "degraded"}` — the error text stays in the log, not on the network. If you embed
TinySesam as a library, build the same check with `auth.store.schreibprobe()` (internals, tier C —
without commitment, like everything under `auth.store`): it raises the sqlite3 exception if no commit
goes through. A `SELECT 1` is not enough — it also succeeds on a read-only file.
It writes at most every 5 s (`Store.SCHREIBPROBE_SEK`, a commit of a sign-in counts too), in between
the probe only checks the connection: `/healthz` is reachable without sign-in, and one commit per call
would let anyone who floods it occupy the write lock. A database that has just become read-only is
therefore reported by the check after 5 s at the latest.

**Housekeeping.** Expired sessions, flows, one-time tokens and old failed attempts stay around until
someone calls `auth.gc()` or `tinysesam gc` (regularly, e.g. by timer). They are no longer read —
but the tables grow. `gc` deliberately does not clean up the audit log (B5-11).

**Deleting and the audit log.** A deleted account becomes `deleted#<id>` in the audit log (H-13; up to 0.24.x `gelöscht#<id>`) —
also in the detail text (`actor=<name>`, the address). Name and time are searched by an index; the
search in the detail text is a substring search that no index narrows down, and for a confirmed
address (deleting in the panel) it reads the whole log — whose size grows without
`audit_retention_days` (default 0 = unlimited). Since 2026-09-26 it runs in blocks of 5000 rows
without a write lock in between (G4): sign-ins and other workers no longer wait out the whole
search; the deletion itself takes as long as the log is large. Since 2026-09-27 (audit round, F4)
also: every spelling under which someone typed the identifier (`login_fail` writes the raw input —
compared in the counting bucket, not if a remaining account shares it), earlier names and addresses
of the account (from its `username_changed`/`email_changed` rows, each for the time it carried them)
and, in its own rows, the values of `old=`, `new=` and `to=` (up to 0.24.x `alt=`, `neu=`, `an=`; both spellings are found).
Not covered: an address that came and
went without `email_changed` (added later from OIDC/LDAP), and the name in the directory.

## Security log contract (fail2ban and log shipping)

Since the PO decision of 2026-10-29 (M-1) the security log is part of the stability promise, tier A. What a
filter or a log shipper may rely on:

- **The logger** `tinysesam.security` (and its parent `tinysesam`; `tinysesam.mail` for mail). `security_log`
  writes the first to a file.
- **The format of that file:** `%(asctime)s %(levelname)s %(message)s` — so a line starts with the date, then
  the level, then the message. The shipped filters strip the date and anchor on the level (`^\s*WARNING …`).
- **The event word** at the start of the message and **the keys behind it, in this order:**

  | Level | Event word | Keys |
  |---|---|---|
  | WARNING | `failed login` | `user=` `ip=` `method=` and, with a cause, `reason=` |
  | WARNING | `failed verification` | `user=` `ip=` `method=` and, with a cause, `reason=` |
  | WARNING | `deferred login`, `deferred verification` | `user=` `ip=` `reason=` |
  | INFO | `repeated login` | `user=` `ip=` `method=` |
  | INFO | `login ok` | `user=` `ip=` `method=` `unban=` |

- **Literal values** a filter can match on: `method=` `blocked`, `claim_admin`, `oidc`, `passkey`, `password`,
  and for `failed verification` the methods that are not a sign-in (`password_change`, `reauth`, `resource`,
  `totp_setup`); `reason=` `account_locked`, `pending`, `unknown_key`; `unban=` `yes`, `no`. A `reason=` or
  `method=` that is not listed may take other values — match it with `\S+`, as the shipped filters do.

**Not promised:** everything after the keys (free text), the values of `user=` and `ip=`, every line that does
not start with one of these event words (LDAP outage, API key denied, configuration notices, …), the audit
event names (`login_fail`, …) in the database, and the file permissions beyond what `deploy/fail2ban/` says.

If one of these changes, it is a break of a tier-A name: it resets the 1.0 clock and the CHANGELOG names the old
and the new line. `tests/test_api_surface.py` holds the lines against `tests/api_surface.json`,
`tests/test_fail2ban_reason.py` holds them against the shipped filters. For these entries the clock starts with
the release that introduces them (the one after 0.24.13), not with 0.22.0.

## HTTP contract for proxies

The forward and gate endpoints are tier A as well: `GET /auth/forward` and its alias `/auth/verify` (`200` with
the identity headers, `401` with `X-TinySesam-Location` and `WWW-Authenticate`, `403` with
`X-TinySesam-Reason: role`), the `/.tinysesam/*` paths on the application's host (`start`, `callback`, `logout`,
`after-logout`) and `/auth/gate/*` on the gateway, the `X-TinySesam-*` headers and the cookie names the gate
sets. Tier A too, because other systems have registered or poll them by hand: the OIDC callback
(`oidc_callback_path`), `POST /auth/saml/acs`, `GET /auth/saml/metadata` and `GET /healthz` (the image's health
check) — moving one would cost you a reconfiguration at the provider or in the orchestrator.

**What a proxy has to set or pass on (tier A):** `Host`, `Authorization`, `X-Api-Key`, `Cookie`, `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Uri` (or `X-Original-Uri` / `X-Original-Url`) and, if you
require roles, `X-TinySesam-Roles`. The shipped templates under `deploy/forward-auth/` do exactly that. The headers
a browser sends on its own (`Accept`, `Referer`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`, `X-Csrf-Token`) are read as
well, but they are **not** an operator contract (tier B): no proxy rule is needed for them, and no proxy rule may
strip them.

The exact list, with every observed status, is in [API.md](../API.md), section “HTTP contract”. The HTML pages are
tier B: path and method stay, the HTML does not.

**Removing or renaming a tier-B path** (a route cannot raise a `DeprecationWarning`): the CHANGELOG announces it
under “Deprecated” at least **two minor versions** before the release that removes it. Tier A follows the 1.0
rule — a break resets the clock.

**The query parameter that marks a sign-out** is `signed_out=1` (`/.tinysesam/start`, `/auth/login`); up to this
release it was `abgemeldet=1`. A bookmarked or in-flight link with the old name still works, but without the hint
“You have been signed out”.

## Managing sessions

A session is a row in `session`; the cookie holds the token, the database only its sha256 (the
**handle**). With a handle a session can be named and ended, but not taken over.

| Who | What | How |
|---|---|---|
| User | view own sessions | `GET /auth/sessions` (created, IP, method, browser, "this one") |
| User | end other own sessions | `POST /auth/sessions/revoke` with `{"scope": "others"}` — API keys stay, the response gives their count |
| User | end everything (panic button) | `{"scope": "all"}` — also ends the current session **and revokes all API keys** |
| Admin | see all sessions | panel or `GET <admin_path>/api/sessions` (`full` is the handle) |
| Admin | end one / all of an account | `POST <admin_path>/api/sessions/revoke` with `{"token": <handle>}` or `{"user_id": …}` |
| Admin | disable account | `POST <admin_path>/api/users/{id}/disable` — ends all sessions, revokes API keys and discards open one-time tokens (sign-in, confirmation, reset link). The block carries the operator flag: even a confirmation link that only comes into existence afterwards does not lift it — only "Unlock" in the panel does (H-18). Blocks from versions up to 0.19.x are raised to the flag by the migration to schema 10, which discards their open tokens, provided the audit log still knows the block — also one that an older version set after a rollback to a schema-10 file: every start re-reads the audit rows since the last start (setting `panel_sperren_bis`) and warns in the log when it finds something; an older one (row already removed, `audit_retention_days`) is blocked again by the same call with `{"disabled": true}`, without unlocking — for a disabled account the panel offers only "Unlock". |
| Code | disable account | `auth.set_disabled(user_id, True)` (tier A, since 0.22.0) — exactly the effect of the panel, which calls this method: operator flag, end sessions, revoke API keys, discard open one-time tokens, audit `user_disable`. `auth.set_disabled(user_id, False)` unlocks. An owner cannot be disabled (`StateError`), an unknown ID returns `False`. Up to 0.21.x this read `auth.store.set_disabled(user_id, True, durch_betreiber=True)` — that only set the flag; sessions, keys and links stayed valid. |
| Code | sessions without HTTP | only via the internals (`auth.store`, tier C — no commitment, may change with every release): `auth.store.list_sessions(user_id)`, `delete_session_by_handle(handle)`, `delete_user_sessions(user_id)`, `delete_user_sessions_except(user_id, handle)` |

What ends a session **by itself**: inactivity (`session_idle_minutes`, default 8 h — for every
session where "Stay signed in" was not **explicitly** ticked, also a permanent one from OIDC or a
sign-in link; `session_idle_minutes_remember`, default off), a no from the identity provider
during the re-check (4a, OIDC) and its expiry (`session_ttl_hours`, default 7 days with
"Stay signed in", otherwise `session_ttl_transient_hours`), the account's own password change (all
other sessions — via `POST /auth/password` as well as via an own page with `change_password`;
only from a session, an API key does not change a password), a password reset by link (all), an
admin reset of the password, the disabling of the account. A session whose account is disabled opens
nothing any more, even if it has not yet expired — and no sign-in method creates a new one for a
disabled account (H-18).

A **step-up** (reauth, renewed factor) gives the session a new token (F-06). The old one stays valid
for `session_rotation_grace_sec` (default 10) seconds, so that a request from a second tab that was
already in flight at that moment does not fail (A-6) — without step-up freshness (no sudo route), not
as a session of its own in the list, and it ends with the new one. `0` = dead immediately.
An app's own step-up page (`confirm_password`, `confirm_pin`, `confirm_totp`, since 0.22.0)
behaves the same way — `/auth/reauth` calls the same building blocks: failed attempts count in the
bucket `reauth` (`reauth_max_attempts`, per account only) and appear as `failed verification` in the
security log (fail2ban does not ban on this line); the lockout affects the step-up, not the sign-in,
and expires with the window (`lockout_window_sec`).

What it does **not** end — named deliberately, because one expects it:

- **With "Stay signed in" no inactivity timeout** (default of
  `session_idle_minutes_remember`): the session lives until its absolute expiry, even unused.
- **The identity provider without a refresh token.** If it issues none, the session stays valid
  there after a block until expiry (4a does not apply). The per-application re-check
  (`oidc_revalidate_minutes`, only with several clients) limits that for forward-auth; otherwise
  the way is: disable in the panel or end the account's sessions.
- **API keys** hang on no session: "end others" leaves them standing, "end everything", the
  block and the admin reset revoke them — **a no from the identity provider (4a) does not**.
- **Step-up** is a deadline on the session (`stepup_max_age_sec`, default 15 min), not a session
  of its own: it lapses, the session stays.

## Changing username and address (self-service)

Since 2026-09-25 everyone changes both on the account page, with a fresh step-up — the
username not alongside LDAP (`ldap_enabled`, since 2026-09-27): there the names come from the
directory, and a local account could take the name of a person who has never signed in
and thereby lock them out (an identifier belongs to exactly one account). Renaming there
only as operator (panel, `tinysesam rename`); for the same reason `allow_signup` alongside LDAP is a
setup error. Everything that hangs on the
account — sessions, keys, factors, roles, bindings to OIDC/LDAP/SAML — hangs on the
**account ID** and stays. Outwardly `Remote-User` and `Remote-Email` change; stable is
**`Remote-Id`** — an app should map users by that.

> **Names become free again.** If an account is deleted or renamed, another account can take over
> the name (or address) and then carries it as `Remote-User` into every app. An app that ties rights
> to the name ("alice may use project X") hands them to the successor. Always bind rights
> to `Remote-Id`.
>
> Inside TinySesam itself, an identifier starts for the account with its **joining** — creation,
> renaming, address change, adding an address later (G2, since 2026-09-26; until then with the creation
> of the account). What stood under it before does not belong to it: failed attempts by a stranger under the
> then free name are not cleared by the new holder's sign-in (they keep counting in the
> throttle of the IP they came from), the account page shows no sign-in of the previous owner, and
> deleting does not rewrite that owner's audit rows. The series of consecutive failed attempts (B2-6),
> by contrast, ends entirely with the first full sign-in: it has no IP and protects only whoever the
> identifier now belongs to. Accounts from before then have no such boundary stored — for them the
> creation still applies.

| | Rule |
|---|---|
| Username | free in names AND addresses; no control characters, at most 150 characters; no `@`, except the own confirmed address; no name from `admin_identifiers` (same answer as "taken"); in the mode `login_identifier="email"` not changeable by oneself — the name follows the address. A self-chosen name never binds via LDAP/SAML (G2-N, see "Managing federated identities"). Switch `self_service_username_change` |
| Username, as operator (G13) | panel "Rename" or `POST <admin_path>/api/users/{id}/username` with `{"username": …}` — the same rules (400 with reason), plus the owner protection: an owner account is renamed only by an owner. Independent of `self_service_username_change`. The name counts as assigned by the operator: the "self-chosen" flag (G2-N) is dropped, the audit row says `by=operator actor=<admin>`. Without a running service: `tinysesam rename --db <file> <name> <new-name>` (`#<id>` instead of the name, e.g. for a name with control characters) — the same basic rules; the CLI knows neither a name from `admin_identifiers` nor the mail mode (it reads no configuration), and `on_security_event` does not fire there. Audit `username_changed … source=cli` |
| Address | link to the NEW one (`email_change_ttl_min`, default 60); only the click makes it the account's address, with proof. An address already taken gets no link — otherwise everything is the same (no oracle, G12b): the same answer, the same notice to the own address, the same quota of the account, the same display on the account page and the same work of the database (a throwaway token that has already expired at creation; `gc()` clears it). An address from `admin_identifiers` likewise gets no link — otherwise a foreign account would, after the holder's good-faith click, carry the allowlist address in use and be first admin. At the click both are checked once more (409). The mail names the account; the request itself already goes as a notice (without link) to the previous confirmed address — for every target, also a taken one. An open change falls with every defence: password reset (also by the admin), password change, "end all/other sessions" — otherwise an intruder who requested it from their session would click their link afterwards. Afterwards: open links to the old address invalid, notice to the old one (ASVS 6.3.7). Needs a mailer. Switch `self_service_email_change` |

Events: `username_changed`, `email_changed` (`on_security_event`), audit rows
`username_changed`, `email_change_requested`, `email_change_taken`, `email_change_reserved`
(allowlist address), `email_changed`, `federation_email_confirm` (link to an address from
LDAP/SAML, written only after sending, detail `account=<id> source=… to=…`); the rows
`email_change_*` from this path begin with `account=<id> source=…`. The account page
always shows a request as `email_change_requested` and `federation_email_confirm` not at all
(G12b) — the real names appear only in the operator's audit log; a rejection at confirmation
(`on_confirmation=1`, 409) keeps its name there. The links
of a change have their own quota per target address (bucket `wechsel`) — requests by strangers for
an address do not use up that of the sign-in link — and one per account
(`mail_per_address_max` in the window `mail_per_address_window_sec`, audit `mail_ratelimit`), so that
an account does not scatter mails to arbitrarily many foreign addresses. The same path confirms addresses from LDAP and
SAML (table under "Managing federated identities").

## Identifier space: name and address belong together

`find_user` looks an identifier up in usernames AND addresses, and the lockout counter folds more
coarsely than the database (NFKC, lowercase, IDNA: `Alice`/`alice`, `Émile`/`émile`, `ｂｏｂ`/`bob`,
`u@bücher.example`/`u@xn--bcher-kva.example`). Both columns are therefore **one** space: no
identifier belongs to two accounts.

- **Since 2026-09-26 the database enforces this** (triggers `trg_users_kennung_insert` and
  `trg_users_kennung_update` over the counting buckets `topf_name`/`topf_mail`). Before, only
  TinySesam checked before writing; two simultaneous requests for the same identifier (two workers, one as
  name, one as address) both got through or ended with a 500. Now the loser gets
  the same answer as for a taken identifier — 409, with registration with confirmation the
  neutral page. Whoever calls the store directly (`store.create_user`, `set_username`, `set_email`)
  gets `sqlite3.IntegrityError` ("tinysesam: identifier taken"; up to 0.24.x "tinysesam: kennung vergeben").
- **Collisions in existing data** (from an older version, a raw UPDATE, a row from a
  foreign writer) stay in place — the start does not fail on them, and nothing is renamed
  automatically, because which account keeps the identifier is for the operator to decide. They cannot
  be made worse any more. The start reports each with the accounts involved
  (`Kennung '<x>': user_id=…, user_id=…`) until it is resolved. Resolve: in the panel
  ("Rename"), with `tinysesam rename --db <file> '#<user_id>' <new-name>` (G13), the holder
  on the account page; from the embedding service `auth.change_username(user_id, new_username,
  by_operator=True)` or
  `store.set_email(user_id, address)` (stores the address unconfirmed, `verified=True` for
  proof); as a last resort a manual UPDATE with the instance stopped — TinySesam then recomputes the bucket
  itself.
- **Limits:** A row from a foreign writer (older version after a rollback,
  sqlite3 tool) carries no bucket and counts for the triggers only once TinySesam has
  filled it in — at start and before every creation. If a foreign writer changes name or
  address, the identifier counts as having only just joined (triggers `trg_users_topf_name`/`_mail`):
  stricter, never looser. A raw UPDATE that renames into a collision
  is not prevented, only reported at the next start. If the triggers cannot
  be created (file read-only), TinySesam starts anyway and says so in the log.
- **Rollback to 0.20.x:** The triggers stay in the file and keep acting there (0.20.x writes
  the buckets along; only built-in SQL functions, so no "no such function"). In a race 0.20.x
  then answers with 500 instead of a collision. Remove with the instance stopped:
  `DROP TRIGGER trg_users_kennung_insert; DROP TRIGGER trg_users_kennung_update;` — a newer
  version recreates them at the next start.

## First-admin one-time token

If there is no admin (fresh instance, or the identity provider withdrew the last one),
TinySesam issues a one-time token for `/auth/claim-admin?token=…` — at start and at the moment of
such a withdrawal. Where it goes is decided by who reads along ([T-17](../backlog/T-17-claim-token-not-in-container-log.md)):

| Situation | Where the token goes | What the log says |
|---|---|---|
| `admin_claim_token_file` set | that file, `0600` (also on a console) | the path |
| stderr is a console (`isatty`) | stderr | "is on the console (stderr), not in this line" |
| stderr is not a console (container, journal, pipe) | `<db_path>.claim`, `0600` | the path |
| … without database file (`:memory:`) or file cannot be created | stderr (fallback) | honestly: stderr is not a console, so the value stands in the service's log |

In a container therefore: `docker exec <container> cat /data/app.db.claim` (path from the log), sign in,
open the URL. After redemption TinySesam deletes `<db_path>.claim`; if there is an admin at start,
it clears a leftover. If the token expires, the file content is invalid,
and the next start writes a new one. A self-chosen `admin_claim_token_file` stays
(its path may be a mounted secret), its content is no longer valid after redemption.
Up to 0.21.x the token without `admin_claim_token_file` always went to stderr — in a container it
therefore stood in `docker logs`, directly before the line "The value is deliberately NOT in the log". Whoever ran such an
instance before an admin existed: the log counts as an accomplice; the token was valid only until
the first admin.

## Owner

Owners are admins who cannot be deleted, disabled or stripped of their rights. There is always at least
one; the role can be passed on, several can be owners. Only an owner grants it, and
only an owner changes an owner account (password, API keys, passkeys, sessions, block, roles) — otherwise
an admin would set the owner's password and be one themselves.

| What | How |
|---|---|
| Grant / give up owner | panel "Make owner" / "Give up owner" or `POST <admin_path>/api/users/{id}/owner` `{"owner": true|false}` — only as owner; giving up only if another remains |
| Code | `auth.set_owner(uid, True|False)` (`StateError` for the last owner, `ConfigError` for a service / disabled account) |
| Hardening values (lockout thresholds, rate limits, password lengths, PIN attempts) | only an owner saves them (`POST <admin_path>/api/security`, otherwise 403); any admin may read. With no owner in the data as before any admin |
| Delete an account, as operator | panel "Delete", or without a panel / a running service `tinysesam delete --db <file> <user>` (`#<id>` instead of the name) — the same route (`Store.konto_entfernen`, audit anonymised as `deleted#<id>`) and the same protection (an owner and the last admin are not deleted; the rule is `Store.loeschsperre`, shared by both). Asks on a terminal, `--yes` for scripts, no terminal and no `--yes` refuses. Audit `user_delete … source=cli` |
| Emergency route (no owner can reach it any more) | `tinysesam owner --db <file> <user>` — whoever has the database operates the instance anyway |
| First owner | the first admin (`/auth/claim-admin`, `admin_identifiers`, `ensure_admin`); in existing data the oldest **active**, manually set admin — no service account, not disabled (`owner_grant` in the audit log). If there is none (only admins from the identity provider or disabled ones), the instance stays without owner and the log names the emergency route |

An owner is always an admin "by hand" (`is_admin=1`): no identity provider takes the right from them (H-5).

## Keys for the TOTP secrets

TOTP secrets are stored AES-256-GCM-encrypted in the database (H-14/H-15, mandatory). The
key (32 bytes, Base64) comes from `TINYSESAM_SECRETS_KEY`, otherwise from `secrets_key_file`, otherwise
from `<db_path>.key` (created at the first start, 0600, with a warning in the log; atomic, even if
several workers start for the first time simultaneously).

- **Back it up separately.** Without the key all TOTP setups are lost; the database
  alone is of no use for that — and that is exactly the point. `tinysesam backup` reminds you of this.
- **Next to the database** it protects against a database file that leaks on its own, not against
  a backup of the whole directory. For real separation use the environment or a file in
  another place (Docker secret).
- **Wrong key** → the start aborts (`ConfigError`) instead of letting every TOTP sign-in fail
  silently — checked against TOTP secrets and refresh tokens, so also on an
  instance without TOTP. SQLite overwrites deleted data (`secure_delete`), so that a replaced
  plaintext does not remain in free pages of the file. A key change (rotation) does not exist yet.
- Also with this key: the refresh tokens of the OIDC sessions (below).
- **Derived** from it (HKDF, own context): the signing key of the gate tokens (below). Whoever
  changes the base key also changes that one — the proxy then needs the new public
  key.

## Gate token in front of third-party applications (ADR-9)

With `gate_token_enabled=True` (gateway: `TINYSESAM_GATE=1`) the proxy checks a short-lived
cookie itself and asks `/auth/forward` only when it is missing or expires. Template:
`deploy/forward-auth/Caddyfile.gate`.

- **Caddy needs the plugin caddy-jwt.** The official image does not have it; it is built from
  `deploy/forward-auth/caddy-gate/Dockerfile` (Caddy version and plugin pinned). A Caddy without
  the plugin does not start at all with the template (`unrecognized directive: jwtauth`).
- **Public key for the proxy:** `tinysesam gate-key --db <file>` — with the same
  environment as the service (`TINYSESAM_SECRETS_KEY` or `--secrets-key-file`). Without a base key
  the command aborts instead of creating a new one. In the Caddyfile as `TS_GATE_PUBKEY`.
- **Issuer:** `base_url` without a trailing slash (`TS_GATE_ISSUER`); without `base_url`
  `tinysesam`.
- **Audience:** the application's host, with required roles including their specification:
  `app.example.com|roles=admin,redaktion` (roles sorted, several `X-TinySesam-Roles` entries joined
  with `;`). If `audience_whitelist` contains a different string, every request falls back to the
  fallback path — safe, just as slow as without the gate. One role specification per host is the simple case;
  several paths with different roles on the same host overwrite each other's cookie.
- **When a token is issued:** only for a full session (no API key), only for hosts from
  `trusted_redirect_hosts`, `oidc_clients` or `base_url`, only after the check has passed
  (approval of the application, roles).
- **Revocation:** signing out, blocking, an approval withdrawn at the provider take effect at the proxy only when
  the token expires (`gate_token_ttl_sec`, default 300, allowed 30–3600). If you must block immediately:
  in the Caddyfile temporarily set `audience_whitelist` to a value that no token carries, and
  reload Caddy — then every request goes through `/auth/forward`, where the revocation is already
  effective. Restore after the lifetime has expired. **Do not** change the base key: the
  TOTP secrets hang on it, TinySesam does not start with a different one (above).
- **Caddy log:** An expired or foreign token is written by caddy-jwt as `invalid token` at level
  `error` — that is the fallback path, not an outage. So is every request with an
  `Authorization` header that is not a gate token: caddy-jwt always checks this header too.

## Managing federated identities

A foreign identity is **bound** to a local account — via an identifier that belongs to the foreign
side and does not change:

| Source | Bound via | Table |
|---|---|---|
| OIDC | `iss` + `sub` | `oidc_identity` |
| LDAP | `objectGUID` / `entryUUID` (`_stabile_kennung`) | `federated_identity` (`quelle="ldap"`) |
| SAML | `NameID` | `federated_identity` (`quelle="saml"`) |

- **First sign-in**: If there is no binding yet, the account is looked up by name or created with
  `*_auto_create` and then bound. An existing, still unbound account binds the
  sign-in via its **name** only within a deadline (G1, since 2026-09-26):
  `federation_name_binding_days` (default 30) days from the first start with the source switched on —
  for existing data therefore from the update — or from the creation of the account, whichever is later (a
  pre-creation in the panel has its own deadline). After that it is rejected: a dormant account
  (someone has left) would otherwise fall, with roles and admin right, to the next person who gets the same
  name in the directory. The rejection writes `<quelle>_namensbindung_zu` to the audit log
  and a line to the security log with identifier and remedy. `0` = only explicitly,
  `-1` = unlimited as up to 0.20.x (the configuration check warns). The same applies to the replacement
  of an origin placeholder and — for a source without a stable identifier — to the first
  assignment of an existing account.
- **A self-chosen name never binds via the name** (G2-N): accounts from registration
  (also with an invitation) and accounts that were renamed on the account page
  (`users.name_selbst_gewaehlt`) are bound by no sign-in via LDAP/SAML — otherwise a
  local account names itself after someone from the directory and, at that person's sign-in, inherits identifier and
  groups. An account created by the operator does not carry the flag; panel and `tinysesam rename`
  rename as operator (the flag is dropped), whoever renames from the embedding service passes
  `auth.change_username(uid, new_username, by_operator=True)`. For existing
  data the first start fills in the flag once from the audit log (`signup`,
  `username_changed` under today's name, from creation on) — what the retention has already
  deleted remains undetected.
- **A name from another source likewise never binds** (attack round 2026-09-26): An account
  that OIDC, SAML or LDAP created carries the name the person has there — with an IdP
  with self-registration a self-chosen one (`preferred_username`, NameID, `uid`). The creation
  remembers the source (`users.name_quelle`), and another source never binds the account via the
  name (`name_from_other_source`, in the audit `reason=name_from_other_source`); otherwise someone picks
  `chefin` at the IdP and, at the
  LDAP sign-in of the real chefin, gets her identifier and groups. The same source keeps replacing its
  placeholder (switching on `ldap_attr_id` later, see below). Renaming resets the origin.
  Existing data: the first start fills it in once where it is documented — OIDC accounts (the
  callback creates every linked account itself) and bindings from the second of creation; accounts
  from before the identifiers (up to 0.19) stay without and hang on the deadline. **Several sources from the
  same directory** (Keycloak in front of LDAP, plus the direct LDAP login): the second source does not bind
  an account of the first via the name; individual accounts are opened with
  `auth.federation_unbind(source, user_id)`. Whoever creates their own accounts from a further identity
  provider passes `create_user(…, self_chosen_name=True)`.
- **Binding existing accounts** (F-11, G1): without waiting for the sign-in — dormant accounts
  never sign in. While the deadline runs, the start message names the number of accounts without
  identifier per source. Once after the update, from the embedding service:

  ```python
  bericht = auth.federation_bind_existing("ldap")          # dry run: writes nothing
  for teil in ("bound", "conflict", "ambiguous", "not_in_directory", "no_identifier",
               "refused", "local_password"):
      print(teil, [(e["username"], e.get("local"), e.get("directory"), e.get("reason"))
                   for e in bericht[teil]])
  auth.federation_bind_existing("ldap", apply=True)       # only after reading
  ```

  LDAP searches, for each account without identifier, in the directory (service account or anonymous; with
  `ldap_user_dn_template` a BASE search on the DN — the directory must allow reading) and
  requires exactly one entry; an outage aborts before the first write. SAML has no
  search path: `mapping={"accountname": "nameid", …}` (e.g. from an export of the IdP) — the same works
  for individual LDAP accounts. Accounts with a local password are only reported (`local_password`),
  self-chosen names and names from another source are rejected (`refused`, `reason`). **Before
  `apply=True` read the report:** if a name had already been reused before the run, this path too
  binds the wrong person; `local` and `directory` therefore appear side by side. Up to 0.21.x
  the parts and fields were German (`gebunden`, `abgewiesen`, `lokal`, `verzeichnis`, `grund` …;
  table in the CHANGELOG for 0.22.0). Every binding is in the audit log (`<source>_identifier_bound
  detail=migration`), the run as a summary line in the security log. A CLI command is deliberately missing:
  LDAP and SAML run only embedded.
- **An account carries exactly one identifier per source.** If a new identifier appears in the directory under the same
  name (account deleted and recreated), the local account is **not** taken over.
- **Move in the directory** (the old identifier is really dead) and **opening explicitly** (deadline
  missed, self-chosen name, name from another source, pre-creation with `0`): `auth.federation_unbind(source,
  user_id)` dissolves the binding for LDAP/SAML and opens binding via the name for the next
  sign-in — for `max(federation_name_binding_days, 1)` days or until it is in place. The operation
  is in the audit log (`<quelle>_kennung_geloest`). For OIDC there is no call of its own — there
  the identifier `sub` of the provider is stable by definition.
- **Switching on `ldap_attr_id` later** (source has so far run without identifier): The accounts then carry only
  the origin placeholder and bind via the name only within the deadline — after it run
  `federation_bind_existing("ldap")` first.
- **Approvals per application** (several OIDC clients): `auth.store.drop_oidc_grants_for_user(user_id,
  client=None)` withdraws them immediately without ending the session — the way when the provider
  has excluded someone from an application. There is no public method for it yet;
  `auth.store` is internals (tier C, without commitment).
- **Groups from the provider** (`apply_idp_groups`) are taken over at every sign-in and
  withdrawn when they disappear at the provider — mapped roles always, since H-5 also the
  admin flag, **provided the provider granted it** (`users.is_admin=2`). An admin from panel,
  CLI, `admin_identifiers` or `/auth/claim-admin` stays, an owner anyway. If it was the last
  admin, the allowlist stays closed afterwards (G6, below).
- **Groups come only if the provider sends them** ([T-16](../backlog/T-16-group-scope-warning.md)).
  PocketID (also Authentik, Keycloak without its own mapper) sends the claim `groups` only with the
  scope `groups`; the default `oidc_scopes="openid profile email"` does not request it. Then
  `oidc_allowed_groups` rejects everyone (audit `oidc_group_denied`), and `oidc_group_role_map`
  assigns no role. The start warns as soon as a group rule runs via the claim `groups` and
  the scope is missing — per client, also for `oidc_clients` with their own `scopes`. Remedy:
  `oidc_scopes="openid profile email groups"` (gateway: `TINYSESAM_OIDC_SCOPES`). TinySesam
  requests nothing on its own: if a provider delivers the claim through a mapper without a scope, the
  warning is moot, and Entra ID even rejects a scope `groups` (AADSTS650053; there
  groups come via "optional claims", the check stays silent for this issuer). **SAML and LDAP**
  have no counterpart in the configuration: whether the IdP releases the attribute `saml_attr_groups`
  or the directory delivers `ldap_group_attr` (`memberOf`; with OpenLDAP only with the memberof overlay)
  is decided on the other side. The symptom is the same — `saml_denied reason=group`
  or `ldap_group_denied` in the audit log for everyone.
- **Revocation follows the provider (4a).** An OIDC session carries its refresh token (encrypted);
  every `oidc_session_refresh_minutes` (default 15) the next request triggers the exchange — one row
  per client, in the background (the request does not wait for the provider; the result applies
  from the request after), and of many parallel requests exactly one exchanges. Disabled accounts
  are not asked about. If the provider refuses, the session ends (`oidc_revoked`), and the
  account's API keys **rest** (below); fresh groups are re-evaluated (a group
  claim that is missing entirely changes nothing). Not reachable → session stays, new attempt after one
  minute. **Prerequisite:** The provider issues refresh tokens (with some only with scope
  `offline_access`, then add to `oidc_scopes`). If it issues none, it stays at the earlier state: the
  session runs until `session_ttl_hours`. **Upper limit without a yes:** If the provider has not confirmed a session
  for `oidc_session_max_unverified_hours` (default 25) — permanent client error,
  provider gone —, it ends (`oidc_unconfirmed` in the audit log). That is not a no from the
  provider: the API keys do not rest because of it. Price: if the provider is away for longer than the limit,
  all OIDC sessions are signed out afterwards. `0` = no limit.
- **API keys follow the provider (finding 8).** For accounts with an OIDC binding a key is valid only as long as
  the provider backs the account: if it says no at 4a (also: removed from the allowed group),
  the keys rest immediately (`api_keys_dormant` in the audit log, rejection `idp_no`). And without confirmation
  within `oidc_apikey_confirm_days` (default 30; login via the provider or refresh exchange with
  yes) they rest as well (`idp_unconfirmed`) — so someone who now works only by script
  and has no session that 4a could re-check is caught too. **Nothing is deleted**: an
  `invalid_grant` does not distinguish between "blocked" and "expired" (RFC 6749 5.2) — the
  next sign-in via the provider wakes the keys. Pure automation belongs on a service account
  (no OIDC binding, not affected). Existing data: the deadline starts with the update. `0` switches off only
  the deadline, the no still counts. With Keycloak note: if the SSO session expires there through
  idling, the refresh likewise answers `invalid_grant` — then the
  TinySesam session ends too, and the keys rest until the next login. **A client error is not a
  no**: `invalid_client` (after a secret rotation), `unauthorized_client`,
  `unsupported_grant_type`, every 401 and every 5xx count like an unreachable provider and
  appear as a warning in the security log; every other 4xx is a no. If an application is taken out of
  `oidc_clients` or recreated at the provider (different `client_id`), 4a discards its
  rows — the sessions then run until their expiry, without re-check.
- **Series lockout (B2-6) and LDAP renaming:** Counting happens under the typed name.
  If an account is meanwhile named differently in the directory than locally (bound via the stable identifier),
  every successful sign-in records the directory name on the binding
  (`federated_identity.name_topf`, only the most recent), and all fallback paths clear it too: the full
  sign-in, the password reset in the panel, `tinysesam passwd` and `tinysesam unlock` (G5, since
  2026-09-26; until then they cleared only the local name and the address, and
  `unlock <directory name>` aborted with "no account"). `tinysesam unlock` takes the identifier as
  typed — name, address or directory name. If it finds no account (existing data: the name is not yet
  recorded, and the sign-in that would record it is blocked), it still clears the
  counters under this identifier and says so; return 1 only if nothing stood there. If the
  directory name locally belongs to ANOTHER account (as name or address), that account's series stays.
  Since 2026-09-27 (audit round lockouts/counters): **An identifier never checks the secrets of two
  accounts.** If the typed identifier locally belongs to one account and the LDAP entry leads to another,
  the sign-in is rejected (failed attempt, `ldap_identifier_rejected reason=identifier_of_two_accounts
  local=<id> directory=<id|new>`); the remedy is to rename the local account (panel, `tinysesam
  rename`) or the name in the directory. The name on an account's binding is taken for all others
  (registration, renaming, admin API, CLI, database), and whoever renames an LDAP account
  whose name was the directory name leaves it standing as the directory name — the panel reset
  keeps clearing the series under it. Only the account that last signed in this way carries the name;
  if two carry it (existing data), it counts for neither, and `unlock` clears under it without naming an
  account.
- **`admin_identifiers` after an IdP withdrawal (H-5, G6):** If the provider withdraws the instance's
  **last** admin, the allowlist promotes nobody afterwards — neither this person nor any
  other account from the list (setting `allowlist_nach_idp_entzug`, audit `admin_bootstrap_denied
  after_idp_withdrawal`). Until 2026-09-26 it promoted the person back in the same login, as admin "by
  hand" and first owner — a right that no provider withdraws any more and that can be neither deleted nor
  disabled. The emergency routes lead back into the panel: the one-time token that TinySesam issues at the moment of
  the withdrawal (on a console to stderr, otherwise in `<db_path>.claim` or
  `admin_claim_token_file`, valid `admin_claim_ttl_min`, after that renewed at the next start; see
  [First-admin one-time token](#first-admin-one-time-token)),
  and `tinysesam owner --db <file> <user>`. If the provider accidentally no longer delivers the
  admin group (mapping, scope), all admins from the provider lose the right
  at once — **therefore keep at least one owner by hand.**
- **Addresses without proof** (OIDC without `email_verified=true`) are not used: no account name,
  no address in the account, no `Remote-Email` (H-3). If the provider delivers the proof later, it is
  filled in if it is free. For a provider that never sends the claim but verifies every address:
  `oidc_email_verified_default=True`.
- **SAML and LDAP deliver no proof** — the operator says per source whether to trust its addresses
  (PO decisions 2026-09-24 and 2026-09-25):

  | Switch | Default | trusted | not trusted |
  |---|---|---|---|
  | `ldap_email_trusted` | **off** | Address counts as proven: into the account, as `Remote-Email`, carries rights up to first admin via `admin_identifiers` | Address not used directly (as H-3); confirmation by link (below) |
  | `saml_email_trusted` | **off** | as above | as above; in addition an account name with `@` (NameID emailAddress, UPN) gives way to a substitute name `saml-<hash>` |

  Three ways to trust, from the weakest to the strongest demand on the source:

  1. **Confirmation by link — the normal way**, as soon as mail is set up
     (`federation_email_confirm`, default on; needs mailer and `base_url`). After the sign-in
     a link goes to the address from the source; only the click makes it the account's address,
     with proof. The same path as the address change of self-service. Only for accounts without a
     proven address, none while an address-change link of the account is open — to whatever address
     (since 2026-09-27; before only to the same one: as long as the first link sat in the outbox,
     a second worker sent one to a `mail` that had meanwhile changed, and whether it arrived revealed whether
     the first address was taken) —, and at most one **delivered** link per
     account and day (if a link lives longer, `email_change_ttl_min`, for that long) — across all workers,
     counted on the audit row `federation_email_confirm`, which comes into being only after sending
     (G12a). A throttled address or a failed send is retried after
     `mail_per_address_window_sec`. If the address already belongs to another account
     (or is in `admin_identifiers`), no link goes out; the rejection
     (`email_change_taken` or `_reserved`, detail `account=<id> source=…`) counts like a send,
     likewise across all workers — otherwise its count on the account page would reveal whether a foreign
     address is taken (attack round 2026-09-26). Remaining: if sending to a free
     address fails, the next sign-in tries again after the window. The same applies if the
     outbox is full: the link expires immediately, instead of holding up the next one as an open one until its
     expiry (likewise for the address change of self-service).
  2. **Proof attribute** for IdPs that carry one: `ldap_attr_email_verified` or
     `saml_attr_email_verified` names an attribute whose true value (`true`, `1`, `yes`) proves
     the address of THIS login — e.g. a Keycloak mapper on `emailVerified`. Viable only
     if users cannot set the attribute themselves. It proves the **address, not the
     name**: with SAML an account name with `@` (NameID emailAddress) stays only if it is exactly the
     proven address — otherwise substitute name `saml-…` and no assignment via the name, as with
     OIDC with `email_verified`.
  3. **Blanket switch** for maintained sources: `ldap_email_trusted=True` for a directory
     in which nobody changes their `mail` attribute themselves; `saml_email_trusted=True` for a
     company IdP without self-registration. Whoever sets it where users maintain their address themselves
     reopens F-14: someone enters the address from `admin_identifiers` and is first admin at the
     first login.

  A trusted login that proves the same address already on the account only upgrades it; an account
  without an address gets it if it is free. A new value in the source does not change the address
  of an existing account — the holder does that themselves via the account page.
  With a source that is not trusted, an unproven name is **never assigned via the name** to an existing
  account — only via the stable identifier, otherwise rejected. Unproven: with SAML a name
  with `@` (NameID emailAddress) or one from the address attribute itself (`saml_attr_username` =
  `saml_attr_email`); with LDAP an input that equals the `mail` value of the entry found
  (a filter like `(|(uid={username})(mail={username}))`, also with `mail=chefin` without `@`). A UPN
  as bind identifier remains an account name. If such a filter hits the identifier of ANOTHER local
  account, the sign-in of the directory entry is rejected (since 2026-09-27,
  `reason=identifier_of_two_accounts`; from 2026-09-26 on it merely did not clear the holder's failed attempts,
  before that every sign-in of the third party reset her account window). New accounts with an
  unproven name are named `saml-…` or `ldap-…`. Whoever does not want these
  names and trusts the IdP sets the switch. An identifier with edge whitespace or
  control characters is rejected by TinySesam instead of trimmed (it would otherwise fall onto a foreign binding).
- **First admin**: A federated address makes an admin only with proof (`email_verified` for OIDC;
  for SAML/LDAP the switch above). The safe way is `/auth/claim-admin` (F-14).

### Measured (T-24, 2026-10-07)

`scripts/gate_measurement.py`: TinySesam as one process (like the gateway image), Caddy 2.11.7 with
caddy-jwt v1.4.0 and `Caddyfile.gate`, the application a static response; load with `hey`, 3000
requests per row, all on a desktop machine (6 cores):

| concurrent | Path | Throughput | Median | 95 % |
|---|---|---|---|---|
| 1 | `/auth/forward` per request | 2 450 /s | 0.40 ms | 0.60 ms |
| 1 | gate token | 7 500 /s | 0.10 ms | 0.20 ms |
| 20 | `/auth/forward` per request | 3 200 /s | 6.30 ms | 7.50 ms |
| 20 | gate token | 40 000 /s | 0.40 ms | 0.90 ms |

For single requests the gate saves about 0.3 ms. The difference arises under concurrency,
that is exactly when a browser loads a page's assets in parallel: a check per request
puts them in a queue at TinySesam (about 3 000 checks per second, median 6 ms), the token
is checked by Caddy itself (factor 12 to 13). If TinySesam sits on a different machine than the proxy, the network path
is added per check — it is missing here. A first attempt with a Python client measured its
thread management instead of the gate; hence `hey`.

### Acceptance per application

`deploy/forward-auth/acceptance.sh` checks a real deployment from outside: sign-in required, a
self-supplied `Remote-User` opens nothing, `/.tinysesam/*` reaches TinySesam, the share path
is open and its path tricks stay shut; with the session cookie of a test account additionally gate token,
tampered token, "sign out only here". `tests/test_gate_caddy.py` runs the script against the
test setup, including a counter-check (a wrong expectation must turn it red).

```bash
APP=https://app.example.com SHARE=/s/abc123 SESSION='__Host-tinysesam_session=…' deploy/forward-auth/acceptance.sh
```

## One central gateway for many applications (code exchange, T-26)

`gate_link_enabled=True`, `base_url` = address of the gateway, **no** `cookie_domain`, `gate_token_enabled=True`.
On every app host the proxy forwards `/.tinysesam/*` to the gateway (both templates do this) and serves
the gateway itself under its `base_url`.

- **Flow:** app without a connection → `/.tinysesam/start` (flow + binding cookie only for the app host) →
  `/auth/gate/authorize` at the gateway (session, otherwise sign-in; approval of the app at the provider; "signed out
  only here" → page with "Continue as …") → one-time code, 120 s → `/.tinysesam/callback` (code, host and
  binding must match) → connection cookie `__Host-tinysesam_link`, host-only, until the end of the session.
- **What the app sees:** none of this — the proxy removes all `tinysesam_*` cookies before it. A
  connection cookie that it picked up anyway would be valid only for its own host.
- **App with its own TinySesam behind it** (0.24.12): It sets `cookie_prefix` (e.g. `"myapp_"`), otherwise the
  proxy removes its cookies too — the OIDC return then fails for lack of the flow cookie, and one lands at the
  login again. The gateway itself stays with `tinysesam_`.
- **Revocation:** session ended (sign out everywhere, block, admin) → every connection ends with it; at the proxy
  as before only when the gate token expires.
- **Sign out everywhere without a connection** (the app was already signed out "only here"): The app host forwards to
  `/auth/gate/logout?host=…` at the gateway, where the session ends. From a foreign site, the confirmation
  prompt on the app host comes first (logout CSRF).
- **Language:** `TINYSESAM_LANG=de` for German gateway pages (default `en`).
- **Schema 14:** table `gate_link`.

## Public paths of an application (share links, T-20)

Both Caddy templates have a block `@share` that lets paths through without sign-in — without
identity and without the TinySesam cookies. By default it is off (`^$`); it is switched on
with `TS_SHARE_PREFIX`, a regular expression over the beginning of the path:

```
TS_SHARE_PREFIX='^/(s|index\.php/s|apps/files_sharing/publicpreview)/'
```

- **Measure instead of guess.** A share page loads its own scripts and calls its own APIs. Open the
  page in the browser (without signing in), look in the developer tools at every request that goes with
  302 to the sign-in, and include only what belongs to the share page.
- **Never by file extension** (`\.js$`): Many applications serve dynamic content
  under `/admin/x.css`.
- **What the rule rejects** (measured with Caddy 2.11.7, `tests/test_gate_caddy.py`): `.` and
  `..` segments in the raw path (`/x/../s/a` — Caddy would otherwise compare the cleaned path, the
  application would get the raw one), also with a path parameter (`/s/..;/admin` is read by Tomcat and Spring as
  `/admin`), backslash, NUL and their encoded forms, wrong upper/lower case (`/S/`), `//s/`. A `..` in the
  query and in a file name (`a.b..c`) remains allowed, and so does a `;` or `%3B` in a file name
  (`/s/<token>/file_%3B%29.bin`; the rule rejected every `;` until B-3 was fixed — copied templates need the new line).
- **What stays open:** These paths are publicly reachable. A vulnerability of the application there is not protected
  by the gate — keep them as narrow as possible.

## Signing out at the application — checklist per application (T-22)

For each application behind the gate, in this order:

1. **Proxy:** `/.tinysesam/*` to TinySesam (contained in both Caddy templates), before the gate.
2. **Application:** its sign-out link or its redirect after signing out points to
   `https://<app>/.tinysesam/logout` (with `?scope=app` or `?scope=all`, otherwise `forward_logout` applies).
   If it signs out at the provider itself (RP logout), its Logout Callback URL points to
   `https://<app>/.tinysesam/after-logout`.
3. **Provider:** enter `https://<app>/.tinysesam/after-logout` as Logout
   Callback URL in the OIDC client of the **gateway** — for every application where "sign out everywhere" should be possible. Without
   the entry PocketID ends its session anyway, but afterwards shows its own page instead of
   redirecting back. With several clients (`oidc_clients`) the address belongs to the client through which the
   sign-in ran.
4. **Counter-check:** sign out; afterwards the application must lead to the sign-in, and with `all` a second
   application in the same browser at the latest after `gate_token_ttl_sec`. In mode `direct` "Signed out"
   is shown for `forward_logged_out_sec` seconds (default 10), then the provider's sign-in page follows — **with**
   a click on Sign in. If the provider instead silently signs in again, its logout has not taken effect
   (check the Logout Callback URL from point 3).

`app` and `direct` together: signing out "only here" holds because the application afterwards always shows the
login page (never the direct path to the provider) — with "Continue as …" for the way back.

## Rollback to 0.21.x

(Schema **13**, after 0.22.0: two new tables `gate_abgemeldet` and `oidc_id_token`, nothing else. 0.22.0
opens the file with the warning "newer schema version" and leaves both in place. Only
"signed out only here" and the `id_token_hint` at the provider logout are then missing.)

0.22.0 raises the schema stamp of the database to **12**. No column changes, but two
stored values are now named in English like the rest of the public surface (PO decision
2026-09-27): the kind of an API key (`api_key.kind`: `automat` → `automation`, `mensch` → `human`) and,
in the open address-change link, the key for the previous address (`alt` → `old`, visible via
`peek_magic`/`redeem_magic`). The first start rewrites them and says so in the log (`… gespeicherte
Werte auf die englischen Namen umgeschrieben`). An old value is still read correctly, and
every start updates the API keys that an older version has meanwhile issued. The
audit rows stayed as they were under 0.22.0: `apikey_create`/`apikey_use` kept naming the kind
as `art=automat`/`art=mensch` (since schema 15 they say `kind=automation`/`kind=human`, see
"Rollback to 0.24.x"). (If 0.21.x runs on the migrated file without the SQL below, it writes
`art=automation`/`art=human` — it outputs the stored value raw.)

**What 0.21.x does with a migrated file** (measured with 0.21.0): It starts and warns once at
start: `The database carries schema version 12, this TinySesam version only knows 11. …`.
It does not know `human` and takes such a key for an automation key — **it then acts without a
session**, with the rights of its account without the admin flag. A human key that was previously worthless on its own
is valid on its own under 0.21.x. `automation` keys act there like `automat`. The payload
of the links is not read by 0.21.x. What it issues itself carries the old values again; 0.22.0 reads
them and rewrites the keys at the next start.

**Therefore before the first start of 0.21.x** — service stopped, backup taken (`tinysesam
backup`, not `cp`):

```sql
UPDATE api_key SET kind = 'automat' WHERE kind = 'automation';
UPDATE api_key SET kind = 'mensch'  WHERE kind = 'human';
UPDATE magic_token SET payload = json_object('alt', json_extract(payload, '$.old'))
 WHERE purpose = 'email_change' AND json_extract(payload, '$.old') IS NOT NULL;
PRAGMA user_version = 11;
```

For example `sqlite3 auth.db < rollback.sql`, or from Python
`sqlite3.connect("auth.db").executescript(open("rollback.sql").read())`; `json_object` needs
SQLite 3.38 or JSON1 (included in the Python images). Afterwards 0.21.x no longer reports a newer
schema version, and a human key again applies only with a session. The stamp 11 is correct:
no column was added, and a later start of 0.22.0 migrates again. `tests/test_values_english.py`
runs exactly this block. Without the SQL 0.21.x runs too — then what was said above applies to human keys
until 0.22.0 starts again.

## Rollback to 0.24.x (schema 15)

**Take a backup before the update** (`tinysesam backup`, not `cp`). The first start of the version with schema
**15** rewrites the stored and logged key vocabulary to English (PO decision 2026-10-29; no column changes) and
says so in the log (`… stored values rewritten to the English vocabulary (schema 15 …)`):

| Where | Up to 0.24.x | Since schema 15 |
|---|---|---|
| `audit.event` | `oidc_widerruf`, `oidc_unbestaetigt`, `api_keys_ruhen`, `lockout_serie`, `sperrhinweis`, `recovery_verwaist_geloescht`, `login_lokal`, `<oidc\|saml\|ldap>_kennung_abgewiesen`/`_gebunden`/`_geloest`/`_ungueltig`/`_wechsel`, `_namensbindung_zu`, `_ohne_kennung` | `oidc_revoked`, `oidc_unconfirmed`, `api_keys_dormant`, `lockout_series`, `lockout_notice`, `recovery_orphan_deleted`, `login_local`, `<…>_identifier_rejected`/`_bound`/`_unbound`/`_invalid`/`_change`, `_name_binding_closed`, `_without_identifier` |
| `audit.detail` (keys) | `grund=`, `konto=`, `quelle=`, `durch=`, `akteur=`, `alt=`, `neu=`, `an=`, `anzahl=`, `beleg=`, `verlangt=`, `verwendet=`, `nachgetragen=`, `fehlversuche=`, `in_folge=`, `kennung=`, `lokal=`, `verzeichnis=`, `zweck=`, `fehlt=`, `art=`, `rollen=`, `beim_bestaetigen=`, `nach_einschreibung=`, … | `reason=`, `account=`, `source=`, `by=`, `actor=`, `old=`, `new=`, `to=`, `count=`, `proof=`, `required=`, `used=`, `backfilled=`, `failed_attempts=`, `in_a_row=`, `identifier=`, `local=`, `directory=`, `purpose=`, `missing=`, `kind=`, `roles=`, `on_confirmation=`, `after_enrollment=`, … |
| `audit.detail` (tokens behind `reason=`, `source=`, `by=`, `kind=`) | `kein_konto`, `konto_gesperrt`, `falsches_geheimnis`, `falsches_bereichsgeheimnis`, `kein_passwort_gesetzt`, `wiederholt`, `gruppe`, `idp_nein`, `idp_unbestaetigt`, `betreiber`, `lokal`, `erst_admin`, `automat`/`mensch`, … | `no_account`, `account_locked`, `wrong_secret`, `wrong_area_secret`, `no_password_set`, `repeated`, `group`, `idp_no`, `idp_unconfirmed`, `operator`, `local`, `first_admin`, `automation`/`human`, … |
| `audit.username` | `gelöscht#<id>` | `deleted#<id>` (also inside the details) |
| `fehlserie.art`, `login_attempt.method` | `pin_folge` | `pin_chain` (counts of both kinds are added up if both exist) |
| trigger message (`sqlite3.IntegrityError`) | `tinysesam: kennung vergeben` | `tinysesam: identifier taken` (the trigger is replaced on every start if its definition differs) |

The complete old → new table is in the CHANGELOG. The security log carries `reason=` instead of `grund=`
(the OIDC and passkey lines included — the shipped fail2ban filters match them from now on, so update the filter
files from `deploy/fail2ban/` together with the release), `remaining=` instead of `verbleibend=`, `kind=` instead
of `art=` and `unban=yes|no` instead of `unban=ja|nein`. Existing filters of your own that match the old
German words have to be adjusted.

**What an older version does with a migrated file** (0.24.x): it starts and warns once at start
("newer schema version"). It shows the new event names and keys as unknown names — the panel and
`tinysesam audit` print them — and it does not recognise them where it evaluates audit rows:

* the account page shows a rejected address-change confirmation under its real name (`email_change_taken`
  instead of `email_change_requested`), because it looks for `beim_bestaetigen=1`, not for `on_confirmation=1`;
* the lockout notice is throttled by the row `sperrhinweis`: after the rollback one more notice per lockout window
  can go out;
* deleting an account does not find `old=`/`new=`/`to=`/`actor=` in migrated rows (names and addresses stay in the
  detail text), nor the earlier names and addresses from `username_changed old=…`.

An older version needs no SQL to start. If you want it to read the audit log in its own words again, restore the
backup taken before the update. Setting the stamp back (`PRAGMA user_version = 14`) only silences the warning;
the next start of the newer version then runs the rewrite again (idempotent). New rows written meanwhile carry the
old words and are mapped by the newer version when it reads them.

**The last breaking pass before the API freeze (2026-10-29) changes no stored data** and does not raise the schema
version: it renames a query parameter (`abgemeldet` → `signed_out`), a message id (`err.locked_serie` →
`err.locked_series`), the `--ja` option (→ `--yes`), the Caddy template variable (`TS_SHARE_PRAEFIX` →
`TS_SHARE_PREFIX`) and a few log texts. Rolling back to the version before it needs no SQL; only your own
configuration (the variable, the option, a custom message id) has to go back to the old name.

## Sign-in methods and their strength

**By default TinySesam is single-factor:** a password alone signs in completely. A second
factor applies only when the user sets up TOTP (then it is required at every login) or the
operator enforces a chain (`login_chain=["password", "totp"]`, `login_chain_strict=True`).

Without a chain the **classic policy** applies: one identifying factor, plus TOTP *if* the
account has one. From this follow ways of differing strength to the same account:

| Way (factor) | What it proves | TOTP afterwards (without chain) | Remark |
|---|---|---|---|
| Password (`password`) | knowledge | yes, if set up | LDAP also runs as `password` |
| PIN (`pin`, with `pin_login`) | knowledge (short) | yes, if set up | weaker than a password, deliberately allowed as first factor (ADR-8); lockout via `pin_max_attempts` and the series (`account_max_consecutive_failures`). If a strict chain requires the PIN behind another factor, it is never first factor: no field on the login page, `/auth/pin` without a session 404 (G7, `pin_as_first_factor()`) |
| Passkey (`passkey`) | possession + user verification (`passkey_user_verification="required"`) | **no** — counts as fully valid on its own | strongest way when UV is enforced (B2-10) |
| Sign-in link (`magic`) | access to the mailbox | yes, if set up — likewise a passkey, also in a chain like `["magic"]` and in route chains `require(factors=[…])` (`magiclink_require_second_factor`, default on) | without a second factor the mailbox is the only factor (ASVS 6.3.6) |
| OIDC (`oidc`) / SAML (`saml`) | what the provider has checked | yes, if set up locally | TinySesam does not see whether the provider demanded MFA |
| Password reset by link | mailbox → new password | yes, at the subsequent login | ends all sessions, does not sign in by itself |
| Recovery code | replacement for TOTP, one-time | — | only in the TOTP step |
| API key | possession of the key | never (no interactive factor) | as an automation key carries no admin flag, reaches no step-up route (R6-5, R3-3) and changes no password (`POST /auth/password`, `change_password`: 403, since 0.22.0) |

**The PIN as follow-up factor** (G7, since 2026-09-26): After the first factor of a chain,
`/auth/pin` asks only for the PIN of the account of the half-open session, without a name field — also with `pin_login=False`
(before a dead end); likewise with a full session in a route chain. The half-open session counts there
only if the global `login_chain` requires the PIN, it is still missing and — in a strict
chain — it is the next step (since 2026-09-27): In classic mode with `pin_login=False`, `/auth/pin`
otherwise checked the PIN for everyone who had only the password (wrong 401, right 303), and in
`password → totp → pin` a PIN stood in the session before the TOTP whose order could afterwards never be
fulfilled. Otherwise it is the guest path (or 404). Failed attempts there count in the
series as `pin_chain` (up to 0.24.x `pin_folge`): A self-service reset does not clear them (like TOTP — only whoever has
the first factor produces them), the full sign-in, the password reset in the panel and `tinysesam unlock`
do. Failed attempts of a PIN as first factor (without a session) are still cleared by the reset (R2-2). In a
**non**-strict chain the PIN with `pin_login=True` remains at the same time a first factor, even if it comes
last — guessable without a password, and the reset clears these failed attempts; the configuration check warns
there. If it should be only a follow-up factor: `pin_login=False`.

**The way out of the series lockout** (since 2026-09-27): If the failed attempts after the password
(TOTP, `pin_chain`) alone reach the limit, a password reset does not lift the lockout. Lockout notice
and security log (`Sign-in for user=… locked: … Lift: …`) then do not name the reset: the
notice names only the operator (`tinysesam unlock`, password reset in the panel), the log in addition the sign-in
by another way; the
sign-in page shows everyone the same text ("Ask the operator for approval; if the failed attempts
were for the password, a password reset also helps") — a separate text per kind would reveal that someone is guessing the
second factor and the account therefore exists. The audit row `lockout_series` (up to 0.24.x `lockout_serie`) arises exactly at the
transition of the settled state across the limit (since 2026-09-27; before also when a
simultaneous full sign-in had already ended the series).

**The strength of an account is that of its weakest enabled way.** An account with TOTP or
passkey is protected via the sign-in link just as well as via the password — without a second factor
the sign-in link is as strong as the mailbox. This also holds in a route chain like
`require(factors=["magic"])`: if the account has TOTP or a passkey, it requires it after the link
(G10, since 2026-09-26; until then the mailbox alone opened the route). **A route chain
only tightens the global rule** (PO decision 2026-09-27, "align"): if the session still owes the
global sign-in a factor — TOTP of an account that has one, or the next step
of the `login_chain` —, it goes there first, even with `require(factors=["password"])`; only afterwards
does the route's list count. Until then the route chain overrode the global policy, and
`["password"]` let an account with TOTP in with the password alone.
ASVS 6.3.4 ("all ways equally strong") is nevertheless **not** met by default — the sign-in link without a second factor stays
as strong as the mailbox; a chain does meet it.

## What is missing for ASVS Level 3

TinySesam targets Level 2. Four requirements from V6.3 (ASVS 5.0) belong to Level 3 (B1-12). Since
2026-09-24 three of them are met (6.3.5, 6.3.7, 6.3.8 with confirmation), 6.3.6 for accounts with
a second factor:

| ASVS | Requirement | Status |
|---|---|---|
| 6.3.5 | Notify users of suspicious sign-in attempts | met as soon as sending is configured: if an account lockout takes effect (window or series), a notice goes to the proven address — at most one per lockout window, without a link (`notify_login_failures`, default on). Looked up and sent in the background, the response reveals neither existence nor runtime |
| 6.3.6 | Email neither as sole nor as second factor | partly (PO decision 2026-09-24, option C): if an account has TOTP or passkey, the sign-in via the sign-in link requires it in addition (`magiclink_require_second_factor`, default on; `False` = the link suffices). Accounts without a second factor are still signed in by the link alone — there the mailbox is the only factor. Strictly met only without `magiclink_enabled` |
| 6.3.7 | Notify users after a change of their credentials | met via the opt-in hook `on_security_event` (H-6): it runs as soon as a sign-in factor is created, changed, removed or consumed (password including reset, PIN, TOTP, recovery codes, passkey), also when an admin intervenes in the panel, and since 2026-09-24 also on the revocation of API keys (`api_key_revoked`, collectively `api_keys_revoked`). The hook sends the mail (see SECURITY.md). Without a hook it only logs. Renaming (account page since 2026-09-25, panel since 2026-09-26) reports `username_changed`, the confirmed address change of the account page `email_changed` (the old address gets a notice anyway); `tinysesam rename` and `store.set_email` directly are operator tools and do not trigger the hook |
| 6.3.8 | Valid accounts not derivable from failures | met with `signup_verify_email=True`: same response and computing time at login (`dummy_verify`) and at registration (the same work in both branches, 2026-09-24). Without confirmation, registration inevitably reveals taken addresses (immediate sign-in vs. 409) — the configuration check warns |

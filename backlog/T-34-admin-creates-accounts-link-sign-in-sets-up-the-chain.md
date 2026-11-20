---
id: T-34
type: Task
title: 'Admin creates accounts, a link signs them in: setup pass and alternatives in the factor chain'
status: erledigt
milestone: M-2
tags: [login, magic-link, chain, onboarding, admin]
created: '2026-11-20'
---
# T-34 — Admin creates accounts, a link signs them in: setup pass and alternatives in the factor chain

Wish (PO 2026-11-20): an operating mode "the admin creates the account + sign-in link". Registration is off, the
admin creates accounts, and the first sign-in (= the registration) happens by a link from the admin (T-33:
`create_signin_link()`, panel button, no mail) or by mail. **Afterwards the person must set up what the
configuration demands — only then are they fully signed in.** What is demanded is free: password, TOTP, passkey,
PIN — alone, combined or as alternatives. After that, the regular sign-in through the chain. Optionally: the link
is only for the first sign-in, not a regular way in.

Examples: chain `["password", "totp"]` → open the link → set a password → set up TOTP → in; later password + TOTP.
Chain `["password|passkey"]` → link → set a password OR a passkey → in.

**Gap before:** `login_chain` knew only fixed factors. `["magic", "totp"]` forced the link every time, there were
no alternatives, and a link sign-in under `["password", "totp"]` was a dead end (`magic` ≠ `password`). Setting up
during a half sign-in existed only for TOTP (`totp_enrollment_user`).

Done when: alternatives per chain step work and are checked by `config_check`; a link sign-in of an account that
lacks factors leads through a setup pass; `magiclink_first_login_only` exists; each safety boundary below is pinned
by a test and proven by mutation; README (de+en) has a recipe; CHANGELOG, CONFIGURATION.md, API.md updated.

## Done (2026-11-20)

Built: `tinysesam/_chain.py` (matching rules), the pass in `TinySesam` (`_begin_setup`, `_setup_session`,
`_setup_step`, `_setup_record`, …), `GET /auth/setup` with the page `account_setup`, the setup routes accepting the
pass, `magiclink_first_login_only`. Tests: `tests/test_link_onboarding.py` (functional + every boundary),
`tests/test_browser.py` (`link_setup_pass`: link → password → TOTP + recovery codes → signed in, strict CSP).

### Decisions

- **Alternatives as `"a|b"` inside `list[str]`** — as specified; the frozen surface only grows. A factor satisfies
  at most one step (maximum matching); a strict chain also needs the factors in the order of the steps. For a chain
  without `|` every answer of the engine is the old one (satisfied, next step = first factor not provided), pinned by
  tests. `config_check` refuses empty steps/alternatives, unknown names in an alternative and chains that cannot be
  satisfied with each factor once (`["password", "password"]` was silently `["password"]` before — now an error).
- **Next page with alternatives:** the first option the account has set up (so `X-TinySesam-Factor` stays a single
  factor name, as before); if it has none, the first one named.
- **Deviation from the design draft — the link replaces no factor the account HAS.** The draft said "the chain
  satisfied with the link standing in for the identifying step plus the freshly set-up factors". Taken literally that
  lets the mailbox (or whoever holds the admin's link) skip an existing password: an account with an admin-set
  password but no TOTP would be link + own TOTP = in, and the password never typed. So: every step the account can
  already satisfy is **provided first**, as at any sign-in, and only then are the missing ones set up; a factor set
  up in the pass counts as provided. For the intended case (account created without any factor) the result is the
  same as the draft; for an account that has something, the link opens the door to setting up, nothing more. The
  same principle as `magiclink_require_second_factor` (ASVS 6.3.6): a mailbox never stands in for a factor the
  account has. Consequence: the pass needs no "link counts as step 1" rule at all — the chain is simply satisfied by
  provided + set-up factors.
- **Existing TOTP/passkey first** (even if the chain does not name it): as `totp_enrollment_user` already did — a
  mailbox never sets up factors past an existing authenticator. An operator window (`grant_mfa_enrollment`) lifts
  this, as before (lost device).
- **State of the pass:** a `flow` row keyed by the handle of the half session (no schema change), valid for
  `stepup_max_age_sec` (0 → the session lifetime, the same reading as `login_fresh()`), checked again on every
  request together with the session age, the account lock and `mfa_enrollment_allowed`. Disable and password reset
  end all sessions, and the pass with them.
- **Only the current step is offered** and accepted (the first missing step; its alternatives as a choice). The
  setup routes accept the half session through one door (`_setup_user`); nothing else does —
  `current_user()`/`session_user()` stay None. The first password in the pass goes through a private
  `_setup_password`; the tier-A building block `set_initial_password` is unchanged (it still needs a full session) —
  the pass with its new token is the built-in page's business, the API stays as it was.
- **Order inside the pass is not enforced:** the server dictates the steps, and the strict order protects the
  regular sign-in (e.g. a PIN as a guessable first factor), which keeps `login_chain_strict` afterwards. Without it
  `[password, pin, totp]` with an existing TOTP (shown first) could never finish.
- **`magiclink_first_login_only`:** a link signs in an account that has never been fully signed in, or one that lacks
  a factor of the chain and may set it up itself. Checked at redemption (403, token spent), when issuing
  (`create_signin_link` → `ValueError`) and before mailing (no mail, same outward answer). **Admin link for a complete
  account ("forgot password"): refused as well**, no exception for the admin — otherwise the admin's link would be a
  second key past the chain. The way back: the operator removes the lost factor and opens a setup window; the link
  then opens the pass, the person provides what they still have and sets up the rest. Not applied to the
  cross-device sign-in: its approval comes from a full session of the same account, it is no first sign-in.
- **`magiclink_require_second_factor`** keeps its meaning and still applies at the end of the pass; inside the pass
  the "existing second factor first" rule is the stricter form of it (it also holds with the switch off — setting up
  is more than signing in).
- **Side fix:** `complete_totp` did not note the first complete sign-in (`first_login_at`) — an account whose chain
  ended with the TOTP step stayed "never signed in", so `mfa_enrollment="first_login"` kept its window open, and
  `magiclink_first_login_only` would have let links through forever. Noted there now.

### Mutation proof (each guard broken alone, `tests/test_link_onboarding.py` turned red)

Pass sets only the offered factor · pass expires with the window · pass only after a link · existing factors first ·
one factor fills one step · locked account ends the pass · existing TOTP/passkey first · `magiclink_first_login_only`
· half session stays half until complete · strict order with alternatives · first sign-in noted after TOTP · the pass
decides the TOTP setup (no legacy bypass) · `mfa_enrollment` respected · `config_check` empty alternatives ·
`config_check` unsatisfiable chain · the link opens the pass · `/auth/setup` bound to the pass · only missing factors
offered (nothing replaced).

### Open

- The TOTP page in a regular (non-link) sign-in offers no "use a passkey instead" when the open step is
  `"totp|passkey"`; the account's own factor is asked. A small follow-up if wanted.

# AGENTS.md — working on TinySesam

Guide for AI coding agents (and humans) who change this repository. Building an app **with** TinySesam instead?
Read [`skills/tinysesam/SKILL.md`](skills/tinysesam/SKILL.md). Ground rules for every contributor:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

TinySesam is an authentication library for FastAPI that also runs as a forward-auth gateway. Other projects trust it
with their front door: keep the surface small, every feature optional, and prove every change with a test.

## Layout

| Path | What |
|---|---|
| `tinysesam/manager.py` | the `TinySesam` class: every public method, guards, sign-in building blocks, sessions |
| `tinysesam/config.py` | `TinySesamConfig` dataclass and presets (`local_accounts`, `oidc_gateway`, `active_directory`, `entra_id`) |
| `tinysesam/config_check.py` | every contradiction of a configuration at construction (errors abort, warnings log); rules by feature in `_config_check_roles.py`, `_config_check_apps.py`, the German findings in `_config_check_de.py` (re-exported) |
| `tinysesam/router.py`, `_routes_forward.py` | `/auth/*` routes of the built-in pages and JSON endpoints; the forward-auth and gate routes as a building block registered only with `forward_auth_enabled` |
| `tinysesam/admin.py` | the admin panel as a mountable router (`/auth/admin`, JSON under `<mount>/api/*`) |
| `tinysesam/_role_levels.py` | role levels (`role_levels`): pure functions the panel and `config_check` share |
| `tinysesam/store.py` | SQLite store core: connection, schema stamp (`Store.SCHEMA_VERSION`, baseline 26), flow state, settings; the index `_PART_METHODS` |
| `tinysesam/_store_<part>.py`, `_store_schema.py` | the other store methods by feature (users, factors, sessions, OAuth, …), loaded on first use (T-112; `tests/test_store_parts.py`); the schema text |
| `tinysesam/security.py` | client IP behind proxies, rate limits, lockout thresholds, the `tinysesam.security` logger |
| `tinysesam/templates.py`, `theme.py`, `topbar.py`, `dialog.py`, `c22.css` | built-in pages, design tokens (the only place with colour values), top bar, own dialogs, C22 adapter |
| `tinysesam/oidc.py`, `saml_.py`, `ldap_.py`, `webauthn_.py`, `totp.py`, `passwords.py` | sign-in methods; optional ones live behind extras |
| `tinysesam/oauth.py` | OAuth 2.1 authorization server for MCP clients (ADR-11) |
| `tinysesam/gate.py`, `gateway.py`, `gate_client.py` | gate token (ADR-9), the ready-to-run OIDC gateway, the gate client for WSGI/ASGI apps without FastAPI (T-86; every check a small function, relaxed one at a time by `tests/_gate_relax.py`) |
| `tinysesam/vault.py` | encryption of reversible secrets at rest |
| `tinysesam/messages.py` | UI texts, English plus German translation |
| `tinysesam/__main__.py`, `_diagnose.py` | CLI `python -m tinysesam` (`passwd`, `backup`, `restore`, `owner`, `unlock`, `keys`, `gate-key`, `diagnose`, …) |
| `tests/` | standalone assert scripts, no pytest; `tests/run_all.py` runs them in parallel |
| `examples/showcase.py` | reference front end; the browser test drives it |
| `web/` | the project website (built by `python -m web.build`) |
| `deploy/` | quickstart stack, proxy templates (Caddy, nginx, Traefik), fail2ban filters, systemd timer, home-network stack |
| `backlog/` | the backlog: one Markdown file per task, bug, decision (ADR) or milestone |
| `scripts/` | generators and release helpers (`_api_docs.py`, `_config_docs.py`, `_backlog.py`, `_release.py`) |
| `spec/` | the gate client specification (`gate-client.md`) and its generated language-neutral vectors (`vectors/`) |
| `clients/` | gate clients in other languages (Go, Rust, JS/TS, PHP), conventions in `clients/README.md` |

## Test

```bash
pip install -e ".[all]"                  # or let scripts/check.sh create .venv with uv
git config core.hooksPath .githooks      # once per clone: the pre-push hook runs the gate
scripts/check.sh                         # all suites + browser test + hygiene + website build
python tests/run_all.py test_core.py     # one suite while you work
```

- **Repeatability is checked by the nightly repeat run** (`nightly-repeat`: the CI suite twice on `main`, a red or flaky
  night is a finding), no longer by running `scripts/check.sh` twice before every push. The pre-push hook is fast
  (hygiene, format/lint, tests of the changed files); `PREPUSH_VOLL=1 git push` runs the full gate. A test that fails on
  the second run is broken. Every suite runs in its own throwaway directory and must not write into the tree.
- `tests/test_browser.py` drives headless Chrome against the showcase (console errors, CSP, dialogs, light/dark).
  Without Chrome it skips — a skip is not a green; run it before a UI change goes out.
- `tests/test_repo.py` is the hygiene test: versions agree, no secrets, no private infrastructure, generated files
  current, every Python block of the READMEs, this file and the skill runs, every dotted name in the docs exists.
- **Mutation proves a fix.** Break the code you fixed (or the guard you wrote), watch the suite go red, restore it
  from a saved copy. Guards carry self-probes: a check that cannot fail proves nothing.
- Never bypass the gate: no `--no-verify`, no `|| true`, no retry over red.

## Generated files — never edit by hand

| File | Source | Regenerate |
|---|---|---|
| `API.md` | code + tiers in `tests/api_surface.json` | `python scripts/_api_docs.py` |
| `CONFIGURATION.md` | comments in `tinysesam/config.py` | `python scripts/_config_docs.py` |
| `tests/api_surface.json` | measured public surface | `python tests/test_api_surface.py --update`, then set the tier |
| `backlog/README.md` | the backlog files | `python scripts/_backlog.py index` |
| `spec/vectors/*.json` | TinySesam's issuing path + attacks in the generator | `python scripts/_gate_vectors.py` |

A new public name has **no tier** until someone decides (A stable, B advanced); an internal name carries a leading
underscore and is not measured. The surface test stays red until then. Tier A and B names must be described in the
hand-written docs (README, `CONFIGURATION.md`, `SECURITY.md`, `docs/`).

## Backlog

One file per item in `backlog/`, id = file prefix (`T-` task, `B-` bug, `ADR-` decision, `M-` milestone), front
matter `id`, `type`, `title`, `status` (`offen`, `in-arbeit`, `erledigt`, `verworfen` — the status words are German
by convention of the shared tooling), `milestone` for tasks and bugs, `created`. The entry moves in the same pull
request as the code. A rejected decision keeps its file with `superseded_by`. Rules: `backlog/README-KONVENTION.md`;
check with `python scripts/_backlog.py check`. Pick the next free number after fetching: open pull requests may
already hold one.

## Language and changes

- **English everywhere**: identifiers, database names, comments, docstrings, docs, commit messages. German only as
  the UI translation (`lang="de"`, `tinysesam/messages.py`, `i18n/`). `tests/test_english_code.py` enforces it.
- `i18n/README.de.md` mirrors the structure of `README.md` (same sections): change both.
- `CHANGELOG.md` (`## [Unreleased]`) and the docs change in the same commit as the code.
- Releases, tags and version bumps are the maintainer's (`scripts/_release.py`); do not bump versions in a change.

## Security rules of this repository

- **Strict CSP with a nonce** on every built-in page: no inline event handlers (`onclick=`), no `style=` attributes,
  every `<script>`/`<style>` carries the response nonce (`tests/test_csp.py`, browser test).
- **No system dialogs**: never `alert`, `confirm` or `prompt`; use `tinysesam/dialog.py` (`tsConfirm`, `tsSecret`, …)
  — `tests/test_dialogs.py`.
- **Design tokens only**: colours are `--ts-*` variables from `tinysesam/theme.py`; no colour value anywhere else.
- **Nothing from third parties** at runtime: no CDN scripts, fonts or images; a plain link is fine, a `src` is not.
- **New access needs a fresh confirmation.** Every route that creates a way into an account (passkey, TOTP, PIN, API
  key, cross-device approval, OAuth consent) calls the one bolt `_require_fresh`; an API key never satisfies it.
  `tests/test_h2_hardening.py` pins that.
- **Sign-in only through the building blocks** (`login_password`, `login_totp`, `login_pin`, `confirm_*`): they
  throttle, count, lock and log for fail2ban. Do not add a path around them.
- **Addresses come from `base_url`**, never from the `Host` header; redirect targets are checked against
  `trusted_redirect_hosts`.
- **No private infrastructure** in code, docs, tests or commits: no real host names, internal addresses or customer
  names — only `example.com` and documentation ranges. Identity (author, contact address, repo URL) is fine. The
  hygiene test enforces it.
- Security changes get a test that fails without the fix; vulnerabilities go through private reporting
  (`SECURITY.md`), not public issues.

## Pitfalls

- `scripts/check.sh` needs a Python that imports FastAPI; without one it builds `.venv` with `uv`.
- The suites lower the password-hash cost only inside the test process (`tests/_starter.py`); a suite started
  directly hashes with production parameters and is slower.
- `tests/_kit/`, `scripts/_backlog.py`, `scripts/_nur_text.sh`, `scripts/_residue_check.sh`, `.githooks/pre-push`
  and `backlog/README-KONVENTION.md` come from a shared kit: do not edit them here.
- A change only to Markdown in the root, `docs/` or `backlog/` takes the text fast path of `scripts/check.sh`: only
  the hygiene test runs (it still executes the Python blocks of this file and checks the names in it).
- CodeQL findings are fixed in code. A real false positive may be dismissed via the API (reason plus comment) and
  must be recorded in `.github/codeql/accepted.md`; never switch a rule off globally (`query-filters`).
- Config fields are read at request time; `TinySesamConfig.validate()` re-checks one changed after construction.
- The schema starts from a baseline (T-111): a new database is created in one step with schema 26, and a database below
  it is refused at start (`Store.BASELINE_SCHEMA`, `Store.LAST_MIGRATING_RELEASE` = 0.30.0). A schema change after the
  baseline raises `Store.SCHEMA_VERSION` with ONE migration step from the state before (in `Store._open_schema`), says
  in `docs/OPERATIONS.md` ("Updating") what an older version does with the file, and adds a test that opens a database
  of the state before (made by `Store` and stamped back) — never a fixture from older files.
  `tests/test_schema_baseline.py` compares a fresh database with `tests/fixtures/schema_baseline.json` (generated from
  the tag v0.30.0); after the first schema change it compares a fresh database with a baseline database migrated by
  the new step.

A quick probe instance for experiments (database in a throwaway directory, never in the tree):

```python
import os
import tempfile

from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "probe.db")))
uid = auth.create_user("probe", password="a long probe password 4711")
assert auth.get_user(uid)["username"] == "probe"
assert auth.has_role(auth.get_user(uid), "editor") is False
```

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
| `tinysesam/config_check.py` | every contradiction of a configuration at construction (errors abort, warnings log) |
| `tinysesam/router.py` | `/auth/*` routes of the built-in pages and JSON endpoints |
| `tinysesam/admin.py` | the admin panel as a mountable router (`/auth/admin`, JSON under `<mount>/api/*`) |
| `tinysesam/_role_levels.py` | role levels (`role_levels`): pure functions the panel and `config_check` share |
| `tinysesam/store.py` | SQLite store, schema and migrations (`Store.SCHEMA_VERSION`) |
| `tinysesam/security.py` | client IP behind proxies, rate limits, lockout thresholds, the `tinysesam.security` logger |
| `tinysesam/templates.py`, `theme.py`, `topbar.py`, `dialog.py`, `c22.css` | built-in pages, design tokens (the only place with colour values), top bar, own dialogs, C22 adapter |
| `tinysesam/oidc.py`, `saml_.py`, `ldap_.py`, `webauthn_.py`, `totp.py`, `passwords.py` | sign-in methods; optional ones live behind extras |
| `tinysesam/oauth.py` | OAuth 2.1 authorization server for MCP clients (ADR-11) |
| `tinysesam/gate.py`, `gateway.py` | gate token (ADR-9) and the ready-to-run OIDC gateway |
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

- **Run `scripts/check.sh` twice; both runs green.** A test that fails on the second run is broken. Every suite runs
  in its own throwaway directory and must not write into the tree.
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

A new public name has **no tier** until someone decides (A stable, B advanced, C internal with a warning alias in
`tinysesam/_deprecated.py`); the surface test stays red until then. Tier A and B names must be described in the
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
- Schema changes need a migration in `tinysesam/store.py`, a rollback note in `docs/OPERATIONS.md` and a test with
  an old database (`tests/fixtures/`).

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

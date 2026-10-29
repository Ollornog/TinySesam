---
id: T-29
type: Task
title: Translate everything to English (code texts, docs, messages)
status: erledigt
milestone: M-2
tags: [i18n, english, docs]
created: 2026-10-28
---

# T-29 — Translate everything to English (code texts, docs, messages)

Switch the repository language to English for international visibility: README, docs, code comments, interface and
error texts (`messages.py`), backlog. The German version of the interface stays as a translation (i18n), nothing is
dropped without replacement. Measure the scope first (texts in `messages.py`/`templates.py`, docs, tests with German
expectations).

## Done

- **Measured:** about 25k lines of German comments, docstrings and docs, about 700 German runtime strings; the interface
  texts, the README, CONTRIBUTING, SECURITY and CODE_OF_CONDUCT were already English (German versions under `i18n/`).
- **Docs and backlog:** CHANGELOG (English Keep a Changelog categories), API.md, CONFIGURATION.md, docs/OPERATIONS.md,
  TODO.md and all backlog files in English, file names too.
- **Code and tests:** comments, docstrings, runtime texts (log lines, exceptions, CLI, start-up warnings, hints of the
  configuration check, mails, account page, admin bar) in English; the German versions are reachable via `lang="de"`
  (`messages.py`, `config_check._DE`, `templates._ACCOUNT_TEXT`, `admin._WARN_HTTP`). Tests follow without weakening.
- **Names:** modules, scripts, test files, backlog files and the twelve last German public names renamed once, without
  aliases (migration table in the CHANGELOG, `[Unreleased]`).
- **Stored vocabulary:** audit event names, audit detail keys and tokens, the substitute name of deleted accounts, the
  trigger message and the placeholders/CSS variables are English as well; existing databases are migrated once (schema 15,
  see the CHANGELOG).
- **Hygiene:** a check for private home-directory paths in `tests/test_repo.py`; fail2ban filters and log lines agree on
  `reason=`, checked by a test.

## Not done (kept deliberately)

- German names of **database tables, columns and setting keys** (`namensbindung`, `fehlserie`, `topf_name`,
  `name_quelle`, `idp_bestaetigt_at`, …) and of private identifiers inside the library: renaming them is a schema change
  of its own with no benefit for users.
- Files managed by the shared test kit (`tests/_kit/**`, `.githooks/pre-push`, `scripts/_backlog.py`, …) and the names the
  kit depends on (`tests/voraussetzung.py`, the `werkzeuge.in` lists): they change with `repokit sync`, not here.

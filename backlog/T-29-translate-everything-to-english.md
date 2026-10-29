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

## Follow-up (2026-10-29): the rest, before the API freeze

The "not done" items of the first pass (German names of database tables, columns and setting keys, private identifiers
inside the library) were done once the repository was to be launched in English (PO decision 2026-10-29; apps, public ones
above all, are coded in English):

- **Identifiers** (about 3,100 names), **comments, docstrings, test descriptions** and internal string values are English;
  module `_vokabular.py` → `_vocabulary.py`.
- **Database names** are English — schema **16**, migration `Store._english_names`, forward only (the way back is `restore` of the backup, `docs/OPERATIONS.md`),
  test `tests/test_db_names_migration.py` against a real schema-15 file (details and the old → new table in the CHANGELOG).
- **Guard** `tests/test_english_code.py` (identifiers, file names, SQL, comments, docstrings); `CONTRIBUTING.md` states the rule.
- **Still German on purpose:** the interface texts (`lang="de"`, `i18n/`) and the files that the shared test kit manages
  (`tests/_kit/**`, `tests/voraussetzung.py`, `scripts/_backlog.py`, `.githooks/pre-push`, the `werkzeuge.in` lists, the job id
  `pruefen` of `release.yml`): they change with `repokit sync`, not here.

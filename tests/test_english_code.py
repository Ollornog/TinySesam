"""No German in the code: identifiers, SQL schema, comments, docstrings — and outside Python (T-29 follow-up, PO decision 2026-10-29).

The repository language is English; German exists only as a translation of the interface (`lang="de"`, `i18n/`).
After the identifiers and the database names were renamed, this guard keeps it that way. It measures:

1. **Identifiers** — every function, method, class, parameter, variable, attribute, keyword argument, import name and
   module name in `tinysesam/`, `web/`, `examples/`, `scripts/` and `tests/`, split into words at `_`, `.` and
   CamelCase; a word from `tests/_german_words.py` is a finding.
2. **File names** of the same directories.
3. **SQL** — the schema (`store.SCHEMA`) and every string that is SQL (`SELECT`, `UPDATE`, `CREATE` ... ) in the
   package: table, column, index, trigger and alias names and the default setting keys must be English.
4. **Comments and docstrings** — German words outside `backticks` and quotation marks (those quote old values and
   German texts on purpose).
5. **Everything that is not Python** (since the follow-up): the shell scripts, workflows, compose and Dockerfiles, the
   Caddy/nginx/traefik templates, the `.in` lists, `pyproject.toml` and the dot files — variable and job names, output
   texts (also inside quotation marks: an `echo "…"` is a text the operator reads) and comments (there backticks and
   quotation marks quote old values, as in Python); the header comments of the hashed `requirements.txt` files (not
   their package lines). The file and directory names of `.github/`, `deploy/` and `scripts/` are measured too.
   Homographs (`art`, `stand` …) count in prose only, as above, so a shell variable `art` slips through.
6. **The English docs** (README, API, SECURITY, CONFIGURATION, CONTRIBUTING, CODE_OF_CONDUCT, TODO, `docs/`,
   `deploy/systemd/README.md`) — German words anywhere, also inside backticks and code blocks (a stale log text or
   an example with German names is exactly what this finds), except where the text talks about the past
   (`tests/_german_words.history_lines`: old → new pairs, version numbers, "German", "schema 15", the rollback
   sections) — and the `tags:` of the backlog entries. `i18n/` is German on purpose and not read.

7. **String literals of the Python sources** (since the string-literal follow-up) — every string and bytes constant
   outside docstrings (f-string parts included): log, error, output and assert messages, test data (passwords,
   usernames, account names, sample values), embedded code (JavaScript, a Python snippet run in a subprocess). A word
   of the list counts anywhere in such a string, quoted or not: a string IS the text. Non-ASCII letters alone do not
   count (a Unicode test input such as `Özlem` or `bücher.example` is no German text). The exceptions are structural:

   * the German half of the interface: a value under a `"de"` key (the message catalog, the account-page texts, the
     demo and website texts), the table `config_check._DE`, and the German data tables listed in `GERMAN_DATA_TABLES`
     (the password blocklist, the probe of the API-name guard, the German page texts of the end-to-end smoke test);
   * German UI text that a TEST asserts: a phrase that is a piece of a German interface text (placeholders cut out:
     `Anmelden bei {app}` is asserted as `Anmelden bei Wiki`), a word that is a whole German interface text of its own
     (`Konto`) next to other text, an all-caps word of such a text (`NIE`), a passage in curly quotation marks
     “…”/„…“, and — in the tests that read `i18n/` — a phrase from the German documentation;
   * the old names the migrations must name, as whole tokens: a compound from the tables of `_vocabulary.py`,
     `Store.RENAMED_*`, `Store.KEY_KINDS_OLD`, `Store._english_names` (`oidc_widerruf`, `kein_konto`), a single old
     key before `=` (`akteur=`), and the code that defines or reads them (`old_value_nodes`); the three tests whose
     INPUT is the old data (`OLD_DATA_TESTS`);
   * names that the kit dictates (`_KIT_NAMES`, its identifier-like strings with an underscore), the HMAC domain
     label `PROTOCOL_CONSTANTS`, and the guards' own probes and word lists (`GUARD_FILES`: German on purpose).

Explicit and small exceptions (everything else is a finding):

* files that the shared test kit manages (`repokit sync`, they change there, not here): `tests/_kit/**`,
  `tests/voraussetzung.py`, `scripts/_backlog.py`, `scripts/_nur_text.sh`, `scripts/_residue_check.sh`,
  `.githooks/pre-push`, `backlog/README-KONVENTION.md`, `.github/workflows/dependabot-auto-merge.yml`, and the names the
  Python ones define or read (computed, not listed); what the repo takes from them stays quoted in `backticks`;
* the migration code that has to name the OLD names: `Store._english_names` and the tables `Store.RENAMED_*`,
  `Store.KEY_KINDS_OLD` (SQL check only);
* the word lists of the guards themselves (strings, not identifiers, so they need no exception).

Self-test: a German identifier, parameter, class, constant, file name, SQL column, docstring and comment are each found
in a probe; a German shell variable, job name, output text, Caddy response, comment, directory name and a stale
log text in the docs likewise; their English twins and a quoted old value are not; a listed word is found in every spelling the
list holds. Mutations: a German name put into a real source text turns the check red (also a German column in
`store.SCHEMA`, a German function in `acceptance.sh`, a German job id in `release.yml`, the German response text
in the `Caddyfile`, a German log text in `docs/OPERATIONS.md`, a German directory under `.github/`).

Works without extras; reads only files.
"""
from __future__ import annotations

import ast
import io
import os
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from _german_words import ENGLISH_HOMOGRAPHS, GERMAN_WORDS, history_lines     # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("English code: identifiers, file names, SQL, comments, docstrings, string literals")

DIRS = ("tinysesam", "web", "examples", "scripts", "tests")
KIT_FILES = ("scripts/_backlog.py", "scripts/_nur_text.sh", "scripts/_residue_check.sh", "tests/voraussetzung.py",
             ".githooks/pre-push", "backlog/README-KONVENTION.md", ".github/workflows/dependabot-auto-merge.yml")
KIT_DIRS = ("tests/_kit/",)
#: Not German, although a word of the list looks like it (project name, technical terms) — spelled out, with the reason.
NOT_GERMAN_TOKENS = frozenset({
    "sesam",        # TinySesam, the project name
})
#: Beyond the Python directories: where non-Python text lives, what is read at the root, and the English docs.
TEXT_ROOTS = (".github", "deploy", "scripts")
ROOT_TEXT_FILES = ("Dockerfile", ".dockerignore", ".gitignore", "MANIFEST.in", "pyproject.toml")
DOC_FILES = ("README.md", "API.md", "SECURITY.md", "CONFIGURATION.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "TODO.md",
             "docs/OPERATIONS.md")
SKIP_SUFFIXES = (".py", ".pyc", ".png", ".ico", ".svg", ".woff2")
#: Where the OLD names have to stand: (file, qualified name) — the schema-16 migration and its tables.
OLD_NAMES_ALLOWED = {("tinysesam/store.py", "_english_names"), ("tinysesam/store.py", "RENAMED_TABLES"),
                     ("tinysesam/store.py", "RENAMED_COLUMNS"), ("tinysesam/store.py", "RENAMED_OBJECTS"),
                     ("tinysesam/store.py", "RENAMED_SETTINGS"), ("tinysesam/store.py", "RENAMED_SETTING_PREFIXES"),
                     ("tinysesam/store.py", "KEY_KINDS_OLD"), ("tinysesam/store.py", "anonymize_audit"),
                     ("tinysesam/store.py", "source_mail_since"), ("tinysesam/store.py", "_OLD_NAME"),
                     ("tinysesam/store.py", "_OLD_MAIL"), ("tinysesam/store.py", "_OWN_VALUES")}
SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|PRAGMA|TRIGGER|VALUES)\b")


def words_of(name: str) -> list:
    """`remove_account` → [remove, account]; `LoginResult` → [login, result]; digits and single letters dropped."""
    parts = re.split(r"[_.\-:/ ]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name)))
    return [re.sub(r"\d+$", "", p.lower()) for p in parts if p and re.sub(r"\d+$", "", p)]


def german_in_identifier(name: str) -> list:
    return sorted({w for w in words_of(name) if w in GERMAN_WORDS and w not in NOT_GERMAN_TOKENS}
                  | {c for c in str(name) if not c.isascii()})


def german_in_text(text: str, quoted: bool = False, umlaut: bool = True) -> list:
    """German words in running English text outside `backticks`, "quotes" and 'quotes' — what a person reads as prose.

    `quoted=True` reads the quoted parts too (output texts of a shell script, names in the docs): there a quotation
    mark does not quote an old value but holds the text itself. `umlaut=False` counts only the words of the list (a
    string literal may hold a non-ASCII name on purpose: a Unicode test input is no German text).
    """
    if not quoted:
        text = re.sub(r"`[^`]*`", " ", text)
        text = re.sub(r"\"[^\"\n]*\"|“[^”]*”|„[^“”\"]*[“”\"]|'[^'\n]{0,60}'", " ", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    found = set()
    for w in re.findall(r"[A-Za-zÄÖÜäöüß]+", text):
        lw = w.lower()
        if len(lw) < 3 and lw not in ("zu", "im", "am", "um", "ob"):
            continue
        if lw in GERMAN_WORDS and lw not in ENGLISH_HOMOGRAPHS and lw not in NOT_GERMAN_TOKENS:
            found.add(lw)
        elif umlaut and any(c in "äöüß" for c in lw):
            found.add(lw)
    return sorted(found)


def is_kit(path: str) -> bool:
    return path in KIT_FILES or path.startswith(KIT_DIRS)


def source_files() -> list:
    out = []
    for d in DIRS:
        for base, dirs, files in os.walk(ROOT / d):
            dirs[:] = [x for x in dirs if x not in ("__pycache__", "fixtures")]
            for f in sorted(files):
                if f.endswith((".py", ".sh", ".sql", ".json", ".txt")):
                    out.append(str((Path(base) / f).relative_to(ROOT)))
    return sorted(out)


def kit_names() -> set:
    """What the kit files define at top level or take as parameters of those functions, plus the keywords and kit
    attributes the repo passes into them — the names we cannot rename here."""
    api, parameters = set(), set()
    for path in [*KIT_FILES, *(str(p.relative_to(ROOT)) for p in (ROOT / "tests" / "_kit").glob("*.py"))]:
        if not path.endswith(".py"):
            continue
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                api.add(n.name)
                if not isinstance(n, ast.ClassDef):
                    parameters |= {a.arg for a in n.args.posonlyargs + n.args.args + n.args.kwonlyargs}
            elif isinstance(n, ast.Assign):
                api |= {t.id for t in n.targets if isinstance(t, ast.Name)}
    names = set(api)
    for path in source_files():
        if is_kit(path) or not path.endswith(".py"):
            continue
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        imported, modules = set(), set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module and (n.module.startswith("_kit") or n.module == "voraussetzung"):
                for a in n.names:
                    (modules if a.name in ("hygiene", "headers", "report", "backlog", "manifest", "automerge",
                                           "textpruefung") else imported).add(a.asname or a.name)
            elif isinstance(n, ast.Import):
                modules |= {(a.asname or a.name).split(".")[-1] for a in n.names if a.name.startswith("_kit")}
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                f = n.func
                if (isinstance(f, ast.Name) and f.id in imported) or (
                        isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in modules):
                    names |= {k.arg for k in n.keywords if k.arg}
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in modules:
                names.add(n.attr)
    # only what the repo's own (non-kit) code really uses counts: a kit-private name does not excuse a German name here
    used = set()
    for path in source_files():
        if is_kit(path) or not path.endswith(".py"):
            continue
        for n in ast.walk(ast.parse((ROOT / path).read_text(encoding="utf-8"))):
            if isinstance(n, ast.Name):
                used.add(n.id)
            elif isinstance(n, ast.Attribute):
                used.add(n.attr)
            elif isinstance(n, ast.keyword) and n.arg:
                used.add(n.arg)
            elif isinstance(n, ast.alias):
                used.add((n.asname or n.name).split(".")[-1])
    return names & used


def identifier_findings(path: str, text: str, skip: set) -> list:
    """[(path:line, name, words)] — every identifier of a Python source with a German word."""
    out = []
    tree = ast.parse(text)
    for n in ast.walk(tree):
        names = []
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(n.name)
        if isinstance(n, ast.arg):
            names.append(n.arg)
        if isinstance(n, ast.Name):
            names.append(n.id)
        if isinstance(n, ast.Attribute):
            names.append(n.attr)
        if isinstance(n, ast.keyword) and n.arg:
            names.append(n.arg)
        if isinstance(n, ast.alias):
            names.append((n.asname or n.name).split(".")[-1])
        if isinstance(n, ast.ExceptHandler) and n.name:
            names.append(n.name)
        for name in names:
            if name in skip:
                continue
            found = german_in_identifier(name)
            if found:
                out.append((f"{path}:{getattr(n, 'lineno', 0)}", name, found))
    return out


def prose_findings(path: str, text: str) -> list:
    """[(path:line, text, words)] — German words in comments and docstrings, outside backticks and quotes."""
    out = []
    tree = ast.parse(text)
    doc = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.body \
                and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant) \
                and isinstance(n.body[0].value.value, str):
            doc.add((n.body[0].value.lineno, n.body[0].value.col_offset))
    for tk in tokenize.generate_tokens(io.StringIO(text).readline):
        if tk.type == tokenize.COMMENT or (tk.type == tokenize.STRING and (tk.start[0], tk.start[1]) in doc):
            body = tk.string
            if tk.type == tokenize.STRING:
                body = re.sub(r'^[rRbBuU]*("""|\'\'\'|"|\')|("""|\'\'\'|"|\')$', "", body)
            # a backtick span may run over several lines of a docstring: look at the whole text, report the first line
            found = german_in_text(body)
            if found:
                out.append((f"{path}:{tk.start[0]}", tk.string[:70].replace("\n", " "), found))
    return out


def sql_findings(path: str, text: str, skip_defs=()) -> list:
    """[(path:line, name, words)] — German words in SQL: the schema and every SQL string constant of the package."""
    out = []
    tree = ast.parse(text)
    allowed = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and (path, n.name) in OLD_NAMES_ALLOWED:
            allowed |= {id(k) for k in ast.walk(n)}
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name) and (path, t.id) in OLD_NAMES_ALLOWED:
                    allowed |= {id(k) for k in ast.walk(n)}
    docs = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef)) and n.body and isinstance(n.body[0], ast.Expr) \
                and isinstance(getattr(n.body[0], "value", None), ast.Constant):
            docs.add(id(n.body[0].value))
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in allowed and id(n) not in docs \
                and (SQL_KEYWORDS.search(n.value) and len(n.value) > 12):
            # the words of the statement outside 'string literals' (those are values) and `-- comments`
            statement = re.sub(r"'[^']*'", " ", n.value)
            found = set()
            for w in re.findall(r"[A-Za-z_][A-Za-z_0-9]*", statement):
                found |= set(german_in_identifier(w))
            comment_free = re.sub(r"--[^\n]*", "", statement)
            found = {w for w in found if re.search(r"(?<![A-Za-z0-9_])[A-Za-z_0-9]*" + re.escape(w), comment_free)} or set()
            if found:
                out.append((f"{path}:{n.lineno}", n.value[:70].replace("\n", " "), sorted(found)))
    return out


# ── string literals of the Python sources ───────────────────────────────────────────────────────
#: Module-level tables whose strings are German on purpose, as (file, name): the German finding templates and the German
#: password blocklist (a list of what German speakers try first).
GERMAN_DATA_TABLES = {("tinysesam/config_check.py", "_DE"), ("tinysesam/passwords.py", "BLOCKLIST"),
                      ("tinysesam/passwords.py", "CONTEXT_BASE_WORDS"),
                      # the probe of the API-name guard in section (k): its German names are its test data
                      ("tests/test_sign_in.py", "_probe_source"), ("tests/test_sign_in.py", "_PROBE_GERMAN"),
                      # the German texts of the pages the end-to-end smoke test drives
                      ("tests/e2e_stage.py", "_DE_CONFIRM"), ("tests/e2e_stage.py", "_DE_REFUSE"),
                      ("tests/e2e_stage.py", "_DE_RATE")}
#: The guards themselves: their probes and word lists are German on purpose (that is their subject). Besides this guard and
#: its word list that is `tests/test_api_surface.py`, the second, narrower guard (the names of the public API, the
#: contract and the log texts): its own German word lists, the old values it must not find again and the probes that
#: prove it finds a German name are spread over its functions.
GUARD_FILES = ("tests/test_english_code.py", "tests/_german_words.py", "tests/test_api_surface.py")
#: Names that the shared test kit dictates and that stay as they are in a string: the worker-count variable, the
#: workflow list of the auto-merge file, the kit scripts and their option, the backlog status value of the kit
#: convention (`status: offen`), and the German OUTPUT of the kit's report
#: (`FEHL <check>`, `<n> ok, <n> Fehler, <n> übersprungen` from `tests/_kit/report.py`, `uebersprungen: <reason>` from
#: `tests/voraussetzung.py`), which `tests/run_all.py` reads and `tests/test_runner.py` imitates.
_KIT_NAMES = re.compile(r"CI_KERNE|PFLICHT_WORKFLOWS|[\w./-]*(?:_nur_text|_residue_check|nur-text-verengung)[\w./-]*"
                        r"|--seit\b|\bstatus: offen\b|\bFEHL\b|\b\d+ ok, \d+ Fehler\b|, \d+ übersprungen\b|\buebersprungen:")
#: Tests whose INPUT is the old German data (audit lines, key kinds, table and column names of the old schema, free text of
#: the old messages): whole files, because the fixtures are the subject — they are the tests that prove the migrations.
OLD_DATA_TESTS = ("tests/test_vocabulary_migration.py", "tests/test_db_names_migration.py",
                  "tests/test_values_english.py")
#: Patterns that must NOT appear in the English and the German docs (the German half is the point): exact strings.
GERMAN_DOC_PATTERNS = frozenset({"within a few days|innerhalb weniger Tage"})
#: Strings that are part of a stored or derived value and must not change: the HMAC domain label of the password-
#: repetition fingerprints (changing a letter would invalidate every stored fingerprint).
PROTOCOL_CONSTANTS = frozenset({"tinysesam/passwort-wiederholung/v1"})
#: Not German in a string, although the word list knows it: `typ` is the JWT header name (RFC 7519).
ENGLISH_STRING_TOKENS = frozenset({"typ"})


_KIT_TOKEN_CACHE: list = []


def kit_string_tokens() -> frozenset:
    """The identifier-like strings WITH an underscore that the shared kit defines or reads (policy keys such as
    `private_namen_sha256_16`, the cookie key `_wert`, `pruefe_cookie_flags` ...): a test string that names one of them
    cannot name it differently."""
    if not _KIT_TOKEN_CACHE:
        found = set()
        for path in [*KIT_FILES, *(str(p.relative_to(ROOT)) for p in (ROOT / "tests" / "_kit").glob("*.py"))]:
            if path.endswith(".py"):
                found |= {text_of(n) for n in _string_nodes(ast.parse((ROOT / path).read_text(encoding="utf-8")))
                          if "_" in text_of(n) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{2,}", text_of(n))}
        _KIT_TOKEN_CACHE.append(frozenset(found))
    return _KIT_TOKEN_CACHE[0]


def without_kit_tokens(value: str) -> str:
    """`value` without the names of the kit (`_KIT_NAMES` and the identifier-like strings of the kit files)."""
    kit = kit_string_tokens()
    value = _KIT_NAMES.sub(" ", value)
    return re.sub(r"[A-Za-z_][A-Za-z_0-9]*", lambda m: " " if m.group(0) in kit else m.group(0), value)


def _string_nodes(tree) -> list:
    """Every string constant of a module that is no docstring (an f-string's literal parts are constants too)."""
    docs = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and n.body \
                and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant):
            docs.add(id(n.body[0].value))
    return [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)) and id(n) not in docs]


def text_of(node) -> str:
    """The text of a string or bytes constant (bytes read as Latin-1: `b"richtig"` is a password like any other)."""
    return node.value if isinstance(node.value, str) else node.value.decode("latin-1")


def _within(root) -> set:
    return {id(k) for k in ast.walk(root)}


def german_ui_nodes(path: str, tree) -> set:
    """ids of the nodes that hold the German half of the interface: the value under a `"de"` key, and the tables of
    `GERMAN_DATA_TABLES` that sit in this file."""
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and k.value == "de":
                    out |= _within(v)
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(isinstance(t, ast.Name) and (path, t.id) in GERMAN_DATA_TABLES for t in targets):
                out |= _within(n)
    return out


def old_value_nodes(path: str, tree) -> set:
    """ids of the nodes that DEFINE or READ the old names of the migrations: the module-level tables of `_vocabulary.py`
    and what `OLD_NAMES_ALLOWED` lists (`Store.RENAMED_*`, `_english_names`, the readers of old audit rows)."""
    out = set()
    if path == "tinysesam/_vocabulary.py":
        for n in tree.body:
            if isinstance(n, ast.Assign):
                out |= _within(n)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and (path, n.name) in OLD_NAMES_ALLOWED:
            out |= _within(n)
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and (path, t.id) in OLD_NAMES_ALLOWED for t in n.targets):
            out |= _within(n)
    return out


def german_ui_corpus() -> list:
    """The German interface texts of the library, to see whether a test string is a fragment of one."""
    out = []
    for path in source_files():
        if not path.endswith(".py") or is_kit(path) or not path.startswith(("tinysesam/", "web/", "examples/")):
            continue
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        ui = german_ui_nodes(path, tree)
        out += [text_of(n) for n in _string_nodes(tree) if id(n) in ui]
    return out


_GERMAN_DOCS_CACHE: list = []


def german_docs_text() -> str:
    """The text of the German translations (`i18n/*.de.md`): German on purpose, and read by tests that run their examples."""
    if not _GERMAN_DOCS_CACHE:
        _GERMAN_DOCS_CACHE.append("\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "i18n").glob("*.de.md"))))
    return _GERMAN_DOCS_CACHE[0]


def old_value_tokens() -> frozenset:
    """The OLD names the migrations must name, as whole tokens: every string of a module-level table of
    `_vocabulary.py`, of `Store.RENAMED_*` / `KEY_KINDS_OLD` and of `Store._english_names`, the words in it
    (split at everything but letters, digits, `_` and `#`: `reason=kein_konto` → `kein_konto`) and the audit event
    families (`<source>_kennung_gebunden`). A string that names such a token (`oidc_widerruf`, `akteur=`,
    `gelöscht#7`) quotes an old value on purpose (see `is_old_name`)."""
    tokens = set()
    tables = {}
    for path in ("tinysesam/_vocabulary.py", "tinysesam/store.py"):
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        roots = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and (
                    path.endswith("_vocabulary.py") and t.id.isupper() or (path, t.id) in OLD_NAMES_ALLOWED)
                    for t in n.targets):
                roots.append(n)
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        try:
                            tables[t.id] = ast.literal_eval(n.value)
                        except ValueError:
                            pass
            elif isinstance(n, ast.FunctionDef) and (path, n.name) in OLD_NAMES_ALLOWED:
                roots.append(n)
        for root in roots:
            for s in _string_nodes(root):
                tokens.add(text_of(s).lower())
                tokens |= {w.lower() for w in re.findall(r"[\w#]+", text_of(s)) if len(w) > 1}
    for source in tables.get("AUDIT_SOURCES", ()):
        tokens |= {(source + suffix).lower() for suffix in tables.get("AUDIT_FAMILIES_OLD", {})}
    return frozenset(tokens)


def is_old_name(value: str, m: "re.Match", old_tokens) -> bool:
    """Does the token `m` in `value` name an old value on purpose? A compound (`kein_konto`, `oidc_widerruf`,
    `gelöscht#`) always does; a single word (`akteur`, `grund`) only as a key before `=`, so that a username `neu` or a
    password word is no excuse."""
    if m.group(0).lower() not in old_tokens:
        return False
    if "_" in m.group(0) or "#" in m.group(0):
        return True
    return value[m.end():m.end() + 1] == "="


def without_old_tokens(value: str, old_tokens) -> str:
    return re.sub(r"[\w#]+", lambda m: " " if is_old_name(value, m, old_tokens) else m.group(0), value)


_PLACEHOLDER = re.compile(r"\{[^{}]*\}|%\([A-Za-z_]+\)[sdr]|%[sdr]|<[^<>]*>|__[A-Z_]+__")
_CURLY_QUOTED = re.compile(r"“[^”]*”|„[^“”\"]*[“”\"]")


def ui_words(ui_corpus) -> frozenset:
    """The German interface texts that are ONE word (`Konto`, `Passwort`, `Zwei-Faktor`): a test that asserts them next
    to other text (`Konto · admin`) quotes the interface. Only as a word of its own, set off by blanks."""
    return frozenset(e.strip() for e in ui_corpus if e.strip() and not re.search(r"\s", e.strip()) and len(e.strip()) >= 3)


def ui_caps(ui_corpus) -> frozenset:
    """Words in CAPITALS inside the German interface texts (`NIE`, `JETZT`): a test that pins them quotes the interface."""
    return frozenset(w for e in ui_corpus for w in re.findall(r"\b[A-ZÄÖÜ]{3,}\b", e))


def ui_fragments(ui_corpus) -> list:
    """The literal pieces of the German interface texts (a phrase of at least 6 characters, or a word of at least 16), longest first: a test string that
    contains one of them quotes the interface (`Anmelden bei {app}` is asserted as `Anmelden bei Wiki`)."""
    pieces = {p.strip() for entry in ui_corpus for p in _PLACEHOLDER.split(entry)
              if (len(p.strip()) >= 6 and " " in p.strip()) or len(p.strip()) >= 16}
    return sorted(pieces, key=len, reverse=True)


def string_hits(path: str, text: str, ui_corpus=(), old_tokens=frozenset(), fragments=None) -> list:
    """[(node, words)] — the string constants of a Python source that hold German words.

    Not counted: the German half of the interface itself (`german_ui_nodes`); in a test, a string that is a part of a
    German interface text or quotes one (the pieces around the placeholders), and a piece of the German
    documentation (`german_docs_text`); a passage in curly quotation marks
    “…” / „…“ (an English description quoting the interface); an old name of the migrations (`old_value_tokens`);
    the names of the kit (`without_kit_tokens`)."""
    if path in GUARD_FILES or path in OLD_DATA_TESTS:
        return []
    fragments = ui_fragments(ui_corpus) if fragments is None else fragments
    words_ui, caps_ui = ui_words(ui_corpus), ui_caps(ui_corpus)
    out = []
    tree = ast.parse(text)
    ui = german_ui_nodes(path, tree) | old_value_nodes(path, tree)
    for n in _string_nodes(tree):
        if id(n) in ui:
            continue
        if text_of(n) in GERMAN_DOC_PATTERNS or text_of(n) in PROTOCOL_CONSTANTS:
            continue
        value = _CURLY_QUOTED.sub(" ", text_of(n))
        if path.startswith("tinysesam/") and SQL_KEYWORDS.search(value) and len(value) > 12:
            value = re.sub(r"'[^']*'|--[^\n]*", " ", value)          # SQL: values and comments (as in `sql_findings`)
        if path.startswith("tests/") and "i18n/" in text and len(value.strip()) >= 8 \
                and (" " in value.strip() or value.strip()[0] in "/#") and value.strip() in german_docs_text():
            continue                # a test finds or runs a piece of the German documentation
        if path.startswith("tests/") and re.search(r"[|\\()]", value) and all(
                w in german_docs_text().lower() for w in german_in_text(value, quoted=True, umlaut=False)):
            continue                # a pattern that finds German documentation (`(?:days|Tage)`)
        if path.startswith("tests/"):
            if any(value.strip() == c.strip() or (" " in value.strip() and len(value.strip()) >= 6 and value.strip() in c)
                   for c in ui_corpus):
                continue            # a test asserts a German interface text or a part of it
            for frag in fragments:
                if frag in value:
                    value = value.replace(frag, " ")
            if " " in value.strip():
                value = " ".join("" if w in words_ui else w for w in value.split(" "))
            value = " ".join("" if w.strip('"\'.,;:()') in caps_ui else w for w in value.split(" "))
        value = without_old_tokens(without_kit_tokens(value), old_tokens)
        found = [w for w in german_in_text(value, quoted=True, umlaut=False) if w not in ENGLISH_STRING_TOKENS]
        if found:
            out.append((n, found))
    return out


def string_findings(path: str, text: str, ui_corpus=(), old_tokens=frozenset(), fragments=None) -> list:
    """[(path:line, text, words)] — German words in the string literals of a Python source (see `string_hits`)."""
    return [(f"{path}:{n.lineno}", text_of(n)[:70].replace("\n", " "), found)
            for n, found in string_hits(path, text, ui_corpus, old_tokens, fragments)]


def filename_findings(paths: list) -> list:
    out = []
    for p in paths:
        if is_kit(p):
            continue
        stem = Path(p).name.rsplit(".", 1)[0]
        found = german_in_identifier(stem)
        if found:
            out.append((p, stem, found))
    return out


# ── outside Python: scripts, workflows, templates, lists, docs ────────────────────────────────────
#: What no text of ours can name differently: URLs, hashes, addresses, finding IDs (`B6-4`, `NEU-1`), and the German names
#: that the shared kit dictates — its scripts and their option (`_nur_text.sh`, `_residue_check.sh --seit`,
#: `scripts/nur-text-verengung.txt`) and the worker-count variable `CI_KERNE`.
_URLS_AND_HASHES = re.compile(
    r"https?://\S+|--hash=\S+|\b[0-9a-f]{12,}\b|\S+@\S+\.\w+|\b[A-Z]{1,6}-\d+[a-z]?\b"
    r"|[\w./-]*(?:_nur_text|_residue_check|nur-text-verengung)[\w./-]*|--seit\b|\bCI_KERNE\b")


def split_comment(line: str) -> tuple:
    """(code, comment) of one line of a shell script / YAML / conf / Dockerfile: the comment starts at a `#` that
    stands at the start or after a blank and outside quotation marks (`$#`, `${#x}` and `"#"` are not comments)."""
    quote = ""
    for i, c in enumerate(line):
        if quote:
            quote = "" if c == quote else quote
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i], line[i:]
    return line, ""


def nonpython_text_findings(path: str, text: str) -> list:
    """[(path:line, text, words)] — German words in a text that is not Python.

    Code part of a line (variable, function, job, matrix and file names, output texts, `name:` values): every word
    counts, quoted or not. Comment part: as in Python, outside `backticks` and quotation marks. Hashed
    `requirements.txt` lists: only the comment lines (package names are not ours to translate).
    """
    out = []
    only_comments = path.endswith("requirements.txt")
    for n, line in enumerate(text.split("\n"), 1):
        code, comment = split_comment(_URLS_AND_HASHES.sub(" ", line))
        found = set(german_in_text(comment)) if comment else set()
        if not only_comments:
            found |= set(german_in_text(code, quoted=True))
        if found:
            out.append((f"{path}:{n}", line.strip()[:70], sorted(found)))
    return out


def doc_findings(path: str, text: str) -> list:
    """[(path:line, text, words)] — German words in an English Markdown doc, also inside backticks and code blocks,
    except in the places that talk about the past (`history_lines`) and the language switch to the German files."""
    out, exempt = [], history_lines(text)
    for n, line in enumerate(text.split("\n"), 1):
        if n in exempt:
            continue
        line = _URLS_AND_HASHES.sub(" ", line)
        if ".de.md" in line:
            line = line.replace("Deutsch", " ")
        found = german_in_text(line, quoted=True)
        if found:
            out.append((f"{path}:{n}", line.strip()[:70], found))
    return out


def backlog_tag_findings(path: str, text: str) -> list:
    """German words in the `tags:` line of a backlog entry (the status values come from the kit convention)."""
    m = re.search(r"^tags: \[([^\]]*)\]", text, re.M)
    found = sorted({w for tag in (m.group(1).split(",") if m else []) for w in german_in_identifier(tag.strip())})
    return [(path, "tags", found)] if found else []


def nonpython_files() -> list:
    """Tracked-looking non-Python text files: under `.github/`, `deploy/`, `scripts/` and a few at the root. Markdown
    under those directories is a doc (`deploy/systemd/README.md`), the rest is code."""
    out = [f for f in ROOT_TEXT_FILES if (ROOT / f).is_file()]
    for d in TEXT_ROOTS:
        for base, dirs, files in os.walk(ROOT / d):
            dirs[:] = [x for x in dirs if x not in ("__pycache__", ".venv", "node_modules")]
            out += [str((Path(base) / f).relative_to(ROOT)) for f in sorted(files) if not f.endswith(SKIP_SUFFIXES)]
    return sorted(out)


def path_findings(paths: list) -> list:
    """German words in any component of a path (directories included: `.github/bau/`)."""
    out = []
    for p in paths:
        if is_kit(p):
            continue
        found = sorted({w for part in Path(p).parts for w in german_in_identifier(part.rsplit(".", 1)[0] if "." in part[1:] else part)})
        if found:
            out.append((p, p, found))
    return out


def nonpython_all_findings() -> list:
    out = []
    files = nonpython_files()
    out += [("path", *f) for f in path_findings(files)]
    for path in files:
        if is_kit(path):
            continue
        text = (ROOT / path).read_text(encoding="utf-8")
        if path.endswith(".md"):
            out += [("doc", *f) for f in doc_findings(path, text)]
        else:
            out += [("non-python", *f) for f in nonpython_text_findings(path, text)]
    for path in DOC_FILES:
        out += [("doc", *f) for f in doc_findings(path, (ROOT / path).read_text(encoding="utf-8"))]
    for path in sorted((ROOT / "backlog").glob("*.md")):
        rel = str(path.relative_to(ROOT))
        if not is_kit(rel):
            out += [("backlog tag", *f) for f in backlog_tag_findings(rel, path.read_text(encoding="utf-8"))]
    return out


def all_findings() -> list:
    paths = source_files()
    skip = kit_names()
    ui_corpus, old_tokens = german_ui_corpus(), old_value_tokens()
    fragments = ui_fragments(ui_corpus)
    out = [("file name", *f) for f in filename_findings(paths)]
    for path in paths:
        if is_kit(path) or not path.endswith(".py"):
            continue
        text = (ROOT / path).read_text(encoding="utf-8")
        out += [("identifier", *f) for f in identifier_findings(path, text, skip)]
        out += [("comment/docstring", *f) for f in prose_findings(path, text)]
        if path.startswith("tinysesam/"):
            out += [("sql", *f) for f in sql_findings(path, text)]
        out += [("string", *f) for f in string_findings(path, text, ui_corpus, old_tokens, fragments)]
    return out + nonpython_all_findings()


def report(findings: list, limit=int(os.environ.get("ENGLISH_CODE_LIMIT", "25"))) -> str:
    return "; ".join(f"[{kind}] {where} {name!r} {words}" for kind, where, name, words in findings[:limit]) \
        + (f" … +{len(findings) - limit}" if len(findings) > limit else "")


# ── the real tree ─────────────────────────────────────────────────────────────────────────────────
tree_findings = all_findings()
r.check("no German identifier, file name, SQL name, comment, docstring or string literal in tinysesam/, web/, examples/, scripts/, tests/",
        not tree_findings, report(tree_findings))
store_text = (ROOT / "tinysesam" / "store.py").read_text(encoding="utf-8")
r.check("the guard sees the schema: `store.SCHEMA` is SQL text and is measured (more than 20 tables)",
        store_text.count("CREATE TABLE IF NOT EXISTS") > 20
        and any(k == "sql" for k, *_ in [("sql", 0)]) and len(sql_findings("tinysesam/store.py", store_text)) == 0)

# ── self-test: probes ─────────────────────────────────────────────────────────────────────────────
PROBE_BAD = {
    "function": "def konto_entfernen(user_id):\n    return user_id\n",
    "method": "class A:\n    def pruefe_namen(self):\n        return 1\n",
    "class": "class Anwendung:\n    pass\n",
    "parameter": "def f(ziel):\n    return ziel\n",
    "variable": "ergebnis = 1\n",
    "constant": "SICHERHEITSEREIGNISSE = ()\n",
    "attribute": "x = obj.kennung\n",
    "keyword argument": "f(grund=1)\n",
    "import name": "from os import path as pfad\n",
    "camel case": "class LoginErgebnis:\n    pass\n",
    "umlaut": "größe = 1\n",
}
PROBE_GOOD = {
    "function": "def remove_account(user_id):\n    return user_id\n",
    "class": "class LoginResult:\n    pass\n",
    "english word near the list": "series = 1\nbase = 2\nstate = 3\nbinding = 4\nowner_id = 5\nsource = 6\nuntil = 7\n",
    "kit-free project name": "class TinySesamConfig:\n    pass\n",
}
bad_ident = {k: bool(identifier_findings("probe.py", t, set())) for k, t in PROBE_BAD.items()}
good_ident = {k: bool(identifier_findings("probe.py", t, set())) for k, t in PROBE_GOOD.items()}
r.check("self-test identifiers: function, method, class, parameter, variable, constant, attribute, keyword, import name, "
        "CamelCase and umlaut are found; the English twins and the project name are not",
        all(bad_ident.values()) and not any(good_ident.values()), f"{bad_ident} {good_ident}")
r.check("self-test file names: a German file name is found, an English one is not",
        bool(filename_findings(["tests/test_konto_entfernen.py"])) and not filename_findings(["tests/test_account.py"]),
        str(filename_findings(["tests/test_konto_entfernen.py"])))
sql_bad = 'CREATE_SQL = "CREATE TABLE IF NOT EXISTS namensbindung (quelle TEXT, user_id INTEGER)"\n'
sql_bad2 = 'Q = "SELECT topf_name FROM users WHERE id = ?"\n'
sql_good = 'Q = "SELECT folded_name FROM users WHERE id = ? AND name_source = \'ldap\' AND kind = \'kein_konto\'"\n'
r.check("self-test SQL: a German table or column is found, English names and German VALUES in quotes are not",
        bool(sql_findings("tinysesam/x.py", sql_bad)) and bool(sql_findings("tinysesam/x.py", sql_bad2))
        and not sql_findings("tinysesam/x.py", sql_good),
        f"{sql_findings('tinysesam/x.py', sql_bad)} {sql_findings('tinysesam/x.py', sql_good)}")
prose_bad = ('"""Die Funktion löscht das Konto und gibt nichts zurück."""\n'
             "def f():\n    # das Passwort wird nicht gespeichert\n    return 1\n")
prose_good = ('"""Deletes the account; the old name `konto_entfernen` and "Konto gelöscht" are quoted on purpose."""\n'
              "def f():\n    # the password is not stored (old spelling `passwort`)\n    return 1\n")
r.check("self-test text: German prose in a docstring and a comment is found; English prose with quoted old values is not",
        len(prose_findings("probe.py", prose_bad)) == 2 and not prose_findings("probe.py", prose_good),
        f"{prose_findings('probe.py', prose_bad)} {prose_findings('probe.py', prose_good)}")
r.check("self-test word list: every listed word is found as an identifier part and (unless it is an English word) in "
        "prose; the list is big enough to mean something",
        len(GERMAN_WORDS) > 1000 and all(german_in_identifier(f"x_{w}_y") for w in GERMAN_WORDS - NOT_GERMAN_TOKENS)
        and all(german_in_text(f"the {w} of it") for w in list(GERMAN_WORDS - ENGLISH_HOMOGRAPHS)[:200]
                if len(w) > 3 and not re.search(r"\d", w) and w not in NOT_GERMAN_TOKENS),
        f"{len(GERMAN_WORDS)} words")
r.check("self-test kit exception: names the kit defines are skipped, others are not",
        {"braucht_modul", "pflicht_werkzeug"} <= kit_names() and "ergebnis" not in kit_names(), str(sorted(kit_names())[:5]))

# ── mutations on real source text ─────────────────────────────────────────────────────────────────
def mutated_findings(path: str, old: str, new: str) -> list:
    text = (ROOT / path).read_text(encoding="utf-8")
    assert old in text, f"mutation anchor {old!r} not in {path}"
    mutated = text.replace(old, new, 1)
    skip = kit_names()
    out = identifier_findings(path, mutated, skip) + prose_findings(path, mutated)
    if path.startswith("tinysesam/"):
        out += sql_findings(path, mutated)
    return out


baseline_store = (identifier_findings("tinysesam/store.py", store_text, set()) + prose_findings("tinysesam/store.py", store_text)
                  + sql_findings("tinysesam/store.py", store_text))
r.check("mutation baseline: the unbroken store.py has no finding", not baseline_store, str(baseline_store[:3]))
for what, path, old, new in (
        ("a German method name", "tinysesam/store.py", "def remove_account(", "def konto_entfernen("),
        ("a German parameter", "tinysesam/store.py", "def reserve_attempt(self, username, ip, method, rules, series=None,",
         "def reserve_attempt(self, username, ip, method, regeln, series=None,"),
        ("a German column in the schema", "tinysesam/store.py", "    folded_name     TEXT,", "    topf_name     TEXT,"),
        ("a German table in the schema", "tinysesam/store.py", "CREATE TABLE IF NOT EXISTS failure_series",
         "CREATE TABLE IF NOT EXISTS fehlserie"),
        ("a German column in a query", "tinysesam/store.py", '"SELECT * FROM oidc_session WHERE token_hash=?"',
         '"SELECT * FROM oidc_session WHERE sitzung_hash=?"'),
        ("a German class", "tinysesam/gate.py", "def audience(", "def zielgruppe("),
        ("a German comment", "tinysesam/manager.py", "# Own line (B5-07/B2-7).", "# Eigene Zeile und kein Passwort (B5-07/B2-7)."),
        ("a German docstring", "tinysesam/totp.py", '"""', '"""Prüft das Passwort nicht. ', )):
    try:
        found = mutated_findings(path, old, new)
        ok = bool(found)
    except AssertionError as error:
        found, ok = [str(error)], False
    r.check(f"mutation: {what} — the check turns red", ok, str(found[:2]))

# ── string literals: probes and mutations ────────────────────────────────────────────────────────
_UI = german_ui_corpus()
_OLD = old_value_tokens()
_FR = ui_fragments(_UI)
_PROBE_UI = ["Anmelden bei {app}", "Konto", "Passwort", "Zu viele Fehlversuche — vorübergehend gesperrt.",
             "Achtung: NIE freigeben"]


def probe_strings(path: str, text: str, ui=None) -> list:
    return string_findings(path, text, _PROBE_UI if ui is None else ui, _OLD, ui_fragments(_PROBE_UI if ui is None else ui))


STR_BAD = {
    "log message in the package": ("tinysesam/x.py", 'log.warning("Datenbank nicht erreichbar")\n'),
    "exception text": ("tinysesam/x.py", 'raise ValueError(f"Konto {user} gesperrt")\n'),
    "f-string part": ("tinysesam/x.py", 'print(f"Fehler bei {x}")\n'),
    "assert message in a test": ("tests/test_x.py", 'assert ok, "Anmeldung fehlgeschlagen"\n'),
    "test password": ("tests/test_x.py", 'create_user("max", password="Geheim-lang-genug")\n'),
    "test user name": ("tests/test_x.py", 'create_user("chefin")\n'),
    "single old word that is no key": ("tests/test_x.py", 'create_user("neu")\n'),
    "password that contains a word of the interface": ("tests/test_x.py", 'create_user("u", password="Dritte-Passwort")\n'),
    "snippet run in a subprocess": ("tests/test_x.py", 'SRC = "def pruefe():\\n    return 1\\n"\n'),
    "bytes constant": ("tests/test_x.py", 'USER = {b"uid=alice": b"richtig"}\n'),
    "English test text with a German word": ("tests/test_x.py", 'r.check("login works für Kunden", ok)\n'),
}
STR_GOOD = {
    "English log text": ("tinysesam/x.py", 'log.warning("database unreachable: %s", error)\n'),
    "German interface text under a de key": ("tinysesam/x.py", 'MESSAGES = {"en": {"a": "Account"}, "de": {"a": "Konto gelöscht"}}\n'),
    "German table of the findings": ("tinysesam/config_check.py", '_DE = {"English": "Deutsch und nicht gesperrt"}\n'),
    "German password blocklist": ("tinysesam/passwords.py", 'BLOCKLIST = frozenset("passwort kennwort geheimnis".split())\n'),
    "old compound value": ("tests/test_x.py", 'assert "oidc_widerruf" not in line\n'),
    "old key before =": ("tests/test_x.py", 'detail = "old=x akteur=helper"\n'),
    "Unicode input": ("tests/test_x.py", 'folded("Özlem") == folded("u@bücher.example")\n'),
    "phrase of the interface with a placeholder filled": ("tests/test_x.py", 'assert "Anmelden bei Wiki" in html\n'),
    "whole interface word next to other text": ("tests/test_x.py", 'assert "Konto · admin" in html\n'),
    "all-caps word of the interface": ("tests/test_x.py", 'assert "NIE" in text\n'),
    "quoted interface text in a description": ("tests/test_x.py", 'r.check("page “Anmelden bei Wiki” shown", ok)\n'),
    "name the kit dictates": ("tests/test_x.py", 'env = {"CI_KERNE": "3"}\n'),
    "docstring (read as prose, not as a string)": ("tinysesam/x.py", 'def f():\n    """Löscht nichts."""\n'),
    "German names inside a guard file": ("tests/_german_words.py", 'GERMAN = frozenset("konto passwort".split())\n'),
    "English twin": ("tests/test_x.py", 'create_user("boss", password="Third-Password")\n'),
}
_bad_str = {k: bool(probe_strings(*v)) for k, v in STR_BAD.items()}
_good_str = {k: bool(probe_strings(*v)) for k, v in STR_GOOD.items()}
r.check("self-test string literals: a German log text, exception text, f-string part, assert message, password, user name, "
        "a single old word that is no key, a password with an interface word in it, a snippet, a bytes constant and an "
        "English text with a German word are found; their English twins, a German interface text, the German finding "
        "table, the blocklist, an old name, Unicode input, a quoted or asserted interface text, a kit name and a "
        "docstring are not",
        all(_bad_str.values()) and not any(_good_str.values()), f"{_bad_str} {_good_str}")


def mutated_string_findings(path: str, old: str, new: str) -> list:
    text = (ROOT / path).read_text(encoding="utf-8")
    assert old in text, f"mutation anchor {old!r} not in {path}"
    return string_findings(path, text.replace(old, new, 1), _UI, _OLD, _FR)


for _path in ("tinysesam/ldap_.py", "tests/test_cookies.py", "tests/test_hardening.py", "tinysesam/messages.py",
              "tinysesam/_vocabulary.py", "tinysesam/store.py"):
    _base = string_findings(_path, (ROOT / _path).read_text(encoding="utf-8"), _UI, _OLD, _FR)
    r.check(f"mutation baseline: the unbroken {_path} has no string finding", not _base, str(_base[:2]))
for what, path, old, new, red in (
        ("a German log/exception text in the package", "tinysesam/ldap_.py", ': search rejected "', ': Suche abgewiesen "', True),
        ("a German assert message in a test", "tests/test_cookies.py", '"logout must overwrite the session cookie, not just empty the DB row"',
         '"Die Sitzung wurde nicht beendet"', True),
        ("a German test password", "tests/test_hardening.py", '"Attacker-Password-1x"', '"Angreifer-Passwort-1x"', True),
        ("a German entry in the message catalog", "tinysesam/messages.py", '"login.signup": "Konto erstellen"',
         '"login.signup": "Neues Konto anlegen und sofort loslegen"', False),
        ("an old name added to the migration table", "tinysesam/_vocabulary.py", '"sperrhinweis": "lockout_notice"',
         '"sperrhinweis": "lockout_notice", "zusatz_hinweis": "extra_notice"', False),
        ("an old table name added to the schema migration", "tinysesam/store.py", '"fehlserie": "failure_series"',
         '"fehlserie": "failure_series", "alte_tabelle": "old_table"', False)):
    try:
        found = mutated_string_findings(path, old, new)
        ok_ = bool(found) == red
    except AssertionError as error:
        found, ok_ = [str(error)], False
    r.check(f"mutation: {what} — the check turns {'red' if red else 'NOT red (German on purpose)'}", ok_, str(found[:2]))
r.check("the string scan sees the tree: it reads tests, package, web, examples and scripts and finds the UI corpus",
        len(_UI) > 400 and len(_OLD) > 100 and "tests/test_cookies.py" in source_files() and "web/flows.py" in source_files(),
        f"{len(_UI)} UI texts, {len(_OLD)} old tokens")


# ── outside Python: the guard sees the files, probes, mutations ────────────────────────────────────
_seen = nonpython_files()
r.check("the non-Python scan sees the workflows, the scripts, the templates, the lists and the dot files",
        {".github/workflows/release.yml", ".github/dependabot.yml", "deploy/forward-auth/acceptance.sh",
         "deploy/forward-auth/Caddyfile", "scripts/check.sh", "scripts/_image_probe.sh", "Dockerfile", ".gitignore",
         ".github/packaging/tools.in", ".github/audit/tools.in"} <= set(_seen) and len(_seen) > 30, str(len(_seen)))

NP_BAD = {
    "shell variable": ("probe.sh", "ergebnis=1\n"),
    "shell function": ("probe.sh", "pruefe() {  # check one thing\n    :\n}\n"),
    "shell output text": ("probe.sh", 'echo "▸ Abbild bauen: $IMAGE"\n'),
    "workflow job id": ("probe.yml", "jobs:\n  pruefen:\n    runs-on: ubuntu-latest\n"),
    "workflow step name": ("probe.yml", "      - name: Abbild starten\n"),
    "compose anchor": ("probe.yml", "x-haertung: &hardening\n"),
    "Caddy response text": ("Caddyfile", 'respond "Kein Zugriff: fehlende Rolle." 403\n'),
    "comment prose": ("probe.sh", "# das Passwort wird nicht gespeichert\n"),
    "umlaut in a text": ("probe.sh", 'echo "grün"\n'),
    "trailing comment": ("probe.sh", "x=1  # wird gesetzt\n"),
}
NP_GOOD = {
    "English code and text": ("probe.sh", 'result=1\necho "▸ Build image: $IMAGE"\nfail() { :; }\n'),
    "old value quoted in a comment": ("probe.yml", "# until 0.24.x `ja|nein`, before that \"ja\" (old value)\nx: 1\n"),
    "URL, hash and finding ID": ("probe.sh", "curl https://example.com/ergebnis  # B6-4 NEU-1 sha256:0123456789abcdef0123\n"),
    "kit names": ("probe.sh", "scripts/_nur_text.sh; scripts/_residue_check.sh check --seit x; echo $CI_KERNE\n"),
    "a # that is no comment": ("probe.sh", 'n=${#arr[@]}; echo "$#"\n'),
    "homograph as an identifier": ("probe.sh", "art=1\n"),
    "package line of a hashed list": ("requirements.txt", "gunicorn==1.0 \\\n    --hash=sha256:0123456789abcdef0123456789abcdef\n"),
}
bad_np = {k: bool(nonpython_text_findings(*v)) for k, v in NP_BAD.items()}
good_np = {k: bool(nonpython_text_findings(*v)) for k, v in NP_GOOD.items()}
r.check("self-test non-Python: a German shell variable, function, output text, job id, step name, compose anchor, Caddy "
        "response, comment and umlaut are found; English code, quoted old values, URLs/hashes/IDs, the kit's names, "
        "a `#` that is no comment, a homograph and a package line are not",
        all(bad_np.values()) and not any(good_np.values()), f"{bad_np} {good_np}")
r.check("self-test paths: a German directory (`.github/bau/`) and a German file name are found, English ones are not",
        bool(path_findings([".github/bau/tools.in"])) and bool(path_findings(["scripts/pruefe_alles.sh"]))
        and not path_findings([".github/packaging/tools.in", "scripts/check.sh", "deploy/forward-auth/acceptance.sh"]),
        str(path_findings([".github/bau/tools.in"])))
DOC_BAD = {
    "German log text in a table": "| **LDAP** | 503 | Log: `LDAP-Verzeichnis nicht erreichbar`. |\n",
    "German name in an example": "```python\nfor teil in report:\n    print(teil)\n```\n",
    "German setting name": "The setting `allowlist_nach_idp_entzug` is read at start.\n",
    "a marker in another table row does not excuse this row":
        "| a | up to 0.24.x `alt` → `old` |\n| b | `Datenbank nicht beschreibbar` |\n",
}
DOC_GOOD = {
    "English text": "The setting `allowlist_after_idp_revocation` is read at start (`reason=`).\n",
    "old → new pair": "The event was renamed (`oidc_widerruf` → `oidc_revoked`).\n",
    "version marker on the next line": "Messages were German (`kein_konto`,\n`gelöscht#<id>`) up to 0.24.x.\n",
    "rollback section": "## Rollback to 0.24.x\n\n```sql\nUPDATE api_key SET kind = 'automat';\n```\n\n## Next\n\nplain.\n",
    "language switch": '<a href="i18n/SECURITY.de.md">Deutsch</a>\n',
    "address example": "`u@bücher.example` and `CI_KERNE`\n",
}
bad_doc = {k: bool(doc_findings("probe.md", v)) for k, v in DOC_BAD.items()}
good_doc = {k: bool(doc_findings("probe.md", v)) for k, v in DOC_GOOD.items()}
r.check("self-test docs: a German log text, a German example name and a German setting name are found, also inside "
        "backticks and code blocks, and next to a history marker in another table row; English text, old → new pairs, "
        "a version marker on the next line, a rollback section, the language switch and an address example are not",
        all(bad_doc.values()) and not any(good_doc.values()), f"{bad_doc} {good_doc}")
r.check("self-test backlog tags: a German tag is found, English tags and the kit's status values are not",
        bool(backlog_tag_findings("b.md", "---\ntags: [security, sicherheit]\nstatus: offen\n---\n"))
        and not backlog_tag_findings("b.md", "---\ntags: [security, ci]\nstatus: offen\n---\n"))


def np_mutation(path: str, old: str, new: str) -> list:
    text = (ROOT / path).read_text(encoding="utf-8")
    assert old in text, f"mutation anchor {old!r} not in {path}"
    mutated = text.replace(old, new, 1)
    return doc_findings(path, mutated) if path.endswith(".md") else nonpython_text_findings(path, mutated)


for _path in ("deploy/forward-auth/acceptance.sh", ".github/workflows/release.yml", "deploy/forward-auth/Caddyfile",
              "docs/OPERATIONS.md", "scripts/_image_probe.sh", ".github/dependabot.yml"):
    _text = (ROOT / _path).read_text(encoding="utf-8")
    _base = doc_findings(_path, _text) if _path.endswith(".md") else nonpython_text_findings(_path, _text)
    r.check(f"mutation baseline: the unbroken {_path} has no finding", not _base, str(_base[:2]))
for what, path, old, new in (
        ("a German shell function", "deploy/forward-auth/acceptance.sh", "check() {", "pruefe() {"),
        ("a German shell variable", "deploy/forward-auth/acceptance.sh", "failed=0", "ergebnis=0"),
        ("a German job id", ".github/workflows/release.yml", "\n  verify:\n", "\n  pruefen:\n"),
        ("a German matrix/job reference", ".github/workflows/release.yml", "needs: verify", "needs: pruefen"),
        ("the German response text in the Caddyfile", "deploy/forward-auth/Caddyfile", "Access denied: missing role.",
         "Kein Zugriff: fehlende Rolle."),
        ("a German output text", "scripts/_image_probe.sh", "▸ Build image", "▸ Abbild bauen"),
        ("a German comment in the Dependabot config", ".github/dependabot.yml", "# Waiting period before version updates",
         "# Wartezeit vor Versions-Updates"),
        ("a German log text in the operator docs", "docs/OPERATIONS.md", "`Healthcheck: database not writable`",
         "`Healthcheck: Datenbank nicht beschreibbar`"),
        ("a German name in the docs", "docs/OPERATIONS.md", "report = auth.federation_bind_existing", "bericht = auth.federation_bind_existing")):
    try:
        found = np_mutation(path, old, new)
        ok = bool(found)
    except AssertionError as error:
        found, ok = [str(error)], False
    r.check(f"mutation: {what} — the check turns red", ok, str(found[:2]))
r.check("mutation: a German directory under .github/ — the check turns red",
        bool(path_findings([p.replace(".github/packaging/", ".github/bau/") for p in _seen])))

raise SystemExit(r.done())

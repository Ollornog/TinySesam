"""No German in the code: identifiers, SQL schema, comments and docstrings (T-29 follow-up, PO decision 2026-10-29).

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

Explicit and small exceptions (everything else is a finding):

* files that the shared test kit manages (`repokit sync`, they change there, not here): `tests/_kit/**`,
  `tests/voraussetzung.py`, `scripts/_backlog.py`, and the names those files define or read (computed, not listed);
* the migration code that has to name the OLD names: `Store._english_names` and the tables `Store.RENAMED_*`,
  `Store.KEY_KINDS_OLD` (SQL check only);
* the word lists of the guards themselves (strings, not identifiers, so they need no exception).

Self-test: a German identifier, parameter, class, constant, file name, SQL column, docstring and comment are each found
in a probe; their English twins and a quoted old value are not; a listed word is found in every spelling the
list holds. Mutations: a German name put into a real source text turns the check red (also a German column in
`store.SCHEMA`).

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

from _german_words import ENGLISH_HOMOGRAPHS, GERMAN_WORDS     # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("English code: identifiers, file names, SQL, comments, docstrings")

DIRS = ("tinysesam", "web", "examples", "scripts", "tests")
KIT_FILES = ("scripts/_backlog.py", "scripts/_nur_text.sh", "scripts/_residue_check.sh", "tests/voraussetzung.py")
KIT_DIRS = ("tests/_kit/",)
#: Not German, although a word of the list looks like it (project name, technical terms) — spelled out, with the reason.
NOT_GERMAN_TOKENS = frozenset({
    "sesam",        # TinySesam, the project name
})
#: Where the OLD names have to stand: (file, qualified name) — the schema-16 migration and its tables.
OLD_NAMES_ALLOWED = {("tinysesam/store.py", "_english_names"), ("tinysesam/store.py", "RENAMED_TABLES"),
                     ("tinysesam/store.py", "RENAMED_COLUMNS"), ("tinysesam/store.py", "RENAMED_OBJECTS"),
                     ("tinysesam/store.py", "RENAMED_SETTINGS"), ("tinysesam/store.py", "RENAMED_SETTING_PREFIXES"),
                     ("tinysesam/store.py", "KEY_KINDS_OLD")}
SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|PRAGMA|TRIGGER|VALUES)\b")


def words_of(name: str) -> list:
    """`remove_account` → [remove, account]; `LoginResult` → [login, result]; digits and single letters dropped."""
    parts = re.split(r"[_.\-:/ ]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name)))
    return [re.sub(r"\d+$", "", p.lower()) for p in parts if p and re.sub(r"\d+$", "", p)]


def german_in_identifier(name: str) -> list:
    return sorted({w for w in words_of(name) if w in GERMAN_WORDS and w not in NOT_GERMAN_TOKENS}
                  | {c for c in str(name) if not c.isascii()})


def german_in_text(text: str) -> list:
    """German words in running English text outside `backticks`, "quotes" and 'quotes' — what a person reads as prose."""
    text = re.sub(r"`[^`]*`", " ", text)
    text = re.sub(r"\"[^\"\n]*\"|“[^”]*”|„[^“”\"]*[“”\"]|'[^'\n]{0,60}'", " ", text)
    found = set()
    for w in re.findall(r"[A-Za-zÄÖÜäöüß]+", text):
        lw = w.lower()
        if len(lw) < 3 and lw not in ("zu", "im", "am", "um", "ob"):
            continue
        if lw in GERMAN_WORDS and lw not in ENGLISH_HOMOGRAPHS and lw not in NOT_GERMAN_TOKENS:
            found.add(lw)
        elif any(c in "äöüß" for c in lw):
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


def all_findings() -> list:
    paths = source_files()
    skip = kit_names()
    out = [("file name", *f) for f in filename_findings(paths)]
    for path in paths:
        if is_kit(path) or not path.endswith(".py"):
            continue
        text = (ROOT / path).read_text(encoding="utf-8")
        out += [("identifier", *f) for f in identifier_findings(path, text, skip)]
        out += [("comment/docstring", *f) for f in prose_findings(path, text)]
        if path.startswith("tinysesam/"):
            out += [("sql", *f) for f in sql_findings(path, text)]
    return out


def report(findings: list, limit=int(os.environ.get("ENGLISH_CODE_LIMIT", "25"))) -> str:
    return "; ".join(f"[{kind}] {where} {name!r} {words}" for kind, where, name, words in findings[:limit]) \
        + (f" … +{len(findings) - limit}" if len(findings) > limit else "")


# ── the real tree ─────────────────────────────────────────────────────────────────────────────────
tree_findings = all_findings()
r.check("no German identifier, file name, SQL name, comment or docstring in tinysesam/, web/, examples/, scripts/, tests/",
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

raise SystemExit(r.done())

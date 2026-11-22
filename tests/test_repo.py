"""Repo hygiene: what a stranger sees when they open the project.

Checks what is reliably forgotten when tidying up — versions that drift apart; leftovers in the
repo; secrets; forgotten debug output; suites nobody runs any more. No network, no
dependencies, runs anywhere.

The general checks and the lock lists live in `tests/_kit/` — a shared,
checked-in base that `repokit sync` writes here. It is stdlib-only and downloads nothing at
test time; the promise above stays literally true. What stands here is what
applies only to this project.
"""

# This suite reads the repo state via git. Without git it is not meaningful —
# a missing prerequisite, not a failure.
import shutil  # noqa: E402
from voraussetzung import braucht  # noqa: E402
braucht(shutil.which("git"), "git missing")
# git on the PATH is not enough: Measurement is against `git ls-files`, and that needs a
# repo. There is none in the unpacked sdist — decline there instead of turning red.
import pathlib  # noqa: E402

# `.exists()`, not `.is_dir()`: In a git worktree and in a submodule `.git`
# is a FILE with a pointer. With `.is_dir()` the whole repo hygiene bowed out there
# — private infrastructure, secrets, SHA pins, everything — and the run reported green.
braucht((pathlib.Path(__file__).resolve().parent.parent / ".git").exists(),
        "no git repo (e.g. an unpacked sdist) — the hygiene check measures against `git ls-files`")
import fnmatch
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import backlog, hygiene, manifest  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = hygiene.lade_policy()
PROJECTS = ["TinySesam"]


def read(*parts) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


FILES = hygiene.getrackte_dateien(ROOT)
LIB = [f for f in FILES if f.startswith("tinysesam/") and f.endswith(".py")]
WEB = [f for f in FILES if f.startswith("web/") and f.endswith(".py")]

# ---------- Version: pyproject, __init__ and CHANGELOG must fit together ----------
pv = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M).group(1)
error = hygiene.pruefe_versionsgleichstand(
    ROOT, weitere={"tinysesam/__init__.py": r'^__version__ = "([^"]+)"'})
assert not error, error
print(f"  Version {pv}: pyproject = __init__ = CHANGELOG")

# ---------- Required files ----------
REQUIRED = ["LICENSE", "SECURITY.md", "i18n/SECURITY.de.md", "CHANGELOG.md", "README.md", "i18n/README.de.md",
           "TODO.md", "tinysesam/py.typed", ".gitignore",
           ".github/workflows/ci.yml", ".github/workflows/pages.yml",
           ".github/workflows/release.yml", "Dockerfile", ".dockerignore",
           "scripts/_residue_check.sh", "tests/_kit/hygiene.py",
           "scripts/_backlog.py", "tests/_kit/backlog.py",
           "backlog/README-KONVENTION.md",
           ".github/dependabot.yml",
           "CODE_OF_CONDUCT.md", "i18n/CODE_OF_CONDUCT.de.md",
           "CONTRIBUTING.md", "i18n/CONTRIBUTING.de.md"]
absent = hygiene.pruefe_pflichtdateien(ROOT, REQUIRED)
assert not absent, f"Required files missing: {absent}"
print("  License, SECURITY, CHANGELOG, both READMEs, py.typed, all workflows present")

# ---------- docs/ now contains only attachments; the pages are built by the action ----------
# Exceptions: OPERATIONS.md, the operator docs (failure behaviour, sessions, sign-in paths), and HOME-NETWORK.md
# (domain or bare IP in a home network, T-37). They are
# source text like API.md, not a built page — the Pages action does not publish docs/.
docs = [f for f in FILES if f.startswith("docs/")]
assert sorted(docs) == ["docs/.nojekyll", "docs/HOME-NETWORK.md", "docs/OPERATIONS.md", "docs/theme.css",
                        "docs/wizard.png"], docs
assert not any(f.endswith(".html") for f in FILES), "generated HTML does not belong in the repo"
assert "_site/" in read(".gitignore")
print("  docs/: only OPERATIONS.md, HOME-NETWORK.md, theme.css, wizard.png, .nojekyll — no generated HTML in the repo")

# ---------- docs/OPERATIONS.md says what the code does ----------
# Operator docs whose numbers drift away from the code are worse than none: People plan
# by them. What is checked is what can be read off mechanically — the wait time on a locked
# database, the healthcheck path and that every identifying factor is in the table of the
# sign-in paths (a new path without a row there would be exactly the gap from B1-11).
operation = read("docs", "OPERATIONS.md")
_store_src = read("tinysesam", "store.py")
_busy = int(re.search(r"^    BUSY_TIMEOUT_MS = ([\d_]+)", _store_src, re.M).group(1).replace("_", ""))
assert f"**{_busy // 1000} s**" in operation, f"OPERATIONS.md does not name the real wait time ({_busy} ms)"
assert re.search(r'^HEALTH_PATH = "/healthz"', read("tinysesam", "gateway.py"), re.M) and "/healthz" in operation
_ident = re.search(r"^    _IDENTIFYING = \(([^)]*)\)", read("tinysesam", "manager.py"), re.M).group(1)
_factors = re.findall(r'"(\w+)"', _ident)
assert len(_factors) >= 6, f"_IDENTIFYING not read: {_factors}"
_absent = [f for f in _factors if f"(`{f}`" not in operation]
assert not _absent, f"OPERATIONS.md: sign-in path without a row in the strength table: {_absent}"
print(f"  docs/OPERATIONS.md: wait time {_busy // 1000} s, /healthz and all {len(_factors)} "
      "identifying factors match the code")

# ---------- The Python names the docs mention exist in the code ----------
# `docs/OPERATIONS.md` sent embedders to `auth.store.schreibprobe()` and `Store.loeschsperre` for weeks after both had
# been renamed — nothing compared the docs with the code in this direction (the READMEs' tier lists check code → docs).
# Every dotted name in the live docs (`auth.…`, `tinysesam.…`, `TinySesam.…`, `Store.…`, `TinySesamConfig.…`; in
# backticks, or anywhere inside a code block) must consist of words that the package defines somewhere: a function,
# class, attribute, parameter, module or imported name. A set of words and not a resolved path on purpose — it needs no
# import and no extras, and it still finds a name that was renamed (the old word is gone from the whole package).
# OLD names stay where the docs talk about the past — `_german_words.history_lines` defines where (old → new pairs,
# version numbers, "German", the rollback sections), the same exemption the German-words guard uses. Not read:
# CHANGELOG and backlog (history by nature). `NAME` is a placeholder, `.git` ends the repo URL, `auth.example.…` is a host name.
import ast as _ast  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "tests"))
from _german_words import history_lines  # noqa: E402

_DOC_ROOTS = r"(?:auth|tinysesam|TinySesam|Store|TinySesamConfig)"
_DOTTED = re.compile(r"(?<![\w.])" + _DOC_ROOTS + r"((?:\.[A-Za-z_]\w*)+)")
_NOT_NAMES = frozenset({"NAME", "git"})


def package_words(sources) -> set:
    """Every name that the given Python sources define, assign, take as a parameter, import or call with a keyword."""
    words = set()
    for rel, source in sources:
        words.add(os.path.splitext(os.path.basename(rel))[0])
        for n in _ast.walk(_ast.parse(source)):
            if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
                words.add(n.name)
            elif isinstance(n, _ast.Name) and isinstance(n.ctx, _ast.Store):
                words.add(n.id)
            elif isinstance(n, _ast.Attribute) and isinstance(n.ctx, _ast.Store):
                words.add(n.attr)
            elif isinstance(n, _ast.arg):
                words.add(n.arg)
            elif isinstance(n, _ast.alias):
                words.add((n.asname or n.name).split(".")[-1])
            elif isinstance(n, _ast.keyword) and n.arg:
                words.add(n.arg)
    return words


def stale_doc_names(text: str, words: set) -> list:
    """[(line, name, [unknown words])] — dotted names in the text with a word the package does not define."""
    out, exempt, fence = [], history_lines(text), False
    for n, line in enumerate(text.split("\n"), 1):
        if line.startswith("```"):
            fence = not fence
            continue
        if n in exempt:
            continue
        for span in ([line] if fence else re.findall(r"`([^`\n]+)`", line)):
            for m in _DOTTED.finditer(span):
                parts = m.group(1).split(".")[1:]
                unknown = [w for w in parts if w not in words and w not in _NOT_NAMES]
                if unknown and parts[0] != "example":     # `auth.example.com` is a host name, not a Python name
                    out.append((n, m.group(0), unknown))
    return out


_package_words = package_words((f, read(f)) for f in LIB)
_live_docs = ["README.md", "API.md", "SECURITY.md", "CONFIGURATION.md", "CONTRIBUTING.md", "TODO.md", "docs/OPERATIONS.md",
              "docs/HOME-NETWORK.md", "deploy/systemd/README.md", "AGENTS.md", "CLAUDE.md",
              "skills/tinysesam/SKILL.md"] + sorted(f for f in FILES if f.startswith("i18n/") and f.endswith(".md"))
_stale = [f"{d}:{n}: {name} → {unknown}" for d in _live_docs for n, name, unknown in stale_doc_names(read(d), _package_words)]
assert not _stale, "the docs name Python names that no longer exist:\n  " + "\n  ".join(_stale[:8])
# Self-test and mutations: a renamed name is found; the same name inside history is not; a real doc with a stale name is red.
_probe_words = {"auth", "store", "write_probe", "Store", "deletion_guard", "set_disabled"}
assert stale_doc_names("Use `auth.store.old_write_probe()` here.\n", _probe_words) == [(1, "auth.store.old_write_probe", ["old_write_probe"])]
assert stale_doc_names("| Row | `Store.old_deletion_guard` |\n", _probe_words)
assert stale_doc_names("```python\nauth.store.write_probe()\nauth.store.old_write_probe()\n```\n", _probe_words)
assert not stale_doc_names("Use `auth.store.write_probe()` and `Store.deletion_guard`, see `auth.example.com`.\n", _probe_words)
assert not stale_doc_names("Up to 0.24.x `auth.store.old_write_probe()`, now `auth.store.write_probe()`.\n", _probe_words)
assert not stale_doc_names("Renamed: `auth.store.old_write_probe()` → `auth.store.write_probe()`.\n", _probe_words)
assert not stale_doc_names("## Rollback to 0.24.x\n\nSee `Store.old_deletion_guard`.\n\n## Next\n", _probe_words)
assert stale_doc_names("## Rollback to 0.24.x\n\n## Next\n\nSee `Store.old_deletion_guard`.\n", _probe_words), \
    "the exemption of a rollback section must end with the section"
for _old_text, _new_text in (("`auth.store.write_probe()`", "`auth.store.old_write_probe()`"),
                             ("`Store.deletion_guard`", "`Store.old_deletion_guard`")):
    assert _old_text in operation, f"mutation anchor {_old_text} not in OPERATIONS.md"
    assert stale_doc_names(operation.replace(_old_text, _new_text, 1), _package_words), \
        f"a stale name in OPERATIONS.md ({_new_text}) goes unnoticed"
assert len(_package_words) > 1500, f"package words not read: {len(_package_words)}"
print(f"  docs: every dotted Python name in {len(_live_docs)} docs exists in the package ({len(_package_words)} words)")

# The image's HEALTHCHECK must wait longer than the database: `/healthz` writes and, like every sign-in,
# waits up to BUSY_TIMEOUT_MS behind a foreign writer. With 4 s the
# check aborted on a 6-s lock, although the service returned 200 afterwards (A-B6-4-healthz-lock).
_df = read("Dockerfile")
_hc_docker = int(re.search(r"HEALTHCHECK [^\n]*--timeout=(\d+)s", _df).group(1))
_hc_client = int(re.search(r"HTTPConnection\(.*?timeout=(\d+)\)", _df).group(1))
assert _hc_client * 1000 > _busy, f"Health client waits {_hc_client} s, the database up to {_busy} ms"
assert _hc_docker > _hc_client, f"Docker aborts after {_hc_docker} s, before the client ({_hc_client} s)"
print(f"  Dockerfile: HEALTHCHECK waits {_hc_client} s/{_hc_docker} s, longer than busy_timeout")

# ---------- Generated artifacts do not belong in the repo ----------
artifacts = hygiene.pruefe_artefakte(FILES, POLICY)
assert not artifacts, f"generated artifacts are versioned: {artifacts[:5]}"
print(f"  no generated artifacts among {len(FILES)} tracked files")

# ---------- Colour values only in the two permitted places ----------
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
allowed = {"tinysesam/theme.py"}
for f in LIB:
    if f in allowed:
        continue
    for line in read(f).splitlines():
        if HEX.search(line) and "#fff" not in line:
            raise AssertionError(f"colour value outside theme.py: {f}: {line.strip()[:70]}")
print("  Colour values: only in tinysesam/theme.py (app) or docs/theme.css (website)")

# ---------- No forgotten debug output in the library ----------
# __main__.py is the CLI — there print is the output, not a leftover. In gateway.py the same
# holds, but ONLY for `main()`: The rest of the file is library and must not print anything.
# (The boundary stands here because an exception for the whole file would let through exactly
# what the check is looking for.)
#
# The SYNTAX TREE is read, not the line text: A `print(...)` in a docstring — such as
# an example of how to catch an error — is not a forgotten debug output. The
# text search mistook one for one and raised the alarm; a false alarm costs the same trust as
# a missed finding.
import ast as _ast  # noqa: E402

for f in LIB:
    if f == "tinysesam/__main__.py":
        continue
    tree = _ast.parse(read(f))
    permitted = set()
    # The `main()` of a command line (the gateway, the reference client `tinysesam-client`, T-60) prints on purpose,
    # and so does the gateway's subcommand `pair` (its `_pair`, called only from `main`) — and `run` of `diagnose`
    # (T-79), the command both CLIs call; the report builders of that module return text and print nothing.
    commands = {"tinysesam/gateway.py": ("main", "_pair"), "tinysesam/client.py": ("main",),
                "tinysesam/_diagnose.py": ("run",)}.get(f, ())
    for node in _ast.walk(tree):
        if isinstance(node, _ast.FunctionDef) and node.name in commands:
            permitted |= set(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call) or not isinstance(node.func, _ast.Name):
            continue
        if node.func.id in ("print", "breakpoint") and node.lineno not in permitted:
            raise AssertionError(f"Debug output in the library:{f}:{node.lineno}: "
                                 f"{node.func.id}(...)")
print("  no print()/breakpoint() in tinysesam/")

# ---------- No obvious secrets ----------
leaks = hygiene.pruefe_geheimnisse(ROOT, FILES, POLICY)
assert not leaks, f"possible key in {leaks[:3]}"
print("  no tokens or private keys checked in")

# ---------- Every suite runs in the collective run ----------
suites = sorted(f for f in FILES if f.startswith("tests/test_") and f.endswith(".py"))
assert len(suites) >= 30, len(suites)
runner = read("tests", "run_all.py")
assert 'glob.glob(os.path.join(HERE, "test_*.py"))' in runner, "run_all no longer collects automatically"
print(f"  {len(suites)} suites, all covered by the collective run")

# ---------- No private infrastructure in the public repo ----------
# The dividing line is **identity versus infrastructure**, not "my name occurs".
# Allowed and partly legally required: author, imprint address, licence, repo URL,
# project name. Forbidden is what helps someone find the systems behind it.
#
# Patterns and block list live in tests/_kit/hygiene_policy.json — one source for all
# repos. Before, every repo carried its own copy, and they drifted apart: this one
# knew seven names, the sister project thirteen, and the IP patterns had the exception for CIDR masks in the docs
# in only one of the two.
hits = hygiene.pruefe_private_infrastruktur(ROOT, FILES, POLICY, PROJECTS)
assert not hits, "private infrastructure in the public repo:\n  " + "\n  ".join(hits[:8])
print(f"  no private infrastructure ({len(POLICY['private_muster'])} patterns"
      f" + {len(POLICY['private_namen_sha256_16'])} names)")

# The kit's patterns catch hosts, IPs and names but not a maintainer's own file paths: a workflow
# comment pointed at a private documentation page in a dot-directory of the home folder and passed unnoticed.
# Local pattern, built from pieces so that this file does not match itself. Files that the test kit
# manages (`repokit sync`) are not edited here and therefore not scanned.
_KIT_MANAGED = {".githooks/pre-push", "scripts/_nur_text.sh", "scripts/_residue_check.sh",
                  "scripts/_backlog.py", "backlog/README-KONVENTION.md"}
_PRIVATE_PATH = re.compile("(?:~/\\." + "|/ho" + "me/[a-z]|\\." + "claude/)")


def private_paths(files, read):
    """`file:line` for every line that names a private home-directory path."""
    hit = []
    for rel in files:
        if rel in _KIT_MANAGED or rel.startswith("tests/_kit/"):
            continue
        try:
            text = read(rel)
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.split("\n"), 1):
            if _PRIVATE_PATH.search(line):
                hit.append(f"{rel}:{n}")
    return hit


_paths = private_paths(FILES, read)
assert not _paths, "private file path in the public repo:\n  " + "\n  ".join(_paths[:8])
# Self-probe: the check must see what it is meant to see (a check that cannot fail proves nothing).
_probe = private_paths(["probe"], lambda _r: "See " + "~/" + ".cl" + "aude/context/x.md")
assert _probe == ["probe:1"], _probe
_probe = private_paths(["probe"], lambda _r: "cp x " + "/ho" + "me/someone/y")
assert _probe == ["probe:1"], _probe
print("  no private home-directory paths in tracked files")

# ---------- Documented standards, enforced by machine ----------
# A tag can be moved; a commit SHA is the only immutable reference.
unpinned = hygiene.pruefe_actions_sha_gepinnt(ROOT, FILES)
assert not unpinned, "actions not pinned to a commit SHA:\n  " + "\n  ".join(unpinned)

# There is no safe default: the initial permission comes from the repo setting.
without_permissions = hygiene.pruefe_workflow_permissions(ROOT, FILES)
assert not without_permissions, "workflow without `permissions:`:\n  " + "\n  ".join(without_permissions)
print(f"  all actions pinned by commit SHA, every workflow sets `permissions:`")

# Keep a Changelog 1.1.0 — fixed set of categories, one language per repo.
categories = hygiene.pruefe_changelog_kategorien(ROOT, POLICY)
assert not categories, "CHANGELOG:\n  " + "\n  ".join(categories[:5])

# GitHub picks the README by LOCATION, not by language — a translation silently goes stale.
# The translations live under i18n/, so that GitHub's health-file detector (CODE_OF_CONDUCT,
# SECURITY, …) picks the English root files and not the alphabetically first .de version.
translation = hygiene.pruefe_uebersetzungs_struktur(ROOT, [("README.md", "i18n/README.de.md")])
assert not translation, "translation deviates:\n  " + "\n  ".join(translation)
print("  CHANGELOG categories valid; i18n/README.de.md follows the structure of README.md")

# ---------- Every pinned example tag points to the current version ----------
# Otherwise the docs silently keep recommending an old version: The pin in the compose file and the
# `pip install` lines in the README do not age along, because nobody runs them.
PINS = (re.compile(r"TinySesam(?:\.git)?[@/](?:releases/download/)?v(\d+\.\d+\.\d+)"),  # Git tag, wheel
        re.compile(r"tinysesam(?:-caddy-gate)?:v(\d+\.\d+\.\d+)"))                     # image tags (gateway, Caddy)
for f in ("README.md", "i18n/README.de.md", "deploy/forward-auth/docker-compose.yml",
          "deploy/quickstart/docker-compose.yml"):
    body = read(f)
    for pat in PINS:
        for found in pat.findall(body):
            assert found == pv, f"{f} pins v{found}, current is v{pv}"
print(f"  all example pins (Git tag, wheel, image) point to v{pv}")

# ---------- No self-update: the library does not download code ----------
# Whoever takes over the admin panel could otherwise switch back to an old, vulnerable version.
# An auth library does not start processes. `sys.executable`/`subprocess` would be the way
# a self-update would come back — hence the boundary is here, not at the word "pip"
# (which appears harmlessly in docstrings that give installation hints).
# The SYNTAX TREE is read, not the line text. The text search only knew
# `import subprocess` and `subprocess.foo(` — `from subprocess import run` and `os.system(...)`
# slipped straight through, although a security statement stands next to it. Both are not exotic
# spellings.
PROCESS_MODULE = {"subprocess", "multiprocessing", "pty"}
PROCESS_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
                   ("os", "execvp"), ("os", "spawnv"), ("os", "spawnl"), ("os", "fork")}

for f in LIB:
    body = read(f)
    assert "self_update" not in body, f"self-update built in again: {f}"
    assert "sys.executable" not in body, f"{f} starts an interpreter"
    tree = _ast.parse(body)
        # Resolve the aliases first: `import os as _o` turns `_o.system(...)` into `os.system(...)`,
        # and a check that only looks at the name "os" overlooks that.
    alias = {}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            for a in node.names:
                alias[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            hit = [a.name.split(".")[0] for a in node.names
                       if a.name.split(".")[0] in PROCESS_MODULE]
            assert not hit, f"{f}:{node.lineno} imports {hit[0]} — starts processes"
        elif isinstance(node, _ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in PROCESS_MODULE, \
                f"{f}:{node.lineno} imports from {root} — starts processes"
        elif isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute):
            value = node.func.value
            if isinstance(value, _ast.Name):
                module = alias.get(value.id, value.id)
                if (module, node.func.attr) in PROCESS_CALLS:
                    raise AssertionError(f"{f}:{node.lineno} calls {module}.{node.func.attr}() "
                                         "— starts a process")
print(f"  no self-update, no process start in the library "
      f"({len(PROCESS_MODULE)} modules, {len(PROCESS_CALLS)} calls checked)")

# ---------- The website generator writes exactly what the action deploys ----------
action = read(".github", "workflows", "pages.yml")
assert "python -m web.build _site" in action
assert "upload-pages-artifact" in action and "path: _site" in action
print("  pages.yml builds web/ and uploads _site")

# ---------- No language filename any more, no second system ----------
for f in WEB + [x for x in FILES if x.startswith("examples/")]:
    body = read(f)
    assert ".de.html" not in body, f"language filename in {f}"
print("  one language system: no `.de.html` anywhere")

# ---------- Imprint complete ----------
sys.path.insert(0, ROOT)
from web.site import OWNER, SITE_URL   # noqa: E402

for key in ("name", "street", "city", "country", "email"):
    v = OWNER[key]
    assert v and not v.startswith("«"), f"OWNER[{key}] is a placeholder"
assert "@" in OWNER["email"] and SITE_URL
print("  Imprint: all mandatory details set")

# ---------- The automation itself: scripts, hook, CI jobs ----------
for f in ("scripts/check.sh", ".githooks/pre-push"):
    assert f in FILES, f"{f} is missing — without the gate nobody runs the suite"
    assert os.access(os.path.join(ROOT, f), os.X_OK), f"{f} is not executable"

hook = read(".githooks", "pre-push")
assert "scripts/check.sh" in hook, "the hook must run the suite"

check = read("scripts", "check.sh")
assert "tests/run_all.py" in check and "web.build" in check

ci = read(".github", "workflows", "ci.yml")
for needed in ("tests/test_browser.py", "tests/test_repo.py", "tests/test_site.py",
               "python -m web.build", "setup-chrome"):
    assert needed in ci, f"CI does not run {needed}"
# B-13: both jobs that start Chrome (`browser`, `repeat`) hand the browser suites setup-chrome's Chrome. Without `CHROME` the
# name lookup finds the runner image's cold preinstalled google-chrome and the start misses its 30 s.
assert ci.count("CHROME: ${{ steps.chrome.outputs.chrome-path }}") >= 3, "CI must pass CHROME to the browser suites"
assert ci.count("id: chrome") >= 2, "setup-chrome needs `id: chrome` for its chrome-path output"

# Every job carries a time limit (pipeline register 2026-10-07): Without it GitHub's default of 360 min applies, and
# a hanging `apt-get` blocked PR #135 for as long as `pr-mergen` waited. The text is read — jobs
# are the keys with two spaces under `jobs:`, the limit is in the block with four spaces.
_without_limit, _jobs_seen = [], 0
for _wf in sorted(pathlib.Path(ROOT, ".github", "workflows").glob("*.yml")):
    _body = _wf.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    for _block in re.split(r"\n(?=  [A-Za-z0-9_-]+:\n)", "\n" + _body):
        _m = re.match(r"\n?  ([A-Za-z0-9_-]+):\n", _block)
        if not _m:
            continue
        _jobs_seen += 1
        # A job that calls a reusable workflow (`uses:` at job level, T-55) may not carry a limit itself — GitHub
        # rejects `timeout-minutes` there; every job of the called workflow carries its own (checked in its file).
        if re.search(r"\n    uses: (\.|\$)/\.github/workflows/[\w.-]+\.yml(?:  #[^\n]*)?\n", _block):
            continue
        if not re.search(r"\n    timeout-minutes: [1-9][0-9]*\n", _block):
            _without_limit.append(f"{_wf.name}: {_m.group(1)}")
assert _jobs_seen >= 20, f"only {_jobs_seen} jobs recognised — check no longer reads the workflows"
assert not _without_limit, "job without timeout-minutes:\n  " + "\n  ".join(_without_limit)
print(f"  timeout-minutes in all {_jobs_seen} jobs")

# Public repo → never a self-hosted runner: a fork PR would otherwise run on foreign hardware.
#
# Via `hygiene.pruefe_kein_self_hosted_runner`, not via a text search of our own: The function
# in the kit strips YAML comments, the text search here did not. A workflow that EXPLAINS
# the rule in a comment ("no self-hosted runners, because …") tripped it — a
# false alarm that punishes precisely the good behaviour. Two checks for the same thing
# are one too many anyway.
self_hosted = hygiene.pruefe_kein_self_hosted_runner(ROOT, FILES)
assert not self_hosted, ("self-hosted runner in a public repo:\n  "
                         + "\n  ".join(self_hosted))

# Kit 0.13.x: every kit check is called or exempted with a reason — the guard below reports
# when a new one silently lies around (that is how three matrix checks lay uncalled in seven repos, and
# every suite looked green). Real public services are not example addresses and are therefore listed
# in a named list, not in an exception.
PUBLIC_SERVICES = ["pypi.org", "raw.githubusercontent.com", "img.shields.io", "spdx.dev",
                        "www.flaticon.com", "ollornog.github.io", "github.com",
                                                # Entra ID endpoint of the bundled preset — a real, fixed
                                                # address of Microsoft, not an example address and nothing of our own.
                        "login.microsoftonline.com",
                                                # H1: where the author of the password corpus behind
                                                # tinysesam/common_passwords.txt released it to the public domain —
                                                # cited as the license evidence.
                        "medium.com",
                                                # ADR-12: the documentation of the keyring patterns it takes over
                                                # (Django, Rails, Tink) — cited as sources.
                        "docs.djangoproject.com", "guides.rubyonrails.org", "developers.google.com"]
addresses = hygiene.pruefe_adressen(ROOT, FILES, POLICY, zusaetzliche_hosts=PUBLIC_SERVICES)
assert not addresses, "addresses outside RFC 2606 and the service list:\n  " + "\n  ".join(addresses)
not_executable = hygiene.pruefe_ausfuehrbar(
    ROOT, ["scripts/check.sh", "scripts/_backlog.py", "scripts/_codeql_backlog.py", "tests/run_all.py"])
assert not not_executable, "\n  ".join(not_executable)
abort = hygiene.pruefe_kein_abbruch_auf_default_branch(ROOT, FILES)
assert not abort, "cancel-in-progress on main:\n  " + "\n  ".join(abort)
matrix_rule = hygiene.pruefe_python_matrix_regel()
assert not matrix_rule, "\n  ".join(matrix_rule)
collects = hygiene.pruefe_run_all_sammelt_automatisch(ROOT)
assert not collects, "\n  ".join(collects)
# Since the decision on PR #54 (lower bound 3.12) this repo runs the kit matrix
# unchanged — the two earlier exceptions are thereby settled and the checks run.
matrix_deviation = hygiene.pruefe_python_matrix(ROOT, FILES)
assert not matrix_deviation, "Python matrix deviates from the kit source:\n  " + "\n  ".join(matrix_deviation)
lower_limit = hygiene.pruefe_requires_python(ROOT)
assert not lower_limit, "\n  ".join(lower_limit)
# Kit 0.14.0: Every `actions/checkout` sets `persist-credentials: false`. **Level:** own
# hardening, not a documented standard — GitHub recommends it nowhere explicitly. What it brings:
# With the default the token is readable for EVERY later step in the job, and after the
# checkout foreign code runs here (`pip install -e`, third-party actions). No exception needed:
# No job of this repo pushes or tags via git — measured, not assumed.
without_pc = hygiene.pruefe_persist_credentials(ROOT, FILES)
assert not without_pc, "checkout without persist-credentials:\n  " + "\n  ".join(without_pc)

# Kit 0.14.0: Is the file list complete at all? An empty list makes EVERY check
# after it green, and the real case was not "empty": Via `git archive` elsewhere 6 of
# 1326 files were missing — the whole `.github/`, i.e. exactly the workflows that two checks above read.
# `root=` is mandatory, otherwise it is only compared against a minimum count instead of against `git ls-tree`.
gaps = hygiene.pruefe_dateiliste_plausibel(FILES, root=ROOT)
assert not gaps, "the checked file list is incomplete:\n  " + "\n  ".join(gaps)

# Kit 0.14.0: Host names WITHOUT `https://` in front. `pruefe_adressen` only looks for URLs with a scheme, and
# the infrastructure pattern demands three name parts — a bare second-level domain slips
# through both. In a foreign repo a real company name stood there that way.
#
# The `grundstock` was REVIEWED ONCE, not generated: Every entry is here because someone
# looked up why the address occurs in the repo. Filled automatically it would be the baseline
# that waves the next real finding through as well.
BARE_ADDRESSES_OK = [
    "ghcr.io",                 # the registry the own image comes from (Dockerfile, compose)
    "gcr.io",                  # the public registry of the runtime base (gcr.io/distroless, Dockerfile, T-59)
    "pypi.org",                # the package index test_packaging checks against
    "python.org",              # source reference in the kit file python_matrix.json
    "devguide.python.org",     # ditto — the release calendar the matrix follows from
    "flaticon.com",            # source reference for the favicon (licence obligation, belongs in plain sight)
    "ollornog.github.io",      # the own project page: identity, not infrastructure
    # The last two are NOT addresses, they just look like it:
    "ab.de",                   # tests/test_identifier.py: `assert not valid_email("ab.de")`
    "admin.app",               # tinysesam/messages.py: a translation key, not a host
]
# Go module manifests (deploy/forward-auth/caddy-gate, since 2026-11-20) are the exception by FILE, not by host: every
# module path starts with its host (`golang.org/x/net`, `howett.net/plist`), the list is written by `go mod tidy` and
# grows with every Dependabot bump — a host list here would turn each such PR red and teach to wave hosts through.
# The files cannot carry a private host either: `go mod download` in the image build fetches every path publicly and
# `go mod verify` holds it against go.sum. All other checks (private patterns, secrets) still read them.
_GO_MANIFESTS = {f for f in FILES if os.path.basename(f) in ("go.mod", "go.sum")}
blank = hygiene.pruefe_blanke_adressen(ROOT, [f for f in FILES if f not in _GO_MANIFESTS], POLICY,
                                       zusaetzliche_hosts=PUBLIC_SERVICES, grundstock=BARE_ADDRESSES_OK)
assert not blank, "bare host names outside the reviewed list:\n  " + "\n  ".join(blank)

# Kit 0.17: three checks on the kit itself. `belegstellen` is empty — TinySesam keeps no
# citation index; the call is there anyway, so that a later entry gets checked.
proof = hygiene.pruefe_belegstellen_eng(ROOT, FILES, [])
assert not proof, "citation patterns hit code:\n  " + "\n  ".join(proof)
table = hygiene.pruefe_tabelle_vollstaendig()
assert not table, "kit check in no list or in several:\n  " + "\n  ".join(table)
key_name = hygiene.pruefe_policy_schluessel_gelesen(POLICY)
assert not key_name, "policy keys without a reader:\n  " + "\n  ".join(key_name)

# Kit 0.18: Nothing is loaded from third parties (PO rule 2026-09-23). A link is a door, a
# `src` is a messenger: objected to are src/srcset, <link href>, url(), @import, fetch()/import(),
# <iframe src> — never an <a href>. Limit: what JavaScript assembles at runtime, this
# check does not see.
foreign = hygiene.pruefe_keine_fremdressourcen(ROOT, FILES, POLICY)
assert not foreign, "third-party resources in the markup:\n  " + "\n  ".join(foreign)
# Kit 0.28 (PO 2026-10-08): every complete page carries a favicon. The built-in pages are built by the code; they
# are checked by tests/test_gate_brand.py (brand_icon) — here the files in the repo (website, demos).
favicon = hygiene.pruefe_favicon(ROOT, FILES, POLICY)
assert not favicon, "pages without favicon:\n  " + "\n  ".join(favicon)

# Kit 0.21: Asked from OUTSIDE whether every test file runs at all. A test that is not wired up
# passes its own call check (the line below) by keeping silent. Here
# `tests/run_all.py` collects via glob — the check recognises that and then does not ask per file.
test_files = hygiene.pruefe_testdateien_gerufen(ROOT)
assert not test_files, "test file without runner:\n  " + "\n  ".join(test_files)

# Kit 0.21.8: In a tag-triggered workflow with a button nothing is published without a tag — the
# general version of the release.yml guard further below (which additionally checks the dry run).
am_tag = hygiene.pruefe_veroeffentlichen_am_tag(ROOT)
assert not am_tag, "published without tag:\n  " + "\n  ".join(am_tag)

# Kit 0.24.0 (T-9): unprotected imports of optional extras in tests otherwise only show up in the job
# `minimal` (PR #101, ldap3). `auch_minimal` = exactly the `pip install` of that job.
_extras = hygiene.pruefe_extras_imports(ROOT, FILES, auch_minimal=["httpx", "setuptools", "wheel"])
assert not _extras, "extra imported unprotected:\n  " + "\n  ".join(_extras)

# Kit 0.27.0: The worker count of parallel runs comes from `CI_KERNE`, never from detection.
_worker = hygiene.pruefe_parallel_worker(ROOT, FILES)
assert not _worker, "worker count not from CI_KERNE:\n  " + "\n  ".join(_worker)

# The vulnerability gate (Kit 0.31.0, M6/B1): audit.yml with pip-audit exists; hence CALLED.
_aw = hygiene.pruefe_audit_workflow(ROOT, FILES)
assert not _aw, "vulnerability gate missing or not armed:\n  " + "\n  ".join(_aw)
print("  Vulnerability gate: pip-audit hashed and pinned, zero-case guard")

# Kit 0.35.0 (T-16): text check (dead links and anchors, frontmatter) and the text fast path
# (wired up in scripts/check.sh, allowlist only narrowed).
_tx = hygiene.pruefe_texte(ROOT, [d for d in FILES if d.endswith(".md")])
assert not _tx, "texts: dead links/anchors or broken frontmatter:\n  " + "\n  ".join(_tx)
_nt = hygiene.pruefe_nur_text(ROOT)
assert not _nt, "text fast path not wired up or list extended:\n  " + "\n  ".join(_nt)
print("  Kit 0.35.0: texts clean (links, anchors, frontmatter), text fast path wired up")

# The vendored test kit is unchanged against its manifest. Until the config check was renamed,
# the kit's "is every check called?" guard counted `config_check.check_config(...)` calls (then
# `pruefe(...)`) as calls of `manifest.pruefe` — a name-only match — so this check never ran here.
_mf = manifest.pruefe(ROOT)
assert not _mf, "test kit differs from its manifest:\n  " + "\n  ".join(_mf)
print("  Test kit: files match MANIFEST.sha256")

uncalled = hygiene.pruefe_kit_prueffunktionen_gerufen(ROOT, ausgenommen={})
assert not uncalled, "kit check lies idle:\n  " + "\n  ".join(uncalled)
print("  Kit 0.21.8: every check called, no exception needed; every test file has a runner; nothing published without a tag")

rel = read(".github", "workflows", "release.yml")
assert "tags:" in rel and "sha256sum" in rel, "release builds no checksums"
assert "linux/amd64,linux/arm64" in rel, "image is not multi-arch"
assert ":latest" not in rel, "a floating `latest` tag does not belong in the release"
# Registries demand lowercase names; `github.repository_owner` delivers the
# spelling of the account and broke the build ("repository name must be lowercase").
for line in rel.splitlines():
    if line.strip().startswith("tags:") and re.search(r"\bghcr\.io/", line):
        assert "repository_owner" not in line, "image tag uses the capitalisation of the account"

# The image must not contain any way to download code — otherwise the self-update would come back
# through the back door. And it does not run as root.
dockerfile = read("Dockerfile")
# Since T-59 the runtime stage is distroless: no shell, no package manager, and only what the build stage hands over.
# Measured on the LAST stage — a `USER tinysesam` or an exec-form RUN in the build stage proves nothing about the image.
_final = dockerfile[dockerfile.rindex("\nFROM "):]
_final_code = re.sub(r"\\\n\s*", " ", "\n".join(z for z in _final.splitlines() if not z.lstrip().startswith("#")))
assert re.search(r"^FROM gcr\.io/distroless/[a-z0-9-]+:nonroot@sha256:[0-9a-f]{64}\s*$", _final_code, re.M), \
    "Dockerfile: the runtime stage is not on a digest-pinned distroless base (T-59)"
assert re.search(r"^USER tinysesam\s*$", _final_code, re.M), "image runs as root"
assert re.search(r"^HEALTHCHECK .*CMD \[", _final_code, re.M), "image without health check (exec form — no shell)"
# Every RUN of the runtime stage in exec form: the base has no /bin/sh, a shell-form RUN would need one — and a base
# that HAS one again would turn it green silently.
_runs = [z for z in _final_code.splitlines() if z.startswith("RUN ")]
_shell_form = [z for z in _runs if not re.match(r"^RUN\s+(--[a-z]+=\S+\s+)*\[", z)]
assert not _shell_form, f"Dockerfile: RUN in shell form in the runtime stage (it has no shell): {_shell_form}"
assert any("deploy/gateway/image_setup.py" in z for z in _runs), \
    "Dockerfile: the runtime stage does not run deploy/gateway/image_setup.py (account, completeness, no shell)"
# pip leaves on all three ways in: the venv's own, the system one, the wheel bundled for ensurepip.
_df_code = "\n".join(z for z in dockerfile.splitlines() if not z.lstrip().startswith("#"))
for away in ("/opt/venv/bin/pip", "site-packages/pip", "ensurepip"):
    assert away in _df_code, f"Dockerfile: {away} is not removed — pip would be in the image"
_setup = read("deploy/gateway/image_setup.py")
_forbidden = re.search(r"^FORBIDDEN = \((.*?)\)$", _setup, re.M | re.S)
assert _forbidden and {"sh", "bash", "busybox", "apt", "dpkg", "apk", "pip"} <= set(re.findall(r'"([^"]+)"',
                                                                                         _forbidden.group(1))), \
    "image_setup.py: FORBIDDEN no longer names shells, package managers and pip"
assert "sh -c true" in read("scripts/_image_probe.sh"), "image-probe no longer checks the RUNNING image for a shell"
print("  check.sh + pre-push present; CI runs browser, hygiene and website tests; release signs checksums; "
      "runtime stage distroless, exec-form only, no pip")

# ---------- Supply chain: what T-13 (B4-*) tightened stays tight ----------
# Every check here measures a commitment from the supply-chain round of T-13. YAML is read as
# text (without PyYAML — the suite also runs in the core job without extras), hence narrow: blocks by
# indentation, comments cut off.
WORKFLOWS = sorted(f for f in FILES if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")))


def _code(text: str) -> list[str]:
    return [hygiene.ohne_yaml_kommentar(z).rstrip() for z in text.splitlines()]


def _jobs(text: str) -> dict[str, list[str]]:
    """Job name → its lines (without comments). Jobs stand two spaces deep under `jobs:`."""
    lines, jobs, name, inside = _code(text), {}, None, False
    for z in lines:
        if z.startswith("jobs:"):
            inside = True
            continue
        if inside and z and not z.startswith(" "):
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", z)
        if inside and m:
            name = m.group(1)
            jobs[name] = []
        elif inside and name:
            jobs[name].append(z)
    return jobs


def _command_list(lines: list[str], key_name: tuple[str, ...] = ("run",)) -> list[str]:
    """The lines of all `run:` steps (or of the key in `key_name`) — single-line and as
    block (`run: |`)."""
    from_, block_depth = [], None
    for z in lines:
        depth = len(z) - len(z.lstrip())
        if block_depth is not None:
            if z.strip() and depth <= block_depth:
                block_depth = None
            else:
                from_.append(z.strip())
                continue
        m = re.match(rf"^(\s+)(?:- )?(?:{'|'.join(key_name)}):\s*(.*)$", z)
        if m:
            if m.group(2) in ("|", ">", "|-", ">-"):
                block_depth = len(m.group(1))
            else:
                from_.append(m.group(2))
    return [k for k in from_ if k]


# B4-4 — Whoever holds an identity or a write permission does not run foreign code. Until 0.19.0
# the whole suite including `pip install ".[all]"` ran in the job that also attested — every
# dependency could have issued an attestation on the workflow's identity.
#
# Which permissions a job holds is read from EVERY spelling: block (`id-token: write`),
# flow map (`{id-token: write}`), `write-all`, and inherited from the workflow level if the job
# sets nothing itself. Until the re-check (A-2) the latch only saw the block spelling and only
# `id-token`/`contents` — a new job with `permissions: write-all` went straight through.
def _permissions_value(value: str, following: list[str], depth: int) -> set[str]:
    """The write permissions from a `permissions:` value; `*` stands for write-all."""
    value = value.strip().strip("'\"")
    if value == "write-all":
        return {"*"}
    if value in ("read-all", "{}"):
        return set()
    if value.startswith("{"):
        pairs = [p.split(":", 1) for p in value.strip("{}").split(",") if ":" in p]
        return {k.strip() for k, v in pairs if v.strip().strip("'\"") == "write"}
    assert not value, f"unknown permissions value {value!r} — adjust guard"
    permissions = set()
    for z in following:
        if z.strip() and len(z) - len(z.lstrip()) <= depth:
            break
        m = re.match(r"^\s+([a-z-]+):\s*(\S+)", z)
        if m and m.group(2).strip("'\"") == "write":
            permissions.add(m.group(1))
    return permissions


def _permissions_above(text: str) -> set[str]:
    lines = _code(text.split("\njobs:", 1)[0])
    for i, z in enumerate(lines):
        m = re.match(r"^permissions:\s*(.*)$", z)
        if m:
            return _permissions_value(m.group(1), lines[i + 1:], 0)
    return {"*"}   # without a statement the repo default applies — in the worst case write permission


def _permissions_job(lines: list[str], inherited: set[str]) -> set[str]:
    for i, z in enumerate(lines):
        m = re.match(r"^    permissions:\s*(.*)$", z)
        if m:
            return _permissions_value(m.group(1), lines[i + 1:], 4)
    return inherited


# Commands a job with identity or write permission may run in `run:` — an allowlist,
# not a block list: `curl … | bash`, `git clone … && node …` or a new tool would slip through
# any word list (A-5). Every member of a command chain and every `$( … )` substitution is checked.
# `gh pr merge` and `gh pr comment` (Dependabot auto-merge, 2026-09-28) stand individually — never
# `gh pr` wholesale: `gh pr checkout` would fetch PR code into a job with write permission.
PERMITTED_WITH_RIGHT = {"echo", "printf", "gh release", "gh attestation", "git log",
                     "gh pr merge", "gh pr comment", "gh workflow run",
                     "gh pr update-branch",  # auto-merge with app: stale branches via rebase (Kit 0.33)
                     "sleep"}  # pause between attest attempts in `rehearsal-attest` (2026-11-22); runs no code


def _commands(line: str) -> list[str]:
    """The individual commands of a shell line — separated at ; && || | ( $( and `.

    What follows after a closing parenthesis belongs to the outer command (`echo "$(git log)"
    >> file`) and is discarded; a pipe inside quotes is read as a separate command
    and thus turns red — better too strict than too blind.
    """
    from_ = []
    for part in re.split(r"\$\(|`|&&|\|\||[;|(]", line):
        words = part.split(")", 1)[0].split()
        while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            words.pop(0)           # VAR=value before the command
        if words:
            from_.append(" ".join(words[:3]))     # three words: `gh pr merge` ≠ `gh pr checkout`
    return from_


def _permitted(command: str) -> bool:
    """An allowlist entry covers the command if it names it word for word:
    `gh release` covers `gh release create`, `gh pr merge` does not cover `gh pr checkout`."""
    words = command.split()
    return any(words[:len(e.split())] == e.split() for e in PERMITTED_WITH_RIGHT)


# Write permissions that MUST get by with checkout — per job exactly these permissions and the reason. The
# checkout is allowed, foreign code in `run:` still is not. If a permission is added, the job turns
# red (the set must match exactly).
CHECKOUT_WITH_RIGHT = {
    (".github/workflows/codeql.yml", "analyse"): ({"security-events"},
                                                   "CodeQL needs the source; no `run:`"),
    (".github/workflows/release.yml", "image"): ({"packages"},
                                                 "build context for the image; pip runs in the BuildKit "
                                                 "container, which does not see the token"),
    (".github/workflows/scorecard.yml", "analysis"): ({"security-events", "id-token"},
                                                      "Scorecard reads the checkout; no `run:` (a condition of "
                                                      "publish_results), id-token only for publishing (H1)"),
}

# A job that only CALLS a reusable workflow of this repo (T-55): it runs no step itself, its permissions are the
# ceiling the called workflow's jobs may narrow — and those jobs go through this loop in their own file. Exactly
# these calls, with exactly these permissions; everything else with a local `uses:` stays red.
REUSABLE_WITH_RIGHT = {
    (".github/workflows/release.yml", "provenance"): ("./.github/workflows/build-provenance.yml",
                                                      {"id-token", "attestations"}),
}

_checked_identity, _exceptions_seen = 0, set()
for wf in WORKFLOWS:
    text = read(wf)
    above = _permissions_above(text)
        # Never a write permission at the top workflow level — every job would inherit it.
    assert not above, f"{wf}: write permission at workflow level ({sorted(above)}) — belongs on the job"
    jobs = _jobs(text)
    assert jobs, f"{wf}: no jobs recognised — check the parser"
    for job, lines in jobs.items():
        permissions = _permissions_job(lines, above)
        if not permissions:
            continue
        _checked_identity += 1
        block = "\n".join(lines)
        call = REUSABLE_WITH_RIGHT.get((wf, job))
        if call:
            _exceptions_seen.add((wf, job))
            assert permissions == call[1], f"{wf} job `{job}`: permissions {sorted(permissions)} instead of {sorted(call[1])}"
            assert re.search(r"^    uses: " + re.escape(call[0]) + r"$", block, re.M), \
                f"{wf} job `{job}` calls something other than {call[0]}"
            assert not re.search(r"^    (steps|runs-on):", block, re.M), f"{wf} job `{job}` runs steps of its own"
            continue
        exception = CHECKOUT_WITH_RIGHT.get((wf, job))
        if exception:
            _exceptions_seen.add((wf, job))
            assert permissions == exception[0], (f"{wf} job `{job}`: permissions {sorted(permissions)} instead of "
                                           f"{sorted(exception[0])} — the exception applies only to that")
        else:
            assert "actions/checkout" not in block, (
                f"{wf} job `{job}` holds {sorted(permissions)} AND checks out the repo — build and "
                "attestation belong in separate jobs")
                # Local actions and Docker actions bring code that no SHA pin holds fast.
        assert not re.search(r"^\s+(?:- )?uses:\s*['\"]?(\./|\$/|docker://)", block, re.M), \
            f"{wf} job `{job}` holds {sorted(permissions)} and uses a local/Docker action"
        assert not re.search(r"^\s+(?:- )?shell:", block, re.M), \
            f"{wf} job `{job}` holds {sorted(permissions)} and sets its own `shell:`"
        for k in _command_list(lines):
            for command in _commands(k):
                assert _permitted(command), (f"{wf} job `{job}` holds {sorted(permissions)} and runs "
                                          f"`{command}`: {k}")
assert _exceptions_seen == set(CHECKOUT_WITH_RIGHT) | set(REUSABLE_WITH_RIGHT), \
    f"exceptions without job: {set(CHECKOUT_WITH_RIGHT) | set(REUSABLE_WITH_RIGHT) - _exceptions_seen} — tidy up the list"
assert _checked_identity >= 6, f"only {_checked_identity} jobs with write permission found — check the parser"
print(f"  {_checked_identity} jobs with identity/write permission (every spelling): only "
      f"{'/'.join(sorted(PERMITTED_WITH_RIGHT))}, checkout only with a justified exception")

# Dependabot auto-merge (PO 2026-09-28): The logic lives in the job without write permission, the job with
# write permission only calls `gh pr merge`/`gh workflow run`/`gh pr comment` (the loop above checks that).
# Here the rest. (Mutation probes: delete `--match-head-commit`; add `--auto`; delete the
# `head_repository` condition; `on: pull_request_target`; take a mandatory workflow out of
# `workflows:`; delete a follow-up trigger → each red.)
_am = read(".github/workflows/dependabot-auto-merge.yml")
_am_jobs = _jobs(_am)
_am_on = "\n".join(_code(_am.split("\njobs:", 1)[0]))
# Triggered by the end of the mandatory workflows, never by `pull_request_target` (foreign context with
# write permission). `workflow_run` runs in the context of main — PR code is never checked out (the
# loop above forbids checkout in jobs with permission; `entscheiden` has no `uses:`).
assert re.search(r"^  workflow_run:", _am_on, re.M) and "pull_request_target" not in _am_on, \
    "dependabot-auto-merge.yml: trigger must be `workflow_run`"
assert not any("uses:" in z for z in _am_jobs.get("entscheiden", [])), \
    "dependabot-auto-merge.yml: `entscheiden` uses an action (checkout?) — API only"
_am_ent = " ".join(z.strip() for z in _am_jobs.get("entscheiden", []))
assert "github.event.workflow_run.event == 'pull_request'" in _am_ent and \
    "github.event.workflow_run.head_repository.full_name == github.repository" in _am_ent, \
    "dependabot-auto-merge.yml: `entscheiden` does not strictly check PR run AND own repo"
assert not _permissions_job(_am_jobs.get("entscheiden", []), _permissions_above(_am)) & {"*"} and \
    not re.search(r"\bwrite\b", " ".join(_am_jobs.get("entscheiden", []))), \
    "dependabot-auto-merge.yml: `entscheiden` holds a write permission — the logic belongs in the read job"
_am_kmd = _command_list(_am_jobs.get("ausfuehren", []))
_am_merge = [k for k in _am_kmd if k.startswith("gh pr merge")]
# Without `--auto`: With `--auto` GitHub would merge later, and the follow-up below would run into the void.
assert _am_merge and all("--match-head-commit" in k and "--auto" not in k for k in _am_merge), \
    f"dependabot-auto-merge.yml: what is merged is not directly exactly the checked head: {_am_merge}"
# The trigger names exactly the mandatory workflows (by `name:`), otherwise nobody merges if a
# missing one finishes last.
_required_wf = re.search(r'PFLICHT_WORKFLOWS:\s*"([^"]+)"', _am)
assert _required_wf, "dependabot-auto-merge.yml: PFLICHT_WORKFLOWS missing"
_wf_name = {}
for _wf in WORKFLOWS:
    _n = re.search(r"^name:\s*(.+?)\s*$", read(_wf), re.M)
    _wf_name[os.path.basename(_wf)] = _n.group(1).strip("\"'") if _n else None
_trigger = re.search(r"workflows:\s*\[([^\]]*)\]", _am_on)
_trigger = {w.strip().strip("\"'") for w in _trigger.group(1).split(",")} if _trigger else set()
assert _trigger == {_wf_name.get(w) for w in _required_wf.group(1).split()}, \
    f"dependabot-auto-merge.yml: `workflows:` {sorted(_trigger)} ≠ PFLICHT_WORKFLOWS " \
    f"{sorted(_wf_name.get(w) or w for w in _required_wf.group(1).split())}"
# Follow-up: What a push to main starts is triggered after the merge via `workflow_dispatch` —
# exactly that, and each of them must know `workflow_dispatch`.
_on_main = set()
for _wf in WORKFLOWS:
    _head = "\n".join(_code(read(_wf).split("\njobs:", 1)[0]))
    if re.search(r"^  push:\s*\n\s+branches:\s*\[main\]", _head, re.M):
        _on_main.add(os.path.basename(_wf))
        assert re.search(r"^  workflow_dispatch:", _head, re.M), \
            f"{_wf} runs on main but has no `workflow_dispatch` — the follow-up cannot trigger it"
# The release automation (kit 0.47.0) also dispatches release.yml after a merge, with `-f automatik=…` — that is not the
# follow-up of a push to main (release.yml does not run on main), so it does not count here.
_triggered = {m.group(1) for k in _am_kmd for m in [re.match(r"gh workflow run (\S+)", k)] if m and "-f automatik=" not in k}
assert any(k.startswith("gh workflow run release.yml") and '-f automatik="$FOLGE"' in k for k in _am_kmd), \
    "dependabot-auto-merge.yml: the release automation dispatch is missing"
assert _triggered == _on_main, \
    f"dependabot-auto-merge.yml: follow-up {sorted(_triggered)} ≠ workflows on main {sorted(_on_main)}"
print("  Dependabot auto-merge: logic without write permission, only own Dependabot PRs, exactly the checked head")

# An action used with several subpaths (`github/codeql-action/init` and
# `/analyze`) must be in ONE Dependabot group: Bumped individually the parts ran in
# different versions, and CodeQL broke (#110/#111). (Mutation probe: delete the group `codeql`
# → red.)
_parts: dict[str, set] = {}
for _wf in WORKFLOWS:
    for _m in re.finditer(r"uses:\s*([\w.-]+/[\w.-]+)/([\w./-]+)@", read(_wf)):
        _parts.setdefault(_m.group(1), set()).add(_m.group(2))
_dep_text = "\n".join(_code(read(".github/dependabot.yml")))
_actions_entry = next(e for e in re.split(r"\n  - ", _dep_text)[1:] if e.startswith("package-ecosystem: github-actions"))
# Per group its patterns — all parts must land in the SAME group, not each in some group.
_groups = {}
for _g in re.finditer(r"^      ([\w-]+):\s*\n((?:        .*\n?)+)", _actions_entry, re.M):
    _pm = re.search(r"patterns:\s*\[([^\]]*)\]", _g.group(2))
    _groups[_g.group(1)] = [m.strip().strip("\"'") for m in _pm.group(1).split(",") if m.strip()] if _pm else []
for _action, _under in sorted(_parts.items()):
    if len(_under) < 2:
        continue
    assert any(all(any(fnmatch.fnmatch(f"{_action}/{u}", m) for m in _ms) for u in _under)
               for _ms in _groups.values()), \
        f"dependabot: {_action} is used with {sorted(_under)}, but is in no common group"
print("  Dependabot: actions with several parts are bumped together")

# B4-6 — Actions that download a tool at runtime. The SHA pin holds the action fast, not
# the tool: Without a statement setup-qemu pulls the `latest` tag of tonistiigi/binfmt (privileged!),
# setup-buildx `moby/buildkit:buildx-stable-1`. Demanded is per tool version AND digest.
# Limit: A NEW action that downloads is not in this table — it is checked when it is
# adopted (extend the list below), not recognised by itself.
TOOL_REQUIRED = {
    "docker/setup-qemu-action": [r"^\s+image:\s*\S+:[\w.-]+@sha256:[0-9a-f]{64}\s*$"],
    "docker/setup-buildx-action": [r"^\s+version:\s*v\d+\.\d+\.\d+\s*$",
                                   r"^\s+driver-opts:\s*image=\S+:v[\d.]+@sha256:[0-9a-f]{64}\s*$",
                                   # M6/B1: buildx not from the actions cache (zizmor cache-poisoning).
                                   r"^\s+cache-binary:\s*false\s*$"],
}
# Checked and fixed without a statement: the tool version is a constant in the pinned commit.
TOOL_IN_SHA = {"anchore/sbom-action": "syft as a constant in src/SyftVersion.ts",
                   "github/codeql-action": "the CodeQL bundle belongs to the action version",
                   "pypa/gh-action-pypi-publish": "image ghcr.io/pypa/…:<sha> or a Dockerfile with constraints",
                   # H1: grype as a constant in GrypeVersion.js; its vulnerability database is fetched fresh on purpose.
                   "anchore/scan-action": "grype as a constant in GrypeVersion.js",
                   # H1: action.yaml names ghcr.io/ossf/scorecard-action:<version> — a TAG in the pinned commit, not a
                   # digest (limit); the job holds only security-events and id-token, no `run:`.
                   "ossf/scorecard-action": "image tag ghcr.io/ossf/scorecard-action:<version> in action.yaml"}
# Deliberately floating: the browser test is meant to run against the current stable Chrome. The job has only
# read permission and ships nothing.
TOOL_WANDERING_OK = {"browser-actions/setup-chrome": "ci.yml, read permission only, ships nothing"}
for wf in WORKFLOWS:
    lines = _code(read(wf))
    for i, z in enumerate(lines):
        m = re.search(r"uses:\s*([^@\s]+)@", z)
        if not m or m.group(1) not in TOOL_REQUIRED:
            continue
                # The `with:` block of the action: the following lines up to the next step.
        following = []
        for w in lines[i + 1:]:
            if re.match(r"^\s+- ", w) or (w and not w.startswith(" ")):
                break
            following.append(w)
        for pattern in TOOL_REQUIRED[m.group(1)]:
            assert any(re.match(pattern, w) for w in following), (
                f"{wf}: {m.group(1)} without a fixed tool ({pattern}) — the SHA pin holds the action "
                "fast, not the image it pulls at runtime")
print(f"  actions that download: tool with version and digest ({', '.join(TOOL_REQUIRED)})")

# B4-6/B4-8 — pip in the build and check path only against a hashed list. Exempt is what the
# suite checks (there the resolution IS the subject under test) — i.e. every job that runs `run_all.py`.
# The SBOM step of build-provenance.yml (T-55) installs the built wheel WITH its dependencies as pip resolves them —
# that resolution is what the SBOM records. Allowed exactly so: wheels only (no package code runs at install), into
# a directory of its own, the built wheel as the only requirement, in a job without identity (loop above).
_SBOM_INSTALL = ('python -m pip install --disable-pip-version-check --only-binary :all: '
                 '--target "$RUNNER_TEMP/sbom-site" dist/*.whl')
_sbom_install_seen = 0
for wf in (".github/workflows/release.yml", ".github/workflows/audit.yml", ".github/workflows/build-provenance.yml"):
    for job, lines in _jobs(read(wf)).items():
        block = "\n".join(lines)
        if "tests/run_all.py" in block:
            continue
        for z in _command_list(lines):
            if wf.endswith("build-provenance.yml") and job == "rebuild" and z.strip() == _SBOM_INSTALL:
                _sbom_install_seen += 1
                continue
                        # Every spelling of pip: `pip3`, `pip3.14`, `"$venv/pip"`, `python -m pip`. Until the
                        # re-check (A-6) `\bpip\b` did not hit `pip3` — `pip3 install build` slipped through.
            if re.search(r"(\bpip[0-9.]*|\bpython[0-9.]*\s+-m\s+pip)[\"']?\s+install\b", z):
                assert "--require-hashes" in z or ("--no-index" in z and "--no-deps" in z), (
                    f"{wf} job `{job}`: pip install neither hashed nor offline: {z}")
                        # Tools that install from the index past the hashed list.
            assert not re.search(r"\b(uvx|pipx|easy_install|conda|mamba|pyproject-build)\b"
                                 r"|\buv[\"']?\s+(tool|run|add|sync|pip\s+(install|sync))\b", z), \
                f"{wf} job `{job}`: tool bypasses the hash: {z}"
                        # Without `--no-isolation` `build` fetches the just-newest setuptools into its own
                        # environment — the hashed list would then be decoration.
            if re.search(r"-m\s+build\b", z):
                assert re.search(r"\s(--no-isolation|-n)\b", z), \
                    f"{wf} job `{job}`: `-m build` with build isolation (pulls setuptools freely): {z}"
_build_job = _jobs(read(".github/workflows/release.yml")).get("build", [])
assert any(re.search(r"-m\s+build\b", k) for k in _command_list(_build_job)), \
    "release.yml: job `build` no longer builds with `-m build` — adjust guard"
assert _sbom_install_seen == 1, "build-provenance.yml: the SBOM install step is missing or changed — adjust guard"
# The isolated builder must build EXACTLY like `build`: its bytes are compared with `build`'s checksums, and a recipe
# that drifted apart would turn every release red — or, worse, be adjusted until it matches. (Mutation probe: change a
# line in one of the two `Build the packages` blocks → red.)


def _build_block(text):
    m = re.search(r"- name: Build the packages\n\s+run: \|\n((?:\s{10}.*\n)+)", text)
    assert m, "`Build the packages` block not found — adjust guard"
    return [z.strip() for z in m.group(1).splitlines()]


assert _build_block(read(".github/workflows/release.yml")) == \
    _build_block(read(".github/workflows/build-provenance.yml")), \
    "build-provenance.yml builds differently from release.yml `build`"
_bp = read(".github/workflows/build-provenance.yml")
assert "sha256sum -c ../shipped/SHA256SUMS" in _bp, "build-provenance.yml: no comparison with the shipped checksums"
_bp_jobs = _jobs(_bp)
_bp_attest = [z.strip() for z in _bp_jobs.get("attest", [])]
assert "if: inputs.attest" in _bp_attest, "build-provenance.yml: `attest` does not hang on the input"
assert [z for z in _bp_attest if z.startswith("subject-path:")] == ['subject-path: "dist/*.whl, dist/*.tar.gz"'] * 2, \
    "build-provenance.yml: `attest` attests something other than wheel and sdist"
assert re.search(r"^  workflow_call:", "\n".join(_code(_bp.split("\njobs:", 1)[0])), re.M) and \
    not re.search(r"^  (push|pull_request|workflow_dispatch|schedule)", _bp, re.M), \
    "build-provenance.yml: must be callable only (workflow_call)"
print("  Build and check tools in release/audit only from hashed lists, build without isolation")

# The button (`workflow_dispatch`) is a dry run: Every job that publishes or holds an
# identity hangs on the tag; the image is built without a tag, but neither logged in nor
# pushed. Until 2026-09-24 the button could have failed at the tag comparison or — without it — published from a
# branch. (Mutation probe: for `release`, `pypi` or `image-attest`
# delete the `if:` line, or turn `push=${{ github.ref_type == 'tag' }}` into `push=true` → red.)
_rel_jobs = _jobs(rel)
_AM_TAG = "if: github.ref_type == 'tag'"
for _j in ("release", "pypi", "image-attest"):
    _lines = [z.strip() for z in _rel_jobs.get(_j, [])]
    assert _AM_TAG in _lines, f"release.yml: job `{_j}` also publishes without a tag (button = dry run)"
# Exception dress rehearsal (PO 2026-10-11): `rehearsal-attest` holds `id-token` WITHOUT a tag, so that
# the attestation actions run on every PR. Allowed only this narrowly: never on the tag, no checkout, no
# environment, and only the probe file is attested — never an artifact, never an image.
# (Mutation probes: `subject-path: rehearsal.txt` → `dist/*.whl`; a checkout in the job; turn the
# `if:` to `== 'tag'` → each red.)
_PROBE = "if: github.ref_type != 'tag'"
_probe_certified = 0
_automation_certified = 0
for _j, _lines in _rel_jobs.items():
    _permissions = " ".join(z.strip() for z in _lines)
    _st = [z.strip() for z in _lines]
    if re.search(r"\b(id-token|contents|attestations): write\b", _permissions) or \
            any(z.strip().startswith("environment:") for z in _lines):
        if _j == "rehearsal-attest":
            assert _PROBE in _st and _AM_TAG not in _st, f"release.yml: `{_j}` does not run exactly without a tag"
            assert not any("actions/checkout" in z for z in _st), f"release.yml: `{_j}` checks out"
            assert not any(z.startswith(("environment:", "subject-name:", "push-to-registry:")) for z in _st), \
                f"release.yml: `{_j}` names an environment, an image or a registry"
            _object = [z for z in _st if z.startswith("subject-path:")]
            assert _object and all(z == "subject-path: rehearsal.txt" for z in _object), \
                f"release.yml: `{_j}` attests more than the probe file: {_object}"
            assert not re.search(r"\bcontents: write\b", _permissions), f"release.yml: `{_j}` holds contents: write"
            _probe_certified += 1
            continue
        if _j == "provenance":
            # The isolated builder (T-55): holds the ceiling for build-provenance.yml on every run, but hands the
            # identity on only for a tag (`attest`), where that workflow's `attest` job hangs on it (checked above).
            # (Mutation probe: `attest: true` → red.)
            assert "attest: ${{ github.ref_type == 'tag' }}" in _st, f"release.yml: `{_j}` attests without a tag"
            continue
        if _j == "automatik":
            # Exception release automation (kit 0.47.1, PO 2026-11-15): dispatched by the auto-merge after a Dependabot
            # merge that changes the image (prepare the release PR) and after that PR's merge (set the tag). It holds an
            # app token for THIS repo (contents/pull-requests), never id-token, attestations, packages or an environment,
            # runs only in that dispatch and only the stdlib kit script. (Mutation probes: drop the `if:`; add
            # `id-token: write`; a second `run:` → each red.)
            assert "if: github.event_name == 'workflow_dispatch' && inputs.automatik != ''" in _st, \
                f"release.yml: `{_j}` does not run only in the dispatch of the release automation"
            assert not re.search(r"\b(id-token|attestations|packages): write\b", _permissions) and \
                not any(z.startswith("environment:") for z in _st), f"release.yml: `{_j}` holds more than the app token"
            _runs = [z for z in _st if z.startswith("run:")]
            assert _runs == ['run: scripts/_release_automatik.py "$STEP" --version "$VERSION"'], \
                f"release.yml: `{_j}` runs more than the kit script: {_runs}"
            _automation_certified += 1
            continue
        assert _AM_TAG in [z.strip() for z in _lines], \
            f"release.yml: job `{_j}` holds an identity or write permission, but is not tied to the tag"
assert _probe_certified == 1, "release.yml: the job `rehearsal-attest` is missing"
assert _automation_certified == 1, "release.yml: the job `automatik` (release automation) is missing"
# Every action that runs only on the tag also runs the dress rehearsal — with the same version. Otherwise
# its update would be unchecked (the auto-merge would then leave it lying, but this says so earlier).
_tag_actions, _probe_actions = set(), set()
for _j, _lines in _rel_jobs.items():
    for _m in re.finditer(r"uses:\s*(\S+@\S+)", "\n".join(_lines)):
        (_probe_actions if _j.startswith("rehearsal") else _tag_actions).add(_m.group(1))
for _a in ("docker/login-action", "docker/build-push-action", "anchore/sbom-action",
           "pypa/gh-action-pypi-publish", "actions/attest-build-provenance", "actions/attest"):
    _t = {x for x in _tag_actions if x.startswith(_a + "@")}
    _p = {x for x in _probe_actions if x.startswith(_a + "@")}
    assert _t and _t == _p, f"release.yml: {_a} — tag {sorted(_t)} ≠ dress rehearsal {sorted(_p)}"
# The attest job of the isolated builder (build-provenance.yml) runs only on the tag as well: its attest actions must be
# the ones the dress rehearsal runs, at the same commit (since 0.26.1 `actions/attest` instead of the deprecated
# `actions/attest-sbom`).
_bp_actions = set(re.findall(r"uses:\s*(actions/attest[\w-]*@\S+)", "\n".join(_jobs(read(
    ".github/workflows/build-provenance.yml")).get("attest", []))))
assert _bp_actions and _bp_actions <= _probe_actions, \
    f"build-provenance.yml: attest actions {sorted(_bp_actions - _probe_actions)} are not in the dress rehearsal"
assert not any("attest-sbom@" in x for x in _tag_actions | _probe_actions | _bp_actions), \
    "actions/attest-sbom is deprecated — use actions/attest (same inputs)"
# The dress rehearsal verifies what it attested, the way a user does after a release — provenance and SBOM, signer
# pinned. (Mutation probe: drop the SBOM line of that step → red.)
_verify = [z.strip() for z in _rel_jobs.get("rehearsal-attest", []) if "gh attestation verify" in z]
assert len(_verify) == 2 and all('--signer-workflow "$SIGNER"' in z for z in _verify) \
    and sum("--predicate-type https://spdx.dev/Document" in z for z in _verify) == 1, \
    f"release.yml: `rehearsal-attest` does not verify provenance and SBOM: {_verify}"
# Up to three attempts per attestation in the dress rehearsal (2026-11-22, Sigstore "error fetching tlog entry - (404)",
# three red runs in one day). Each attest step starts or continues a chain: a soft attempt (`continue-on-error: true`,
# with an `id`) is followed by exactly ONE later attempt of the same action with the same inputs under
# `if: steps.<id>.outcome == 'failure'`; the chain ends in a hard attempt without continue-on-error — so failures of
# every attempt stay red. A pause is only `sleep N` and runs only after a failed soft attempt, before its follower. The
# verify step comes after every attempt and runs unconditionally, so it checks what was attested. Nowhere else in
# release.yml may a step or job fail softly. (Mutation probes: drop the third provenance attempt; give it
# `continue-on-error: true`; give the verify step an `if:`; set continue-on-error in the `image-probe` scan → each red.)


def _steps(lines: list[str]) -> list[list[str]]:
    """The steps of a job (lines without comments), each as its lines relative to the step's keys."""
    steps: list[list[str]] = []
    for z in lines:
        if z.startswith("      - "):
            steps.append([z[8:].rstrip()])
        elif steps and z.startswith("        "):
            steps[-1].append(z[8:].rstrip())
    return steps


def _step_key(step: list[str], key: str) -> str | None:
    return next((z.split(":", 1)[1].strip() for z in step if z.startswith(key + ":")), None)


def _step_inputs(step: list[str]) -> list[str]:
    return [z.strip() for z in step if z.startswith("  ")]


_ra = _steps(_rel_jobs.get("rehearsal-attest", []))
_attempts = [i for i, s in enumerate(_ra) if (_step_key(s, "uses") or "").startswith("actions/attest")]
_ids = {_step_key(_ra[i], "id"): i for i in _attempts if _step_key(_ra[i], "id")}
_soft = [i for i, s in enumerate(_ra) if _step_key(s, "continue-on-error") is not None]
assert set(_soft) <= set(_attempts), "release.yml: `rehearsal-attest` lets a step other than an attest attempt fail softly"
_in_chain, _chains = set(), 0
for _head in (i for i in _attempts if _step_key(_ra[i], "if") is None):
    _chains += 1
    _i, _n = _head, 1
    while True:
        _s = _ra[_i]
        assert _i not in _in_chain, f"release.yml: `rehearsal-attest` step {_s[0]!r} belongs to two chains"
        _in_chain.add(_i)
        _coe = _step_key(_s, "continue-on-error")
        if _coe is None:
            break                                   # the hard attempt ends the chain
        _id = _step_key(_s, "id")
        assert _coe == "true" and _id, f"release.yml: `rehearsal-attest` step {_s[0]!r} fails softly without an id"
        _cond = f"steps.{_id}.outcome == 'failure'"
        _next = [j for j in _attempts if j > _i and _step_key(_ra[j], "if") == _cond]
        assert len(_next) == 1 and _step_key(_ra[_next[0]], "uses") == _step_key(_s, "uses") \
            and _step_inputs(_ra[_next[0]]) == _step_inputs(_s), \
            f"release.yml: `rehearsal-attest` step {_s[0]!r} fails softly without exactly one next attempt (same action " \
            "and inputs, `if: steps.<id>.outcome == 'failure'`)"
        for _k in range(_i + 1, _next[0]):           # between them only the pause after this failure
            assert _step_key(_ra[_k], "if") != _cond or re.fullmatch(r"sleep \d+", _step_key(_ra[_k], "run") or ""), \
                f"release.yml: `rehearsal-attest` runs {_ra[_k][0]!r} after the failure of {_s[0]!r}"
        _i, _n = _next[0], _n + 1
    assert _n <= 3, f"release.yml: `rehearsal-attest` tries {_ra[_head][0]!r} {_n} times — at most three"
assert _chains == 2 and _in_chain == set(_attempts), \
    "release.yml: `rehearsal-attest` attests outside the chains of soft and final hard attempts (provenance, SBOM)"
for _k, _s in enumerate(_ra):
    if _step_key(_s, "run") and _step_key(_s, "run").startswith("sleep"):
        _m = re.fullmatch(r"steps\.([\w-]+)\.outcome == 'failure'", _step_key(_s, "if") or "")
        assert _m and _ids.get(_m.group(1)) in _soft and _ids[_m.group(1)] < _k, f"release.yml: `rehearsal-attest` pauses {_s[0]!r} not only after a failure"
_ra_verify = [i for i, s in enumerate(_ra) if any("gh attestation verify" in z for z in s)]
assert len(_ra_verify) == 1 and _ra_verify[0] > max(_attempts) and _step_key(_ra[_ra_verify[0]], "if") is None \
    and _step_key(_ra[_ra_verify[0]], "continue-on-error") is None, \
    "release.yml: `rehearsal-attest` does not verify unconditionally after every attest attempt"
for _j, _lines in _rel_jobs.items():
    if _j != "rehearsal-attest":
        assert not any(re.match(r"\s*continue-on-error:", z) for z in _lines), \
            f"release.yml: job `{_j}` fails softly (continue-on-error) — only the dress rehearsal's attempts may"
_image = "\n".join(_rel_jobs.get("image", []))
assert "push=${{ github.ref_type == 'tag' }}" in _image and "push=true" not in _image, \
    "release.yml: the image is also pushed without a tag"
_login = re.search(r"- name: Log in to GHCR\n\s+" + re.escape(_AM_TAG), _image)
assert _login, "release.yml: the GHCR login in job `image` is not tied to the tag"
_check = "\n".join(_rel_jobs.get("verify", []))
assert "_release.py --check" in _check and "if: github.ref_type != 'tag'" in _check, \
    "release.yml: the dry run checks nothing (scripts/_release.py --check missing)"
print("  release.yml: dry run without a tag — check and build yes, publish never")

# The dry run is also the mandatory check for automatic updates (PO 2026-09-28): It runs on
# every PR, checks the downloaded artifacts and starts the image BEFORE anything is published or
# pushed. Without a PR trigger no mandatory check would vet the build tools, the lock list and the
# base image, and Dependabot would merge them unchecked. (Mutation probes: delete `pull_request:`;
# take `image-probe` out of `needs:` of `image`; `checksums` out of `needs:` of `release`; give the
# suite step in `check` an `if: github.ref_type != 'tag'` → each red.)
_rel_on = rel.split("\njobs:", 1)[0]
assert re.search(r"^  pull_request:", _rel_on, re.M), \
    "release.yml: no `pull_request` trigger — the dry run is no longer a mandatory check"
_needs = {j: re.search(r"^    needs:\s*(.+)$", "\n".join(z), re.M) for j, z in _rel_jobs.items()}
_needs = {j: set(re.findall(r"[A-Za-z0-9_-]+", m.group(1))) if m else set() for j, m in _needs.items()}
assert "checksums" in _needs.get("release", set()), \
    "release.yml: `release` publishes without `checksums` having checked the artifacts"
assert "image-probe" in _needs.get("image", set()) and \
    "needs.image-probe.result == 'success'" in " ".join(_rel_jobs.get("image", [])), \
    "release.yml: `image` pushes without `image-probe` having started the image"
for _j in ("checksums", "image-probe"):
    assert not any(z.strip().startswith("if:") for z in _rel_jobs.get(_j, []) if z.startswith("    if")), \
        f"release.yml: `{_j}` hangs on a condition — it must run on every PR and every tag"
assert any("sha256sum -c SHA256SUMS" in k for k in _command_list(_rel_jobs.get("checksums", []))), \
    "release.yml: `checksums` does not check the checksums"
assert any(k.startswith("scripts/_image_probe.sh") for k in _command_list(_rel_jobs.get("image-probe", []))), \
    "release.yml: `image-probe` does not start the image (scripts/_image_probe.sh)"
# The suite in `check` may be skipped ONLY on a PR (there ci.yml runs it) — on the tag it runs.
_suite = re.search(r"- name: Run the suite[^\n]*\n((?:\s{8}.*\n)+)", "\n".join(_rel_jobs.get("verify", [])) + "\n")
assert _suite, "release.yml: the suite step in `verify` is missing"
_suite_if = [z.strip() for z in _suite.group(1).splitlines() if z.strip().startswith("if:")]
assert _suite_if in ([], ["if: github.event_name != 'pull_request'"]), \
    f"release.yml: the suite in `verify` is not skipped only on PRs: {_suite_if}"
# The image tag is the git tag only on the tag. On a PR `github.ref_name` is `108/merge` —
# invalid as an image tag, `image` broke on the first PR with this dry run because of it.
# (Mutation probe: `tags:` back to `…:${{ github.ref_name }}` → red.)
_image_tags = re.findall(r"^\s+tags:\s*(.+?)\s*$", _image, re.M)
assert len(_image_tags) == 2, f"release.yml: `image` builds {len(_image_tags)} images, expected gateway and Caddy"
for _tag in _image_tags:
    assert "${{ github.ref_type == 'tag' && github.ref_name || '" in _tag, \
        f"release.yml: the image tag takes the ref even without a tag (on PRs `N/merge`): {_tag}"
# The Caddy image (since 2026-11-20) is treated like the gateway image: scanned before the push (image-probe), pushed
# only for the tag (above), attested with provenance and SBOM. (Mutation probes: drop its Grype step; drop its SBOM
# attestation → each red.)
_probe_scans = re.findall(r"^\s+image:\s*(\S+)", "\n".join(_rel_jobs.get("image-probe", [])), re.M)
assert set(_probe_scans) == {"tinysesam-probe:local", "tinysesam-caddy-gate-probe:local"}, \
    f"release.yml: image-probe does not scan both images: {_probe_scans}"
_attest = "\n".join(_rel_jobs.get("image-attest", []))
for _name in ("tinysesam", "tinysesam-caddy-gate"):
    _subjects = re.findall(rf"subject-name: ghcr\.io/\$\{{\{{ env\.OWNER_LC \}}\}}/{_name}\s*$", _attest, re.M)
    assert len(_subjects) == 2, f"release.yml: image-attest attests {_name} {len(_subjects)}× (provenance + SBOM expected)"
for _sbom in ("sbom.spdx.json", "sbom-caddy-gate.spdx.json"):
    assert re.search(rf"^\s+output-file: {re.escape(_sbom)}\s*$", _attest, re.M) and \
        re.search(rf"^\s+sbom-path: {re.escape(_sbom)}\s*$", _attest, re.M), \
        f"release.yml: image-attest does not generate AND attest {_sbom}"
print("  release.yml: the dry run runs on every PR; release and image depend on checksums and start probe")

# B4-7 — The image installs what the lock list says, byte for byte. The digest pin in FROM
# holds only the base image; a `pip install ".[gateway]"` resolved anew on every build.
BLOCKLIST = "deploy/gateway/requirements.txt"
_df = "\n".join(z for z in dockerfile.splitlines() if not z.lstrip().startswith("#"))
assert "--require-hashes" in _df and "-r requirements.txt" in _df, \
    "the image does not install from the hashed lock list"
assert f"COPY {BLOCKLIST}" in _df, f"the Dockerfile does not copy {BLOCKLIST}"
assert "--upgrade pip" not in _df, "`pip install --upgrade pip` pulls the newest pip on every build"
_own = [z for z in _df.splitlines() if re.search(r"pip install .*\s\.\s*(\\|$)", z)]
assert _own and all("--no-index" in z and "--no-deps" in z for z in _own), \
    f"TinySesam itself is installed with network or resolution: {_own}"
assert f"!{BLOCKLIST}" in read(".dockerignore"), f".dockerignore does not let {BLOCKLIST} through"
# `--no-deps` also installs an incomplete list without complaint (A-1 of the re-check): If
# a transitive dependency is missing — say because Dependabot bumped a line that brings a new one —,
# the image breaks only at startup. `pip check` and the import therefore belong in the same
# RUN, after both installations and before removing setuptools; audit.yml runs the same
# steps on every PR, otherwise it would only show up at release (no PR run builds the image).
_run = re.sub(r"\\\n\s*", " ", _df)
_chain = next((z for z in _run.splitlines() if "-r requirements.txt" in z), "")
_tiers = [s.strip() for s in _chain.split("&&")]
_pos = {n: next((i for i, s in enumerate(_tiers) if re.search(m, s)), -1) for n, m in (
    ("blocklist", r"--require-hashes"), ("own", r"--no-index"), ("check", r"/pip check$"),
    ("import", r"python -c \"import tinysesam\.gateway\"$"), ("setuptools", r"uninstall"))}
assert -1 not in _pos.values(), f"Dockerfile: step missing in the installation RUN: {_pos}"
assert _pos["blocklist"] < _pos["own"] < _pos["check"] < _pos["import"] < _pos["setuptools"], \
    f"Dockerfile: `pip check`/import not after the installation and before the cleanup: {_pos}"
_audit_execution = _command_list(_code(read(".github/workflows/audit.yml")))
for _m in (rf"pip\"? install --require-hashes --no-deps -r {re.escape(BLOCKLIST)}$",
           r"pip\"? install --no-deps --no-index --no-build-isolation \.$",
           r"pip\"? check$", r"python\"? -c \"import tinysesam\.gateway\"$", r"^python3\.(\d+) -m venv"):
    assert any(re.search(_m, k) for k in _audit_execution), f"audit.yml: probe of the lock list without `{_m}`"
# The probe runs in the Python series of the image (the lock list is resolved for it).
_row = re.search(r"^FROM python:(3\.\d+)", dockerfile, re.M).group(1)
assert any(k.startswith(f"python{_row} -m venv") for k in _audit_execution), \
    f"audit.yml: probe of the lock list not on Python {_row} (FROM in the Dockerfile)"
# pip is removed by pattern, not with a fixed series: After the jump from 3.12 to 3.14 (#74)
# all `python3.12` paths pointed into the void, and pip was back in the final image.
for _row_fixed in set(re.findall(r"(?:python|pip)(3\.\d+)", _df)):
    assert _row_fixed == _row, (f"Dockerfile names Python {_row_fixed}, the image is "
                                   f"{_row} — write paths by pattern (`python3.*`)")


def _blocklist(rel: str) -> dict[str, str]:
    """name → version; every requirement pinned and with at least one hash."""
    text = read(rel).replace("\\\n", " ")
    pins = {}
    for z in text.splitlines():
        z = z.split("#", 1)[0].strip()
        if not z:
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)==([0-9][^\s;]*)\s*(;[^-]*)?(.*)$", z)
        assert m, f"{rel}: not pinned: {z[:60]}"
        assert "--hash=sha256:" in m.group(4), f"{rel}: {m.group(1)} without hash"
        pins[m.group(1).lower().replace("_", "-")] = m.group(2)
    return pins


def _v(text: str) -> tuple:
    return tuple(int(t) for t in re.findall(r"\d+", text)[:4])


_lock = _blocklist(BLOCKLIST)
import tomllib as _toml  # noqa: E402
_proj = _toml.loads(read("pyproject.toml"))["project"]
_requires = list(_proj["dependencies"]) + list(_proj["optional-dependencies"]["gateway"])
for _req in _requires:
    _m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*>=\s*([0-9.]+)$", _req)
    assert _m, f"pyproject: unexpected requirement {_req!r} — adjust guard"
    _n = _m.group(1).lower().replace("_", "-")
    assert _n in _lock, f"{BLOCKLIST} lacks {_n} — regenerate (command in the file header)"
    assert _v(_lock[_n]) >= _v(_m.group(2)), (f"{BLOCKLIST}: {_n}=={_lock[_n]} is below the "
                                              f"bound {_req} — regenerate")
assert "setuptools" in _lock, f"{BLOCKLIST}: setuptools missing — without build isolation the image needs it"
# Offline part of completeness: Every name in a `# via` must itself be in the list
# (or be the root). Whoever deletes a block by hand leaves its `via` references behind with the
# dependencies. Limit: A leaf without dependencies of its own and a NEW dependency
# after a bump are not seen by this — only `pip check` in audit.yml catches them (see above).
_via, _in_via = set(), False
for _z in read(BLOCKLIST).splitlines():
    _s = _z.strip()
    _vm = re.match(r"^# via(?:\s+(\S+))?", _s)
    if _vm:
        _in_via = not _vm.group(1)
        if _vm.group(1):
            _via.add(_vm.group(1).lower())
    elif _in_via and re.match(r"^#\s{2,}\S", _s):
        _via.add(_s.lstrip("#").split()[0].lower())
    else:
        _in_via = False
_via -= {"tinysesam", "-r"}
assert _via and _via <= set(_lock), (f"{BLOCKLIST}: `# via` names packages that are missing: "
                                     f"{sorted(_via - set(_lock))} — regenerate")
# Since 2026-10-10 Dependabot's uv ecosystem regenerates the lock list, from EXACTLY ONE input: requirements.in next to it.
# (The line-by-line pip update did not carry over new transitive dependencies, #126.) The input repeats
# `dependencies` + extra `gateway` from pyproject.toml and names setuptools — if it drifts apart, the image resolves
# something other than the package demands. And the header must carry what Dependabot reads the switches from.
INPUT = "deploy/gateway/requirements.in"
_one = {}
for _z in read(INPUT).splitlines():
    _z = _z.split("#", 1)[0].strip()
    if _z:
        _em = re.match(r"^([A-Za-z0-9._-]+)\s*(>=\s*[0-9.]+)?$", _z)
        assert _em, f"{INPUT}: unexpected line {_z!r}"
        _one[_em.group(1).lower().replace("_", "-")] = (_em.group(2) or "").replace(" ", "")
_should = {"setuptools": ""}
for _req in _requires:
    _sm = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(>=\s*[0-9.]+)$", _req)
    _should[_sm.group(1).lower().replace("_", "-")] = _sm.group(2).replace(" ", "")
# The same packages; the lower bound in the image may be HIGHER than that of the package, never lower (since 2026-10-11).
# Until then equality applied — then every uv PR from Dependabot stayed red (it only bumps requirements.in, #159), and
# the pyproject line had to be updated by hand. The image still resolves with the higher bound only
# what the package allows; the package's commitment (its minimum version) stays where it is.
# (Mutation probes: lower a bound in requirements.in below that of pyproject; delete a package → each red.)
def _version(g: str) -> tuple:
    return tuple(int(t) for t in re.findall(r"\d+", g))
assert set(_one) == set(_should), (f"{INPUT} names different packages than pyproject (dependencies + gateway): "
                                 f"only there {sorted(set(_one) - set(_should))}, only in pyproject {sorted(set(_should) - set(_one))}")
_to_deep = [f"{p}: {_one[p] or 'without Limit'} < {_should[p]}" for p in _should
            if _should[p] and (not _one[p] or _version(_one[p]) < _version(_should[p]))]
assert not _to_deep, f"{INPUT}: lower bound below that of the package: {_to_deep}"
# The command line itself, not just any comment: Dependabot does look for the switches in the whole text, but only this
# line says what the file was really generated with (a mention in the explanatory text above would prove nothing).
_head = next((z for z in read(BLOCKLIST).splitlines() if z.startswith("#    uv pip compile ")), "")
for _switch in ("uv pip compile requirements.in", "--universal", "--generate-hashes",
                  f"--python-version {re.search(r'^FROM python:(3\.\d+)', dockerfile, re.M).group(1)}",
                  "--output-file requirements.txt"):
    assert _switch in _head, f"{BLOCKLIST}: header without `{_switch}` — Dependabot (uv) would otherwise regenerate differently"
assert not os.path.exists(os.path.join(ROOT, "deploy/gateway/build.in")), \
    "deploy/gateway/build.in is back — setuptools is in requirements.in (one input for Dependabot)"
print(f"  Gateway image: {len(_lock)} packages from hashed lock list, covers pyproject, no pip upgrade, "
      f"input = pyproject")

# B4-2 — The vulnerability gate: every hashed list and both resolutions go through pip-audit,
# on every PR and nightly, and the gate must not be able to turn red without blocking.
_audit = read(".github/workflows/audit.yml")
_audit_code = "\n".join(_code(_audit))
for necessary in ("pull_request:", "schedule:", "pip-audit", "--strict", "--resolution lowest-direct",
               "--all-extras"):
    assert necessary in _audit_code, f"audit.yml: `{necessary}` missing — the gate checks less than it says"
assert "continue-on-error" not in _audit_code, "audit.yml must not wave things through (continue-on-error)"
BLOCKLISTS = sorted(f for f in FILES if os.path.basename(f) == "requirements.txt")
assert len(BLOCKLISTS) >= 3, f"only {BLOCKLISTS} found"
for rel in BLOCKLISTS:
    _blocklist(rel)                                  # pinned + hashed, otherwise red
    assert rel in _audit_code, f"{rel} is not checked by audit.yml"
print(f"  Vulnerability gate: {len(BLOCKLISTS)} lock lists + newest + lowest resolution, --strict")

# B4-3/B4-12 — Dependabot sees every place where something is pinned, and none where there is nothing
# to bump. A pip entry for `/` read the `>=` bounds, and Dependabot never bumps those.
_dep = "\n".join(_code(read(".github/dependabot.yml")))


def _dependabot_dirs(ecosystem: str) -> set[str]:
    dirs = set()
    for entry in re.split(r"\n  - ", _dep)[1:]:
        if not re.match(rf"package-ecosystem:\s*{re.escape(ecosystem)}\s*$", entry.splitlines()[0]):
            continue
        for m in re.finditer(r"directory:\s*(\S+)", entry):
            dirs.add(m.group(1).strip("\"'"))
        for m in re.finditer(r"directories:\s*\[([^\]]*)\]", entry):
            dirs |= {d.strip().strip("\"'") for d in m.group(1).split(",") if d.strip()}
    return dirs


assert "/" not in _dependabot_dirs("pip"), ("dependabot: pip on `/` reads only the `>=` bounds "
                                            "and never bumps anything — the floors are checked by audit.yml")
# pip bumps line by line, uv regenerates from requirements.in (since 2026-10-10 for deploy/gateway). A folder belongs
# to exactly ONE of the two — both at once would give two PRs for the same jump, and the pip PR would again be the broken one.
_pip, _uv = _dependabot_dirs("pip"), _dependabot_dirs("uv")
assert not _pip & _uv, f"dependabot: pip AND uv for {sorted(_pip & _uv)}"
for rel in BLOCKLISTS:
    assert "/" + os.path.dirname(rel) in _pip | _uv, f"Dependabot does not bump {rel}"
for _d in _uv:
    assert os.path.exists(os.path.join(ROOT, _d.lstrip("/"), "requirements.in")), \
        f"dependabot: uv for {_d}, but requirements.in is missing there (the one input that uv recompiles)"
for rel in (f for f in FILES if re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", f)):
    assert "/" + os.path.dirname(rel) in _dependabot_dirs("docker-compose"), \
        f"Dependabot does not see {rel} (entry `docker-compose`)"
# The own images in a compose file carry the release version and move with `scripts/_release.py`, never with
# Dependabot: its quickstart job of 2026-11-20 died on `ghcr.io/ollornog/tinysesam-caddy-gate`, which the registry did
# not have before its first release (DockerRegistry2::NotFound) — and once it exists, a Dependabot PR would race the
# release PR. Every docker-compose entry whose folder pins an own image ignores it by name — and the check must find
# the two images of the quickstart, or it measures nothing.
# (Mutation probe: drop the `ignore` of the quickstart entry → red.)
for _entry in re.split(r"\n  - ", _dep)[1:]:
    if not re.match(r"package-ecosystem:\s*docker-compose\s*$", _entry.splitlines()[0]):
        continue
    _dir = re.search(r"directory:\s*(\S+)", _entry).group(1).strip("\"'").lstrip("/")
    _own = set()
    for rel in (f for f in FILES if os.path.dirname(f) == _dir and re.search(r"(docker-)?compose[^/]*\.ya?ml$", f)):
        # Dependabot names a ghcr.io image without the registry (its log: "Error processing ollornog/…").
        _own |= set(re.findall(r"^\s*image:\s*ghcr\.io/(ollornog/[\w.-]+)[:@]", read(rel), re.M))
    _ignored = set(re.findall(r'dependency-name:\s*"?([^"\s]+)"?', _entry))
    assert _own <= _ignored, f"dependabot: docker-compose /{_dir} does not ignore the own image(s) {sorted(_own - _ignored)}"
    if _dir == "deploy/quickstart":
        assert _own == {"ollornog/tinysesam", "ollornog/tinysesam-caddy-gate"}, f"own images of the quickstart: {_own}"
# Go modules (since 2026-11-20: Caddy and caddy-jwt of tinysesam-caddy-gate) — before, the plugin was an xcaddy ARG
# that no entry could see.
for rel in (f for f in FILES if os.path.basename(f) == "go.mod"):
    assert "/" + os.path.dirname(rel) in _dependabot_dirs("gomod"), f"Dependabot does not see {rel} (entry `gomod`)"
for rel in (f for f in FILES if os.path.basename(f) == "Dockerfile"):
    assert "/" + os.path.dirname(rel).rstrip("/") in {d.rstrip("/") or "/" for d in _dependabot_dirs("docker")} \
        or (os.path.dirname(rel) == "" and "/" in _dependabot_dirs("docker")), f"Dependabot does not see {rel}"
assert _dependabot_dirs("github-actions"), "Dependabot does not bump the actions"
# Docker files never under .github/: Dependabot may not open a PR there. The pypiserver update of 2026-11-12 in
# .github/rehearsal ended with "The request contains invalid or unauthorized changes" (dependency_file_not_supported),
# no PR — the same as a docker file under .github/ in another repository on 2026-11-05. pip under .github/ (audit,
# packaging) is not affected.
_in_github = sorted(d for e in ("docker", "docker-compose") for d in _dependabot_dirs(e)
                    if d.strip("/").split("/")[0] == ".github")
assert not _in_github, f"dependabot: docker files under .github/ cannot be updated (no PR): {_in_github} — move them out"
# The base-image digest: the docker cooldown counts from the tag's last push on Docker Hub, and official images re-push
# `3.x-slim` every few days. A monthly run then regularly finds every candidate inside the cooldown and keeps the old
# digest for another month (Python 3.14.7 until 2026-11-12). Only a daily run reliably hits a three-day quiet window.
_docker_entry = next((e for e in re.split(r"\n  - ", _dep)[1:]
                      if re.match(r"package-ecosystem:\s*docker\s*$", e.splitlines()[0])), "")
assert re.search(r"interval:\s*daily\b", _docker_entry), \
    "dependabot: the `docker` entry must run daily — monthly keeps missing the cooldown window of re-pushed base tags"
print("  Dependabot: every lock list, every compose file, every Dockerfile, the actions — no dead pip entry; "
      "base images daily")

# B4-11 — The reference stack and the quickstart: every third-party image with a digest, the own ones with the version
# tag, and every service hardened. `caddy:2` moved with every Caddy version.
_OWN_IMAGES = {f"ghcr.io/ollornog/tinysesam:v{pv}", f"ghcr.io/ollornog/tinysesam-caddy-gate:v{pv}"}
for _stack in ("deploy/forward-auth/docker-compose.yml", "deploy/quickstart/docker-compose.yml"):
    _cz = _code(read(_stack))
    _images = [z.split("image:", 1)[1].strip() for z in _cz if re.match(r"^\s+image:", z)]
    assert len(_images) >= 2, _images
    for image in _images:
        assert image in _OWN_IMAGES or re.search(r":[\w.-]+@sha256:[0-9a-f]{64}$", image), \
            f"{_stack}: {image} is neither an own version image nor pinned by version+digest"
    _anchor = re.search(r"^x-hardening: &hardening\n((?:  .*\n)+)", "\n".join(_cz) + "\n", re.M)
    assert _anchor, f"{_stack}: the hardening anchor x-hardening is missing"
    for necessary in ("read_only: true", "cap_drop: [ALL]", 'security_opt: ["no-new-privileges:true"]'):
        assert necessary in _anchor.group(1), f"{_stack}: x-hardening without `{necessary}`"
    _services = re.search(r"^services:\n(.*?)^\S", "\n".join(_cz) + "\nEND", re.M | re.S).group(1)
    _names = re.findall(r"^  ([a-z0-9_-]+):\s*$", _services, re.M)
    _blocks = re.split(r"^  [a-z0-9_-]+:\s*$", _services, flags=re.M)[1:]
    assert len(_names) == len(_blocks) >= 2, _names
    for name, block in zip(_names, _blocks):
        assert "<<: *hardening" in block, f"{_stack}: service `{name}` without hardening (<<: *hardening)"
        assert "cap_add" not in block or re.search(r"cap_add: \[NET_BIND_SERVICE\]", block), \
            f"{_stack}: service `{name}` takes back more than NET_BIND_SERVICE"
    print(f"  {_stack}: {len(_images)} images pinned, {len(_names)} services hardened")
# The quickstart runs the Caddy image of the same release — the one with caddy-jwt that release.yml publishes.
assert f"ghcr.io/ollornog/tinysesam-caddy-gate:v{pv}" in read("deploy/quickstart/docker-compose.yml"), \
    "quickstart: not on the release's Caddy image"

# B4-10 — SECURITY.md names a path everyone can reach, and deadlines that can be measured.
from web.site import OWNER as _OWNER  # noqa: E402
for _sec in ("SECURITY.md", "i18n/SECURITY.de.md"):
    _t = read(_sec)
    assert "security/advisories/new" in _t, f"{_sec}: no direct link to the private report"
    assert _OWNER["email"] in _t, f"{_sec}: no email as a path without a GitHub account ({_OWNER['email']})"
    _deadlines = re.findall(r"\*\*(\d+) (?:days|Tage)\*\*", _t)
    assert len(_deadlines) >= 3, f"{_sec}: no measurable deadlines (found: {_deadlines})"
    assert not re.search(r"within a few days|innerhalb weniger Tage", _t), f"{_sec}: „wenige Tage“ is not a deadline"
_en = re.findall(r"\*\*(\d+) days\*\*", read("SECURITY.md"))
_de = re.findall(r"\*\*(\d+) Tage\*\*", read("i18n/SECURITY.de.md"))
assert _en == _de, f"SECURITY: deadlines EN {_en} ≠ DE {_de}"
print(f"  SECURITY: two reporting paths, deadlines {'/'.join(_en)} days in both languages")

# B4-14 — OpenSSF Scorecard: what has already been achieved stays achieved. Per criterion the check that
# carries it offline (Scorecard itself needs the GitHub API). Not checkable offline and therefore
# NOT here: Branch-Protection, Code-Review, Maintained, Signed-Releases (Sigstore attestations
# instead of signature files), Fuzzing (not achieved).
_scorecard = {}
_all_wf = {wf: "\n".join(_code(read(wf))) for wf in WORKFLOWS}
# Dangerous-Workflow: no trigger that runs foreign code with privileges; no expression from the
# event in a shell step or an `actions/github-script` `script:` (script injection
# via titles, branch names, comments). EVERY `${{ … }}` expression that touches the event is
# checked — also inside a function: Until the re-check (A-7) the guard only saw
# `${{ github.event… }}` directly, `${{ toJSON(github.event…) }}` or `format('{0}', github.head_ref)`
# went through.
_EVENT = re.compile(r"\bgithub\s*(?:\.\s*|\[\s*['\"])(?:event|head_ref)\b")
for wf, t in _all_wf.items():
    assert not re.search(r"\b(pull_request_target|issue_comment)\b", t), \
        f"{wf}: dangerous trigger (Scorecard Dangerous-Workflow)"
        # `workflow_run` runs with write permission in the context of main. Scorecard objects to it only
        # together with a checkout of the PR code ("used in conjunction with an explicit pull request
        # checkout", docs/checks.md). Stricter here: a `workflow_run` workflow uses NO action AT ALL,
        # only `gh`/API — so no code from the PR can get in (Dependabot auto-merge, 2026-09-28).
        # (Mutation probe: add a `uses: actions/checkout@…` in dependabot-auto-merge.yml → red.)
        # Only exception since 2026-10-11 (Kit 0.33, GitHub App): `actions/create-github-app-token`, from
        # GitHub itself, pinned by SHA — it only issues a token and touches no PR code.
        # (Mutation probe: widen the exception to `actions/checkout` → the mutation probe above stays red.)
    if re.search(r"\bworkflow_run\b", t):
        _foreign = [u for u in re.findall(r"^\s+(?:- )?uses:\s*(\S+)", t, re.M)
                  if not re.fullmatch(r"actions/create-github-app-token@[0-9a-f]{40}", u)]
        assert not _foreign, \
            f"{wf}: `workflow_run` with an action {_foreign} — API only, never code from the PR (Scorecard Dangerous-Workflow)"
    for k in _command_list(t.splitlines(), ("run", "script")):
        for expression in re.findall(r"\$\{\{(.*?)\}\}", k):
            assert not _EVENT.search(expression), \
                f"{wf}: event expression in shell/script step (script injection): {k}"
_scorecard["Dangerous-Workflow"] = True
# Token-Permissions: every workflow sets `permissions:` at the top and nothing with write there (checked above).
_scorecard["Token-Permissions"] = all(re.search(r"^permissions:", t, re.M) for t in _all_wf.values())
assert _scorecard["Token-Permissions"], "a workflow without `permissions:` at the top level"
# Pinned-Dependencies (the part that is achieved): actions by SHA (above), base image by digest.
_scorecard["Pinned-Dependencies"] = all("@sha256:" in z for z in dockerfile.splitlines() if z.startswith("FROM "))
assert _scorecard["Pinned-Dependencies"], "Dockerfile: FROM without digest"
# SAST: CodeQL on PRs and main.
_codeql = _all_wf.get(".github/workflows/codeql.yml", "")
_scorecard["SAST"] = "github/codeql-action/analyze" in _codeql and "pull_request:" in _codeql and "push:" in _codeql
assert _scorecard["SAST"], "CodeQL no longer runs on PRs and main (Scorecard SAST)"
# Security-Policy, License, Dependency-Update-Tool, CI-Tests.
_scorecard["Security-Policy"] = "SECURITY.md" in FILES
_scorecard["License"] = "LICENSE" in FILES
_scorecard["Dependency-Update-Tool"] = ".github/dependabot.yml" in FILES
_scorecard["CI-Tests"] = "pull_request:" in _all_wf[".github/workflows/ci.yml"]
# Binary-Artifacts: no executable binary files in the repo.
_bin = [f for f in FILES if f.endswith((".exe", ".dll", ".so", ".dylib", ".jar", ".class", ".pyc", ".whl", ".egg"))]
_scorecard["Binary-Artifacts"] = not _bin
_lost = sorted(k for k, v in _scorecard.items() if not v)
assert not _lost, f"Scorecard criteria lost: {_lost} (binary files: {_bin[:3]})"
print(f"  Scorecard: {len(_scorecard)} achieved criteria guarded ({', '.join(sorted(_scorecard))})")

# ---------- The release script only replaces pins, not history ----------
# Until 0.20.0 `scripts/_release.py` replaced every occurrence of the old version — and thereby rewrote
# "0.19.0 raised to schema 8" and "until 0.19.0 one ended up in the same account" to the new version.
# (Mutation probe: in `replace_pins` `text.replace(alt, neu)` again → red.)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import _release  # noqa: E402
_probe = ("x@v0.19.0\ntinysesam:v0.19.0\n/v0.19.0/tinysesam-0.19.0-py3\n==0.19.0\n"
          'version = "0.19.0"\n__version__ = "0.19.0"\nUntil 0.19.0 applied\n0.19.0 took it\nv0.19.01')
_new, _n = _release.replace_pins(_probe, "0.19.0", "0.20.0")
assert _n == 7 and "Until 0.19.0 applied" in _new and "0.19.0 took it" in _new and "v0.19.01" in _new, (_n, _new)
# The sdist pin and the forward reference of an unreleased feature (0.26.0 release: both by hand). The sdist name ends
# in `.tar.gz`, and the lookahead that keeps `v0.19.01` whole refused the dot after the version. "From the release
# after X" turns into "since <new>" once that release exists; a plain "since X" is history and stays.
# (Mutation probes: lookahead `(?![\d.])` again → the sdist line falls; drop `replace_forward` → the "after" lines fall.)
_probe2 = ("gh attestation verify tinysesam-0.19.0.tar.gz --owner x\n"
           "SLSA Build L3, from the release after 0.19.0): the\n"
           "SLSA Build L3, ab dem Release nach 0.19.0): Der\nsince 0.18.0 and seit 0.19.0 stay\n")
_new2, _ = _release.replace_pins(_probe2, "0.19.0", "0.20.0")
_new2, _n2 = _release.replace_forward(_new2, "0.19.0", "0.20.0")
assert "tinysesam-0.20.0.tar.gz" in _new2, _new2
assert "SLSA Build L3, since 0.20.0): the" in _new2 and "SLSA Build L3, seit 0.20.0): Der" in _new2 and _n2 == 2, _new2
assert "since 0.18.0 and seit 0.19.0 stay" in _new2, _new2
print("  Release script: sdist pin and \"from the release after X\" (en/de) follow the new version")

# ---------- Docs travel along: the changelog knows the current state ----------
changelog = read("CHANGELOG.md")
assert any(k in changelog for k in ("## [Unreleased]", f"## [{pv}]")), \
    "CHANGELOG has neither an open section nor one for the package version"
for readme in ("README.md", "i18n/README.de.md"):
    body = read(readme)
    assert "tests/test_browser.py" in body, f"{readme} does not explain the browser test"
    assert "tests/test_repo.py" in body, f"{readme} does not explain the hygiene test"
print("  both READMEs explain browser and hygiene tests; CHANGELOG maintained")

# ---------- Backlog: structure, references, generated index ----------
# The backlog is part of the repo, so the suite checks it like any other file.
# A backlog that is only "mostly right" is not believed and then not maintained.
violations = backlog.alle_pruefungen(ROOT)
assert not violations, "backlog violations:\n  " + "\n  ".join(violations)

entries = backlog.lade(ROOT)
assert entries, "backlog/ is empty — it should contain at least one milestone"

# The index is generated: if it deviates, someone maintained it by hand
# or forgot to rebuild it.
import subprocess  # noqa: E402
_r = subprocess.run([sys.executable, "scripts/_backlog.py", "index", "--dry-run"],
                    cwd=ROOT, capture_output=True, text=True)
assert _r.returncode == 0, ("backlog/README.md is stale — "
                            "run `python3 scripts/_backlog.py index`")
print(f"  Backlog: {len(entries)} entries, structure clean, index current")

# ---------- Promised Python versions: measured, not claimed ----------
# A classifier is a promise to the user. Until 0.18.0 TinySesam promised 3.11 and 3.13,
# and the CI ran neither — the promise was never measured. Conversely a test died on 3.10
# on `tomllib` (only exists from 3.11), and because `ci-local` runs only ONE version, it
# only showed up in the GitHub matrix. This check catches both.
import re as _re  # noqa: E402

_read = lambda *parts: pathlib.Path(ROOT, *parts).read_text(encoding="utf-8", errors="replace")
_pp = _read("pyproject.toml")
promised = set(_re.findall(r"Programming Language :: Python :: (\d+\.\d+)", _pp))
_ci = _read(".github", "workflows", "ci.yml")
_m = _re.search(r"python-version:\s*\[([^\]]+)\]", _ci)
driven = set(_re.findall(r"[\"']([\d.]+)[\"']", _m.group(1))) if _m else set()
missing = sorted(promised - driven, key=lambda v: [int(t) for t in v.split(".")])
assert not missing, ("classifiers promise Python " + ", ".join(missing) +
                   ", the CI matrix does not run them — either extend the matrix "
                   "or drop the classifier. An unmeasured commitment is a claim.")
print(f"  Python {', '.join(sorted(promised))} promised AND in the CI matrix")

# Standard-library names that do not exist yet in the oldest promised version.
# The import is often in the middle of a file and never shows up locally.
TO_NEW = {"tomllib": (3, 11), "typing.Self": (3, 11), "datetime.UTC": (3, 11),
          "itertools.batched": (3, 12), "typing.override": (3, 12)}
_min = tuple(int(t) for t in min(promised, key=lambda v: [int(t) for t in v.split(".")]).split("."))
to_new = []
for path in FILES:
    if not path.endswith(".py"):
        continue
    text = _read(path)
    for name, start_from in TO_NEW.items():
        if start_from <= _min:
            continue
        short = name.split(".")[-1]
        if _re.search(rf"^\s*import {_re.escape(name)}\b", text, _re.M) or \
           _re.search(rf"^\s*from {_re.escape(name.rsplit('.', 1)[0])} import .*\b{short}\b", text, _re.M):
            to_new.append(f"{path}: {name} is only available from Python {start_from[0]}.{start_from[1]}")
assert not to_new, ("Promised from Python %d.%d onwards:\n  " % _min) + "\n  ".join(to_new)
print(f"  no standard library beyond Python {_min[0]}.{_min[1]} ({len(TO_NEW)} patterns)")

# ---------- README.md is also the PyPI description ----------
# Nothing resolves relative repo paths there: Until 0.18.0 the logo and
# seven links were dead on the package page — the first page a prospect sees. The German version under
# i18n/ is read only on GitHub and may stay relative.
_readme = _read("pyproject.toml")
assert 'readme = "README.md"' in _readme, ("pyproject no longer points to README.md — "
                                           "this check then belongs on the other file")
_r = _read("README.md")
_rel = _re.findall(r"!?\[[^\]]*\]\((?!https?://|#)([^)]+)\)", _r)
_rel += _re.findall(r'<img src="(?!https?://)([^"]+)"', _r)
_rel += _re.findall(r'<a href="(?!https?://|#)([^"]+)"', _r)
assert not _rel, ("relative references in README.md — dead on the PyPI page:\n  " +
                  "\n  ".join(sorted(set(_rel))))
print(f"  README.md without relative references (PyPI-ready)")

# ---------- Configuration reference: every field explained, dump current ----------
# Of 119 fields 39 appeared in no README. Maintaining a reference by hand means
# that it is incomplete again at the next new field — hence generated, from the
# comments in config.py. Two promises: the file is current, and no field is silent.
_gen = subprocess.run([sys.executable, "scripts/_config_docs.py", "--dry-run"],
                      cwd=ROOT, capture_output=True, text=True)
assert _gen.returncode == 0, ("CONFIGURATION.md is stale — "
                              "run `python3 scripts/_config_docs.py`")
_config = _read("CONFIGURATION.md")
# B3-15: Descriptions slipped. The indented continuation of a trailing comment ended up
# at the NEXT field — `login_identifier` began with the text of `https_mode`, `admin_identifiers`
# broke off mid-sentence. Measured on three fields that have exactly this form, and on the
# `#:` form whose colon used to stand in the text.
def _line(slot):
    return next(z for z in _config.splitlines() if z.startswith(f"| `{slot}` "))
assert "warn = also runs WITHOUT a certificate" in _line("https_mode"), _line("https_mode")
assert "warn =" not in _line("login_identifier") and "What do people sign in with?" in _line("login_identifier"), \
    _line("login_identifier")
assert "AS LONG AS there is no admin" in _line("admin_identifiers"), _line("admin_identifiers")
assert "ONLY as an additional factor" in _line("pin_login"), _line("pin_login")
assert not _re.search(r"\| : ", _config), "`#:` colon is still in the text"
_silent = _re.findall(r"^\| `([a-z0-9_]+)` .* \| — \|$", _config, _re.M)
assert not _silent, ("these config fields have no explanatory comment in config.py:\n  " +
                    "\n  ".join(_silent[:8]) +
                    "\n  (write a comment after the field, then regenerate.)")
# Character class with digits: `saml_idp_x509cert` otherwise slipped through, and the test
# reported 118 instead of 119 — a regex that almost fits counts wrongly instead of not at all.
_number = len(_re.findall(r"^\| `[a-z0-9_]+` \|", _config, _re.M))
from dataclasses import fields as _dc_fields  # noqa: E402
import sys as _sys2  # noqa: E402
_sys2.path.insert(0, ROOT)
from tinysesam import TinySesamConfig as _TSC  # noqa: E402
assert _number == len(_dc_fields(_TSC)), (f"CONFIGURATION.md lists {_number} fields, "
                                        f"TinySesamConfig has {len(_dc_fields(_TSC))}")
# The tier (0.22.0): Almost every field is A; whoever deviates enters it in their line — otherwise
# someone would read the tombstone `totp_required` as a commitment until 1.0.
import json as _json_k  # noqa: E402
_field_tiers = {n: e.get("tier") for n, e in
               _json_k.loads(_read("tests/api_surface.json"))["TinySesamConfig.fields"].items()}
_not_a = sorted(n for n, st in _field_tiers.items() if st != "A")
assert _not_a, "no field outside tier A — `totp_required` is B (PO decision 2026-09-26)"
for _slot in _not_a:
    assert f"**Tier {_field_tiers[_slot]}.**" in _line(_slot), _line(_slot)
print(f"  Configuration reference: {_number} fields, each explained, dump current, "
      f"{len(_not_a)} marked outside tier A")

# ---------- API reference: every frozen method explained, dump current ----------
# 68 of the 105 frozen methods appeared in no docs. Whoever embeds TinySesam saw a
# commitment ("this surface stays stable") without a place that says what it contains.
_api = subprocess.run([sys.executable, "scripts/_api_docs.py", "--dry-run"],
                      cwd=ROOT, capture_output=True, text=True)
assert _api.returncode == 0, ("API.md is stale or the generator rejects something — "
                              "run `python3 scripts/_api_docs.py`\n" + _api.stderr[-400:])
_apidoc = _read("API.md")
# Methods `### \`name(…)\``, properties `### \`name\` — Property …` (frozen since 0.20.1),
# since 0.22.0 also the constants (`— Constant`, explanation from the `#:` block above), the
# methods of TinySesamConfig and the function exports: With the tiering they stand as a
# commitment (A) or building block (B) — without an explanation they would be a commitment into the blue. Likewise the
# methods and constants of the result types `LoginResult` and `PasswordChangeResult` (0.22.0); their
# fields are checked by the generator.
_empty = _re.findall(r"^### `((?:TinySesamConfig\.|tinysesam\.|LoginResult\.|PasswordChangeResult\.)?"
                    r"[A-Za-z_][A-Za-z0-9_]*)"
                    r"(?:\(|` — Property|` — Constant).*\n\n—$", _apidoc, _re.M)
assert not _empty, ("these names have no docstring or `#:` comment:\n  " +
                   "\n  ".join(_empty[:8]) +
                   "\n  (a frozen method without explanation is a commitment into the blue.)")
# Structured by tier (PO decision 2026-09-26): A and B with explanation, C as a table of old
# name → replacement (since 0.22.0 every C name warns; whoever sees the warning looks here for the replacement).
for _head in ("## A · Methods of `TinySesam`", "## B · Methods of `TinySesam`",
              "## A · Result of the sign-in building blocks: `tinysesam.LoginResult`",
              "## A · Result of the password change: `tinysesam.PasswordChangeResult`",
              "## C · Deprecated — removed with 1.0"):
    assert _head in _apidoc, f"API.md without section {_head!r} — structure by tier is missing"
_c_lines = _re.findall(r"^\| `(\w+)` \| (?:Method|Constant) \| (.+) \|$", _apidoc, _re.M)
_c_names = sorted(n for _b, _ee in _json_k.loads(_read("tests/api_surface.json")).items()
                  for n, _e in _ee.items() if isinstance(_e, dict) and _e.get("tier") == "C")
assert sorted(n for n, _ in _c_lines) == _c_names, (
    "API.md: the table „Deprecated“ does not match the C names of the baseline")
assert all(_e.strip() and not _e.startswith("—") for _, _e in _c_lines), (
    "API.md: a C name without replacement in the table „Deprecated“")
assert "## No tier" not in _apidoc, ("API.md lists names without a tier — "
                                        "`python tests/test_api_surface.py` says which")
print(f"  API reference: {_apidoc.count(chr(10) + '### ')} entries, each explained, dump current")

# ---------- Numbers in the READMEs: measured instead of maintained ----------
# The docs comparison of 2026-09-21 found numbers from old states in both READMEs: "17 and 22
# test files" at actually 45, "Python 3.10–3.13" with a matrix up to 3.14, "119 config fields"
# after the 120th field. A number nobody re-measures is wrong after the next commit — and
# it stands precisely in the section where a prospect reads off the maturity.
import glob as _glob  # noqa: E402

_readmes = {"README.md": _read("README.md"), "i18n/README.de.md": _read("i18n/README.de.md")}

_should_tests = len(_glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
for _file, _text in _readmes.items():
    _named = {int(n) for n in _re.findall(r"\*?\*?(\d+)\*?\*? (?:test files|Testdateien)", _text)}
    assert _named, f"{_file} no longer names a test file count — adjust pattern in the guard"
    assert _named == {_should_tests}, (
        f"{_file} names {sorted(_named)} test files, there are {_should_tests}")
print(f"  READMEs: test file count correct ({_should_tests})")

# The Python matrix: the READMEs name a range, ci.yml the list. Both must mean the same.
_ci = _read(".github/workflows/ci.yml")
_matrix = _re.search(r'python-version:\s*\[([^\]]+)\]', _ci)
assert _matrix, "python-version matrix in ci.yml not found"
_versions = _re.findall(r'"([\d.]+)"', _matrix.group(1))
_span = f"{_versions[0]}–{_versions[-1]}"
for _file, _text in _readmes.items():
    _found = _re.findall(r"Python (\d+\.\d+[–-]\d+\.\d+)", _text)
    assert _found, f"{_file} no longer names a Python range — adjust pattern in the guard"
    assert set(_found) == {_span}, (
        f"{_file} names Python {sorted(set(_found))}, the CI runs {_span}")
print(f"  READMEs: Python range correct ({_span})")

# ---------- The tiers of the public API are in both READMEs (0.22.0) ----------
# PO decision 2026-09-26: B is "öffentlich für Fortgeschrittene" with its own docs section.
# A B building block that no README names is a commitment nobody knows about — exactly the
# state the tiering was meant to end (68 of 105 methods stood nowhere). The list
# comes from the guard's baseline, not from this test: A new B name turns it red until
# it is in both READMEs. The fields are listed completely in CONFIGURATION.md.
import json as _json  # noqa: E402
_storage = _json.loads(_read("tests/api_surface.json"))
# The contract areas (hook, HTTP routes, security log; PO decision 2026-10-29) are not Python building blocks:
# their documentation is the generated API.md and docs/OPERATIONS.md, checked right below.
_contract = ("TinySesam.attributes", "TinySesam.event_payload", "http.routes", "http.forward", "http.contract",
            "log.loggers", "log.lines")
# The gate client (T-86) has a section of its own in both READMEs, checked right after this loop.
_tier_b = sorted({n for _area, _entries in _storage.items()
                   if _area not in ("TinySesamConfig.fields", "gate_client") and _area not in _contract
                   for n, _e in _entries.items() if isinstance(_e, dict) and _e.get("tier") == "B"})
assert len(_tier_b) >= 50, f"only {len(_tier_b)} B names in tests/api_surface.json — baseline broken?"
for _file, _head in (("README.md", "### For advanced use (tier B)"),
                      ("i18n/README.de.md", "### Für Fortgeschrittene (Stufe B)")):
    _text = _readmes[_file]
    assert _head in _text, f"{_file}: section {_head!r} missing"
    _section = _text.split(_head, 1)[1].split("\n## ", 1)[0]
    _missing = [n for n in _tier_b if not _re.search(rf"`[^`\n]*\b{_re.escape(n)}\b[^`\n]*`", _section)]
    assert not _missing, (f"{_file}: These B building blocks are missing in section {_head!r}:\n  " +
                        "\n  ".join(_missing))
        # What consumers use but that was in no README until 0.21.0 (tier A).
    for _name in ("create_user", "has_role", "current_user", "session_cookie_name",
                  "dataclasses.fields(TinySesamConfig)"):
        assert _name in _text, f"{_file} does not document {_name}"
print(f"  READMEs: all {len(_tier_b)} B building blocks in the section for advanced users, "
      "the used A names documented")
# Every name of `tinysesam.gate_client` in its own README section (a class member under its own name, as it is used:
# `gate.identify(…)`), and the tier-B section points there.
_gate_names = sorted(n for n, _e in _storage.get("gate_client", {}).items() if isinstance(_e, dict)
                     and _e.get("tier") in ("A", "B"))
assert len(_gate_names) >= 40, f"only {len(_gate_names)} gate client names in the baseline — measurement broken?"
for _file, _head, _b_head in (
        ("README.md", "### Gate client for Flask, Django and other Python apps (T-86)", "### For advanced use (tier B)"),
        ("i18n/README.de.md", "### Gate-Client für Flask, Django und andere Python-Apps (T-86)",
         "### Für Fortgeschrittene (Stufe B)")):
    _text = _readmes[_file]
    assert _head in _text, f"{_file}: section {_head!r} missing"
    _section = _text.split(_head, 1)[1].split("\n### ", 1)[0]
    _missing = [n for n in _gate_names
                if not _re.search(rf"`[^`\n]*\b{_re.escape(n.rsplit('.', 1)[-1])}\b[^`\n]*`", _section)]
    assert not _missing, f"{_file}: gate client names missing in section {_head!r}: {_missing}"
    assert "`tinysesam.gate_client`" in _text.split(_b_head, 1)[1].split("\n## ", 1)[0], (
        f"{_file}: the tier-B section does not point to the gate client")
print(f"  READMEs: all {len(_gate_names)} gate client names in its own section, the tier-B section points there")

# ---------- The contract beyond the Python names is documented (PO decision 2026-10-29) ----------
# The measurement is tests/test_api_surface.py; here the documentation is held against it: API.md has the
# generated sections, both READMEs the paragraph, and docs/OPERATIONS.md names every event word and every literal
# value of the security log and every logger — a promise the operator cannot read is no promise to them.
for _head in ("## A · Attributes of `TinySesam`", "## HTTP contract", "### A · Forward, gate and provider paths — for reverse proxies, identity providers and the health check",
              "### B · Pages and API routes", "## A · Security log — for fail2ban and log shipping"):
    assert _head in _apidoc, f"API.md without section {_head!r} — `python3 scripts/_api_docs.py`"
for _file, _head in (("README.md", "**Beyond the Python names**"), ("i18n/README.de.md", "**Über die Python-Namen hinaus**")):
    assert _head in _readmes[_file], f"{_file} without the paragraph {_head!r} on the contract beyond the Python names"
_operation = _read("docs/OPERATIONS.md")
assert "## Security log contract (fail2ban and log shipping)" in _operation, "docs/OPERATIONS.md: security log contract missing"
_operation_section = _operation.split("## Security log contract (fail2ban and log shipping)", 1)[1].split("\n## ", 1)[0]
_gappy = []
for _name in _storage["log.lines"]:
    _kind, _, _rest = _name.partition(":")
    if _kind == "event" and f"`{_rest}`" not in _operation_section:
        _gappy.append(_name)
    elif _kind == "value":
        _key_name, _, _value = _rest.partition("=")
        if f"`{_value}`" not in _operation_section or f"`{_key_name}=`" not in _operation_section:
            _gappy.append(_name)
    elif _kind == "format" and f"`{_rest}`" not in _operation_section:
        _gappy.append(_name)
for _name in _storage["log.loggers"]:
    if f"`{_name}`" not in _operation_section:
        _gappy.append("logger:" + _name)
assert not _gappy, ("docs/OPERATIONS.md, “Security log contract” does not name:\n  "
                          + "\n  ".join(_gappy))
print(f"  contract beyond the Python names: API.md sections, README paragraphs and the operator page name "
      f"{len(_storage['log.lines'])} log atoms and {len(_storage['log.loggers'])} loggers")

# ---------- The installation leads with the pinned PyPI path ----------
# Until 2026-09-27 this guard forbade every PyPI line ("only from 1.0") — by then TinySesam had been
# there since 0.19.0: According to ADR-6 every tag goes to PyPI via Trusted Publishing. The guard thereby
# held the wrong statement fast, and both READMEs sent everyone on the detour via Git. Now:
# Both lead with `pip install "tinysesam==<version>"` (scripts/_release.py sets the version too),
# no line installs unpinned, and no sentence claims the package is missing from PyPI.
from tinysesam import __version__ as _ver  # noqa: E402
for _file, _text in _readmes.items():
    assert f'pip install "tinysesam=={_ver}"' in _text, (
        f'{_file} does not show the pinned PyPI installation (pip install "tinysesam=={_ver}")')
    _unpinned = [z.strip() for z in _text.splitlines()
                  if _re.match(r'^\s*pip install ["\']?tinysesam[\[\]a-z,]*["\']?\s*(#.*)?$', z)]
    assert not _unpinned, f"{_file} installs unpinned:\n  " + "\n  ".join(_unpinned)
    _wrong = _re.search(r"not on PyPI|nicht auf PyPI|noch nicht auf PyPI", _text, _re.I)
    assert not _wrong, f"{_file} claims TinySesam is missing from PyPI: {_wrong.group(0)!r}"
print("  READMEs install pinned from PyPI (since 0.19.0)")

# ---------- The code examples in the READMEs must build ----------
# The very first block a new user copies enabled `oidc_enabled=True` and set
# no `base_url` — and since the rework N1 that is exactly a `ConfigError` in the constructor.
# The rule came, the example stayed. That is the same class of error as
# `pip install tinysesam` one check further up: The first line anyone tries was
# the first one that failed. So what is measured is not the text, but the build.
#
# Two stages, because they carry different distances:
#   (1) Every `TinySesamConfig(…)` call of both READMEs is built. `TinySesam(cfg)` imports
#       the extras only lazily (it just warns), so this stage also runs in the core job without [all]
#       — it is the measurement that can be relied on.
#   (2) Every COMPLETE block (one with `from tinysesam import …`) additionally runs as a
#       program of its own in a throwaway directory. That is the sharper probe (syntax,
#       method names, `auth.router()`), but needs the extras that its switches name:
#       `auth.router()` throws a `MissingExtra` without [passkey]/[oidc]. If an extra is missing, the
#       line says so and stage (1) stands.
#
# `db_path` is redirected to a throwaway directory, otherwise the run would create `app.db` in the repo.
# The path is not what is measured here.
import contextlib as _cl  # noqa: E402
import importlib.util as _ilu  # noqa: E402
import io as _io  # noqa: E402
import logging as _log  # noqa: E402
import subprocess as _sp  # noqa: E402
import tempfile as _tmp  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.errors import ConfigError as _CfgErr  # noqa: E402

_EXTRA_MODULE = {"passkey_enabled": ("webauthn", "passkey"), "oidc_enabled": ("authlib", "oidc"),
                "saml_enabled": ("onelogin", "saml"), "ldap_enabled": ("ldap3", "ldap")}


def _py_blocks(text):
    return _re.findall(r"```python\n(.*?)```", text, _re.S)


def _config_calls(text):
    """One `TinySesamConfig(…)` call as source text — via bracket depth, not via regex."""
    for m in _re.finditer(r"TinySesamConfig\(", text):
        depth = 0
        for j in range(m.end() - 1, len(text)):
            if text[j] == "(":
                depth += 1
            elif text[j] == ")":
                depth -= 1
                if depth == 0:
                    yield text[m.start():j + 1]
                    break


# The guide for coding agents (`AGENTS.md`) and the skill for app builders (`skills/tinysesam/SKILL.md`) are read
# by assistants that copy what they see — an example there that no longer runs is copied just the same. So their
# blocks go through both stages too, and there EVERY Python block must be a complete program (no snippet that only
# looks right): see the AI docs guard below.
_AI_DOCS = ("AGENTS.md", "skills/tinysesam/SKILL.md")
_example_docs = dict(_readmes, **{f: _read(f) for f in _AI_DOCS})

_seclog = _log.getLogger("tinysesam.security")
_before = _seclog.level
_seclog.setLevel(_log.CRITICAL)          # the build warns about missing extras — only noise here
_built = 0
try:
    for _file, _text in _example_docs.items():
        for _nr, _block in enumerate(_py_blocks(_text), 1):
            for _source in _config_calls(_block):
                try:
                    _cfg = eval(_source, {"TinySesamConfig": TinySesamConfig, "os": os, "tempfile": _tmp})   # noqa: S307
                except Exception as _e:
                    raise AssertionError(
                        f"{_file}, Block {_nr}: `{_source.splitlines()[0]}…` cannot even be "
                        f"evaluated — {type(_e).__name__}: {_e}")
                _cfg.db_path = os.path.join(_tmp.mkdtemp(), "example.db")
                try:
                    with _cl.redirect_stderr(_io.StringIO()):     # first-admin token to the operator
                        TinySesam(_cfg)
                except _CfgErr as _e:
                    raise AssertionError(
                        f"{_file}, Block {_nr}: the example does not build.\n  {_source[:90]}…\n  "
                        f"ConfigError: {str(_e)[:300]}\n  (Whoever copies it does not get past the "
                        f"first line — like the `pip install` above.)")
                _built += 1
finally:
    _seclog.setLevel(_before)
assert _built >= 12, f"only {_built} config examples found — adjust pattern in the guard"
print(f"  READMEs: all {_built} config examples build (ConfigError-free)")

# Stage 2 — actually run the complete blocks.
_executed, _skipped = 0, []
_executed_ai = 0
for _file, _text in _example_docs.items():
    for _nr, _block in enumerate(_py_blocks(_text), 1):
        if "from tinysesam import" not in _block and "import tinysesam" not in _block:
            assert _file not in _AI_DOCS, (
                f"{_file}, block {_nr} is a snippet — every Python block there must be a complete program "
                "(with `from tinysesam import …`), because the suite runs it")
            continue                      # a snippet, not a program
        _missing = [f"[{_x}] ({_m})" for _s, (_m, _x) in _EXTRA_MODULE.items()
                  if f"{_s}=True" in _block and _ilu.find_spec(_m) is None]
        if _missing:
            _skipped.append(f"{_file} Block {_nr}: " + ", ".join(_missing))
            continue
        _where = _tmp.mkdtemp()
        _script = os.path.join(_where, "example.py")
        with open(_script, "w", encoding="utf-8") as _fh:
            _fh.write(_block)
        _env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        _execution = _sp.run([sys.executable, _script], cwd=_where, env=_env,
                        capture_output=True, text=True, timeout=120)
        assert _execution.returncode == 0, (
            f"{_file}, block {_nr} does not run through (exit {_execution.returncode}):\n"
            + (_execution.stderr or _execution.stdout)[-900:])
        _executed += 1
        _executed_ai += _file in _AI_DOCS
assert _executed_ai >= 8, f"only {_executed_ai} blocks of {_AI_DOCS} ran — the guard sees too little"
assert _executed + len(_skipped) >= 2, "the READMEs no longer contain two complete examples"
if _skipped:
        # No silent waving through: Stage 1 built the same configs, only `auth.router()` is missing.
    print("  (block not run, extra missing: " + "; ".join(_skipped) + ")")
else:
    assert _executed >= 2, f"only {_executed} complete examples — adjust pattern"
print(f"  READMEs, AGENTS.md, skill: {_executed} complete examples run through in the throwaway directory "
      f"({_executed_ai} of them from the AI docs)")

# ---------- The AI docs: every name they mention exists (T-65) ----------
# `AGENTS.md` (for agents that change this repo) and `skills/tinysesam/SKILL.md` (for agents that build an app with
# TinySesam) are read by assistants that act on every word without checking it. A renamed config field, a moved
# template or a dropped route would be passed on as an instruction. The dotted names (`auth.…`) are covered by the
# docs guard above and the code blocks by the two stages; this guard takes the rest of what they name in backticks:
#   * snake_case words outside quotes → a config field or a word the package defines,
#   * `TINYSESAM_…` environment variables and `X-TinySesam-…` headers → spelled somewhere in the package,
#   * repo paths (`deploy/forward-auth/Caddyfile`, `tinysesam/theme.py`) → exist,
#   * routes (`/auth/…`, `/.tinysesam/…`, `/.well-known/…`) → a route of the measured HTTP surface.
# Plus the wiring: the skill's front matter, `CLAUDE.md` importing `AGENTS.md`, the plugin marketplace pointing at the
# skill, and both READMEs naming the install line.

_CONFIG_FIELDS = {f.name for f in _dc_fields(TinySesamConfig)}
_LIB_TEXT = "\n".join(read(f) for f in LIB)
# A configurable path is recorded as a placeholder (`<admin>`, `<oidc_callback_path>`): the docs name its default.
_PLACEHOLDER_DEFAULT = {"admin": TinySesamConfig.admin_path, "oidc_callback_path": TinySesamConfig.oidc_callback_path}
_ROUTES = sorted({re.sub(r"<(\w+)>", lambda m: _PLACEHOLDER_DEFAULT.get(m.group(1), m.group(0)), k.split(" ", 1)[1])
                  for k in _json.loads(read("tests/api_surface.json"))["http.routes"]})
_TOP = {f.split("/", 1)[0] for f in FILES}
_SNAKE = re.compile(r"(?<![\w.$-])([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?![\w-])")
_ENV = re.compile(r"\bTINYSESAM_[A-Z_]*[A-Z]\b")
_HEADER = re.compile(r"\bX-TinySesam-[A-Za-z-]*[A-Za-z]\b")
_ROUTE = re.compile(r"(?<![\w.])(/(?:auth|\.tinysesam|\.well-known)(?:/[\w.{},-]*)*)")
_PATH = re.compile(r"^[\w.-]+(?:/[\w.-]+)+/?$")


def _route_known(path, routes):
    """A literal route, or a prefix of one (`/auth/*`, `…/oauth-protected-resource*`); `{x}` matches any segment."""
    path = path.rstrip("/") or "/"
    pattern = re.compile("^" + re.sub(r"\\\{[^/]*?\\\}", "[^/]+", re.escape(path)))
    return any(pattern.match(re.sub(r"\{[^/}]*\}", "x", r)) or r.startswith(path) for r in routes)


def ai_doc_findings(text, *, fields, words, lib_text, routes, exists, top):
    """[(line, finding)] — names in backticks (outside code blocks) that the code does not know."""
    out, fence = [], False
    for n, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        for span in re.findall(r"`([^`\n]+)`", line):
            bare = re.sub(r"\"[^\"]*\"|'[^']*'", "", span)          # values in quotes are not names
            for w in ([] if "/" in bare else _SNAKE.findall(bare)):   # a path is checked as a path below
                if w not in fields and w not in words:
                    out.append((n, f"unknown name `{w}`"))
            for e in _ENV.findall(span) + _HEADER.findall(span):
                if e not in lib_text:
                    out.append((n, f"`{e}` is spelled nowhere in the package"))
            for r in _ROUTE.findall(span.split("?", 1)[0].rstrip("*")):
                if not _route_known(r, routes):
                    out.append((n, f"unknown route `{r}`"))
            token = span.strip().rstrip("*")
            if _PATH.match(token) and token.split("/", 1)[0] in top and not exists(token):
                out.append((n, f"path `{token}` does not exist"))
    return out


# Words of the repo's own tooling count too: the guide for contributors names suites (`test_csp`), the surface dump
# (`api_surface`) and backlog keys (`superseded_by`).
_tool_words = package_words((f, read(f)) for f in FILES
                            if f.endswith(".py") and f.startswith(("scripts/", "tests/")))
_tool_words |= {os.path.splitext(os.path.basename(f))[0] for f in FILES}
# ... the directives of the shipped proxy templates (`reverse_proxy`, `handle_response` in the Caddyfile) and the
# backlog's front-matter keys from its convention (`superseded_by`).
_tool_words |= {w for f in FILES if (f.startswith("deploy/") and not f.endswith(".py"))
                or f == "backlog/README-KONVENTION.md"
                for w in re.findall(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+", read(f))}
_ai_kw = dict(fields=_CONFIG_FIELDS, words=_package_words | _tool_words, lib_text=_LIB_TEXT, routes=_ROUTES,
              exists=lambda p: os.path.exists(os.path.join(ROOT, p)), top=_TOP)
_ai_findings = [f"{d}:{n}: {what}" for d in _AI_DOCS for n, what in ai_doc_findings(read(d), **_ai_kw)]
assert not _ai_findings, "the AI docs name what the code does not know:\n  " + "\n  ".join(_ai_findings[:10])
# Self-probes: each kind of stale name is found, the real ones and quoted values pass.
_probe_ok = ("Use `login_chain=[\"password\", \"totp\"]`, `mfa_enrollment=\"first_login\"`, `TINYSESAM_BASE_URL`, "
             "`X-TinySesam-Reauth`, `/auth/reauth`, `/auth/passkey/{register,login}/{begin,finish}`, "
             "`/.well-known/oauth-protected-resource*`, `deploy/forward-auth/Caddyfile`, `tinysesam/theme.py`.\n")
assert ai_doc_findings(_probe_ok, **_ai_kw) == [], ai_doc_findings(_probe_ok, **_ai_kw)
for _bad, _kind in (("`login_chian=[]`", "unknown name"), ("`TINYSESAM_BASE_URI`", "spelled nowhere"),
                    ("`X-TinySesam-Reauthenticate`", "spelled nowhere"), ("`/auth/re-auth`", "unknown route"),
                    ("`deploy/forward-auth/Caddyfile.old`", "does not exist"),
                    ("```bash\n`x`\n```\n`stepup_max_age_secs`", "unknown name")):
    _hit = ai_doc_findings(_bad, **_ai_kw)
    assert len(_hit) == 1 and _kind in _hit[0][1], f"probe {_bad!r} → {_hit}"
for _doc, _real, _stale in (("skills/tinysesam/SKILL.md", "`admin_require_mfa=True`", "`admin_require_2fa=True`"),
                            ("skills/tinysesam/SKILL.md", "`deploy/home-network/`", "`deploy/homenet/`"),
                            ("AGENTS.md", "`tests/test_csp.py`", "`tests/test_csp_strict.py`")):
    assert _real in read(_doc), f"mutation anchor {_real} not in {_doc}"
    assert ai_doc_findings(read(_doc).replace(_real, _stale, 1), **_ai_kw), f"{_doc}: stale {_stale} goes unnoticed"

# The wiring. Agent Skills format: `name` (lowercase, digits, hyphens, ≤ 64, = folder) and `description` (≤ 1024)
# in the front matter; the description is what makes the skill fire, so it must name the trigger words.
_skill = read("skills/tinysesam/SKILL.md")
_front = re.match(r"---\n(.*?)\n---\n", _skill, re.S)
assert _front, "SKILL.md without front matter"
_name = re.search(r"^name:\s*(\S+)\s*$", _front.group(1), re.M)
assert _name and _name.group(1) == "tinysesam" and re.fullmatch(r"[a-z0-9-]{1,64}", _name.group(1)), _front.group(1)
_desc = re.search(r"^description:\s*>-\n((?:  .*\n?)+)", _front.group(1) + "\n", re.M)
assert _desc, "SKILL.md: description missing (folded `>-` block expected)"
_desc_text = " ".join(x.strip() for x in _desc.group(1).splitlines())
assert 100 < len(_desc_text) <= 1024, f"description length {len(_desc_text)}"
for _trigger in ("FastAPI", "forward auth", "OAuth", "TOTP", "proxy"):
    assert _trigger in _desc_text, f"the skill description no longer names {_trigger!r} — it would not fire"
assert re.search(r"^@AGENTS\.md$", read("CLAUDE.md"), re.M), "CLAUDE.md no longer imports AGENTS.md"
_market = _json.loads(read(".claude-plugin/marketplace.json"))
assert _market["name"] and _market["owner"]["name"], _market
_entry = [p for p in _market["plugins"] if p["name"] == "tinysesam"]
assert len(_entry) == 1 and _entry[0]["source"] == "./", _market["plugins"]
assert os.path.isfile(os.path.join(ROOT, "skills", _entry[0]["name"], "SKILL.md")), "the plugin carries no skill"
for _file, _text in _readmes.items():
    assert f"/plugin install tinysesam@{_market['name']}" in _text, f"{_file}: install line of the skill missing"
print(f"  AI docs: {len(_AI_DOCS)} files, every name in backticks known; skill front matter, CLAUDE.md import, "
      "plugin marketplace and install line wired")

# ---------- Accepted CodeQL findings are recorded in the repository ----------
# A dismissed alert is a click in the GitHub UI, invisible and not reviewable; `.github/codeql/accepted.md` is its
# trace in the repository. Offline check of the table only: every row complete, alert numbers unique.
_accepted = read(".github/codeql/accepted.md")
_rows = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in _accepted.splitlines()
         if re.match(r"\|\s*\d+\s*\|", ln)]
assert _rows, ".github/codeql/accepted.md: no table rows"
for _r in _rows:
    assert len(_r) == 6 and all(_r), f"accepted.md: incomplete row {_r[:2]}"
    assert re.fullmatch(r"py/[a-z-]+", _r[1].strip("`")) and re.fullmatch(r"\d{4}-\d\d-\d\d", _r[4]), _r[:5]
_nums = [_r[0] for _r in _rows]
assert len(set(_nums)) == len(_nums), "accepted.md: alert number twice"
print(f"  CodeQL: {len(_rows)} accepted findings recorded, rows complete, numbers unique")

# Kit 0.22.0 (M-1, stage 3): Has every check before it SEEN something? A check over an
# empty set is always green. Must run LAST, it evaluates the case counts before it.
unseen = hygiene.pruefe_etwas_gesehen()
assert not unseen, "kit check without case:\n  " + "\n  ".join(unseen)
print("  Kit 0.22.0: every check has seen something")

print("OK test_repo")

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
braucht(shutil.which("git"), "git fehlt")
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
PROJEKTE = ["TinySesam"]


def read(*parts) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


FILES = hygiene.getrackte_dateien(ROOT)
LIB = [f for f in FILES if f.startswith("tinysesam/") and f.endswith(".py")]
WEB = [f for f in FILES if f.startswith("web/") and f.endswith(".py")]

# ---------- Version: pyproject, __init__ and CHANGELOG must fit together ----------
pv = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M).group(1)
fehler = hygiene.pruefe_versionsgleichstand(
    ROOT, weitere={"tinysesam/__init__.py": r'^__version__ = "([^"]+)"'})
assert not fehler, fehler
print(f"  Version {pv}: pyproject = __init__ = CHANGELOG")

# ---------- Required files ----------
PFLICHT = ["LICENSE", "SECURITY.md", "i18n/SECURITY.de.md", "CHANGELOG.md", "README.md", "i18n/README.de.md",
           "TODO.md", "tinysesam/py.typed", ".gitignore",
           ".github/workflows/ci.yml", ".github/workflows/pages.yml",
           ".github/workflows/release.yml", "Dockerfile", ".dockerignore",
           "scripts/_residue_check.sh", "tests/_kit/hygiene.py",
           "scripts/_backlog.py", "tests/_kit/backlog.py",
           "backlog/README-KONVENTION.md",
           ".github/dependabot.yml",
           "CODE_OF_CONDUCT.md", "i18n/CODE_OF_CONDUCT.de.md",
           "CONTRIBUTING.md", "i18n/CONTRIBUTING.de.md"]
fehlend = hygiene.pruefe_pflichtdateien(ROOT, PFLICHT)
assert not fehlend, f"Required files missing: {fehlend}"
print("  License, SECURITY, CHANGELOG, both READMEs, py.typed, all workflows present")

# ---------- docs/ now contains only attachments; the pages are built by the action ----------
# Exception: OPERATIONS.md, the operator docs (failure behaviour, sessions, sign-in paths). It is
# source text like API.md, not a built page — the Pages action does not publish docs/.
docs = [f for f in FILES if f.startswith("docs/")]
assert sorted(docs) == ["docs/.nojekyll", "docs/OPERATIONS.md", "docs/theme.css", "docs/wizard.png"], docs
assert not any(f.endswith(".html") for f in FILES), "generated HTML does not belong in the repo"
assert "_site/" in read(".gitignore")
print("  docs/: only OPERATIONS.md, theme.css, wizard.png, .nojekyll — no generated HTML in the repo")

# ---------- docs/OPERATIONS.md says what the code does ----------
# Operator docs whose numbers drift away from the code are worse than none: People plan
# by them. What is checked is what can be read off mechanically — the wait time on a locked
# database, the healthcheck path and that every identifying factor is in the table of the
# sign-in paths (a new path without a row there would be exactly the gap from B1-11).
betrieb = read("docs", "OPERATIONS.md")
_store_src = read("tinysesam", "store.py")
_busy = int(re.search(r"^    BUSY_TIMEOUT_MS = ([\d_]+)", _store_src, re.M).group(1).replace("_", ""))
assert f"**{_busy // 1000} s**" in betrieb, f"OPERATIONS.md does not name the real wait time ({_busy} ms)"
assert re.search(r'^HEALTH_PATH = "/healthz"', read("tinysesam", "gateway.py"), re.M) and "/healthz" in betrieb
_ident = re.search(r"^    _IDENTIFYING = \(([^)]*)\)", read("tinysesam", "manager.py"), re.M).group(1)
_faktoren = re.findall(r'"(\w+)"', _ident)
assert len(_faktoren) >= 6, f"_IDENTIFYING not read: {_faktoren}"
_fehlend = [f for f in _faktoren if f"(`{f}`" not in betrieb]
assert not _fehlend, f"OPERATIONS.md: sign-in path without a row in the strength table: {_fehlend}"
print(f"  docs/OPERATIONS.md: wait time {_busy // 1000} s, /healthz and all {len(_faktoren)} "
      "identifying factors match the code")

# The image's HEALTHCHECK must wait longer than the database: `/healthz` writes and, like every sign-in,
# waits up to BUSY_TIMEOUT_MS behind a foreign writer. With 4 s the
# check aborted on a 6-s lock, although the service returned 200 afterwards (A-B6-4-healthz-sperre).
_df = read("Dockerfile")
_hc_docker = int(re.search(r"HEALTHCHECK [^\n]*--timeout=(\d+)s", _df).group(1))
_hc_client = int(re.search(r"HTTPConnection\(.*?timeout=(\d+)\)", _df).group(1))
assert _hc_client * 1000 > _busy, f"Health client waits {_hc_client} s, the database up to {_busy} ms"
assert _hc_docker > _hc_client, f"Docker aborts after {_hc_docker} s, before the client ({_hc_client} s)"
print(f"  Dockerfile: HEALTHCHECK waits {_hc_client} s/{_hc_docker} s, longer than busy_timeout")

# ---------- Generated artifacts do not belong in the repo ----------
artefakte = hygiene.pruefe_artefakte(FILES, POLICY)
assert not artefakte, f"generated artifacts are versioned: {artefakte[:5]}"
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
    baum = _ast.parse(read(f))
    erlaubt = set()
    if f == "tinysesam/gateway.py":
        for knoten in _ast.walk(baum):
            if isinstance(knoten, _ast.FunctionDef) and knoten.name == "main":
                erlaubt = set(range(knoten.lineno, (knoten.end_lineno or knoten.lineno) + 1))
    for knoten in _ast.walk(baum):
        if not isinstance(knoten, _ast.Call) or not isinstance(knoten.func, _ast.Name):
            continue
        if knoten.func.id in ("print", "breakpoint") and knoten.lineno not in erlaubt:
            raise AssertionError(f"Debug-Ausgabe in der Bibliothek: {f}:{knoten.lineno}: "
                                 f"{knoten.func.id}(...)")
print("  no print()/breakpoint() in tinysesam/")

# ---------- No obvious secrets ----------
lecks = hygiene.pruefe_geheimnisse(ROOT, FILES, POLICY)
assert not lecks, f"possible key in {lecks[:3]}"
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
hits = hygiene.pruefe_private_infrastruktur(ROOT, FILES, POLICY, PROJEKTE)
assert not hits, "private infrastructure in the public repo:\n  " + "\n  ".join(hits[:8])
print(f"  no private infrastructure ({len(POLICY['private_muster'])} patterns"
      f" + {len(POLICY['private_namen_sha256_16'])} names)")

# The kit's patterns catch hosts, IPs and names but not a maintainer's own file paths: a workflow
# comment pointed at a private documentation page in a dot-directory of the home folder and passed unnoticed.
# Local pattern, built from pieces so that this file does not match itself. Files that the test kit
# manages (`repokit sync`) are not edited here and therefore not scanned.
_KIT_VERWALTET = {".githooks/pre-push", "scripts/_nur_text.sh", "scripts/_residue_check.sh",
                  "scripts/_backlog.py", "backlog/README-KONVENTION.md"}
_PRIVATER_PFAD = re.compile("(?:~/\\." + "|/ho" + "me/[a-z]|\\." + "claude/)")


def private_pfade(dateien, lies):
    """`datei:zeile` for every line that names a private home-directory path."""
    treffer = []
    for rel in dateien:
        if rel in _KIT_VERWALTET or rel.startswith("tests/_kit/"):
            continue
        try:
            text = lies(rel)
        except (UnicodeDecodeError, OSError):
            continue
        for n, zeile in enumerate(text.split("\n"), 1):
            if _PRIVATER_PFAD.search(zeile):
                treffer.append(f"{rel}:{n}")
    return treffer


_pfade = private_pfade(FILES, read)
assert not _pfade, "private file path in the public repo:\n  " + "\n  ".join(_pfade[:8])
# Self-probe: the check must see what it is meant to see (a check that cannot fail proves nothing).
_probe = private_pfade(["probe"], lambda _r: "See " + "~/" + ".cl" + "aude/context/x.md")
assert _probe == ["probe:1"], _probe
_probe = private_pfade(["probe"], lambda _r: "cp x " + "/ho" + "me/someone/y")
assert _probe == ["probe:1"], _probe
print("  no private home-directory paths in tracked files")

# ---------- Documented standards, enforced by machine ----------
# A tag can be moved; a commit SHA is the only immutable reference.
ungepinnt = hygiene.pruefe_actions_sha_gepinnt(ROOT, FILES)
assert not ungepinnt, "actions not pinned to a commit SHA:\n  " + "\n  ".join(ungepinnt)

# There is no safe default: the initial permission comes from the repo setting.
ohne_rechte = hygiene.pruefe_workflow_permissions(ROOT, FILES)
assert not ohne_rechte, "workflow without `permissions:`:\n  " + "\n  ".join(ohne_rechte)
print(f"  all actions pinned by commit SHA, every workflow sets `permissions:`")

# Keep a Changelog 1.1.0 — fixed set of categories, one language per repo.
kategorien = hygiene.pruefe_changelog_kategorien(ROOT, POLICY)
assert not kategorien, "CHANGELOG:\n  " + "\n  ".join(kategorien[:5])

# GitHub picks the README by LOCATION, not by language — a translation silently goes stale.
# The translations live under i18n/, so that GitHub's health-file detector (CODE_OF_CONDUCT,
# SECURITY, …) picks the English root files and not the alphabetically first .de version.
uebersetzung = hygiene.pruefe_uebersetzungs_struktur(ROOT, [("README.md", "i18n/README.de.md")])
assert not uebersetzung, "translation deviates:\n  " + "\n  ".join(uebersetzung)
print("  CHANGELOG categories valid; i18n/README.de.md follows the structure of README.md")

# ---------- Every pinned example tag points to the current version ----------
# Otherwise the docs silently keep recommending an old version: The pin in the compose file and the
# `pip install` lines in the README do not age along, because nobody runs them.
PINS = (re.compile(r"TinySesam(?:\.git)?[@/](?:releases/download/)?v(\d+\.\d+\.\d+)"),  # Git tag, wheel
        re.compile(r"tinysesam:v(\d+\.\d+\.\d+)"))                                     # image tag
for f in ("README.md", "i18n/README.de.md", "deploy/forward-auth/docker-compose.yml"):
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
PROZESS_MODULE = {"subprocess", "multiprocessing", "pty"}
PROZESS_AUFRUFE = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
                   ("os", "execvp"), ("os", "spawnv"), ("os", "spawnl"), ("os", "fork")}

for f in LIB:
    body = read(f)
    assert "self_update" not in body, f"self-update built in again: {f}"
    assert "sys.executable" not in body, f"{f} starts an interpreter"
    baum = _ast.parse(body)
        # Resolve the aliases first: `import os as _o` turns `_o.system(...)` into `os.system(...)`,
        # and a check that only looks at the name "os" overlooks that.
    alias = {}
    for knoten in _ast.walk(baum):
        if isinstance(knoten, _ast.Import):
            for a in knoten.names:
                alias[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]
    for knoten in _ast.walk(baum):
        if isinstance(knoten, _ast.Import):
            treffer = [a.name.split(".")[0] for a in knoten.names
                       if a.name.split(".")[0] in PROZESS_MODULE]
            assert not treffer, f"{f}:{knoten.lineno} imports {treffer[0]} — starts processes"
        elif isinstance(knoten, _ast.ImportFrom):
            wurzel = (knoten.module or "").split(".")[0]
            assert wurzel not in PROZESS_MODULE, \
                f"{f}:{knoten.lineno} imports from {wurzel} — starts processes"
        elif isinstance(knoten, _ast.Call) and isinstance(knoten.func, _ast.Attribute):
            wert = knoten.func.value
            if isinstance(wert, _ast.Name):
                modul = alias.get(wert.id, wert.id)
                if (modul, knoten.func.attr) in PROZESS_AUFRUFE:
                    raise AssertionError(f"{f}:{knoten.lineno} ruft {modul}.{knoten.func.attr}() "
                                         "— startet einen Prozess")
print(f"  no self-update, no process start in the library "
      f"({len(PROZESS_MODULE)} modules, {len(PROZESS_AUFRUFE)} calls checked)")

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

# Every job carries a time limit (pipeline register 2026-10-07): Without it GitHub's default of 360 min applies, and
# a hanging `apt-get` blocked PR #135 for as long as `pr-mergen` waited. The text is read — jobs
# are the keys with two spaces under `jobs:`, the limit is in the block with four spaces.
_ohne_grenze, _jobs_gesehen = [], 0
for _wf in sorted(pathlib.Path(ROOT, ".github", "workflows").glob("*.yml")):
    _rumpf = _wf.read_text(encoding="utf-8").split("\njobs:\n", 1)[1]
    for _block in re.split(r"\n(?=  [A-Za-z0-9_-]+:\n)", "\n" + _rumpf):
        _m = re.match(r"\n?  ([A-Za-z0-9_-]+):\n", _block)
        if not _m:
            continue
        _jobs_gesehen += 1
        if not re.search(r"\n    timeout-minutes: [1-9][0-9]*\n", _block):
            _ohne_grenze.append(f"{_wf.name}: {_m.group(1)}")
assert _jobs_gesehen >= 20, f"only {_jobs_gesehen} jobs recognised — check no longer reads the workflows"
assert not _ohne_grenze, "job without timeout-minutes:\n  " + "\n  ".join(_ohne_grenze)
print(f"  timeout-minutes in all {_jobs_gesehen} jobs")

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
OEFFENTLICHE_DIENSTE = ["pypi.org", "raw.githubusercontent.com", "img.shields.io", "spdx.dev",
                        "www.flaticon.com", "ollornog.github.io", "github.com",
                                                # Entra ID endpoint of the bundled preset — a real, fixed
                                                # address of Microsoft, not an example address and nothing of our own.
                        "login.microsoftonline.com"]
adressen = hygiene.pruefe_adressen(ROOT, FILES, POLICY, zusaetzliche_hosts=OEFFENTLICHE_DIENSTE)
assert not adressen, "addresses outside RFC 2606 and the service list:\n  " + "\n  ".join(adressen)
nicht_ausfuehrbar = hygiene.pruefe_ausfuehrbar(
    ROOT, ["scripts/check.sh", "scripts/_backlog.py", "scripts/_codeql_backlog.py", "tests/run_all.py"])
assert not nicht_ausfuehrbar, "\n  ".join(nicht_ausfuehrbar)
abbruch = hygiene.pruefe_kein_abbruch_auf_default_branch(ROOT, FILES)
assert not abbruch, "cancel-in-progress on main:\n  " + "\n  ".join(abbruch)
matrix_regel = hygiene.pruefe_python_matrix_regel()
assert not matrix_regel, "\n  ".join(matrix_regel)
sammelt = hygiene.pruefe_run_all_sammelt_automatisch(ROOT)
assert not sammelt, "\n  ".join(sammelt)
# Since the decision on PR #54 (lower bound 3.12) this repo runs the kit matrix
# unchanged — the two earlier exceptions are thereby settled and the checks run.
matrix_abweichung = hygiene.pruefe_python_matrix(ROOT, FILES)
assert not matrix_abweichung, "Python matrix deviates from the kit source:\n  " + "\n  ".join(matrix_abweichung)
untergrenze = hygiene.pruefe_requires_python(ROOT)
assert not untergrenze, "\n  ".join(untergrenze)
# Kit 0.14.0: Every `actions/checkout` sets `persist-credentials: false`. **Level:** own
# hardening, not a documented standard — GitHub recommends it nowhere explicitly. What it brings:
# With the default the token is readable for EVERY later step in the job, and after the
# checkout foreign code runs here (`pip install -e`, third-party actions). No exception needed:
# No job of this repo pushes or tags via git — measured, not assumed.
ohne_pc = hygiene.pruefe_persist_credentials(ROOT, FILES)
assert not ohne_pc, "checkout without persist-credentials:\n  " + "\n  ".join(ohne_pc)

# Kit 0.14.0: Is the file list complete at all? An empty list makes EVERY check
# after it green, and the real case was not "empty": Via `git archive` elsewhere 6 of
# 1326 files were missing — the whole `.github/`, i.e. exactly the workflows that two checks above read.
# `root=` is mandatory, otherwise it is only compared against a minimum count instead of against `git ls-tree`.
luecken = hygiene.pruefe_dateiliste_plausibel(FILES, root=ROOT)
assert not luecken, "the checked file list is incomplete:\n  " + "\n  ".join(luecken)

# Kit 0.14.0: Host names WITHOUT `https://` in front. `pruefe_adressen` only looks for URLs with a scheme, and
# the infrastructure pattern demands three name parts — a bare second-level domain slips
# through both. In a foreign repo a real company name stood there that way.
#
# The `grundstock` was REVIEWED ONCE, not generated: Every entry is here because someone
# looked up why the address occurs in the repo. Filled automatically it would be the baseline
# that waves the next real finding through as well.
BLANKE_ADRESSEN_OK = [
    "ghcr.io",                 # the registry the own image comes from (Dockerfile, compose)
    "pypi.org",                # the package index test_packaging checks against
    "python.org",              # source reference in the kit file python_matrix.json
    "devguide.python.org",     # ditto — the release calendar the matrix follows from
    "flaticon.com",            # source reference for the favicon (licence obligation, belongs in plain sight)
    "ollornog.github.io",      # the own project page: identity, not infrastructure
    # The last two are NOT addresses, they just look like it:
    "ab.de",                   # tests/test_identifier.py: `assert not valid_email("ab.de")`
    "admin.app",               # tinysesam/messages.py: a translation key, not a host
]
blank = hygiene.pruefe_blanke_adressen(ROOT, FILES, POLICY, zusaetzliche_hosts=OEFFENTLICHE_DIENSTE,
                                       grundstock=BLANKE_ADRESSEN_OK)
assert not blank, "bare host names outside the reviewed list:\n  " + "\n  ".join(blank)

# Kit 0.17: three checks on the kit itself. `belegstellen` is empty — TinySesam keeps no
# citation index; the call is there anyway, so that a later entry gets checked.
beleg = hygiene.pruefe_belegstellen_eng(ROOT, FILES, [])
assert not beleg, "citation patterns hit code:\n  " + "\n  ".join(beleg)
tabelle = hygiene.pruefe_tabelle_vollstaendig()
assert not tabelle, "kit check in no list or in several:\n  " + "\n  ".join(tabelle)
schluessel = hygiene.pruefe_policy_schluessel_gelesen(POLICY)
assert not schluessel, "policy keys without a reader:\n  " + "\n  ".join(schluessel)

# Kit 0.18: Nothing is loaded from third parties (PO rule 2026-09-23). A link is a door, a
# `src` is a messenger: objected to are src/srcset, <link href>, url(), @import, fetch()/import(),
# <iframe src> — never an <a href>. Limit: what JavaScript assembles at runtime, this
# check does not see.
fremd = hygiene.pruefe_keine_fremdressourcen(ROOT, FILES, POLICY)
assert not fremd, "third-party resources in the markup:\n  " + "\n  ".join(fremd)
# Kit 0.28 (PO 2026-10-08): every complete page carries a favicon. The built-in pages are built by the code; they
# are checked by tests/test_gate_brand.py (brand_icon) — here the files in the repo (website, demos).
favicon = hygiene.pruefe_favicon(ROOT, FILES, POLICY)
assert not favicon, "pages without favicon:\n  " + "\n  ".join(favicon)

# Kit 0.21: Asked from OUTSIDE whether every test file runs at all. A test that is not wired up
# passes its own call check (the line below) by keeping silent. Here
# `tests/run_all.py` collects via glob — the check recognises that and then does not ask per file.
testdateien = hygiene.pruefe_testdateien_gerufen(ROOT)
assert not testdateien, "test file without runner:\n  " + "\n  ".join(testdateien)

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

ungerufen = hygiene.pruefe_kit_prueffunktionen_gerufen(ROOT, ausgenommen={})
assert not ungerufen, "kit check lies idle:\n  " + "\n  ".join(ungerufen)
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
assert "USER tinysesam" in dockerfile, "image runs as root"
assert "HEALTHCHECK" in dockerfile, "image without health check"
for weg in ("/opt/venv/bin/pip", "/usr/local/bin/pip"):
    assert weg in dockerfile, f"{weg} is not removed — the venv brings its own pip"
print("  check.sh + pre-push present; CI runs browser, hygiene and website tests; release signs checksums")

# ---------- Supply chain: what T-13 (B4-*) tightened stays tight ----------
# Every check here measures a commitment from the supply-chain round of T-13. YAML is read as
# text (without PyYAML — the suite also runs in the core job without extras), hence narrow: blocks by
# indentation, comments cut off.
WORKFLOWS = sorted(f for f in FILES if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")))


def _code(text: str) -> list[str]:
    return [hygiene.ohne_yaml_kommentar(z).rstrip() for z in text.splitlines()]


def _jobs(text: str) -> dict[str, list[str]]:
    """Job name → its lines (without comments). Jobs stand two spaces deep under `jobs:`."""
    zeilen, jobs, name, drin = _code(text), {}, None, False
    for z in zeilen:
        if z.startswith("jobs:"):
            drin = True
            continue
        if drin and z and not z.startswith(" "):
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", z)
        if drin and m:
            name = m.group(1)
            jobs[name] = []
        elif drin and name:
            jobs[name].append(z)
    return jobs


def _kommandos(zeilen: list[str], schluessel: tuple[str, ...] = ("run",)) -> list[str]:
    """The lines of all `run:` steps (or of the key in `schluessel`) — single-line and as
    block (`run: |`)."""
    aus, block_tiefe = [], None
    for z in zeilen:
        tiefe = len(z) - len(z.lstrip())
        if block_tiefe is not None:
            if z.strip() and tiefe <= block_tiefe:
                block_tiefe = None
            else:
                aus.append(z.strip())
                continue
        m = re.match(rf"^(\s+)(?:- )?(?:{'|'.join(schluessel)}):\s*(.*)$", z)
        if m:
            if m.group(2) in ("|", ">", "|-", ">-"):
                block_tiefe = len(m.group(1))
            else:
                aus.append(m.group(2))
    return [k for k in aus if k]


# B4-4 — Whoever holds an identity or a write permission does not run foreign code. Until 0.19.0
# the whole suite including `pip install ".[all]"` ran in the job that also attested — every
# dependency could have issued an attestation on the workflow's identity.
#
# Which permissions a job holds is read from EVERY spelling: block (`id-token: write`),
# flow map (`{id-token: write}`), `write-all`, and inherited from the workflow level if the job
# sets nothing itself. Until the re-check (A-2) the latch only saw the block spelling and only
# `id-token`/`contents` — a new job with `permissions: write-all` went straight through.
def _rechte_wert(wert: str, folgend: list[str], tiefe: int) -> set[str]:
    """The write permissions from a `permissions:` value; `*` stands for write-all."""
    wert = wert.strip().strip("'\"")
    if wert == "write-all":
        return {"*"}
    if wert in ("read-all", "{}"):
        return set()
    if wert.startswith("{"):
        paare = [p.split(":", 1) for p in wert.strip("{}").split(",") if ":" in p]
        return {k.strip() for k, v in paare if v.strip().strip("'\"") == "write"}
    assert not wert, f"unknown permissions value {wert!r} — adjust guard"
    rechte = set()
    for z in folgend:
        if z.strip() and len(z) - len(z.lstrip()) <= tiefe:
            break
        m = re.match(r"^\s+([a-z-]+):\s*(\S+)", z)
        if m and m.group(2).strip("'\"") == "write":
            rechte.add(m.group(1))
    return rechte


def _rechte_oben(text: str) -> set[str]:
    zeilen = _code(text.split("\njobs:", 1)[0])
    for i, z in enumerate(zeilen):
        m = re.match(r"^permissions:\s*(.*)$", z)
        if m:
            return _rechte_wert(m.group(1), zeilen[i + 1:], 0)
    return {"*"}   # without a statement the repo default applies — in the worst case write permission


def _rechte_job(zeilen: list[str], geerbt: set[str]) -> set[str]:
    for i, z in enumerate(zeilen):
        m = re.match(r"^    permissions:\s*(.*)$", z)
        if m:
            return _rechte_wert(m.group(1), zeilen[i + 1:], 4)
    return geerbt


# Commands a job with identity or write permission may run in `run:` — an allowlist,
# not a block list: `curl … | bash`, `git clone … && node …` or a new tool would slip through
# any word list (A-5). Every member of a command chain and every `$( … )` substitution is checked.
# `gh pr merge` and `gh pr comment` (Dependabot auto-merge, 2026-09-28) stand individually — never
# `gh pr` wholesale: `gh pr checkout` would fetch PR code into a job with write permission.
ERLAUBT_MIT_RECHT = {"echo", "printf", "gh release", "gh attestation", "git log",
                     "gh pr merge", "gh pr comment", "gh workflow run",
                     "gh pr update-branch"}  # auto-merge with app: stale branches via rebase (Kit 0.33)


def _befehle(zeile: str) -> list[str]:
    """The individual commands of a shell line — separated at ; && || | ( $( and `.

    What follows after a closing parenthesis belongs to the outer command (`echo "$(git log)"
    >> file`) and is discarded; a pipe inside quotes is read as a separate command
    and thus turns red — better too strict than too blind.
    """
    aus = []
    for teil in re.split(r"\$\(|`|&&|\|\||[;|(]", zeile):
        woerter = teil.split(")", 1)[0].split()
        while woerter and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", woerter[0]):
            woerter.pop(0)           # VAR=value before the command
        if woerter:
            aus.append(" ".join(woerter[:3]))     # three words: `gh pr merge` ≠ `gh pr checkout`
    return aus


def _erlaubt(befehl: str) -> bool:
    """An allowlist entry covers the command if it names it word for word:
    `gh release` covers `gh release create`, `gh pr merge` does not cover `gh pr checkout`."""
    woerter = befehl.split()
    return any(woerter[:len(e.split())] == e.split() for e in ERLAUBT_MIT_RECHT)


# Write permissions that MUST get by with checkout — per job exactly these permissions and the reason. The
# checkout is allowed, foreign code in `run:` still is not. If a permission is added, the job turns
# red (the set must match exactly).
CHECKOUT_MIT_RECHT = {
    (".github/workflows/codeql.yml", "analyse"): ({"security-events"},
                                                   "CodeQL needs the source; no `run:`"),
    (".github/workflows/release.yml", "image"): ({"packages"},
                                                 "build context for the image; pip runs in the BuildKit "
                                                 "container, which does not see the token"),
}

_geprueft_identitaet, _ausnahmen_gesehen = 0, set()
for wf in WORKFLOWS:
    text = read(wf)
    oben = _rechte_oben(text)
        # Never a write permission at the top workflow level — every job would inherit it.
    assert not oben, f"{wf}: write permission at workflow level ({sorted(oben)}) — belongs on the job"
    jobs = _jobs(text)
    assert jobs, f"{wf}: no jobs recognised — check the parser"
    for job, zeilen in jobs.items():
        rechte = _rechte_job(zeilen, oben)
        if not rechte:
            continue
        _geprueft_identitaet += 1
        block = "\n".join(zeilen)
        ausnahme = CHECKOUT_MIT_RECHT.get((wf, job))
        if ausnahme:
            _ausnahmen_gesehen.add((wf, job))
            assert rechte == ausnahme[0], (f"{wf} job `{job}`: permissions {sorted(rechte)} instead of "
                                           f"{sorted(ausnahme[0])} — the exception applies only to that")
        else:
            assert "actions/checkout" not in block, (
                f"{wf} job `{job}` holds {sorted(rechte)} AND checks out the repo — build and "
                "attestation belong in separate jobs")
                # Local actions and Docker actions bring code that no SHA pin holds fast.
        assert not re.search(r"^\s+(?:- )?uses:\s*['\"]?(\./|docker://)", block, re.M), \
            f"{wf} job `{job}` holds {sorted(rechte)} and uses a local/Docker action"
        assert not re.search(r"^\s+(?:- )?shell:", block, re.M), \
            f"{wf} job `{job}` holds {sorted(rechte)} and sets its own `shell:`"
        for k in _kommandos(zeilen):
            for befehl in _befehle(k):
                assert _erlaubt(befehl), (f"{wf} job `{job}` holds {sorted(rechte)} and runs "
                                          f"`{befehl}`: {k}")
assert _ausnahmen_gesehen == set(CHECKOUT_MIT_RECHT), \
    f"exceptions without job: {set(CHECKOUT_MIT_RECHT) - _ausnahmen_gesehen} — tidy up the list"
assert _geprueft_identitaet >= 6, f"only {_geprueft_identitaet} jobs with write permission found — check the parser"
print(f"  {_geprueft_identitaet} jobs with identity/write permission (every spelling): only "
      f"{'/'.join(sorted(ERLAUBT_MIT_RECHT))}, checkout only with a justified exception")

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
assert not _rechte_job(_am_jobs.get("entscheiden", []), _rechte_oben(_am)) & {"*"} and \
    not re.search(r"\bwrite\b", " ".join(_am_jobs.get("entscheiden", []))), \
    "dependabot-auto-merge.yml: `entscheiden` holds a write permission — the logic belongs in the read job"
_am_kmd = _kommandos(_am_jobs.get("ausfuehren", []))
_am_merge = [k for k in _am_kmd if k.startswith("gh pr merge")]
# Without `--auto`: With `--auto` GitHub would merge later, and the follow-up below would run into the void.
assert _am_merge and all("--match-head-commit" in k and "--auto" not in k for k in _am_merge), \
    f"dependabot-auto-merge.yml: what is merged is not directly exactly the checked head: {_am_merge}"
# The trigger names exactly the mandatory workflows (by `name:`), otherwise nobody merges if a
# missing one finishes last.
_pflicht_wf = re.search(r'PFLICHT_WORKFLOWS:\s*"([^"]+)"', _am)
assert _pflicht_wf, "dependabot-auto-merge.yml: PFLICHT_WORKFLOWS missing"
_wf_name = {}
for _wf in WORKFLOWS:
    _n = re.search(r"^name:\s*(.+?)\s*$", read(_wf), re.M)
    _wf_name[os.path.basename(_wf)] = _n.group(1).strip("\"'") if _n else None
_ausloeser = re.search(r"workflows:\s*\[([^\]]*)\]", _am_on)
_ausloeser = {w.strip().strip("\"'") for w in _ausloeser.group(1).split(",")} if _ausloeser else set()
assert _ausloeser == {_wf_name.get(w) for w in _pflicht_wf.group(1).split()}, \
    f"dependabot-auto-merge.yml: `workflows:` {sorted(_ausloeser)} ≠ PFLICHT_WORKFLOWS " \
    f"{sorted(_wf_name.get(w) or w for w in _pflicht_wf.group(1).split())}"
# Follow-up: What a push to main starts is triggered after the merge via `workflow_dispatch` —
# exactly that, and each of them must know `workflow_dispatch`.
_auf_main = set()
for _wf in WORKFLOWS:
    _kopf = "\n".join(_code(read(_wf).split("\njobs:", 1)[0]))
    if re.search(r"^  push:\s*\n\s+branches:\s*\[main\]", _kopf, re.M):
        _auf_main.add(os.path.basename(_wf))
        assert re.search(r"^  workflow_dispatch:", _kopf, re.M), \
            f"{_wf} runs on main but has no `workflow_dispatch` — the follow-up cannot trigger it"
_angestossen = {m.group(1) for k in _am_kmd for m in [re.match(r"gh workflow run (\S+)", k)] if m}
assert _angestossen == _auf_main, \
    f"dependabot-auto-merge.yml: follow-up {sorted(_angestossen)} ≠ workflows on main {sorted(_auf_main)}"
print("  Dependabot auto-merge: logic without write permission, only own Dependabot PRs, exactly the checked head")

# An action used with several subpaths (`github/codeql-action/init` and
# `/analyze`) must be in ONE Dependabot group: Bumped individually the parts ran in
# different versions, and CodeQL broke (#110/#111). (Mutation probe: delete the group `codeql`
# → red.)
_teile: dict[str, set] = {}
for _wf in WORKFLOWS:
    for _m in re.finditer(r"uses:\s*([\w.-]+/[\w.-]+)/([\w./-]+)@", read(_wf)):
        _teile.setdefault(_m.group(1), set()).add(_m.group(2))
_dep_text = "\n".join(_code(read(".github/dependabot.yml")))
_actions_eintrag = next(e for e in re.split(r"\n  - ", _dep_text)[1:] if e.startswith("package-ecosystem: github-actions"))
# Per group its patterns — all parts must land in the SAME group, not each in some group.
_gruppen = {}
for _g in re.finditer(r"^      ([\w-]+):\s*\n((?:        .*\n?)+)", _actions_eintrag, re.M):
    _pm = re.search(r"patterns:\s*\[([^\]]*)\]", _g.group(2))
    _gruppen[_g.group(1)] = [m.strip().strip("\"'") for m in _pm.group(1).split(",") if m.strip()] if _pm else []
for _action, _unter in sorted(_teile.items()):
    if len(_unter) < 2:
        continue
    assert any(all(any(fnmatch.fnmatch(f"{_action}/{u}", m) for m in _ms) for u in _unter)
               for _ms in _gruppen.values()), \
        f"dependabot: {_action} is used with {sorted(_unter)}, but is in no common group"
print("  Dependabot: actions with several parts are bumped together")

# B4-6 — Actions that download a tool at runtime. The SHA pin holds the action fast, not
# the tool: Without a statement setup-qemu pulls the `latest` tag of tonistiigi/binfmt (privileged!),
# setup-buildx `moby/buildkit:buildx-stable-1`. Demanded is per tool version AND digest.
# Limit: A NEW action that downloads is not in this table — it is checked when it is
# adopted (extend the list below), not recognised by itself.
WERKZEUG_PFLICHT = {
    "docker/setup-qemu-action": [r"^\s+image:\s*\S+:[\w.-]+@sha256:[0-9a-f]{64}\s*$"],
    "docker/setup-buildx-action": [r"^\s+version:\s*v\d+\.\d+\.\d+\s*$",
                                   r"^\s+driver-opts:\s*image=\S+:v[\d.]+@sha256:[0-9a-f]{64}\s*$",
                                   # M6/B1: buildx not from the actions cache (zizmor cache-poisoning).
                                   r"^\s+cache-binary:\s*false\s*$"],
}
# Checked and fixed without a statement: the tool version is a constant in the pinned commit.
WERKZEUG_IM_SHA = {"anchore/sbom-action": "syft as a constant in src/SyftVersion.ts",
                   "github/codeql-action": "the CodeQL bundle belongs to the action version",
                   "pypa/gh-action-pypi-publish": "image ghcr.io/pypa/…:<sha> or a Dockerfile with constraints"}
# Deliberately floating: the browser test is meant to run against the current stable Chrome. The job has only
# read permission and ships nothing.
WERKZEUG_WANDERND_OK = {"browser-actions/setup-chrome": "ci.yml, read permission only, ships nothing"}
for wf in WORKFLOWS:
    zeilen = _code(read(wf))
    for i, z in enumerate(zeilen):
        m = re.search(r"uses:\s*([^@\s]+)@", z)
        if not m or m.group(1) not in WERKZEUG_PFLICHT:
            continue
                # The `with:` block of the action: the following lines up to the next step.
        folgend = []
        for w in zeilen[i + 1:]:
            if re.match(r"^\s+- ", w) or (w and not w.startswith(" ")):
                break
            folgend.append(w)
        for muster in WERKZEUG_PFLICHT[m.group(1)]:
            assert any(re.match(muster, w) for w in folgend), (
                f"{wf}: {m.group(1)} without a fixed tool ({muster}) — the SHA pin holds the action "
                "fast, not the image it pulls at runtime")
print(f"  actions that download: tool with version and digest ({', '.join(WERKZEUG_PFLICHT)})")

# B4-6/B4-8 — pip in the build and check path only against a hashed list. Exempt is what the
# suite checks (there the resolution IS the subject under test) — i.e. every job that runs `run_all.py`.
for wf in (".github/workflows/release.yml", ".github/workflows/audit.yml"):
    for job, zeilen in _jobs(read(wf)).items():
        block = "\n".join(zeilen)
        if "tests/run_all.py" in block:
            continue
        for z in _kommandos(zeilen):
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
_bau_job = _jobs(read(".github/workflows/release.yml")).get("bauen", [])
assert any(re.search(r"-m\s+build\b", k) for k in _kommandos(_bau_job)), \
    "release.yml: job `bauen` no longer builds with `-m build` — adjust guard"
print("  Build and check tools in release/audit only from hashed lists, build without isolation")

# The button (`workflow_dispatch`) is a dry run: Every job that publishes or holds an
# identity hangs on the tag; the image is built without a tag, but neither logged in nor
# pushed. Until 2026-09-24 the button could have failed at the tag comparison or — without it — published from a
# branch. (Mutation probe: for `release`, `pypi` or `image-beglaubigen`
# delete the `if:` line, or turn `push=${{ github.ref_type == 'tag' }}` into `push=true` → red.)
_rel_jobs = _jobs(rel)
_AM_TAG = "if: github.ref_type == 'tag'"
for _j in ("release", "pypi", "image-beglaubigen"):
    _zeilen = [z.strip() for z in _rel_jobs.get(_j, [])]
    assert _AM_TAG in _zeilen, f"release.yml: job `{_j}` also publishes without a tag (button = dry run)"
# Exception dress rehearsal (PO 2026-10-11): `generalprobe-beglaubigen` holds `id-token` WITHOUT a tag, so that
# the attestation actions run on every PR. Allowed only this narrowly: never on the tag, no checkout, no
# environment, and only the probe file is attested — never an artifact, never an image.
# (Mutation probes: `subject-path: generalprobe.txt` → `dist/*.whl`; a checkout in the job; turn the
# `if:` to `== 'tag'` → each red.)
_PROBE = "if: github.ref_type != 'tag'"
_probe_beglaubigt = 0
for _j, _zeilen in _rel_jobs.items():
    _rechte = " ".join(z.strip() for z in _zeilen)
    _st = [z.strip() for z in _zeilen]
    if re.search(r"\b(id-token|contents|attestations): write\b", _rechte) or \
            any(z.strip().startswith("environment:") for z in _zeilen):
        if _j == "generalprobe-beglaubigen":
            assert _PROBE in _st and _AM_TAG not in _st, f"release.yml: `{_j}` does not run exactly without a tag"
            assert not any("actions/checkout" in z for z in _st), f"release.yml: `{_j}` checks out"
            assert not any(z.startswith(("environment:", "subject-name:", "push-to-registry:")) for z in _st), \
                f"release.yml: `{_j}` names an environment, an image or a registry"
            _gegenstand = [z for z in _st if z.startswith("subject-path:")]
            assert _gegenstand and all(z == "subject-path: generalprobe.txt" for z in _gegenstand), \
                f"release.yml: `{_j}` attests more than the probe file: {_gegenstand}"
            assert not re.search(r"\bcontents: write\b", _rechte), f"release.yml: `{_j}` holds contents: write"
            _probe_beglaubigt += 1
            continue
        assert _AM_TAG in [z.strip() for z in _zeilen], \
            f"release.yml: job `{_j}` holds an identity or write permission, but is not tied to the tag"
assert _probe_beglaubigt == 1, "release.yml: the job `generalprobe-beglaubigen` is missing"
# Every action that runs only on the tag also runs the dress rehearsal — with the same version. Otherwise
# its update would be unchecked (the auto-merge would then leave it lying, but this says so earlier).
_tag_actions, _probe_actions = set(), set()
for _j, _zeilen in _rel_jobs.items():
    for _m in re.finditer(r"uses:\s*(\S+@\S+)", "\n".join(_zeilen)):
        (_probe_actions if _j.startswith("generalprobe") else _tag_actions).add(_m.group(1))
for _a in ("docker/login-action", "docker/build-push-action", "anchore/sbom-action",
           "pypa/gh-action-pypi-publish", "actions/attest-build-provenance", "actions/attest-sbom"):
    _t = {x for x in _tag_actions if x.startswith(_a + "@")}
    _p = {x for x in _probe_actions if x.startswith(_a + "@")}
    assert _t and _t == _p, f"release.yml: {_a} — tag {sorted(_t)} ≠ dress rehearsal {sorted(_p)}"
_image = "\n".join(_rel_jobs.get("image", []))
assert "push=${{ github.ref_type == 'tag' }}" in _image and "push=true" not in _image, \
    "release.yml: the image is also pushed without a tag"
_login = re.search(r"- name: Log in to GHCR\n\s+" + re.escape(_AM_TAG), _image)
assert _login, "release.yml: the GHCR login in job `image` is not tied to the tag"
_pruef = "\n".join(_rel_jobs.get("pruefen", []))
assert "_release.py --pruefen" in _pruef and "if: github.ref_type != 'tag'" in _pruef, \
    "release.yml: the dry run checks nothing (scripts/_release.py --pruefen missing)"
print("  release.yml: dry run without a tag — check and build yes, publish never")

# The dry run is also the mandatory check for automatic updates (PO 2026-09-28): It runs on
# every PR, checks the downloaded artifacts and starts the image BEFORE anything is published or
# pushed. Without a PR trigger no mandatory check would vet the build tools, the lock list and the
# base image, and Dependabot would merge them unchecked. (Mutation probes: delete `pull_request:`;
# take `abbild-probe` out of `needs:` of `image`; `pruefsummen` out of `needs:` of `release`; give the
# suite step in `pruefen` an `if: github.ref_type != 'tag'` → each red.)
_rel_on = rel.split("\njobs:", 1)[0]
assert re.search(r"^  pull_request:", _rel_on, re.M), \
    "release.yml: no `pull_request` trigger — the dry run is no longer a mandatory check"
_needs = {j: re.search(r"^    needs:\s*(.+)$", "\n".join(z), re.M) for j, z in _rel_jobs.items()}
_needs = {j: set(re.findall(r"[A-Za-z0-9_-]+", m.group(1))) if m else set() for j, m in _needs.items()}
assert "pruefsummen" in _needs.get("release", set()), \
    "release.yml: `release` publishes without `pruefsummen` having checked the artifacts"
assert "abbild-probe" in _needs.get("image", set()) and \
    "needs.abbild-probe.result == 'success'" in " ".join(_rel_jobs.get("image", [])), \
    "release.yml: `image` pushes without `abbild-probe` having started the image"
for _j in ("pruefsummen", "abbild-probe"):
    assert not any(z.strip().startswith("if:") for z in _rel_jobs.get(_j, []) if z.startswith("    if")), \
        f"release.yml: `{_j}` hangs on a condition — it must run on every PR and every tag"
assert any("sha256sum -c SHA256SUMS" in k for k in _kommandos(_rel_jobs.get("pruefsummen", []))), \
    "release.yml: `pruefsummen` does not check the checksums"
assert any(k.startswith("scripts/_image_probe.sh") for k in _kommandos(_rel_jobs.get("abbild-probe", []))), \
    "release.yml: `abbild-probe` does not start the image (scripts/_image_probe.sh)"
# The suite in `pruefen` may be skipped ONLY on a PR (there ci.yml runs it) — on the tag it runs.
_suite = re.search(r"- name: Run the suite[^\n]*\n((?:\s{8}.*\n)+)", "\n".join(_rel_jobs.get("pruefen", [])) + "\n")
assert _suite, "release.yml: the suite step in `pruefen` is missing"
_suite_if = [z.strip() for z in _suite.group(1).splitlines() if z.strip().startswith("if:")]
assert _suite_if in ([], ["if: github.event_name != 'pull_request'"]), \
    f"release.yml: the suite in `pruefen` is not skipped only on PRs: {_suite_if}"
# The image tag is the git tag only on the tag. On a PR `github.ref_name` is `108/merge` —
# invalid as an image tag, `image` broke on the first PR with this dry run because of it.
# (Mutation probe: `tags:` back to `…:${{ github.ref_name }}` → red.)
_abbild_tag = re.search(r"^\s+tags:\s*(.+?)\s*$", _image, re.M)
assert _abbild_tag and "${{ github.ref_type == 'tag' && github.ref_name || '" in _abbild_tag.group(1), \
    f"release.yml: the image tag takes the ref even without a tag (on PRs `N/merge`): {_abbild_tag and _abbild_tag.group(1)}"
print("  release.yml: the dry run runs on every PR; release and image depend on checksums and start probe")

# B4-7 — The image installs what the lock list says, byte for byte. The digest pin in FROM
# holds only the base image; a `pip install ".[gateway]"` resolved anew on every build.
SPERRLISTE = "deploy/gateway/requirements.txt"
_df = "\n".join(z for z in dockerfile.splitlines() if not z.lstrip().startswith("#"))
assert "--require-hashes" in _df and "-r requirements.txt" in _df, \
    "the image does not install from the hashed lock list"
assert f"COPY {SPERRLISTE}" in _df, f"the Dockerfile does not copy {SPERRLISTE}"
assert "--upgrade pip" not in _df, "`pip install --upgrade pip` pulls the newest pip on every build"
_eigen = [z for z in _df.splitlines() if re.search(r"pip install .*\s\.\s*(\\|$)", z)]
assert _eigen and all("--no-index" in z and "--no-deps" in z for z in _eigen), \
    f"TinySesam itself is installed with network or resolution: {_eigen}"
assert f"!{SPERRLISTE}" in read(".dockerignore"), f".dockerignore does not let {SPERRLISTE} through"
# `--no-deps` also installs an incomplete list without complaint (A-1 of the re-check): If
# a transitive dependency is missing — say because Dependabot bumped a line that brings a new one —,
# the image breaks only at startup. `pip check` and the import therefore belong in the same
# RUN, after both installations and before removing setuptools; audit.yml runs the same
# steps on every PR, otherwise it would only show up at release (no PR run builds the image).
_run = re.sub(r"\\\n\s*", " ", _df)
_kette = next((z for z in _run.splitlines() if "-r requirements.txt" in z), "")
_stufen = [s.strip() for s in _kette.split("&&")]
_pos = {n: next((i for i, s in enumerate(_stufen) if re.search(m, s)), -1) for n, m in (
    ("sperrliste", r"--require-hashes"), ("eigen", r"--no-index"), ("check", r"/pip check$"),
    ("import", r"python -c \"import tinysesam\.gateway\"$"), ("setuptools", r"uninstall"))}
assert -1 not in _pos.values(), f"Dockerfile: step missing in the installation RUN: {_pos}"
assert _pos["sperrliste"] < _pos["eigen"] < _pos["check"] < _pos["import"] < _pos["setuptools"], \
    f"Dockerfile: `pip check`/import not after the installation and before the cleanup: {_pos}"
_audit_lauf = _kommandos(_code(read(".github/workflows/audit.yml")))
for _m in (rf"pip\"? install --require-hashes --no-deps -r {re.escape(SPERRLISTE)}$",
           r"pip\"? install --no-deps --no-index --no-build-isolation \.$",
           r"pip\"? check$", r"python\"? -c \"import tinysesam\.gateway\"$", r"^python3\.(\d+) -m venv"):
    assert any(re.search(_m, k) for k in _audit_lauf), f"audit.yml: probe of the lock list without `{_m}`"
# The probe runs in the Python series of the image (the lock list is resolved for it).
_reihe = re.search(r"^FROM python:(3\.\d+)", dockerfile, re.M).group(1)
assert any(k.startswith(f"python{_reihe} -m venv") for k in _audit_lauf), \
    f"audit.yml: probe of the lock list not on Python {_reihe} (FROM in the Dockerfile)"
# pip is removed by pattern, not with a fixed series: After the jump from 3.12 to 3.14 (#74)
# all `python3.12` paths pointed into the void, and pip was back in the final image.
for _reihe_fest in set(re.findall(r"(?:python|pip)(3\.\d+)", _df)):
    assert _reihe_fest == _reihe, (f"Dockerfile names Python {_reihe_fest}, the image is "
                                   f"{_reihe} — write paths by pattern (`python3.*`)")


def _sperrliste(rel: str) -> dict[str, str]:
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


_lock = _sperrliste(SPERRLISTE)
import tomllib as _toml  # noqa: E402
_proj = _toml.loads(read("pyproject.toml"))["project"]
_braucht = list(_proj["dependencies"]) + list(_proj["optional-dependencies"]["gateway"])
for _anf in _braucht:
    _m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*>=\s*([0-9.]+)$", _anf)
    assert _m, f"pyproject: unexpected requirement {_anf!r} — adjust guard"
    _n = _m.group(1).lower().replace("_", "-")
    assert _n in _lock, f"{SPERRLISTE} lacks {_n} — regenerate (command in the file header)"
    assert _v(_lock[_n]) >= _v(_m.group(2)), (f"{SPERRLISTE}: {_n}=={_lock[_n]} is below the "
                                              f"bound {_anf} — regenerate")
assert "setuptools" in _lock, f"{SPERRLISTE}: setuptools missing — without build isolation the image needs it"
# Offline part of completeness: Every name in a `# via` must itself be in the list
# (or be the root). Whoever deletes a block by hand leaves its `via` references behind with the
# dependencies. Limit: A leaf without dependencies of its own and a NEW dependency
# after a bump are not seen by this — only `pip check` in audit.yml catches them (see above).
_via, _in_via = set(), False
for _z in read(SPERRLISTE).splitlines():
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
assert _via and _via <= set(_lock), (f"{SPERRLISTE}: `# via` names packages that are missing: "
                                     f"{sorted(_via - set(_lock))} — regenerate")
# Since 2026-10-10 Dependabot's uv ecosystem regenerates the lock list, from EXACTLY ONE input: requirements.in next to it.
# (The line-by-line pip update did not carry over new transitive dependencies, #126.) The input repeats
# `dependencies` + extra `gateway` from pyproject.toml and names setuptools — if it drifts apart, the image resolves
# something other than the package demands. And the header must carry what Dependabot reads the switches from.
EINGABE = "deploy/gateway/requirements.in"
_ein = {}
for _z in read(EINGABE).splitlines():
    _z = _z.split("#", 1)[0].strip()
    if _z:
        _em = re.match(r"^([A-Za-z0-9._-]+)\s*(>=\s*[0-9.]+)?$", _z)
        assert _em, f"{EINGABE}: unexpected line {_z!r}"
        _ein[_em.group(1).lower().replace("_", "-")] = (_em.group(2) or "").replace(" ", "")
_soll = {"setuptools": ""}
for _anf in _braucht:
    _sm = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(>=\s*[0-9.]+)$", _anf)
    _soll[_sm.group(1).lower().replace("_", "-")] = _sm.group(2).replace(" ", "")
# The same packages; the lower bound in the image may be HIGHER than that of the package, never lower (since 2026-10-11).
# Until then equality applied — then every uv PR from Dependabot stayed red (it only bumps requirements.in, #159), and
# the pyproject line had to be updated by hand. The image still resolves with the higher bound only
# what the package allows; the package's commitment (its minimum version) stays where it is.
# (Mutation probes: lower a bound in requirements.in below that of pyproject; delete a package → each red.)
def _fassung(g: str) -> tuple:
    return tuple(int(t) for t in re.findall(r"\d+", g))
assert set(_ein) == set(_soll), (f"{EINGABE} names different packages than pyproject (dependencies + gateway): "
                                 f"only there {sorted(set(_ein) - set(_soll))}, only in pyproject {sorted(set(_soll) - set(_ein))}")
_zu_tief = [f"{p}: {_ein[p] or 'ohne Grenze'} < {_soll[p]}" for p in _soll
            if _soll[p] and (not _ein[p] or _fassung(_ein[p]) < _fassung(_soll[p]))]
assert not _zu_tief, f"{EINGABE}: lower bound below that of the package: {_zu_tief}"
# The command line itself, not just any comment: Dependabot does look for the switches in the whole text, but only this
# line says what the file was really generated with (a mention in the explanatory text above would prove nothing).
_kopf = next((z for z in read(SPERRLISTE).splitlines() if z.startswith("#    uv pip compile ")), "")
for _schalter in ("uv pip compile requirements.in", "--universal", "--generate-hashes",
                  f"--python-version {re.search(r'^FROM python:(3\.\d+)', dockerfile, re.M).group(1)}",
                  "--output-file requirements.txt"):
    assert _schalter in _kopf, f"{SPERRLISTE}: header without `{_schalter}` — Dependabot (uv) would otherwise regenerate differently"
assert not os.path.exists(os.path.join(ROOT, "deploy/gateway/bau.in")), \
    "deploy/gateway/bau.in is back — setuptools is in requirements.in (one input for Dependabot)"
print(f"  Gateway image: {len(_lock)} packages from hashed lock list, covers pyproject, no pip upgrade, "
      f"input = pyproject")

# B4-2 — The vulnerability gate: every hashed list and both resolutions go through pip-audit,
# on every PR and nightly, and the gate must not be able to turn red without blocking.
_audit = read(".github/workflows/audit.yml")
_audit_code = "\n".join(_code(_audit))
for noetig in ("pull_request:", "schedule:", "pip-audit", "--strict", "--resolution lowest-direct",
               "--all-extras"):
    assert noetig in _audit_code, f"audit.yml: `{noetig}` missing — the gate checks less than it says"
assert "continue-on-error" not in _audit_code, "audit.yml must not wave things through (continue-on-error)"
SPERRLISTEN = sorted(f for f in FILES if os.path.basename(f) == "requirements.txt")
assert len(SPERRLISTEN) >= 3, f"only {SPERRLISTEN} found"
for rel in SPERRLISTEN:
    _sperrliste(rel)                                  # pinned + hashed, otherwise red
    assert rel in _audit_code, f"{rel} is not checked by audit.yml"
print(f"  Vulnerability gate: {len(SPERRLISTEN)} lock lists + newest + lowest resolution, --strict")

# B4-3/B4-12 — Dependabot sees every place where something is pinned, and none where there is nothing
# to bump. A pip entry for `/` read the `>=` bounds, and Dependabot never bumps those.
_dep = "\n".join(_code(read(".github/dependabot.yml")))


def _dependabot_dirs(oekosystem: str) -> set[str]:
    dirs = set()
    for eintrag in re.split(r"\n  - ", _dep)[1:]:
        if not re.match(rf"package-ecosystem:\s*{re.escape(oekosystem)}\s*$", eintrag.splitlines()[0]):
            continue
        for m in re.finditer(r"directory:\s*(\S+)", eintrag):
            dirs.add(m.group(1).strip("\"'"))
        for m in re.finditer(r"directories:\s*\[([^\]]*)\]", eintrag):
            dirs |= {d.strip().strip("\"'") for d in m.group(1).split(",") if d.strip()}
    return dirs


assert "/" not in _dependabot_dirs("pip"), ("dependabot: pip on `/` reads only the `>=` bounds "
                                            "and never bumps anything — the floors are checked by audit.yml")
# pip bumps line by line, uv regenerates from requirements.in (since 2026-10-10 for deploy/gateway). A folder belongs
# to exactly ONE of the two — both at once would give two PRs for the same jump, and the pip PR would again be the broken one.
_pip, _uv = _dependabot_dirs("pip"), _dependabot_dirs("uv")
assert not _pip & _uv, f"dependabot: pip AND uv for {sorted(_pip & _uv)}"
for rel in SPERRLISTEN:
    assert "/" + os.path.dirname(rel) in _pip | _uv, f"Dependabot does not bump {rel}"
for _d in _uv:
    assert os.path.exists(os.path.join(ROOT, _d.lstrip("/"), "requirements.in")), \
        f"dependabot: uv for {_d}, but requirements.in is missing there (the one input that uv recompiles)"
for rel in (f for f in FILES if re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", f)):
    assert "/" + os.path.dirname(rel) in _dependabot_dirs("docker-compose"), \
        f"Dependabot does not see {rel} (entry `docker-compose`)"
for rel in (f for f in FILES if os.path.basename(f) == "Dockerfile"):
    assert "/" + os.path.dirname(rel).rstrip("/") in {d.rstrip("/") or "/" for d in _dependabot_dirs("docker")} \
        or (os.path.dirname(rel) == "" and "/" in _dependabot_dirs("docker")), f"Dependabot does not see {rel}"
assert _dependabot_dirs("github-actions"), "Dependabot does not bump the actions"
print("  Dependabot: every lock list, every compose file, every Dockerfile, the actions — no dead pip entry")

# B4-11 — The reference stack: every third-party image with a digest, the own one with the version tag, and
# every service hardened. `caddy:2` moved with every Caddy version.
_compose = read("deploy/forward-auth/docker-compose.yml")
_cz = _code(_compose)
_bilder = [z.split("image:", 1)[1].strip() for z in _cz if re.match(r"^\s+image:", z)]
assert len(_bilder) >= 2, _bilder
for bild in _bilder:
    assert bild == f"ghcr.io/ollornog/tinysesam:v{pv}" or re.search(r":[\w.-]+@sha256:[0-9a-f]{64}$", bild), \
        f"compose: {bild} is neither the own version image nor pinned by version+digest"
_anker = re.search(r"^x-haertung: &haertung\n((?:  .*\n)+)", "\n".join(_cz) + "\n", re.M)
assert _anker, "compose: the hardening anchor x-haertung is missing"
for noetig in ("read_only: true", "cap_drop: [ALL]", 'security_opt: ["no-new-privileges:true"]'):
    assert noetig in _anker.group(1), f"compose: x-haertung without `{noetig}`"
_dienste = re.search(r"^services:\n(.*?)^\S", "\n".join(_cz) + "\nENDE", re.M | re.S).group(1)
_namen = re.findall(r"^  ([a-z0-9_-]+):\s*$", _dienste, re.M)
_bloecke = re.split(r"^  [a-z0-9_-]+:\s*$", _dienste, flags=re.M)[1:]
assert len(_namen) == len(_bloecke) >= 2, _namen
for name, block in zip(_namen, _bloecke):
    assert "<<: *haertung" in block, f"compose: service `{name}` without hardening (<<: *haertung)"
    assert "cap_add" not in block or re.search(r"cap_add: \[NET_BIND_SERVICE\]", block), \
        f"compose: service `{name}` takes back more than NET_BIND_SERVICE"
print(f"  Reference stack: {len(_bilder)} images pinned, {len(_namen)} services hardened")

# B4-10 — SECURITY.md names a path everyone can reach, and deadlines that can be measured.
from web.site import OWNER as _OWNER  # noqa: E402
for _sec in ("SECURITY.md", "i18n/SECURITY.de.md"):
    _t = read(_sec)
    assert "security/advisories/new" in _t, f"{_sec}: no direct link to the private report"
    assert _OWNER["email"] in _t, f"{_sec}: no email as a path without a GitHub account ({_OWNER['email']})"
    _fristen = re.findall(r"\*\*(\d+) (?:days|Tage)\*\*", _t)
    assert len(_fristen) >= 3, f"{_sec}: no measurable deadlines (found: {_fristen})"
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
_alle_wf = {wf: "\n".join(_code(read(wf))) for wf in WORKFLOWS}
# Dangerous-Workflow: no trigger that runs foreign code with privileges; no expression from the
# event in a shell step or an `actions/github-script` `script:` (script injection
# via titles, branch names, comments). EVERY `${{ … }}` expression that touches the event is
# checked — also inside a function: Until the re-check (A-7) the guard only saw
# `${{ github.event… }}` directly, `${{ toJSON(github.event…) }}` or `format('{0}', github.head_ref)`
# went through.
_EREIGNIS = re.compile(r"\bgithub\s*(?:\.\s*|\[\s*['\"])(?:event|head_ref)\b")
for wf, t in _alle_wf.items():
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
        _fremd = [u for u in re.findall(r"^\s+(?:- )?uses:\s*(\S+)", t, re.M)
                  if not re.fullmatch(r"actions/create-github-app-token@[0-9a-f]{40}", u)]
        assert not _fremd, \
            f"{wf}: `workflow_run` with an action {_fremd} — API only, never code from the PR (Scorecard Dangerous-Workflow)"
    for k in _kommandos(t.splitlines(), ("run", "script")):
        for ausdruck in re.findall(r"\$\{\{(.*?)\}\}", k):
            assert not _EREIGNIS.search(ausdruck), \
                f"{wf}: event expression in shell/script step (script injection): {k}"
_scorecard["Dangerous-Workflow"] = True
# Token-Permissions: every workflow sets `permissions:` at the top and nothing with write there (checked above).
_scorecard["Token-Permissions"] = all(re.search(r"^permissions:", t, re.M) for t in _alle_wf.values())
assert _scorecard["Token-Permissions"], "a workflow without `permissions:` at the top level"
# Pinned-Dependencies (the part that is achieved): actions by SHA (above), base image by digest.
_scorecard["Pinned-Dependencies"] = all("@sha256:" in z for z in dockerfile.splitlines() if z.startswith("FROM "))
assert _scorecard["Pinned-Dependencies"], "Dockerfile: FROM without digest"
# SAST: CodeQL on PRs and main.
_codeql = _alle_wf.get(".github/workflows/codeql.yml", "")
_scorecard["SAST"] = "github/codeql-action/analyze" in _codeql and "pull_request:" in _codeql and "push:" in _codeql
assert _scorecard["SAST"], "CodeQL no longer runs on PRs and main (Scorecard SAST)"
# Security-Policy, License, Dependency-Update-Tool, CI-Tests.
_scorecard["Security-Policy"] = "SECURITY.md" in FILES
_scorecard["License"] = "LICENSE" in FILES
_scorecard["Dependency-Update-Tool"] = ".github/dependabot.yml" in FILES
_scorecard["CI-Tests"] = "pull_request:" in _alle_wf[".github/workflows/ci.yml"]
# Binary-Artifacts: no executable binary files in the repo.
_bin = [f for f in FILES if f.endswith((".exe", ".dll", ".so", ".dylib", ".jar", ".class", ".pyc", ".whl", ".egg"))]
_scorecard["Binary-Artifacts"] = not _bin
_verloren = sorted(k for k, v in _scorecard.items() if not v)
assert not _verloren, f"Scorecard criteria lost: {_verloren} (binary files: {_bin[:3]})"
print(f"  Scorecard: {len(_scorecard)} achieved criteria guarded ({', '.join(sorted(_scorecard))})")

# ---------- The release script only replaces pins, not history ----------
# Until 0.20.0 `scripts/_release.py` replaced every occurrence of the old version — and thereby rewrote
# "0.19.0 raised to schema 8" and "until 0.19.0 one ended up in the same account" to the new version.
# (Mutation probe: in `ersetze_pins` `text.replace(alt, neu)` again → red.)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import _release  # noqa: E402
_probe = ("x@v0.19.0\ntinysesam:v0.19.0\n/v0.19.0/tinysesam-0.19.0-py3\n==0.19.0\n"
          'version = "0.19.0"\n__version__ = "0.19.0"\nBis 0.19.0 galt\n0.19.0 took it\nv0.19.01')
_neu, _n = _release.ersetze_pins(_probe, "0.19.0", "0.20.0")
assert _n == 7 and "Bis 0.19.0 galt" in _neu and "0.19.0 took it" in _neu and "v0.19.01" in _neu, (_n, _neu)
print("  Release script replaces only pins (7 forms), narrative text stays")

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
verstoesse = backlog.alle_pruefungen(ROOT)
assert not verstoesse, "backlog violations:\n  " + "\n  ".join(verstoesse)

eintraege = backlog.lade(ROOT)
assert eintraege, "backlog/ is empty — it should contain at least one milestone"

# The index is generated: if it deviates, someone maintained it by hand
# or forgot to rebuild it.
import subprocess  # noqa: E402
_r = subprocess.run([sys.executable, "scripts/_backlog.py", "index", "--dry-run"],
                    cwd=ROOT, capture_output=True, text=True)
assert _r.returncode == 0, ("backlog/README.md is stale — "
                            "run `python3 scripts/_backlog.py index`")
print(f"  Backlog: {len(eintraege)} entries, structure clean, index current")

# ---------- Promised Python versions: measured, not claimed ----------
# A classifier is a promise to the user. Until 0.18.0 TinySesam promised 3.11 and 3.13,
# and the CI ran neither — the promise was never measured. Conversely a test died on 3.10
# on `tomllib` (only exists from 3.11), and because `ci-local` runs only ONE version, it
# only showed up in the GitHub matrix. This check catches both.
import re as _re  # noqa: E402

_lies = lambda *teile: pathlib.Path(ROOT, *teile).read_text(encoding="utf-8", errors="replace")
_pp = _lies("pyproject.toml")
versprochen = set(_re.findall(r"Programming Language :: Python :: (\d+\.\d+)", _pp))
_ci = _lies(".github", "workflows", "ci.yml")
_m = _re.search(r"python-version:\s*\[([^\]]+)\]", _ci)
gefahren = set(_re.findall(r"[\"']([\d.]+)[\"']", _m.group(1))) if _m else set()
fehlt = sorted(versprochen - gefahren, key=lambda v: [int(t) for t in v.split(".")])
assert not fehlt, ("classifiers promise Python " + ", ".join(fehlt) +
                   ", the CI matrix does not run them — either extend the matrix "
                   "or drop the classifier. An unmeasured commitment is a claim.")
print(f"  Python {', '.join(sorted(versprochen))} promised AND in the CI matrix")

# Standard-library names that do not exist yet in the oldest promised version.
# The import is often in the middle of a file and never shows up locally.
ZU_NEU = {"tomllib": (3, 11), "typing.Self": (3, 11), "datetime.UTC": (3, 11),
          "itertools.batched": (3, 12), "typing.override": (3, 12)}
_min = tuple(int(t) for t in min(versprochen, key=lambda v: [int(t) for t in v.split(".")]).split("."))
zu_neu = []
for pfad in FILES:
    if not pfad.endswith(".py"):
        continue
    text = _lies(pfad)
    for name, ab in ZU_NEU.items():
        if ab <= _min:
            continue
        kurz = name.split(".")[-1]
        if _re.search(rf"^\s*import {_re.escape(name)}\b", text, _re.M) or \
           _re.search(rf"^\s*from {_re.escape(name.rsplit('.', 1)[0])} import .*\b{kurz}\b", text, _re.M):
            zu_neu.append(f"{pfad}: {name} gibt es erst ab Python {ab[0]}.{ab[1]}")
assert not zu_neu, ("Promised from Python %d.%d onwards:\n  " % _min) + "\n  ".join(zu_neu)
print(f"  no standard library beyond Python {_min[0]}.{_min[1]} ({len(ZU_NEU)} patterns)")

# ---------- README.md is also the PyPI description ----------
# Nothing resolves relative repo paths there: Until 0.18.0 the logo and
# seven links were dead on the package page — the first page a prospect sees. The German version under
# i18n/ is read only on GitHub and may stay relative.
_readme = _lies("pyproject.toml")
assert 'readme = "README.md"' in _readme, ("pyproject no longer points to README.md — "
                                           "this check then belongs on the other file")
_r = _lies("README.md")
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
_konf = _lies("CONFIGURATION.md")
# B3-15: Descriptions slipped. The indented continuation of a trailing comment ended up
# at the NEXT field — `login_identifier` began with the text of `https_mode`, `admin_identifiers`
# broke off mid-sentence. Measured on three fields that have exactly this form, and on the
# `#:` form whose colon used to stand in the text.
def _zeile(feld):
    return next(z for z in _konf.splitlines() if z.startswith(f"| `{feld}` "))
assert "warn = also runs WITHOUT a certificate" in _zeile("https_mode"), _zeile("https_mode")
assert "warn =" not in _zeile("login_identifier") and "What do people sign in with?" in _zeile("login_identifier"), \
    _zeile("login_identifier")
assert "AS LONG AS there is no admin" in _zeile("admin_identifiers"), _zeile("admin_identifiers")
assert "ONLY as an additional factor" in _zeile("pin_login"), _zeile("pin_login")
assert not _re.search(r"\| : ", _konf), "`#:` colon is still in the text"
_stumm = _re.findall(r"^\| `([a-z0-9_]+)` .* \| — \|$", _konf, _re.M)
assert not _stumm, ("these config fields have no explanatory comment in config.py:\n  " +
                    "\n  ".join(_stumm[:8]) +
                    "\n  (write a comment after the field, then regenerate.)")
# Character class with digits: `saml_idp_x509cert` otherwise slipped through, and the test
# reported 118 instead of 119 — a regex that almost fits counts wrongly instead of not at all.
_zahl = len(_re.findall(r"^\| `[a-z0-9_]+` \|", _konf, _re.M))
from dataclasses import fields as _dc_fields  # noqa: E402
import sys as _sys2  # noqa: E402
_sys2.path.insert(0, ROOT)
from tinysesam import TinySesamConfig as _TSC  # noqa: E402
assert _zahl == len(_dc_fields(_TSC)), (f"CONFIGURATION.md lists {_zahl} fields, "
                                        f"TinySesamConfig has {len(_dc_fields(_TSC))}")
# The tier (0.22.0): Almost every field is A; whoever deviates enters it in their line — otherwise
# someone would read the tombstone `totp_required` as a commitment until 1.0.
import json as _json_k  # noqa: E402
_feldstufen = {n: e.get("stufe") for n, e in
               _json_k.loads(_lies("tests/api_surface.json"))["TinySesamConfig.felder"].items()}
_nicht_a = sorted(n for n, st in _feldstufen.items() if st != "A")
assert _nicht_a, "no field outside tier A — `totp_required` is B (PO decision 2026-09-26)"
for _feld in _nicht_a:
    assert f"**Tier {_feldstufen[_feld]}.**" in _zeile(_feld), _zeile(_feld)
print(f"  Configuration reference: {_zahl} fields, each explained, dump current, "
      f"{len(_nicht_a)} marked outside tier A")

# ---------- API reference: every frozen method explained, dump current ----------
# 68 of the 105 frozen methods appeared in no docs. Whoever embeds TinySesam saw a
# commitment ("this surface stays stable") without a place that says what it contains.
_api = subprocess.run([sys.executable, "scripts/_api_docs.py", "--dry-run"],
                      cwd=ROOT, capture_output=True, text=True)
assert _api.returncode == 0, ("API.md is stale or the generator rejects something — "
                              "run `python3 scripts/_api_docs.py`\n" + _api.stderr[-400:])
_apidoc = _lies("API.md")
# Methods `### \`name(…)\``, properties `### \`name\` — Property …` (frozen since 0.20.1),
# since 0.22.0 also the constants (`— Constant`, explanation from the `#:` block above), the
# methods of TinySesamConfig and the function exports: With the tiering they stand as a
# commitment (A) or building block (B) — without an explanation they would be a commitment into the blue. Likewise the
# methods and constants of the result types `LoginResult` and `PasswordChangeResult` (0.22.0); their
# fields are checked by the generator.
_leer = _re.findall(r"^### `((?:TinySesamConfig\.|tinysesam\.|LoginResult\.|PasswordChangeResult\.)?"
                    r"[A-Za-z_][A-Za-z0-9_]*)"
                    r"(?:\(|` — Property|` — Constant).*\n\n—$", _apidoc, _re.M)
assert not _leer, ("these names have no docstring or `#:` comment:\n  " +
                   "\n  ".join(_leer[:8]) +
                   "\n  (a frozen method without explanation is a commitment into the blue.)")
# Structured by tier (PO decision 2026-09-26): A and B with explanation, C as a table of old
# name → replacement (since 0.22.0 every C name warns; whoever sees the warning looks here for the replacement).
for _kopf in ("## A · Methods of `TinySesam`", "## B · Methods of `TinySesam`",
              "## A · Result of the sign-in building blocks: `tinysesam.LoginResult`",
              "## A · Result of the password change: `tinysesam.PasswordChangeResult`",
              "## C · Deprecated — removed with 1.0"):
    assert _kopf in _apidoc, f"API.md without section {_kopf!r} — structure by tier is missing"
_c_zeilen = _re.findall(r"^\| `(\w+)` \| (?:Method|Constant) \| (.+) \|$", _apidoc, _re.M)
_c_namen = sorted(n for _b, _ee in _json_k.loads(_lies("tests/api_surface.json")).items()
                  for n, _e in _ee.items() if isinstance(_e, dict) and _e.get("stufe") == "C")
assert sorted(n for n, _ in _c_zeilen) == _c_namen, (
    "API.md: the table „Deprecated“ does not match the C names of the baseline")
assert all(_e.strip() and not _e.startswith("—") for _, _e in _c_zeilen), (
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

_readmes = {"README.md": _lies("README.md"), "i18n/README.de.md": _lies("i18n/README.de.md")}

_soll_tests = len(_glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
for _datei, _text in _readmes.items():
    _genannt = {int(n) for n in _re.findall(r"\*?\*?(\d+)\*?\*? (?:test files|Testdateien)", _text)}
    assert _genannt, f"{_datei} no longer names a test file count — adjust pattern in the guard"
    assert _genannt == {_soll_tests}, (
        f"{_datei} names {sorted(_genannt)} test files, there are {_soll_tests}")
print(f"  READMEs: test file count correct ({_soll_tests})")

# The Python matrix: the READMEs name a range, ci.yml the list. Both must mean the same.
_ci = _lies(".github/workflows/ci.yml")
_matrix = _re.search(r'python-version:\s*\[([^\]]+)\]', _ci)
assert _matrix, "python-version matrix in ci.yml not found"
_versionen = _re.findall(r'"([\d.]+)"', _matrix.group(1))
_spanne = f"{_versionen[0]}–{_versionen[-1]}"
for _datei, _text in _readmes.items():
    _gefunden = _re.findall(r"Python (\d+\.\d+[–-]\d+\.\d+)", _text)
    assert _gefunden, f"{_datei} no longer names a Python range — adjust pattern in the guard"
    assert set(_gefunden) == {_spanne}, (
        f"{_datei} names Python {sorted(set(_gefunden))}, the CI runs {_spanne}")
print(f"  READMEs: Python range correct ({_spanne})")

# ---------- The tiers of the public API are in both READMEs (0.22.0) ----------
# PO decision 2026-09-26: B is "öffentlich für Fortgeschrittene" with its own docs section.
# A B building block that no README names is a commitment nobody knows about — exactly the
# state the tiering was meant to end (68 of 105 methods stood nowhere). The list
# comes from the guard's baseline, not from this test: A new B name turns it red until
# it is in both READMEs. The fields are listed completely in CONFIGURATION.md.
import json as _json  # noqa: E402
_ablage = _json.loads(_lies("tests/api_surface.json"))
_stufe_b = sorted({n for _bereich, _eintraege in _ablage.items() if _bereich != "TinySesamConfig.felder"
                   for n, _e in _eintraege.items() if isinstance(_e, dict) and _e.get("stufe") == "B"})
assert len(_stufe_b) >= 50, f"only {len(_stufe_b)} B names in tests/api_surface.json — baseline broken?"
for _datei, _kopf in (("README.md", "### For advanced use (tier B)"),
                      ("i18n/README.de.md", "### Für Fortgeschrittene (Stufe B)")):
    _text = _readmes[_datei]
    assert _kopf in _text, f"{_datei}: section {_kopf!r} missing"
    _abschnitt = _text.split(_kopf, 1)[1].split("\n## ", 1)[0]
    _fehlt = [n for n in _stufe_b if not _re.search(rf"`[^`\n]*\b{_re.escape(n)}\b[^`\n]*`", _abschnitt)]
    assert not _fehlt, (f"{_datei}: These B building blocks are missing in section {_kopf!r}:\n  " +
                        "\n  ".join(_fehlt))
        # What consumers use but that was in no README until 0.21.0 (tier A).
    for _name in ("create_user", "has_role", "current_user", "session_cookie_name",
                  "dataclasses.fields(TinySesamConfig)"):
        assert _name in _text, f"{_datei} does not document {_name}"
print(f"  READMEs: all {len(_stufe_b)} B building blocks in the section for advanced users, "
      "the used A names documented")

# ---------- The installation leads with the pinned PyPI path ----------
# Until 2026-09-27 this guard forbade every PyPI line ("only from 1.0") — by then TinySesam had been
# there since 0.19.0: According to ADR-6 every tag goes to PyPI via Trusted Publishing. The guard thereby
# held the wrong statement fast, and both READMEs sent everyone on the detour via Git. Now:
# Both lead with `pip install "tinysesam==<version>"` (scripts/_release.py sets the version too),
# no line installs unpinned, and no sentence claims the package is missing from PyPI.
from tinysesam import __version__ as _ver  # noqa: E402
for _datei, _text in _readmes.items():
    assert f'pip install "tinysesam=={_ver}"' in _text, (
        f'{_datei} does not show the pinned PyPI installation (pip install "tinysesam=={_ver}")')
    _ungepinnt = [z.strip() for z in _text.splitlines()
                  if _re.match(r'^\s*pip install ["\']?tinysesam[\[\]a-z,]*["\']?\s*(#.*)?$', z)]
    assert not _ungepinnt, f"{_datei} installs unpinned:\n  " + "\n  ".join(_ungepinnt)
    _falsch = _re.search(r"not on PyPI|nicht auf PyPI|noch nicht auf PyPI", _text, _re.I)
    assert not _falsch, f"{_datei} claims TinySesam is missing from PyPI: {_falsch.group(0)!r}"
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

_EXTRA_MODUL = {"passkey_enabled": ("webauthn", "passkey"), "oidc_enabled": ("authlib", "oidc"),
                "saml_enabled": ("onelogin", "saml"), "ldap_enabled": ("ldap3", "ldap")}


def _py_bloecke(text):
    return _re.findall(r"```python\n(.*?)```", text, _re.S)


def _config_aufrufe(text):
    """One `TinySesamConfig(…)` call as source text — via bracket depth, not via regex."""
    for m in _re.finditer(r"TinySesamConfig\(", text):
        tiefe = 0
        for j in range(m.end() - 1, len(text)):
            if text[j] == "(":
                tiefe += 1
            elif text[j] == ")":
                tiefe -= 1
                if tiefe == 0:
                    yield text[m.start():j + 1]
                    break


_seclog = _log.getLogger("tinysesam.security")
_vorher = _seclog.level
_seclog.setLevel(_log.CRITICAL)          # the build warns about missing extras — only noise here
_gebaut = 0
try:
    for _datei, _text in _readmes.items():
        for _nr, _block in enumerate(_py_bloecke(_text), 1):
            for _quelle in _config_aufrufe(_block):
                try:
                    _cfg = eval(_quelle, {"TinySesamConfig": TinySesamConfig})   # noqa: S307
                except Exception as _e:
                    raise AssertionError(
                        f"{_datei}, Block {_nr}: `{_quelle.splitlines()[0]}…` cannot even be "
                        f"evaluated — {type(_e).__name__}: {_e}")
                _cfg.db_path = os.path.join(_tmp.mkdtemp(), "beispiel.db")
                try:
                    with _cl.redirect_stderr(_io.StringIO()):     # first-admin token to the operator
                        TinySesam(_cfg)
                except _CfgErr as _e:
                    raise AssertionError(
                        f"{_datei}, Block {_nr}: the example does not build.\n  {_quelle[:90]}…\n  "
                        f"ConfigError: {str(_e)[:300]}\n  (Whoever copies it does not get past the "
                        f"first line — like the `pip install` above.)")
                _gebaut += 1
finally:
    _seclog.setLevel(_vorher)
assert _gebaut >= 12, f"only {_gebaut} config examples found — adjust pattern in the guard"
print(f"  READMEs: all {_gebaut} config examples build (ConfigError-free)")

# Stage 2 — actually run the complete blocks.
_ausgefuehrt, _uebersprungen = 0, []
for _datei, _text in _readmes.items():
    for _nr, _block in enumerate(_py_bloecke(_text), 1):
        if "from tinysesam import" not in _block and "import tinysesam" not in _block:
            continue                      # a snippet, not a program
        _fehlt = [f"[{_x}] ({_m})" for _s, (_m, _x) in _EXTRA_MODUL.items()
                  if f"{_s}=True" in _block and _ilu.find_spec(_m) is None]
        if _fehlt:
            _uebersprungen.append(f"{_datei} Block {_nr}: " + ", ".join(_fehlt))
            continue
        _wo = _tmp.mkdtemp()
        _skript = os.path.join(_wo, "beispiel.py")
        with open(_skript, "w", encoding="utf-8") as _fh:
            _fh.write(_block)
        _umg = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        _lauf = _sp.run([sys.executable, _skript], cwd=_wo, env=_umg,
                        capture_output=True, text=True, timeout=120)
        assert _lauf.returncode == 0, (
            f"{_datei}, block {_nr} does not run through (exit {_lauf.returncode}):\n"
            + (_lauf.stderr or _lauf.stdout)[-900:])
        _ausgefuehrt += 1
assert _ausgefuehrt + len(_uebersprungen) >= 2, "the READMEs no longer contain two complete examples"
if _uebersprungen:
        # No silent waving through: Stage 1 built the same configs, only `auth.router()` is missing.
    print("  (block not run, extra missing: " + "; ".join(_uebersprungen) + ")")
else:
    assert _ausgefuehrt >= 2, f"only {_ausgefuehrt} complete examples — adjust pattern"
print(f"  READMEs: {_ausgefuehrt} complete examples run through in the throwaway directory")

# Kit 0.22.0 (M-1, stage 3): Has every check before it SEEN something? A check over an
# empty set is always green. Must run LAST, it evaluates the case counts before it.
ungesehen = hygiene.pruefe_etwas_gesehen()
assert not ungesehen, "kit check without case:\n  " + "\n  ".join(ungesehen)
print("  Kit 0.22.0: every check has seen something")

print("OK test_repo")

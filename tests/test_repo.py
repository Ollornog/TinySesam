"""Repo-Hygiene: was ein Fremder sieht, wenn er das Projekt öffnet.

Prüft, was man beim Aufräumen zuverlässig vergisst — Versionen, die auseinanderlaufen; Reste im
Repo; Geheimnisse; vergessene Debug-Ausgaben; Suiten, die niemand mehr ausführt. Kein Netz, keine
Abhängigkeiten, läuft überall.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def tracked() -> list:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.split()


FILES = tracked()
LIB = [f for f in FILES if f.startswith("tinysesam/") and f.endswith(".py")]
WEB = [f for f in FILES if f.startswith("web/") and f.endswith(".py")]

# ---------- Version: pyproject, __init__ und der letzte Tag müssen zusammenpassen ----------
pv = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M).group(1)
iv = re.search(r'^__version__ = "([^"]+)"', read("tinysesam/__init__.py"), re.M).group(1)
assert pv == iv, f"pyproject={pv} aber __init__={iv}"
assert re.fullmatch(r"\d+\.\d+\.\d+", pv), pv
assert f"## [{pv}]" in read("CHANGELOG.md"), f"CHANGELOG kennt {pv} nicht"
print(f"  Version {pv}: pyproject = __init__ = CHANGELOG")

# ---------- Pflichtdateien ----------
for name in ("LICENSE", "SECURITY.md", "CHANGELOG.md", "README.md", "README.de.md",
             "TODO.md", "tinysesam/py.typed", ".gitignore",
             ".github/workflows/ci.yml", ".github/workflows/pages.yml"):
    assert name in FILES, f"{name} fehlt im Repo"
print("  Lizenz, SECURITY, CHANGELOG, beide READMEs, py.typed, beide Workflows vorhanden")

# ---------- docs/ enthält nur noch Beilagen; die Seiten baut die Action ----------
docs = [f for f in FILES if f.startswith("docs/")]
assert sorted(docs) == ["docs/.nojekyll", "docs/theme.css", "docs/wizard.png"], docs
assert not any(f.endswith(".html") for f in FILES), "generiertes HTML gehört nicht ins Repo"
assert "_site/" in read(".gitignore")
print("  docs/: nur theme.css, wizard.png, .nojekyll — kein generiertes HTML im Repo")

# ---------- Farbwerte nur an den zwei erlaubten Stellen ----------
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
allowed = {"tinysesam/theme.py"}
for f in LIB:
    if f in allowed:
        continue
    for line in read(f).splitlines():
        if HEX.search(line) and "#fff" not in line:
            raise AssertionError(f"Farbwert außerhalb theme.py: {f}: {line.strip()[:70]}")
print("  Farbwerte: nur in tinysesam/theme.py (App) bzw. docs/theme.css (Website)")

# ---------- Keine vergessenen Debug-Ausgaben in der Bibliothek ----------
# __main__.py ist die CLI — dort ist print die Ausgabe, kein Überbleibsel.
for f in LIB:
    if f == "tinysesam/__main__.py":
        continue
    for n, line in enumerate(read(f).splitlines(), 1):
        s = line.strip()
        if s.startswith("print(") or s.startswith("breakpoint("):
            raise AssertionError(f"Debug-Ausgabe in der Bibliothek: {f}:{n}: {s[:60]}")
print("  keine print()/breakpoint() in tinysesam/")

# ---------- Keine offensichtlichen Geheimnisse ----------
SECRETS = (re.compile(r"ghp_[A-Za-z0-9]{20,}"),          # GitHub-Token
           re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY"),
           re.compile(r"AKIA[0-9A-Z]{16}"))              # AWS
for f in FILES:
    if f.endswith((".png", ".ico")):
        continue
    try:
        body = read(f)
    except (UnicodeDecodeError, IsADirectoryError):
        continue
    for pat in SECRETS:
        assert not pat.search(body), f"möglicher Schlüssel in {f}"
print("  keine Tokens oder privaten Schlüssel eingecheckt")

# ---------- Jede Suite läuft im Sammellauf mit ----------
suites = sorted(f for f in FILES if f.startswith("tests/test_") and f.endswith(".py"))
assert len(suites) >= 30, len(suites)
runner = read("tests", "run_all.py")
assert 'glob.glob(os.path.join(HERE, "test_*.py"))' in runner, "run_all sammelt nicht mehr automatisch"
print(f"  {len(suites)} Suiten, alle vom Sammellauf erfasst")

# ---------- Der Website-Generator schreibt genau das, was die Action deployt ----------
action = read(".github", "workflows", "pages.yml")
assert "python -m web.build _site" in action
assert "upload-pages-artifact" in action and "path: _site" in action
print("  pages.yml baut web/ und lädt _site hoch")

# ---------- Kein Sprach-Dateiname mehr, kein zweites System ----------
for f in WEB + [x for x in FILES if x.startswith("examples/")]:
    body = read(f)
    assert ".de.html" not in body, f"Sprach-Dateiname in {f}"
print("  ein Sprachsystem: nirgends ein `.de.html`")

# ---------- Impressum vollständig ----------
sys.path.insert(0, ROOT)
from web.site import OWNER, SITE_URL   # noqa: E402

for key in ("name", "street", "city", "country", "email"):
    v = OWNER[key]
    assert v and not v.startswith("«"), f"OWNER[{key}] ist ein Platzhalter"
assert "@" in OWNER["email"] and SITE_URL
print("  Impressum: alle Pflichtangaben gesetzt")

print("OK test_repo")

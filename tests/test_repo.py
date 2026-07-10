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
             ".github/workflows/ci.yml", ".github/workflows/pages.yml",
             ".github/workflows/release.yml"):
    assert name in FILES, f"{name} fehlt im Repo"
print("  Lizenz, SECURITY, CHANGELOG, beide READMEs, py.typed, alle Workflows vorhanden")

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

# ---------- Keine privaten Namen im öffentlichen Repo ----------
# Das Repo kann jeder lesen. Hostnamen, Kundennamen und Namen anderer Projekte des Autors
# gehören deshalb nicht hinein — weder in Code noch in Beispiele, Tests oder Kommentare.
# Konfiguriert wird über Umgebungsvariablen, nicht über Vorgabewerte im Quelltext.
#
# Vier Stellen dürfen echte Namen tragen, weil sie ohne sie sinnlos wären: LICENSE und
# pyproject.toml (Urheberschaft), der OWNER-Block in web/site.py (Impressumspflicht) — und
# diese Datei selbst, die die verbotene Wortliste ja enthalten muss.
PRIVATE = ("drog", "drog-tower", "specdoor", "brunpower", "paperlaiss", "hetz", "backmox",
           "loco", "rasbox", "drogbox", "ollornog")
# Die eigene Repo- und Pages-Adresse ist keine private Spur, sondern die Anschrift des Projekts.
PUBLIC_REFS = ("github.com/Ollornog/TinySesam", "Ollornog/TinySesam",
               "ollornog.github.io/TinySesam", "github-tinysesam")
NAME_EXEMPT = {"LICENSE", "pyproject.toml", "web/site.py", "tests/test_repo.py"}
hits = []
for f in FILES:
    if f in NAME_EXEMPT or f.endswith((".png", ".ico")):
        continue
    try:
        body = read(f)
    except (UnicodeDecodeError, IsADirectoryError):
        continue
    for n, line in enumerate(body.splitlines(), 1):
        for ref in PUBLIC_REFS:                      # erlaubte Adressen ausblenden …
            line = line.replace(ref, "")
        for word in PRIVATE:                         # … und erst dann suchen
            if re.search(rf"\b{re.escape(word)}\b", line, re.I):
                hits.append(f"{f}:{n}: {line.strip()[:70]}")
assert not hits, "private Namen im öffentlichen Repo:\n  " + "\n  ".join(hits[:8])
print(f"  keine privaten Namen ({len(PRIVATE)} Begriffe geprüft, {len(NAME_EXEMPT)} Ausnahmen)")

# ---------- Jeder gepinnte Beispiel-Tag zeigt auf die aktuelle Version ----------
# Sonst empfiehlt die Doku eine Version, die es nie gab: `pip install …@v0.11.0` bricht ab,
# weil der Tag nie gepusht wurde. Genau das stand hier — unbemerkt, weil niemand es nachbaut.
PIN = re.compile(r"TinySesam(?:\.git)?[@/](?:releases/download/)?v(\d+\.\d+\.\d+)")
for f in ("README.md", "README.de.md", "deploy/forward-auth/docker-compose.yml"):
    for found in PIN.findall(read(f)):
        assert found == pv, f"{f} pinnt v{found}, aktuell ist v{pv}"
print(f"  alle Beispiel-Pins zeigen auf v{pv}")

# ---------- Kein Selbst-Update: die Bibliothek lädt keinen Code nach ----------
# Wer das Admin-Panel übernimmt, könnte sonst auf eine alte, lückenhafte Version zurückschalten.
# Eine Auth-Bibliothek startet keine Prozesse. `sys.executable`/`subprocess` wären der Weg,
# auf dem ein Selbst-Update zurückkäme — deshalb hier die Grenze, nicht beim Wort „pip"
# (das steht harmlos in Docstrings, die Installationshinweise geben).
for f in LIB:
    body = read(f)
    assert "self_update" not in body, f"Selbst-Update wieder eingebaut: {f}"
    assert "sys.executable" not in body, f"{f} startet einen Interpreter"
    assert not re.search(r"^\s*import subprocess|\bsubprocess\.\w+\(", body, re.M), \
        f"{f} startet einen Prozess"
print("  kein Selbst-Update, kein Prozessstart in der Bibliothek")

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

# ---------- Die Automatik selbst: Skripte, Hook, CI-Jobs ----------
for f in ("scripts/check.sh", ".githooks/pre-push"):
    assert f in FILES, f"{f} fehlt — ohne das Tor läuft niemand die Suite"
    assert os.access(os.path.join(ROOT, f), os.X_OK), f"{f} ist nicht ausführbar"

hook = read(".githooks", "pre-push")
assert "scripts/check.sh" in hook, "der Hook muss die Suite fahren"

check = read("scripts", "check.sh")
assert "tests/run_all.py" in check and "web.build" in check

ci = read(".github", "workflows", "ci.yml")
for needed in ("tests/test_browser.py", "tests/test_repo.py", "tests/test_site.py",
               "python -m web.build", "setup-chrome"):
    assert needed in ci, f"CI fährt {needed} nicht"

# Öffentliches Repo → niemals self-hosted Runner: ein Fork-PR liefe sonst auf fremder Hardware.
for wf in (f for f in FILES if f.startswith(".github/workflows/")):
    assert "self-hosted" not in read(wf), f"{wf} nutzt einen self-hosted Runner"

rel = read(".github", "workflows", "release.yml")
assert "tags:" in rel and "sha256sum" in rel, "Release baut keine Prüfsummen"
print("  check.sh + pre-push da; CI fährt Browser-, Hygiene- und Website-Test; Release signiert Prüfsummen")

# ---------- Doku wandert mit: der Changelog kennt den aktuellen Stand ----------
changelog = read("CHANGELOG.md")
assert "## [Unreleased]" in changelog or f"## [{pv}]" in changelog
for readme in ("README.md", "README.de.md"):
    body = read(readme)
    assert "tests/test_browser.py" in body, f"{readme} erklärt den Browser-Test nicht"
    assert "tests/test_repo.py" in body, f"{readme} erklärt den Hygiene-Test nicht"
print("  beide READMEs erklären Browser- und Hygiene-Test; CHANGELOG gepflegt")

print("OK test_repo")

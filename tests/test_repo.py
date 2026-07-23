"""Repo-Hygiene: was ein Fremder sieht, wenn er das Projekt öffnet.

Prüft, was man beim Aufräumen zuverlässig vergisst — Versionen, die auseinanderlaufen; Reste im
Repo; Geheimnisse; vergessene Debug-Ausgaben; Suiten, die niemand mehr ausführt. Kein Netz, keine
Abhängigkeiten, läuft überall.

Die allgemeinen Prüfungen und die Sperrlisten stehen in `tests/_kit/` — einer geteilten,
eingecheckten Basis, die `repokit sync` hierher schreibt. Sie ist stdlib-only und lädt zur
Testzeit nichts nach; die Zusage oben bleibt wörtlich wahr. Was hier steht, ist das, was
nur für dieses Projekt gilt.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import backlog, hygiene  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = hygiene.lade_policy()
PROJEKTE = ["TinySesam"]


def read(*parts) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


FILES = hygiene.getrackte_dateien(ROOT)
LIB = [f for f in FILES if f.startswith("tinysesam/") and f.endswith(".py")]
WEB = [f for f in FILES if f.startswith("web/") and f.endswith(".py")]

# ---------- Version: pyproject, __init__ und CHANGELOG müssen zusammenpassen ----------
pv = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M).group(1)
fehler = hygiene.pruefe_versionsgleichstand(
    ROOT, weitere={"tinysesam/__init__.py": r'^__version__ = "([^"]+)"'})
assert not fehler, fehler
print(f"  Version {pv}: pyproject = __init__ = CHANGELOG")

# ---------- Pflichtdateien ----------
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
assert not fehlend, f"Pflichtdateien fehlen: {fehlend}"
print("  Lizenz, SECURITY, CHANGELOG, beide READMEs, py.typed, alle Workflows vorhanden")

# ---------- docs/ enthält nur noch Beilagen; die Seiten baut die Action ----------
docs = [f for f in FILES if f.startswith("docs/")]
assert sorted(docs) == ["docs/.nojekyll", "docs/theme.css", "docs/wizard.png"], docs
assert not any(f.endswith(".html") for f in FILES), "generiertes HTML gehört nicht ins Repo"
assert "_site/" in read(".gitignore")
print("  docs/: nur theme.css, wizard.png, .nojekyll — kein generiertes HTML im Repo")

# ---------- Generierte Artefakte gehören nicht ins Repo ----------
artefakte = hygiene.pruefe_artefakte(FILES, POLICY)
assert not artefakte, f"generierte Artefakte sind versioniert: {artefakte[:5]}"
print(f"  keine generierten Artefakte unter {len(FILES)} getrackten Dateien")

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
lecks = hygiene.pruefe_geheimnisse(ROOT, FILES, POLICY)
assert not lecks, f"möglicher Schlüssel in {lecks[:3]}"
print("  keine Tokens oder privaten Schlüssel eingecheckt")

# ---------- Jede Suite läuft im Sammellauf mit ----------
suites = sorted(f for f in FILES if f.startswith("tests/test_") and f.endswith(".py"))
assert len(suites) >= 30, len(suites)
runner = read("tests", "run_all.py")
assert 'glob.glob(os.path.join(HERE, "test_*.py"))' in runner, "run_all sammelt nicht mehr automatisch"
print(f"  {len(suites)} Suiten, alle vom Sammellauf erfasst")

# ---------- Keine private Infrastruktur im öffentlichen Repo ----------
# Die Trennlinie ist **Identität gegen Infrastruktur**, nicht „mein Name kommt vor".
# Erlaubt und teils rechtlich nötig: Autor, Impressumsadresse, Lizenz, Repo-URL,
# Projektname. Verboten ist, was jemandem hilft, die Systeme dahinter zu finden.
#
# Muster und Sperrliste stehen in tests/_kit/hygiene_policy.json — einer Quelle für alle
# Repos. Vorher trug jedes Repo seine eigene Kopie, und sie liefen auseinander: diese hier
# kannte sieben Namen, das Schwesterprojekt dreizehn, und die IP-Muster hatten in nur einem
# der beiden die Ausnahme für CIDR-Masken in der Doku.
hits = hygiene.pruefe_private_infrastruktur(ROOT, FILES, POLICY, PROJEKTE)
assert not hits, "private Infrastruktur im öffentlichen Repo:\n  " + "\n  ".join(hits[:8])
print(f"  keine private Infrastruktur ({len(POLICY['private_muster'])} Muster"
      f" + {len(POLICY['private_namen_sha256_16'])} Namen)")

# ---------- Belegte Standards, maschinell erzwungen (context/repo-standards.md) ----------
# Ein Tag lässt sich verschieben; ein Commit-SHA ist die einzige unveränderliche Referenz.
ungepinnt = hygiene.pruefe_actions_sha_gepinnt(ROOT, FILES)
assert not ungepinnt, "Actions nicht auf Commit-SHA gepinnt:\n  " + "\n  ".join(ungepinnt)

# Es gibt keinen sicheren Default: die Ausgangsberechtigung kommt aus der Repo-Einstellung.
ohne_rechte = hygiene.pruefe_workflow_permissions(ROOT, FILES)
assert not ohne_rechte, "Workflow ohne `permissions:`:\n  " + "\n  ".join(ohne_rechte)
print(f"  alle Actions per Commit-SHA gepinnt, jeder Workflow setzt `permissions:`")

# Keep a Changelog 1.1.0 — fester Satz Kategorien, eine Sprache je Repo.
kategorien = hygiene.pruefe_changelog_kategorien(ROOT, POLICY)
assert not kategorien, "CHANGELOG:\n  " + "\n  ".join(kategorien[:5])

# GitHub wählt die README nach ORT aus, nicht nach Sprache — eine Übersetzung veraltet still.
# Die Übersetzungen liegen unter i18n/, damit GitHubs Health-File-Detektor (CODE_OF_CONDUCT,
# SECURITY, …) die englischen Root-Dateien wählt und nicht die alphabetisch erste .de-Fassung.
uebersetzung = hygiene.pruefe_uebersetzungs_struktur(ROOT, [("README.md", "i18n/README.de.md")])
assert not uebersetzung, "Übersetzung weicht ab:\n  " + "\n  ".join(uebersetzung)
print("  CHANGELOG-Kategorien gültig; i18n/README.de.md folgt der Struktur von README.md")

# ---------- Jeder gepinnte Beispiel-Tag zeigt auf die aktuelle Version ----------
# Sonst empfiehlt die Doku still eine alte Version weiter: Der Pin im Compose und die
# `pip install`-Zeilen im README altern nicht mit, weil sie niemand ausführt.
PINS = (re.compile(r"TinySesam(?:\.git)?[@/](?:releases/download/)?v(\d+\.\d+\.\d+)"),  # Git-Tag, Wheel
        re.compile(r"tinysesam:v(\d+\.\d+\.\d+)"))                                     # Abbild-Tag
for f in ("README.md", "i18n/README.de.md", "deploy/forward-auth/docker-compose.yml"):
    body = read(f)
    for pat in PINS:
        for found in pat.findall(body):
            assert found == pv, f"{f} pinnt v{found}, aktuell ist v{pv}"
print(f"  alle Beispiel-Pins (Git-Tag, Wheel, Abbild) zeigen auf v{pv}")

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
assert "linux/amd64,linux/arm64" in rel, "Abbild ist nicht multi-arch"
assert ":latest" not in rel, "ein wandernder `latest`-Tag gehört nicht ins Release"
# Registries verlangen kleingeschriebene Namen; `github.repository_owner` liefert die
# Schreibweise des Kontos und brach den Build ab („repository name must be lowercase").
for line in rel.splitlines():
    if line.strip().startswith("tags:") and "ghcr.io" in line:
        assert "repository_owner" not in line, "Abbild-Tag nutzt die Groß-/Kleinschreibung des Kontos"

# Das Abbild darf keinen Weg zum Nachladen von Code enthalten — sonst käme das Selbst-Update
# durch die Hintertür zurück. Und es läuft nicht als root.
dockerfile = read("Dockerfile")
assert "USER tinysesam" in dockerfile, "Abbild läuft als root"
assert "HEALTHCHECK" in dockerfile, "Abbild ohne Health-Check"
for weg in ("/opt/venv/bin/pip", "/usr/local/bin/pip"):
    assert weg in dockerfile, f"{weg} wird nicht entfernt — das venv bringt ein eigenes pip mit"
print("  check.sh + pre-push da; CI fährt Browser-, Hygiene- und Website-Test; Release signiert Prüfsummen")

# ---------- Doku wandert mit: der Changelog kennt den aktuellen Stand ----------
changelog = read("CHANGELOG.md")
assert "## [Unreleased]" in changelog or f"## [{pv}]" in changelog
for readme in ("README.md", "i18n/README.de.md"):
    body = read(readme)
    assert "tests/test_browser.py" in body, f"{readme} erklärt den Browser-Test nicht"
    assert "tests/test_repo.py" in body, f"{readme} erklärt den Hygiene-Test nicht"
print("  beide READMEs erklären Browser- und Hygiene-Test; CHANGELOG gepflegt")

# ---------- Backlog: Struktur, Verweise, generierter Index ----------
# Der Backlog ist Teil des Repos, also prueft ihn die Suite wie jede andere Datei.
# Ein Backlog, der nur "meistens stimmt", wird nicht geglaubt und dann nicht gepflegt.
verstoesse = backlog.alle_pruefungen(ROOT)
assert not verstoesse, "Backlog-Verstoesse:\n  " + "\n  ".join(verstoesse)

eintraege = backlog.lade(ROOT)
assert eintraege, "backlog/ ist leer — mindestens ein Meilenstein gehoert hinein"

# Der Index ist generiert: weicht er ab, hat jemand ihn von Hand gepflegt
# oder vergessen, ihn neu zu bauen.
import subprocess  # noqa: E402
_r = subprocess.run([sys.executable, "scripts/_backlog.py", "index", "--dry-run"],
                    cwd=ROOT, capture_output=True, text=True)
assert _r.returncode == 0, ("backlog/README.md ist veraltet — "
                            "`python3 scripts/_backlog.py index` fahren")
print(f"  Backlog: {len(eintraege)} Eintraege, Struktur sauber, Index aktuell")

print("OK test_repo")

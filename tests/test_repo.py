"""Repo-Hygiene: was ein Fremder sieht, wenn er das Projekt öffnet.

Prüft, was man beim Aufräumen zuverlässig vergisst — Versionen, die auseinanderlaufen; Reste im
Repo; Geheimnisse; vergessene Debug-Ausgaben; Suiten, die niemand mehr ausführt. Kein Netz, keine
Abhängigkeiten, läuft überall.

Die allgemeinen Prüfungen und die Sperrlisten stehen in `tests/_kit/` — einer geteilten,
eingecheckten Basis, die `repokit sync` hierher schreibt. Sie ist stdlib-only und lädt zur
Testzeit nichts nach; die Zusage oben bleibt wörtlich wahr. Was hier steht, ist das, was
nur für dieses Projekt gilt.
"""

# Diese Suite liest den Repo-Zustand ueber git. Ohne git ist sie nicht aussagekraeftig —
# eine fehlende Voraussetzung, kein Fehlschlag.
import shutil  # noqa: E402
from voraussetzung import braucht  # noqa: E402
braucht(shutil.which("git"), "git fehlt")
# git im PATH genügt nicht: Gemessen wird gegen `git ls-files`, und das braucht ein
# Repo. Im ausgepackten sdist gibt es keins — dort absagen statt rot werden.
import pathlib  # noqa: E402

# `.exists()`, nicht `.is_dir()`: In einem git-worktree und in einem Submodul ist `.git`
# eine DATEI mit einem Verweis. Mit `.is_dir()` wand sich die gesamte Repo-Hygiene dort ab
# — private Infrastruktur, Geheimnisse, SHA-Pins, alles — und der Lauf meldete grün.
braucht((pathlib.Path(__file__).resolve().parent.parent / ".git").exists(),
        "kein Git-Repo (z.B. ausgepacktes sdist) — die Hygiene misst gegen `git ls-files`")
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
# Ausnahme: BETRIEB.md, die Betreiber-Doku (Ausfallverhalten, Sitzungen, Anmeldewege). Sie ist
# Quelltext wie API.md, keine gebaute Seite — die Pages-Action veröffentlicht docs/ nicht.
docs = [f for f in FILES if f.startswith("docs/")]
assert sorted(docs) == ["docs/.nojekyll", "docs/BETRIEB.md", "docs/theme.css", "docs/wizard.png"], docs
assert not any(f.endswith(".html") for f in FILES), "generiertes HTML gehört nicht ins Repo"
assert "_site/" in read(".gitignore")
print("  docs/: nur BETRIEB.md, theme.css, wizard.png, .nojekyll — kein generiertes HTML im Repo")

# ---------- docs/BETRIEB.md sagt, was der Code tut ----------
# Eine Betreiber-Doku, deren Zahlen vom Code wegwandern, ist schlimmer als keine: Man plant
# danach. Geprüft wird, was sich mechanisch ablesen lässt — die Wartezeit auf eine gesperrte
# Datenbank, der Healthcheck-Pfad und dass jeder identifizierende Faktor in der Tabelle der
# Anmeldewege steht (ein neuer Weg ohne Zeile dort wäre genau die Lücke aus B1-11).
betrieb = read("docs", "BETRIEB.md")
_store_src = read("tinysesam", "store.py")
_busy = int(re.search(r"^    BUSY_TIMEOUT_MS = ([\d_]+)", _store_src, re.M).group(1).replace("_", ""))
assert f"**{_busy // 1000} s**" in betrieb, f"BETRIEB.md nennt nicht die echte Wartezeit ({_busy} ms)"
assert re.search(r'^HEALTH_PATH = "/healthz"', read("tinysesam", "gateway.py"), re.M) and "/healthz" in betrieb
_ident = re.search(r"^    IDENTIFYING = \(([^)]*)\)", read("tinysesam", "manager.py"), re.M).group(1)
_faktoren = re.findall(r'"(\w+)"', _ident)
assert len(_faktoren) >= 6, f"IDENTIFYING nicht gelesen: {_faktoren}"
_fehlend = [f for f in _faktoren if f"(`{f}`" not in betrieb]
assert not _fehlend, f"BETRIEB.md: Anmeldeweg ohne Zeile in der Stärke-Tabelle: {_fehlend}"
print(f"  docs/BETRIEB.md: Wartezeit {_busy // 1000} s, /healthz und alle {len(_faktoren)} "
      "identifizierenden Faktoren stimmen mit dem Code")

# Der HEALTHCHECK des Abbilds muss länger warten als die Datenbank: `/healthz` schreibt und steht
# wie jede Anmeldung bis zu BUSY_TIMEOUT_MS hinter einem fremden Schreiber. Mit 4 s brach der
# Check bei einer 6-s-Sperre ab, obwohl der Dienst danach 200 lieferte (A-B6-4-healthz-sperre).
_df = read("Dockerfile")
_hc_docker = int(re.search(r"HEALTHCHECK [^\n]*--timeout=(\d+)s", _df).group(1))
_hc_client = int(re.search(r"HTTPConnection\(.*?timeout=(\d+)\)", _df).group(1))
assert _hc_client * 1000 > _busy, f"Health-Client wartet {_hc_client} s, die Datenbank bis {_busy} ms"
assert _hc_docker > _hc_client, f"Docker bricht nach {_hc_docker} s ab, vor dem Client ({_hc_client} s)"
print(f"  Dockerfile: HEALTHCHECK wartet {_hc_client} s/{_hc_docker} s, länger als busy_timeout")

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
# __main__.py ist die CLI — dort ist print die Ausgabe, kein Überbleibsel. In gateway.py gilt
# dasselbe, aber NUR für `main()`: Der Rest der Datei ist Bibliothek und darf nichts ausgeben.
# (Die Grenze steht hier, weil eine Ausnahme für die ganze Datei genau das durchgehen liesse,
# was die Prüfung sucht.)
#
# Gelesen wird der SYNTAXBAUM, nicht der Zeilentext: Ein `print(...)` in einem Docstring — etwa
# ein Beispiel, wie man einen Fehler abfängt — ist keine vergessene Debug-Ausgabe. Die
# Textsuche hielt eines für eine und schlug Alarm; ein Fehlalarm kostet dasselbe Vertrauen wie
# ein übersehener Fund.
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
# Gelesen wird der SYNTAXBAUM, nicht der Zeilentext. Die Textsuche kannte nur
# `import subprocess` und `subprocess.foo(` — `from subprocess import run` und `os.system(...)`
# gingen glatt durch, obwohl daneben eine Sicherheitsaussage steht. Beides sind keine exotischen
# Schreibweisen.
PROZESS_MODULE = {"subprocess", "multiprocessing", "pty"}
PROZESS_AUFRUFE = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
                   ("os", "execvp"), ("os", "spawnv"), ("os", "spawnl"), ("os", "fork")}

for f in LIB:
    body = read(f)
    assert "self_update" not in body, f"Selbst-Update wieder eingebaut: {f}"
    assert "sys.executable" not in body, f"{f} startet einen Interpreter"
    baum = _ast.parse(body)
    # Erst die Aliase auflösen: `import os as _o` macht `_o.system(...)` zu `os.system(...)`,
    # und eine Prüfung, die nur auf den Namen „os" sieht, übersieht das.
    alias = {}
    for knoten in _ast.walk(baum):
        if isinstance(knoten, _ast.Import):
            for a in knoten.names:
                alias[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]
    for knoten in _ast.walk(baum):
        if isinstance(knoten, _ast.Import):
            treffer = [a.name.split(".")[0] for a in knoten.names
                       if a.name.split(".")[0] in PROZESS_MODULE]
            assert not treffer, f"{f}:{knoten.lineno} importiert {treffer[0]} — startet Prozesse"
        elif isinstance(knoten, _ast.ImportFrom):
            wurzel = (knoten.module or "").split(".")[0]
            assert wurzel not in PROZESS_MODULE, \
                f"{f}:{knoten.lineno} importiert aus {wurzel} — startet Prozesse"
        elif isinstance(knoten, _ast.Call) and isinstance(knoten.func, _ast.Attribute):
            wert = knoten.func.value
            if isinstance(wert, _ast.Name):
                modul = alias.get(wert.id, wert.id)
                if (modul, knoten.func.attr) in PROZESS_AUFRUFE:
                    raise AssertionError(f"{f}:{knoten.lineno} ruft {modul}.{knoten.func.attr}() "
                                         "— startet einen Prozess")
print(f"  kein Selbst-Update, kein Prozessstart in der Bibliothek "
      f"({len(PROZESS_MODULE)} Module, {len(PROZESS_AUFRUFE)} Aufrufe geprüft)")

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
#
# Über `hygiene.pruefe_kein_self_hosted_runner`, nicht über eine eigene Textsuche: Die Funktion
# im Kit schneidet YAML-Kommentare ab, die Textsuche hier tat es nicht. Ein Workflow, der die
# Regel im Kommentar ERKLÄRT („keine self-hosted Runner, weil …"), schlug damit an — ein
# Fehlalarm, der ausgerechnet das gute Verhalten bestraft. Zwei Prüfungen für dieselbe Sache
# sind ohnehin eine zu viel.
self_hosted = hygiene.pruefe_kein_self_hosted_runner(ROOT, FILES)
assert not self_hosted, ("self-hosted Runner in einem öffentlichen Repo:\n  "
                         + "\n  ".join(self_hosted))

# Kit 0.13.x: jede Kit-Prüfung wird gerufen oder mit Grund ausgenommen — der Wächter darunter meldet,
# wenn eine neue still liegen bleibt (so lagen drei Matrix-Prüfungen in sieben Repos ungerufen, und
# jede Suite sah grün aus). Echte öffentliche Dienste sind keine Beispieladressen und stehen deshalb
# in einer benannten Liste, nicht in einer Ausnahme.
OEFFENTLICHE_DIENSTE = ["pypi.org", "raw.githubusercontent.com", "img.shields.io", "spdx.dev",
                        "www.flaticon.com", "ollornog.github.io", "github.com",
                        # Entra-ID-Endpunkt des mitgelieferten Presets — eine echte, feste
                        # Adresse von Microsoft, keine Beispieladresse und nichts Eigenes.
                        "login.microsoftonline.com"]
adressen = hygiene.pruefe_adressen(ROOT, FILES, POLICY, zusaetzliche_hosts=OEFFENTLICHE_DIENSTE)
assert not adressen, "Adressen ausserhalb RFC 2606 und der Dienstliste:\n  " + "\n  ".join(adressen)
nicht_ausfuehrbar = hygiene.pruefe_ausfuehrbar(
    ROOT, ["scripts/check.sh", "scripts/_backlog.py", "scripts/_codeql_backlog.py", "tests/run_all.py"])
assert not nicht_ausfuehrbar, "\n  ".join(nicht_ausfuehrbar)
abbruch = hygiene.pruefe_kein_abbruch_auf_default_branch(ROOT, FILES)
assert not abbruch, "cancel-in-progress auf main:\n  " + "\n  ".join(abbruch)
matrix_regel = hygiene.pruefe_python_matrix_regel()
assert not matrix_regel, "\n  ".join(matrix_regel)
sammelt = hygiene.pruefe_run_all_sammelt_automatisch(ROOT)
assert not sammelt, "\n  ".join(sammelt)
# Seit der Entscheidung zu PR #54 (Untergrenze 3.12) fährt dieses Repo die Kit-Matrix
# unverändert — die beiden Ausnahmen von vorher sind damit erledigt und die Prüfungen laufen.
matrix_abweichung = hygiene.pruefe_python_matrix(ROOT, FILES)
assert not matrix_abweichung, "Python-Matrix weicht von der Kit-Quelle ab:\n  " + "\n  ".join(matrix_abweichung)
untergrenze = hygiene.pruefe_requires_python(ROOT)
assert not untergrenze, "\n  ".join(untergrenze)
# Kit 0.14.0: Jeder `actions/checkout` setzt `persist-credentials: false`. **Ebene:** eigene
# Härtung, kein belegter Standard — GitHub empfiehlt es nirgends ausdrücklich. Was es bringt:
# Mit der Vorgabe liegt das Token für JEDEN späteren Schritt im Job lesbar da, und nach dem
# Checkout läuft hier fremder Code (`pip install -e`, Actions Dritter). Keine Ausnahme nötig:
# Kein Job dieses Repos pusht oder taggt per git — nachgemessen, nicht angenommen.
ohne_pc = hygiene.pruefe_persist_credentials(ROOT, FILES)
assert not ohne_pc, "checkout ohne persist-credentials:\n  " + "\n  ".join(ohne_pc)

# Kit 0.14.0: Ist die Dateiliste überhaupt vollständig? Eine leere Liste macht JEDE Prüfung
# danach grün, und der echte Fall war nicht „leer": Über `git archive` fehlten anderswo 6 von
# 1326 Dateien — das ganze `.github/`, also genau die Workflows, die zwei Prüfungen oben lesen.
# `root=` ist Pflicht, sonst wird nur gegen eine Mindestzahl verglichen statt gegen `git ls-tree`.
luecken = hygiene.pruefe_dateiliste_plausibel(FILES, root=ROOT)
assert not luecken, "die geprüfte Dateiliste ist unvollständig:\n  " + "\n  ".join(luecken)

# Kit 0.14.0: Hostnamen OHNE `https://` davor. `pruefe_adressen` sucht nur URLs mit Schema, und
# das Infrastruktur-Muster verlangt drei Namensteile — eine blanke Second-Level-Domain fällt
# durch beide. In einem fremden Repo stand so ein realer Firmenname.
#
# Der `grundstock` ist EINMAL DURCHGESEHEN, nicht erzeugt: Jeder Eintrag steht hier, weil jemand
# nachgesehen hat, warum die Adresse im Repo vorkommt. Automatisch befüllt wäre er die Baseline,
# die den nächsten echten Fund mit abnickt.
BLANKE_ADRESSEN_OK = [
    "ghcr.io",                 # die Registry, aus der das eigene Abbild kommt (Dockerfile, compose)
    "pypi.org",                # der Paketindex, gegen den test_packaging prüft
    "python.org",              # Quellenangabe in der Kit-Datei python_matrix.json
    "devguide.python.org",     # dito — der Release-Kalender, aus dem die Matrix folgt
    "flaticon.com",            # Quellenangabe für das Favicon (Lizenzpflicht, gehört sichtbar hin)
    "ollornog.github.io",      # die eigene Projektseite: Identität, keine Infrastruktur
    # Die beiden letzten sind KEINE Adressen, sondern sehen nur so aus:
    "ab.de",                   # tests/test_identifier.py: `assert not valid_email("ab.de")`
    "admin.app",               # tinysesam/messages.py: ein Übersetzungsschlüssel, kein Host
]
blank = hygiene.pruefe_blanke_adressen(ROOT, FILES, POLICY, zusaetzliche_hosts=OEFFENTLICHE_DIENSTE,
                                       grundstock=BLANKE_ADRESSEN_OK)
assert not blank, "blanke Hostnamen ausserhalb der durchgesehenen Liste:\n  " + "\n  ".join(blank)

# Kit 0.17: drei Prüfungen über das Kit selbst. `belegstellen` ist leer — TinySesam führt kein
# Zitatverzeichnis; der Aufruf steht trotzdem, damit ein späterer Eintrag geprüft wird.
beleg = hygiene.pruefe_belegstellen_eng(ROOT, FILES, [])
assert not beleg, "Belegstellen-Muster treffen Code:\n  " + "\n  ".join(beleg)
tabelle = hygiene.pruefe_tabelle_vollstaendig()
assert not tabelle, "Kit-Prüfung in keiner oder mehreren Listen:\n  " + "\n  ".join(tabelle)
schluessel = hygiene.pruefe_policy_schluessel_gelesen(POLICY)
assert not schluessel, "Policy-Schlüssel ohne Leser:\n  " + "\n  ".join(schluessel)

# Kit 0.18: Nichts wird von Dritten nachgeladen (PO-Regel 2026-09-23). Ein Link ist eine Tür, ein
# `src` ist ein Bote: beanstandet werden src/srcset, <link href>, url(), @import, fetch()/import(),
# <iframe src> — nie ein <a href>. Grenze: was JavaScript zur Laufzeit zusammenbaut, sieht diese
# Prüfung nicht.
fremd = hygiene.pruefe_keine_fremdressourcen(ROOT, FILES, POLICY)
assert not fremd, "Ressourcen von Dritten im Markup:\n  " + "\n  ".join(fremd)

# Kit 0.21: Von AUSSEN gefragt, ob jede Testdatei überhaupt läuft. Ein nicht verkabelter Test
# besteht seine eigene Aufruf-Prüfung (die Zeile darunter) dadurch, dass er schweigt. Hier
# sammelt `tests/run_all.py` per glob — die Prüfung erkennt das und fragt dann nicht je Datei.
testdateien = hygiene.pruefe_testdateien_gerufen(ROOT)
assert not testdateien, "Testdatei ohne Läufer:\n  " + "\n  ".join(testdateien)

# Kit 0.21.8: In einem tag-getriggerten Workflow mit Knopf veröffentlicht nichts ohne Tag — die
# allgemeine Fassung des release.yml-Wächters weiter unten (der prüft zusätzlich den Trockenlauf).
am_tag = hygiene.pruefe_veroeffentlichen_am_tag(ROOT)
assert not am_tag, "veröffentlicht ohne Tag:\n  " + "\n  ".join(am_tag)

ungerufen = hygiene.pruefe_kit_prueffunktionen_gerufen(ROOT, ausgenommen={})
assert not ungerufen, "Kit-Prüfung liegt still:\n  " + "\n  ".join(ungerufen)
print("  Kit 0.21.8: jede Prüfung gerufen, keine Ausnahme nötig; jede Testdatei hat einen Läufer; nichts veröffentlicht ohne Tag")

rel = read(".github", "workflows", "release.yml")
assert "tags:" in rel and "sha256sum" in rel, "Release baut keine Prüfsummen"
assert "linux/amd64,linux/arm64" in rel, "Abbild ist nicht multi-arch"
assert ":latest" not in rel, "ein wandernder `latest`-Tag gehört nicht ins Release"
# Registries verlangen kleingeschriebene Namen; `github.repository_owner` liefert die
# Schreibweise des Kontos und brach den Build ab („repository name must be lowercase").
for line in rel.splitlines():
    if line.strip().startswith("tags:") and re.search(r"\bghcr\.io/", line):
        assert "repository_owner" not in line, "Abbild-Tag nutzt die Groß-/Kleinschreibung des Kontos"

# Das Abbild darf keinen Weg zum Nachladen von Code enthalten — sonst käme das Selbst-Update
# durch die Hintertür zurück. Und es läuft nicht als root.
dockerfile = read("Dockerfile")
assert "USER tinysesam" in dockerfile, "Abbild läuft als root"
assert "HEALTHCHECK" in dockerfile, "Abbild ohne Health-Check"
for weg in ("/opt/venv/bin/pip", "/usr/local/bin/pip"):
    assert weg in dockerfile, f"{weg} wird nicht entfernt — das venv bringt ein eigenes pip mit"
print("  check.sh + pre-push da; CI fährt Browser-, Hygiene- und Website-Test; Release signiert Prüfsummen")

# ---------- Lieferkette: was T-13 (B4-*) festgezogen hat, bleibt fest ----------
# Jede Prüfung hier misst eine Zusage aus der Lieferketten-Runde von T-13. Gelesen wird YAML als
# Text (ohne PyYAML — die Suite läuft auch im Kern-Job ohne Extras), deshalb eng: Blöcke nach
# Einrückung, Kommentare abgeschnitten.
WORKFLOWS = sorted(f for f in FILES if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")))


def _code(text: str) -> list[str]:
    return [hygiene.ohne_yaml_kommentar(z).rstrip() for z in text.splitlines()]


def _jobs(text: str) -> dict[str, list[str]]:
    """Job-Name → seine Zeilen (ohne Kommentare). Jobs stehen zwei Leerzeichen tief unter `jobs:`."""
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
    """Die Zeilen aller `run:`-Schritte (bzw. der Schlüssel in `schluessel`) — einzeilig und als
    Block (`run: |`)."""
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


# B4-4 — Wer eine Identität oder ein Schreibrecht hält, führt keinen fremden Code aus. Bis 0.19.0
# lief die ganze Suite samt `pip install ".[all]"` im Job, der auch beglaubigte — jede
# Abhängigkeit hätte eine Attestation auf die Identität des Workflows ausstellen können.
#
# Welche Rechte ein Job hält, wird aus JEDER Schreibweise gelesen: Block (`id-token: write`),
# Flow-Map (`{id-token: write}`), `write-all`, und geerbt von der Workflow-Ebene, wenn der Job
# selbst nichts setzt. Bis zur Nachprüfung (A-2) sah der Riegel nur die Blockschreibweise und nur
# `id-token`/`contents` — ein neuer Job mit `permissions: write-all` lief komplett durch.
def _rechte_wert(wert: str, folgend: list[str], tiefe: int) -> set[str]:
    """Die Schreibrechte aus einem `permissions:`-Wert; `*` steht für write-all."""
    wert = wert.strip().strip("'\"")
    if wert == "write-all":
        return {"*"}
    if wert in ("read-all", "{}"):
        return set()
    if wert.startswith("{"):
        paare = [p.split(":", 1) for p in wert.strip("{}").split(",") if ":" in p]
        return {k.strip() for k, v in paare if v.strip().strip("'\"") == "write"}
    assert not wert, f"unbekannter permissions-Wert {wert!r} — Wächter anpassen"
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
    return {"*"}   # ohne Angabe gilt die Repo-Vorgabe — im schlimmsten Fall Schreibrecht


def _rechte_job(zeilen: list[str], geerbt: set[str]) -> set[str]:
    for i, z in enumerate(zeilen):
        m = re.match(r"^    permissions:\s*(.*)$", z)
        if m:
            return _rechte_wert(m.group(1), zeilen[i + 1:], 4)
    return geerbt


# Befehle, die ein Job mit Identität oder Schreibrecht in `run:` ausführen darf — eine Positivliste,
# keine Sperrliste: `curl … | bash`, `git clone … && node …` oder ein neues Werkzeug fielen durch
# jede Wortliste (A-5). Geprüft wird jedes Glied einer Befehlskette und jede `$( … )`-Ersetzung.
ERLAUBT_MIT_RECHT = {"echo", "printf", "gh release", "gh attestation", "git log"}


def _befehle(zeile: str) -> list[str]:
    """Die einzelnen Befehle einer Shell-Zeile — getrennt an ; && || | ( $( und `.

    Was hinter einer schliessenden Klammer folgt, gehört zum äusseren Befehl (`echo "$(git log)"
    >> datei`) und wird verworfen; eine Pipe in Anführungszeichen wird dabei als eigener Befehl
    gelesen und damit rot — lieber zu streng als zu blind.
    """
    aus = []
    for teil in re.split(r"\$\(|`|&&|\|\||[;|(]", zeile):
        woerter = teil.split(")", 1)[0].split()
        while woerter and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", woerter[0]):
            woerter.pop(0)           # VAR=wert vor dem Befehl
        if woerter:
            aus.append(" ".join(woerter[:2]))
    return aus


def _erlaubt(befehl: str) -> bool:
    return befehl.split()[0] in ERLAUBT_MIT_RECHT or befehl in ERLAUBT_MIT_RECHT


# Schreibrechte, die mit Checkout auskommen MÜSSEN — je Job genau diese Rechte und der Grund. Der
# Checkout ist erlaubt, fremder Code in `run:` weiterhin nicht. Kommt ein Recht dazu, wird der Job
# rot (die Menge muss exakt stimmen).
CHECKOUT_MIT_RECHT = {
    (".github/workflows/codeql.yml", "analyse"): ({"security-events"},
                                                   "CodeQL braucht den Quelltext; kein `run:`"),
    (".github/workflows/release.yml", "image"): ({"packages"},
                                                 "Build-Kontext fürs Abbild; pip läuft im BuildKit-"
                                                 "Container, der das Token nicht sieht"),
}

_geprueft_identitaet, _ausnahmen_gesehen = 0, set()
for wf in WORKFLOWS:
    text = read(wf)
    oben = _rechte_oben(text)
    # Oben auf Workflow-Ebene steht nie ein Schreibrecht — das erbte sonst jeder Job.
    assert not oben, f"{wf}: Schreibrecht auf Workflow-Ebene ({sorted(oben)}) — gehört an den Job"
    jobs = _jobs(text)
    assert jobs, f"{wf}: keine Jobs erkannt — Parser prüfen"
    for job, zeilen in jobs.items():
        rechte = _rechte_job(zeilen, oben)
        if not rechte:
            continue
        _geprueft_identitaet += 1
        block = "\n".join(zeilen)
        ausnahme = CHECKOUT_MIT_RECHT.get((wf, job))
        if ausnahme:
            _ausnahmen_gesehen.add((wf, job))
            assert rechte == ausnahme[0], (f"{wf} Job `{job}`: Rechte {sorted(rechte)} statt "
                                           f"{sorted(ausnahme[0])} — die Ausnahme gilt nur dafür")
        else:
            assert "actions/checkout" not in block, (
                f"{wf} Job `{job}` hält {sorted(rechte)} UND checkt das Repo aus — Bau und "
                "Beglaubigung gehören in getrennte Jobs")
        # Lokale Actions und Docker-Actions bringen Code mit, den kein SHA-Pin festhält.
        assert not re.search(r"^\s+(?:- )?uses:\s*['\"]?(\./|docker://)", block, re.M), \
            f"{wf} Job `{job}` hält {sorted(rechte)} und nutzt eine lokale/Docker-Action"
        assert not re.search(r"^\s+(?:- )?shell:", block, re.M), \
            f"{wf} Job `{job}` hält {sorted(rechte)} und setzt eine eigene `shell:`"
        for k in _kommandos(zeilen):
            for befehl in _befehle(k):
                assert _erlaubt(befehl), (f"{wf} Job `{job}` hält {sorted(rechte)} und führt "
                                          f"`{befehl}` aus: {k}")
assert _ausnahmen_gesehen == set(CHECKOUT_MIT_RECHT), \
    f"Ausnahmen ohne Job: {set(CHECKOUT_MIT_RECHT) - _ausnahmen_gesehen} — Liste aufräumen"
assert _geprueft_identitaet >= 6, f"nur {_geprueft_identitaet} Jobs mit Schreibrecht gefunden — Parser prüfen"
print(f"  {_geprueft_identitaet} Jobs mit Identität/Schreibrecht (jede Schreibweise): nur "
      f"{'/'.join(sorted(ERLAUBT_MIT_RECHT))}, Checkout nur mit begründeter Ausnahme")

# B4-6 — Actions, die zur Laufzeit ein Werkzeug nachladen. Der SHA-Pin hält die Action fest, nicht
# das Werkzeug: Ohne Angabe zieht setup-qemu den `latest`-Tag von tonistiigi/binfmt (privilegiert!),
# setup-buildx `moby/buildkit:buildx-stable-1`. Verlangt wird je Werkzeug Version UND Digest.
# Grenze: Eine NEUE Action, die nachlädt, steht nicht in dieser Tabelle — sie wird beim Aufnehmen
# geprüft (Liste unten erweitern), nicht von selbst erkannt.
WERKZEUG_PFLICHT = {
    "docker/setup-qemu-action": [r"^\s+image:\s*\S+:[\w.-]+@sha256:[0-9a-f]{64}\s*$"],
    "docker/setup-buildx-action": [r"^\s+version:\s*v\d+\.\d+\.\d+\s*$",
                                   r"^\s+driver-opts:\s*image=\S+:v[\d.]+@sha256:[0-9a-f]{64}\s*$"],
}
# Geprüft und ohne Angabe fest: die Werkzeug-Fassung steht als Konstante im gepinnten Commit.
WERKZEUG_IM_SHA = {"anchore/sbom-action": "syft als Konstante in src/SyftVersion.ts",
                   "github/codeql-action": "CodeQL-Bundle gehört zur Action-Fassung",
                   "pypa/gh-action-pypi-publish": "Abbild ghcr.io/pypa/…:<sha> bzw. Dockerfile mit Constraints"}
# Bewusst wandernd: der Browser-Test soll gegen das aktuelle stabile Chrome laufen. Der Job hat nur
# Leserecht und liefert nichts aus.
WERKZEUG_WANDERND_OK = {"browser-actions/setup-chrome": "ci.yml, nur Leserecht, liefert nichts aus"}
for wf in WORKFLOWS:
    zeilen = _code(read(wf))
    for i, z in enumerate(zeilen):
        m = re.search(r"uses:\s*([^@\s]+)@", z)
        if not m or m.group(1) not in WERKZEUG_PFLICHT:
            continue
        # Der `with:`-Block der Action: die folgenden Zeilen bis zum nächsten Schritt.
        folgend = []
        for w in zeilen[i + 1:]:
            if re.match(r"^\s+- ", w) or (w and not w.startswith(" ")):
                break
            folgend.append(w)
        for muster in WERKZEUG_PFLICHT[m.group(1)]:
            assert any(re.match(muster, w) for w in folgend), (
                f"{wf}: {m.group(1)} ohne festes Werkzeug ({muster}) — der SHA-Pin hält die Action "
                "fest, nicht das Abbild, das sie zur Laufzeit zieht")
print(f"  nachladende Actions: Werkzeug mit Version und Digest ({', '.join(WERKZEUG_PFLICHT)})")

# B4-6/B4-8 — pip im Bau- und im Prüfpfad nur gegen eine gehashte Liste. Ausgenommen ist, was die
# Suite prüft (dort IST die Auflösung der Prüfgegenstand) — also jeder Job, der `run_all.py` fährt.
for wf in (".github/workflows/release.yml", ".github/workflows/audit.yml"):
    for job, zeilen in _jobs(read(wf)).items():
        block = "\n".join(zeilen)
        if "tests/run_all.py" in block:
            continue
        for z in _kommandos(zeilen):
            # Jede Schreibweise von pip: `pip3`, `pip3.14`, `"$venv/pip"`, `python -m pip`. Bis zur
            # Nachprüfung (A-6) traf `\bpip\b` kein `pip3` — `pip3 install build` rutschte durch.
            if re.search(r"(\bpip[0-9.]*|\bpython[0-9.]*\s+-m\s+pip)[\"']?\s+install\b", z):
                assert "--require-hashes" in z or ("--no-index" in z and "--no-deps" in z), (
                    f"{wf} Job `{job}`: pip install weder gehasht noch ohne Netz: {z}")
            # Werkzeuge, die an der gehashten Liste vorbei aus dem Index installieren.
            assert not re.search(r"\b(uvx|pipx|easy_install|conda|mamba|pyproject-build)\b"
                                 r"|\buv[\"']?\s+(tool|run|add|sync|pip\s+(install|sync))\b", z), \
                f"{wf} Job `{job}`: Werkzeug am Hash vorbei: {z}"
            # Ohne `--no-isolation` holt sich `build` das gerade neueste setuptools in eine eigene
            # Umgebung — die gehashte Liste wäre dann Dekoration.
            if re.search(r"-m\s+build\b", z):
                assert re.search(r"\s(--no-isolation|-n)\b", z), \
                    f"{wf} Job `{job}`: `-m build` mit Bau-Isolierung (zieht setuptools frei): {z}"
_bau_job = _jobs(read(".github/workflows/release.yml")).get("bauen", [])
assert any(re.search(r"-m\s+build\b", k) for k in _kommandos(_bau_job)), \
    "release.yml: Job `bauen` baut nicht mehr mit `-m build` — Wächter anpassen"
print("  Bau- und Prüfwerkzeuge im Release/Audit nur aus gehashten Listen, Bau ohne Isolierung")

# Der Knopf (`workflow_dispatch`) ist ein Trockenlauf: Jeder Job, der veröffentlicht oder eine
# Identität hält, hängt am Tag; das Abbild wird ohne Tag gebaut, aber weder angemeldet noch
# geschoben. Bis 2026-09-24 hätte der Knopf am Tag-Vergleich scheitern oder — ohne ihn — aus einem
# Zweig veröffentlichen können. (Mutationsprobe: bei `release`, `pypi` oder `image-beglaubigen`
# die `if:`-Zeile streichen, oder `push=${{ github.ref_type == 'tag' }}` auf `push=true` → rot.)
_rel_jobs = _jobs(rel)
_AM_TAG = "if: github.ref_type == 'tag'"
for _j in ("release", "pypi", "image-beglaubigen"):
    _zeilen = [z.strip() for z in _rel_jobs.get(_j, [])]
    assert _AM_TAG in _zeilen, f"release.yml: Job `{_j}` veröffentlicht auch ohne Tag (Knopf = Trockenlauf)"
for _j, _zeilen in _rel_jobs.items():
    _rechte = " ".join(z.strip() for z in _zeilen)
    if re.search(r"\b(id-token|contents|attestations): write\b", _rechte) or \
            any(z.strip().startswith("environment:") for z in _zeilen):
        assert _AM_TAG in [z.strip() for z in _zeilen], \
            f"release.yml: Job `{_j}` hält eine Identität oder Schreibrecht, hängt aber nicht am Tag"
_image = "\n".join(_rel_jobs.get("image", []))
assert "push=${{ github.ref_type == 'tag' }}" in _image and "push=true" not in _image, \
    "release.yml: das Abbild wird auch ohne Tag geschoben"
_login = re.search(r"- name: An GHCR anmelden\n\s+" + re.escape(_AM_TAG), _image)
assert _login, "release.yml: die GHCR-Anmeldung im Job `image` hängt nicht am Tag"
_pruef = "\n".join(_rel_jobs.get("pruefen", []))
assert "_release.py --pruefen" in _pruef and "if: github.ref_type != 'tag'" in _pruef, \
    "release.yml: der Trockenlauf prüft nichts (scripts/_release.py --pruefen fehlt)"
print("  release.yml: ohne Tag ein Trockenlauf — prüfen und bauen ja, veröffentlichen nie")

# B4-7 — Das Abbild installiert, was die Sperrliste sagt, Byte für Byte. Der Digest-Pin im FROM
# hält nur das Basis-Abbild; ein `pip install ".[gateway]"` löste bei jedem Bau neu auf.
SPERRLISTE = "deploy/gateway/requirements.txt"
_df = "\n".join(z for z in dockerfile.splitlines() if not z.lstrip().startswith("#"))
assert "--require-hashes" in _df and "-r requirements.txt" in _df, \
    "das Abbild installiert nicht aus der gehashten Sperrliste"
assert f"COPY {SPERRLISTE}" in _df, f"das Dockerfile kopiert {SPERRLISTE} nicht"
assert "--upgrade pip" not in _df, "`pip install --upgrade pip` zieht bei jedem Bau das neueste pip"
_eigen = [z for z in _df.splitlines() if re.search(r"pip install .*\s\.\s*(\\|$)", z)]
assert _eigen and all("--no-index" in z and "--no-deps" in z for z in _eigen), \
    f"TinySesam selbst wird mit Netz oder Auflösung installiert: {_eigen}"
assert f"!{SPERRLISTE}" in read(".dockerignore"), f".dockerignore lässt {SPERRLISTE} nicht durch"
# `--no-deps` installiert auch eine unvollständige Liste ohne Murren (A-1 der Nachprüfung): Fehlt
# eine transitive Abhängigkeit — etwa weil Dependabot eine Zeile hob, die eine neue mitbringt —,
# bricht das Abbild erst beim Start ab. `pip check` und der Import gehören deshalb in denselben
# RUN, nach beide Installationen und vor das Entfernen von setuptools; audit.yml fährt dieselben
# Schritte bei jedem PR, sonst fiele es erst beim Release auf (kein PR-Lauf baut das Abbild).
_run = re.sub(r"\\\n\s*", " ", _df)
_kette = next((z for z in _run.splitlines() if "-r requirements.txt" in z), "")
_stufen = [s.strip() for s in _kette.split("&&")]
_pos = {n: next((i for i, s in enumerate(_stufen) if re.search(m, s)), -1) for n, m in (
    ("sperrliste", r"--require-hashes"), ("eigen", r"--no-index"), ("check", r"/pip check$"),
    ("import", r"python -c \"import tinysesam\.gateway\"$"), ("setuptools", r"uninstall"))}
assert -1 not in _pos.values(), f"Dockerfile: Schritt fehlt im Installations-RUN: {_pos}"
assert _pos["sperrliste"] < _pos["eigen"] < _pos["check"] < _pos["import"] < _pos["setuptools"], \
    f"Dockerfile: `pip check`/Import nicht nach der Installation und vor dem Aufräumen: {_pos}"
_audit_lauf = _kommandos(_code(read(".github/workflows/audit.yml")))
for _m in (rf"pip\"? install --require-hashes --no-deps -r {re.escape(SPERRLISTE)}$",
           r"pip\"? install --no-deps --no-index --no-build-isolation \.$",
           r"pip\"? check$", r"python\"? -c \"import tinysesam\.gateway\"$", r"^python3\.(\d+) -m venv"):
    assert any(re.search(_m, k) for k in _audit_lauf), f"audit.yml: Probe der Sperrliste ohne `{_m}`"
# Die Probe läuft in der Python-Reihe des Abbilds (die Sperrliste ist für sie aufgelöst).
_reihe = re.search(r"^FROM python:(3\.\d+)", dockerfile, re.M).group(1)
assert any(k.startswith(f"python{_reihe} -m venv") for k in _audit_lauf), \
    f"audit.yml: Probe der Sperrliste nicht auf Python {_reihe} (FROM im Dockerfile)"
# pip wird per Muster entfernt, nicht mit fester Reihe: Nach dem Sprung von 3.12 auf 3.14 (#74)
# zeigten alle `python3.12`-Pfade ins Leere, und pip lag wieder im Endabbild.
for _reihe_fest in set(re.findall(r"(?:python|pip)(3\.\d+)", _df)):
    assert _reihe_fest == _reihe, (f"Dockerfile nennt Python {_reihe_fest}, das Abbild ist "
                                   f"{_reihe} — Pfade per Muster (`python3.*`) schreiben")


def _sperrliste(rel: str) -> dict[str, str]:
    """name → version; jede Anforderung gepinnt und mit mindestens einem Hash."""
    text = read(rel).replace("\\\n", " ")
    pins = {}
    for z in text.splitlines():
        z = z.split("#", 1)[0].strip()
        if not z:
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)==([0-9][^\s;]*)\s*(;[^-]*)?(.*)$", z)
        assert m, f"{rel}: nicht gepinnt: {z[:60]}"
        assert "--hash=sha256:" in m.group(4), f"{rel}: {m.group(1)} ohne Hash"
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
    assert _m, f"pyproject: unerwartete Anforderung {_anf!r} — Wächter anpassen"
    _n = _m.group(1).lower().replace("_", "-")
    assert _n in _lock, f"{SPERRLISTE} fehlt {_n} — neu erzeugen (Befehl im Kopf der Datei)"
    assert _v(_lock[_n]) >= _v(_m.group(2)), (f"{SPERRLISTE}: {_n}=={_lock[_n]} liegt unter der "
                                              f"Grenze {_anf} — neu erzeugen")
assert "setuptools" in _lock, f"{SPERRLISTE}: setuptools fehlt — ohne Bau-Isolierung braucht das Abbild es"
# Offline-Teil der Vollständigkeit: Jeder Name in einem `# via` muss selbst in der Liste stehen
# (oder die Wurzel sein). Wer einen Block von Hand löscht, lässt dessen `via`-Verweise bei den
# Abhängigkeiten zurück. Grenze: Ein Blatt ohne eigene Abhängigkeiten und eine NEUE Abhängigkeit
# nach einem Bump sieht das nicht — die fängt erst `pip check` in audit.yml (siehe oben).
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
assert _via and _via <= set(_lock), (f"{SPERRLISTE}: `# via` nennt Pakete, die fehlen: "
                                     f"{sorted(_via - set(_lock))} — neu erzeugen")
print(f"  Gateway-Abbild: {len(_lock)} Pakete aus gehashter Sperrliste, deckt pyproject ab, kein pip-Upgrade")

# B4-2 — Das Schwachstellen-Tor: jede gehashte Liste und beide Auflösungen gehen durch pip-audit,
# bei jedem PR und nächtlich, und das Tor darf nicht rot werden können, ohne zu blockieren.
_audit = read(".github/workflows/audit.yml")
_audit_code = "\n".join(_code(_audit))
for noetig in ("pull_request:", "schedule:", "pip-audit", "--strict", "--resolution lowest-direct",
               "--all-extras"):
    assert noetig in _audit_code, f"audit.yml: `{noetig}` fehlt — das Tor prüft weniger, als es sagt"
assert "continue-on-error" not in _audit_code, "audit.yml darf nicht durchwinken (continue-on-error)"
SPERRLISTEN = sorted(f for f in FILES if os.path.basename(f) == "requirements.txt")
assert len(SPERRLISTEN) >= 3, f"nur {SPERRLISTEN} gefunden"
for rel in SPERRLISTEN:
    _sperrliste(rel)                                  # gepinnt + gehasht, sonst rot
    assert rel in _audit_code, f"{rel} wird von audit.yml nicht geprüft"
print(f"  Schwachstellen-Tor: {len(SPERRLISTEN)} Sperrlisten + neueste + niedrigste Auflösung, --strict")

# B4-3/B4-12 — Dependabot sieht jede Stelle, an der etwas gepinnt ist, und keine, an der es nichts
# zu heben gibt. Ein pip-Eintrag für `/` las die `>=`-Grenzen, und die hebt Dependabot nie.
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


assert "/" not in _dependabot_dirs("pip"), ("dependabot: pip auf `/` liest nur die `>=`-Grenzen "
                                            "und hebt nie etwas — die Böden prüft audit.yml")
for rel in SPERRLISTEN:
    assert "/" + os.path.dirname(rel) in _dependabot_dirs("pip"), f"Dependabot hebt {rel} nicht"
for rel in (f for f in FILES if re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", f)):
    assert "/" + os.path.dirname(rel) in _dependabot_dirs("docker-compose"), \
        f"Dependabot sieht {rel} nicht (Eintrag `docker-compose`)"
for rel in (f for f in FILES if os.path.basename(f) == "Dockerfile"):
    assert "/" + os.path.dirname(rel).rstrip("/") in {d.rstrip("/") or "/" for d in _dependabot_dirs("docker")} \
        or (os.path.dirname(rel) == "" and "/" in _dependabot_dirs("docker")), f"Dependabot sieht {rel} nicht"
assert _dependabot_dirs("github-actions"), "Dependabot hebt die Actions nicht"
print("  Dependabot: jede Sperrliste, jedes Compose, jedes Dockerfile, die Actions — kein toter pip-Eintrag")

# B4-11 — Der Referenz-Stack: jedes Fremd-Abbild mit Digest, das eigene mit dem Versions-Tag, und
# jeder Dienst gehärtet. `caddy:2` wanderte mit jeder Caddy-Version.
_compose = read("deploy/forward-auth/docker-compose.yml")
_cz = _code(_compose)
_bilder = [z.split("image:", 1)[1].strip() for z in _cz if re.match(r"^\s+image:", z)]
assert len(_bilder) >= 2, _bilder
for bild in _bilder:
    assert bild == f"ghcr.io/ollornog/tinysesam:v{pv}" or re.search(r":[\w.-]+@sha256:[0-9a-f]{64}$", bild), \
        f"compose: {bild} ist weder das eigene Versions-Abbild noch per Version+Digest gepinnt"
_anker = re.search(r"^x-haertung: &haertung\n((?:  .*\n)+)", "\n".join(_cz) + "\n", re.M)
assert _anker, "compose: der Härtungs-Anker x-haertung fehlt"
for noetig in ("read_only: true", "cap_drop: [ALL]", 'security_opt: ["no-new-privileges:true"]'):
    assert noetig in _anker.group(1), f"compose: x-haertung ohne `{noetig}`"
_dienste = re.search(r"^services:\n(.*?)^\S", "\n".join(_cz) + "\nENDE", re.M | re.S).group(1)
_namen = re.findall(r"^  ([a-z0-9_-]+):\s*$", _dienste, re.M)
_bloecke = re.split(r"^  [a-z0-9_-]+:\s*$", _dienste, flags=re.M)[1:]
assert len(_namen) == len(_bloecke) >= 2, _namen
for name, block in zip(_namen, _bloecke):
    assert "<<: *haertung" in block, f"compose: Dienst `{name}` ohne Härtung (<<: *haertung)"
    assert "cap_add" not in block or re.search(r"cap_add: \[NET_BIND_SERVICE\]", block), \
        f"compose: Dienst `{name}` holt sich mehr als NET_BIND_SERVICE zurück"
print(f"  Referenz-Stack: {len(_bilder)} Abbilder gepinnt, {len(_namen)} Dienste gehärtet")

# B4-10 — SECURITY.md nennt einen Weg, den jeder erreicht, und Fristen, die man nachmessen kann.
from web.site import OWNER as _OWNER  # noqa: E402
for _sec in ("SECURITY.md", "i18n/SECURITY.de.md"):
    _t = read(_sec)
    assert "security/advisories/new" in _t, f"{_sec}: kein direkter Link zur privaten Meldung"
    assert _OWNER["email"] in _t, f"{_sec}: keine E-Mail als Weg ohne GitHub-Konto ({_OWNER['email']})"
    _fristen = re.findall(r"\*\*(\d+) (?:days|Tage)\*\*", _t)
    assert len(_fristen) >= 3, f"{_sec}: keine messbaren Fristen (gefunden: {_fristen})"
    assert not re.search(r"within a few days|innerhalb weniger Tage", _t), f"{_sec}: „wenige Tage“ ist keine Frist"
_en = re.findall(r"\*\*(\d+) days\*\*", read("SECURITY.md"))
_de = re.findall(r"\*\*(\d+) Tage\*\*", read("i18n/SECURITY.de.md"))
assert _en == _de, f"SECURITY: Fristen EN {_en} ≠ DE {_de}"
print(f"  SECURITY: zwei Meldewege, Fristen {'/'.join(_en)} Tage in beiden Sprachen")

# B4-14 — OpenSSF-Scorecard: was schon erreicht ist, bleibt erreicht. Je Kriterium die Prüfung, die
# es offline trägt (Scorecard selbst braucht die GitHub-API). Nicht offline prüfbar und deshalb
# NICHT hier: Branch-Protection, Code-Review, Maintained, Signed-Releases (Sigstore-Attestationen
# statt Signaturdateien), Fuzzing (nicht erreicht).
_scorecard = {}
_alle_wf = {wf: "\n".join(_code(read(wf))) for wf in WORKFLOWS}
# Dangerous-Workflow: kein Trigger, der fremden Code mit Rechten ausführt; kein Ausdruck aus dem
# Ereignis in einem Shell-Schritt oder einem `actions/github-script`-`script:` (Skript-Injektion
# über Titel, Zweignamen, Kommentare). Geprüft wird JEDER `${{ … }}`-Ausdruck, der das Ereignis
# anfasst — auch in einer Funktion: Bis zur Nachprüfung (A-7) sah der Wächter nur
# `${{ github.event… }}` direkt, `${{ toJSON(github.event…) }}` oder `format('{0}', github.head_ref)`
# gingen durch.
_EREIGNIS = re.compile(r"\bgithub\s*(?:\.\s*|\[\s*['\"])(?:event|head_ref)\b")
for wf, t in _alle_wf.items():
    assert not re.search(r"\b(pull_request_target|workflow_run|issue_comment)\b", t), \
        f"{wf}: gefährlicher Trigger (Scorecard Dangerous-Workflow)"
    for k in _kommandos(t.splitlines(), ("run", "script")):
        for ausdruck in re.findall(r"\$\{\{(.*?)\}\}", k):
            assert not _EREIGNIS.search(ausdruck), \
                f"{wf}: Ereignis-Ausdruck im Shell-/Skript-Schritt (Skript-Injektion): {k}"
_scorecard["Dangerous-Workflow"] = True
# Token-Permissions: jeder Workflow setzt oben `permissions:` und dort nichts mit write (oben geprüft).
_scorecard["Token-Permissions"] = all(re.search(r"^permissions:", t, re.M) for t in _alle_wf.values())
assert _scorecard["Token-Permissions"], "ein Workflow ohne `permissions:` auf oberster Ebene"
# Pinned-Dependencies (Teil, der erreicht ist): Actions per SHA (oben), Basis-Abbild per Digest.
_scorecard["Pinned-Dependencies"] = all("@sha256:" in z for z in dockerfile.splitlines() if z.startswith("FROM "))
assert _scorecard["Pinned-Dependencies"], "Dockerfile: FROM ohne Digest"
# SAST: CodeQL auf PRs und main.
_codeql = _alle_wf.get(".github/workflows/codeql.yml", "")
_scorecard["SAST"] = "github/codeql-action/analyze" in _codeql and "pull_request:" in _codeql and "push:" in _codeql
assert _scorecard["SAST"], "CodeQL läuft nicht mehr auf PRs und main (Scorecard SAST)"
# Security-Policy, License, Dependency-Update-Tool, CI-Tests.
_scorecard["Security-Policy"] = "SECURITY.md" in FILES
_scorecard["License"] = "LICENSE" in FILES
_scorecard["Dependency-Update-Tool"] = ".github/dependabot.yml" in FILES
_scorecard["CI-Tests"] = "pull_request:" in _alle_wf[".github/workflows/ci.yml"]
# Binary-Artifacts: keine ausführbaren Binärdateien im Repo.
_bin = [f for f in FILES if f.endswith((".exe", ".dll", ".so", ".dylib", ".jar", ".class", ".pyc", ".whl", ".egg"))]
_scorecard["Binary-Artifacts"] = not _bin
_verloren = sorted(k for k, v in _scorecard.items() if not v)
assert not _verloren, f"Scorecard-Kriterien verloren: {_verloren} (Binärdateien: {_bin[:3]})"
print(f"  Scorecard: {len(_scorecard)} erreichte Kriterien bewacht ({', '.join(sorted(_scorecard))})")

# ---------- Das Release-Skript ersetzt nur Pins, keine Geschichte ----------
# Bis 0.20.0 ersetzte `scripts/_release.py` jede Fundstelle der alten Version — und schrieb damit
# „0.19.0 hob auf Schema 8" und „bis 0.19.0 landete man im selben Konto" auf die neue Fassung um.
# (Mutationsprobe: in `ersetze_pins` wieder `text.replace(alt, neu)` → rot.)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import _release  # noqa: E402
_probe = ("x@v0.19.0\ntinysesam:v0.19.0\n/v0.19.0/tinysesam-0.19.0-py3\n==0.19.0\n"
          'version = "0.19.0"\n__version__ = "0.19.0"\nBis 0.19.0 galt\n0.19.0 took it\nv0.19.01')
_neu, _n = _release.ersetze_pins(_probe, "0.19.0", "0.20.0")
assert _n == 7 and "Bis 0.19.0 galt" in _neu and "0.19.0 took it" in _neu and "v0.19.01" in _neu, (_n, _neu)
print("  Release-Skript ersetzt nur Pins (7 Formen), erzählender Text bleibt")

# ---------- Doku wandert mit: der Changelog kennt den aktuellen Stand ----------
changelog = read("CHANGELOG.md")
assert any(k in changelog for k in ("## [Unveröffentlicht]", "## [Unreleased]", f"## [{pv}]")), \
    "CHANGELOG hat weder einen offenen Abschnitt noch einen für die Paketversion"
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

# ---------- Zugesagte Python-Versionen: gemessen, nicht behauptet ----------
# Ein Classifier ist eine Zusage an den Nutzer. Bis 0.18.0 versprach TinySesam 3.11 und 3.13,
# und die CI fuhr beide nicht — die Zusage war nie gemessen. Umgekehrt starb ein Test auf 3.10
# an `tomllib` (gibt es erst ab 3.11), und weil `ci-local` nur EINE Version faehrt, fiel das
# erst in der GitHub-Matrix auf. Beides faengt diese Pruefung.
import re as _re  # noqa: E402

_lies = lambda *teile: pathlib.Path(ROOT, *teile).read_text(encoding="utf-8", errors="replace")
_pp = _lies("pyproject.toml")
versprochen = set(_re.findall(r"Programming Language :: Python :: (\d+\.\d+)", _pp))
_ci = _lies(".github", "workflows", "ci.yml")
_m = _re.search(r"python-version:\s*\[([^\]]+)\]", _ci)
gefahren = set(_re.findall(r"[\"']([\d.]+)[\"']", _m.group(1))) if _m else set()
fehlt = sorted(versprochen - gefahren, key=lambda v: [int(t) for t in v.split(".")])
assert not fehlt, ("Classifier versprechen Python " + ", ".join(fehlt) +
                   ", die CI-Matrix faehrt sie nicht — entweder Matrix erweitern "
                   "oder den Classifier streichen. Eine ungemessene Zusage ist eine Behauptung.")
print(f"  Python {', '.join(sorted(versprochen))} zugesagt UND in der CI-Matrix")

# Standardbibliotheks-Namen, die es in der aeltesten zugesagten Version noch nicht gibt.
# Der Import steht oft mitten in einer Datei und faellt lokal nie auf.
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
assert not zu_neu, ("Zugesagt ist ab Python %d.%d:\n  " % _min) + "\n  ".join(zu_neu)
print(f"  keine Standardbibliothek jenseits von Python {_min[0]}.{_min[1]} ({len(ZU_NEU)} Muster)")

# ---------- README.md ist zugleich die PyPI-Beschreibung ----------
# Dort löst nichts relative Repo-Pfade auf: Bis 0.18.0 waren auf der Paketseite das Logo und
# sieben Verweise tot — die erste Seite, die ein Interessent sieht. Die deutsche Fassung unter
# i18n/ wird nur auf GitHub gelesen und darf relativ bleiben.
_readme = _lies("pyproject.toml")
assert 'readme = "README.md"' in _readme, ("pyproject verweist nicht mehr auf README.md — "
                                           "diese Prüfung gehört dann auf die andere Datei")
_r = _lies("README.md")
_rel = _re.findall(r"!?\[[^\]]*\]\((?!https?://|#)([^)]+)\)", _r)
_rel += _re.findall(r'<img src="(?!https?://)([^"]+)"', _r)
_rel += _re.findall(r'<a href="(?!https?://|#)([^"]+)"', _r)
assert not _rel, ("Relative Verweise in README.md — auf der PyPI-Seite tot:\n  " +
                  "\n  ".join(sorted(set(_rel))))
print(f"  README.md ohne relative Verweise (PyPI-tauglich)")

# ---------- Konfigurations-Nachschlag: jedes Feld erklärt, Abzug aktuell ----------
# Von 119 Feldern kamen 39 in keiner README vor. Ein Nachschlagewerk von Hand zu pflegen heisst,
# dass es beim nächsten neuen Feld wieder unvollständig ist — deshalb generiert, aus den
# Kommentaren in config.py. Zwei Zusagen: die Datei ist aktuell, und kein Feld schweigt.
_gen = subprocess.run([sys.executable, "scripts/_config_doku.py", "--dry-run"],
                      cwd=ROOT, capture_output=True, text=True)
assert _gen.returncode == 0, ("KONFIGURATION.md ist veraltet — "
                              "`python3 scripts/_config_doku.py` fahren")
_konf = _lies("KONFIGURATION.md")
# B3-15: Beschreibungen verrutschten. Die eingerückte Fortsetzung eines Hinter-Kommentars landete
# beim NÄCHSTEN Feld — `login_identifier` begann mit dem Text von `https_mode`, `admin_identifiers`
# brach mitten im Satz ab. Gemessen an drei Feldern, die genau diese Form haben, und an der
# `#:`-Form, deren Doppelpunkt vorher im Text stand.
def _zeile(feld):
    return next(z for z in _konf.splitlines() if z.startswith(f"| `{feld}` "))
assert "warn = läuft auch OHNE Zertifikat" in _zeile("https_mode"), _zeile("https_mode")
assert "warn =" not in _zeile("login_identifier") and "Womit meldet" in _zeile("login_identifier"), \
    _zeile("login_identifier")
assert "SOLANGE es keinen Admin gibt" in _zeile("admin_identifiers"), _zeile("admin_identifiers")
assert "NUR als Zusatzfaktor" in _zeile("pin_login"), _zeile("pin_login")
assert not _re.search(r"\| : ", _konf), "`#:`-Doppelpunkt steht noch im Text"
_stumm = _re.findall(r"^\| `([a-z0-9_]+)` .* \| — \|$", _konf, _re.M)
assert not _stumm, ("Diese Config-Felder haben keinen erklärenden Kommentar in config.py:\n  " +
                    "\n  ".join(_stumm[:8]) +
                    "\n  (Kommentar hinter das Feld schreiben, dann neu generieren.)")
# Zeichenklasse mit Ziffern: `saml_idp_x509cert` fiel sonst durch, und der Test
# meldete 118 statt 119 — ein Regex, der fast passt, zählt falsch statt gar nicht.
_zahl = len(_re.findall(r"^\| `[a-z0-9_]+` \|", _konf, _re.M))
from dataclasses import fields as _dc_fields  # noqa: E402
import sys as _sys2  # noqa: E402
_sys2.path.insert(0, ROOT)
from tinysesam import TinySesamConfig as _TSC  # noqa: E402
assert _zahl == len(_dc_fields(_TSC)), (f"KONFIGURATION.md führt {_zahl} Felder, "
                                        f"TinySesamConfig hat {len(_dc_fields(_TSC))}")
print(f"  Konfigurations-Nachschlag: {_zahl} Felder, jedes erklärt, Abzug aktuell")

# ---------- API-Nachschlag: jede eingefrorene Methode erklärt, Abzug aktuell ----------
# 68 der 105 eingefrorenen Methoden kamen in keiner Doku vor. Wer TinySesam einbettet, sah eine
# Zusage („diese Oberfläche bleibt stabil") ohne eine Stelle, an der steht, was sie enthält.
_api = subprocess.run([sys.executable, "scripts/_api_doku.py", "--dry-run"],
                      cwd=ROOT, capture_output=True, text=True)
assert _api.returncode == 0, "API.md ist veraltet — `python3 scripts/_api_doku.py` fahren"
_apidoc = _lies("API.md")
# Methoden `### \`name(…)\``, Properties `### \`name\` — Property …` (seit 0.20.1 eingefroren).
_leer = _re.findall(r"^### `([a-z_][a-z0-9_]*)(?:\(|` — Property).*\n\n—$", _apidoc, _re.M)
assert not _leer, ("Diese Methoden haben keinen Docstring:\n  " + "\n  ".join(_leer[:8]) +
                   "\n  (Eine eingefrorene Methode ohne Erklärung ist eine Zusage ins Blaue.)")
print(f"  API-Nachschlag: {_apidoc.count(chr(10) + '### ')} Einträge, jeder erklärt, Abzug aktuell")

# ---------- Zahlen in den READMEs: nachgemessen statt nachgepflegt ----------
# Der Doku-Abgleich vom 2026-09-21 fand in beiden READMEs Zahlen aus alten Ständen: „17 bzw. 22
# Testdateien" bei tatsächlich 45, „Python 3.10–3.13" bei einer Matrix bis 3.14, „119 Config-Felder"
# nach dem 120. Feld. Eine Zahl, die niemand nachmisst, ist nach dem nächsten Commit falsch — und
# sie steht ausgerechnet im Abschnitt, an dem ein Interessent den Reifegrad abliest.
import glob as _glob  # noqa: E402

_readmes = {"README.md": _lies("README.md"), "i18n/README.de.md": _lies("i18n/README.de.md")}

_soll_tests = len(_glob.glob(os.path.join(ROOT, "tests", "test_*.py")))
for _datei, _text in _readmes.items():
    _genannt = {int(n) for n in _re.findall(r"\*?\*?(\d+)\*?\*? (?:test files|Testdateien)", _text)}
    assert _genannt, f"{_datei} nennt keine Testdateizahl mehr — Muster im Wächter anpassen"
    assert _genannt == {_soll_tests}, (
        f"{_datei} nennt {sorted(_genannt)} Testdateien, es sind {_soll_tests}")
print(f"  READMEs: Testdateizahl stimmt ({_soll_tests})")

# Die Python-Matrix: die READMEs nennen eine Spanne, ci.yml die Liste. Beide müssen dasselbe meinen.
_ci = _lies(".github/workflows/ci.yml")
_matrix = _re.search(r'python-version:\s*\[([^\]]+)\]', _ci)
assert _matrix, "python-version-Matrix in ci.yml nicht gefunden"
_versionen = _re.findall(r'"([\d.]+)"', _matrix.group(1))
_spanne = f"{_versionen[0]}–{_versionen[-1]}"
for _datei, _text in _readmes.items():
    _gefunden = _re.findall(r"Python (\d+\.\d+[–-]\d+\.\d+)", _text)
    assert _gefunden, f"{_datei} nennt keine Python-Spanne mehr — Muster im Wächter anpassen"
    assert set(_gefunden) == {_spanne}, (
        f"{_datei} nennt Python {sorted(set(_gefunden))}, die CI fährt {_spanne}")
print(f"  READMEs: Python-Spanne stimmt ({_spanne})")

# ---------- Kein `pip install tinysesam` vor der Veröffentlichung ----------
# Beide READMEs führten mit `pip install tinysesam` — der Name ist auf PyPI nicht registriert, der
# Befehl endet mit „No matching distribution found". Die erste Zeile, die jemand ausprobiert, darf
# nicht die erste sein, die fehlschlägt. Veröffentlicht wird laut ADR-6 mit 1.0; bis dahin gilt
# ausschliesslich der gepinnte Git-Tag, und dieser Wächter fällt mit dem Sprung auf 1.0 von selbst weg.
from tinysesam import __version__ as _ver  # noqa: E402
if int(_ver.split(".")[0]) < 1:
    for _datei, _text in _readmes.items():
        _pypi = [z.strip() for z in _text.splitlines()
                 if _re.match(r'^\s*pip install ["\']?tinysesam[\[\]a-z,]*["\']?\s*(#.*)?$', z)
                 or _re.match(r'^\s*pip install ["\']?tinysesam[\[\]a-z,]*==', z)]
        assert not _pypi, (
            f"{_datei} zeigt eine PyPI-Installation, TinySesam ist dort aber nicht (bis 1.0):\n  "
            + "\n  ".join(_pypi))
    print("  READMEs installieren über den Git-Tag (PyPI erst ab 1.0)")

# ---------- Die Code-Beispiele der READMEs müssen bauen ----------
# Der allererste Block, den ein neuer Nutzer kopiert, schaltete `oidc_enabled=True` und setzte
# kein `base_url` — und seit der Nacharbeit N1 ist genau das ein `ConfigError` im Konstruktor.
# Die Regel kam, das Beispiel blieb stehen. Das ist dieselbe Klasse Fehler wie
# `pip install tinysesam` eine Prüfung weiter oben: Die erste Zeile, die jemand ausprobiert, war
# die erste, die fehlschlug. Gemessen wird deshalb nicht der Text, sondern der Bau.
#
# Zwei Stufen, weil sie verschieden weit tragen:
#   (1) Jeder `TinySesamConfig(…)`-Aufruf beider READMEs wird gebaut. `TinySesam(cfg)` importiert
#       die Extras nur lazy (es warnt bloss), also läuft diese Stufe auch im Kern-Job ohne [all]
#       — sie ist die Messung, auf die Verlass ist.
#   (2) Jeder VOLLSTÄNDIGE Block (einer mit `from tinysesam import …`) läuft zusätzlich als
#       eigenes Programm in einem Wegwerf-Verzeichnis. Das ist die schärfere Probe (Syntax,
#       Methodennamen, `auth.router()`), braucht aber die Extras, die seine Schalter nennen:
#       `auth.router()` wirft ohne [passkey]/[oidc] einen `MissingExtra`. Fehlt ein Extra, sagt
#       die Zeile es und Stufe (1) bleibt stehen.
#
# `db_path` wird auf ein Wegwerf-Verzeichnis umgebogen, sonst legte der Lauf `app.db` im Repo an.
# Der Pfad ist nicht das, was hier gemessen wird.
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
    """Jeden `TinySesamConfig(…)`-Aufruf als Quelltext — über Klammertiefe, nicht per Regex."""
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
_seclog.setLevel(_log.CRITICAL)          # der Bau warnt über fehlende Extras — hier nur Lärm
_gebaut = 0
try:
    for _datei, _text in _readmes.items():
        for _nr, _block in enumerate(_py_bloecke(_text), 1):
            for _quelle in _config_aufrufe(_block):
                try:
                    _cfg = eval(_quelle, {"TinySesamConfig": TinySesamConfig})   # noqa: S307
                except Exception as _e:
                    raise AssertionError(
                        f"{_datei}, Block {_nr}: `{_quelle.splitlines()[0]}…` lässt sich nicht "
                        f"einmal auswerten — {type(_e).__name__}: {_e}")
                _cfg.db_path = os.path.join(_tmp.mkdtemp(), "beispiel.db")
                try:
                    with _cl.redirect_stderr(_io.StringIO()):     # Erst-Admin-Token an den Betreiber
                        TinySesam(_cfg)
                except _CfgErr as _e:
                    raise AssertionError(
                        f"{_datei}, Block {_nr}: das Beispiel baut nicht.\n  {_quelle[:90]}…\n  "
                        f"ConfigError: {str(_e)[:300]}\n  (Wer es kopiert, kommt nicht über die "
                        f"erste Zeile hinaus — wie beim `pip install` oben.)")
                _gebaut += 1
finally:
    _seclog.setLevel(_vorher)
assert _gebaut >= 12, f"nur {_gebaut} Konfig-Beispiele gefunden — Muster im Wächter anpassen"
print(f"  READMEs: alle {_gebaut} Konfig-Beispiele bauen (ConfigError-frei)")

# Stufe 2 — die vollständigen Blöcke wirklich ausführen.
_ausgefuehrt, _uebersprungen = 0, []
for _datei, _text in _readmes.items():
    for _nr, _block in enumerate(_py_bloecke(_text), 1):
        if "from tinysesam import" not in _block and "import tinysesam" not in _block:
            continue                      # ein Ausschnitt, kein Programm
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
            f"{_datei}, Block {_nr} läuft nicht durch (Exit {_lauf.returncode}):\n"
            + (_lauf.stderr or _lauf.stdout)[-900:])
        _ausgefuehrt += 1
assert _ausgefuehrt + len(_uebersprungen) >= 2, "die READMEs enthalten keine zwei vollständigen Beispiele mehr"
if _uebersprungen:
    # Kein stilles Durchwinken: Stufe 1 hat dieselben Configs gebaut, nur `auth.router()` fehlt.
    print("  (Block nicht ausgeführt, Extra fehlt: " + "; ".join(_uebersprungen) + ")")
else:
    assert _ausgefuehrt >= 2, f"nur {_ausgefuehrt} vollständige Beispiele — Muster anpassen"
print(f"  READMEs: {_ausgefuehrt} vollständige Beispiele laufen im Wegwerf-Verzeichnis durch")

# Kit 0.22.0 (M-1, Stufe 3): Hat jede Prüfung davor etwas GESEHEN? Eine Prüfung über eine
# leere Menge ist immer grün. Muss als LETZTE laufen, sie wertet die Fallzahlen davor aus.
ungesehen = hygiene.pruefe_etwas_gesehen()
assert not ungesehen, "Kit-Prüfung ohne Fall:\n  " + "\n  ".join(ungesehen)
print("  Kit 0.22.0: jede Prüfung hat etwas gesehen")

print("OK test_repo")

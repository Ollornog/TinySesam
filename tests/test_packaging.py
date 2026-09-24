"""Das Paket, wie es beim Nutzer ankommt — nicht die Absicht im `pyproject.toml`.

Seit 1.0 ist PyPI der Installationsweg ([ADR-6](../backlog/ADR-6-pypi-veroeffentlichen.md)).
Damit zählt nicht mehr, was im Repo liegt, sondern was im Wheel und im sdist landet — und die
beiden werden aus verschiedenen Regeln gebaut. Ein Wheel, dem eine Datei fehlt, installiert
sauber und stürzt erst beim Nutzer ab; eine Version, die auf PyPI steht, lässt sich nicht
zurückholen. Beides fällt hier auf, bevor ein Tag gesetzt wird.

Deshalb wird wirklich **gebaut**, statt das `pyproject.toml` zu lesen: Gebaut wird der
versionierte Baum (`git ls-files`) in einer Kopie ausserhalb des Repos — offline, ohne
Bau-Isolierung, damit nichts nachgeladen werden muss und der Arbeitsbaum unberührt bleibt
(die CI prüft danach, dass er es ist).

Gefunden hat dieser Test gleich beim ersten Lauf, wofür er gedacht war: Das sdist enthielt
`tests/test_*.py`, aber weder `tests/run_all.py` noch `tests/_kit/` — eine Suite, die sich
nicht starten lässt. Siehe `MANIFEST.in`.
"""

# Diese Suite liest den Repo-Zustand ueber git. Ohne git ist sie nicht aussagekraeftig —
# eine fehlende Voraussetzung, kein Fehlschlag.
import re as _re_pkg
import shutil  # noqa: E402
from voraussetzung import braucht  # noqa: E402
import pathlib  # noqa: E402

braucht(shutil.which("git"), "git fehlt")
# git im PATH genügt nicht: Gemessen wird gegen `git ls-files`, und das braucht ein
# Repo. Im ausgepackten sdist gibt es keins — dort absagen statt rot werden.
braucht((pathlib.Path(__file__).resolve().parent.parent / ".git").exists(),
        "kein Git-Repo (z.B. ausgepacktes sdist) — der Paket-Test vergleicht gegen `git ls-files`")
import email.parser
import re
import shutil
import os
import sys
import tarfile
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import hygiene  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import _artefakte_normalisieren  # noqa: E402

# Ohne setuptools lässt sich nichts bauen — und ohne Bau prüft dieser Test nichts. Ein
# stilles „übersprungen" wäre hier die schlechteste Antwort: Es sähe grün aus und wäre leer.
try:
    import setuptools
    from setuptools import build_meta
except ImportError:  # pragma: no cover
    print("  setuptools fehlt — ohne Bau-Backend ist diese Suite nicht aussagekräftig.")
    print("  → pip install setuptools wheel")
    sys.exit(1)
# Der SPDX-Lizenzausdruck (PEP 639, T-7) braucht setuptools >= 77. Mit einem älteren scheitert
# der Bau unten mit einer Meldung über `project.license`, die niemand auf die Version bezieht —
# deshalb hier laut und mit dem Grund.
if int(setuptools.__version__.split(".")[0]) < 77:  # pragma: no cover
    print(f"  setuptools {setuptools.__version__} ist zu alt — der Lizenzausdruck braucht >= 77.")
    print("  → pip install -U setuptools")
    sys.exit(1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ok(name):
    print(f"  ✓ {name}")


# Feste Bauzeit für den Reproduzierbarkeits-Vergleich unten. Der Wert ist beliebig — es zählt,
# dass beide Bauläufe denselben sehen, wie im Release-Workflow der Zeitstempel des Commits.
BAUZEIT = 1700000000
GEGRAFTET = ("tests", "examples", "deploy")   # die `graft`-Bäume aus MANIFEST.in


def attrappen_aus_gitignore() -> list[str]:
    """Für jedes Muster aus .gitignore je eine Attrappe in jedem gegrafteten Baum (B4-13)."""
    pfade = []
    for zeile in pathlib.Path(ROOT, ".gitignore").read_text(encoding="utf-8").splitlines():
        muster = zeile.strip()
        if not muster or muster.startswith(("#", "!")) or muster.startswith("/"):
            continue
        name = muster.rstrip("/").replace("*", "attrappe")
        for baum in GEGRAFTET:
            pfade.append(f"{baum}/{name}/attrappe.txt" if muster.endswith("/") else f"{baum}/{name}")
    return pfade


def baue(verschiebung: float = 0.0, attrappen: tuple[str, ...] = (),
         gruppe_schreibt: bool = False) -> tuple[str, str, str]:
    """(verzeichnis, wheel, sdist) — aus einer Kopie der versionierten Dateien.

    `verschiebung` setzt die Datei-Zeitstempel der Kopie um so viele Sekunden anders — so sieht
    ein zweiter Checkout desselben Commits aus. `gruppe_schreibt` gibt jeder Datei g+w, so wie ein
    Checkout unter umask 0002 (Ubuntu/Mint) sie anlegt. `attrappen` legt ungetrackte Dateien dazu,
    so wie sie in einem benutzten Arbeitsbaum liegen.
    """
    arbeit = tempfile.mkdtemp(prefix="tinysesam-pack-")
    quelle, ziel = os.path.join(arbeit, "src"), os.path.join(arbeit, "dist")
    os.makedirs(quelle)
    os.makedirs(ziel)
    for rel in list(hygiene.getrackte_dateien(ROOT)) + list(attrappen):
        pfad = os.path.join(quelle, rel)
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        if rel in attrappen:
            pathlib.Path(pfad).write_text("gehört nicht ins sdist\n", encoding="utf-8")
        else:
            shutil.copy2(os.path.join(ROOT, rel), pfad)
        if verschiebung:
            stempel = os.stat(pfad).st_mtime + verschiebung
            os.utime(pfad, (stempel, stempel))
        # Die Rechte in BEIDE Richtungen setzen: Die Quelle selbst liegt je nach umask schon auf
        # 0664 oder 0644 — nur „g+w dazu" wäre auf einem 0002-Rechner kein Unterschied.
        modus = os.stat(pfad).st_mode
        os.chmod(pfad, (modus | 0o020) if gruppe_schreibt else (modus & ~0o022))

    vorher, sde = os.getcwd(), os.environ.get("SOURCE_DATE_EPOCH")
    try:
        os.chdir(quelle)
        os.environ["SOURCE_DATE_EPOCH"] = str(BAUZEIT)
        whl = build_meta.build_wheel(ziel)
        sdist = build_meta.build_sdist(ziel)
    finally:
        os.chdir(vorher)
        if sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = sde
    # Derselbe Schritt wie im Release-Workflow — ohne ihn hinge das sdist an Zeitstempeln und
    # Rechten des Checkouts, das Wheel an dessen Rechten (umask).
    _artefakte_normalisieren.sdist_normalisieren(os.path.join(ziel, sdist), BAUZEIT)
    _artefakte_normalisieren.wheel_normalisieren(os.path.join(ziel, whl))
    return arbeit, os.path.join(ziel, whl), os.path.join(ziel, sdist)


def kopf(text: bytes):
    return email.parser.BytesParser().parsebytes(text)


ATTRAPPEN = tuple(attrappen_aus_gitignore())
ARBEIT, WHEEL, SDIST = baue(attrappen=ATTRAPPEN)
ZWEITER = None
try:
    with zipfile.ZipFile(WHEEL) as z:
        wheel_dateien = set(z.namelist())
        metadata_name = next(n for n in wheel_dateien if n.endswith(".dist-info/METADATA"))
        META = kopf(z.read(metadata_name))
    with tarfile.open(SDIST) as t:
        sdist_roh = t.getnames()
        praefix = os.path.basename(SDIST)[: -len(".tar.gz")] + "/"
        sdist_dateien = {n[len(praefix):] for n in sdist_roh if n.startswith(praefix)}
        pkg_info = next(n for n in sdist_roh if n.endswith(praefix + "PKG-INFO"))
        PKG = kopf(t.extractfile(pkg_info).read())

    VERSION = META["Version"]
    KLASSEN = META.get_all("Classifier") or []

    # ---------- Wheel: was zur Laufzeit gebraucht wird, ist auch drin ----------
    # Der eigentliche Grund für diese Suite. Heute besteht das Paket nur aus `.py` und
    # `py.typed`; sobald jemand eine Vorlage, ein Bild oder eine Übersetzungsdatei dazulegt,
    # fehlt sie ohne Eintrag in `[tool.setuptools.package-data]` — im Repo sichtbar, im Wheel
    # nicht, und der Fehler entsteht auf einem fremden Rechner.
    paketdateien = [f for f in hygiene.getrackte_dateien(ROOT) if f.startswith("tinysesam/")]
    assert paketdateien, "keine versionierten Dateien unter tinysesam/ gefunden"
    fehlend = [f for f in paketdateien if f not in wheel_dateien]
    assert not fehlend, ("diese versionierten Dateien fehlen im Wheel — ohne Eintrag unter "
                         f"[tool.setuptools.package-data] werden sie nicht mitgepackt: {fehlend}")
    nicht_py = [f for f in paketdateien if not f.endswith(".py")]
    ok(f"Wheel vollständig: {len(paketdateien)} Dateien, davon {len(nicht_py)} ohne .py "
       f"({', '.join(os.path.basename(f) for f in nicht_py)})")

    assert f"tinysesam-{VERSION}.dist-info/entry_points.txt" in wheel_dateien, \
        "das Konsolenkommando `tinysesam` fehlt im Wheel"
    # Seit T-7 (setuptools >= 77, PEP 639) liegt die Lizenz unter `dist-info/licenses/`, und die
    # Metadaten nennen sie als `License-File`. Bis dahin lag sie je nach Bau-Werkzeug direkt im
    # `dist-info` — der Test kannte beide Orte, weil lokal ein älteres setuptools baute.
    lizenzen = [n for n in wheel_dateien if ".dist-info/licenses/" in n and "LICENSE" in n.upper()]
    assert lizenzen, "die Lizenz liegt nicht im Wheel — erwartet unter <name>.dist-info/licenses/LICENSE"
    assert "LICENSE" in (META.get_all("License-File") or []), \
        f"die Metadaten nennen die Lizenzdatei nicht (License-File: {META.get_all('License-File')})"
    ok(f"Wheel enthält Konsolenkommando und Lizenz ({lizenzen[0].split('.dist-info/')[1]})")

    # ---------- Version: eine Zahl, überall dieselbe ----------
    modul = re.search(r'^__version__ = "([^"]+)"',
                      pathlib.Path(ROOT, "tinysesam/__init__.py").read_text(encoding="utf-8"),
                      re.M).group(1)
    assert VERSION == modul == PKG["Version"], (VERSION, modul, PKG["Version"])
    ok(f"Version {VERSION}: Wheel = sdist = tinysesam.__version__")

    # ---------- Der Sperrriegel ist weg, und er darf nicht zurückkommen ----------
    # `Private :: Do Not Upload` liess PyPI jeden Upload ablehnen — richtig, solange nicht
    # veröffentlicht wurde. Seit 1.0 wäre er ein Release, das erst am Index scheitert.
    privat = [k for k in KLASSEN if k.startswith("Private ::")]
    assert not privat, f"Upload-Sperre noch im Paket: {privat}"

    # Der Reifegrad ist kein Gefühl: ab 1.0 sagt das Paket „stabil", davor „Beta".
    haupt = int(VERSION.split(".")[0])
    erwartet = ("Development Status :: 5 - Production/Stable" if haupt >= 1
                else "Development Status :: 4 - Beta")
    assert erwartet in KLASSEN, f"bei Version {VERSION} gehört '{erwartet}' in die Classifier"
    ok(f"keine Upload-Sperre; Reifegrad passt zur Version ({erwartet.split(' :: ')[1]})")

    # ---------- Python-Versionen: Zusage und Prüflauf sind dasselbe ----------
    # Ein Classifier ist ein Versprechen. Eines, das die CI nicht fährt, ist geraten.
    ci = pathlib.Path(ROOT, ".github/workflows/ci.yml").read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[([^\]]+)\]", ci)
    assert matrix, "ci.yml hat keine python-version-Matrix mehr — dann prüft hier niemand mehr mit"
    gefahren = re.findall(r'"(\d+\.\d+)"', matrix.group(1))
    genannt = [k.rsplit(" :: ", 1)[1] for k in KLASSEN
               if re.fullmatch(r"Programming Language :: Python :: \d+\.\d+", k)]
    ungedeckt = [v for v in gefahren if v not in genannt]
    assert not ungedeckt, f"die CI fährt {ungedeckt}, das Paket nennt sie nicht als Classifier"

    untergrenze = re.search(r">=\s*(\d+)\.(\d+)", META["Requires-Python"])
    assert untergrenze, f"Requires-Python ohne Untergrenze: {META['Requires-Python']!r}"
    kleinste = min(tuple(int(x) for x in v.split(".")) for v in genannt)
    assert kleinste == (int(untergrenze.group(1)), int(untergrenze.group(2))), (
        f"Requires-Python sagt {META['Requires-Python']}, der kleinste Classifier nennt "
        f"{'.'.join(str(x) for x in kleinste)}")
    ok(f"Python {META['Requires-Python']}: Classifier {genannt[0]}–{genannt[-1]}, "
       f"CI fährt {', '.join(gefahren)}")

    # ---------- Untergrenzen: der Boden ist gemessen, nicht geraten ----------
    # Ein `>=` ohne Deckel ist eine Zusage an jeden, der eine Fassung festhält (Lockfile,
    # Constraints, Distributionspaket): „ab hier wird es unterstützt". Lag der Boden unter einem
    # Sicherheitsfix, war die Zusage falsch — und niemand merkte es, weil eine Neuinstallation
    # ohnehin das Neueste zieht. Bis 0.18.0 löste die niedrigste erlaubte Auflösung nach
    # authlib 1.3.0, python-multipart 0.0.9 und (über FastAPI) starlette 0.36.3 auf, alle drei
    # mit offenen Advisories (B4-1 aus T-13).
    #
    # Gemessen wird gegen eine Tabelle, nicht gegen das Netz: Ein Test, der OSV befragt, ist
    # weder offline lauffähig noch bei zwei Läufen gleich. Die Tabelle entsteht bei jeder
    # Abhängigkeitsrunde neu (`uv pip compile --resolution=lowest-direct` + OSV-Batch) und wird
    # hier eingefroren. Dieser Test hält also NICHT die Welt aktuell — er hält fest, dass der
    # einmal gemessene Boden nicht wieder abrutscht.
    GEMESSENER_BODEN = {          # Stand 2026-09-22, Quelle OSV.dev
        "fastapi": (0, 133, 0),        # erst ab hier ist starlette >= 1.3.1 erlaubt
        "python-multipart": (0, 0, 31),
        "authlib": (1, 6, 12),         # GHSA-5357-c2jx-v7qh u.a. (Algorithmen-Konfusion)
    }

    def _zahlen(text: str) -> tuple:
        return tuple(int(x) for x in _re_pkg.findall(r"\d+", text))

    gemessen = []
    for zeile in (META.get_all("Requires-Dist") or []):
        # "authlib>=1.6.12; extra == \"oidc\"" → Name, Untergrenze
        anforderung = zeile.split(";", 1)[0].strip()
        treffer = _re_pkg.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*>=\s*([0-9.]+)", anforderung)
        if not treffer:
            continue
        name = treffer.group(1).lower().replace("_", "-")
        if name not in GEMESSENER_BODEN:
            continue
        ist, soll = _zahlen(treffer.group(2)), GEMESSENER_BODEN[name]
        assert ist >= soll, (
            f"{name}>={treffer.group(2)} liegt unter dem gemessenen lückenfreien Boden "
            f"{'.'.join(str(x) for x in soll)} — eine Installation, die die Untergrenze "
            "festhält, bekommt eine Fassung mit bekannter Lücke")
        gemessen.append(name)
    fehlend = sorted(set(GEMESSENER_BODEN) - set(gemessen))
    assert not fehlend, (f"für {fehlend} steht keine `>=`-Untergrenze im Paket — ohne Boden "
                         "installiert der Nutzer, was er gerade festhält")
    # Eine obere Schranke gehört NICHT hierher: Ein Deckel in einer Bibliothek blockiert genau
    # die Aktualisierung, die den nächsten Sicherheitsfix bringt, und vererbt sich an jede App.
    deckel = [z for z in (META.get_all("Requires-Dist") or []) if "<" in z.split(";", 1)[0]]
    assert not deckel, f"obere Schranken im Paket: {deckel} — eine Bibliothek deckelt nicht"
    ok(f"Untergrenzen über dem gemessenen Boden ({', '.join(sorted(set(gemessen)))}), keine obere Schranke")

    # ---------- Die Projektseite im Index ----------
    urls = dict(z.split(", ", 1) for z in (META.get_all("Project-URL") or []))
    for pflicht in ("Homepage", "Documentation", "Repository", "Changelog", "Issues"):
        assert pflicht in urls, f"[project.urls] ohne '{pflicht}' — die Leiste im Index bleibt leer"
        assert urls[pflicht].startswith("https://"), f"{pflicht} zeigt nicht auf https"
    assert META["Summary"] and len(META["Summary"]) > 20, "Kurzbeschreibung fehlt oder ist zu knapp"
    # Die Lizenz steht als SPDX-Ausdruck in den Metadaten (PEP 639) — und NICHT zusätzlich als
    # Classifier: Beides nebeneinander lehnt PEP 639 ab, und der Index zeigt sonst zwei Quellen.
    assert META["License-Expression"] == "MIT", f"License-Expression ist {META['License-Expression']!r}"
    assert not [k for k in KLASSEN if k.startswith("License ::")], "Lizenz-Classifier neben dem SPDX-Ausdruck"
    ok(f"Projektseite vollständig: {', '.join(sorted(urls))}")

    # ---------- Die lange Beschreibung wird gerendert, nicht als Text abgeladen ----------
    # Ohne `Description-Content-Type` zeigt PyPI die README als Rohtext — mit allen Auszeichnungen.
    assert (META["Description-Content-Type"] or "").startswith("text/markdown"), \
        f"Description-Content-Type ist {META['Description-Content-Type']!r}"
    beschreibung = META.get_payload() or ""
    assert len(beschreibung) > 2000, f"die README kam nicht ins Paket ({len(beschreibung)} Zeichen)"
    assert float((META["Metadata-Version"] or "0")) >= 2.1, META["Metadata-Version"]
    ok(f"README als Markdown im Paket ({len(beschreibung) // 1000} kB), "
       f"Metadata {META['Metadata-Version']}")

    # ---------- sdist: die Quelle der Bibliothek, vollständig oder gar nicht ----------
    for pflicht in ("pyproject.toml", "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md",
                    "i18n/README.de.md", "i18n/SECURITY.de.md"):
        assert pflicht in sdist_dateien, f"{pflicht} fehlt im sdist"
    fehlend = [f for f in paketdateien if f not in sdist_dateien]
    assert not fehlend, f"diese Paketdateien fehlen im sdist: {fehlend}"

    # Die Testsuite liegt im sdist — VOLLSTÄNDIG oder gar nicht. setuptools zieht nach einer
    # alten Heuristik nur `tests/test_*.py` hinein, ohne `run_all.py`, ohne `_kit/`, ohne
    # `api_surface.json`: Eine halbe Suite ist schlimmer als keine, weil sie behauptet, man
    # könne das Quellpaket prüfen, und am Import scheitert. `MANIFEST.in` nimmt deshalb `graft
    # tests`. Wer TinySesam neu paketiert, soll den Bau prüfen können — das ist der Sinn eines
    # Quellpakets; die repo-gebundenen Suiten sagen dort von selbst ab (Exit 77).
    tests_drin = {f for f in sdist_dateien if f.startswith("tests/")}
    assert tests_drin, "das sdist enthält keine Testsuite — `graft tests` in MANIFEST.in prüfen"
    for pflicht in ("tests/run_all.py", "tests/voraussetzung.py", "tests/api_surface.json",
                    "tests/_kit/report.py", "tests/_kit/hygiene.py"):
        assert pflicht in tests_drin, (f"{pflicht} fehlt im sdist — ohne diese Datei startet die "
                                       "Suite dort nicht, und eine halbe Suite ist schlimmer als keine")
    # Jede Suite, die der Sammellauf im Repo kennt, muss auch im Quellpaket liegen.
    im_repo = {f"tests/{n}" for n in os.listdir(os.path.join(str(ROOT), "tests"))
              if n.startswith("test_") and n.endswith(".py")}
    fehlende_suiten = sorted(im_repo - tests_drin)
    assert not fehlende_suiten, f"diese Suiten fehlen im sdist: {fehlende_suiten}"
    ok(f"sdist trägt die vollständige Suite ({len(tests_drin)} Dateien, {len(im_repo)} Suiten)")

    # Was die README verlinkt, soll im Quellpaket auch liegen — ein toter Verweis ist in einem
    # Tarball ärgerlicher als im Web, dort gibt es kein GitHub daneben.
    for pflicht in ("examples/showcase.py", "deploy/forward-auth/docker-compose.yml",
                    "deploy/fail2ban/tinysesam-jail.conf"):
        assert pflicht in sdist_dateien, f"{pflicht} fehlt im sdist (in der README verlinkt)"
    muell = sorted(f for f in sdist_dateien | wheel_dateien
                   if "__pycache__" in f or f.endswith((".pyc", ".pyo")))
    assert not muell, f"Bauartefakte im Paket: {muell[:3]}"
    ok(f"sdist: {len(sdist_dateien)} Dateien, Lizenz/CHANGELOG/SECURITY dabei, "
       "keine halbe Testsuite, kein Bytecode")

    # ---------- Was .gitignore ausschliesst, bleibt draussen (B4-13) ----------
    # Gebaut wurde oben MIT einer Attrappe je .gitignore-Muster in jedem gegrafteten Baum — so
    # sieht ein benutzter Arbeitsbaum aus (eine `examples/app.db`, eine `deploy/…/.env`). Der
    # Release baut aus einem frischen Checkout; wer selbst paketiert, nicht.
    assert len(ATTRAPPEN) >= 3 * len(GEGRAFTET), f"zu wenige Attrappen aus .gitignore: {ATTRAPPEN}"
    durchgerutscht = sorted(a for a in ATTRAPPEN if a in sdist_dateien or a in wheel_dateien)
    assert not durchgerutscht, ("gitignorierte Dateien im Paket — Muster in MANIFEST.in "
                                f"nachziehen: {durchgerutscht[:6]}")
    ok(f"keine der {len(ATTRAPPEN)} gitignorierten Attrappen im sdist oder Wheel")

    # ---------- Bit-reproduzierbar: zweiter Checkout, gleiche Prüfsummen (B4-8) ----------
    # Ein zweiter Bau mit anderen Datei-Zeitstempeln und g+w-Rechten — so unterscheiden sich zwei
    # Checkouts desselben Commits (anderer Zeitpunkt, andere umask). Mit gleicher
    # `SOURCE_DATE_EPOCH` müssen Wheel und sdist Byte für Byte gleich sein, sonst kann niemand die
    # veröffentlichte Prüfsumme nachstellen. Bis zur Nachprüfung (A-3) kopierte der zweite Bau die
    # Rechte mit — der Unterschied 0644/0664 im Wheel fiel so nie auf.
    import hashlib  # noqa: E402
    ZWEITER, WHEEL2, SDIST2 = baue(verschiebung=86400.0, attrappen=ATTRAPPEN, gruppe_schreibt=True)

    def _sha(pfad: str) -> str:
        return hashlib.sha256(pathlib.Path(pfad).read_bytes()).hexdigest()

    assert _sha(WHEEL) == _sha(WHEEL2), ("Wheel nicht reproduzierbar (SOURCE_DATE_EPOCH oder "
                                         "die Rechte-Normalisierung wirkt nicht)")
    assert _sha(SDIST) == _sha(SDIST2), ("sdist nicht reproduzierbar — "
                                         "scripts/_artefakte_normalisieren.py greift nicht")
    # Der Release-Workflow macht dasselbe, in dieser Reihenfolge und im selben Schritt: Zeit
    # exportieren, ohne Isolierung bauen, beide Artefakte normalisieren. Ein blosses „kommt irgendwo
    # vor" (bis zur Nachprüfung, A-6) hielt weder die Reihenfolge noch `--no-isolation` fest.
    rel_zeilen = [hygiene.ohne_yaml_kommentar(z).strip() for z in
                  pathlib.Path(ROOT, ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()]
    bau = next((i for i, z in enumerate(rel_zeilen) if re.search(r"-m\s+build\b", z)), None)
    assert bau is not None, "release.yml baut nicht mit `-m build`"
    assert "--no-isolation" in rel_zeilen[bau], f"release.yml baut mit Isolierung: {rel_zeilen[bau]}"
    anfang = max(i for i in range(bau) if re.match(r"^(- )?(name|run|uses):", rel_zeilen[i]))
    ende = next((i for i in range(bau + 1, len(rel_zeilen))
                 if re.match(r"^- (name|uses|run):", rel_zeilen[i])), len(rel_zeilen))
    davor, danach = rel_zeilen[anfang:bau], rel_zeilen[bau + 1:ende]
    assert "export SOURCE_DATE_EPOCH" in davor, "release.yml: SOURCE_DATE_EPOCH nicht vor dem Bau exportiert"
    assert any(re.match(r"^SOURCE_DATE_EPOCH=\"\$\(git log -1 --format=%ct\)\"$", z) for z in davor), \
        "release.yml: SOURCE_DATE_EPOCH nicht aus dem Commit-Zeitstempel"
    assert any("scripts/_artefakte_normalisieren.py" in z and "dist/*.whl" in z and "dist/*.tar.gz" in z
               for z in danach), "release.yml: Wheel und sdist werden nach dem Bau nicht normalisiert"
    ok(f"Wheel und sdist bit-reproduzierbar (sha256 {_sha(SDIST)[:12]}…), Release baut genauso")

    # ---------- Veröffentlicht wird ohne Geheimnis ----------
    # Trusted Publishing (OIDC) statt API-Token: kein Wert im Repo, keiner, der rotiert werden
    # muss, und keiner, den ein Fork-PR abgreifen könnte.
    zeilen = pathlib.Path(ROOT, ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()
    rel = "\n".join(zeilen)
    assert 'tags: ["v*"]' in rel, "veröffentlicht würde ohne Tag — den Knopf drückt ein Mensch"
    assert "id-token: write" in rel, "ohne id-token-Recht gibt es keine OIDC-Identität"
    assert "name: pypi" in rel, ("dem Upload fehlt das Environment `pypi` — es ist der Name, "
                                "den der Publisher auf pypi.org nennt, und der Ort für eine "
                                "zweite Hand vor der Veröffentlichung")

    # Den Schritt selbst ansehen, nicht die ganze Datei: Ein `password:` gibt es hier
    # legitim — beim Anmelden an der Container-Registry. Nur der PyPI-Schritt darf keins haben.
    i = next((n for n, z in enumerate(zeilen) if "pypa/gh-action-pypi-publish" in z), None)
    assert i is not None, "das Release veröffentlicht nicht nach PyPI"

    # Geprüft wird die GANZE Datei, nicht nur „der Block unter der uses-Zeile".
    #
    # Die erste Fassung schnitt den Schritt an der Einrückung der `uses:`-Zeile ab. Steht dort
    # wie üblich ein `name:` davor, rückt `uses:` eine Ebene tiefer — und alles darunter,
    # inklusive eines `password: ${{ secrets.PYPI_API_TOKEN }}`, galt als „nicht mehr im
    # Schritt". Der gewöhnlichste YAML-Umbau schaltete die Prüfung also stumm ab. Vor einer
    # Erstveröffentlichung ist das der teuerste denkbare Fehlalarm-in-Gegenrichtung: Sie meldet
    # grün, während ein Token im Workflow steht.
    #
    # Ein Token gehört nirgends in diese Datei, also braucht es die Abgrenzung gar nicht.
    for verboten in ("PYPI_API_TOKEN", "TWINE_", "TWINE_PASSWORD", "twine upload"):
        treffer = [f"Zeile {n + 1}: {z.strip()}" for n, z in enumerate(zeilen) if verboten in z]
        assert not treffer, (f"'{verboten}' im Release-Workflow: {treffer} — Trusted Publishing "
                             "braucht kein Geheimnis")
    # `password:` kommt in Kommentaren vor (die Datei erklärt, warum es keins gibt) — deshalb
    # nur echte YAML-Zuweisungen. Ausgenommen ist `secrets.GITHUB_TOKEN`: Der wird von GitHub
    # je Lauf erzeugt, ist kein gepflegtes Geheimnis und meldet hier das Abbild an GHCR an.
    pw_zeilen = [f"Zeile {n + 1}: {z.strip()}" for n, z in enumerate(zeilen)
                 if _re_pkg.match(r"^\s*password\s*:", z) and "secrets.GITHUB_TOKEN" not in z]
    assert not pw_zeilen, (f"`password:` im Release-Workflow: {pw_zeilen} — Trusted Publishing "
                           "braucht kein Geheimnis")
    ok("Release veröffentlicht per Trusted Publishing, nur auf einen Tag hin, ohne Geheimnis")

finally:
    shutil.rmtree(ARBEIT, ignore_errors=True)
    if ZWEITER:
        shutil.rmtree(ZWEITER, ignore_errors=True)

print("OK test_packaging")

"""Der Dependabot-Auto-Merge-Workflow eines Repos — aus der Vorlage gebaut und gegen sie geprüft.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.

WARUM (PO 2026-10-11, alle Repos: „alles automatisch mergen solange tests grün … auch majors“):
Bis dahin trug jedes Repo seine eigene Fassung des Workflows. Zehn Fassungen derselben Logik
laufen auseinander — TinySesam wartete auf alle Pflicht-Workflows, die anderen mergten beim
ersten grünen; TinySesam ließ Majors durch, die anderen nicht. Jetzt gibt es eine Vorlage
(`vorlage_dependabot_auto_merge.yml.in`), und je Repo frei sind nur zwei Werte:

    AUTO_OEKO          Ökosysteme, die ein Pflicht-Check wirklich abnimmt
    PFLICHT_WORKFLOWS  Workflows (Dateinamen), deren Jobs das Repo als Abnahme gelten lässt
    DOKU_PR            optional "aus": keine Doku-Schnellspur (Zweige doku/…, backlog) in diesem Repo
    DOKU_SPRACHE       optional "de" (since 0.53.0): the language rule of the docs fast lane accepts German docs
                       (root README/CHANGELOG, docs/); the backlog stays English

Alles andere leitet `rendere()` aus den Workflows des Repos ab: den Auslöser (`workflows:` =
deren `name:`) und den Nachlauf (jeder Workflow, den ein Push auf den Standardzweig startet).
`pruefe()` baut den Workflow mit den Werten aus der Datei neu und vergleicht — weicht etwas ab,
hat jemand die Logik von Hand geändert oder einen Workflow umbenannt, ohne nachzuziehen.

Zusätzlich die Bedingungen, ohne die die Vorlage still falsch wird:
  - Ein Pflicht-Workflow läuft auf `pull_request` OHNE Pfadfilter. Sonst gibt es für manche PRs
    nie einen Lauf, und der Merge wartet ewig (Skip ist kein Grün).
  - Jeder Nachlauf-Workflow kennt `workflow_dispatch` — sonst kann ihn der Nachlauf nicht anstoßen.

PINS DER VORLAGE (seit 0.36.0, W8): Die Vorlage nennt ihre Actions nur als Platzhalter
`@@PIN:<owner>/<action>@@`. Den Pin liefert der Spiegel `vorlage_actions.yml` neben ihr — in repokit ein
echter Workflow (`.github/workflows/vorlage-actions.yml`), den Dependabot dort hebt und der nach dem
Merge den neuen Pin abnimmt. Vorher stand der SHA wörtlich in der Vorlage: Dependabot hob ihn in jedem
Ziel-Repo, die Datei wich danach von der Vorlage ab, und der PR wurde nie grün. In den
Ziel-Repos ignoriert Dependabot diese Actions deshalb (`pruefe` verlangt das); der neue Pin kommt mit
dem nächsten `repokit sync`.

stdlib-only: kein YAML-Parser. Gelesen wird nur der Kopf (`on:`) und `name:` — Einrückung und
die üblichen Schreibweisen (Block, Liste, Einzelwort).
"""
from __future__ import annotations

import hashlib
import json
import os
import re

WORKFLOW = ".github/workflows/dependabot-auto-merge.yml"
# `.yml.in`, nicht `.yml` (0.30.1): Mit Platzhaltern ist die Vorlage kein gültiges YAML, und ein
# YAML-Lint über alle *.yml eines Repos (ci-infra) wurde daran rot.
VORLAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vorlage_dependabot_auto_merge.yml.in")
# Der Spiegel der Pins (siehe Kopf). In repokit ein Symlink auf den Workflow, den Dependabot hebt.
SPIEGEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vorlage_actions.yml")
SPIEGEL_WORKFLOW = ".github/workflows/vorlage-actions.yml"
PIN_PLATZHALTER = re.compile(r"@@PIN:([\w.-]+/[\w./-]+?)@@")
PIN_ZEILE = re.compile(r"^\s*(?:-\s+)?uses:\s*(([\w.-]+/[\w./-]+?)@[0-9a-f]{40}(?:\s+#.*)?)\s*$")
# Load note at failure (0.64.0): one source, scripts/_load_note.sh (kit/scripts in repokit, scripts/ in a repo — both two
# levels above this file). The templates have no checkout, so its body is rendered into their read-only jobs.
LASTVERMERK = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           "scripts", "_load_note.sh")
# The grype image of the weekly rebuild check (0.64.0): a Dockerfile, so that Dependabot (docker) raises it in repokit.
# `grype.Dockerfile`, not `grype/Dockerfile`: Dependabot (docker) matches any name containing "dockerfile", the kit's Go
# check (`pruefe_dependabot_go`) and a repo's own coverage tests look for files named `Dockerfile*` — a synced
# `Dockerfile` would demand a Dependabot entry in every repo, and a bump there would break the manifest.
GRYPE_DATEI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grype.Dockerfile")
GRYPE_ZEILE = re.compile(r"^FROM (anchore/grype:v[0-9.]+@sha256:[0-9a-f]{64})\s*$", re.M)
ANFANG = "          # --- je Repo: Anfang\n"
ENDE = "          # --- je Repo: Ende\n"
STANDARDZWEIGE = ("main", "master")


def _zeilen(text: str) -> list[str]:
    """Zeilen nur an \\n — wie grep und Editor zählen (nicht splitlines(), das auch an U+2028 trennt)."""
    z = [t.rstrip("\r") for t in text.split("\n")]
    return z[:-1] if z and z[-1] == "" else z


def _lies(pfad: str) -> str | None:
    try:
        with open(pfad, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _workflows(root: str) -> dict[str, str]:
    """Dateiname -> Inhalt, ohne den Auto-Merge selbst."""
    verz = os.path.join(root, ".github", "workflows")
    aus: dict[str, str] = {}
    if not os.path.isdir(verz):
        return aus
    for name in sorted(os.listdir(verz)):
        if name.endswith((".yml", ".yaml")) and name != os.path.basename(WORKFLOW):
            text = _lies(os.path.join(verz, name))
            if text is not None:
                aus[name] = text
    return aus


def _name(text: str) -> str | None:
    m = re.search(r"^name:\s*(.+?)\s*$", text, re.M)
    if not m:
        return None
    return re.sub(r"\s+#.*$", "", m.group(1)).strip().strip("\"'")


def ausloeser(text: str) -> dict[str, list[str]]:
    """Die Auslöser aus dem `on:`-Kopf: Ereignis -> Zeilen seines Blocks (ohne Kommentare).

    `on: push` und `on: [push, pull_request]` ergeben Ereignisse ohne Zeilen.
    """
    zeilen = _zeilen(text)
    for i, z in enumerate(zeilen):
        m = re.match(r"^(?:on|\"on\"|'on'):\s*(.*?)\s*(?:#.*)?$", z)
        if not m:
            continue
        rest = m.group(1)
        if rest.startswith("["):
            return {e.strip(): [] for e in rest.strip("[]").split(",") if e.strip()}
        if rest:
            return {rest: []}
        aus: dict[str, list[str]] = {}
        aktuell = None
        for z2 in zeilen[i + 1:]:
            if not z2.strip() or z2.lstrip().startswith("#"):
                continue
            if not z2.startswith(" "):
                break
            tiefe = len(z2) - len(z2.lstrip())
            inhalt = re.sub(r"\s+#.*$", "", z2.strip())
            if tiefe == 2:
                aktuell = inhalt.split(":", 1)[0].strip()
                aus[aktuell] = []
                rest2 = inhalt.split(":", 1)[1].strip() if ":" in inhalt else ""
                if rest2 and rest2 not in ("", "{}", "null"):
                    aus[aktuell].append(rest2)
            elif aktuell is not None:
                aus[aktuell].append(inhalt)
        return aus
    return {}


def laeuft_auf_standardzweig(text: str) -> bool:
    """Startet ein Push auf main/master diesen Workflow?"""
    push = ausloeser(text).get("push")
    if push is None:
        return False
    block = " ".join(push)
    if "branches" in block:
        return any(re.search(rf"(?<![\w/-]){z}(?![\w/-])", block) for z in STANDARDZWEIGE)
    # Nur `tags:` (oder `tags-ignore:`) heißt: kein Zweig-Push.
    return not re.search(r"\btags(-ignore)?\s*:", block)


def pins(text: str | None = None) -> dict[str, str]:
    """Action -> `owner/action@<sha>  # vX` aus dem Spiegel (Vorgabe: die Datei neben der Vorlage)."""
    if text is None:
        text = _lies(SPIEGEL) or ""
    aus: dict[str, str] = {}
    for z in _zeilen(text):
        m = PIN_ZEILE.match(z)
        if m:
            aus.setdefault(m.group(2), m.group(1).rstrip())
    return aus


def vorlagen_actions() -> list[str]:
    """Die Actions, die die Vorlage über einen Platzhalter nennt."""
    return sorted(set(PIN_PLATZHALTER.findall(_lies(VORLAGE) or "")))


def _dependabot_actions_bloecke(text: str) -> list[tuple[int, list[str]]]:
    """(Zeilennummer, Zeilen) je `updates:`-Eintrag mit `package-ecosystem: github-actions`.

    Die Einträge sind die Listenpunkte direkt unter `updates:` (gleicher Einzug wie der erste); ein Eintrag
    reicht bis zum nächsten Punkt dieses Einzugs oder bis zur ersten Zeile mit kleinerem Einzug.
    """
    zeilen = _zeilen(text)
    try:
        kopf = next(i for i, z in enumerate(zeilen) if re.match(r"^updates\s*:\s*(?:#.*)?$", z))
    except StopIteration:
        return []
    starts: list[int] = []
    einzug = None
    ende = len(zeilen)
    for i in range(kopf + 1, len(zeilen)):
        z = zeilen[i]
        if not z.strip() or z.lstrip().startswith("#"):
            continue
        tiefe = len(z) - len(z.lstrip())
        if einzug is None:
            if not z.lstrip().startswith("- "):
                return []
            einzug = tiefe
        if tiefe < einzug or (tiefe == einzug and not z.lstrip().startswith("- ")):
            ende = i
            break
        if tiefe == einzug:
            starts.append(i)
    bloecke = []
    for n, st in enumerate(starts):
        block = zeilen[st:(starts[n + 1] if n + 1 < len(starts) else ende)]
        if any(re.match(r"^\s*(?:-\s+)?package-ecosystem:\s*[\"']?github-actions[\"']?\s*(?:#.*)?$", z)
               for z in block):
            bloecke.append((st + 1, block))
    return bloecke


def _ignoriert(block: list[str], action: str) -> bool:
    """Ignoriert dieser Dependabot-Eintrag `action` VOLLSTÄNDIG (ohne versions/update-types)?"""
    for i, z in enumerate(block):
        m = re.match(r"^(\s*)-\s+dependency-name:\s*[\"']?([^\"'\s#]+)[\"']?\s*(?:#.*)?$", z)
        if not m or m.group(2) != action:
            continue
        einzug = len(m.group(1))
        for z2 in block[i + 1:]:
            if not z2.strip() or z2.lstrip().startswith("#"):
                continue
            tiefe = len(z2) - len(z2.lstrip())
            if tiefe <= einzug:
                break
            if re.match(r"^\s*(versions|update-types)\s*:", z2):
                return False
        return True
    return False


def pruefe_dependabot(root: str) -> list[str]:
    """Hebt Dependabot hier einen Pin, den die Vorlage besitzt? Dann bräche jeder solche PR die Vorlage.

    Im Ziel-Repo muss jeder `github-actions`-Eintrag die Vorlagen-Actions ignorieren; im Haus des
    Spiegels (repokit) darf er es gerade NICHT — dort soll Dependabot sie heben.
    """
    text = _lies(os.path.join(root, ".github", "dependabot.yml"))
    if text is None:
        return []
    spiegel_hier = os.path.exists(os.path.join(root, SPIEGEL_WORKFLOW))
    fehler = []
    for nr, block in _dependabot_actions_bloecke(text):
        for action in vorlagen_actions():
            ign = _ignoriert(block, action)
            if spiegel_hier and ign:
                fehler.append(f".github/dependabot.yml:{nr}: ignoriert {action} — hier liegt der Spiegel "
                              f"{SPIEGEL_WORKFLOW}, Dependabot soll den Pin genau hier heben")
            elif not spiegel_hier and not ign:
                fehler.append(f".github/dependabot.yml:{nr}: github-actions ignoriert {action} nicht — den Pin "
                              f"besitzt die repokit-Vorlage; ein Bump hier wiche von ihr ab, und der PR würde nie grün. "
                              f"Eintragen: `ignore: [{{dependency-name: \"{action}\"}}]` (der neue Pin kommt mit "
                              f"`repokit sync`)")
    return fehler


# `runs-on: self-hosted` oder `runs-on: [self-hosted, …]` (Block-Liste `- self-hosted` ebenso) — Kommentare zählen nicht.
EIGENER_RUNNER = re.compile(r"^\s*runs-on:\s*(?:\[\s*)?[\"']?self-hosted(?![\w-])|^\s*runs-on:\s*\n\s*-\s*[\"']?self-hosted(?![\w-])", re.M)


def runner(wfs: dict[str, str]) -> str:
    """`runs-on` der Vorlage (seit 0.51.0): `self-hosted`, wenn ein anderer Workflow des Repos auf eigenen Runnern
    läuft (dann ist es privat — öffentliche Repos laufen nie dort, ci-policy), sonst `ubuntu-latest`.

    Abgeleitet statt eingetragen: Ein neuer Wert im Block je Repo käme nur mit Handarbeit in jedes Repo, und ein
    vergessener Eintrag kostete still GitHub-Minuten.
    """
    return "self-hosted" if any(EIGENER_RUNNER.search(t) for t in wfs.values()) else "ubuntu-latest"


def nachlauf(root: str) -> list[str]:
    return [n for n, t in _workflows(root).items() if laeuft_auf_standardzweig(t)]


def rendere(root: str, je_repo: str) -> tuple[str, list[str]]:
    """Den Workflow für dieses Repo bauen. `je_repo` ist der freie Block (eingerückte env-Zeilen).

    Gibt (Text, Probleme) zurück; Probleme sind Bedingungen, ohne die die Vorlage still falsch wird.
    """
    probleme: list[str] = []
    vorlage = _lies(VORLAGE)
    if vorlage is None:
        return "", [f"Vorlage fehlt: {VORLAGE}"]
    wfs = _workflows(root)
    m = re.search(r'PFLICHT_WORKFLOWS:\s*"([^"]*)"', je_repo)
    pflicht = m.group(1).split() if m else []
    if not pflicht:
        probleme.append("PFLICHT_WORKFLOWS fehlt oder ist leer")
    if not re.search(r'AUTO_OEKO:\s*"[^"]*"', je_repo):
        probleme.append("AUTO_OEKO fehlt")
    namen = []
    for wf in pflicht:
        text = wfs.get(wf)
        if text is None:
            probleme.append(f"Pflicht-Workflow {wf} gibt es nicht")
            continue
        n = _name(text)
        if not n:
            probleme.append(f"{wf}: kein `name:` — `workflow_run` braucht ihn")
            continue
        namen.append(n)
        pr = ausloeser(text).get("pull_request")
        if pr is None:
            probleme.append(f"{wf} läuft nicht auf `pull_request` — er nimmt keinen PR ab")
        elif re.search(r"\bpaths(-ignore)?\s*:", " ".join(pr)):
            probleme.append(f"{wf}: `pull_request` mit Pfadfilter — manche PRs bekämen nie einen Lauf")
    probleme += release_automatik(root, je_repo, wfs)
    # Doku-Schnellspur (seit 0.52.0): an ist der Normalfall, abschalten mit genau "aus" — jeder andere Wert wäre
    # still „an“ (die Vorlage fragt nur `!= aus`), also kein Tippfehler, der still nichts tut.
    doku = _wert(je_repo, "DOKU_PR")
    if doku is not None and doku != "aus":
        probleme.append(f'DOKU_PR "{doku}": nur "aus" (abschalten) — ohne den Eintrag ist die Doku-Schnellspur an')
    # German docs per repo (since 0.53.0, PO 2026-11-22): exactly "de". The template asks `= de`, so any other value
    # ("DE", "deutsch", "en") would silently do nothing — a typo must not pass as a switch.
    # Quoted or not: YAML reads `DOKU_SPRACHE: de` as the string too, so an unquoted typo must not slip past.
    ms = re.search(r'^\s*DOKU_SPRACHE:[ \t]*(.*?)[ \t]*(?:#.*)?$', je_repo, re.M)
    sprache = ms.group(1) if ms else None
    if sprache is not None and sprache not in ('"de"', "'de'", "de"):
        probleme.append(f'DOKU_SPRACHE "{sprache}": only "de" (German docs allowed) — without the entry docs are English')
    nach = nachlauf(root)
    # Abnahme nach dem Merge (seit 0.32.0): Jede so eingetragene Action muss in einem Workflow stehen,
    # den der Nachlauf auf dem Standardzweig startet — sonst nähme sie gar nichts ab, und ihr Update
    # mergte ungeprüft. (Tag-Workflows zählen nicht: Die laufen erst beim nächsten Release.)
    mn = re.search(r'NACH_MERGE_ABGENOMMEN:\s*"([^"]*)"', je_repo)
    for action in (mn.group(1).split() if mn else []):
        muster = re.compile(r"uses:\s*" + re.escape(action) + r"(/[^@\s]*)?@")
        if not any(muster.search(wfs[wf]) for wf in nach):
            probleme.append(f"NACH_MERGE_ABGENOMMEN: {action} läuft in keinem Nachlauf-Workflow "
                            f"({', '.join(nach) or 'keiner'}) — nach dem Merge nähme sie nichts ab")
    for wf in nach:
        if "workflow_dispatch" not in ausloeser(wfs[wf]):
            probleme.append(f"{wf} läuft auf dem Standardzweig, kennt aber kein `workflow_dispatch` "
                            f"— der Nachlauf kann ihn nicht anstoßen")
    workflows = "[" + ", ".join(f'"{n}"' for n in namen) + "]"
    nachlauf_zeilen = "".join(
        f'          gh workflow run {wf} --repo "$REPO" --ref "$STANDARD"\n' for wf in nach)
    gepinnt = pins()
    def pin(m: re.Match) -> str:
        if m.group(1) not in gepinnt:
            probleme.append(f"Vorlage nennt {m.group(1)}, der Spiegel {os.path.basename(SPIEGEL)} pinnt es nicht")
            return m.group(0)
        return gepinnt[m.group(1)]
    vorlage = PIN_PLATZHALTER.sub(pin, vorlage)
    text = (vorlage.replace("@@WORKFLOWS@@", workflows)
            .replace("@@JE_REPO@@\n", je_repo if je_repo.endswith("\n") else je_repo + "\n")
            .replace("@@NACHLAUF@@\n", nachlauf_zeilen)
            .replace("@@RUNNER@@", runner(wfs))
            .replace("@@NEUBAU_CRON@@\n", neubau_cron(root, je_repo))
            .replace("@@GRYPE@@", grype_bild(probleme))
            .replace("@@LASTVERMERK@@\n", lastvermerk_schritt(probleme)))
    return text, probleme


def lastvermerk_schritt(probleme: list[str]) -> str:
    """The step `if: failure()` with the body of scripts/_load_note.sh (between `# >>> body` and `# <<< body`)."""
    text = _lies(LASTVERMERK)
    m = re.search(r"^# >>> body\n(.*?)^# <<< body$", text or "", re.S | re.M)
    if not m:
        probleme.append(f"load note missing or without body markers: {LASTVERMERK}")
        return ""
    rumpf = "".join(f"          {z}\n" if z.strip() else "\n" for z in _zeilen(m.group(1)))
    return ("      - name: Load at failure (from scripts/_load_note.sh)\n"
            "        if: failure()\n"
            "        run: |\n" + rumpf)


def grype_bild(probleme: list[str]) -> str:
    """`anchore/grype:v…@sha256:…` from tests/_kit/grype.Dockerfile."""
    m = GRYPE_ZEILE.search(_lies(GRYPE_DATEI) or "")
    if not m:
        probleme.append(f"grype pin missing: {GRYPE_DATEI} needs `FROM anchore/grype:v<version>@sha256:<digest>`")
        return "@@GRYPE@@"
    return m.group(1)


WOCHENTAGE = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def neubau_zeit(abbild: str) -> tuple[int, int, int]:
    """(weekday 1–5, hour 6–13 UTC, minute) of the weekly rebuild check, spread by the image name (stable in every
    working tree, unlike the folder name): Monday to Friday, 07:00–14:59 Berlin in winter, 08:00–15:59 in summer."""
    # sha256, not crc32: for the fleet's image names (same prefix) crc32 put four of seven repos on the same Friday.
    c = int.from_bytes(hashlib.sha256(abbild.encode("utf-8")).digest()[:8], "big")
    return 1 + c % 5, 6 + (c // 5) % 8, (c // 40) % 60


def neubau_cron(root: str, je_repo: str) -> str:
    """The weekly cron entry (with its time comment) for a repo with release automation and own images, else ""."""
    if _wert(je_repo, "APP_PR") != "release":
        return ""
    try:
        konfig = json.loads(_lies(os.path.join(root, ".github", "release-automatik.json")) or "{}")
    except ValueError:
        return ""
    abbilder = konfig.get("abbilder") or [] if isinstance(konfig, dict) else []
    if not abbilder or not isinstance(abbilder[0], str):
        return ""
    tag, stunde, minute = neubau_zeit(abbilder[0])
    return (f"    # Weekly rebuild check: {WOCHENTAGE[tag]} {stunde:02d}:{minute:02d} UTC = {stunde + 1:02d}:{minute:02d} "
            f"Europe/Berlin in winter, {stunde + 2:02d}:{minute:02d} in summer (spread by the image name).\n"
            f'    - cron: "{minute} {stunde} * * {tag}"\n')


def _wert(je_repo: str, name: str) -> str | None:
    m = re.search(rf'^\s*{name}:\s*"([^"]*)"', je_repo, re.M)
    return m.group(1) if m else None


def release_automatik(root: str, je_repo: str, wfs: dict[str, str]) -> list[str]:
    """Bedingungen der Release-Automatik (seit 0.45.0), ohne die sie still nichts täte.

    `APP_PR: "release"` und `ABBILD_PFADE` verlangen ein `release.yml`, das `automatik` und `version` als Eingaben von
    `workflow_dispatch` kennt (sonst schlägt der Anstoß nach dem Merge fehl), die Konfiguration
    `.github/release-automatik.json` und `scripts/_release_automatik.py`. `APP_PR: "pin"` verlangt `PIN_PRAEFIX`
    (registry/owner/), sonst nähme die Diff-Prüfung jede Zeile an oder keine. `PIN_ANHAENGE` (seit 0.48.0) nur mit
    `APP_PR: "pin"` und in der Form `<owner/repo>=<ordner>:<datei|*>`.
    """
    probleme: list[str] = []
    art = _wert(je_repo, "APP_PR")
    abbild = _wert(je_repo, "ABBILD_PFADE")
    if art not in (None, "release", "pin"):
        probleme.append(f'APP_PR "{art}": release oder pin')
    if abbild is not None and art != "release":
        probleme.append('ABBILD_PFADE ohne APP_PR: "release" — den Release-PR der Automatik nähme niemand an')
    if abbild is not None and not abbild.split():
        probleme.append("ABBILD_PFADE ist leer")
    if art == "release":
        if not (_wert(je_repo, "RELEASE_DATEIEN") or "").split():
            probleme.append('APP_PR: "release" ohne RELEASE_DATEIEN — der Release-PR dürfte keine Datei ändern')
        rel = wfs.get("release.yml")
        if rel is None:
            probleme.append('APP_PR: "release" ohne .github/workflows/release.yml')
        else:
            block = " ".join(ausloeser(rel).get("workflow_dispatch", []))
            for eingabe in ("automatik", "version"):
                if not re.search(rf"(^|\s){eingabe}:", block):
                    probleme.append(f"release.yml: workflow_dispatch ohne Eingabe `{eingabe}` — der Anstoß der "
                                    "Release-Automatik schlüge fehl")
        for pfad in (".github/release-automatik.json", "scripts/_release_automatik.py"):
            if not os.path.exists(os.path.join(root, pfad)):
                probleme.append(f'APP_PR: "release" ohne {pfad}')
    if art == "pin":
        praefix = _wert(je_repo, "PIN_PRAEFIX") or ""
        if not re.fullmatch(r"[a-z0-9.-]+/[a-z0-9._-]+/", praefix):
            probleme.append(f'APP_PR: "pin" ohne gültiges PIN_PRAEFIX (registry/owner/, ist "{praefix}")')
    anhaenge = _wert(je_repo, "PIN_ANHAENGE")
    if anhaenge is not None:
        # Release-Anhänge im Pin-PR (seit 0.48.0): nur mit APP_PR pin, jeder Eintrag <owner/repo>=<ordner>:<datei|*>.
        if art != "pin":
            probleme.append('PIN_ANHAENGE ohne APP_PR: "pin" — den Pin-PR nähme niemand an')
        if not anhaenge.split():
            probleme.append("PIN_ANHAENGE ist leer")
        for e in anhaenge.split():
            m = re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+=([A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*)"
                             r":(\*|[A-Za-z0-9._-]+)", e)
            if not m:
                probleme.append(f"PIN_ANHAENGE: {e!r} nicht in der Form <owner/repo>=<ordner>:<datei|*>")
    return probleme


APP_TOKEN_ACTION = "actions/create-github-app-token"


def app_token_pins(wfs: dict[str, str]) -> list[str]:
    """Every workflow with the app token action pins it by SHA with a version comment (0.49.1; findings).

    Dependabot does not raise this action in a target repo (the template owns the pin, `pruefe_dependabot`), so a tag
    (`@v3`) or a pin without comment would never be noticed. All workflows are checked (release.yml, image.yml, …), not
    only the auto-merge workflow, which `rendere` keeps line-equal to the template anyway.

    Since 0.65.0 a SHA pin that merely differs from the template's pin is no finding here but a warning
    (`pin_warnungen`): `repokit sync` must not touch a repo's own workflows (the repokit guard may push exactly the two
    kit-rendered workflows, PO 2026-11-24), so with the strict check every kit release that raised the pin turned the
    sync PR of every repo with a release.yml red (kit 0.64.0, v3.3.0 → v3.4.0).
    """
    probleme: list[str] = []
    for name, text in sorted(wfs.items()):
        if name == os.path.basename(WORKFLOW):
            continue
        for z in _zeilen(text):
            if z.lstrip().startswith("#"):
                continue
            m = re.match(r"^\s*(?:-\s+)?uses:\s*" + re.escape(APP_TOKEN_ACTION) + r"(@\S*)?(.*)$", z)
            if not m:
                continue
            ist = f"{APP_TOKEN_ACTION}{m.group(1) or ''}{m.group(2)}".rstrip()
            if not re.fullmatch(re.escape(APP_TOKEN_ACTION) + r"@[0-9a-f]{40}  # v\d\S*", ist):
                probleme.append(f"{name}: `{ist}` ist kein SHA-Pin mit Versionskommentar (`@<40 Hex>  # vX.Y.Z`)")
    return probleme


def _version(pin: str) -> tuple[int, ...] | None:
    """`(3, 4, 0)` from a pin's version comment `# v3.4.0`; None without a readable version."""
    m = re.search(r"#\s*v(\d+(?:\.\d+)*)", pin)
    return tuple(int(t) for t in m.group(1).split(".")) if m else None


def _hebt(ist: str, soll: str) -> bool:
    """Does the kit pin raise this pin? Only to a strictly higher version — a sync never lowers a pin (0.66.0)."""
    alt, neu = _version(ist), _version(soll)
    return alt is not None and neu is not None and neu > alt


def _fremde_pins(root: str) -> list[tuple[str, int, str, str]]:
    """(workflow, line index, current pin, template pin) for every SHA pin of a template action that differs.

    Only a repo's own workflows (not the auto-merge workflow, which `rendere` builds) and only lines in the exact pin
    form `<action>@<40 hex>  # v…` — anything else is a finding of `app_token_pins`, never rewritten by guessing.
    """
    soll_pins = pins()
    aus: list[tuple[str, int, str, str]] = []
    for name, text in sorted(_workflows(root).items()):
        for i, z in enumerate(_zeilen(text)):
            m = PIN_ZEILE.match(z)
            if not m or m.group(2) not in soll_pins:
                continue
            ist, soll = m.group(1).rstrip(), soll_pins[m.group(2)]
            if ist != soll and re.fullmatch(re.escape(m.group(2)) + r"@[0-9a-f]{40}  # v\d\S*", ist):
                aus.append((name, i, ist, soll))
    return aus


def pin_warnungen(root: str) -> list[str]:
    """Warnings (never a failure, since 0.65.0): a repo's own workflow pins a template action differently from the kit.

    Dependabot ignores these actions in the target repo (`pruefe_dependabot`), so without this line the pin would age
    silently. Since 0.66.0 `repokit sync` raises an older pin; what is left here is a pin the kit does not raise (its
    own version is the same or newer, or unreadable).
    """
    aus = []
    for name, i, ist, soll in _fremde_pins(root):
        was = ("`repokit sync` raises it" if _hebt(ist, soll)
               else "not raised (same or newer version, or no version to compare) — check it by hand")
        aus.append(f".github/workflows/{name}:{i + 1}: `{ist}` differs from the kit pin `{soll}` — {was}")
    return aus


def pins_heben(root: str) -> list[str]:
    """Raise every older SHA pin of a template action in the repo's own workflows to the kit pin (since 0.65.0).

    Only the pin itself is replaced (indentation, `- `, the rest of the line, line endings stay); a pin with the same
    or a newer version is never lowered (0.66.0). Returns the changed workflow paths. Called by `repokit sync` (since
    0.66.0, PO 2026-11-24 "yes, but strict") and `repokit automerge`. The repokit guard pushes such a diff only when
    `pin_diff_befunde` confirms that every changed line is exactly such a raised pin line (`repokit pins --pruefe`).
    """
    geaendert: list[str] = []
    je_datei: dict[str, list[tuple[int, str, str]]] = {}
    for name, i, ist, soll in _fremde_pins(root):
        if _hebt(ist, soll):
            je_datei.setdefault(name, []).append((i, ist, soll))
    for name, treffer in je_datei.items():
        pfad = os.path.join(root, ".github", "workflows", name)
        try:            # newline="": CRLF stays CRLF — only the pin may change, not every line ending of the file
            with open(pfad, encoding="utf-8", newline="") as fh:
                zeilen = fh.read().split("\n")
        except OSError:
            continue
        for i, ist, soll in treffer:
            zeilen[i] = zeilen[i].replace(ist, soll, 1)
        with open(pfad, "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(zeilen))
        geaendert.append(f".github/workflows/{name}")
    return geaendert


# A path whose diff `pin_diff_befunde` may confirm: a workflow file directly in .github/workflows/.
PIN_DIFF_PFAD = re.compile(r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml")
_DIFF_KOPF = re.compile(r"^(?:index [0-9a-f]+\.\.[0-9a-f]+(?: [0-7]{6})?|--- a/\S.*|\+\+\+ b/\S.*)$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def pin_diff_befunde(diff: str, pfad: str, soll_pins: dict[str, str] | None = None) -> list[str]:
    """Findings for a unified diff (`git diff HEAD -- <pfad>`) that is meant to raise kit action pins only (0.66.0).

    Empty list = confirmed: the diff touches exactly `pfad`, and every changed line is a pin line of a kit-known action
    (`uses: <action>@<40 hex>  # vX.Y.Z`) replaced by the very line `pins_heben` writes — same line, only the pin
    swapped for the kit pin, to a higher version. Anything else is a finding, and the repokit guard pushes nothing
    (PO 2026-11-24, "yes, but strict"): an extra line, a removed or added line without partner, an unknown action, a
    tag, a lowered pin, a mode change, a new, deleted, renamed or binary file, an empty diff. Fail-closed: a line of
    the diff this parser does not know is a finding, never skipped.
    """
    soll_pins = pins() if soll_pins is None else soll_pins
    befunde: list[str] = []
    if not PIN_DIFF_PFAD.fullmatch(pfad):
        return [f"{pfad}: not a workflow file directly in .github/workflows/ — only those are checked"]
    zeilen = diff.split("\n")
    if zeilen and zeilen[-1] == "":
        zeilen.pop()
    if not zeilen:
        return [f"{pfad}: no change against HEAD (a new or untracked file is no pin change)"]
    kopf_erwartet = f"diff --git a/{pfad} b/{pfad}"
    hunks: list[tuple[int, list[str], list[str], list[str]]] = []      # (diff line, removed, added, markers)
    im_kopf = False
    dateien = 0
    for nr, z in enumerate(zeilen, 1):
        if z.startswith("diff --git "):
            dateien += 1
            if z != kopf_erwartet:
                befunde.append(f"{pfad}: diff line {nr} names another file: {z!r}")
            im_kopf = True
            continue
        if im_kopf and _DIFF_KOPF.match(z):
            if z.startswith(("--- ", "+++ ")) and z[6:] != pfad:
                befunde.append(f"{pfad}: diff line {nr} names another file: {z!r}")
            continue
        if _HUNK.match(z) and dateien:
            im_kopf = False
            hunks.append((nr, [], [], []))
            continue
        if not im_kopf and hunks and z[:1] in ("-", "+"):
            hunks[-1][1 if z[0] == "-" else 2].append(z[1:])
            hunks[-1][3].append(z[0])
            continue
        if not im_kopf and hunks and z == "\\ No newline at end of file":
            hunks[-1][3].append("\\" + (hunks[-1][3][-1] if hunks[-1][3] else "?"))
            continue
        if not im_kopf and hunks and z.startswith(" "):
            continue            # context line: unchanged
        befunde.append(f"{pfad}: diff line {nr} is not a pin change: {z!r}")
    if dateien != 1:
        befunde.append(f"{pfad}: the diff must cover exactly this one file (found {dateien})")
    if not hunks and not befunde:
        befunde.append(f"{pfad}: the diff changes no line")
    for nr, weg, dazu, marken in hunks:
        if "\\-" in marken and "\\+" not in marken or "\\+" in marken and "\\-" not in marken:
            befunde.append(f"{pfad}: hunk at diff line {nr} changes the newline at the end of the file")
        if len(weg) != len(dazu) or not weg:
            befunde.append(f"{pfad}: hunk at diff line {nr} removes {len(weg)} and adds {len(dazu)} lines — "
                           "a pin change replaces each line by one line")
            continue
        for alt, neu in zip(weg, dazu):
            befunde.extend(_pin_paar_befunde(pfad, nr, alt, neu, soll_pins))
    return befunde


def _pin_paar_befunde(pfad: str, nr: int, alt: str, neu: str, soll_pins: dict[str, str]) -> list[str]:
    """Findings for one removed/added line pair of a pin diff (empty = exactly the line `pins_heben` writes)."""
    m = PIN_ZEILE.match(alt.rstrip("\r"))
    if not m:
        return [f"{pfad}: hunk at diff line {nr}: {alt.strip()!r} is no pin line (`uses: <action>@<40 hex>  # vX`)"]
    action, ist = m.group(2), m.group(1).rstrip()
    if action not in soll_pins:
        return [f"{pfad}: hunk at diff line {nr}: {action} is no kit action (kit pins: {', '.join(sorted(soll_pins))})"]
    soll = soll_pins[action]
    if not re.fullmatch(re.escape(action) + r"@[0-9a-f]{40}  # v\d\S*", ist):
        return [f"{pfad}: hunk at diff line {nr}: `{ist}` is not in the exact pin form, the kit does not rewrite it"]
    if not _hebt(ist, soll):
        return [f"{pfad}: hunk at diff line {nr}: `{ist}` → `{soll}` does not raise the version"]
    if neu != alt.replace(ist, soll, 1):
        return [f"{pfad}: hunk at diff line {nr}: {neu.strip()!r} is not the line with only the kit pin swapped in "
                f"(expected {alt.replace(ist, soll, 1).strip()!r})"]
    return []


def je_repo_block(text: str) -> str | None:
    if ANFANG not in text or ENDE not in text:
        return None
    return text.split(ANFANG, 1)[1].split(ENDE, 1)[0]


def pruefe(root: str) -> list[str]:
    """Abweichungen des Auto-Merge-Workflows von der Vorlage; leer heißt „stimmt“.

    Ohne Workflow ist das ein Befund, kein Erfolg: Ein Repo mit Dependabot, aber ohne Auto-Merge
    lässt jeden PR liegen.
    """
    text = _lies(os.path.join(root, WORKFLOW))
    dependabot = pruefe_dependabot(root)
    app_pins = [f".github/workflows/{p}" for p in app_token_pins(_workflows(root))]
    if text is None:
        if os.path.exists(os.path.join(root, ".github", "dependabot.yml")):
            return [f"{WORKFLOW} fehlt — Dependabot-PRs blieben liegen (`repokit automerge` baut ihn)"] + app_pins
        return app_pins
    block = je_repo_block(text)
    if block is None:
        return [f"{WORKFLOW}: Block „je Repo: Anfang/Ende“ fehlt — nicht aus der Vorlage gebaut"] + app_pins
    soll, probleme = rendere(root, block)
    fehler = [f"{WORKFLOW}: {p}" for p in probleme] + dependabot + app_pins
    if text != soll:
        ist_z, soll_z = _zeilen(text), _zeilen(soll)
        for nr, (a, b) in enumerate(zip(ist_z, soll_z), 1):
            if a != b:
                fehler.append(f"{WORKFLOW}:{nr}: weicht von der Vorlage ab — ist `{a.strip()}`, "
                              f"soll `{b.strip()}` (`repokit automerge` baut ihn neu)")
                break
        else:
            fehler.append(f"{WORKFLOW}: Länge weicht von der Vorlage ab ({len(ist_z)} statt "
                          f"{len(soll_z)} Zeilen)")
    return fehler

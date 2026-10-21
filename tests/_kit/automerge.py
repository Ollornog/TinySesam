"""Der Dependabot-Auto-Merge-Workflow eines Repos — aus der Vorlage gebaut und gegen sie geprüft.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.

WARUM (PO 2026-10-11, alle Repos: „alles automatisch mergen solange tests grün … auch majors“):
Bis dahin trug jedes Repo seine eigene Fassung des Workflows. Zehn Fassungen derselben Logik
laufen auseinander — TinySesam wartete auf alle Pflicht-Workflows, die anderen mergten beim
ersten grünen; TinySesam ließ Majors durch, die anderen nicht. Jetzt gibt es eine Vorlage
(`vorlage_dependabot_auto_merge.yml.in`), und je Repo frei sind nur zwei Werte:

    AUTO_OEKO          Ökosysteme, die ein Pflicht-Check wirklich abnimmt
    PFLICHT_WORKFLOWS  Workflows (Dateinamen), deren Jobs das Repo als Abnahme gelten lässt

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
            .replace("@@NACHLAUF@@\n", nachlauf_zeilen))
    return text, probleme


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
    if text is None:
        if os.path.exists(os.path.join(root, ".github", "dependabot.yml")):
            return [f"{WORKFLOW} fehlt — Dependabot-PRs blieben liegen (`repokit automerge` baut ihn)"]
        return []
    block = je_repo_block(text)
    if block is None:
        return [f"{WORKFLOW}: Block „je Repo: Anfang/Ende“ fehlt — nicht aus der Vorlage gebaut"]
    soll, probleme = rendere(root, block)
    fehler = [f"{WORKFLOW}: {p}" for p in probleme] + dependabot
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

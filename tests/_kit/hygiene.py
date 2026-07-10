"""Geteilte Hygiene-Prüfungen. Eine Quelle für alle Repos.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.
Die Regeln selbst stehen daneben in `hygiene_policy.json` (reine Daten, kein Code).

**Kein Netz, keine Abhängigkeiten.** Nur stdlib. Die Datei ist eingecheckt und liegt
darum in jedem `git clone`, jedem GitHub-ZIP und jedem Release-Tarball.

**Jede Prüfung gibt eine Liste von Verstößen zurück, sie wirft nicht.** Das ist Absicht:
so passt derselbe Code in ein `assert not pruefe_...(...)` wie in ein sammelndes
`r.check(name, not pruefe_...(...))`. Kein Repo muss sein Test-Idiom aufgeben.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess

HIER = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Laden und Einlesen
# ---------------------------------------------------------------------------
def lade_policy(pfad: str | None = None) -> dict:
    with open(pfad or os.path.join(HIER, "hygiene_policy.json"), encoding="utf-8") as fh:
        return json.load(fh)


def getrackte_dateien(root: str) -> list[str]:
    """Nur versionierte Dateien; alles andere geht das Repo nichts an."""
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                         capture_output=True, check=True)
    return [n for n in out.stdout.decode("utf-8").split("\0") if n]


def _lies(root: str, rel: str) -> str | None:
    """Textinhalt oder None, wenn die Datei binär/unlesbar ist."""
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return fh.read()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        return None


def _texte(root: str, dateien: list[str], policy: dict, mit_selbst: bool = False):
    """(pfad, inhalt) je lesbarer Datei. Nimmt die Musterträger selbst aus."""
    binaer = tuple(policy["binaer_endungen"])
    selbst = set() if mit_selbst else set(policy["selbst_ausnahmen"])
    for rel in dateien:
        if rel in selbst or rel.endswith(binaer):
            continue
        inhalt = _lies(root, rel)
        if inhalt is not None:
            yield rel, inhalt


# ---------------------------------------------------------------------------
# Die Prüfungen
# ---------------------------------------------------------------------------
def pruefe_artefakte(dateien: list[str], policy: dict) -> list[str]:
    """Generierte Artefakte gehören nicht ins Repo.

    `pip install -e .` schreibt `<paket>.egg-info/` bei jedem Lauf neu. Versioniert macht
    das die Suite unwiederholbar — und zwar unsichtbar: `PKG-INFO` ändert sich nur, wenn
    sich Metadaten ändern. Der Baum bleibt zufällig sauber, bis die Version steigt.
    Genau so überlebte der Fehler einmal sechs grüne Läufe. Keine Testsuite fand ihn,
    nur der Rückstands-Check. Die `.gitignore` schützt nur, was noch nicht eingecheckt ist.
    """
    teile = tuple(policy["artefakt_teile"])
    verzeichnisse = set(policy["artefakt_verzeichnisse"])
    endungen = tuple(policy["artefakt_endungen"])
    treffer = []
    for rel in dateien:
        segmente = rel.split("/")
        if (any(t in rel for t in teile)
                or any(s in verzeichnisse for s in segmente[:-1])
                or rel.endswith(endungen)):
            treffer.append(rel)
    return treffer


def pruefe_private_infrastruktur(root: str, dateien: list[str], policy: dict,
                                 projekte: list[str]) -> list[str]:
    """Keine private Infrastruktur im öffentlichen Repo.

    Die Trennlinie ist **Identität gegen Infrastruktur**, nicht „mein Name kommt vor".
    Erlaubt und teils rechtlich nötig: Autor, Impressumsadresse, Lizenz, Repo-URL,
    Projektname. Verboten ist, was jemandem hilft, die Systeme dahinter zu finden.

    `projekte` sind die eigenen Projektnamen, deren Repo-URLs erlaubt bleiben.
    """
    muster = [re.compile(m, re.IGNORECASE) for m in policy["private_muster"]]
    namen = frozenset(policy["private_namen_sha256_16"])
    erlaubt = re.compile(
        policy["erlaubte_identitaet"].format(projekte="|".join(re.escape(p) for p in projekte)),
        re.IGNORECASE)
    wort = re.compile(r"[a-z][a-z0-9-]{3,}")

    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        for n, zeile in enumerate(inhalt.splitlines(), 1):
            sauber = erlaubt.sub("", zeile)
            for pat in muster:
                if pat.search(sauber):
                    treffer.append(f"{rel}:{n}: {zeile.strip()[:60]}")
            for w in wort.findall(sauber.lower()):
                if hashlib.sha256(w.encode()).hexdigest()[:16] in namen:
                    treffer.append(f"{rel}:{n}: verbotener Name")
    return treffer


def pruefe_geheimnisse(root: str, dateien: list[str], policy: dict) -> list[str]:
    """Keine Tokens, Schlüssel oder Passwörter im Klartext.

    Vereinigt beide Ansätze: Credential-**Formate** (`ghp_`, PEM, `AKIA`) fangen einen
    versehentlich eingecheckten Schlüssel auch ohne Zuweisung; das **Zuweisungsmuster**
    fängt `token = "…"`. Gescannt wird jede lesbare Datei, nicht nur bekannte Endungen —
    ein `.pem` fiele sonst schon durch die Dateiauswahl.
    """
    muster = [re.compile(m, re.IGNORECASE) for m in policy["geheimnis_muster"]]
    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        for pat in muster:
            if pat.search(inhalt):
                treffer.append(rel)
                break
    return treffer


def pruefe_adressen(root: str, dateien: list[str], policy: dict,
                    zusaetzliche_hosts: list[str] | None = None) -> list[str]:
    """Nur neutrale Beispieladressen (RFC 2606) in Doku und Code."""
    hosts = list(policy["erlaubte_hosts"]) + list(zusaetzliche_hosts or [])
    erlaubt = re.compile(r"(?:^|\.)(?:" + "|".join(hosts) + r")$", re.IGNORECASE)
    url = re.compile(r"https?://([a-z0-9.-]+)", re.IGNORECASE)
    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        for host in url.findall(inhalt):
            # Regex-Literale im Frontend enthalten "https?://" ohne echten Host.
            if "." not in host or not re.search(r"[a-z]", host, re.IGNORECASE):
                continue
            if not erlaubt.search(host):
                treffer.append(f"{rel}: {host}")
    return treffer


def pruefe_kein_self_hosted_runner(root: str, dateien: list[str]) -> list[str]:
    """Öffentliche Repos laufen auf `ubuntu-latest`.

    Ein self-hosted Runner führt bei einem Fork-PR fremden Code auf eigener Hardware aus,
    und die Runner sind nicht ephemer. GitHub rät ausdrücklich ab.
    """
    treffer = []
    for rel in dateien:
        if not rel.startswith(".github/workflows/"):
            continue
        inhalt = _lies(root, rel) or ""
        for n, zeile in enumerate(inhalt.splitlines(), 1):
            if "self-hosted" in zeile:
                treffer.append(f"{rel}:{n}")
    return treffer


def pruefe_versionsgleichstand(root: str, weitere: dict[str, str] | None = None) -> list[str]:
    """`pyproject.toml`, CHANGELOG und optionale weitere Quellen nennen dieselbe Version.

    `weitere` bildet Datei -> Regex mit genau einer Gruppe ab, z.B.
    {"tinysesam/__init__.py": r'^__version__ = "([^"]+)"'}
    """
    fehler = []
    pyproject = _lies(root, "pyproject.toml") or ""
    treffer = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not treffer:
        return ["pyproject.toml nennt keine version"]
    version = treffer.group(1)

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fehler.append(f"Version ist kein SemVer: {version}")

    changelog = _lies(root, "CHANGELOG.md") or ""
    if f"[{version}]" not in changelog and f"## {version}" not in changelog:
        fehler.append(f"CHANGELOG kennt Version {version} nicht")

    for datei, regex in (weitere or {}).items():
        inhalt = _lies(root, datei)
        if inhalt is None:
            fehler.append(f"{datei} fehlt")
            continue
        m = re.search(regex, inhalt, re.M)
        if not m:
            fehler.append(f"{datei} nennt keine Version")
        elif m.group(1) != version:
            fehler.append(f"{datei}={m.group(1)} aber pyproject={version}")
    return fehler


def pruefe_run_all_sammelt_automatisch(root: str) -> list[str]:
    """Eine Suite, die niemand aufruft, prüft nichts."""
    runner = _lies(root, "tests/run_all.py")
    if runner is None:
        return ["tests/run_all.py fehlt"]
    if "glob(" not in runner and "glob.glob" not in runner and "iterdir" not in runner:
        return ["run_all.py sammelt die Suiten nicht automatisch"]
    return []


def pruefe_ausfuehrbar(root: str, pfade: list[str]) -> list[str]:
    treffer = []
    for rel in pfade:
        voll = os.path.join(root, rel)
        if not os.path.exists(voll):
            treffer.append(f"{rel} fehlt")
        elif not os.stat(voll).st_mode & 0o111:
            treffer.append(f"{rel} ist nicht ausführbar")
    return treffer


def pruefe_pflichtdateien(root: str, namen: list[str]) -> list[str]:
    return [n for n in namen if not os.path.exists(os.path.join(root, n))]

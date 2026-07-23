"""Backlog-Prüfungen — stdlib-only, offline, ohne Prozessstart.

Der Backlog eines Repos lebt als Markdown mit Frontmatter unter `backlog/` im Repo-Root.

**Warum nicht `docs/`:** Dort liegt bei manchen Repos die GitHub-Pages-Site (`docs/` als
Publish-Verzeichnis). Der Backlog gehoert nicht in die veroeffentlichte Website — und ein
Test, der ueber den Inhalt von `docs/` wacht, faellt sonst ueber ihn. Aufgefallen beim
TinySesam-Pilot 2026-07-23.
Dieses Modul liest ihn und gibt **Listen von Verstößen zurück** — es wirft nicht und
gibt nichts aus. Genau wie `hygiene.py`: so kann jede Suite ihr eigenes Idiom
benutzen (`assert not fn()` oder `report.check(...)`).

Warum kein YAML-Parser: das Kit ist stdlib-only, damit `scripts/check.sh` ohne Netz
und ohne Abhängigkeiten läuft. Das Frontmatter-Schema hier ist bewusst so eng, dass
ein 40-Zeilen-Parser reicht — Schlüssel/Wert und flache Listen, sonst nichts.

Schema (siehe backlog/README-KONVENTION.md im Zielrepo):

    ---
    id: T-012                  # Pflicht, eindeutig, Präfix passend zum type
    type: Task                 # Pflicht: Milestone | Task | Decision | Bug
    title: Kurzer Satz         # Pflicht
    status: offen              # Pflicht: offen | in-arbeit | erledigt | verworfen
    milestone: M2              # bei Task/Bug: auf welchen Meilenstein zahlt es ein
    blocked_by: [T-011]        # optional
    superseded_by: ADR-7       # bei verworfenen Decisions Pflicht
    tags: [auth, cookies]
    created: 2026-07-23
    ---
"""
from __future__ import annotations

import os
import re

BACKLOG_DIR = "backlog"

TYPEN = {"Milestone", "Task", "Decision", "Bug"}
PRAEFIX = {"Milestone": "M", "Task": "T", "Decision": "ADR", "Bug": "B"}
STATUS = {"offen", "in-arbeit", "erledigt", "verworfen"}
PFLICHT = ("id", "type", "title", "status")

_FM = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n?", re.DOTALL)
_ID = re.compile(r"\A(M|T|ADR|B)-\d{1,4}\Z")


def _skalar(wert: str):
    """'[a, b]' -> ['a','b'] · '"x"' -> 'x' · sonst der getrimmte Text."""
    wert = wert.strip()
    if wert.startswith("[") and wert.endswith("]"):
        inner = wert[1:-1].strip()
        return [t.strip().strip("\"'") for t in inner.split(",") if t.strip()] if inner else []
    if len(wert) >= 2 and wert[0] == wert[-1] and wert[0] in "\"'":
        return wert[1:-1]
    return wert


def frontmatter(text: str) -> tuple[dict, str]:
    """-> (felder, rumpf). Ohne Frontmatter: ({}, text)."""
    m = _FM.match(text)
    if not m:
        return {}, text
    felder: dict = {}
    for zeile in m.group(1).splitlines():
        if not zeile.strip() or zeile.lstrip().startswith("#"):
            continue
        if zeile[:1] in " \t":          # verschachteltes YAML ist im Schema nicht vorgesehen
            continue
        if ":" not in zeile:
            continue
        k, _, v = zeile.partition(":")
        felder[k.strip()] = _skalar(v)
    return felder, text[m.end():]


def lade(root: str = ".") -> list[dict]:
    """Alle Backlog-Einträge als Dicts (Felder + '_datei' + '_rumpf')."""
    verz = os.path.join(root, BACKLOG_DIR)
    eintraege: list[dict] = []
    if not os.path.isdir(verz):
        return eintraege
    for name in sorted(os.listdir(verz)):
        if not name.endswith(".md") or name.startswith("README"):
            continue
        pfad = os.path.join(verz, name)
        with open(pfad, encoding="utf-8") as fh:
            text = fh.read()
        felder, rumpf = frontmatter(text)
        felder["_datei"] = os.path.join(BACKLOG_DIR, name)
        felder["_rumpf"] = rumpf
        eintraege.append(felder)
    return eintraege


def pruefe_backlog(root: str = ".") -> list[str]:
    """Alle Strukturprüfungen. Leere Liste = sauber."""
    eintraege = lade(root)
    if not eintraege:
        return []
    fehler: list[str] = []
    ids: dict[str, str] = {}

    for e in eintraege:
        d = e["_datei"]
        for feld in PFLICHT:
            if not e.get(feld):
                fehler.append(f"{d}: Pflichtfeld '{feld}' fehlt")
        typ, ident, status = e.get("type"), e.get("id"), e.get("status")

        if typ and typ not in TYPEN:
            fehler.append(f"{d}: type '{typ}' unbekannt (erlaubt: {sorted(TYPEN)})")
        if status and status not in STATUS:
            fehler.append(f"{d}: status '{status}' unbekannt (erlaubt: {sorted(STATUS)})")
        if ident:
            if not _ID.match(str(ident)):
                fehler.append(f"{d}: id '{ident}' folgt nicht dem Muster M-1 / T-12 / ADR-3 / B-7")
            elif ident in ids:
                fehler.append(f"{d}: id '{ident}' schon vergeben in {ids[ident]}")
            else:
                ids[ident] = d
            if typ in PRAEFIX and not str(ident).startswith(PRAEFIX[typ] + "-"):
                fehler.append(f"{d}: id '{ident}' passt nicht zu type '{typ}' "
                              f"(erwartet Präfix '{PRAEFIX[typ]}-')")
        # Dateiname trägt die id -> im Verzeichnis sortiert und ohne Öffnen erkennbar
        if ident and not os.path.basename(d).startswith(str(ident) + "-"):
            fehler.append(f"{d}: Dateiname sollte mit '{ident}-' beginnen")

    bekannt = set(ids)
    for e in eintraege:
        d, typ, status = e["_datei"], e.get("type"), e.get("status")
        for feld in ("milestone", "blocked_by", "superseded_by", "supersedes"):
            werte = e.get(feld) or []
            for w in ([werte] if isinstance(werte, str) else werte):
                if w and w not in bekannt:
                    fehler.append(f"{d}: {feld} verweist auf unbekannte id '{w}'")
        # Eine verworfene Entscheidung ohne Nachfolger ist eine Sackgasse: der Leser
        # sieht, dass es nicht mehr gilt, aber nicht, was stattdessen gilt.
        if typ == "Decision" and status == "verworfen" and not e.get("superseded_by"):
            fehler.append(f"{d}: verworfene Decision braucht 'superseded_by' "
                          "(sonst weiss niemand, was stattdessen gilt)")
        if typ in ("Task", "Bug") and not e.get("milestone"):
            fehler.append(f"{d}: {typ} ohne 'milestone' — auf welchen Meilenstein zahlt es ein?")

    return fehler


def pruefe_keine_zyklen(root: str = ".") -> list[str]:
    """`blocked_by` darf keinen Kreis bilden — sonst ist nichts mehr startbar."""
    eintraege = lade(root)
    kanten = {}
    for e in eintraege:
        b = e.get("blocked_by") or []
        kanten[e.get("id")] = [b] if isinstance(b, str) else list(b)
    fehler, gesehen = [], set()

    def lauf(knoten, pfad):
        if knoten in pfad:
            kreis = " -> ".join(pfad[pfad.index(knoten):] + [knoten])
            fehler.append(f"blocked_by bildet einen Kreis: {kreis}")
            return
        if knoten in gesehen:
            return
        gesehen.add(knoten)
        for n in kanten.get(knoten, []):
            lauf(n, pfad + [knoten])

    for k in list(kanten):
        lauf(k, [])
    return sorted(set(fehler))


def offene_gegen_erledigten_milestone(root: str = ".") -> list[str]:
    """Ein Meilenstein gilt als erledigt, seine Aufgaben aber nicht — einer von beiden lügt."""
    eintraege = lade(root)
    ms_status = {e["id"]: e.get("status") for e in eintraege if e.get("type") == "Milestone" and e.get("id")}
    fehler = []
    for e in eintraege:
        if e.get("type") in ("Task", "Bug") and e.get("status") in ("offen", "in-arbeit"):
            m = e.get("milestone")
            if m and ms_status.get(m) == "erledigt":
                fehler.append(f"{e['_datei']}: {e.get('status')}, aber Meilenstein {m} steht auf 'erledigt'")
    return fehler


def alle_pruefungen(root: str = ".") -> list[str]:
    return (pruefe_backlog(root)
            + pruefe_keine_zyklen(root)
            + offene_gegen_erledigten_milestone(root))

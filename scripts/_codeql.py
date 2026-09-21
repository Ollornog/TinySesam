#!/usr/bin/env python3
"""Offene Code-Scanning-Funde holen und als Backlog-Eintrag ablegen.

Warum: GitHub schickt CodeQL-Funde als **PR-Kommentar** an den Autor — also per Mail, mit dem
Satz „found more than 20 potential problems" und ohne zu sagen, welche. Der Security-Tab hat die
Details, aber niemand sieht ihn regelmässig an. Hier ist die Zwischenstufe: eine Datei im
Backlog, die im Repo liegt, versioniert ist und beim nächsten Anfassen auffällt.

    python3 scripts/_codeql.py            # backlog/S-1-codeql.md schreiben
    python3 scripts/_codeql.py --zeigen   # nur ausgeben, nichts schreiben

Braucht `gh` mit Leserecht auf das Repo. Ohne Funde wird die Datei entfernt.
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZIEL = ROOT / "backlog" / "S-1-codeql.md"
REPO = "Ollornog/TinySesam"

#: Was TinySesam bewusst anders bewertet als CodeQL — mit Grund, nicht als Stummschalten.
BEWERTET = {
    "py/url-redirection": (
        "geprüft, Fehlalarm: Das Ziel ist immer der relative `cfg.login_path`; der "
        "nutzergelieferte Teil landet nur im `next`-Parameter, und `safe_next()` wirft externe "
        "Ziele auf `/`. Nachgemessen mit `//evil.example`, `https://evil.example` und "
        "Parameter-Injection über `&next=` — alle vier blieben intern."),
}


def alerts() -> list[dict]:
    roh = subprocess.run(
        ["gh", "api", f"repos/{REPO}/code-scanning/alerts?state=open&per_page=100"],
        capture_output=True, text=True)
    if roh.returncode != 0:
        print(f"gh api fehlgeschlagen: {roh.stderr.strip()[:200]}", file=sys.stderr)
        raise SystemExit(1)
    return json.loads(roh.stdout)


def bauen(daten: list[dict]) -> str:
    nach_regel: dict = defaultdict(list)
    for a in daten:
        ort = a["most_recent_instance"]["location"]
        nach_regel[(a["rule"]["id"], a["rule"].get("security_severity_level")
                    or a["rule"].get("severity"))].append(
            f'{ort["path"]}:{ort["start_line"]}')

    zeilen = [
        "---", "id: S-1", "type: Task",
        "title: Offene CodeQL-Funde sichten", "status: offen", "milestone: M-2",
        "tags: [sicherheit, codeql, generiert]", "created: 2026-09-21", "---", "",
        "# S-1 — offene CodeQL-Funde", "",
        "<!-- GENERIERT von scripts/_codeql.py — nicht von Hand pflegen. -->", "",
        "GitHub meldet Code-Scanning-Funde per Mail an den PR-Autor — mit der Zahl, ohne die",
        "Liste — und legt die Details in den Security-Tab. Diese Seite ist der Abzug davon:",
        "im Repo, versioniert, und beim nächsten Anfassen sichtbar.", "",
        f"**{len(daten)} offene Funde.** Ein Fund ist eine Behauptung: erst nachmessen, dann",
        "beheben oder mit Begründung abtun.", "",
    ]
    for (regel, schwere), orte in sorted(nach_regel.items(), key=lambda kv: -len(kv[1])):
        bib = [o for o in orte if o.startswith("tinysesam/")]
        zeilen.append(f"## `{regel}` — {len(orte)}× ({schwere or 'note'})")
        zeilen.append("")
        if regel in BEWERTET:
            zeilen.append(f"> **Bewertet:** {BEWERTET[regel]}")
            zeilen.append("")
        if bib:
            zeilen.append(f"**In der Bibliothek:** {', '.join(f'`{o}`' for o in bib)}")
            zeilen.append("")
        andere = [o for o in orte if not o.startswith("tinysesam/")]
        if andere:
            gezeigt = ", ".join(f"`{o}`" for o in andere[:6])
            rest = f" … und {len(andere) - 6} weitere" if len(andere) > 6 else ""
            zeilen.append(f"Ausserhalb der Bibliothek: {gezeigt}{rest}")
            zeilen.append("")
    return "\n".join(zeilen) + "\n"


def main() -> int:
    daten = alerts()
    if not daten:
        if ZIEL.exists():
            ZIEL.unlink()
            print(f"Keine offenen Funde — {ZIEL.name} entfernt.")
        else:
            print("Keine offenen Funde.")
        return 0
    text = bauen(daten)
    if "--zeigen" in sys.argv:
        print(text)
        return 0
    ZIEL.write_text(text, encoding="utf-8")
    print(f"geschrieben: {ZIEL.relative_to(ROOT)} ({len(daten)} Funde)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Offene CodeQL-Alerts in den Backlog ziehen — statt in ein Postfach.

    python3 scripts/_codeql_backlog.py            # Tabelle in backlog/T-12-codeql-bestand.md erneuern
    python3 scripts/_codeql_backlog.py --zeige    # nur ausgeben, nichts schreiben

CodeQL meldet jeden Fund als E-Mail und — bei einem Pull Request — als Review-Thread, der den
Merge blockiert, solange er offen ist (auch bei Schwere „note"). Was auf `main` offen liegt,
sieht dagegen niemand, bis ein PR zufällig dieselben Zeilen berührt. Dieses Skript holt die
offene Liste über die GitHub-API und schreibt sie als Tabelle zwischen die Marker in der
Backlog-Datei; alles ausserhalb der Marker bleibt, wie es ist. Braucht ein angemeldetes `gh`.

Bewertete Alerts werden in GitHub mit Begründung abgewiesen (`gh api -X PATCH …/alerts/N`),
nicht hier gestrichen — sonst kämen sie beim nächsten Lauf zurück.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIEL = os.path.join(ROOT, "backlog", "T-12-codeql-bestand.md")
START, ENDE = "<!-- CODEQL:START -->", "<!-- CODEQL:END -->"
RANG = {"error": 0, "warning": 1, "note": 2}


def hole_alerts() -> list[dict]:
    repo = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
                          capture_output=True, text=True, check=True, cwd=ROOT).stdout.strip()
    raw = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/code-scanning/alerts?state=open&per_page=100",
         "--jq", ".[] | {n:.number, rule:.rule.id, sev:.rule.severity, path:.most_recent_instance.location.path,"
                 " line:.most_recent_instance.location.start_line, url:.html_url}"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    alerts = [json.loads(z) for z in raw.splitlines() if z.strip()]
    return sorted(alerts, key=lambda a: (RANG.get(a["sev"], 9), a["path"], a["line"]))


def tabelle(alerts: list[dict]) -> str:
    if not alerts:
        return "_Keine offenen Alerts._"
    zeilen = ["| # | Schwere | Regel | Stelle |", "|---|---|---|---|"]
    for a in alerts:
        zeilen.append(f"| [{a['n']}]({a['url']}) | {a['sev']} | `{a['rule']}` | `{a['path']}:{a['line']}` |")
    je = {}
    for a in alerts:
        je[a["sev"]] = je.get(a["sev"], 0) + 1
    summe = ", ".join(f"{n} {s}" for s, n in sorted(je.items(), key=lambda x: RANG.get(x[0], 9)))
    return f"**{len(alerts)} offen** ({summe}).\n\n" + "\n".join(zeilen)


def main(argv: list[str]) -> int:
    alerts = hole_alerts()
    text = tabelle(alerts)
    if "--zeige" in argv:
        print(text)
        return 0
    with open(ZIEL, encoding="utf-8") as fh:
        alt = fh.read()
    if START not in alt or ENDE not in alt:
        print(f"Marker {START} / {ENDE} fehlen in {ZIEL}", file=sys.stderr)
        return 1
    kopf, rest = alt.split(START, 1)
    _, fuss = rest.split(ENDE, 1)
    neu = f"{kopf}{START}\n{text}\n{ENDE}{fuss}"
    if neu != alt:
        with open(ZIEL, "w", encoding="utf-8") as fh:
            fh.write(neu)
    print(f"{len(alerts)} offene Alerts → {os.path.relpath(ZIEL, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

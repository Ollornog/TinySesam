#!/usr/bin/env python3
"""backlog — Übersicht über den Repo-Backlog erzeugen und prüfen. stdlib-only.

    python3 scripts/_backlog.py index    backlog/README.md neu erzeugen
    python3 scripts/_backlog.py check    Strukturprüfung (Exit 1 bei Verstößen)
    python3 scripts/_backlog.py list     offene Punkte, nach Meilenstein
    python3 scripts/_backlog.py list --alle --type Decision

Die Prüflogik liegt in `tests/_kit/backlog.py` — dieselbe Datei, die auch die
Testsuite benutzt. Hier ist nur die Bedienoberfläche.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
from _kit import backlog as bl  # noqa: E402

OFFEN = ("offen", "in-arbeit")
SYMBOL = {"offen": "☐", "in-arbeit": "◐", "erledigt": "☑", "verworfen": "✗"}


def _sortier(e: dict):
    ident = str(e.get("id") or "")
    praefix, _, nummer = ident.partition("-")
    return (praefix, int(nummer) if nummer.isdigit() else 0)


def cmd_check(args) -> int:
    fehler = bl.alle_pruefungen(args.root)
    if not fehler:
        n = len(bl.lade(args.root))
        print(f"Backlog sauber ({n} Einträge).")
        return 0
    for f in fehler:
        print(f"✗ {f}")
    print(f"\n{len(fehler)} Verstoß/Verstöße.")
    return 1


def cmd_list(args) -> int:
    eintraege = sorted(bl.lade(args.root), key=_sortier)
    if args.type:
        eintraege = [e for e in eintraege if e.get("type") == args.type]
    if not args.alle:
        eintraege = [e for e in eintraege if e.get("status") in OFFEN]
    if not eintraege:
        print("nichts gefunden.")
        return 0
    nach_ms: dict[str, list[dict]] = {}
    for e in eintraege:
        nach_ms.setdefault(str(e.get("milestone") or "—"), []).append(e)
    for ms in sorted(nach_ms):
        print(f"\n{ms}")
        for e in nach_ms[ms]:
            s = SYMBOL.get(str(e.get("status")), "?")
            blk = e.get("blocked_by") or []
            blk = [blk] if isinstance(blk, str) else blk
            hint = f"  (wartet auf {', '.join(blk)})" if blk else ""
            print(f"   {s} {e.get('id'):<7} {e.get('title')}{hint}")
    print(f"\n{len(eintraege)} Einträge.")
    return 0


def cmd_index(args) -> int:
    eintraege = sorted(bl.lade(args.root), key=_sortier)
    if not eintraege:
        print("kein Backlog gefunden — nichts zu tun.")
        return 0

    ms = [e for e in eintraege if e.get("type") == "Milestone"]
    zeilen = [
        "# Backlog",
        "",
        "<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: "
        "`python3 scripts/_backlog.py index` -->",
        "",
        "Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.",
        "Konventionen: [README-KONVENTION.md](README-KONVENTION.md).",
        "",
    ]

    if ms:
        zeilen += ["## Meilensteine", ""]
        for m in ms:
            aufgaben = [e for e in eintraege if e.get("milestone") == m.get("id")]
            fertig = [e for e in aufgaben if e.get("status") == "erledigt"]
            quote = f"{len(fertig)}/{len(aufgaben)}" if aufgaben else "—"
            s = SYMBOL.get(str(m.get("status")), "?")
            zeilen.append(f"* {s} **[{m.get('id')}]({os.path.basename(m['_datei'])})** "
                          f"{m.get('title')} — {quote} erledigt")
        zeilen.append("")

    for typ, titel in (("Task", "Aufgaben"), ("Bug", "Fehler"), ("Decision", "Entscheidungen (ADR)")):
        gruppe = [e for e in eintraege if e.get("type") == typ]
        if not gruppe:
            continue
        zeilen += [f"## {titel}", ""]
        for e in gruppe:
            s = SYMBOL.get(str(e.get("status")), "?")
            zusatz = ""
            if e.get("milestone"):
                zusatz += f" · {e['milestone']}"
            if e.get("superseded_by"):
                zusatz += f" · abgelöst durch {e['superseded_by']}"
            zeilen.append(f"* {s} **[{e.get('id')}]({os.path.basename(e['_datei'])})** "
                          f"{e.get('title')}{zusatz}")
        zeilen.append("")

    ziel = os.path.join(args.root, bl.BACKLOG_DIR, "README.md")
    inhalt = "\n".join(zeilen).rstrip() + "\n"
    alt = ""
    if os.path.exists(ziel):
        with open(ziel, encoding="utf-8") as fh:
            alt = fh.read()
    if alt == inhalt:
        print("Index ist aktuell.")
        return 0
    if args.dry_run:
        print("Index würde sich ändern.")
        return 1
    with open(ziel, "w", encoding="utf-8") as fh:
        fh.write(inhalt)
    print(f"geschrieben: {os.path.relpath(ziel, args.root)}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="backlog", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", default=".", help="Repo-Wurzel (default: .)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("check", help="Strukturprüfung")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("list", help="Einträge auflisten")
    s.add_argument("--alle", action="store_true", help="auch erledigte/verworfene")
    s.add_argument("--type", choices=sorted(bl.TYPEN))
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("index", help="backlog/README.md erzeugen")
    s.add_argument("--dry-run", action="store_true", help="Exit 1, wenn er sich ändern würde")
    s.set_defaults(func=cmd_index)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

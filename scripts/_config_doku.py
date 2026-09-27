#!/usr/bin/env python3
"""Erzeugt KONFIGURATION.md aus tinysesam/config.py.

Warum generiert: Von 119 Feldern kamen 39 in keiner README vor — ein Nachschlagewerk von Hand
zu pflegen heisst, dass es beim nächsten neuen Feld wieder unvollständig ist. Hier ist die
Quelle der Code, und eine Prüfung im Hygiene-Test hält beide zusammen (wie beim Backlog-Index).

    python3 scripts/_config_doku.py              # schreiben
    python3 scripts/_config_doku.py --dry-run    # nur prüfen (Exit 1 = veraltet)

Geerntet werden die Abschnittsüberschriften (`# --- … ---`), der Kommentar hinter einem Feld
und, wenn keiner dasteht, die Kommentarzeilen direkt darüber.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
QUELLE = ROOT / "tinysesam" / "config.py"
ZIEL = ROOT / "KONFIGURATION.md"
#: Die Stufe je Feld (seit 0.21.0) steht beim Wächter der öffentlichen Oberfläche.
ABLAGE = ROOT / "tests" / "api_surface.json"

KOPF = """# Konfiguration — alle Felder von `TinySesamConfig`

<!-- GENERIERT von scripts/_config_doku.py — nicht von Hand pflegen.
     Neu bauen: `python3 scripts/_config_doku.py` -->

Die Quelle ist `tinysesam/config.py`; diese Seite ist ihr Abzug. Was ein Feld *bedeutet*, steht
dort als Kommentar — hier in derselben Reihenfolge, nach Themen gegliedert.

Die READMEs erklären die **Wege** (welche Methode wofür, wie man sie kombiniert). Dieses
Nachschlagewerk beantwortet die andere Frage: *„Es gibt da ein Feld — was tut es?"*

Presets (`TinySesamConfig.local_accounts()`, `.oidc_gateway()`, …) setzen Bündel dieser Felder;
einzelne lassen sich per `**overrides` überschreiben.

"""


def stufen() -> dict:
    """{feld: stufe} aus `tests/api_surface.json` — leer, wenn es die Datei nicht gibt."""
    if not ABLAGE.exists():
        return {}
    felder = json.loads(ABLAGE.read_text(encoding="utf-8")).get("TinySesamConfig.felder", {})
    return {n: e.get("stufe") for n, e in felder.items() if isinstance(e, dict)}


def felder():
    """(abschnitt, name, typ, vorgabe, beschreibung) in Quelltext-Reihenfolge."""
    text = QUELLE.read_text(encoding="utf-8")
    # Nur der Klassenrumpf bis zur ersten Methode.
    rumpf = text[text.index("class TinySesamConfig"):]
    schnitt = re.search(r"\n    @|\n    def ", rumpf)
    if schnitt:
        rumpf = rumpf[:schnitt.start()]

    abschnitt = "Allgemein"
    davor: list[str] = []
    ergebnis: list[list[str]] = []
    # War die Zeile davor ein Feld MIT Kommentar dahinter? Dann gehört eine eingerückte
    # Kommentarzeile direkt darunter zu DIESEM Feld (Fortsetzung), nicht zum nächsten (B3-15).
    # Vorher landete z.B. „warn = läuft auch OHNE Zertifikat" aus `https_mode` in der
    # Beschreibung von `login_identifier` — ein sicherheitsrelevantes Feld mit fremdem Text.
    fortsetzung = False
    for zeile in rumpf.splitlines():
        blank = zeile.strip()
        kopf = re.match(r"^#\s*---\s*(.+?)\s*---\s*$", blank)
        if kopf:
            abschnitt, davor, fortsetzung = kopf.group(1), [], False
            continue
        if blank.startswith("#"):
            # `#:` ist die Doc-Kommentar-Form; der Doppelpunkt gehört nicht in den Text.
            text = blank.lstrip("#").lstrip(":").strip()
            einrueckung = len(zeile) - len(zeile.lstrip())
            if fortsetzung and einrueckung > 4:
                ergebnis[-1][4] = (ergebnis[-1][4] + " " + text).strip()
            else:
                fortsetzung = False
                davor.append(text)
            continue
        fortsetzung = False
        feld = re.match(r"^\s{4}([a-z_][a-z0-9_]*)\s*:\s*([^=]+?)\s*=\s*(.+?)\s*(?:#\s*(.*))?$", zeile)
        if not feld:
            if blank:
                davor = []
            continue
        name, typ, vorgabe, hinter = feld.groups()
        beschreibung = (hinter or " ".join(t for t in davor if t)).strip()
        fortsetzung = bool(hinter)
        davor = []
        ergebnis.append([abschnitt, name, typ.strip(), vorgabe.strip(), beschreibung])
    for eintrag in ergebnis:
        yield tuple(eintrag)


def bauen() -> str:
    alle = list(felder())
    # Ein Abschnitt mit genau EINEM Feld ist in Wahrheit die Beschreibung dieses Feldes —
    # `# --- Sprache der eingebauten Texte (en|de) ---` über `lang: str = "en"` etwa. Ohne
    # diesen Handgriff stünde bei 35 Feldern ein „—", und ein Nachschlagewerk, das bei jedem
    # dritten Eintrag schweigt, schlägt niemand zweimal nach.
    je_abschnitt: dict = {}
    for abschnitt, *_ in alle:
        je_abschnitt[abschnitt] = je_abschnitt.get(abschnitt, 0) + 1

    # Die Stufe (PO-Entscheid 2026-09-26): Fast jedes Feld ist A. Markiert wird nur, was davon
    # abweicht — in der Bedeutungsspalte, damit die Zeile weiter mit „| `name` |" beginnt.
    stufe = stufen()
    abweichend = sorted(n for _, n, *_ in alle if stufe.get(n) != "A")
    teile = [KOPF, "**Stufe:** Jedes Feld gehört zur Stufe A — öffentlich, stabil ab 1.0 (siehe "
                   "[API.md](API.md), „Drei Stufen“)"
             + ("" if not abweichend else
                ", ausser " + ", ".join(f"`{n}` ({stufe.get(n) or 'ohne Stufe'})"
                                        for n in abweichend))
             + ".\n"]
    aktuell = None
    for abschnitt, name, typ, vorgabe, beschreibung in alle:
        if not beschreibung and je_abschnitt[abschnitt] == 1:
            beschreibung = abschnitt
        if abschnitt != aktuell:
            aktuell = abschnitt
            teile.append(f"\n## {abschnitt}\n\n| Feld | Typ | Vorgabe | Bedeutung |\n|---|---|---|---|\n")
        vor = vorgabe.replace("field(default_factory=lambda: ", "").replace("field(default_factory=", "")
        vor = vor.rstrip(")") if vor.endswith(")") and "(" not in vor[:-1] else vor
        text = beschreibung.replace("|", "\\|") or "—"
        if stufe.get(name) != "A" and text != "—":
            text = f"**Stufe {stufe.get(name) or '?'}.** {text}"
        teile.append(f"| `{name}` | `{typ}` | `{vor}` | {text} |\n")
    zahl = len(alle)
    teile.append(f"\n---\n\n{zahl} Felder, erzeugt aus `tinysesam/config.py`.\n")
    return "".join(teile)


def main() -> int:
    neu = bauen()
    trocken = "--dry-run" in sys.argv
    alt = ZIEL.read_text(encoding="utf-8") if ZIEL.exists() else ""
    if trocken:
        if alt != neu:
            print(f"{ZIEL.name} ist veraltet — `python3 scripts/_config_doku.py` fahren",
                  file=sys.stderr)
            return 1
        return 0
    ZIEL.write_text(neu, encoding="utf-8")
    print(f"geschrieben: {ZIEL.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

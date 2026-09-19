"""Die öffentliche API festhalten — damit ein Bruch AUFFÄLLT, statt zu passieren.

Der Meilenstein 1.0 verlangt, dass die öffentliche API sich über zwei Minor-Versionen nicht mehr
bricht (`backlog/M-1-api-stabil-1-0.md`). Ohne Messung ist das eine Behauptung: Beide letzten
Releases haben gebrochen, und beide Male fiel es erst beim Schreiben des CHANGELOG auf.

Dieser Test schreibt die Oberfläche in `tests/api_surface.json` fest und vergleicht bei jedem Lauf.
Er verbietet nichts — er erzwingt eine **bewusste Entscheidung**:

    python tests/test_api_surface.py --update      # Änderung übernehmen, danach committen

Was als Bruch gilt, steht unten in `beurteile()`: Entfernt oder umbenannt ist ein Bruch,
eine geänderte Signatur meistens auch, etwas Neues ist eine Erweiterung. Die Unterscheidung
steht im Bericht, damit man nicht jede Zeile selbst nachschlagen muss.
"""
import inspect
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tinysesam
from tinysesam import TinySesam, TinySesamConfig

ABLAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_surface.json")


def ok(name):
    print(f"  ✓ {name}")


def signatur(fn) -> str:
    """Die Signatur ohne `self` — Parameternamen und Reihenfolge sind Teil des Versprechens.

    Erfasst wird auch, ob ein Parameter keyword-only ist: Genau daran hing der Bruch in 0.15
    (`require_role("editor", True)` meinte einmal `mfa=True` und wäre danach eine zweite Rolle).
    """
    try:
        s = inspect.signature(fn)
    except (TypeError, ValueError):
        return "?"
    teile = [str(p) for name, p in s.parameters.items() if name != "self"]
    return "(" + ", ".join(teile) + ")"


def oberflaeche() -> dict:
    """Was ein Einbindender benutzt: die Klasse, die Konfiguration, die Exporte."""
    manager = {name: signatur(fn)
               for name, fn in inspect.getmembers(TinySesam, callable)
               if not name.startswith("_")}
    felder = {f.name: str(f.type) for f in TinySesamConfig.__dataclass_fields__.values()}
    presets = {name: signatur(fn)
               for name, fn in inspect.getmembers(TinySesamConfig, callable)
               if not name.startswith("_")}
    exporte = sorted(getattr(tinysesam, "__all__", None)
                     or [n for n in dir(tinysesam) if not n.startswith("_")])
    return {"TinySesam": manager, "TinySesamConfig.felder": felder,
            "TinySesamConfig.methoden": presets, "exporte": exporte}


def teile(sig: str) -> list:
    """Signatur-String in Parameter zerlegen — nur auf Kommas ausserhalb von Klammern."""
    inhalt = sig.strip()[1:-1]
    teile, tiefe, akt = [], 0, ""
    for c in inhalt:
        if c in "([{":
            tiefe += 1
        elif c in ")]}":
            tiefe -= 1
        if c == "," and tiefe == 0:
            teile.append(akt.strip())
            akt = ""
        else:
            akt += c
    if akt.strip():
        teile.append(akt.strip())
    return teile


def nur_erweitert(alt: str, neu: str) -> bool:
    """Ist die neue Signatur mit der alten aufrufbar?

    Ein Parameter, der MIT Vorgabewert hinten angehängt wird, bricht nichts — jeder bestehende
    Aufruf funktioniert weiter. Das als Bruch zu melden wäre nicht nur falsch, es wäre schädlich:
    Ein Wächter, der bei Harmlosem schreit, wird weggeklickt, und dann übersieht man den echten.
    """
    a, n = teile(alt), teile(neu)
    if len(n) < len(a) or n[:len(a)] != a:
        return False
    return all("=" in p or p.startswith("*") for p in n[len(a):])


def beurteile(alt: dict, neu: dict):
    """(brueche, erweiterungen) — beides mit lesbarer Beschreibung."""
    brueche, erweiterungen = [], []
    for bereich in sorted(set(alt) | set(neu)):
        a, n = alt.get(bereich, {}), neu.get(bereich, {})
        if isinstance(a, list) or isinstance(n, list):
            fort = sorted(set(a) - set(n))
            dazu = sorted(set(n) - set(a))
            brueche += [f"{bereich}: '{x}' ist fort" for x in fort]
            erweiterungen += [f"{bereich}: '{x}' ist neu" for x in dazu]
            continue
        for name in sorted(set(a) - set(n)):
            brueche.append(f"{bereich}.{name} ist fort (entfernt oder umbenannt)")
        for name in sorted(set(n) - set(a)):
            erweiterungen.append(f"{bereich}.{name} ist neu")
        for name in sorted(set(a) & set(n)):
            if a[name] == n[name]:
                continue
            zeile = (f"{bereich}.{name}:\n        vorher {a[name]}\n        jetzt  {n[name]}")
            if isinstance(a[name], str) and a[name].startswith("(") and nur_erweitert(a[name], n[name]):
                erweiterungen.append(zeile + "\n        (nur angehängt, mit Vorgabewert — "
                                            "bestehende Aufrufe laufen weiter)")
            else:
                brueche.append(zeile)
    return brueche, erweiterungen


def main(argv):
    jetzt = oberflaeche()

    if "--update" in argv:
        with open(ABLAGE, "w", encoding="utf-8") as fh:
            json.dump(jetzt, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        print(f"  Oberfläche festgeschrieben: {ABLAGE}")
        return 0

    if not os.path.exists(ABLAGE):
        print(f"  {ABLAGE} fehlt — einmalig anlegen mit: python tests/test_api_surface.py --update")
        return 1

    with open(ABLAGE, encoding="utf-8") as fh:
        frueher = json.load(fh)

    brueche, erweiterungen = beurteile(frueher, jetzt)
    if not brueche and not erweiterungen:
        n = sum(len(v) for v in jetzt.values())
        ok(f"öffentliche API unverändert ({n} Namen)")
        return 0

    print("\n  Die öffentliche API hat sich geändert.\n")
    for b in brueche:
        print(f"    BRUCH        {b}")
    for e in erweiterungen:
        print(f"    Erweiterung  {e}")
    print("\n  Ein Bruch kostet die Nutzer Arbeit und setzt die Uhr für 1.0 zurück (M-1).")
    print("  War die Änderung gewollt: `python tests/test_api_surface.py --update`, dann committen")
    print("  — und im CHANGELOG darauf hinweisen, wenn ein BRUCH dabei ist.\n")
    return 1


if __name__ == "__main__":
    code = main(sys.argv[1:])
    print("\nAPI-OBERFLÄCHE " + ("OK ✅" if code == 0 else "GEÄNDERT ❌"))
    sys.exit(code)

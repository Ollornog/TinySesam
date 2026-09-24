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
import dataclasses
import inspect
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
from tinysesam import TinySesam, TinySesamConfig

_paket = importlib.import_module("tinysesam")

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
    # Der Rückgabetyp gehört dazu. Ohne ihn liesse sich `-> dict` still zu `-> str` ändern:
    # Jeder Aufruf bricht, und der Wächter schwiege — er erfasste nur die Eingänge.
    zurueck = "" if s.return_annotation is inspect.Signature.empty else \
        f" -> {inspect.formatannotation(s.return_annotation)}"
    return "(" + ", ".join(teile) + ")" + zurueck


def oberflaeche() -> dict:
    """Was ein Einbindender benutzt: die Klasse, die Konfiguration, die Exporte."""
    manager = {name: signatur(fn)
               for name, fn in inspect.getmembers(TinySesam, callable)
               if not name.startswith("_")}
    # Mit VORGABEWERT. Ohne ihn liesse sich `session_ttl_hours` still von 168 auf 1 ändern —
    # ein Verhaltensbruch für jeden, der das Feld nie angefasst hat, und genau die Sorte, die
    # niemand im CHANGELOG sucht. Der Wächter deckte bis 0.18.0 nur Name und Typ ab.
    felder = {}
    for f in TinySesamConfig.__dataclass_fields__.values():
        if f.default is not dataclasses.MISSING:
            vorgabe = repr(f.default)
        elif f.default_factory is not dataclasses.MISSING:   # type: ignore[misc]
            try:
                vorgabe = repr(f.default_factory())          # type: ignore[misc]
            except Exception:
                vorgabe = "<factory>"
        else:
            vorgabe = "<pflicht>"
        felder[f.name] = f"{f.type} = {vorgabe}"
    presets = {name: signatur(fn)
               for name, fn in inspect.getmembers(TinySesamConfig, callable)
               if not name.startswith("_")}
    exporte = sorted(getattr(_paket, "__all__", None)
                     or [n for n in dir(_paket) if not n.startswith("_")])
    # Öffentliche Klassenattribute gehören dazu. `inspect.getmembers(…, callable)` erfasst nur
    # Aufrufbares — `FORWARD_HEADERS_DEFAULT` liess sich damit still ändern, obwohl die Doku es
    # als Zusage führt („der Authelia-übliche Satz Remote-User/-Name/-Email/-Groups"). Eine
    # Änderung bricht jede Caddy-/Traefik-Installation, ohne dass eine Zeile Code anders aussieht.
    konstanten = {name: repr(wert) for name, wert in vars(TinySesam).items()
                  if not name.startswith("_") and not callable(wert)
                  and not isinstance(wert, (property, staticmethod, classmethod))}
    return {"TinySesam": manager, "TinySesam.konstanten": konstanten,
            "TinySesamConfig.felder": felder,
            "TinySesamConfig.methoden": presets, "exporte": exporte}


def _klammer_und_rest(sig: str) -> tuple:
    """`(a, b) -> 'bool'` → (`a, b`, ` -> 'bool'`). Bis T-13 schnitt `teile()` einfach das
    erste und letzte Zeichen ab — bei einer Signatur MIT Rückgabetyp landete der dann im
    letzten Parameter, und ein harmlos angehängter Parameter galt als BRUCH."""
    s, tiefe = sig.strip(), 0
    for i, c in enumerate(s):
        if c in "([{":
            tiefe += 1
        elif c in ")]}":
            tiefe -= 1
            if tiefe == 0:
                return s[1:i], s[i + 1:].strip()
    return s[1:-1], ""


def teile(sig: str) -> list:
    """Signatur-String in Parameter zerlegen — nur auf Kommas ausserhalb von Klammern."""
    inhalt = _klammer_und_rest(sig)[0]
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
    if _klammer_und_rest(alt)[1] != _klammer_und_rest(neu)[1]:
        return False                                  # anderer Rückgabetyp
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

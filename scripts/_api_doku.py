#!/usr/bin/env python3
"""Erzeugt API.md — die öffentliche Oberfläche von `TinySesam`, nach Stufe, mit Signatur und
erstem Satz.

Warum: 68 der 105 eingefrorenen Methoden kamen in keiner Doku vor. Wer TinySesam einbettet,
sah eine Zusage („diese Oberfläche bleibt stabil") ohne eine Stelle, an der steht, was sie
enthält. Der Wächter `tests/test_api_surface.py` misst dieselbe Menge — hier ist sie lesbar.

    python3 scripts/_api_doku.py              # schreiben
    python3 scripts/_api_doku.py --dry-run    # nur prüfen (Exit 1 = veraltet)

Seit 0.21.0 ist die Oberfläche nicht mehr nur gemessen, sondern **eingestuft** (PO-Entscheid
2026-09-26): Die Stufe jedes Namens steht in `tests/api_surface.json`, und diese Seite gliedert
danach — A „öffentlich, stabil ab 1.0", B „für Fortgeschrittene", C „intern". C steht ohne
Erklärung da (niemand soll dort einen Baustein finden), aber mit dem Ersatz: Seit 0.21.0 ist jeder
C-Name ein Alias, der beim Aufruf warnt (`tinysesam/_veraltet.py`), und wer die Warnung sieht,
sucht hier, was er stattdessen nimmt. Ein Name ohne Stufe landet sichtbar in einem eigenen
Abschnitt; rot macht ihn der Wächter, nicht diese Seite.
"""
from __future__ import annotations

import ast
import inspect
import json
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
ZIEL = ROOT / "API.md"
ABLAGE = ROOT / "tests" / "api_surface.json"

import tinysesam as paket  # noqa: E402
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import errors as fehler_modul  # noqa: E402
from tinysesam._veraltet import BIS, Veraltet  # noqa: E402

#: Überschrift und Zusage je Stufe — derselbe Wortlaut wie in den READMEs („Public API: three
#: tiers" / „Öffentliche API: drei Stufen").
STUFEN = {
    "A": ("öffentlich, stabil ab 1.0",
          "dokumentiert und/oder von Einbettenden genutzt",
          "Kein Bruch über zwei Minor-Versionen — die Bedingung für 1.0 "
          "([M-1](backlog/M-1-api-stabil-1-0.md)). Der Zähler startet mit 0.21.0, dem Release, "
          "das die Einstufung bringt."),
    "B": ("für Fortgeschrittene",
          "Bausteine für eigene Konto- und Admin-Seiten, eigene Mail- und Token-Abläufe, "
          "Erweiterungspunkte",
          "Bleibt. Entfernen oder umbauen erst, nachdem eine `DeprecationWarning` zwei "
          "Minor-Versionen lang darauf hingewiesen hat. Schwächer als A: Ein Umbau mit Vorlauf "
          "ist erlaubt."),
    "C": ("intern",
          "Verdrahtung der eingebauten Routen",
          "Keine. Die Implementierung trägt seit 0.21.0 einen führenden Unterstrich; der alte "
          "Name bleibt bis 1.0 als Alias, der beim Aufruf eine `DeprecationWarning` auslöst, und "
          "fällt dann weg."),
}

#: Die inneren Prüfer, vor denen der C-Abschnitt ausdrücklich warnt (PO-Befund 2026-09-26). Der
#: Text nennt sie beim Namen — steht einer nicht mehr in C, stimmt der Text nicht mehr.
UNGEDROSSELT = ("check_password", "check_pin", "check_ldap", "check_saml")

KOPF = """# API — die öffentliche Oberfläche von `TinySesam`

<!-- GENERIERT von scripts/_api_doku.py — nicht von Hand pflegen.
     Neu bauen: `python3 scripts/_api_doku.py` -->

Diese Namen hält `tests/api_surface.json` fest, jeden mit seiner **Stufe**: Was hier steht,
ändert sich nicht ohne eine bewusste Entscheidung und einen Eintrag im CHANGELOG.

Die READMEs zeigen die **Wege** (welche Methode wofür, wie man sie kombiniert). Hier steht, was
es überhaupt gibt — die Frage „gibt es dafür schon etwas?" beantwortet diese Seite, nicht der
Quelltext.

## Drei Stufen — was zugesagt ist

| Stufe | Was | Zusage |
|---|---|---|
"""


def erster_satz(fn) -> str:
    text = (inspect.getdoc(fn) or "").strip()
    if not text:
        return "—"
    satz = text.split("\n\n")[0].replace("\n", " ").strip()
    return satz.replace("|", "\\|")


def signatur(fn) -> str:
    try:
        s = inspect.signature(fn)
    except (TypeError, ValueError):
        return "(…)"
    teile = [str(p) for name, p in s.parameters.items() if name != "self"]
    zurueck = "" if s.return_annotation is inspect.Signature.empty else \
        f" -> {inspect.formatannotation(s.return_annotation)}"
    return "(" + ", ".join(teile) + ")" + zurueck


def stufen() -> dict:
    """{bereich: {name: stufe}} aus der Ablage des Wächters; fehlende Stufe = None."""
    if not ABLAGE.exists():
        return {}
    datei = json.loads(ABLAGE.read_text(encoding="utf-8"))
    return {bereich: {name: (e.get("stufe") if isinstance(e, dict) else None)
                      for name, e in eintraege.items()}
            for bereich, eintraege in datei.items() if isinstance(eintraege, dict)}


def kommentare(klasse) -> dict:
    """{NAME: Text} — die `#:`-Zeilen direkt über jeder Klassenzuweisung.

    Konstanten haben keinen Docstring; ihre Erklärung steht als `#:`-Block darüber (dieselbe
    Form, die Sphinx liest). Ein Zeilenende mit Bindestrich schliesst ohne Leerzeichen an; folgt
    ein Kleinbuchstabe, war es eine Worttrennung, und der Strich fällt weg.
    """
    quelle = Path(inspect.getsourcefile(klasse)).read_text(encoding="utf-8")
    zeilen = quelle.splitlines()
    knoten = next(k for k in ast.walk(ast.parse(quelle))
                  if isinstance(k, ast.ClassDef) and k.name == klasse.__name__)
    ergebnis = {}
    for anw in knoten.body:
        if not isinstance(anw, (ast.Assign, ast.AnnAssign)):
            continue
        ziele = anw.targets if isinstance(anw, ast.Assign) else [anw.target]
        block, i = [], anw.lineno - 2
        while i >= 0 and zeilen[i].strip().startswith("#:"):
            block.insert(0, zeilen[i].strip()[2:].strip())
            i -= 1
        text = ""
        for teil in block:
            if text.endswith("-") and teil[:1].islower():
                text = text[:-1] + teil               # „Anmelde-" + „faktor" → „Anmeldefaktor"
            elif text.endswith("-") or not text:
                text += teil                          # „E-" + „Mail" → „E-Mail"
            else:
                text += " " + teil
        for ziel in ziele:
            if isinstance(ziel, ast.Name):
                ergebnis[ziel.id] = text
    return ergebnis


def satz(text: str) -> str:
    """Der erste Satz — „z. B." beendet keinen (vor dem Punkt stehen mindestens zwei Zeichen)."""
    if not text:
        return "—"
    m = re.match(r"(.+?[^\s.][^\s.]\.)\s+(?=[A-ZÄÖÜ`„])", text)
    return (m.group(1) if m else text).replace("|", "\\|")


def wert(w) -> str:
    kurz = repr(w)
    if len(kurz) <= 200:
        return f"Wert: `{kurz}`"
    if isinstance(w, dict):
        return "Schlüssel: " + ", ".join(f"`{k}`" for k in w)
    if isinstance(w, (tuple, list)):
        return "Werte: " + ", ".join(f"`{x}`" for x in w)
    return f"Wert: `{kurz[:197]}…`"


def _abschnitt(titel: str, eintraege: list, vorspann: str = "") -> str:
    if not eintraege:
        return ""
    return f"## {titel}\n\n{vorspann}" + "".join(eintraege)


def bauen() -> str:
    st = stufen()

    def von(bereich, name):
        return st.get(bereich, {}).get(name)

    # `getmembers` liest jedes Attribut — auch die Konstanten-Aliase der Stufe C, die beim Lesen
    # warnen. Das Beschreiben ist kein Gebrauch.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        methoden = [(n, f) for n, f in inspect.getmembers(TinySesam, callable)
                    if not n.startswith("_")]
    eigenschaften = [(n, p) for n, p in inspect.getmembers_static(
                         TinySesam, lambda w: isinstance(w, property)) if not n.startswith("_")]
    aliase = {n: w for n, w in vars(TinySesam).items() if isinstance(w, Veraltet)}
    konstanten = sorted(n for n, w in vars(TinySesam).items()
                        if not n.startswith("_") and not callable(w)
                        and not isinstance(w, (property, staticmethod, classmethod))
                        and not (isinstance(w, Veraltet) and w.methode))
    presets = [(n, f) for n, f in inspect.getmembers(TinySesamConfig, callable)
               if not n.startswith("_")]
    felder = list(TinySesamConfig.__dataclass_fields__)
    exporte = sorted(getattr(paket, "__all__", None) or [n for n in dir(paket) if not n.startswith("_")])
    # Fehlertypen samt Hierarchie. Warum generiert und nicht bloss in den READMEs erzählt:
    # `api_surface.json` friert Namen und SIGNATUREN ein — welchen Typ eine Methode WIRFT, sieht
    # es nicht. Eine Änderung wie „totp_begin wirft jetzt StateError" blieb damit unsichtbar,
    # obwohl sie jeden Aufrufer trifft, der den alten Typ fängt (Nacharbeit zu B2-1).
    typen = [(n, k) for n, k in vars(fehler_modul).items()
             if isinstance(k, type) and issubclass(k, fehler_modul.TinySesamError)]
    typen.sort(key=lambda kv: (len(kv[1].__mro__), kv[0]))
    notiz = kommentare(TinySesam)

    # Wer ohne Stufe ist, steht am Ende sichtbar da — statt still in A zu landen.
    alle = ([("TinySesam", n) for n, _ in methoden] + [("TinySesam.eigenschaften", n) for n, _ in eigenschaften]
            + [("TinySesam.konstanten", n) for n in konstanten]
            + [("TinySesamConfig.methoden", n) for n, _ in presets]
            + [("TinySesamConfig.felder", n) for n in felder] + [("exporte", n) for n in exporte])
    zahl = {s: sum(1 for b, n in alle if von(b, n) == s) for s in STUFEN}
    ohne = [(b, n) for b, n in alle if von(b, n) not in STUFEN]

    for name in UNGEDROSSELT:
        assert von("TinySesam", name) == "C", (
            f"{name} ist nicht mehr Stufe C — den Warnsatz in scripts/_api_doku.py anpassen")

    teile = [KOPF]
    for s, (titel, was, zusage) in STUFEN.items():
        teile.append(f"| **{s} — {titel}** | {was} | {zusage} |\n")
    felder_a = sum(1 for f in felder if von("TinySesamConfig.felder", f) == "A")
    teile.append(
        "\nDie Stufe steht je Name in `tests/api_surface.json`. Der Wächter "
        "`tests/test_api_surface.py` verlangt für jeden öffentlichen Namen eine ausdrückliche: "
        "Ein neuer Name kommt ohne Stufe herein und hält ihn rot, bis jemand entscheidet — "
        "nichts wird aus Versehen zugesagt.\n\n"
        f"Die Konfigurationsfelder stehen in [KONFIGURATION.md](KONFIGURATION.md): {felder_a} "
        f"von {len(felder)} in Stufe A, die übrigen unten bei ihrer Stufe.\n\n"
        f"**Stand:** {' · '.join(f'{s} {n}' for s, n in zahl.items())} Namen"
        + (f", {len(ohne)} ohne Stufe" if ohne else "") + ".\n\n")

    for s in ("A", "B"):
        titel = f"{s} · "
        teile.append(_abschnitt(
            f"{titel}Methoden von `TinySesam`",
            [f"### `{n}{signatur(f)}`\n\n{erster_satz(f)}\n\n"
             for n, f in methoden if von("TinySesam", n) == s]))
        # Properties (seit 0.20.1 eingefroren wie die Methoden): Die Cookie-Namen sind die
        # dokumentierte Ersatz-API für feste Namen — eine Seite, die sie verschweigt, schickt
        # Integratoren zurück in den Quelltext.
        teile.append(_abschnitt(
            f"{titel}Eigenschaften von `TinySesam`",
            [f"### `{n}` — Property `{signatur(p.fget)[2:].strip()}`\n\n{erster_satz(p)}\n\n"
             for n, p in eigenschaften if von("TinySesam.eigenschaften", n) == s],
            "Ohne Klammern gelesen (`auth.csrf_cookie_name`). Zur Laufzeit berechnet: Sie folgen "
            "der Konfiguration, auch wenn `cfg` nach dem Aufbau geändert wird.\n\n"))
        teile.append(_abschnitt(
            f"{titel}Konstanten von `TinySesam`",
            [f"### `{n}` — Konstante\n\n{satz(notiz.get(n, ''))}\n\n{wert(getattr(TinySesam, n))}\n\n"
             for n in konstanten if von("TinySesam.konstanten", n) == s],
            "Klassenattribute, gelesen als `TinySesam.NAME` oder `auth.NAME`. Der Wert gehört "
            "zur Zusage — der Wächter hält ihn fest.\n\n"))
        # Die Felder der Stufe A stehen vollständig in KONFIGURATION.md; hier nur die Ausnahmen.
        eigene_felder = [f for f in felder if von("TinySesamConfig.felder", f) == s]
        teile.append(_abschnitt(
            f"{titel}`TinySesamConfig`",
            ([f"Felder dieser Stufe (Bedeutung in [KONFIGURATION.md](KONFIGURATION.md)): "
              + ", ".join(f"`{f}`" for f in eigene_felder) + ".\n\n"]
             if eigene_felder and s != "A" else [])
            + [f"### `TinySesamConfig.{n}{signatur(f)}`\n\n{erster_satz(f)}\n\n"
               for n, f in presets if von("TinySesamConfig.methoden", n) == s],
            "`TinySesamConfig` ist eine Dataclass und bleibt eine: `dataclasses.fields("
            "TinySesamConfig)` zählt jedes Feld auf. Presets setzen Bündel dieser Felder, "
            "einzelne lassen sich per `**overrides` überschreiben.\n\n" if s == "A" else ""))
        eigene_typen = [(n, k) for n, k in typen if von("exporte", n) == s]
        teile.append(_abschnitt(
            f"{titel}Fehlertypen",
            [f"### `{n}` (erbt von {', '.join(f'`{b.__name__}`' for b in k.__bases__)})\n\n"
             f"{erster_satz(k)}\n\n" for n, k in eigene_typen],
            "Exportiert aus `tinysesam`. Jeder erbt zusätzlich von dem eingebauten Typ, den "
            "er ersetzt — bestehendes `except ValueError` / `except RuntimeError` fängt "
            "weiter, es wird nur unterscheidbar. **Auf den Meldungstext prüft niemand:** er "
            "ist übersetzt und darf sich ändern; die Typen hier und die Attribute an ihnen "
            "sind die Zusage.\n\n"))
        uebrige = [n for n in exporte if von("exporte", n) == s and n not in dict(typen)]
        klassen = [n for n in uebrige if not inspect.isfunction(getattr(paket, n))]
        teile.append(_abschnitt(
            f"{titel}weitere Exporte von `tinysesam`",
            (["".join(f"- `{n}`\n" for n in klassen) + "\n"] if klassen else [])
            + [f"### `tinysesam.{n}{signatur(getattr(paket, n))}`\n\n"
               f"{erster_satz(getattr(paket, n))}\n\n"
               for n in uebrige if inspect.isfunction(getattr(paket, n))]))

    intern = [(b, n) for b, n in alle if von(b, n) == "C"]
    if intern:
        teile.append(
            f"## C · Veraltet — fällt mit {BIS} weg\n\n"
            "Diese Namen gehören nicht zur Zusage. Seit 0.21.0 heisst die Implementierung "
            f"`_name`; der alte Name bleibt bis {BIS} als Alias, der **beim Aufruf** (Konstanten: "
            "beim Lesen) eine `DeprecationWarning` mit dem Ersatz auslöst, und fällt dann weg. "
            "**Neu nicht verwenden** — für eigene Seiten stehen die Bausteine in A und B. Wer "
            "prüfen will, ob seine App einen davon ruft, lässt ihre Tests einmal mit "
            "`python -W error::DeprecationWarning` laufen.\n\n"
            "**Vorsicht bei den inneren Prüfern** "
            + ", ".join(f"`{n}`" for n in UNGEDROSSELT) + ": Sie drosseln nicht selbst — "
            "Sperre, Fehlversuchszähler und Serie setzen nur die eingebauten Routen. Eine eigene "
            "Login-Seite, die sie aufruft, ist gegen Passwort-Raten ungeschützt.\n\n"
            "| Alter Name | Art | Ersatz |\n|---|---|---|\n")
        for b, n in sorted(intern, key=lambda bn: bn[1].lower()):
            alias = aliase.get(n)
            art = "Konstante" if b == "TinySesam.konstanten" else "Methode"
            ersatz = alias.ersatz if alias else "— (kein Alias: Wächter rot)"
            ersatz = ersatz.removeprefix("stattdessen ").replace("|", "\\|")
            teile.append(f"| `{n}` | {art} | {ersatz[:1].upper()}{ersatz[1:]} |\n")
        teile.append("\n")

    if ohne:
        teile.append("## Ohne Stufe\n\nDer Wächter `tests/test_api_surface.py` ist rot, bis diese "
                     "Namen eine Stufe tragen:\n\n"
                     + "".join(f"- `{b}.{n}`\n" for b, n in ohne) + "\n")

    teile.append(f"---\n\n{len(methoden)} Methoden, {len(eigenschaften)} Eigenschaften, "
                 f"{len(konstanten)} Konstanten, {len(presets)} Methoden von `TinySesamConfig`, "
                 f"{len(exporte)} Exporte, davon {len(typen)} Fehlertypen — erzeugt aus den "
                 "Docstrings und `tests/api_surface.json`.\n")
    return "".join(teile)


def main() -> int:
    neu = bauen()
    alt = ZIEL.read_text(encoding="utf-8") if ZIEL.exists() else ""
    if "--dry-run" in sys.argv:
        if alt != neu:
            print(f"{ZIEL.name} ist veraltet — `python3 scripts/_api_doku.py` fahren", file=sys.stderr)
            return 1
        return 0
    ZIEL.write_text(neu, encoding="utf-8")
    print(f"geschrieben: {ZIEL.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

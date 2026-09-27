"""Die öffentliche API festhalten — damit ein Bruch AUFFÄLLT, statt zu passieren.

Der Meilenstein 1.0 verlangt, dass die öffentliche API sich über zwei Minor-Versionen nicht mehr
bricht (`backlog/M-1-api-stabil-1-0.md`). Ohne Messung ist das eine Behauptung: Beide letzten
Releases haben gebrochen, und beide Male fiel es erst beim Schreiben des CHANGELOG auf.

Dieser Test schreibt die Oberfläche in `tests/api_surface.json` fest und vergleicht bei jedem Lauf.
Erfasst werden Methoden, Klassenkonstanten, seit 0.20.1 auch die Properties (die Cookie-Namen),
die Konfigurationsfelder mit Vorgabe, die Presets und die Exporte.
Er verbietet nichts — er erzwingt eine **bewusste Entscheidung**:

    python tests/test_api_surface.py --update      # Änderung übernehmen, danach committen

Was als Bruch gilt, steht unten in `beurteile()`: Entfernt oder umbenannt ist ein Bruch,
eine geänderte Signatur meistens auch, etwas Neues ist eine Erweiterung. Die Unterscheidung
steht im Bericht, damit man nicht jede Zeile selbst nachschlagen muss.

**Seit 0.21.0 trägt jeder Name eine Stufe** (PO-Entscheid 2026-09-26, `STUFEN` unten): A ist
dauerhaft öffentlich und die einzige Stufe mit der 1.0-Zusage, B ist für Fortgeschrittene mit
schwächerer Zusage, C ist intern. Bis dahin war die Oberfläche *gemessen, nicht ausgewählt* —
eingefroren war, was keinen Unterstrich trug. Die Stufe ist eine Entscheidung, keine Messung:
Sie steht je Eintrag in `api_surface.json`, `--update` übernimmt sie, vergibt aber NIE selbst
eine. Ein neuer Name kommt ohne Stufe herein und hält den Wächter rot, bis jemand sie einträgt
— ein stilles „A" hätte jede Hilfsmethode, die zufällig ohne Unterstrich entsteht, für immer
zugesagt.
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

#: Die Stufen der öffentlichen Oberfläche (PO-Entscheid 2026-09-26). Nur für A gilt die Zusage
#: aus M-1 („zwei Minor-Versionen ohne Bruch“); der Zähler startet mit 0.21.0.
STUFEN = {
    "A": "öffentlich, stabil ab 1.0 — ein Bruch setzt die 1.0-Uhr zurück (M-1)",
    "B": "für Fortgeschrittene — entfernen oder umbauen erst nach einer DeprecationWarning "
         "über zwei Minor-Versionen",
    "C": "intern — bekommt einen führenden Unterstrich, der alte Name bleibt bis 1.0 als Alias "
         "mit DeprecationWarning",
}

#: Unter welchem Schlüssel ein Eintrag in `api_surface.json` seinen GEMESSENEN Wert trägt.
#: Alles andere am Eintrag (`stufe`, später Alias-Angaben) ist Entscheidung und wird von
#: `--update` übernommen, nicht neu gemessen. Die Exporte haben keinen Messwert — nur den Namen.
MESSWERT = {"TinySesam": "sig", "TinySesam.eigenschaften": "sig",
            "TinySesamConfig.methoden": "sig", "TinySesam.konstanten": "wert",
            "TinySesamConfig.felder": "feld", "exporte": None}


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
    # Properties gehören ebenso dazu (0.20.1): `session_cookie_name`, `csrf_cookie_name`,
    # `resource_cookie_name` sind die dokumentierte Ersatz-API für feste Cookie-Namen. Erfasst
    # wird der Rückgabetyp des Getters; ein Setter hängt „(schreibbar)" an.
    eigenschaften = {name: signatur(wert.fget) + (" (schreibbar)" if wert.fset else "")
                     for name, wert in inspect.getmembers(TinySesam,
                                                          lambda w: isinstance(w, property))
                     if not name.startswith("_")}
    return {"TinySesam": manager, "TinySesam.konstanten": konstanten,
            "TinySesam.eigenschaften": eigenschaften,
            "TinySesamConfig.felder": felder,
            "TinySesamConfig.methoden": presets, "exporte": exporte}


def messung(datei: dict) -> dict:
    """Die Ablage auf die reine Messung zurückführen — die Form, die `oberflaeche()` liefert.

    Verträgt auch die Ablage von vor 0.21.0 (Wert als Zeichenkette, Exporte als Liste): Ein
    Vergleich mit einem älteren Release (`git show v0.20.1:tests/api_surface.json`) soll nicht an
    der Form scheitern.
    """
    ergebnis = {}
    for bereich, eintraege in datei.items():
        if isinstance(eintraege, list):
            ergebnis[bereich] = sorted(eintraege)
            continue
        schluessel = MESSWERT.get(bereich)
        if schluessel is None:
            ergebnis[bereich] = sorted(eintraege)
            continue
        ergebnis[bereich] = {name: (e[schluessel] if isinstance(e, dict) else e)
                             for name, e in eintraege.items()}
    return ergebnis


def mit_stufen(jetzt: dict, frueher: dict) -> dict:
    """Die neue Ablage: gemessene Werte von `jetzt`, jede Entscheidung aus `frueher`.

    Übernommen wird alles am alten Eintrag ausser dem Messwert — die `stufe`, später auch
    Alias-Angaben —, und zwar nur für denselben Namen im selben Bereich. Ein neuer Name bekommt
    KEINE Stufe: Der Wächter meldet ihn dann, statt ihn still zuzusagen.
    """
    ablage = {}
    for bereich, gemessen in jetzt.items():
        alt = frueher.get(bereich, {})
        if isinstance(alt, list):                     # Form vor 0.21.0: keine Entscheidungen
            alt = {}
        schluessel = MESSWERT[bereich]
        neu = {}
        for name in (gemessen if schluessel is None else sorted(gemessen)):
            vorher = alt.get(name)
            eintrag = ({k: v for k, v in vorher.items() if k != schluessel}
                       if isinstance(vorher, dict) else {})
            if schluessel is not None:
                eintrag[schluessel] = gemessen[name]
            neu[name] = eintrag
        ablage[bereich] = neu
    return ablage


def stufen_aus(datei: dict) -> dict:
    """{bereich: {name: stufe}} — nur Einträge, die eine tragen."""
    return {bereich: {name: e["stufe"] for name, e in eintraege.items()
                      if isinstance(e, dict) and "stufe" in e}
            for bereich, eintraege in datei.items() if isinstance(eintraege, dict)}


def ohne_stufe(datei: dict) -> list:
    """Jeder Eintrag ohne gültige Stufe, als lesbare Zeile. Leer = alles eingestuft."""
    fehlt = []
    for bereich in sorted(datei):
        eintraege = datei[bereich]
        if not isinstance(eintraege, dict):
            fehlt.append(f"{bereich}: ganze Liste ohne Stufen (Form vor 0.21.0)")
            continue
        for name in sorted(eintraege):
            e = eintraege[name]
            stufe = e.get("stufe") if isinstance(e, dict) else None
            if stufe is None:
                fehlt.append(f"{bereich}.{name}: keine Stufe")
            elif stufe not in STUFEN:
                fehlt.append(f"{bereich}.{name}: unbekannte Stufe {stufe!r} "
                             f"(erlaubt: {', '.join(STUFEN)})")
    return fehlt


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


def beurteile(alt: dict, neu: dict, stufen: "dict | None" = None):
    """(brueche, erweiterungen) — beides mit lesbarer Beschreibung.

    Mit `stufen` (aus `stufen_aus()` der alten Ablage) beginnt jeder Bruch mit der Stufe des
    Namens, `[A] …`: Ob die 1.0-Uhr zurückspringt, hängt allein daran.
    """
    brueche, erweiterungen = [], []

    def marke(bereich, name):
        if stufen is None:
            return ""
        return f"[{stufen.get(bereich, {}).get(name, '?')}] "

    for bereich in sorted(set(alt) | set(neu)):
        a, n = alt.get(bereich, {}), neu.get(bereich, {})
        if isinstance(a, list) or isinstance(n, list):
            fort = sorted(set(a) - set(n))
            dazu = sorted(set(n) - set(a))
            brueche += [f"{marke(bereich, x)}{bereich}: '{x}' ist fort" for x in fort]
            erweiterungen += [f"{bereich}: '{x}' ist neu" for x in dazu]
            continue
        for name in sorted(set(a) - set(n)):
            brueche.append(f"{marke(bereich, name)}{bereich}.{name} ist fort "
                           "(entfernt oder umbenannt)")
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
                brueche.append(marke(bereich, name) + zeile)
    return brueche, erweiterungen


#: Diese Properties MÜSSEN in der Oberfläche stehen — der CHANGELOG von 0.20.0 schickt jede
#: einbettende App zu ihnen („den CSRF-Cookie-Namen aus `auth.csrf_cookie_name` lesen").
PFLICHT_EIGENSCHAFTEN = ("session_cookie_name", "csrf_cookie_name", "resource_cookie_name")


def selbstpruefung(jetzt: dict) -> None:
    """Misst der Wächter die Properties überhaupt? (0.20.1)

    Bis 0.20.0 schloss `oberflaeche()` sie ausdrücklich aus (`isinstance(wert, property)`), und
    `getmembers(…, callable)` sieht sie ohnehin nicht. Ein Umbenennen von `csrf_cookie_name` —
    genau des Namens, den eigenes JS und eigene Routen brauchen — fiel damit keinem Wächter auf.
    Läuft auch vor `--update`: Sonst liesse sich der Ausschluss samt neuem Abzug einchecken.
    (Mutationsprobe: in `oberflaeche()` den Bereich `TinySesam.eigenschaften` streichen → rot.)
    """
    eig = jetzt.get("TinySesam.eigenschaften", {})
    fehlt = [n for n in PFLICHT_EIGENSCHAFTEN if n not in eig]
    assert not fehlt, f"Properties fehlen in der eingefrorenen Oberfläche: {fehlt}"
    # Gegenprobe am Vergleich selbst: Ein umbenanntes Property ist ein BRUCH, keine Erweiterung.
    umbenannt = json.loads(json.dumps(jetzt))
    umbenannt["TinySesam.eigenschaften"]["csrf_cookie"] = \
        umbenannt["TinySesam.eigenschaften"].pop("csrf_cookie_name")
    brueche, _ = beurteile(jetzt, umbenannt)
    assert any("csrf_cookie_name ist fort" in b for b in brueche), brueche
    ok(f"Properties eingefroren ({len(eig)}), ein Umbenennen gälte als Bruch")


def selbstpruefung_stufen(jetzt: dict) -> None:
    """Schlägt die Stufen-Pflicht an, und vergibt `--update` wirklich keine Stufe? (0.21.0)

    An synthetischen Ablagen aus der echten Messung, damit die Prüfung nicht an der
    eingecheckten Datei hängt, die gerade vollständig sein mag. Läuft auch vor `--update`.
    """
    assert set(MESSWERT) == set(jetzt), (
        f"Bereiche ohne Messwert-Schlüssel: {sorted(set(jetzt) - set(MESSWERT))} — "
        "MESSWERT ergänzen, sonst weiss die Ablage nicht, was gemessen und was entschieden ist")
    gesamt = sum(len(v) for v in jetzt.values())
    # 1. Frisch gemessen trägt KEIN Eintrag eine Stufe — jeder einzelne wird gemeldet.
    roh = mit_stufen(jetzt, {})
    assert len(ohne_stufe(roh)) == gesamt, (len(ohne_stufe(roh)), gesamt)
    # 2. Alles eingestuft → nichts gemeldet; eine unbekannte Stufe (auch kleingeschrieben) → gemeldet.
    voll = json.loads(json.dumps(roh))
    for eintraege in voll.values():
        for e in eintraege.values():
            e["stufe"] = "A"
    assert ohne_stufe(voll) == [], ohne_stufe(voll)
    for bereich, falsch in (("TinySesam", "a"), ("exporte", "D")):
        kaputt = json.loads(json.dumps(voll))
        name = sorted(kaputt[bereich])[0]
        kaputt[bereich][name]["stufe"] = falsch
        assert any(f"{bereich}.{name}: unbekannte Stufe" in z for z in ohne_stufe(kaputt)), falsch
        del kaputt[bereich][name]["stufe"]
        assert f"{bereich}.{name}: keine Stufe" in ohne_stufe(kaputt), bereich
    # 3. `--update` übernimmt Entscheidungen, misst neu, und ein neuer Name bleibt ohne Stufe.
    frueher = json.loads(json.dumps(voll))
    methode = sorted(frueher["TinySesam"])[0]
    frueher["TinySesam"][methode].update(stufe="B", sig="(veraltet)", ersatz="neu_name")
    del frueher["TinySesam"][sorted(frueher["TinySesam"])[1]]      # „neu" seit der alten Ablage
    del frueher["exporte"][sorted(frueher["exporte"])[0]]
    frueher["TinySesam"]["fort_seit_langem"] = {"sig": "()", "stufe": "A"}
    neu = mit_stufen(jetzt, frueher)
    assert neu["TinySesam"][methode] == {"sig": jetzt["TinySesam"][methode], "stufe": "B",
                                         "ersatz": "neu_name"}, neu["TinySesam"][methode]
    assert "fort_seit_langem" not in neu["TinySesam"]
    assert ohne_stufe(neu) == [f"TinySesam.{sorted(jetzt['TinySesam'])[1]}: keine Stufe",
                               f"exporte.{sorted(jetzt['exporte'])[0]}: keine Stufe"], ohne_stufe(neu)
    # 4. Die Ablage führt verlustfrei auf die Messung zurück — sonst vergliche `beurteile` Äpfel.
    assert messung(neu) == jetzt
    # 5. Ein Bruch nennt die Stufe des Namens.
    weg = json.loads(json.dumps(jetzt))
    del weg["TinySesam"][methode]
    brueche, _ = beurteile(jetzt, weg, stufen_aus(neu))
    assert brueche and brueche[0].startswith(f"[B] TinySesam.{methode} ist fort"), brueche
    # 6. Der normale Lauf — dieselbe Funktion, die `main()` ausführt — ist rot, sobald EIN Name
    #    ohne Stufe ist, auch wenn sich an der Messung nichts geändert hat.
    rot, fehlt, b, e = vergleiche(voll, jetzt)
    assert (rot, fehlt, b, e) == (False, [], [], []), (rot, fehlt, b, e)
    luecke = json.loads(json.dumps(voll))
    del luecke["TinySesam.eigenschaften"]["csrf_cookie_name"]["stufe"]
    rot, fehlt, b, e = vergleiche(luecke, jetzt)
    assert rot and fehlt == ["TinySesam.eigenschaften.csrf_cookie_name: keine Stufe"] \
        and not b and not e, (rot, fehlt, b, e)
    ok(f"Stufen-Pflicht greift ({gesamt} Namen): fehlende und unbekannte Stufe gemeldet, "
       "`--update` vergibt keine")


def vergleiche(frueher_datei: dict, jetzt: dict) -> tuple:
    """(rot, ohne_stufe, brueche, erweiterungen) — die ganze Entscheidung des normalen Laufs.

    Eine eigene Funktion, damit die Selbstprüfung genau das prüft, was `main()` ausführt: Eine
    Stufen-Prüfung, die nur in der Selbstprüfung stünde, liefe im echten Lauf ins Leere.
    """
    fehlt = ohne_stufe(frueher_datei)
    brueche, erweiterungen = beurteile(messung(frueher_datei), jetzt, stufen_aus(frueher_datei))
    return bool(fehlt or brueche or erweiterungen), fehlt, brueche, erweiterungen


def _zaehle_stufen(datei: dict) -> str:
    zahl = {s: 0 for s in STUFEN}
    for je_name in stufen_aus(datei).values():
        for stufe in je_name.values():
            zahl[stufe] = zahl.get(stufe, 0) + 1
    return ", ".join(f"{s} {n}" for s, n in zahl.items())


def _melde_ohne_stufe(fehlt: list) -> None:
    print(f"\n  {len(fehlt)} öffentliche Namen ohne gültige Stufe:\n")
    for zeile in fehlt:
        print(f"    OHNE STUFE   {zeile}")
    print("\n  Jeder öffentliche Name braucht eine ausdrückliche Stufe — in tests/api_surface.json")
    print('  am Eintrag `"stufe": "A"|"B"|"C"` setzen (Bedeutung: API.md, „Drei Stufen“):')
    for stufe, text in STUFEN.items():
        print(f"    {stufe}  {text}")
    print("  Nichts Öffentliches soll aus Versehen entstehen: Ist der Name intern, bekommt er einen")
    print("  führenden Unterstrich und verschwindet aus der Ablage.\n")


def main(argv):
    jetzt = oberflaeche()
    selbstpruefung(jetzt)
    selbstpruefung_stufen(jetzt)

    frueher_datei = {}
    if os.path.exists(ABLAGE):
        with open(ABLAGE, encoding="utf-8") as fh:
            frueher_datei = json.load(fh)

    if "--update" in argv:
        ablage = mit_stufen(jetzt, frueher_datei)
        with open(ABLAGE, "w", encoding="utf-8") as fh:
            json.dump(ablage, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        print(f"  Oberfläche festgeschrieben: {ABLAGE}")
        fehlt = ohne_stufe(ablage)
        if fehlt:
            _melde_ohne_stufe(fehlt)
            return 1
        return 0

    if not frueher_datei:
        print(f"  {ABLAGE} fehlt — einmalig anlegen mit: python tests/test_api_surface.py --update")
        return 1

    rot, fehlt, brueche, erweiterungen = vergleiche(frueher_datei, jetzt)
    if fehlt:
        _melde_ohne_stufe(fehlt)
    else:
        ok(f"jeder öffentliche Name hat eine Stufe ({_zaehle_stufen(frueher_datei)})")

    if not brueche and not erweiterungen:
        n = sum(len(v) for v in jetzt.values())
        ok(f"öffentliche API unverändert ({n} Namen)")
        return 1 if rot else 0

    print("\n  Die öffentliche API hat sich geändert.\n")
    for b in brueche:
        print(f"    BRUCH        {b}")
    for e in erweiterungen:
        print(f"    Erweiterung  {e}")
    print("\n  Ein Bruch kostet die Nutzer Arbeit. Was er kostet, sagt die Stufe davor:")
    for stufe, text in STUFEN.items():
        print(f"    [{stufe}] {text}")
    print("  War die Änderung gewollt: `python tests/test_api_surface.py --update`, dann committen")
    print("  — und im CHANGELOG darauf hinweisen, wenn ein BRUCH dabei ist. Ein neuer Name")
    print("  braucht danach noch seine Stufe.\n")
    return 1


if __name__ == "__main__":
    code = main(sys.argv[1:])
    print("\nAPI-OBERFLÄCHE " + ("OK ✅" if code == 0 else "GEÄNDERT ODER OHNE STUFE ❌"))
    sys.exit(code)

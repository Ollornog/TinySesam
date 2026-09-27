"""Die öffentliche API festhalten — damit ein Bruch AUFFÄLLT, statt zu passieren.

Der Meilenstein 1.0 verlangt, dass die öffentliche API sich über zwei Minor-Versionen nicht mehr
bricht (`backlog/M-1-api-stabil-1-0.md`). Ohne Messung ist das eine Behauptung: Beide letzten
Releases haben gebrochen, und beide Male fiel es erst beim Schreiben des CHANGELOG auf.

Dieser Test schreibt die Oberfläche in `tests/api_surface.json` fest und vergleicht bei jedem Lauf.
Erfasst werden Methoden, Klassenkonstanten, seit 0.20.1 auch die Properties (die Cookie-Namen),
die Konfigurationsfelder mit Vorgabe, die Presets und die Exporte, seit 0.22.0 dazu der
Ergebnistyp der Anmelde-Bausteine (`LoginResult`: Felder, Methoden, Gründe).
Er verbietet nichts — er erzwingt eine **bewusste Entscheidung**:

    python tests/test_api_surface.py --update      # Änderung übernehmen, danach committen

Was als Bruch gilt, steht unten in `beurteile()`: Entfernt oder umbenannt ist ein Bruch,
eine geänderte Signatur meistens auch, etwas Neues ist eine Erweiterung. Die Unterscheidung
steht im Bericht, damit man nicht jede Zeile selbst nachschlagen muss.

**Seit 0.22.0 trägt jeder Name eine Stufe** (PO-Entscheid 2026-09-26, `STUFEN` unten): A ist
dauerhaft öffentlich und die einzige Stufe mit der 1.0-Zusage, B ist für Fortgeschrittene mit
schwächerer Zusage, C ist intern. Bis dahin war die Oberfläche *gemessen, nicht ausgewählt* —
eingefroren war, was keinen Unterstrich trug. Die Stufe ist eine Entscheidung, keine Messung:
Sie steht je Eintrag in `api_surface.json`, `--update` übernimmt sie, vergibt aber NIE selbst
eine. Ein neuer Name kommt ohne Stufe herein und hält den Wächter rot, bis jemand sie einträgt
— ein stilles „A" hätte jede Hilfsmethode, die zufällig ohne Unterstrich entsteht, für immer
zugesagt.

**Stufe C ist seit 0.22.0 nur noch ein Alias** (`tinysesam/_veraltet.py`): Die Implementierung
heisst `_name`, der alte Name reicht bis 1.0 weiter und warnt. Der Wächter hält dazu fest
(`c_befunde()`): Jeder C-Eintrag ist in der Klasse ein `Veraltet` und umgekehrt, er zeigt auf die
Unterstrich-Implementierung, sein Aufruf warnt genau einmal mit Ersatz und auf den Aufrufer, kein
Code im Paket benutzt einen alten Namen, und ab 1.0 steht keiner mehr da.
"""
import ast
import dataclasses
import inspect
import json
import os
import subprocess
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
from tinysesam import LoginResult, TinySesam, TinySesamConfig
from tinysesam._veraltet import BIS, Veraltet

_paket = importlib.import_module("tinysesam")
WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ABLAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_surface.json")

#: Die Stufen der öffentlichen Oberfläche (PO-Entscheid 2026-09-26). Nur für A gilt die Zusage
#: aus M-1 („zwei Minor-Versionen ohne Bruch“); der Zähler startet mit 0.22.0.
STUFEN = {
    "A": "öffentlich, stabil ab 1.0 — ein Bruch setzt die 1.0-Uhr zurück (M-1)",
    "B": "für Fortgeschrittene — entfernen oder umbauen erst nach einer DeprecationWarning "
         "über zwei Minor-Versionen",
    "C": "intern — die Implementierung trägt einen führenden Unterstrich, der alte Name bleibt "
         "bis 1.0 als Alias mit DeprecationWarning (Eintrag mit `ziel`, `seit`, `bis`)",
}

#: Seit wann die C-Aliase warnen (Zusatzfeld `seit` an jedem C-Eintrag).
C_SEIT = "0.22.0"

#: Unter welchem Schlüssel ein Eintrag in `api_surface.json` seinen GEMESSENEN Wert trägt.
#: Alles andere am Eintrag (`stufe`, später Alias-Angaben) ist Entscheidung und wird von
#: `--update` übernommen, nicht neu gemessen. Die Exporte haben keinen Messwert — nur den Namen.
MESSWERT = {"TinySesam": "sig", "TinySesam.eigenschaften": "sig",
            "TinySesamConfig.methoden": "sig", "TinySesam.konstanten": "wert",
            "TinySesamConfig.felder": "feld", "exporte": None, "LoginResult": "sig"}


def ok(name):
    print(f"  ✓ {name}")


def parameter_mit_marken(parameter) -> list:
    """`str(p)` je Parameter, dazu die Marken `*` (davor nur Schlüsselwort) und `/` (davor nur
    Position) an der Stelle, an der Python sie in der Signatur verlangt.

    Bis 0.22.0 setzte `signatur()` die Parameter einzeln zusammen und verlor dabei beide Marken:
    `(request, username, password, *, next='')` stand als `(…, password, next='')` in der Ablage.
    Ein nachträglich eingefügtes `*` — jeder Aufruf `login_password(r, u, p, "/start")` bricht
    — sah damit aus wie keine Änderung (Befund aus Schritt 3 der Einstufung, M-1).
    """
    teile, stern = [], any(p.kind is p.VAR_POSITIONAL for p in parameter)
    for i, p in enumerate(parameter):
        erster_kw = i == 0 or parameter[i - 1].kind is not p.KEYWORD_ONLY
        if p.kind is p.KEYWORD_ONLY and not stern and erster_kw:
            teile.append("*")
        teile.append(str(p))
        if p.kind is p.POSITIONAL_ONLY and (i + 1 == len(parameter)
                                            or parameter[i + 1].kind is not p.POSITIONAL_ONLY):
            teile.append("/")
    return teile


def signatur(fn) -> str:
    """Die Signatur ohne `self` — Parameternamen und Reihenfolge sind Teil des Versprechens.

    Erfasst wird auch, ob ein Parameter keyword-only ist: Genau daran hing der Bruch in 0.15
    (`require_role("editor", True)` meinte einmal `mfa=True` und wäre danach eine zweite Rolle).
    Seit 0.22.0 wirklich: mit den Marken `*` und `/` (`parameter_mit_marken`).
    """
    try:
        s = inspect.signature(fn)
    except (TypeError, ValueError):
        return "?"
    teile = parameter_mit_marken([p for name, p in s.parameters.items() if name != "self"])
    # Der Rückgabetyp gehört dazu. Ohne ihn liesse sich `-> dict` still zu `-> str` ändern:
    # Jeder Aufruf bricht, und der Wächter schwiege — er erfasste nur die Eingänge.
    zurueck = "" if s.return_annotation is inspect.Signature.empty else \
        f" -> {inspect.formatannotation(s.return_annotation)}"
    return "(" + ", ".join(teile) + ")" + zurueck


def oberflaeche() -> dict:
    """Was ein Einbindender benutzt: die Klasse, die Konfiguration, die Exporte."""
    # Das Messen ist kein Gebrauch: `getmembers` liest jedes Attribut, auch die Konstanten-Aliase
    # der Stufe C, und die warnen beim Lesen. Methoden-Aliase liefern hier ihre Hülle — deren
    # Signatur ist über `__wrapped__` die des Ziels, und genau die ist zugesagt.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
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
    # Ein Konstanten-Alias (Stufe C) wird mit dem Wert seines Ziels gemessen — statisch gelesen,
    # ohne ihn auszulösen; ein Methoden-Alias steht oben bei den Methoden.
    konstanten = {}
    for name, wert in vars(TinySesam).items():
        if isinstance(wert, Veraltet):
            if wert.methode:
                continue
            wert = vars(TinySesam)[wert.ziel]
        elif callable(wert) or isinstance(wert, (property, staticmethod, classmethod)):
            continue
        if not name.startswith("_"):
            konstanten[name] = repr(wert)
    # Properties gehören ebenso dazu (0.20.1): `session_cookie_name`, `csrf_cookie_name`,
    # `resource_cookie_name` sind die dokumentierte Ersatz-API für feste Cookie-Namen. Erfasst
    # wird der Rückgabetyp des Getters; ein Setter hängt „(schreibbar)" an. Statisch gelesen:
    # Ein Property ist auch dann das Property-Objekt, und kein Konstanten-Alias warnt dabei.
    eigenschaften = {name: signatur(wert.fget) + (" (schreibbar)" if wert.fset else "")
                     for name, wert in inspect.getmembers_static(
                         TinySesam, lambda w: isinstance(w, property))
                     if not name.startswith("_")}
    return {"TinySesam": manager, "TinySesam.konstanten": konstanten,
            "TinySesam.eigenschaften": eigenschaften,
            "TinySesamConfig.felder": felder,
            "TinySesamConfig.methoden": presets, "exporte": exporte,
            "LoginResult": ergebnistyp_oberflaeche()}


def ergebnistyp_oberflaeche() -> dict:
    """Der Ergebnistyp der Anmelde-Bausteine (0.22.0, Stufe A): Felder, Methoden, Gründe.

    Die Exporte erfasst der Wächter nur beim Namen. Für `LoginResult` genügt das nicht: Wer
    `result.next_factor` liest oder auf `result.reason == "locked"` prüft, bricht an einem
    umbenannten Feld oder einem gestrichenen Grund genauso wie an einer umbenannten Methode.
    Felder mit Typ und Vorgabe (wie die Konfiguration), Methoden mit Signatur, `REASONS` mit dem
    Wert.
    """
    ergebnis = {}
    for f in dataclasses.fields(LoginResult):
        vorgabe = "<pflicht>" if f.default is dataclasses.MISSING else repr(f.default)
        ergebnis[f.name] = f"{f.type} = {vorgabe}"
    ergebnis.update({name: signatur(fn) for name, fn in inspect.getmembers(LoginResult, inspect.isfunction)
                     if not name.startswith("_")})
    ergebnis["REASONS"] = repr(LoginResult.REASONS)
    return ergebnis


class OhneMarken(str):
    """Eine Signatur aus einer Ablage von vor 0.22.0: gemessen OHNE die Marken `*` und `/`.

    Wo die Marken standen, weiss so ein Eintrag nicht mehr. `beurteile()` vergleicht ihn deshalb
    mit der heutigen Messung ohne Marken (`ohne_marken`) — sonst meldete ein Vergleich mit einem
    älteren Release jede Methode mit Nur-Schlüsselwort-Parametern als Bruch, und ein echter
    ginge darin unter. Ein Unterschied in Namen, Reihenfolge, Vorgaben oder Rückgabe bleibt einer.
    """


def ohne_marken(sig: str) -> str:
    """`(a, *, b=1) -> 'x'` → `(a, b=1) -> 'x'` — die Form, in der vor 0.22.0 gemessen wurde."""
    rest = _klammer_und_rest(sig)[1]
    return ("(" + ", ".join(t for t in teile(sig) if t not in ("*", "/")) + ")"
            + (" " + rest if rest else ""))


def messung(datei: dict) -> dict:
    """Die Ablage auf die reine Messung zurückführen — die Form, die `oberflaeche()` liefert.

    Verträgt auch die Ablage von vor 0.22.0 (Wert als Zeichenkette, Exporte als Liste): Ein
    Vergleich mit einem älteren Release (`git show v0.21.0:tests/api_surface.json`) soll nicht an
    der Form scheitern. Deren Signaturen kamen ohne die Marken `*`/`/` — sie werden als
    `OhneMarken` eingelesen und ohne Marken verglichen.
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
        ergebnis[bereich] = {name: (e[schluessel] if isinstance(e, dict)
                                    else OhneMarken(e) if schluessel == "sig" else e)
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
        if isinstance(alt, list):                     # Form vor 0.22.0: keine Entscheidungen
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
            fehlt.append(f"{bereich}: ganze Liste ohne Stufen (Form vor 0.22.0)")
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
            jetzt = n[name]
            if isinstance(a[name], OhneMarken) and isinstance(jetzt, str):
                jetzt = ohne_marken(jetzt)        # alte Ablage: ohne `*`/`/` gemessen
            if a[name] == jetzt:
                continue
            zeile = (f"{bereich}.{name}:\n        vorher {a[name]}\n        jetzt  {n[name]}")
            if isinstance(a[name], str) and a[name].startswith("(") and nur_erweitert(a[name], jetzt):
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


def selbstpruefung_signatur(jetzt: dict) -> None:
    """Misst `signatur()` die Marken `*` und `/`, und meldet ein eingefügtes `*` als Bruch? (0.22.0)

    Dazu: Eine Ablage von vor 0.22.0 (ohne Marken gemessen) lässt sich weiter vergleichen — ohne
    dass jede Methode mit Nur-Schlüsselwort-Parametern als Bruch erscheint, und ohne dass ein
    echter Unterschied darin verschwindet. Läuft auch vor `--update`.
    """
    def probe(self, a, /, b, *, c=1, d: "int" = 2) -> bool:   # noqa: ARG001
        return True

    def mit_args(self, a, *rest, c=1, **kw):                   # noqa: ARG001
        return None

    assert signatur(probe) == "(a, /, b, *, c=1, d: 'int' = 2) -> bool", signatur(probe)
    assert signatur(mit_args) == "(a, *rest, c=1, **kw)", signatur(mit_args)
    assert signatur(lambda *, x: x) == "(*, x)", signatur(lambda *, x: x)
    sig = jetzt["TinySesam"]["login_password"]
    assert ", *, next: " in sig, f"login_password ohne `*` gemessen: {sig}"
    # `API.md` zeigt dieselbe Signatur (eigene Kopie in scripts/_api_doku.py, dort fehlten die
    # Marken genauso).
    import importlib.util
    spec = importlib.util.spec_from_file_location("_api_doku_probe",
                                                  os.path.join(WURZEL, "scripts", "_api_doku.py"))
    doku = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doku)
    for fn in (probe, mit_args, TinySesam.login_password, TinySesamConfig.oidc_gateway):
        assert doku.signatur(fn) == signatur(fn), (fn, doku.signatur(fn), signatur(fn))
    # Ein nachträglich eingefügtes `*` (oder `/`) bricht jeden positionellen Aufruf.
    vorher = {"TinySesam": {"m": "(request, username, next='')"}}
    for nachher in ("(request, username, *, next='')", "(request, /, username, next='')"):
        brueche, _ = beurteile(vorher, {"TinySesam": {"m": nachher}})
        assert brueche and "TinySesam.m:" in brueche[0], (nachher, brueche)
    assert nur_erweitert("(a, b=1)", "(a, b=1, *, c=2)"), "kw-only mit Vorgabe hinten ist harmlos"
    assert not nur_erweitert("(a, *, b=1)", "(a, *, b=1, c)"), "kw-only OHNE Vorgabe bricht"
    # Alte Ablage (Form vor 0.22.0): ohne Marken eingelesen und ohne Marken verglichen.
    alt = messung({"TinySesam": {"m": "(request, username, next='') -> 'x'",
                                 "n": "(request, next='')"}, "exporte": ["TinySesam"]})
    assert isinstance(alt["TinySesam"]["m"], OhneMarken)
    neu = {"TinySesam": {"m": "(request, username, *, next='') -> 'x'",
                         "n": "(request, *, weiter='')"}, "exporte": ["TinySesam"]}
    brueche, erw = beurteile(alt, neu)
    assert len(brueche) == 1 and brueche[0].startswith("TinySesam.n:") and not erw, (brueche, erw)
    ok("Signaturen mit `*` und `/`: ein eingefügtes `*` ist ein Bruch, eine Ablage von vor 0.22.0 "
       "vergleicht ohne Marken")


def selbstpruefung_stufen(jetzt: dict) -> None:
    """Schlägt die Stufen-Pflicht an, und vergibt `--update` wirklich keine Stufe? (0.22.0)

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


# ---------- Stufe C: die Aliase (0.22.0) ----------
# PO-Entscheid 2026-09-26: Ein Name der Stufe C bekommt einen führenden Unterstrich; der alte Name
# bleibt bis 1.0 als Alias, der beim Aufruf eine DeprecationWarning auslöst. Das ist nur dann
# wahr, wenn es gemessen wird — ein Alias, der still weiterreicht, oder eine Route, die noch den
# alten Namen ruft (und damit bei jeder Anmeldung warnt), sähe sonst genauso grün aus.

#: Wo Code liegt, der zum Paket gehört oder es benutzt, ohne Test zu sein: Dort steht kein alter
#: Name. Die Tests rufen die Unterstrich-Namen; die alten ruft nur dieser Wächter.
EIGENER_CODE = ("tinysesam", "examples", "scripts", "web")
#: Unter diesen Bereichen darf ein Name Stufe C tragen — nur dort gibt es einen Alias.
C_BEREICHE = {"TinySesam": True, "TinySesam.konstanten": False}   # Bereich → Methode?


def c_eintraege(datei: dict) -> dict:
    """{(bereich, name): eintrag} — jeder Eintrag der Stufe C, in welchem Bereich auch immer."""
    return {(bereich, name): e for bereich, eintraege in datei.items()
            if isinstance(eintraege, dict)
            for name, e in eintraege.items() if isinstance(e, dict) and e.get("stufe") == "C"}


def _warnt(klasse, name: str, alias: Veraltet) -> list:
    """Warnt der Alias genau einmal, mit Ersatz und auf den Aufrufer — und reicht er weiter?

    An einem Objekt ohne Konstruktor, dessen Ziel ein Stub ist: So misst der Wächter den Alias
    selbst, nicht das, was die echte Methode mit Testdaten täte."""
    fehler = []
    probe = klasse.__new__(klasse)
    zeichen, erhalten = object(), []
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")
        if alias.methode:
            probe.__dict__[alias.ziel] = lambda *a, **k: (erhalten.append((a, k)), zeichen)[1]
            fn = getattr(probe, name)
            if gewarnt:
                fehler.append("warnt schon beim Nachschlagen (hasattr, getmembers) statt beim Aufruf")
                del gewarnt[:]
            ergebnis = fn(1, zwei=2)
            if ergebnis is not zeichen or erhalten != [((1,), {"zwei": 2})]:
                fehler.append(f"reicht nicht unverändert an {alias.ziel} weiter "
                              f"(erhalten {erhalten!r})")
        else:
            ergebnis = getattr(klasse, name)
            if ergebnis is not vars(klasse)[alias.ziel]:
                fehler.append(f"liefert nicht den Wert von {alias.ziel}")
    if len(gewarnt) != 1:
        fehler.append(f"löst {len(gewarnt)} Warnungen aus statt genau einer")
    for w in gewarnt[:1]:
        text = str(w.message)
        if w.category is not DeprecationWarning:
            fehler.append(f"warnt als {w.category.__name__}, nicht als DeprecationWarning")
        if os.path.abspath(w.filename) != os.path.abspath(__file__):
            fehler.append(f"die Warnung zeigt auf {os.path.basename(w.filename)} statt auf den "
                          "Aufrufer (stacklevel)")
        for teil in (f"{klasse.__name__}.{name} ", f"fällt mit {BIS} weg", alias.ersatz):
            if teil not in text:
                fehler.append(f"die Meldung nennt {teil!r} nicht: {text!r}")
    return [f"TinySesam{'' if alias.methode else '.konstanten'}.{name}: Alias {f}" for f in fehler]


def _zuweisung(klasse, name: str, alias: Veraltet) -> list:
    """Eine Zuweisung auf den alten Namen am Objekt (Test-Fake) wirkt nicht mehr — warnt sie?

    Genau eine `RuntimeWarning` (sichtbar ohne Filter), die das Ziel nennt und auf die Zuweisung
    zeigt; danach liest der alte Name den gesetzten Wert, und `del` stellt den Alias wieder her
    (so räumt `mock.patch.object` auf). Befund der Gegenprüfung 2026-09-27: Ein Fake auf
    `check_password` wurde 0-mal gerufen, der Login ergab 303, und niemand warnte."""
    fehler = []
    probe = klasse.__new__(klasse)
    fake = object()
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")
        try:
            setattr(probe, name, fake)
            gelesen = probe.__dict__.get(name, None) is fake and getattr(probe, name) is fake
            delattr(probe, name)
        except Exception as e:                     # noqa: BLE001 — jede Ausnahme ist ein Befund
            return [f"TinySesam.{name}: Alias: Zuweisung am Objekt wirft {type(e).__name__}: {e}"]
    if [w.category for w in gewarnt] != [RuntimeWarning]:
        fehler.append(f"Zuweisung am Objekt löst {[w.category.__name__ for w in gewarnt]} aus "
                      "statt genau einer RuntimeWarning")
    else:
        text = str(gewarnt[0].message)
        if f"`{alias.ziel}`" not in text:
            fehler.append(f"die Warnung bei einer Zuweisung nennt das Ziel `{alias.ziel}` nicht: "
                          f"{text!r}")
        if os.path.abspath(gewarnt[0].filename) != os.path.abspath(__file__):
            fehler.append(f"die Warnung bei einer Zuweisung zeigt auf "
                          f"{os.path.basename(gewarnt[0].filename)} statt auf die Zuweisung")
    if not gelesen:
        fehler.append("liefert nach einer Zuweisung am Objekt nicht den gesetzten Wert")
    if name in probe.__dict__:
        fehler.append("`del` lässt den am Objekt gesetzten Wert stehen")
    art = "" if alias.methode else ".konstanten"
    return [f"TinySesam{art}.{name}: Alias {f}" for f in fehler]


def alias_befunde(datei: dict, klasse=TinySesam) -> list:
    """Stimmen Ablage und Klasse bei Stufe C überein, und tut jeder Alias, was er soll?"""
    befunde = []
    stufe = {(b, n): e.get("stufe") for b, ee in datei.items() if isinstance(ee, dict)
             for n, e in ee.items() if isinstance(e, dict)}
    c = c_eintraege(datei)
    for (bereich, name), e in sorted(c.items()):
        if bereich not in C_BEREICHE:
            befunde.append(f"{bereich}.{name}: Stufe C gibt es nur für Methoden und Konstanten "
                           "der Klasse — dort als Alias")
            continue
        alias = inspect.getattr_static(klasse, name, None)
        if not isinstance(alias, Veraltet):
            art = "fehlt in der Klasse" if alias is None else "hat eine eigene Implementierung"
            befunde.append(f"{bereich}.{name}: Stufe C, {art} — die Implementierung heisst "
                           f"`_{name}`, der alte Name wird `Veraltet(\"_{name}\", \"<Ersatz>\")`")
            continue
        if alias.methode != C_BEREICHE[bereich]:
            befunde.append(f"{bereich}.{name}: der Alias zeigt auf "
                           f"{'eine Methode' if alias.methode else 'eine Konstante'}")
        if e.get("ziel") != alias.ziel:
            befunde.append(f"{bereich}.{name}: die Ablage nennt `ziel` {e.get('ziel')!r}, der "
                           f"Alias zeigt auf {alias.ziel!r}")
        ziel = inspect.getattr_static(klasse, alias.ziel, None)
        if ziel is None or isinstance(ziel, Veraltet):
            befunde.append(f"{bereich}.{name}: das Ziel {alias.ziel!r} ist keine Implementierung")
        elif alias.ziel != f"_{name}" and stufe.get((bereich, alias.ziel)) != "A":
            befunde.append(f"{bereich}.{name}: zeigt auf {alias.ziel!r} — erlaubt ist `_{name}` "
                           "oder ein Name der Stufe A (so `complete_mfa` → `complete_totp`)")
        if not e.get("seit") or e.get("bis") != alias.bis:
            befunde.append(f"{bereich}.{name}: `seit`/`bis` fehlen oder passen nicht zum Alias "
                           f"(Ablage {e.get('seit')!r}/{e.get('bis')!r}, Alias bis {alias.bis})")
        befunde += _warnt(klasse, name, alias) + _zuweisung(klasse, name, alias)
    for name, alias in sorted(vars(klasse).items()):
        if isinstance(alias, Veraltet):
            bereich = "TinySesam" if alias.methode else "TinySesam.konstanten"
            if (bereich, name) not in c:
                befunde.append(f"{bereich}.{name}: ist in der Klasse ein Alias (Veraltet), in der "
                               "Ablage aber nicht Stufe C")
    return befunde


def alte_namen_im_text(text: str, ziele: dict, zeichenketten: bool) -> list:
    """[(zeile, befund)] — Zugriffe auf einen alten Namen in einem Quelltext (AST, nicht grep:
    ein Kommentar oder Docstring, der den Namen erwähnt, ist kein Aufruf)."""
    treffer = []
    for k in ast.walk(ast.parse(text)):
        if isinstance(k, ast.Attribute) and k.attr in ziele:
            treffer.append((k.lineno, f"`.{k.attr}` ist der alte Name — `.{ziele[k.attr]}` nehmen"))
        elif (zeichenketten and isinstance(k, ast.Constant) and isinstance(k.value, str)
              and k.value in ziele):
            treffer.append((k.lineno, f"Zeichenkette {k.value!r} — getattr/setattr auf den alten "
                                      f"Namen? `{ziele[k.value]}` nehmen"))
    return sorted(treffer)


def interne_aufrufe(ziele: dict, wurzel: str = WURZEL) -> tuple:
    """(befunde, geprüfte Dateien) — benutzt Code im Repo, der kein Test ist, einen alten Namen?

    Zeichenketten zählen nur im Paket selbst (`security.EIGENE_SPERRE` nennt Methoden beim
    Namen); `scripts/_api_doku.py` darf die alten Namen nennen — es beschreibt sie."""
    befunde, zahl = [], 0
    for ordner in EIGENER_CODE:
        for pfad_, unter, dateien in os.walk(os.path.join(wurzel, ordner)):
            unter[:] = sorted(u for u in unter if u != "__pycache__")
            for datei in sorted(dateien):
                if not datei.endswith(".py"):
                    continue
                pfad = os.path.join(pfad_, datei)
                with open(pfad, encoding="utf-8") as fh:
                    text = fh.read()
                zahl += 1
                rel = os.path.relpath(pfad, wurzel)
                befunde += [f"{rel}:{z}: {was}"
                            for z, was in alte_namen_im_text(text, ziele, ordner == "tinysesam")]
    return befunde, zahl


def _version(text: str) -> tuple:
    zahlen = []
    for teil in str(text).split(".")[:3]:
        ziffern = ""
        for zeichen in teil:
            if not zeichen.isdigit():
                break
            ziffern += zeichen
        zahlen.append(int(ziffern or 0))
    return tuple(zahlen + [0] * (3 - len(zahlen)))


def frist_befunde(datei: dict, version: str) -> list:
    """Mit 1.0 fallen die Aliase — steht dann noch einer da, ist das rot, nicht vergessen."""
    return [f"{bereich}.{name}: der Alias hätte mit {e.get('bis', BIS)} fallen müssen "
            f"(Version {version}) — Alias und Eintrag entfernen, CHANGELOG „Entfernt“"
            for (bereich, name), e in sorted(c_eintraege(datei).items())
            if _version(version) >= _version(e.get("bis", BIS))]


#: Der Name des noch offenen Abschnitts im CHANGELOG — was dort steht, ist in keinem Release.
OFFEN = "Unveröffentlicht"


def changelog_veraltet(text: str) -> list:
    """[(abschnitt, {namen})] in der Reihenfolge des CHANGELOG (neueste zuerst): je Abschnitt
    `## [X.Y.Z]` bzw. `## [Unveröffentlicht]` die Namen in Backticks unter `### Veraltet`."""
    abschnitte, akt, in_veraltet = [], None, False
    for zeile in text.split("\n"):
        if zeile.startswith("## ["):
            kopf = zeile[4:].split("]", 1)[0].strip()
            akt = (kopf, set())
            abschnitte.append(akt)
            in_veraltet = False
        elif zeile.startswith("### "):
            in_veraltet = akt is not None and zeile[4:].strip().startswith("Veraltet")
        elif in_veraltet:
            teile = zeile.split("`")
            akt[1].update(t for t in teile[1::2] if t.isidentifier())
    return abschnitte


def seit_befunde(datei: dict, changelog: str) -> list:
    """Stimmt `seit` jedes Alias mit dem Release überein, das ihn einführt? (0.22.0)

    Anlass: Die Einstufung war mit `seit: 0.21.0` gebaut, dann ging 0.21.0 ohne sie hinaus. Ein
    `seit`, das ein schon veröffentlichtes Release nennt, in dem es den Alias gar nicht gab,
    schickt jeden, der die Warnung liest, in die falsche Version — und nichts fiel auf, weil
    nur geprüft wurde, OB das Feld da ist. Die Regel, am CHANGELOG gemessen:

    * Der Alias steht unter `### Veraltet` in genau dem Abschnitt, der ihn einführt — dem
      ältesten, der ihn dort nennt. Fehlt er überall, ist das rot.
    * Führt ihn `[Unveröffentlicht]` ein, muss `seit` **grösser** sein als das jüngste Release
      im CHANGELOG: Das nächste Release bringt ihn, keines der schon draussen ist.
    * Führt ihn ein Release `[X.Y.Z]` ein, muss `seit` genau `X.Y.Z` sein. Beim Umbenennen von
      `[Unveröffentlicht]` in das neue Release greift damit dieselbe Regel weiter.
    """
    abschnitte = changelog_veraltet(changelog)
    releases = [kopf for kopf, _ in abschnitte if kopf != OFFEN and kopf[:1].isdigit()]
    if not releases:
        return ["CHANGELOG.md: kein Release-Abschnitt `## [X.Y.Z]` gefunden — `seit` der Aliase "
                "lässt sich nicht prüfen"]
    juengstes = max(releases, key=_version)
    befunde = []
    for (bereich, name), e in sorted(c_eintraege(datei).items()):
        seit = str(e.get("seit") or "")
        wo = [kopf for kopf, namen in abschnitte if name in namen]
        if not wo:
            befunde.append(f"{bereich}.{name}: CHANGELOG nennt den Alias in keinem Abschnitt unter "
                           f"„Veraltet“ — dort gehört er hin, mit Ersatz (`seit` {seit!r})")
            continue
        einfuehrung = wo[-1]                   # der älteste Abschnitt, der ihn nennt
        if einfuehrung == OFFEN:
            if _version(seit) <= _version(juengstes):
                befunde.append(
                    f"{bereich}.{name}: `seit` {seit!r}, aber der Alias steht erst unter "
                    f"[{OFFEN}] — {juengstes} ist schon veröffentlicht und kannte ihn nicht; "
                    f"`seit` auf das nächste Release setzen (grösser als {juengstes})")
        elif _version(seit) != _version(einfuehrung):
            befunde.append(f"{bereich}.{name}: `seit` {seit!r}, eingeführt hat den Alias aber "
                           f"[{einfuehrung}] (CHANGELOG, „Veraltet“)")
    return befunde


def c_befunde(datei: dict, klasse=TinySesam, version: str = _paket.__version__,
              wurzel: str = WURZEL, changelog: "str | None" = None) -> tuple:
    """(befunde, geprüfte Dateien) — die ganze Stufe-C-Prüfung des normalen Laufs."""
    ziele = {name: alias.ziel for name, alias in vars(klasse).items() if isinstance(alias, Veraltet)}
    ziele.update({name: e.get("ziel") or f"_{name}" for (_, name), e in c_eintraege(datei).items()
                  if name not in ziele})
    innen, zahl = interne_aufrufe(ziele, wurzel)
    if changelog is None:
        with open(os.path.join(wurzel, "CHANGELOG.md"), encoding="utf-8") as fh:
            changelog = fh.read()
    return (alias_befunde(datei, klasse) + innen + frist_befunde(datei, version)
            + seit_befunde(datei, changelog)), zahl


def pruefe_unterklasse() -> None:
    """Eine Unterklasse, die einen alten Namen überschreibt, muss es erfahren (RuntimeWarning):
    Seit 0.22.0 rufen die Routen `_name`, die Überschreibung liefe still ins Leere."""
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")

        class _Ueberschreibt(TinySesam):
            def check_password(self, username, password):
                return None

            def eigene_methode(self):
                return None
    assert [w.category for w in gewarnt] == [RuntimeWarning], [str(w.message) for w in gewarnt]
    text = str(gewarnt[0].message)
    assert "_Ueberschreibt.check_password" in text and "`_check_password`" in text, text
    assert os.path.abspath(gewarnt[0].filename) == os.path.abspath(__file__), gewarnt[0].filename
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")

        class _Harmlos(TinySesam):
            def eigene_methode(self):
                return None
    assert not gewarnt, [str(w.message) for w in gewarnt]
    ok("eine Unterklasse, die einen alten Namen überschreibt, bekommt eine RuntimeWarning")


def pruefe_warnfilter() -> None:
    """Macht `tests/run_all.py` einen alten Namen, gerufen AUS dem Paket, wirklich zum Fehler?

    Ein falsch geschriebener `-W`-Filter wird von Python nur mit „Invalid -W option ignored"
    quittiert — der Lauf bliebe grün, ohne etwas zu prüfen. Deshalb die Wirkung messen: In einem
    frischen Prozess mit genau der Umgebung einer Suite ruft Code, der sich als Modul des Pakets
    ausgibt, einen Alias (Methode und Konstante) — das muss werfen; derselbe Aufruf aus
    `__main__` (ein Nutzer, ein Test) nur warnen."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import run_all
    import tempfile
    sandbox = tempfile.mkdtemp(prefix="tinysesam-warnfilter-")
    # Nur der Filter von run_all.py zählt — ein von aussen gesetztes PYTHONWARNINGS (etwa ein
    # strenger Lauf mit `error::DeprecationWarning`) würde die Gegenprobe aus `__main__` verfälschen.
    von_aussen = os.environ.pop("PYTHONWARNINGS", None)
    try:
        umgebung = run_all.umgebung(sandbox)
    finally:
        if von_aussen is not None:
            os.environ["PYTHONWARNINGS"] = von_aussen
    eintraege = set(umgebung.get("PYTHONWARNINGS", "").split(","))
    module = set()
    for pfad_, unter, dateien in os.walk(os.path.join(WURZEL, "tinysesam")):
        unter[:] = [u for u in unter if u != "__pycache__"]
        teile = os.path.relpath(pfad_, WURZEL).split(os.sep)
        module |= {".".join(teile if d == "__init__.py" else teile + [d[:-3]])
                   for d in dateien if d.endswith(".py")}
    fehlt = sorted(m for m in module if f"error:TinySesam.:DeprecationWarning:{m}" not in eintraege)
    assert not fehlt, f"run_all.py filtert diese Module nicht: {fehlt}"
    probe = (
        "import warnings\n"
        "from tinysesam import TinySesam\n"
        "p = TinySesam.__new__(TinySesam)\n"
        "p.__dict__['_sec'] = lambda key: 1\n"
        "for code in ('p.sec(\"x\")', 'p.DEMO_USERS'):\n"
        "    for modul in ('tinysesam.router', '__main__'):\n"
        "        try:\n"
        "            exec(code, {'__name__': modul, 'p': p})\n"
        "            print(modul, 'warnt')\n"
        "        except DeprecationWarning:\n"
        "            print(modul, 'wirft')\n")
    r = subprocess.run([sys.executable, "-c", probe], cwd=WURZEL, env=umgebung,
                       capture_output=True, text=True)
    import shutil
    shutil.rmtree(sandbox, ignore_errors=True)
    assert r.returncode == 0, r.stderr[-800:]
    assert "Invalid -W option" not in r.stderr, r.stderr[-800:]
    assert r.stdout.split("\n")[:4] == ["tinysesam.router wirft", "__main__ warnt"] * 2, r.stdout
    ok(f"run_all.py: ein alter Name aus dem Paket wirft ({len(module)} Module gefiltert), "
       "aus eigenem Code warnt er nur")


def selbstpruefung_c() -> None:
    """Schlägt jede Stufe-C-Regel an? An einer Probeklasse, nicht an TinySesam — deren Aliase
    stimmen hoffentlich gerade, und eine Regel, die nie rot war, beweist nichts."""
    import tempfile

    def klasse(alias_typ=Veraltet, echt_f=False):
        ns = {"_f": lambda self, *a, **k: ("f", a, k), "_K": (1, 2),
              "g": lambda self: None, "K": alias_typ("_K", "ohne Ersatz, intern")}
        ns["f"] = (lambda self: None) if echt_f else alias_typ("_f", "stattdessen `g`")
        return type("TinySesam", (), ns)

    def ablage(**zusatz):
        e_f = {"sig": "()", "stufe": "C", "ziel": "_f", "seit": C_SEIT, "bis": BIS}
        e_k = {"wert": "(1, 2)", "stufe": "C", "ziel": "_K", "seit": C_SEIT, "bis": BIS}
        d = {"TinySesam": {"f": e_f, "g": {"sig": "()", "stufe": "A"}},
             "TinySesam.konstanten": {"K": e_k}, "exporte": {}}
        for pfad, wert in zusatz.items():
            bereich, name, feld = pfad.split("__")
            bereich = {"m": "TinySesam", "k": "TinySesam.konstanten", "x": "exporte"}[bereich]
            eintrag = d[bereich].setdefault(name, {"stufe": "C"})
            if wert is None:
                eintrag.pop(feld, None)
            else:
                eintrag[feld] = wert
        return d

    def rot(befunde, stueck):
        assert any(stueck in b for b in befunde), (stueck, befunde)

    sauber = alias_befunde(ablage(), klasse())
    assert sauber == [], sauber

    class Stumm(Veraltet):
        __slots__ = ()

        def _warnen(self):
            pass

    class Tief(Veraltet):
        __slots__ = ()

        def _warnen(self):
            warnings.warn(self.meldung, DeprecationWarning, stacklevel=2)

    class Verschluckt(Veraltet):
        __slots__ = ()

        def __get__(self, obj, owner=None):
            fn = super().__get__(obj, owner)
            return (lambda *a, **k: fn(*a)) if self.methode else fn

    class StilleZuweisung(Veraltet):
        __slots__ = ()

        def __set__(self, obj, wert):
            obj.__dict__[self.name] = wert

    class Falsch(Veraltet):
        __slots__ = ()

        def __set__(self, obj, wert):
            warnings.warn("veraltet", RuntimeWarning, stacklevel=2)
            obj.__dict__[self.name] = wert

    class Anderswo(Veraltet):
        __slots__ = ()

        def __set__(self, obj, wert):
            warnings.warn_explicit(f"auf `{self.ziel}` setzen", RuntimeWarning, "anderswo.py", 1)
            obj.__dict__[self.name] = wert

    rot(alias_befunde(ablage(), klasse(StilleZuweisung)),
        "TinySesam.f: Alias Zuweisung am Objekt löst [] aus")
    rot(alias_befunde(ablage(), klasse(Falsch)), "nennt das Ziel `_f` nicht")
    rot(alias_befunde(ablage(), klasse(Anderswo)), "zeigt auf anderswo.py statt auf die Zuweisung")
    rot(alias_befunde(ablage(), klasse(Stumm)), "löst 0 Warnungen aus")
    rot(alias_befunde(ablage(), klasse(Tief)), "statt auf den Aufrufer")
    rot(alias_befunde(ablage(), klasse(Verschluckt)), "reicht nicht unverändert")
    rot(alias_befunde(ablage(), klasse(echt_f=True)), "TinySesam.f: Stufe C, hat eine eigene")
    rot(alias_befunde(ablage(m__f__stufe="A"), klasse()), "in der Ablage aber nicht Stufe C")
    rot(alias_befunde(ablage(m__f__ziel="_g"), klasse()), "die Ablage nennt `ziel` '_g'")
    rot(alias_befunde(ablage(m__f__bis=None), klasse()), "`seit`/`bis` fehlen")
    rot(alias_befunde(ablage(x__Neu__stufe="C"), klasse()), "exporte.Neu: Stufe C gibt es nur")
    rot(alias_befunde(ablage(m__h__ziel="_h"), klasse()), "TinySesam.h: Stufe C, fehlt")
    umgelenkt = type("TinySesam", (), {"_f": lambda self: None, "g": lambda self: None,
                                        "_K": 1, "K": Veraltet("_K", "x"),
                                        "f": Veraltet("g", "stattdessen `g`")})
    assert alias_befunde(ablage(m__f__ziel="g"), umgelenkt) == [], "Ziel der Stufe A ist erlaubt"
    rot(alias_befunde(ablage(m__f__ziel="g", m__g__stufe="B"), umgelenkt), "erlaubt ist `_f`")
    # Interne Aufrufe: AST über ein Probe-Repo — Attribut überall, Zeichenkette nur im Paket.
    probe = tempfile.mkdtemp(prefix="tinysesam-c-")
    for rel, text in (("tinysesam/m.py", "auth.f(1)\nauth._f(2)\ngetattr(auth, 'f')\n# auth.f\n"),
                      ("examples/e.py", "x = 'f'\nauth.K\n"), ("tests/t.py", "auth.f()\n")):
        os.makedirs(os.path.join(probe, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(probe, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    innen, zahl = interne_aufrufe({"f": "_f", "K": "_K"}, probe)
    assert zahl == 2 and sorted(b.split(": ")[0] for b in innen) == [
        "examples/e.py:2", "tinysesam/m.py:1", "tinysesam/m.py:3"], (zahl, innen)
    # Frist: ab 1.0 ist jeder verbliebene Alias rot, davor keiner.
    assert frist_befunde(ablage(), "0.22.0") == [] and frist_befunde(ablage(), "0.99.3") == []
    assert len(frist_befunde(ablage(), "1.0.0")) == 2 and frist_befunde(ablage(), "1.2")

    # `seit` gegen das CHANGELOG (0.22.0): Der Alias steht unter „Veraltet“ im Abschnitt, der ihn
    # einführt; im offenen Abschnitt ist `seit` grösser als das jüngste Release, sonst genau dieses.
    def changelog(offen="", release=""):
        return ("# Changelog\n\n## [Unveröffentlicht]\n\n### Veraltet\n\n" + offen + "\n\n"
                "## [0.21.0] — 2026-09-27\n\n### Geändert\n\n- `f` und `K` zählen hier nicht\n\n"
                "### Veraltet\n\n" + release + "\n\n## [0.20.1] — 2026-09-24\n")
    beide = "- `f` → `_f`, `K` → `_K`"
    neu = ablage(m__f__seit="0.22.0", k__K__seit="0.21.1")
    assert seit_befunde(neu, changelog(offen=beide)) == [], seit_befunde(neu, changelog(offen=beide))
    rot(seit_befunde(ablage(m__f__seit="0.21.0"), changelog(offen=beide)),
        "TinySesam.f: `seit` '0.21.0', aber der Alias steht erst unter [Unveröffentlicht]")
    rot(seit_befunde(ablage(k__K__seit="0.19.0"), changelog(offen=beide)),
        "TinySesam.konstanten.K: `seit` '0.19.0', aber")
    alt = ablage(m__f__seit="0.21.0", k__K__seit="0.21.0")
    assert seit_befunde(alt, changelog(release=beide)) == []
    assert seit_befunde(alt, changelog(offen=beide, release=beide)) == [], "der älteste zählt"
    rot(seit_befunde(ablage(m__f__seit="0.22.0"), changelog(release=beide)),
        "TinySesam.f: `seit` '0.22.0', eingeführt hat den Alias aber [0.21.0]")
    rot(seit_befunde(ablage(), changelog(offen="- `K` → `_K`")), "TinySesam.f: CHANGELOG nennt")
    rot(seit_befunde(ablage(), "# Changelog\n\n## [Unveröffentlicht]\n"), "kein Release-Abschnitt")
    # Der normale Lauf geht durch dieselbe Funktion und sieht alle vier Arten.
    befunde, _ = c_befunde(ablage(m__f__seit="0.21.0", k__K__seit="0.22.0"), klasse(Stumm),
                           "1.0.0", probe, changelog(offen=beide))
    import shutil
    shutil.rmtree(probe, ignore_errors=True)
    for art in ("löst 0 Warnungen", "tinysesam/m.py:1", "fallen müssen", "kannte ihn nicht"):
        rot(befunde, art)
    ok("Stufe-C-Regeln schlagen an: Alias stumm, falscher stacklevel, verschluckte Argumente, "
       "stille Zuweisung am Objekt, eigene Implementierung, Ablage ≠ Klasse, falsches Ziel, "
       "interner Aufruf, Frist 1.0, `seit` gegen das CHANGELOG")


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
    selbstpruefung_signatur(jetzt)
    selbstpruefung_stufen(jetzt)
    selbstpruefung_c()

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

    # Stufe C (0.22.0): Aliase, keine Aufrufe alter Namen im eigenen Code, Frist 1.0.
    c_fehler, c_dateien = c_befunde(frueher_datei)
    assert c_dateien >= 20, f"nur {c_dateien} Dateien nach alten Namen durchsucht — Pfad kaputt?"
    if c_fehler:
        rot = True
        print(f"\n  {len(c_fehler)} Befunde zu Stufe C (Alias bis 1.0):\n")
        for zeile in c_fehler:
            print(f"    STUFE C      {zeile}")
        print("\n  Stufe C heisst: Die Implementierung trägt einen Unterstrich, der alte Name ist "
              "`Veraltet(\"_name\", \"<Ersatz>\")`\n  (tinysesam/_veraltet.py), und nichts im "
              "Paket ruft ihn. Der Eintrag in tests/api_surface.json\n  trägt `ziel`, `seit` und "
              "`bis`.\n")
    else:
        ok(f"Stufe C: {len(c_eintraege(frueher_datei))} Aliase warnen genau einmal und zeigen auf "
           f"ihre Implementierung, eine Zuweisung am Objekt (Test-Fake) warnt; {c_dateien} "
           "Dateien ohne alten Namen")
    pruefe_unterklasse()
    pruefe_warnfilter()

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

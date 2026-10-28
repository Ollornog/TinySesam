"""Pin down the public API — so a break gets NOTICED instead of just happening.

Milestone 1.0 demands that the public API does not break across two minor versions
(`backlog/M-1-api-stable-1-0.md`). Without measurement that is a claim: both most recent
releases broke it, and both times it was only noticed while writing the CHANGELOG.

This test pins the surface in `tests/api_surface.json` and compares on every run.
It records methods, class constants, since 0.20.1 also the properties (the cookie names),
the configuration fields with defaults, the presets and the exports, and since 0.22.0 also the
result types of the building blocks for custom pages (`LoginResult`, `PasswordChangeResult`:
fields, methods, reasons).
It forbids nothing — it forces a **deliberate decision**:

    python tests/test_api_surface.py --update      # accept the change, then commit

What counts as a break is defined below in `beurteile()`: removed or renamed is a break,
a changed signature usually is too, something new is an extension. The distinction
appears in the report, so nobody has to look up every line themselves.

**Since 0.22.0 every name carries a tier** (PO decision 2026-09-26, `STUFEN` below): A is
permanently public and the only tier with the 1.0 commitment, B is for advanced users with a
weaker commitment, C is internal. Until then the surface was *measured, not chosen* —
what had no underscore was frozen. The tier is a decision, not a measurement:
it is stored per entry in `api_surface.json`, `--update` carries it over, but NEVER assigns
one itself. A new name comes in without a tier and keeps the guard red until someone enters one
— a silent "A" would have committed every helper method that happens to be created without an
underscore, for good.

**Tier C is only an alias since 0.22.0** (`tinysesam/_deprecated.py`): The implementation
is called `_name`, the old name keeps forwarding until 1.0 and warns. The guard additionally
pins down (`c_befunde()`): every C entry is a `Deprecated` in the class and vice versa, it points to the
underscore implementation, calling it warns exactly once with the replacement and at the caller, no
code in the package uses an old name, and from 1.0 none is left.

**Tiers A and B are named in English** (PO decision 2026-09-27, `pruefe_namen()`): No name,
parameter, configuration field or attribute of an error type in tiers A/B carries a German
word — measured on the live object, with a minimum count and self-checks. **So do their keys
and values** (second PO decision of the same day, `pruefe_werte()`): what the surface returns
or accepts, the payload of `on_security_event`, the context of custom pages, the JSON of the routes
and the stored values — on a probe instance, on the constants and in the source, against the
word list and against every name up to 0.21.x (`ALTE_WERTE`). It does not measure audit and log lines:
they stay as they are.
"""
import ast
import dataclasses
import inspect
import json
import os
import re
import subprocess
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import importlib
from tinysesam import ConfigError, LoginResult, PasswordChangeResult, TinySesam, TinySesamConfig
from tinysesam._deprecated import BIS, Deprecated

_paket = importlib.import_module("tinysesam")
WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ABLAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_surface.json")

#: The tiers of the public surface (PO decision 2026-09-26). Only A carries the commitment
#: from M-1 ("two minor versions without a break"); the counter starts at 0.22.0.
STUFEN = {
    "A": "öffentlich, stabil ab 1.0 — ein Bruch setzt die 1.0-Uhr zurück (M-1)",
    "B": "für Fortgeschrittene — entfernen oder umbauen erst nach einer DeprecationWarning "
         "über zwei Minor-Versionen",
    "C": "intern — die Implementierung trägt einen führenden Unterstrich, der alte Name bleibt "
         "bis 1.0 als Alias mit DeprecationWarning (Eintrag mit `ziel`, `seit`, `bis`)",
}

#: Since when the C aliases warn (extra field `seit` on every C entry).
C_SEIT = "0.22.0"

#: Under which key an entry in `api_surface.json` carries its MEASURED value.
#: Everything else on the entry (`stufe`, later alias details) is a decision and is carried over by
#: `--update`, not re-measured. The exports have no measured value — only the name.
MESSWERT = {"TinySesam": "sig", "TinySesam.eigenschaften": "sig",
            "TinySesamConfig.methoden": "sig", "TinySesam.konstanten": "wert",
            "TinySesamConfig.felder": "feld", "exporte": None, "LoginResult": "sig",
            "PasswordChangeResult": "sig"}

#: The result types of the building blocks for custom pages (0.22.0, tier A), each with its own area in
#: the baseline: `LoginResult` (`login_*`, `confirm_*`), `PasswordChangeResult` (`change_password`).
ERGEBNISTYPEN = {"LoginResult": LoginResult, "PasswordChangeResult": PasswordChangeResult}


def ok(name):
    print(f"  ✓ {name}")


def parameter_mit_marken(parameter) -> list:
    """`str(p)` per parameter, plus the marks `*` (keyword-only before it) and `/` (positional-only
    before it) at the place where Python requires them in the signature.

    Until 0.22.0 `signatur()` assembled the parameters individually and lost both marks:
    `(request, username, password, *, next='')` was stored as `(…, password, next='')` in the baseline.
    A `*` inserted later — every call `login_password(r, u, p, "/start")` breaks
    — thus looked like no change (finding from step 3 of the tiering, M-1).
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
    """The signature without `self` — parameter names and order are part of the promise.

    Whether a parameter is keyword-only is captured too: That is exactly what the break in 0.15 hinged on
    (`require_role("editor", True)` once meant `mfa=True` and would afterwards have been a second role).
    Really so since 0.22.0: with the marks `*` and `/` (`parameter_mit_marken`).
    """
    try:
        s = inspect.signature(fn)
    except (TypeError, ValueError):
        return "?"
    teile = parameter_mit_marken([p for name, p in s.parameters.items() if name != "self"])
    # The return type belongs to it. Without it `-> dict` could silently change to `-> str`:
    # every call breaks, and the guard would stay silent — it only covered the inputs.
    zurueck = "" if s.return_annotation is inspect.Signature.empty else \
        f" -> {inspect.formatannotation(s.return_annotation)}"
    return "(" + ", ".join(teile) + ")" + zurueck


def oberflaeche() -> dict:
    """What an embedder uses: the class, the configuration, the exports."""
    # Measuring is not using: `getmembers` reads every attribute, including the constant aliases
    # of tier C, and those warn when read. Method aliases deliver their wrapper here — its
    # signature is that of the target via `__wrapped__`, and that is exactly what is promised.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        manager = {name: signatur(fn)
                   for name, fn in inspect.getmembers(TinySesam, callable)
                   if not name.startswith("_")}
    # With DEFAULT VALUE. Without it `session_ttl_hours` could silently change from 168 to 1 —
    # a behaviour break for everyone who never touched the field, and exactly the kind that
    # nobody looks for in the CHANGELOG. Until 0.18.0 the guard only covered name and type.
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
    # Public class attributes belong to it. `inspect.getmembers(…, callable)` only captures
    # callables — `FORWARD_HEADERS_DEFAULT` could silently change that way, although the docs
    # list it as a commitment ("the Authelia-style set Remote-User/-Name/-Email/-Groups"). A
    # change breaks every Caddy/Traefik installation without a single line of code looking different.
    # A constant alias (tier C) is measured with the value of its target — read statically,
    # without triggering it; a method alias is listed above with the methods.
    konstanten = {}
    for name, wert in vars(TinySesam).items():
        if isinstance(wert, Deprecated):
            if wert.methode:
                continue
            wert = vars(TinySesam)[wert.ziel]
        elif callable(wert) or isinstance(wert, (property, staticmethod, classmethod)):
            continue
        if not name.startswith("_"):
            konstanten[name] = repr(wert)
    # Properties belong to it as well (0.20.1): `session_cookie_name`, `csrf_cookie_name`,
    # `resource_cookie_name` are the documented replacement API for fixed cookie names. What is
    # captured is the return type of the getter; a setter appends "(writable)". Read statically:
    # a property is the property object even then, and no constant alias warns in the process.
    eigenschaften = {name: signatur(wert.fget) + (" (schreibbar)" if wert.fset else "")
                     for name, wert in inspect.getmembers_static(
                         TinySesam, lambda w: isinstance(w, property))
                     if not name.startswith("_")}
    return {"TinySesam": manager, "TinySesam.konstanten": konstanten,
            "TinySesam.eigenschaften": eigenschaften,
            "TinySesamConfig.felder": felder,
            "TinySesamConfig.methoden": presets, "exporte": exporte,
            **{name: ergebnistyp_oberflaeche(typ) for name, typ in ERGEBNISTYPEN.items()}}


def ergebnistyp_oberflaeche(typ=LoginResult) -> dict:
    """A result type of the building blocks for custom pages (0.22.0, tier A): fields, methods, reasons.

    The guard captures the exports by name only. For `LoginResult` that is not enough: Whoever reads
    `result.next_factor` or checks `result.reason == "locked"` breaks on a
    renamed field or a dropped reason just as on a renamed method.
    Fields with type and default (like the configuration), methods with signature, `REASONS` with the
    value. The same holds for `PasswordChangeResult` (`result.api_keys_active`).
    """
    ergebnis = {}
    for f in dataclasses.fields(typ):
        vorgabe = "<pflicht>" if f.default is dataclasses.MISSING else repr(f.default)
        ergebnis[f.name] = f"{f.type} = {vorgabe}"
    ergebnis.update({name: signatur(fn) for name, fn in inspect.getmembers(typ, inspect.isfunction)
                     if not name.startswith("_")})
    ergebnis["REASONS"] = repr(typ.REASONS)
    return ergebnis


class OhneMarken(str):
    """A signature from a baseline from before 0.22.0: measured WITHOUT the marks `*` and `/`.

    Where the marks were, such an entry no longer knows. `beurteile()` therefore compares it
    with today's measurement without marks (`ohne_marken`) — otherwise a comparison with an
    older release would report every method with keyword-only parameters as a break, and a real
    one would be lost in it. A difference in names, order, defaults or return stays one.
    """


def ohne_marken(sig: str) -> str:
    """`(a, *, b=1) -> 'x'` → `(a, b=1) -> 'x'` — the form in which measurements were taken before 0.22.0."""
    rest = _klammer_und_rest(sig)[1]
    return ("(" + ", ".join(t for t in teile(sig) if t not in ("*", "/")) + ")"
            + (" " + rest if rest else ""))


def messung(datei: dict) -> dict:
    """Reduce the baseline to the pure measurement — the form `oberflaeche()` delivers.

    Also tolerates the baseline from before 0.22.0 (value as string, exports as list): A
    comparison with an older release (`git show v0.21.0:tests/api_surface.json`) should not fail on
    the form. Its signatures came without the marks `*`/`/` — they are read in as
    `OhneMarken` and compared without marks.
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
    """The new baseline: measured values from `jetzt`, every decision from `frueher`.

    Everything on the old entry except the measured value is carried over — the `stufe`, later also
    alias details —, and only for the same name in the same area. A new name gets
    NO tier: The guard then reports it instead of silently committing to it.
    """
    ablage = {}
    for bereich, gemessen in jetzt.items():
        alt = frueher.get(bereich, {})
        if isinstance(alt, list):                     # form before 0.22.0: no decisions
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
    """{area: {name: tier}} — only entries that carry one."""
    return {bereich: {name: e["stufe"] for name, e in eintraege.items()
                      if isinstance(e, dict) and "stufe" in e}
            for bereich, eintraege in datei.items() if isinstance(eintraege, dict)}


def ohne_stufe(datei: dict) -> list:
    """Every entry without a valid tier, as a readable line. Empty = everything tiered."""
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
    """`(a, b) -> 'bool'` → (`a, b`, ` -> 'bool'`). Until T-13 `teile()` simply cut off the
    first and last character — for a signature WITH a return type that ended up in the
    last parameter, and a harmlessly appended parameter counted as a BREAK."""
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
    """Split a signature string into parameters — only at commas outside brackets."""
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
    """Is the new signature callable like the old one?

    A parameter appended at the end WITH a default breaks nothing — every existing
    call keeps working. Reporting that as a break would not only be wrong, it would be harmful:
    A guard that cries wolf at harmless things gets clicked away, and then the real one is overlooked.
    """
    a, n = teile(alt), teile(neu)
    if _klammer_und_rest(alt)[1] != _klammer_und_rest(neu)[1]:
        return False                                  # different return type
    if len(n) < len(a) or n[:len(a)] != a:
        return False
    return all("=" in p or p.startswith("*") for p in n[len(a):])


def beurteile(alt: dict, neu: dict, stufen: "dict | None" = None):
    """(breaks, extensions) — both with a readable description.

    With `stufen` (from `stufen_aus()` of the old baseline) every break starts with the tier of the
    name, `[A] …`: Whether the 1.0 clock jumps back depends on that alone.
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
                jetzt = ohne_marken(jetzt)        # old baseline: measured without `*`/`/`
            if a[name] == jetzt:
                continue
            zeile = (f"{bereich}.{name}:\n        vorher {a[name]}\n        jetzt  {n[name]}")
            if isinstance(a[name], str) and a[name].startswith("(") and nur_erweitert(a[name], jetzt):
                erweiterungen.append(zeile + "\n        (nur angehängt, mit Vorgabewert — "
                                            "bestehende Aufrufe laufen weiter)")
            else:
                brueche.append(marke(bereich, name) + zeile)
    return brueche, erweiterungen


#: These properties MUST be in the surface — the CHANGELOG of 0.20.0 sends every
#: embedding app to them ("read the CSRF cookie name from `auth.csrf_cookie_name`").
PFLICHT_EIGENSCHAFTEN = ("session_cookie_name", "csrf_cookie_name", "resource_cookie_name")


def selbstpruefung(jetzt: dict) -> None:
    """Does the guard measure the properties at all? (0.20.1)

    Until 0.20.0 `oberflaeche()` explicitly excluded them (`isinstance(wert, property)`), and
    `getmembers(…, callable)` does not see them anyway. Renaming `csrf_cookie_name` —
    exactly the name that custom JS and custom routes need — thus went unnoticed by every guard.
    Also runs before `--update`: Otherwise the exclusion could be checked in together with the new dump.
    (Mutation probe: delete the area `TinySesam.eigenschaften` in `oberflaeche()` → red.)
    """
    eig = jetzt.get("TinySesam.eigenschaften", {})
    fehlt = [n for n in PFLICHT_EIGENSCHAFTEN if n not in eig]
    assert not fehlt, f"Properties missing from the frozen surface: {fehlt}"
    # Counter-check on the comparison itself: A renamed property is a BREAK, not an extension.
    umbenannt = json.loads(json.dumps(jetzt))
    umbenannt["TinySesam.eigenschaften"]["csrf_cookie"] = \
        umbenannt["TinySesam.eigenschaften"].pop("csrf_cookie_name")
    brueche, _ = beurteile(jetzt, umbenannt)
    assert any("csrf_cookie_name ist fort" in b for b in brueche), brueche
    ok(f"Properties frozen ({len(eig)}), renaming one would count as a break")


def selbstpruefung_signatur(jetzt: dict) -> None:
    """Does `signatur()` measure the marks `*` and `/`, and report an inserted `*` as a break? (0.22.0)

    In addition: A baseline from before 0.22.0 (measured without marks) can still be compared — without
    every method with keyword-only parameters appearing as a break, and without a
    real difference disappearing in it. Also runs before `--update`.
    """
    def probe(self, a, /, b, *, c=1, d: "int" = 2) -> bool:   # noqa: ARG001
        return True

    def mit_args(self, a, *rest, c=1, **kw):                   # noqa: ARG001
        return None

    assert signatur(probe) == "(a, /, b, *, c=1, d: 'int' = 2) -> bool", signatur(probe)
    assert signatur(mit_args) == "(a, *rest, c=1, **kw)", signatur(mit_args)
    assert signatur(lambda *, x: x) == "(*, x)", signatur(lambda *, x: x)
    sig = jetzt["TinySesam"]["login_password"]
    assert ", *, next: " in sig, f"login_password measured without `*`: {sig}"
    # `API.md` shows the same signature (own copy in scripts/_api_docs.py, where the
    # marks were missing just the same).
    import importlib.util
    spec = importlib.util.spec_from_file_location("_api_doku_probe",
                                                  os.path.join(WURZEL, "scripts", "_api_docs.py"))
    doku = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doku)
    for fn in (probe, mit_args, TinySesam.login_password, TinySesamConfig.oidc_gateway):
        assert doku.signatur(fn) == signatur(fn), (fn, doku.signatur(fn), signatur(fn))
    # A `*` (or `/`) inserted later breaks every positional call.
    vorher = {"TinySesam": {"m": "(request, username, next='')"}}
    for nachher in ("(request, username, *, next='')", "(request, /, username, next='')"):
        brueche, _ = beurteile(vorher, {"TinySesam": {"m": nachher}})
        assert brueche and "TinySesam.m:" in brueche[0], (nachher, brueche)
    assert nur_erweitert("(a, b=1)", "(a, b=1, *, c=2)"), "kw-only with a default at the end is harmless"
    assert not nur_erweitert("(a, *, b=1)", "(a, *, b=1, c)"), "kw-only WITHOUT a default breaks"
    # Old baseline (form before 0.22.0): read in without marks and compared without marks.
    alt = messung({"TinySesam": {"m": "(request, username, next='') -> 'x'",
                                 "n": "(request, next='')"}, "exporte": ["TinySesam"]})
    assert isinstance(alt["TinySesam"]["m"], OhneMarken)
    neu = {"TinySesam": {"m": "(request, username, *, next='') -> 'x'",
                         "n": "(request, *, weiter='')"}, "exporte": ["TinySesam"]}
    brueche, erw = beurteile(alt, neu)
    assert len(brueche) == 1 and brueche[0].startswith("TinySesam.n:") and not erw, (brueche, erw)
    ok("Signatures with `*` and `/`: an inserted `*` is a break, a baseline from before 0.22.0 "
       "compares without marks")


def selbstpruefung_stufen(jetzt: dict) -> None:
    """Does the tier requirement trigger, and does `--update` really assign no tier? (0.22.0)

    On synthetic baselines made from the real measurement, so that the check does not depend on the
    checked-in file, which may happen to be complete. Also runs before `--update`.
    """
    assert set(MESSWERT) == set(jetzt), (
        f"Areas without a measured-value key: {sorted(set(jetzt) - set(MESSWERT))} — "
        "add to MESSWERT, otherwise the baseline does not know what was measured and what was decided")
    gesamt = sum(len(v) for v in jetzt.values())
    # 1. Freshly measured, NO entry carries a tier — every single one is reported.
    roh = mit_stufen(jetzt, {})
    assert len(ohne_stufe(roh)) == gesamt, (len(ohne_stufe(roh)), gesamt)
    # 2. Everything tiered → nothing reported; an unknown tier (also lowercase) → reported.
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
    # 3. `--update` carries decisions over, re-measures, and a new name stays without a tier.
    frueher = json.loads(json.dumps(voll))
    methode = sorted(frueher["TinySesam"])[0]
    frueher["TinySesam"][methode].update(stufe="B", sig="(veraltet)", ersatz="neu_name")
    del frueher["TinySesam"][sorted(frueher["TinySesam"])[1]]      # "new" since the old baseline
    del frueher["exporte"][sorted(frueher["exporte"])[0]]
    frueher["TinySesam"]["fort_seit_langem"] = {"sig": "()", "stufe": "A"}
    neu = mit_stufen(jetzt, frueher)
    assert neu["TinySesam"][methode] == {"sig": jetzt["TinySesam"][methode], "stufe": "B",
                                         "ersatz": "neu_name"}, neu["TinySesam"][methode]
    assert "fort_seit_langem" not in neu["TinySesam"]
    assert ohne_stufe(neu) == [f"TinySesam.{sorted(jetzt['TinySesam'])[1]}: keine Stufe",
                               f"exporte.{sorted(jetzt['exporte'])[0]}: keine Stufe"], ohne_stufe(neu)
    # 4. The baseline leads back to the measurement losslessly — otherwise `beurteile` would compare apples.
    assert messung(neu) == jetzt
    # 5. A break names the tier of the name.
    weg = json.loads(json.dumps(jetzt))
    del weg["TinySesam"][methode]
    brueche, _ = beurteile(jetzt, weg, stufen_aus(neu))
    assert brueche and brueche[0].startswith(f"[B] TinySesam.{methode} ist fort"), brueche
    # 6. The normal run — the same function `main()` executes — is red as soon as ONE name
    #    has no tier, even if nothing about the measurement changed.
    rot, fehlt, b, e = vergleiche(voll, jetzt)
    assert (rot, fehlt, b, e) == (False, [], [], []), (rot, fehlt, b, e)
    luecke = json.loads(json.dumps(voll))
    del luecke["TinySesam.eigenschaften"]["csrf_cookie_name"]["stufe"]
    rot, fehlt, b, e = vergleiche(luecke, jetzt)
    assert rot and fehlt == ["TinySesam.eigenschaften.csrf_cookie_name: keine Stufe"] \
        and not b and not e, (rot, fehlt, b, e)
    ok(f"Tier requirement works ({gesamt} names): missing and unknown tier reported, "
       "`--update` assigns none")


def vergleiche(frueher_datei: dict, jetzt: dict) -> tuple:
    """(red, without_tier, breaks, extensions) — the whole decision of the normal run.

    A function of its own, so that the self-check checks exactly what `main()` executes: A
    tier check that existed only in the self-check would run into the void in the real run.
    """
    fehlt = ohne_stufe(frueher_datei)
    brueche, erweiterungen = beurteile(messung(frueher_datei), jetzt, stufen_aus(frueher_datei))
    return bool(fehlt or brueche or erweiterungen), fehlt, brueche, erweiterungen


# ---------- Tier C: the aliases (0.22.0) ----------
# PO decision 2026-09-26: A tier-C name gets a leading underscore; the old name
# stays as an alias until 1.0 that triggers a DeprecationWarning when called. That is only
# true if it is measured — an alias that silently forwards, or a route that still calls the
# old name (and thus warns on every login), would look just as green.

#: Where code lives that belongs to the package or uses it without being a test: No old
#: name appears there. The tests call the underscore names; only this guard calls the old ones.
EIGENER_CODE = ("tinysesam", "examples", "scripts", "web")
#: Under these areas a name may carry tier C — only there is there an alias.
C_BEREICHE = {"TinySesam": True, "TinySesam.konstanten": False}   # area → method?


def c_eintraege(datei: dict) -> dict:
    """{(area, name): entry} — every tier-C entry, in whichever area."""
    return {(bereich, name): e for bereich, eintraege in datei.items()
            if isinstance(eintraege, dict)
            for name, e in eintraege.items() if isinstance(e, dict) and e.get("stufe") == "C"}


def _warnt(klasse, name: str, alias: Deprecated) -> list:
    """Does the alias warn exactly once, with replacement and at the caller — and does it forward?

    On an object without constructor whose target is a stub: This is how the guard measures the alias
    itself, not what the real method would do with test data."""
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


def _zuweisung(klasse, name: str, alias: Deprecated) -> list:
    """An assignment to the old name on the object (test fake) no longer takes effect — does it warn?

    Exactly one `RuntimeWarning` (visible without a filter) that names the target and points to the assignment;
    afterwards the old name reads the assigned value, and `del` restores the alias
    (this is how `mock.patch.object` cleans up). Finding of the counter-check 2026-09-27: A fake on
    `check_password` was called 0 times, the login gave 303, and nobody warned."""
    fehler = []
    probe = klasse.__new__(klasse)
    fake = object()
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")
        try:
            setattr(probe, name, fake)
            gelesen = probe.__dict__.get(name, None) is fake and getattr(probe, name) is fake
            delattr(probe, name)
        except Exception as e:                     # noqa: BLE001 — every exception is a finding
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
    """Do baseline and class agree for tier C, and does every alias do what it should?"""
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
        if not isinstance(alias, Deprecated):
            art = "fehlt in der Klasse" if alias is None else "hat eine eigene Implementierung"
            befunde.append(f"{bereich}.{name}: Stufe C, {art} — die Implementierung heisst "
                           f"`_{name}`, der alte Name wird `Deprecated(\"_{name}\", \"<Ersatz>\")`")
            continue
        if alias.methode != C_BEREICHE[bereich]:
            befunde.append(f"{bereich}.{name}: der Alias zeigt auf "
                           f"{'eine Methode' if alias.methode else 'eine Konstante'}")
        if e.get("ziel") != alias.ziel:
            befunde.append(f"{bereich}.{name}: die Ablage nennt `ziel` {e.get('ziel')!r}, der "
                           f"Alias zeigt auf {alias.ziel!r}")
        ziel = inspect.getattr_static(klasse, alias.ziel, None)
        if ziel is None or isinstance(ziel, Deprecated):
            befunde.append(f"{bereich}.{name}: das Ziel {alias.ziel!r} ist keine Implementierung")
        elif alias.ziel != f"_{name}" and stufe.get((bereich, alias.ziel)) != "A":
            befunde.append(f"{bereich}.{name}: zeigt auf {alias.ziel!r} — erlaubt ist `_{name}` "
                           "oder ein Name der Stufe A (so `complete_mfa` → `complete_totp`)")
        if not e.get("seit") or e.get("bis") != alias.bis:
            befunde.append(f"{bereich}.{name}: `seit`/`bis` fehlen oder passen nicht zum Alias "
                           f"(Ablage {e.get('seit')!r}/{e.get('bis')!r}, Alias bis {alias.bis})")
        befunde += _warnt(klasse, name, alias) + _zuweisung(klasse, name, alias)
    for name, alias in sorted(vars(klasse).items()):
        if isinstance(alias, Deprecated):
            bereich = "TinySesam" if alias.methode else "TinySesam.konstanten"
            if (bereich, name) not in c:
                befunde.append(f"{bereich}.{name}: ist in der Klasse ein Alias (Deprecated), in der "
                               "Ablage aber nicht Stufe C")
    return befunde


def alte_namen_im_text(text: str, ziele: dict, zeichenketten: bool) -> list:
    """[(line, finding)] — accesses to an old name in a source text (AST, not grep:
    a comment or docstring that mentions the name is not a call)."""
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
    """(findings, checked files) — does code in the repo that is not a test use an old name?

    Strings only count in the package itself (`security.EIGENE_SPERRE` names methods by
    name); `scripts/_api_docs.py` may name the old names — it describes them."""
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
    """With 1.0 the aliases fall — if one is still there, that is red, not forgotten."""
    return [f"{bereich}.{name}: der Alias hätte mit {e.get('bis', BIS)} fallen müssen "
            f"(Version {version}) — Alias und Eintrag entfernen, CHANGELOG „Removed“"
            for (bereich, name), e in sorted(c_eintraege(datei).items())
            if _version(version) >= _version(e.get("bis", BIS))]


#: The name of the still-open section in the CHANGELOG — what is in it is in no release.
OFFEN = "Unreleased"


def changelog_veraltet(text: str) -> list:
    """[(section, {names})] in CHANGELOG order (newest first): per section
    `## [X.Y.Z]` or `## [Unreleased]` the names in backticks under `### Deprecated`."""
    abschnitte, akt, in_veraltet = [], None, False
    for zeile in text.split("\n"):
        if zeile.startswith("## ["):
            kopf = zeile[4:].split("]", 1)[0].strip()
            akt = (kopf, set())
            abschnitte.append(akt)
            in_veraltet = False
        elif zeile.startswith("### "):
            in_veraltet = akt is not None and zeile[4:].strip().startswith("Deprecated")
        elif in_veraltet:
            teile = zeile.split("`")
            akt[1].update(t for t in teile[1::2] if t.isidentifier())
    return abschnitte


def seit_befunde(datei: dict, changelog: str) -> list:
    """Does the `seit` of every alias match the release that introduces it? (0.22.0)

    Reason: The tiering was built with `seit: 0.21.0`, then 0.21.0 went out without it. A
    `seit` that names an already published release in which the alias did not exist
    sends everyone who reads the warning to the wrong version — and nothing was noticed, because
    only whether the field is there was checked. The rule, measured against the CHANGELOG:

    * The alias is under `### Deprecated` in exactly the section that introduces it — the
      oldest that names it there. If it is missing everywhere, that is red.
    * If `[Unreleased]` introduces it, `seit` must be **greater** than the latest release
      in the CHANGELOG: The next release brings it, none of those already out.
    * If a release `[X.Y.Z]` introduces it, `seit` must be exactly `X.Y.Z`. When renaming
      `[Unreleased]` to the new release the same rule keeps applying.
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
                           f"„Deprecated“ — dort gehört er hin, mit Ersatz (`seit` {seit!r})")
            continue
        einfuehrung = wo[-1]                   # the oldest section that names it
        if einfuehrung == OFFEN:
            if _version(seit) <= _version(juengstes):
                befunde.append(
                    f"{bereich}.{name}: `seit` {seit!r}, aber der Alias steht erst unter "
                    f"[{OFFEN}] — {juengstes} ist schon veröffentlicht und kannte ihn nicht; "
                    f"`seit` auf das nächste Release setzen (grösser als {juengstes})")
        elif _version(seit) != _version(einfuehrung):
            befunde.append(f"{bereich}.{name}: `seit` {seit!r}, eingeführt hat den Alias aber "
                           f"[{einfuehrung}] (CHANGELOG, „Deprecated“)")
    return befunde


def c_befunde(datei: dict, klasse=TinySesam, version: str = _paket.__version__,
              wurzel: str = WURZEL, changelog: "str | None" = None) -> tuple:
    """(findings, checked files) — the whole tier-C check of the normal run."""
    ziele = {name: alias.ziel for name, alias in vars(klasse).items() if isinstance(alias, Deprecated)}
    ziele.update({name: e.get("ziel") or f"_{name}" for (_, name), e in c_eintraege(datei).items()
                  if name not in ziele})
    innen, zahl = interne_aufrufe(ziele, wurzel)
    if changelog is None:
        with open(os.path.join(wurzel, "CHANGELOG.md"), encoding="utf-8") as fh:
            changelog = fh.read()
    return (alias_befunde(datei, klasse) + innen + frist_befunde(datei, version)
            + seit_befunde(datei, changelog)), zahl


def pruefe_unterklasse() -> None:
    """A subclass that overrides an old name must find out (RuntimeWarning):
    Since 0.22.0 the routes call `_name`, the override would silently run into the void."""
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")

        class _Ueberschreibt(TinySesam):
            def check_password(self, username, password):
                return None

            def eigene_methode(self):
                return None
    assert [w.category for w in gewarnt] == [RuntimeWarning], [str(w.message) for w in gewarnt]
    text = str(gewarnt[0].message)
    assert f"{_Ueberschreibt.__name__}.check_password" in text and "`_check_password`" in text, text
    assert os.path.abspath(gewarnt[0].filename) == os.path.abspath(__file__), gewarnt[0].filename
    with warnings.catch_warnings(record=True) as gewarnt:
        warnings.simplefilter("always")

        class _Harmlos(TinySesam):
            def eigene_methode(self):
                return None
    assert not gewarnt, (_Harmlos.__name__, [str(w.message) for w in gewarnt])
    ok("a subclass that overrides an old name gets a RuntimeWarning")


def pruefe_warnfilter() -> None:
    """Does `tests/run_all.py` really turn an old name, called FROM the package, into an error?

    A misspelled `-W` filter is only acknowledged by Python with "Invalid -W option ignored"
    — the run would stay green without checking anything. Hence measure the effect: In a
    fresh process with exactly the environment of a suite, code that poses as a module of the package
    calls an alias (method and constant) — that must raise; the same call from
    `__main__` (a user, a test) only warn."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import run_all
    import tempfile
    sandbox = tempfile.mkdtemp(prefix="tinysesam-warnfilter-")
    # Only the filter of run_all.py counts — an externally set PYTHONWARNINGS (such as a
    # strict run with `error::DeprecationWarning`) would falsify the counter-check from `__main__`.
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
    assert not fehlt, f"run_all.py does not filter these modules: {fehlt}"
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
    ok(f"run_all.py: an old name from the package raises ({len(module)} modules filtered), "
       "from own code it only warns")


def selbstpruefung_c() -> None:
    """Does every tier-C rule trigger? On a probe class, not on TinySesam — its aliases
    hopefully happen to be right, and a rule that was never red proves nothing."""
    import tempfile

    def klasse(alias_typ=Deprecated, echt_f=False):
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

    class Stumm(Deprecated):
        __slots__ = ()

        def _warnen(self):
            pass

    class Tief(Deprecated):
        __slots__ = ()

        def _warnen(self):
            warnings.warn(self.meldung, DeprecationWarning, stacklevel=2)

    class Verschluckt(Deprecated):
        __slots__ = ()

        def __get__(self, obj, owner=None):
            fn = super().__get__(obj, owner)
            return (lambda *a, **k: fn(*a)) if self.methode else fn

    class StilleZuweisung(Deprecated):
        __slots__ = ()

        def __set__(self, obj, wert):
            obj.__dict__[self.name] = wert

    class Falsch(Deprecated):
        __slots__ = ()

        def __set__(self, obj, wert):
            warnings.warn("veraltet", RuntimeWarning, stacklevel=2)
            obj.__dict__[self.name] = wert

    class Anderswo(Deprecated):
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
                                        "_K": 1, "K": Deprecated("_K", "x"),
                                        "f": Deprecated("g", "stattdessen `g`")})
    assert alias_befunde(ablage(m__f__ziel="g"), umgelenkt) == [], "target of tier A is allowed"
    rot(alias_befunde(ablage(m__f__ziel="g", m__g__stufe="B"), umgelenkt), "erlaubt ist `_f`")
    # Internal calls: AST over a probe repo — attribute everywhere, string only in the package.
    probe = tempfile.mkdtemp(prefix="tinysesam-c-")
    for rel, text in (("tinysesam/m.py", "auth.f(1)\nauth._f(2)\ngetattr(auth, 'f')\n# auth.f\n"),
                      ("examples/e.py", "x = 'f'\nauth.K\n"), ("tests/t.py", "auth.f()\n")):
        os.makedirs(os.path.join(probe, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(probe, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    innen, zahl = interne_aufrufe({"f": "_f", "K": "_K"}, probe)
    assert zahl == 2 and sorted(b.split(": ")[0] for b in innen) == [
        "examples/e.py:2", "tinysesam/m.py:1", "tinysesam/m.py:3"], (zahl, innen)
    # Deadline: from 1.0 every remaining alias is red, before that none.
    assert frist_befunde(ablage(), "0.22.0") == [] and frist_befunde(ablage(), "0.99.3") == []
    assert len(frist_befunde(ablage(), "1.0.0")) == 2 and frist_befunde(ablage(), "1.2")

    # `seit` against the CHANGELOG (0.22.0): The alias is under "Deprecated" in the section that
    # introduces it; in the open section `seit` is greater than the latest release, otherwise exactly that one.
    def changelog(offen="", release=""):
        return ("# Changelog\n\n## [Unreleased]\n\n### Deprecated\n\n" + offen + "\n\n"
                "## [0.21.0] — 2026-09-27\n\n### Changed\n\n- `f` und `K` zählen hier nicht\n\n"
                "### Deprecated\n\n" + release + "\n\n## [0.20.1] — 2026-09-24\n")
    beide = "- `f` → `_f`, `K` → `_K`"
    neu = ablage(m__f__seit="0.22.0", k__K__seit="0.21.1")
    assert seit_befunde(neu, changelog(offen=beide)) == [], seit_befunde(neu, changelog(offen=beide))
    rot(seit_befunde(ablage(m__f__seit="0.21.0"), changelog(offen=beide)),
        "TinySesam.f: `seit` '0.21.0', aber der Alias steht erst unter [Unreleased]")
    rot(seit_befunde(ablage(k__K__seit="0.19.0"), changelog(offen=beide)),
        "TinySesam.konstanten.K: `seit` '0.19.0', aber")
    alt = ablage(m__f__seit="0.21.0", k__K__seit="0.21.0")
    assert seit_befunde(alt, changelog(release=beide)) == []
    assert seit_befunde(alt, changelog(offen=beide, release=beide)) == [], "the oldest counts"
    rot(seit_befunde(ablage(m__f__seit="0.22.0"), changelog(release=beide)),
        "TinySesam.f: `seit` '0.22.0', eingeführt hat den Alias aber [0.21.0]")
    rot(seit_befunde(ablage(), changelog(offen="- `K` → `_K`")), "TinySesam.f: CHANGELOG nennt")
    rot(seit_befunde(ablage(), "# Changelog\n\n## [Unreleased]\n"), "kein Release-Abschnitt")
    # The normal run goes through the same function and sees all four kinds.
    befunde, _ = c_befunde(ablage(m__f__seit="0.21.0", k__K__seit="0.22.0"), klasse(Stumm),
                           "1.0.0", probe, changelog(offen=beide))
    import shutil
    shutil.rmtree(probe, ignore_errors=True)
    for art in ("löst 0 Warnungen", "tinysesam/m.py:1", "fallen müssen", "kannte ihn nicht"):
        rot(befunde, art)
    ok("Tier-C rules trigger: silent alias, wrong stacklevel, swallowed arguments, "
       "silent assignment on the object, own implementation, baseline ≠ class, wrong target, "
       "internal call, deadline 1.0, `seit` against the CHANGELOG")


# ---------- The names of tiers A and B: English (0.22.0) ----------
# PO decision 2026-09-27: The public surface is named in English — renamed before 0.22.0,
# **without an alias**, because the commitments of the tiers only begin with this release and no consumer
# used any of the German names (CHANGELOG, "Was beim Update auffällt"). So that no German
# word comes back, the guard measures the WHOLE surface of tiers A and B: every name of the
# baseline, the parameters of every method and function (on the live object), the configuration fields
# and the public attributes and constructor parameters of the exported error types
# (`ConfigError.field`, `MissingExtra(message, extra)`). Tier C stays out: Those are the
# old names that keep forwarding as aliases until 1.0. The keys and values this surface
# returns or accepts are measured, since the second PO decision of the same day, by `pruefe_werte()`
# further below; audit and log lines (`login_fail … grund=`, fail2ban) stay as they are.
# Section (k) in `tests/test_sign_in.py` additionally measures the surface of the login building block together with
# the values of `LoginResult.REASONS` — with the same word list (`deutsch_in`).
# (Mutation probes: `by_operator` in `change_username` back to `durch_betreiber` → red;
# `ConfigError.owner_id` back to `besitzer_id` → red; a configuration field `sperre_minuten`
# with a tier → red; emptying `STAMM` → self-check red; no longer measuring the parameters → red.)

#: German words, as a WHOLE word of a name (split at `_`, `.` and CamelCase). Chosen with
#: care: none of them is also an English word that occurs in an API — `die`, `alt`,
#: `hat`, `was`, `man`, `also` are therefore missing, `serie` only counts whole (otherwise `series` would be flagged).
DEUTSCH = frozenset("""
    abgeschaltet abmelden alle als andere anderen anmelden anmeldung antwort anwendung anzahl art arten
    aufheben auftrag ausfuehren basis bei benutzer besitzer bestaetigt betreiber bindung bis darf der
    durch eigene einrichten ereignis ereignisse ergebnis erlaubt erstfaktor falsch fehler fehlgriff
    feld felder fertig foederation foederiert foederierte freigabe frist fremde fuer gesperrt gewaehlt
    gruende grund gruppe gruppen gueltig jetzt kandidat kein keine kennung kennungen konto konten
    leer lesen liste loese loeschen mangel meldung methoden minuten mit nach nachbinden nachbindung
    nachricht naechster neu nur oder ohne passwort pfad praefix pruefen pruefung quelle quellen rolle
    rollen schluessel schreiben seit seite seiten sekunden selbst serie setzen sicherheit
    sicherheitsereignisse sitzung sitzungen sperre sperren sprache stunden tage ueberlauf und
    vergeben verzeichnis von weg weiter weiterleitung wert werte zahl zeit ziel zu zuordnung zurueck
    zweck
    abgewiesen anders ausgefuehrt automat dienstkonto gebunden konflikt lokal mehrdeutig mensch
    schon treffer verbleibend
""".split())
#: German word stems that are also conspicuous INSIDE a word: A constant like
#: `SICHERHEITSEREIGNISSE` is ONE word after splitting. Only stems of five or more letters that are in
#: no English word (`bindung` ≠ `binding`, `sitzung`, `kennung` …).
STAMM = ("anmeld", "aufheb", "ausfuehr", "benutzer", "besitzer", "bestaetig", "betreiber",
         "bindung", "einricht", "ereignis", "ergebnis", "erstfaktor", "fehlgriff", "fehlserie",
         "foederi", "gesperrt", "gewaehlt", "gueltig", "kennung", "loesch", "nachricht", "passwort",
         "pruef", "schluessel", "sicherheit", "sitzung", "ueberlauf", "verworfen", "verzeichnis",
         "zuordnung")


def woerter(name: str) -> set:
    """`LoginResult` → {login, result}, `SECURITY_EVENTS` → {security, events}."""
    return {w for w in re.split(r"[_.]", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name)).lower())
            if w}


def deutsch_in(name: str) -> set:
    """What is German in `name`: whole words from `DEUTSCH`, stems from `STAMM` (also in the middle of a
    word) and umlauts/ß — empty if nothing. A set, so that the finding says WHAT stood out."""
    ww = woerter(name)
    funde = ww & DEUTSCH
    funde |= {s for s in STAMM for w in ww if s in w}
    funde |= {z for z in str(name) if not z.isascii()}
    return funde


def _parameter(fn) -> list:
    """The parameter names of a method or function, without `self`/`cls` — `[]` if no
    signature is available (then `pruefe_namen` reports that via the minimum count)."""
    try:
        return [p for p in inspect.signature(fn).parameters if p not in ("self", "cls")]
    except (TypeError, ValueError):
        return []


def oberflaeche_namen(datei: dict, klasse=TinySesam, config=TinySesamConfig,
                      paket=_paket) -> list:
    """[(where, name)] — every name of tiers A and B, plus parameters, fields, attributes.

    The names come from the baseline (the normal run keeps it equal to the measurement), the
    parameters and attributes from the live object — a new parameter needs no new
    entry to be seen."""
    namen = []
    objekte = {"TinySesam": klasse, "TinySesamConfig.methoden": config, **ERGEBNISTYPEN}
    eigen = {klasse.__name__, config.__name__, *ERGEBNISTYPEN}   # have their own areas
    for bereich in sorted(datei):
        eintraege = datei[bereich]
        if not isinstance(eintraege, dict):
            continue
        for name in sorted(eintraege):
            e = eintraege[name]
            if not isinstance(e, dict) or e.get("stufe") not in ("A", "B"):
                continue
            namen.append((bereich, name))
            if bereich in objekte:
                ziel = inspect.getattr_static(objekte[bereich], name, None)
                if isinstance(ziel, (staticmethod, classmethod)):
                    ziel = ziel.__func__
                if inspect.isfunction(ziel):
                    namen += [(f"{bereich}.{name}()", p) for p in _parameter(ziel)]
            elif bereich == "exporte":
                obj = getattr(paket, name, None)
                if inspect.isfunction(obj):
                    namen += [(f"{name}()", p) for p in _parameter(obj)]
                elif inspect.isclass(obj) and name not in eigen:
                    attribute = {a for a in list(vars(obj)) + list(inspect.get_annotations(obj))
                                 if not a.startswith("_")}
                    namen += [(name, a) for a in sorted(attribute)]
                    if "__init__" in vars(obj):
                        namen += [(f"{name}()", p) for p in _parameter(vars(obj)["__init__"])]
    return namen


def namens_befunde(namen: list) -> list:
    """Every name with a German word, as a readable line. Empty = everything English."""
    return [f"{wo}: {name!r} ({', '.join(sorted(deutsch_in(name)))})"
            for wo, name in namen if deutsch_in(name)]


#: What the measurement must see at minimum — otherwise it silently measures less than it promises
#: (an empty intersection looks like a clean surface).
NAMEN_PFLICHT = (("TinySesam", "change_username"), ("TinySesam.change_username()", "by_operator"),
                 ("TinySesam.konstanten", "SECURITY_EVENTS"),
                 ("TinySesamConfig.felder", "federation_name_binding_days"),
                 ("TinySesamConfig.methoden", "validate"), ("TinySesam.eigenschaften", "csrf_cookie_name"),
                 ("ConfigError", "owner_id"), ("MissingExtra()", "message"),
                 ("LoginResult", "next_factor"), ("PasswordChangeResult", "api_keys_active"),
                 ("exporte", "current_version"))


def pruefe_namen(datei: dict, klasse=TinySesam, paket=_paket, pflicht=NAMEN_PFLICHT,
                 mindestens=(500, 200, 150)) -> tuple:
    """(findings, count) — the whole name check of the normal run, with minimum count. The same
    function checks the self-probe; a check that existed only there would run into the void in the run."""
    namen = oberflaeche_namen(datei, klasse=klasse, paket=paket)
    fehlt = [f"{wo}: {name!r} wird nicht gemessen — Messung kaputt?"
             for wo, name in pflicht if (wo, name) not in namen]
    parameter = sum(1 for wo, _ in namen if wo.endswith("()"))
    felder = sum(1 for wo, _ in namen if wo == "TinySesamConfig.felder")
    # As of 0.22.0: 596 entries, of which 278 parameters and 159 fields — with headroom downwards.
    if len(namen) < mindestens[0] or parameter < mindestens[1] or felder < mindestens[2]:
        fehlt.append(f"zu wenig gemessen: {len(namen)} Namen, {parameter} Parameter, {felder} "
                     f"Felder (erwartet mindestens {'/'.join(map(str, mindestens))})")
    return fehlt + namens_befunde(namen), len(namen)


def selbstpruefung_namen() -> None:
    """Does the name check find what it should find — and only that? On a probe, not on the
    real surface: That one is hopefully clean right now, and a list that never found anything
    proves nothing."""
    for deutsch in ("foederation_nachbinden", "loese_fremde_bindung", "SICHERHEITSEREIGNISSE",
                    "andere_sitzungen", "api_key_art", "kennung_vergeben", "nach_der_antwort",
                    "nur_foederiert", "passwort_mangel", "pin_als_erstfaktor", "pruefen",
                    "sperre_aufheben", "FOEDERIERTE_QUELLEN", "MFA_ENROLLMENT_ARTEN",
                    "NACHBINDUNG_GRUENDE", "SEITEN", "durch_betreiber", "zuordnung", "ausfuehren",
                    "quelle", "neu", "kandidat", "email_bestaetigt", "jetzt", "basis", "auftrag",
                    "bei_ueberlauf", "methoden", "name_selbst_gewaehlt", "feld", "besitzer_id",
                    "nachricht", "pfad", "darf_mfa_einrichten", "SperreMinuten", "größe",
                    # keys and values up to 0.21.x (`pruefe_werte`, PO decision 2026-09-27):
                    "ausgefuehrt", "gebunden", "konflikt", "mehrdeutig", "nicht_im_verzeichnis",
                    "ohne_kennung", "abgewiesen", "lokal", "verzeichnis", "gebunden_an", "treffer",
                    "grund", "kein_konto", "dienstkonto", "gesperrt", "schon_gebunden",
                    "anders_gebunden", "adresse_als_name", "kennung_ungueltig", "name_aus_quelle",
                    "frist", "fehlserien", "verworfene_rollen", "verbleibend", "anzahl",
                    "recovery_codes_geloescht", "automat", "mensch", "praefix", "zweck", "vergeben",
                    "sperre", "admin_passwort", "passwort_reset", "sitzungen_beendet", "_key_art",
                    # only findable via a stem — composed, not a word of the list:
                    "KENNUNGSRAUM", "passwortregel", "sitzungsdauer", "Verzeichnisname"):
        assert deutsch_in(deutsch), f"{deutsch!r} is not noticed by the name check"
    for englisch in ("federation_bind_existing", "federation_unbind", "SECURITY_EVENTS",
                     "count_other_sessions", "locked_series", "series", "start", "partial",
                     "binding", "TinySesam", "base", "base_url", "new_username", "mapping", "apply",
                     "source", "now", "methods", "message", "owner_id", "field", "path",
                     "browser_path", "after_response", "on_overflow", "artifact", "nachos",
                     "prefix", "background", "validate", "PAGES",
                     # the keys and values since 0.22.0 — and English words close to the list:
                     "applied", "bound", "conflict", "ambiguous", "not_in_directory",
                     "no_identifier", "refused", "local_password", "local", "directory",
                     "bound_to", "matches", "reason", "no_account", "service_account", "disabled",
                     "already_bound", "bound_elsewhere", "address_as_name", "invalid_identifier",
                     "self_chosen_name", "name_from_other_source", "binding_window_expired",
                     "failure_series", "dropped_roles", "remaining", "count",
                     "recovery_codes_deleted", "automation", "automatic", "human", "purpose",
                     "taken", "account_disabled", "admin_password_reset", "password_reset",
                     "sessions_revoked", "_key_kind", "old", "new", "alternative", "schema"):
        assert not deutsch_in(englisch), f"{englisch!r}: false alarm ({deutsch_in(englisch)})"

    class Probe:
        GUT = 1
        SICHERHEITSEREIGNISSE = ()

        def gut(self, request, *, by_operator=False):             # noqa: ARG002
            return None

        def schlecht(self, request, *, durch_betreiber=False):     # noqa: ARG002
            return None

    class ProbeError(Exception):
        field = ""
        besitzer_id = None

        def __init__(self, nachricht: str, extra: str = ""):
            super().__init__(nachricht)

    probe_paket = type(sys)("probe_paket")
    probe_paket.ProbeError = ProbeError
    ablage = {"TinySesam": {"gut": {"stufe": "A"}, "schlecht": {"stufe": "B"}},
              "TinySesam.konstanten": {"GUT": {"stufe": "A"}, "SICHERHEITSEREIGNISSE": {"stufe": "C"}},
              "TinySesamConfig.felder": {"sperre_minuten": {"stufe": "A"}, "ok_feld": {"stufe": "C"}},
              "exporte": {"ProbeError": {"stufe": "A"}}}
    namen = oberflaeche_namen(ablage, klasse=Probe, paket=probe_paket)
    assert ("TinySesam.gut()", "by_operator") in namen and ("ProbeError", "field") in namen, namen
    # Tier C does not count: The old names are there as aliases until 1.0.
    assert not any(n in ("SICHERHEITSEREIGNISSE", "ok_feld") for _, n in namen), namen
    # Through the same function as the normal run: the four German names, nothing else.
    befunde, zahl = pruefe_namen(ablage, klasse=Probe, paket=probe_paket, pflicht=(),
                                 mindestens=(len(namen), 0, 0))
    assert [b.split(": ")[1].split(" ")[0] for b in befunde] == [
        "'durch_betreiber'", "'sperre_minuten'", "'besitzer_id'", "'nachricht'"], befunde
    # … and the minimum count triggers when a kind is missing or too little is measured.
    befunde, _ = pruefe_namen(ablage, klasse=Probe, paket=probe_paket,
                              pflicht=(("ProbeError()", "message"),), mindestens=(zahl + 1, 0, 0))
    assert len(befunde) == 6 and "'message' wird nicht gemessen" in befunde[0] \
        and "zu wenig gemessen" in befunde[1], befunde
    # Wired up: The normal run calls exactly this function — a check that would only
    # exist here would stay silent in the run.
    gerufen = {k.func.id for k in ast.walk(ast.parse(inspect.getsource(main)))
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)}
    assert "pruefe_namen" in gerufen, "main() does not call pruefe_namen"
    ok("Name check triggers: German names, parameters, fields, attributes, constructor, "
       f"umlaut — {len(STAMM)} stems, {len(DEUTSCH)} words, no false alarm on English ones")


# ---------- Keys and values of tiers A and B: English (0.22.0) ----------
# PO decision 2026-09-27 ("Translate everything, DB values too"): After the names also what the
# surface returns or accepts — the result dicts of the methods (`gc()`, the report of
# `federation_bind_existing`, `create_api_key` …), the payload of `on_security_event`, the context
# of custom pages (`set_template`: `ctx["prefix"]`, `ctx["purpose"]`), the JSON responses of the routes,
# the values of `kind` and what of it is in the database. No alias; stored values are carried over
# by the migration to schema 12 (`Store._werte_englisch`), an old value is still read
# (tests/test_legacy_data.py). Audit and log lines stay as they are (fail2ban, operators'
# filters) — this check does not measure them.
#
# Measured twice: on the live object (a probe instance runs through the paths, a hook
# collects the events, custom templates record their context) and in the source (every
# call of `_security_event`, `render_page`, every key a built-in page reads from
# `ctx`, every returned JSON response of the routes). The probe sees what really
# goes out; the source what the probe does not reach (such as `passkey_added` without the extra).
# (Mutation probes: `failure_series` in `gc()` back to `fehlserien` → red; `reason=` in
# `_keys_widerrufen` back to `grund=` → red; `ctx.setdefault("prefix", …)` back to
# `"praefix"` → red; `create_api_key` writes `automat` again → red; no longer calling the probe
# → wiring red.)

#: The keys and values up to 0.21.x — also those that passed as English as a word (`alt` is an
#: English word and is therefore not in `DEUTSCH`). If one reappears, it is a
#: regression, not a new name.
ALTE_WERTE = frozenset("""
    quelle ausgefuehrt gebunden konflikt mehrdeutig nicht_im_verzeichnis ohne_kennung abgewiesen
    lokal verzeichnis kennung grund gebunden_an treffer kein_konto dienstkonto gesperrt
    schon_gebunden anders_gebunden adresse_als_name kennung_ungueltig name_selbst_gewaehlt
    name_aus_quelle frist fehlserien verworfene_rollen alt neu anzahl verbleibend
    recovery_codes_geloescht automat mensch praefix zweck vergeben sperre admin_passwort
    passwort_reset sitzungen_beendet _key_art
""".split())


def wert_befunde(paare: list) -> list:
    """Every key or value with a German word or from `ALTE_WERTE`, as a readable line."""
    return [f"{wo}: {wert!r} ({', '.join(sorted(deutsch_in(wert)) or ['Name bis 0.21.x'])})"
            for wo, wert in paare if deutsch_in(wert) or wert in ALTE_WERTE]


def _schluessel(wo: str, obj) -> list:
    """[(where, key)] of a dict, recursive for lists and sub-dicts."""
    paare = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            paare.append((wo, str(k)))
            paare += _schluessel(f"{wo}.{k}", v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            paare += _schluessel(f"{wo}[]", v)
    return paare


def werte_der_probe(klasse=TinySesam) -> list:
    """[(where, key_or_value)] — what a probe instance emits, on all paths that work without
    extra. `klasse` for the self-probe (a subclass that delivers an old key)."""
    import re as _re
    import tempfile
    import pyotp
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    paare: list = []
    with tempfile.TemporaryDirectory() as verz:
        post: list = []
        ereignisse: list = []
        a = klasse(TinySesamConfig(
            db_path=os.path.join(verz, "probe.db"), cookie_secure=False, csrf_enabled=False,
            passkey_enabled=False, pin_enabled=True, magiclink_enabled=True,
            base_url="https://app.example.com"))
        a.set_mailer(lambda to, betreff, text, html=None: post.append(text))
        a.on_security_event = lambda e, konto, details: ereignisse.append((e, konto, details))

        def link(pfad):
            return next(m.group(1) for t in reversed(post)
                        for m in [_re.search(rf"{pfad}([A-Za-z0-9_\-]+)", t)] if m)

        uid = a.create_user("probe", password="Probe-Pw-1234", email="probe@example.com")
        paare += [("get_user()", k) for k in a.get_user(uid)]
        paare += [("find_user()", k) for k in a.find_user("probe")]
        paare += [("identifier_taken()", k) for k in a.identifier_taken("probe")]
        a.set_password(uid, "Neu-Pw-5678xyz")
        a.set_pin(uid, "4711")
        a.disable_pin(uid)
        tb = a.totp_begin(uid)
        paare += _schluessel("totp_begin()", tb)
        a.totp_confirm(uid, pyotp.TOTP(tb["secret"]).now())
        codes = a.generate_recovery_codes(uid)
        a._verify_recovery_code(uid, codes[0])
        a.totp_disable(uid)
        k = a.create_api_key(uid, name="probe")
        paare += _schluessel("create_api_key()", k) + [("create_api_key().kind", k["kind"])]
        km = a.create_api_key(uid, name="cli", kind="human")
        paare += [("create_api_key(kind=).kind", km["kind"])]
        for e in a.list_api_keys(uid):
            paare += _schluessel("list_api_keys()[]", e) + [("list_api_keys()[].kind", e["kind"])]
        paare += [("api_key_kind()", a.api_key_kind(km["key"])), ("api_key_kind()", a.api_key_kind(k["key"]))]
        konto, _ = a.verify_api_key(k["key"])
        paare += _schluessel("verify_api_key()[0]", konto)
        paare += [("api_key.kind (Datenbank)", z["kind"])
                  for z in a.store._all("SELECT kind FROM api_key")]
        paare += [("TinySesam._KEY_ARTEN", w) for w in a._KEY_ARTEN]
        a.revoke_api_key(k["id"])
        a.change_username(uid, "probe2")
        a.request_email_change(uid, "neu@example.com", "https://app.example.com")()
        tok = link("/auth/email/")
        paare += _schluessel("peek_magic(email_change)", a.peek_magic(tok))
        paare += [("magic_token.payload (Datenbank)", k2) for z in
                  a.store._all("SELECT payload FROM magic_token WHERE purpose='email_change'")
                  for k2 in json.loads(z["payload"] or "{}")]
        paare += [("confirm_email_change()", a.confirm_email_change(tok))]
        a.request_email_change(uid, "frei@example.com", "https://app.example.com")()
        tok = link("/auth/email/")
        a.create_user("dritte", email="frei@example.com")
        paare += [("confirm_email_change()", a.confirm_email_change(tok))]
        inv = a.create_invite("gast@example.com", "https://app.example.com", roles=["leser"])
        paare += _schluessel("create_invite()", inv) + _schluessel("peek_magic(invite)",
                                                                   a.peek_magic(inv["token"]))
        paare += _schluessel("own_events()", a.own_events(uid))
        paare += _schluessel("all_security()", a.all_security())

        # Custom pages: Which keys does a custom template really get?
        kontexte: dict = {}

        def aufzeichnen(name):
            def fn(auth, ctx):
                kontexte[name] = sorted(ctx)
                return "<p>probe</p>"
            return fn
        for seite in ("login", "magic_confirm"):
            a.set_template(seite, aufzeichnen(seite))
        app = FastAPI()
        app.include_router(a.router())
        c = TestClient(app)
        c.get("/auth/login")
        c.get(f"/auth/magic/{a.create_magic_token('login', user_id=uid, email='neu@example.com')}")
        for seite, schluessel in kontexte.items():
            paare += [(f"set_template({seite!r}) ctx", s) for s in schluessel]

        # JSON of the routes, on the live object: account page and admin API.
        app.include_router(a.admin_router(), prefix="/probe-admin")
        a.create_user("chef", password="Chef-Pw-12345", is_admin=True)
        for name, pw in (("probe2", "Neu-Pw-5678xyz"), ("chef", "Chef-Pw-12345")):
            k_c = TestClient(app)
            k_c.post("/auth/login", data={"username": name, "password": pw}, follow_redirects=False)
            if name == "probe2":
                paare += _schluessel("GET /auth/me", k_c.get("/auth/me").json())
                neu_k = k_c.post("/auth/apikeys", json={"name": "json"}).json()
                paare += _schluessel("POST /auth/apikeys", neu_k)
                liste = k_c.get("/auth/apikeys").json()
                paare += _schluessel("GET /auth/apikeys", liste)
                paare += [("GET /auth/apikeys[].kind", e.get("kind")) for e in liste]
            else:
                konten = k_c.get("/probe-admin/api/users").json()
                paare += _schluessel("GET <admin>/api/users", konten)
        try:
            a.create_user("probe2")
        except ConfigError as e:
            paare.append(("ConfigError.field", e.field))
        try:
            a.create_user("vierte", email="neu@example.com")
        except ConfigError as e:
            paare.append(("ConfigError.field", e.field))

        # Events: the reason of the collective revocation is a value.
        a.set_disabled(uid, True)
        a.store.set_disabled(a.find_user("dritte")["id"], True)     # lock of an open confirmation
        chef_c = TestClient(app)
        chef_c.post("/auth/login", data={"username": "chef", "password": "Chef-Pw-12345"},
                    follow_redirects=False)
        paare += [("GET <admin>/api/users[].disabled_by", k2["disabled_by"])
                  for k2 in chef_c.get("/probe-admin/api/users").json() if k2["disabled_by"]]
        for e, konto_e, details in ereignisse:
            paare += [(f"on_security_event({e!r}) konto", s) for s in konto_e]
            paare += _schluessel(f"on_security_event({e!r}) details", details)
            if "reason" in details:
                paare.append((f"on_security_event({e!r}).reason", details["reason"]))
        paare += [("TinySesam._KEYS_WIDERRUFEN_GRUENDE", g) for g in a._KEYS_WIDERRUFEN_GRUENDE]

        # Existing-binding: all parts of the report, entries and reasons.
        class Verzeichnis:
            def eintrag_suchen(self, name):
                return {"anna": [{"id": "u-anna", "name": "Anna", "email": "anna@example.com"}],
                        "dora": [{"id": "u-d1"}, {"id": "u-d2"}],
                        "emil": [{"id": "u-fritz"}]}.get(name, [])
        a.ldap = Verzeichnis()
        for n in ("anna", "dora", "bert", "emil", "fritz"):
            a.create_user(n)
        a.store.link_federated("ldap", "u-fritz", a.find_user("fritz")["id"], 0)
        a.create_service("dienst")
        for bericht in (a.federation_bind_existing("ldap"),
                        a.federation_bind_existing("saml", mapping={"niemand": "x", "anna": "",
                                                                    "dienst": "d", "probe2": "p"})):
            paare += _schluessel("federation_bind_existing()", bericht)
            paare += [("federation_bind_existing()[].reason", e["reason"])
                      for teil in bericht.values() if isinstance(teil, list)
                      for e in teil if "reason" in e]
        paare += [("NAME_BINDING_REFUSALS", g) for g in a.NAME_BINDING_REFUSALS]
        paare += _schluessel("gc()", a.gc())
    return paare


def werte_der_konstanten(datei: dict) -> list:
    """[(where, value)] — the values of the constants of tiers A/B (elements, keys; running text with
    spaces not) and the defaults of the configuration fields that look like an abbreviation."""
    paare = []
    for name, e in (datei.get("TinySesam.konstanten") or {}).items():
        if not isinstance(e, dict) or e.get("stufe") not in ("A", "B"):
            continue
        wert = inspect.getattr_static(TinySesam, name, None)
        for w in (wert if isinstance(wert, (tuple, list, dict, frozenset, set)) else [wert]):
            if isinstance(w, str) and " " not in w:
                paare.append((f"TinySesam.{name}", w))
    for typ in ERGEBNISTYPEN.values():
        paare += [(f"{typ.__name__}.REASONS", w) for w in typ.REASONS]
    for f in dataclasses.fields(TinySesamConfig):
        if isinstance(f.default, str) and re.fullmatch(r"[A-Za-z_]+", f.default or "-"):
            paare.append((f"TinySesamConfig.{f.name} (Vorgabe)", f.default))
    return paare


#: Modules with routes: What is returned there is a JSON response.
ROUTEN_MODULE = ("router.py", "admin.py", "webauthn_.py", "oidc.py", "saml_.py", "gateway.py")


def werte_im_code(quellen: dict) -> list:
    """[(where, name)] from the source (`{filename: text}`): keyword arguments of every call of
    `_security_event` (the payload of `on_security_event`) and `render_page` (the context
    of custom pages), every key a built-in renderer reads from `ctx` or
    `render_page` puts into it, the keys of the `…_ctx` helpers, and every key of a
    returned JSON response in a routes module."""
    paare = []

    def konst(k):
        return k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else None

    def dict_schluessel(knoten):
        if isinstance(knoten, ast.Dict):
            return [konst(k) for k in knoten.keys if konst(k)]
        if isinstance(knoten, ast.Call) and getattr(knoten.func, "id", "") == "dict":
            return [k.arg for k in knoten.keywords if k.arg]
        if isinstance(knoten, (ast.ListComp, ast.GeneratorExp)):
            return dict_schluessel(knoten.elt)
        if isinstance(knoten, ast.List):
            return [s for e in knoten.elts for s in dict_schluessel(e)]
        return []

    for datei, text in sorted(quellen.items()):
        baum = ast.parse(text)
        for k in ast.walk(baum):
            if isinstance(k, ast.Call):
                name = k.func.attr if isinstance(k.func, ast.Attribute) else getattr(k.func, "id", "")
                if name == "_security_event":
                    paare += [(f"{datei}: on_security_event-Nutzlast", w.arg) for w in k.keywords if w.arg]
                elif name == "render_page":
                    paare += [(f"{datei}: render_page-Kontext", w.arg) for w in k.keywords
                              if w.arg and w.arg not in ("request", "status")]
                elif name in ("get", "setdefault") and isinstance(k.func, ast.Attribute) \
                        and getattr(k.func.value, "id", "") == "ctx" and k.args and konst(k.args[0]):
                    paare.append((f"{datei}: ctx", konst(k.args[0])))
                elif name == "JSONResponse" and datei in ROUTEN_MODULE and k.args:
                    paare += [(f"{datei}: JSON-Antwort", s) for s in dict_schluessel(k.args[0])]
            elif isinstance(k, ast.Subscript) and getattr(k.value, "id", "") == "ctx" \
                    and konst(k.slice):
                paare.append((f"{datei}: ctx", konst(k.slice)))
            elif isinstance(k, ast.FunctionDef) and k.name.endswith("_ctx"):
                paare += [(f"{datei}: {k.name}", s) for r in ast.walk(k) if isinstance(r, ast.Return)
                          and r.value is not None for s in dict_schluessel(r.value)]
            elif isinstance(k, ast.Return) and k.value is not None and datei in ROUTEN_MODULE:
                paare += [(f"{datei}: JSON-Antwort", s) for s in dict_schluessel(k.value)]
    return paare


def _quellen(wurzel: str = WURZEL) -> dict:
    paket = os.path.join(wurzel, "tinysesam")
    quellen = {}
    for n in sorted(os.listdir(paket)):
        if n.endswith(".py"):
            with open(os.path.join(paket, n), encoding="utf-8") as fh:
                quellen[n] = fh.read()
    return quellen


#: What the value check must see at minimum — one entry per path that occurs only there.
WERTE_PFLICHT = (("gc()", "failure_series"), ("create_api_key()", "dropped_roles"),
                 ("create_api_key(kind=).kind", "human"), ("list_api_keys()[].kind", "automation"),
                 ("api_key.kind (Datenbank)", "human"), ("magic_token.payload (Datenbank)", "old"),
                 ("peek_magic(email_change).payload", "old"), ("confirm_email_change()", "taken"),
                 ("federation_bind_existing()", "local_password"),
                 ("federation_bind_existing().conflict[]", "bound_to"),
                 ("federation_bind_existing().ambiguous[]", "matches"),
                 ("federation_bind_existing()[].reason", "no_account"),
                 ("on_security_event('api_keys_revoked').reason", "account_disabled"),
                 ("on_security_event('username_changed') details", "old"),
                 ("set_template('magic_confirm') ctx", "purpose"),
                 ("set_template('login') ctx", "prefix"),
                 ("webauthn_.py: on_security_event-Nutzlast", "name"),
                 ("manager.py: ctx", "prefix"), ("router.py: render_page-Kontext", "purpose"),
                 ("admin.py: JSON-Antwort", "disabled_by"), ("TinySesam.SECURITY_EVENTS", "api_keys_revoked"),
                 ("POST /auth/apikeys", "dropped_roles"), ("GET /auth/apikeys[].kind", "automation"),
                 ("GET <admin>/api/users[].disabled_by", "operator"),
                 ("GET <admin>/api/users[].disabled_by", "confirmation"), ("ConfigError.field", "email"))


def pruefe_werte(datei: dict, klasse=TinySesam, quellen: "dict | None" = None,
                 pflicht=WERTE_PFLICHT, mindestens: int = 600) -> tuple:
    """(findings, count) — the whole value check of the normal run, with minimum count (as of 0.22.0:
    790 entries, with headroom downwards). The same function checks the self-probe."""
    paare = (werte_der_probe(klasse) + werte_der_konstanten(datei)
             + werte_im_code(_quellen() if quellen is None else quellen))
    gesehen = set(paare)
    fehlt = [f"{wo}: {wert!r} wird nicht gemessen — Probe oder Messung kaputt?"
             for wo, wert in pflicht if (wo, wert) not in gesehen]
    if len(paare) < mindestens:
        fehlt.append(f"zu wenig gemessen: {len(paare)} Schlüssel und Werte (erwartet mindestens "
                     f"{mindestens})")
    return fehlt + wert_befunde(sorted(gesehen)), len(paare)


def selbstpruefung_werte() -> None:
    """Does the value check find an old key — in the probe and in the source?"""
    assert all(wert_befunde([("x", w)]) for w in ALTE_WERTE), "ALTE_WERTE measures nothing"
    assert not wert_befunde([("x", w)
                             for w in ("old", "new", "count", "reason", "human", "automation",
                                       "prefix", "purpose", "taken", "failure_series")]), \
        "False alarm on the English values"

    class Rueckfall(TinySesam):
        def gc(self, attempts_older_than_sec: int = 86400) -> dict:
            return {"fehlserien": 0, **super().gc(attempts_older_than_sec)}

    probe = [w for wo, w in werte_der_probe(Rueckfall) if wo == "gc()"]
    assert "fehlserien" in probe and wert_befunde([("gc()", "fehlserien")]), probe
    quelle = {"router.py": 'def f(auth, request):\n'
                           '    auth._security_event("x", 1, anzahl=2)\n'
                           '    return auth.render_page("p", request=request, zweck="login")\n'
                           'def g():\n    return {"ok": True, "gebunden": []}\n'
                           'def _reg_ctx(nxt):\n    return dict(next=nxt, kennung="")\n',
              "templates.py": 'def _p(auth, ctx):\n    return ctx.get("praefix") + ctx["alt"]\n'}
    funde = sorted({w for _, w in werte_im_code(quelle) if wert_befunde([("", w)])})
    assert funde == ["alt", "anzahl", "gebunden", "kennung", "praefix", "zweck"], funde
    befunde, _ = pruefe_werte({}, quellen={}, pflicht=(("gc()", "gibt-es-nicht"),),
                              mindestens=10 ** 6)
    assert "'gibt-es-nicht' wird nicht gemessen" in befunde[0] and "zu wenig gemessen" in befunde[1], \
        befunde[:2]
    gerufen = {k.func.id for k in ast.walk(ast.parse(inspect.getsource(main)))
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)}
    assert "pruefe_werte" in gerufen, "main() does not call pruefe_werte"
    ok("Value check triggers: an old key in the probe (gc), in an event, in the context "
       "of a page, in a JSON response, in a ctx helper; minimum count and wiring")


def _zaehle_stufen(datei: dict) -> str:
    zahl = {s: 0 for s in STUFEN}
    for je_name in stufen_aus(datei).values():
        for stufe in je_name.values():
            zahl[stufe] = zahl.get(stufe, 0) + 1
    return ", ".join(f"{s} {n}" for s, n in zahl.items())


def _melde_ohne_stufe(fehlt: list) -> None:
    print(f"\n  {len(fehlt)} public names without a valid tier:\n")
    for zeile in fehlt:
        print(f"    NO TIER     {zeile}")
    print("\n  Every public name needs an explicit tier — in tests/api_surface.json")
    print('  set `"stufe": "A"|"B"|"C"` on the entry (meaning: API.md, „Drei Stufen“):')
    for stufe, text in STUFEN.items():
        print(f"    {stufe}  {text}")
    print("  Nothing public should arise by accident: If the name is internal, it gets a")
    print("  leading underscore and disappears from the baseline.\n")


def main(argv):
    jetzt = oberflaeche()
    selbstpruefung(jetzt)
    selbstpruefung_signatur(jetzt)
    selbstpruefung_stufen(jetzt)
    selbstpruefung_c()
    selbstpruefung_namen()
    selbstpruefung_werte()

    frueher_datei = {}
    if os.path.exists(ABLAGE):
        with open(ABLAGE, encoding="utf-8") as fh:
            frueher_datei = json.load(fh)

    if "--update" in argv:
        ablage = mit_stufen(jetzt, frueher_datei)
        with open(ABLAGE, "w", encoding="utf-8") as fh:
            json.dump(ablage, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        print(f"  Surface pinned: {ABLAGE}")
        fehlt = ohne_stufe(ablage)
        if fehlt:
            _melde_ohne_stufe(fehlt)
            return 1
        return 0

    if not frueher_datei:
        print(f"  {ABLAGE} is missing — create it once with: python tests/test_api_surface.py --update")
        return 1

    rot, fehlt, brueche, erweiterungen = vergleiche(frueher_datei, jetzt)
    if fehlt:
        _melde_ohne_stufe(fehlt)
    else:
        ok(f"every public name has a tier ({_zaehle_stufen(frueher_datei)})")

    # Tier C (0.22.0): aliases, no calls of old names in own code, deadline 1.0.
    c_fehler, c_dateien = c_befunde(frueher_datei)
    assert c_dateien >= 20, f"only {c_dateien} files searched for old names — path broken?"
    if c_fehler:
        rot = True
        print(f"\n  {len(c_fehler)} findings on tier C (alias until 1.0):\n")
        for zeile in c_fehler:
            print(f"    TIER C       {zeile}")
        print("\n  Tier C means: The implementation carries an underscore, the old name is "
              "`Deprecated(\"_name\", \"<Ersatz>\")`\n  (tinysesam/_deprecated.py), and nothing in the "
              "package calls it. The entry in tests/api_surface.json\n  carries `ziel`, `seit` and "
              "`bis`.\n")
    else:
        ok(f"Tier C: {len(c_eintraege(frueher_datei))} aliases warn exactly once and point to "
           f"their implementation, an assignment on the object (test fake) warns; {c_dateien} "
           "files without an old name")
    pruefe_unterklasse()
    pruefe_warnfilter()

    # The names of tiers A and B are English (PO decision 2026-09-27).
    n_fehler, n_zahl = pruefe_namen(frueher_datei)
    if n_fehler:
        rot = True
        print(f"\n  {len(n_fehler)} names of tiers A/B with a German word (or measurement too small):\n")
        for zeile in n_fehler:
            print(f"    GERMAN       {zeile}")
        print("\n  The public surface is named in English — names, parameters, configuration fields,")
        print("  attributes of the error types. If a hit is an English word, it belongs out of")
        print("  `DEUTSCH`/`STAMM` (with a counter-check in `selbstpruefung_namen`).\n")
    else:
        ok(f"Tiers A and B English: {n_zahl} names, parameters, fields and attributes, no "
           "German word")

    # The keys and values of tiers A and B are English (PO decision 2026-09-27).
    w_fehler, w_zahl = pruefe_werte(frueher_datei)
    if w_fehler:
        rot = True
        print(f"\n  {len(w_fehler)} keys/values of tiers A/B German or from 0.21.x "
              "(or measurement too small):\n")
        for zeile in w_fehler:
            print(f"    VALUE        {zeile}")
        print("\n  What the public surface returns or accepts is English — result dicts,")
        print("  event payload, context of custom pages, JSON responses, stored values. Audit")
        print("  and log lines are not meant (this check does not measure them).\n")
    else:
        ok(f"Keys and values of tiers A and B English: {w_zahl} measured (probe instance, "
           "constants, source), no German word, none from 0.21.x")

    if not brueche and not erweiterungen:
        n = sum(len(v) for v in jetzt.values())
        ok(f"public API unchanged ({n} names)")
        return 1 if rot else 0

    print("\n  The public API has changed.\n")
    for b in brueche:
        print(f"    BREAK        {b}")
    for e in erweiterungen:
        print(f"    Extension    {e}")
    print("\n  A break costs users work. What it costs is told by the tier before it:")
    for stufe, text in STUFEN.items():
        print(f"    [{stufe}] {text}")
    print("  If the change was intended: `python tests/test_api_surface.py --update`, then commit")
    print("  — and point it out in the CHANGELOG if a BREAK is involved. A new name")
    print("  needs its tier afterwards.\n")
    return 1


if __name__ == "__main__":
    code = main(sys.argv[1:])
    print("\nAPI SURFACE " + ("OK ✅" if code == 0 else "CHANGED OR WITHOUT TIER ❌"))
    sys.exit(code)

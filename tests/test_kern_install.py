"""Was `pip install tinysesam` OHNE Extras können muss.

Warum es diese Suite gibt: Bis 2026-09-21 stand `passkey_enabled` per Vorgabe auf `True`, obwohl
`webauthn` nicht im Kern liegt, sondern im Extra `[passkey]`. Damit stürzte der allererste Schritt
jedes neuen Nutzers ab — `TinySesam(TinySesamConfig(db_path=…)).router()` endete mit
`ModuleNotFoundError: webauthn`. Gesehen hat es niemand, weil `run_all.py` echte Fehlschläge als
„übersprungen" verbuchte.

Die Prüfungen hier laufen absichtlich OHNE die Extras zu importieren: Sie messen die Vorgabewerte,
nicht die Umgebung. So schlagen sie auch im vollen Lauf an, in dem alle Extras installiert sind —
dort, wo der Fehler sonst unsichtbar bleibt.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tinysesam import TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Kern-Install — was ohne Extras gehen muss")

# Welcher Schalter welches Extra braucht — aus dem CODE, nicht als Kopie. Eine Tabelle hier
# wäre beim nächsten neuen Verfahren still veraltet und der Test dann grün, ohne es zu prüfen.
from tinysesam.manager import SCHALTER_BRAUCHT_EXTRA  # noqa: E402

r.check("die Tabelle Schalter→Extra ist nicht leer", bool(SCHALTER_BRAUCHT_EXTRA),
        "leer — dann prüft die Schleife darunter nichts")

# Jeder Schalter muss es auch geben: Ein Tippfehler in der Tabelle träfe sonst nie zu und
# fiele niemandem auf.
vorgabe = TinySesamConfig(db_path=":memory:")
unbekannt = [k for k in SCHALTER_BRAUCHT_EXTRA if not hasattr(vorgabe, k)]
r.check("jeder Schalter aus der Tabelle existiert in der Config", not unbekannt, f"{unbekannt}")

# Und jedes genannte Extra muss im pyproject stehen.
_roh_vorab = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
fehlende_extras = [e for _, e in SCHALTER_BRAUCHT_EXTRA.values()
                   if f"\n{e} = [" not in _roh_vorab]
r.check("jedes genannte Extra gibt es im pyproject", not fehlende_extras, f"{fehlende_extras}")

for schalter, (modul, extra) in sorted(SCHALTER_BRAUCHT_EXTRA.items()):
    an = bool(getattr(vorgabe, schalter, False))
    r.check(f"{schalter} ist per Vorgabe AUS (braucht {modul} aus [{extra}])", not an,
            f"steht auf True — `pip install tinysesam` ohne [{extra}] stürzt beim Router-Bau ab")

# Die Kern-Abhängigkeiten sind das, was `pip install tinysesam` wirklich mitbringt.
# Was per Vorgabe an ist, darf nur daraus schöpfen.
# Gelesen wird `pyproject.toml` — die Datei, aus der das Paket gebaut wird.
#
# Zwischendurch lief das über `importlib.metadata.requires()`, mit dem Argument „misst näher am
# Gegenstand: was nach `pip install tinysesam` wirklich da ist". Das stimmte und war trotzdem
# falsch: Die Metadaten einer `pip install -e .`-Installation werden EINMAL geschrieben. Im
# CI-Abbild liegt eine solche Installation, der Arbeitsstand wird daneben gemountet — der Test
# maß also den Stand von vorgestern und meldete ein Extra als fehlend, das seit einer Stunde
# im pyproject steht. Für die Frage „was verspricht das Paket" ist die Quelldatei richtig.
#
# (Von Hand gelesen statt mit `tomllib` geparst: das war noetig, solange 3.10 zugesagt war
# — dort gibt es `tomllib` noch nicht. Seit der Untergrenze 3.12 (2026-09-22) waere es
# moeglich; fuer zwei Listen lohnt der Umbau aber nicht, und ohne Parser bleibt der Test
# auch in einem Klon lauffaehig, den jemand mit einem aelteren Interpreter oeffnet.)
import re as _re  # noqa: E402

_roh = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _liste(name: str, quelle: str = "") -> list:
    """Den Inhalt einer `name = [...]`-Zuweisung als Liste von Zeichenketten."""
    treffer = _re.search(rf"^{_re.escape(name)}\s*=\s*\[(.*?)\]", quelle or _roh, _re.S | _re.M)
    return _re.findall(r'"([^"]+)"', treffer.group(1)) if treffer else []


anforderungen = _liste("dependencies")
r.check("die Kern-Abhängigkeiten sind überhaupt ablesbar", bool(anforderungen),
        "pyproject.toml lieferte keine `dependencies`-Liste — dann prüft der Rest nichts")

_extras_block = _roh[_roh.index("[project.optional-dependencies]"):]
_extras_block = _extras_block[:_extras_block.index("\n[", 1)]

# `dependencies` ist per Definition der Kern — Extras stehen in einem eigenen Abschnitt.
kern = {_d.split(";")[0].split(">")[0].split("=")[0].split("[")[0].strip().lower()
        for _d in anforderungen}
r.check("fastapi gehört zum Kern", "fastapi" in kern)
r.check("webauthn gehört NICHT zum Kern (sonst wäre der Schalter oben harmlos)",
        "webauthn" not in kern)

# Ein aktivierter Schalter ohne sein Extra muss eine LESBARE Meldung geben, keinen
# ModuleNotFoundError aus dem Innern der Bibliothek.
# Gemessen wird das VERHALTEN, nicht ob zwei Wörter in der Quelldatei stehen. Die frühere
# Fassung prüfte `"tinysesam[passkey]" in router_py` — wer den Schutz entfernt und die Wörter
# als Kommentar stehen lässt, kam damit durch, während der echte Aufruf einen nackten
# ModuleNotFoundError wirft.
import importlib  # noqa: E402


class _Blockiert:
    def __init__(self, name):
        self.name = name

    def find_spec(self, fullname, pfad=None, ziel=None):
        if fullname == self.name or fullname.startswith(self.name + "."):
            raise ModuleNotFoundError(f"No module named '{fullname}'", name=fullname)
        return None


def _ohne(name, fn):
    blocker = _Blockiert(name)
    sys.meta_path.insert(0, blocker)
    weg = {n: m for n, m in list(sys.modules.items()) if n == name or n.startswith(name + ".")}
    for n in weg:
        del sys.modules[n]
    try:
        return fn()
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(weg)
        importlib.invalidate_caches()


import tempfile  # noqa: E402

from tinysesam import MissingExtra, TinySesam  # noqa: E402


def _mit_passkey():
    # Der Router-Bau ist die Stelle, an der die Passkey-Routen entstehen — dort fällt das
    # fehlende Extra auf. Der Konstruktor warnt nur (ein Client liesse sich ersetzen).
    pfad = str(Path(tempfile.mkdtemp()) / "t.db")
    auth = TinySesam(TinySesamConfig(db_path=pfad, cookie_secure=False, passkey_enabled=True))
    return auth.router()


try:
    _ohne("webauthn", _mit_passkey)
    fehler = None
except Exception as e:
    fehler = e
r.check("passkey ohne Extra meldet sich verständlich statt mit ModuleNotFoundError",
        isinstance(fehler, MissingExtra),
        f"{type(fehler).__name__}: {str(fehler)[:70]}")
r.check("...und nennt das Extra maschinenlesbar", getattr(fehler, "extra", None) == "passkey",
        f"extra={getattr(fehler, 'extra', None)!r}")

# Und der Runner darf „übersprungen" nicht mehr raten.
runner = (ROOT / "tests" / "run_all.py").read_text(encoding="utf-8")
r.check("run_all wertet nur den vereinbarten Exit-Code als übersprungen",
        "SKIP_EXIT = 77" in runner and "r.returncode == SKIP_EXIT" in runner)
r.check("run_all rät nicht mehr am stderr herum",
        'ModuleNotFoundError" in r.stderr' not in runner,
        "die alte Heuristik ist zurück — sie kann 'Test braucht Extra' nicht von "
        "'Bibliothek stürzt ab' unterscheiden")


# ── Das Gateway startete nach der eigenen Anleitung nicht ────────────────────
# Die README nannte `pip install 'tinysesam[oidc]'` und `python -m tinysesam.gateway` in einem
# Atemzug. `[oidc]` bringt aber keinen ASGI-Server mit: Der Startbefehl endete in einem
# ModuleNotFoundError für uvicorn, was wie ein Defekt aussah statt wie eine fehlende Zeile im
# Install-Befehl. Das Docker-Abbild lief, weil es `uvicorn` von Hand danebeninstallierte — der
# Flicken verdeckte die Lücke im Extra.
gateway_extra = _liste("gateway", _extras_block)
r.check("es gibt ein Extra [gateway]", bool(gateway_extra),
        "nur [oidc] — dann startet die dokumentierte Zeile nicht")
r.check("und es enthält einen ASGI-Server",
        any("uvicorn" in d for d in gateway_extra), f"{gateway_extra}")

# Die Anleitung muss auf dieses Extra zeigen, nicht mehr auf [oidc]. Gesucht wird der
# Gateway-Abschnitt selbst (die Überschrift mit „gateway"/„Gateway"), nicht eine Formulierung —
# der deutsche und der englische Text sind verschieden gebaut.
import re as _re2  # noqa: E402

for datei in ("README.md", "i18n/README.de.md"):
    text = (ROOT / datei).read_text(encoding="utf-8")
    abschnitte = _re2.split(r"^## ", text, flags=_re2.M)
    passend = [a for a in abschnitte if _re2.search(r"[Gg]ateway", a.splitlines()[0] if a else "")]
    r.check(f"{datei} hat einen Gateway-Abschnitt", bool(passend),
            "nicht gefunden — dann prüft der Test darunter nichts")
    zusammen = "\n".join(passend)
    r.check(f"{datei} nennt fürs Gateway das Extra [gateway]",
            "tinysesam[gateway]" in zusammen, "verweist weiter auf [oidc]")
    r.check(f"{datei} nennt dort NICHT mehr [oidc] als Installationsweg",
            "pip install 'tinysesam[oidc]'" not in zusammen,
            "die alte, nicht startfähige Zeile steht noch da")

# `--help` ist eine Frage, kein Startbefehl: vorher lief der Server auf 0.0.0.0:8000.
import subprocess  # noqa: E402

lauf = subprocess.run([sys.executable, "-m", "tinysesam.gateway", "--help"],
                      cwd=ROOT, capture_output=True, text=True, timeout=30)
r.check("`python -m tinysesam.gateway --help` beendet sich mit 0", lauf.returncode == 0,
        f"Exit {lauf.returncode}: {(lauf.stderr or lauf.stdout)[:100]}")
r.check("...und gibt eine Hilfe aus, statt einen Server zu starten",
        "TINYSESAM_OIDC_ISSUER" in lauf.stdout and "0.0.0.0" not in lauf.stdout.split("Bindeadresse")[0],
        f"Ausgabe: {lauf.stdout[:120]!r}")

fehl = subprocess.run([sys.executable, "-m", "tinysesam.gateway", "--quatsch"],
                      cwd=ROOT, capture_output=True, text=True, timeout=30)
r.check("ein unbekanntes Argument endet mit 2, nicht mit einem laufenden Server",
        fehl.returncode == 2, f"Exit {fehl.returncode}")

sys.exit(r.done())

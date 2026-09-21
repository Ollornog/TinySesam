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

# Welcher Vorgabe-Schalter zieht welches Extra nach sich. Steht einer davon per Vorgabe auf True,
# ist der Kern-Install kaputt — unabhängig davon, was gerade installiert ist.
SCHALTER_BRAUCHT_EXTRA = {
    "passkey_enabled": ("webauthn", "passkey"),
    "oidc_enabled": ("authlib", "oidc"),
    "saml_enabled": ("onelogin", "saml"),
    "ldap_enabled": ("ldap3", "ldap"),
}

vorgabe = TinySesamConfig(db_path=":memory:")

for schalter, (modul, extra) in sorted(SCHALTER_BRAUCHT_EXTRA.items()):
    an = bool(getattr(vorgabe, schalter, False))
    r.check(f"{schalter} ist per Vorgabe AUS (braucht {modul} aus [{extra}])", not an,
            f"steht auf True — `pip install tinysesam` ohne [{extra}] stürzt beim Router-Bau ab")

# Die Kern-Abhängigkeiten sind das, was `pip install tinysesam` wirklich mitbringt.
# Was per Vorgabe an ist, darf nur daraus schöpfen.
# Über die Paket-Metadaten, nicht über pyproject.toml: Das misst, was beim Nutzer nach
# `pip install tinysesam` tatsächlich landet — und es läuft auf jeder unterstützten Version.
# (`tomllib` gibt es erst ab 3.11; der Test starb auf 3.10 mit ModuleNotFoundError, und weil
# ci-local nur EINE Version fährt, fiel das erst in der GitHub-Matrix auf.)
from importlib.metadata import PackageNotFoundError, requires  # noqa: E402

try:
    anforderungen = requires("tinysesam") or []
except PackageNotFoundError:                     # aus dem Quellbaum importiert, nicht installiert
    import re as _re
    roh = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = _re.search(r"^dependencies\s*=\s*\[(.*?)\]", roh, _re.S | _re.M)
    anforderungen = _re.findall(r'"([^"]+)"', block.group(1)) if block else []
    r.check("die Kern-Abhängigkeiten sind überhaupt ablesbar", bool(anforderungen),
            "weder Paket-Metadaten noch pyproject lieferten eine Liste")

# Was hinter einem Extra hängt, gehört nicht zum Kern.
kern = {_d.split(";")[0].split(">")[0].split("=")[0].split("[")[0].strip().lower()
        for _d in anforderungen if "extra ==" not in _d}
r.check("fastapi gehört zum Kern", "fastapi" in kern)
r.check("webauthn gehört NICHT zum Kern (sonst wäre der Schalter oben harmlos)",
        "webauthn" not in kern)

# Ein aktivierter Schalter ohne sein Extra muss eine LESBARE Meldung geben, keinen
# ModuleNotFoundError aus dem Innern der Bibliothek.
router_py = (ROOT / "tinysesam" / "router.py").read_text(encoding="utf-8")
r.check("passkey ohne Extra meldet sich verständlich statt mit ModuleNotFoundError",
        "tinysesam[passkey]" in router_py and "ModuleNotFoundError" in router_py,
        "router.py fängt den Importfehler nicht ab")

# Und der Runner darf „übersprungen" nicht mehr raten.
runner = (ROOT / "tests" / "run_all.py").read_text(encoding="utf-8")
r.check("run_all wertet nur den vereinbarten Exit-Code als übersprungen",
        "SKIP_EXIT = 77" in runner and "r.returncode == SKIP_EXIT" in runner)
r.check("run_all rät nicht mehr am stderr herum",
        'ModuleNotFoundError" in r.stderr' not in runner,
        "die alte Heuristik ist zurück — sie kann 'Test braucht Extra' nicht von "
        "'Bibliothek stürzt ab' unterscheiden")

sys.exit(r.done())

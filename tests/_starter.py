"""Startet EINE Suite für den Sammellauf — mit billigen Hash-Parametern, nur in diesem Prozess.

    python tests/_starter.py tests/test_core.py     # so ruft `tests/run_all.py` jede Suite

WARUM: Ein Passwort-Hash kostet mit den Produktionswerten gemessen ~110 ms (scrypt, der Fallback
ohne `[argon2]`) bzw. ~26–35 ms (argon2). Das ist Absicht — im Betrieb. Im Testlauf rechnet jede
Suite Dutzende davon, und keiner prüft etwas, das nicht auch ein billiger Hash prüfen würde:
Format, Verfahren, richtige/falsche Eingabe und alle Wege drumherum bleiben dieselben. Gemessen
vor dieser Datei (0.22.0): im schmalen Lauf (ohne Extras) gingen **rund zwei Drittel** der
Suitenlaufzeit in scrypt, im vollen Lauf ein Viertel bis die Hälfte in argon2.

WAS NICHT: Das Paket bekommt dafür KEINEN Schalter. `tinysesam.passwords` liest weder eine
Umgebungsvariable noch eine Einstellung für seine Parameter — ein solcher Schalter wäre ein Weg,
eine Produktion mit geschwächten Hashes zu betreiben, und er hinge an jedem Container, der die
Variable erbt. Abgesenkt wird HIER, im Testprozess, per Monkeypatch; der Wächter
`tests/test_testlauf.py` hält beides fest. Wer eine Suite direkt startet (`python tests/test_x.py`),
rechnet mit den Produktionswerten, ebenso jeder Unterprozess, den eine Suite startet.

AUSNAHMEN (`PRODUKTIONSWERTE`): Suiten, die die Parameter oder die Laufzeit des Hashens SELBST
prüfen, laufen mit den echten Werten — mit abgesenkten wären ihre Prüfungen leer (ein Dummy-Verify,
der nichts kostet, ist von „kein Dummy-Verify" nicht zu unterscheiden). Welche Suite dazugehört,
entscheidet ein Wächter in `tests/test_testlauf.py` aus dem Quelltext der Suiten, nicht das
Gedächtnis.

Abgesenkt wird erst, wenn die Suite `tinysesam.passwords` selbst importiert (Import-Haken). Ein
Vorab-Import von hier aus würde die Import-Reihenfolge der Suite ändern — und einige Suiten
blenden vor dem ersten Import gezielt Module aus, um „ohne Extra" nachzustellen.
"""
from __future__ import annotations

import os
import runpy
import sys

#: Suite → Grund. Diese Suiten rechnen mit den Produktionswerten.
PRODUKTIONSWERTE = {
    "test_bestandsdaten.py": "prüft die scrypt-Parameter selbst (Altformat 0.17.0, needs_rehash)",
    "test_hardening2.py": "misst, dass der Dummy-Verify so lange rechnet wie ein echter Verify",
}

#: scrypt im Testlauf: N=2^4 statt 2^15, p=1 statt 3 (r bleibt). Formate und Wege bleiben gleich,
#: nur die Arbeit fällt weg (gemessen ~0,03 ms statt ~110 ms).
SCRYPT_TEST = {"n": 2 ** 4, "r": 8, "p": 1}
#: argon2 im Testlauf: das kleinste, was argon2 zulässt (m = 8 KiB bei p = 1), eine Runde.
ARGON2_TEST = {"time_cost": 1, "memory_cost": 8, "parallelism": 1}

MODUL = "tinysesam.passwords"


def absenken(passwords) -> None:
    """Die Parameter eines frisch geladenen `tinysesam.passwords` absenken — im Prozess."""
    passwords._SCRYPT = {**passwords._SCRYPT, **SCRYPT_TEST}
    if passwords._ARGON:
        passwords._PH = passwords.PasswordHasher(**ARGON2_TEST)
    # Der Dummy für den Timing-Ausgleich entstand beim Import mit den Produktionswerten. Mit dem
    # aktiven Verfahren neu erzeugen, sonst kostete jeder Dummy-Verify weiter die volle Zeit.
    passwords._DUMMY = passwords.hash_password("tinysesam-timing-dummy")


class _NachDemLaden:
    """Import-Haken: lädt `tinysesam.passwords` wie gewohnt und senkt danach ab."""

    def find_spec(self, name, pfad=None, ziel=None):
        if name != MODUL:
            return None
        sys.meta_path.remove(self)                 # einmal genügt; sonst fände er sich selbst
        for finder in sys.meta_path:
            spec = finder.find_spec(name, pfad, ziel) if hasattr(finder, "find_spec") else None
            if spec is not None and spec.loader is not None:
                laden = spec.loader.exec_module

                def exec_module(modul, _laden=laden):
                    _laden(modul)
                    absenken(modul)
                spec.loader.exec_module = exec_module
                return spec
        return None


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("Aufruf: python tests/_starter.py <suite.py> [argumente …]")
    suite = os.path.abspath(argv[0])
    # Wie ein direkter Start: sys.argv[0] ist die Suite, ihr Verzeichnis steht vorn im Pfad.
    sys.argv = [suite, *argv[1:]]
    sys.path[0] = os.path.dirname(suite)
    if os.path.basename(suite) not in PRODUKTIONSWERTE:
        if MODUL in sys.modules:                   # pragma: no cover — hier importiert niemand
            absenken(sys.modules[MODUL])
        else:
            sys.meta_path.insert(0, _NachDemLaden())
    runpy.run_path(suite, run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])

"""Weicht die gevendorte Testbasis vom Manifest ab?

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.

WARUM SIE SEIT 2026-09-22 IM KIT LIEGT: Die Prüfung gab es nur als `repokit check`,
also als Kommando auf dem Tower. Verdrahtet war sie in genau EINEM Repo, dort hinter
`command -v repokit` — und das Runner-Abbild kennt kein repokit, also fiel sie dort
immer in den skip-Zweig. Ein Test, der nie läuft, ist kein Test: gemessene Folge war,
dass derselbe Backlog-Fehler zweimal behoben wurde, das zweite Mal von Hand in der
gevendorten Kopie eines öffentlichen Repos, direkt auf `main`. Genau davor soll das
Manifest warnen.

Als stdlib-only Modul im Kit läuft die Prüfung überall mit der Suite — auch auf
`ubuntu-latest`, wo es weder repokit noch den Quellbaum gibt — und ist damit von den
Required Checks gedeckt. `repokit check` lädt dieselbe Datei; es gibt nur diese eine
Fassung, Drift zwischen Werkzeug und Kit ist so nicht möglich.

Das Manifest bleibt ein Stolperdraht, kein Schloss: wer die Kit-Dateien ändert, kann
`MANIFEST.sha256` im selben Commit neu schreiben. Er tut es dann wenigstens sichtbar.
"""
from __future__ import annotations

import hashlib
import os

# Stufe 3 (M-1): Fallzahl je Prüfung. Einzeln per Pfad geladen (so lädt `repokit` selbst
# `manifest.py`) gibt es kein Paket und damit keine Zählung — dann bleibt alles wie vorher.
try:
    from .hygiene import mit_fallzahl, zaehle_fall
except ImportError:  # pragma: no cover — nur beim Laden ohne Paket
    def mit_fallzahl(name, fn):
        return fn

    def zaehle_fall(n=1):
        return None

# Pfade relativ zur Repo-Wurzel — beide schreibt `repokit sync`.
MANIFEST = "tests/_kit/MANIFEST.sha256"
KIT_VERSION = "tests/_kit/KIT_VERSION"


def sha256(pfad: str) -> str:
    h = hashlib.sha256()
    with open(pfad, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def pruefe(root: str) -> list[str]:
    """Liste der Abweichungen; leer heißt „die Kopie ist unverändert".

    Wie jede Kit-Prüfung wirft sie nicht, sondern gibt Verstöße zurück — passt damit
    in `assert not …` genauso wie in ein sammelndes `r.check(…)`.
    """
    pfad = os.path.join(root, MANIFEST)
    if not os.path.exists(pfad):
        # Nicht gesynct ist kein Erfolg. Ein leeres Ergebnis hieße hier „alles gut",
        # obwohl gar nichts geprüft wurde.
        return ["MANIFEST.sha256 fehlt — nie gesynct?"]
    abweichungen: list[str] = []
    with open(pfad, encoding="utf-8") as fh:
        for nr, zeile in enumerate(fh, 1):
            zeile = zeile.strip()
            if not zeile or zeile.startswith("#"):
                continue
            if "  " not in zeile:
                # Eine kaputte Zeile darf nicht stillschweigend durchrutschen: sonst
                # nähme ein Tippfehler im Manifest genau die Datei aus der Prüfung,
                # um die es geht (2026-09-22).
                abweichungen.append(f"MANIFEST.sha256 Zeile {nr}: unlesbar")
                continue
            erwartet, rel = zeile.split("  ", 1)
            zaehle_fall()
            voll = os.path.join(root, rel)
            if not os.path.exists(voll):
                abweichungen.append(f"{rel}: fehlt")
            elif sha256(voll) != erwartet:
                abweichungen.append(f"{rel}: geändert")
    return abweichungen


def version(root: str) -> str | None:
    """Welchen Kit-Stand trägt das Repo? `None`, wenn nie gesynct wurde."""
    pfad = os.path.join(root, KIT_VERSION)
    if not os.path.exists(pfad):
        return None
    with open(pfad, encoding="utf-8") as fh:
        return fh.read().strip() or None


# Jede Prüfung dieses Moduls zählt ihre Fälle (M-1, Stufe 3) — Auswertung: hygiene.pruefe_etwas_gesehen.
pruefe = mit_fallzahl("manifest.pruefe", pruefe)

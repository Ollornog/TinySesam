#!/usr/bin/env python3
"""Wheel und sdist bit-reproduzierbar umschreiben — der Release-Workflow ruft das nach `python -m build`.

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 scripts/_artefakte_normalisieren.py dist/*.whl dist/*.tar.gz

sdist: setuptools übernimmt die Datei-Zeitstempel des Arbeitsbaums (bei einem frischen Checkout
also die Uhrzeit des Klonens) und schreibt die aktuelle Zeit in den gzip-Kopf. Zwei Bauläufe
desselben Commits ergaben damit zwei verschiedene Prüfsummen — und die veröffentlichte Prüfsumme
liess sich von niemandem nachstellen. Hier wird das Archiv mit festen Werten neu geschrieben:
sortierte Einträge, Zeitstempel = `SOURCE_DATE_EPOCH`, Eigentümer 0 ohne Namen, Rechte 0644/0755.

Wheel: Die Zeitstempel richtet `SOURCE_DATE_EPOCH` schon, die Dateirechte nicht — setuptools
schreibt die Rechte des Checkouts in jeden Zip-Eintrag, und die hängen von der umask ab. Ein
Nachbau auf Ubuntu/Mint (Benutzer-umask 0002, also 0664) ergab eine andere Prüfsumme als der
Runner (0022, also 0644), bei identischem Inhalt (A-3 der Nachprüfung). Deshalb auch hier 0644/0755.

Der Inhalt jeder Datei bleibt Byte für Byte, wie setuptools ihn geschrieben hat — im Wheel stimmt
`RECORD` damit weiter. stdlib-only, damit der Release-Job nichts dafür installieren muss.
"""
from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile
import zipfile


def _rechte(modus: int) -> int:
    return 0o755 if modus & 0o111 else 0o644


def sdist_normalisieren(pfad: str, epoch: int) -> None:
    """Schreibt das sdist unter `pfad` deterministisch neu (siehe Moduldoku)."""
    with tarfile.open(pfad, "r:gz") as alt:
        eintraege = []
        for m in alt.getmembers():
            fh = alt.extractfile(m) if m.isfile() else None
            daten = fh.read() if fh is not None else None
            eintraege.append((m, daten))
    puffer = io.BytesIO()
    with tarfile.open(fileobj=puffer, mode="w", format=tarfile.PAX_FORMAT) as neu:
        for m, daten in sorted(eintraege, key=lambda e: e[0].name):
            m.mtime = epoch
            m.uid = m.gid = 0
            m.uname = m.gname = ""
            m.pax_headers = {}
            m.mode = 0o755 if m.isdir() else _rechte(m.mode)
            neu.addfile(m, io.BytesIO(daten) if daten is not None else None)
    # gzip schreibt sonst die aktuelle Zeit und den Dateinamen in den Kopf.
    with open(pfad, "wb") as ziel:
        with gzip.GzipFile(filename="", mode="wb", fileobj=ziel, mtime=epoch, compresslevel=9) as gz:
            gz.write(puffer.getvalue())


def wheel_normalisieren(pfad: str) -> None:
    """Schreibt das Wheel unter `pfad` mit festen Dateirechten neu (siehe Moduldoku).

    Reihenfolge und Zeitstempel der Einträge bleiben, wie setuptools sie gesetzt hat (RECORD
    zuletzt, wie PEP 427 empfiehlt); die Zeitstempel sind mit `SOURCE_DATE_EPOCH` bereits fest.
    """
    with zipfile.ZipFile(pfad) as alt:
        eintraege = [(i, alt.read(i)) for i in alt.infolist()]
    puffer = io.BytesIO()
    with zipfile.ZipFile(puffer, "w") as neu:
        for alt_info, daten in eintraege:
            info = zipfile.ZipInfo(alt_info.filename, date_time=alt_info.date_time)
            info.compress_type = alt_info.compress_type
            info.create_system = 3                      # Unix — sonst gelten die Rechte nicht
            ist_dir = alt_info.filename.endswith("/")
            modus = 0o755 if ist_dir else _rechte(alt_info.external_attr >> 16)
            info.external_attr = ((0o040000 if ist_dir else 0o100000) | modus) << 16
            neu.writestr(info, daten)
    with open(pfad, "wb") as ziel:
        ziel.write(puffer.getvalue())


def main(argv: list[str]) -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not argv or not epoch:
        # Ohne feste Zeit gibt es nichts, worauf sich zwei Bauläufe einigen könnten.
        print(__doc__, file=sys.stderr)
        return 2
    for pfad in argv:
        if pfad.endswith(".whl"):
            wheel_normalisieren(pfad)
        elif pfad.endswith(".tar.gz"):
            sdist_normalisieren(pfad, int(epoch))
        else:
            print(f"weder Wheel noch sdist: {pfad}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Ein sdist bit-reproduzierbar umschreiben — der Release-Workflow ruft das nach `python -m build`.

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 scripts/_sdist_normalisieren.py dist/*.tar.gz

Das Wheel ist mit `SOURCE_DATE_EPOCH` bit-reproduzierbar, das sdist nicht: setuptools übernimmt
die Datei-Zeitstempel des Arbeitsbaums (bei einem frischen Checkout also die Uhrzeit des Klonens)
und schreibt die aktuelle Zeit in den gzip-Kopf. Zwei Bauläufe desselben Commits ergaben damit
zwei verschiedene Prüfsummen — und die veröffentlichte Prüfsumme liess sich von niemandem
nachstellen. Hier wird das Archiv mit festen Werten neu geschrieben: sortierte Einträge,
Zeitstempel = `SOURCE_DATE_EPOCH`, Eigentümer 0 ohne Namen, Rechte 0644/0755. Der Inhalt jeder
Datei bleibt Byte für Byte, wie setuptools ihn geschrieben hat.

stdlib-only, damit der Release-Job nichts dafür installieren muss.
"""
from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile


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
            if m.isdir():
                m.mode = 0o755
            else:
                m.mode = 0o755 if m.mode & 0o111 else 0o644
            neu.addfile(m, io.BytesIO(daten) if daten is not None else None)
    # gzip schreibt sonst die aktuelle Zeit und den Dateinamen in den Kopf.
    with open(pfad, "wb") as ziel:
        with gzip.GzipFile(filename="", mode="wb", fileobj=ziel, mtime=epoch, compresslevel=9) as gz:
            gz.write(puffer.getvalue())


def main(argv: list[str]) -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not argv or not epoch:
        # Ohne feste Zeit gibt es nichts, worauf sich zwei Bauläufe einigen könnten.
        print(__doc__, file=sys.stderr)
        return 2
    for pfad in argv:
        sdist_normalisieren(pfad, int(epoch))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

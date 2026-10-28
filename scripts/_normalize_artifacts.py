#!/usr/bin/env python3
"""Rewrite wheel and sdist bit-reproducibly — the release workflow calls this after `python -m build`.

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 scripts/_normalize_artifacts.py dist/*.whl dist/*.tar.gz

sdist: setuptools takes over the file timestamps of the working tree (in a fresh checkout that
is the time of cloning) and writes the current time into the gzip header. Two builds of the
same commit thus produced two different checksums — and nobody could reproduce the published
checksum. Here the archive is rewritten with fixed values: sorted entries, timestamp =
`SOURCE_DATE_EPOCH`, owner 0 without a name, permissions 0644/0755.

Wheel: `SOURCE_DATE_EPOCH` already fixes the timestamps, but not the file permissions —
setuptools writes the permissions of the checkout into every zip entry, and these depend on the
umask. A rebuild on Ubuntu/Mint (user umask 0002, i.e. 0664) produced a different checksum than
the runner (0022, i.e. 0644), with identical content (A-3 of the re-verification). Hence 0644/0755
here as well.

The content of every file stays byte for byte as setuptools wrote it — in the wheel `RECORD`
therefore still matches. stdlib-only, so the release job does not have to install anything for it.
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
    """Rewrite the sdist at `pfad` deterministically (see module docstring)."""
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
    # Otherwise gzip writes the current time and the file name into the header.
    with open(pfad, "wb") as ziel:
        with gzip.GzipFile(filename="", mode="wb", fileobj=ziel, mtime=epoch, compresslevel=9) as gz:
            gz.write(puffer.getvalue())


def wheel_normalisieren(pfad: str) -> None:
    """Rewrite the wheel at `pfad` with fixed file permissions (see module docstring).

    Order and timestamps of the entries stay as setuptools set them (RECORD last, as PEP 427
    recommends); the timestamps are already fixed by `SOURCE_DATE_EPOCH`.
    """
    with zipfile.ZipFile(pfad) as alt:
        eintraege = [(i, alt.read(i)) for i in alt.infolist()]
    puffer = io.BytesIO()
    with zipfile.ZipFile(puffer, "w") as neu:
        for alt_info, daten in eintraege:
            info = zipfile.ZipInfo(alt_info.filename, date_time=alt_info.date_time)
            info.compress_type = alt_info.compress_type
            info.create_system = 3                      # Unix — otherwise the permissions do not apply
            ist_dir = alt_info.filename.endswith("/")
            modus = 0o755 if ist_dir else _rechte(alt_info.external_attr >> 16)
            info.external_attr = ((0o040000 if ist_dir else 0o100000) | modus) << 16
            neu.writestr(info, daten)
    with open(pfad, "wb") as ziel:
        ziel.write(puffer.getvalue())


def main(argv: list[str]) -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not argv or not epoch:
        # Without a fixed time there is nothing two builds could agree on.
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

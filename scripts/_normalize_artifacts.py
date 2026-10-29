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


def _permissions(mode: int) -> int:
    return 0o755 if mode & 0o111 else 0o644


def normalize_sdist(path: str, epoch: int) -> None:
    """Rewrite the sdist at `path` deterministically (see module docstring)."""
    with tarfile.open(path, "r:gz") as old:
        entries = []
        for m in old.getmembers():
            fh = old.extractfile(m) if m.isfile() else None
            data = fh.read() if fh is not None else None
            entries.append((m, data))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as new:
        for m, data in sorted(entries, key=lambda e: e[0].name):
            m.mtime = epoch
            m.uid = m.gid = 0
            m.uname = m.gname = ""
            m.pax_headers = {}
            m.mode = 0o755 if m.isdir() else _permissions(m.mode)
            new.addfile(m, io.BytesIO(data) if data is not None else None)
    # Otherwise gzip writes the current time and the file name into the header.
    with open(path, "wb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=epoch, compresslevel=9) as gz:
            gz.write(buffer.getvalue())


def normalize_wheel(path: str) -> None:
    """Rewrite the wheel at `path` with fixed file permissions (see module docstring).

    Order and timestamps of the entries stay as setuptools set them (RECORD last, as PEP 427
    recommends); the timestamps are already fixed by `SOURCE_DATE_EPOCH`.
    """
    with zipfile.ZipFile(path) as old:
        entries = [(i, old.read(i)) for i in old.infolist()]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as new:
        for old_info, data in entries:
            info = zipfile.ZipInfo(old_info.filename, date_time=old_info.date_time)
            info.compress_type = old_info.compress_type
            info.create_system = 3                      # Unix — otherwise the permissions do not apply
            is_dir = old_info.filename.endswith("/")
            mode = 0o755 if is_dir else _permissions(old_info.external_attr >> 16)
            info.external_attr = ((0o040000 if is_dir else 0o100000) | mode) << 16
            new.writestr(info, data)
    with open(path, "wb") as destination:
        destination.write(buffer.getvalue())


def main(argv: list[str]) -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not argv or not epoch:
        # Without a fixed time there is nothing two builds could agree on.
        print(__doc__, file=sys.stderr)
        return 2
    for path in argv:
        if path.endswith(".whl"):
            normalize_wheel(path)
        elif path.endswith(".tar.gz"):
            normalize_sdist(path, int(epoch))
        else:
            print(f"neither wheel nor sdist: {path}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

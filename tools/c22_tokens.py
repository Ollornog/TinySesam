#!/usr/bin/env python3
"""Refresh tests/fixtures/c22_tokens.txt — the pinned list of C22 token names the adapter may read.

    tools/c22_tokens.py <C22 checkout> [--out tests/fixtures/c22_tokens.txt] [--commit <sha>]

The C22 checkout must have its pack stylesheets built (`scripts/build-gallery.sh` in C22, which
writes c22/static/css/c22-<pack>.css). The list holds every custom property that ALL packs define
on `:root`/`.dark` — a token only some packs know would leave the others on TinySesam's fallback.
The header names the C22 commit, so a reader knows which state the list describes.

Nothing in TinySesam's runtime or CI reads the C22 repository; only this list is versioned.
"""
import argparse
import glob
import os
import re
import subprocess
import sys

_BLOCK = re.compile(r"([^{}]+)\{([^{}]*)\}")
_ROOT_SELECTOR = re.compile(r"(:root|:host|\.dark)(\s*,\s*(:root|:host|\.dark))*")
_PROPERTY = re.compile(r"(?:^|;)\s*(--[A-Za-z0-9_-]+)\s*:")


def tokens_of(css: str) -> set:
    """Custom properties defined in the innermost `:root`/`:host`/`.dark` rules of a stylesheet."""
    found = set()
    for block in _BLOCK.finditer(css):
        if _ROOT_SELECTOR.fullmatch(block.group(1).strip()):
            found |= set(_PROPERTY.findall(block.group(2)))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("c22", help="path of a C22 checkout with built pack stylesheets")
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures",
                                                      "c22_tokens.txt"))
    parser.add_argument("--commit", help="C22 commit to name in the header (for an export without .git)")
    args = parser.parse_args()
    packs = sorted(glob.glob(os.path.join(args.c22, "c22", "static", "css", "c22-*.css")))
    if not packs:
        print("no c22/static/css/c22-*.css — build the packs in C22 first (scripts/build-gallery.sh)",
              file=sys.stderr)
        return 1
    sets = []
    for path in packs:
        with open(path, encoding="utf-8") as f:
            sets.append(tokens_of(f.read()))
    common = sorted(set.intersection(*sets))
    sha = args.commit
    try:
        sha = sha or subprocess.run(["git", "-C", args.c22, "rev-parse", "HEAD"], capture_output=True, text=True,
                             check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sha = "unknown (not a git checkout)"
    names = ", ".join(os.path.basename(p)[len("c22-"):-len(".css")] for p in packs)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# C22 token names defined by every pack on :root/.dark — read by tests/test_c22_adapter.py.\n")
        f.write(f"# C22 commit: {sha}\n")
        f.write(f"# Packs: {names}\n")
        f.write("# Refresh: build the packs in a C22 checkout, then tools/c22_tokens.py <checkout>.\n")
        f.writelines(n + "\n" for n in common)
    print(f"{len(common)} tokens from {len(packs)} packs → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

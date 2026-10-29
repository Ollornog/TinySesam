#!/usr/bin/env python3
"""release — do the manual steps before a release and check them. stdlib-only.

    python3 scripts/_release.py 0.17.0          set the version, close the CHANGELOG
    python3 scripts/_release.py --pruefen       check only, change nothing

The version appears in six places (package, module, two READMEs several times, compose example) and
in the CHANGELOG. By hand this has worked so far because a test enforces it — but "works because
a test complains" is not a procedure, it is a loop of error and correction. Milestone 1.0
explicitly requires that a release runs through without manual steps
(`backlog/M-1-api-stable-1-0.md`).

What this script deliberately does NOT do: tag and push. A human presses the button — the same
separation as for rollout (delivery, not deployment). It prepares and says what follows.
"""
from __future__ import annotations

import datetime as dt
import pathlib
import re
import sys

WURZEL = pathlib.Path(__file__).resolve().parent.parent
# Everywhere a version appears. The READMEs name it several times (git ref, wheel URL, image tag,
# verification commands) — so we replace, rather than patch a fixed line number.
DATEIEN = ["pyproject.toml", "tinysesam/__init__.py", "README.md", "i18n/README.de.md",
           "deploy/forward-auth/docker-compose.yml"]
CHANGELOG = WURZEL / "CHANGELOG.md"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def aktuelle_version() -> str:
    text = (WURZEL / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def pruefen() -> int:
    """Does everything match? Returns the number of complaints."""
    version = aktuelle_version()
    fehler = []

    modul = (WURZEL / "tinysesam/__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{version}"' not in modul:
        fehler.append(f"tinysesam/__init__.py does not name {version}")

    for name in DATEIEN[2:]:
        text = (WURZEL / name).read_text(encoding="utf-8")
        # An older version in an example is not a cosmetic flaw: it sends users to a state
        # that this release is just replacing.
        alt = {v for v in re.findall(r"tinysesam[:@/-]v?(\d+\.\d+\.\d+)", text)} - {version}
        if alt:
            fehler.append(f"{name} still refers to {', '.join(sorted(alt))}")

    text = CHANGELOG.read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\] — \d{{4}}-\d{{2}}-\d{{2}}", text, re.M):
        fehler.append(f"CHANGELOG has no closed section [{version}] — <date>")

    for f in fehler:
        print(f"  ✗ {f}")
    if not fehler:
        print(f"  ✓ everything on {version}: package, module, both READMEs, compose example, CHANGELOG")
    return len(fehler)


def ersetze_pins(text: str, alt: str, neu: str) -> tuple[str, int]:
    """Replace the version only where it is a **pin** — not in narrative text.

    Up to 0.20.0 the script replaced every occurrence of the string `alt` in the READMEs. That
    turned "0.19.0 upgraded the database to schema 8" into a false "0.20.0 upgraded …" and
    "up to 0.19.0 you ended up in the same account" into a statement about the new version. A pin
    is recognised by what precedes it: `@v`, `:v`, `/v` (git ref, image tag, release path),
    `tinysesam-` (wheel), `==` (PyPI), and in `pyproject.toml`/`__init__.py` by the assignment."""
    muster = re.compile(r'(?:(?<=@v)|(?<=:v)|(?<=/v)|(?<=tinysesam-)|(?<===)|(?<=version = ")'
                        r'|(?<=__version__ = "))' + re.escape(alt) + r"(?![\d.])")
    return muster.subn(neu, text)


def setzen(neu: str) -> int:
    alt = aktuelle_version()
    if alt == neu:
        print(f"  Version is already {neu} — nothing to do.")
        return 0
    print(f"  {alt} → {neu}")

    for name in DATEIEN:
        p = WURZEL / name
        text, anzahl = ersetze_pins(p.read_text(encoding="utf-8"), alt, neu)
        if anzahl:
            p.write_text(text, encoding="utf-8")
            print(f"    {name}: {anzahl} Stelle(n)")

    text = CHANGELOG.read_text(encoding="utf-8")
    heute = dt.date.today().isoformat()
    # The CHANGELOG is English (since T-29; before, German with "[Unveröffentlicht]") and names the open section
    # "[Unreleased]".
    for offen in ("## [Unreleased]",):
        if offen in text:
            CHANGELOG.write_text(text.replace(offen, f"## [{neu}] — {heute}", 1), encoding="utf-8")
            print(f"    CHANGELOG: {offen[3:]} → [{neu}] — {heute}")
            break
    else:
        print("    CHANGELOG: no [Unreleased] section found — please check by hand")

    print("\n  What is still missing (and a human should decide):")
    print("    1. Summarise at the top of the CHANGELOG section WHO needs this release.")
    print("       For a breaking change, the warning belongs in the first line.")
    print("    2. Run the suite, open the release PR against main, merge it.")
    print(f"    3. Set the tag: git tag -a v{neu} -m \"…\" && git push origin v{neu}")
    print("    4. Then check the artifacts yourself — not the traffic light:")
    print("       gh release view · manifest (both architectures, no latest) ·")
    print("       gh attestation verify")
    return 0


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--pruefen":
        return 1 if pruefen() else 0
    if not SEMVER.match(argv[0]):
        print(f"  '{argv[0]}' is not a version of the form X.Y.Z")
        return 2
    return setzen(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

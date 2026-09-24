#!/usr/bin/env python3
"""release — die Handgriffe vor einem Release erledigen und prüfen. stdlib-only.

    python3 scripts/_release.py 0.17.0          Version setzen, CHANGELOG schliessen
    python3 scripts/_release.py --pruefen       nur prüfen, nichts ändern

Die Version steht an sechs Stellen (Paket, Modul, zwei READMEs mehrfach, Compose-Beispiel) und
im CHANGELOG. Von Hand hat das bisher funktioniert, weil ein Test es erzwingt — aber „funktioniert,
weil ein Test schimpft" ist kein Verfahren, sondern eine Schleife aus Fehler und Korrektur. Der
Meilenstein 1.0 verlangt ausdrücklich, dass ein Release ohne Handgriffe durchläuft
(`backlog/M-1-api-stabil-1-0.md`).

Was dieses Skript BEWUSST NICHT tut: taggen und pushen. Den Knopf drückt ein Mensch — dieselbe
Trennung wie beim Ausrollen (Delivery, nicht Deployment). Es bereitet vor und sagt, was folgt.
"""
from __future__ import annotations

import datetime as dt
import pathlib
import re
import sys

WURZEL = pathlib.Path(__file__).resolve().parent.parent
# Wo überall eine Version steht. Die READMEs nennen sie mehrfach (Git-Ref, Wheel-URL, Abbild-Tag,
# Verifikations-Befehle) — deshalb wird ersetzt, nicht an einer Zeilennummer geschraubt.
DATEIEN = ["pyproject.toml", "tinysesam/__init__.py", "README.md", "i18n/README.de.md",
           "deploy/forward-auth/docker-compose.yml"]
CHANGELOG = WURZEL / "CHANGELOG.md"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def aktuelle_version() -> str:
    text = (WURZEL / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def pruefen() -> int:
    """Stimmt alles überein? Gibt die Zahl der Beanstandungen zurück."""
    version = aktuelle_version()
    fehler = []

    modul = (WURZEL / "tinysesam/__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{version}"' not in modul:
        fehler.append(f"tinysesam/__init__.py nennt nicht {version}")

    for name in DATEIEN[2:]:
        text = (WURZEL / name).read_text(encoding="utf-8")
        # Eine ältere Version in einem Beispiel ist kein Schönheitsfehler: Sie schickt Nutzer auf
        # einen Stand, den dieses Release gerade ersetzt.
        alt = {v for v in re.findall(r"tinysesam[:@/-]v?(\d+\.\d+\.\d+)", text)} - {version}
        if alt:
            fehler.append(f"{name} verweist noch auf {', '.join(sorted(alt))}")

    text = CHANGELOG.read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\] — \d{{4}}-\d{{2}}-\d{{2}}", text, re.M):
        fehler.append(f"CHANGELOG hat keinen abgeschlossenen Abschnitt [{version}] — <Datum>")

    for f in fehler:
        print(f"  ✗ {f}")
    if not fehler:
        print(f"  ✓ alles auf {version}: Paket, Modul, beide READMEs, Compose-Beispiel, CHANGELOG")
    return len(fehler)


def ersetze_pins(text: str, alt: str, neu: str) -> tuple[str, int]:
    """Die Version nur dort ersetzen, wo sie ein **Pin** ist — nicht in erzählendem Text.

    Bis 0.20.0 ersetzte das Skript jede Zeichenkette `alt` in den READMEs. Damit wurde aus
    „0.19.0 hob die Datenbank auf Schema 8“ ein falsches „0.20.0 hob …“ und aus „bis 0.19.0
    landete man im selben Konto“ eine Aussage über die neue Fassung. Ein Pin erkennt man an dem,
    was davor steht: `@v`, `:v`, `/v` (Git-Ref, Abbild-Tag, Release-Pfad), `tinysesam-` (Wheel),
    `==` (PyPI), und in `pyproject.toml`/`__init__.py` an der Zuweisung."""
    muster = re.compile(r'(?:(?<=@v)|(?<=:v)|(?<=/v)|(?<=tinysesam-)|(?<===)|(?<=version = ")'
                        r'|(?<=__version__ = "))' + re.escape(alt) + r"(?![\d.])")
    return muster.subn(neu, text)


def setzen(neu: str) -> int:
    alt = aktuelle_version()
    if alt == neu:
        print(f"  Version ist bereits {neu} — nichts zu tun.")
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
    # Der CHANGELOG ist deutsch und nennt den Abschnitt „[Unveröffentlicht]“; bis 0.20.0 suchte
    # das Skript nur die englische Form und bat bei jedem Release um Handarbeit.
    for offen in ("## [Unveröffentlicht]", "## [Unreleased]"):
        if offen in text:
            CHANGELOG.write_text(text.replace(offen, f"## [{neu}] — {heute}", 1), encoding="utf-8")
            print(f"    CHANGELOG: {offen[3:]} → [{neu}] — {heute}")
            break
    else:
        print("    CHANGELOG: kein [Unveröffentlicht]-Abschnitt gefunden — bitte von Hand nachsehen")

    print("\n  Was noch fehlt (und ein Mensch entscheiden soll):")
    print("    1. Im CHANGELOG-Abschnitt oben zusammenfassen, WER dieses Release braucht.")
    print("       Bei einem Bruch gehört die Warnung in die erste Zeile.")
    print("    2. Suite fahren, Release-PR nach main, mergen.")
    print(f"    3. Tag setzen: git tag -a v{neu} -m \"…\" && git push origin v{neu}")
    print("    4. Danach die Artefakte selbst prüfen — nicht die Ampel:")
    print("       gh release view · Manifest (beide Architekturen, kein latest) ·")
    print("       gh attestation verify")
    return 0


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--pruefen":
        return 1 if pruefen() else 0
    if not SEMVER.match(argv[0]):
        print(f"  '{argv[0]}' ist keine Version der Form X.Y.Z")
        return 2
    return setzen(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

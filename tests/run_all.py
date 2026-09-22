#!/usr/bin/env python3
"""Test-Runner für TinySesam — führt alle (oder ausgewählte) tests/test_*.py aus.

    python tests/run_all.py                # alle Suiten
    python tests/run_all.py test_core.py   # nur bestimmte

Exit-Code 0 = alles grün, 1 = mind. ein Fehlschlag. Kein pytest nötig (Suiten sind
eigenständige assert-Skripte).

Eine Suite, der eine optionale Abhängigkeit fehlt, beendet sich SELBST mit Exit 77
(`tests/_kit/voraussetzung.py`) — dann gilt sie als übersprungen. Jeder andere
Fehlschlag ist ein Fehlschlag. Diese Unterscheidung ist wichtiger, als sie aussieht:
Vorher riet der Runner am stderr, und konnte „der Test braucht ein Extra" nicht von
„die Bibliothek stürzt ohne ein Extra ab" trennen — der zweite Fall blieb dadurch
monatelang unsichtbar.

Jede Suite läuft in einem EIGENEN Wegwerf-Verzeichnis (TMPDIR/HOME/XDG_* zeigen
dorthin, danach wird es gelöscht). So kann kein Zustand aus einem Lauf den nächsten
beeinflussen und keine Suite die andere stören — die Tests sind wiederholbar.
Nachweis: `ci-local --full` fährt die Suite zweimal im selben Baum.
"""
import sys
import os
import glob
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# Exit-Code, mit dem eine Suite SELBST sagt: "mir fehlt eine Voraussetzung, wertet mich nicht".
# 77 ist die Konvention aus automake. Warum ein Code und keine Textsuche im stderr:
#
# Bis 2026-09-21 riet der Runner anhand von `ModuleNotFoundError` + einer Namensliste, ob ein
# Fehlschlag "nur" eine fehlende optionale Abhaengigkeit war. Das kann zwei Faelle nicht
# unterscheiden, die voellig verschieden sind:
#   (a) Die SUITE braucht ein Extra, das nicht da ist  -> ueberspringen ist richtig.
#   (b) Die BIBLIOTHEK stuerzt ab, weil sie ein Extra braucht, das sie nicht haben duerfte
#       -> das ist ein Fehler, und zwar ein schwerer.
# Fall (b) trat real ein: `pip install tinysesam` + Vorgabe-Konfiguration endete mit
# `ModuleNotFoundError: webauthn` (passkey_enabled stand auf True), und der Runner verbuchte
# das als "uebersprungen". Die Suite war gruen, weil sie nicht gemessen hat.
#
# Jetzt ist "uebersprungen" eine ZUSAGE der Suite, kein Ratespiel ueber fremdes stderr.
SKIP_EXIT = 77


def main(argv):
    # --no-browser: der Browser-Test ist der langsamste. Nur für Zwischenläufe, nie vor einem Push.
    skip_browser = "--no-browser" in argv
    argv = [a for a in argv if a != "--no-browser"]
    if argv:
        files = [os.path.join(HERE, a if a.endswith(".py") else f"test_{a}.py") for a in argv]
    else:
        files = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    if skip_browser:
        files = [f for f in files if not f.endswith("test_browser.py")]
    ok, skipped, failed = [], [], []
    for path in files:
        name = os.path.basename(path)
        if not os.path.exists(path):
            print(f"  ??   {name} (nicht gefunden)")
            failed.append(name)
            continue

        # Jede Suite bekommt ein EIGENES Wegwerf-Verzeichnis: TMPDIR, HOME und die
        # XDG-Pfade zeigen dorthin. Damit kann kein Zustand einen zweiten Lauf
        # beeinflussen -- und keine Suite die naechste stoeren. Danach wird es geloescht.
        # (Policy: "Tests sind wiederholbar"; Nachweis: `ci-local --full`.)
        sandbox = tempfile.mkdtemp(prefix=f"tinysesam-{name[:-3]}-")
        env = {
            **os.environ,
            "PYTHONPATH": ROOT,
            "TMPDIR": sandbox, "TMP": sandbox, "TEMP": sandbox,
            "HOME": sandbox,
            "XDG_CACHE_HOME": os.path.join(sandbox, ".cache"),
            "XDG_CONFIG_HOME": os.path.join(sandbox, ".config"),
            "XDG_DATA_HOME": os.path.join(sandbox, ".local", "share"),
        }
        try:
            r = subprocess.run([sys.executable, path], cwd=ROOT, env=env,
                               capture_output=True, text=True)
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
        if r.returncode == 0:
            print(f"  ok   {name}")
            ok.append(name)
        elif r.returncode == SKIP_EXIT:
            # Die Suite hat selbst abgewunken — der Grund steht in ihrer eigenen Ausgabe.
            grund = (r.stdout or r.stderr or "").strip().splitlines()
            print(f"  skip {name}" + (f" ({grund[-1][:70]})" if grund else ""))
            skipped.append(name)
        else:
            print(f"  FAIL {name}")
            sys.stdout.write((r.stdout or "")[-2000:])
            sys.stderr.write((r.stderr or "")[-2000:])
            failed.append(name)
    total = len(files)
    print(f"\n{len(ok)}/{total} grün, {len(skipped)} übersprungen, {len(failed)} fehlgeschlagen")
    if failed:
        return 1

    # Ein Boden gegen „grün, weil nichts gemessen wurde".
    #
    # Bis hierher genügte „nichts fehlgeschlagen" für Exit 0 — auch bei „0 grün, alles
    # übersprungen". Genau so sah der Lauf in einem git-worktree aus: Die Hygiene-Suiten hielten
    # `.git` (dort eine Datei) für „kein Repo", wanden ab, und `scripts/check.sh` druckte
    # darüber „✓ alles grün". Dieselbe Klasse Fehler, gegen die Exit 77 eingeführt wurde, nur
    # eine Ebene höher.
    if not ok:
        print("\nFEHLER: keine einzige Suite ist gelaufen — das ist kein grüner Lauf.",
              file=sys.stderr)
        return 1
    anteil = len(skipped) / total if total else 0
    if anteil > 0.5:
        print(f"\nFEHLER: {len(skipped)} von {total} Suiten übersprungen ({anteil:.0%}). "
              "Ein Lauf, der mehr abwinkt als misst, ist keine Aussage — fehlende Voraussetzungen "
              "nachinstallieren oder die Auswahl einschränken.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

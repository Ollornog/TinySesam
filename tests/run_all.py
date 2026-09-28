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

PARALLEL: Die Suiten laufen gleichzeitig, `CI_TEST_JOBS` (ganze Zahl ≥ 1) legt fest, wie
viele; ohne die Variable die Hälfte der Kerne, mindestens eine. Die Ausgabe jeder Suite wird
gepuffert und in der festen Reihenfolge der Dateinamen ausgegeben — das Protokoll liest sich wie
ein serieller Lauf und ist bei gleichem Ergebnis Zeile für Zeile gleich. `CI_TEST_JOBS=1`
ist der serielle Lauf von früher: eine Suite nach der anderen, in dieser Reihenfolge.
Voraussetzung dafür: Keine Suite schreibt in feste Pfade im Baum oder teilt sich etwas mit einer
anderen (Port, Datei, Datenbank) — jede hat ihr eigenes Wegwerf-Verzeichnis (s. o.).

Gestartet wird jede Suite über `tests/_starter.py`: Der senkt die Hash-Parameter im Testprozess
ab (dort steht, warum und für welche Suiten nicht). Das Paket selbst hat dafür keinen Schalter.
"""
import sys
import os
import glob
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

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

#: Startet jede Suite (senkt die Hash-Parameter im Testprozess ab, s. dort).
STARTER = os.path.join(HERE, "_starter.py")
JOBS_VARIABLE = "CI_TEST_JOBS"

#: Diese Suiten starten bei parallelem Lauf ZUERST — die langsamsten, gemessen 2026-09-27 (0.22.0).
#: Die Liste bestimmt nur, WANN eine Suite anfängt; Ergebnis und Reihenfolge der Ausgabe bleiben
#: gleich. Ohne sie begannen `test_browser.py` (~80 s, fast nur Warten auf Chrome) und
#: `test_vorbuchung_schwebe.py` (10 s, absichtliche Wartezeit) als letzte und legten das Ende des
#: ganzen Laufs fest. Mit einem Job gilt sie nicht — das ist der serielle Lauf von früher. Ein
#: veralteter Eintrag kostet Zeit, nie ein Ergebnis; dass jeder Eintrag noch eine Suite ist, prüft
#: `tests/test_testlauf.py`.
LANGE_ZUERST = ("test_browser.py", "test_ldap.py", "test_vorbuchung_schwebe.py",
                "test_audit_runde2.py", "test_t13_entscheide.py", "test_repo.py",
                "test_admin_konto.py", "test_sicherheit_befunde.py", "test_hardening2.py")



#: So viel vom Ende der Ausgabe einer roten Suite steht im Protokoll — der Zusammenhang.
FAIL_ENDE = 2000


def _fail_ausgabe(aus: str) -> str:
    """Was unter `FAIL <suite>` steht: jede gescheiterte Prüfung (`FEHL …`) ungekürzt, dann das Ende
    der Ausgabe ab einer Zeilengrenze.

    Bis 2026-09-28 stand hier nur das Ende (2000 Zeichen). Eine Suite druckt ihre Prüfungen in der
    Reihenfolge, in der sie laufen — scheiterte eine frühe, stand ihre `FEHL`-Zeile vor dem Ausschnitt
    und fehlte im Protokoll. Gesehen im CI-Job `repeat`: `FAIL test_vorbuchung_schwebe.py`, darunter
    „ufschub“ und 42 ok-Zeilen, aber nicht, WAS rot war. Ein Wackeltest, der sich lokal nicht
    nachstellen lässt, ist ohne diese Zeile nicht aufzuklären.
    """
    ende = aus[-FAIL_ENDE:]
    if len(aus) > FAIL_ENDE and "\n" in ende:
        ende = ende.split("\n", 1)[1]          # nicht mitten im Wort beginnen
    davor = [z for z in aus[: len(aus) - len(ende)].splitlines() if z.lstrip().startswith("FEHL ")]
    kopf = ("  ── gescheiterte Prüfungen oberhalb des Ausschnitts ──\n" + "\n".join(davor) + "\n"
            "  ── Ende der Ausgabe ──\n") if davor else ""
    return kopf + ende

def warnfilter() -> str:
    """`PYTHONWARNINGS`: Ein veralteter TinySesam-Name (Stufe C), gerufen AUS dem Paket selbst, ist
    ein Fehler — in jeder Suite, nicht nur in einer (0.22.0, PO-Entscheid 2026-09-26).

    Seit 0.22.0 heisst die Implementierung der internen Namen `_name`; der alte Name ist ein
    Alias, der warnt. Ruft Code im Paket noch den alten Namen, sähe das niemand: Eine
    `DeprecationWarning` aus einem Bibliotheksmodul zeigt Python ohne Filter gar nicht an. Die
    AST-Suche in `tests/test_api_surface.py` findet `auth.check_password(…)`, aber kein
    `getattr(auth, name)` — dieser Filter findet beides, sobald eine Suite den Weg durchläuft.

    Ein `-W`-Filter vergleicht das Modul WÖRTLICH (kein Präfix), deshalb eine Zeile je Modul; die
    Meldung beginnt mit `TinySesam.` (siehe `tinysesam/_veraltet.py`). Fremde Warnungen, auch
    fremde `DeprecationWarning`s aus tinysesam-Code, bleiben unberührt.
    """
    module = set()
    for wurzel, ordner, dateien in os.walk(os.path.join(ROOT, "tinysesam")):
        ordner[:] = [o for o in ordner if o != "__pycache__"]
        teile = os.path.relpath(wurzel, ROOT).split(os.sep)
        for f in dateien:
            if f.endswith(".py"):
                module.add(".".join(teile if f == "__init__.py" else teile + [f[:-3]]))
    module = sorted(module)
    return ",".join(f"error:TinySesam.:DeprecationWarning:{m}" for m in module)


def umgebung(sandbox: str) -> dict:
    """Die Umgebung einer Suite: eigenes Wegwerf-Verzeichnis, Paket im Pfad, Warnfilter."""
    vorher = os.environ.get("PYTHONWARNINGS", "")
    return {
        **os.environ,
        "PYTHONPATH": ROOT,
        "TMPDIR": sandbox, "TMP": sandbox, "TEMP": sandbox,
        "HOME": sandbox,
        "XDG_CACHE_HOME": os.path.join(sandbox, ".cache"),
        "XDG_CONFIG_HOME": os.path.join(sandbox, ".config"),
        "XDG_DATA_HOME": os.path.join(sandbox, ".local", "share"),
        "PYTHONWARNINGS": ",".join(x for x in (vorher, warnfilter()) if x),
    }


def jobs_bestimmen(roh=None) -> int:
    """Wie viele Suiten gleichzeitig laufen: `CI_TEST_JOBS`, sonst die Hälfte der Kerne.

    Ein Wert, der keine ganze Zahl ≥ 1 ist, ist ein Fehler (`ValueError`) — nicht still die
    Vorgabe: Wer `CI_TEST_JOBS=1` für einen seriellen Lauf setzt und sich vertippt, soll
    das erfahren, statt einen parallelen Lauf für einen seriellen zu halten.
    """
    roh = os.environ.get(JOBS_VARIABLE, "") if roh is None else roh
    if not roh.strip():
        return max(1, (os.cpu_count() or 1) // 2)
    try:
        jobs = int(roh.strip())
    except ValueError:
        jobs = 0
    if jobs < 1:
        raise ValueError(f"{JOBS_VARIABLE}={roh!r} — erwartet eine ganze Zahl ≥ 1")
    return jobs


def startreihenfolge(files, jobs) -> list:
    """Die Indizes von `files` in der Reihenfolge, in der die Suiten starten.

    Ein Job: genau die Reihenfolge der Liste (der serielle Lauf). Mehrere: erst `LANGE_ZUERST`,
    dann der Rest in Listenreihenfolge."""
    if jobs <= 1:
        return list(range(len(files)))
    rang = {name: i for i, name in enumerate(LANGE_ZUERST)}
    return sorted(range(len(files)),
                  key=lambda i: (rang.get(os.path.basename(files[i]), len(rang)), i))


def suite_fahren(path):
    """Eine Suite in ihrem eigenen Wegwerf-Verzeichnis; Ausgabe gepuffert (`CompletedProcess`)."""
    name = os.path.basename(path)
    # Jede Suite bekommt ein EIGENES Wegwerf-Verzeichnis: TMPDIR, HOME und die
    # XDG-Pfade zeigen dorthin. Damit kann kein Zustand einen zweiten Lauf
    # beeinflussen -- und keine Suite die naechste stoeren. Danach wird es geloescht.
    # (Policy: "Tests sind wiederholbar"; Nachweis: `ci-local --full`.)
    sandbox = tempfile.mkdtemp(prefix=f"tinysesam-{name[:-3]}-")
    env = umgebung(sandbox)
    try:
        return subprocess.run([sys.executable, STARTER, path], cwd=ROOT, env=env,
                              capture_output=True, text=True)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


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
    try:
        jobs = jobs_bestimmen()
    except ValueError as fehler:
        print(f"FEHLER: {fehler}", file=sys.stderr)
        return 2
    print(f"▸ Test-Jobs: {jobs}", flush=True)
    ok, skipped, failed = [], [], []
    # Gestartet wird nach `startreihenfolge` (mit einem Job: die Liste, also der serielle Lauf).
    # Ausgegeben wird in der Reihenfolge der Liste, sobald eine Suite UND alle vor ihr fertig
    # sind — nie in der Reihenfolge, in der sie zufällig fertig werden.
    pool = ThreadPoolExecutor(max_workers=jobs)
    try:
        laufend = [None] * len(files)
        for i in startreihenfolge(files, jobs):
            if os.path.exists(files[i]):
                laufend[i] = pool.submit(suite_fahren, files[i])
        for path, zukunft in zip(files, laufend):
            name = os.path.basename(path)
            if zukunft is None:
                print(f"  ??   {name} (nicht gefunden)", flush=True)
                failed.append(name)
                continue
            r = zukunft.result()
            if r.returncode == 0:
                print(f"  ok   {name}", flush=True)
                ok.append(name)
            elif r.returncode == SKIP_EXIT:
                # Die Suite hat selbst abgewunken — der Grund steht in ihrer eigenen Ausgabe.
                grund = (r.stdout or r.stderr or "").strip().splitlines()
                # Nicht kürzen: Die Zeile nennt den Befehl zum Nachinstallieren (`pip install 'tinysesam[…]'`),
                # und eine Kürzung vor der schliessenden Klammer sah aus wie ein Tippfehler im Befehl.
                print(f"  skip {name}" + (f" ({grund[-1]})" if grund else ""), flush=True)
                skipped.append(name)
            else:
                print(f"  FAIL {name}", flush=True)
                sys.stdout.write(_fail_ausgabe(r.stdout or ""))
                sys.stdout.flush()
                sys.stderr.write((r.stderr or "")[-2000:])
                sys.stderr.flush()
                failed.append(name)
    finally:
        # Bei Strg-C keine wartenden Suiten mehr anfangen; laufende zu Ende kommen lassen.
        pool.shutdown(wait=True, cancel_futures=True)
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

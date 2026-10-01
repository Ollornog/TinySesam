"""Der Sammellauf selbst: parallel, aber so aussagekräftig wie seriell — und billige Hashes nur im Test.

Seit dem Testlauf-Umbau (nach 0.22.0) fährt `tests/run_all.py` die Suiten gleichzeitig
(`CI_TEST_JOBS`) und startet jede über `tests/_starter.py`, der die Hash-Parameter im
Testprozess absenkt. Beides spart Zeit — und beides könnte still Aussagekraft kosten. Gemessen wird:

A  eine rote Suite macht den Lauf rot, auch wenn sie parallel läuft, und ihr Grund steht im Log;
B  die Ausgabe folgt der Reihenfolge der Liste, nicht der Reihenfolge, in der Suiten fertig werden —
   zwei Läufe liefern dasselbe Protokoll;
C  „parallel" ist wirklich gleichzeitig, `CI_TEST_JOBS=1` wirklich der alte serielle Lauf;
D  ein unbrauchbarer Wert für `CI_TEST_JOBS` ist ein Fehler, keine stille Vorgabe;
E  der Warnfilter (veraltete Namen aus dem Paket = Fehler) wirkt auch durch den Starter;
F  der Starter senkt nur im Sammellauf ab, lässt die Import-Reihenfolge der Suite in Ruhe, und die
   Suiten, die Hash-Parameter oder -Laufzeiten selbst prüfen, rechnen mit den echten Werten;
G  das PAKET hat keinen Schalter, der Hashes schwächt — keine Umgebungsvariable, keine Einstellung;
H  das Tor (`scripts/check.sh`) baut die Website in ein Wegwerf-Verzeichnis, nicht nach `_site/`.
I  unter `FAIL` steht jede gescheiterte Prüfung, auch wenn die Ausgabe der Suite lang ist;
J  jede Suite hat ihr eigenes Wegwerf-Verzeichnis (TMPDIR, HOME, XDG_*), das danach weg ist.
"""
from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import _starter  # noqa: E402
import run_all  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Sammellauf — parallel, billige Hashes nur im Test")
RUN_ALL = str(ROOT / "tests" / "run_all.py")


def suite(ordner: Path, name: str, rumpf: str) -> str:
    """Eine Attrappen-Suite anlegen (Pfad zurück)."""
    pfad = ordner / name
    pfad.write_text(textwrap.dedent(rumpf), encoding="utf-8")
    return str(pfad)


def sammellauf(pfade, jobs, **umgebung):
    """`run_all.py` mit genau diesen Suiten fahren."""
    env = {**os.environ, **umgebung}
    if jobs is None:
        env.pop(run_all.JOBS_VARIABLE, None)
    else:
        env[run_all.JOBS_VARIABLE] = str(jobs)
    return subprocess.run([sys.executable, RUN_ALL, *pfade], cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=120)


def zeilen(lauf) -> list[str]:
    return [z for z in lauf.stdout.splitlines() if z.strip()]


# ── A + B: rot bleibt rot, Reihenfolge der Liste, gleiches Protokoll ─────────────────────────────
ab = Path(tempfile.mkdtemp(prefix="sammel-ab-"))
ab_suiten = [
    # a braucht am längsten — wird also als letzte fertig und muss trotzdem zuerst im Log stehen.
    suite(ab, "test_a_gruen.py", "import time\ntime.sleep(0.8)\nprint('a fertig')\n"),
    suite(ab, "test_b_rot.py", """\
        import sys
        print("Grund: absichtlich rot (Probe 4711)")
        print("stderr der roten Suite", file=sys.stderr)
        sys.exit(1)
    """),
    suite(ab, "test_c_skip.py", """\
        import sys
        print("uebersprungen: Modul 'xyz' fehlt — pip install 'tinysesam[xyz]'")
        sys.exit(77)
    """),
    suite(ab, "test_d_gruen.py", "print('d fertig')\n"),
]
lauf1 = sammellauf(ab_suiten, 4)
lauf2 = sammellauf(ab_suiten, 4)
z1 = zeilen(lauf1)
r.check("A: eine rote Suite macht den parallelen Lauf rot (Exit 1)", lauf1.returncode == 1,
        f"Exit {lauf1.returncode}\n{lauf1.stdout[-600:]}{lauf1.stderr[-400:]}")
r.check("A: die erste Zeile nennt die Zahl der Jobs", z1[:1] == ["▸ Test-Jobs: 4"], f"{z1[:1]}")
fail_zeile = next((i for i, z in enumerate(z1) if z == "  FAIL test_b_rot.py"), None)
r.check("A: … sie steht als FAIL im Log, darunter ihr Grund (stdout), ihr stderr auf stderr",
        fail_zeile is not None and "Grund: absichtlich rot (Probe 4711)" in z1[fail_zeile + 1]
        and "stderr der roten Suite" in lauf1.stderr, f"{z1}\nstderr: {lauf1.stderr[-300:]}")
r.check("A: der Skip-Grund steht ungekürzt da, samt Installationsbefehl",
        "  skip test_c_skip.py (uebersprungen: Modul 'xyz' fehlt — pip install 'tinysesam[xyz]')" in z1,
        f"{z1}")
r.check("A: die Bilanz stimmt", "2/4 grün, 1 übersprungen, 1 fehlgeschlagen" in z1, f"{z1[-2:]}")
reihe = [z.split()[1] for z in z1 if z.split()[:1] and z.split()[0] in ("ok", "FAIL", "skip")]
r.check("B: Ausgabe in der Reihenfolge der Liste, obwohl die erste Suite zuletzt fertig wird",
        reihe == ["test_a_gruen.py", "test_b_rot.py", "test_c_skip.py", "test_d_gruen.py"], f"{reihe}")
r.check("B: zwei Läufe, ein Protokoll (Zeile für Zeile gleich)",
        lauf1.stdout == lauf2.stdout and lauf1.returncode == lauf2.returncode,
        f"\n{lauf1.stdout}\n---\n{lauf2.stdout}")

# ── C: wirklich gleichzeitig — und mit einem Job wirklich seriell ─────────────────────────────────
# Gleichzeitig: Drei Suiten warten aufeinander (jede legt eine Marke ab und wartet auf die beiden
# anderen). Nacheinander gestartet, wartet die erste vergeblich und wird rot.
treff = Path(tempfile.mkdtemp(prefix="sammel-treff-"))
treffen = """\
    import os, sys, time
    ordner = os.environ["SAMMEL_TREFFPUNKT"]
    open(os.path.join(ordner, os.path.basename(__file__)), "w").close()
    frist = time.monotonic() + 15
    while len(os.listdir(ordner)) < 3 and time.monotonic() < frist:
        time.sleep(0.02)
    da = len(os.listdir(ordner))
    print(f"{da} von 3 da")
    sys.exit(0 if da == 3 else 1)
"""
c = Path(tempfile.mkdtemp(prefix="sammel-c-"))
lauf_c = sammellauf([suite(c, f"test_treffen_{i}.py", treffen) for i in (1, 2, 3)], 3,
                    SAMMEL_TREFFPUNKT=str(treff))
r.check("C: mit 3 Jobs laufen 3 Suiten wirklich gleichzeitig (sie treffen sich)",
        lauf_c.returncode == 0, f"Exit {lauf_c.returncode}\n{lauf_c.stdout[-500:]}")

# Seriell: jede Suite schreibt Anfang und Ende in ein gemeinsames Protokoll. `test_ldap.py` steht
# in `LANGE_ZUERST` — mit einem Job darf das NICHTS an der Reihenfolge ändern.
spur = Path(tempfile.mkdtemp(prefix="sammel-spur-")) / "spur.txt"
spuren = """\
    import os, time
    name = os.path.basename(__file__)
    with open(os.environ["SAMMEL_SPUR"], "a") as f:
        f.write(f"an {name}\\n")
    time.sleep(0.15)
    with open(os.environ["SAMMEL_SPUR"], "a") as f:
        f.write(f"aus {name}\\n")
"""
s = Path(tempfile.mkdtemp(prefix="sammel-s-"))
seriell = [suite(s, n, spuren) for n in ("test_a.py", "test_ldap.py", "test_z.py")]
assert "test_ldap.py" in run_all.LANGE_ZUERST
lauf_s = sammellauf(seriell, 1, SAMMEL_SPUR=str(spur))
gelesen = spur.read_text(encoding="utf-8").split("\n")[:-1] if spur.exists() else []
r.check("C: CI_TEST_JOBS=1 ist der serielle Lauf — eine nach der anderen, in Listenfolge",
        lauf_s.returncode == 0 and gelesen == ["an test_a.py", "aus test_a.py", "an test_ldap.py",
                                               "aus test_ldap.py", "an test_z.py", "aus test_z.py"],
        f"Exit {lauf_s.returncode}, Spur {gelesen}")
r.check("C: … und sagt das auch", zeilen(lauf_s)[:1] == ["▸ Test-Jobs: 1"], f"{zeilen(lauf_s)[:1]}")

# Die Startreihenfolge: mit mehreren Jobs die langen zuerst, sonst die Liste.
namen = ["/x/test_a.py", "/x/test_ldap.py", "/x/test_b.py", "/x/test_vorbuchung_schwebe.py"]
r.check("C: Startreihenfolge mit einem Job = Liste; mit mehreren die langen zuerst, Rest in Listenfolge",
        run_all.startreihenfolge(namen, 1) == [0, 1, 2, 3]
        and run_all.startreihenfolge(namen, 4) == [1, 3, 0, 2],
        f"{run_all.startreihenfolge(namen, 1)} / {run_all.startreihenfolge(namen, 4)}")
fehlen = [n for n in run_all.LANGE_ZUERST if not (ROOT / "tests" / n).exists()]
r.check("C: jeder Eintrag in LANGE_ZUERST ist noch eine Suite", not fehlen, f"{fehlen}")

# ── D: CI_TEST_JOBS / CI_KERNE ──────────────────────────────────────────────────────────────
r.check("D: CI_TEST_JOBS gilt vor CI_KERNE; Leerraum stört nicht",
        run_all.jobs_bestimmen(" 3 ", "7") == 3 and run_all.jobs_bestimmen("1", "7") == 1)
r.check("D: ohne CI_TEST_JOBS gilt CI_KERNE (die Zahl des Runners)",
        run_all.jobs_bestimmen("", "5") == 5 and run_all.jobs_bestimmen("", " 1 ") == 1)
# Keine Erkennung: `os.cpu_count()` sieht im Container alle Kerne des Hosts, nicht die Quote.
r.check("D: ohne beide die feste Vorgabe 2 — keine Erkennung der Kerne",
        run_all.jobs_bestimmen("", "") == 2 == run_all.JOBS_VORGABE,
        f"{run_all.jobs_bestimmen('', '')}")
for kaputt in ("0", "zwei"):
    try:
        run_all.jobs_bestimmen("", kaputt)
        abgelehnt = False
    except ValueError as fehler:
        abgelehnt = "CI_KERNE" in str(fehler)
    r.check(f"D: CI_KERNE={kaputt!r} ist ein Fehler, keine stille Vorgabe", abgelehnt)
spur_d = Path(tempfile.mkdtemp(prefix="sammel-d-")) / "spur.txt"
for kaputt in ("0", "-2", "zwei", "1.5"):
    lauf_d = sammellauf([seriell[0]], kaputt, SAMMEL_SPUR=str(spur_d))
    r.check(f"D: CI_TEST_JOBS={kaputt!r} bricht ab, statt still eine Vorgabe zu nehmen",
            lauf_d.returncode not in (0, 1) and "CI_TEST_JOBS" in lauf_d.stderr
            and "Test-Jobs" not in lauf_d.stdout and not spur_d.exists(),
            f"Exit {lauf_d.returncode}: {lauf_d.stdout[-200:]} {lauf_d.stderr[-200:]}")
lauf_0 = sammellauf([ab_suiten[2]], 2)
r.check("D: der Boden bleibt — nur Übersprungenes ist kein grüner Lauf",
        lauf_0.returncode == 1 and "keine einzige Suite" in lauf_0.stderr, f"Exit {lauf_0.returncode}")

# ── E: der Warnfilter wirkt durch den Starter ─────────────────────────────────────────────────────
e = Path(tempfile.mkdtemp(prefix="sammel-e-"))
lauf_e = sammellauf([suite(e, "test_w_alt.py", """\
        import warnings
        warnings.warn_explicit("TinySesam.alt ist veraltet", DeprecationWarning, "x.py", 1,
                               module="tinysesam.router")
    """), ab_suiten[3]], 2)
r.check("E: ein veralteter Name, gerufen aus dem Paket, macht die Suite rot — auch parallel",
        lauf_e.returncode == 1 and "  FAIL test_w_alt.py" in zeilen(lauf_e)
        and "DeprecationWarning" in lauf_e.stderr, f"Exit {lauf_e.returncode}\n{lauf_e.stdout[-300:]}")

# ── F: der Starter ────────────────────────────────────────────────────────────────────────────────
PROBE = """\
    import json, os, sys
    vorher = sorted(m for m in sys.modules if m == "tinysesam" or m.startswith("tinysesam."))
    from tinysesam import passwords as p
    h = p.hash_password("Probe-Pw-12")
    aus = {"vorher": vorher, "argon": p._ARGON, "scrypt": [p._SCRYPT["n"], p._SCRYPT["r"], p._SCRYPT["p"]],
           "hash": h.split("$")[:4],
           "dummy": p._DUMMY.split("$")[:4], "stimmt": p.verify_password("Probe-Pw-12", h),
           "falsch": p.verify_password("Probe-Pw-13", h), "erneuern": p.needs_rehash(h)}
    if p._ARGON:
        from argon2 import PasswordHasher
        vorgabe = PasswordHasher()
        aus["argon_vorgabe"] = [vorgabe.memory_cost, vorgabe.time_cost, vorgabe.parallelism]
        aus["argon_aktiv"] = [p._PH.memory_cost, p._PH.time_cost, p._PH.parallelism]
    with open(os.environ["SAMMEL_PROBE"], "w") as f:
        json.dump(aus, f)
"""


def probe_lesen(pfad: Path) -> dict:
    return json.loads(pfad.read_text(encoding="utf-8")) if pfad.exists() else {}


def abgesenkt(p: dict) -> bool:
    if not p:
        return False
    n, rr, pp = _starter.SCRYPT_TEST["n"], _starter.SCRYPT_TEST["r"], _starter.SCRYPT_TEST["p"]
    if p["scrypt"] != [n, rr, pp]:
        return False
    if p["argon"]:
        ziel = [_starter.ARGON2_TEST["memory_cost"], _starter.ARGON2_TEST["time_cost"],
                _starter.ARGON2_TEST["parallelism"]]
        teil = f"m={ziel[0]},t={ziel[1]},p={ziel[2]}"
        return p["argon_aktiv"] == ziel and p["hash"][3] == teil and p["dummy"][3] == teil
    return p["hash"] == ["scrypt", str(n), str(rr), str(pp)] and p["dummy"] == p["hash"]


def produktiv(p: dict) -> bool:
    if not p or p["scrypt"] != [2 ** 15, 8, 3]:
        return False
    if p["argon"]:
        return p["argon_aktiv"] == p["argon_vorgabe"] and p["dummy"][3] == p["hash"][3]
    return p["hash"] == ["scrypt", "32768", "8", "3"] and p["dummy"] == p["hash"]


f = Path(tempfile.mkdtemp(prefix="sammel-f-"))
probe_im_lauf = f / "im_lauf.json"
lauf_f = sammellauf([suite(f, "test_probe.py", PROBE)], 2, SAMMEL_PROBE=str(probe_im_lauf))
p_lauf = probe_lesen(probe_im_lauf)
r.check("F: im Sammellauf rechnet eine Suite mit den abgesenkten Parametern — Hash UND Dummy",
        lauf_f.returncode == 0 and abgesenkt(p_lauf), f"Exit {lauf_f.returncode}, {p_lauf}")
r.check("F: … Verfahren und Prüfung bleiben dieselben (richtig/falsch, kein Erneuern)",
        p_lauf.get("stimmt") is True and p_lauf.get("falsch") is False
        and p_lauf.get("erneuern") is False, f"{p_lauf}")
r.check("F: der Starter importiert tinysesam nicht vor der Suite (Import-Reihenfolge unverändert)",
        p_lauf.get("vorher") == [], f"{p_lauf.get('vorher')}")

# Direkt gestartet — und mit Variablen, die nach einem Schalter aussehen: Produktionswerte.
probe_direkt = f / "direkt.json"
direkt = subprocess.run([sys.executable, str(f / "test_probe.py")], cwd=str(ROOT), timeout=60,
                        env={**os.environ, "PYTHONPATH": str(ROOT), "SAMMEL_PROBE": str(probe_direkt),
                             "TINYSESAM_SCRYPT_N": "16", "TINYSESAM_SCRYPT_P": "1",
                             "TINYSESAM_ARGON2_MEMORY_COST": "8", "TINYSESAM_ARGON2_TIME_COST": "1",
                             "TINYSESAM_HASH_PARAMS": "test", "CI_TEST_JOBS": "1"},
                        capture_output=True, text=True)
p_direkt = probe_lesen(probe_direkt)
r.check("F: direkt gestartet rechnet dieselbe Suite mit den Produktionswerten, Variablen hin oder her",
        direkt.returncode == 0 and produktiv(p_direkt),
        f"Exit {direkt.returncode}, {p_direkt} {direkt.stderr[-300:]}")

# Die Ausnahmen: unter dem Namen einer Suite aus PRODUKTIONSWERTE bleibt es bei den echten Werten.
probe_ausnahme = f / "ausnahme.json"
ausnahme = next(iter(sorted(_starter.PRODUKTIONSWERTE)))
g = Path(tempfile.mkdtemp(prefix="sammel-g-"))
lauf_g = sammellauf([suite(g, ausnahme, PROBE)], 2, SAMMEL_PROBE=str(probe_ausnahme))
p_ausnahme = probe_lesen(probe_ausnahme)
r.check(f"F: eine Suite aus PRODUKTIONSWERTE ({ausnahme}) rechnet auch im Sammellauf mit den echten Werten",
        lauf_g.returncode == 0 and produktiv(p_ausnahme), f"Exit {lauf_g.returncode}, {p_ausnahme}")
r.check("F: jede Ausnahme ist eine Suite und hat einen Grund",
        all((ROOT / "tests" / n).exists() and str(g_).strip()
            for n, g_ in _starter.PRODUKTIONSWERTE.items()), f"{_starter.PRODUKTIONSWERTE}")

# Welche Suiten gehören auf die Liste? Die, die Hash-Interna anfassen oder Laufzeit messen —
# entschieden am Quelltext (AST, also ohne Kommentare und Zeichenketten), nicht aus dem Gedächtnis.
AUSLOESER = {"_SCRYPT", "_SCRYPT_ALT", "_MAXMEM", "_PH", "_DUMMY", "needs_rehash",
             "check_needs_rehash", "dummy_verify", "PasswordHasher", "scrypt", "perf_counter"}


def ausloeser(pfad: Path) -> set:
    baum = ast.parse(pfad.read_text(encoding="utf-8"))
    return ({n.attr for n in ast.walk(baum) if isinstance(n, ast.Attribute)}
            | {n.id for n in ast.walk(baum) if isinstance(n, ast.Name)}
            | {a.name for n in ast.walk(baum) if isinstance(n, ast.ImportFrom) for a in n.names}) \
        & AUSLOESER


gefunden = {p.name: sorted(ausloeser(p)) for p in sorted((ROOT / "tests").glob("test_*.py"))
            if p.name != Path(__file__).name and ausloeser(p)}
r.check("F: jede Suite, die Hash-Parameter oder Laufzeiten prüft, steht in PRODUKTIONSWERTE — "
        "und nur solche", set(gefunden) == set(_starter.PRODUKTIONSWERTE),
        f"gefunden {gefunden}, eingetragen {sorted(_starter.PRODUKTIONSWERTE)} — eine solche Suite "
        "wäre mit abgesenkten Parametern leer (tests/_starter.py)")

# ── G: kein Schalter im Paket ─────────────────────────────────────────────────────────────────────
PAKET = ROOT / "tinysesam"
pw_baum = ast.parse((PAKET / "passwords.py").read_text(encoding="utf-8"))
pw_namen = ({n.attr for n in ast.walk(pw_baum) if isinstance(n, ast.Attribute)}
            | {n.id for n in ast.walk(pw_baum) if isinstance(n, ast.Name)}
            | {a.name for n in ast.walk(pw_baum) if isinstance(n, (ast.Import, ast.ImportFrom))
               for a in n.names})
r.check("G: tinysesam/passwords.py liest keine Umgebung",
        not pw_namen & {"environ", "environb", "getenv", "getenvb", "putenv"},
        f"{sorted(pw_namen & {'environ', 'environb', 'getenv', 'getenvb', 'putenv'})}")
paketimporte = [n.module or "." for n in ast.walk(pw_baum)
                if isinstance(n, ast.ImportFrom) and (n.level or (n.module or "").startswith("tinysesam"))]
r.check("G: … und importiert nichts aus dem Paket (also auch keine Konfiguration)",
        not paketimporte, f"{paketimporte}")


def konstant(knoten, bekannt: set) -> bool:
    """Ist der Ausdruck aus Literalen gebaut (Zahlen, Rechenzeichen, bekannte Konstanten)?"""
    if isinstance(knoten, ast.Constant):
        return True
    if isinstance(knoten, ast.BinOp):
        return konstant(knoten.left, bekannt) and konstant(knoten.right, bekannt)
    if isinstance(knoten, ast.Name):
        return knoten.id in bekannt
    return False


zuweisungen = {z.targets[0].id: z.value for z in pw_baum.body
               if isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name)}
bekannt = {"_MAXMEM"} if konstant(zuweisungen.get("_MAXMEM"), set()) else set()
scrypt_literal = all(
    isinstance(zuweisungen.get(k), ast.Call) and not zuweisungen[k].args
    and all(konstant(kw.value, bekannt) for kw in zuweisungen[k].keywords)
    for k in ("_SCRYPT", "_SCRYPT_ALT"))
ph_wert = next((z.value for z in ast.walk(pw_baum) if isinstance(z, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "_PH" for t in z.targets)), None)
r.check("G: die scrypt-Parameter sind Literale, argon2 läuft mit den Vorgaben von argon2-cffi",
        scrypt_literal and bool(bekannt) and isinstance(ph_wert, ast.Call)
        and not ph_wert.args and not ph_wert.keywords,
        "ein Parameter kommt aus einem Ausdruck — dann kann er von aussen kommen")
from tinysesam import passwords as _pw  # noqa: E402
r.check("G: hash_password nimmt nur das Passwort (kein Kosten-Parameter von aussen)",
        list(inspect.signature(_pw.hash_password).parameters) == ["pw"],
        f"{inspect.signature(_pw.hash_password)}")

GESCHUETZT = {"_SCRYPT", "_SCRYPT_ALT", "_MAXMEM", "_PH", "_DUMMY"}
setzer = []
for datei in sorted(PAKET.rglob("*.py")):
    baum = ast.parse(datei.read_text(encoding="utf-8"))
    for n in ast.walk(baum):
        ziele = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(
            n, (ast.AugAssign, ast.AnnAssign)) else []
        for t in ziele:
            if isinstance(t, ast.Attribute) and t.attr in GESCHUETZT:
                setzer.append(f"{datei.relative_to(ROOT)}:{n.lineno}")
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "setattr"
                and len(n.args) > 1 and isinstance(n.args[1], ast.Constant)
                and n.args[1].value in GESCHUETZT):
            setzer.append(f"{datei.relative_to(ROOT)}:{n.lineno}")
r.check("G: kein Modul des Pakets überschreibt die Hash-Parameter von aussen", not setzer, f"{setzer}")

from tinysesam import TinySesamConfig  # noqa: E402
VERDAECHTIG = ("scrypt", "argon", "kdf", "hash_cost", "memory_cost", "time_cost", "work_factor")
felder = [x.name for x in dataclasses.fields(TinySesamConfig) if any(v in x.name for v in VERDAECHTIG)]
variablen = sorted({k.value for d in PAKET.rglob("*.py")
                    for k in ast.walk(ast.parse(d.read_text(encoding="utf-8")))
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                    and k.value.startswith("TINYSESAM_")
                    and any(v in k.value.lower() for v in VERDAECHTIG + ("hash",))})
r.check("G: keine Einstellung und keine TINYSESAM_-Variable für Hash-Kosten", not felder and not variablen,
        f"Felder {felder}, Variablen {variablen}")

# ── H: das Tor baut die Website nicht in den Baum ─────────────────────────────────────────────────
# Bis zum Umbau baute `scripts/check.sh` nach `_site/` im Baum und löschte den Ordner danach — ein
# eigenes `_site/` war damit weg, und zwei Läufe im selben Baum räumten einander die Seite unter
# den Füßen weg. Geprüft an einer KOPIE der versionierten Dateien (in den echten Baum schreibt keine
# Suite) mit einem vorhandenen `_site/`; den Sammellauf ersetzt ein Stellvertreter, sonst liefe
# hier alles ein zweites Mal. `scripts/` gehört nicht ins Quellpaket — dort gibt es nichts zu prüfen.
liste = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT), capture_output=True)
if liste.returncode != 0 or not (ROOT / "scripts" / "check.sh").exists():
    print("  H: kein Git-Checkout mit scripts/check.sh (Quellpaket) — das Tor gibt es hier nicht")
else:
    kopie = Path(tempfile.mkdtemp(prefix="sammel-h-")) / "baum"
    for rel in (n for n in liste.stdout.decode("utf-8").split("\0") if n):
        if (ROOT / rel).is_file():
            (kopie / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, kopie / rel)
    (kopie / "_site").mkdir()
    (kopie / "_site" / "eigen.txt").write_text("gehört dem Menschen, nicht dem Tor\n", encoding="utf-8")
    vertreter = kopie.parent / "python-stellvertreter"
    vertreter.write_text(f'''#!/bin/sh
if [ "$1" = "tests/run_all.py" ]; then echo "Sammellauf: Stellvertreter"; exit 0; fi
exec "{sys.executable}" "$@"
''', encoding="utf-8")
    vertreter.chmod(vertreter.stat().st_mode | stat.S_IXUSR)
    vorher_h = sorted(str(x.relative_to(kopie)) for x in kopie.rglob("*"))
    tor = subprocess.run(["bash", "scripts/check.sh", "--fast"], cwd=str(kopie), timeout=120,
                         env={**os.environ, "PYTHON": str(vertreter), "PYTHONPATH": str(kopie)},
                         capture_output=True, text=True)
    nachher_h = sorted(str(x.relative_to(kopie)) for x in kopie.rglob("*") if "__pycache__" not in x.parts)
    r.check("H: check.sh baut die Website (Exit 0, alle Pflichtdateien im Bau)",
            tor.returncode == 0 and "alles grün" in tor.stdout,
            f"Exit {tor.returncode}\n{tor.stdout[-400:]}{tor.stderr[-400:]}")
    r.check("H: … ein vorhandenes _site/ bleibt unangetastet, und im Baum entsteht nichts Neues",
            (kopie / "_site" / "eigen.txt").exists() and nachher_h == vorher_h,
            f"eigen.txt da: {(kopie / '_site' / 'eigen.txt').exists()}, neu: "
            f"{sorted(set(nachher_h) - set(vorher_h))}, weg: {sorted(set(vorher_h) - set(nachher_h))}")


# ── I: die gescheiterte Prüfung steht im Protokoll, auch bei langer Ausgabe ───────────────────────
# Bis 2026-09-28 stand unter `FAIL` nur das Ende der Ausgabe (2000 Zeichen). Scheiterte eine frühe
# Prüfung, fehlte ihre Zeile — gesehen im CI-Job `repeat` bei test_vorbuchung_schwebe.py.
# (Mutationsprobe: in `_fail_ausgabe` nur `ende` zurückgeben → rot.)
ordner_i = Path(tempfile.mkdtemp(prefix="sammel-i-"))
lang = suite(ordner_i, "test_lang_rot.py", """\
    import sys
    print("  FEHL frühe Prüfung (Probe 4712): erwartet 1, war 2")
    for i in range(120):
        print(f"  ok   spätere Prüfung {i:03d}, die das Ende der Ausgabe füllt")
    print("120 ok, 1 Fehler")
    sys.exit(1)
""")
lauf_i = sammellauf([lang], 1)
aus_i = lauf_i.stdout
r.check("I: die frühe FEHL-Zeile steht unter FAIL, obwohl danach über 2000 Zeichen folgen",
        lauf_i.returncode == 1 and "FEHL frühe Prüfung (Probe 4712): erwartet 1, war 2" in aus_i
        and aus_i.index("FAIL test_lang_rot.py") < aus_i.index("Probe 4712"),
        aus_i[-600:])
r.check("I: … das Ende der Ausgabe steht weiter da und beginnt an einer Zeilengrenze",
        "120 ok, 1 Fehler" in aus_i and "── Ende der Ausgabe ──" in aus_i
        and aus_i.split("── Ende der Ausgabe ──\n", 1)[-1].startswith("  ok   spätere Prüfung"),
        aus_i.split("── Ende der Ausgabe ──", 1)[-1][:120])

# ── J: eigenes Wegwerf-Verzeichnis je Suite ───────────────────────────────────────────────────
# Die Zusage, auf der der parallele Lauf und „Tests sind wiederholbar" stehen. Bis 2026-10-01 prüfte
# sie keine Suite: Ein gemeinsames, nie gelöschtes Verzeichnis für alle Suiten blieb grün.
# (Mutationsprobe: in `suite_fahren` ein festes Verzeichnis nehmen und nicht löschen → rot.)
ordner_j = Path(tempfile.mkdtemp(prefix="sammel-j-"))
spur_j = Path(tempfile.mkdtemp(prefix="sammel-j-spur-"))
rumpf_j = """\
    import json, os, sys, tempfile
    from pathlib import Path
    werte = {k: os.environ.get(k, "") for k in ("TMPDIR", "HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
                                                "XDG_DATA_HOME")}
    werte["gettempdir"] = tempfile.gettempdir()
    Path(os.environ["SAMMEL_SPUR_J"], Path(sys.argv[0]).name + ".json").write_text(json.dumps(werte))
"""
lauf_j = sammellauf([suite(ordner_j, "test_j1.py", rumpf_j), suite(ordner_j, "test_j2.py", rumpf_j)],
                    2, SAMMEL_SPUR_J=str(spur_j))
spuren = [json.loads(f.read_text()) for f in sorted(spur_j.glob("*.json"))]
r.check("J: beide Suiten liefen und haben ihre Umgebung abgelegt",
        lauf_j.returncode == 0 and len(spuren) == 2, f"Exit {lauf_j.returncode}, {len(spuren)} Spuren")
if len(spuren) == 2:
    eins, zwei = spuren
    r.check("J: TMPDIR, HOME, XDG_* und gettempdir zeigen in dasselbe Verzeichnis der Suite",
            all(eins[k] and eins[k].startswith(eins["TMPDIR"]) for k in eins)
            and all(zwei[k] and zwei[k].startswith(zwei["TMPDIR"]) for k in zwei), f"{spuren}")
    r.check("J: jede Suite hat ein eigenes Verzeichnis", eins["TMPDIR"] != zwei["TMPDIR"], f"{spuren}")
    r.check("J: nach dem Lauf sind beide Verzeichnisse weg",
            not os.path.exists(eins["TMPDIR"]) and not os.path.exists(zwei["TMPDIR"]), f"{spuren}")

sys.exit(r.done())

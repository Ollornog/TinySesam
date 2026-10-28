"""The collective run itself: parallel, but as meaningful as serial — and cheap hashes only in the test.

Since the test-run rework (after 0.22.0) `tests/run_all.py` runs the suites simultaneously
(`CI_TEST_JOBS`) and starts each via `tests/_starter.py`, which lowers the hash parameters in the
test process. Both save time — and both could silently cost meaning. What is measured:

A  a red suite makes the run red, even if it runs in parallel, and its reason is in the log;
B  the output follows the order of the list, not the order in which suites finish —
   two runs deliver the same log;
C  “parallel” is really simultaneous, `CI_TEST_JOBS=1` really the old serial run;
D  an unusable value for `CI_TEST_JOBS` is an error, not a silent default;
E  the warning filter (deprecated names from the package = error) also works through the starter;
F  the starter lowers only in the collective run, leaves the import order of the suite alone, and the
   suites that check hash parameters or runtimes themselves calculate with the real values;
G  the PACKAGE has no switch that weakens hashes — no environment variable, no setting;
H  the gate (`scripts/check.sh`) builds the website into a throwaway directory, not into `_site/`.
I  every failed check is under `FAIL`, even if the output of the suite is long;
J  every suite has its own throwaway directory (TMPDIR, HOME, XDG_*), which is gone afterwards.
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
    """Create a dummy suite (returns the path)."""
    pfad = ordner / name
    pfad.write_text(textwrap.dedent(rumpf), encoding="utf-8")
    return str(pfad)


def sammellauf(pfade, jobs, **umgebung):
    """Run `run_all.py` with exactly these suites."""
    env = {**os.environ, **umgebung}
    if jobs is None:
        env.pop(run_all.JOBS_VARIABLE, None)
    else:
        env[run_all.JOBS_VARIABLE] = str(jobs)
    return subprocess.run([sys.executable, RUN_ALL, *pfade], cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=120)


def zeilen(lauf) -> list[str]:
    return [z for z in lauf.stdout.splitlines() if z.strip()]


# ── A + B: red stays red, order of the list, same log ────────────────────────────────────────
ab = Path(tempfile.mkdtemp(prefix="sammel-ab-"))
ab_suiten = [
    # a takes the longest — so it finishes last and must still be first in the log.
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
r.check("A: a red suite makes the parallel run red (exit 1)", lauf1.returncode == 1,
        f"Exit {lauf1.returncode}\n{lauf1.stdout[-600:]}{lauf1.stderr[-400:]}")
r.check("A: the first line names the number of jobs", z1[:1] == ["▸ Test-Jobs: 4"], f"{z1[:1]}")
fail_zeile = next((i for i, z in enumerate(z1) if z == "  FAIL test_b_rot.py"), None)
r.check("A: … it appears as FAIL in the log, below it its reason (stdout), its stderr on stderr",
        fail_zeile is not None and "Grund: absichtlich rot (Probe 4711)" in z1[fail_zeile + 1]
        and "stderr der roten Suite" in lauf1.stderr, f"{z1}\nstderr: {lauf1.stderr[-300:]}")
r.check("A: the skip reason is there in full, including the install command",
        "  skip test_c_skip.py (uebersprungen: Modul 'xyz' fehlt — pip install 'tinysesam[xyz]')" in z1,
        f"{z1}")
r.check("A: the tally is correct", "2/4 grün, 1 übersprungen, 1 fehlgeschlagen" in z1, f"{z1[-2:]}")
reihe = [z.split()[1] for z in z1 if z.split()[:1] and z.split()[0] in ("ok", "FAIL", "skip")]
r.check("B: output in the order of the list, although the first suite finishes last",
        reihe == ["test_a_gruen.py", "test_b_rot.py", "test_c_skip.py", "test_d_gruen.py"], f"{reihe}")
r.check("B: two runs, one log (identical line by line)",
        lauf1.stdout == lauf2.stdout and lauf1.returncode == lauf2.returncode,
        f"\n{lauf1.stdout}\n---\n{lauf2.stdout}")

# ── C: really simultaneous — and with one job really serial ──────────────────────────────────
# Simultaneous: three suites wait for each other (each drops a marker and waits for the two
# others). Started one after another, the first waits in vain and turns red.
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
r.check("C: with 3 jobs 3 suites really run simultaneously (they meet)",
        lauf_c.returncode == 0, f"Exit {lauf_c.returncode}\n{lauf_c.stdout[-500:]}")

# Serial: every suite writes start and end into a shared log. `test_ldap.py` is
# in `LANGE_ZUERST` — with one job that must change NOTHING about the order.
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
r.check("C: CI_TEST_JOBS=1 is the serial run — one after the other, in list order",
        lauf_s.returncode == 0 and gelesen == ["an test_a.py", "aus test_a.py", "an test_ldap.py",
                                               "aus test_ldap.py", "an test_z.py", "aus test_z.py"],
        f"Exit {lauf_s.returncode}, Spur {gelesen}")
r.check("C: … and says so", zeilen(lauf_s)[:1] == ["▸ Test-Jobs: 1"], f"{zeilen(lauf_s)[:1]}")

# The start order: with several jobs the long ones first, otherwise the list.
namen = ["/x/test_a.py", "/x/test_ldap.py", "/x/test_b.py", "/x/test_vorbuchung_schwebe.py"]
r.check("C: start order with one job = list; with several the long ones first, rest in list order",
        run_all.startreihenfolge(namen, 1) == [0, 1, 2, 3]
        and run_all.startreihenfolge(namen, 4) == [1, 3, 0, 2],
        f"{run_all.startreihenfolge(namen, 1)} / {run_all.startreihenfolge(namen, 4)}")
fehlen = [n for n in run_all.LANGE_ZUERST if not (ROOT / "tests" / n).exists()]
r.check("C: every entry in LANGE_ZUERST is still a suite", not fehlen, f"{fehlen}")

# ── D: CI_TEST_JOBS / CI_KERNE ──────────────────────────────────────────────────────────────
r.check("D: CI_TEST_JOBS takes precedence over CI_KERNE; whitespace does not matter",
        run_all.jobs_bestimmen(" 3 ", "7") == 3 and run_all.jobs_bestimmen("1", "7") == 1)
r.check("D: without CI_TEST_JOBS, CI_KERNE applies (the number of the runner)",
        run_all.jobs_bestimmen("", "5") == 5 and run_all.jobs_bestimmen("", " 1 ") == 1)
# No detection: `os.cpu_count()` sees all cores of the host in the container, not the quota.
r.check("D: without both the fixed default 2 — no detection of the cores",
        run_all.jobs_bestimmen("", "") == 2 == run_all.JOBS_VORGABE,
        f"{run_all.jobs_bestimmen('', '')}")
for kaputt in ("0", "zwei"):
    try:
        run_all.jobs_bestimmen("", kaputt)
        abgelehnt = False
    except ValueError as fehler:
        abgelehnt = "CI_KERNE" in str(fehler)
    r.check(f"D: CI_KERNE={kaputt!r} is an error, not a silent default", abgelehnt)
spur_d = Path(tempfile.mkdtemp(prefix="sammel-d-")) / "spur.txt"
for kaputt in ("0", "-2", "zwei", "1.5"):
    lauf_d = sammellauf([seriell[0]], kaputt, SAMMEL_SPUR=str(spur_d))
    r.check(f"D: CI_TEST_JOBS={kaputt!r} aborts instead of silently taking a default",
            lauf_d.returncode not in (0, 1) and "CI_TEST_JOBS" in lauf_d.stderr
            and "Test-Jobs" not in lauf_d.stdout and not spur_d.exists(),
            f"Exit {lauf_d.returncode}: {lauf_d.stdout[-200:]} {lauf_d.stderr[-200:]}")
lauf_0 = sammellauf([ab_suiten[2]], 2)
r.check("D: the floor stays — only skipped is not a green run",
        lauf_0.returncode == 1 and "keine einzige Suite" in lauf_0.stderr, f"Exit {lauf_0.returncode}")

# ── E: the warning filter works through the starter ──────────────────────────────────────────
e = Path(tempfile.mkdtemp(prefix="sammel-e-"))
lauf_e = sammellauf([suite(e, "test_w_alt.py", """\
        import warnings
        warnings.warn_explicit("TinySesam.alt ist veraltet", DeprecationWarning, "x.py", 1,
                               module="tinysesam.router")
    """), ab_suiten[3]], 2)
r.check("E: a deprecated name, called from the package, makes the suite red — also in parallel",
        lauf_e.returncode == 1 and "  FAIL test_w_alt.py" in zeilen(lauf_e)
        and "DeprecationWarning" in lauf_e.stderr, f"Exit {lauf_e.returncode}\n{lauf_e.stdout[-300:]}")

# ── F: the starter ───────────────────────────────────────────────────────────────────────────
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
r.check("F: in the collective run a suite calculates with the lowered parameters — hash AND dummy",
        lauf_f.returncode == 0 and abgesenkt(p_lauf), f"Exit {lauf_f.returncode}, {p_lauf}")
r.check("F: … method and check remain the same (right/wrong, no renewal)",
        p_lauf.get("stimmt") is True and p_lauf.get("falsch") is False
        and p_lauf.get("erneuern") is False, f"{p_lauf}")
r.check("F: the starter does not import tinysesam before the suite (import order unchanged)",
        p_lauf.get("vorher") == [], f"{p_lauf.get('vorher')}")

# Started directly — and with variables that look like a switch: production values.
probe_direkt = f / "direkt.json"
direkt = subprocess.run([sys.executable, str(f / "test_probe.py")], cwd=str(ROOT), timeout=60,
                        env={**os.environ, "PYTHONPATH": str(ROOT), "SAMMEL_PROBE": str(probe_direkt),
                             "TINYSESAM_SCRYPT_N": "16", "TINYSESAM_SCRYPT_P": "1",
                             "TINYSESAM_ARGON2_MEMORY_COST": "8", "TINYSESAM_ARGON2_TIME_COST": "1",
                             "TINYSESAM_HASH_PARAMS": "test", "CI_TEST_JOBS": "1"},
                        capture_output=True, text=True)
p_direkt = probe_lesen(probe_direkt)
r.check("F: started directly the same suite calculates with the production values, variables or not",
        direkt.returncode == 0 and produktiv(p_direkt),
        f"Exit {direkt.returncode}, {p_direkt} {direkt.stderr[-300:]}")

# The exceptions: under the name of a suite from PRODUKTIONSWERTE it stays with the real values.
probe_ausnahme = f / "ausnahme.json"
ausnahme = next(iter(sorted(_starter.PRODUKTIONSWERTE)))
g = Path(tempfile.mkdtemp(prefix="sammel-g-"))
lauf_g = sammellauf([suite(g, ausnahme, PROBE)], 2, SAMMEL_PROBE=str(probe_ausnahme))
p_ausnahme = probe_lesen(probe_ausnahme)
r.check(f"F: a suite from PRODUKTIONSWERTE ({ausnahme}) also calculates with the real values in the collective run",
        lauf_g.returncode == 0 and produktiv(p_ausnahme), f"Exit {lauf_g.returncode}, {p_ausnahme}")
r.check("F: every exception is a suite and has a reason",
        all((ROOT / "tests" / n).exists() and str(g_).strip()
            for n, g_ in _starter.PRODUKTIONSWERTE.items()), f"{_starter.PRODUKTIONSWERTE}")

# Which suites belong on the list? Those that touch hash internals or measure runtime —
# decided on the source (AST, i.e. without comments and strings), not from memory.
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
r.check("F: every suite that checks hash parameters or runtimes is in PRODUKTIONSWERTE — "
        "and only those", set(gefunden) == set(_starter.PRODUKTIONSWERTE),
        f"found {gefunden}, entered {sorted(_starter.PRODUKTIONSWERTE)} — such a suite "
        "would be empty with lowered parameters (tests/_starter.py)")

# ── G: no switch in the package ──────────────────────────────────────────────────────────────
PAKET = ROOT / "tinysesam"
pw_baum = ast.parse((PAKET / "passwords.py").read_text(encoding="utf-8"))
pw_namen = ({n.attr for n in ast.walk(pw_baum) if isinstance(n, ast.Attribute)}
            | {n.id for n in ast.walk(pw_baum) if isinstance(n, ast.Name)}
            | {a.name for n in ast.walk(pw_baum) if isinstance(n, (ast.Import, ast.ImportFrom))
               for a in n.names})
r.check("G: tinysesam/passwords.py reads no environment",
        not pw_namen & {"environ", "environb", "getenv", "getenvb", "putenv"},
        f"{sorted(pw_namen & {'environ', 'environb', 'getenv', 'getenvb', 'putenv'})}")
paketimporte = [n.module or "." for n in ast.walk(pw_baum)
                if isinstance(n, ast.ImportFrom) and (n.level or (n.module or "").startswith("tinysesam"))]
r.check("G: … and imports nothing from the package (so no configuration either)",
        not paketimporte, f"{paketimporte}")


def konstant(knoten, bekannt: set) -> bool:
    """Is the expression built from literals (numbers, operators, known constants)?"""
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
r.check("G: the scrypt parameters are literals, argon2 runs with the defaults of argon2-cffi",
        scrypt_literal and bool(bekannt) and isinstance(ph_wert, ast.Call)
        and not ph_wert.args and not ph_wert.keywords,
        "a parameter comes from an expression — then it can come from outside")
from tinysesam import passwords as _pw  # noqa: E402
r.check("G: hash_password takes only the password (no cost parameter from outside)",
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
r.check("G: no module of the package overrides the hash parameters from outside", not setzer, f"{setzer}")

from tinysesam import TinySesamConfig  # noqa: E402
VERDAECHTIG = ("scrypt", "argon", "kdf", "hash_cost", "memory_cost", "time_cost", "work_factor")
felder = [x.name for x in dataclasses.fields(TinySesamConfig) if any(v in x.name for v in VERDAECHTIG)]
variablen = sorted({k.value for d in PAKET.rglob("*.py")
                    for k in ast.walk(ast.parse(d.read_text(encoding="utf-8")))
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                    and k.value.startswith("TINYSESAM_")
                    and any(v in k.value.lower() for v in VERDAECHTIG + ("hash",))})
r.check("G: no setting and no TINYSESAM_ variable for hash cost", not felder and not variablen,
        f"Felder {felder}, Variablen {variablen}")

# ── H: the gate does not build the website into the tree ─────────────────────────────────────
# Until the rework `scripts/check.sh` built into `_site/` in the tree and deleted the folder afterwards — a
# `_site/` of one's own was gone with it, and two runs in the same tree cleared the site away
# from under each other. Checked on a COPY of the versioned files (no suite writes into
# the real tree) with an existing `_site/`; a stand-in replaces the collective run, otherwise everything would run
# a second time here. `scripts/` does not belong in the source package — there is nothing to check there.
liste = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT), capture_output=True)
if liste.returncode != 0 or not (ROOT / "scripts" / "check.sh").exists():
    print("  H: no Git checkout with scripts/check.sh (source package) — the gate does not exist here")
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
    r.check("H: check.sh builds the website (exit 0, all required files in the build)",
            tor.returncode == 0 and "alles grün" in tor.stdout,
            f"Exit {tor.returncode}\n{tor.stdout[-400:]}{tor.stderr[-400:]}")
    r.check("H: … an existing _site/ stays untouched, and nothing new arises in the tree",
            (kopie / "_site" / "eigen.txt").exists() and nachher_h == vorher_h,
            f"eigen.txt da: {(kopie / '_site' / 'eigen.txt').exists()}, neu: "
            f"{sorted(set(nachher_h) - set(vorher_h))}, weg: {sorted(set(vorher_h) - set(nachher_h))}")


# ── I: the failed check is in the log, even with long output ─────────────────────────────────
# Until 2026-09-28 only the end of the output (2000 characters) stood under `FAIL`. If an early
# check failed, its line was missing — seen in the CI job `repeat` at test_vorbuchung_schwebe.py.
# (Mutation probe: return only `ende` in `_fail_ausgabe` → red.)
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
r.check("I: the early FEHL line is under FAIL, although more than 2000 characters follow",
        lauf_i.returncode == 1 and "FEHL frühe Prüfung (Probe 4712): erwartet 1, war 2" in aus_i
        and aus_i.index("FAIL test_lang_rot.py") < aus_i.index("Probe 4712"),
        aus_i[-600:])
r.check("I: … the end of the output is still there and begins at a line boundary",
        "120 ok, 1 Fehler" in aus_i and "── Ende der Ausgabe ──" in aus_i
        and aus_i.split("── Ende der Ausgabe ──\n", 1)[-1].startswith("  ok   spätere Prüfung"),
        aus_i.split("── Ende der Ausgabe ──", 1)[-1][:120])

# ── J: eigenes Wegwerf-Verzeichnis je Suite ───────────────────────────────────────────────────
# The promise on which the parallel run and “tests are repeatable” stand. Until 2026-10-01 no
# suite checked it: a shared, never deleted directory for all suites stayed green.
# (Mutation probe: take a fixed directory in `suite_fahren` and not delete it → red.)
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
r.check("J: both suites ran and have put down their environment",
        lauf_j.returncode == 0 and len(spuren) == 2, f"Exit {lauf_j.returncode}, {len(spuren)} Spuren")
if len(spuren) == 2:
    eins, zwei = spuren
    r.check("J: TMPDIR, HOME, XDG_* and gettempdir point to the same directory of the suite",
            all(eins[k] and eins[k].startswith(eins["TMPDIR"]) for k in eins)
            and all(zwei[k] and zwei[k].startswith(zwei["TMPDIR"]) for k in zwei), f"{spuren}")
    r.check("J: every suite has a directory of its own", eins["TMPDIR"] != zwei["TMPDIR"], f"{spuren}")
    r.check("J: after the run both directories are gone",
            not os.path.exists(eins["TMPDIR"]) and not os.path.exists(zwei["TMPDIR"]), f"{spuren}")

sys.exit(r.done())

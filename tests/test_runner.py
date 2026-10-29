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


def suite(folder: Path, name: str, body: str) -> str:
    """Create a dummy suite (returns the path)."""
    path = folder / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(path)


def collect_run(paths, jobs, **environment):
    """Run `run_all.py` with exactly these suites."""
    env = {**os.environ, **environment}
    if jobs is None:
        env.pop(run_all.JOBS_VARIABLE, None)
    else:
        env[run_all.JOBS_VARIABLE] = str(jobs)
    return subprocess.run([sys.executable, RUN_ALL, *paths], cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=120)


def lines(execution) -> list[str]:
    return [z for z in execution.stdout.splitlines() if z.strip()]


# ── A + B: red stays red, order of the list, same log ────────────────────────────────────────
start_from = Path(tempfile.mkdtemp(prefix="sammel-ab-"))
from_suites = [
    # a takes the longest — so it finishes last and must still be first in the log.
    suite(start_from, "test_a_gruen.py", "import time\ntime.sleep(0.8)\nprint('a fertig')\n"),
    suite(start_from, "test_b_rot.py", """\
        import sys
        print("Grund: absichtlich rot (Probe 4711)")
        print("stderr der roten Suite", file=sys.stderr)
        sys.exit(1)
    """),
    suite(start_from, "test_c_skip.py", """\
        import sys
        print("uebersprungen: Modul 'xyz' fehlt — pip install 'tinysesam[xyz]'")
        sys.exit(77)
    """),
    suite(start_from, "test_d_gruen.py", "print('d fertig')\n"),
]
execution1 = collect_run(from_suites, 4)
execution2 = collect_run(from_suites, 4)
z1 = lines(execution1)
r.check("A: a red suite makes the parallel run red (exit 1)", execution1.returncode == 1,
        f"Exit {execution1.returncode}\n{execution1.stdout[-600:]}{execution1.stderr[-400:]}")
r.check("A: the first line names the number of jobs", z1[:1] == ["▸ Test-Jobs: 4"], f"{z1[:1]}")
fail_line = next((i for i, z in enumerate(z1) if z == "  FAIL test_b_rot.py"), None)
r.check("A: … it appears as FAIL in the log, below it its reason (stdout), its stderr on stderr",
        fail_line is not None and "Grund: absichtlich rot (Probe 4711)" in z1[fail_line + 1]
        and "stderr der roten Suite" in execution1.stderr, f"{z1}\nstderr: {execution1.stderr[-300:]}")
r.check("A: the skip reason is there in full, including the install command",
        "  skip test_c_skip.py (uebersprungen: Modul 'xyz' fehlt — pip install 'tinysesam[xyz]')" in z1,
        f"{z1}")
r.check("A: the tally is correct", "2/4 grün, 1 übersprungen, 1 fehlgeschlagen" in z1, f"{z1[-2:]}")
row = [z.split()[1] for z in z1 if z.split()[:1] and z.split()[0] in ("ok", "FAIL", "skip")]
r.check("B: output in the order of the list, although the first suite finishes last",
        row == ["test_a_gruen.py", "test_b_rot.py", "test_c_skip.py", "test_d_gruen.py"], f"{row}")
r.check("B: two runs, one log (identical line by line)",
        execution1.stdout == execution2.stdout and execution1.returncode == execution2.returncode,
        f"\n{execution1.stdout}\n---\n{execution2.stdout}")

# ── C: really simultaneous — and with one job really serial ──────────────────────────────────
# Simultaneous: three suites wait for each other (each drops a marker and waits for the two
# others). Started one after another, the first waits in vain and turns red.
hit = Path(tempfile.mkdtemp(prefix="sammel-treff-"))
match = """\
    import os, sys, time
    ordner = os.environ["COLLECT_MEETING_POINT"]
    open(os.path.join(ordner, os.path.basename(__file__)), "w").close()
    frist = time.monotonic() + 15
    while len(os.listdir(ordner)) < 3 and time.monotonic() < frist:
        time.sleep(0.02)
    da = len(os.listdir(ordner))
    print(f"{da} von 3 da")
    sys.exit(0 if da == 3 else 1)
"""
c = Path(tempfile.mkdtemp(prefix="sammel-c-"))
execution_c = collect_run([suite(c, f"test_treffen_{i}.py", match) for i in (1, 2, 3)], 3,
                    COLLECT_MEETING_POINT=str(hit))
r.check("C: with 3 jobs 3 suites really run simultaneously (they meet)",
        execution_c.returncode == 0, f"Exit {execution_c.returncode}\n{execution_c.stdout[-500:]}")

# Serial: every suite writes start and end into a shared log. `test_ldap.py` is
# in `LONG_FIRST` — with one job that must change NOTHING about the order.
trace = Path(tempfile.mkdtemp(prefix="sammel-spur-")) / "spur.txt"
traces = """\
    import os, time
    name = os.path.basename(__file__)
    with open(os.environ["COLLECT_TRACE"], "a") as f:
        f.write(f"an {name}\\n")
    time.sleep(0.15)
    with open(os.environ["COLLECT_TRACE"], "a") as f:
        f.write(f"aus {name}\\n")
"""
s = Path(tempfile.mkdtemp(prefix="sammel-s-"))
serial = [suite(s, n, traces) for n in ("test_a.py", "test_ldap.py", "test_z.py")]
assert "test_ldap.py" in run_all.LONG_FIRST
execution_s = collect_run(serial, 1, COLLECT_TRACE=str(trace))
read = trace.read_text(encoding="utf-8").split("\n")[:-1] if trace.exists() else []
r.check("C: CI_TEST_JOBS=1 is the serial run — one after the other, in list order",
        execution_s.returncode == 0 and read == ["an test_a.py", "aus test_a.py", "an test_ldap.py",
                                               "aus test_ldap.py", "an test_z.py", "aus test_z.py"],
        f"Exit {execution_s.returncode}, Spur {read}")
r.check("C: … and says so", lines(execution_s)[:1] == ["▸ Test-Jobs: 1"], f"{lines(execution_s)[:1]}")

# The start order: with several jobs the long ones first, otherwise the list.
names = ["/x/test_a.py", "/x/test_ldap.py", "/x/test_b.py", "/x/test_prebooking_pending.py"]
r.check("C: start order with one job = list; with several the long ones first, rest in list order",
        run_all.start_order(names, 1) == [0, 1, 2, 3]
        and run_all.start_order(names, 4) == [1, 3, 0, 2],
        f"{run_all.start_order(names, 1)} / {run_all.start_order(names, 4)}")
be_missing = [n for n in run_all.LONG_FIRST if not (ROOT / "tests" / n).exists()]
r.check("C: every entry in LONG_FIRST is still a suite", not be_missing, f"{be_missing}")

# ── D: CI_TEST_JOBS / `CI_KERNE` ──────────────────────────────────────────────────────────────
r.check("D: CI_TEST_JOBS takes precedence over CI_KERNE; whitespace does not matter",
        run_all.jobs_determine(" 3 ", "7") == 3 and run_all.jobs_determine("1", "7") == 1)
r.check("D: without CI_TEST_JOBS, CI_KERNE applies (the number of the runner)",
        run_all.jobs_determine("", "5") == 5 and run_all.jobs_determine("", " 1 ") == 1)
# No detection: `os.cpu_count()` sees all cores of the host in the container, not the quota.
r.check("D: without both the fixed default 2 — no detection of the cores",
        run_all.jobs_determine("", "") == 2 == run_all.JOBS_DEFAULT,
        f"{run_all.jobs_determine('', '')}")
for broken in ("0", "zwei"):
    try:
        run_all.jobs_determine("", broken)
        declined = False
    except ValueError as error:
        declined = "CI_KERNE" in str(error)
    r.check(f"D: CI_KERNE={broken!r} is an error, not a silent default", declined)
trace_d = Path(tempfile.mkdtemp(prefix="sammel-d-")) / "spur.txt"
for broken in ("0", "-2", "zwei", "1.5"):
    execution_d = collect_run([serial[0]], broken, COLLECT_TRACE=str(trace_d))
    r.check(f"D: CI_TEST_JOBS={broken!r} aborts instead of silently taking a default",
            execution_d.returncode not in (0, 1) and "CI_TEST_JOBS" in execution_d.stderr
            and "Test-Jobs" not in execution_d.stdout and not trace_d.exists(),
            f"Exit {execution_d.returncode}: {execution_d.stdout[-200:]} {execution_d.stderr[-200:]}")
execution_0 = collect_run([from_suites[2]], 2)
r.check("D: the floor stays — only skipped is not a green run",
        execution_0.returncode == 1 and "keine einzige Suite" in execution_0.stderr, f"Exit {execution_0.returncode}")

# ── E: the warning filter works through the starter ──────────────────────────────────────────
e = Path(tempfile.mkdtemp(prefix="sammel-e-"))
execution_e = collect_run([suite(e, "test_w_alt.py", """\
        import warnings
        warnings.warn_explicit("TinySesam.alt ist veraltet", DeprecationWarning, "x.py", 1,
                               module="tinysesam.router")
    """), from_suites[3]], 2)
r.check("E: a deprecated name, called from the package, makes the suite red — also in parallel",
        execution_e.returncode == 1 and "  FAIL test_w_alt.py" in lines(execution_e)
        and "DeprecationWarning" in execution_e.stderr, f"Exit {execution_e.returncode}\n{execution_e.stdout[-300:]}")

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
    with open(os.environ["COLLECT_PROBE"], "w") as f:
        json.dump(aus, f)
"""


def read_probe(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def lowered(p: dict) -> bool:
    if not p:
        return False
    n, rr, pp = _starter.SCRYPT_TEST["n"], _starter.SCRYPT_TEST["r"], _starter.SCRYPT_TEST["p"]
    if p["scrypt"] != [n, rr, pp]:
        return False
    if p["argon"]:
        destination = [_starter.ARGON2_TEST["memory_cost"], _starter.ARGON2_TEST["time_cost"],
                _starter.ARGON2_TEST["parallelism"]]
        part = f"m={destination[0]},t={destination[1]},p={destination[2]}"
        return p["argon_aktiv"] == destination and p["hash"][3] == part and p["dummy"][3] == part
    return p["hash"] == ["scrypt", str(n), str(rr), str(pp)] and p["dummy"] == p["hash"]


def production(p: dict) -> bool:
    if not p or p["scrypt"] != [2 ** 15, 8, 3]:
        return False
    if p["argon"]:
        return p["argon_aktiv"] == p["argon_vorgabe"] and p["dummy"][3] == p["hash"][3]
    return p["hash"] == ["scrypt", "32768", "8", "3"] and p["dummy"] == p["hash"]


f = Path(tempfile.mkdtemp(prefix="sammel-f-"))
probe_in_execution = f / "im_lauf.json"
execution_f = collect_run([suite(f, "test_probe.py", PROBE)], 2, COLLECT_PROBE=str(probe_in_execution))
p_execution = read_probe(probe_in_execution)
r.check("F: in the collective run a suite calculates with the lowered parameters — hash AND dummy",
        execution_f.returncode == 0 and lowered(p_execution), f"Exit {execution_f.returncode}, {p_execution}")
r.check("F: … method and check remain the same (right/wrong, no renewal)",
        p_execution.get("stimmt") is True and p_execution.get("falsch") is False
        and p_execution.get("erneuern") is False, f"{p_execution}")
r.check("F: the starter does not import tinysesam before the suite (import order unchanged)",
        p_execution.get("vorher") == [], f"{p_execution.get('vorher')}")

# Started directly — and with variables that look like a switch: production values.
probe_direct = f / "direkt.json"
direct = subprocess.run([sys.executable, str(f / "test_probe.py")], cwd=str(ROOT), timeout=60,
                        env={**os.environ, "PYTHONPATH": str(ROOT), "COLLECT_PROBE": str(probe_direct),
                             "TINYSESAM_SCRYPT_N": "16", "TINYSESAM_SCRYPT_P": "1",
                             "TINYSESAM_ARGON2_MEMORY_COST": "8", "TINYSESAM_ARGON2_TIME_COST": "1",
                             "TINYSESAM_HASH_PARAMS": "test", "CI_TEST_JOBS": "1"},
                        capture_output=True, text=True)
p_direct = read_probe(probe_direct)
r.check("F: started directly the same suite calculates with the production values, variables or not",
        direct.returncode == 0 and production(p_direct),
        f"Exit {direct.returncode}, {p_direct} {direct.stderr[-300:]}")

# The exceptions: under the name of a suite from PRODUCTION_VALUES it stays with the real values.
probe_exception = f / "ausnahme.json"
exception = next(iter(sorted(_starter.PRODUCTION_VALUES)))
g = Path(tempfile.mkdtemp(prefix="sammel-g-"))
execution_g = collect_run([suite(g, exception, PROBE)], 2, COLLECT_PROBE=str(probe_exception))
p_exception = read_probe(probe_exception)
r.check(f"F: a suite from PRODUKTIONSWERTE ({exception}) also calculates with the real values in the collective run",
        execution_g.returncode == 0 and production(p_exception), f"Exit {execution_g.returncode}, {p_exception}")
r.check("F: every exception is a suite and has a reason",
        all((ROOT / "tests" / n).exists() and str(g_).strip()
            for n, g_ in _starter.PRODUCTION_VALUES.items()), f"{_starter.PRODUCTION_VALUES}")

# Which suites belong on the list? Those that touch hash internals or measure runtime —
# decided on the source (AST, i.e. without comments and strings), not from memory.
TRIGGER = {"_SCRYPT", "_SCRYPT_OLD", "_MAXMEM", "_PH", "_DUMMY", "needs_rehash",
             "check_needs_rehash", "dummy_verify", "PasswordHasher", "scrypt", "perf_counter"}


def trigger(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return ({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            | {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}) \
        & TRIGGER


found = {p.name: sorted(trigger(p)) for p in sorted((ROOT / "tests").glob("test_*.py"))
            if p.name != Path(__file__).name and trigger(p)}
r.check("F: every suite that checks hash parameters or runtimes is in PRODUCTION_VALUES — "
        "and only those", set(found) == set(_starter.PRODUCTION_VALUES),
        f"found {found}, entered {sorted(_starter.PRODUCTION_VALUES)} — such a suite "
        "would be empty with lowered parameters (tests/_starter.py)")

# ── G: no switch in the package ──────────────────────────────────────────────────────────────
PACKAGE = ROOT / "tinysesam"
pw_tree = ast.parse((PACKAGE / "passwords.py").read_text(encoding="utf-8"))
pw_names = ({n.attr for n in ast.walk(pw_tree) if isinstance(n, ast.Attribute)}
            | {n.id for n in ast.walk(pw_tree) if isinstance(n, ast.Name)}
            | {a.name for n in ast.walk(pw_tree) if isinstance(n, (ast.Import, ast.ImportFrom))
               for a in n.names})
r.check("G: tinysesam/passwords.py reads no environment",
        not pw_names & {"environ", "environb", "getenv", "getenvb", "putenv"},
        f"{sorted(pw_names & {'environ', 'environb', 'getenv', 'getenvb', 'putenv'})}")
package_imports = [n.module or "." for n in ast.walk(pw_tree)
                if isinstance(n, ast.ImportFrom) and (n.level or (n.module or "").startswith("tinysesam"))]
r.check("G: … and imports nothing from the package (so no configuration either)",
        not package_imports, f"{package_imports}")


def constant(node, known: set) -> bool:
    """Is the expression built from literals (numbers, operators, known constants)?"""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp):
        return constant(node.left, known) and constant(node.right, known)
    if isinstance(node, ast.Name):
        return node.id in known
    return False


assignments = {z.targets[0].id: z.value for z in pw_tree.body
               if isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name)}
known = {"_MAXMEM"} if constant(assignments.get("_MAXMEM"), set()) else set()
scrypt_literal = all(
    isinstance(assignments.get(k), ast.Call) and not assignments[k].args
    and all(constant(kw.value, known) for kw in assignments[k].keywords)
    for k in ("_SCRYPT", "_SCRYPT_OLD"))
ph_value = next((z.value for z in ast.walk(pw_tree) if isinstance(z, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "_PH" for t in z.targets)), None)
r.check("G: the scrypt parameters are literals, argon2 runs with the defaults of argon2-cffi",
        scrypt_literal and bool(known) and isinstance(ph_value, ast.Call)
        and not ph_value.args and not ph_value.keywords,
        "a parameter comes from an expression — then it can come from outside")
from tinysesam import passwords as _pw  # noqa: E402
r.check("G: hash_password takes only the password (no cost parameter from outside)",
        list(inspect.signature(_pw.hash_password).parameters) == ["pw"],
        f"{inspect.signature(_pw.hash_password)}")

PROTECTED = {"_SCRYPT", "_SCRYPT_OLD", "_MAXMEM", "_PH", "_DUMMY"}
setter = []
for file in sorted(PACKAGE.rglob("*.py")):
    tree = ast.parse(file.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        destinations = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(
            n, (ast.AugAssign, ast.AnnAssign)) else []
        for t in destinations:
            if isinstance(t, ast.Attribute) and t.attr in PROTECTED:
                setter.append(f"{file.relative_to(ROOT)}:{n.lineno}")
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "setattr"
                and len(n.args) > 1 and isinstance(n.args[1], ast.Constant)
                and n.args[1].value in PROTECTED):
            setter.append(f"{file.relative_to(ROOT)}:{n.lineno}")
r.check("G: no module of the package overrides the hash parameters from outside", not setter, f"{setter}")

from tinysesam import TinySesamConfig  # noqa: E402
SUSPICIOUS = ("scrypt", "argon", "kdf", "hash_cost", "memory_cost", "time_cost", "work_factor")
fields = [x.name for x in dataclasses.fields(TinySesamConfig) if any(v in x.name for v in SUSPICIOUS)]
variables = sorted({k.value for d in PACKAGE.rglob("*.py")
                    for k in ast.walk(ast.parse(d.read_text(encoding="utf-8")))
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                    and k.value.startswith("TINYSESAM_")
                    and any(v in k.value.lower() for v in SUSPICIOUS + ("hash",))})
r.check("G: no setting and no TINYSESAM_ variable for hash cost", not fields and not variables,
        f"fields {fields}, variables {variables}")

# ── H: the gate does not build the website into the tree ─────────────────────────────────────
# Until the rework `scripts/check.sh` built into `_site/` in the tree and deleted the folder afterwards — a
# `_site/` of one's own was gone with it, and two runs in the same tree cleared the site away
# from under each other. Checked on a COPY of the versioned files (no suite writes into
# the real tree) with an existing `_site/`; a stand-in replaces the collective run, otherwise everything would run
# a second time here. `scripts/` does not belong in the source package — there is nothing to check there.
items = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT), capture_output=True)
if items.returncode != 0 or not (ROOT / "scripts" / "check.sh").exists():
    print("  H: no Git checkout with scripts/check.sh (source package) — the gate does not exist here")
else:
    copy = Path(tempfile.mkdtemp(prefix="sammel-h-")) / "baum"
    for rel in (n for n in items.stdout.decode("utf-8").split("\0") if n):
        if (ROOT / rel).is_file():
            (copy / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, copy / rel)
    (copy / "_site").mkdir()
    (copy / "_site" / "eigen.txt").write_text("gehört dem Menschen, nicht dem Tor\n", encoding="utf-8")
    representative = copy.parent / "python-stellvertreter"
    representative.write_text(f'''#!/bin/sh
if [ "$1" = "tests/run_all.py" ]; then echo "Sammellauf: Stellvertreter"; exit 0; fi
exec "{sys.executable}" "$@"
''', encoding="utf-8")
    representative.chmod(representative.stat().st_mode | stat.S_IXUSR)
    before_h = sorted(str(x.relative_to(copy)) for x in copy.rglob("*"))
    gate = subprocess.run(["bash", "scripts/check.sh", "--fast"], cwd=str(copy), timeout=120,
                         env={**os.environ, "PYTHON": str(representative), "PYTHONPATH": str(copy)},
                         capture_output=True, text=True)
    afterwards_h = sorted(str(x.relative_to(copy)) for x in copy.rglob("*") if "__pycache__" not in x.parts)
    r.check("H: check.sh builds the website (exit 0, all required files in the build)",
            gate.returncode == 0 and "all green" in gate.stdout,
            f"Exit {gate.returncode}\n{gate.stdout[-400:]}{gate.stderr[-400:]}")
    r.check("H: … an existing _site/ stays untouched, and nothing new arises in the tree",
            (copy / "_site" / "eigen.txt").exists() and afterwards_h == before_h,
            f"eigen.txt present: {(copy / '_site' / 'eigen.txt').exists()}, new: "
            f"{sorted(set(afterwards_h) - set(before_h))}, gone:{sorted(set(before_h) - set(afterwards_h))}")


# ── I: the failed check is in the log, even with long output ─────────────────────────────────
# Until 2026-09-28 only the end of the output (2000 characters) stood under `FAIL`. If an early
# check failed, its line was missing — seen in the CI job `repeat` at test_prebooking_pending.py.
# (Mutation probe: return only `end` in `_fail_output` → red.)
folder_i = Path(tempfile.mkdtemp(prefix="sammel-i-"))
lang = suite(folder_i, "test_lang_rot.py", """\
    import sys
    print("  FEHL frühe Prüfung (Probe 4712): erwartet 1, war 2")
    for i in range(120):
        print(f"  ok   spätere Prüfung {i:03d}, die das Ende der Ausgabe füllt")
    print("120 ok, 1 Fehler")
    sys.exit(1)
""")
execution_i = collect_run([lang], 1)
from_i = execution_i.stdout
r.check("I: the early FEHL line is under FAIL, although more than 2000 characters follow",
        execution_i.returncode == 1 and "FEHL frühe Prüfung (Probe 4712): erwartet 1, war 2" in from_i
        and from_i.index("FAIL test_lang_rot.py") < from_i.index("Probe 4712"),
        from_i[-600:])
r.check("I: … the end of the output is still there and begins at a line boundary",
        "120 ok, 1 Fehler" in from_i and "── Ende der Ausgabe ──" in from_i
        and from_i.split("── Ende der Ausgabe ──\n", 1)[-1].startswith("  ok   spätere Prüfung"),
        from_i.split("── Ende der Ausgabe ──", 1)[-1][:120])

# ── J: own throwaway directory per suite───────────────────────────────────────────────────
# The promise on which the parallel run and “tests are repeatable” stand. Until 2026-10-01 no
# suite checked it: a shared, never deleted directory for all suites stayed green.
# (Mutation probe: take a fixed directory in `run_suite` and not delete it → red.)
folder_j = Path(tempfile.mkdtemp(prefix="sammel-j-"))
trace_j = Path(tempfile.mkdtemp(prefix="sammel-j-spur-"))
body_j = """\
    import json, os, sys, tempfile
    from pathlib import Path
    werte = {k: os.environ.get(k, "") for k in ("TMPDIR", "HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
                                                "XDG_DATA_HOME")}
    werte["gettempdir"] = tempfile.gettempdir()
    Path(os.environ["COLLECT_TRACE_J"], Path(sys.argv[0]).name + ".json").write_text(json.dumps(werte))
"""
execution_j = collect_run([suite(folder_j, "test_j1.py", body_j), suite(folder_j, "test_j2.py", body_j)],
                    2, COLLECT_TRACE_J=str(trace_j))
traces = [json.loads(f.read_text()) for f in sorted(trace_j.glob("*.json"))]
r.check("J: both suites ran and have put down their environment",
        execution_j.returncode == 0 and len(traces) == 2, f"Exit {execution_j.returncode}, {len(traces)} traces")
if len(traces) == 2:
    one, two = traces
    r.check("J: TMPDIR, HOME, XDG_* and gettempdir point to the same directory of the suite",
            all(one[k] and one[k].startswith(one["TMPDIR"]) for k in one)
            and all(two[k] and two[k].startswith(two["TMPDIR"]) for k in two), f"{traces}")
    r.check("J: every suite has a directory of its own", one["TMPDIR"] != two["TMPDIR"], f"{traces}")
    r.check("J: after the run both directories are gone",
            not os.path.exists(one["TMPDIR"]) and not os.path.exists(two["TMPDIR"]), f"{traces}")

sys.exit(r.done())

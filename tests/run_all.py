#!/usr/bin/env python3
"""Test runner for TinySesam — runs all (or selected) tests/test_*.py.

    python tests/run_all.py                # all suites
    python tests/run_all.py test_core.py   # only specific ones

Exit code 0 = all green, 1 = at least one failure. No pytest needed (suites are
standalone assert scripts).

A suite that lacks an optional dependency ends ITSELF with exit 77
(`tests/_kit/voraussetzung.py`) — then it counts as skipped. Every other
failure is a failure. This distinction matters more than it looks:
previously the runner guessed from stderr and could not tell "the test needs an extra" from
"the library crashes without an extra" — which kept the second case
invisible for months.

Each suite runs in its OWN throwaway directory (TMPDIR/HOME/XDG_* point
there, afterwards it is deleted). That way no state from one run can influence the next
and no suite can disturb another — the tests are repeatable.
Proof: `ci-local --full` runs the suite twice in the same tree.

PARALLEL: The suites run concurrently, `CI_TEST_JOBS` (integer ≥ 1) sets how
many; without it `CI_KERNE` (set by the CI runner), without both 2. The output of each suite is
buffered and printed in the fixed order of the file names — the log reads like
a serial run and, for the same result, is identical line by line. `CI_TEST_JOBS=1`
is the serial run of old: one suite after the other, in that order.
Prerequisite: no suite writes to fixed paths in the tree or shares anything with
another (port, file, database) — each has its own throwaway directory (see above).

Each suite is started via `tests/_starter.py`: it lowers the hash parameters in the test process
(it explains why and for which suites not). The package itself has no switch for this.
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
# Exit code with which a suite says ITSELF: "a prerequisite is missing, do not count me".
# 77 is the automake convention. Why a code and not a text search in stderr:
#
# Until 2026-09-21 the runner guessed from `ModuleNotFoundError` + a list of names whether a
# failure was "only" a missing optional dependency. That cannot tell apart two cases
# that are completely different:
#   (a) The SUITE needs an extra that is not there  -> skipping is right.
#   (b) The LIBRARY crashes because it needs an extra it should not have needed
#       -> that is a bug, and a serious one.
# Case (b) really happened: `pip install tinysesam` + default configuration ended with
# `ModuleNotFoundError: webauthn` (passkey_enabled was True), and the runner booked
# that as "skipped". The suite was green because it did not measure.
#
# Now "skipped" is a PLEDGE of the suite, not a guessing game over foreign stderr.
SKIP_EXIT = 77

#: Starts each suite (lowers the hash parameters in the test process, see there).
STARTER = os.path.join(HERE, "_starter.py")
JOBS_VARIABLE = "CI_TEST_JOBS"
#: The worker count the CI runner prescribes. Applies when `CI_TEST_JOBS` is missing.
KERNE_VARIABLE = "CI_KERNE"
#: Without both variables: two jobs — a safe default, not a detection (see `jobs_bestimmen`).
JOBS_VORGABE = 2

#: These suites start FIRST in a parallel run — the slowest, measured 2026-09-27 (0.22.0).
#: The list only determines WHEN a suite starts; result and order of the output stay
#: the same. Without it `test_browser.py` (~80 s, almost only waiting for Chrome) and
#: `test_prebooking_pending.py` (10 s, deliberate wait) started last and fixed the end of the
#: whole run. With one job it does not apply — that is the serial run of old. A
#: stale entry costs time, never a result; that every entry is still a suite is checked by
#: `tests/test_runner.py`.
LANGE_ZUERST = ("test_browser.py", "test_ldap.py", "test_prebooking_pending.py",
                "test_audit_round2.py", "test_t13_decisions.py", "test_repo.py",
                "test_admin_account.py", "test_security_findings.py", "test_hardening2.py")



#: This much of the end of a red suite's output goes into the log — the context.
FAIL_ENDE = 2000


def _fail_ausgabe(aus: str) -> str:
    """What goes under `FAIL <suite>`: every failed check (`FEHL …`) in full, then the end
    of the output from a line boundary.

    Until 2026-09-28 only the end (2000 characters) was shown here. A suite prints its checks in the
    order in which they run — if an early one failed, its `FEHL` line was before the excerpt
    and missing from the log. Seen in the CI job `repeat`: `FAIL test_prebooking_pending.py`, below it
    "ufschub" and 42 ok lines, but not WHAT was red. A flaky test that cannot be reproduced
    locally cannot be explained without this line.
    """
    ende = aus[-FAIL_ENDE:]
    if len(aus) > FAIL_ENDE and "\n" in ende:
        ende = ende.split("\n", 1)[1]          # do not start in the middle of a word
    davor = [z for z in aus[: len(aus) - len(ende)].splitlines() if z.lstrip().startswith("FEHL ")]
    kopf = ("  ── gescheiterte Prüfungen oberhalb des Ausschnitts ──\n" + "\n".join(davor) + "\n"
            "  ── Ende der Ausgabe ──\n") if davor else ""
    return kopf + ende

def warnfilter() -> str:
    """`PYTHONWARNINGS`: a deprecated TinySesam name (stage C), called FROM the package itself, is
    an error — in every suite, not just in one (0.22.0, PO decision 2026-09-26).

    Since 0.22.0 the implementation of the internal names is called `_name`; the old name is an
    alias that warns. If code in the package still calls the old name, nobody would see it: a
    `DeprecationWarning` from a library module is not shown by Python at all without a filter. The
    AST search in `tests/test_api_surface.py` finds `auth.check_password(…)`, but not
    `getattr(auth, name)` — this filter finds both as soon as a suite goes through the path.

    A `-W` filter compares the module LITERALLY (no prefix), hence one line per module; the
    message begins with `TinySesam.` (see `tinysesam/_deprecated.py`). Foreign warnings, including
    foreign `DeprecationWarning`s from tinysesam code, are left untouched.
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
    """The environment of a suite: own throwaway directory, package on the path, warning filter."""
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


def jobs_bestimmen(roh=None, kerne=None) -> int:
    """How many suites run concurrently: `CI_TEST_JOBS`, else `CI_KERNE`, else 2.

    No detection of the cores: until 2026-10-01 this had `os.cpu_count() // 2`. In a container
    `os.cpu_count()` sees all cores of the host, not the CPU quota of the container — a runner with a
    two-core quota on a host with twelve started six jobs, and several runners on one machine
    crushed each other. The number therefore comes from the one who knows the quota: the runner
    (`CI_KERNE`). `CI_TEST_JOBS` remains the manual switch, e.g. `1` for the serial run.

    A set value that is not an integer ≥ 1 is an error (`ValueError`) — not silently
    the default: whoever sets `CI_TEST_JOBS=1` for a serial run and makes a typo should
    learn about it, instead of taking a parallel run for a serial one.
    """
    roh = os.environ.get(JOBS_VARIABLE, "") if roh is None else roh
    kerne = os.environ.get(KERNE_VARIABLE, "") if kerne is None else kerne
    for variable, wert in ((JOBS_VARIABLE, roh), (KERNE_VARIABLE, kerne)):
        if not wert.strip():
            continue
        try:
            jobs = int(wert.strip())
        except ValueError:
            jobs = 0
        if jobs < 1:
            raise ValueError(f"{variable}={wert!r} — erwartet eine ganze Zahl ≥ 1")
        return jobs
    return JOBS_VORGABE


def startreihenfolge(files, jobs) -> list:
    """The indices of `files` in the order in which the suites start.

    One job: exactly the order of the list (the serial run). Several: first `LANGE_ZUERST`,
    then the rest in list order."""
    if jobs <= 1:
        return list(range(len(files)))
    rang = {name: i for i, name in enumerate(LANGE_ZUERST)}
    return sorted(range(len(files)),
                  key=lambda i: (rang.get(os.path.basename(files[i]), len(rang)), i))


def suite_fahren(path):
    """One suite in its own throwaway directory; output buffered (`CompletedProcess`)."""
    name = os.path.basename(path)
    # Each suite gets its OWN throwaway directory: TMPDIR, HOME and the
    # XDG paths point there. That way no state can influence a second run
    # -- and no suite can disturb the next. Afterwards it is deleted.
    # (Policy: "tests are repeatable"; proof: `ci-local --full`.)
    sandbox = tempfile.mkdtemp(prefix=f"tinysesam-{name[:-3]}-")
    env = umgebung(sandbox)
    try:
        return subprocess.run([sys.executable, STARTER, path], cwd=ROOT, env=env,
                              capture_output=True, text=True)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def main(argv):
    # --no-browser: the browser test is the slowest. Only for interim runs, never before a push.
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
    # Started according to `startreihenfolge` (with one job: the list, i.e. the serial run).
    # Printed in the order of the list, as soon as a suite AND all before it are done
    # — never in the order in which they happen to finish.
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
                # The suite bailed out itself — the reason is in its own output.
                grund = (r.stdout or r.stderr or "").strip().splitlines()
                # Do not truncate: the line names the command to install it (`pip install 'tinysesam[…]'`),
                # and a truncation before the closing bracket looked like a typo in the command.
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
        # On Ctrl-C do not start any more waiting suites; let running ones finish.
        pool.shutdown(wait=True, cancel_futures=True)
    total = len(files)
    print(f"\n{len(ok)}/{total} grün, {len(skipped)} übersprungen, {len(failed)} fehlgeschlagen")
    if failed:
        return 1

    # A floor against "green because nothing was measured".
    #
    # Up to here "nothing failed" was enough for exit 0 — even for "0 green, everything
    # skipped". That is exactly what the run looked like in a git worktree: the hygiene suites took
    # `.git` (a file there) for "no repo", bailed out, and `scripts/check.sh` printed
    # "✓ alles grün" above it. The same class of bug that exit 77 was introduced against, just
    # one level higher.
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

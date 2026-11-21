"""Starts ONE suite for the combined run — with cheap hash parameters, in this process only.

    python tests/_starter.py tests/test_core.py     # this is how `tests/run_all.py` calls each suite

WHY: With the production values, a password hash costs ~110 ms measured (scrypt, the fallback
without `[argon2]`) or ~26–35 ms (argon2). That is intentional — in production. In a test run
every suite computes dozens of them, and none checks anything that a cheap hash would not check
just as well: format, algorithm, right/wrong input and all the paths around it stay the same.
Measured before this file (0.22.0): in the slim run (without extras) **about two thirds** of the
suite runtime went into scrypt, in the full run a quarter to a half into argon2.

WHAT NOT: The package gets NO switch for this. `tinysesam.passwords` reads neither an
environment variable nor a setting for its parameters — such a switch would be a way to run
production with weakened hashes, and it would hang on every container that inherits the
variable. The parameters are lowered HERE, in the test process, by monkeypatch; the guard
`tests/test_runner.py` pins both. Whoever starts a suite directly (`python tests/test_x.py`)
computes with the production values, and so does every subprocess a suite starts.

EXCEPTIONS (`PRODUCTION_VALUES`): suites that check the parameters or the runtime of the hashing
THEMSELVES run with the real values — with lowered ones their checks would be empty (a dummy
verify that costs nothing is indistinguishable from "no dummy verify"). Which suite belongs
here is decided by a guard in `tests/test_runner.py` from the source text of the suites, not
by memory.

The lowering happens only when the suite itself imports `tinysesam.passwords` (import hook). An
up-front import from here would change the import order of the suite — and some suites hide
modules on purpose before the first import to simulate "without extra".

SECOND JOB — closing a database waits for the background outbox (2026-11-20). TinySesam sends its
notices (new access, lockout) from a worker thread (`tinysesam.mailer.Outbox`), and the job uses the
store's connection: it reads the account and writes an `audit` row. Many suites close that
connection themselves (`auth.store.db.close()`) to start the library again on the same file —
right after an action that enqueued a notice. If the worker was still inside SQLite at that moment,
`sqlite3` freed the connection under it: a segmentation fault, the suite died without a word
(`test_values_english.py`, three times in CI; reproduced locally in 3 of 3 attempts of 200 rounds of
create key → close). Production never closes the connection under a running worker; only the tests
do. So here, in the test process, every `sqlite3` connection is created with `_DrainingConnection`,
whose `close()` first waits until every outbox has finished its queued jobs. The guard
`tests/test_runner.py` (K) checks it. A suite started directly (`python tests/test_x.py`) closes
without waiting, as before.
Since T-67 the library has its own orderly shutdown (`TinySesam.close()`: refuse new jobs, drain, close the store
under its lock) and the suites call it instead of `auth.store.db.close()`; `tests/test_close.py` proves it without
this file. The drain here stays as a safety net for a suite that closes a connection by hand.
"""
from __future__ import annotations

import os
import runpy
import sqlite3
import sys
import threading
import weakref

#: Suite → reason. These suites compute with the production values.
PRODUCTION_VALUES = {
    "test_legacy_data.py": "checks the scrypt parameters itself (old format 0.17.0, needs_rehash)",
    "test_hardening2.py": "measures that the dummy verify takes as long as a real verify",
}

#: scrypt in the test run: N=2^4 instead of 2^15, p=1 instead of 3 (r stays). Formats and paths stay
#: the same, only the work is gone (measured ~0.03 ms instead of ~110 ms).
SCRYPT_TEST = {"n": 2 ** 4, "r": 8, "p": 1}
#: argon2 in the test run: the smallest argon2 allows (m = 8 KiB at p = 1), one round.
ARGON2_TEST = {"time_cost": 1, "memory_cost": 8, "parallelism": 1}

MODULE = "tinysesam.passwords"
#: The module of the background outbox, see “SECOND JOB”.
OUTBOX_MODULE = "tinysesam.mailer"


def lower(passwords) -> None:
    """Lower the parameters of a freshly loaded `tinysesam.passwords` — in this process."""
    passwords._SCRYPT = {**passwords._SCRYPT, **SCRYPT_TEST}
    if passwords._ARGON:
        passwords._PH = passwords.PasswordHasher(**ARGON2_TEST)
    # The dummy for the timing balance was created at import with the production values. Recreate
    # it with the active algorithm, otherwise every dummy verify would still cost the full time.
    passwords._DUMMY = passwords.hash_password("tinysesam-timing-dummy")


#: Every outbox of this process (weak: a dropped instance does not stay alive for this).
_OUTBOXES: "weakref.WeakSet" = weakref.WeakSet()


def track_outboxes(mailer) -> None:
    """Note every `Outbox` that the freshly loaded `tinysesam.mailer` creates — in this process."""
    original = mailer.Outbox.__init__

    def __init__(self, *args, **kwargs):
        original(self, *args, **kwargs)
        _OUTBOXES.add(self)
    mailer.Outbox.__init__ = __init__


def drain_outboxes() -> None:
    """Wait until every outbox has run what it was given (`Outbox.wait`, at most 10 s per job).

    Not from a worker of an outbox itself: it would wait for its own job."""
    if threading.current_thread().name.startswith("tinysesam-"):
        return
    for box in list(_OUTBOXES):
        box.wait()


class _DrainingConnection(sqlite3.Connection):
    """A `sqlite3` connection whose `close()` first lets the background jobs finish."""

    def close(self):
        drain_outboxes()
        super().close()


def _connect(*args, **kwargs):
    kwargs.setdefault("factory", _DrainingConnection)
    return _CONNECT(*args, **kwargs)


_CONNECT = sqlite3.connect


class _AfterTheLoad:
    """Import hook: loads `module` as usual and calls `then(module)` afterwards."""

    def __init__(self, module: str, then):
        self.module, self.then = module, then

    def find_spec(self, name, path=None, destination=None):
        if name != self.module:
            return None
        sys.meta_path.remove(self)                 # once is enough; otherwise it would find itself
        for finder in sys.meta_path:
            spec = finder.find_spec(name, path, destination) if hasattr(finder, "find_spec") else None
            if spec is not None and spec.loader is not None:
                load = spec.loader.exec_module

                def exec_module(module, _load=load, _then=self.then):
                    _load(module)
                    _then(module)
                spec.loader.exec_module = exec_module
                return spec
        return None


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("Call: python tests/_starter.py <suite.py> [arguments …]")
    suite = os.path.abspath(argv[0])
    # Like a direct start: sys.argv[0] is the suite, its directory is first on the path.
    sys.argv = [suite, *argv[1:]]
    sys.path[0] = os.path.dirname(suite)
    if os.path.basename(suite) not in PRODUCTION_VALUES:
        if MODULE in sys.modules:                   # pragma: no cover — nobody imports it here
            lower(sys.modules[MODULE])
        else:
            sys.meta_path.insert(0, _AfterTheLoad(MODULE, lower))
    sys.meta_path.insert(0, _AfterTheLoad(OUTBOX_MODULE, track_outboxes))
    sqlite3.connect = _connect
    runpy.run_path(suite, run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])

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
"""
from __future__ import annotations

import os
import runpy
import sys

#: Suite → reason. These suites compute with the production values.
PRODUCTION_VALUES = {
    "test_legacy_data.py": "prüft die scrypt-Parameter selbst (Altformat 0.17.0, needs_rehash)",
    "test_hardening2.py": "misst, dass der Dummy-Verify so lange rechnet wie ein echter Verify",
}

#: scrypt in the test run: N=2^4 instead of 2^15, p=1 instead of 3 (r stays). Formats and paths stay
#: the same, only the work is gone (measured ~0.03 ms instead of ~110 ms).
SCRYPT_TEST = {"n": 2 ** 4, "r": 8, "p": 1}
#: argon2 in the test run: the smallest argon2 allows (m = 8 KiB at p = 1), one round.
ARGON2_TEST = {"time_cost": 1, "memory_cost": 8, "parallelism": 1}

MODULE = "tinysesam.passwords"


def lower(passwords) -> None:
    """Lower the parameters of a freshly loaded `tinysesam.passwords` — in this process."""
    passwords._SCRYPT = {**passwords._SCRYPT, **SCRYPT_TEST}
    if passwords._ARGON:
        passwords._PH = passwords.PasswordHasher(**ARGON2_TEST)
    # The dummy for the timing balance was created at import with the production values. Recreate
    # it with the active algorithm, otherwise every dummy verify would still cost the full time.
    passwords._DUMMY = passwords.hash_password("tinysesam-timing-dummy")


class _AfterTheLoad:
    """Import hook: loads `tinysesam.passwords` as usual and lowers the parameters afterwards."""

    def find_spec(self, name, path=None, destination=None):
        if name != MODULE:
            return None
        sys.meta_path.remove(self)                 # once is enough; otherwise it would find itself
        for finder in sys.meta_path:
            spec = finder.find_spec(name, path, destination) if hasattr(finder, "find_spec") else None
            if spec is not None and spec.loader is not None:
                load = spec.loader.exec_module

                def exec_module(module, _load=load):
                    _load(module)
                    lower(module)
                spec.loader.exec_module = exec_module
                return spec
        return None


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("Aufruf: python tests/_starter.py <suite.py> [argumente …]")
    suite = os.path.abspath(argv[0])
    # Like a direct start: sys.argv[0] is the suite, its directory is first on the path.
    sys.argv = [suite, *argv[1:]]
    sys.path[0] = os.path.dirname(suite)
    if os.path.basename(suite) not in PRODUCTION_VALUES:
        if MODULE in sys.modules:                   # pragma: no cover — nobody imports it here
            lower(sys.modules[MODULE])
        else:
            sys.meta_path.insert(0, _AfterTheLoad())
    runpy.run_path(suite, run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])

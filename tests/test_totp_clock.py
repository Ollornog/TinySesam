"""The TOTP codes of the suites come from one safe moment (`tests/_totp_clock.py`) — replayed at a step boundary.

The suites confirm a TOTP setup with the code of the previous step and expect a code of the next step to be refused.
Computed as `TOTP(secret).at(time.time() - 30)` and checked a moment later by the library, a step boundary in between
turned the previous code into one two steps old (refused) and the next code into the running one (accepted): a
wobble under load (`test_next_whatwg` once red in a run without product changes). This suite replays exactly that
race against the library's own check with a fake clock, shows that the old way fails and the helper does not, and
keeps every suite on the helper.
"""
import os
import re
import sys
import time
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import pyotp  # noqa: E402

import _totp_clock  # noqa: E402
from tinysesam import totp as _totp  # noqa: E402

SECRET = pyotp.random_base32()
#: The library's default window (T-57): the previous and the running step.
BACK, AHEAD = _totp.WINDOWS["previous"]


def ok(name):
    print(f"  ✓ {name}")


class FakeClock:
    """A wall clock the test moves by hand; `sleep` moves it too."""

    def __init__(self, now):
        self.now = float(now)
        self.slept = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


BOUNDARY = 30 * (int(time.time()) // 30 + 1000)      # a step boundary, far from the real clock
LATENCY = 0.2                                         # computing the code → the library checks it


def library_step(code, clock):
    """The step the library matches for `code` at the fake moment (its own `matching_step`, real code path)."""
    with mock.patch("time.time", clock.time):
        return _totp.matching_step(SECRET, code, BACK, AHEAD)


# ══ The race is real: the old way fails across a boundary ═══════════════════════════════════════════════════════
clock = FakeClock(BOUNDARY - 0.1)
old_previous = pyotp.TOTP(SECRET).at(clock.time() - 30)
clock.now += LATENCY
assert library_step(old_previous, clock) is None, "self-probe: the previous code computed before a boundary is refused"
clock = FakeClock(BOUNDARY - 0.1)
old_next = pyotp.TOTP(SECRET).at(clock.time() + 30)
clock.now += LATENCY
assert library_step(old_next, clock) is not None, "self-probe: the next code computed before a boundary passes"
ok("self-probe: `at(time.time() ± 30)` flips at a step boundary (previous refused, next accepted)")

# ══ The helper: the same race, the intended answers ═════════════════════════════════════════════════════════════
clock = FakeClock(BOUNDARY - 0.1)
code = _totp_clock.previous_code(SECRET, clock=clock.time, sleep=clock.sleep)
clock.now += LATENCY
assert clock.slept, "the helper waits out the end of the step"
assert library_step(code, clock) is not None, "the previous code from the helper is accepted across the boundary"
clock = FakeClock(BOUNDARY - 0.1)
code = _totp_clock.next_code(SECRET, clock=clock.time, sleep=clock.sleep)
clock.now += LATENCY
assert library_step(code, clock) is None, "the next code from the helper stays refused across the boundary"
# A generator works like the secret.
clock = FakeClock(BOUNDARY - 0.1)
assert (_totp_clock.previous_code(pyotp.TOTP(SECRET), clock=clock.time, sleep=clock.sleep)
        == pyotp.TOTP(SECRET).at(BOUNDARY - 30)), "generator and secret give the same code"
ok("helper: previous code accepted and next code refused although a step boundary falls in between")

# ══ The margin: waits only in the last MARGIN seconds ════════════════════════════════════════════════════════════
for offset, waits in ((10.0, False), (30 - _totp_clock.MARGIN - 0.1, False), (30 - _totp_clock.MARGIN + 0.1, True),
                      (29.99, True)):
    clock = FakeClock(BOUNDARY - 30 + offset)
    _totp_clock.code(SECRET, 0, clock=clock.time, sleep=clock.sleep)
    assert bool(clock.slept) is waits, (offset, clock.slept)
    if waits:
        assert clock.now % 30 < 1, "after the wait the moment lies at the start of the next step"
assert _totp_clock.MARGIN >= 2, "a margin of a few seconds covers a loaded machine"
ok(f"margin: a wait only in the last {_totp_clock.MARGIN:g} s of a step, and then into the next step")

# ══ Guard: no suite derives a TOTP code from the wall clock itself ══════════════════════════════════════════════
RAW = re.compile(r"\.at\(\s*(?:int\(\s*)?[\w.]*time\(\)\s*\)?\s*[-+]\s*30\b")
for probe in ("pyotp.TOTP(s).at(time.time() - 30)", "gen.at(int(time.time()) + 30)", "_pyotp.TOTP(s).at(_when.time() - 30)",
              "gen.at(time.time() + 30 * offset_steps)", "pyotp.TOTP(s).at(int(_time.time()) - 30)"):
    assert RAW.search(probe), f"self-probe: the guard sees {probe!r}"
assert not RAW.search("previous_code(secret)") and not RAW.search("res['expires_at'] <= time.time() + 30 * 60")
found = []
for path in sorted(HERE.glob("test_*.py")):
    if path.name == os.path.basename(__file__):
        continue
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if RAW.search(line):
            found.append(f"{path.name}:{number}: {line.strip()}")
assert not found, "TOTP codes from the wall clock — use tests/_totp_clock.py:\n" + "\n".join(found)
ok("every suite takes its TOTP codes ±1 step from tests/_totp_clock.py")

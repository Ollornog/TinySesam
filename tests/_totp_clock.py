"""TOTP codes for the suites, computed from ONE moment that is safely inside its 30-second step.

WHY: The suites confirm a TOTP setup with the code of the PREVIOUS step (`totp_window="previous"`, T-57) so that the
running step stays free for a later sign-in with `.now()`. Written as `TOTP(secret).at(time.time() - 30)`, the code
is computed at one moment and checked by the library a little later. When a step boundary falls in between, the code
is two steps old and refused — a wobble under load, not a finding (pipeline register 2026-11-21: `test_next_whatwg`
once red with `{"ok": false}` in a run that changed no product code). The same holds for a code of the NEXT step
that a test expects to be refused: across a boundary it becomes the running step and passes.

WHAT: `code(secret, steps)` picks one moment with at least `MARGIN` seconds left in its step (it sleeps over the
boundary otherwise) and derives the code from exactly that moment. The library keeps its own clock: nothing in the
product is loosened for the tests. `tests/test_totp_clock.py` replays the race with a fake clock and keeps every
suite on this helper.
"""
from __future__ import annotations

import time

import pyotp

#: Length of a TOTP step in seconds (RFC 6238 default, the only one TinySesam issues).
STEP = 30
#: Seconds that must remain in the running step before a code is computed. A suite checks its code within
#: milliseconds; five seconds also cover a loaded CI machine.
MARGIN = 5.0


def safe_moment(clock=time.time, sleep=time.sleep) -> float:
    """A moment with at least `MARGIN` seconds left in its step — now, or just after the next boundary."""
    now = clock()
    left = STEP - now % STEP
    if left < MARGIN:
        sleep(left + 0.5)
        now = clock()
    return now


def code(secret, steps: int = 0, *, clock=time.time, sleep=time.sleep) -> str:
    """The code `steps` steps away from the running one (-1 previous, 0 current, 1 next), from one safe moment.

    `secret` is the base32 secret or a `pyotp.TOTP` generator."""
    gen = secret if isinstance(secret, pyotp.TOTP) else pyotp.TOTP(secret)
    return gen.at(safe_moment(clock, sleep) + steps * STEP)


def previous_code(secret, **kw) -> str:
    """The code of the previous step: accepted by the default window, leaves the running step free."""
    return code(secret, -1, **kw)


def next_code(secret, **kw) -> str:
    """The code of the next step: accepted only by `totp_window="previous_and_next"`."""
    return code(secret, 1, **kw)

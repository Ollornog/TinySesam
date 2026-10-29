"""Deprecated tier-C names — kept as a warning alias until 1.0 (PO decision 2026-09-26).

Tier C means: internal, no promise. Up to 0.21.x these names carried no underscore and
therefore looked like any other method — `check_password` was even listed as a building block in the
README, although it does not throttle. Since 0.22.0 the implementation is called `_check_password`; the
old name stays as a class attribute until 1.0:

    check_password = Deprecated("_check_password", "stattdessen `POST /auth/login` …")

Methods warn on **call**, not on lookup: `hasattr`, `inspect.getmembers` or
an autocompletion should not trigger a warning the caller did not cause at all.
Constants warn on **read** — reading is the use there; even a walk over
all attributes (`inspect.getmembers`) reads them. Whoever walks like that without using them reads
statically (`inspect.getattr_static`) or suppresses the `DeprecationWarning` — as the guard
and `scripts/_api_docs.py` do.

The warning points at the caller (not into this file): only then can it be found specifically with
`-W error::DeprecationWarning` or a filter on the own module.

An assignment on the object — typically a test fake, `auth.check_password = fake` or
`mock.patch.object(auth, "rate_ok", …)` — **no longer takes effect**: up to 0.21.x it replaced what the
built-in routes called; since 0.22.0 they call `_check_password`, and the fake would silently run
into the void (measured: 0 calls, login still 303). That is why the alias is a **data** descriptor:
`__set__` stores the value on the object as before — whoever reads it via the old name gets
it —, but triggers a `RuntimeWarning` that is visible without a filter and names the target the
fake belongs on. Same reasoning as for a subclass that overrides the old name
(`TinySesam.__init_subclass__`). An assignment on the CLASS
(`mock.patch.object(TinySesam, "rate_ok", …)`) replaces the alias itself and goes unnoticed —
that would need a metaclass; it no longer takes effect either.
"""
from __future__ import annotations

import functools
import types
import warnings

#: With which release the aliases fall. The guard (`tests/test_api_surface.py`) turns red
#: as soon as the version reaches this limit and an alias still stands in the class.
BIS = "1.0"


class Deprecated:
    """An old tier-C name: forwards to `ziel` and warns exactly once while doing so.

    `ziel` is the name of the implementation in the same class (`_check_password`), `ersatz` the
    part of the message after the dash — what the caller should use instead. It is mandatory:
    a warning that only says "deprecated" sends everyone into the source code.
    """

    __slots__ = ("ziel", "ersatz", "bis", "name", "klasse", "methode")

    def __init__(self, ziel: str, ersatz: str, bis: str = BIS):
        if not ziel or not ersatz or not ersatz.strip():
            raise ValueError("Deprecated needs a target and a replacement")
        self.ziel, self.ersatz, self.bis = ziel, ersatz.strip().rstrip("."), bis
        self.name = self.klasse = ""
        self.methode = False

    def __set_name__(self, owner, name):
        self.name, self.klasse = name, owner.__name__
        # At class construction, not at the first call: an alias to a target that does not
        # exist should make the import fail — not the caller only a year later.
        if self.ziel not in vars(owner):
            raise TypeError(f"{self.klasse}.{name}: target {self.ziel!r} is missing in the class")
        self.methode = isinstance(vars(owner)[self.ziel],
                                  (types.FunctionType, staticmethod, classmethod))

    @property
    def meldung(self) -> str:
        return (f"{self.klasse}.{self.name} is internal (tier C) and goes away with {self.bis} — "
                f"{self.ersatz}.")

    def _warnen(self) -> None:
        # Stack: 1 = _warnen, 2 = the alias or __get__, 3 = the caller.
        warnings.warn(self.meldung, DeprecationWarning, stacklevel=3)

    def __get__(self, obj, owner=None):
        # A value set on the object (test fake, see `__set__`) takes precedence — as with an
        # ordinary method that an assignment on the object shadows.
        if obj is not None and self.name in getattr(obj, "__dict__", ()):
            return obj.__dict__[self.name]
        wert = getattr(obj if obj is not None else owner, self.ziel)
        if not self.methode:
            self._warnen()
            return wert

        @functools.wraps(wert)          # `__wrapped__` → inspect.signature shows the target's
        def alias(*args, **kwargs):
            self._warnen()
            return wert(*args, **kwargs)

        alias.__name__ = self.name
        alias.__qualname__ = f"{self.klasse}.{self.name}"
        alias.__doc__ = self.meldung + ("\n\n" + wert.__doc__ if wert.__doc__ else "")
        return alias

    def __set__(self, obj, wert) -> None:
        """Assignment on the object: store as before, but loudly — the value no longer takes effect."""
        # Stack: 1 = __set__, 2 = the assignment (or `setattr` in `mock.patch`).
        warnings.warn(
            f"{type(obj).__name__}.{self.name} set on the object (test fake?) — this has had no effect since "
            f"0.22.0: TinySesam calls `{self.ziel}` internally; set the fake on `{self.ziel}` "
            f"instead. {self.meldung}", RuntimeWarning, stacklevel=2)
        obj.__dict__[self.name] = wert

    def __delete__(self, obj) -> None:
        """`del auth.check_password` or the end of `mock.patch.object`: the alias applies again."""
        try:
            del obj.__dict__[self.name]
        except KeyError:
            raise AttributeError(self.name) from None

    def __repr__(self) -> str:
        return f"Deprecated({self.ziel!r}, bis {self.bis})"

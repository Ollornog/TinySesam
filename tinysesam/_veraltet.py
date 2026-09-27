"""Veraltete Namen der Stufe C — bis 1.0 als warnender Alias (PO-Entscheid 2026-09-26).

Stufe C heisst: intern, keine Zusage. Bis 0.21.x trugen diese Namen keinen Unterstrich und
sahen damit aus wie jede andere Methode — `check_password` stand sogar als Baustein in der
README, obwohl es nicht drosselt. Seit 0.22.0 heisst die Implementierung `_check_password`; der
alte Name bleibt bis 1.0 als Klassenattribut stehen:

    check_password = Veraltet("_check_password", "stattdessen `POST /auth/login` …")

Methoden warnen beim **Aufruf**, nicht beim Nachschlagen: `hasattr`, `inspect.getmembers` oder
eine Autovervollständigung sollen keine Warnung auslösen, die der Aufrufer gar nicht verursacht
hat. Konstanten warnen beim **Lesen** — das Lesen ist dort der Gebrauch; auch ein Durchlauf über
alle Attribute (`inspect.getmembers`) liest sie. Wer so durchläuft, ohne sie zu benutzen, liest
statisch (`inspect.getattr_static`) oder unterdrückt die `DeprecationWarning` — so wie der Wächter
und `scripts/_api_doku.py`.

Die Warnung zeigt auf den Aufrufer (nicht in diese Datei): Nur so lässt sie sich mit
`-W error::DeprecationWarning` oder einem Filter auf das eigene Modul gezielt finden.

Eine Zuweisung am Objekt — typisch ein Test-Fake, `auth.check_password = fake` oder
`mock.patch.object(auth, "rate_ok", …)` — **wirkt nicht mehr**: Bis 0.21.x ersetzte sie, was die
eingebauten Routen riefen; seit 0.22.0 rufen sie `_check_password`, und der Fake liefe still ins
Leere (gemessen: 0 Aufrufe, Login trotzdem 303). Deshalb ist der Alias ein **Daten**-Deskriptor:
`__set__` legt den Wert wie bisher am Objekt ab — wer ihn über den alten Namen liest, bekommt
ihn —, löst aber eine `RuntimeWarning` aus, die ohne Filter sichtbar ist und das Ziel nennt, auf
das der Fake gehört. Dieselbe Begründung wie bei einer Unterklasse, die den alten Namen
überschreibt (`TinySesam.__init_subclass__`). Eine Zuweisung an der KLASSE
(`mock.patch.object(TinySesam, "rate_ok", …)`) ersetzt den Alias selbst und bleibt unbemerkt —
dafür bräuchte es eine Metaklasse; auch sie wirkt nicht mehr.
"""
from __future__ import annotations

import functools
import types
import warnings

#: Mit welchem Release die Aliase fallen. Der Wächter (`tests/test_api_surface.py`) wird rot,
#: sobald die Version diese Grenze erreicht und noch ein Alias in der Klasse steht.
BIS = "1.0"


class Veraltet:
    """Ein alter Name der Stufe C: reicht an `ziel` weiter und warnt dabei genau einmal.

    `ziel` ist der Name der Implementierung in derselben Klasse (`_check_password`), `ersatz` der
    Teil der Meldung nach dem Gedankenstrich — was der Aufrufer stattdessen nimmt. Er ist Pflicht:
    Eine Warnung, die nur „veraltet" sagt, schickt jeden in den Quelltext.
    """

    __slots__ = ("ziel", "ersatz", "bis", "name", "klasse", "methode")

    def __init__(self, ziel: str, ersatz: str, bis: str = BIS):
        if not ziel or not ersatz or not ersatz.strip():
            raise ValueError("Veraltet braucht ein Ziel und einen Ersatz")
        self.ziel, self.ersatz, self.bis = ziel, ersatz.strip().rstrip("."), bis
        self.name = self.klasse = ""
        self.methode = False

    def __set_name__(self, owner, name):
        self.name, self.klasse = name, owner.__name__
        # Beim Bau der Klasse, nicht beim ersten Aufruf: Ein Alias auf ein Ziel, das es nicht
        # gibt, soll den Import scheitern lassen — nicht erst den Aufrufer in einem Jahr.
        if self.ziel not in vars(owner):
            raise TypeError(f"{self.klasse}.{name}: Ziel {self.ziel!r} fehlt in der Klasse")
        self.methode = isinstance(vars(owner)[self.ziel],
                                  (types.FunctionType, staticmethod, classmethod))

    @property
    def meldung(self) -> str:
        return (f"{self.klasse}.{self.name} ist intern (Stufe C) und fällt mit {self.bis} weg — "
                f"{self.ersatz}.")

    def _warnen(self) -> None:
        # Stapel: 1 = _warnen, 2 = der Alias bzw. __get__, 3 = der Aufrufer.
        warnings.warn(self.meldung, DeprecationWarning, stacklevel=3)

    def __get__(self, obj, owner=None):
        # Ein am Objekt gesetzter Wert (Test-Fake, s. `__set__`) geht vor — wie bei einer
        # gewöhnlichen Methode, die eine Zuweisung am Objekt verdeckt.
        if obj is not None and self.name in getattr(obj, "__dict__", ()):
            return obj.__dict__[self.name]
        wert = getattr(obj if obj is not None else owner, self.ziel)
        if not self.methode:
            self._warnen()
            return wert

        @functools.wraps(wert)          # `__wrapped__` → inspect.signature zeigt die des Ziels
        def alias(*args, **kwargs):
            self._warnen()
            return wert(*args, **kwargs)

        alias.__name__ = self.name
        alias.__qualname__ = f"{self.klasse}.{self.name}"
        alias.__doc__ = self.meldung + ("\n\n" + wert.__doc__ if wert.__doc__ else "")
        return alias

    def __set__(self, obj, wert) -> None:
        """Zuweisung am Objekt: ablegen wie bisher, aber laut — der Wert wirkt nicht mehr."""
        # Stapel: 1 = __set__, 2 = die Zuweisung (bzw. `setattr` in `mock.patch`).
        warnings.warn(
            f"{type(obj).__name__}.{self.name} am Objekt gesetzt (Test-Fake?) — das wirkt seit "
            f"0.22.0 nicht mehr: TinySesam ruft intern `{self.ziel}`; den Fake auf `{self.ziel}` "
            f"setzen. {self.meldung}", RuntimeWarning, stacklevel=2)
        obj.__dict__[self.name] = wert

    def __delete__(self, obj) -> None:
        """`del auth.check_password` bzw. das Ende von `mock.patch.object`: der Alias gilt wieder."""
        try:
            del obj.__dict__[self.name]
        except KeyError:
            raise AttributeError(self.name) from None

    def __repr__(self) -> str:
        return f"Veraltet({self.ziel!r}, bis {self.bis})"

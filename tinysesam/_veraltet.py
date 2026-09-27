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

Ein Nicht-Daten-Deskriptor (nur `__get__`): Eine Zuweisung am Objekt — ein Test-Fake, der
`auth.check_password = …` setzt — überschreibt den Alias weiter wie eine normale Methode.
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

    def __repr__(self) -> str:
        return f"Veraltet({self.ziel!r}, bis {self.bis})"

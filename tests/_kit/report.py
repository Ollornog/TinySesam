"""Kleine Bilanz für Test-Suiten — sammelt Ergebnisse, statt beim ersten Fehler abzubrechen.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.

Ein Repo kann diese Klasse benutzen (`r.check(name, bedingung)`) oder bei nacktem
`assert` bleiben. Die Prüffunktionen in `hygiene.py` geben Listen zurück und passen
in beides. Wer alle Verstöße auf einmal sehen will, nimmt `Report`; wer beim ersten
Fehler stehen bleiben will, nimmt `assert`.
"""
from __future__ import annotations

from typing import Callable


class Report:
    """Kleine Bilanz — jede Suite meldet Exit 0/1."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.ok = 0
        self.fail = 0
        self.skipped = 0
        print(f"\n{title}")

    def check(self, name: str, passed: bool, info: str = "") -> bool:
        if passed:
            self.ok += 1
            print(f"  ok   {name}", flush=True)
        else:
            self.fail += 1
            print(f"  FEHL {name}{': ' + info if info else ''}", flush=True)
        return bool(passed)

    def run(self, name: str, fn: Callable[[], object]) -> None:
        try:
            fn()
            self.check(name, True)
        except Exception as exc:  # noqa: BLE001
            self.check(name, False, str(exc))

    def skip(self, name: str, why: str) -> None:
        self.skipped += 1
        print(f"  skip {name}: {why}", flush=True)

    def done(self) -> int:
        extra = f", {self.skipped} übersprungen" if self.skipped else ""
        print(f"\n{self.ok} ok, {self.fail} Fehler{extra}", flush=True)
        return 1 if self.fail else 0

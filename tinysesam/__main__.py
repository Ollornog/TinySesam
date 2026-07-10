"""CLI: python -m tinysesam version   (auch als Konsolenskript `tinysesam`).

Bewusst mager. TinySesam installiert sich nicht selbst — ein Auth-Modul, das zur Laufzeit
Code nachlädt, ist eine Hintertür mit Bedienungsanleitung. Aktualisiert wird von außen:
Tag hochziehen, neu installieren, Dienst neu starten. Siehe README, „Installation und Updates".
"""
import sys

from . import current_version


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "version"
    if cmd == "version":
        print(current_version())
    else:
        print("usage: python -m tinysesam version")
        sys.exit(2)


if __name__ == "__main__":
    main()

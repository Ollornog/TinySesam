"""CLI: python -m tinysesam [version | check | update [ref]]  (auch als Konsolenskript `tinysesam`)."""
import sys
import json

from .updater import current_version, update_available, self_update


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "version"
    if cmd == "version":
        print(current_version())
    elif cmd == "check":
        print(json.dumps(update_available(), indent=2, ensure_ascii=False))
    elif cmd == "update":
        ref = argv[1] if len(argv) > 1 else None
        r = self_update(ref=ref)
        print(r["output"])
        print("OK — Host-App neu starten, damit der neue Code geladen wird." if r["ok"] else "FEHLGESCHLAGEN")
        sys.exit(0 if r["ok"] else 1)
    else:
        print("usage: python -m tinysesam [version | check | update [ref]]")
        sys.exit(2)


if __name__ == "__main__":
    main()

"""CLI: `python -m tinysesam <kommando>` (auch als Konsolenskript `tinysesam`).

    version                          die installierte Version
    passwd --db auth.db <benutzer>   Passwort offline neu setzen (Wartung)

Bewusst mager. TinySesam installiert sich nicht selbst — ein Auth-Modul, das zur Laufzeit
Code nachlädt, ist eine Hintertür mit Bedienungsanleitung. Aktualisiert wird von außen:
Tag hochziehen, neu installieren, Dienst neu starten. Siehe README, „Installation und Updates".

`passwd` widerspricht dem nicht (ADR-2): Es lädt nichts nach und spricht keinen laufenden Dienst
an, sondern öffnet eine Datenbankdatei, auf die man ohnehin Dateizugriff braucht. Es ist der
Ausweg für den Fall, für den die Presets ohne Mailer gedacht sind — internes Werkzeug, Admin-
Passwort weg, kein „Passwort vergessen"-Link und kein zweiter Admin.
"""
import sys
import getpass
import argparse

from . import current_version


def _passwd(argv) -> int:
    ap = argparse.ArgumentParser(prog="tinysesam passwd",
                                 description="Passwort eines Kontos offline neu setzen.")
    ap.add_argument("username", help="Benutzername des Kontos")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank (config.db_path)")
    ap.add_argument("--stdin", action="store_true",
                    help="Passwort von der Standardeingabe lesen statt interaktiv fragen")
    ap.add_argument("--keep-sessions", action="store_true",
                    help="offene Sitzungen des Kontos NICHT beenden (Vorgabe: beenden)")
    a = ap.parse_args(argv)

    # Store statt TinySesam: kein FastAPI nötig, und die Instanz hätte Nebenwirkungen
    # (Demo-Seeding, Erst-Admin-Token) — beides hat in einem Wartungsbefehl nichts verloren.
    import os
    from .store import Store
    from .passwords import hash_password
    from .security import SECURITY_DEFAULTS

    # Ohne diese Prüfung legt sqlite3 die Datei stillschweigend an und der Tippfehler im Pfad
    # käme als „Kein Konto 'admin'" zurück — die ratloseste aller Fehlermeldungen.
    if not os.path.exists(a.db):
        print(f"Keine Datenbank unter {a.db}.", file=sys.stderr)
        return 1
    store = Store(a.db)
    user = store.get_user_by_name(a.username)
    if not user:
        print(f"Kein Konto '{a.username}' in {a.db}.", file=sys.stderr)
        return 1

    if a.stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Neues Passwort: ")
        if pw != getpass.getpass("Wiederholen:    "):
            print("Die beiden Eingaben sind verschieden.", file=sys.stderr)
            return 1
    try:
        minlen = int(store.get_setting("password_min_length") or SECURITY_DEFAULTS["password_min_length"])
    except (TypeError, ValueError):
        minlen = SECURITY_DEFAULTS["password_min_length"]
    if len(pw) < minlen:
        print(f"Passwort zu kurz (min. {minlen}).", file=sys.stderr)
        return 1

    store.set_password_hash(user["id"], hash_password(pw))
    note = ""
    if not a.keep_sessions:
        # Standard nach jedem Credential-Wechsel: offene Sitzungen gelten nicht weiter.
        store.delete_user_sessions(user["id"])
        note = " (offene Sitzungen beendet)"
    store.audit_log("password_reset_cli", a.username, None, "offline")
    print(f"Passwort für '{a.username}' gesetzt{note}.")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "version"
    if cmd == "version":
        print(current_version())
    elif cmd == "passwd":
        sys.exit(_passwd(argv[1:]))
    else:
        print("usage: python -m tinysesam version\n"
              "       python -m tinysesam passwd --db <datei> <benutzer>")
        sys.exit(2)


if __name__ == "__main__":
    main()

"""CLI: `python -m tinysesam <kommando>` (auch als Konsolenskript `tinysesam`).

    version                          die installierte Version
    passwd --db auth.db <benutzer>   Passwort offline neu setzen (Wartung)
    backup --db auth.db <ziel>       konsistente Kopie ziehen (NICHT die Datei kopieren!)
    gc --db auth.db                  Abgelaufenes wegräumen (für Cron/Timer)

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


def _oeffne(pfad: str):
    """Store auf einer BESTEHENDEN Datei. Wie bei `passwd`: kein TinySesam, damit ein
    Wartungsbefehl kein Demo-Seeding und kein Erst-Admin-Token auslöst."""
    import os
    from .store import Store
    if not os.path.exists(pfad):
        print(f"Keine Datenbank unter {pfad}.", file=sys.stderr)
        return None
    return Store(pfad)


def _backup(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam backup",
        description="Konsistente Kopie der Datenbank ziehen, auch im laufenden Betrieb.",
        epilog="Eine Datei-Kopie (cp/rsync) taugt NICHT: Die Datenbank läuft im WAL-Modus, alles "
               "seit dem letzten Checkpoint steht in der -wal-Datei. Wer nur die .db sichert, "
               "bekommt einen Torso — und merkt es erst beim Zurückspielen.")
    ap.add_argument("ziel", help="Pfad der Sicherungsdatei (wird angelegt)")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank (config.db_path)")
    a = ap.parse_args(argv)
    import os

    from .store import Store
    if not os.path.exists(a.db):
        print(f"Keine Datenbank unter {a.db}.", file=sys.stderr)
        return 1
    if os.path.exists(a.ziel):
        print(f"{a.ziel} gibt es schon — nichts überschrieben.", file=sys.stderr)
        return 1
    # NICHT über `_oeffne()`: Der Store-Konstruktor migriert die Datei, bevor eine Kopie
    # existiert — eine Sicherung, die die Quelle verändert, ist keine. `sichere_datei` öffnet
    # read-only.
    try:
        Store.sichere_datei(a.db, a.ziel)
    except Exception as e:
        print(f"Sicherung fehlgeschlagen: {type(e).__name__}: {e}", file=sys.stderr)
        for rest in ("", "-wal", "-shm"):
            if os.path.exists(a.ziel + rest):
                os.remove(a.ziel + rest)      # keine halbe Datei zurücklassen
        return 1
    print(f"Sicherung geschrieben: {a.ziel} ({os.path.getsize(a.ziel)} Bytes, Rechte 0600).")
    return 0


def _gc(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam gc",
        description="Abgelaufene Sitzungen, Flows, Einmal-Token und alte Login-Versuche löschen.",
        epilog="Läuft nicht von selbst. Für einen Timer/Cron gedacht — das Audit-Log bleibt "
               "bewusst unangetastet.")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank (config.db_path)")
    ap.add_argument("--attempts-older-than", type=int, default=86400, metavar="SEK",
                    help="Login-Versuche älter als N Sekunden löschen (Vorgabe: 86400)")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    import time as _t
    zahlen = {
        "sessions": store.gc_sessions(),
        "flow": store.gc_flow(),
        "magic_tokens": store.gc_magic_tokens(),
        "resource_unlocks": store.gc_resource_unlocks(),
        "login_attempts": store.gc_attempts(int(_t.time()) - a.attempts_older_than),
    }
    print(" ".join(f"{k}={v}" for k, v in zahlen.items()))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "version"
    if cmd == "version":
        print(current_version())
    elif cmd == "passwd":
        sys.exit(_passwd(argv[1:]))
    elif cmd == "backup":
        sys.exit(_backup(argv[1:]))
    elif cmd == "gc":
        sys.exit(_gc(argv[1:]))
    else:
        # `--help` ist eine Frage, kein Fehler: Sie gehört nach stdout und endet mit 0. Ein
        # Tippfehler dagegen nach stderr und endet mit 2, sonst merkt kein Skript den Unterschied.
        hilfe = cmd in ("--help", "-h", "help")
        print("usage: python -m tinysesam version\n"
              "       python -m tinysesam passwd --db <datei> <benutzer>\n"
              "       python -m tinysesam backup --db <datei> <ziel>\n"
              "       python -m tinysesam gc     --db <datei>",
              file=sys.stdout if hilfe else sys.stderr)
        sys.exit(0 if hilfe else 2)


if __name__ == "__main__":
    main()

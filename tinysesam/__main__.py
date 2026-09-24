"""CLI: `python -m tinysesam <kommando>` (auch als Konsolenskript `tinysesam`).

    version                          die installierte Version
    passwd --db auth.db <benutzer>   Passwort offline neu setzen (Wartung; --blocklist-file,
                                     --rp-name: dieselbe Passwortregel wie die Config)
    backup --db auth.db <ziel>       konsistente Kopie ziehen (NICHT die Datei kopieren!)
    restore --db auth.db <quelle>    eine Sicherung zurückspielen (Dienst vorher stoppen!)
    gc --db auth.db                  Abgelaufenes wegräumen (für Cron/Timer)
    audit --db auth.db [--user X]    ins Protokoll sehen (auch wenn niemand hereinkommt)
    unlock --db auth.db <benutzer>   eine Brute-Force-Sperre aufheben

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
    # Das CLI liest keine Config — was dort für die Passwortregel steht, bekommt es hier.
    # Ohne diese beiden Schalter galt offline eine schwächere Regel als im Web (A-7).
    ap.add_argument("--blocklist-file", default="",
                    help="eigene Blockliste wie config.password_blocklist_file")
    ap.add_argument("--rp-name", default="",
                    help="Dienstname wie config.rp_name (gilt als Kontextwort)")
    a = ap.parse_args(argv)

    # Store statt TinySesam: kein FastAPI nötig, und die Instanz hätte Nebenwirkungen
    # (Demo-Seeding, Erst-Admin-Token) — beides hat in einem Wartungsbefehl nichts verloren.
    import os
    from .store import Store
    from .passwords import hash_password, passwort_mangel, blockliste_lesen
    from .security import haertung_lesen

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
    # Die Mindestlänge über DENSELBEN Leseweg wie `TinySesam.sec()`: Roh gelesen galt ein
    # Altwert ohne Grenzen (4, 0) hier weiter, während das Web ihn auf 8 zog.
    #
    # Und die STRENGERE der beiden Längen (B2-4): Das CLI liest keine Konfiguration und weiss
    # deshalb nicht, ob eine Kette einen zweiten Faktor erzwingt. Im Zweifel gilt die Regel für
    # ein Passwort, das allein anmelden kann; wer das nicht will, stellt
    # `password_min_length_single_factor` im Panel herunter.
    minlen = max(haertung_lesen(store, "password_min_length"),
                 haertung_lesen(store, "password_min_length_single_factor"))
    # Dieselbe Regel wie im Web (Länge, Höchstlänge, eingebaute Blockliste, Benutzername,
    # E-Mail-Name) — das CLI ist ein Setzweg wie die anderen. Blockliste und Dienstname des
    # Betreibers kommen über `--blocklist-file` und `--rp-name`, weil das CLI keine Config liest.
    blockliste: frozenset = frozenset()
    if a.blocklist_file:
        try:
            blockliste = blockliste_lesen(a.blocklist_file)
        except OSError as e:
            print(f"Blockliste {a.blocklist_file!r} lässt sich nicht lesen: {e}", file=sys.stderr)
            return 1
    mangel = passwort_mangel(pw, minlen, blockliste=blockliste,
                             kontext=(a.username, (user["email"] or "").split("@", 1)[0], a.rp_name))
    if mangel:
        grund, werte = mangel
        print({"short": f"Passwort zu kurz (min. {werte.get('n')}).",
               "long": f"Passwort zu lang (max. {werte.get('n')}).",
               "weak": "Passwort zu leicht zu erraten (bekannt, trivial oder aus dem Kontonamen)."}[grund],
              file=sys.stderr)
        return 1

    store.set_password_hash(user["id"], hash_password(pw))
    # Neu gebunden: Eine Serien-Sperre (B2-6) endet hier wie bei jedem anderen Reset.
    from .store import norm_kennung
    for kennung in {norm_kennung(a.username), norm_kennung(user["email"] or "")} - {""}:
        store.fehlserie_loeschen(kennung)
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


def _restore(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam restore",
        description="Eine Sicherung zurückspielen — mit der Reihenfolge, auf die es ankommt.",
        epilog="Den Dienst VORHER stoppen. Ein blosses `cp sicherung.db auth.db` genügt nicht: "
               "Nach einem Absturz liegen `auth.db-wal` und `auth.db-shm` daneben, und SQLite "
               "spielt sie beim nächsten Start auf die frisch zurückgespielte Datei — der alte "
               "Stand ist wieder da, ohne Fehlermeldung, und `PRAGMA integrity_check` sagt `ok`. "
               "Dieses Kommando räumt beide Dateien weg, bevor es ersetzt.")
    ap.add_argument("quelle", help="die Sicherungsdatei")
    ap.add_argument("--db", required=True, help="Ziel: die Datenbank des Dienstes")
    ap.add_argument("--ja", action="store_true", help="nicht nachfragen (für Skripte)")
    a = ap.parse_args(argv)
    import os
    import shutil
    import sqlite3

    if not os.path.exists(a.quelle):
        print(f"Keine Sicherung unter {a.quelle}.", file=sys.stderr)
        return 1
    # Erst prüfen, ob die Sicherung überhaupt taugt — nicht erst nach dem Überschreiben.
    try:
        pruef = sqlite3.connect(f"file:{a.quelle}?mode=ro", uri=True)
        heil = pruef.execute("PRAGMA integrity_check").fetchone()[0]
        konten = pruef.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        stand = pruef.execute("PRAGMA user_version").fetchone()[0]
        pruef.close()
    except Exception as e:
        print(f"{a.quelle} ist keine lesbare TinySesam-Datenbank: {e}", file=sys.stderr)
        return 1
    if heil != "ok":
        print(f"Die Sicherung ist beschädigt (integrity_check: {heil}).", file=sys.stderr)
        return 1

    from .store import Store
    if stand > Store.SCHEMA_VERSION:
        print(f"Die Sicherung trägt Schema-Version {stand}, diese Fassung kennt {Store.SCHEMA_VERSION}. "
              "Sie stammt aus einer neueren TinySesam-Version — passende Version installieren.",
              file=sys.stderr)
        return 1

    print(f"Sicherung: {a.quelle} — {konten} Konten, Schema {stand}, integrity_check ok")
    if os.path.exists(a.db) and not a.ja:
        print(f"Das überschreibt {a.db}. Der Dienst muss GESTOPPT sein.")
        if input("Weiter? [j/N] ").strip().lower() not in ("j", "ja", "y", "yes"):
            print("Abgebrochen.")
            return 1

    # Die Reihenfolge ist der eigentliche Inhalt dieses Kommandos.
    for rest in ("-wal", "-shm"):
        if os.path.exists(a.db + rest):
            os.remove(a.db + rest)
    shutil.copyfile(a.quelle, a.db)
    try:
        os.chmod(a.db, Store.DATEIRECHTE)
    except OSError:
        pass  # Dateisystem ohne Unix-Rechte — die Kopie selbst ist vollständig
    print(f"Zurückgespielt: {a.db} (Rechte 0600). Dienst wieder starten.")
    return 0


def _gc(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam gc",
        description="Abgelaufene Sitzungen, Flows, Einmal-Token und alte Login-Versuche löschen.",
        epilog="Läuft nicht von selbst. Für einen Timer/Cron gedacht. Das Audit-Log bleibt "
               "unangetastet, solange --audit-days nicht gesetzt ist.")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank (config.db_path)")
    ap.add_argument("--attempts-older-than", type=int, default=86400, metavar="SEK",
                    help="Login-Versuche älter als N Sekunden löschen (Vorgabe: 86400)")
    ap.add_argument("--audit-days", type=int, default=0, metavar="TAGE",
                    help="Audit-Einträge älter als N Tage löschen (Vorgabe: 0 = keine; "
                         "Gegenstück zu config.audit_retention_days)")
    a = ap.parse_args(argv)
    # Dieselbe Grenze wie `audit_retention_days` — geprüft, bevor irgendetwas gelöscht wird.
    # 10**20 brach sonst mit OverflowError ab, als Sitzungen und Tokens schon weg waren.
    from .konfigpruefung import ZAHLENGRENZEN
    unten, oben = ZAHLENGRENZEN["audit_retention_days"]
    if not unten <= a.audit_days <= oben:
        ap.error(f"--audit-days muss zwischen {unten} und {oben} liegen (Tage, nicht Sekunden)")
    # Dasselbe für die Login-Versuche (zweite Angriffsrunde): ±10**20 brach nach den ersten
    # Löschschritten ab, ein negativer Wert räumte auch das laufende Sperrfenster weg.
    from .store import versuchsfrist, VERSUCHSFRIST_MAX_SEK
    try:
        versuchsfrist(a.attempts_older_than)
    except ValueError:
        ap.error(f"--attempts-older-than muss zwischen 0 und {VERSUCHSFRIST_MAX_SEK} liegen "
                 "(Sekunden; 0 räumt alle Fehlversuche)")
    store = _oeffne(a.db)
    if store is None:
        return 1
    import time as _t
    zahlen = {
        "unverified_accounts": store.gc_unbestaetigte_konten(),   # vor den Tokens (R4-09)
        "sessions": store.gc_sessions(),
        "flow": store.gc_flow(),
        "magic_tokens": store.gc_magic_tokens(),
        "resource_unlocks": store.gc_resource_unlocks(),
        "login_attempts": store.gc_attempts(int(_t.time()) - a.attempts_older_than),
    }
    if a.audit_days > 0:
        zahlen["audit"] = store.gc_audit(int(_t.time()) - a.audit_days * 86400)
    print(" ".join(f"{k}={v}" for k, v in zahlen.items()))
    return 0


def _audit(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam audit",
        description="Ins Audit-Log sehen — von der Kommandozeile.",
        epilog="Gelesen wurde es bisher nur über das Admin-Panel, also nur als angemeldeter "
               "Admin — ausgerechnet dann unerreichbar, wenn die Anmeldung das Problem ist.")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank")
    ap.add_argument("--user", default="", help="nur Einträge zu diesem Konto")
    ap.add_argument("-n", type=int, default=30, help="wie viele Zeilen (Vorgabe: 30)")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    import datetime as _dt
    # In SQL filtern, nicht hier: Ein Nachsieben der jüngsten Zeilen fand die Einträge eines
    # Kontos nur, wenn sie zufällig ins Fenster fielen — bei einer Brute-Force-Welle also gerade
    # nicht. Das Kommando meldete dann „Keine Einträge zu 'X'." und Exit 0, obwohl sie dastanden.
    zeilen = store.recent_audit(a.n, username=a.user or None)
    if not zeilen:
        print("Keine Einträge." if not a.user else f"Keine Einträge zu '{a.user}'.")
        return 0
    # Jedes Feld durch `zeilenfest` (B5-06): Benutzername und Detail stammen aus Formularen und
    # fremden Antworten. Ein `\n` darin druckte hier eine zweite, frei erfundene Zeile — mit
    # Zeitstempel, Ereignis und IP nach Wahl — genau in der Ansicht, auf die man sich im
    # Anlassfall verlässt. Ein Steuerzeichen (ESC) konnte zudem das Terminal selbst umstellen.
    from .security import zeilenfest as _z
    for z in reversed(zeilen):
        zeit = _dt.datetime.fromtimestamp(z["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{zeit}  {_z(z['event']):22} {_z(z['username'] or '-'):16} "
              f"{_z(z['ip'] or '-'):18} {_z(z['detail'] or '')}")
    return 0


def _unlock(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam unlock",
        description="Die Brute-Force-Sperre eines Kontos aufheben.",
        epilog="Bisher gab es dafür keinen Weg: `clear_fails` lief nur intern nach einer "
               "erfolgreichen Anmeldung — und genau die ist ja gesperrt. Übrig blieb `gc "
               "--attempts-older-than 0`, das die Fehlversuche ALLER Konten wegräumt.")
    ap.add_argument("username", help="Benutzername des Kontos")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    if not store.get_user_by_name(a.username):
        print(f"Kein Konto '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    # Gezählt wird unter der gefalteten Kennung (`norm_kennung`), also auch so räumen.
    from .store import norm_kennung
    topf = norm_kennung(a.username)
    offen = store.count_fails(0, username=topf)
    store.clear_fails(username=topf)
    # Auch die Serien-Sperre (B2-6), unter Name UND Adresse — gezählt wird unter dem, was
    # jemand eingetippt hat.
    konto = store.get_user_by_name(a.username)
    serie = sum(store.fehlserie_loeschen(k) for k in
                {topf, norm_kennung(konto["email"] if konto else "")} - {""})
    store.audit_log("unlock_cli", a.username, None, f"fehlversuche={offen} in_folge={serie}")
    print(f"Sperre für '{a.username}' aufgehoben ({offen} Fehlversuche verworfen).")
    return 0


def _owner(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam owner",
        description="Ein Konto zum Owner machen — der Notweg, wenn kein Owner mehr herankommt.",
        epilog="Im Panel vergibt nur ein Owner die Rolle. Ist der einzige Owner ausgesperrt (Passkey "
               "verloren, Person weg), bleibt der Weg über die Datenbank: wer sie in der Hand hat, "
               "betreibt die Instanz ohnehin.")
    ap.add_argument("username", help="Benutzername des Kontos")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    konto = store.get_user_by_name(a.username)
    if not konto:
        print(f"Kein Konto '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    if konto["is_service"] or konto["disabled"]:
        print(f"'{a.username}' ist gesperrt oder ein Service-Konto — Owner muss sich anmelden können.",
              file=sys.stderr)
        return 1
    store.set_owner(konto["id"], True)
    store.audit_log("owner_grant", a.username, None, "quelle=cli")
    print(f"'{a.username}' ist Owner (und Admin).")
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
    elif cmd == "restore":
        sys.exit(_restore(argv[1:]))
    elif cmd == "gc":
        sys.exit(_gc(argv[1:]))
    elif cmd == "audit":
        sys.exit(_audit(argv[1:]))
    elif cmd == "unlock":
        sys.exit(_unlock(argv[1:]))
    elif cmd == "owner":
        sys.exit(_owner(argv[1:]))
    else:
        # `--help` ist eine Frage, kein Fehler: Sie gehört nach stdout und endet mit 0. Ein
        # Tippfehler dagegen nach stderr und endet mit 2, sonst merkt kein Skript den Unterschied.
        hilfe = cmd in ("--help", "-h", "help")
        print("usage: python -m tinysesam version\n"
              "       python -m tinysesam passwd --db <datei> <benutzer>\n"
              "       python -m tinysesam backup --db <datei> <ziel>\n"
              "       python -m tinysesam restore --db <datei> <sicherung>\n"
              "       python -m tinysesam gc     --db <datei>\n"
              "       python -m tinysesam audit  --db <datei> [--user X]\n"
              "       python -m tinysesam unlock --db <datei> <benutzer>\n"
              "       python -m tinysesam owner  --db <datei> <benutzer>",
              file=sys.stdout if hilfe else sys.stderr)
        sys.exit(0 if hilfe else 2)


if __name__ == "__main__":
    main()

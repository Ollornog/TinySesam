"""CLI: `python -m tinysesam <kommando>` (auch als Konsolenskript `tinysesam`).

    version                          die installierte Version
    passwd --db auth.db <benutzer>   Passwort offline neu setzen (Wartung; --blocklist-file,
                                     --rp-name: dieselbe Passwortregel wie die Config)
    backup --db auth.db <ziel>       konsistente Kopie ziehen (NICHT die Datei kopieren!)
    restore --db auth.db <quelle>    eine Sicherung zurückspielen (Dienst vorher stoppen!)
    gc --db auth.db                  Abgelaufenes wegräumen (für Cron/Timer)
    audit --db auth.db [--user X]    ins Protokoll sehen (auch wenn niemand hereinkommt)
    unlock --db auth.db <benutzer>   eine Brute-Force-Sperre aufheben
    owner --db auth.db <benutzer>    ein Konto zum Owner machen (Notweg)
    rename --db auth.db <alt> <neu>  ein Konto umbenennen (Kennungs-Kollision auflösen)
    gate-key --db auth.db            öffentlicher Schlüssel der Gate-Token (für den Proxy, ADR-9)

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
    # Die Mindestlänge über DENSELBEN Leseweg wie `TinySesam._sec()`: Roh gelesen galt ein
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
    # Neu gebunden: Eine Serien-Sperre (B2-6) endet hier wie bei jedem anderen Reset — unter
    # Name, Adresse und dem Namen im Verzeichnis (G5, `Store.zaehl_kennungen`).
    for kennung in store.zaehl_kennungen(user["id"]):
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
    # Die Sicherung enthält die TOTP-Geheimnisse nur verschlüsselt (H-14/H-15). Ohne den Schlüssel
    # ist sie für TOTP wertlos — er gehört getrennt mitgesichert, nicht in dieselbe Ablage.
    if os.path.exists(a.db + ".key"):
        print(f"Hinweis: Der Schlüssel der TOTP-Geheimnisse liegt in {a.db}.key und ist NICHT in der "
              "Sicherung. Getrennt sichern — ohne ihn müssen alle Konten TOTP neu einrichten.")
    else:
        print("Hinweis: Den Schlüssel der TOTP-Geheimnisse (TINYSESAM_SECRETS_KEY bzw. "
              "secrets_key_file) getrennt sichern — ohne ihn ist TOTP aus dieser Sicherung verloren.")
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
    ap.add_argument("username", help="die Kennung, wie sie eingetippt wird: Benutzername, Adresse "
                                     "oder der Name im Verzeichnis (LDAP)")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    # Gezählt wird unter der gefalteten Kennung (`norm_kennung`), also auch so räumen.
    from .store import norm_kennung
    topf = norm_kennung(a.username)
    # Das Konto zur Kennung: über den Namen, über Name oder Adresse im Zähl-Topf, oder über den
    # Namen, unter dem es sich zuletzt im Verzeichnis angemeldet hat (G5). Bis 2026-09-26 nur
    # über den Namen — nach einer Umbenennung im Verzeichnis (lokal `alice`, dort `alice.neu`)
    # brach `unlock alice.neu` mit „Kein Konto" ab, obwohl genau unter diesem Namen gezählt wurde.
    konto = (store.get_user_by_name(a.username) or store.konto_mit_topf(topf)
             or store.konto_mit_bindungsname(topf))
    offen = store.count_fails(0, username=topf)
    store.clear_fails(username=topf)
    # Auch die Serien-Sperre (B2-6), unter allen Kennungen des Kontos — gezählt wird unter dem,
    # was jemand eingetippt hat — und immer unter der eingetippten selbst.
    serie = sum(store.fehlserie_loeschen(k) for k in
                ({topf} | (store.zaehl_kennungen(konto["id"]) if konto else set())) - {""})
    if konto is None:
        # Kein Konto — gezählt wird aber auch für Kennungen ohne Konto (B2-6 verrät nicht, ob es
        # eins gibt), und ein Bestand kennt den Namen im Verzeichnis noch nicht (er entsteht erst
        # mit der nächsten erfolgreichen Anmeldung). Was unter der Kennung stand, ist geräumt.
        if not (offen or serie):
            print(f"Kein Konto '{a.username}' in {a.db}, und unter dieser Kennung steht keine Sperre.",
                  file=sys.stderr)
            return 1
        store.audit_log("unlock_cli", a.username, None, f"fehlversuche={offen} in_folge={serie} ohne_konto=1")
        print(f"Kein Konto '{a.username}' — die Sperre unter dieser Kennung ist trotzdem aufgehoben "
              f"({offen} Fehlversuche, {serie} in Folge verworfen).")
        return 0
    store.audit_log("unlock_cli", str(konto["username"]), None,
                    f"fehlversuche={offen} in_folge={serie}"
                    + (f" kennung={a.username}" if norm_kennung(konto["username"]) != topf else ""))
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


#: Höchstlänge eines Benutzernamens — dieselbe wie `TinySesam.NAME_MAX` (das CLI importiert den
#: Manager nicht, er zieht FastAPI nach; tests/test_admin_konto.py hält beide gleich).
_NAME_MAX = 150


def _rename(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam rename",
        description="Ein Konto umbenennen — als Betreiber, ohne laufenden Dienst.",
        epilog="Der Weg für eine Kennungs-Kollision im Bestand, die der Start meldet (G13). Dieselben "
               "Grundregeln wie im Panel: frei in Benutzernamen UND Adressen (auch als Namensvetter "
               "wie Alice/alice) und nicht der Name eines anderen Kontos im Verzeichnis, keine Steuerzeichen, höchstens 150 Zeichen, ein Name mit @ nur als "
               "die eigene bestätigte Adresse. Die Konfiguration kennt das CLI nicht: Einen Namen aus "
               "admin_identifiers prüft es nicht, und im Modus login_identifier='email' folgt der "
               "Name der Adresse — dort nicht umbenennen. Sitzungen, Keys, Faktoren und Bindungen "
               "hängen an der Konto-ID und bleiben; nach aussen ändert sich Remote-User.")
    ap.add_argument("username", help="heutiger Benutzername des Kontos, oder #<id> (die user_id "
                                     "aus der Startmeldung — für einen Namen, der sich nicht "
                                     "eintippen lässt)")
    ap.add_argument("neuer_name", help="der neue Benutzername")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    import sqlite3
    from .store import name_ungueltig, norm_email, norm_kennung
    konto = store.get_user_by_name(a.username)
    if konto is None and a.username[:1] == "#" and a.username[1:].isascii() and a.username[1:].isdigit():
        # Über die ID: Ein Name mit Steuerzeichen (Bestand) lässt sich nicht eintippen, und bei
        # einer Kollision nennt die Startmeldung die Konten ohnehin über ihre user_id.
        konto = store.get_user(int(a.username[1:]))
    if not konto:
        print(f"Kein Konto '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    neu = a.neuer_name.strip()
    if not neu or len(neu) > _NAME_MAX or name_ungueltig(neu):
        print("Ungültiger Benutzername (leer, länger als 150 Zeichen oder mit Steuerzeichen).",
              file=sys.stderr)
        return 1
    eigene = norm_email(konto["email"]) if konto["email"] and konto["email_verified"] else None
    if "@" in norm_kennung(neu) and norm_email(neu) != eigene:
        # Wie `change_username`: Ein Name, der eine fremde Adresse ist, besetzte das Postfach
        # einer Person, die es hier noch nicht gibt.
        print(f"'{neu}' ist eine Adresse — als Name nur die eigene bestätigte Adresse des Kontos.",
              file=sys.stderr)
        return 1
    alt = str(konto["username"])
    if neu == alt:
        print(f"'{alt}' heisst schon so — nichts geändert.")
        return 0
    # Kreuzweise, wie `TinySesam.identifier_taken`: Name, Adresse, Zähl-Topf und der Name im
    # Verzeichnis eines anderen Kontos (Prüfrunde 2026-09-27).
    for treffer in (store.get_user_by_name(neu), store.get_user_by_email(neu),
                    store.konto_mit_topf(neu, ausser=konto["id"]),
                    store.konto_mit_verzeichnisname(neu, ausser=konto["id"])):
        if treffer is not None and treffer["id"] != konto["id"]:
            print(f"'{neu}' ist schon vergeben (Konto {treffer['id']}, als Name, Adresse oder Name "
                  "im Verzeichnis).", file=sys.stderr)
            return 1
    try:
        # Als Betreiber: Der Merker „selbst gewählt" (G2-N) fällt — der Name steht für den
        # Betreiber, und die Anmeldung über LDAP/SAML darf das Konto wieder über ihn binden.
        store.set_username(konto["id"], neu, selbst_gewaehlt=False)
    except sqlite3.IntegrityError:
        # Wettlauf mit dem laufenden Dienst: dazwischen vergeben — die Datenbank entscheidet (G12c).
        print(f"'{neu}' ist schon vergeben — die Datenbank hat das Umbenennen abgewiesen, nichts "
              "geändert.", file=sys.stderr)
        return 1
    store.audit_log("username_changed", neu, None, f"alt={alt} durch=betreiber quelle=cli")
    print(f"'{alt}' heisst jetzt '{neu}'. Apps sehen den neuen Namen als Remote-User; die Konto-ID "
          "(Remote-Id) bleibt.")
    return 0


def _gate_key(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam gate-key",
        description="Den öffentlichen Schlüssel der Gate-Token ausgeben (sign_key für caddy-jwt, "
                    "sign_alg EdDSA). Öffentlich, kein Geheimnis.")
    ap.add_argument("--db", required=True, help="Pfad zur TinySesam-Datenbank (config.db_path)")
    ap.add_argument("--secrets-key-file", default="", help="wie config.secrets_key_file")
    a = ap.parse_args(argv)
    import os
    from . import gate, geheimnis
    # Der Schlüssel wird aus dem Grundschlüssel abgeleitet. Gibt es den noch nicht, legt ihn
    # `schluessel_laden` an — das darf ein Lesebefehl nicht: Der Proxy bekäme einen Schlüssel,
    # den der Dienst (mit seiner Umgebung) gar nicht benutzt.
    if not (os.environ.get(geheimnis.UMGEBUNG, "").strip() or a.secrets_key_file
            or os.path.exists(a.db + ".key")):
        print(f"Kein Grundschlüssel: weder {geheimnis.UMGEBUNG} noch --secrets-key-file noch "
              f"{a.db}.key. Mit derselben Umgebung aufrufen wie den Dienst.", file=sys.stderr)
        return 1
    try:
        schluessel, _herkunft = geheimnis.schluessel_laden(a.db, a.secrets_key_file)
    except geheimnis.ConfigError as e:
        print(str(e), file=sys.stderr)
        return 1
    print(gate.oeffentlich_b64(gate.schluessel_ableiten(schluessel)))
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
    elif cmd == "rename":
        sys.exit(_rename(argv[1:]))
    elif cmd == "gate-key":
        sys.exit(_gate_key(argv[1:]))
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
              "       python -m tinysesam owner  --db <datei> <benutzer>\n"
              "       python -m tinysesam rename --db <datei> <benutzer> <neuer-name>\n"
              "       python -m tinysesam gate-key --db <datei>",
              file=sys.stdout if hilfe else sys.stderr)
        sys.exit(0 if hilfe else 2)


if __name__ == "__main__":
    main()

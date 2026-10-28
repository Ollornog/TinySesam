"""CLI: `python -m tinysesam <command>` (also as the console script `tinysesam`).

    version                          the installed version
    passwd --db auth.db <user>       reset a password offline (maintenance; --blocklist-file,
                                     --rp-name: the same password rule as the config)
    backup --db auth.db <target>     take a consistent copy (do NOT copy the file!)
    restore --db auth.db <source>    restore a backup (stop the service first!)
    gc --db auth.db                  clear out what has expired (for cron/timer)
    audit --db auth.db [--user X]    look into the log (even if nobody gets in)
    unlock --db auth.db <user>       lift a brute-force lockout
    owner --db auth.db <user>        make an account an owner (emergency route)
    rename --db auth.db <old> <new>  rename an account (resolve an identifier collision)
    gate-key --db auth.db            public key of the gate tokens (for the proxy, ADR-9)

Deliberately lean. TinySesam does not install itself — an auth module that reloads
code at runtime is a back door with an instruction manual. Updating is done from outside:
pull the tag, reinstall, restart the service. See README, "Installation and updates".

`passwd` does not contradict this (ADR-2): it loads nothing and talks to no running service,
but opens a database file to which one needs file access anyway. It is the
way out for the case the presets without a mailer are meant for — internal tool, admin
password gone, no "forgot password" link and no second admin.
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
    # The CLI reads no config — what stands there for the password rule, it gets here.
    # Without these two switches a weaker rule applied offline than on the web (A-7).
    ap.add_argument("--blocklist-file", default="",
                    help="eigene Blockliste wie config.password_blocklist_file")
    ap.add_argument("--rp-name", default="",
                    help="Dienstname wie config.rp_name (gilt als Kontextwort)")
    a = ap.parse_args(argv)

    # Store instead of TinySesam: no FastAPI needed, and the instance would have side effects
    # (demo seeding, first-admin token) — neither has any business in a maintenance command.
    import os
    from .store import Store
    from .passwords import hash_password, passwort_mangel, blockliste_lesen
    from .security import haertung_lesen

    # Without this check sqlite3 silently creates the file and the typo in the path
    # would come back as "Kein Konto 'admin'" — the most baffling of all error messages.
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
    # The minimum length via THE SAME read path as `TinySesam._sec()`: read raw, a
    # legacy value without bounds (4, 0) kept applying here, while the web pulled it up to 8.
    #
    # And the STRICTER of the two lengths (B2-4): the CLI reads no configuration and therefore
    # does not know whether a chain enforces a second factor. When in doubt the rule for
    # a password that can sign in on its own applies; whoever does not want that lowers
    # `password_min_length_single_factor` in the panel.
    minlen = max(haertung_lesen(store, "password_min_length"),
                 haertung_lesen(store, "password_min_length_single_factor"))
    # The same rule as on the web (length, maximum length, built-in blocklist, username,
    # e-mail name) — the CLI is a way of setting like the others. The operator's blocklist and service
    # name come via `--blocklist-file` and `--rp-name`, because the CLI reads no config.
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
    # Bound anew: a series lockout (B2-6) ends here like with any other reset — under
    # name, address and the name in the directory (G5, `Store.zaehl_kennungen`).
    for kennung in store.zaehl_kennungen(user["id"]):
        store.fehlserie_loeschen(kennung)
    note = ""
    if not a.keep_sessions:
        # Standard after every credential change: open sessions no longer count.
        store.delete_user_sessions(user["id"])
        note = " (offene Sitzungen beendet)"
    store.audit_log("password_reset_cli", a.username, None, "offline")
    print(f"Passwort für '{a.username}' gesetzt{note}.")
    return 0


def _oeffne(pfad: str):
    """Store on an EXISTING file. As with `passwd`: no TinySesam, so that a
    maintenance command triggers no demo seeding and no first-admin token."""
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
    # NOT via `_oeffne()`: the Store constructor migrates the file before a copy
    # exists — a backup that changes its source is none. `sichere_datei` opens
    # read-only.
    try:
        Store.sichere_datei(a.db, a.ziel)
    except Exception as e:
        print(f"Sicherung fehlgeschlagen: {type(e).__name__}: {e}", file=sys.stderr)
        for rest in ("", "-wal", "-shm"):
            if os.path.exists(a.ziel + rest):
                os.remove(a.ziel + rest)      # leave no half file behind
        return 1
    print(f"Sicherung geschrieben: {a.ziel} ({os.path.getsize(a.ziel)} Bytes, Rechte 0600).")
    # The backup contains the TOTP secrets only encrypted (H-14/H-15). Without the key
    # it is worthless for TOTP — it belongs backed up separately, not in the same storage.
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
    # First check whether the backup is any good at all — not only after overwriting.
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

    # The order is the actual content of this command.
    for rest in ("-wal", "-shm"):
        if os.path.exists(a.db + rest):
            os.remove(a.db + rest)
    shutil.copyfile(a.quelle, a.db)
    try:
        os.chmod(a.db, Store.DATEIRECHTE)
    except OSError:
        pass  # file system without Unix permissions — the copy itself is complete
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
    # The same bound as `audit_retention_days` — checked before anything is deleted.
    # 10**20 otherwise aborted with OverflowError when sessions and tokens were already gone.
    from .konfigpruefung import ZAHLENGRENZEN
    unten, oben = ZAHLENGRENZEN["audit_retention_days"]
    if not unten <= a.audit_days <= oben:
        ap.error(f"--audit-days muss zwischen {unten} und {oben} liegen (Tage, nicht Sekunden)")
    # The same for the login attempts (second attack round): ±10**20 aborted after the first
    # deletion steps, a negative value also cleared the running lockout window.
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
    # Filter in SQL, not here: post-filtering the most recent rows found an account's entries
    # only if they happened to fall into the window — so precisely not during a brute-force wave.
    # The command then reported "Keine Einträge zu 'X'." and exit 0, although they were there.
    zeilen = store.recent_audit(a.n, username=a.user or None)
    if not zeilen:
        print("Keine Einträge." if not a.user else f"Keine Einträge zu '{a.user}'.")
        return 0
    # Every field through `zeilenfest` (B5-06): username and detail come from forms and
    # foreign responses. A `\n` in them printed a second, freely invented line here — with
    # timestamp, event and IP of choice — exactly in the view one relies on in
    # the case at hand. A control character (ESC) could moreover reconfigure the terminal itself.
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
    # Counting is done under the folded identifier (`norm_kennung`), so clear it that way, too.
    from .store import norm_kennung
    topf = norm_kennung(a.username)
    # The account for the identifier: via the name, via name or address in the counting bucket, or via the
    # name under which it last signed in in the directory (G5). Until 2026-09-26 only
    # via the name — after a rename in the directory (locally `alice`, there `alice.neu`)
    # `unlock alice.neu` aborted with "Kein Konto", although counting was done under exactly that name.
    konto = (store.get_user_by_name(a.username) or store.konto_mit_topf(topf)
             or store.konto_mit_bindungsname(topf))
    offen = store.count_fails(0, username=topf)
    store.clear_fails(username=topf)
    # The series lockout (B2-6) as well, under all identifiers of the account — counting is done under what
    # someone typed — and always under the typed one itself.
    serie = sum(store.fehlserie_loeschen(k) for k in
                ({topf} | (store.zaehl_kennungen(konto["id"]) if konto else set())) - {""})
    if konto is None:
        # No account — but counting is also done for identifiers without an account (B2-6 does not reveal whether there
        # is one), and an existing database does not know the name in the directory yet (it only comes into being
        # with the next successful sign-in). What stood under the identifier is cleared.
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


#: Maximum length of a username — the same as `TinySesam.NAME_MAX` (the CLI does not import the
#: manager, it pulls in FastAPI; tests/test_admin_konto.py keeps both equal).
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
        # Via the ID: a name with control characters (existing data) cannot be typed in, and on
        # a collision the startup message names the accounts via their user_id anyway.
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
        # As with `change_username`: a name that is a foreign address would occupy the mailbox
        # of a person who does not exist here yet.
        print(f"'{neu}' ist eine Adresse — als Name nur die eigene bestätigte Adresse des Kontos.",
              file=sys.stderr)
        return 1
    alt = str(konto["username"])
    if neu == alt:
        print(f"'{alt}' heisst schon so — nichts geändert.")
        return 0
    # Cross-wise, like `TinySesam.identifier_taken`: name, address, counting bucket and the name in the
    # directory of another account (review round 2026-09-27).
    for treffer in (store.get_user_by_name(neu), store.get_user_by_email(neu),
                    store.konto_mit_topf(neu, ausser=konto["id"]),
                    store.konto_mit_verzeichnisname(neu, ausser=konto["id"])):
        if treffer is not None and treffer["id"] != konto["id"]:
            print(f"'{neu}' ist schon vergeben (Konto {treffer['id']}, als Name, Adresse oder Name "
                  "im Verzeichnis).", file=sys.stderr)
            return 1
    try:
        # As operator: the marker "chosen by themselves" (G2-N) is dropped — the name stands for the
        # operator, and the sign-in via LDAP/SAML may bind the account via it again.
        store.set_username(konto["id"], neu, selbst_gewaehlt=False)
    except sqlite3.IntegrityError:
        # Race with the running service: assigned in between — the database decides (G12c).
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
    # The key is derived from the base key. If that does not exist yet, `schluessel_laden`
    # creates it — a read command must not do that: the proxy would get a key
    # that the service (with its environment) does not use at all.
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
        # `--help` is a question, not an error: it belongs on stdout and ends with 0. A
        # typo, on the other hand, goes to stderr and ends with 2, otherwise no script notices the difference.
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

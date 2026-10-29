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
    delete --db auth.db <user>       delete an account (asks; --ja for scripts; not an owner)
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
                                 description="Reset an account's password offline.")
    ap.add_argument("username", help="username of the account")
    ap.add_argument("--db", required=True, help="path to the TinySesam database (config.db_path)")
    ap.add_argument("--stdin", action="store_true",
                    help="read the password from standard input instead of prompting")
    ap.add_argument("--keep-sessions", action="store_true",
                    help="do NOT end the account's open sessions (default: end them)")
    # The CLI reads no config — what stands there for the password rule, it gets here.
    # Without these two switches a weaker rule applied offline than on the web (A-7).
    ap.add_argument("--blocklist-file", default="",
                    help="custom blocklist like config.password_blocklist_file")
    ap.add_argument("--rp-name", default="",
                    help="service name like config.rp_name (counts as a context word)")
    a = ap.parse_args(argv)

    # Store instead of TinySesam: no FastAPI needed, and the instance would have side effects
    # (demo seeding, first-admin token) — neither has any business in a maintenance command.
    import os
    from .store import Store
    from .passwords import hash_password, passwort_mangel, blockliste_lesen
    from .security import haertung_lesen

    # Without this check sqlite3 silently creates the file and the typo in the path
    # would come back as "No account 'admin'" — the most baffling of all error messages.
    if not os.path.exists(a.db):
        print(f"No database at {a.db}.", file=sys.stderr)
        return 1
    store = Store(a.db)
    user = store.get_user_by_name(a.username)
    if not user:
        print(f"No account '{a.username}' in {a.db}.", file=sys.stderr)
        return 1

    if a.stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Repeat:       "):
            print("The two entries differ.", file=sys.stderr)
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
            print(f"Blocklist {a.blocklist_file!r} cannot be read: {e}", file=sys.stderr)
            return 1
    mangel = passwort_mangel(pw, minlen, blockliste=blockliste,
                             kontext=(a.username, (user["email"] or "").split("@", 1)[0], a.rp_name))
    if mangel:
        grund, werte = mangel
        print({"short": f"Password too short (min. {werte.get('n')}).",
               "long": f"Password too long (max. {werte.get('n')}).",
               "weak": "Password too easy to guess (known, trivial or derived from the account name)."}[grund],
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
        note = " (open sessions ended)"
    store.audit_log("password_reset_cli", a.username, None, "offline")
    print(f"Password for '{a.username}' set{note}.")
    return 0


def _oeffne(pfad: str):
    """Store on an EXISTING file. As with `passwd`: no TinySesam, so that a
    maintenance command triggers no demo seeding and no first-admin token."""
    import os
    from .store import Store
    if not os.path.exists(pfad):
        print(f"No database at {pfad}.", file=sys.stderr)
        return None
    return Store(pfad)


def _backup(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam backup",
        description="Take a consistent copy of the database, even while the service is running.",
        epilog="A file copy (cp/rsync) is NOT enough: the database runs in WAL mode, everything "
               "since the last checkpoint is in the -wal file. Backing up only the .db "
               "gives you a stump — and you only notice when restoring.")
    ap.add_argument("ziel", help="path of the backup file (will be created)")
    ap.add_argument("--db", required=True, help="path to the TinySesam database (config.db_path)")
    a = ap.parse_args(argv)
    import os

    from .store import Store
    if not os.path.exists(a.db):
        print(f"No database at {a.db}.", file=sys.stderr)
        return 1
    if os.path.exists(a.ziel):
        print(f"{a.ziel} already exists — nothing overwritten.", file=sys.stderr)
        return 1
    # NOT via `_oeffne()`: the Store constructor migrates the file before a copy
    # exists — a backup that changes its source is none. `sichere_datei` opens
    # read-only.
    try:
        Store.sichere_datei(a.db, a.ziel)
    except Exception as e:
        print(f"Backup failed: {type(e).__name__}: {e}", file=sys.stderr)
        for rest in ("", "-wal", "-shm"):
            if os.path.exists(a.ziel + rest):
                os.remove(a.ziel + rest)      # leave no half file behind
        return 1
    print(f"Backup written: {a.ziel} ({os.path.getsize(a.ziel)} bytes, mode 0600).")
    # The backup contains the TOTP secrets only encrypted (H-14/H-15). Without the key
    # it is worthless for TOTP — it belongs backed up separately, not in the same storage.
    if os.path.exists(a.db + ".key"):
        print(f"Note: the key for the TOTP secrets is in {a.db}.key and is NOT in the "
              "backup. Back it up separately — without it all accounts have to set up TOTP again.")
    else:
        print("Note: back up the key for the TOTP secrets (TINYSESAM_SECRETS_KEY or "
              "secrets_key_file) separately — without it TOTP is lost from this backup.")
    return 0


def _restore(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam restore",
        description="Restore a backup — in the order that matters.",
        epilog="Stop the service FIRST. A plain `cp backup.db auth.db` is not enough: "
               "after a crash `auth.db-wal` and `auth.db-shm` sit next to it, and SQLite "
               "replays them onto the freshly restored file at the next start — the old "
               "state is back, without an error message, and `PRAGMA integrity_check` says `ok`. "
               "This command removes both files before it replaces.")
    ap.add_argument("quelle", help="the backup file")
    ap.add_argument("--db", required=True, help="target: the service's database")
    ap.add_argument("--ja", action="store_true", help="do not ask for confirmation (for scripts)")
    a = ap.parse_args(argv)
    import os
    import shutil
    import sqlite3

    if not os.path.exists(a.quelle):
        print(f"No backup at {a.quelle}.", file=sys.stderr)
        return 1
    # First check whether the backup is any good at all — not only after overwriting.
    try:
        pruef = sqlite3.connect(f"file:{a.quelle}?mode=ro", uri=True)
        heil = pruef.execute("PRAGMA integrity_check").fetchone()[0]
        konten = pruef.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        stand = pruef.execute("PRAGMA user_version").fetchone()[0]
        pruef.close()
    except Exception as e:
        print(f"{a.quelle} is not a readable TinySesam database: {e}", file=sys.stderr)
        return 1
    if heil != "ok":
        print(f"The backup is damaged (integrity_check: {heil}).", file=sys.stderr)
        return 1

    from .store import Store
    if stand > Store.SCHEMA_VERSION:
        print(f"The backup carries schema version {stand}, this version knows {Store.SCHEMA_VERSION}. "
              "It comes from a newer TinySesam version — install the matching version.",
              file=sys.stderr)
        return 1

    print(f"Backup: {a.quelle} — {konten} accounts, schema {stand}, integrity_check ok")
    if os.path.exists(a.db) and not a.ja:
        print(f"This overwrites {a.db}. The service must be STOPPED.")
        if input("Continue? [y/N] ").strip().lower() not in ("j", "ja", "y", "yes"):
            print("Aborted.")
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
    print(f"Restored: {a.db} (mode 0600). Start the service again.")
    return 0


def _gc(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam gc",
        description="Delete expired sessions, flows, one-time tokens and old login attempts.",
        epilog="Does not run by itself. Meant for a timer/cron. The audit log is left "
               "untouched unless --audit-days is set.")
    ap.add_argument("--db", required=True, help="path to the TinySesam database (config.db_path)")
    ap.add_argument("--attempts-older-than", type=int, default=86400, metavar="SEC",
                    help="delete login attempts older than N seconds (default: 86400)")
    ap.add_argument("--audit-days", type=int, default=0, metavar="DAYS",
                    help="delete audit entries older than N days (default: 0 = none; "
                         "counterpart to config.audit_retention_days)")
    a = ap.parse_args(argv)
    # The same bound as `audit_retention_days` — checked before anything is deleted.
    # 10**20 otherwise aborted with OverflowError when sessions and tokens were already gone.
    from .config_check import ZAHLENGRENZEN
    unten, oben = ZAHLENGRENZEN["audit_retention_days"]
    if not unten <= a.audit_days <= oben:
        ap.error(f"--audit-days must be between {unten} and {oben} (days, not seconds)")
    # The same for the login attempts (second attack round): ±10**20 aborted after the first
    # deletion steps, a negative value also cleared the running lockout window.
    from .store import versuchsfrist, VERSUCHSFRIST_MAX_SEK
    try:
        versuchsfrist(a.attempts_older_than)
    except ValueError:
        ap.error(f"--attempts-older-than must be between 0 and {VERSUCHSFRIST_MAX_SEK} "
                 "(seconds; 0 clears all failed attempts)")
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
        description="Look into the audit log — from the command line.",
        epilog="Until now it could only be read through the admin panel, i.e. only as a signed-in "
               "admin — unreachable precisely when signing in is the problem.")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
    ap.add_argument("--user", default="", help="only entries for this account")
    ap.add_argument("-n", type=int, default=30, help="how many lines (default: 30)")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    import datetime as _dt
    # Filter in SQL, not here: post-filtering the most recent rows found an account's entries
    # only if they happened to fall into the window — so precisely not during a brute-force wave.
    # The command then reported "No entries for 'X'." and exit 0, although they were there.
    zeilen = store.recent_audit(a.n, username=a.user or None)
    if not zeilen:
        print("No entries." if not a.user else f"No entries for '{a.user}'.")
        return 0
    # Every field through `zeilenfest` (B5-06): username and detail come from forms and
    # foreign responses. A `\n` in them printed a second, freely invented line here — with
    # timestamp, event and IP of choice — exactly in the view one relies on in
    # the case at hand. A control character (ESC) could moreover reconfigure the terminal itself.
    from .security import zeilenfest as _z
    from ._vokabular import audit_zeile_neu
    for z in reversed(zeilen):
        z = audit_zeile_neu(z)       # always the English spelling (rows written by an older version too)
        zeit = _dt.datetime.fromtimestamp(z["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{zeit}  {_z(z['event']):22} {_z(z['username'] or '-'):16} "
              f"{_z(z['ip'] or '-'):18} {_z(z['detail'] or '')}")
    return 0


def _unlock(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam unlock",
        description="Lift an account's brute-force lockout.",
        epilog="There used to be no way to do this: `clear_fails` only ran internally after a "
               "successful sign-in — and that is exactly what is locked. What remained was `gc "
               "--attempts-older-than 0`, which clears the failed attempts of ALL accounts.")
    ap.add_argument("username", help="the identifier as typed: username, address "
                                     "or the name in the directory (LDAP)")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
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
            print(f"No account '{a.username}' in {a.db}, and there is no lockout under this identifier.",
                  file=sys.stderr)
            return 1
        store.audit_log("unlock_cli", a.username, None,
                        f"failed_attempts={offen} in_a_row={serie} without_account=1")
        print(f"No account '{a.username}' — the lockout under this identifier is lifted anyway "
              f"({offen} failed attempts, {serie} in a row discarded).")
        return 0
    store.audit_log("unlock_cli", str(konto["username"]), None,
                    f"failed_attempts={offen} in_a_row={serie}"
                    + (f" identifier={a.username}" if norm_kennung(konto["username"]) != topf else ""))
    print(f"Lockout for '{a.username}' lifted ({offen} failed attempts discarded).")
    return 0


def _owner(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam owner",
        description="Make an account an owner — the emergency route when no owner can get in any more.",
        epilog="In the panel only an owner grants the role. If the only owner is locked out (passkey "
               "lost, person gone), the way in is through the database: whoever holds it "
               "runs the instance anyway.")
    ap.add_argument("username", help="username of the account")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    konto = store.get_user_by_name(a.username)
    if not konto:
        print(f"No account '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    if konto["is_service"] or konto["disabled"]:
        print(f"'{a.username}' is locked or a service account — an owner must be able to sign in.",
              file=sys.stderr)
        return 1
    store.set_owner(konto["id"], True)
    store.audit_log("owner_grant", a.username, None, "source=cli")
    print(f"'{a.username}' is an owner (and admin).")
    return 0


#: Maximum length of a username — the same as `TinySesam.NAME_MAX` (the CLI does not import the
#: manager, it pulls in FastAPI; tests/test_admin_account.py keeps both equal).
_NAME_MAX = 150


def _rename(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam rename",
        description="Rename an account — as operator, without a running service.",
        epilog="The way out of an identifier collision in existing data, which startup reports (G13). The same "
               "ground rules as in the panel: free among usernames AND addresses (also as namesakes "
               "like Alice/alice) and not the name of another account in the directory, no control characters, at most 150 characters, a name with @ only as "
               "the account's own confirmed address. The CLI does not know the configuration: it does not check a name from "
               "admin_identifiers, and in login_identifier='email' mode the "
               "name follows the address — do not rename there. Sessions, keys, factors and bindings "
               "hang on the account ID and stay; Remote-User changes towards the outside.")
    ap.add_argument("username", help="current username of the account, or #<id> (the user_id "
                                     "from the startup message — for a name that cannot "
                                     "be typed in)")
    ap.add_argument("neuer_name", help="the new username")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
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
        print(f"No account '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    neu = a.neuer_name.strip()
    if not neu or len(neu) > _NAME_MAX or name_ungueltig(neu):
        print("Invalid username (empty, longer than 150 characters or containing control characters).",
              file=sys.stderr)
        return 1
    eigene = norm_email(konto["email"]) if konto["email"] and konto["email_verified"] else None
    if "@" in norm_kennung(neu) and norm_email(neu) != eigene:
        # As with `change_username`: a name that is a foreign address would occupy the mailbox
        # of a person who does not exist here yet.
        print(f"'{neu}' is an address — as a name only the account's own confirmed address is allowed.",
              file=sys.stderr)
        return 1
    alt = str(konto["username"])
    if neu == alt:
        print(f"'{alt}' is already called that — nothing changed.")
        return 0
    # Cross-wise, like `TinySesam.identifier_taken`: name, address, counting bucket and the name in the
    # directory of another account (review round 2026-09-27).
    for treffer in (store.get_user_by_name(neu), store.get_user_by_email(neu),
                    store.konto_mit_topf(neu, ausser=konto["id"]),
                    store.konto_mit_verzeichnisname(neu, ausser=konto["id"])):
        if treffer is not None and treffer["id"] != konto["id"]:
            print(f"'{neu}' is already taken (account {treffer['id']}, as name, address or name "
                  "in the directory).", file=sys.stderr)
            return 1
    try:
        # As operator: the marker "chosen by themselves" (G2-N) is dropped — the name stands for the
        # operator, and the sign-in via LDAP/SAML may bind the account via it again.
        store.set_username(konto["id"], neu, selbst_gewaehlt=False)
    except sqlite3.IntegrityError:
        # Race with the running service: assigned in between — the database decides (G12c).
        print(f"'{neu}' is already taken — the database rejected the rename, nothing "
              "changed.", file=sys.stderr)
        return 1
    store.audit_log("username_changed", neu, None, f"old={alt} by=operator source=cli")
    print(f"'{alt}' is now called '{neu}'. Apps see the new name as Remote-User; the account ID "
          "(Remote-Id) stays.")
    return 0


def _delete(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam delete",
        description="Delete an account — as operator, without a running service or admin panel.",
        epilog="The same route and the same protection rules as the panel's \"Delete\" (H-13): "
               "credentials, sessions and identities go, the sign-in attempts under name and address "
               "go, and the name in the audit log becomes deleted#<id> — the rows themselves stay. "
               "An owner and the last admin are not deleted. Without --ja the command asks, and "
               "without a terminal it refuses. A raw DELETE in the database is the wrong way: it "
               "leaves the name in every audit row.")
    ap.add_argument("username", help="username of the account, or #<id> (the user_id from the "
                                     "startup message — for a name that cannot be typed in)")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
    ap.add_argument("--ja", action="store_true", help="do not ask for confirmation (for scripts)")
    a = ap.parse_args(argv)
    store = _oeffne(a.db)
    if store is None:
        return 1
    from .security import zeilenfest as _z
    from .store import ersatzname

    def finde():
        k = store.get_user_by_name(a.username)
        if k is None and a.username[:1] == "#" and a.username[1:].isascii() and a.username[1:].isdigit():
            k = store.get_user(int(a.username[1:]))
        return k

    def sperre_melden(k) -> bool:
        # THE rule of the panel (`TinySesam.delete_user`), not a copy of it.
        grund = store.loeschsperre(k)
        if grund == "owner":
            print(f"'{_z(k['username'])}' is an owner and cannot be deleted — hand over the owner "
                  "role first (this requires another owner to exist).", file=sys.stderr)
        elif grund == "last_admin":
            print(f"'{_z(k['username'])}' is the last admin and cannot be deleted.", file=sys.stderr)
        return grund is not None

    konto = finde()
    if not konto:
        print(f"No account '{_z(a.username)}' in {a.db}.", file=sys.stderr)
        return 1
    if sperre_melden(konto):
        return 1
    uid = int(konto["id"])
    n_sitzungen, n_identitaeten, n_schluessel = store.konto_bestand(uid)
    name = _z(konto["username"])
    umfang = (f"{n_sitzungen} session(s), {n_identitaeten} identity link(s), "
              f"{n_schluessel} API key(s)")
    if not a.ja:
        # Without a person to answer there is no confirmation: a script has to say --ja.
        if not sys.stdin.isatty():
            print("Not a terminal and no --ja — nothing deleted.", file=sys.stderr)
            return 1
        print(f"This deletes the account '{name}' (id {uid}) with {umfang}. "
              "The service may keep running.")
        try:
            antwort = input("Delete? [y/N] ")
        except EOFError:
            antwort = ""
        if antwort.strip().lower() not in ("j", "ja", "y", "yes"):
            print("Aborted.")
            return 1
        # The service may have changed the account while the question stood.
        konto = finde()
        if not konto:
            print(f"The account '{name}' is gone in the meantime — nothing to do.", file=sys.stderr)
            return 1
        if sperre_melden(konto):
            return 1
    # The ONE deletion path (`Store.konto_entfernen`), as in `TinySesam.delete_user`: only here, in
    # the deliberate deletion, does a verified address count as the account's own from before creation.
    # NOT `Store.delete_user`: that leaves the name in every audit row.
    entfernt = store.konto_entfernen(uid, adresse_unbefristet=True)
    if entfernt is None:
        print(f"The account '{name}' is gone in the meantime — nothing to do.", file=sys.stderr)
        return 1
    ersatz, n = entfernt
    store.audit_log("user_delete", ersatz, None, f"uid={uid} audit_anonymized={n} source=cli")
    print(f"Deleted '{name}' (id {uid}): {umfang}; {int(n)} audit row(s) anonymised as {ersatzname(uid)}.")
    return 0


def _gate_key(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam gate-key",
        description="Print the public key of the gate tokens (sign_key for caddy-jwt, "
                    "sign_alg EdDSA). Public, not a secret.")
    ap.add_argument("--db", required=True, help="path to the TinySesam database (config.db_path)")
    ap.add_argument("--secrets-key-file", default="", help="like config.secrets_key_file")
    a = ap.parse_args(argv)
    import os
    from . import gate, vault
    # The key is derived from the base key. If that does not exist yet, `load_key`
    # creates it — a read command must not do that: the proxy would get a key
    # that the service (with its environment) does not use at all.
    if not (os.environ.get(vault.ENV_VAR, "").strip() or a.secrets_key_file
            or os.path.exists(a.db + ".key")):
        print(f"No base key: neither {vault.ENV_VAR} nor --secrets-key-file nor "
              f"{a.db}.key. Call it with the same environment as the service.", file=sys.stderr)
        return 1
    try:
        schluessel, _herkunft = vault.load_key(a.db, a.secrets_key_file)
    except vault.ConfigError as e:
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
    elif cmd == "delete":
        sys.exit(_delete(argv[1:]))
    elif cmd == "gate-key":
        sys.exit(_gate_key(argv[1:]))
    else:
        # `--help` is a question, not an error: it belongs on stdout and ends with 0. A
        # typo, on the other hand, goes to stderr and ends with 2, otherwise no script notices the difference.
        hilfe = cmd in ("--help", "-h", "help")
        print("usage: python -m tinysesam version\n"
              "       python -m tinysesam passwd --db <file> <user>\n"
              "       python -m tinysesam backup --db <file> <target>\n"
              "       python -m tinysesam restore --db <file> <backup>\n"
              "       python -m tinysesam gc     --db <file>\n"
              "       python -m tinysesam audit  --db <file> [--user X]\n"
              "       python -m tinysesam unlock --db <file> <user>\n"
              "       python -m tinysesam owner  --db <file> <user>\n"
              "       python -m tinysesam rename --db <file> <user> <new-name>\n"
              "       python -m tinysesam delete --db <file> <user> [--ja]\n"
              "       python -m tinysesam gate-key --db <file>",
              file=sys.stdout if hilfe else sys.stderr)
        sys.exit(0 if hilfe else 2)


if __name__ == "__main__":
    main()

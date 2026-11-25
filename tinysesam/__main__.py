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
    delete --db auth.db <user>       delete an account (asks; --yes for scripts; not an owner)
    gate-key --db auth.db            public key of the gate tokens (for the proxy, ADR-9); --jwks: the key set
    accounts list|adopt|release|restore --db auth.db [--app X] [--config mod:attr]
                                     accounts of applications (account API): take over, release, cancel a deletion
    keys list|rotate|reencrypt|retire --db auth.db [--purpose vault|gate|oauth-pepper]
                                     the installation's keys (T-48, ADR-12): rotation without data loss
    diagnose [--config mod:attr] [--log F]  a redacted report and a prefilled bug-form link (T-79):
                                     no network request, nothing written, nothing sent — you check and submit

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
                    help="do NOT end the account's open sessions and standing credentials (API keys, app passwords, "
                         "services, connected OAuth devices; default: end and revoke them)")
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
    from .passwords import hash_password, password_defect, read_blocklist
    from .security import read_hardening

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
    minlen = max(read_hardening(store, "password_min_length"),
                 read_hardening(store, "password_min_length_single_factor"))
    # The same rule as on the web (length, maximum length, built-in blocklist, username,
    # e-mail name) — the CLI is a way of setting like the others. The operator's blocklist and service
    # name come via `--blocklist-file` and `--rp-name`, because the CLI reads no config.
    blocklist: frozenset = frozenset()
    if a.blocklist_file:
        try:
            blocklist = read_blocklist(a.blocklist_file)
        except OSError as e:
            print(f"Blocklist {a.blocklist_file!r} cannot be read: {e}", file=sys.stderr)
            return 1
    defect = password_defect(pw, minlen, blocklist=blocklist,
                             context=(a.username, (user["email"] or "").split("@", 1)[0], a.rp_name))
    if defect:
        reason, values = defect
        print({"short": f"Password too short (min. {values.get('n')}).",
               "long": f"Password too long (max. {values.get('n')}).",
               "weak": "Password too easy to guess (known, trivial or derived from the account name)."}[reason],
              file=sys.stderr)
        return 1

    store.set_password_hash(user["id"], hash_password(pw))
    # Bound anew: a series lockout (B2-6) ends here like with any other reset — under
    # name, address and the name in the directory (G5, `Store.count_identifiers`).
    for identifier in store.count_identifiers(user["id"]):
        store.delete_failure_series(identifier)
    note = ""
    if not a.keep_sessions:
        # Standard after every credential change: open sessions no longer count. And the standing credentials go
        # with them like with the admin reset in the panel (`TinySesam._keys_revoked`): whoever resets offline does so
        # for a lost or taken-over account, and a key, app password or connected device would keep the door open
        # (attack round 2026-11-21, A-1). Offline there is no hook — the audit line names the counts.
        store.delete_user_sessions(user["id"])
        revoked = store.revoke_user_access(user["id"], "admin_password_reset")
        note = " (open sessions ended" + "".join(f", {n} {what} revoked" for what, n in revoked.items() if n) + ")"
    store.audit_log("password_reset_cli", a.username, None,
                    "offline" + ("" if a.keep_sessions else "".join(f" {what}_revoked={n}" for what, n in revoked.items())))
    print(f"Password for '{a.username}' set{note}.")
    return 0


def _open(path: str):
    """Store on an EXISTING file. As with `passwd`: no TinySesam, so that a
    maintenance command triggers no demo seeding and no first-admin token."""
    import os
    from .store import Store
    if not os.path.exists(path):
        print(f"No database at {path}.", file=sys.stderr)
        return None
    return Store(path)


def _backup(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam backup",
        description="Take a consistent copy of the database, even while the service is running.",
        epilog="A file copy (cp/rsync) is NOT enough: the database runs in WAL mode, everything "
               "since the last checkpoint is in the -wal file. Backing up only the .db "
               "gives you a stump — and you only notice when restoring.")
    ap.add_argument("destination", help="path of the backup file (will be created)")
    ap.add_argument("--db", required=True, help="path to the TinySesam database (config.db_path)")
    a = ap.parse_args(argv)
    import os

    from .store import Store
    if not os.path.exists(a.db):
        print(f"No database at {a.db}.", file=sys.stderr)
        return 1
    if os.path.exists(a.destination):
        print(f"{a.destination} already exists — nothing overwritten.", file=sys.stderr)
        return 1
    # NOT via `_open()`: the Store constructor migrates the file before a copy
    # exists — a backup that changes its source is none. `secure_file` opens
    # read-only.
    try:
        Store.secure_file(a.db, a.destination)
    except Exception as e:
        print(f"Backup failed: {type(e).__name__}: {e}", file=sys.stderr)
        for rest in ("", "-wal", "-shm"):
            if os.path.exists(a.destination + rest):
                os.remove(a.destination + rest)      # leave no half file behind
        return 1
    print(f"Backup written: {a.destination} ({os.path.getsize(a.destination)} bytes, mode 0600).")
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
    ap.add_argument("source", help="the backup file")
    ap.add_argument("--db", required=True, help="target: the service's database")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation (for scripts)")
    a = ap.parse_args(argv)
    import os
    import shutil
    import sqlite3

    if not os.path.exists(a.source):
        print(f"No backup at {a.source}.", file=sys.stderr)
        return 1
    # First check whether the backup is any good at all — not only after overwriting.
    try:
        check = sqlite3.connect(f"file:{a.source}?mode=ro", uri=True)
        whole = check.execute("PRAGMA integrity_check").fetchone()[0]
        accounts = check.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        state = check.execute("PRAGMA user_version").fetchone()[0]
        check.close()
    except Exception as e:
        print(f"{a.source} is not a readable TinySesam database: {e}", file=sys.stderr)
        return 1
    if whole != "ok":
        print(f"The backup is damaged (integrity_check: {whole}).", file=sys.stderr)
        return 1

    from .store import Store
    if state > Store.SCHEMA_VERSION:
        print(f"The backup carries schema version {state}, this version knows {Store.SCHEMA_VERSION}. "
              "It comes from a newer TinySesam version — install the matching version.",
              file=sys.stderr)
        return 1

    print(f"Backup: {a.source} — {accounts} accounts, schema {state}, integrity_check ok")
    if os.path.exists(a.db) and not a.yes:
        print(f"This overwrites {a.db}. The service must be STOPPED.")
        if input("Continue? [y/N] ").strip().lower() not in ("j", "ja", "y", "yes"):
            print("Aborted.")
            return 1

    # The order is the actual content of this command.
    for rest in ("-wal", "-shm"):
        if os.path.exists(a.db + rest):
            os.remove(a.db + rest)
    shutil.copyfile(a.source, a.db)
    try:
        os.chmod(a.db, Store.FILE_PERMISSIONS)
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
    from .config_check import NUMBER_LIMITS
    below, above = NUMBER_LIMITS["audit_retention_days"]
    if not below <= a.audit_days <= above:
        ap.error(f"--audit-days must be between {below} and {above} (days, not seconds)")
    # The same for the login attempts (second attack round): ±10**20 aborted after the first
    # deletion steps, a negative value also cleared the running lockout window.
    from .store import attempt_deadline, ATTEMPT_DEADLINE_MAX_SEC
    try:
        attempt_deadline(a.attempts_older_than)
    except ValueError:
        ap.error(f"--attempts-older-than must be between 0 and {ATTEMPT_DEADLINE_MAX_SEC} "
                 "(seconds; 0 clears all failed attempts)")
    store = _open(a.db)
    if store is None:
        return 1
    import time as _t
    numbers = {
        "unverified_accounts": store.gc_unconfirmed_accounts(),   # before the tokens (R4-09)
        "sessions": store.gc_sessions(),
        "flow": store.gc_flow(),
        "magic_tokens": store.gc_magic_tokens(),
        "resource_unlocks": store.gc_resource_unlocks(),
        "login_attempts": store.gc_attempts(int(_t.time()) - a.attempts_older_than),
    }
    # OAuth (T-36): the same step as `TinySesam.gc()` — the systemd timer runs this command.
    from . import oauth as _oauth
    numbers.update(store.gc_oauth(int(_t.time()), _oauth.IDLE_CLIENT_SEC, _oauth.REVOKED_KEEP_SEC))
    # Account API (stage B): the same step as `TinySesam.gc()` — accounts whose grace period after a deletion by their
    # application has run out, through the one deletion path (audit anonymised).
    numbers["provisioning_deleted"] = store.gc_provisioning(int(_t.time()))
    if a.audit_days > 0:
        numbers["audit"] = store.gc_audit(int(_t.time()) - a.audit_days * 86400)
    print(" ".join(f"{k}={v}" for k, v in numbers.items()))
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
    store = _open(a.db)
    if store is None:
        return 1
    import datetime as _dt
    # Filter in SQL, not here: post-filtering the most recent rows found an account's entries
    # only if they happened to fall into the window — so precisely not during a brute-force wave.
    # The command then reported "No entries for 'X'." and exit 0, although they were there.
    lines = store.recent_audit(a.n, username=a.user or None)
    if not lines:
        print("No entries." if not a.user else f"No entries for '{a.user}'.")
        return 0
    # Every field through `line_fixed` (B5-06): username and detail come from forms and
    # foreign responses. A `\n` in them printed a second, freely invented line here — with
    # timestamp, event and IP of choice — exactly in the view one relies on in
    # the case at hand. A control character (ESC) could moreover reconfigure the terminal itself.
    from .security import line_fixed as _z
    for z in reversed(lines):
        when = _dt.datetime.fromtimestamp(z["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{when}  {_z(z['event']):22} {_z(z['username'] or '-'):16} "
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
    store = _open(a.db)
    if store is None:
        return 1
    # Counting is done under the folded identifier (`norm_identifier`), so clear it that way, too.
    from .store import norm_identifier
    bucket = norm_identifier(a.username)
    # The account for the identifier: via the name, via name or address in the counting bucket, or via the
    # name under which it last signed in in the directory (G5). Until 2026-09-26 only
    # via the name — after a rename in the directory (locally `alice`, there `alice.neu`)
    # `unlock alice.neu` aborted with "Kein Konto", although counting was done under exactly that name.
    account = (store.get_user_by_name(a.username) or store.account_by_bucket(bucket)
             or store.account_with_binding_name(bucket))
    unclosed = store.count_fails(0, username=bucket)
    store.clear_fails(username=bucket)
    # The series lockout (B2-6) as well, under all identifiers of the account — counting is done under what
    # someone typed — and always under the typed one itself.
    series = sum(store.delete_failure_series(k) for k in
                ({bucket} | (store.count_identifiers(account["id"]) if account else set())) - {""})
    if account is None:
        # No account — but counting is also done for identifiers without an account (B2-6 does not reveal whether there
        # is one), and an existing database does not know the name in the directory yet (it only comes into being
        # with the next successful sign-in). What stood under the identifier is cleared.
        if not (unclosed or series):
            print(f"No account '{a.username}' in {a.db}, and there is no lockout under this identifier.",
                  file=sys.stderr)
            return 1
        store.audit_log("unlock_cli", a.username, None,
                        f"failed_attempts={unclosed} in_a_row={series} without_account=1")
        print(f"No account '{a.username}' — the lockout under this identifier is lifted anyway "
              f"({unclosed} failed attempts, {series} in a row discarded).")
        return 0
    store.audit_log("unlock_cli", str(account["username"]), None,
                    f"failed_attempts={unclosed} in_a_row={series}"
                    + (f" identifier={a.username}" if norm_identifier(account["username"]) != bucket else ""))
    print(f"Lockout for '{a.username}' lifted ({unclosed} failed attempts discarded).")
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
    store = _open(a.db)
    if store is None:
        return 1
    account = store.get_user_by_name(a.username)
    if not account:
        print(f"No account '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    if account["is_service"] or account["disabled"]:
        print(f"'{a.username}' is locked or a service account — an owner must be able to sign in.",
              file=sys.stderr)
        return 1
    store.set_owner(account["id"], True)
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
    ap.add_argument("new_name", help="the new username")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
    a = ap.parse_args(argv)
    store = _open(a.db)
    if store is None:
        return 1
    import sqlite3
    from .store import name_invalid, norm_email, norm_identifier
    account = store.get_user_by_name(a.username)
    if account is None and a.username[:1] == "#" and a.username[1:].isascii() and a.username[1:].isdigit():
        # Via the ID: a name with control characters (existing data) cannot be typed in, and on
        # a collision the startup message names the accounts via their user_id anyway.
        account = store.get_user(int(a.username[1:]))
    if not account:
        print(f"No account '{a.username}' in {a.db}.", file=sys.stderr)
        return 1
    new = a.new_name.strip()
    if not new or len(new) > _NAME_MAX or name_invalid(new):
        print("Invalid username (empty, longer than 150 characters or containing control characters).",
              file=sys.stderr)
        return 1
    own = norm_email(account["email"]) if account["email"] and account["email_verified"] else None
    if "@" in norm_identifier(new) and norm_email(new) != own:
        # As with `change_username`: a name that is a foreign address would occupy the mailbox
        # of a person who does not exist here yet.
        print(f"'{new}' is an address — as a name only the account's own confirmed address is allowed.",
              file=sys.stderr)
        return 1
    old = str(account["username"])
    if new == old:
        print(f"'{old}' is already called that — nothing changed.")
        return 0
    # Cross-wise, like `TinySesam.identifier_taken`: name, address, counting bucket and the name in the
    # directory of another account (review round 2026-09-27).
    for hit in (store.get_user_by_name(new), store.get_user_by_email(new),
                    store.account_by_bucket(new, other_than=account["id"]),
                    store.account_with_directory_name(new, other_than=account["id"])):
        if hit is not None and hit["id"] != account["id"]:
            print(f"'{new}' is already taken (account {hit['id']}, as name, address or name "
                  "in the directory).", file=sys.stderr)
            return 1
    try:
        # As operator: the marker "chosen by themselves" (G2-N) is dropped — the name stands for the
        # operator, and the sign-in via LDAP/SAML may bind the account via it again.
        store.set_username(account["id"], new, itself_chosen=False)
    except sqlite3.IntegrityError:
        # Race with the running service: assigned in between — the database decides (G12c).
        print(f"'{new}' is already taken — the database rejected the rename, nothing "
              "changed.", file=sys.stderr)
        return 1
    store.audit_log("username_changed", new, None, f"old={old} by=operator source=cli")
    print(f"'{old}' is now called '{new}'. Apps see the new name as Remote-User; the account ID "
          "(Remote-Id) stays.")
    return 0


def _delete(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam delete",
        description="Delete an account — as operator, without a running service or admin panel.",
        epilog="The same route and the same protection rules as the panel's \"Delete\" (H-13): "
               "credentials, sessions and identities go, the sign-in attempts under name and address "
               "go, and the name in the audit log becomes deleted#<id> — the rows themselves stay. "
               "An owner and the last admin are not deleted. Without --yes the command asks, and "
               "without a terminal it refuses. A raw DELETE in the database is the wrong way: it "
               "leaves the name in every audit row.")
    ap.add_argument("username", help="username of the account, or #<id> (the user_id from the "
                                     "startup message — for a name that cannot be typed in)")
    ap.add_argument("--db", required=True, help="path to the TinySesam database")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation (for scripts)")
    a = ap.parse_args(argv)
    store = _open(a.db)
    if store is None:
        return 1
    from .security import line_fixed as _z
    from .store import replacement_name

    def find():
        k = store.get_user_by_name(a.username)
        if k is None and a.username[:1] == "#" and a.username[1:].isascii() and a.username[1:].isdigit():
            k = store.get_user(int(a.username[1:]))
        return k

    def report_lock(k) -> bool:
        # THE rule of the panel (`TinySesam.delete_user`), not a copy of it.
        reason = store.deletion_guard(k)
        if reason == "owner":
            print(f"'{_z(k['username'])}' is an owner and cannot be deleted — hand over the owner "
                  "role first (this requires another owner to exist).", file=sys.stderr)
        elif reason == "last_admin":
            print(f"'{_z(k['username'])}' is the last admin and cannot be deleted.", file=sys.stderr)
        return reason is not None

    account = find()
    if not account:
        print(f"No account '{_z(a.username)}' in {a.db}.", file=sys.stderr)
        return 1
    if report_lock(account):
        return 1
    uid = int(account["id"])
    n_sessions, n_identities, n_key_name = store.account_footprint(uid)
    name = _z(account["username"])
    scope = (f"{n_sessions} session(s), {n_identities} identity link(s), "
              f"{n_key_name} API key(s)")
    if not a.yes:
        # Without a person to answer there is no confirmation: a script has to say --yes.
        if not sys.stdin.isatty():
            print("Not a terminal and no --yes — nothing deleted.", file=sys.stderr)
            return 1
        print(f"This deletes the account '{name}' (id {uid}) with {scope}. "
              "The service may keep running.")
        try:
            response = input("Delete? [y/N] ")
        except EOFError:
            response = ""
        if response.strip().lower() not in ("j", "ja", "y", "yes"):
            print("Aborted.")
            return 1
        # The service may have changed the account while the question stood.
        account = find()
        if not account:
            print(f"The account '{name}' is gone in the meantime — nothing to do.", file=sys.stderr)
            return 1
        if report_lock(account):
            return 1
    # The ONE deletion path (`Store.remove_account`), as in `TinySesam.delete_user`: only here, in
    # the deliberate deletion, does a verified address count as the account's own from before creation.
    # NOT `Store.delete_user`: that leaves the name in every audit row.
    removed = store.remove_account(uid, address_unlimited=True)
    if removed is None:
        print(f"The account '{name}' is gone in the meantime — nothing to do.", file=sys.stderr)
        return 1
    replacement, n = removed
    store.audit_log("user_delete", replacement, None, f"uid={uid} audit_anonymized={n} source=cli")
    print(f"Deleted '{name}' (id {uid}): {scope}; {int(n)} audit row(s) anonymised as {replacement_name(uid)}.")
    return 0


def _key_args(ap) -> None:
    ap.add_argument("--db", required=True, help="path to the TinySesam database (config.db_path)")
    ap.add_argument("--secrets-key-file", default="", help="like config.secrets_key_file")
    ap.add_argument("--gate-key-file", default="", help="like config.gate_key_file")
    ap.add_argument("--oauth-pepper-file", default="", help="like config.oauth_pepper_file")
    ap.add_argument("--approval-key-file", default="", help="like config.approval_key_file")


def _open_keys(a):
    """(store, {purpose: keyring}) with the same sources as the service — never creating a key: a maintenance
    command that made up a vault key would hand out one the service (with its environment) does not use."""
    import os
    from . import keys as K, vault as V
    from .store import Store
    if not os.path.exists(a.db):
        raise V.ConfigError(f"No database at {a.db}.")
    if not (os.environ.get(K.ENV[K.VAULT], "").strip() or a.secrets_key_file or os.path.exists(a.db + ".key")):
        raise V.ConfigError(f"No vault key: neither {K.ENV[K.VAULT]} nor --secrets-key-file nor {a.db}.key. "
                            f"Call it with the same environment as the service.")
    rings: dict = {K.VAULT: K.load_vault(a.db, a.secrets_key_file)}
    store = Store(a.db)
    store.vault = V.Vault(rings[K.VAULT])
    for purpose, path in ((K.GATE, a.gate_key_file), (K.PEPPER, a.oauth_pepper_file),
                          (K.APPROVAL, a.approval_key_file)):
        ring = K.from_override(purpose, path)
        if ring is None:
            try:
                rows = store.key_ring_rows(purpose)
            except ValueError as e:      # a row that is not vault ciphertext or does not match its ID (A-5)
                raise V.ConfigError(f"key_material ({purpose}): {e}") from None
            ring = K.Keyring(purpose, rows, "database") if rows else None
        rings[purpose] = ring
    return store, rings


def _when(t) -> str:
    import datetime
    if t is None:
        return "unknown"
    return datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _keys(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam keys",
        description="The installation's keys (T-48, ADR-12): list them, rotate one, re-encrypt the stored secrets "
                    "with the active key, retire keys nothing needs any more. Never prints key material.")
    sub = ap.add_subparsers(dest="action", required=True)
    for name, text in (("list", "every key with its ID, state and what still needs it"),
                       ("rotate", "a new active key for --purpose; the old one stays previous"),
                       ("reencrypt", "rewrite every stored secret with the active vault key (with progress)"),
                       ("retire", "remove previous keys of --purpose — refuses while anything needs them")):
        p = sub.add_parser(name, help=text, description=text)
        _key_args(p)
        if name in ("rotate", "retire"):
            p.add_argument("--purpose", required=True, choices=("vault", "gate", "oauth-pepper", "approval"))
        if name == "retire":
            p.add_argument("--kid", action="append", default=[], help="only this previous key (repeatable)")
            p.add_argument("--force", action="store_true",
                           help="gate/oauth-pepper/approval only: retire before the overlap has passed (tokens signed "
                                "or digested with it stop working — gate: one fallback request, OAuth: reconnect, "
                                "approval: a confirmation not yet checked fails)")
    a = ap.parse_args(argv)
    import time
    from . import keys as K, vault as V
    try:
        store, rings = _open_keys(a)
    except V.ConfigError as e:
        print(str(e), file=sys.stderr)
        return 1
    now = int(time.time())

    if a.action == "list":
        counts = store.ciphertext_counts()
        for purpose in K.PURPOSES:
            ring = rings[purpose]
            if ring is None:
                print(f"{purpose:<13} — none yet (TinySesam creates it on its next start)")
                continue
            for i, k in enumerate(ring.keys):
                state = "active  " if i == 0 else f"previous since {_when(k.since)}"
                extra = f"  values: {counts.get(k.kid, 0)}" if purpose == K.VAULT else ""
                if purpose in K.SIGNING and i and k.since is not None:
                    extra = ("  published" if now - k.since <= K.OVERLAP_SEC[purpose] else "  no longer published")
                note = f"  note: {k.note}" if k.note else ""
                print(f"{purpose:<13} {k.kid}  {state}  [{ring.origin}]{extra}{note}")
        old = store.old_format_count()
        if old:
            print(f"vault         {old} value(s) in a format before 0.26 — not read by this version; re-encrypt "
                  f"them with TinySesam {store.LAST_MIGRATING_RELEASE} (`tinysesam keys reencrypt`)")
        return 0

    if a.action == "reencrypt":
        def show(column, done, total):
            if done == total or done % 100 == 0:
                print(f"  {column}: {done}/{total}", flush=True)
        try:
            store.extract_secrets()
            result = store.reencrypt(progress=show)
        except V.ConfigError as e:
            print(str(e), file=sys.stderr)
            return 1
        print(f"Re-encrypted {sum(result.values())} value(s) with key {store.vault.active_kid}.")
        left = {k: n for k, n in store.ciphertext_counts().items() if k != store.vault.active_kid}
        if left:
            print(f"Still with other keys (written meanwhile by a service that was not restarted?): {left} — "
                  f"restart TinySesam and run this again.", file=sys.stderr)
            return 1
        return 0

    purpose = a.purpose
    ring = rings[purpose]
    if ring is None:
        print(f"No {purpose} key yet — start TinySesam (this version) once, it creates it.", file=sys.stderr)
        return 1
    env = K.ENV[purpose]
    if ring.origin == "environment":
        print(f"The {purpose} key comes from {env}: change it there. Rotate: the new key into {env}, the old one "
              f"into {env}_PREVIOUS, restart{'; then `tinysesam keys reencrypt`' if purpose == K.VAULT else ''}. "
              f"Retire: drop it from {env}_PREVIOUS. A new key: python -c \"import os,base64;"
              f"print(base64.b64encode(os.urandom(32)).decode())\"", file=sys.stderr)
        return 1

    if a.action == "rotate":
        material = K.new_material(purpose)
        if ring.origin == "database":
            kid = store.key_ring_rotate(purpose, material)
        else:
            kid = K.kid_for(purpose, material)
            keys = [K.Key(kid, material)] + [K.Key(k.kid, k.material, now if i == 0 else k.since, k.note)
                                              for i, k in enumerate(ring.keys)]
            try:
                K.write_file(purpose, ring.path, keys)
            except (OSError, V.ConfigError) as e:
                print(f"{ring.path}: {e}", file=sys.stderr)
                return 1
        store.audit_log("key_rotated", None, None, f"purpose={purpose} kid={kid} source=cli")
        print(f"New active {purpose} key: {kid} (the previous one {ring.active.kid} stays until `keys retire`).")
        print("Restart TinySesam (all workers) so it uses the new key.")
        if purpose == K.VAULT:
            print("Then: tinysesam keys reencrypt --db … ; once `keys list` shows no values for the old key: "
                  "tinysesam keys retire --purpose vault. Back up the key file again — apart from the database.")
        elif purpose == K.GATE:
            from . import gate as G
            print("A proxy with jwk_url (/auth/gate/jwks.json, the template) follows by itself. One with a fixed "
                  f"sign_key needs the new value: {G.public_b64(K.gate_private(material))} — until then tokens of the "
                  "new key take the fallback path.")
            print(f"After {K.GATE_OVERLAP_SEC // 60} minutes: tinysesam keys retire --purpose gate")
        elif purpose == K.APPROVAL:
            print("Applications that check confirmations fetch /auth/approvals/jwks.json and learn the new key there "
                  "(an unknown kid makes them fetch again). An application configured with a fixed key needs "
                  "the new one.")
            print(f"After {K.APPROVAL_OVERLAP_SEC // 60} minutes: tinysesam keys retire --purpose approval")
        else:
            print("Connected programs stay connected, app passwords, API keys and open links stay valid and nobody is "
                  "signed out (looked up with the previous pepper; a program's next refresh and the next use of an app "
                  "password or API key move them to the new one, a session or link keeps its pepper until it ends). "
                  "tinysesam keys retire --purpose oauth-pepper once `keys retire` no longer refuses.")
        return 0

    # retire
    chosen = [k for k in ring.previous if not a.kid or k.kid in a.kid]
    unknown = set(a.kid) - {k.kid for k in ring.previous}
    if unknown:
        print(f"Not a previous {purpose} key: {', '.join(sorted(unknown))} (the active key is never retired).",
              file=sys.stderr)
        return 1
    if not chosen:
        print(f"No previous {purpose} key — nothing to retire.")
        return 0
    refusals = []
    counts = store.ciphertext_counts() if purpose == K.VAULT else {}
    for k in chosen:
        if purpose == K.VAULT:
            if counts.get(k.kid):
                refusals.append(f"{k.kid}: {counts[k.kid]} stored value(s) still need it — `tinysesam keys reencrypt`")
            if store.old_format_count():
                refusals.append(f"{k.kid}: {store.old_format_count()} value(s) in a format before 0.26 may need it — "
                                f"re-encrypt them with TinySesam {store.LAST_MIGRATING_RELEASE} first")
        elif a.force:
            continue
        elif k.since is None:
            refusals.append(f"{k.kid}: unknown since when it is previous — --force if the overlap has passed")
        elif purpose == K.GATE and now - k.since <= K.GATE_OVERLAP_SEC:
            refusals.append(f"{k.kid}: gate tokens signed with it may still be valid until "
                            f"{_when(k.since + K.GATE_OVERLAP_SEC)} (--force: they take the fallback path once)")
        elif purpose == K.APPROVAL and now - k.since <= K.APPROVAL_OVERLAP_SEC:
            refusals.append(f"{k.kid}: approval confirmations signed with it may still be valid until "
                            f"{_when(k.since + K.APPROVAL_OVERLAP_SEC)} (--force: an application that has not checked "
                            f"one yet refuses it)")
        elif purpose == K.PEPPER and (n := store.oauth_live_tokens_before(k.since, now)):
            refusals.append(f"{k.kid}: {n} OAuth code(s)/token(s) from before the rotation are still valid "
                            f"(--force: those programs must connect again)")
        elif purpose == K.PEPPER and (n := store.sessions_live_before(k.since, now)):
            # T-71: a session handle is an HMAC with the pepper of its creation and keeps it until the session ends.
            refusals.append(f"{k.kid}: {n} session(s) or app-host link(s) from before the rotation are still valid "
                            f"(--force: those people sign in again)")
        elif purpose == K.PEPPER and (n := store.app_passwords_with_kid(k.kid, now)):
            # T-66: an app password moves to the active pepper on its next use; one not used since the rotation
            # still carries the old digest.
            refusals.append(f"{k.kid}: {n} app password(s) not used since the rotation still need it "
                            f"(--force: they stop working and must be created anew)")
        elif purpose == K.PEPPER and any(live := store.tokens_live_before(k.since, now)):
            # T-72: one-time tokens and API keys are digested with the pepper; an API key moves to the active one on
            # its next use, an open link never does.
            refusals.append(f"{k.kid}: {live[0]} open one-time token(s) (sign-in links, invitations, pairing codes) "
                            f"and {live[1]} API key(s) not used since the rotation still need it (--force: those "
                            f"links stop working, those keys must be created anew)")
    if refusals:
        print("Not retired:\n  " + "\n  ".join(refusals), file=sys.stderr)
        return 1
    gone = [k.kid for k in chosen]
    if ring.origin == "database":
        store.key_ring_retire(purpose, gone)
    else:
        try:
            K.write_file(purpose, ring.path, [k for k in ring.keys if k.kid not in gone])
        except (OSError, V.ConfigError) as e:
            print(f"{ring.path}: {e}", file=sys.stderr)
            return 1
    store.audit_log("key_retired", None, None, f"purpose={purpose} kid={','.join(gone)} source=cli")
    print(f"Retired {purpose} key(s): {', '.join(gone)}.")
    return 0


def _gate_key(argv) -> int:
    ap = argparse.ArgumentParser(
        prog="tinysesam gate-key",
        description="Print the public key of the gate tokens (sign_key for caddy-jwt, "
                    "sign_alg EdDSA) — or with --jwks the key set of /auth/gate/jwks.json. Public, not a secret.")
    _key_args(ap)
    ap.add_argument("--jwks", action="store_true", help="the JSON Web Key Set (active + previous within the overlap)")
    a = ap.parse_args(argv)
    import json
    import time
    from . import gate, keys as K, vault as V
    try:
        _store, rings = _open_keys(a)
    except V.ConfigError as e:
        print(str(e), file=sys.stderr)
        return 1
    ring = rings[K.GATE]
    if ring is None:
        print("No gate key yet — start TinySesam (this version) once, it creates it.", file=sys.stderr)
        return 1
    if a.jwks:
        print(json.dumps(K.jwks(ring, int(time.time())), indent=2))
    else:
        print(gate.public_b64(K.gate_private(ring.active.material)))
    return 0


def main(argv=None):
    """The command line. A database the commands cannot open (below the schema baseline, T-111) ends with its message
    and exit code 1 instead of a traceback."""
    from .errors import ConfigError
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "version"
    try:
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
        elif cmd == "keys":
            sys.exit(_keys(argv[1:]))
        elif cmd == "accounts":
            from ._accounts import run as _accounts_run
            sys.exit(_accounts_run(argv[1:], prog="tinysesam accounts"))
        elif cmd == "roles":
            from ._role_catalog import run as _roles_run
            sys.exit(_roles_run(argv[1:], prog="tinysesam roles"))
        elif cmd == "diagnose":
            from ._diagnose import run
            sys.exit(run(argv[1:], mode="library", prog="tinysesam diagnose"))
        else:
            # `--help` is a question, not an error: it belongs on stdout and ends with 0. A
            # typo, on the other hand, goes to stderr and ends with 2, otherwise no script notices the difference.
            help_text = cmd in ("--help", "-h", "help")
            print("usage: python -m tinysesam version\n"
                  "       python -m tinysesam passwd --db <file> <user>\n"
                  "       python -m tinysesam backup --db <file> <target>\n"
                  "       python -m tinysesam restore --db <file> <backup>\n"
                  "       python -m tinysesam gc     --db <file>\n"
                  "       python -m tinysesam audit  --db <file> [--user X]\n"
                  "       python -m tinysesam unlock --db <file> <user>\n"
                  "       python -m tinysesam owner  --db <file> <user>\n"
                  "       python -m tinysesam rename --db <file> <user> <new-name>\n"
                  "       python -m tinysesam delete --db <file> <user> [--yes]\n"
                  "       python -m tinysesam gate-key --db <file> [--jwks]\n"
                  "       python -m tinysesam keys list|rotate|reencrypt|retire --db <file> [--purpose P]\n"
                  "       python -m tinysesam accounts list|adopt|release|restore --db <file> [--app X]\n"
                  "       python -m tinysesam roles  list|create|delete --db <file> [--config mod:attr] [<role>]\n"
                  "       python -m tinysesam diagnose [--config module:attr] [--db <file>] [--log <file>]",
                  file=sys.stdout if help_text else sys.stderr)
            sys.exit(0 if help_text else 2)
    except ConfigError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

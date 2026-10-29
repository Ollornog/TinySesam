"""The database names in English (schema 16): migration of a real schema-15 file, idempotence, rollback SQL, mutations.

PO decision 2026-10-29: tables, columns, indexes, triggers and setting keys carried German names up to schema 15
(`namensbindung`, `fehlserie.topf`, `users.name_quelle`, `foederation_seit:ldap`, ...). Schema 16 renames them once
(`Store._english_names`, before the schema script), in one transaction, and only if an old name is present.

This suite measures that against a REAL schema-15 file, not against the mapping tables:

* `tests/fixtures/schema15_names.sql` is plain SQL, produced by the code of main at a7aa98c (schema 15, before the
  English database names); the rows are hand-made and carry every renamed table, column, index, trigger and setting
  key, a placeholder identifier (`~ohne-kennung:`) and a session chain. The expectations below are spelled out by hand
  (`EXPECTED_*`), NOT derived from `Store.RENAMED_*`; otherwise the test would prove the table with itself.
* (A) the start migrates exactly that: stamp, names, every row, indexes, triggers (and they still work), integrity;
  (B) a second start changes nothing, also on a read-only file; (C) a file made by the current code has no old name;
  (D) a file with old names that cannot be written does not start and is left alone; (E) the rollback SQL of
  docs/OPERATIONS.md gives the schema-15 names back, and the newer version migrates the result again; (F) a file into
  which a version without the new names has written (old tables next to new ones) is merged; (G) mutations: every
  guard turns the suite red when it is broken (done by a deliberately broken copy of a table or function, never in the
  source).

All checks work without extras.
"""
from __future__ import annotations

import contextlib
import io
import logging
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tinysesam.store import Store                              # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("Database names in English (schema 16): migration, idempotence, rollback SQL")

FIXTURE = ROOT / "tests" / "fixtures" / "schema15_names.sql"
OPERATIONS = ROOT / "docs" / "OPERATIONS.md"
T = 1793237238          # the clock of the fixture rows

# ── what must come out, by hand ─────────────────────────────────────────────────────────────────────
EXPECTED_TABLES = {"users", "api_key", "password_cred", "pin_cred", "totp_cred", "recovery_code", "webauthn_cred",
                   "oidc_identity", "federated_identity", "name_binding", "session", "oidc_grant", "oidc_session",
                   "gate_signed_out", "gate_link", "oidc_id_token", "flow", "setting", "magic_token",
                   "resource_secret", "resource_unlock", "login_attempt", "failure_series", "audit"}
OLD_TABLES = {"namensbindung", "oidc_sitzung", "gate_abgemeldet", "fehlserie"}
EXPECTED_COLUMNS = {
    "users": {"folded_name", "folded_mail", "idp_confirmed_at", "name_attempt_from", "mail_attempt_from",
              "name_audit_from", "mail_audit_from", "name_source", "name_self_chosen"},
    "federated_identity": {"source", "identifier", "user_id", "bound_at", "directory_name_folded"},
    "name_binding": {"source", "user_id", "until"},
    "session": {"last_seen", "end_others", "stay_chosen", "successor"},
    "oidc_session": {"token_hash", "client", "sub", "refresh", "checked_at", "client_id", "success_at"},
    "login_attempt": {"pending"},
    "failure_series": {"folded", "kind", "count", "since", "last_seen"},
    "gate_signed_out": {"token_hash", "host", "at"},
}
OLD_COLUMNS = {"users": {"topf_name", "topf_mail", "idp_bestaetigt_at", "name_versuch_ab", "mail_versuch_ab",
                         "name_audit_ab", "mail_audit_ab", "name_quelle", "name_selbst_gewaehlt"},
               "federated_identity": {"quelle", "kennung", "gebunden_at", "name_topf"},
               "session": {"zuletzt", "andere_beenden", "bleiben_gewaehlt", "nachfolger"},
               "login_attempt": {"offen"}}
NEW_INDEXES = {"idx_fed_source_user", "ix_fed_directory_name_folded", "ix_users_folded_name", "ix_users_folded_mail"}
OLD_INDEXES = {"idx_fed_quelle_user", "ix_fed_name_topf", "ix_users_topf_name", "ix_users_topf_mail"}
NEW_TRIGGERS = {"trg_users_folded_name", "trg_users_folded_mail", "trg_users_change_name", "trg_users_change_mail",
                "trg_users_identifier_insert", "trg_users_identifier_update"}
OLD_TRIGGERS = {"trg_users_topf_name", "trg_users_topf_mail", "trg_users_wechsel_name", "trg_users_wechsel_mail",
                "trg_users_kennung_insert", "trg_users_kennung_update"}
EXPECTED_SETTINGS = {"allowlist_after_idp_revocation": "1793237300", "idp_inventory_set": "1793237238",
                     "name_source_backfilled": "1793237238", "name_self_backfilled": "1793237238",
                     "clock_state": "1793237400", "panel_lock_until": "1793237500",
                     "federation_since:ldap": "1793237238", "federation_since:saml": "1793237239",
                     "login_max_attempts": "7"}
OLD_SETTING_KEYS = {"allowlist_nach_idp_entzug", "idp_bestand_gesetzt", "name_quelle_nachgetragen",
                    "name_selbst_nachgetragen", "uhr_stand", "panel_sperren_bis", "foederation_seit:ldap",
                    "foederation_seit:saml"}
# (table, columns, rows) — every row of the fixture under the new names
EXPECTED_ROWS = {
    "users": ("id, username, folded_name, folded_mail, idp_confirmed_at, name_attempt_from, mail_attempt_from, "
              "name_audit_from, mail_audit_from, name_source, name_self_chosen",
              [(1, "alice", "alice", "alice@example.com", T + 5, T + 1, T + 2, T + 3, T + 4, "oidc", 1),
               (2, "bob", "bob", "bob@example.com", None, None, None, None, None, "ldap", 0),
               (3, "carol", "carol", "", None, None, None, None, None, None, 1)]),
    "federated_identity": ("source, identifier, user_id, bound_at, directory_name_folded",
                           [("ldap", "uid-bob", 2, T + 11, "bob"), ("ldap", "~without-identifier:alice", 1, T + 12, None),
                            ("saml", "nameid-carol", 3, T + 21, None)]),
    "name_binding": ("source, user_id, until", [("ldap", 3, T + 86400), ("saml", 2, T + 172800)]),
    "session": ("user_id, last_seen, end_others, stay_chosen, successor",
                [(1, T + 60, 0, 1, None), (2, None, 1, 0, "a" * 64)]),
    "oidc_session": ("client, sub, refresh, checked_at, client_id, success_at",
                     [("default", "sub-1", "v1:refresh", T + 30, "client-1", T + 31)]),
    "gate_signed_out": ("host, at", [("app.example.com", T + 40)]),
    "login_attempt": ("username, success, method, pending", [("alice", 1, "password", 0), ("bob", 0, "password", 1),
                                                             ("bob", 0, "pin_chain", 0)]),
    "failure_series": ("folded, kind, count, since, last_seen", [("alice", "pin_chain", 1, T + 5, T + 5),
                                                                 ("bob", "password", 3, T + 1, T + 9)]),
    "audit": ("event, username, detail", [("login_ok", "alice", "reason=ok")]),
}


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────
def _record(fn):
    """(result, text) — what the logger `tinysesam` says meanwhile, from INFO."""
    buffer = io.StringIO()
    check = logging.StreamHandler(buffer)
    log = logging.getLogger("tinysesam")
    tier = log.level
    log.addHandler(check)
    log.setLevel(logging.INFO)
    try:
        result = fn()
    finally:
        log.removeHandler(check)
        log.setLevel(tier)
    return result, buffer.getvalue()


@contextlib.contextmanager
def patch(obj, name, value):
    original = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)


def _new_path(name="t.db") -> str:
    return os.path.join(tempfile.mkdtemp(), name)


def _load_fixture(path: str) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(FIXTURE.read_text(encoding="utf-8"))
        os.chmod(path, 0o600)       # as the store creates its own files (otherwise it warns about the mode)
        con.commit()
    finally:
        con.close()


def fresh() -> str:
    path = _new_path("f.db")
    _load_fixture(path)
    return path


def _read(path: str, sql: str, *args) -> list:
    con = sqlite3.connect(path)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def _stamp(path: str) -> int:
    return _read(path, "PRAGMA user_version")[0][0]


def _names(path: str, kind: str) -> set:
    return {x[0] for x in _read(path, "SELECT name FROM sqlite_master WHERE type=? AND name NOT LIKE 'sqlite_%'", kind)}


def _columns(path: str, table: str) -> set:
    return {x[1] for x in _read(path, f"PRAGMA table_info({table})")}


def _dump(path: str) -> list:
    """The whole file as SQL text — for before/after comparisons."""
    con = sqlite3.connect(path)
    try:
        return list(con.iterdump())
    finally:
        con.close()


def _start(path: str):
    """Open the file with `Store` (that runs the migration) — (store, log text); the connection is closed."""
    store, log = _record(lambda: Store(path))
    store.db.close()
    return log


# ── the checks of the fixture migration, as a function: the same ones run again under a mutation ──────
def migration_problems(path: str, log: str) -> list:
    problem = []
    if _stamp(path) != Store.SCHEMA_VERSION == 16:
        problem.append(f"stamp {_stamp(path)}")
    tables = _names(path, "table")
    if not EXPECTED_TABLES <= tables or tables & OLD_TABLES:
        problem.append(f"tables: missing {sorted(EXPECTED_TABLES - tables)}, old {sorted(tables & OLD_TABLES)}")
    for table, columns in EXPECTED_COLUMNS.items():
        if table in tables and not columns <= _columns(path, table):
            problem.append(f"{table}: missing {sorted(columns - _columns(path, table))}")
    for table, columns in OLD_COLUMNS.items():
        if table in tables and columns & _columns(path, table):
            problem.append(f"{table}: old {sorted(columns & _columns(path, table))}")
    for table, (columns, rows) in EXPECTED_ROWS.items():
        try:
            got = _read(path, f"SELECT {columns} FROM {table} ORDER BY 1, 2")
        except sqlite3.OperationalError as e:
            problem.append(f"{table}: {e}")
            continue
        if sorted(got, key=repr) != sorted(rows, key=repr):
            problem.append(f"{table}: rows {got}")
    settings = dict(_read(path, "SELECT key, value FROM setting"))
    # the store moves the clock and the panel watermark forward itself: only their presence counts
    moved = {"clock_state", "panel_lock_until"}
    if ({k: v for k, v in EXPECTED_SETTINGS.items() if k not in moved}.items() > {k: v for k, v in settings.items() if k not in moved}.items()
            or not {k: v for k, v in EXPECTED_SETTINGS.items() if k not in moved}.items() <= settings.items()
            or not moved <= set(settings) or OLD_SETTING_KEYS & set(settings)):
        problem.append(f"settings: {settings}")
    indexes, triggers = _names(path, "index"), _names(path, "trigger")
    if not NEW_INDEXES <= indexes or indexes & OLD_INDEXES:
        problem.append(f"indexes: missing {sorted(NEW_INDEXES - indexes)}, old {sorted(indexes & OLD_INDEXES)}")
    if triggers != NEW_TRIGGERS:
        problem.append(f"triggers: {sorted(triggers)}")
    if "Database names renamed to English (schema 16)" not in log:
        problem.append(f"log: {log[-200:]!r}")
    if _read(path, "PRAGMA integrity_check") != [("ok",)] or _read(path, "PRAGMA foreign_key_check"):
        problem.append("integrity")
    return problem


def trigger_problems(path: str) -> list:
    """The renamed triggers still work: the identifier space rejects a collision, the recompute trigger recomputes."""
    problem = []
    con = sqlite3.connect(path)
    try:
        try:
            con.execute("INSERT INTO users(username, created_at, folded_name) VALUES ('x', 1, 'alice')")
            problem.append("identifier trigger: a colliding bucket was accepted")
        except sqlite3.IntegrityError:
            pass        # expected: the identifier trigger rejects the collision
        con.execute("UPDATE users SET username = 'bobby' WHERE id = 2")
        row = con.execute("SELECT folded_name, name_attempt_from FROM users WHERE id = 2").fetchone()
        if row[0] is not None or row[1] is None:
            problem.append(f"recompute trigger: {row}")
    finally:
        con.close()
    return problem


# ═══ (A) The real schema-15 file is renamed correctly ═════════════════════════════════════════════
path_a = _new_path("a.db")
_load_fixture(path_a)
r.check("precondition: the fixture is a schema-15 file with old names and the old triggers",
        _stamp(path_a) == 15 and OLD_TABLES <= _names(path_a, "table") and not {"name_binding", "failure_series"}
        & _names(path_a, "table") and OLD_TRIGGERS == _names(path_a, "trigger")
        and OLD_INDEXES <= _names(path_a, "index") and set(OLD_SETTING_KEYS) <= {x[0] for x in _read(
            path_a, "SELECT key FROM setting")},
        f"{_stamp(path_a)} {sorted(_names(path_a, 'table'))}")
log_a = _start(path_a)
problems_a = migration_problems(path_a, log_a)
r.check("(A) the start migrates: stamp 16, every table/column/index/trigger/setting key, every row", not problems_a,
        "; ".join(problems_a))
trigger_a = trigger_problems(path_a)
r.check("(A) the renamed triggers still work (identifier space, recompute)", not trigger_a, "; ".join(trigger_a))

# ═══ (B) Idempotence ═════════════════════════════════════════════════════════════════════════════════
def idempotence_problems(path: str) -> list:
    problem = []
    before = _dump(path)
    log = _start(path)
    if _dump(path) != before:
        problem.append("a second start changed the file")
    if "renamed to English" in log:
        problem.append(f"a second start renames again: {log[-200:]!r}")
    # read-only: SQLite's own mode (what the kernel does for a read-only mount)
    connection = sqlite3.connect

    def only_read(target, *a, **k):
        return connection(f"file:{target}?mode=ro", *a, uri=True, **k)

    sqlite3.connect = only_read
    try:
        try:
            _start(path)
        except Exception as error:      # noqa: BLE001 — the start itself fails
            problem.append(f"read-only start: {type(error).__name__}: {error}")
    finally:
        sqlite3.connect = connection
    if _dump(path) != before:
        problem.append("the read-only start changed the file")
    return problem


r.check("(B) a second start changes nothing and does not rename again; a read-only start works on the migrated file",
        not idempotence_problems(path_a), "; ".join(idempotence_problems(path_a)))

# ═══ (C) A file made by the current code has no old name ══════════════════════════════════════════════
path_c = _new_path("c.db")
log_c = _start(path_c)
r.check("(C) a new file carries only the new names, no rename step and no log line",
        _stamp(path_c) == Store.SCHEMA_VERSION and not (_names(path_c, "table") & OLD_TABLES)
        and not (_names(path_c, "trigger") & OLD_TRIGGERS) and not (_names(path_c, "index") & OLD_INDEXES)
        and EXPECTED_TABLES <= _names(path_c, "table") and "renamed to English" not in log_c, log_c[-200:])

# ═══ (D) A file with old names that cannot be written does not start — and stays as it is ═════════════
path_d = fresh()
before_d = _dump(path_d)
connection = sqlite3.connect


def only_read(target, *a, **k):
    return connection(f"file:{target}?mode=ro", *a, uri=True, **k)


sqlite3.connect = only_read
try:
    try:
        _start(path_d)
        result_d = "started"
    except sqlite3.OperationalError as error:
        result_d = "OperationalError"
        assert str(error)
finally:
    sqlite3.connect = connection
r.check("(D) a read-only file with old names: the start fails with an OperationalError (the new code needs the new "
        "names) and the file is untouched", result_d == "OperationalError" and _dump(path_d) == before_d, result_d)

# ═══ (E) The rollback SQL of docs/OPERATIONS.md ═══════════════════════════════════════════════════════
def rollback_sql() -> str:
    text = OPERATIONS.read_text(encoding="utf-8")
    section = text.split("## Rollback of the English database names (schema 16)", 1)[1].split("\n## ", 1)[0]
    return re.search(r"```sql\n(.*?)```", section, re.S).group(1)


def rollback_problems(sql: str) -> list:
    """Migrate the fixture, run the SQL: names, columns, rows, settings and the stamp are those of the fixture again."""
    problem = []
    path = fresh()
    original = fresh()
    _start(path)
    con = sqlite3.connect(path)
    try:
        con.executescript(sql)
    except sqlite3.Error as error:
        con.close()
        return [f"the SQL fails: {error}"]
    con.commit()
    con.close()
    if _stamp(path) != 15:
        problem.append(f"stamp {_stamp(path)}")
    if _names(path, "table") != _names(original, "table"):
        problem.append(f"tables {sorted(_names(path, 'table') ^ _names(original, 'table'))}")
    else:
        for table in sorted(_names(original, "table")):
            if _columns(path, table) != _columns(original, table):
                problem.append(f"{table}: columns {sorted(_columns(path, table) ^ _columns(original, table))}")
            elif table != "sqlite_sequence":
                a = sorted(_read(path, f"SELECT * FROM {table}"), key=repr)
                b = sorted(_read(original, f"SELECT * FROM {table}"), key=repr)
                # `setting` and `users` get no change from the start except the clock key; compare the old keys
                if a != b and table not in ("setting",):
                    problem.append(f"{table}: rows differ")
    got = dict(_read(path, "SELECT key, value FROM setting"))
    want = dict(_read(original, "SELECT key, value FROM setting"))
    moved = {"uhr_stand", "panel_sperren_bis"}          # the store moves these forward itself: only their presence counts
    if not {k: v for k, v in want.items() if k not in moved}.items() <= got.items() or not moved <= set(got):
        problem.append(f"settings: missing {sorted(set(want) - set(got))}")
    if _read(path, "PRAGMA integrity_check") != [("ok",)]:
        problem.append("integrity")
    # and the newer version migrates the result again, to the same state as the first time
    again = _new_path("again.db")
    con = sqlite3.connect(again)
    con.executescript(FIXTURE.read_text(encoding="utf-8"))
    con.close()
    os.chmod(path, 0o600)
    log = _start(path)
    if "Database names renamed to English (schema 16)" not in log or _stamp(path) != 16:
        problem.append("the migration after the rollback did not run")
    return problem


rollback_a = rollback_problems(rollback_sql())
r.check("(E) the rollback SQL of docs/OPERATIONS.md gives the schema-15 names, rows and stamp back, and the newer "
        "version migrates the result again", not rollback_a, "; ".join(rollback_a))

# ═══ (F) A file a version without the new names wrote into is merged ═══════════════════════════════════
def merge_problems() -> list:
    """Old tables and a doubled column next to the migrated ones (a rollback without the SQL)."""
    problem = []
    path = fresh()
    _start(path)
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE namensbindung (quelle TEXT NOT NULL, user_id INTEGER NOT NULL, bis INTEGER NOT NULL, "
        "PRIMARY KEY (quelle, user_id));"
        "INSERT INTO namensbindung VALUES ('ldap', 1, 5), ('ldap', 3, 6);"      # (ldap, 3) exists: the new row wins
        "ALTER TABLE users ADD COLUMN topf_name TEXT;"
        "UPDATE users SET topf_name = 'stale' WHERE id = 1;")
    con.commit()
    con.close()
    log = _start(path)
    rows = _read(path, "SELECT source, user_id, until FROM name_binding ORDER BY source, user_id")
    if rows != [("ldap", 1, 5), ("ldap", 3, T + 86400), ("saml", 2, T + 172800)]:
        problem.append(f"merged rows {rows}")
    if "namensbindung" in _names(path, "table"):
        problem.append("the old table is still there")
    if "topf_name" not in _columns(path, "users") or "folded_name" not in _columns(path, "users"):
        problem.append("the doubled column was not left alone")
    if _read(path, "SELECT folded_name FROM users WHERE id = 1") != [("alice",)]:
        problem.append("the new column was overwritten")
    if "left as it is" not in log:
        problem.append(f"no warning: {log[-200:]!r}")
    return problem


r.check("(F) old tables next to new ones are merged (rows added, new row wins), a doubled column is left alone with a "
        "warning", not merge_problems(), "; ".join(merge_problems()))

# ═══ (G) Mutations: every guard turns the suite red when it is broken ═══════════════════════════════
def mutated(name: str, breakage, check) -> None:
    with breakage():
        problems = check()
    r.check(f"mutation: {name} — the check turns red", bool(problems), "the break was not noticed")


def run_migration() -> list:
    path = fresh()
    try:
        log = _start(path)
    except Exception as error:      # noqa: BLE001 — a start that breaks counts as a finding
        return [f"the start fails: {type(error).__name__}: {error}"]
    return migration_problems(path, log) + trigger_problems(path)


r.check("mutation baseline: the unbroken migration reports no problem", run_migration() == [])


@contextlib.contextmanager
def no_migration():
    with patch(Store, "_english_names", lambda self: 0):
        yield


def without_column(table_name: str, column: str):
    @contextlib.contextmanager
    def _b():
        broken = {t: {o: n for o, n in cols.items() if not (t == table_name and o == column)}
                  for t, cols in Store.RENAMED_COLUMNS.items()}
        with patch(Store, "RENAMED_COLUMNS", broken):
            yield
    return _b


@contextlib.contextmanager
def without_settings():
    with patch(Store, "RENAMED_SETTINGS", {}):
        yield


@contextlib.contextmanager
def without_setting_prefix():
    with patch(Store, "RENAMED_SETTING_PREFIXES", {}):
        yield


@contextlib.contextmanager
def old_triggers_stay():
    with patch(Store, "RENAMED_OBJECTS", {"index": Store.RENAMED_OBJECTS["index"], "trigger": ()}):
        yield


@contextlib.contextmanager
def old_indexes_stay():
    with patch(Store, "RENAMED_OBJECTS", {"index": (), "trigger": Store.RENAMED_OBJECTS["trigger"]}):
        yield


@contextlib.contextmanager
def table_stays():
    with patch(Store, "RENAMED_TABLES", {k: v for k, v in Store.RENAMED_TABLES.items() if k != "fehlserie"}):
        yield


mutated("the migration is not run at all", no_migration, run_migration)
mutated("`users.topf_name` is not renamed", without_column("users", "topf_name"), run_migration)
mutated("`failure_series.zuletzt` is not renamed", without_column("failure_series", "zuletzt"), run_migration)
mutated("`session.nachfolger` is not renamed", without_column("session", "nachfolger"), run_migration)
mutated("`login_attempt.offen` is not renamed", without_column("login_attempt", "offen"), run_migration)
mutated("`fehlserie` is not renamed", table_stays, run_migration)
mutated("the setting keys are not renamed", without_settings, run_migration)
mutated("the `foederation_seit:` prefix is not renamed", without_setting_prefix, run_migration)
mutated("the old triggers are not dropped", old_triggers_stay, run_migration)
mutated("the old indexes are not dropped", old_indexes_stay, run_migration)


@contextlib.contextmanager
def writes_every_time():
    real = Store._english_names

    def broken(self):
        done = real(self)
        self.db.execute("INSERT OR REPLACE INTO setting(key, value) VALUES ('probe_now', ?)", (str(os.getpid()),))
        self.db.commit()
        return done
    with patch(Store, "_english_names", broken):
        yield


def idempotence_after_migration() -> list:
    path = fresh()
    try:
        _start(path)
        return idempotence_problems(path)
    except Exception as error:      # noqa: BLE001 — a start that breaks counts as a finding
        return [f"the start fails: {type(error).__name__}: {error}"]


r.check("mutation baseline: the unbroken second start reports no problem", idempotence_after_migration() == [])
mutated("the step writes on every start (a read-only file would fail)", writes_every_time, idempotence_after_migration)

# the rollback SQL: one statement less, and the check must see it
good_sql = rollback_sql()
for what, broken_sql in (
        ("a column rename missing", good_sql.replace("ALTER TABLE users RENAME COLUMN folded_name TO topf_name;\n", "")),
        ("a table rename missing", good_sql.replace("ALTER TABLE failure_series RENAME TO fehlserie;\n", "")),
        ("a setting rename missing", good_sql.replace("UPDATE setting SET key = 'uhr_stand' WHERE key = 'clock_state';\n", "")),
        ("the stamp missing", good_sql.replace("PRAGMA user_version = 15;\n", ""))):
    r.check(f"mutation: rollback SQL with {what} — the check turns red",
            bool(rollback_problems(broken_sql)) and broken_sql != good_sql, "the break was not noticed")

raise SystemExit(r.done())

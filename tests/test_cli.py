"""CLI: `version` and the maintenance command `passwd` (reset a password offline).

Background: with a preset without a mailer (local_accounts) "forgot password" and the
magic link are off, and the first-admin paths only work while no admin exists. Anyone who
lost their admin password therefore had no documented way back.
"""
import io
import os
import sys
import tempfile
import contextlib

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.__main__ import main


def ok(name):
    print(f"  ✓ {name}")


def cli(*argv, stdin=None):
    """Call main(), collect output and exit code."""
    old = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    from_, code = io.StringIO(), 0
    try:
        with contextlib.redirect_stdout(from_), contextlib.redirect_stderr(from_):
            main(list(argv))
    except SystemExit as e:
        code = e.code or 0
    finally:
        sys.stdin = old
    return code, from_.getvalue()


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, passkey_enabled=False))
auth.create_user("admin", "altes-geheim", is_admin=True)
uid = auth.store.get_user_by_name("admin")["id"]

code, from_ = cli("version")
assert code == 0 and from_.strip()
ok("version prints the installed version")

code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin="neues-geheim-lang-genug\n")
assert code == 0, from_
assert auth._check_password("admin", "neues-geheim-lang-genug")
assert not auth._check_password("admin", "altes-geheim")
ok("passwd sets the password (the way back without a mailer and without a second admin)")

# open sessions no longer apply after a credential change
tok = auth.store.create_session(uid, 3600, True, "password")
cli("passwd", "--db", db, "--stdin", "admin", stdin="noch-eins-geheim\n")
assert auth.store.get_session(tok) is None
ok("open sessions are ended (--keep-sessions leaves them alone)")

tok = auth.store.create_session(uid, 3600, True, "password")
cli("passwd", "--db", db, "--stdin", "--keep-sessions", "admin", stdin="und-noch-eins-lang\n")
assert auth.store.get_session(tok) is not None
ok("--keep-sessions keeps them")

assert any(a["event"] == "password_reset_cli" for a in auth.store.recent_audit(50))
ok("the intervention is in the audit log")

code, from_ = cli("passwd", "--db", db, "--stdin", "gibtsnicht", stdin="egal-egal-egal\n")
assert code == 1 and "gibtsnicht" in from_
ok("unknown account -> error message, exit 1")

code, from_ = cli("passwd", "--db", db + ".fehlt", "--stdin", "admin", stdin="egal-egal-egal\n")
assert code == 1 and "No database at" in from_
assert not os.path.exists(db + ".fehlt")     # otherwise sqlite silently creates an empty file
ok("wrong DB path -> clear message, no empty database as a side effect")

code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin="kurz\n")
assert code == 1 and "too short" in from_
assert auth._check_password("admin", "und-noch-eins-lang")
ok("password_min_length applies here too")

# Without configuration the CLI does not know whether a chain enforces a second factor — it takes
# the stricter length (B2-4): 15 characters, as long as nobody lowers it in the panel.
code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin="Vierzehn-Zeich\n")   # 14 characters
assert code == 1 and "too short (min. 15)" in from_, from_
ok("passwd takes the single-factor length (15) because it does not know the chain")
# (Mutation probe: read only `password_min_length` in `_passwd` -> red.)

# From here on it is about the rule behind the length (blocklist, context, legacy values) — the short
# examples must not already fail on the single-factor length.
auth.store.set_setting("password_min_length_single_factor", "8")

# Same rule as on the web (B2-5/B2-13): blocklist, username, maximum length.
for _weak, _text in (("Passwort2026!", "too easy to guess"), ("admin-admin", "too easy to guess"),
                        ("y" * 257, "too long")):
    code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin=_weak + "\n")
    assert code == 1 and _text in from_, (_weak[:20], from_)
assert auth._check_password("admin", "und-noch-eins-lang")
ok("passwd: blocklist, account word and maximum length apply offline too")

# A-7: The operator blocklist and the service name did not apply offline — a password from the
# own list could be set via the CLI. Now via the same values as in the config.
_items = os.path.join(tempfile.mkdtemp(), "block.txt")
with open(_items, "wb") as _f:
    _f.write(b"# Kommentar\nfirmengeheimnis\nsch\xf6nwetter99\n")   # second line is Latin-1
for _args, _pw in ((("--blocklist-file", _items), "Firmengeheimnis2026!"),
                   (("--blocklist-file", _items), "Schönwetter99"),
                   (("--rp-name", "Beispielportal"), "Beispielportal1!")):
    code, from_ = cli("passwd", "--db", db, "--stdin", *_args, "admin", stdin=_pw + "\n")
    assert code == 1 and "too easy to guess" in from_, (_args, _pw, from_)
_from_the_list = "Firmengeheimnis2026!"
code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin=_from_the_list + "\n")
assert code == 0, from_    # control: without the switch the CLI does not know the list
code, from_ = cli("passwd", "--db", db, "--stdin", "--blocklist-file", _items + ".fehlt", "admin",
                stdin="noch-ein-anderes\n")
assert code == 1 and "cannot be read" in from_, from_
assert auth._check_password("admin", _from_the_list)
ok("passwd reads --blocklist-file (also Latin-1 lines) and --rp-name like the config")

# The CLI reads the minimum length like the web (T-13 attack, factors x configuration): a
# legacy value from a version without limits (`password_min_length` = 4 or 0) counts as 8 on
# the web (`sec()` pulls it to the limit), the CLI read it raw and set passwords that every
# web setter rejects.
from tinysesam import security as _security

for _old_value in ("4", "0"):
    auth.store.set_setting("password_min_length", _old_value)
    code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin="k9T#q7\n")   # 6 characters
    assert code == 1 and "too short (min. 8)" in from_, (_old_value, code, from_)
    assert auth._sec("password_min_length") == 8 == _security.read_hardening(auth.store, "password_min_length")
    assert auth._check_password("admin", _from_the_list)
auth.store.set_setting("password_min_length", "12")                 # valid value: applies as on the web
code, from_ = cli("passwd", "--db", db, "--stdin", "admin", stdin="Elf-Zeichen\n")   # 11 characters
assert code == 1 and "too short (min. 12)" in from_, (code, from_)
auth.store._exec("DELETE FROM setting WHERE key='password_min_length'")   # back to the default
auth.store._exec("DELETE FROM setting WHERE key='password_min_length_single_factor'")
ok("passwd reads the minimum length like the web (legacy value beyond the limit counts as the limit)")
# (Mutation probe: in `_passwd` put back `int(store.get_setting("password_min_length") or …)` instead of
# `read_hardening` -> red.)

# The class behind it: every hardening threshold is read via `security.read_hardening` — a
# second, raw read path would otherwise decide with the weaker value. Every read access to the
# settings table in the package is checked, not only the spelling the first finding used
# (second attack round, konfig: `get_setting(key="…")`, a key via a variable and
# `all_settings()[…]` got through, and a wrong path would have checked zero files — green).
import ast as _ast
import pathlib as _pl
import re as _re

#: Where a NON-literal key is allowed (file, function) — the shared read path itself.
_SETTING_FREE_KEY_NAME = {("security.py", "read_hardening")}
#: Where `all_settings()` may be called. Nowhere today; whoever needs it enters the place
#: here and justifies why no hardening threshold is read raw there.
_SETTING_ALL = set()
_SETTING_METHODS = ("get_setting", "all_settings")
# The classes instead of the spellings (final finding konfig-2: the guard searched case-sensitively for
# `FROM setting` and saw `get_setting` only as an attribute call — lowercase SQL, `main.`,
# quotation marks, an f-string with the table name, `getattr(store, "get_setting")` and an
# alias `lesen = store.get_setting` stayed green):
# 1. Raw SQL on the `setting` table outside store.py: a string in which `setting` stands as a
#    table after FROM/JOIN/UPDATE/INTO — whatever the spelling (SQLite does not distinguish
#    there), with schema prefix (`main.`), in quotes or brackets, with a comment instead of a
#    space. A write access falls under this too: it would bypass the store just the same.
# 2. SQL whose table name is only added at runtime (f-string, `+`, `%`, `.format`): the text
#    starts with an SQL verb, and after FROM/JOIN/UPDATE/INTO there is a gap. Which table
#    it becomes, no syntax tree sees.
#    Per expression the whole text is checked: f-strings and `+` chains are assembled
#    (a gap stands as `{}`), so `"… FROM sett" + "ing"` falls under 1. Docstrings do not
#    count — they never run against the database.
# 3. Every mention of `get_setting`/`all_settings` that is not a direct call (alias,
#    `functools.partial`, passed as an argument) and every string that is called exactly that (`getattr`,
#    `operator.methodcaller`). A call via a name (`get_setting(...)` as a parameter)
#    is checked like a method call.
# Limit: a name that only ARISES at runtime (`getattr(store, name)`), SQL that grows over several
# statements (`sql += …`), SQL from a file and an own sqlite3 connection with SQL built
# that way are not seen by this guard; they could be recognised completely only at runtime.
# Conversely it would flag English prose of the form "… from setting …" (none in the package today):
# then it names file and line, and the wording is changed.
_SQL_SETTING = _re.compile(
    r"(?i)(?<![\w$])(?:from|join|update|into)(?:\s|/\*(?:[^*]|\*(?!/))*\*/)*"
    r"(?:(?:\"[^\"]*\"|`[^`]*`|\[[^\]]*\]|\w+)\s*\.\s*)?[\"'`\[]?setting(?![\w$])", _re.S)
_SQL_START = _re.compile(r"(?is)^(?:\s|--[^\n]*\n|/\*(?:[^*]|\*(?!/))*\*/)*(?:select|with|update|insert|replace|delete|explain)\b")
_SQL_TABLE_UNCLOSED = _re.compile(r"(?i)(?<![\w$])(?:from|join|update|into)(?:\s|/\*(?:[^*]|\*(?!/))*\*/)+[\"'`\[]?\s*(?:\{|%)", _re.S)


def _sql_text(k):
    """The text of a string expression: constant, f-string or `+` chain (gaps as `{}`)."""
    if isinstance(k, _ast.Constant) and isinstance(k.value, str):
        return k.value
    if isinstance(k, _ast.JoinedStr):
        return "".join(t.value if isinstance(t, _ast.Constant) else "{}" for t in k.values)
    if isinstance(k, _ast.BinOp) and isinstance(k.op, _ast.Add):
        links, right = _sql_text(k.left), _sql_text(k.right)
        if links is None and right is None:
            return None
        return (links if links is not None else "{}") + (right if right is not None else "{}")
    if isinstance(k, _ast.BinOp) and isinstance(k.op, _ast.Mod):
        return _sql_text(k.left)
    return None


def _setting_read_paths(sources):
    """(violations, allowed places seen) for [(filename, source), …]."""
    violations, seen = [], set()
    for name, text in sources:
        tree = _ast.parse(text)
        parents = {}
        for node in _ast.walk(tree):
            for kind in _ast.iter_child_nodes(node):
                parents[kind] = node

        def function(k):
            while k in parents:
                k = parents[k]
                if isinstance(k, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    return k.name
            return "<modul>"
        for k in _ast.walk(tree):
            text = _sql_text(k)
            if text is not None:
                p = parents.get(k)
                whole = not (isinstance(p, _ast.JoinedStr) or _sql_text(p) is not None
                            and isinstance(p, _ast.BinOp))
                if name != "store.py" and whole and not isinstance(p, _ast.Expr):
                    if _SQL_SETTING.search(text):
                        violations.append(f"{name}:{k.lineno} raw SQL on the settings table")
                    elif _SQL_START.search(text) and _SQL_TABLE_UNCLOSED.search(text):
                        violations.append(f"{name}:{k.lineno} SQL with table name at runtime")
                if isinstance(k, _ast.Constant) and k.value in _SETTING_METHODS:
                    violations.append(f"{name}:{k.lineno} {k.value!r} as text (getattr or similar)")
                continue
            if isinstance(k, _ast.Attribute):
                method = k.attr
            elif isinstance(k, _ast.Name):
                method = k.id
            else:
                continue
            if method not in _SETTING_METHODS:
                continue
            call = parents.get(k)
            place = (name, function(k))
            if not (isinstance(call, _ast.Call) and call.func is k):
                violations.append(f"{name}:{k.lineno} {method} als Wert weitergereicht in {place[1]}")
                continue
            if method == "all_settings":
                if place in _SETTING_ALL:
                    seen.add(place)
                else:
                    violations.append(f"{name}:{k.lineno} all_settings() in {place[1]}")
                continue
            key_name = call.args[0] if call.args else next(
                (w.value for w in call.keywords if w.arg == "key"), None)
            if isinstance(key_name, _ast.Constant) and isinstance(key_name.value, str):
                if key_name.value in _security.SECURITY_DEFAULTS:
                    violations.append(f"{name}:{k.lineno} hardening threshold {key_name.value!r} read raw")
            elif place in _SETTING_FREE_KEY_NAME:
                seen.add(place)
            else:
                violations.append(f"{name}:{k.lineno} get_setting without a literal key in {place[1]}")
    return violations, seen


# Self-test of the guard: every spelling of a raw read path gets noticed.
for _spelling in ('n = int(store.get_setting("password_min_length") or 8)',
                      'n = int(store.get_setting(key="password_min_length") or 8)',
                      'k = "max_login_attempts"\nn = int(store.get_setting(k) or 5)',
                      'n = int(store.all_settings().get("max_login_attempts", 5))',
                      'n = db.execute("SELECT value FROM setting WHERE key=?", (k,))',
                      # Final finding konfig-2: got through as long as the guard saw one spelling.
                      'n = db.execute("select value from setting where key=?", (k,))',
                      'n = db.execute("SELECT value FROM main.setting WHERE key=?", (k,))',
                      'n = db.execute(\'SELECT value FROM "setting" WHERE key=?\', (k,))',
                      't = "setting"\nn = db.execute(f"SELECT value FROM {t} WHERE key=?", (k,))',
                      'n = getattr(store, "get_setting")("password_min_length")',
                      'lesen = store.get_setting\nn = lesen("password_min_length")',
                      # The same classes in further spellings:
                      'n = db.execute("SELECT value FROM [setting] WHERE key=?", (k,))',
                      'n = db.execute("SELECT value FROM/**/Setting WHERE key=?", (k,))',
                      'n = db.execute("SELECT value FROM %s WHERE key=?" % t, (k,))',
                      'n = db.execute("SELECT value FROM {} WHERE key=?".format(t), (k,))',
                      'n = db.execute("SELECT value FROM " + t + " WHERE key=?", (k,))',
                      'n = functools.partial(store.get_setting, "password_min_length")()',
                      'n = operator.methodcaller("get_setting", "password_min_length")(store)',
                      'alle = getattr(store, "all_settings")()',
                      'def f(get_setting):\n    return get_setting("password_min_length")',
                      'n = Store.get_setting(store, "password_min_length")',
                      'n = db.execute("SELECT value FROM sett" + "ing WHERE key=?", (k,))',
                      'n = db.execute("SELECT value " + "FROM " + t + " WHERE key=?", (k,))',
                      'n = db.execute(\'SELECT value FROM "main"."setting"\')',
                      'n = db.execute("UPDATE setting SET value=value WHERE key=? RETURNING value", (k,))'):
    assert _setting_read_paths([("fremd.py", _spelling)])[0], f"guard overlooks: {_spelling}"
# Control: a literal key without hardening threshold, the mail header `From`, prose about
# "settings"/"setting" and a docstring stay without a finding — otherwise the self-test would only check that
# everything trips.
for _harmless in ('x = store.get_setting("demo_users")', 'msg["From"] = absender',
                 'hinweis = "Die settings from the panel gelten sofort."',
                 'hinweis = "Select whether this setting applies."',
                 'hinweis = f"Login from {ip}"',
                 'def f():\n    """Liest nie SELECT value FROM setting — nur ein Docstring."""'):
    assert not _setting_read_paths([("fremd.py", _harmless)])[0], f"false alarm: {_harmless}"

_package = sorted((_pl.Path(__file__).resolve().parent.parent / "tinysesam").rglob("*.py"))
assert len(_package) >= 10 and any(d.name == "security.py" for d in _package), \
    f"guard does not find the package: {len(_package)} file(s)"
_violations, _seen = _setting_read_paths([(d.name, d.read_text(encoding="utf-8")) for d in _package])
assert not _violations, f"settings read past the shared read path: {_violations}"
assert _seen == _SETTING_FREE_KEY_NAME | _SETTING_ALL, \
    f"exception list outdated or guard blind: seen {_seen}"
ok("every read access to the settings goes through literal keys or security.read_hardening")
# (Mutation probes: in the guard read only `aufruf.args[0]`, skip keywords -> the
# self-test turns red; remove the branch for non-literal keys -> red; in `_passwd` again
# `int(store.get_setting("password_min_length") or …)` -> the guard names `__main__.py:<line>`,
# checked individually because in the suite the assert further up trips first. Final round,
# each individually -> red: remove `(?i)`; do not allow the schema prefix; remove the check for the
# table name at runtime; switch off the assembling of `+` chains; remove the message
# "passed on as a value"; skip the method name as text; skip calls via a
# name -> the self-test turns red. Not requiring the SQL verb at the start -> the
# control `f"Login from {ip}"` turns red; also checking docstrings -> the docstring control turns
# red. On the package: the finding mutation (lowercase SQL and alias) in security.py -> red with
# `security.py:<line>`; `getattr(self.store, "get_setting")` in manager.py -> red with
# `manager.py:<line>`; an f-string `select value from {_T}` in admin.py -> red with `admin.py:<line>`.)

code, from_ = cli("quatsch")
assert code == 2 and "usage" in from_
ok("unknown command -> usage, exit 2")

# `--help` is a question, not an error: exit 0, so a script sees the difference from a typo.
# (The audit report had flagged this for the gateway — here is the control.)
code, from_ = cli("--help")
assert code == 0 and "usage" in from_, (code, from_)
ok("--help -> usage, exit 0 (not 2 like a typo)")

# ---------- backup: a file copy is no good in WAL mode ----------
import sqlite3

bare = os.path.join(tempfile.mkdtemp(), "t.db")
code, from_ = cli("backup", "--db", db, bare)
assert code == 0 and "Backup written" in from_, (code, from_)
names = {z[0] for z in sqlite3.connect(bare).execute("SELECT username FROM users")}
assert names, "backup without accounts"
ok(f"backup takes a copy that is consistent on its own ({len(names)} accounts)")

import stat as _stat

assert _stat.S_IMODE(os.stat(bare).st_mode) == 0o600, oct(_stat.S_IMODE(os.stat(bare).st_mode))
ok("the backup carries the same tight permissions as the source")

# The naive backup as a control — it is exactly the error the command takes off your hands.
import shutil

raw = os.path.join(tempfile.mkdtemp(), "t.db")
shutil.copy(db, raw)
try:
    sqlite3.connect(raw).execute("SELECT COUNT(*) FROM users").fetchone()
    naive_ok = True
except sqlite3.DatabaseError:
    naive_ok = False
assert not naive_ok, "the plain file copy was usable — then the test measures nothing"
ok("a plain file copy is unusable (WAL) — that is why the command exists")

code, from_ = cli("backup", "--db", db, bare)
assert code == 1 and "already exists" in from_, (code, from_)
ok("backup does not overwrite an existing file")

code, from_ = cli("backup", "--db", os.path.join(tempfile.mkdtemp(), "t.db"), os.path.join(tempfile.mkdtemp(), "datei"))
assert code == 1 and "No database at" in from_, (code, from_)
ok("backup of a missing database -> exit 1, no empty file created")

# ---------- gc: cleaning up needs a way from outside ----------
# R4-09: an account that was never confirmed (locked, expired unused confirmation token) is also
# removed by the CLI path — and BEFORE the tokens, otherwise the marker would vanish first.
_sq = auth.create_user("squatter", password="geheim12345", email="opfer@example.com")
auth.store.set_disabled(_sq, True)
auth.store.add_magic_token("abgelaufen-verify", "verify_email", 1, user_id=_sq, email="opfer@example.com")
code, from_ = cli("gc", "--db", db)
assert code == 0 and "sessions=" in from_ and "login_attempts=" in from_, (code, from_)
assert "unverified_accounts=1" in from_ and auth.store.get_user(_sq) is None, from_
ok("gc cleans up and names the count per area (for cron/timer), never-confirmed accounts first")

# `--audit-days` is the counterpart of `audit_retention_days` and holds the same limit
# (T-13 attack, audit x configuration): 10**20 aborted with OverflowError AFTER sessions and
# tokens were already deleted; seconds instead of days (2592000) let the period silently run into the void.
auth.store.audit_log("bleibt", "x", None)
for _days in (str(10 ** 20), "2592000", "-1"):
    try:
        code, from_ = cli("gc", "--db", db, "--audit-days", _days)
    except Exception as e:   # noqa: BLE001 — a traceback is the finding here
        code, from_ = f"{type(e).__name__}", str(e)
    assert code == 2 and "--audit-days" in from_, (_days, code, from_[-200:])
assert any(z["event"] == "bleibt" for z in auth.store.recent_audit(20))
ok("gc --audit-days holds the same limit as audit_retention_days (no crash, nothing deleted)")
# (Mutation probe: revert the range check in `_gc` to `a.audit_days < 0` -> red.)

# The same class at the neighbouring parameter (second attack round, konfig): `--attempts-older-than` and
# `TinySesam.gc(attempts_older_than_sec=)` had no limit. ±10**20 aborted with OverflowError
# AFTER sessions, flows, tokens and unlocks were already deleted; a negative value cleared
# every failed attempt — including those in the running lockout window — and thereby lifted every account lock.
# 0 stays allowed: the documented way to clear all failed attempts (see `unlock`).
_gc_uid = auth.create_user("gc-probe", password="Gc-Probe#lang-12345")
auth.store.create_session(_gc_uid, 3600, True, "password")
auth.store._exec("UPDATE session SET expires_at=1 WHERE user_id=?", (_gc_uid,))   # expired


def _expired_sessions():
    return auth.store._one("SELECT COUNT(*) AS n FROM session WHERE user_id=?", (_gc_uid,))["n"]


for _ in range(auth._sec("max_login_attempts") + 1):
    auth._record_login("gc-probe", "198.51.100.7", False, "password")
assert auth._is_locked("gc-probe", "198.51.100.7")
for _sec in (str(10 ** 20), str(-10 ** 20), "-1"):
    try:
        code, from_ = cli("gc", "--db", db, "--attempts-older-than", _sec)
    except Exception as e:   # noqa: BLE001 — a traceback is the finding here
        code, from_ = f"{type(e).__name__}", str(e)
    assert code == 2 and "--attempts-older-than" in from_, (_sec, code, from_[-200:])
assert _expired_sessions() == 1, "gc deleted although the argument was rejected"
assert auth._is_locked("gc-probe", "198.51.100.7"), "a rejected gc run lifted the lock"
for _sec in (10 ** 20, -10 ** 20, -1, True, float("inf"), "viel"):
    try:
        auth.gc(attempts_older_than_sec=_sec)
        _gc_hit = "angenommen"
    except ValueError:
        _gc_hit = None
    except Exception as e:   # noqa: BLE001 — any other crash is the finding here
        _gc_hit = f"{type(e).__name__}: {e}"
    assert _gc_hit is None, (_sec, _gc_hit)
assert _expired_sessions() == 1 and auth._is_locked("gc-probe", "198.51.100.7")
assert auth.gc(attempts_older_than_sec=86400)["sessions"] >= 1 and _expired_sessions() == 0
code, from_ = cli("gc", "--db", db, "--attempts-older-than", "0")
assert code == 0 and "login_attempts=" in from_, (code, from_)
ok("gc --attempts-older-than and auth.gc() check the period before anything is deleted")
# (Mutation probe: replace `store.versuchsfrist(...)` in `_gc` by the raw value -> red
# (OverflowError or exit 0); the same in `TinySesam.gc` -> red.)

os.remove(bare)
os.remove(raw)
os.remove(db)
print("\nCLI OK ✅")

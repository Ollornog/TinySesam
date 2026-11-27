"""The schema baseline (T-111): a new database comes into being in one step, and nothing older is opened.

What must hold, each against the real code paths:

  (a) a new database equals the schema the last release with migrations reaches — `sqlite_master` of a fresh
      database of this version against `tests/fixtures/schema_baseline.json`, which was generated from the release
      tag (`python tests/test_schema_baseline.py --update`); the fixture itself is regenerated from the tag and
      compared, so a fixture edited by hand turns red (T-127) — without the tag in the clone the suite fails instead
      of skipping (every CI job that runs it checks out the whole history with its tags)
  (b) a database below the baseline (stamp 25, or no stamp at all with TinySesam tables) is refused with a message
      that names the release with the migrations — and the file is left byte for byte as it was; the command line
      says the same with exit code 1 instead of a traceback; the tables of another program in the same file do not
      count
  (c) a stored secret in a format before 0.26 (`v1:` or plain text) stops the start with the same way out;
      `keys list` counts it, `keys retire --purpose vault` refuses while it is there
  (d) a gate key or pepper derived from the vault key by 0.25.x (note `derived-v1`) stops the start with the kid and
      the command that removes it — and that command (`tinysesam keys retire`) suffices: afterwards it starts
  (e) the ballast is gone: no migration chain, no vocabulary or alias module, no derived key material, no session
      handle rewrite in `tinysesam/`
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from _kit.report import Report  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "schema_baseline.json"
TAG = "v0.30.0"

def normalized(sql: str) -> str:
    """The statement without `-- comments` and with single spaces — the comments in `SCHEMA` may change, the
    structure may not. Literals stay as they are (a default value is structure)."""
    tokens = re.findall(r"'(?:[^']|'')*'|--[^\n]*|[^'-]+|['-]", sql or "")    # as `test_english_code.sql_code`
    out = "".join("" if t.startswith("--") else t for t in tokens)
    out = re.sub(r"\s+", " ", out).strip()
    return re.sub(r"\s*([(),])\s*", r"\1", out)


def schema_of(db_path: str) -> dict:
    """{"user_version": n, "objects": {"<type> <name>": normalized sql}} — the comparable shape of a database."""
    db = sqlite3.connect(db_path)
    try:
        objects = {f"{t} {n}": normalized(s) for t, n, s in db.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")}
        return {"user_version": int(db.execute("PRAGMA user_version").fetchone()[0]), "objects": objects}
    finally:
        db.close()


def fresh_db(source_root: Path, directory: str) -> str:
    """A new database made by the `Store` of the code under `source_root`, in a child process (its own imports)."""
    path = os.path.join(directory, "fresh.db")
    subprocess.run([sys.executable, "-c", "import sys; from tinysesam.store import Store; Store(sys.argv[1]).close()",
                    path], check=True, cwd=directory, env={**os.environ, "PYTHONPATH": str(source_root)},
                   capture_output=True, text=True, timeout=120)
    return path


def schema_from_tag(directory: str):
    """The schema a fresh database of the release tag has — None if the tag is not in this clone."""
    if subprocess.run(["git", "-C", str(ROOT), "rev-parse", "-q", "--verify", f"{TAG}^{{commit}}"],
                      capture_output=True).returncode != 0:
        return None
    tree = os.path.join(directory, "tag")
    os.makedirs(tree)
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", TAG, "tinysesam"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", tree], input=archive.stdout, check=True)
    tag_dir = os.path.join(directory, "tag-db")
    os.makedirs(tag_dir)
    return schema_of(fresh_db(Path(tree), tag_dir))


if "--update" in sys.argv:
    with tempfile.TemporaryDirectory() as d:
        shape = schema_from_tag(d)
        if shape is None:
            sys.exit(f"the tag {TAG} is not in this clone: git fetch origin tag {TAG}")
        shape = {"generated_from": TAG, **shape}
        FIXTURE.write_text(json.dumps(shape, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{FIXTURE.relative_to(ROOT)}: {len(shape['objects'])} objects, schema {shape['user_version']}")
    sys.exit(0)

r = Report("schema baseline (T-111)")
work = tempfile.mkdtemp(prefix="ts-baseline-")

# ── (a) a fresh database is the baseline plus the steps after it ────────────────────────────────────────
# Since the first schema change after the baseline (27, T-100: two permission tables, additive) a fresh database is
# the baseline plus exactly the objects of the steps after it — and a baseline database opened by this version reaches
# the same schema (the step itself), with nothing of the baseline changed.
#: The objects each schema step after the baseline adds (additive steps only).
STEPS = {27: {"table app_permission", "table role_permission", "index idx_role_permission_app"},
         # 28, T-102: the IdP group import (catalog notes and what each source delivered per account).
         28: {"table idp_role", "table idp_role_membership", "index idx_idp_role_membership_role"}}
expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
mine = schema_of(fresh_db(ROOT, tempfile.mkdtemp(dir=work)))
added = set().union(*STEPS.values())
missing = sorted(set(expected["objects"]) - set(mine["objects"]))
extra = sorted(set(mine["objects"]) - set(expected["objects"]) - added)
differ = sorted(k for k in set(expected["objects"]) & set(mine["objects"]) if expected["objects"][k] != mine["objects"][k])
from tinysesam.store import Store  # noqa: E402
r.check(f"(a) a new database is created in one step: the schema of {expected['generated_from']} "
        f"({len(expected['objects'])} tables, indexes and triggers, stamp {expected['user_version']}) plus the steps "
        f"{sorted(STEPS)}, stamp {Store.SCHEMA_VERSION}",
        not (missing or extra or differ) and added <= set(mine["objects"])
        and mine["user_version"] == Store.SCHEMA_VERSION == max(STEPS) and expected["user_version"] == 26
        and len(expected["objects"]) > 40,
        f"missing {missing} extra {extra} different {differ} stamp {mine['user_version']}")
r.check("(a) the baseline constants agree: baseline and the release named in every refusal; the schema is one step on",
        Store.BASELINE_SCHEMA == expected["user_version"] and Store.SCHEMA_VERSION == Store.BASELINE_SCHEMA + len(STEPS)
        and f"v{Store.LAST_MIGRATING_RELEASE}" == expected["generated_from"] == TAG,
        f"{Store.SCHEMA_VERSION} {Store.BASELINE_SCHEMA} {Store.LAST_MIGRATING_RELEASE}")
# Every step on a database of the state before: made by this version's `Store`, the objects of that step and of every
# later one dropped and stamped back (AGENTS.md: never a fixture from older files), with an account in it. Opened again
# it reaches the fresh schema and keeps the account — 26 → 28 in one start as well as 27 → 28.
for _step in sorted(STEPS):
    _later = set().union(*(o for v, o in STEPS.items() if v >= _step))
    step_db = os.path.join(tempfile.mkdtemp(dir=work), f"step{_step}.db")
    _s = Store(step_db)
    _s.create_user("kept", display_name="Kept")
    _s.close()
    _raw = sqlite3.connect(step_db)
    for _obj in sorted(_later, reverse=True):
        _kind, _name = _obj.split(" ", 1)
        _raw.execute(f"DROP {_kind.upper()} IF EXISTS {_name}")
    _raw.execute(f"PRAGMA user_version = {_step - 1}")
    _raw.commit()
    _raw.close()
    before = schema_of(step_db)
    Store(step_db).close()
    after = schema_of(step_db)
    _raw = sqlite3.connect(step_db)
    _kept = _raw.execute("SELECT username FROM users").fetchall()
    _raw.close()
    r.check(f"(a) the step {_step - 1} → {Store.SCHEMA_VERSION}: a database of the state before (made by Store, stamped "
            "back) reaches the fresh schema, the earlier objects untouched, its account kept",
            before["user_version"] == _step - 1 and not (_later & set(before["objects"])) and after == mine
            and {k: v for k, v in after["objects"].items() if k not in _later} == before["objects"]
            and _kept == [("kept",)],
            f"before {before['user_version']} after {after['user_version']} "
            f"diff {sorted(set(after['objects']) ^ set(mine['objects']))} kept {_kept}")
# The fixture is only as good as its source: regenerated from the tag, it must be identical — a fixture edited by hand
# (together with the schema in the code, so that the comparison above stays green) turns this red (T-127). Without
# the tag there is nothing to compare with, and that is a failure, not a skip: every CI job that runs this suite
# checks out the whole history with its tags (`fetch-depth: 0`), a local clone has it anyway.
from_tag = schema_from_tag(tempfile.mkdtemp(dir=work))
r.check(f"(a) the tag {TAG} is in this clone, so the fixture can be regenerated from it",
        from_tag is not None,
        f"the tag {TAG} is missing (a shallow clone without tags?): git fetch --depth=1 origin tag {TAG}")
if from_tag is not None:
    tag_differ = sorted(k for k in set(from_tag["objects"]) & set(expected["objects"])
                        if from_tag["objects"][k] != expected["objects"][k])
    r.check(f"(a) the fixture is what {TAG} creates: regenerated from the tag in this clone, it is identical",
            from_tag == {k: v for k, v in expected.items() if k != "generated_from"},
            f"only in the tag {sorted(set(from_tag['objects']) - set(expected['objects']))} "
            f"only in the fixture {sorted(set(expected['objects']) - set(from_tag['objects']))} "
            f"different {tag_differ} stamp {from_tag['user_version']} / {expected['user_version']}")
# the self-probe of the comparison: a changed column type, a dropped index and a comment are told apart
probe = json.loads(json.dumps(mine))
probe["objects"]["table users"] = probe["objects"]["table users"].replace("username TEXT", "username BLOB", 1)
r.check("(a) self-probe: the comparison sees a changed column type and ignores a changed comment",
        probe["objects"]["table users"] != expected["objects"]["table users"]
        and normalized("CREATE TABLE t (a INTEGER -- one\n)") == normalized("CREATE TABLE t (a INTEGER -- two\n)")
        and normalized("CREATE TABLE t (a INTEGER DEFAULT 'x')") != normalized("CREATE TABLE t (a INTEGER DEFAULT 'y')"),
        probe["objects"]["table users"][:80])


# A new database comes into being in ONE transaction: a failure in the middle (here a broken index statement after the
# tables) leaves no half schema behind, and the next start creates the whole one.
half = os.path.join(tempfile.mkdtemp(dir=work), "half.db")
_broken_start = ("import sys; from tinysesam.store import Store\n"
                 "Store.INDEXES = Store.INDEXES + ('CREATE INDEX broken ON no_such_table(x)',)\n"
                 "Store(sys.argv[1])")
broken = subprocess.run([sys.executable, "-c", _broken_start, half], capture_output=True, text=True, timeout=120,
                        env={**os.environ, "PYTHONPATH": str(ROOT)})
_tables = schema_of(half)["objects"]
r.check("(a) a failure while creating a new database leaves no half schema (one transaction), no stamp",
        broken.returncode != 0 and "no_such_table" in broken.stderr
        and not any(k.startswith("table ") for k in _tables) and schema_of(half)["user_version"] == 0,
        f"{broken.returncode} {sorted(_tables)[:5]}")
Store(half).close()
r.check("(a) … and the next start creates the whole schema", schema_of(half)["objects"] == mine["objects"],
        str(sorted(set(mine["objects"]) ^ set(schema_of(half)["objects"]))[:5]))


# ── (b) below the baseline ───────────────────────────────────────────────────────────────────────────
def old_file(stamp: int, table: str = "users") -> str:
    path = os.path.join(tempfile.mkdtemp(dir=work), "old.db")
    db = sqlite3.connect(path)
    db.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY, username TEXT)")
    db.execute("INSERT INTO " + table + " (username) VALUES ('alice')")
    db.execute(f"PRAGMA user_version = {stamp}")
    db.commit()
    db.close()
    return path


def digest(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def refused(path: str):
    try:
        Store(path).close()
    except Exception as e:  # noqa: BLE001 — the type is checked by the caller
        return e
    return None


for stamp in (25, 0):
    path = old_file(stamp)
    before = digest(path)
    error = refused(path)
    from tinysesam.errors import ConfigError  # noqa: E402
    r.check(f"(b) a database with schema {stamp} is refused with the way out (first {Store.LAST_MIGRATING_RELEASE}, "
            "then this version) — and the file is unchanged",
            isinstance(error, ConfigError) and "0.30.0" in str(error) and f"schema {stamp}" in str(error)
            and "keys reencrypt" in str(error) and digest(path) == before
            and not os.path.exists(path + "-wal"),
            f"{type(error).__name__}: {error}")
path = old_file(25)
_cli = {}
for command in (["keys", "list"], ["gc"], ["audit"]):
    out = subprocess.run([sys.executable, "-m", "tinysesam", *command, "--db", path], capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(ROOT), "TINYSESAM_SECRETS_KEY": "A" * 43 + "="}, timeout=120)
    _cli[command[0]] = (out.returncode, "0.30.0" in out.stderr, "Traceback" in out.stderr)
r.check("(b) the command line (keys, gc, audit) refuses it with the message and exit code 1, without a traceback",
        all(v == (1, True, False) for v in _cli.values()), str(_cli))
foreign = old_file(0, table="invoices")
error = refused(foreign)
r.check("(b) a file with only another program's tables (no TinySesam table, no stamp) is not refused: it gets the schema",
        error is None and schema_of(foreign)["user_version"] == Store.SCHEMA_VERSION
        and "table invoices" in schema_of(foreign)["objects"],
        str(error))

# ── (c) secrets in a format before 0.26 ─────────────────────────────────────────────────────────────
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402


def instance(path: str, **kw) -> TinySesam:
    return TinySesam(TinySesamConfig(db_path=path, **kw))


def start_error(path: str, **kw):
    try:
        instance(path, **kw).close()
    except Exception as e:  # noqa: BLE001
        return e
    return None


def run_cli(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "tinysesam", *args], capture_output=True, text=True, timeout=120,
                          env={**os.environ, "PYTHONPATH": str(ROOT)})


base = tempfile.mkdtemp(dir=work)
db_v1 = os.path.join(base, "v1.db")
auth = instance(db_v1)
uid = auth.create_user("carol", password="a long probe password 4711")
auth.close()
raw = sqlite3.connect(db_v1)
raw.execute("INSERT INTO totp_cred(user_id, secret, confirmed, created_at) VALUES (?, ?, 1, ?)",
            (uid, "v1:" + "A" * 40, int(time.time())))
raw.commit()
raw.close()
error = start_error(db_v1)
listing = run_cli("keys", "list", "--db", db_v1)
rotate = run_cli("keys", "rotate", "--db", db_v1, "--purpose", "vault")
retire = run_cli("keys", "retire", "--db", db_v1, "--purpose", "vault")
r.check("(c) a `v1:` secret stops the start: it names the count, the release with the migrations and `keys reencrypt`",
        isinstance(error, ConfigError) and "1 stored secret" in str(error) and "0.30.0" in str(error)
        and "keys reencrypt" in str(error), f"{type(error).__name__}: {error}")
r.check("(c) `keys list` counts the value in the old format and names the way out",
        listing.returncode == 0 and "1 value(s) in a format before 0.26" in listing.stdout, listing.stdout + listing.stderr)
raw = sqlite3.connect(db_v1)
raw.execute("UPDATE totp_cred SET secret = 'JBSWY3DPEHPK3PXP' WHERE user_id = ?", (uid,))
raw.commit()
raw.close()
error = start_error(db_v1)
r.check("(c) a plain-text TOTP secret stops the start the same way (it is no longer encrypted on the fly)",
        isinstance(error, ConfigError) and "1 stored secret" in str(error), f"{type(error).__name__}: {error}")
r.check("(c) `keys retire --purpose vault` refuses to retire the old vault key while such a value is there",
        rotate.returncode == 0 and retire.returncode == 1 and "format before 0.26" in retire.stderr
        and "0.30.0" in retire.stderr, rotate.stdout + rotate.stderr + retire.stdout + retire.stderr)

# ── (d) keys derived from the vault key ─────────────────────────────────────────────────────────────
for purpose, extra in (("gate", ()), ("oauth-pepper", ("--force",))):
    db_k = os.path.join(tempfile.mkdtemp(dir=work), "k.db")
    instance(db_k).close()
    store = Store(db_k)
    from tinysesam import keys as K, vault as V  # noqa: E402
    store.vault = V.Vault(K.load_vault(db_k, ""))
    store.key_ring_rotate(purpose, K.new_material(purpose))
    store._exec("UPDATE key_material SET note = 'derived-v1', since = ? WHERE purpose = ? AND since IS NOT NULL",
                (int(time.time()) - 7 * 86400, purpose))
    old_kid = store._one("SELECT kid FROM key_material WHERE purpose = ? AND since IS NOT NULL", (purpose,))["kid"]
    store.close()
    error = start_error(db_k)
    named = f"tinysesam keys retire --db {db_k} --purpose {purpose} --kid {old_kid}"
    r.check(f"(d) a {purpose} key with the note derived-v1 stops the start, naming the kid and `keys retire`",
            isinstance(error, ConfigError) and named in str(error) and "keys list" in str(error),
            f"{type(error).__name__}: {error}")
    listed = run_cli("keys", "list", "--db", db_k)
    r.check(f"(d) `keys list` shows the {purpose} key with its note (the check step before the update)",
            f"{old_kid}" in listed.stdout and "note: derived-v1" in listed.stdout, listed.stdout + listed.stderr)
    done = run_cli("keys", "retire", "--db", db_k, "--purpose", purpose, "--kid", old_kid, *extra)
    r.check(f"(d) the named command suffices: `keys retire` removes the {purpose} key, and TinySesam starts",
            done.returncode == 0 and start_error(db_k) is None, done.stdout + done.stderr)

# ── (e) the ballast is gone ─────────────────────────────────────────────────────────────────────────
package = {p.name: p.read_text(encoding="utf-8") for p in (ROOT / "tinysesam").glob("*.py")}
gone = ("_migrate", "_vocabulary", "_deprecated", "DERIVED_V1", "pepper_session_handles", "derive_key_name",
        "derive_pepper", "KEY_KINDS_OLD", "_english_names", "encrypt_v1")
found = sorted(f"{name}: {w}" for name, text in package.items() for w in gone if re.search(rf"\b{w}\b", text))
r.check("(e) no migration chain, vocabulary or alias module, derived key material or session handle rewrite in "
        "tinysesam/", not found and "_vocabulary.py" not in package and "_deprecated.py" not in package, str(found))

# ── (f) the update from 0.30.x (T-126) ──────────────────────────────────────────────────────────────
# A database as 0.30.0 leaves it: made by this version's `Store` (the schema is the same, 26) and stamped back to what
# 0.30.0 wrote — an API key stored as the plain sha256 of the key (before T-72), and a gate key it took over from 0.25.x
# as a previous key with the note `derived-v1`. No fixture from older files.
import logging  # noqa: E402

db_u = os.path.join(tempfile.mkdtemp(dir=work), "u.db")
auth = instance(db_u)
svc = auth.create_service("ci-runner")
old_key = auth.create_api_key(svc, name="ci")["key"]
auth.close()
store = Store(db_u)
store.vault = V.Vault(K.load_vault(db_u, ""))
store._exec("UPDATE api_key SET key_hash = ?", (hashlib.sha256(old_key.encode()).hexdigest(),))
store.key_ring_rotate("gate", K.new_material("gate"))
store._exec("UPDATE key_material SET note = 'derived-v1', since = ? WHERE purpose = 'gate' AND since IS NOT NULL",
            (int(time.time()) - 7 * 86400,))
gate_kid = store._one("SELECT kid FROM key_material WHERE purpose = 'gate' AND since IS NOT NULL")["kid"]
store.close()

error = start_error(db_u)
retire_cmd = f"tinysesam keys retire --db {db_u} --purpose gate --kid {gate_kid}"
r.check("(f) a 0.30.0 database with a derived-v1 gate key: the new version refuses to start and names the retire "
        "command", isinstance(error, ConfigError) and retire_cmd in str(error), f"{type(error).__name__}: {error}")
report = run_cli("diagnose", "--db", db_u, "--no-link")
r.check("(f) `tinysesam diagnose` lists the same blocker with its command, without starting",
        report.returncode == 0 and "Update blockers: 1 —" in report.stdout
        and f"`tinysesam keys retire --db <db> --purpose gate --kid {gate_kid}`" in report.stdout,
        report.stdout[-900:] + report.stderr[-300:])
below = run_cli("diagnose", "--db", old_file(25), "--no-link")
r.check("(f) diagnose on a database below the baseline: refused at start (not \"migrates\"), the way through 0.30.0",
        below.returncode == 0 and "below the baseline 26" in below.stdout and "migrates" not in below.stdout
        and "update to TinySesam 0.30.0 first" in below.stdout, below.stdout[-900:] + below.stderr[-300:])
old_secret = run_cli("diagnose", "--db", db_v1, "--no-link")
r.check("(f) diagnose on a database with a secret in a format before 0.26 (from (c)): counted, with the way out",
        "1 stored secret(s) in a format before 0.26" in old_secret.stdout and "keys reencrypt" in old_secret.stdout,
        old_secret.stdout[-900:] + old_secret.stderr[-300:])
done = run_cli("keys", "retire", "--db", db_u, "--purpose", "gate", "--kid", gate_kid)
report = run_cli("diagnose", "--db", db_u, "--no-link")
r.check("(f) after the named retire the start succeeds, and diagnose finds no blocker any more",
        done.returncode == 0 and start_error(db_u) is None and "Update blockers: none" in report.stdout,
        done.stdout + done.stderr + report.stdout[-600:])


class _Lines(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


seen = _Lines()
logging.getLogger("tinysesam.security").addHandler(seen)
auth = instance(db_u)
refused_key = auth.verify_api_key(old_key)
fresh = auth.create_api_key(svc, name="new")["key"]
unknown = auth.verify_api_key("tsk_" + "x" * 40)
works = auth.verify_api_key(fresh)[0]
denied = [row["detail"] for row in auth.store._all("SELECT detail FROM audit WHERE event = 'apikey_denied' "
                                                   "AND username = 'ci-runner'")]
auth.close()
logging.getLogger("tinysesam.security").removeHandler(seen)
r.check("(f) the old API key is refused with a clear reason: audit and security log name the key, its owner and "
        "`pre_pepper`", refused_key == (None, None) and any("reason=pre_pepper" in d for d in denied)
        and any("api key denied user=ci-runner" in line and "reason=pre_pepper" in line for line in seen.lines),
        f"{refused_key} {denied} {seen.lines}")
r.check("(f) counter-probe: a key issued after the update works, an unknown one is still `unknown` (no owner)",
        works is not None and works["username"] == "ci-runner" and unknown == (None, None)
        and any("user=- " in line and "reason=unknown" in line for line in seen.lines), str(seen.lines))

sys.exit(r.done())

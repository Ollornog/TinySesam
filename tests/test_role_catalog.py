"""The role catalog (schema 25): roles administrators add without a change of the configuration.

* Schema: a file of schema 24 gets the table on open and the stamp 25, again and again without change.
* Rules (`_role_catalog`): the name (T-85 plus C1/format characters, at most 64), the configuration owns what it names
  (also `admin`, `__admin__`), no second spelling (casefold), no ambiguous role level entry, at most `LIMIT` rows.
* Deleting: refused while the role is held or waiting — accounts, API key scopes (not revoked, not expired), OAuth
  service scopes, open invitations and pairing codes, pending approvals adding it — and while it is one level of a
  role level entry whose other roles are known. Revoked keys, expired links and decided approvals do not block. A
  catalog row the configuration names too may go (the role stays known).
* The race: the usage check and the delete are one transaction; a concurrent assignment waits for it and lands after
  (then the account holds a role the catalog no longer knows — listed as "only on accounts"), or lands before (then the
  delete is refused). Never in between.
* Role level entries: one entry adds every level role at once, an entry goes as a whole.
* The panel: administrators only (a delegate, a plain account, an automation key get 403; without CSRF 403), the
  role picker and the role levels offer `available_roles` ∪ catalog, errors in words (English, German), audit lines.
* `TinySesam.create_role`/`delete_role`/`known_roles`/`role_usage`/`role_catalog`, the CLI `tinysesam roles`, the start
  checks (a catalog row the configuration names too; ladder coverage over the known roles).

Mutations in the PR description, each named next to its check.
"""
import contextlib
import io
import json
import logging
import os
import sqlite3
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import RoleError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import _role_catalog as C  # noqa: E402
from tinysesam.store import Store  # noqa: E402

PW = "a long probe password 4711"
COLL = {"name": "collections", "label": {"en": "Collections", "de": "Sammlungen"},
        "levels": [{"name": "read", "role": "coll:{1}-read"}, {"name": "write", "role": "coll:{1}"}]}


def ok(name):
    print(f"  ✓ {name}")


class Lines(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


log_lines = Lines()
logging.getLogger("tinysesam").addHandler(log_lines)


def build(lang="en", csrf=False, **extra):
    values = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), csrf_enabled=csrf, lang=lang, cookie_secure=False,
                  passkey_enabled=False, base_url="https://auth.example.com", magiclink_enabled=True,
                  apikey_enabled=True, available_roles=["staff", "lead"], role_levels=[COLL],
                  admin_delegates={"lead": {"roles": ["staff"]}}, signup_default_roles=["staff"])
    values.update(extra)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    now = int(time.time())
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (now, now, auth.store.session_hash(tok)))
    c.cookies.set(auth.cfg.session_cookie, tok)
    return c


def code(fn):
    try:
        fn()
    except RoleError as e:
        return e.code
    return None


# ---------- schema 25 ----------
auth, app = build()
path = auth.cfg.db_path
raw = sqlite3.connect(path)
raw.execute("DROP TABLE role_catalog")
raw.execute("PRAGMA user_version = 24")
raw.commit()
raw.close()
again = Store(path)
assert Store.SCHEMA_VERSION == 25 and int(again.db.execute("PRAGMA user_version").fetchone()[0]) == 25
assert again.catalog_roles() == []
again.add_catalog_roles(["x"], None, 10)
assert [r["name"] for r in Store(path).catalog_roles()] == ["x"]           # a second open changes nothing
again.delete_catalog_roles_if_unused(["x"])
ok("schema 25: a file of schema 24 gets the table and the stamp; reopening is idempotent")

# ---------- rules ----------
boss = auth.create_user("boss", password=PW, is_admin=True)
assert auth.create_role("editor", actor=auth.store.get_user(boss)) == {"name": "editor"}
# (Mutation: drop the casefold comparison in `_check_new` → "Editor" accepted → red.)
assert code(lambda: auth.create_role("Editor")) == "exists"
# (Mutation: drop `config_names` in `_check_new` → "staff" accepted → red.)
for owned in ("staff", "STAFF", "lead", "admin", "__admin__"):
    assert code(lambda: auth.create_role(owned)) == "in_config", owned
# (Mutation: `name_problem` returns None → each of these accepted → red.)
for bad in ("a,b", " x", "x ", "", "ad\x01min", "a‮b", "a​b", "a\u0085b", "x" * 65):
    assert code(lambda: auth.create_role(bad)) == "invalid", repr(bad)
assert code(lambda: auth.create_role("x" * 64)) is None
# A role that would make an ambiguous role level entry (`a-read` with `coll:a-read` of `a`).
# (Mutation: drop `_ladder_conflict` → accepted → red.)
assert code(lambda: auth.create_role("coll:a-read-read")) == "invalid"
# (Mutation: drop the count in `add_catalog_roles` → the 4th row goes in → red.)
small = Store(os.path.join(tempfile.mkdtemp(), "s.db"))
assert [small.add_catalog_roles([f"r{i}"], None, 3) for i in range(4)] == ["ok", "ok", "ok", "full"]
assert small.add_catalog_roles(["a", "b", "c"], None, 99) == "ok" and small.add_catalog_roles(["d", "a"], None, 99) \
    == "exists" and "d" not in [r["name"] for r in small.catalog_roles()]          # all or none
member = auth.create_user("member", password=PW, roles=["staff"])
lead = auth.create_user("leader", password=PW, roles=["lead"])
assert code(lambda: auth.create_role("other", actor=auth.store.get_user(lead))) == "forbidden"
assert code(lambda: auth.create_role("other", actor={"username": "x"})) == "forbidden"
ok("rules: name, configuration owns its roles, casefold, ambiguous entries, the limit, administrators only")

# ---------- known roles and the panel's view ----------
assert auth.known_roles() == ["editor", "lead", "staff", "x" * 64]
cat = {r["name"]: r for r in auth.role_catalog()}
assert set(cat) == {"editor", "x" * 64} and cat["editor"]["created_by"] == "boss" and not cat["editor"]["in_config"]
ok("known_roles = available_roles ∪ catalog; role_catalog with author")

# ---------- deleting: every source of use ----------
now = int(time.time())


def blocked(name, kind):
    try:
        auth.delete_role(name)
    except RoleError as e:
        return e.code == "in_use" and e.usage[name][kind] >= 1
    return False


for role in ("u-role", "k-role", "s-role", "i-role", "p-role", "a-role", "k-revoked", "k-expired", "i-old",
             "a-done"):
    auth.create_role(role)
# accounts
auth.set_roles(member, ["staff", "u-role"])
# API key scopes: one live, one revoked, one expired
auth.set_roles(boss, ["k-role", "k-revoked", "k-expired"])
auth.store.add_api_key(boss, "live", "tsk_a", "h1", roles=["k-role"])
gone = auth.store.add_api_key(boss, "gone", "tsk_b", "h2", roles=["k-revoked"])
auth.store._exec("UPDATE api_key SET revoked=1 WHERE id=?", (gone,))
auth.store.add_api_key(boss, "old", "tsk_c", "h3", roles=["k-expired"], expires_at=now - 10)
auth.set_roles(boss, [])
# OAuth service scope
auth.store._exec("INSERT INTO oauth_client(client_id, name, redirect_uris, created_at) VALUES ('svc','s','[]',?)",
                 (now,))
auth.store._exec("INSERT INTO oauth_service_client(client_id, user_id, roles, resources) VALUES ('svc',?,?, '[]')",
                 (boss, json.dumps(["s-role"])))
# open invitation, open pairing code, an expired invitation
auth.store.add_magic_token("t1", "invite", now + 600, None, None, {"roles": ["i-role"]})
auth.store.add_magic_token("t2", "oauth_pairing", now + 600, boss, None, {"roles": ["p-role"], "resources": []})
auth.store.add_magic_token("t3", "invite", now - 1, None, None, {"roles": ["i-old"]})
# a pending approval adding a role, a decided one


def approval(aid, role, state):
    auth.store._exec(
        "INSERT INTO approval(id, class, type, subject_id, requester_kind, requester_ref, payload, payload_hash, "
        "match_code, state, created_at, expires_at) VALUES (?, 'tinysesam', 'tinysesam.account.set_roles', ?, "
        "'apikey', '1', ?, 'h', '111 111', ?, ?, ?)",
        (aid, boss, json.dumps({"account": str(member), "add": [role], "remove": []}), state, now, now + 600))


approval("apv_1", "a-role", "pending")
approval("apv_2", "a-done", "rejected")
# (Mutation per source: drop it from `_role_usage_locked` → its row red.)
for role, kind in (("u-role", "users"), ("k-role", "keys"), ("s-role", "services"), ("i-role", "links"),
                   ("p-role", "links"), ("a-role", "approvals")):
    assert blocked(role, kind), (role, kind)
    assert role in auth.known_roles()
# (Mutations: drop `revoked = 0` / the expiry / `expires_at > ?` / `state = 'pending'` → the row red.)
for role in ("k-revoked", "k-expired", "i-old", "a-done"):
    assert auth.delete_role(role) == {"name": role, "in_config": False}, role
assert auth.role_usage("u-role")["users"] == 1
assert code(lambda: auth.delete_role("nothing-here")) == "not_found"
assert code(lambda: auth.delete_role("staff")) == "not_found"          # a configured role is no catalog role
ok("delete: refused for accounts, key scopes, service scopes, invitations, pairing codes, pending approvals; "
   "revoked, expired and decided ones do not block")

# ---------- role level entries ----------
r = C.create_entry(auth.cfg, auth.store, "collections", "b", "boss")
assert r["added"] == ["coll:b-read", "coll:b"] and {"coll:b", "coll:b-read"} <= set(auth.known_roles())
assert code(lambda: C.create_entry(auth.cfg, auth.store, "collections", "b")) == "exists"
assert code(lambda: C.create_entry(auth.cfg, auth.store, "collections", "a-read")) == "invalid"   # would overlap
assert code(lambda: C.create_entry(auth.cfg, auth.store, "nope", "b")) == "not_found"
# (Mutation: drop the entry check in `delete` → `coll:b` alone deleted, half an entry left → red.)
assert code(lambda: auth.delete_role("coll:b")) == "in_ladder"
auth.set_roles(member, ["staff", "u-role", "coll:b-read"])
assert code(lambda: C.delete_entry(auth.cfg, auth.store, "collections", "b")) == "in_use"
assert {"coll:b", "coll:b-read"} <= set(auth.known_roles())                       # all or none
auth.set_roles(member, ["staff", "u-role"])
assert C.delete_entry(auth.cfg, auth.store, "collections", "b")["removed"] == ["coll:b-read", "coll:b"]
assert not {"coll:b", "coll:b-read"} & set(auth.known_roles())
ok("role level entries: added at once, deleted as a whole, a single level refused")

# ---------- the race: delete against a concurrent assignment ----------
auth.create_role("race")
other = Store(path)                                   # a second connection, as a second worker would have
events = {}


def assign():
    events["started"] = time.monotonic()
    other.set_roles(member, ["staff", "u-role", "race"])
    events["done"] = time.monotonic()


def hook():
    # Inside the delete's transaction, after the usage check: a worker assigns the role now. It must wait for the lock.
    t = threading.Thread(target=assign)
    events["thread"] = t
    t.start()
    time.sleep(0.6)
    events["blocked"] = "done" not in events


auth.store._catalog_hook = hook
res, _ = auth.store.delete_catalog_roles_if_unused(["race"])
events["thread"].join(15)
auth.store._catalog_hook = lambda: None
# (Mutation: commit before the usage check / run the check outside the transaction → the assignment completes while
# the hook waits → `blocked` False → red.)
assert res == "ok" and events["blocked"] and "done" in events, (res, events)
assert "race" not in auth.known_roles() and "race" in auth.user_roles(auth.store.get_user(member))
listed = {x["name"]: x for x in C.listing(auth.cfg, auth.store, auth.store.roles_in_use())["roles"]}
assert listed["race"]["source"] == "accounts" and not listed["race"]["deletable"]
# The other order: the assignment commits first — the delete sees it and refuses.
auth.create_role("race2")
other.set_roles(member, ["staff", "u-role", "race", "race2"])
assert auth.store.delete_catalog_roles_if_unused(["race2"])[0] == "in_use"
auth.set_roles(member, ["staff", "u-role"])
ok("race: the assignment waits for the delete's transaction and lands after it, or lands before and the delete "
   "is refused — never in between")

# ---------- a catalog row the configuration names too ----------
auth.create_role("later")
cfg2 = TinySesamConfig(db_path=path, available_roles=["staff", "lead", "later"], role_levels=[COLL],
                       admin_delegates={"lead": {"roles": ["staff"]}})
log_lines.lines.clear()
auth2 = TinySesam(cfg2)
# (Mutation: drop the redundancy hint in `_check_role_catalog` → red.)
assert any("names the catalog roles later too" in x for x in log_lines.lines), log_lines.lines
assert auth2.role_catalog()[[r["name"] for r in auth2.role_catalog()].index("later")]["in_config"]
assert auth2.delete_role("later") == {"name": "later", "in_config": True} and "later" in auth2.known_roles()
# Ladder coverage over the known roles at start: entries from the catalog count.
assert any("'collections' has no entry among the known roles" in x for x in log_lines.lines), log_lines.lines
C.create_entry(auth2.cfg, auth2.store, "collections", "c")
log_lines.lines.clear()
TinySesam(cfg2)
assert not any("'collections' has no entry" in x for x in log_lines.lines), log_lines.lines
C.delete_entry(auth2.cfg, auth2.store, "collections", "c")
ok("configuration wins: a doubled row is named at start and may go; ladder coverage counts catalog entries")

# ---------- the panel ----------
cb = session_client(auth, app, boss)
r = cb.get("/auth/admin")
assert r.status_code == 200 and '"editor"' in r.text.split("const ROLES=")[1].split(";")[0], r.text[:200]
r = cb.post("/auth/admin/api/roles", json={"name": "panel-role"})
assert r.status_code == 200 and "panel-role" in auth.known_roles(), r.text
r = cb.post("/auth/admin/api/roles", json={"name": "panel-role"})
assert r.status_code == 409 and "exists already" in r.json()["detail"], (r.status_code, r.text)
r = cb.post("/auth/admin/api/roles", json={"name": "a,b"})
assert r.status_code == 400 and "a,b" in r.json()["detail"], r.text
r = cb.post("/auth/admin/api/roles/delete", json={"name": "u-role"})
assert r.status_code == 409 and "accounts" in r.json()["detail"], r.text
view = cb.get("/auth/admin/api/roles").json()
by = {x["name"]: x for x in view["roles"]}
assert by["staff"]["source"] == "config" and by["panel-role"]["source"] == "catalog" and by["panel-role"]["deletable"]
assert by["u-role"]["reason"] == "in_use" and view["ladders"][0]["templates"] == ["coll:{1}-read", "coll:{1}"]
r = cb.post("/auth/admin/api/roles/entry", json={"ladder": "collections", "key": "d"})
assert r.status_code == 200 and r.json()["added"] == ["coll:d-read", "coll:d"], r.text
page = cb.get("/auth/admin").text
ladders = json.loads(page.split("const LADDERS=")[1].split(";")[0])
assert [e["key"] for e in ladders[0]["entries"]] == ["d"], ladders              # the ladder knows the catalog entry
r = cb.post("/auth/admin/api/roles/entry/delete", json={"ladder": "collections", "key": "d"})
assert r.status_code == 200 and r.json()["removed"] == ["coll:d-read", "coll:d"], r.text
r = cb.post("/auth/admin/api/roles/delete", json={"name": "panel-role"})
assert r.status_code == 200 and "panel-role" not in auth.known_roles(), r.text
lines = [x["event"] + " " + (x["detail"] or "") for x in auth.store.recent_audit(limit=60)]
assert any(x.startswith("role_created name=panel-role via=panel") for x in lines), lines
assert any(x.startswith("role_deleted name=panel-role via=panel") for x in lines), lines
assert any(x.startswith("role_delete_refused name=u-role where=users") for x in lines), lines
assert any(x.startswith("role_created name=coll:d-read via=panel entry=d") for x in lines), lines
# Others: a delegate, a plain account, an automation key of an administrator.
# (Mutation: the routes on `team` instead of `guard` → the delegate's create passes → red.)
for uid in (lead, member):
    c = session_client(auth, app, uid)
    assert c.post("/auth/admin/api/roles", json={"name": "sneaky"}).status_code == 403
    assert c.get("/auth/admin/api/roles").status_code == 403
key = auth.create_api_key(boss, "ci")["key"]
assert TestClient(app).post("/auth/admin/api/roles", json={"name": "sneaky"},
                            headers={"x-api-key": key}).status_code == 403
assert "sneaky" not in auth.known_roles()
# CSRF: the central check of the panel covers the new routes.
auth_c, app_c = build(csrf=True)
boss_c = auth_c.create_user("boss", password=PW, is_admin=True)
assert session_client(auth_c, app_c, boss_c).post("/auth/admin/api/roles", json={"name": "x1"}).status_code == 403
assert "x1" not in auth_c.known_roles()
# German texts.
auth_de, app_de = build(lang="de")
boss_de = auth_de.create_user("boss", password=PW, is_admin=True)
auth_de.create_role("held-role")
auth_de.set_roles(boss_de, ["held-role"])
r = session_client(auth_de, app_de, boss_de).post("/auth/admin/api/roles/delete", json={"name": "held-role"})
en = auth.t("api.catalog_in_use", role="'held-role'", where=auth.t("admin.usage_users"))
assert r.status_code == 409 and r.json()["detail"] != en and "'held-role'" in r.json()["detail"], r.text
ok("panel: administrators only (delegate, account, key, missing CSRF → 403), picker and ladders know the catalog, "
   "errors in words (en/de), audit lines")

# ---------- the CLI ----------
from tinysesam.__main__ import main as cli_main  # noqa: E402

cfg_file = os.path.join(tempfile.mkdtemp(), "cliconf.py")
with open(cfg_file, "w", encoding="utf-8") as f:
    f.write("from tinysesam import TinySesamConfig\n"
            f"config = TinySesamConfig(db_path={path!r}, available_roles=['staff', 'lead'],\n"
            "    admin_delegates={'lead': {'roles': ['staff']}})\n")


def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv
    sys.argv = ["tinysesam", "roles", *args]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli_main()
                rc = 0
            except SystemExit as e:
                rc = int(e.code or 0)
    finally:
        sys.argv = old
    return rc, out.getvalue(), err.getvalue()


rc, out, _ = cli("create", "--db", path, "--config", f"{cfg_file}:config", "cli-role")
assert rc == 0 and "cli-role" in auth.known_roles(), out
rc, _, err = cli("create", "--db", path, "--config", f"{cfg_file}:config", "staff")
assert rc == 1 and err.startswith("in_config"), err
rc, _, err = cli("create", "--db", path, "cli-two")                  # without the configuration: refused
assert rc != 0 and "cli-two" not in auth.known_roles()
rc, out, _ = cli("list", "--db", path, "--config", f"{cfg_file}:config")
assert rc == 0 and "cli-role" in out and "staff" in out and "users 1" in out, out
rc, _, err = cli("delete", "--db", path, "--config", f"{cfg_file}:config", "u-role")
assert rc == 1 and err.startswith("in_use"), err
rc, out, _ = cli("delete", "--db", path, "--config", f"{cfg_file}:config", "cli-role")
assert rc == 0 and "cli-role" not in auth.known_roles(), out
lines = [x["event"] + " " + (x["detail"] or "") for x in auth.store.recent_audit(limit=60)]
assert any(x == "role_created name=cli-role via=cli" for x in lines) and \
    any(x == "role_deleted name=cli-role via=cli" for x in lines), lines
ok("CLI: create, list, delete with the configuration; refused without it, for configured and used roles; audit")
print("test_role_catalog: all checks passed")

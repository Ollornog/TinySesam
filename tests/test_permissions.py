"""T-100, ADR-17: permissions — the application declares, the operator assigns, `has_permission` answers.

What must hold, each against the real code paths:

  (a) the configuration's manifest (`apps[id].permissions`) is registered at the start and grants nothing; an
      invalid manifest stops the construction; an entry with only permissions needs no service account
  (b) assigned to a role, a permission is held by its accounts — for THAT application only, the union over the roles
  (c) an API key's scope narrows the roles first (a service gets the intersection); an automation key of an
      administrator never holds a permission by the flag
  (d) the admin flag grants nothing unless `admin_implies_permissions`
  (e) a permission that leaves the manifest is orphaned: it grants nothing, is shown with its suspended assignments,
      and when it comes back they stay suspended — never silently re-granted; only an orphaned one can be deleted
  (f) the application only registers: its manifest never touches the configuration's names, never assigns
  (g) `require_permission`: 401 without a session, 403 without the permission, 200 with it; a typo in the application
      fails when the route is built
  (h) a role with assignments is in use (the catalog does not delete it, so a new role of that name inherits nothing)
  (i) every change leaves an audit line
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.errors import ConfigError, RoleError  # noqa: E402

PW = "a long probe password 4711"
DOCS = [{"name": "docs.read", "label": {"en": "Read documents", "de": "Dokumente lesen"}},
        {"name": "docs.delete", "label": {"en": "Delete documents", "de": "Dokumente löschen"}, "danger": True,
         "suggested_roles": ["editors"]}]


def ok(name):
    print(f"  ✓ {name}")


def build(db=None, **over):
    cfg = dict(db_path=db or os.path.join(tempfile.mkdtemp(), "t.db"), lang="en", cookie_secure=False,
               available_roles=["editors", "viewers"], apikey_enabled=True,
               apps={"docs": {"name": "Docs", "permissions": DOCS}, "wiki": {"permissions": [{"name": "docs.delete"}]}})
    cfg.update(over)
    return TinySesam(TinySesamConfig(**cfg))


def audited(auth, event):
    return [a for a in auth.store.recent_audit(200) if a["event"] == event]


def user(auth, uid):
    return auth.get_user(uid)


# ── (a) ─────────────────────────────────────────────────────────────────────────────────────────────
auth = build()
ed = int(auth.create_user("ed", password=PW, roles=["editors"]))
vi = int(auth.create_user("vi", password=PW, roles=["viewers"]))
both = int(auth.create_user("bo", password=PW, roles=["editors", "viewers"]))
boss = int(auth.create_user("boss", password=PW, is_admin=True))
rows = {r["name"]: r for r in auth.app_permissions("docs")}
assert set(rows) == {"docs.read", "docs.delete"} and rows["docs.delete"]["danger"] and not rows["docs.read"]["danger"]
assert rows["docs.read"]["label"] == {"en": "Read documents", "de": "Dokumente lesen"} and rows["docs.read"]["source"] == "config"
assert rows["docs.delete"]["suggested_roles"] == ["editors"] and rows["docs.delete"]["roles"] == []
assert not any(auth.has_permission(user(auth, u), p, app="docs") for u in (ed, vi, both, boss) for p in rows)
ok("(a) the configuration's manifest is registered at the start and grants nothing — not even to an administrator")

for bad, why in (([{"name": "Docs.Read"}], "upper case"), ([{"name": "docs"}], "no segment"),
                 ([{"name": "docs.read"}, {"name": "docs.read"}], "twice"),
                 ([{"name": "docs.read", "danger": "yes"}], "danger no bool"),
                 ([{"name": "docs.read", "extra": 1}], "unknown member"),
                 ([{"name": f"docs.p{i}"} for i in range(201)], "more than 200")):
    try:
        build(apps={"docs": {"permissions": bad}})
    except ConfigError as e:
        assert "permissions" in str(e), (why, str(e))
    else:
        raise AssertionError(f"an invalid manifest was accepted ({why})")
    try:
        auth.register_permissions("docs", bad)
    except ValueError:
        pass
    else:
        raise AssertionError(f"register_permissions accepted an invalid manifest ({why})")
try:
    auth.register_permissions("nosuchapp", [{"name": "x.y"}])
except ConfigError:
    pass
else:
    raise AssertionError("register_permissions for an application that is not in apps")
try:
    build(apps={"docs": {"permissions": DOCS, "provisioning": {"roles": ["editors"], "scopes": ["users:read"]}}})
except ConfigError as e:
    assert "account" in str(e), str(e)
else:
    raise AssertionError("provisioning without a service account")
ok("(a) invalid manifests stop the construction and register_permissions alike; only provisioning needs `account`")

# ── (b) ─────────────────────────────────────────────────────────────────────────────────────────────
assert auth.grant_permission("editors", "docs.delete", app="docs", by="boss") is True
assert auth.grant_permission("editors", "docs.delete", app="docs", by="boss") is False      # already held
auth.grant_permission("viewers", "docs.read", app="docs", by="boss")
assert auth.has_permission(user(auth, ed), "docs.delete", app="docs")
assert not auth.has_permission(user(auth, ed), "docs.read", app="docs")
assert auth.permissions_of(user(auth, both), app="docs") == ["docs.delete", "docs.read"]
assert not auth.has_permission(user(auth, ed), "docs.delete", app="wiki"), "a permission leaked into another app"
for role, why in (("nobody", "unknown role"), ("editors,admin", "comma"), ("admin", "the admin flag")):
    try:
        auth.grant_permission(role, "docs.read", app="docs")
    except ValueError:
        pass
    else:
        raise AssertionError(f"grant_permission to {why}")
try:
    auth.grant_permission("editors", "docs.nothing", app="docs")
except ValueError:
    pass
else:
    raise AssertionError("an undeclared permission was granted")
ok("(b) assigned to a role, held by its accounts — the union over the roles, for that application only")

# ── (c) ─────────────────────────────────────────────────────────────────────────────────────────────
app = FastAPI()
app.include_router(auth.router())


@app.post("/docs/delete")
def delete_doc(u=Depends(auth.require_permission("docs.delete", app="docs"))):
    return {"by": u["username"]}


c = TestClient(app)
narrow = auth.create_api_key(both, name="viewer-only", roles=["viewers"])["key"]
wide = auth.create_api_key(both, name="all")["key"]
assert c.post("/docs/delete", headers={"X-Api-Key": narrow}).status_code == 403
assert c.post("/docs/delete", headers={"X-Api-Key": wide}).status_code == 200
ok("(c) an API key's scope narrows the roles first: the viewer-only key of an editor cannot delete")

# ── (d) ─────────────────────────────────────────────────────────────────────────────────────────────
assert not auth.has_permission(user(auth, boss), "docs.delete", app="docs")
admins = build(db=auth.cfg.db_path, admin_implies_permissions=True)
assert admins.has_permission(user(admins, boss), "docs.delete", app="docs")
assert admins.permissions_of(user(admins, boss), app="docs") == ["docs.delete", "docs.read"]
boss_key = admins.create_api_key(boss, name="machine")["key"]
app2 = FastAPI()
app2.include_router(admins.router())


@app2.post("/docs/delete")
def delete_doc2(u=Depends(admins.require_permission("docs.delete", app="docs"))):
    return {"by": u["username"]}


assert TestClient(app2).post("/docs/delete", headers={"X-Api-Key": boss_key}).status_code == 403
ok("(d) the admin flag grants nothing by default; admin_implies_permissions=True grants every current one — never "
   "through an automation key")

# ── (e) and (f) ─────────────────────────────────────────────────────────────────────────────────────
out = auth.register_permissions("docs", [{"name": "docs.export", "label": "Export"}])
assert out["added"] == ["docs.export"] and not out["orphaned"], out
assert {r["name"] for r in auth.app_permissions("docs") if not r["orphaned"]} == {"docs.read", "docs.delete",
                                                                                   "docs.export"}
assert not auth.has_permission(user(auth, ed), "docs.export", app="docs")
auth.grant_permission("editors", "docs.export", app="docs")
assert auth.has_permission(user(auth, ed), "docs.export", app="docs")
out = auth.register_permissions("docs", [{"name": "docs.archive"}])          # the app dropped docs.export
assert out["orphaned"] == ["docs.export"] and out["added"] == ["docs.archive"], out
row = {r["name"]: r for r in auth.app_permissions("docs")}["docs.export"]
assert row["orphaned"] and row["roles"] == [] and row["suspended_roles"] == ["editors"], row
assert not auth.has_permission(user(auth, ed), "docs.export", app="docs")
try:
    auth.grant_permission("editors", "docs.export", app="docs")
except ValueError:
    pass
else:
    raise AssertionError("an orphaned permission was granted")
out = auth.register_permissions("docs", [{"name": "docs.export"}, {"name": "docs.archive"}])   # it comes back
assert out["returned"] == ["docs.export"], out
assert not auth.has_permission(user(auth, ed), "docs.export", app="docs"), "an orphaned assignment was re-granted silently"
row = {r["name"]: r for r in auth.app_permissions("docs")}["docs.export"]
assert not row["orphaned"] and row["suspended_roles"] == ["editors"] and row["roles"] == []
assert auth.grant_permission("editors", "docs.export", app="docs") is True          # the administrator's explicit act
assert auth.has_permission(user(auth, ed), "docs.export", app="docs")
ok("(e) left the manifest: orphaned, grants nothing, shown with the suspended role; back: still suspended until "
   "assigned anew")
assert auth.has_permission(user(auth, ed), "docs.delete", app="docs"), "the app's manifest touched a configured name"
assert {r["name"]: r["source"] for r in auth.app_permissions("docs")}["docs.delete"] == "config"
auth.register_permissions("docs", [])
assert auth.has_permission(user(auth, ed), "docs.delete", app="docs")
assert not auth.has_permission(user(auth, ed), "docs.export", app="docs")
ok("(f) the application's manifest never orphans the configuration's names, and registering assigns nothing")
try:
    auth.delete_permission("docs.delete", app="docs")
except ValueError:
    pass
else:
    raise AssertionError("a declared permission was deleted")
assert auth.delete_permission("docs.export", app="docs") is True
assert "docs.export" not in {r["name"] for r in auth.app_permissions("docs")}
assert not auth.store._one("SELECT 1 AS x FROM role_permission WHERE name = 'docs.export'")
ok("(e) only an orphaned permission can be deleted — with its assignments")

# The configuration drops a permission between two starts: orphaned at the next start, its assignment suspended.
again = build(db=auth.cfg.db_path, apps={"docs": {"permissions": [DOCS[0]]}, "wiki": {"permissions": []}})
row = {r["name"]: r for r in again.app_permissions("docs")}["docs.delete"]
assert row["orphaned"] and row["suspended_roles"] == ["editors"] and not again.has_permission(user(again, ed),
                                                                                              "docs.delete", app="docs")
gone = build(db=auth.cfg.db_path, apps={"docs": {"name": "Docs"}, "wiki": {"name": "Wiki"}})
assert all(r["orphaned"] for r in gone.app_permissions("docs") if r["source"] == "config")
ok("(e) a permission the configuration no longer declares is orphaned at the next start (also with no list at all)")

# ── (g) ─────────────────────────────────────────────────────────────────────────────────────────────
auth = build()
ed = int(auth.create_user("ed", password=PW, roles=["editors"]))
vi = int(auth.create_user("vi", password=PW, roles=["viewers"]))
auth.grant_permission("editors", "docs.delete", app="docs")
app = FastAPI()
app.include_router(auth.router())


@app.post("/docs/delete")
def delete_doc3(u=Depends(auth.require_permission("docs.delete", app="docs"))):
    return {"by": u["username"]}


def signed_in(name):
    s = TestClient(app)
    s.get("/auth/login")
    r = s.post("/auth/login", data={"username": name, "password": PW, "_csrf": s.cookies.get(auth.csrf_cookie_name)},
               follow_redirects=False)
    assert r.status_code == 303, (name, r.status_code)
    return s


assert TestClient(app).post("/docs/delete", headers={"Accept": "application/json"}).status_code == 401
r = signed_in("vi").post("/docs/delete", headers={"Accept": "application/json"})
assert r.status_code == 403 and "docs.delete" in r.text, (r.status_code, r.text)
assert signed_in("ed").post("/docs/delete").json() == {"by": "ed"}
try:
    auth.require_permission("docs.delete", app="dcos")
except ConfigError:
    pass
else:
    raise AssertionError("require_permission with an application that is not in apps")
ok("(g) require_permission: 401 without a session, 403 without the permission, 200 with it; a typo fails at build")

# ── (h) ─────────────────────────────────────────────────────────────────────────────────────────────
auth.create_role("archivists")
auth.grant_permission("archivists", "docs.read", app="docs")
assert auth.role_usage("archivists")["permissions"] == 1
try:
    auth.delete_role("archivists")
except RoleError as e:
    assert e.code == "in_use", e.code
else:
    raise AssertionError("a role holding permissions was deleted — a new role of that name would inherit them")
auth.revoke_permission("archivists", "docs.read", app="docs")
auth.delete_role("archivists")
ok("(h) a role with assigned permissions is in use: the catalog keeps it until they are withdrawn")

# ── (i) ─────────────────────────────────────────────────────────────────────────────────────────────
assert audited(auth, "permissions_registered") and audited(auth, "permission_granted")
assert audited(auth, "permission_revoked")
granted = audited(auth, "permission_granted")[0]["detail"]
assert "app=docs" in granted and "role=" in granted and "permission=" in granted, granted
ok("(i) registration, assignment and withdrawal leave audit lines (app, permission, role)")

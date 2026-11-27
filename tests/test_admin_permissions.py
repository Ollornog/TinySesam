"""T-100, ADR-17: the admin panel's permission matrix — who assigns which permission of which application to which role.

  (a) an administrator sees every application with declared permissions and every known role, assigns and withdraws;
      each change is audited with the actor
  (b) a `danger` permission needs a fresh confirmation for everyone — also with `admin_require_mfa=False`, where the
      panel itself does not ask; an ordinary one does not
  (c) an area administrator (a delegate role with `apps` and the action `permissions`) sees only its applications and
      roles, assigns only there (an application outside: 404, a role outside: 403), never deletes; a delegate without
      an area gets 403
  (d) an orphaned permission is shown with its suspended roles, offers no tick, and an administrator deletes it
  (e) the panel page offers the matrix (button, view, texts) and the JS refers to the routes; CSRF guards the writes
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402

PW = "a long probe password 4711"
CSRF = "csrfProbeToken0123456789abcdefgh"
STALE = 100000
APPS = {"docs": {"name": {"en": "Documents"}, "permissions": [
            {"name": "docs.read", "label": "Read documents", "suggested_roles": ["docs-reader"]},
            {"name": "docs.delete", "label": "Delete documents", "danger": True}]},
        "wiki": {"name": "Wiki", "permissions": [{"name": "wiki.edit"}]}}


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), lang="en", cookie_secure=False,
               available_roles=["docs-reader", "docs-editor", "wiki-editor", "area-docs", "plain-delegate",
                                "roles-only"],
               admin_delegates={"area-docs": {"roles": ["docs-reader", "docs-editor"], "apps": ["docs"]},
                                "plain-delegate": {"roles": ["docs-reader"]},
                                "roles-only": {"roles": ["docs-reader"], "apps": ["docs"], "can": ["roles"]}},
               apps=APPS, admin_require_mfa=False)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session(auth, app, uid, age=0):
    c = TestClient(app, follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    if age:
        then = int(time.time()) - age
        auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                         (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    return c


def assign(c, app_id, perm, role, granted=True, csrf=True):
    return c.post("/auth/admin/api/permissions/assign", json={"app": app_id, "permission": perm, "role": role,
                                                              "granted": granted},
                  headers={"X-CSRF-Token": CSRF} if csrf else {})


def row(auth, app_id, perm):
    return {r["name"]: r for r in auth.app_permissions(app_id)}[perm]


auth, app = build()
boss = int(auth.create_user("boss", password=PW, is_admin=True))
area = int(auth.create_user("anne", password=PW, roles=["area-docs"]))
plain = int(auth.create_user("pete", password=PW, roles=["plain-delegate"]))
roles_only = int(auth.create_user("rosa", password=PW, roles=["roles-only"]))

# ── (a) ─────────────────────────────────────────────────────────────────────────────────────────────
c = session(auth, app, boss)
view = c.get("/auth/admin/api/permissions").json()
assert [a["id"] for a in view["apps"]] == ["docs", "wiki"] and not view["area"], view
assert {"docs-reader", "docs-editor", "wiki-editor"} <= set(view["roles"]) and "admin" not in view["roles"]
assert assign(c, "docs", "docs.read", "docs-reader").json() == {"ok": True, "changed": True}
assert assign(c, "wiki", "wiki.edit", "wiki-editor").status_code == 200
assert row(auth, "docs", "docs.read")["roles"] == ["docs-reader"]
assert assign(c, "docs", "docs.read", "docs-reader", granted=False).json()["changed"] is True
assert row(auth, "docs", "docs.read")["roles"] == []
assert assign(c, "docs", "docs.read", "docs-reader", csrf=False).status_code == 403
assert assign(c, "docs", "docs.read", "nobody").status_code == 409
assert assign(c, "nosuch", "docs.read", "docs-reader").status_code == 404
assert assign(c, "docs", "docs.nothing", "docs-reader").status_code == 404
lines = [a for a in auth.store.recent_audit(50) if a["event"] in ("permission_granted", "permission_revoked")]
assert lines and all(a["username"] == "boss" for a in lines), lines
ok("(a) an administrator sees every application and role, assigns and withdraws; CSRF guards it; audited with the actor")

# ── (b) ─────────────────────────────────────────────────────────────────────────────────────────────
stale = session(auth, app, boss, age=STALE)
assert assign(stale, "docs", "docs.read", "docs-editor").status_code == 200, "an ordinary permission asked for a step-up"
r = assign(stale, "docs", "docs.delete", "docs-editor")
assert r.status_code == 403 and "x-tinysesam-reauth" in {k.lower() for k in r.headers}, (r.status_code, r.headers)
assert row(auth, "docs", "docs.delete")["roles"] == []
r = assign(stale, "docs", "docs.delete", "docs-editor", granted=False)
assert r.status_code == 403, "withdrawing a dangerous permission from a stale session"
assert assign(c, "docs", "docs.delete", "docs-editor").status_code == 200
assert row(auth, "docs", "docs.delete")["roles"] == ["docs-editor"]
ok("(b) a dangerous permission needs a fresh confirmation (also with admin_require_mfa=False); an ordinary one not")

# ── (c) ─────────────────────────────────────────────────────────────────────────────────────────────
d = session(auth, app, area)
view = d.get("/auth/admin/api/permissions").json()
assert [a["id"] for a in view["apps"]] == ["docs"] and view["area"] and set(view["roles"]) == {"docs-reader",
                                                                                               "docs-editor"}, view
assert assign(d, "docs", "docs.read", "docs-reader").status_code == 200
assert assign(d, "wiki", "wiki.edit", "docs-reader").status_code == 404, "an application outside the area"
r = assign(d, "docs", "docs.read", "wiki-editor")
assert r.status_code == 403 and row(auth, "docs", "docs.read")["roles"] == ["docs-editor", "docs-reader"], r.status_code
assert assign(d, "docs", "docs.read", "area-docs").status_code == 403, "its own delegate role"
assert d.post("/auth/admin/api/permissions/delete", json={"app": "docs", "permission": "docs.read"},
              headers={"X-CSRF-Token": CSRF}).status_code == 403
assert session(auth, app, area, age=STALE).post(
    "/auth/admin/api/permissions/assign", json={"app": "docs", "permission": "docs.delete", "role": "docs-reader",
                                                "granted": True}, headers={"X-CSRF-Token": CSRF}).status_code == 403
p = session(auth, app, plain)
assert p.get("/auth/admin/api/permissions").status_code == 403
assert assign(p, "docs", "docs.read", "docs-reader").status_code == 403
q = session(auth, app, roles_only)
assert q.get("/auth/admin/api/permissions").status_code == 403, "an area without the action `permissions`"
assert assign(q, "docs", "docs.read", "docs-reader").status_code == 403
ok("(c) an area administrator sees and assigns only in its applications and roles, never deletes; no area or no "
   "action `permissions` → 403")

try:
    build(admin_delegates={"area-docs": {"roles": ["docs-reader"], "apps": ["nosuch"]}})
except ConfigError as e:
    assert "apps" in str(e) and "nosuch" in str(e), str(e)
else:
    raise AssertionError("a delegate area naming an application that does not exist")
ok("(c) a delegate area naming an unknown application stops the construction")

# ── (d) ─────────────────────────────────────────────────────────────────────────────────────────────
auth2, app2 = build(db_path=auth.cfg.db_path, apps={"docs": {"permissions": [APPS["docs"]["permissions"][0]]},
                                                     "wiki": APPS["wiki"]})
c2 = session(auth2, app2, boss)
docs = [a for a in c2.get("/auth/admin/api/permissions").json()["apps"] if a["id"] == "docs"][0]
gone = {p["name"]: p for p in docs["permissions"]}["docs.delete"]
assert gone["orphaned"] and gone["suspended_roles"] == ["docs-editor"] and gone["roles"] == [], gone
assert assign(c2, "docs", "docs.delete", "docs-editor").status_code == 409
assert c2.post("/auth/admin/api/permissions/delete", json={"app": "docs", "permission": "docs.read"},
               headers={"X-CSRF-Token": CSRF}).status_code == 409, "a current permission was deleted"
assert c2.post("/auth/admin/api/permissions/delete", json={"app": "docs", "permission": "docs.delete"},
               headers={"X-CSRF-Token": CSRF}).json() == {"ok": True}
assert "docs.delete" not in {r["name"] for r in auth2.app_permissions("docs")}
ok("(d) an orphaned permission is shown with its suspended role, cannot be assigned, and is deleted by an administrator")

# ── (e) ─────────────────────────────────────────────────────────────────────────────────────────────
page = c2.get("/auth/admin").text
for needle in ("const PERMS=", "async function permsview", '"/api/permissions/assign"', "#perms", "permset,permdel",
               auth2.t("admin.perms_btn")):
    assert needle in page, needle
area_page = session(auth2, app2, area).get("/auth/admin").text
assert '"apps": ["docs"]' in area_page or '"apps":["docs"]' in area_page, "the area is not in the delegate's view"
ok("(e) the panel page carries the matrix: button, view, routes; the delegate's view names its area")

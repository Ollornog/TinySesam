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
  (f) B-19/B-20: a role that leaves the configuration keeps no effective permission — at once (an account may still carry
      it), and from the next start its assignments are suspended, named in the security log and audited; the panel
      shows them in a marked column (symbol and word) for administrators to withdraw; a role created again under the
      same name (configuration or catalog) does not take them over until an administrator assigns anew
"""
from __future__ import annotations

import io
import logging
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, _role_catalog, security  # noqa: E402
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

# ── (f) B-19 ────────────────────────────────────────────────────────────────────────────────────────
ROLES = ["docs-reader", "docs-editor", "wiki-editor", "area-docs", "plain-delegate", "roles-only"]


def started(db, roles):
    """A start on `db` with `roles` as `available_roles`, and the security log it wrote."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    security.seclog.addHandler(handler)
    try:
        a, ap = build(db_path=db, available_roles=roles)
    finally:
        security.seclog.removeHandler(handler)
    return a, ap, buf.getvalue()


auth4, app4 = build(available_roles=ROLES + ["temp-role"])
db4 = auth4.cfg.db_path
boss4 = int(auth4.create_user("boss", password=PW, is_admin=True))
tia = int(auth4.create_user("tia", password=PW, roles=["temp-role"]))
anne4 = int(auth4.create_user("anne", password=PW, roles=["area-docs"]))
assert auth4.grant_permission("temp-role", "docs.delete", app="docs", by="boss")
assert auth4.has_permission(auth4.get_user(tia), "docs.delete", app="docs")
# At once: the role leaves the configuration while the instance runs — the assignment grants nothing any more.
auth4.cfg.available_roles = list(ROLES)
assert not auth4.has_permission(auth4.get_user(tia), "docs.delete", app="docs"), \
    "a role no longer in the configuration still granted its permission"
# B-20: back in the configuration without a start in between — the assignment stays suspended (audited once).
auth4.cfg.available_roles = ROLES + ["temp-role"]
assert not auth4.has_permission(auth4.get_user(tia), "docs.delete", app="docs"), \
    "a role removed and re-added at runtime kept its assignment"
assert row(auth4, "docs", "docs.delete")["suspended_roles"] == ["temp-role"], row(auth4, "docs", "docs.delete")

# The next start without the role: suspended, named, audited; the account still carries the role and holds nothing.
auth5, app5, log5 = started(db4, list(ROLES))
assert "temp-role" in auth5.user_roles(auth5.get_user(tia)), "the probe needs the role still on the account"
assert not auth5.has_permission(auth5.get_user(tia), "docs.delete", app="docs")
assert row(auth5, "docs", "docs.delete")["suspended_roles"] == ["temp-role"], row(auth5, "docs", "docs.delete")
assert "1 permission assignment(s) of role(s) no longer in the configuration" in log5 and \
    "temp-role → docs/docs.delete" in log5, log5
lines = [a for a in auth5.store.recent_audit(50) if a["event"] == "permissions_suspended"]
assert len(lines) == 1 and "reason=role_removed temp-role:docs/docs.delete" in lines[0]["detail"], lines
c5 = session(auth5, app5, boss4)
assert c5.get("/auth/admin/api/permissions").json()["removed_roles"] == ["temp-role"]
assert session(auth5, app5, anne4).get("/auth/admin/api/permissions").json()["removed_roles"] == [], \
    "an area administrator saw a column it cannot act on"
assert assign(c5, "docs", "docs.delete", "temp-role").status_code == 409, "assigned to a role that does not exist"
page5 = c5.get("/auth/admin").text
for needle in ("removed_roles", "perm_role_removed", "permdrop", auth5.t("admin.perm_role_removed")):
    assert needle in page5, needle
_, _, log5b = started(db4, list(ROLES))
assert "temp-role → docs/docs.delete" in log5b and len(
    [a for a in auth5.store.recent_audit(80) if a["event"] == "permissions_suspended"]) == 1, \
    "a second start must name the row again, but not audit it again"
ok("(f) B-19/B-20: a removed role grants nothing at once and its assignment is suspended at once — back without a "
   "start it holds nothing; the next start names it in the security log, audited once; the panel lists it for "
   "administrators only")

# B-20: an administrator assigns again — only that gives the permission back (a fresh instance, not the file above).
authr, appr = build(available_roles=ROLES + ["temp-role"])
rid = int(authr.create_user("rex", password=PW, roles=["temp-role"]))
assert authr.grant_permission("temp-role", "docs.delete", app="docs", by="boss")
authr.cfg.available_roles = list(ROLES)
assert not authr.has_permission(authr.get_user(rid), "docs.delete", app="docs")
authr.cfg.available_roles = ROLES + ["temp-role"]
assert not authr.has_permission(authr.get_user(rid), "docs.delete", app="docs")
assert authr.grant_permission("temp-role", "docs.delete", app="docs", by="boss") is True, "the tick must re-activate"
assert authr.has_permission(authr.get_user(rid), "docs.delete", app="docs")
ok("(f) B-20: removed and re-added at runtime, the role holds nothing until an administrator assigns again")

# The role comes back — in the configuration, and as a catalog role: the assignment stays suspended.
auth6, app6, log6 = started(db4, ROLES + ["temp-role"])
assert not auth6.has_permission(auth6.get_user(tia), "docs.delete", app="docs"), \
    "a role created again under the same name inherited the old assignment"
assert row(auth6, "docs", "docs.delete")["suspended_roles"] == ["temp-role"] and "temp-role" not in log6
c6 = session(auth6, app6, boss4)
assert c6.get("/auth/admin/api/permissions").json()["removed_roles"] == []
auth7, app7, _ = started(db4, list(ROLES))
_role_catalog.create(auth7.cfg, auth7.store, "temp-role", "boss")        # the panel's and the CLI's path
assert not auth7.has_permission(auth7.get_user(tia), "docs.delete", app="docs"), "the catalog role inherited it"
assert assign(c6, "docs", "docs.delete", "temp-role").json() == {"ok": True, "changed": True}
assert auth6.has_permission(auth6.get_user(tia), "docs.delete", app="docs")
ok("(f) B-19: a role created again (configuration or catalog) does not take the old assignment over; an "
   "administrator's tick gives it back")

# Withdrawn by an administrator while the role is gone: the row goes, the next start says nothing.
auth8, app8, _ = started(db4, list(ROLES))
assert assign(session(auth8, app8, boss4), "docs", "docs.delete", "temp-role", granted=False).json()["changed"]
auth9, app9, log9 = started(db4, list(ROLES))
assert "temp-role" not in log9 and session(auth9, app9, boss4).get(
    "/auth/admin/api/permissions").json()["removed_roles"] == []
ok("(f) B-19: an administrator withdraws the assignment of a removed role; the next start names nothing")

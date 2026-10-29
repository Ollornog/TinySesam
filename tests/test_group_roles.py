"""Group→Role-Mapping (IdP-Gruppen → lokale Rollen) + available_roles im Admin-Panel."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


# ---------- apply_idp_groups: sync of mapped roles, manual ones stay, __admin__ follows the IdP (H-5) ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False))
uid = auth.create_user("bob", roles=["manual"])   # manuell vergebene Rolle
mapping = {"editors": "editor", "admins": "__admin__", "viewers": "viewer"}

# has editors + admins → editor role + admin flag; manual role stays
# (compared EXACTLY — default since group_match="exact")
auth.apply_idp_groups(uid, ["editors", "admins"], mapping)
u = auth.store.get_user(uid)
# is_admin=2: “granted by the identity provider” — only such a flag may he take away later.
assert set(auth.user_roles(u)) == {"manual", "editor"} and u["is_admin"] == 2
ok("groups→roles: editor set, manual role stays, __admin__ → admin flag (mark: from the IdP)")

# next login without editors and admins group → editor lapses, manual stays, and the
# admin flag that the IdP granted goes with it (H-5, PO decision 2026-09-24). Until then
# this said “admin stays (no auto-revocation)” — exactly that was the finding.
auth.apply_idp_groups(uid, ["viewers"], mapping)
u = auth.store.get_user(uid)
assert set(auth.user_roles(u)) == {"manual", "viewer"} and not u["is_admin"]
ok("erneuter Login: gemappte Rollen synchronisiert (editor weg, viewer da); vom IdP vergebenes Admin-Flag entzogen")

# leeres Mapping → No-Op
before = auth.user_roles(auth.store.get_user(uid))
auth.apply_idp_groups(uid, ["editors"], {})
assert auth.user_roles(auth.store.get_user(uid)) == before
ok("empty mapping → no change")

# exact comparison: 'editors' must NOT match 'nicht-editors'
auth.apply_idp_groups(uid, ["nicht-editors"], {"editors": "editor"})
assert "editor" not in auth.user_roles(auth.store.get_user(uid))
ok("default exact: partial match grants no role")

# substring remains possible for DNs — explicit
auth.apply_idp_groups(uid, ["cn=admins,ou=g,dc=x"], {"cn=admins,ou=g": "__admin__"}, substring=True)
assert auth.store.get_user(uid)["is_admin"] == 2
ok("substring=True: DN-Teiltreffer greift (so nutzt LDAP es)")
os.remove(db)

# ---------- LDAP-Login wendet ldap_group_role_map an ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False,
                                 ldap_enabled=True, ldap_url="ldap://x", ldap_allow_plaintext=True,
                                 ldap_group_role_map={"staff": "editor"}))

class FakeLDAP:
    def authenticate(self, u, p):
        return {"username": u, "email": None, "name": u, "groups": ["cn=staff,ou=groups"]} if p == "x" else None
auth.ldap = FakeLDAP()
u = auth._check_ldap("alice", "x")
assert u and auth.has_role(u, "editor")
ok("LDAP-Login: memberOf 'staff' → Rolle 'editor' (Teilstring-Match)")
os.remove(db)

# ---------- Admin panel: available_roles end up as ROLES in the panel HTML ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False,
                                 available_roles=["editor", "viewer"]))
auth.ensure_admin("admin", "geheim123")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app)
c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False)
html = c.get("/auth/admin", headers={"Accept": "text/html"}).text
assert 'const ROLES=["editor", "viewer"]' in html or 'const ROLES=["editor","viewer"]' in html
ok("admin panel: available_roles injected as ROLES (checkbox editor)")
os.remove(db)

print("\nGROUP→ROLE OK ✅")

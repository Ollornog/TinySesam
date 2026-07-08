"""Group→Role-Mapping (IdP-Gruppen → lokale Rollen) + available_roles im Admin-Panel."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


# ---------- apply_idp_groups: sync gemappter Rollen, manuelle bleiben, __admin__ grant-only ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False))
uid = auth.create_user("bob", roles=["manual"])   # manuell vergebene Rolle
mapping = {"editors": "editor", "cn=admins,ou=g": "__admin__", "viewers": "viewer"}

# hat editors + admins → editor-Rolle + Admin-Flag; manuelle Rolle bleibt
auth.apply_idp_groups(uid, ["editors", "cn=admins,ou=g,dc=x"], mapping)
u = auth.store.get_user(uid)
assert set(auth.user_roles(u)) == {"manual", "editor"} and u["is_admin"] == 1
ok("Gruppen→Rollen: editor gesetzt, manuelle Rolle bleibt, __admin__ → Admin-Flag")

# nächster Login ohne editors-Gruppe → editor entfällt (managed sync), manual bleibt, Admin bleibt (grant-only)
auth.apply_idp_groups(uid, ["viewers"], mapping)
u = auth.store.get_user(uid)
assert set(auth.user_roles(u)) == {"manual", "viewer"} and u["is_admin"] == 1
ok("erneuter Login: gemappte Rollen synchronisiert (editor weg, viewer da); Admin bleibt (kein Auto-Entzug)")

# leeres Mapping → No-Op
before = auth.user_roles(auth.store.get_user(uid))
auth.apply_idp_groups(uid, ["editors"], {})
assert auth.user_roles(auth.store.get_user(uid)) == before
ok("leeres Mapping → keine Änderung")
os.remove(db)

# ---------- LDAP-Login wendet ldap_group_role_map an ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False,
                                 ldap_enabled=True, ldap_url="ldap://x",
                                 ldap_group_role_map={"staff": "editor"}))

class FakeLDAP:
    def authenticate(self, u, p):
        return {"username": u, "email": None, "name": u, "groups": ["cn=staff,ou=groups"]} if p == "x" else None
auth.ldap = FakeLDAP()
u = auth.check_ldap("alice", "x")
assert u and auth.has_role(u, "editor")
ok("LDAP-Login: memberOf 'staff' → Rolle 'editor' (Teilstring-Match)")
os.remove(db)

# ---------- Admin-Panel: available_roles landen als ROLES im Panel-HTML ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False,
                                 available_roles=["editor", "viewer"]))
auth.ensure_admin("admin", "geheim123")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app)
c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False)
html = c.get("/auth/admin", headers={"Accept": "text/html"}).text
assert 'const ROLES=["editor", "viewer"]' in html or 'const ROLES=["editor","viewer"]' in html
ok("Admin-Panel: available_roles als ROLES injiziert (Checkbox-Editor)")
os.remove(db)

print("\nGROUP→ROLE OK ✅")

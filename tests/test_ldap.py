"""Batch B: LDAP/lldap-Backend — Login gegen Verzeichnis, Auto-Create, Gruppen-Gate.
Nutzt einen gefälschten LDAP-Client (kein Server/ldap3 nötig) und testet die Integration."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


class FakeLDAP:
    def __init__(self, users):
        self.users = users   # {username: {"password","email","name","groups"}}

    def authenticate(self, username, password):
        u = self.users.get(username)
        if not u or u["password"] != password:
            return None
        return {"username": username, "email": u.get("email"),
                "name": u.get("name", username), "groups": u.get("groups", [])}


def build(**cfgkw):
    db = tempfile.mktemp(suffix=".db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, ldap_enabled=True, ldap_url="ldap://dummy", **cfgkw))
    auth.ensure_admin("admin", "lokalpw")   # lokaler User mit lokalem Passwort
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, TestClient(app)


JSON = {"Accept": "application/json"}

# ---------- LDAP-User ohne lokales Passwort → Login + Auto-Create ----------
db, auth, c = build()
auth.ldap = FakeLDAP({"alice": {"password": "ldappw", "email": "alice@corp", "name": "Alice",
                                "groups": ["cn=staff,ou=groups,dc=corp"]}})
assert auth.store.get_user_by_name("alice") is None
r = c.post("/auth/login", data={"username": "alice", "password": "ldappw", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert c.get("/geheim", headers=JSON).json() == {"u": "alice"}
u = auth.store.get_user_by_name("alice")
assert u and u["email"] == "alice@corp" and u["display_name"] == "Alice"
ok("LDAP-Login legt lokalen User automatisch an (E-Mail/Name übernommen)")

# falsches LDAP-Passwort → 401
c.get("/auth/logout")
assert c.post("/auth/login", data={"username": "alice", "password": "falsch"}).status_code == 401
ok("falsches LDAP-Passwort → 401")
os.remove(db)

# ---------- lokales Passwort funktioniert weiter neben LDAP ----------
db, auth, c = build()
auth.ldap = FakeLDAP({})
r = c.post("/auth/login", data={"username": "admin", "password": "lokalpw", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("lokaler Passwort-Login funktioniert weiterhin (LDAP nur Fallback)")
os.remove(db)

# ---------- Gruppen-Gate ----------
db, auth, c = build(ldap_allowed_groups=["staff"])
auth.ldap = FakeLDAP({
    "bob": {"password": "x", "groups": ["cn=staff,ou=groups,dc=corp"]},      # erlaubt
    "eve": {"password": "x", "groups": ["cn=extern,ou=groups,dc=corp"]},     # nicht erlaubt
})
assert c.post("/auth/login", data={"username": "eve", "password": "x"}).status_code == 401
ok("Gruppen-Gate: User ohne erlaubte Gruppe → 401")
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "bob", "password": "x", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "bob"}
ok("Gruppen-Gate: User mit erlaubter Gruppe → Login")
os.remove(db)

# ---------- auto_create=False → kein lokaler User, kein Login ----------
db, auth, c = build(ldap_auto_create=False)
auth.ldap = FakeLDAP({"carol": {"password": "x"}})
assert c.post("/auth/login", data={"username": "carol", "password": "x"}).status_code == 401
ok("ldap_auto_create=False: unbekannter LDAP-User wird nicht angelegt")
os.remove(db)

print("\nLDAP-BACKEND OK ✅")

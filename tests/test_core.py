"""End-to-End-Test des Passwort- + TOTP-Kerns via FastAPI-TestClient (ohne Browser)."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False,
                                 oidc_enabled=False, cookie_secure=False))
assert auth.ensure_admin("admin", "geheim123"), "admin sollte angelegt werden"
assert not auth.ensure_admin("x", "y"), "zweiter ensure_admin darf nichts tun"

app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"user": u["username"], "admin": bool(u["is_admin"])}


c = TestClient(app)


def ok(name):
    print(f"  ✓ {name}")


# 1) ohne Login → 401 (JSON-Client)
assert c.get("/geheim").status_code == 401
ok("geschützt ohne Login → 401")

# 2) Login-Seite rendert
r = c.get("/auth/login")
assert r.status_code == 200 and "Passwort" in r.text
ok("Login-Seite")

# 3) falsches Passwort
assert c.post("/auth/login", data={"username": "admin", "password": "falsch", "next": "/geheim"}).status_code == 401
ok("falsches Passwort → 401")

# 4) richtiges Passwort (noch kein TOTP) → 303 + Cookie, kein MFA
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and "set-cookie" in {k.lower() for k in r.headers}
ok("Login ohne 2FA → eingeloggt")

# 5) geschützt jetzt erreichbar
r = c.get("/geheim")
assert r.status_code == 200 and r.json()["user"] == "admin"
ok("geschützt mit Session erreichbar")
assert c.get("/auth/me").json()["authenticated"] is True
ok("/auth/me authenticated")

# 6) TOTP einrichten
uid = auth.store.get_user_by_name("admin")["id"]
secret = auth.totp_begin(uid)["secret"]
assert auth.totp_confirm(uid, pyotp.TOTP(secret).now()) and auth.store.has_confirmed_totp(uid)
ok("TOTP eingerichtet")

# 7) Logout → Login jetzt MFA-pflichtig
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
assert c.get("/geheim").status_code == 401, "mit 2FA-pending noch nicht voll eingeloggt"
ok("Login mit TOTP → 2FA-Schritt verlangt")

# 8) falscher + richtiger TOTP-Code
assert c.post("/auth/totp", data={"code": "000000", "next": "/geheim"}).status_code == 401
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303
assert c.get("/geheim").json()["user"] == "admin"
ok("TOTP korrekt → voll eingeloggt")

# 9) Rollen (optional)
auth.set_roles(uid, ["editor"])
u = auth.store.get_user(uid)
assert auth.has_role(u, "editor") and auth.has_role(u, "irgendwas")  # admin ⇒ alle Rollen
auth.store.set_disabled(uid, False)
ok("Rollen + Admin-Override")

os.remove(db)
print("\nALLE TESTS OK ✅")

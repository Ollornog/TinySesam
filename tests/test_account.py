"""Phase 7: Eingebaute Account-Seite (Selbstverwaltung) + Selbst-Passwortänderung + Override."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, pin_enabled=True))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

# nicht eingeloggt → Redirect zum Login
r = c.get("/auth/account", follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
ok("Account-Seite verlangt Login")

c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
html = c.get("/auth/account").text
assert "Konto · admin" in html
assert "Passwort" in html and "PIN" in html and "Zwei-Faktor" in html and "API-Keys" in html
assert "Admin-Panel" in html   # admin sieht den Link
ok("Account-Seite zeigt Abschnitte (Passwort/PIN/2FA/API-Keys) + Admin-Link")

# Passwort ändern: falsches aktuelles → 403
assert c.post("/auth/password", json={"current": "falsch", "new": "neuespasswort"}).status_code == 403
# zu kurz → 400
assert c.post("/auth/password", json={"current": "geheim123", "new": "x"}).status_code == 400
# korrekt → 200, danach neuer Login funktioniert
assert c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"}).json() == {"ok": True}
c.get("/auth/logout")
assert c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False).status_code == 401
assert c.post("/auth/login", data={"username": "admin", "password": "neuespasswort"}, follow_redirects=False).status_code == 303
ok("Selbst-Passwortänderung (aktuelles Passwort nötig, Mindestlänge)")

# Robustheit: kaputter JSON-Body → 400 (nicht 500)
r = c.post("/auth/password", content="{kaputt}", headers={"Content-Type": "application/json"})
assert r.status_code == 400, r.status_code
ok("kaputter JSON-Body → 400 (nicht 500)")

# Template-Override der Account-Seite
auth.set_template("account", lambda a, ctx: f"<html>MEIN-KONTO {ctx['user']['username']}</html>")
assert "MEIN-KONTO admin" in c.get("/auth/account").text
ok("Account-Seite per set_template ersetzbar")

os.remove(db)
print("\nACCOUNT OK ✅")

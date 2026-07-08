"""Admin-Panel: Zugriffsschutz, User-/Service-/Key-Verwaltung, User sperren/entsperren,
Sitzungen, Härtung, Update, Audit."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False, cookie_secure=False))
auth.ensure_admin("admin", "pw12345")
auth.create_user("bob", password="bobpw", is_admin=False)

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)


def by_name(n):
    return next(u for u in c.get("/auth/admin/api/users").json() if u["username"] == n)


# ohne Admin-Login gesperrt
assert c.get("/auth/admin/api/users").status_code in (401, 403)
# bob (kein Admin) darf nicht
cb = TestClient(app)
cb.post("/auth/login", data={"username": "bob", "password": "bobpw"})
assert cb.get("/auth/admin/api/users").status_code == 403
print("  ✓ Zugriffsschutz: nur Admins")

# Admin-Login
c.post("/auth/login", data={"username": "admin", "password": "pw12345"})
assert c.get("/auth/admin/api/users").status_code == 200
print("  ✓ Admin sieht Benutzer-Liste")

# Service-Account + Key anlegen
sid = c.post("/auth/admin/api/users", json={"username": "svc1", "is_service": True, "roles": ["reader"]}).json()["id"]
key = c.post(f"/auth/admin/api/users/{sid}/keys", json={"name": "k1"}).json()["key"]
assert key.startswith("tsk_")
print("  ✓ Admin legt Service-Account + API-Key an")

# User SPERREN (disable, nicht löschen) → Login blockiert, Konto bleibt
bid = by_name("bob")["id"]
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": True})
assert by_name("bob")["disabled"] is True
assert TestClient(app).post("/auth/login", data={"username": "bob", "password": "bobpw"}).status_code == 401
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": False})
assert by_name("bob")["disabled"] is False
print("  ✓ Admin sperrt/entsperrt User explizit (nicht gelöscht, Login blockiert)")

# Selbst-Sperre verhindert
mid = by_name("admin")["id"]
assert c.post(f"/auth/admin/api/users/{mid}/disable", json={"disabled": True}).status_code == 400
print("  ✓ Selbst-Sperre verhindert")

# Sitzungen sichtbar + widerrufbar
assert len(c.get("/auth/admin/api/sessions").json()) >= 1
print("  ✓ Sitzungen einsehbar")

# Härtung lesen/setzen
assert "max_login_attempts" in c.get("/auth/admin/api/security").json()
c.post("/auth/admin/api/security", json={"max_login_attempts": 7})
assert auth.sec("max_login_attempts") == 7
print("  ✓ Härtungs-Schwellen im Panel setzbar")

# Update-Panel
assert "status" in c.get("/auth/admin/api/update").json()
c.post("/auth/admin/api/update/settings", json={"mode": "auto", "pin": "v0.3.0"})
assert auth.update_settings() == {"mode": "auto", "pin": "v0.3.0"}
print("  ✓ Update-Panel: Modus + Version-Pin")

# Audit + HTML
assert len(c.get("/auth/admin/api/audit").json()) >= 1
assert c.get("/auth/admin").status_code == 200 and "Admin" in c.get("/auth/admin").text
print("  ✓ Audit-Log + Admin-UI-Seite")

os.remove(db)
print("\nADMIN-PANEL OK ✅")

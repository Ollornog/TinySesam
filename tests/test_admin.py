"""Admin-Panel: Zugriffsschutz, User-/Service-/Key-Verwaltung, User sperren/entsperren,
Sitzungen, Härtung, Update, Audit."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
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

# Version — nur anzeigen. Die früheren Update-Routen sind bewusst weg: über sie konnte ein
# übernommener Admin-Zugang auf eine alte, lückenhafte Version zurückschalten.
assert c.get("/auth/admin/api/version").json()["version"][0].isdigit()
for gone in ("/auth/admin/api/update", "/auth/admin/api/update/run"):
    assert c.get(gone).status_code == 404, f"{gone} lebt noch"
print("  ✓ Version wird angezeigt; kein Update-Endpunkt mehr")

# Audit + HTML
assert len(c.get("/auth/admin/api/audit").json()) >= 1
assert c.get("/auth/admin").status_code == 200 and "Admin" in c.get("/auth/admin").text
print("  ✓ Audit-Log + Admin-UI-Seite")

# ---------- R6-1: den letzten Admin nicht entmachten ----------
# Ohne Admin öffnet sich der Erst-Admin-Weg neu (Einmal-Token im Log), und niemand kann es
# im Panel zurückdrehen. Geprüft wird VOR dem Schreiben: auch die Rollen bleiben unverändert.
mid = by_name("admin")["id"]
r = c.post(f"/auth/admin/api/users/{mid}/roles", json={"roles": ["x"], "is_admin": False})
assert r.status_code == 400, r.status_code
assert by_name("admin")["is_admin"] is True and by_name("admin")["roles"] == [], by_name("admin")
# Ein GESPERRTER zweiter Admin zählt nicht — er kann sich nicht anmelden.
bid = by_name("bob")["id"]
assert c.post(f"/auth/admin/api/users/{bid}/roles", json={"roles": [], "is_admin": True}).status_code == 200
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": True})
assert c.post(f"/auth/admin/api/users/{mid}/roles", json={"roles": [], "is_admin": False}).status_code == 400
assert by_name("admin")["is_admin"] is True
# Gegenprobe: Mit einem zweiten AKTIVEN Admin geht das Entmachten (die Regel sperrt nicht alles).
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": False})
assert c.post(f"/auth/admin/api/users/{bid}/roles", json={"roles": [], "is_admin": False}).status_code == 200
assert by_name("bob")["is_admin"] is False and by_name("admin")["is_admin"] is True
print("  ✓ R6-1: letzter aktiver Admin nicht entmachtbar (gesperrte zählen nicht), sonst schon")
# (Mutationsprobe: `and not andere_aktive_admins(uid)` → `and False` in admin.user_roles → rot.)

# ---------- R6-2: kein Admin-Service-Konto ----------
r = c.post("/auth/admin/api/users", json={"username": "svc2", "is_service": True, "is_admin": True})
assert r.status_code == 400, r.status_code
assert not any(u["username"] == "svc2" for u in c.get("/auth/admin/api/users").json())
assert c.post(f"/auth/admin/api/users/{sid}/roles", json={"roles": ["reader"], "is_admin": True}).status_code == 400
assert by_name("svc1")["is_admin"] is False
print("  ✓ R6-2: Service-Konto wird weder beim Anlegen noch über die Rollen zum Admin")

# ---------- R6-4 / B2-9: Härtungs-Schwellen mit Grenzen ----------
from tinysesam import ConfigError  # noqa: E402
vorher = auth.sec("max_login_attempts")
for boese in ({"rate_limit_max": 0}, {"max_login_attempts": 0}, {"lockout_window_sec": 10**9},
              {"password_min_length": 1}, {"rate_limit_max": "viele"}, {"gibtsnicht": 5},
              {"max_login_attempts": True}):
    assert c.post("/auth/admin/api/security", json=boese).status_code == 400, boese
# Alles-oder-nichts: ein gültiger Wert neben einem ungültigen wird NICHT geschrieben.
assert c.post("/auth/admin/api/security",
              json={"max_login_attempts": vorher + 2, "rate_limit_max": 0}).status_code == 400
assert auth.sec("max_login_attempts") == vorher and auth.sec("rate_limit_max") == 30
try:
    auth.set_security("rate_limit_max", 0)
    raise AssertionError("set_security nahm 0 an")
except ConfigError:
    pass
# Ein Wert, der schon in der Datenbank steht (Fassung ohne Grenzen): die Vorgabe gilt.
auth.store.set_setting("rate_limit_max", "0")
assert auth.sec("rate_limit_max") == 30, auth.sec("rate_limit_max")
auth.store.set_setting("rate_limit_max", "30")
print("  ✓ R6-4/B2-9: Grenzen im Panel und in set_security, alles-oder-nichts, Altwert fällt auf Vorgabe")
# (Mutationsprobe: in security.pruefe_haertung die Bereichsprüfung auskommentieren → rot.)

# ---------- R6-8: Key-Route antwortet 400 statt 500 ----------
for boese in ({"name": "x", "roles": ["gibtsnicht"]}, {"name": "x", "expires_days": 0},
              {"name": "x", "expires_days": "morgen"}):
    r = c.post(f"/auth/admin/api/users/{sid}/keys", json=boese)
    assert r.status_code == 400, (boese, r.status_code)
# Selbstbedienung: dieselbe Klasse.
assert c.post("/auth/apikeys", json={"name": "x", "roles": ["gibtsnicht"]}).status_code == 400
print("  ✓ R6-8: unbrauchbarer Scope/Ablauf → 400 mit Grund (Panel und /auth/apikeys)")

# ---------- R6-6: ein Key mintet keinen Key ----------
# (a) fail-closed für eine Key-Art, die es nicht gibt: Das Admin-Flag fällt weg, nicht nur bei
#     "automat". Vorher behielt `kind="Automat"` (Tippfehler in der Spalte) die Admin-Rechte.
k = auth.create_api_key(mid, name="ci")
auth.store._exec("UPDATE api_key SET kind='Automat' WHERE id=?", (k["id"],))
ohne = TestClient(app)
assert ohne.get("/auth/admin/api/users", headers={"x-api-key": k["key"]}).status_code == 403
# (b) Die Panel-Route verlangt selbst eine Sitzung — unabhängig davon, ob R6-5 das Admin-Flag
#     schon wegnimmt. Simuliert wird ein per Key angemeldeter Admin (der Fall, den R6-5 heute
#     verhindert); die Route darf trotzdem keinen Key ausgeben.
echt = auth.current_user
auth.current_user = lambda req: {**dict(auth.store.get_user(mid)), "_via": "apikey"}
try:
    r = ohne.post(f"/auth/admin/api/users/{sid}/keys", json={"name": "gemintet"})
    assert r.status_code == 403, r.status_code
finally:
    auth.current_user = echt
assert not any(x["name"] == "gemintet" for x in auth.list_api_keys(sid))
print("  ✓ R6-6: unbekannte Key-Art trägt kein Admin-Flag; Panel-Key nur aus einer Sitzung")
# (Mutationsproben: `art != "mensch"` → `art == "automat"` in current_user → (a) rot;
#  die `_via`-Prüfung in admin.user_key_create entfernen → (b) rot.)

os.remove(db)
print("\nADMIN-PANEL OK ✅")

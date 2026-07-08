"""Phase 4: Geteiltes Ressourcen-Geheimnis (PIN ODER Passphrase) — ohne Benutzerkonto."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, resource_locks_enabled=True))
# zwei Bereiche: einer PIN, einer Passphrase
auth.set_resource_secret("fotos", "2468", kind="pin", label="Familienfotos")
auth.set_resource_secret("wiki", "geheime passphrase", kind="password", label="Team-Wiki")

app = FastAPI()
app.include_router(auth.router())


@app.get("/fotos")
def fotos(_=Depends(auth.require_resource("fotos"))):
    return {"area": "fotos"}


@app.get("/wiki")
def wiki(_=Depends(auth.require_resource("wiki"))):
    return {"area": "wiki"}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# gesperrt ohne Unlock → 401 (JSON) bzw. 307 zur Unlock-Seite (Browser)
assert c.get("/fotos", headers=JSON).status_code == 401
r = c.get("/fotos", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"] == "/auth/resource/fotos?next=/fotos"
ok("gesperrter Bereich: JSON→401, Browser→307 zur Unlock-Seite")

# Unlock-Seite zeigt PIN- bzw. Passwort-Feld je nach kind
assert "Familienfotos" in c.get("/auth/resource/fotos").text
assert "Zugangswort" in c.get("/auth/resource/wiki").text
ok("Unlock-Seite: PIN-Feld bzw. Passphrase-Feld je nach kind")

# falsches Geheimnis → 401
assert c.post("/auth/resource/fotos", data={"secret": "0000", "next": "/fotos"}).status_code == 401
ok("falsches Geheimnis → 401")

# richtige PIN schaltet frei → Zugriff, ohne jeden User-Login
r = c.post("/auth/resource/fotos", data={"secret": "2468", "next": "/fotos"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/fotos"
assert c.get("/fotos", headers=JSON).json() == {"area": "fotos"}
ok("PIN korrekt → Bereich frei (kein Benutzerkonto nötig)")

# Freischaltung ist pro Bereich: wiki noch gesperrt
assert c.get("/wiki", headers=JSON).status_code == 401
r = c.post("/auth/resource/wiki", data={"secret": "geheime passphrase", "next": "/wiki"}, follow_redirects=False)
assert r.status_code == 303
assert c.get("/wiki", headers=JSON).json() == {"area": "wiki"}
# fotos bleibt parallel offen
assert c.get("/fotos", headers=JSON).status_code == 200
ok("Freischaltung pro Bereich getrennt (Passphrase-Bereich separat)")

# Lockout nach zu vielen Fehlversuchen (pseudo-User res:name)
c2 = TestClient(app)
for _ in range(5):
    c2.post("/auth/resource/fotos", data={"secret": "0000", "next": "/"})
assert c2.post("/auth/resource/fotos", data={"secret": "2468", "next": "/"}).status_code == 429
ok("Ressourcen-Lockout greift")

# Admin-API verwaltet Geheimnisse
admin = auth.store.get_user_by_name("admin")
# (kein Admin angelegt in diesem Test → über Manager prüfen)
auth.set_resource_secret("neu", "1234", kind="pin", label="Neu")
names = {r["name"] for r in auth.list_resource_secrets()}
assert {"fotos", "wiki", "neu"} <= names
auth.remove_resource_secret("neu")
assert "neu" not in {r["name"] for r in auth.list_resource_secrets()}
ok("Manager/Admin: Geheimnisse anlegen + löschen")

os.remove(db)
print("\nRESOURCE-LOCK OK ✅")

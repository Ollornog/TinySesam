"""Phase 4: Geteiltes Ressourcen-Geheimnis (PIN ODER Passphrase) — ohne Benutzerkonto."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
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
GRENZE = auth.sec("resource_max_attempts")
codes = [c2.post("/auth/resource/fotos", data={"secret": "0000", "next": "/"}).status_code
         for _ in range(GRENZE)]
assert codes == [401] * GRENZE, codes
assert c2.post("/auth/resource/fotos", data={"secret": "2468", "next": "/"}).status_code == 429
ok("Ressourcen-Lockout greift")

# ---------- Runde 2: Bereichs-Fehlgriffe sperren keine ANMELDUNG ----------
# Die Bereichs-PIN darf JEDER Besucher probieren — ein Konto braucht es dafür nicht. Ihre
# Fehlgriffe liefen trotzdem in den Login-Topf (`record_login(pseudo, …, "resource")` +
# `is_locked`), und weil dort die IP-Schwelle `max_login_attempts * ip_attempt_factor` gilt,
# genügten drei Bereiche à fünf Fehlgriffe von derselben Adresse, um die Anmeldung von Konten
# zu verriegeln, die damit nichts zu tun hatten. Jetzt sperrt der eigene Topf das, was er
# schützt: Bereiche. (Mutationsprobe: in `resource_submit` wieder `is_locked` prüfen und
# "resource" aus `security.EIGENE_SPERRE` nehmen → (a) wird rot.)
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, rp_name="Test",
                                  passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                  resource_locks_enabled=True))
auth2.create_user("unbeteiligt", "Unbeteiligt-Passwort-1")
app2 = FastAPI()
app2.include_router(auth2.router())
c3 = TestClient(app2)
bereiche = ["lager", "archiv", "keller"]
for n in bereiche:
    auth2.set_resource_secret(n, "1234", kind="pin", label=n)
for n in bereiche:
    for _ in range(auth2.sec("resource_max_attempts")):
        c3.post(f"/auth/resource/{n}", data={"secret": "0000", "next": "/"})
IP_GRENZE = auth2.sec("max_login_attempts") * auth2.sec("ip_attempt_factor")
assert auth2.store.count_fails(0, ip="testclient", method="resource") >= IP_GRENZE, \
    "Angriffslage nicht hergestellt: die Test-IP hat die Login-IP-Schwelle nicht erreicht"

# (a) Der Angriff: Die Anmeldung eines Unbeteiligten von derselben Adresse bleibt offen.
assert not auth2.is_locked("unbeteiligt", "testclient"), \
    "Fehlgriffe an der Bereichs-PIN sperren die Anmeldung Unbeteiligter"
r = c3.post("/auth/login", data={"username": "unbeteiligt", "password": "Unbeteiligt-Passwort-1"},
            follow_redirects=False)
assert r.status_code == 303, f"Login des Unbeteiligten gesperrt: {r.status_code}"
ok("Bereichs-Fehlgriffe sperren keine Anmeldung (eigener Topf)")

# (b) Die IP-Dimension bleibt hier trotzdem erhalten — anders als bei den angemeldeten Wegen:
# Hier rät ein Fremder, das Opfer ist kein bestimmter Nutzer, und ohne sie könnte er über immer
# neue Bereichsnamen endlos weiterraten. Ein VIERTER, nie berührter Bereich ist deshalb von
# derselben Adresse aus zu.
auth2.set_resource_secret("tresor", "9876", kind="pin", label="Tresor")
assert auth2.store.count_fails(0, username="res:tresor", method="resource") == 0, \
    "Vorbedingung: dieser Bereich hat selbst keinen Fehlgriff gesehen"
r = c3.post("/auth/resource/tresor", data={"secret": "9876", "next": "/"})
assert r.status_code == 429, f"die IP-Schwelle des Bereichs-Topfes greift nicht: {r.status_code}"
# …und ein anderer Anschluss ist davon unberührt (die Sperre klebt an der Adresse, nicht am Bereich).
c4 = TestClient(app2, client=("203.0.113.30", 50000))
r = c4.post("/auth/resource/tresor", data={"secret": "9876", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"fremder Anschluss mitgesperrt: {r.status_code}"
ok("…die IP-Schwelle des Bereichs-Topfes bleibt (sperrt Bereiche, keine Anmeldungen)")
os.remove(db2)

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

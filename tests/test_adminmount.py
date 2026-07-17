"""Admin-Panel: frei wählbarer Pfad, an eigenem Prefix montierbar, nur-JSON (für eigenes Panel),
HTTPS-Modi (warn = ohne Zertifikat mit Hinweis, force = HTTP→HTTPS-Redirect)."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def fresh(**cfg):
    db = tempfile.mktemp(suffix=".db")
    # cookie_secure=False ist der Normalfall dieser Suite (TestClient spricht http://),
    # muss aber überschreibbar sein: Fall 5 fährt https_mode='force', und force zusammen
    # mit einem unsicheren Cookie lehnt der Konstruktor zu Recht ab.
    kw = dict(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False,
              oidc_enabled=False, cookie_secure=False)
    kw.update(cfg)
    a = TinySesam(TinySesamConfig(**kw))
    a.ensure_admin("a", "pw")
    return a, db


def login(app):
    c = TestClient(app)
    c.post("/auth/login", data={"username": "a", "password": "pw"})
    return c


# 1) frei gewählter Pfad
a, db = fresh(admin_path="/verwaltung")
app = FastAPI(); app.include_router(a.router())
c = login(app)
assert c.get("/verwaltung/api/users").status_code == 200
assert c.get("/verwaltung").status_code == 200 and "Admin" in c.get("/verwaltung").text
assert c.get("/auth/admin/api/users").status_code == 404
os.remove(db)
print("  ✓ Admin-Panel an frei wählbarem Pfad (/verwaltung)")

# 2) admin_router() selbst montieren, Auto-Mount aus
a, db = fresh(admin_enabled=False)
app = FastAPI(); app.include_router(a.router()); app.include_router(a.admin_router(), prefix="/adminx")
c = login(app)
assert c.get("/adminx/api/users").status_code == 200
assert c.get("/auth/admin/api/users").status_code == 404
os.remove(db)
print("  ✓ admin_router() an eigenem Prefix montierbar (Auto-Mount aus)")

# 3) nur JSON-API (UI zum Einbetten in bestehendes Panel deaktiviert)
a, db = fresh(admin_ui_enabled=False)
app = FastAPI(); app.include_router(a.router())
c = login(app)
assert c.get("/auth/admin/api/users").status_code == 200
assert c.get("/auth/admin").status_code == 404
os.remove(db)
print("  ✓ admin_ui_enabled=False → nur JSON-API")

# 4) https_mode=warn → läuft ohne Zertifikat, Warnhinweis im Panel
a, db = fresh(https_mode="warn")
app = FastAPI(); a.install_https(app); app.include_router(a.router())
c = login(app)
assert "Unverschlüsselt" in c.get("/auth/admin").text
os.remove(db)
print("  ✓ https_mode=warn: ohne Zertifikat nutzbar + Warnhinweis")

# 5) https_mode=force → HTTP wird auf HTTPS umgeleitet
# cookie_secure=True ist hier Pflicht, nicht Zierde: force + unsicheres Cookie lehnt der
# Konstruktor ab (die App leitete sonst auf HTTPS um und gäbe das Cookie trotzdem ohne
# Secure-Flag heraus). Dieser Fall meldet sich ohnehin nicht an — er prüft nur den Redirect.
a, db = fresh(https_mode="force", cookie_secure=True)
app = FastAPI(); a.install_https(app); app.include_router(a.router())
r = TestClient(app).get("/auth/login", follow_redirects=False)
assert r.status_code in (307, 308) and r.headers["location"].startswith("https://")
os.remove(db)
print("  ✓ https_mode=force: HTTP → HTTPS-Redirect")

print("\nADMIN-MOUNT / HTTPS OK ✅")

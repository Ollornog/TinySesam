"""Phase 4.5: Faktor-Ketten-Engine — geordnete Kombinationen, global + per-Route, strict-Flag."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def fresh(chain=None, strict=True, **kw):
    db = tempfile.mktemp(suffix=".db")
    cfg = TinySesamConfig(csrf_enabled=False, db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                          cookie_secure=False, login_chain=chain or [], login_chain_strict=strict,
                          pin_enabled=True, **kw)
    auth = TinySesam(cfg)
    auth.ensure_admin("admin", "geheim123")
    uid = auth.store.get_user_by_name("admin")["id"]
    auth.set_pin(uid, "2468")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, uid, app


# ---------- Globale Kette ["pin","password"] strikt: Reihenfolge erzwungen ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=True)


@app.get("/area")
def area(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# Erstfaktor PIN → Sitzung unvollständig, noch kein Zugriff
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login"), r.headers.get("location")
assert c.get("/area", headers=JSON).status_code == 401
ok("Kette pin→password: nach PIN erst Weiterleitung zu /auth/login, noch kein Zugriff")

# Zweiter Faktor Passwort → Kette erfüllt → Zugriff
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/area", r.headers.get("location")
assert c.get("/area", headers=JSON).json() == {"u": "admin"}
ok("Kette pin→password: nach Passwort vollständig eingeloggt")
os.remove(db)

# ---------- Strikt: falsche Reihenfolge gewährt KEINEN Zugriff ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=True)
c = TestClient(app)
# Passwort zuerst (falsche Reihenfolge) → wird zu /auth/pin geschickt, aber nie „fertig"
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/pin")
assert c.get("/geheim", headers=JSON).status_code == 401
ok("strikt: Passwort-vor-PIN erfüllt die Kette nicht (kein Zugriff)")
os.remove(db)

# ---------- Nicht-strikt: beliebige Reihenfolge genügt ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=False)
c = TestClient(app)
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).status_code == 401   # nur ein Faktor
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("nicht-strikt: Passwort dann PIN (umgekehrte Reihenfolge) genügt")
os.remove(db)

# ---------- Globale Kette ["password","totp"] mit echtem TOTP ----------
db, auth, uid, app = fresh(chain=["password", "totp"], strict=True)
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).now())
c = TestClient(app)
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp")
assert c.get("/geheim", headers=JSON).status_code == 401
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("Kette password→totp erfüllt")
os.remove(db)

# ---------- Per-Route-Override: Route verlangt zusätzlich einen bestimmten Faktor ----------
db, auth, uid, app = fresh(chain=[])   # global klassisch


@app.get("/pin-area")
def pin_area(u=Depends(auth.require(factors=["password", "pin"]))):
    return {"u": u["username"]}


c = TestClient(app)
# klassischer Passwort-Login (global vollständig, kein TOTP)
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}       # normale Route frei
r = c.get("/pin-area", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"].startswith("/auth/pin"), r.headers.get("location")
# PIN als Zusatzfaktor an die laufende Sitzung anhängen
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/pin-area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/pin-area"
assert c.get("/pin-area", headers=JSON).json() == {"u": "admin"}
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}       # normale Route weiterhin frei
ok("per-Route factors=[password,pin]: PIN als Zusatzfaktor, Sitzung bleibt gültig")
os.remove(db)

print("\nFAKTOR-KETTEN OK ✅")

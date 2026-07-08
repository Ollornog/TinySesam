"""G1/G2: zentraler Theming-Hook (brand_css) + themed Fehlerseiten (install_error_pages)."""
import tempfile, os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


BRAND = "body{background:#123456}.card{border-color:#abcdef}"
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", lang="de", brand_css=BRAND,
                                 passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                 csrf_enabled=False, pin_enabled=True, allow_signup=True))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


@app.get("/boom")
def boom():
    raise RuntimeError("kaputt")


@app.get("/forbidden")
def forbidden():
    raise HTTPException(403, "kein Zugriff")


c = TestClient(app, raise_server_exceptions=False)
HTML = {"Accept": "text/html"}
JSON = {"Accept": "application/json"}

# ---------- brand_css landet in ALLEN eingebauten Seiten ----------
for path in ["/auth/login", "/auth/register"]:
    assert BRAND in c.get(path).text, path
# auch Konto-Seite (eigenes Layout) + eingeloggt
c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False)
assert BRAND in c.get("/auth/account").text
assert BRAND in c.get("/auth/admin", headers=HTML).text
ok("brand_css re-skinnt Login/Register/Konto/Admin-Panel (ein Hook)")

# ---------- themed Fehlerseiten für Browser, JSON für API ----------
r = c.get("/gibtsnicht", headers=HTML)
assert r.status_code == 404 and "404" in r.text and BRAND in r.text
ok("404: themed HTML-Fehlerseite (mit Branding)")

r = c.get("/forbidden", headers=HTML)
assert r.status_code == 403 and "403" in r.text and "kein Zugriff" in r.text
ok("403: themed Fehlerseite mit Meldung")

r = c.get("/boom", headers=HTML)
assert r.status_code == 500 and "500" in r.text
ok("500: unbehandelte Exception → themed 500-Seite")

# API-Clients bekommen JSON, keine HTML-Seite
r = c.get("/gibtsnicht", headers=JSON)
assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")
ok("API-Client (Accept json): 404 als JSON, nicht HTML")

# ---------- Redirects (Login) bleiben Redirects trotz Error-Handler ----------
c2 = TestClient(app, raise_server_exceptions=False)
r = c2.get("/geheim", headers=HTML, follow_redirects=False)
assert r.status_code == 307 and "/auth/login" in r.headers["location"]
ok("Login-Redirect (307) bleibt Redirect (nicht als Fehlerseite abgefangen)")

os.remove(db)
print("\nTHEME + ERROR-PAGES OK ✅")

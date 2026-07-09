"""E2: CSRF-Schutz (double-submit). CSRF ist hier AN (Default)."""
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False))   # csrf_enabled default True
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


def csrf_token(client):
    """CSRF-Cookie + versteckten Feldwert von der Login-Seite holen (double-submit)."""
    html = client.get("/auth/login").text
    field = re.search(r"name=_csrf value='([^']+)'", html).group(1)
    cookie = client.cookies.get("tinysesam_csrf")
    return field, cookie


c = TestClient(app)
JSON = {"Accept": "application/json"}

# ---------- Login-Seite setzt CSRF-Cookie + bettet _csrf-Feld ein (identisch) ----------
field, cookie = csrf_token(c)
assert field and cookie and field == cookie
ok("Login-Seite: CSRF-Cookie == verstecktes _csrf-Feld (double-submit)")

# ---------- POST OHNE Token → 403 ----------
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert r.status_code == 403, r.status_code
ok("Login-POST ohne CSRF-Token → 403")

# ---------- POST MIT Token → ok ----------
field, cookie = csrf_token(c)
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/", "_csrf": field},
           follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("Login-POST mit gültigem CSRF-Token → 303")

# ---------- JSON-Endpoint ohne Header → 403, mit Header → ok ----------
assert c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"}).status_code == 403
tok = c.cookies.get("tinysesam_csrf")
r = c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"},
           headers={"X-CSRF-Token": tok})
assert r.status_code == 200, r.status_code
ok("JSON-POST: ohne X-CSRF-Token → 403, mit → 200")

# ---------- falscher Token → 403 ----------
c.get("/auth/logout")                 # ausloggen, damit die Login-Seite wieder ein Formular zeigt
csrf_token(c)                          # frisches CSRF-Cookie holen
r = c.post("/auth/login", data={"username": "admin", "password": "neuespasswort", "_csrf": "falsch"})
assert r.status_code == 403
ok("falscher CSRF-Token → 403")

# ---------- API-Key ist von CSRF ausgenommen (maschinell, kein Cookie-Risiko) ----------
key = auth.create_api_key(uid, name="k")["key"]
c2 = TestClient(app)
# JSON-Endpoint per Key ohne CSRF-Token → erlaubt
r = c2.get("/auth/apikeys", headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 200
ok("API-Key-Request ohne CSRF-Token erlaubt (ausgenommen)")

os.remove(db)
print("\nCSRF OK ✅")

# ---------- Das Token darf nicht bei jedem Rendern rotieren ----------
# Sonst macht jede andere gerenderte Seite ein offenes Formular ungültig ("Formular abgelaufen").
import re as _re

_db = tempfile.mktemp(suffix=".db")
_a = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, cookie_secure=False,
                               allow_signup=True, signup_require_email=False,
                               login_identifier="username"))
_a.create_user("max", password="geheim12345")
_app = FastAPI()
_app.include_router(_a.router())
_a.install_error_pages(_app)
_c = TestClient(_app, headers={"accept": "text/html"}, raise_server_exceptions=False)

_r1 = _c.get("/auth/login")
_tok = _re.search(r"name=_csrf value='([^']+)'", _r1.text).group(1)
assert "tinysesam_csrf" in _r1.headers.get("set-cookie", ""), "erstes Rendern setzt das Cookie"

# jede weitere gerenderte Seite (auch Fehlerseiten) darf es NICHT überschreiben
for _p in ("/auth/login", "/auth/register", "/gibtsnicht"):
    assert "tinysesam_csrf" not in _c.get(_p).headers.get("set-cookie", ""), _p

_r = _c.post("/auth/login", data={"username": "max", "password": "geheim12345", "next": "/", "_csrf": _tok},
             follow_redirects=False)
assert _r.status_code == 303, f"Token der offenen Seite muss gültig bleiben, war {_r.status_code}"

# Schutz bleibt scharf
assert _c.post("/auth/login", data={"username": "max", "password": "geheim12345", "_csrf": "falsch"}).status_code == 403
assert _c.post("/auth/login", data={"username": "max", "password": "geheim12345"}).status_code == 403
os.remove(_db)
print("  CSRF-Token bleibt über Seitenwechsel gültig; falsches/fehlendes Token weiterhin 403")

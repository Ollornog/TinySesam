"""E2: CSRF-Schutz (double-submit). CSRF ist hier AN (Default)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
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

_db = os.path.join(tempfile.mkdtemp(), "t.db")
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

# ---------- H-2 / F-02: Herkunft vor dem Token-Vergleich ----------
# Das naive Double-Submit prüft nur, ob Cookie und Feld zusammenpassen. Wer über eine
# Nachbar-Subdomain Cookies setzen kann, setzt das passende Paar gleich mit und schickt das
# Opfer per Formular in SEIN Konto (Login-CSRF). Hier ist das Paar deshalb immer GÜLTIG — nur
# die Herkunft entscheidet.
import logging  # noqa: E402

_db = os.path.join(tempfile.mkdtemp(), "t.db")


def _instanz(**kw):
    a = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, cookie_secure=False,
                                  apikey_enabled=True, **kw))
    a.ensure_admin("admin", "geheim123")
    ap = FastAPI()
    ap.include_router(a.router())
    return a, ap


_a, _app = _instanz(trusted_redirect_hosts=["portal.example.com"])


def _login(kopf, app=None):
    cl = TestClient(app or _app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    return cl.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                        "_csrf": feld}, headers=kopf, follow_redirects=False).status_code


class _Fang(logging.Handler):
    zeilen: list = []

    def emit(self, record):
        _Fang.zeilen.append(record.getMessage())


_log = logging.getLogger("tinysesam.security")
_fang = _Fang()
_log.addHandler(_fang)
try:
    assert _login({"Origin": "https://angreifer.example"}) == 403, "fremder Origin mit gültigem Paar"
    assert _login({"Origin": "https://nachbar.example.com", "Sec-Fetch-Site": "same-site"}) == 403, \
        "Nachbar-Subdomain (cookie tossing) muss scheitern"
    assert _login({"Sec-Fetch-Site": "cross-site"}) == 403, "cross-site ohne Origin"
    assert any("csrf origin rejected" in z for z in _Fang.zeilen), "Abweisung muss im Log stehen"
    ok("H-2: fremder Origin, Nachbar-Subdomain und cross-site → 403, obwohl das Token-Paar stimmt")

    assert _login({"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}) == 303
    assert _login({}) == 303, "ohne beide Header entscheidet das Token (alter Browser, Skript)"
    assert _login({"Origin": "null"}) == 303, "Origin null allein sagt nichts — Token entscheidet"
    assert _login({"Origin": "https://portal.example.com"}) == 303, "trusted_redirect_hosts zählt als eigen"
    ok("H-2: eigener Origin, fehlende Header, Origin null und vertraute Hosts gehen durch")

    # Proxy schreibt den Host um (upstream-Name), ohne X-Forwarded-Host — base_url rettet es.
    _a2, _app2 = _instanz(base_url="https://auth.example.com")
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}, _app2) == 303
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000",
                   "X-Forwarded-Host": "auth.example.com"}, _app) == 303, "X-Forwarded-Host zählt"
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}, _app) == 403
    ok("H-2: Proxy mit umgeschriebenem Host — base_url oder X-Forwarded-Host machen den Origin eigen")

    # JSON-Weg (json_body) prüft genauso.
    cl = TestClient(_app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    cl.post("/auth/login", data={"username": "admin", "password": "geheim123", "_csrf": feld})
    r = cl.post("/auth/password", json={"current": "geheim123", "new": "anderespasswort1"},
                headers={"X-CSRF-Token": feld, "Origin": "https://angreifer.example"})
    assert r.status_code == 403, r.status_code
    ok("H-2: auch der JSON-Weg (X-CSRF-Token) weist fremde Herkunft ab")

    # Ein echter API-Key bleibt ausgenommen — ein Daemon hat keinen Browser.
    _key = _a.create_api_key(_a.store.get_user_by_name("admin")["id"], name="k")["key"]
    r = TestClient(_app).get("/auth/apikeys", headers={"Authorization": f"Bearer {_key}",
                                                       "Origin": "https://angreifer.example"})
    assert r.status_code == 200
    ok("H-2: API-Key-Requests bleiben von der CSRF-Schicht ausgenommen")

    _a3, _app3 = _instanz(csrf_origin_check=False)
    assert _login({"Origin": "https://angreifer.example"}, _app3) == 303
    ok("csrf_origin_check=False schaltet nur die Vorprüfung ab (Notausgang für schiefe Proxys)")
finally:
    _log.removeHandler(_fang)

# Das eingebaute JS liest den TATSÄCHLICHEN Cookie-Namen — mit __Host- (H-1) hieße das Cookie
# sonst anders als das, was die Kontoseite sucht, und jeder Knopf dort antwortete 403.
_a4 = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, pin_enabled=True))
assert _a4.csrf_cookie_name == "__Host-tinysesam_csrf"
_html = _a4.templates.render("account", _a4, {"user": {"username": "x", "display_name": "x"},
                                              "methods": ["password", "pin"]})
assert "__Host-tinysesam_csrf=" in _html and "; )tinysesam_csrf=" not in _html, "Kontoseite liest falschen Namen"
ok("Kontoseite liest das CSRF-Cookie unter seinem tatsächlichen Namen (__Host-…)")
os.remove(_db)

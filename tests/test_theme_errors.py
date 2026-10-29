"""G1/G2: zentraler Theming-Hook (brand_css) + themed Fehlerseiten (install_error_pages)."""
import os
import tempfile, os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


BRAND = "body{background:#123456}.card{border-color:#abcdef}"
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", lang="de", brand_css=BRAND,
                                 passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                 csrf_enabled=False, pin_enabled=True, allow_signup=True))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)


@app.get("/geheim")
def secret_text(u=Depends(auth.require_user)):
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
# also account page (own layout) + logged in
c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False)
assert BRAND in c.get("/auth/account").text
assert BRAND in c.get("/auth/admin", headers=HTML).text
ok("brand_css re-skins login/register/account/admin panel (one hook)")

# ---------- themed error pages for browsers, JSON for API ----------
r = c.get("/gibtsnicht", headers=HTML)
assert r.status_code == 404 and "404" in r.text and BRAND in r.text
ok("404: themed HTML error page (with branding)")

r = c.get("/forbidden", headers=HTML)
assert r.status_code == 403 and "403" in r.text and "kein Zugriff" in r.text
ok("403: themed error page with message")

r = c.get("/boom", headers=HTML)
assert r.status_code == 500 and "500" in r.text
ok("500: unbehandelte Exception → themed 500-Seite")

# API clients get JSON, no HTML page
r = c.get("/gibtsnicht", headers=JSON)
assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")
ok("API client (Accept json): 404 as JSON, not HTML")

# ---------- Redirects (Login) bleiben Redirects trotz Error-Handler ----------
c2 = TestClient(app, raise_server_exceptions=False)
r = c2.get("/geheim", headers=HTML, follow_redirects=False)
assert r.status_code == 307 and "/auth/login" in r.headers["location"]
ok("login redirect (307) stays a redirect (not caught as an error page)")

os.remove(db)
print("\nTHEME + ERROR-PAGES OK ✅")


# ---------- brand_icon: one value, favicon on all built-in pages ----------
import os as _os
import tempfile as _tf
from tinysesam.admin import render_panel as _rp

_db = _os.path.join(_tf.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, csrf_enabled=False, lang="de", passkey_enabled=False,
                               allow_signup=True, magiclink_enabled=True, brand_icon="/logo.png",
                               base_url="https://auth.example.com"))
_app = FastAPI(); _app.include_router(_a.router()); _a.install_error_pages(_app)
_c = TestClient(_app, headers={"accept": "text/html"}, raise_server_exceptions=False)
for _p in ("/auth/login", "/auth/register", "/auth/magic/request", "/gibtsnicht"):
    assert "rel=icon href='/logo.png'" in _c.get(_p).text, _p
assert "rel=icon href='/logo.png'" in _rp(_a, "/auth/admin"), "Admin-Panel"
os.unlink(_db)

_db = _os.path.join(_tf.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, csrf_enabled=False, lang="de", passkey_enabled=False))
_app = FastAPI(); _app.include_router(_a.router())
assert "rel=icon href='data:image/svg+xml;base64," in TestClient(_app).get("/auth/login").text, \
    "without brand_icon the built-in default favicon (since 0.24.8)"
os.unlink(_db)
print("OK brand_icon: favicon centrally on all built-in pages")


# ---------- Demo notice stands outside the login card ----------
_db = _os.path.join(_tf.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, csrf_enabled=False, lang="de", passkey_enabled=False,
                               pin_enabled=True, demo_mode=True, cookie_secure=False))
_app = FastAPI(); _app.include_router(_a.router())
_c = TestClient(_app, headers={"accept": "text/html"})
_lp = _c.get("/auth/login").text
assert _lp.index("class=demobar") < _lp.index("<div class=card>"), "notice before the card"
assert "<div class=card>" not in _lp[:_lp.index("class=demobar")], "and outside"
assert "demo_mode" in _lp, "warning that it belongs off in production"
os.unlink(_db)

# without demo_mode no notice
_db = _os.path.join(_tf.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, csrf_enabled=False, lang="de", passkey_enabled=False))
_app = FastAPI(); _app.include_router(_a.router())
assert "class=demobar" not in TestClient(_app).get("/auth/login").text
os.unlink(_db)
print("OK demo notice: outside the card, only with demo_mode")

# ---------- brand_header / brand_footer: body of the host app around EVERY built-in page ----------
_db = _os.path.join(_tf.mkdtemp(), "t.db")
_calls = []


def _hdr(a):
    _calls.append("h")
    return "<nav id=meinenav>NAV</nav>"


_a = TinySesam(TinySesamConfig(db_path=_db, csrf_enabled=False, lang="de", passkey_enabled=False,
                              cookie_secure=False, allow_signup=True, signup_require_email=False,
                              login_identifier="username",
                              brand_header=_hdr, brand_footer="<footer id=meinfooter>F</footer>"))
_a.create_user("max", password="geheim12345", is_admin=True)
_app = FastAPI(); _app.include_router(_a.router()); _a.install_error_pages(_app)
_c = TestClient(_app, headers={"accept": "text/html"}, raise_server_exceptions=False)

for _p in ("/auth/login", "/auth/register", "/gibtsnicht"):
    _t = _c.get(_p).text
    assert "meinenav" in _t and "meinfooter" in _t, _p
    assert _t.index("meinenav") < _t.index("class=tsmain") < _t.index("meinfooter"), _p
assert _calls, "callable is evaluated per call"

_c.post("/auth/login", data={"username": "max", "password": "geheim12345", "next": "/"})
for _p in ("/auth/account", "/auth/admin"):
    _t = _c.get(_p).text
    assert "meinenav" in _t and "meinfooter" in _t, _p

# a broken body does not drag the login page down with it
_a.cfg.brand_header = lambda a: 1 / 0
assert "<div class=card>" in _c.get("/auth/login").text
os.unlink(_db)

# without brand_header/-footer everything stays as before
_db = _os.path.join(_tf.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, csrf_enabled=False, lang="de", passkey_enabled=False))
_app = FastAPI(); _app.include_router(_a.router())
_t = TestClient(_app).get("/auth/login").text
assert "<body><div class=tsmain>" in _t
os.unlink(_db)
print("OK brand_header/brand_footer: body around login, account, admin and error pages")

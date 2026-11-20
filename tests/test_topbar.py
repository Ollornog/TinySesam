"""Top bar of the built-in pages (T-64) — the HTML side; the behaviour in a browser is in tests/test_browser.py
(`top_bar`: menu, keyboard, light/dark before the first paint, phone width, sign-out).

Checked here:
* links — `topbar_links` takes paths on the own origin and https addresses on base_url's host or
  trusted_redirect_hosts; a foreign origin, `javascript:`, `//host`, a breakout or a malformed entry is refused;
* menu — account pages show the account menu for a session, the admin entry only for admins, the sign-out is a
  POST with the CSRF field; sign-in and error pages show logo and name only; an API key gets no menu;
* switch — `topbar_enabled=False` takes the bar away and gives the account page its own links back;
* logo and favicon — `brand_icon` (own origin) is the logo, "none" none, otherwise the built-in mark; the built-in
  favicon is the same mark;
* building blocks — `auth.topbar_head()` / `auth.topbar(request)` for an app's own pages: nonce, mount prefix, menu.
"""
import base64
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.templates import STANDARD_FAVICON  # noqa: E402

HTML = {"Accept": "text/html"}


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    d = tempfile.mkdtemp()
    kw.setdefault("lang", "en")
    a = TinySesam(TinySesamConfig(db_path=os.path.join(d, "t.db"), passkey_enabled=False, cookie_secure=False,
                                  **kw))
    a.set_security("password_min_length_single_factor", 8)
    return a


# --- links: config check ----------------------------------------------------------------------------
good = [("Wiki", "/wiki"), ("Files", "https://files.example.com/x"), ("Home", "https://auth.example.com/")]
make(topbar_links=good, trusted_redirect_hosts=["files.example.com"], base_url="https://auth.example.com")
for bad in ([("Evil", "https://evil.example/")], [("JS", "javascript:alert(1)")], [("Slash", "//evil.example/")],
            [("Data", "data:text/html,x")], [("Quote", "/a'onmouseover=x")], [("Space", "/a b")],
            [("Plain", "http://files.example.com/")], [("", "/x")], ["/x"], [("A", "/x", "extra")],
            [("T" * 61, "/x")]):
    try:
        make(topbar_links=bad, trusted_redirect_hosts=["files.example.com"])
    except ConfigError as e:
        assert "topbar_links" in str(e), e
    else:
        raise AssertionError(f"topbar_links={bad!r} accepted")
ok("topbar_links: own paths and https on trusted hosts pass; foreign origins, javascript:, //, breakouts refused")

# --- menu on the account page: user vs admin ---------------------------------------------------------
auth = make(topbar_links=[("Docs", "/docs")])
auth.ensure_admin("boss", "boss-pw-12345")
auth.create_user("carol", password="carol-pw-12345")
app = FastAPI()
app.include_router(auth.router())


@app.get("/own", response_class=HTMLResponse)
def own(request: Request):
    """An app's own page with the bar (README "Look & feel")."""
    nonce = "n0nce"
    return (f"<!doctype html><html><head>{auth.topbar_head(nonce=nonce)}</head><body>"
            f"{auth.topbar(request, nonce=nonce, current='/docs')}<p>own</p></body></html>")


def client(name):
    c = TestClient(app)
    tok = re.search(r"name=_csrf value='([^']+)'", c.get("/auth/login", headers=HTML).text).group(1)
    r = c.post("/auth/login", data={"username": name, "password": f"{name}-pw-12345", "next": "/", "_csrf": tok},
               follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    return c


carol = client("carol")
page = carol.get("/auth/account", headers=HTML).text
bar = re.search(r"<header class=tsbar>.*?</header>", page, re.S).group(0)
assert "tsbar-btn" in bar and "aria-expanded=false" in bar, "no menu button on the account page"
assert "/auth/admin" not in bar, "admin entry for a non-admin"
csrf = carol.cookies.get(auth.csrf_cookie_name)
assert f"<form method=post action='/auth/logout'><input type=hidden name=_csrf value='{csrf}'>" in bar, \
    "sign-out is not a POST with the CSRF field"
assert "href='/auth/account' aria-current=page" in bar, "the account entry does not mark the page"
assert ">Docs</a>" in bar and "data-theme-mode=light" in bar and "data-theme-mode=system" in bar
assert "href='/auth/logout'" not in page, "the account page still carries its own sign-out link"
ok("account page (user): menu with account, theme, POST sign-out with CSRF; no admin entry")

boss = client("boss")
bar = re.search(r"<header class=tsbar>.*?</header>", boss.get("/auth/account", headers=HTML).text, re.S).group(0)
assert "href='/auth/admin'" in bar, "no admin entry for an admin"
panel = boss.get("/auth/admin", headers=HTML)
assert panel.status_code == 200, panel.status_code
pbar = re.search(r"<header class=tsbar>.*?</header>", panel.text, re.S).group(0)
assert "href='/auth/admin' aria-current=page" in pbar and "action='/auth/logout'" in pbar
assert f"name=_csrf value='{boss.cookies.get(auth.csrf_cookie_name)}'" in pbar, "panel sign-out without CSRF token"
assert panel.text.index("<header class=tsbar>") < panel.text.index("<div class=tsadmin>"), \
    "the bar must sit outside .tsadmin (its rules would bleed into it)"
ok("admin: entry in the menu, the panel carries the same bar (marked, CSRF), outside .tsadmin")

# Sign-out through the bar's form ends the session.
r = carol.post("/auth/logout", data={"_csrf": csrf}, follow_redirects=False)
assert r.status_code == 303 and carol.get("/auth/me").status_code == 401
ok("the bar's sign-out form signs out")

# --- pages without the menu ------------------------------------------------------------------------------
anon = TestClient(app)
login = anon.get("/auth/login", headers=HTML).text
assert "<header class=tsbar>" in login and "class=tsbar-btn" not in login and "class=tsbar-links" not in login
ok("sign-in page: logo and name only")

key = auth.create_api_key(auth.store.get_user_by_name("carol")["id"], "probe")["key"]
keyed = TestClient(app).get("/auth/account", headers={**HTML, "Authorization": f"Bearer {key}"})
assert "class=tsbar-btn" not in keyed.text, "an API key must not get the account menu (it signs out a cookie)"
ok("API key: no account menu")

# --- switch off ---------------------------------------------------------------------------------------------
auth.cfg.topbar_enabled = False
page = boss.get("/auth/account", headers=HTML).text
assert "tsbar" not in page.split("</head>", 1)[1], "topbar_enabled=False still renders the bar"
assert "href='/auth/logout'" in page and "href='/auth/admin'" in page, "without the bar the page needs its own links"
assert "tsbar" not in boss.get("/auth/admin", headers=HTML).text.split("</head>", 1)[1]
auth.cfg.topbar_enabled = True
ok("topbar_enabled=False: no bar; the account page carries admin and sign-out links again")

# --- logo and favicon ------------------------------------------------------------------------------------------
fav = base64.b64decode(STANDARD_FAVICON.split(",", 1)[1]).decode()
assert "rx='8'" in fav and "circle cx='16' cy='13'" in fav and "prefers-color-scheme:dark" in fav, fav
for icon, want in (("/logo.svg", "<img class=tsbar-logo src='/logo.svg'"), ("none", None),
                   ("", "<svg class=tsbar-logo"), ("https://cdn.example.com/x.png", "<svg class=tsbar-logo")):
    a = make(brand_icon=icon)
    logo_app = FastAPI()
    logo_app.include_router(a.router())
    h = TestClient(logo_app).get("/auth/login", headers=HTML).text
    brand = re.search(r"<a class=tsbar-brand.*?</a>", h, re.S).group(0)
    if want:
        assert want in brand, (icon, brand)
    else:
        assert "tsbar-logo" not in brand, (icon, brand)
ok("logo: brand_icon from the own origin, 'none' none, otherwise (and for a foreign address) the built-in mark")

# --- building blocks for an app's own pages ---------------------------------------------------------------------
own_page = boss.get("/own").text
head = own_page.split("</head>", 1)[0]
assert "localStorage.getItem('themeMode')" in head and "--ts-bg:" in head and ".tsbar{" in head
assert not re.search(r"<(script|style)(?![^>]*nonce=\"n0nce\")", own_page), "a tag without the nonce"
assert "aria-current=page>Docs</a>" in own_page and "href='/auth/admin'" in own_page
assert "__TS_P__" not in own_page
ok("auth.topbar_head()/topbar(): tokens + CSS + restore in <head>, every tag with the nonce, menu for the session")

mounted = make()
mounted.ensure_admin("boss", "boss-pw-12345")
from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Mount  # noqa: E402
inner = FastAPI()
inner.include_router(mounted.router())


@inner.get("/own", response_class=HTMLResponse)
def own_mounted(request: Request):
    return mounted.topbar(request)


mc = TestClient(Starlette(routes=[Mount("/sso", app=inner)]))
_tok = re.search(r"name=_csrf value='([^']+)'", mc.get("/sso/auth/login", headers=HTML).text).group(1)
mc.post("/sso/auth/login", data={"username": "boss", "password": "boss-pw-12345", "next": "/", "_csrf": _tok})
mbar = mc.get("/sso/own").text
assert "href='/sso/auth/account'" in mbar and "action='/sso/auth/logout'" in mbar and "href='/sso/'" in mbar, mbar
ok("auth.topbar() under a mount prefix: every TinySesam path carries it")

print("topbar OK")

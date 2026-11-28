"""T-104, surface "hybrid": the TinySesam area of an application and the application's icon (ADR-19).

The application draws its own navigation and links one entry to `/auth/area?app=<id>`; the area shows the tiles of the
own account — account, security, sessions, programs, approvals and, for the application's administrators, the panel —
framed with the application's name, icon and links, with a way back. Checked here:

  A. `apps[id].icon`: a path on TinySesam's origin or a `data:image/…` address; a foreign address, `//host`, a quote
     or another data type is a `ConfigError`.
  B. `?app=<id>` names the frame of the application's host on every page (the account page here), and the frame's bar
     carries the icon.
  C. The gate's sign-in page says "Sign in to <application>" with the application's icon.
  D. The area: signed out to the sign-in page and back, in the frame; the tiles from `account_overview`; the panel
     only for an administrator or an area administrator of THIS application; the approvals tile only with
     approvals; the way back to the frame's home; an unknown id changes nothing; without hosts (a library) the
     heading names the application and a `next` is the way back only when `safe_next` lets it through.
  E. Strict CSP: the nonce on every style and script, no `style=` attribute, no inline handler.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://auth.example.com"
APP_HOST = "docs.example.com"
PW = "a long probe password 4711"
ICON = "data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%3E%3C/svg%3E".replace("'", "%27")


def ok(name):
    print(f"  ✓ {name}")


def make(apps=None, **kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "area.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=[APP_HOST], forward_auth_enabled=True,
               available_roles=["docs-reader", "wiki-reader", "area-docs", "area-wiki"],
               admin_delegates={"area-docs": {"roles": ["docs-reader"], "apps": ["docs"]},
                                "area-wiki": {"roles": ["wiki-reader"], "apps": ["wiki"]}},
               forward_apps={APP_HOST: {"name": "Docs", "home": "/start", "links": [("Files", "/files")]}},
               apps=apps if apps is not None else {
                   "docs": {"name": {"en": "Documents", "de": "Dokumente"}, "hosts": [APP_HOST], "icon": ICON,
                            "permissions": [{"name": "docs.read", "label": {"en": "Read documents"}}]},
                   "wiki": {"name": "Wiki", "icon": "/icons/wiki.svg",
                            "permissions": [{"name": "wiki.edit", "label": {"en": "Edit the wiki"}}]}})
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def client(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def sign_in(auth, app, name):
    c = client(app)
    c.get("/auth/login")
    r = c.post("/auth/login", data={"username": name, "password": PW, "_csrf": c.cookies.get(auth.csrf_cookie_name)})
    assert r.status_code == 303, (r.status_code, r.text[:300])
    return c


def tiles(html):
    return re.findall(r"data-tile=(\w+)", html)


# ── A. the icon in the configuration ──────────────────────────────────────────────────────────────────────────────────
auth, app = make()
for bad in ("https://cdn.example.net/docs.svg", "//cdn.example.net/docs.svg", "/icons/a'b.svg", "/icons/a b.svg",
            "data:text/html,<b>x</b>", "data:image/svg+xml,<svg onload=x>", "docs.svg", 17, ""):
    try:
        make(apps={"docs": {"name": "Docs", "icon": bad}}, admin_delegates={})
    except ConfigError as e:
        assert "apps['docs'].icon" in str(e), e
    else:
        raise AssertionError(f"apps[docs].icon={bad!r} accepted")
for good in ("/icons/docs.svg", "data:image/png;base64,iVBORw0KGgo=", ICON):
    make(apps={"docs": {"name": "Docs", "icon": good}}, admin_delegates={})
ok("A apps[id].icon: a path on the own origin or data:image/… — a foreign address, //host, quote, space, another "
   "data type, a bare name refused")

# ── B. ?app=<id> names the frame, the frame's bar carries the icon ────────────────────────────────────────────────────
for name in ("ada", "kim", "lee", "max"):
    auth.create_user(name, password=PW, is_admin=(name == "ada"),
                     roles={"lee": ["area-docs"], "max": ["area-wiki"]}.get(name, []))
kim = sign_in(auth, app, "kim")
page = kim.get("/auth/account?app=docs").text
assert "<header class='tsbar tsframe'" in page or "class=\"tsbar tsframe\"" in page or "tsbar tsframe" in page, \
    "?app=<id> does not frame the account page"
assert f"<img class=tsbar-logo src='{ICON}'" in page, "the frame's bar does not carry the application's icon"
assert "https://docs.example.com/start" in page, "the frame's way home is missing"
plain = kim.get("/auth/account?app=nosuchapp").text
assert "tsbar tsframe" not in plain, "an unknown id frames the page"
assert "tsbar tsframe" in kim.get(f"/auth/account?app={APP_HOST}").text, "?app=<host> no longer frames the page"
ok("B ?app=<id> frames the account page like ?app=<host>, the bar shows the icon; an unknown id frames nothing")

# ── C. the gate's sign-in page: "Sign in to <application>" with the icon ─────────────────────────────────────────────
anon = client(app)
login = anon.get(f"/auth/login?next=https://{APP_HOST}/files").text
assert re.search(r"<img class=app-icon src='" + re.escape(ICON) + r"' alt='' width=48 height=48><h1>Sign in to Docs</h1>",
                 login), "the gate's sign-in page lacks the application's icon above the heading"
login_plain = anon.get("/auth/login").text
assert "class=app-icon" not in login_plain, "the plain sign-in page shows an application icon"
ok("C the gate's sign-in page: the application's icon above \"Sign in to Docs\"; none without an application")

# ── D. the area ──────────────────────────────────────────────────────────────────────────────────────────────────────
r = anon.get("/auth/area?app=docs")
assert r.status_code == 303 and r.headers["location"] == "/auth/login?next=%2Fauth%2Farea%3Fapp%3Ddocs", \
    (r.status_code, r.headers.get("location"))
framed_login = anon.get(r.headers["location"]).text
assert "tsbar tsframe" in framed_login and "Sign in to Docs" in framed_login, "the sign-in page before the area is unframed"
c = client(app)
c.get("/auth/login?next=%2Fauth%2Farea%3Fapp%3Ddocs")
r = c.post("/auth/login", data={"username": "kim", "password": PW, "next": "/auth/area?app=docs",
                                "_csrf": c.cookies.get(auth.csrf_cookie_name)})
assert r.status_code == 303 and r.headers["location"] == "/auth/area?app=docs", r.headers.get("location")
area = kim.get("/auth/area?app=docs")
assert area.status_code == 200, area.status_code
html = area.text
assert tiles(html) == ["account", "security", "sessions"], tiles(html)
assert f"<div class=area-app><img class=app-icon src='{ICON}' alt='' width=40 height=40><span>Documents</span></div>" \
       "<h1>Account and security</h1>" in html, "the heading does not name the application with its icon"
assert "href='https://auth.example.com/auth/account?app=docs.example.com#sessions'" in html, \
    "the sessions tile does not lead to the framed account page"
assert "<a class=btn2 href='https://docs.example.com/start'>Back to Documents</a>" in html, "no way back to the frame's home"
assert "tsbar tsframe" in html, "the area is not framed"
ok("D1 the area: signed out to the framed sign-in and back; tiles account, security, sessions from account_overview, "
   "framed links; heading with icon and name; the way back to the frame's home")

assert tiles(sign_in(auth, app, "ada").get("/auth/area?app=docs").text)[-1] == "admin", "no panel for the administrator"
assert tiles(sign_in(auth, app, "lee").get("/auth/area?app=docs").text)[-1] == "admin", \
    "no panel for the area administrator of docs"
assert "admin" not in tiles(sign_in(auth, app, "max").get("/auth/area?app=docs").text), \
    "the area administrator of another application sees the panel in docs' area"
assert "admin" not in tiles(html), "an ordinary account sees the panel"
ok("D2 the panel tile: administrator and area administrator of docs yes; of wiki and an ordinary account no")

unknown = kim.get("/auth/area?app=nosuchapp")
assert unknown.status_code == 200 and tiles(unknown.text) == ["account", "security", "sessions"], unknown.status_code
assert "tsbar tsframe" not in unknown.text and "class=area-back" not in unknown.text \
       and "class=area-app" not in unknown.text, \
    "an unknown id changes the page"
lib = kim.get("/auth/area?app=wiki&next=/wiki/home").text
assert "<span>Wiki</span>" in lib and "src='/icons/wiki.svg'" in lib, "an application without hosts is not named"
assert "<a class=btn2 href='/wiki/home'>Back to Wiki</a>" in lib, "a checked next is not the way back"
foreign = kim.get("/auth/area?app=wiki&next=https://evil.example.net/").text
assert "class=area-back" not in foreign and "evil.example.net" not in foreign, "a foreign next became the way back"
ok("D3 an unknown id: the same tiles, no frame, no way back; an application without hosts: name and icon, a checked "
   "next is the way back, a foreign one is dropped")

apv, apv_app = make(approvals_enabled=True)
apv.create_user("kim", password=PW)
assert "approvals" in tiles(sign_in(apv, apv_app, "kim").get("/auth/area?app=docs").text), "no approvals tile"
ok("D4 with approvals_enabled the approvals tile appears")

# ── E. strict CSP ────────────────────────────────────────────────────────────────────────────────────────────────────
csp = area.headers.get("content-security-policy", "")
nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
for tag in re.findall(r"<(?:style|script)\b[^>]*>", html, re.I):
    assert f'nonce="{nonce}"' in tag, f"a block without the nonce: {tag}"
assert not re.search(r"\sstyle=|\son[a-z]+=", html, re.I), "an inline style or handler on the area page"
ok("E strict CSP: the nonce on every block, no style= attribute, no inline handler")

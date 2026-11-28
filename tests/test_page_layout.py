"""T-104, part 2: the library slot `page_layout` and mail links that carry the app frame.

  A. `page_layout` — `fn(request, page) -> {"head", "header", "footer"}`: the application's head and foot around every
     built-in page; every `<script>`/`<style>` in them gets the page's nonce, the CSP header stays the strict one; with
     a header TinySesam's bar gives way; `brand_header`/`brand_footer` give way to the parts it returns; the function
     learns which page it frames; a function that fails or answers nothing leaves TinySesam's own layout; anything but
     a function is a `ConfigError`.
  B. Mail links carry the frame (`frame` in the token — `app` names the application of an account-API link): a sign-in link asked for in an application's frame opens its
     confirmation page in that frame, so does a reset link; without a frame, or with an unknown one, the token
     carries none and the page stands unframed.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://auth.example.com"
APP_HOST = "docs.example.com"
PW = "a long probe password 4711"


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "layout.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE)
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def client(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def nonce_of(r):
    return re.search(r"'nonce-([^']+)'", r.headers["content-security-policy"]).group(1)


# ── A. page_layout ───────────────────────────────────────────────────────────────────────────────────────────────────
seen = []


def layout(request, page):
    seen.append((request.url.path, page))
    return {"head": "<style>.app-nav{display:flex}</style>",
            "header": "<nav class=app-nav><a href='/'>Docs</a> <a href='/auth/area?app=docs'>Account</a></nav>"
                      "<script>window.appNav = true;</script>",
            "footer": "<footer class=app-foot>Docs footer</footer>"}


auth, app = make(page_layout=layout, brand_header="<div class=brandhead>brand</div>",
                 brand_footer="<div class=brandfoot>brand</div>")
r = client(app).get("/auth/login")
html, nonce = r.text, nonce_of(r)
assert "<nav class=app-nav>" in html and "<footer class=app-foot>Docs footer</footer>" in html, "the layout is missing"
assert f'<style nonce="{nonce}">.app-nav' in html, "the layout's style lacks the page's nonce"
assert f'<script nonce="{nonce}">window.appNav' in html, "the layout's script lacks the page's nonce"
assert "script-src 'nonce-" in r.headers["content-security-policy"] and "unsafe-inline" not in \
    r.headers["content-security-policy"], "the CSP is no longer the strict one"
assert "class=tsbar" not in html and "class='tsbar" not in html, "TinySesam's bar is drawn beside the application's"
assert "brandhead" not in html and "brandfoot" not in html, "brand_header/brand_footer did not give way"
assert html.index("<nav class=app-nav>") < html.index("<div class=tsmain>") < html.index("<footer class=app-foot>"), \
    "header and footer are not around the page"
assert seen[-1] == ("/auth/login", "login"), seen
ok("A1 page_layout: head, header and footer around the sign-in page, the nonce on its style and script, strict CSP, "
   "no bar of TinySesam's, brand_header/brand_footer give way; the function learns the page")

auth.create_user("kim", password=PW)
c = client(app)
c.get("/auth/login")
c.post("/auth/login", data={"username": "kim", "password": PW, "_csrf": c.cookies.get(auth.csrf_cookie_name)})
assert "<nav class=app-nav>" in c.get("/auth/account").text and seen[-1] == ("/auth/account", "account"), seen
assert "<nav class=app-nav>" in c.get("/auth/area").text and seen[-1] == ("/auth/area", "area"), seen
ok("A2 the account page and the area stand in the application's layout too")

foot_only, foot_app = make(page_layout=lambda request, page: {"footer": "<footer class=app-foot>f</footer>"})
html = client(foot_app).get("/auth/login").text
assert "app-foot" in html and "tsbar" in html, "a layout without a header removed TinySesam's bar"


def broken(request, page):
    raise RuntimeError("the application's layout broke")


for fn in (broken, lambda request, page: None, lambda request, page: {}, lambda request, page: "<nav>"):
    _, a = make(page_layout=fn, brand_header="<div class=brandhead>brand</div>")
    r = client(a).get("/auth/login")
    assert r.status_code == 200 and "brandhead" in r.text and "tsbar" in r.text, f"{fn}: {r.status_code}"
for bad in ("<nav>", {"header": "x"}, 17):
    try:
        make(page_layout=bad)
    except ConfigError as e:
        assert "page_layout" in str(e), e
    else:
        raise AssertionError(f"page_layout={bad!r} accepted")
ok("A3 a footer only keeps TinySesam's bar; a failing function or an empty answer leaves TinySesam's own layout; "
   "anything but a function is a ConfigError")

# ── B. mail links carry the frame ────────────────────────────────────────────────────────────────────────────────────
mails = []
mauth, mapp = make(magiclink_enabled=True, magiclink_self_request=True, password_reset_enabled=True,
                   forward_auth_enabled=True, trusted_redirect_hosts=[APP_HOST],
                   forward_apps={APP_HOST: {"name": "Docs", "home": "/", "links": [("Files", "/files")]}},
                   apps={"docs": {"name": "Documents", "hosts": [APP_HOST]}})
mauth.set_mailer(lambda to, subject, text, html=None: mails.append(text))
for n in range(6):          # one address per mail: the per-address mail throttle would stop a second one
    mauth.create_user(f"lee{n}", password=PW, email=f"lee{n}@example.com")
addresses = iter(f"lee{n}@example.com" for n in range(6))


def mailed_link():
    assert mails, "no mail went out"
    url = re.search(r"https://auth\.example\.com/\S+", mails.pop()).group(0)
    return urlsplit(url).path + (f"?{urlsplit(url).query}" if urlsplit(url).query else "")


def ask(path, query=""):
    c = client(mapp)
    c.get(path + query)
    r = c.post(path + query, data={"email": next(addresses), "_csrf": c.cookies.get(mauth.csrf_cookie_name)})
    assert r.status_code == 200, (path, r.status_code)
    return client(mapp).get(mailed_link())


framed = ask("/auth/magic/request", "?app=docs")
assert framed.status_code == 200 and "tsbar tsframe" in framed.text, "the sign-in link opens unframed"
plain = ask("/auth/magic/request")
assert plain.status_code == 200 and "tsframe" not in plain.text, "a sign-in link without a frame opens framed"
forged = ask("/auth/magic/request", "?app=nosuchapp")
assert "tsframe" not in forged.text, "an unknown frame travelled in the token"
reset = ask("/auth/forgot", f"?app={APP_HOST}")
assert reset.status_code == 200 and "tsbar tsframe" in reset.text, "the reset link opens unframed"
assert "tsframe" not in ask("/auth/forgot").text, "a reset link without a frame opens framed"
login_page = client(mapp).get("/auth/login?app=docs").text
assert "href='/auth/forgot?app=docs.example.com'" in login_page, "the framed sign-in page loses the frame to the reset"
assert "/auth/magic/request?next=%2F&amp;app=docs.example.com" in login_page, \
    "the framed sign-in page loses the frame to the sign-in link"
ok("B mail links carry the frame: the sign-in and the reset link open in the application's frame they were asked for "
   "in; without one or with an unknown one unframed; the framed sign-in page keeps the frame to both")

# ── C. the frame in the token of address change, e-mail confirmation and invitation (T-152) ────────────────────────
cauth, capp = make(allow_signup=True, signup_verify_email=True, admin_enabled=True,
                   forward_auth_enabled=True, trusted_redirect_hosts=[APP_HOST], stepup_max_age_sec=900,
                   forward_apps={APP_HOST: {"name": "Docs", "home": "/", "links": [("Files", "/files")]}},
                   apps={"docs": {"name": "Documents", "hosts": [APP_HOST]}})
cmails = []
cauth.set_mailer(lambda to, subject, text, html=None: cmails.append(text))


def link_of(text, path):
    url = re.search(rf"https://auth\.example\.com{path}\S+", text).group(0)
    return urlsplit(url).path + (f"?{urlsplit(url).query}" if urlsplit(url).query else "")


def signed_in(uid):
    c = client(capp)
    c.cookies.set(cauth.session_cookie_name, cauth.store.create_session(uid, 3600, True, "password",
                                                                        factors=["password"]))
    c.get("/auth/account")
    return c


def address_change(query):
    uid = cauth.create_user(f"amy{len(cmails)}", password=PW, email=f"amy{len(cmails)}@example.com")
    c = signed_in(uid)
    r = c.post("/auth/account/email" + query, json={"email": f"new{len(cmails)}@example.com"},
               headers={"X-CSRF-Token": c.cookies.get(cauth.csrf_cookie_name)})
    assert r.status_code == 200, r.text
    return client(capp).get(link_of(next(m for m in reversed(cmails) if "/auth/email/" in m), "/auth/email/"))


assert "tsbar tsframe" in address_change("?app=docs").text, "the address-change link opens unframed"
assert "tsframe" not in address_change("").text, "an address-change link without a frame opens framed"
assert "tsframe" not in address_change("?app=nosuchapp").text, "an unknown frame travelled in the token"


def registration(query):
    c = client(capp)
    c.get("/auth/register" + query)
    n = len(cmails)
    r = c.post("/auth/register" + query, data={"username": f"reg{n}", "email": f"reg{n}@example.com",
                                               "password": PW, "_csrf": c.cookies.get(cauth.csrf_cookie_name)})
    assert r.status_code == 200, r.status_code
    return client(capp).get(link_of(next(m for m in reversed(cmails) if "/auth/verify/" in m), "/auth/verify/"))


assert "tsbar tsframe" in registration(f"?app={APP_HOST}").text, "the confirmation link opens unframed"
assert "tsframe" not in registration("").text, "a confirmation link without a frame opens framed"
framed_form = client(capp).get("/auth/register?app=docs").text
assert "action='/auth/register?app=docs.example.com'" in framed_form, "the framed registration loses its frame"

url = cauth.create_invite("ivy@example.com", BASE, app="docs")["url"]
r = client(capp).get(urlsplit(url).path)
assert r.status_code == 303 and r.headers["location"].endswith("&app=docs.example.com"), r.headers.get("location")
assert "tsbar tsframe" in client(capp).get(r.headers["location"]).text, "the invitation's registration is unframed"
r = client(capp).get(urlsplit(cauth.create_invite("ida@example.com", BASE)["url"]).path)
assert "app=" not in r.headers["location"], "an invitation without a frame names one"
r = client(capp).get(urlsplit(cauth.create_invite("ira@example.com", BASE, app="nosuchapp")["url"]).path)
assert "app=" not in r.headers["location"], "an unknown frame travelled in the invitation"
ok("C the address-change, confirmation and invitation links open in the application's frame they were asked for in "
   "(T-152); without one or with an unknown one unframed; the framed registration keeps its frame")

"""E2: CSRF protection (double-submit). CSRF is ON here (default)."""
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
auth.ensure_admin("admin", "geheim123-lang-genug")
uid = auth.store.get_user_by_name("admin")["id"]
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


def csrf_token(client):
    """Fetch the CSRF cookie + hidden field value from the login page (double-submit)."""
    html = client.get("/auth/login").text
    field = re.search(r"name=_csrf value='([^']+)'", html).group(1)
    cookie = client.cookies.get("tinysesam_csrf")
    return field, cookie


c = TestClient(app)
JSON = {"Accept": "application/json"}

# ---------- login page sets the CSRF cookie + embeds the _csrf field (identical) ----------
field, cookie = csrf_token(c)
assert field and cookie and field == cookie
ok("login page: CSRF cookie == hidden _csrf field (double-submit)")

# ---------- POST WITHOUT token → 403 ----------
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/"}, follow_redirects=False)
assert r.status_code == 403, r.status_code
ok("login POST without CSRF token → 403")

# ---------- POST WITH token → ok ----------
field, cookie = csrf_token(c)
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/", "_csrf": field},
           follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("login POST with valid CSRF token → 303")

# ---------- R4-02: the one-time link redeems via POST — and that needs the CSRF token ----------
_m_db = os.path.join(tempfile.mkdtemp(), "t.db")
_m = TinySesam(TinySesamConfig(db_path=_m_db, passkey_enabled=False, cookie_secure=False,
                               magiclink_enabled=True, base_url="https://auth.example.com"))
_m_uid = _m.create_user("mia", password="geheim12345-lang-genug", email="mia@example.com")
_m_app = FastAPI(); _m_app.include_router(_m.router())
_mc = TestClient(_m_app)
_m_tok = _m.create_magic_token("login", user_id=_m_uid, email="mia@example.com", payload={"next": "/"})
assert _mc.post(f"/auth/magic/{_m_tok}", follow_redirects=False).status_code == 403, "without token"
_seite = _mc.get(f"/auth/magic/{_m_tok}").text
_feld = re.search(r"name=_csrf value='([^']+)'", _seite).group(1)
assert _mc.post(f"/auth/magic/{_m_tok}", data={"_csrf": _feld}, follow_redirects=False).status_code == 303
os.remove(_m_db)
ok("R4-02: confirmation page carries the CSRF field; POST without token 403, with token redeemed")

# ---------- JSON endpoint without header → 403, with header → ok ----------
assert c.post("/auth/password", json={"current": "geheim123-lang-genug", "new": "neuespasswort-lang"}).status_code == 403
tok = c.cookies.get("tinysesam_csrf")
r = c.post("/auth/password", json={"current": "geheim123-lang-genug", "new": "neuespasswort-lang"},
           headers={"X-CSRF-Token": tok})
assert r.status_code == 200, r.status_code
ok("JSON POST: without X-CSRF-Token → 403, with → 200")

# ---------- wrong token → 403 ----------
c.get("/auth/logout")                 # log out so the login page shows a form again
csrf_token(c)                          # fetch a fresh CSRF cookie
r = c.post("/auth/login", data={"username": "admin", "password": "neuespasswort-lang", "_csrf": "falsch"})
assert r.status_code == 403
ok("wrong CSRF token → 403")

# ---------- API key is exempt from CSRF (machine-to-machine, no cookie risk) ----------
key = auth.create_api_key(uid, name="k")["key"]
c2 = TestClient(app)
# JSON endpoint via key without CSRF token → allowed
r = c2.get("/auth/apikeys", headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 200
ok("API key request without CSRF token allowed (exempt)")

os.remove(db)
print("\nCSRF OK ✅")

# ---------- The token must not rotate on every render ----------
# Otherwise every other rendered page invalidates an open form ("form expired").
import re as _re

_db = os.path.join(tempfile.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, cookie_secure=False,
                               allow_signup=True, signup_require_email=False,
                               login_identifier="username"))
_a.create_user("max", password="geheim12345-lang-genug")
_app = FastAPI()
_app.include_router(_a.router())
_a.install_error_pages(_app)
_c = TestClient(_app, headers={"accept": "text/html"}, raise_server_exceptions=False)

_r1 = _c.get("/auth/login")
_tok = _re.search(r"name=_csrf value='([^']+)'", _r1.text).group(1)
assert "tinysesam_csrf" in _r1.headers.get("set-cookie", ""), "first render sets the cookie"

# every further rendered page (error pages too) must NOT overwrite it
for _p in ("/auth/login", "/auth/register", "/gibtsnicht"):
    assert "tinysesam_csrf" not in _c.get(_p).headers.get("set-cookie", ""), _p

_r = _c.post("/auth/login", data={"username": "max", "password": "geheim12345-lang-genug", "next": "/", "_csrf": _tok},
             follow_redirects=False)
assert _r.status_code == 303, f"token of the open page must stay valid, was {_r.status_code}"

# Protection stays sharp
assert _c.post("/auth/login", data={"username": "max", "password": "geheim12345-lang-genug", "_csrf": "falsch"}).status_code == 403
assert _c.post("/auth/login", data={"username": "max", "password": "geheim12345-lang-genug"}).status_code == 403
os.remove(_db)
print("  CSRF token stays valid across page changes; wrong/missing token still 403")

# ---------- H-2 / F-02: origin before the token comparison ----------
# Naive double-submit only checks that cookie and field match. Whoever can set cookies via a
# neighbouring subdomain sets the matching pair as well and sends the victim by form into THEIR
# account (login CSRF). Here the pair is therefore always VALID — only
# the origin decides.
import logging  # noqa: E402

_db = os.path.join(tempfile.mkdtemp(), "t.db")


def _instanz(**kw):
    a = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, cookie_secure=False,
                                  apikey_enabled=True, **kw))
    a.ensure_admin("admin", "geheim123-lang-genug")
    ap = FastAPI()
    ap.include_router(a.router())
    return a, ap


_a, _app = _instanz(trusted_redirect_hosts=["portal.example.com"])


def _login(kopf, app=None):
    cl = TestClient(app or _app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    return cl.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/",
                                        "_csrf": feld}, headers=kopf, follow_redirects=False).status_code


class _Fang(logging.Handler):
    zeilen: list = []

    def emit(self, record):
        _Fang.zeilen.append(record.getMessage())


_log = logging.getLogger("tinysesam.security")
_fang = _Fang()
_log.addHandler(_fang)
try:
    assert _login({"Origin": "https://angreifer.example"}) == 403, "foreign origin with a valid pair"
    assert _login({"Origin": "https://nachbar.example.com", "Sec-Fetch-Site": "same-site"}) == 403, \
        "neighbouring subdomain (cookie tossing) must fail"
    assert _login({"Sec-Fetch-Site": "cross-site"}) == 403, "cross-site without origin"
    assert any("csrf origin rejected" in z for z in _Fang.zeilen), "rejection must appear in the log"
    ok("H-2: foreign origin, neighbouring subdomain and cross-site → 403, although the token pair matches")

    assert _login({"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}) == 303
    assert _login({}) == 303, "without both headers the token decides (old browser, script)"
    assert _login({"Origin": "null"}) == 303, "Origin null alone says nothing — token decides"
    ok("H-2: own origin, missing headers and Origin null pass")

    # `trusted_redirect_hosts` are permitted TARGETS for `?next=` — in the forward-auth setup the
    # protected apps. They are not an own origin: a compromised app on one of
    # these hosts would otherwise send forms with a valid origin to TinySesam (login CSRF,
    # ending the victim's sessions). Until the follow-up they counted as own here.
    # (Mutation probe: put `trusted_redirect_hosts` back into `_eigene_hosts` → red.)
    assert _login({"Origin": "https://portal.example.com"}) == 403, \
        "a host from trusted_redirect_hosts counts as own origin"
    assert _login({"Origin": "https://portal.example.com", "Sec-Fetch-Site": "same-site"}) == 403
    ok("H-2: trusted_redirect_hosts are redirect targets, not an own origin → 403")

    # The same app serves its page with `Referrer-Policy: no-referrer`: then its
    # form POST carries `Origin: null`, and `Sec-Fetch-Site` still says `same-site`. Until the
    # follow-up only `cross-site` without origin weighed heavily — `null` with `same-site` got through,
    # and where the CSRF cookie cannot carry `__Host-`, the token alone decided again.
    # (Mutation probe: in `_herkunft_ok` reset the rejection for `same-site` without own origin to
    # `cross-site` only → red.)
    assert _login({"Origin": "null", "Sec-Fetch-Site": "same-site"}) == 403, \
        "Origin null from a neighbouring subdomain (no-referrer) passes the origin check"
    assert _login({"Sec-Fetch-Site": "same-site"}) == 403, "same-site without origin"
    assert _login({"Origin": "null", "Sec-Fetch-Site": "cross-site"}) == 403
    ok("H-2: same-site or cross-site without a usable origin (null, missing) → 403")

    # Proxy rewrites the host (upstream name), without X-Forwarded-Host — base_url saves it.
    _a2, _app2 = _instanz(base_url="https://auth.example.com")
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}, _app2) == 303
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000",
                   "X-Forwarded-Host": "auth.example.com"}, _app) == 303, "X-Forwarded-Host counts"
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}, _app) == 403
    ok("H-2: proxy with rewritten host — base_url or X-Forwarded-Host make the origin own")

    # A-3: The same proxy WITHOUT base_url (nginx default, plain password login) locked out after the
    # update every POST. A current browser says `Sec-Fetch-Site: same-origin` — measured
    # against the address IT sees — and that holds. A neighbouring subdomain gets `same-site`.
    _proxy = {"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}
    assert _login({**_proxy, "Sec-Fetch-Site": "same-origin"}, _app) == 303, \
        "proxy without base_url/X-Forwarded-Host locks out the own login"
    assert _login({"Origin": "https://nachbar.example.com", "Host": "127.0.0.1:8000",
                   "Sec-Fetch-Site": "same-site"}, _app) == 403, "neighbouring subdomain stays out"
    ok("A-3: proxy with rewritten host without base_url — Sec-Fetch-Site: same-origin carries the login")

    # The JSON route (json_body) checks the same way.
    cl = TestClient(_app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    cl.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "_csrf": feld})
    r = cl.post("/auth/password", json={"current": "geheim123-lang-genug", "new": "anderespasswort1"},
                headers={"X-CSRF-Token": feld, "Origin": "https://angreifer.example"})
    assert r.status_code == 403, r.status_code
    ok("H-2: the JSON route (X-CSRF-Token) also rejects a foreign origin")

    # A real API key stays exempt — a daemon has no browser.
    _key = _a.create_api_key(_a.store.get_user_by_name("admin")["id"], name="k")["key"]
    r = TestClient(_app).get("/auth/apikeys", headers={"Authorization": f"Bearer {_key}",
                                                       "Origin": "https://angreifer.example"})
    assert r.status_code == 200
    ok("H-2: API key requests stay exempt from the CSRF layer")

    _a3, _app3 = _instanz(csrf_origin_check=False)
    assert _login({"Origin": "https://angreifer.example"}, _app3) == 303
    ok("csrf_origin_check=False switches off only the pre-check (escape hatch for crooked proxies)")
finally:
    _log.removeHandler(_fang)

# ---------- H-1 in the forward-auth setup: the CSRF cookie carries `__Host-` even with cookie_domain ----------
# With `cookie_domain` (SSO across subdomains) the SESSION cookie cannot carry `__Host-`. TinySesam
# never sets the CSRF cookie with a domain, though — it is always host-only and may
# always carry the prefix. Without it every neighbouring subdomain (a compromised app) would set a
# `tinysesam_csrf=BEKANNT; Domain=.example.com`, and double-submit passed with its value.
# (Mutation probe: remove host_only=True in `csrf_cookie_name` → red.)
_fa_db = os.path.join(tempfile.mkdtemp(), "t.db")
_fa = TinySesam(TinySesamConfig(db_path=_fa_db, lang="de", passkey_enabled=False, oidc_enabled=False,
                                cookie_secure=True, base_url="https://auth.example.com",
                                cookie_domain=".example.com", forward_auth_enabled=True,
                                trusted_redirect_hosts=["app.example.com"]))
_fa.ensure_admin("admin", "geheim123-lang-genug")
_fa.create_user("mallory", password="angreifer-pw-15")
_fa_app = FastAPI()
_fa_app.include_router(_fa.router())
assert _fa.session_cookie_name == "tinysesam_session", "session with cookie_domain: without prefix"
assert _fa.csrf_cookie_name == "__Host-tinysesam_csrf", _fa.csrf_cookie_name
_fa_c = TestClient(_fa_app, base_url="https://auth.example.com")
_seite = _fa_c.get("/auth/login")
_zeile = [z for z in _seite.headers.get_list("set-cookie") if z.startswith("__Host-tinysesam_csrf=")]
assert len(_zeile) == 1 and "domain" not in _zeile[0].lower() and "secure" in _zeile[0].lower() \
    and "path=/" in _zeile[0].lower(), _seite.headers.get_list("set-cookie")
_feld = re.search(r"name=_csrf value='([^']+)'", _seite.text).group(1)
assert _fa_c.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/",
                                       "_csrf": _feld}, follow_redirects=False).status_code == 303
ok("H-1: with cookie_domain the CSRF cookie is named __Host-…, without Domain; login works")


def _geworfen(kopf):
    """Login CSRF with a planted domain cookie `tinysesam_csrf=BEKANNT`."""
    cl = TestClient(_fa_app, base_url="https://auth.example.com")
    cl.cookies.set("tinysesam_csrf", "BEKANNT", domain=".example.com", path="/")
    return cl.post("/auth/login", data={"username": "mallory", "password": "angreifer-pw-15",
                                        "next": "/", "_csrf": "BEKANNT"},
                   headers=kopf, follow_redirects=False).status_code


assert _geworfen({}) == 403, "a planted tinysesam_csrf passes double-submit"
assert _geworfen({"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"}) == 403, \
    "login CSRF from the protected app"
# And with the victim's session: the protected app does not end its other sessions.
_opfer = TestClient(_fa_app, base_url="https://auth.example.com")
_f = re.search(r"name=_csrf value='([^']+)'", _opfer.get("/auth/login").text).group(1)
_opfer.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/",
                                 "_csrf": _f}, follow_redirects=False)
_opfer.cookies.set("tinysesam_csrf", "BEKANNT", domain=".example.com", path="/")
_r = _opfer.post("/auth/sessions/revoke", content='{"scope":"others","_csrf":"BEKANNT"}',
                 headers={"Content-Type": "text/plain", "Origin": "https://app.example.com",
                          "Sec-Fetch-Site": "same-site"})
assert _r.status_code == 403, (_r.status_code, _r.text[:120])
ok("H-1/H-2: a CSRF cookie planted by an app carries neither login nor session action")
os.remove(_fa_db)

# Where the prefix cannot take effect (switched off here, likewise with cookie_path≠"/" or without
# Secure), `tinysesam_csrf` can be planted — then the origin check holds alone.
# The compromised app sends its form under `Referrer-Policy: no-referrer`, i.e. with
# `Origin: null` and `Sec-Fetch-Site: same-site`. Before: 303 and a session as mallory.
# (Mutation probe: as above, let `same-site` without own origin through again → red.)
_np_db = os.path.join(tempfile.mkdtemp(), "t.db")
_np = TinySesam(TinySesamConfig(db_path=_np_db, lang="de", passkey_enabled=False, oidc_enabled=False,
                                cookie_secure=True, base_url="https://auth.example.com",
                                cookie_domain=".example.com", forward_auth_enabled=True,
                                cookie_host_prefix=False, trusted_redirect_hosts=["app.example.com"]))
_np.ensure_admin("admin", "geheim123-lang-genug")
_np.create_user("mallory", password="angreifer-pw-15")
_np_app = FastAPI()
_np_app.include_router(_np.router())
assert _np.csrf_cookie_name == "tinysesam_csrf"


def _ohne_praefix(kopf):
    cl = TestClient(_np_app, base_url="https://auth.example.com")
    cl.cookies.set("tinysesam_csrf", "BEKANNT", domain=".example.com", path="/")
    r = cl.post("/auth/login", data={"username": "mallory", "password": "angreifer-pw-15",
                                     "next": "/", "_csrf": "BEKANNT"},
                headers=kopf, follow_redirects=False)
    return r.status_code, [z.split("=", 1)[0] for z in r.headers.get_list("set-cookie")]


assert _ohne_praefix({"Origin": "null", "Sec-Fetch-Site": "same-site"}) == (403, []), \
    "login CSRF via Origin null + same-site without __Host- CSRF cookie"
assert _ohne_praefix({"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"})[0] == 403
assert _ohne_praefix({"Origin": "https://auth.example.com", "Sec-Fetch-Site": "same-origin"})[0] == 303, \
    "the own login must keep working without prefix"
ok("H-2: without the __Host- prefix the origin check alone stops Origin null + same-site")
os.remove(_np_db)

# The built-in JS reads the ACTUAL cookie name — with __Host- (H-1) the cookie would otherwise be
# named differently from what the account page looks for, and every button there answered 403.
_a4 = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, pin_enabled=True))
assert _a4.csrf_cookie_name == "__Host-tinysesam_csrf"
_html = _a4.templates.render("account", _a4, {"user": {"username": "x", "display_name": "x"},
                                              "methods": ["password", "pin"]})
assert "__Host-tinysesam_csrf=" in _html and "; )tinysesam_csrf=" not in _html, "account page reads wrong name"
ok("account page reads the CSRF cookie under its actual name (__Host-…)")
os.remove(_db)


# ======================================================================================
# 0.20.1 — CSRF for embedding apps: `ensure_csrf()`, rotation on sign-in, sign-out
# ======================================================================================
# Two consumers had to rebuild TinySesam when upgrading to 0.20.0: `issue_csrf()` rolls
# new every time (every page invalidated the forms of the other tabs), `csrf_token()` sets no
# cookie. Both combined `csrf_cookie_name` + `issue_csrf()` on a carrier response and
# copied the Set-Cookie line across. Besides, `csrf_rotieren()` promised a fresh token
# „at login" — it was only called at the end of a TOTP step, and sign-out left the
# CSRF cookie in place.
import ast  # noqa: E402
import importlib.util  # noqa: E402
import json as _json  # noqa: E402
import pathlib  # noqa: E402
import time as _time  # noqa: E402
import types as _types  # noqa: E402
from urllib.parse import parse_qs as _parse_qs, urlparse as _urlparse  # noqa: E402

import pyotp  # noqa: E402
from fastapi import Form, Request, Response  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse  # noqa: E402

CK = "__Host-tinysesam_csrf"
BASIS = "https://testserver"
_FORM = re.compile(r"[A-Za-z0-9_-]{32,128}")


def _set_cookies(antwort) -> list:
    h = antwort.headers
    return list(h.get_list("set-cookie") if hasattr(h, "get_list") else h.getlist("set-cookie"))


def _zeilen(antwort, name=CK) -> list:
    """The raw Set-Cookie lines of this response for exactly this name."""
    return [z for z in _set_cookies(antwort) if z.startswith(name + "=")]


def _wert(zeile: str) -> str:
    return zeile.split(";", 1)[0].split("=", 1)[1].strip()


def _attribute(zeile: str) -> set:
    """All attributes except value, expiry and Max-Age — lowercase, as a set."""
    teile = [t.strip().lower() for t in zeile.split(";")[1:]]
    return {t for t in teile if t and not t.startswith(("expires=", "max-age="))}


def _geloescht(zeile: str) -> bool:
    return _wert(zeile) in ("", '""') and "max-age=0" in zeile.lower()


def _feld(html: str) -> str:
    return re.search(r"name=_csrf value='([^']+)'", html).group(1)


def _instanz(**kw):
    """Instance with `__Host-` cookies (Secure, host-only) and the routes of an embedding app."""
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), lang="de", passkey_enabled=False,
               oidc_enabled=False, base_url=BASIS)
    cfg.update(kw)
    a = TinySesam(TinySesamConfig(**cfg))
    ap = FastAPI()
    ap.include_router(a.router())

    # Way 1 of the docs: FastAPI response parameters, the page as return value.
    @ap.get("/app/formular", response_class=HTMLResponse)
    def formular(request: Request, response: Response):
        csrf = a.ensure_csrf(request, response)
        return (f"<meta name=tinysesam-csrf-cookie content='{a.csrf_cookie_name}'>"
                f"<form method=post action=/app/speichern><input name=_csrf value='{csrf}'></form>")

    # Way 2 of the docs: a finished response (Jinja `TemplateResponse` & co.) — first the token,
    # then the page, then the cookie onto the finished response.
    @ap.get("/app/fertig")
    def fertig(request: Request):
        csrf = a.csrf_token(request)
        antwort = HTMLResponse(f"<input name=_csrf value='{csrf}'>")
        antwort.headers["x-ensure"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/speichern")
    def speichern(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        a.require_csrf(request, csrf_tok)
        return {"ok": True}

    # An app's own sign-in route: `start_session` + `set_cookie`, then the form of the
    # same response.
    @ap.post("/app/anmelden")
    def anmelden(request: Request):
        token, _ok = a.start_session(a.store.get_user_by_name("erika")["id"], "password")
        antwort = JSONResponse({})
        a.set_cookie(antwort, token)
        antwort.headers["x-csrf"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/abmelden")
    def abmelden(request: Request):
        antwort = JSONResponse({})
        a.logout(request, antwort)
        antwort.headers["x-csrf"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/nur-abmelden")
    def nur_abmelden(request: Request):
        antwort = JSONResponse({})
        a.logout(request, antwort)
        return antwort

    # Way 2 and sign-in/sign-out in the SAME response — the limit the docs name since the
    # follow-up: the finished page is rendered before `set_cookie`/`logout` turns.
    @ap.post("/app/anmelden-fertig")
    def anmelden_fertig(request: Request):
        token, _ok = a.start_session(a.store.get_user_by_name("erika")["id"], "password")
        csrf = a.csrf_token(request)
        antwort = HTMLResponse(f"<input name=_csrf value='{csrf}'>")
        a.set_cookie(antwort, token)
        antwort.headers["x-ensure"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/abmelden-fertig")
    def abmelden_fertig(request: Request):
        csrf = a.csrf_token(request)
        antwort = HTMLResponse(f"<input name=_csrf value='{csrf}'>")
        a.logout(request, antwort)
        antwort.headers["x-ensure"] = a.ensure_csrf(request, antwort)
        return antwort

    # The way the docs name for this: sign in/out, redirect, the follow-up request renders.
    @ap.post("/app/anmelden-umleiten")
    def anmelden_umleiten(request: Request):
        token, _ok = a.start_session(a.store.get_user_by_name("erika")["id"], "password")
        antwort = RedirectResponse("/app/fertig", 303)
        a.set_cookie(antwort, token)
        return antwort

    @ap.post("/app/abmelden-umleiten")
    def abmelden_umleiten(request: Request):
        antwort = RedirectResponse("/app/fertig", 303)
        a.logout(request, antwort)
        return antwort

    a.create_user("erika", password="geheim12345-lang-genug", email="erika@example.com")
    return a, ap


def _client(ap):
    return TestClient(ap, base_url=BASIS)


# The attributes `issue_csrf()` sets — the yardstick for every other setter.
_a0, _ = _instanz()
_r0 = Response()
_a0.issue_csrf(_r0)
_ATTR = _attribute(_zeilen(_r0)[0])
assert _ATTR == {"path=/", "samesite=lax", "secure"}, _ATTR

# ---------- E1. ensure_csrf(): keep an existing token, otherwise set one ----------
# (Mutation probe: in `ensure_csrf` always roll anew like `issue_csrf` → red.)
_a, _ap = _instanz()
_c = _client(_ap)
_r = _c.get("/app/formular")
assert _r.status_code == 200 and len(_zeilen(_r)) == 1, _set_cookies(_r)
_t1 = _wert(_zeilen(_r)[0])
assert _feld(_r.text) == _t1 and _FORM.fullmatch(_t1), (_feld(_r.text), _t1)
assert _attribute(_zeilen(_r)[0]) == _ATTR, "ensure_csrf sets different attributes than issue_csrf"
assert f"content='{_a.csrf_cookie_name}'" in _r.text
ok("ensure_csrf: first visit sets the cookie (attributes like issue_csrf), return value = form value")

_r = _c.get("/app/formular")
assert not _zeilen(_r) and _feld(_r.text) == _t1, (_set_cookies(_r), _feld(_r.text))
_r = _c.get("/app/fertig")
assert not _zeilen(_r) and _feld(_r.text) == _t1 == _r.headers["x-ensure"]
_r = _c.get("/auth/login")
assert not _zeilen(_r) and _feld(_r.text) == _t1, "render_page and ensure_csrf share the token"
assert _c.post("/app/speichern", data={"_csrf": _t1}).status_code == 200
assert _c.post("/app/speichern", data={"_csrf": "falsch"}).status_code == 403
ok("ensure_csrf: existing token stays (no Set-Cookie) — the forms of other tabs stay valid")

# Way 2: `csrf_token()` before rendering, `ensure_csrf()` on the finished response — the same token.
# (Mutation probe: in `_csrf_der_anfrage` do not remember the new token per request → red.)
_c2 = _client(_ap)
_r = _c2.get("/app/fertig")
assert len(_zeilen(_r)) == 1 and _wert(_zeilen(_r)[0]) == _feld(_r.text) == _r.headers["x-ensure"], \
    (_set_cookies(_r), _feld(_r.text), _r.headers.get("x-ensure"))
ok("csrf_token() + ensure_csrf(finished response): the same token in form and cookie")

# Accept nothing arbitrary: a cookie that does not look like a token is replaced —
# by ensure_csrf, csrf_token and render_page alike.
# (Mutation probe: remove the format check in `_csrf_der_anfrage` → red.)
for _schlecht in ("kurz", "A" * 31, "A" * 129, "A" * 30 + "<>", "A" * 30 + "'x"):
    for _pfad in ("/app/formular", "/app/fertig", "/auth/login"):
        _cs = _client(_ap)
        _cs.cookies.set(CK, _schlecht)
        _r = _cs.get(_pfad)
        assert len(_zeilen(_r)) == 1, (_schlecht, _pfad, _set_cookies(_r))
        _neu = _wert(_zeilen(_r)[0])
        assert _neu != _schlecht and _FORM.fullmatch(_neu) and _feld(_r.text) == _neu, \
            (_schlecht, _pfad, _neu, _feld(_r.text))
_gut = "B" * 43                          # e.g. secrets.token_urlsafe(32) — valid, stays
_cs = _client(_ap)
_cs.cookies.set(CK, _gut)
_r = _cs.get("/app/formular")
assert not _zeilen(_r) and _feld(_r.text) == _gut
ok("ensure_csrf/csrf_token/render_page: invalid cookie (short, too long, foreign characters) is replaced")

_ax, _apx = _instanz(csrf_enabled=False)
_r = _client(_apx).get("/app/formular")
assert not _set_cookies(_r) and "value=''" in _r.text
ok("csrf_enabled=False: ensure_csrf sets nothing and returns ''")

# Signing in in the SAME response: ensure_csrf afterwards returns the rotated token, not the old one.
# (Mutation probe: in `ensure_csrf` do not consult the response → red.)
_c3 = _client(_ap)
_alt = _feld(_c3.get("/app/formular").text)
_r = _c3.post("/app/anmelden")
assert len(_zeilen(_r)) == 1, _set_cookies(_r)
_neu = _wert(_zeilen(_r)[0])
assert _neu != _alt and _r.headers["x-csrf"] == _neu, (_alt, _neu, _r.headers.get("x-csrf"))
_r = _c3.get("/app/formular")
assert not _zeilen(_r) and _feld(_r.text) == _neu
ok("own sign-in route (start_session + set_cookie): token rotated, ensure_csrf afterwards returns the new one")

# Signing out in the same response: ensure_csrf afterwards sets a NEW one (replacing the delete line).
# (Mutation probe: in `_csrf_cookie_setzen` do not remove the existing line → red.)
_r = _c3.post("/app/abmelden")
assert len(_zeilen(_r)) == 1 and not _geloescht(_zeilen(_r)[0]), _set_cookies(_r)
assert _wert(_zeilen(_r)[0]) == _r.headers["x-csrf"] not in (_neu, _alt)
ok("logout() + ensure_csrf() in one response: exactly one line, a new token instead of the deletion")

# Way 2 (finished response) and sign-in/sign-out in the SAME response does not work — the limit the
# README and `ensure_csrf` have named since the 0.20.1 follow-up (finding from the attack on the
# CSRF changes: the promise "both return the same token" did not hold there, silently). The page is
# rendered before `set_cookie` rotates the token or `logout` deletes it; its form carries the
# old one and fails with 403. That is fail-closed and stays so: rotation on sign-in is the
# security promise, it must not depend on whether a token was issued beforehand. No
# code fix, hence no mutation probe — the block records what the docs say. If it turns red because
# the form suddenly is valid, either the rotation is gone or the docs are outdated.
for _weg in ("anmelden", "abmelden"):
    _cw = _client(_ap)
    if _weg == "abmelden":
        assert _cw.post("/app/anmelden").status_code == 200
    _vorher = _feld(_cw.get("/app/formular").text)
    _r = _cw.post(f"/app/{_weg}-fertig")
    _nachher = _cw.cookies.get(CK)
    assert _feld(_r.text) == _vorher != _nachher == _r.headers["x-ensure"], \
        (_weg, _vorher, _feld(_r.text), _nachher, _r.headers.get("x-ensure"))
    assert _cw.post("/app/speichern", data={"_csrf": _feld(_r.text)}).status_code == 403, _weg
    # The documented way: redirect; the follow-up request renders with the new cookie.
    _cw = _client(_ap)
    if _weg == "abmelden":
        assert _cw.post("/app/anmelden").status_code == 200
    _vorher = _feld(_cw.get("/app/formular").text)
    _r = _cw.post(f"/app/{_weg}-umleiten", follow_redirects=False)
    assert _r.status_code == 303, (_weg, _r.status_code)
    _r = _cw.get("/app/fertig")
    assert _feld(_r.text) == _cw.cookies.get(CK) != _vorher, (_weg, _feld(_r.text), _vorher)
    assert _cw.post("/app/speichern", data={"_csrf": _feld(_r.text)}).status_code == 200, _weg
ok("way 2 + sign-in/sign-out in one response: form carries the old token (403, documented); "
   "redirecting works")


# ---------- E2. Every sign-in route rotates the CSRF token (OWASP: "changes with each login") ----------
# Centrally at `set_cookie()`: every fully signed-in session is created in `_sitzung_anlegen()` and
# is flagged there; setting its cookie rotates the CSRF token in the same response. A
# step-up does not rotate it — that would only invalidate the forms of the other open tabs.
# (Mutation probe: remove the call of `csrf_rotieren` in `set_cookie` → red;
# remove the flagging in `_sitzung_anlegen` → red; call `store.create_session` directly again
# in `complete_totp` → red; rotate every full session in `set_cookie` instead of only
# the flagged ones → red at step-up.)
def _dreht(name, cl, schritt, ap_=None):
    """`schritt(cl)` signs in. Checks: exactly one new CSRF line, the old token is dead, the
    new one is valid, and the next page — built-in as well as own — renders with the new one."""
    alt = cl.cookies.get(CK)
    assert alt, f"{name}: precondition — a CSRF cookie exists before sign-in"
    r = schritt(cl)
    assert r.status_code in (200, 303), (name, r.status_code, r.text[:200])
    zeilen = _zeilen(r)
    assert len(zeilen) == 1, f"{name}: the CSRF token was not rotated: {_set_cookies(r)}"
    neu = _wert(zeilen[0])
    assert neu != alt and _FORM.fullmatch(neu), (name, alt, neu)
    assert _attribute(zeilen[0]) == _ATTR, (name, zeilen[0])
    assert cl.cookies.get(CK) == neu
    assert cl.post("/app/speichern", data={"_csrf": alt}).status_code == 403, f"{name}: old token is valid"
    assert cl.post("/app/speichern", data={"_csrf": neu}).status_code == 200, f"{name}: new one is not valid"
    seite = cl.get("/app/formular")
    assert not _zeilen(seite) and _feld(seite.text) == neu, (name, _feld(seite.text))
    # A built-in page after sign-in (the sign-out prompt) carries the new token.
    seite = cl.get("/auth/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert seite.status_code == 200 and _feld(seite.text) == neu, (name, seite.status_code)
    ok(f"sign-in route {name}: CSRF token rotated, follow-up pages render with the new one")
    return neu


def _bleibt(name, cl, schritt, warum="ein Step-up entwertet keine anderen Reiter"):
    alt = cl.cookies.get(CK)
    r = schritt(cl)
    assert r.status_code in (200, 303), (name, r.status_code, r.text[:200])
    assert not _zeilen(r) and cl.cookies.get(CK) == alt, f"{name}: rotates the CSRF token: {_set_cookies(r)}"
    ok(f"{name}: CSRF token stays ({warum})")


def _passwort(cl, user="erika", pw="geheim12345-lang-genug"):
    seite = cl.get("/auth/login", follow_redirects=False)     # signed in: 303 instead of form
    f = _feld(seite.text) if seite.status_code == 200 else cl.cookies.get(CK)
    return cl.post("/auth/login", data={"username": user, "password": pw, "next": "/", "_csrf": f},
                   follow_redirects=False)


# Password
_a, _ap = _instanz()
_c = _client(_ap)
_c.get("/auth/login")
_dreht("Passwort", _c, _passwort)
# Step-up by password (reauth) on the full session does not rotate.
_bleibt("Step-up /auth/reauth", _c, lambda cl: cl.post(
    "/auth/reauth", data={"password": "geheim12345-lang-genug", "next": "/", "_csrf": cl.cookies.get(CK)},
    follow_redirects=False))
# Signing in again as the same person with a full session is a step-up, as another person a login.
_a.create_user("otto", password="geheim67890-lang-genug")
_dreht("Identitätswechsel (andere Person meldet sich an)", _c,
       lambda cl: _passwort(cl, "otto", "geheim67890-lang-genug"))

# Registration with immediate sign-in
_a, _ap = _instanz(allow_signup=True, signup_require_email=False, login_identifier="username")
_c = _client(_ap)
_c.get("/auth/register")
_dreht("Registrierung", _c, lambda cl: cl.post(
    "/auth/register", data={"username": "neu1", "password": "langes-passwort-1", "next": "/",
                            "_csrf": _feld(cl.get("/auth/register").text)}, follow_redirects=False))

# PIN as first factor
_a, _ap = _instanz(pin_enabled=True, pin_login=True)
_a.set_pin(_a.store.get_user_by_name("erika")["id"], "480915")
_c = _client(_ap)
_c.get("/auth/login")
_dreht("PIN", _c, lambda cl: cl.post(
    "/auth/pin", data={"username": "erika", "pin": "480915", "next": "/",
                       "_csrf": _feld(cl.get("/auth/pin").text)}, follow_redirects=False))

# Sign-in link
_a, _ap = _instanz(magiclink_enabled=True)
_tok = _a.create_magic_token("login", user_id=_a.store.get_user_by_name("erika")["id"],
                             email="erika@example.com", payload={"next": "/"})
_c = _client(_ap)
_c.get("/auth/login")
_dreht("Anmelde-Link", _c, lambda cl: cl.post(
    f"/auth/magic/{_tok}", data={"_csrf": _feld(cl.get(f"/auth/magic/{_tok}").text)},
    follow_redirects=False))

# Chain password → TOTP: rotation happens where the session becomes full — not yet at the first
# factor (the half session is no sign-in).
_a, _ap = _instanz(login_chain=["password", "totp"])
_uid = _a.store.get_user_by_name("erika")["id"]
_geheim = _a.totp_begin(_uid)["secret"]
assert _a.totp_confirm(_uid, pyotp.TOTP(_geheim).at(int(_time.time()) - 30))
_c = _client(_ap)
_c.get("/auth/login")
_bleibt("Kette: erster Faktor", _c, _passwort, "die halbe Sitzung ist noch keine Anmeldung")
_dreht("Kette Passwort → TOTP", _c, lambda cl: cl.post(
    "/auth/totp", data={"code": pyotp.TOTP(_geheim).now(), "next": "/",
                        "_csrf": _feld(cl.get("/auth/totp").text)}, follow_redirects=False))
_bleibt("Step-up per TOTP", _c, lambda cl: cl.post(
    "/auth/totp", data={"code": pyotp.TOTP(_geheim).at(int(_time.time()) + 30), "next": "/",
                        "_csrf": cl.cookies.get(CK)}, follow_redirects=False))

# Chain with mandatory setup: the confirmation code completes the sign-in (JSON response).
_a, _ap = _instanz(login_chain=["password", "totp"])
_uid = _a.store.get_user_by_name("erika")["id"]
_c = _client(_ap)
_c.get("/auth/login")
assert _passwort(_c).status_code == 303
_start = _c.post("/auth/totp/setup/start", data={"next": "/", "_csrf": _c.cookies.get(CK)})
assert _start.status_code == 200, _start.status_code
_geheim = _a.store.get_totp(_uid)["secret"]
_dreht("Kette mit TOTP-Einrichtung", _c, lambda cl: cl.post(
    "/auth/totp/setup", data={"code": pyotp.TOTP(_geheim).now(), "next": "/"},
    headers={"X-CSRF-Token": cl.cookies.get(CK)}))

# OIDC return path (no network: discovery prefilled, token exchange as a dummy)
if importlib.util.find_spec("authlib") is None:
    print("  - OIDC skipped: extra [oidc] (authlib) missing — guard E3 covers the route structurally")
else:
    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    _idp = "https://idp.example.com"
    _a, _ap = _instanz(oidc_enabled=True, oidc_issuer=_idp, oidc_client_id="probe",
                       oidc_client_secret="geheim")
    _a.oidc._meta = {"issuer": _idp, "authorization_endpoint": _idp + "/authorize",
                     "token_endpoint": _idp + "/token", "userinfo_endpoint": _idp + "/userinfo",
                     "jwks_uri": _idp + "/jwks"}
    _a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"sub": "oidc-1", "preferred_username": "olga", "name": "Olga",
                 "email": "olga@example.com", "email_verified": True, "nonce": nonce}),
        {"access_token": "at"})
    _a.oidc.userinfo = lambda at, erwartetes_sub="": {}
    _c = _client(_ap)
    _c.get("/auth/login")

    def _oidc(cl):
        start = cl.get("/auth/oidc/start", follow_redirects=False)
        state = _parse_qs(_urlparse(start.headers["location"]).query)["state"][0]
        return cl.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)
    _dreht("OIDC", _c, _oidc)

# SAML ACS (assertion as a dummy — the signature check is tested by test_saml.py)
if importlib.util.find_spec("onelogin") is None:
    print("  - SAML skipped: extra [saml] missing — guard E3 covers the route structurally")
else:
    class _FakeSAML:
        def login_url(self, req, base, return_to="/"):
            return "https://idp.example.com/sso?SAMLRequest=abc", "_id-1"

        def process(self, req, base, request_id=""):
            return {"nameid": "sara", "attrs": {"email": ["sara@example.com"]}}

        def metadata(self, base):
            return "<md:EntityDescriptor/>"

    _db_s = os.path.join(tempfile.mkdtemp(), "t.db")
    _a = TinySesam(TinySesamConfig(db_path=_db_s, lang="de", passkey_enabled=False, oidc_enabled=False,
                                   base_url=BASIS, saml_enabled=True,
                                   saml_idp_sso_url="https://idp.example.com/sso",
                                   saml_idp_x509cert="MIID...dummy", saml_attr_email="email"))
    _a.saml = _FakeSAML()
    _ap = FastAPI()
    _ap.include_router(_a.router())

    @_ap.post("/app/speichern")
    def _s_speichern(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        _a.require_csrf(request, csrf_tok)
        return {"ok": True}

    @_ap.get("/app/formular", response_class=HTMLResponse)
    def _s_formular(request: Request, response: Response):
        return f"<input name=_csrf value='{_a.ensure_csrf(request, response)}'>"

    _c = _client(_ap)
    _c.get("/auth/login")
    _dreht("SAML", _c, lambda cl: cl.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                                          follow_redirects=False))

# Passkey (signature check replaced — what is tested is the wiring, not WebAuthn)
if importlib.util.find_spec("webauthn") is None:
    print("  - Passkey skipped: extra [passkey] missing — guard E3 covers the route structurally")
else:
    import webauthn as _webauthn
    _echt = _webauthn.verify_authentication_response
    _webauthn.verify_authentication_response = lambda **kw: _types.SimpleNamespace(new_sign_count=1)
    try:
        _a, _ap = _instanz(passkey_enabled=True, rp_id="testserver", origin=BASIS)
    finally:
        _webauthn.verify_authentication_response = _echt
    _a.store.add_webauthn(_a.store.get_user_by_name("erika")["id"], "Y3JlZC10ZXN0", "pk", 0,
                          ["internal"], "Test")
    _c = _client(_ap)
    _c.get("/auth/login")

    def _passkey(cl):
        kopf = {"X-CSRF-Token": cl.cookies.get(CK), "Content-Type": "application/json"}
        assert cl.post("/auth/passkey/login/begin", headers=kopf).status_code == 200
        return cl.post("/auth/passkey/login/finish", content=_json.dumps({"id": "Y3JlZC10ZXN0"}),
                       headers=kopf)
    _dreht("Passkey", _c, _passkey)

# Own sign-in route of the app (start_session + set_cookie, without a built-in route)
_a, _ap = _instanz()
_c = _client(_ap)
_c.get("/app/formular")
_dreht("eigene Route (start_session + set_cookie)", _c, lambda cl: cl.post("/app/anmelden"))


# ---------- E2b. Signing out deletes the CSRF cookie ----------
# (Mutation probe: remove the deletion of the CSRF cookie in `logout()` → red; omit the
# `secure=` in `_csrf_cookie_loeschen` → red.)
def _abmelden_loescht(name, schritt):
    a, ap = _instanz()
    cl = _client(ap)
    assert _passwort(cl).status_code == 303
    alt = cl.cookies.get(CK)
    r = schritt(cl)
    zeilen = _zeilen(r)
    assert len(zeilen) == 1 and _geloescht(zeilen[0]), f"{name}: {_set_cookies(r)}"
    assert _attribute(zeilen[0]) == _ATTR, (name, zeilen[0])     # Secure + Path=/: otherwise the browser
    assert cl.cookies.get(CK) is None                            # discards the __Host- deletion
    neu = _feld(cl.get("/auth/login").text)
    assert neu != alt and cl.cookies.get(CK) == neu, (name, alt, neu)
    ok(f"{name}: CSRF cookie deleted, the page afterwards gets a new token")


_abmelden_loescht("POST /auth/logout", lambda cl: cl.post(
    "/auth/logout", data={"_csrf": cl.cookies.get(CK)}, follow_redirects=False))
_abmelden_loescht("GET /auth/logout (eigene Seite)",
                  lambda cl: cl.get("/auth/logout", follow_redirects=False))
_abmelden_loescht("auth.logout() in einer eigenen Route", lambda cl: cl.post("/app/nur-abmelden"))


# ---------- E3. Guard: no sign-in route can bypass the rotation ----------
# The rotation hangs on two chokepoints: every session row is created in `_sitzung_anlegen()`
# (the full one is flagged there), and every session cookie is set by `set_cookie()` (rotation
# happens there). A new sign-in route that bypasses one of them is caught here — even one for which
# E2 has no run.
# (Mutation probe: in `apply_factor` call `self.store.create_session(…)` directly again → red.)
class _Aufrufe(ast.NodeVisitor):
    def __init__(self):
        self.stapel, self.funde = [], []

    def visit_FunctionDef(self, node):
        self.stapel.append(node.name)
        self.generic_visit(node)
        self.stapel.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Attribute):
            erstes = node.args[0] if node.args else None
            if f.attr == "create_session" and isinstance(f.value, ast.Attribute) and f.value.attr == "store":
                self.funde.append(("create_session", tuple(self.stapel), node.lineno))
            if (f.attr == "set_cookie" and isinstance(erstes, ast.Attribute)
                    and erstes.attr == "session_cookie_name"):
                self.funde.append(("sitzungs_cookie", tuple(self.stapel), node.lineno))
        self.generic_visit(node)


_paket = pathlib.Path(__file__).resolve().parent.parent / "tinysesam"
_funde = []
for _datei in sorted(_paket.glob("*.py")):
    _v = _Aufrufe()
    _v.visit(ast.parse(_datei.read_text(encoding="utf-8")))
    _funde += [(_datei.name,) + f for f in _v.funde]
_anlage = [f for f in _funde if f[1] == "create_session"]
_cookie = [f for f in _funde if f[1] == "sitzungs_cookie"]
assert _anlage and all(f[0] == "manager.py" and f[2][-1:] == ("_sitzung_anlegen",) for f in _anlage), \
    f"a session is created bypassing `_sitzung_anlegen` (not flagged): {_anlage}"
assert _cookie and all(f[0] == "manager.py" and f[2][-1:] == ("set_cookie",) for f in _cookie), \
    f"a session cookie is set bypassing `set_cookie` (rotates no CSRF token): {_cookie}"
ok(f"guard: {len(_anlage)} session creation(s) only in _sitzung_anlegen, session cookie only in set_cookie")
print("\nCSRF 0.20.1 (ensure_csrf, rotation, sign-out) OK ✅")

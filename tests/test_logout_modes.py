"""Signing out at the application (T-22): /.tinysesam/logout with "app", "all" and "ask".

"app" leaves the session standing, but locks THIS host until the person chooses
"Weiter als …" on the login page. "all" ends the session and — for an OIDC sign-in with
oidc_rp_logout — the one at the provider, with the ID token as `id_token_hint`.
"""
import os
import re
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig
from tinysesam import config_check
from tinysesam.oidc import DEFAULT_CLIENT


def ok(name):
    print(f"  ✓ {name}")


META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
        "token_endpoint": "https://id.example.com/token",
        "authorization_endpoint": "https://id.example.com/auth",
        "end_session_endpoint": "https://id.example.com/api/oidc/end-session"}
APP = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com"}
WIKI = {**APP, "X-Forwarded-Host": "wiki.example.com"}


def instance(**extra):
    values = dict(issuer="https://id.example.com", client_id="main", client_secret="s",
                 base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "g.db"),
                 trusted_redirect_hosts=["app.example.com", "wiki.example.com"],
                 allowed_groups=["people"], oidc_scopes="openid profile email groups",
                 https_mode="off", lang="de")
    values.update(extra)
    cfg = TinySesamConfig.oidc_gateway(**values)
    cfg.cookie_secure = False
    cfg.csrf_enabled = False
    auth = TinySesam(cfg)
    for key_name in [DEFAULT_CLIENT] + auth.oidc_clients.names():
        auth.oidc_clients[key_name]._meta, auth.oidc_clients[key_name]._meta_when = dict(META), time.time()
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def signed_in(auth, app, name="anna", id_token=None):
    """An OIDC session as after the callback: method oidc, unlock, ID token."""
    uid = auth.create_user(name)
    token = auth.store.create_session(uid, 3600, True, "oidc")
    auth._record_oidc_approval(token, DEFAULT_CLIENT)
    if id_token:
        auth.store.set_oidc_id_token(auth.store.session_hash(token), DEFAULT_CLIENT, id_token)
    c = TestClient(app)
    c.cookies.set(auth.session_cookie_name, token)
    return c, token, uid


def forward(c, head, uri="/page"):
    return c.get("/auth/forward", headers={**head, "X-Forwarded-Uri": uri,
                                           "Sec-Fetch-Mode": "navigate", "Accept": "text/html"})


def gate_deleted(r, auth):
    return any(v.startswith(f"{auth.cfg.gate_cookie_name}=;") and "Max-Age=0" in v
               for v in r.headers.get_list("set-cookie"))


auth, app = instance(gate_token_enabled=True,
                    forward_apps={"wiki.example.com": {"name": "Wiki", "logout": "app"}})
assert auth.cfg.forward_logout == "all" and auth.cfg.oidc_rp_logout is True
ok("Gateway: default forward_logout=all, oidc_rp_logout=True")

# ---------- sign out of one application only ----------
c, token, uid = signed_in(auth, app)
assert forward(c, WIKI).status_code == 200 and forward(c, APP).status_code == 200
r = c.get("/.tinysesam/logout", headers=WIKI, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/", (r.status_code, r.headers.get("location"))
assert gate_deleted(r, auth), r.headers.get_list("set-cookie")
assert auth.store.get_session(token), "the session must stay"
ok("logout=app: 303 back to the application, gate cookie deleted, session stays")

r = forward(c, WIKI)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-signed-out", dict(r.headers)
loc = urlsplit(r.headers["X-TinySesam-Location"])
assert loc.path == "/auth/login", "after “sign out here only” never straight to the provider (it signed in silently)"
assert forward(c, APP).status_code == 200
assert "X-TinySesam-Gate-Cookie" not in forward(c, WIKI).headers
ok("afterwards: wiki → 401 app-signed-out to the login page (not direct), app still 200, no gate token for wiki")

page_html = c.get(loc.path + "?" + loc.query)
assert page_html.status_code == 200, page_html.status_code
assert "<h1>Anmelden bei Wiki</h1>" in page_html.text and "Weiter als anna" in page_html.text, \
    re.findall(r"<h1>.*?</h1>|<button[^>]*>[^<]*", page_html.text)
ok("login page instead of jump back (no loop): “Anmelden bei Wiki” with “Weiter als anna”")

nxt = parse_qs(loc.query)["next"][0]
r = c.post("/auth/gate/resume", data={"next": nxt}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == nxt
assert forward(c, WIKI).status_code == 200
ok("“Weiter als …” → back to the application, wiki lets through again")

# A new sign-in with target wiki lifts the lockout just the same (the completion of every login).
c.get("/.tinysesam/logout", headers=WIKI, follow_redirects=False)
assert forward(c, WIKI).status_code == 401
assert auth._login_redirect_after(None, token, uid, "https://wiki.example.com/x") == "https://wiki.example.com/x"
assert forward(c, WIKI).status_code == 200
ok("a completed sign-in with target wiki lifts “signed out here only”")

# The lockout survives the rotation of the session (step-up) — otherwise it would be gone with the next factor.
c.get("/.tinysesam/logout", headers=WIKI, follow_redirects=False)
new = auth.store.rotate_session(auth.store.session_hash(token))
c.cookies.set(auth.session_cookie_name, new)
assert forward(c, WIKI).status_code == 401 and forward(c, APP).status_code == 200
ok("“signed out here only” moves along when the session is rotated")

# ---------- sign out everywhere, with id_token_hint ----------
c2, token2, _ = signed_in(auth, app, "bee", id_token="eyJ.ID.TOKEN")
r = c2.get("/.tinysesam/logout?scope=all", headers=APP, follow_redirects=False)
assert r.status_code == 303, r.status_code
destination = urlsplit(r.headers["location"])
q = parse_qs(destination.query)
assert f"{destination.scheme}://{destination.netloc}{destination.path}" == META["end_session_endpoint"], r.headers["location"]
assert q["id_token_hint"] == ["eyJ.ID.TOKEN"] and q["client_id"] == ["main"], q
assert q["post_logout_redirect_uri"] == ["https://app.example.com/.tinysesam/after-logout"], q
assert not auth.store.get_session(token2), "the session must end"
assert gate_deleted(r, auth)
ok("scope=all: session ended, gate cookie deleted, to the provider with id_token_hint, client_id and way back")

# Way back from the provider: without a session a page “Abgemeldet”, no redirect into a new round.
r = TestClient(app).get("/.tinysesam/after-logout", headers=APP, follow_redirects=False)
assert r.status_code == 200 and "Abgemeldet" in r.text and gate_deleted(r, auth)
assert "content='10;url=/'" in r.text, "mode direct (oidc_gateway): after 10 s back to the application"
_pa, _papp = instance(forward_login="page")
_pr = TestClient(_papp).get("/.tinysesam/after-logout", headers=APP, follow_redirects=False)
assert "http-equiv=refresh" not in _pr.text and "Wieder anmelden" in _pr.text, "mode page: the page does not continue on its own"
ok("after-logout without session: page “Abgemeldet” (no new round), gate cookie deleted")

# Chain from the application (its RP logout → provider → after-logout): the session is still alive.
c3, token3, _ = signed_in(auth, app, "cleo", id_token="eyJ.C")
r = c3.get("/.tinysesam/after-logout", headers={**APP, "Sec-Fetch-Site": "same-site"}, follow_redirects=False)
assert not auth.store.get_session(token3), "after-logout must end the still living session"
assert r.status_code == 303 and r.headers["location"].startswith(META["end_session_endpoint"]), r.headers.get("location")
ok("after-logout with still living session (chain from the app): session ends")

# From a foreign page: ask first (logout CSRF, F-07).
c4, token4, _ = signed_in(auth, app, "dora")
r = c4.get("/.tinysesam/logout?scope=all", headers={**APP, "Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 200 and "Überall abmelden?" in r.text and auth.store.get_session(token4)
r = c4.get("/.tinysesam/after-logout", headers={**APP, "Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 200 and auth.store.get_session(token4)
r = c4.post("/.tinysesam/logout", data={"scope": "all", "next": "/"}, headers=APP, follow_redirects=False)
assert r.status_code == 303 and not auth.store.get_session(token4)
ok("from a foreign page: confirmation instead of signing out; the POST signs out")

# Without OIDC sign-in (password session or similar) no detour via the provider.
uid5 = auth.create_user("emil")
t5 = auth.store.create_session(uid5, 3600, True, "password")
c5 = TestClient(app)
c5.cookies.set(auth.session_cookie_name, t5)
r = c5.get("/.tinysesam/logout?scope=all", headers=APP, follow_redirects=False)
assert r.headers["location"] == "/.tinysesam/after-logout" and not auth.store.get_session(t5)
ok("session without OIDC: sign out without a provider detour")

# ---------- queries ----------
auth2, app2 = instance(forward_logout="ask", forward_apps={"wiki.example.com": {"name": "Wiki"}})
c6, t6, _ = signed_in(auth2, app2)
r = c6.get("/.tinysesam/logout", headers=WIKI)
assert r.status_code == 200 and "Nur von Wiki abmelden oder überall?" in r.text, r.text[:400]
assert "Nur von Wiki" in r.text and "Überall" in r.text and auth2.store.get_session(t6)
r = c6.post("/.tinysesam/logout", data={"scope": "app", "next": "/"}, headers=WIKI, follow_redirects=False)
assert r.status_code == 303 and auth2.store.get_session(t6) and forward(c6, WIKI).status_code == 401
ok("logout=ask: page with both paths; “Nur von Wiki” by POST locks only wiki")

assert c6.post("/.tinysesam/logout", data={"scope": "whatever"}, headers=WIKI).status_code == 400
ok("POST with unknown scope → 400")

# ---------- foreign host ----------
r = TestClient(app).get("/.tinysesam/logout", headers={**APP, "X-Forwarded-Host": "foreign.example.net"})
assert r.status_code == 404
ok("a host that this installation does not protect → 404")

# ---------- Configuration check ----------
def findings(**w):
    return config_check.check_config(TinySesamConfig(db_path=":memory:", **w))[0]


assert any("forward_logout" in b for b in findings(forward_logout="only_here"))
assert any("['logout']" in b for b in findings(forward_apps={"a.example.com": {"logout": "now"}}))
assert not [b for b in findings(forward_logout="ask", forward_apps={"a.example.com": {"logout": "app"}})
            if "logout" in b]
ok("configuration check: unknown logout mode (global and per app)")

print("Logout-Modi OK")

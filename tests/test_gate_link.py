"""Central gateway with code exchange (T-26): the session never leaves the gateway's host.

An app host gets, via /.tinysesam/start → /auth/gate/authorize → /.tinysesam/callback, only a
connection cookie of its own (`__Host-tinysesam_link`), which applies exclusively to it. Checked with two
TestClients on two hosts — like two origins in the browser: a cookie of one does not reach the other.
"""
import os
import tempfile
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, ConfigError
from tinysesam import config_check


def ok(name):
    print(f"  ✓ {name}")


GW = "https://auth.example.com"
APP = "https://app.example.com"
WIKI = "https://wiki.example.com"
PW = "Gate-Link-Probe-17!"

auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Gate",
    passkey_enabled=False, oidc_enabled=False, forward_auth_enabled=True, base_url=GW,
    trusted_redirect_hosts=["app.example.com", "wiki.example.com"], gate_token_enabled=True,
    gate_link_enabled=True, forward_apps={"app.example.com": {"name": "App", "login": "page"},
                                          "wiki.example.com": {"name": "Wiki"}}))

_fa_orig = auth._forward_app


def _wiki_direct():
    """The “direct” branch for wiki: the configuration check requires OIDC as the only method for it, but this probe
    signs in by password — therefore bent only for the checks concerned."""
    auth._forward_app = lambda h: {**_fa_orig(h), "login": "direct"} if "wiki" in str(h) else _fa_orig(h)
uid = auth.create_user("anna", PW)
fa = FastAPI()
fa.include_router(auth.router())


def browser():
    """One browser: a client of its own per origin (own cookie store)."""
    return {"gw": TestClient(fa, base_url=GW), "app": TestClient(fa, base_url=APP),
            "wiki": TestClient(fa, base_url=WIKI)}


def forward(c, host="app.example.com", uri="/seite"):
    return c.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": host,
                                           "X-Forwarded-Uri": uri, "Sec-Fetch-Mode": "navigate"})


def place(r):
    return r.headers.get("location") or r.headers.get("X-TinySesam-Location") or ""


def couple(b, rd="/seite", sign_in=True, guest="app"):
    """The whole exchange for one browser. Returns: (callback response, code)."""
    s = b[guest].get(f"/.tinysesam/start?rd={rd}", follow_redirects=False)
    assert s.status_code == 303 and place(s).startswith(GW + "/auth/gate/authorize?flow="), place(s)
    a = b["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
    if a.status_code == 303 and urlsplit(place(a)).path == "/auth/login" and sign_in:
        nxt = parse_qs(urlsplit(place(a)).query)["next"][0]
        b["gw"].post("/auth/login", data={"username": "anna", "password": PW, "next": nxt}, follow_redirects=False)
        a = b["gw"].get(nxt, follow_redirects=False)
    assert a.status_code == 303 and "/.tinysesam/callback?code=" in place(a), (a.status_code, place(a))
    code = parse_qs(urlsplit(place(a)).query)["code"][0]
    couple.binding = b[guest].cookies.get("__Host-tinysesam_linkflow")
    return b[guest].get(f"/.tinysesam/callback?code={code}", follow_redirects=False), code


# ---------- the path ----------
b = browser()
r = forward(b["app"])
assert r.status_code == 401 and place(r) == APP + "/.tinysesam/start?rd=%2Fseite", place(r)
ok("app host without link → 401 on ITS /.tinysesam/start (not on the login page)")

s = b["app"].get("/.tinysesam/start?rd=/seite", follow_redirects=False)
assert any(v.startswith("__Host-tinysesam_linkflow=") for v in s.headers.get_list("set-cookie"))
a = b["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
assert a.status_code == 303 and urlsplit(place(a)).path == "/auth/login", place(a)
page_html = b["gw"].get(urlsplit(place(a)).path + "?" + urlsplit(place(a)).query)
assert "Anmelden bei App" in page_html.text, page_html.text[:300]
assert "Anmelden bei" not in b["gw"].get("/auth/login?next=/&gate_host=evil.example.net").text
ok("gateway without session → login “Anmelden bei App”, the flow waits (foreign gate_host → no name)")

cb, code = couple(b)
assert cb.status_code == 303 and place(cb) == "/seite", (cb.status_code, place(cb))
link = [v for v in cb.headers.get_list("set-cookie") if v.startswith("__Host-tinysesam_link=")]
assert link and "Secure" in link[0] and "HttpOnly" in link[0] and "Domain" not in link[0], link
ok("callback → back to rd, link cookie __Host- (Secure, HttpOnly, without Domain)")

r = forward(b["app"])
assert r.status_code == 200 and r.headers["Remote-User"] == "anna", (r.status_code, dict(r.headers))
assert "X-TinySesam-Gate-Cookie" in r.headers
ok("with link → 200, Remote-User, gate token")

assert auth.session_cookie_name not in b["app"].cookies and auth.session_cookie_name in b["gw"].cookies
ok("the session exists only at the gateway — the app host never saw it")

# B-3: `;`, `%3B` and `&amp;` in the path. A semicolon is a path-parameter separator in RFC 3986 and Tomcat/Spring
# cut at it — TinySesam must not: the path is opaque. Signed out → the exchange carries the path home unchanged,
# signed in (with the link) → 200 for exactly the same address.
SEMI = ["/a;b.pdf", "/a%3Bb.pdf", "/Tom&amp;Jerry.pdf", "/d/x;y/z;", "/a;b.pdf?k=1;2&m=%3B"]
for path in SEMI:
    r = forward(browser()["app"], uri=path)
    assert r.status_code == 401, (path, r.status_code)
    rd = parse_qs(urlsplit(place(r)).query)["rd"][0]
    assert rd == path, (path, rd, place(r))
    c_ = browser()
    cb_, _ = couple(c_, rd=quote(rd, safe=""))
    assert place(cb_) == path, (path, place(cb_))
    r = forward(c_["app"], uri=path)
    assert r.status_code == 200 and r.headers["Remote-User"] == "anna", (path, r.status_code, place(r))
ok(f"B-3: {len(SEMI)} paths with ; / %3B / &amp; — signed out: rd carries the path unchanged; signed in: 200")

# ---------- Angriffe ----------
raw = b["app"].cookies.get("__Host-tinysesam_link")
foreign = TestClient(fa, base_url=WIKI)
foreign.cookies.set("__Host-tinysesam_link", raw)
assert forward(foreign, host="wiki.example.com").status_code == 401
ok("the link of app does not apply to wiki (bound to the host)")

# With the same binding as the first time — otherwise the second attempt would fail on the missing
# binding and not on the consumed code (mutation probe: put the code back after redeeming → red).
again = TestClient(fa, base_url=APP)
again.cookies.set("__Host-tinysesam_linkflow", couple.binding)
assert again.get(f"/.tinysesam/callback?code={code}", follow_redirects=False).status_code == 400
ok("a code applies exactly once (even with the matching binding)")

b2 = browser()
b2["gw"].post("/auth/login", data={"username": "anna", "password": PW, "next": "/"}, follow_redirects=False)
s = b2["app"].get("/.tinysesam/start?rd=/x", follow_redirects=False)
a = b2["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
code2 = parse_qs(urlsplit(place(a)).query)["code"][0]
victim = TestClient(fa, base_url=APP)       # another browser, without binding cookie
assert victim.get(f"/.tinysesam/callback?code={code2}", follow_redirects=False).status_code == 400
ok("a foreign code in another person's browser (without binding) → 400, no link")

b3 = browser()
b3["gw"].post("/auth/login", data={"username": "anna", "password": PW, "next": "/"}, follow_redirects=False)
s = b3["app"].get("/.tinysesam/start?rd=/x", follow_redirects=False)
a = b3["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
code3 = parse_qs(urlsplit(place(a)).query)["code"][0]
b3["wiki"].cookies.set("__Host-tinysesam_linkflow", b3["app"].cookies.get("__Host-tinysesam_linkflow"))
assert b3["wiki"].get(f"/.tinysesam/callback?code={code3}", follow_redirects=False).status_code == 400
ok("a code for app, redeemed at wiki → 400")

for evil in ("//evil.example/x", "https://evil.example/", "\\\\evil", "evil"):
    s = browser()["app"].get("/.tinysesam/start", params={"rd": evil}, follow_redirects=False)
    flow = parse_qs(urlsplit(place(s)).query)["flow"][0]
    assert auth.store.pop_flow("gatelink:" + flow)["rd"] == "/", evil
ok("rd takes only paths of this host (//, foreign address, backslash → /)")

assert TestClient(fa, base_url=GW).get("/auth/gate/authorize?flow=erfunden").status_code == 400
assert TestClient(fa, base_url="https://fremd.example.net").get("/.tinysesam/start").status_code == 404
ok("unknown flow → 400, unprotected host → 404")

# ---------- the session is rotated, the link moves along ----------
h = auth.store.session_hash(b["gw"].cookies.get(auth.session_cookie_name))
new = auth.store.rotate_session(h)
b["gw"].cookies.set(auth.session_cookie_name, new)
assert forward(b["app"]).status_code == 200
ok("session rotated (step-up) — the link of the app host remains valid")

# ---------- sign out here only ----------
r = b["app"].get("/.tinysesam/logout?scope=app", follow_redirects=False)
assert r.status_code == 303
assert any(v.startswith("__Host-tinysesam_link=;") or v.startswith("__Host-tinysesam_link=; ")
           for v in r.headers.get_list("set-cookie")), r.headers.get_list("set-cookie")
b["app"].cookies.delete("__Host-tinysesam_link")
assert forward(b["app"]).status_code == 401
s = b["app"].get("/.tinysesam/start?rd=/seite", follow_redirects=False)
a = b["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
assert a.status_code == 200 and "Weiter als anna" in a.text and "name=gate_host value='app.example.com'" in a.text, a.status_code
ok("signed out here only: link gone; the new exchange shows “Weiter als anna” instead of silently linking")

nxt = "/auth/gate/authorize?flow=" + parse_qs(urlsplit(place(s)).query)["flow"][0]
r = b["gw"].post("/auth/gate/resume", data={"next": nxt, "gate_host": "app.example.com"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == nxt
a = b["gw"].get(nxt, follow_redirects=False)
assert "/.tinysesam/callback?code=" in place(a)
ok("“Weiter als …” lifts the sign-out for app, the exchange continues")

# ---------- sign out everywhere from the app host ----------
b4 = browser()
couple(b4)
assert forward(b4["app"]).status_code == 200
r = b4["app"].get("/.tinysesam/logout?scope=all", follow_redirects=False)
assert r.status_code == 303
assert b4["gw"].get("/auth/me").status_code == 401, "the session at the gateway must end"
assert forward(b4["app"]).status_code == 401
ok("signing out everywhere at the app host ends the session at the gateway — and with it every link")

# ---------- first only here, then everywhere: the session at the gateway must not be left over ----------
b5 = browser()
couple(b5)
b5["app"].get("/.tinysesam/logout?scope=app", follow_redirects=False)
b5["app"].cookies.delete("__Host-tinysesam_link")
r = b5["app"].get("/.tinysesam/logout?scope=all", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == GW + "/auth/gate/logout?host=app.example.com", r.headers.get("location")
r = b5["gw"].get("/auth/gate/logout?host=app.example.com", headers={"Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == APP + "/.tinysesam/logout", r.headers.get("location")
assert b5["gw"].get("/auth/me").status_code == 200, "cross-site must not end the session (logout CSRF)"
r = b5["gw"].get("/auth/gate/logout?host=app.example.com", headers={"Sec-Fetch-Site": "same-site"}, follow_redirects=False)
assert r.status_code == 303 and b5["gw"].get("/auth/me").status_code == 401, (r.status_code, r.headers.get("location"))
r = b5["gw"].get("/auth/gate/logout?host=app.example.com", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/gate/logged-out?host=app.example.com", r.headers.get("location")
r = b5["gw"].get("/auth/gate/logged-out?host=app.example.com", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == APP + "/.tinysesam/start?rd=%2F&signed_out=1", r.headers.get("location")
_wiki_direct()
r = b5["gw"].get("/auth/gate/logged-out?host=wiki.example.com")
auth._forward_app = _fa_orig
assert r.status_code == 200 and "href='https://wiki.example.com/'" in r.text, r.text[-400:]
assert b5["gw"].get("/auth/gate/logged-out?host=evil.example.net").status_code == 400
assert b5["gw"].get("/auth/gate/logout?host=evil.example.net").status_code == 400
ok("sign out everywhere without link → to the gateway, where the session ends (cross-site first a confirmation, no loop); without session “Abgemeldet” at the gateway with path to the app")

# ---------- after signing out: sign-in page with a hint instead of an intermediate page (mode page, PO 2026-10-08) ----------
b6 = browser()
r = b6["app"].get("/.tinysesam/after-logout", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/.tinysesam/start?rd=%2F&signed_out=1", (r.status_code, r.headers.get("location"))
s = b6["app"].get("/.tinysesam/start?rd=%2F&signed_out=1", follow_redirects=False)
a = b6["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
assert a.status_code == 303 and "signed_out=1" in place(a), place(a)
page_html = b6["gw"].get(urlsplit(place(a)).path + "?" + urlsplit(place(a)).query)
assert "Du wurdest abgemeldet." in page_html.text and "Anmelden bei App" in page_html.text, page_html.text[:400]
s = b6["app"].get("/.tinysesam/start?rd=%2F", follow_redirects=False)
a = b6["gw"].get(urlsplit(place(s)).path + "?" + urlsplit(place(s)).query, follow_redirects=False)
assert "signed_out" not in place(a) and "abgemeldet" not in b6["gw"].get(urlsplit(place(a)).path + "?" + urlsplit(place(a)).query).text.lower()
assert "abgemeldet" not in b6["gw"].get("/auth/login?next=/&signed_out=0").text.lower()
_wiki_direct()
w = TestClient(fa, base_url=WIKI).get("/.tinysesam/after-logout")
auth._forward_app = _fa_orig
assert w.status_code == 200 and "Abgemeldet" in w.text, w.status_code
ok("after signing out: sign-in page “Anmelden bei App” with “Du wurdest abgemeldet.” (page); mode direct keeps the page")

# ---------- mode direct: “Abgemeldet” returns on its own after forward_logged_out_sec (PO 2026-10-10) ----------
_wiki_direct()
w = TestClient(fa, base_url=WIKI).get("/.tinysesam/after-logout")
g = b6["gw"].get("/auth/gate/logged-out?host=wiki.example.com")
assert "<meta http-equiv=refresh content='10;url=/'>" in w.text.split("</head>")[0], w.text[:600]
assert "In 10 Sekunden geht es zur Anmeldung." in w.text and "Jetzt anmelden" in w.text
assert "content='10;url=https://wiki.example.com/'" in g.text.split("</head>")[0], g.text[:600]
auth.cfg.forward_logged_out_sec = 0
w0 = TestClient(fa, base_url=WIKI).get("/.tinysesam/after-logout")
auth.cfg.forward_logged_out_sec = 10
auth._forward_app = _fa_orig
assert "http-equiv=refresh" not in w0.text and "Wieder anmelden" in w0.text and "Sekunden" not in w0.text
p6 = b6["gw"].get("/auth/gate/logged-out?host=app.example.com", follow_redirects=False)
assert p6.status_code == 303, "page redirects on to the sign-in page, without an intermediate page"
assert "http-equiv=refresh" not in TestClient(fa, base_url=APP).get("/.tinysesam/after-logout").text
ok("direct: “Abgemeldet” with meta refresh after 10 s to the app (app host and gateway), 0 = leave standing; page without")
assert any("forward_logged_out_sec" in f for f in config_check.check_config(TinySesamConfig(
    db_path=":memory:", forward_logged_out_sec=301))[0])
ok("forward_logged_out_sec above 300 is a configuration error")

# ---------- Configuration check ----------
try:
    TinySesam(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True, gate_token_enabled=True,
                              gate_link_enabled=True, base_url=GW, cookie_domain=".example.com"))
except ConfigError as e:
    assert "cookie_domain" in str(e)
else:
    raise AssertionError("link mode with cookie_domain starts")
assert any("gate_token_enabled" in f for f in config_check.check_config(TinySesamConfig(
    db_path=":memory:", forward_auth_enabled=True, gate_link_enabled=True, base_url=GW))[0])
ok("configuration check: link mode not with cookie_domain, not without gate token")

print("Gate-Link OK")

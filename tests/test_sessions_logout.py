"""Batch D: manage own sessions (+ “sign out everywhere”) and optional OIDC RP logout."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def secret_text(u=Depends(auth.require_user)):
    return {"u": u["username"]}


JSON = {"Accept": "application/json"}
a, b, cc = TestClient(app), TestClient(app), TestClient(app)   # three sessions of the same user
for c in (a, b, cc):
    c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)

# ---------- list own sessions (masked, no tokens) + mark “this one” ----------
lst = a.get("/auth/sessions").json()
assert len(lst) == 3 and sum(1 for s in lst if s["current"]) == 1
assert all("token" not in s for s in lst)
ok("GET /auth/sessions: 3 sessions, exactly one as 'current', no tokens in the output")

# ---------- end other sessions: the current one stays, the others go ----------
a.post("/auth/sessions/revoke", json={"scope": "others"})
assert a.get("/geheim", headers=JSON).status_code == 200
assert b.get("/geheim", headers=JSON).status_code == 401
assert cc.get("/geheim", headers=JSON).status_code == 401
assert len(a.get("/auth/sessions").json()) == 1
ok("revoke scope=others: current session stays, others ended")

# ---------- scope=all: also the own one ----------
a.post("/auth/sessions/revoke", json={"scope": "all"})
assert a.get("/geheim", headers=JSON).status_code == 401
ok("revoke scope=all: the own session ended too")
os.remove(db)

# ---------- OIDC RP logout: end_session_url + logout redirect to the provider ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=True,
                                 oidc_issuer="https://id.example.invalid", oidc_client_id="cid",
                                 oidc_client_secret="sec", cookie_secure=False, oidc_rp_logout=True,
                                 base_url="https://app.example.com", logout_redirect="/"))
# fake discovery metadata (no network)
auth.oidc._meta = {"issuer": "https://id.example.invalid",
                   "end_session_endpoint": "https://id.example.invalid/logout"}
url = auth.oidc.end_session_url("https://app.example.com/")
assert url and url.startswith("https://id.example.invalid/logout?") and "client_id=cid" in url \
    and "post_logout_redirect_uri=" in url
ok("OIDCClient.end_session_url baut Provider-Logout-URL (client_id + post_logout_redirect_uri)")

app = FastAPI(); app.include_router(auth.router())
c = TestClient(app)
# simulate an OIDC session (method='oidc') and logout → redirect to the provider
auth.ensure_admin("admin", "pw")
uid = auth.store.get_user_by_name("admin")["id"]
tok, _ = auth.start_session(uid, "oidc")
c.cookies.set("tinysesam_session", tok)
r = c.get("/auth/logout", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("https://id.example.invalid/logout")
ok("logout of an OIDC session → redirect to the provider logout (oidc_rp_logout=True)")
os.remove(db)

# ---------- F-09 / B1-7 / F-07 on an instance with CSRF, PIN and API keys ----------
import re  # noqa: E402
import time  # noqa: E402

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
                                 oidc_enabled=False, cookie_secure=False, pin_enabled=True,
                                 apikey_enabled=True, stepup_max_age_sec=900))
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def secret_text2(u=Depends(auth.require_user)):
    return {"u": u["username"]}


def sign_in():
    cl = TestClient(app)
    slot = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    cl.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                 "_csrf": slot}, follow_redirects=False)
    return cl


def head(cl):
    return {**JSON, "X-CSRF-Token": cl.cookies.get("tinysesam_csrf") or ""}


def alternate(cl):
    auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(cl.cookies.get("tinysesam_session"))))


x, y = sign_in(), sign_in()
alternate(x)
r = x.post("/auth/sessions/revoke", json={"scope": "all"}, headers=head(x))
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", r.status_code
assert y.get("/geheim", headers=JSON).status_code == 200 and x.get("/geheim", headers=JSON).status_code == 200
ok("F-09: ending sessions with stale confirmation → 403 + reauth hint, nothing ended")

key = auth.create_api_key(uid, name="k")["key"]
service = TestClient(app)
bearer = {**JSON, "Authorization": f"Bearer {key}"}
assert service.post("/auth/sessions/revoke", json={"scope": "all"}, headers=bearer).status_code == 403
assert service.get("/auth/sessions", headers=bearer).status_code == 403, "list only for a real session"
assert y.get("/geheim", headers=JSON).status_code == 200 and auth.store.count_active_api_keys(uid) == 1
ok("F-09: an API key may neither end nor list sessions (and does not revoke itself)")

assert len(x.get("/auth/sessions", headers=JSON).json()) == 2, "viewing remains possible without reauth"
ok("F-09: viewing the list works with a session even without fresh confirmation (ASVS 7.5.2)")

# B1-7: after a factor change the response says how many OTHER sessions are running.
z = sign_in()                                      # fresh → may change factors
r = z.post("/auth/pin/set", json={"pin": "24680"}, headers=head(z))
assert r.status_code == 200 and r.json() == {"ok": True, "other_sessions": 2}, r.text
r = z.post("/auth/pin/disable", headers=head(z))
assert r.json()["other_sessions"] == 2
r = z.post("/auth/sessions/revoke", json={"scope": "others"}, headers=head(z))
assert r.status_code == 200 and x.get("/geheim", headers=JSON).status_code == 401
r = z.post("/auth/pin/set", json={"pin": "24680"}, headers=head(z))
assert r.json()["other_sessions"] == 0
page_html = z.get("/auth/account").text
assert "other_sessions" in page_html and "andere" in auth.t("acc.sessions_offer").lower() \
    and auth.t("acc.sessions_offer")[:20] in page_html, "account page must offer ending"
ok("B1-7: factor change reports other_sessions, the account page offers ending")

# A-5: the own TOTP setup page also offers ending, and when freshness has expired
# the consent travels via the reauth to the account page (?revoke_others=1) — there it asks
# once more. `offer()` is executed in test_browser.py (section 10).
setup = auth.templates.render("totp_setup", auth, {"data": {"secret": "ABC", "qr": ""}})
assert "await offer(r)" in setup and "function tsRevokeOthers" in setup, "setup page without offer"
assert "/auth/account?revoke_others=1" in setup, "consent would be lost during the reauth"
assert "revoke_others" in page_html and "tsRevokeOthers" in page_html, "account page without return switch"
without_account = TinySesam(TinySesamConfig(lang="de", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                       passkey_enabled=False, account_enabled=False))
setup = without_account.templates.render("totp_setup", without_account, {"data": {"secret": "ABC", "qr": ""}})
assert "await offer(r)" in setup and "revoke_others" not in setup, "without account page no dead way back"
r = z.post("/auth/reauth", data={"password": "geheim123", "next": "/auth/account?revoke_others=1",
                                 "_csrf": z.cookies.get("tinysesam_csrf")},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/account?revoke_others=1", r.headers
ok("A-5: TOTP setup offers ending; the reauth detour keeps ?revoke_others=1")

# F-07: logout CSRF. From a foreign page (cross-site) the GET does NOT sign out but asks.
w = sign_in()
r = w.get("/auth/logout", headers={"Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 200 and "method=post" in r.text and "_csrf" in r.text, r.status_code
assert w.get("/geheim", headers=JSON).status_code == 200, "foreign link must not sign out"
ok("F-07: GET /auth/logout from a foreign page → confirmation with POST form, session stays")

r = w.post("/auth/logout", follow_redirects=False)
assert r.status_code == 403 and w.get("/geheim", headers=JSON).status_code == 200
r = w.post("/auth/logout", data={"_csrf": w.cookies.get("tinysesam_csrf")}, follow_redirects=False)
assert r.status_code == 303 and w.get("/geheim", headers=JSON).status_code == 401
ok("F-07: POST /auth/logout without token → 403, with token → signed out")

for head_ in ({"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "same-site"},
              {"Sec-Fetch-Site": "none"}, {}):
    v = sign_in()
    assert v.get("/auth/logout", headers=head_, follow_redirects=False).status_code == 303
    assert v.get("/geheim", headers=JSON).status_code == 401, head_
ok("F-07: own link, neighbouring app, address bar and old browsers still sign out by GET")
os.remove(db)

print("\nSESSIONS + OIDC-LOGOUT OK ✅")

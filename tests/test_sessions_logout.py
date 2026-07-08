"""Batch D: eigene Sitzungen verwalten (+ „überall abmelden") und optionaler OIDC-RP-Logout."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


JSON = {"Accept": "application/json"}
a, b, cc = TestClient(app), TestClient(app), TestClient(app)   # drei Sitzungen desselben Users
for c in (a, b, cc):
    c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)

# ---------- eigene Sitzungen listen (maskiert, keine Tokens) + „diese" markiert ----------
lst = a.get("/auth/sessions").json()
assert len(lst) == 3 and sum(1 for s in lst if s["current"]) == 1
assert all("token" not in s for s in lst)
ok("GET /auth/sessions: 3 Sitzungen, genau eine als 'current', keine Tokens im Output")

# ---------- andere Sitzungen beenden: aktuelle bleibt, die anderen fliegen ----------
a.post("/auth/sessions/revoke", json={"scope": "others"})
assert a.get("/geheim", headers=JSON).status_code == 200
assert b.get("/geheim", headers=JSON).status_code == 401
assert cc.get("/geheim", headers=JSON).status_code == 401
assert len(a.get("/auth/sessions").json()) == 1
ok("revoke scope=others: aktuelle Sitzung bleibt, andere beendet")

# ---------- scope=all: auch die eigene ----------
a.post("/auth/sessions/revoke", json={"scope": "all"})
assert a.get("/geheim", headers=JSON).status_code == 401
ok("revoke scope=all: auch die eigene Sitzung beendet")
os.remove(db)

# ---------- OIDC-RP-Logout: end_session_url + Logout-Redirect zum Provider ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=True,
                                 oidc_issuer="https://id.example.invalid", oidc_client_id="cid",
                                 oidc_client_secret="sec", cookie_secure=False, oidc_rp_logout=True,
                                 base_url="https://app.example.com", logout_redirect="/"))
# Discovery-Metadaten fälschen (kein Netzwerk)
auth.oidc._meta = {"issuer": "https://id.example.invalid",
                   "end_session_endpoint": "https://id.example.invalid/logout"}
url = auth.oidc.end_session_url("https://app.example.com/")
assert url and url.startswith("https://id.example.invalid/logout?") and "client_id=cid" in url \
    and "post_logout_redirect_uri=" in url
ok("OIDCClient.end_session_url baut Provider-Logout-URL (client_id + post_logout_redirect_uri)")

app = FastAPI(); app.include_router(auth.router())
c = TestClient(app)
# eine OIDC-Sitzung simulieren (method='oidc') und Logout → Redirect zum Provider
uid = auth.ensure_admin("admin", "pw") or auth.store.get_user_by_name("admin")["id"]
uid = auth.store.get_user_by_name("admin")["id"]
tok, _ = auth.start_session(uid, "oidc")
c.cookies.set("tinysesam_session", tok)
r = c.get("/auth/logout", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("https://id.example.invalid/logout")
ok("Logout einer OIDC-Sitzung → Redirect zum Provider-Logout (oidc_rp_logout=True)")
os.remove(db)

print("\nSESSIONS + OIDC-LOGOUT OK ✅")

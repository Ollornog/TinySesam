"""Batch D: eigene Sitzungen verwalten (+ „überall abmelden") und optionaler OIDC-RP-Logout."""
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=True,
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
auth.ensure_admin("admin", "pw")
uid = auth.store.get_user_by_name("admin")["id"]
tok, _ = auth.start_session(uid, "oidc")
c.cookies.set("tinysesam_session", tok)
r = c.get("/auth/logout", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("https://id.example.invalid/logout")
ok("Logout einer OIDC-Sitzung → Redirect zum Provider-Logout (oidc_rp_logout=True)")
os.remove(db)

# ---------- F-09 / B1-7 / F-07 an einer Instanz mit CSRF, PIN und API-Keys ----------
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
def geheim2(u=Depends(auth.require_user)):
    return {"u": u["username"]}


def anmelden():
    cl = TestClient(app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    cl.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                 "_csrf": feld}, follow_redirects=False)
    return cl


def kopf(cl):
    return {**JSON, "X-CSRF-Token": cl.cookies.get("tinysesam_csrf") or ""}


def altern(cl):
    auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(cl.cookies.get("tinysesam_session"))))


x, y = anmelden(), anmelden()
altern(x)
r = x.post("/auth/sessions/revoke", json={"scope": "all"}, headers=kopf(x))
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", r.status_code
assert y.get("/geheim", headers=JSON).status_code == 200 and x.get("/geheim", headers=JSON).status_code == 200
ok("F-09: Sitzungen beenden mit veralteter Bestätigung → 403 + Reauth-Hinweis, nichts beendet")

key = auth.create_api_key(uid, name="k")["key"]
dienst = TestClient(app)
bearer = {**JSON, "Authorization": f"Bearer {key}"}
assert dienst.post("/auth/sessions/revoke", json={"scope": "all"}, headers=bearer).status_code == 403
assert dienst.get("/auth/sessions", headers=bearer).status_code == 403, "Liste nur für eine echte Sitzung"
assert y.get("/geheim", headers=JSON).status_code == 200 and auth.store.count_active_api_keys(uid) == 1
ok("F-09: ein API-Key darf Sitzungen weder beenden noch auflisten (und widerruft sich nicht selbst)")

assert len(x.get("/auth/sessions", headers=JSON).json()) == 2, "Ansehen bleibt ohne Reauth möglich"
ok("F-09: die Liste ansehen geht mit einer Sitzung auch ohne frische Bestätigung (ASVS 7.5.2)")

# B1-7: Nach einer Faktor-Änderung sagt die Antwort, wie viele ANDERE Sitzungen laufen.
z = anmelden()                                      # frisch → darf Faktoren ändern
r = z.post("/auth/pin/set", json={"pin": "24680"}, headers=kopf(z))
assert r.status_code == 200 and r.json() == {"ok": True, "other_sessions": 2}, r.text
r = z.post("/auth/pin/disable", headers=kopf(z))
assert r.json()["other_sessions"] == 2
r = z.post("/auth/sessions/revoke", json={"scope": "others"}, headers=kopf(z))
assert r.status_code == 200 and x.get("/geheim", headers=JSON).status_code == 401
r = z.post("/auth/pin/set", json={"pin": "24680"}, headers=kopf(z))
assert r.json()["other_sessions"] == 0
seite = z.get("/auth/account").text
assert "other_sessions" in seite and "andere" in auth.t("acc.sessions_offer").lower() \
    and auth.t("acc.sessions_offer")[:20] in seite, "Kontoseite muss das Beenden anbieten"
ok("B1-7: Faktor-Änderung meldet other_sessions, die Kontoseite bietet das Beenden an")

# F-07: Logout-CSRF. Von einer fremden Seite (cross-site) meldet der GET NICHT ab, sondern fragt.
w = anmelden()
r = w.get("/auth/logout", headers={"Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 200 and "method=post" in r.text and "_csrf" in r.text, r.status_code
assert w.get("/geheim", headers=JSON).status_code == 200, "fremder Link darf nicht abmelden"
ok("F-07: GET /auth/logout von fremder Seite → Rückfrage mit POST-Formular, Sitzung bleibt")

r = w.post("/auth/logout", follow_redirects=False)
assert r.status_code == 403 and w.get("/geheim", headers=JSON).status_code == 200
r = w.post("/auth/logout", data={"_csrf": w.cookies.get("tinysesam_csrf")}, follow_redirects=False)
assert r.status_code == 303 and w.get("/geheim", headers=JSON).status_code == 401
ok("F-07: POST /auth/logout ohne Token → 403, mit Token → abgemeldet")

for kopf_ in ({"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "same-site"},
              {"Sec-Fetch-Site": "none"}, {}):
    v = anmelden()
    assert v.get("/auth/logout", headers=kopf_, follow_redirects=False).status_code == 303
    assert v.get("/geheim", headers=JSON).status_code == 401, kopf_
ok("F-07: eigener Link, Nachbar-App, Adresszeile und alte Browser melden per GET weiter ab")
os.remove(db)

print("\nSESSIONS + OIDC-LOGOUT OK ✅")

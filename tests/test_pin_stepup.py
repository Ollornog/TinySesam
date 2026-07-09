"""Drei Aufbauten ohne E-Mail: nur User+Passwort, PIN als Route-Faktor, PIN als Step-up."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

HTML = {"accept": "text/html"}


def login(c, u="max", pw="geheim12345"):
    return c.post("/auth/login", data={"username": u, "password": pw, "next": "/"}, follow_redirects=False)


# ---------- 1) Nur Benutzername + Passwort, keine E-Mail im Spiel ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, allow_signup=True,
                                                cookie_secure=False))
cfg = auth.cfg
assert cfg.login_identifier == "username" and not cfg.signup_require_email
assert not cfg.magiclink_enabled and not cfg.password_reset_enabled and not cfg.signup_verify_email
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app, headers=HTML)

page = c.get("/auth/register").text
assert "name=username" in page and "name=email" not in page or "required" not in page
r = c.post("/auth/register", data={"username": "max", "password": "geheim12345", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303, r.text[:200]
assert auth.store.get_user_by_name("max")["email"] is None
c.cookies.clear()

lp = c.get("/auth/login").text
assert "Benutzer</label>" in lp, "kein Kombi-Feld"
for gone in ("/auth/magic/request", "/auth/forgot"):
    assert gone not in lp, f"{gone} darf nicht angeboten werden"
assert c.get("/auth/magic/request").status_code == 404
assert c.get("/auth/forgot").status_code == 404
assert login(c).status_code == 303
os.unlink(db)
print("  local_accounts(): User+Passwort, keine E-Mail-Wege ok")


# ---------- 2) PIN als Zusatzfaktor einer Route (schon eingeloggt) ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                cookie_secure=False))
uid = auth.create_user("max", password="geheim12345")
auth.set_pin(uid, "2468")
app = FastAPI()
app.include_router(auth.router())


@app.get("/tresor")
def tresor(user=Depends(auth.require(factors=["password", "pin"]))):
    return {"ok": user["username"]}


c = TestClient(app, headers=HTML)
assert login(c).status_code == 303
# Passwort allein reicht nicht — Route schickt zum PIN-Schritt
r = c.get("/tresor", follow_redirects=False)
assert r.status_code in (303, 307) and r.headers["location"].startswith("/auth/pin"), r.headers
page = c.get("/auth/pin?next=/tresor").text
assert "name=pin" in page and "name=username" not in page, "eingeloggt → kein Benutzerfeld"
r = c.post("/auth/pin", data={"pin": "1111", "next": "/tresor"})
assert r.status_code == 401 and "name=username" not in r.text
r = c.post("/auth/pin", data={"pin": "2468", "next": "/tresor"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/tresor"
assert c.get("/tresor", headers={"accept": "application/json"}).json() == {"ok": "max"}
os.unlink(db)
print("  require(factors=[password,pin]): PIN ohne Benutzerfeld, Route danach offen ok")


# ---------- 3) PIN als Step-up für sensible Bereiche ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], stepup_max_age_sec=1,
                                                cookie_secure=False))
uid = auth.create_user("max", password="geheim12345")
auth.set_pin(uid, "2468")
app = FastAPI()
app.include_router(auth.router())


@app.get("/sensibel")
def sensibel(user=Depends(auth.require(mfa=True))):
    return {"ok": user["username"]}


c = TestClient(app, headers=HTML)
assert login(c).status_code == 303
u = auth.store.get_user_by_name("max")
assert auth.stepup_options(u) == ["pin"], auth.stepup_options(u)

# Frische künstlich abgelaufen lassen → Step-up wird verlangt
s = auth.store.list_sessions()[0]
auth.store.set_session_mfa(s["token"], True)
auth.store.db.execute("UPDATE session SET mfa_at=0 WHERE token=?", (s["token"],))
auth.store.db.commit()

r = c.get("/sensibel", follow_redirects=False)
assert r.status_code == 307 and r.headers["location"].startswith("/auth/reauth"), r.headers
page = c.get("/auth/reauth?next=/sensibel").text
assert "name=pin" in page and "PIN zur Bestätigung" in page
assert "name=password" not in page, "stepup_methods=['pin'] → kein Passwortfeld"
r = c.post("/auth/reauth", data={"pin": "9999", "next": "/sensibel"})
assert r.status_code == 401
# Passwort wird NICHT akzeptiert, wenn nur PIN erlaubt ist
r = c.post("/auth/reauth", data={"password": "geheim12345", "next": "/sensibel"})
assert r.status_code == 401, "Passwort darf hier nicht durchgehen"
r = c.post("/auth/reauth", data={"pin": "2468", "next": "/sensibel"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/sensibel"
assert c.get("/sensibel", headers={"accept": "application/json"}).json() == {"ok": "max"}
os.unlink(db)
print("  stepup_methods=['pin']: sensibler Bereich verlangt PIN trotz Login ok")


# ---------- 4) Fallback: gewünschte Methode nicht eingerichtet ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], cookie_secure=False))
uid = auth.create_user("ohnepin", password="geheim12345")   # keine PIN gesetzt
u = auth.store.get_user(uid)
assert auth.stepup_options(u) == ["password"], "ohne PIN → Passwort statt Sackgasse"
os.unlink(db)
print("  Fallback ohne eingerichtete PIN → Passwort ok")

# ---------- 5) pin_login=False: PIN ist kein Erstfaktor ----------
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                pin_login=False, cookie_secure=False))
uid = auth.create_user("max", password="geheim12345")
auth.set_pin(uid, "2468")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
assert "pin" not in auth.cfg.enabled_methods()
lp = c.get("/auth/login").text
assert "name=pin" not in lp, "PIN-Formular darf nicht auf der Login-Seite stehen"
# Gast kann sich nicht per PIN anmelden
r = c.get("/auth/pin", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login")
r = c.post("/auth/pin", data={"username": "max", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 404, r.status_code
# eingeloggt darf die PIN weiterhin bestätigen
assert login(c).status_code == 303
assert "name=pin" in c.get("/auth/pin").text
os.unlink(db)
print("  pin_login=False: PIN nur noch als Zusatzfaktor ok")



# ---------- 6) Demo-Modus + Erst-Admin-Bootstrap ----------
db = tempfile.mktemp(suffix=".db")
kw = dict(db_path=db, csrf_enabled=False, lang="de", passkey_enabled=False,
          cookie_secure=False, pin_enabled=True, demo_mode=True)
auth = TinySesam(TinySesamConfig.local_accounts(**kw))
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
assert auth.store.get_user_by_name("demo") and auth.store.get_user_by_name("demoadmin")["is_admin"]
lp = c.get("/auth/login").text
assert "Demo-Modus" in lp and "demoadmin" in lp and "demo_mode" in lp, "Zugangsdaten + Warnung"
assert c.post("/auth/login", data={"username": "demo", "password": "demo1234", "next": "/"},
              follow_redirects=False).status_code == 303
assert "Demo-PIN" in c.get("/auth/pin").text
# abschalten → Konten weg
auth2 = TinySesam(TinySesamConfig.local_accounts(**{**kw, "demo_mode": False}))
assert not auth2.store.get_user_by_name("demo") and not auth2.store.get_user_by_name("demoadmin")
os.unlink(db)
print("  demo_mode: Konten + Hinweis, beim Abschalten gelöscht ok")

# Allowlist: nur wer draufsteht wird Admin — und nur solange keiner existiert
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, cookie_secure=False,
                                                admin_identifiers=["chef"]))
auth.create_user("fremder", password="geheim12345")
auth.create_user("chef", password="geheim12345")
app = FastAPI(); app.include_router(auth.router()); c = TestClient(app, headers=HTML)
c.post("/auth/login", data={"username": "fremder", "password": "geheim12345", "next": "/"})
assert not auth.store.get_user_by_name("fremder")["is_admin"], "Fremder darf kein Admin werden"
c.cookies.clear()
c.post("/auth/login", data={"username": "chef", "password": "geheim12345", "next": "/"})
assert auth.store.get_user_by_name("chef")["is_admin"]
os.unlink(db)

# Einmal-Token: genau einmal, danach ist die Route weg
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, cookie_secure=False))
tok = auth.admin_claim_token()
assert tok
auth.create_user("erster", password="geheim12345")
app = FastAPI(); app.include_router(auth.router()); c = TestClient(app, headers=HTML)
r = c.get(f"/auth/claim-admin?token={tok}", follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"], "ohne Login erst anmelden"
c.post("/auth/login", data={"username": "erster", "password": "geheim12345", "next": "/"})
assert c.get("/auth/claim-admin?token=falsch").status_code == 403
r = c.get(f"/auth/claim-admin?token={tok}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/admin"
assert auth.store.get_user_by_name("erster")["is_admin"]
assert c.get(f"/auth/claim-admin?token={tok}").status_code == 404, "Route verschwindet mit dem ersten Admin"
assert auth.admin_claim_token() is None
os.unlink(db)
print("  Erst-Admin: Allowlist + Einmal-Token, kein 'erster User gewinnt' ok")
print("OK test_pin_stepup")

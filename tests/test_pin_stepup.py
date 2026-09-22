"""Drei Aufbauten ohne E-Mail: nur User+Passwort, PIN als Route-Faktor, PIN als Step-up."""
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

HTML = {"accept": "text/html"}


def login(c, u="max", pw="geheim12345"):
    return c.post("/auth/login", data={"username": u, "password": pw, "next": "/"}, follow_redirects=False)


# ---------- 1) Nur Benutzername + Passwort, keine E-Mail im Spiel ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
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
auth.store.set_session_mfa(s["token_hash"], True)
auth.store.db.execute("UPDATE session SET mfa_at=0 WHERE token_hash=?", (s["token_hash"],))
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], cookie_secure=False))
uid = auth.create_user("ohnepin", password="geheim12345")   # keine PIN gesetzt
u = auth.store.get_user(uid)
assert auth.stepup_options(u) == ["password"], "ohne PIN → Passwort statt Sackgasse"
os.unlink(db)
print("  Fallback ohne eingerichtete PIN → Passwort ok")

# ---------- 5) pin_login=False: PIN ist kein Erstfaktor ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
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
db = os.path.join(tempfile.mkdtemp(), "t.db")
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


# ---------- 7) Die ERSTE PIN eines Kontos ohne jeden Faktor ----------
# `/auth/pin/set` ist nicht nur der Weg, eine PIN zu ersetzen, sondern der einzige, sie
# anzulegen. Hinter `require_mfa()` war das für ein rein föderiertes Konto (kein Passwort,
# keine PIN, kein TOTP) eine Sackgasse: `stepup_options()` ist leer, es gibt also nichts,
# womit dieses Konto einen Step-up leisten könnte, und nach Ablauf von `stepup_max_age_sec`
# kam es nie mehr an die Einrichtung. Nachgestellt in `a2_r33_pin_sackgasse.py` (Runde 3).
# Jetzt: ANLEGEN hängt am Alter der Anmeldung, ERSETZEN und Abbauen bleiben hinter
# `require_mfa()`. Mutationsprobe: die Fallunterscheidung in `pin_set` wieder auf ein
# nacktes `require_mfa()` zurückgedreht → (a) wird rot; `login_fresh` immer True → (b) wird rot.
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                                 passkey_enabled=False, oidc_enabled=False,
                                 password_enabled=False,      # rein föderiertes Konto
                                 pin_enabled=True, totp_enabled=True, stepup_max_age_sec=900))
uid = auth.create_user("sso-nutzer")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
J = {"Accept": "application/json"}
assert not auth.store.get_password_hash(uid) and not auth.has_pin(uid)
assert not auth.store.has_confirmed_totp(uid)
assert auth.stepup_options(auth.get_user(uid)) == [], "Vorbedingung: nichts zum Bestätigen da"

tok, mfa_ok = auth.start_session(uid, "oidc", remember=True)
assert mfa_ok, "der föderierte Login allein macht die Sitzung vollwertig"
c.cookies.set(auth.cfg.session_cookie, tok)
# Die Frische ist abgelaufen (das Fenster ist 15 Minuten, die Sitzung hält Tage) — genau die
# Lage, in der die Sackgasse zuschnappte. Die Anmeldung selbst ist noch jung.
auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                 (int(time.time()) - 100000, auth.store.session_hash(tok)))
assert c.get("/auth/me", headers=J).status_code == 200, "die Sitzung muss gültig bleiben"
r = c.post("/auth/pin/set", json={"pin": "2468"}, headers=J)
assert r.status_code == 200, (r.status_code, r.text[:120])       # (a)
assert auth.verify_user_pin(uid, "2468"), "die erste PIN muss ankommen"
print("  (a) erste PIN ohne jeden Faktor: frische Anmeldung genügt ok")

# Jetzt HAT das Konto einen Faktor → das Ersetzen verlangt wieder eine Bestätigung, und die
# ist über die PIN auch leistbar. Die Zusage „Faktor ändern verlangt Frische" bleibt intakt.
r = c.post("/auth/pin/set", json={"pin": "1357"}, headers=J)
assert r.status_code == 403, (r.status_code, r.text[:120])
assert r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", dict(r.headers)
assert auth.verify_user_pin(uid, "2468"), "die alte PIN darf stehen bleiben"
seite = c.get("/auth/reauth").text
assert "name=pin" in seite, "die Reauth-Seite muss jetzt ein PIN-Feld haben"
r = c.post("/auth/reauth", data={"pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert c.post("/auth/pin/set", json={"pin": "1357"}, headers=J).status_code == 200
assert auth.verify_user_pin(uid, "1357")
print("  PIN ERSETZEN bleibt hinter require_mfa (403 → Reauth per PIN → 200) ok")
os.unlink(db)

# Und die alte Anmeldung öffnet nichts mehr: Ist auch der Login zu alt, bleibt es bei 403 —
# aber mit dem Hinweis, der hilft (neu anmelden), und OHNE den Verweis auf eine Reauth-Seite,
# die diesem Konto kein Feld anbieten kann.
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                                 passkey_enabled=False, oidc_enabled=False, password_enabled=False,
                                 pin_enabled=True, totp_enabled=True, stepup_max_age_sec=900))
uid = auth.create_user("sso-nutzer")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
tok, _ = auth.start_session(uid, "oidc", remember=True)
c.cookies.set(auth.cfg.session_cookie, tok)
auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                 (int(time.time()) - 100000, int(time.time()) - 100000,
                  auth.store.session_hash(tok)))
r = c.post("/auth/pin/set", json={"pin": "2468"}, headers={"Accept": "application/json"})
assert r.status_code == 403, (r.status_code, r.text[:120])       # (b)
assert r.json().get("detail") == auth.t("api.stepup_relogin"), r.text[:160]
assert "X-TinySesam-Reauth" not in r.headers, dict(r.headers)
assert not auth.has_pin(uid), "ohne frische Anmeldung darf keine PIN gesetzt werden"
# Die Reauth-Seite sagt dem Konto die Wahrheit, statt ein Passwortfeld anzubieten, das es
# nicht hat (jeder Versuch wäre aussichtslos — und zählte in denselben Sperr-Topf).
seite = c.get("/auth/reauth")
felder = re.findall(r"<input[^>]*name=[\"\']?(\w+)", seite.text)
assert felder == [], felder
assert auth.t("err.stepup_none") in seite.text, seite.text[:300]
antwort = c.post("/auth/reauth", data={"password": "geraten", "next": "/"})
assert antwort.status_code == 403, antwort.status_code
assert auth.store.count_fails(0, username="sso-nutzer") == 0, "kein Fehlversuch im Sperr-Topf"
os.unlink(db)
print("  (b) zu alte Anmeldung: 403 'neu anmelden', Reauth-Seite ohne Feld ok")


# ---------- 8) Dieselbe Route für ein Konto MIT Passwort: die Regel, genau ----------
# Die Ausnahme aus (7) gilt schmal: Sie ist für ein Konto gedacht, das gar nichts hat, womit
# es bestätigen könnte. Sobald `stepup_options()` etwas hergibt — und das tut sie für jedes
# Konto mit Passwort —, verlangt auch das ANLEGEN der ersten PIN eine frische Bestätigung.
# Das ist Absicht und keine Nachlässigkeit: Mit `pin_login` ist eine PIN ein vollwertiger
# Erstfaktor, ein gestohlenes Sitzungscookie richtete sich damit sonst einen eigenen Zugang
# ein, der den Diebstahl überdauert. Eine frische Anmeldung allein genügt dafür NICHT.
# Bis zur zweiten Runde behauptete der CHANGELOG pauschal, das Anlegen hänge am Alter der
# Anmeldung; gemessen wurde die Regel von keiner Suite. Jetzt hier. (Mutationsprobe:
# `or auth.stepup_options(u)` in `pin_set` streichen → (b) wird rot.)
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                                 passkey_enabled=False, oidc_enabled=False, pin_enabled=True,
                                 pin_login=True, stepup_max_age_sec=900))
PW = "Anna-Passwort-2026"
uid = auth.create_user("anna", PW)
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
J = {"Accept": "application/json"}
assert auth.stepup_options(auth.get_user(uid)) == ["password"], "Vorbedingung: das Konto kann bestätigen"
assert c.post("/auth/login", data={"username": "anna", "password": PW, "next": "/"},
              follow_redirects=False).status_code == 303

# (a) Frisch angemeldet: Die erste PIN geht durch — die Anmeldung IST hier die Bestätigung.
r = c.post("/auth/pin/set", json={"pin": "2468"}, headers=J)
assert r.status_code == 200, (r.status_code, r.text[:120])
assert auth.verify_user_pin(uid, "2468")
print("  (a) Passwort-Konto, frisch angemeldet: erste PIN geht durch ok")

# (b) Bestätigung abgelaufen, Anmeldung noch jung: 403 — und zwar der, der weiterhilft.
auth.disable_pin(uid)
_hash = auth.store.session_hash(c.cookies.get(auth.cfg.session_cookie))
auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?", (int(time.time()) - 100000, _hash))
_sitzung = auth.store._one("SELECT created_at, mfa_at FROM session WHERE token_hash=?", (_hash,))
# Vorbedingung, sonst misst (b) den falschen Riegel: Die ANMELDUNG ist noch jung, nur die
# Bestätigung ist abgelaufen. Genau diese Lage trennt `login_fresh()` von `stepup_fresh()`.
assert int(time.time()) - _sitzung["created_at"] < auth.cfg.stepup_max_age_sec, dict(_sitzung)
assert int(time.time()) - _sitzung["mfa_at"] > auth.cfg.stepup_max_age_sec, dict(_sitzung)
r = c.post("/auth/pin/set", json={"pin": "1357"}, headers=J)
assert r.status_code == 403, (r.status_code, r.text[:120])
assert r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", dict(r.headers)
assert not auth.has_pin(uid), "ohne Bestätigung darf kein Anmeldefaktor entstehen"
print("  (b) Passwort-Konto, Bestätigung abgelaufen: 403 + Verweis auf die Reauth-Seite ok")

# (c) Und der Weg, auf den der Verweis zeigt, führt zum Ziel: Passwort bestätigen → PIN setzen.
r = c.post("/auth/reauth", data={"password": PW, "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
r = c.post("/auth/pin/set", json={"pin": "1357"}, headers=J)
assert r.status_code == 200, (r.status_code, r.text[:120])
assert auth.verify_user_pin(uid, "1357")
print("  (c) nach der Bestätigung auf /auth/reauth: erste PIN geht durch ok")
os.unlink(db)

# ---------- 5) Eine an der PIN-Anmeldung gesperrte PIN lässt sich auf /auth/reauth nicht weiterraten (C-3) ----------
# Die Step-up-Seite hat ihren eigenen Topf (`is_reauth_locked`); der darf die PIN-Sperre der
# Anmeldung nicht aushebeln — sonst verdoppelt sich der Keyspace-Vorrat eines Angreifers.
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], stepup_max_age_sec=1,
                                                cookie_secure=False))
uid = auth.create_user("max", password="geheim12345")
auth.set_pin(uid, "2468")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app, headers=HTML)
assert login(c).status_code == 303
for _ in range(int(auth.sec("pin_max_attempts")) + 1):
    c.post("/auth/pin", data={"pin": "0000", "next": "/"})
assert auth.is_pin_locked("max", "testclient"), "Vorbedingung: die PIN-Anmeldung ist gesperrt"
time.sleep(1.1)
r = c.post("/auth/reauth", data={"pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 429, f"gesperrte PIN wird auf /auth/reauth weiter angenommen: {r.status_code}"
os.unlink(db)
print("  (C-3) PIN-Sperre der Anmeldung gilt auch auf der Step-up-Seite ok")

print("OK test_pin_stepup")

"""Phase 6: Registrierung (deaktivierbar) + E-Mail-Verifikation + Einladung (invite-only)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def build(**cfgkw):
    sent = []
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, **cfgkw))
    auth.set_mailer(lambda to, s, t, html=None: sent.append({"to": to, "text": t}))
    auth.ensure_admin("admin", "geheim123")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, app, sent, TestClient(app)


JSON = {"Accept": "application/json"}

# ---------- Registrierung deaktiviert (Default) → keine Route ----------
db, auth, app, sent, c = build(allow_signup=False)
assert c.get("/auth/register").status_code == 404
os.remove(db)
ok("allow_signup=False → /auth/register existiert nicht (404)")

# ---------- Einfache Registrierung → sofort eingeloggt ----------
db, auth, app, sent, c = build(allow_signup=True)
assert "Konto erstellen" in c.get("/auth/register").text
r = c.post("/auth/register", data={"username": "neu", "password": "supergeheim", "email": "neu@example.com", "next": "/geheim"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "neu"}
# zu kurzes Passwort abgelehnt
r = c.post("/auth/register", data={"username": "x", "password": "1", "next": "/"})
assert r.status_code == 400
# E-Mail ist Pflicht (signup_require_email, Default an)
r = c.post("/auth/register", data={"username": "y", "password": "supergeheim", "next": "/"})
assert r.status_code == 400
# vergebener Name (mit eigener, freier E-Mail → scheitert wirklich am Namen)
r = c.post("/auth/register", data={"username": "neu", "password": "supergeheim",
                                   "email": "anders@example.com", "next": "/"})
assert r.status_code == 409
os.remove(db)
ok("allow_signup=True: Konto anlegen → eingeloggt; Validierung greift")

# ---------- E-Mail-Verifikation: Konto erst nach Link aktiv ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True)
r = c.post("/auth/register", data={"username": "verify", "password": "supergeheim", "email": "v@example.com", "next": "/"})
assert "Bestätigung" in r.text or "bestätig" in r.text.lower()
uid = auth.store.get_user_by_name("verify")["id"]
assert auth.store.get_user(uid)["disabled"] == 1     # noch gesperrt
assert len(sent) == 1
# Der Bestätigungslink zeigt auf den EIGENEN Endpunkt, nicht mehr auf /auth/magic/ —
# sonst nimmt magiclink_enabled=False die E-Mail-Bestätigung mit (siehe unten).
token = re.search(r"/auth/verify/([\w\-]+)", sent[0]["text"]).group(1)
assert "/auth/magic/" not in sent[0]["text"]
r = c.get(f"/auth/verify/{token}", follow_redirects=False)
assert r.status_code == 303
assert auth.store.get_user(uid)["disabled"] == 0     # aktiviert
assert c.get(f"/auth/verify/{token}", follow_redirects=False).status_code == 400   # one-shot
ok("signup_verify_email: eigener Endpunkt /auth/verify/{token}, einmal einlösbar")
os.remove(db)

# … und der funktioniert OHNE Magic-Link. Das war der eigentliche Fehler: beides hing am selben
# Endpunkt, also verlor man mit dem Anmelde-Link auch die Bestätigung.
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=False)
c.post("/auth/register", data={"username": "ohne", "password": "supergeheim",
                               "email": "o@example.com", "next": "/"})
uid = auth.store.get_user_by_name("ohne")["id"]
token = re.search(r"/auth/verify/([\w\-]+)", sent[0]["text"]).group(1)
assert c.get(f"/auth/verify/{token}", follow_redirects=False).status_code == 303
assert auth.store.get_user(uid)["disabled"] == 0
assert c.get("/auth/magic/request").status_code == 404     # Magic-Link ist wirklich aus
ok("E-Mail-Bestätigung funktioniert ohne Magic-Link")
os.remove(db)

# ---------- Invite-only: ohne Einladung kein Zugang, mit Einladung ok ----------
db, auth, app, sent, c = build(allow_signup=True, signup_invite_only=True, magiclink_enabled=True)
assert c.get("/auth/register").status_code == 403        # ohne Einladung
inv = auth.create_invite("gast@example.com", "http://testserver", roles=["editor"])
token = inv["token"]
# Link öffnen → Weiterleitung zur Registrierung (Token NICHT verbraucht)
assert "/auth/invite/" in inv["url"] and "/auth/magic/" not in inv["url"]
r = c.get(f"/auth/invite/{token}", follow_redirects=False)
assert r.status_code == 303 and "/auth/register?invite=" in r.headers["location"]
# Registrierungsseite mit Einladung erreichbar, E-Mail vorbefüllt
page = c.get(f"/auth/register?invite={token}").text
assert "gast@example.com" in page
# Registrieren → Konto mit Rollen aus der Einladung, eingeloggt
r = c.post("/auth/register", data={"username": "gast", "password": "supergeheim", "invite": token, "next": "/geheim"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
u = auth.store.get_user_by_name("gast")
assert u and auth.has_role(u, "editor")
# Einladung ist verbraucht → erneut nutzen scheitert
assert auth.peek_magic(token, purpose="invite") is None
r2 = TestClient(app).get(f"/auth/register?invite={token}")
assert r2.status_code == 403
ok("invite-only: nur mit gültiger Einladung; Rollen übernommen; Einladung one-shot")
os.remove(db)

print("\nREGISTER + INVITE OK ✅")

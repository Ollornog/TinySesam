"""Phase 9: Kombinations-Matrix — Features einzeln/aus/kombiniert, ohne gegenseitige Störung.

Prüft die Leitlinie: jede Fähigkeit funktioniert allein, ist abschaltbar (dann keine Route/kein
Verhalten) und lässt sich mit den anderen kombinieren."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def absent(c, path):
    """True, wenn die Route nicht existiert (404). GET, ohne Redirects folgen."""
    return c.get(path, follow_redirects=False).status_code == 404


# ---------- ALLES AUS: nur Basis-Routen, keine optionalen ----------
db = tempfile.mktemp(suffix=".db")
a = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=db, passkey_enabled=False, oidc_enabled=False,
                              pin_enabled=False, magiclink_enabled=False, allow_signup=False,
                              resource_locks_enabled=False, forward_auth_enabled=False,
                              account_enabled=False, admin_enabled=False, cookie_secure=False))
app = FastAPI(); app.include_router(a.router())
c = TestClient(app, raise_server_exceptions=False)
for path in ("/auth/pin", "/auth/magic/request", "/auth/register", "/auth/resource/x",
             "/auth/forward", "/auth/account"):
    assert absent(c, path), f"{path} sollte fehlen (404)"
assert c.get("/auth/login").status_code == 200
assert c.get("/auth/logout", follow_redirects=False).status_code in (303, 307)
os.remove(db)
ok("alle optionalen Features aus → zugehörige Routen fehlen (404), Basis bleibt")

# ---------- ALLES AN: Routen vorhanden, keine Kollision ----------
db = tempfile.mktemp(suffix=".db")
a = TinySesam(TinySesamConfig(csrf_enabled=False, 
    db_path=db, passkey_enabled=False, oidc_enabled=False,
    pin_enabled=True, magiclink_enabled=True, allow_signup=True, resource_locks_enabled=True,
    forward_auth_enabled=True, account_enabled=True, admin_enabled=True,
    remember_me_enabled=True, cookie_secure=False, base_url="https://auth.example.com"))
a.set_mailer(lambda *x, **k: None)
a.ensure_admin("admin", "geheim123")
uid = a.store.get_user_by_name("admin")["id"]
a.set_pin(uid, "2468")
a.set_resource_secret("z", "1234", kind="pin", label="Z")
app = FastAPI(); app.include_router(a.router())
c = TestClient(app, raise_server_exceptions=False)
JSON = {"Accept": "application/json"}
for path in ("/auth/pin", "/auth/magic/request", "/auth/register", "/auth/resource/z",
             "/auth/forward", "/auth/account", "/auth/reauth"):
    assert not absent(c, path), f"{path} sollte vorhanden sein"
assert c.get("/auth/login").status_code == 200
ok("alle Features an → alle Routen erreichbar, keine Kollision")
secret = a.totp_begin(uid)["secret"]
a.totp_confirm(uid, pyotp.TOTP(secret).now())

# PIN-Login → TOTP-Schritt (klassisch: PIN identifiziert, TOTP als 2. Faktor)
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
assert r.status_code == 303
# eingeloggt: Konto-Seite + Forward-Auth ok
assert "Konto · admin" in c.get("/auth/account").text
assert c.get("/auth/forward", headers={"X-Forwarded-Host": "app", "X-Forwarded-Uri": "/x"}).status_code == 200
# Ressourcen-PIN unabhängig vom Login
c2 = TestClient(app)
assert c2.post("/auth/resource/z", data={"secret": "1234", "next": "/"}, follow_redirects=False).status_code == 303
ok("PIN+TOTP-Login, Konto-Seite, Forward-Auth und Ressourcen-PIN gleichzeitig nutzbar")
os.remove(db)

# ---------- Feature einzeln: nur Magic-Link (kein Passwort) ----------
db = tempfile.mktemp(suffix=".db")
sent = []
a = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=db, password_enabled=False, passkey_enabled=False,
                              oidc_enabled=False, magiclink_enabled=True, cookie_secure=False))
a.set_mailer(lambda to, s, t, html=None: sent.append(t))
a.create_user("nurmail", email="m@example.com")
app = FastAPI(); app.include_router(a.router())
c = TestClient(app)
# kein Passwort-Login
assert c.post("/auth/login", data={"username": "nurmail", "password": "x"}).status_code == 404
# Magic-Link funktioniert allein
c.post("/auth/magic/request", data={"email": "m@example.com", "next": "/"})
import re
tok = re.search(r"/auth/magic/([\w\-]+)", sent[0]).group(1)
assert c.get(f"/auth/magic/{tok}", follow_redirects=False).status_code == 303
os.remove(db)
ok("nur Magic-Link (Passwort aus): Passwort-Login 404, Magic-Login funktioniert allein")

print("\nKOMBINATIONS-MATRIX OK ✅")

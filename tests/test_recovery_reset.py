"""Batch C: TOTP-Recovery-Codes (one-shot) + Forgot-Password (Reset per E-Mail)."""
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


sent = []
db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, magiclink_enabled=True, password_reset_enabled=True,
                                 recovery_code_count=6))
auth.set_mailer(lambda to, s, t, html=None: sent.append({"to": to, "text": t}))
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
auth.store._exec("UPDATE users SET email=? WHERE id=?", ("admin@example.com", uid))
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# ---------- Recovery-Codes: einlösbar im TOTP-Schritt, one-shot ----------
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).now())
codes = auth.generate_recovery_codes(uid)
assert len(codes) == 6 and auth.recovery_codes_remaining(uid) == 6
ok("generate_recovery_codes → 6 Codes")

# Login → TOTP-Schritt; statt TOTP einen Recovery-Code eingeben
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).status_code == 401
r = c.post("/auth/totp", data={"code": codes[0], "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "admin"}
assert auth.recovery_codes_remaining(uid) == 5
ok("Recovery-Code statt TOTP → eingeloggt (verbraucht: 6→5)")

# derselbe Code ein zweites Mal → ungültig
c.get("/auth/logout")
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.post("/auth/totp", data={"code": codes[0], "next": "/"}).status_code == 401
ok("verbrauchter Recovery-Code ist ungültig (one-shot)")

# Self-Service-Regenerierung erfordert eingeloggt + TOTP
c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
r = c.post("/auth/totp/recovery")
assert r.status_code == 200 and len(r.json()["codes"]) == 6
assert auth.recovery_codes_remaining(uid) == 6   # ersetzt die alten
ok("Self-Service: neue Recovery-Codes ersetzen die alten")
c.get("/auth/logout")

# ---------- Forgot-Password ----------
assert "Passwort vergessen" in c.get("/auth/login").text   # Link auf Login-Seite
sent.clear()
# unbekannte Adresse → generisch, keine Mail
c.post("/auth/forgot", data={"email": "fremd@example.com"})
assert sent == []
# bekannte Adresse → Reset-Mail
c.post("/auth/forgot", data={"email": "admin@example.com"})
assert len(sent) == 1
token = re.search(r"/auth/magic/([\w\-]+)", sent[0]["text"]).group(1)
ok("Forgot: Reset-Link nur für existierendes Konto (keine Enumeration)")

# Link öffnen → Weiterleitung zur Reset-Seite (Token nicht verbraucht)
r = c.get(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 303 and "/auth/reset?token=" in r.headers["location"]
assert "Neues Passwort" in c.get(f"/auth/reset?token={token}").text
# zu kurzes Passwort → 400
assert c.post("/auth/reset", data={"token": token, "password": "x"}).status_code == 400
# neues Passwort setzen → Redirect zum Login, Token verbraucht
r = c.post("/auth/reset", data={"token": token, "password": "ganzneuespw"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
assert auth.peek_magic(token, purpose="reset_password") is None
ok("Reset: neues Passwort gesetzt, Token verbraucht")

# altes Passwort weg, neues geht
c2 = TestClient(app)
assert c2.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False).status_code == 401
r = c2.post("/auth/login", data={"username": "admin", "password": "ganzneuespw", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("nach Reset: altes Passwort ungültig, neues gültig")

os.remove(db)
print("\nRECOVERY + RESET OK ✅")

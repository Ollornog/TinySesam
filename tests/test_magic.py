"""Phase 5: Mailer-Hook + Magic-Link (Einmal-Login per E-Mail)."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


sent = []   # abgefangene Mails

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, magiclink_enabled=True, magiclink_ttl_min=15))
auth.set_mailer(lambda to, subject, text, html=None: sent.append({"to": to, "subject": subject, "text": text}))
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

# Login-Seite zeigt Magic-Option
assert "Login-Link per E-Mail" in c.get("/auth/login").text
ok("Login-Seite zeigt Magic-Link-Option")

# Request-Seite
assert "E-Mail" in c.get("/auth/magic/request").text

# unbekannte Adresse → gleiche Antwort, KEINE Mail (keine Enumeration)
r = c.post("/auth/magic/request", data={"email": "fremd@example.com", "next": "/geheim"})
assert r.status_code == 200 and "unterwegs" in r.text
assert sent == []
ok("unbekannte Adresse: generische Antwort, keine Mail (keine Enumeration)")

# bekannte Adresse → Mail mit Link
r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/geheim"})
assert r.status_code == 200 and "unterwegs" in r.text
assert len(sent) == 1 and sent[0]["to"] == "admin@example.com"
import re
m = re.search(r"/auth/magic/([\w\-]+)", sent[0]["text"])
assert m, sent[0]["text"]
token = m.group(1)
ok("bekannte Adresse: Anmelde-Link per Mail verschickt")

# noch nicht eingeloggt
assert c.get("/geheim", headers=JSON).status_code == 401

# Link einlösen → eingeloggt, Redirect auf next
r = c.get(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim", r.headers.get("location")
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("Magic-Link einlösen → eingeloggt (Faktor 'magic')")

# one-shot: zweite Einlösung schlägt fehl
c2 = TestClient(app)
r = c2.get(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 400 and "ungültig" in r.text.lower()
ok("Token ist one-shot (zweite Einlösung ungültig)")

# abgelaufener Token
raw = auth.create_magic_token("login", user_id=uid, email="admin@example.com", ttl_min=15, payload={"next": "/"})
h = __import__("hashlib").sha256(raw.encode()).hexdigest()
auth.store._exec("UPDATE magic_token SET expires_at=0 WHERE token_hash=?", (h,))
assert auth.redeem_magic(raw) is None
ok("abgelaufener Token → ungültig")

# mail_configured / MailNotConfigured
assert auth.mail_configured() is True
db2 = tempfile.mktemp(suffix=".db")
a2 = TinySesam(TinySesamConfig(db_path=db2, magiclink_enabled=True))   # kein smtp_host, kein Mailer
assert a2.mail_configured() is False
from tinysesam.mailer import MailNotConfigured
try:
    a2.send_mail("x@y.z", "s", "t"); assert False
except MailNotConfigured:
    ok("ohne SMTP/Mailer: send_mail wirft MailNotConfigured")
os.remove(db2)

os.remove(db)
print("\nMAGIC-LINK OK ✅")

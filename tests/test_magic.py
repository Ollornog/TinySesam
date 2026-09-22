"""Phase 5: Mailer-Hook + Magic-Link (Einmal-Login per E-Mail)."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


sent = []   # abgefangene Mails

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, magiclink_enabled=True, magiclink_ttl_min=15,
                                 # Seit R4-01 baut TinySesam Mail-Links nur aus einer zugesagten
                                 # öffentlichen Adresse, nicht mehr aus dem Host-Header.
                                 base_url="https://auth.example.com"))
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
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
a2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, magiclink_enabled=True,
                               # Pflicht seit der base_url-Nacharbeit; geprüft wird hier der
                               # fehlende MAILER, nicht die fehlende Basis.
                               base_url="https://auth.example.com"))   # kein smtp_host, kein Mailer
assert a2.mail_configured() is False
from tinysesam.mailer import MailNotConfigured
try:
    a2.send_mail("x@y.z", "s", "t"); assert False
except MailNotConfigured:
    ok("ohne SMTP/Mailer: send_mail wirft MailNotConfigured")
os.remove(db2)

# ---------- /auth/magic/{token} ist seit 0.16 NUR der Anmelde-Link ----------
# Vorher war es der Eingang für vier Zwecke; wer den Magic-Link abschaltete, verlor Bestätigung
# und Einladung gleich mit. Ein Token anderen Zwecks wird hier jetzt abgewiesen.
fremd = auth.create_magic_token("verify_email", user_id=uid, email="admin@example.com")
r = c.get(f"/auth/magic/{fremd}", follow_redirects=False)
assert r.status_code == 400, r.status_code
assert auth.peek_magic(fremd, purpose="verify_email"), "und bleibt dabei unverbraucht"
ok("/auth/magic/{token} nimmt nur noch login-Token (eigene Endpunkte für den Rest)")

os.remove(db)
print("\nMAGIC-LINK OK ✅")

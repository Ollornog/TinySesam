"""Batch C: TOTP-Recovery-Codes (one-shot) + Forgot-Password (Reset per E-Mail)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


sent = []
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, magiclink_enabled=True, password_reset_enabled=True,
                                 recovery_code_count=6,
                                 # Mail-Links brauchen seit R4-01 eine zugesagte Adresse.
                                 base_url="https://auth.example.com"))
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
# Der Reset-Link zeigt direkt auf die Reset-Seite — bis 0.15 lief er über /auth/magic/ und
# nahm damit den Umweg über einen Endpunkt, der mit dem Reset nichts zu tun hat.
token = re.search(r"/auth/reset\?token=([\w\-]+)", sent[0]["text"]).group(1)
assert "/auth/magic/" not in sent[0]["text"]
ok("Forgot: Reset-Link nur für existierendes Konto (keine Enumeration)")

assert "Neues Passwort" in c.get(f"/auth/reset?token={token}").text
# zu kurzes Passwort → 400
assert c.post("/auth/reset", data={"token": token, "password": "x"}).status_code == 400
# neues Passwort setzen → Redirect zum Login, Token verbraucht
r = c.post("/auth/reset", data={"token": token, "password": "ganzneuespw"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
assert auth.peek_magic(token, purpose="reset_password") is None
ok("Reset: neues Passwort gesetzt, Token verbraucht")

# Der Reset hängt am Mailer, nicht am Magic-Link. Bis 0.15 verlangte die Route beides
# (password_reset_enabled AND magiclink_enabled) — zwei Dinge, die nichts miteinander zu tun haben.
db_x = os.path.join(tempfile.mkdtemp(), "t.db")
post_x = []
ax = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_x, cookie_secure=False,
                               passkey_enabled=False, password_reset_enabled=True,
                               magiclink_enabled=False, base_url="https://auth.example.com"))
ax.set_mailer(lambda to, subject, text, html=None: post_x.append(text))
ax.create_user("ohne", "altes-geheim", email="ohne@example.com")
appx = FastAPI()
appx.include_router(ax.router())
cx = TestClient(appx, headers={"Accept": "text/html"})
assert cx.get("/auth/magic/request").status_code == 404, "Magic-Link ist aus"
assert cx.get("/auth/forgot").status_code == 200, "Passwort-vergessen bleibt trotzdem erreichbar"
cx.post("/auth/forgot", data={"email": "ohne@example.com"})
tok_x = re.search(r"/auth/reset\?token=([\w\-]+)", post_x[0]).group(1)
r = cx.post("/auth/reset", data={"token": tok_x, "password": "frisches-passwort"},
            follow_redirects=False)
assert r.status_code == 303
assert ax.check_password("ohne", "frisches-passwort")
os.remove(db_x)
ok("Passwort-Reset funktioniert ohne Magic-Link (Kopplung gelöst)")

# altes Passwort weg, neues geht
c2 = TestClient(app)
assert c2.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False).status_code == 401
r = c2.post("/auth/login", data={"username": "admin", "password": "ganzneuespw", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("nach Reset: altes Passwort ungültig, neues gültig")

# ---------- R4-13 / H-10: Der Reset ist der Weg aus der Sperre ----------
# Bis T-13 setzte der Selbstbedienungs-Reset das Passwort und liess die Fehlversuche stehen:
# Wer sich ausgesperrt hatte und den vorgesehenen Weg ging, stand mit dem NEUEN Passwort vor
# derselben 429 — bis das Fenster ablief oder ein Admin `tinysesam unlock` fuhr. Der Reset
# prüft die Sperre nicht (unabhängiger Weg, H-10) und hebt jetzt die Passwort-Sperre auf. Die
# TOTP-Fehlversuche bleiben: Ein Postfach beweist den zweiten Faktor nicht.
# (Mutationsprobe: `sperre_aufheben` in `reset_submit` streichen → 429 statt 303.)
db_s = os.path.join(tempfile.mkdtemp(), "t.db")
post_s = []
a_s = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_s, cookie_secure=False,
                                passkey_enabled=False, password_reset_enabled=True,
                                base_url="https://auth.example.com"))
a_s.set_mailer(lambda to, subject, text, html=None: post_s.append(text))
a_s.create_user("gesperrt", "altes-geheimnis-1", email="gesperrt@example.com")
app_s = FastAPI()
app_s.include_router(a_s.router())
c_s = TestClient(app_s, headers={"Accept": "text/html"})
for _ in range(a_s.sec("max_login_attempts")):
    assert c_s.post("/auth/login", data={"username": "gesperrt", "password": "vergessen"}).status_code == 401
a_s.record_login("gesperrt", "testclient", False, "totp")       # ein Fehlgriff am zweiten Faktor
assert c_s.post("/auth/login", data={"username": "gesperrt", "password": "altes-geheimnis-1"}).status_code == 429, \
    "Vorbedingung: das Konto ist gesperrt"
c_s.post("/auth/forgot", data={"email": "gesperrt@example.com"})
tok_s = re.search(r"/auth/reset\?token=([\w\-]+)", post_s[0]).group(1)
assert c_s.post("/auth/reset", data={"token": tok_s, "password": "neues-geheimnis-2"},
                follow_redirects=False).status_code == 303, "der Reset selbst hängt an der Sperre"
r = c_s.post("/auth/login", data={"username": "gesperrt", "password": "neues-geheimnis-2"},
             follow_redirects=False)
assert r.status_code == 303, f"nach dem Reset weiter gesperrt: {r.status_code}"
ok("R4-13/H-10: der Reset läuft an der Sperre vorbei und hebt sie auf")
# Der Login oben war vollständig und hat damit ohnehin alles geräumt (R7-1); gemessen wird der
# Reset deshalb am Zähler direkt, mit einem frischen Fehlgriff je Methode.
a_s.record_login("gesperrt", "testclient", False, "password")
a_s.record_login("gesperrt", "testclient", False, "totp")
weg = a_s.sperre_aufheben(a_s.store.get_user_by_name("gesperrt")["id"], methoden=("password",))
assert weg == 1 and a_s.store.count_fails(0, username="gesperrt", method="totp") == 1, \
    "der Reset räumt auch Fehlversuche am zweiten Faktor"
assert any("fehlversuche_verworfen=" in (z["detail"] or "") for z in a_s.store.recent_audit(20)
           if z["event"] == "password_reset"), "das Audit-Log sagt nicht, was der Reset geräumt hat"
ok("…nur die Passwort-Fehlversuche, nicht die des zweiten Faktors; das Audit-Log nennt die Zahl")
os.remove(db_s)


# ---------- base_url mit Leerraum (C-2): der Link bleibt sauber, eine unbrauchbare Basis fällt beim Aufbau ----------
from tinysesam.errors import ConfigError as _CfgErr
_db2 = os.path.join(tempfile.mkdtemp(), "t.db")
_a2 = TinySesam(TinySesamConfig(db_path=_db2, rp_name="T", passkey_enabled=False, oidc_enabled=False,
                                cookie_secure=False, password_reset_enabled=True,
                                base_url="https://auth.example.com "))
_post = []
_a2.set_mailer(lambda to, subject, text, html=None: _post.append(text))
_a2.create_user("lea", password="geheim12345", email="lea@example.com")
_a2.send_password_reset("lea@example.com", _a2.cfg.base_url)
assert _post and " " not in _post[0].split("https://auth.example.com", 1)[1].split()[0] \
    and "https://auth.example.com/auth/reset" in _post[0], _post
try:
    TinySesam(TinySesamConfig(db_path=_db2, rp_name="T", passkey_enabled=False, oidc_enabled=False,
                              cookie_secure=False, password_reset_enabled=True, base_url="auth.example.com"))
    raise AssertionError("base_url ohne Schema wurde angenommen")
except _CfgErr as e:
    assert "base_url" in str(e), e
os.remove(_db2)
print("  (C-2) base_url wird getrimmt, ohne Schema abgewiesen ok")

os.remove(db)
print("\nRECOVERY + RESET OK ✅")

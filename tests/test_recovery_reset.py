"""Batch C: TOTP-Recovery-Codes (one-shot) + Forgot-Password (Reset per E-Mail)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import time
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
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
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

# ---------- B2-7: ein verbrauchter Recovery-Code wird nachgehalten und gemeldet ----------
# (Mutationsprobe: in `verify_recovery_code` direkt `return self.store.consume_recovery_code(…)`
# wie vor T-13 → rot: keine Audit-Zeile, kein Ereignis.)
db_r = os.path.join(tempfile.mkdtemp(), "r.db")
auth_r = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_r, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False, recovery_code_count=4,
                                   password_reset_enabled=True, base_url="https://auth.example.com"))
post_r = []
auth_r.set_mailer(lambda to, s, t, html=None: post_r.append(t))
ereig_r = []
auth_r.on_security_event = lambda e, k, d: ereig_r.append((e, d))
uid_r = auth_r.create_user("rita", "rita-geheim-1", email="rita@example.com")
geheim_r = auth_r.totp_begin(uid_r)["secret"]
auth_r.totp_confirm(uid_r, pyotp.TOTP(geheim_r).at(time.time() - 30))
codes_r = auth_r.generate_recovery_codes(uid_r)
app_r = FastAPI()
app_r.include_router(auth_r.router())
cr = TestClient(app_r)
cr.post("/auth/login", data={"username": "rita", "password": "rita-geheim-1"}, follow_redirects=False)
assert cr.post("/auth/totp", data={"code": codes_r[0], "next": "/"}, follow_redirects=False).status_code == 303
zeilen = [z for z in auth_r.store.recent_audit(20) if z["event"] == "recovery_used"]
assert len(zeilen) == 1 and "verbleibend=3" in zeilen[0]["detail"], zeilen
assert ("recovery_code_used", {"verbleibend": 3}) in ereig_r, ereig_r
seite = cr.get("/auth/account").text
assert "Nur noch 3 Recovery-Codes" in seite, "die Kontoseite nennt den knappen Rest nicht"
auth_r.generate_recovery_codes(uid_r)
assert "4 Recovery-Codes übrig" in cr.get("/auth/account").text
assert [e for e, _ in ereig_r] == ["totp_enabled", "recovery_codes_generated", "recovery_code_used",
                                   "recovery_codes_generated"], ereig_r
ok("B2-7: Recovery-Verbrauch → Audit mit Rest, Ereignis, Anzeige auf der Kontoseite")

# ---------- R4-14: der Selbstbedienungs-Reset widerruft die API-Keys ----------
# (Mutationsprobe: `revoke_user_api_keys` in reset_submit streichen → rot.)
key_r = auth_r.create_api_key(uid_r, name="ci")["key"]
assert auth_r.verify_api_key(key_r)[0] is not None
auth_r.send_password_reset("rita@example.com", auth_r.cfg.base_url)
tok_r = re.search(r"/auth/reset\?token=([\w\-]+)", post_r[-1]).group(1)
# Erst die Regel: ein schwaches Passwort wird abgelehnt und lässt den Link gültig.
r = cr.post("/auth/reset", data={"token": tok_r, "password": "Rita2024!"})
assert r.status_code == 400 and "leicht zu erraten" in r.text
assert auth_r.peek_magic(tok_r, purpose="reset_password"), "ein abgelehntes Passwort entwertet den Link"
r = cr.post("/auth/reset", data={"token": tok_r, "password": "ein-frisches-passwort"}, follow_redirects=False)
assert r.status_code == 303
assert auth_r.verify_api_key(key_r)[0] is None, "der API-Key überlebt den Reset"
assert auth_r.store.count_active_api_keys(uid_r) == 0
assert any(z["event"] == "password_reset" and "api_keys_revoked=1" in (z["detail"] or "")
           for z in auth_r.store.recent_audit(20))
assert ereig_r[-1][0] == "password_changed"
ok("R4-14: Passwort-Reset per Mail widerruft die API-Keys (und prüft die Passwortregel)")

# A-8: Ein toter Link geht der Passwortregel vor — sonst hiess es „zu leicht", und erst der
# zweite Versuch verriet, dass der Link nicht mehr gilt. (tok_r ist oben verbraucht.)
for _tok in ("quatsch", tok_r):
    r = cr.post("/auth/reset", data={"token": _tok, "password": "password"})
    assert r.status_code == 400 and auth_r.t("magic.invalid") in r.text, r.text[:300]
    assert "leicht zu erraten" not in r.text
ok("A-8: ungültiger oder verbrauchter Link → „Link ungültig“ vor der Passwortregel")
auth_r.totp_disable(uid_r)
assert ereig_r[-1] == ("totp_disabled", {"recovery_codes_geloescht": 4}), ereig_r[-1]
os.remove(db_r)

os.remove(db)
print("\nRECOVERY + RESET OK ✅")

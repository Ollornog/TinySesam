"""End-to-End-Test des Passwort- + TOTP-Kerns via FastAPI-TestClient (ohne Browser)."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import time
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
                                 oidc_enabled=False, cookie_secure=False))
assert auth.ensure_admin("admin", "geheim123"), "admin sollte angelegt werden"
assert not auth.ensure_admin("x", "y"), "zweiter ensure_admin darf nichts tun"

app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"user": u["username"], "admin": bool(u["is_admin"])}


c = TestClient(app)


def ok(name):
    print(f"  ✓ {name}")


# 1) ohne Login → 401 (JSON-Client)
assert c.get("/geheim").status_code == 401
ok("geschützt ohne Login → 401")

# 2) Login-Seite rendert
r = c.get("/auth/login")
assert r.status_code == 200 and "Passwort" in r.text
ok("Login-Seite")

# 3) falsches Passwort
assert c.post("/auth/login", data={"username": "admin", "password": "falsch", "next": "/geheim"}).status_code == 401
ok("falsches Passwort → 401")

# 4) richtiges Passwort (noch kein TOTP) → 303 + Cookie, kein MFA
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and "set-cookie" in {k.lower() for k in r.headers}
ok("Login ohne 2FA → eingeloggt")

# 5) geschützt jetzt erreichbar
r = c.get("/geheim")
assert r.status_code == 200 and r.json()["user"] == "admin"
ok("geschützt mit Session erreichbar")
assert c.get("/auth/me").json()["authenticated"] is True
ok("/auth/me authenticated")

# 6) TOTP einrichten
uid = auth.store.get_user_by_name("admin")["id"]
secret = auth.totp_begin(uid)["secret"]
assert auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30)) and auth.store.has_confirmed_totp(uid)
ok("TOTP eingerichtet")

# 7) Logout → Login jetzt MFA-pflichtig
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
assert c.get("/geheim").status_code == 401, "mit 2FA-pending noch nicht voll eingeloggt"
ok("Login mit TOTP → 2FA-Schritt verlangt")

# 8) falscher + richtiger TOTP-Code
assert c.post("/auth/totp", data={"code": "000000", "next": "/geheim"}).status_code == 401
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303
assert c.get("/geheim").json()["user"] == "admin"
ok("TOTP korrekt → voll eingeloggt")

# 9) Rollen (optional)
auth.set_roles(uid, ["editor"])
u = auth.store.get_user(uid)
assert auth.has_role(u, "editor") and auth.has_role(u, "irgendwas")  # admin ⇒ alle Rollen
auth.store.set_disabled(uid, False)
ok("Rollen + Admin-Override")

# ---------- B2-3: der Einrichtungscode ist verbraucht ----------
# Bis T-13 buchte `totp_confirm` den Zeitschritt nicht: derselbe Code, eben zur Einrichtung
# eingetippt, meldete danach noch bis zu 90 Sekunden an. (Mutationsprobe: in `totp_confirm`
# `_totp.verify(...)` statt `passender_schritt` + `totp_step_verbrauchen` → rot.)
db_b = os.path.join(tempfile.mkdtemp(), "b.db")
auth_b = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_b, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False))
uid_b = auth_b.create_user("berta", "berta-geheim-1")
_ereig = []
auth_b.on_security_event = lambda e, k, d: _ereig.append(e)
geheim_b = auth_b.totp_begin(uid_b)["secret"]
code_b = pyotp.TOTP(geheim_b).now()
assert auth_b.totp_confirm(uid_b, code_b)
assert not auth_b.verify_totp(uid_b, code_b), "der Einrichtungscode meldet danach noch an"
assert not auth_b.totp_confirm(uid_b, code_b), "…und bestätigt ein zweites Mal"
assert _ereig == ["totp_enabled"], _ereig
assert any(z["event"] == "totp_setup_confirm" for z in auth_b.store.recent_audit(20))
ok("B2-3: der Einrichtungscode gilt genau einmal (danach auch an /auth/totp nicht mehr)")

# ---------- B2-12 / R3-6: Drossel, eigener Topf und Protokoll an der Einrichtungsbestätigung ----------
# (Mutationsprobe: die `is_totp_setup_locked`-Abfrage in router.totp_setup_confirm streichen → rot.)
auth_b.totp_disable(uid_b)
app_b = FastAPI()
app_b.include_router(auth_b.router())
cb = TestClient(app_b)
assert cb.post("/auth/login", data={"username": "berta", "password": "berta-geheim-1"},
               follow_redirects=False).status_code == 303
geheim_b = auth_b.totp_begin(uid_b)["secret"]
grenze = auth_b.sec("totp_setup_max_attempts")
antworten = [cb.post("/auth/totp/setup", data={"code": "000000"}).json().get("ok") for _ in range(grenze)]
assert antworten == [False] * grenze, antworten
r = cb.post("/auth/totp/setup", data={"code": pyotp.TOTP(geheim_b).now()})
assert r.status_code == 429, f"nach {grenze} Fehlgriffen muss die Bestätigung sperren, war {r.status_code}"
assert not auth_b.store.has_confirmed_totp(uid_b)
fehl = [z for z in auth_b.store.recent_audit(50) if z["event"] == "login_fail" and "totp_setup" in (z["detail"] or "")]
assert len(fehl) >= grenze, "jeder Fehlgriff steht im Audit-Log"
# Eigener Topf: Die Anmeldung desselben Kontos bleibt offen.
assert not auth_b.is_locked("berta", "testclient")
assert TestClient(app_b).post("/auth/login", data={"username": "berta", "password": "berta-geheim-1"},
                              follow_redirects=False).status_code == 303
ok("B2-12/R3-6: Einrichtungsbestätigung gedrosselt, gesperrt, protokolliert — Login bleibt offen")
os.remove(db_b)

os.remove(db)
print("\nALLE TESTS OK ✅")

"""Härtung: Brute-Force-Lockout (pro User), Attempt-Tracking, Audit-Log, Panel-Settings."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, trusted_proxies=["127.0.0.1/32"]))
auth.ensure_admin("admin", "geheim123")

# Härtung schärfer stellen (wie im Admin-Panel) und persistent prüfen
auth.set_security("max_login_attempts", 3)
assert auth.sec("max_login_attempts") == 3

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

# 3 Fehlversuche → danach gesperrt, auch mit RICHTIGEM Passwort
for i in range(3):
    assert c.post("/auth/login", data={"username": "admin", "password": "falsch"}).status_code == 401, i
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123"})
assert r.status_code == 429, f"nach Lockout erwartet 429, war {r.status_code}"
print("  ✓ Lockout nach 3 Fehlversuchen (blockt auch korrektes Passwort)")

fails = [a for a in auth.store.recent_audit(20) if a["event"] == "login_fail"]
assert len(fails) >= 3
print(f"  ✓ Audit-Log: {len(fails)}× login_fail")

# Entsperren (Admin) → Login wieder möglich + login-Audit
auth.store.clear_fails(username="admin")
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False)
assert r.status_code == 303
assert any(a["event"] == "login" for a in auth.store.recent_audit(5))
print("  ✓ nach Entsperren Login OK + login-Audit")

# Settings-Roundtrip (Panel-editierbar)
auth.set_security("rate_limit_max", 99)
assert auth.sec("rate_limit_max") == 99 and auth.all_security()["rate_limit_max"] == 99
print("  ✓ Härtungs-Settings persistent + über all_security() lesbar")

# Trusted-Proxy: XFF nur von vertrauenswürdigem Peer
from tinysesam import security
class Req:  # Minimal-Fake
    def __init__(self, host, xff=None):
        self.client = type("C", (), {"host": host})()
        self.headers = {"x-forwarded-for": xff} if xff else {}
assert security.client_ip(Req("127.0.0.1", "9.9.9.9"), ["127.0.0.1/32"]) == "9.9.9.9"      # trusted Proxy → XFF gilt
assert security.client_ip(Req("8.8.8.8", "9.9.9.9"), ["127.0.0.1/32"]) == "8.8.8.8"        # untrusted Peer → XFF ignoriert
print("  ✓ echte Client-IP: XFF nur hinter vertrauenswürdigem Proxy")

# ---------- R4-10: /auth/password ist kein Passwort-Orakel ----------
# Angriff: Die Alt-Passwort-Prüfung dieser Route lief ohne rate_ok/is_locked/record_login UND
# löste das Konto über die Login-Kennung auf (`check_password(u["username"], …)` → find_user)
# statt über die ID der eigenen Sitzung. Wer ein Konto namens "chef@example.com" besitzt,
# während das Konto "chef" genau diese E-Mail trägt, riet darüber unbegrenzt und lautlos das
# Passwort des FREMDEN Kontos — kein 429, kein Fehlversuch, kein Protokolleintrag, und der
# Treffer setzte still das eigene Passwort (der Angriff blieb also auch im Erfolg unsichtbar).
AT = chr(64)          # keine Adresse im Klartext im Quelltext
def _mail(lokal): return lokal + AT + "example.com"

db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False))
auth2.set_security("max_login_attempts", 3)
app2 = FastAPI()
app2.include_router(auth2.router())
OPFER_PW = "Opfer-Passwort-2026"
ANG_PW = "Angreifer-Passwort-1"
uid_opfer = auth2.create_user("chef", OPFER_PW, email=_mail("chef"), is_admin=True)
# Die Kollision entsteht hier über create_user (Admin-Weg) — damit hängt diese Prüfung NICHT
# daran, ob die Selbstregistrierung den zweiten Namensraum inzwischen kreuzweise absichert.
uid_ang = auth2.create_user(_mail("chef"), ANG_PW, email=_mail("eve"))

# Vorbedingung: Die Kennung des Angreifers zeigt tatsächlich auf das fremde Konto. Ohne sie
# liefe der Angriff ins Leere und der Test bewiese nichts.
assert auth2.find_user(_mail("chef"))["id"] == uid_opfer != uid_ang, "Angriffslage nicht hergestellt"

ang = TestClient(app2)
tok, _ = auth2.start_session(uid_ang, "password", remember=True)
ang.cookies.set(auth2.cfg.session_cookie, tok)

# (a) Das RICHTIGE Passwort des Opfers ist für diese Sitzung kein Treffer mehr.
r = ang.post("/auth/password", json={"current": OPFER_PW, "new": "neues-langes-passwort"})
assert r.status_code == 403, f"fremdes Passwort wurde akzeptiert: {r.status_code}"
assert auth2.check_password("chef", OPFER_PW) is not None, "Passwort des Opfers wurde verändert"
print("  ✓ /auth/password prüft die eigene Konto-ID, nicht die aufgelöste Login-Kennung")

# (b) Raten wird gedrosselt: spätestens nach max_login_attempts kommt 429 statt 403.
auth2.store.clear_fails(username=_mail("chef"))
codes = [ang.post("/auth/password", json={"current": f"falsch{i}", "new": "neues-langes-passwort"}).status_code
         for i in range(auth2.sec("max_login_attempts") + 2)]
assert 429 in codes, f"kein Lockout auf /auth/password: {codes}"
assert auth2.store.count_fails(0, username=_mail("chef")) >= auth2.sec("max_login_attempts"), \
    "Fehlversuche wurden nicht verbucht"
assert any(a["event"] == "login_fail" and "password_change" in (a["detail"] or "")
           for a in auth2.store.recent_audit(20)), "kein Protokolleintrag zum Fehlversuch"
print("  ✓ Alt-Passwort-Raten läuft in Sperre + Protokoll (429, login_attempt, Audit-Log)")

# (c) Der legitime Weg funktioniert weiter — mit dem EIGENEN Passwort.
auth2.store.clear_fails(username=_mail("chef"))
r = ang.post("/auth/password", json={"current": ANG_PW, "new": "neues-langes-passwort"})
assert r.status_code == 200, f"eigener Passwortwechsel scheitert: {r.status_code} {r.text[:120]}"
assert auth2.verify_user_password(uid_ang, "neues-langes-passwort"), "neues Passwort nicht gesetzt"
assert auth2.check_password("chef", OPFER_PW) is not None, "fremdes Konto angefasst"
print("  ✓ eigener Passwortwechsel unverändert möglich")

os.remove(db2)

os.remove(db)
print("\nHÄRTUNG OK ✅")

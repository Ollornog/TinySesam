"""Härtung: Brute-Force-Lockout (pro User), Attempt-Tracking, Audit-Log, Panel-Settings."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, passkey_enabled=False, oidc_enabled=False,
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

os.remove(db)
print("\nHÄRTUNG OK ✅")

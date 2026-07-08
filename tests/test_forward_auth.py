"""Phase 8: Forward-Auth (Reverse-Proxy-Verify-Endpoint) + next zurück auf die App."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", 
    db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
    forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com"]))
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
auth.store._exec("UPDATE users SET email=?, roles=? WHERE id=?",
                 ("admin@example.com", '["editor"]', uid))

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/geheim"}

# nicht eingeloggt → 401 + Login-URL mit next zurück auf die App
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 401
loc = r.headers.get("X-TinySesam-Location")
assert loc and loc.startswith("https://auth.example.com/auth/login?next=")
assert "app.example.com" in loc
ok("nicht eingeloggt → 401 + X-TinySesam-Location (zentraler Login, next=App-URL)")

# eingeloggt (Session) → 200 + Remote-*-Header
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200
assert r.headers["Remote-User"] == "admin"
assert r.headers["Remote-Email"] == "admin@example.com"
assert "editor" in r.headers["Remote-Groups"] and "admin" in r.headers["Remote-Groups"]
ok("eingeloggt → 200 + Remote-User/Email/Groups")

# /auth/verify Alias verhält sich gleich
assert c.get("/auth/verify", headers=PROXY).status_code == 200
ok("/auth/verify Alias funktioniert")

# API-Key erfüllt Forward-Auth (maschinell)
key = auth.create_api_key(uid, name="k")["key"]
c2 = TestClient(app)
r = c2.get("/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and r.headers["Remote-User"] == "admin"
ok("API-Key → 200 (maschineller Zugang)")

# Open-Redirect-Schutz: safe_next lässt die App-URL nur wegen trusted_redirect_hosts durch
assert auth.safe_next("https://app.example.com/geheim") == "https://app.example.com/geheim"
assert auth.safe_next("https://evil.com/x") == "/"
ok("safe_next: App-Host erlaubt (trusted_redirect_hosts), Fremd-Host blockiert")

os.remove(db)
print("\nFORWARD-AUTH OK ✅")

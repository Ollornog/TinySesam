"""Admin panel: freely selectable path, mountable at its own prefix, JSON-only (for a custom panel),
HTTPS modes (warn = without certificate with a notice, force = HTTP→HTTPS redirect)."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def fresh(**cfg):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    # cookie_secure=False is the normal case for this suite (TestClient speaks http://),
    # but it must be overridable: case 5 runs https_mode='force', and force together
    # with an insecure cookie is rightly rejected by the constructor.
    kw = dict(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False,
              oidc_enabled=False, cookie_secure=False)
    kw.update(cfg)
    a = TinySesam(TinySesamConfig(**kw))
    a.ensure_admin("a", "pw")
    return a, db


def login(app):
    c = TestClient(app)
    c.post("/auth/login", data={"username": "a", "password": "pw"})
    return c


# 1) freely chosen path
a, db = fresh(admin_path="/verwaltung")
app = FastAPI(); app.include_router(a.router())
c = login(app)
assert c.get("/verwaltung/api/users").status_code == 200
assert c.get("/verwaltung").status_code == 200 and "Admin" in c.get("/verwaltung").text
assert c.get("/auth/admin/api/users").status_code == 404
os.remove(db)
print("  ✓ Admin panel at a freely selectable path (/verwaltung)")

# 2) mount admin_router() yourself, auto-mount off
a, db = fresh(admin_enabled=False)
app = FastAPI(); app.include_router(a.router()); app.include_router(a.admin_router(), prefix="/adminx")
c = login(app)
assert c.get("/adminx/api/users").status_code == 200
assert c.get("/auth/admin/api/users").status_code == 404
os.remove(db)
print("  ✓ admin_router() mountable at its own prefix (auto-mount off)")

# 3) JSON API only (UI disabled for embedding in an existing panel)
a, db = fresh(admin_ui_enabled=False)
app = FastAPI(); app.include_router(a.router())
c = login(app)
assert c.get("/auth/admin/api/users").status_code == 200
assert c.get("/auth/admin").status_code == 404
os.remove(db)
print("  ✓ admin_ui_enabled=False → JSON API only")

# 4) https_mode=warn → runs without a certificate, warning notice in the panel
a, db = fresh(https_mode="warn")
app = FastAPI(); a.install_https(app); app.include_router(a.router())
c = login(app)
assert "Unverschlüsselt" in c.get("/auth/admin").text
os.remove(db)
print("  ✓ https_mode=warn: usable without certificate + warning notice")

# 5) https_mode=force → HTTP is redirected to HTTPS
# cookie_secure=True is mandatory here, not decoration: force + insecure cookie is rejected by the
# constructor (the app would otherwise redirect to HTTPS and still issue the cookie without the
# Secure flag). This case does not sign in anyway — it only checks the redirect.
a, db = fresh(https_mode="force", cookie_secure=True)
app = FastAPI(); a.install_https(app); app.include_router(a.router())
r = TestClient(app).get("/auth/login", follow_redirects=False)
assert r.status_code in (307, 308) and r.headers["location"].startswith("https://")
os.remove(db)
print("  ✓ https_mode=force: HTTP → HTTPS redirect")

print("\nADMIN-MOUNT / HTTPS OK ✅")

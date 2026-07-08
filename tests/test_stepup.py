"""Phase 2: Step-up / per-Route-MFA (Flag am Guard), Reauth-Frische, admin_require_mfa."""
import tempfile, os, time
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, stepup_max_age_sec=900))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/normal")
def normal(u=Depends(auth.require_user)):
    return {"u": u["username"]}


@app.get("/sudo")
def sudo(u=Depends(auth.require(mfa=True))):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}
uid = auth.store.get_user_by_name("admin")["id"]


def stale():
    """mfa_at der aktuellen Sitzung künstlich altern lassen."""
    tok = c.cookies.get("tinysesam_session")
    auth.store._exec("UPDATE session SET mfa_at=? WHERE token=?", (int(time.time()) - 100000, tok))


# ---------- frisch nach Login → sudo erreichbar ----------
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.get("/normal", headers=JSON).status_code == 200
assert c.get("/sudo", headers=JSON).status_code == 200
ok("frische Sitzung: require_user UND require(mfa=True) erreichbar")

# ---------- Frische abgelaufen → normal ok, sudo blockt (403 + Reauth-Header) ----------
stale()
assert c.get("/normal", headers=JSON).status_code == 200, "normale Route bleibt erreichbar"
r = c.get("/sudo", headers=JSON)
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", (r.status_code, dict(r.headers))
ok("abgelaufene Frische: JSON-Client → 403 + X-TinySesam-Reauth")

# Browser (Accept: text/html) → Redirect auf /auth/reauth
r = c.get("/sudo", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"] == "/auth/reauth?next=/sudo", r.headers.get("location")
ok("abgelaufene Frische: Browser → 307 /auth/reauth?next=/sudo")

# ---------- Reauth per Passwort (User ohne TOTP) → wieder frisch ----------
r = c.get("/auth/reauth", follow_redirects=False)
assert r.status_code == 200 and "Passwort" in r.text
assert c.post("/auth/reauth", data={"password": "falsch", "next": "/sudo"}).status_code == 401
r = c.post("/auth/reauth", data={"password": "geheim123", "next": "/sudo"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/sudo"
assert c.get("/sudo", headers=JSON).status_code == 200
ok("Reauth per Passwort → sudo wieder erreichbar")

# ---------- API-Key erfüllt Step-up NICHT ----------
key = auth.create_api_key(uid, name="k")["key"]
assert c.get("/normal", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 200
# frische Session-Cookies raus, nur Key
c2 = TestClient(app)
assert c2.get("/normal", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 200
assert c2.get("/sudo", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 403
ok("API-Key: require_user ok, require(mfa=True) → 403 (kein interaktiver Faktor)")

# ---------- admin_require_mfa mit TOTP-User ----------
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).now())
auth.cfg.admin_require_mfa = True
c3 = TestClient(app)
# Login → TOTP-Schritt → voll eingeloggt (frisch)
c3.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
c3.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
r = c3.get("/auth/admin", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 200, r.status_code
# altern → Admin-Panel verlangt Reauth
tok = c3.cookies.get("tinysesam_session")
auth.store._exec("UPDATE session SET mfa_at=? WHERE token=?", (int(time.time()) - 100000, tok))
r = c3.get("/auth/admin", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and "/auth/reauth" in r.headers["location"], r.headers.get("location")
# Reauth verlangt jetzt TOTP (nicht Passwort)
assert "Authenticator" in c3.get("/auth/reauth").text
r = c3.post("/auth/reauth", data={"code": pyotp.TOTP(secret).now(), "next": "/auth/admin"}, follow_redirects=False)
assert r.status_code == 303
assert c3.get("/auth/admin", headers={"Accept": "text/html"}).status_code == 200
ok("admin_require_mfa: Panel altert → Reauth per TOTP → wieder frei")

os.remove(db)
print("\nSTEP-UP OK ✅")

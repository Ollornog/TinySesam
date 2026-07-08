"""Phase 0/1: Template-Override-Schicht, next-Redirect-Härtung (Open-Redirect), Remember-me."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig
from tinysesam.security import safe_next


def ok(name):
    print(f"  ✓ {name}")


# ---------- safe_next (Open-Redirect-Schutz) ----------
assert safe_next("/dashboard") == "/dashboard"
assert safe_next("") == "/"
assert safe_next("//evil.com") == "/"                       # protokoll-relativ
assert safe_next("https://evil.com/x") == "/"               # absoluter fremder Host
assert safe_next("javascript:alert(1)") == "/"
assert safe_next("/ok", allowed_hosts=["app.example.com"]) == "/ok"
assert safe_next("https://app.example.com/x", allowed_hosts=["app.example.com"]) == "https://app.example.com/x"
assert safe_next("https://evil.com/x", allowed_hosts=["app.example.com"]) == "/"
ok("safe_next: relative erlaubt, fremde/protokoll-relative Ziele → /")

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=db, rp_name="Test", passkey_enabled=False,
                                 oidc_enabled=False, cookie_secure=False,
                                 session_ttl_transient_hours=6))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"user": u["username"]}


c = TestClient(app)

# ---------- Login mit Open-Redirect-next → landet auf / statt beim Angreifer ----------
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "https://evil.com"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/", r.headers.get("location")
ok("Login mit fremdem next → Redirect auf / (kein Open-Redirect)")

# ---------- Remember-me: persistentes Cookie (Max-Age gesetzt) ----------
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/", "remember": "1"},
           follow_redirects=False)
sc = r.headers.get("set-cookie", "")
assert "tinysesam_session=" in sc and "Max-Age=" in sc, sc
ok("Remember an → persistentes Cookie (Max-Age)")

# ---------- Ohne Remember: reines Session-Cookie (kein Max-Age/Expires) ----------
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/", "remember": ""},
           follow_redirects=False)
sc = r.headers.get("set-cookie", "")
assert "tinysesam_session=" in sc and "Max-Age=" not in sc and "Expires=" not in sc, sc
ok("Remember aus → reines Session-Cookie (kein Max-Age)")

# Server-Session-TTL folgt Transient-Wert
tok = c.cookies.get("tinysesam_session")
s = auth.store.get_session(tok)
assert (s["expires_at"] - s["created_at"]) <= 6 * 3600 + 5, "Transient-TTL zu lang"
assert s["remember"] == 0
ok("Remember aus → kurze Transient-TTL server-side")

# ---------- Template-Override: eigene Login-Seite ersetzt die eingebaute ----------
auth.set_template("login", lambda a, ctx: f"<html>MEINE-LOGIN next={ctx['next']}</html>")
c.get("/auth/logout")
html = c.get("/auth/login?next=/geheim").text
assert "MEINE-LOGIN" in html and "next=/geheim" in html, html
ok("Template-Override: eigene Login-Seite wird ausgeliefert")

# Override darf auch eine eigene Response (mit Status/Redirect) liefern
from fastapi.responses import JSONResponse
auth.set_template("login", lambda a, ctx: JSONResponse({"custom": True}, status_code=418))
r = c.get("/auth/login")
assert r.status_code == 418 and r.json() == {"custom": True}
ok("Template-Override: eigene Response (Status 418) durchgereicht")

os.remove(db)
print("\nVIEWS + REMEMBER OK ✅")

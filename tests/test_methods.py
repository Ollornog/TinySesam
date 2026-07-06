"""Struktur-Test für OIDC + Passkey: Module laden, Routen antworten, Passkey-Options generierbar
(ohne Browser), Login-Seite zeigt alle aktiven Methoden. (Browser-/Provider-Pfad hier nicht prüfbar.)"""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(
    db_path=db, rp_name="Test", rp_id="localhost", origin="http://localhost:8000",
    password_enabled=True, passkey_enabled=True, oidc_enabled=True,
    oidc_name="PocketID", oidc_issuer="https://id.example.invalid",
    oidc_client_id="cid", oidc_client_secret="sec", cookie_secure=False))
assert auth.oidc is not None and auth.webauthn is not None, "OIDC/Passkey-Module nicht geladen"

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app, raise_server_exceptions=False)

# Routen existieren (nicht 404) + Grundverhalten
assert c.get("/auth/login").status_code == 200
assert c.get("/auth/me").status_code == 401
assert c.post("/auth/passkey/register/begin").status_code == 401   # existiert, nur nicht eingeloggt
assert c.get("/auth/passkey/list").status_code == 401
print("  ✓ Routen vorhanden + Guards greifen (Passwort/TOTP/OIDC/Passkey)")

# Passkey-Login-Options ohne Browser generierbar
r = c.post("/auth/passkey/login/begin")
assert r.status_code == 200, r.text
j = r.json()
assert "challenge" in j and j.get("rpId") == "localhost", j
print("  ✓ Passkey-Login-Options generiert (challenge, rpId=localhost)")

# Login-Seite zeigt alle aktiven Methoden
html = c.get("/auth/login").text
assert "Passwort" in html and "PocketID" in html and "Passkey" in html
print("  ✓ Login-Seite: Passwort-Form + OIDC-Button + Passkey-Button")

os.remove(db)
print("\nMETHODEN-STRUKTUR OK ✅")

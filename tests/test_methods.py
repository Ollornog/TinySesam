"""Struktur-Test für OIDC + Passkey: Module laden, Routen antworten, Passkey-Options generierbar
(ohne Browser), Login-Seite zeigt alle aktiven Methoden. (Browser-/Provider-Pfad hier nicht prüfbar.)"""

# Diese Suite baut absichtlich eine App MIT Passkey und OIDC — ohne die Extras gibt es nichts
# zu pruefen. Das ist eine fehlende Voraussetzung dieser Suite, kein Fehler der Bibliothek:
# genau diese Unterscheidung hat der Runner frueher nicht getroffen.
from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("webauthn", extra="passkey")
braucht_modul("authlib", extra="oidc")
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", 
    db_path=db, rp_name="Test", rp_id="localhost", origin="http://localhost:8000",
    password_enabled=True, passkey_enabled=True, oidc_enabled=True,
    oidc_name="PocketID", oidc_issuer="https://id.example.invalid",
    oidc_client_id="cid", oidc_client_secret="sec", cookie_secure=False,
    # Pflicht bei oidc_enabled: Die Redirect-URI geht zum IdP und darf nicht aus dem
    # Host-Header kommen (R4-01).
    base_url="https://auth.example.com"))
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

# ---------- register/finish bindet den Passkey ans ANGEMELDETE Konto (N5) ----------
# Zusage im CHANGELOG: „`register/finish` bindet den neuen Passkey zusätzlich an das angemeldete
# Konto statt nur an das Flow-Cookie." Gemessen hat das niemand: Mutation M15 (die Zeile
# `if flow["user_id"] != u["id"]` gestrichen) lief mit 46/46 grün durch, und `grep -rn "wareg:"
# tests/` fand keine Zeile, die einen FREMDEN Flow unterschiebt. Der Riegel ist die Antwort auf
# „wer über eine Subdomain ein Cookie setzen kann" — genau die Sorte Schutz, die still
# verschwindet, weil ihr Fehlen im Normalbetrieb nichts ändert.
FLOW = "tinysesam_waflow"
a_id = auth.create_user("konto_a", password="Geheim12345!")
b_id = auth.create_user("konto_b", password="Geheim12345!")


def _sitzung(uid):
    cx = TestClient(app, raise_server_exceptions=False)
    cx.cookies.set(auth.cfg.session_cookie, auth.store.create_session(uid, 3600, True, "password"))
    return cx


c_a = _sitzung(a_id)
r_begin = c_a.post("/auth/passkey/register/begin")
assert r_begin.status_code == 200, r_begin.text[:150]
flow_a = c_a.cookies.get(FLOW)
assert flow_a, "register/begin setzt kein Flow-Cookie — dann schiebt der Angriff unten nichts unter"

# Der Angriff: B ist angemeldet und bringt den Flow von A mit.
c_b = _sitzung(b_id)
c_b.cookies.set(FLOW, flow_a)
r_fremd = c_b.post("/auth/passkey/register/finish", json={})
assert r_fremd.status_code == 400, (
    f"fremder Flow → HTTP {r_fremd.status_code}: {r_fremd.text[:150]!r} — ohne den Riegel läuft "
    "die Registrierung weiter und der Passkey landet am falschen Konto")
assert r_fremd.json().get("detail") == auth.t("api.passkey_reg_expired"), r_fremd.text[:150]
assert auth.store.list_webauthn(a_id) == [], "ein Passkey kam an A dazu"
assert auth.store.list_webauthn(b_id) == [], "ein Passkey kam an B dazu"

# Gegenprobe: Mit dem EIGENEN Flow scheitert derselbe (leere) Körper an einer anderen Stelle —
# sonst wäre „400 für jeden" auch grün und der Riegel gar nicht gemessen.
c_a2 = _sitzung(a_id)
assert c_a2.post("/auth/passkey/register/begin").status_code == 200
r_eigen = c_a2.post("/auth/passkey/register/finish", json={})
assert not (r_eigen.status_code == 400
            and r_eigen.json().get("detail") == auth.t("api.passkey_reg_expired")), (
    "der eigene Flow wird genauso abgewiesen wie der fremde — dann misst die Prüfung oben nur, "
    f"dass finish() mit leerem Körper scheitert (HTTP {r_eigen.status_code})")
print("  ✓ register/finish: fremder Flow → 400, kein Passkey an einem der beiden Konten")

os.remove(db)
print("\nMETHODEN-STRUKTUR OK ✅")

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


def ok_(name):
    print(f"  ✓ {name}")


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

# ---------- B2-10: ein Passkey ohne Nutzerprüfung ist kein vollwertiger Login ----------
# Ein Passkey meldet in TinySesam ALLEIN an. Ohne Nutzerprüfung belegt er nur den Besitz des
# Schlüssels: der entsperrte Rechner, der eingesteckte Stick, das kurz aus der Hand gelegte
# Telefon. Bis 0.18.x stand in der Anfrage „preferred" UND die Antwort wurde nicht geprüft —
# ein Authenticator konnte also nein sagen und galt trotzdem.
import json as _json_b210                                                  # noqa: E402
from tinysesam.errors import ConfigError as _ConfigError                    # noqa: E402

_opt_reg = _json_b210.loads(_sitzung(a_id).post("/auth/passkey/register/begin").text)
assert _opt_reg["authenticatorSelection"]["userVerification"] == "required", _opt_reg["authenticatorSelection"]
_opt_log = _json_b210.loads(c.post("/auth/passkey/login/begin").text)
assert _opt_log["userVerification"] == "required", _opt_log
ok_("B2-10: Registrierung und Login verlangen die Nutzerprüfung (Vorgabe)")

# Abschaltbar, aber nicht still: Der Aufbau sagt es, und die Konfigurationsprüfung warnt.
_db_p = os.path.join(tempfile.mkdtemp(), "t.db")
_auth_p = TinySesam(TinySesamConfig(db_path=_db_p, csrf_enabled=False, cookie_secure=False,
                                    passkey_enabled=True, rp_id="localhost",
                                    origin="http://localhost:8000",
                                    passkey_user_verification="preferred"))
_app_p = FastAPI()
_app_p.include_router(_auth_p.router())
_opt_p = _json_b210.loads(TestClient(_app_p).post("/auth/passkey/login/begin").text)
assert _opt_p["userVerification"] == "preferred", _opt_p
from tinysesam.konfigpruefung import pruefe as _pruefe                      # noqa: E402
_f, _w = _pruefe(_auth_p.cfg)
assert any("passkey_user_verification" in x for x in _w), _w
ok_("B2-10: 'preferred' ist möglich, meldet sich aber beim Aufbau und in der Konfigprüfung")

# Ein Tippfehler bricht ab, statt die Prüfung stillschweigend abzuschalten.
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                              passkey_enabled=True, rp_id="localhost",
                              origin="http://localhost:8000",
                              passkey_user_verification="egal"))
    raise AssertionError("unbekannter Wert kam durch")
except _ConfigError:
    pass
ok_("B2-10: ein unbekannter Wert für passkey_user_verification bricht den Aufbau ab")

# Drosselung: Der Passkey-Login war die einzige Anmeldestrecke ohne Bremse — und jeder Aufruf
# legte eine flow-Zeile an, die erst nach fünf Minuten verfiel.
_db_r = os.path.join(tempfile.mkdtemp(), "t.db")
_auth_r = TinySesam(TinySesamConfig(db_path=_db_r, csrf_enabled=False, cookie_secure=False,
                                    passkey_enabled=True, rp_id="localhost",
                                    origin="http://localhost:8000"))
_auth_r.store.set_setting("rate_limit_max", "3")
_app_r = FastAPI()
_app_r.include_router(_auth_r.router())
_c_r = TestClient(_app_r)
_codes = [_c_r.post("/auth/passkey/login/begin").status_code for _ in range(6)]
assert 429 in _codes, f"keine Drosselung am Passkey-Login: {_codes}"
ok_("B2-10: der Passkey-Login ist gedrosselt wie jeder andere Einstieg")

# Protokoll: Ein unbekannter Schlüssel ist ein Fehlversuch und trifft die fail2ban-Jail.
import io as _io_b210, logging as _logging_b210                             # noqa: E402
from tinysesam import security as _sec_b210                                 # noqa: E402

# Eigene Instanz: die Drosselung oben hat die vorherige absichtlich dichtgemacht.
_db_l = os.path.join(tempfile.mkdtemp(), "t.db")
_auth_l = TinySesam(TinySesamConfig(db_path=_db_l, csrf_enabled=False, cookie_secure=False,
                                    passkey_enabled=True, rp_id="localhost",
                                    origin="http://localhost:8000"))
_app_l = FastAPI()
_app_l.include_router(_auth_l.router())
_puffer_b = _io_b210.StringIO()
_haken_b = _logging_b210.StreamHandler(_puffer_b)
_sec_b210.seclog.addHandler(_haken_b)
try:
    _c_l = TestClient(_app_l)
    _c_l.post("/auth/passkey/login/begin")
    _c_l.post("/auth/passkey/login/finish", content=_json_b210.dumps({"id": "gibtsnicht"}))
finally:
    _sec_b210.seclog.removeHandler(_haken_b)
_text_b = _puffer_b.getvalue()
assert _sec_b210.log_ereignis("passkey") in _text_b, f"keine Jail-Zeile: {_text_b[:200]!r}"
assert "unbekannter_schluessel" in _text_b, _text_b[:200]
assert any(e["event"] == "passkey_unknown" for e in _auth_l.store.recent_audit(limit=10))
ok_("B2-10: eine Passkey-Fehlanmeldung steht im Protokoll und trifft die Jail")

for _d in (_db_p, _db_r, _db_l):
    os.remove(_d)

os.remove(db)
print("\nMETHODEN-STRUKTUR OK ✅")

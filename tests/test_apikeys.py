"""API-Keys + Service-/Daemon-Accounts: Zugang per Key, Rollen-Scope, Widerruf (sperren), Ablauf."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False, cookie_secure=False))
auth.ensure_admin("admin", "pw")

app = FastAPI()
app.include_router(auth.router())


@app.get("/who")
def who(u=Depends(auth.require_user)):
    return {"user": u["username"], "via": u.get("_via")}


@app.get("/editor")
def editor(u=Depends(auth.require_role("editor"))):
    return {"ok": True}


c = TestClient(app)

# System-/Service-Account für einen Daemon: kein Login, nur Key, Rolle 'editor'
svc = auth.create_service("backup-daemon", roles=["editor"])
res = auth.create_api_key(svc, name="nightly-backup")
key = res["key"]
assert key.startswith("tsk_") and res["prefix"].startswith("tsk_")
print("  ✓ Service-Account + API-Key erzeugt:", res["prefix"])

# Zugang per Key — ganz ohne Session/Login
r = c.get("/who", headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 200 and r.json() == {"user": "backup-daemon", "via": "apikey"}
assert c.get("/who", headers={"X-API-Key": key}).status_code == 200
print("  ✓ Zugang per Bearer- und X-API-Key-Header")

# Rollen-Scope greift auch per Key
assert c.get("/editor", headers={"X-API-Key": key}).status_code == 200
print("  ✓ require_role über Key (Service hat 'editor')")

# kein/falscher Key → 401
assert c.get("/who").status_code == 401
assert c.get("/who", headers={"X-API-Key": "tsk_falsch"}).status_code == 401
print("  ✓ kein/ungültiger Key → 401")

# Widerruf = sperren (nicht löschen) → sofort ungültig, Key bleibt in der Liste
kid = auth.list_api_keys(svc)[0]["id"]
auth.revoke_api_key(kid)
assert c.get("/who", headers={"X-API-Key": key}).status_code == 401
assert any(k["revoked"] for k in auth.list_api_keys(svc))
print("  ✓ Widerruf wirkt sofort (Key gesperrt, nicht gelöscht)")

# Ablauf
exp = auth.create_api_key(svc, name="temp", expires_days=-1)   # bereits abgelaufen
assert c.get("/who", headers={"X-API-Key": exp["key"]}).status_code == 401
print("  ✓ abgelaufener Key → 401")

# ---------- R6-5: zwei Arten Key ----------
# Ein Key war bis 0.18.x eine vollständige Schreib-API im Namen seines Besitzers — bei einem
# Admin also: Nutzer anlegen, is_admin setzen, Passwörter zurücksetzen, Schwellen ändern. Ohne
# zweiten Faktor, ohne CSRF-Schicht. Ein abgeflossener CI-Key war die Instanz.
from tinysesam.errors import ConfigError                                   # noqa: E402

app2 = FastAPI()
app2.include_router(auth.router())


@app2.get("/nur-admin")
def nur_admin(u=Depends(auth.require_admin)):
    return {"ok": True, "via": u.get("_via")}


@app2.get("/wer")
def wer(u=Depends(auth.require_user)):
    return {"user": u["username"], "via": u.get("_via"), "admin": bool(u["is_admin"])}


c2 = TestClient(app2)
_admin_id = auth.store.get_user_by_name("admin")["id"]
_automat = auth.create_api_key(_admin_id, name="ci", kind="automat")
_mensch = auth.create_api_key(_admin_id, name="cli", kind="mensch")

# Der Automaten-Key kommt herein, aber ohne das Admin-Flag seines Besitzers.
_a = c2.get("/wer", headers={"X-API-Key": _automat["key"]})
assert _a.status_code == 200 and _a.json()["user"] == "admin", _a.text[:120]
assert _a.json()["admin"] is False, "der Automaten-Key trägt das Admin-Flag weiter"
assert c2.get("/nur-admin", headers={"X-API-Key": _automat["key"]}).status_code == 403
print("  ✓ Automaten-Key: angemeldet ja, Admin nein (R6-5)")

# Der Menschen-Key allein ist wertlos — er gilt nur mit einer Sitzung desselben Kontos.
assert c2.get("/wer", headers={"X-API-Key": _mensch["key"]}).status_code == 401
c3 = TestClient(app2)
c3.post("/auth/login", data={"username": "admin", "password": "pw", "next": "/"}, follow_redirects=False)
_m = c3.get("/wer", headers={"X-API-Key": _mensch["key"]})
assert _m.status_code == 200 and _m.json()["admin"] is True, _m.text[:120]
print("  ✓ Menschen-Key: allein wertlos, mit Sitzung voll wirksam")

# Und er gilt nur für SEIN Konto, nicht für irgendeine Sitzung.
_zweit = auth.create_user("zweitkonto", password="pw2")
c4 = TestClient(app2)
c4.post("/auth/login", data={"username": "zweitkonto", "password": "pw2", "next": "/"},
        follow_redirects=False)
assert c4.get("/wer", headers={"X-API-Key": _mensch["key"]}).json()["user"] == "zweitkonto", \
    "die fremde Sitzung darf den Key nicht aktivieren — sonst genügt IRGENDEINE Anmeldung"
print("  ✓ …und nur zusammen mit der Sitzung SEINES Kontos")

# Ablauf: Vorgabe greift, unbefristet braucht die ausdrückliche Erlaubnis.
_mit_vorgabe = auth.create_api_key(svc, name="mit-vorgabe")
assert _mit_vorgabe["expires_at"] is not None
assert abs((_mit_vorgabe["expires_at"] - int(__import__("time").time())) / 86400 - 90) < 1
try:
    auth.create_api_key(svc, name="ewig", expires_days=0)
    raise AssertionError("ein unbefristeter Key kam ohne Erlaubnis durch")
except ConfigError:
    pass
_frei = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  passkey_enabled=False, cookie_secure=False,
                                  apikey_allow_unlimited=True))
_uid_frei = _frei.create_service("geraet")
assert _frei.create_api_key(_uid_frei, name="dauer", expires_days=0)["expires_at"] is None
print("  ✓ Ablauf: 90 Tage als Vorgabe, unbefristet nur mit apikey_allow_unlimited")

# Eine unbekannte Art ist ein Fehler, keine stille Annahme.
try:
    auth.create_api_key(svc, name="quatsch", kind="halbstark")
    raise AssertionError("unbekannte Art kam durch")
except ConfigError:
    pass
print("  ✓ eine unbekannte Key-Art bricht ab, statt als Automat durchzugehen")

os.remove(db)
print("\nAPI-KEYS OK ✅")

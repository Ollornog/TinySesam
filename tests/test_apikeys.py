"""API-Keys + Service-/Daemon-Accounts: Zugang per Key, Rollen-Scope, Widerruf (sperren), Ablauf."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=db, passkey_enabled=False, oidc_enabled=False, cookie_secure=False))
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

os.remove(db)
print("\nAPI-KEYS OK ✅")

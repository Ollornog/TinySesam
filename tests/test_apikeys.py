"""API keys + service/daemon accounts: access by key, role scope, revocation (blocking), expiry."""
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

# System/service account for a daemon: no login, key only, role 'editor'
svc = auth.create_service("backup-daemon", roles=["editor"])
res = auth.create_api_key(svc, name="nightly-backup")
key = res["key"]
assert key.startswith("tsk_") and res["prefix"].startswith("tsk_")
print("  ✓ Service account + API key created:", res["prefix"])

# Access by key — entirely without session/login
r = c.get("/who", headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 200 and r.json() == {"user": "backup-daemon", "via": "apikey"}
assert c.get("/who", headers={"X-API-Key": key}).status_code == 200
print("  ✓ Access via Bearer and X-API-Key header")

# Role scope also applies via key
assert c.get("/editor", headers={"X-API-Key": key}).status_code == 200
print("  ✓ require_role via key (service has 'editor')")

# missing/wrong key → 401
assert c.get("/who").status_code == 401
assert c.get("/who", headers={"X-API-Key": "tsk_wrong"}).status_code == 401
print("  ✓ missing/invalid key → 401")

# Revocation = blocking (not deleting) → invalid immediately, key stays in the list
kid = auth.list_api_keys(svc)[0]["id"]
auth.revoke_api_key(kid)
assert c.get("/who", headers={"X-API-Key": key}).status_code == 401
assert any(k["revoked"] for k in auth.list_api_keys(svc))
print("  ✓ Revocation takes effect immediately (key blocked, not deleted)")

# Expiry
exp = auth.create_api_key(svc, name="temp", expires_days=-1)   # already expired
assert c.get("/who", headers={"X-API-Key": exp["key"]}).status_code == 401
print("  ✓ expired key → 401")

# ---------- R6-5: two kinds of key ----------
# Up to 0.18.x a key was a full write API in the name of its owner — for an admin that means:
# create users, set is_admin, reset passwords, change thresholds. Without a second factor,
# without a CSRF layer. A leaked CI key was the instance.
from tinysesam.errors import ConfigError                                   # noqa: E402

app2 = FastAPI()
app2.include_router(auth.router())


@app2.get("/only-admin")
def only_admin(u=Depends(auth.require_admin)):
    return {"ok": True, "via": u.get("_via")}


@app2.get("/wer")
def person(u=Depends(auth.require_user)):
    return {"user": u["username"], "via": u.get("_via"), "admin": bool(u["is_admin"])}


c2 = TestClient(app2)
_admin_id = auth.store.get_user_by_name("admin")["id"]
_automaton = auth.create_api_key(_admin_id, name="ci", kind="automation")
_human = auth.create_api_key(_admin_id, name="cli", kind="human")

# The automation key gets in, but without the admin flag of its owner.
_a = c2.get("/wer", headers={"X-API-Key": _automaton["key"]})
assert _a.status_code == 200 and _a.json()["user"] == "admin", _a.text[:120]
assert _a.json()["admin"] is False, "the automation key carries the admin flag along"
assert c2.get("/only-admin", headers={"X-API-Key": _automaton["key"]}).status_code == 403
print("  ✓ Automation key: signed in yes, admin no (R6-5)")

# The human key alone is worthless — it only counts together with a session of the same account.
assert c2.get("/wer", headers={"X-API-Key": _human["key"]}).status_code == 401
c3 = TestClient(app2)
c3.post("/auth/login", data={"username": "admin", "password": "pw", "next": "/"}, follow_redirects=False)
_m = c3.get("/wer", headers={"X-API-Key": _human["key"]})
assert _m.status_code == 200 and _m.json()["admin"] is True, _m.text[:120]
print("  ✓ Human key: worthless alone, fully effective with a session")

# And it only counts for ITS account, not for any session.
auth.create_user("zweitkonto", password="pw2")
c4 = TestClient(app2)
c4.post("/auth/login", data={"username": "zweitkonto", "password": "pw2", "next": "/"},
        follow_redirects=False)
assert c4.get("/wer", headers={"X-API-Key": _human["key"]}).json()["user"] == "zweitkonto", \
    "a foreign session must not activate the key — otherwise ANY sign-in would suffice"
print("  ✓ …and only together with the session of ITS account")

# Expiry: the default applies, unlimited needs explicit permission.
_with_default = auth.create_api_key(svc, name="with-default")
assert _with_default["expires_at"] is not None
assert abs((_with_default["expires_at"] - int(__import__("time").time())) / 86400 - 90) < 1
try:
    auth.create_api_key(svc, name="eternal", expires_days=0)
    raise AssertionError("an unlimited key got through without permission")
except ConfigError:
    pass
_free = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  passkey_enabled=False, cookie_secure=False,
                                  apikey_allow_unlimited=True))
_uid_free = _free.create_service("geraet")
assert _free.create_api_key(_uid_free, name="duration", expires_days=0)["expires_at"] is None
print("  ✓ Expiry: 90 days as default, unlimited only with apikey_allow_unlimited")

# An unknown kind is an error, not a silent assumption.
try:
    auth.create_api_key(svc, name="nonsense", kind="halfstrong")
    raise AssertionError("unknown kind got through")
except ConfigError:
    pass
print("  ✓ an unknown key kind aborts instead of passing as automation")

os.remove(db)
print("\nAPI-KEYS OK ✅")

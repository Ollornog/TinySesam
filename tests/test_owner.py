"""Owner model (PO decision 2026-09-24): owners are admins who cannot be deleted, locked or
stripped of power. The role can be passed on, several can be owners, there is always
at least one, and only an owner grants it — or changes an owner account.
"""
from __future__ import annotations

import io
import sqlite3
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, StateError, TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Owner — not deletable, transferable, at least one")
PW = "Owner-Test-Passwort-1"


def _app(**cfg):
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de")
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def _client(app, name):
    c = TestClient(app)
    c.post("/auth/login", data={"username": name, "password": PW}, follow_redirects=False)
    return c


# ── Bootstrap: the first admin is the first owner ───────────────────────────────────────
auth, app = _app()
r.check("ensure_admin creates the first admin — and he is owner",
        auth.ensure_admin("gruender", PW) and auth.store.get_user_by_name("gruender")["is_owner"] == 1)
auth_c, _ = _app()
candidate = auth_c.create_user("claimer", password=PW)
token = auth_c.admin_claim_token()
r.check("… likewise via /auth/claim-admin (one-time token)",
        auth_c._consume_admin_claim(token, auth_c.get_user(candidate))
        and auth_c.store.get_user(candidate)["is_owner"] == 1)

# ── Existing data: admins without owner → the oldest hand-made admin becomes owner ─────
path = str(Path(tempfile.mkdtemp()) / "bestand.db")
old, _ = _app(db_path=path)
old.create_user("idp-admin", password=PW)
old.store._exec("UPDATE users SET is_admin=2 WHERE username='idp-admin'")      # from the IdP, older
old.create_user("hand-admin", password=PW, is_admin=True)
old.create_user("zweit-admin", password=PW, is_admin=True)
old.store._exec("UPDATE users SET is_owner=0")
old.store.db.close()
new, _ = _app(db_path=path)
owner = [u["username"] for u in new.store.list_users() if u["is_owner"]]
r.check("existing data without owner: the oldest hand-set admin becomes owner (not the IdP admin)",
        owner == ["hand-admin"], str(owner))
r.check("… with a row in the audit log",
        any(z["event"] == "owner_grant" and z["detail"] == "source=existing oldest_admin" for z in new.store.recent_audit(20)))

# ── Protection: not deletable, not lockable, not strippable of power ───────────────────
auth, app = _app()
auth.ensure_admin("chefin", PW)
manager = auth.store.get_user_by_name("chefin")
admin2 = auth.create_user("admin2", password=PW, is_admin=True)
try:
    auth.delete_user(manager["id"])
    deleted = True
except StateError:
    deleted = False
r.check("an owner cannot be deleted (also via the Python API)", not deleted)
ca = _client(app, "admin2")            # an admin, but no owner
co = _client(app, "chefin")            # the owner
# Counter-check: the admin without owner role is really signed in and may do what an admin may —
# otherwise all the 403s below would be green even without owner protection (rejected because not signed in at all).
regular = auth.create_user("normalo", password=PW)
r.check("counter-check: the admin without owner role is signed in and sets a password on a normal account",
        ca.get("/auth/admin/api/users").status_code == 200
        and ca.post(f"/auth/admin/api/users/{regular}/password", json={"password": "Normales-Neues-Pw-1"}).status_code == 200)
r.check("in the panel: delete → rejected",
        ca.post(f"/auth/admin/api/users/{manager['id']}/delete").status_code in (403, 409))
r.check("… disable → rejected",
        ca.post(f"/auth/admin/api/users/{manager['id']}/disable", json={"disabled": True}).status_code in (400, 403))
r.check("… strip power (admin flag removed) → rejected",
        ca.post(f"/auth/admin/api/users/{manager['id']}/roles", json={"roles": [], "is_admin": False}).status_code
        in (400, 403))
r.check("… the owner himself cannot lock or strip himself of power either, as long as he is owner",
        co.post(f"/auth/admin/api/users/{manager['id']}/roles", json={"roles": [], "is_admin": False}).status_code == 400)
r.check("owner account stays what it was", auth.store.get_user(manager["id"])["is_admin"] == 1
        and not auth.store.get_user(manager["id"])["disabled"])

# ── Only an owner changes an owner account (otherwise: set password and be owner oneself) ─
r.check("an admin without owner role sets no password on the owner",
        ca.post(f"/auth/admin/api/users/{manager['id']}/password", json={"password": "Uebernahme-Versuch-1"}).status_code == 403
        and auth._check_password("chefin", PW) is not None)
r.check("… issues him no API key",
        ca.post(f"/auth/admin/api/users/{manager['id']}/keys", json={"name": "x"}).status_code == 403)
r.check("… deletes no passkey of his",
        ca.post(f"/auth/admin/api/users/{manager['id']}/passkeys/1/delete").status_code == 403)
r.check("… and does not grant the owner role (not even to himself)",
        ca.post(f"/auth/admin/api/users/{admin2}/owner", json={"owner": True}).status_code == 403
        and not auth.store.get_user(admin2)["is_owner"])

# ── Passing on, several, at least one ────────────────────────────────────────────────────
r.check("the owner makes another one an owner",
        co.post(f"/auth/admin/api/users/{admin2}/owner", json={"owner": True}).status_code == 200
        and auth.store.owner_count() == 2)
r.check("… and then gives up his role (one remains)",
        co.post(f"/auth/admin/api/users/{manager['id']}/owner", json={"owner": False}).status_code == 200
        and auth.store.owner_count() == 1)
co2 = _client(app, "admin2")
r.check("the last owner cannot give up his role",
        co2.post(f"/auth/admin/api/users/{admin2}/owner", json={"owner": False}).status_code == 400
        and auth.store.owner_count() == 1)
try:
    auth.set_owner(admin2, False)
    last = False
except StateError:
    last = True
r.check("… not via the Python API either (StateError)", last)
service = auth.create_user("dienst", is_service=True)
try:
    auth.set_owner(service, True)
    service_owner = True
except ConfigError:
    service_owner = False
r.check("a service account does not become owner (it cannot sign in)", not service_owner)
r.check("the user list in the panel shows who is owner",
        any(u.get("is_owner") for u in co2.get("/auth/admin/api/users").json()))

# ── Owner and identity provider (H-5) ────────────────────────────────────────────────────
idp = auth.create_user("idp-nutzer", password=PW)
auth.apply_idp_groups(idp, ["admins"], {"admins": "__admin__"})
co2.post(f"/auth/admin/api/users/{idp}/owner", json={"owner": True})
auth.apply_idp_groups(idp, [], {"admins": "__admin__"})
r.check("an owner who had his admin right from the IdP keeps it when the IdP takes the group away",
        auth.store.get_user(idp)["is_admin"] == 1 and auth.store.get_user(idp)["is_owner"] == 1)

# ── Findings from the attack on the second round ─────────────────────────────────────────
# Finding 1: an admin granted by the IdP (2) does NOT become owner at the next start — otherwise no provider
# could withdraw the right from him any more.
path_i = str(Path(tempfile.mkdtemp()) / "idp.db")
idp_a, _ = _app(db_path=path_i)
idp_uid = idp_a.create_user("nur-idp-admin", password=PW)
idp_a.apply_idp_groups(idp_uid, ["admins"], {"admins": "__admin__"})
idp_a.store.db.close()
idp_b, _ = _app(db_path=path_i)
r.check("finding 1: an admin granted by the IdP does not become owner at restart (stays revocable)",
        idp_b.store.get_user(idp_uid)["is_owner"] == 0 and idp_b.store.get_user(idp_uid)["is_admin"] == 2)
idp_b.apply_idp_groups(idp_uid, [], {"admins": "__admin__"})
r.check("… and the provider still takes the right from him", not idp_b.store.get_user(idp_uid)["is_admin"])
idp_b.store.db.close()
# Finding 2: a locked hand-made admin does not become owner, an active one does.
path_g = str(Path(tempfile.mkdtemp()) / "gesperrt.db")
g_a, _ = _app(db_path=path_g)
old_admin = g_a.create_user("gefeuert", password=PW, is_admin=True)
active_admin = g_a.create_user("aktiv", password=PW, is_admin=True)
g_a.store._exec("UPDATE users SET is_owner=0")
g_a.store._exec("UPDATE users SET disabled=2 WHERE id=?", (old_admin,))
g_a.store.db.close()
g_b, _ = _app(db_path=path_g)
r.check("finding 2: in existing data the oldest ACTIVE hand-made admin becomes owner, not a locked one",
        g_b.store.get_user(active_admin)["is_owner"] == 1 and g_b.store.get_user(old_admin)["is_owner"] == 0)
g_b.store.db.close()
# Finding 3: an admin without owner role revokes neither keys nor sessions of the owner.
auth3, app3 = _app()
auth3.ensure_admin("owner3", PW)
o3 = auth3.store.get_user_by_name("owner3")["id"]
auth3.create_user("admin3", password=PW, is_admin=True)
key3 = auth3.create_api_key(o3, name="ci")
c_owner3 = _client(app3, "owner3")
c_admin3 = _client(app3, "admin3")
r.check("finding 3: an admin without owner role revokes no key of the owner",
        c_admin3.post(f"/auth/admin/api/keys/{key3['id']}/revoke").status_code == 403
        and auth3.verify_api_key(key3["key"])[0] is not None)
r.check("… and does not end his sessions (neither per account nor per handle)",
        c_admin3.post("/auth/admin/api/sessions/revoke", json={"user_id": o3}).status_code == 403
        and c_admin3.post("/auth/admin/api/sessions/revoke",
                          json={"token": auth3.store.list_sessions(o3)[0]["token_hash"]}).status_code == 403
        and c_owner3.get("/auth/me").status_code == 200)
# Finding 12: the code path does not lock an owner either, and gc() deletes none.
try:
    auth3.store.set_disabled(o3, True, through_operator=True)
    code_lock = True
except StateError:
    code_lock = False
r.check("Fund 12: `store.set_disabled` does not disable an owner (StateError)", not code_lock)
waiting = auth3.create_user("wartend", password=PW, email="wartend@example.com")
auth3.store.set_disabled(waiting, True)
auth3.create_magic_token("verify_email", user_id=waiting)
auth3.store._exec("UPDATE magic_token SET expires_at = 1 WHERE user_id=?", (waiting,))
auth3.store._exec("UPDATE users SET is_owner=1 WHERE id=?", (waiting,))        # constructed: waiting owner
auth3.gc()
r.check("… and `gc()` clears no owner, not even one waiting for a confirmation",
        auth3.store.get_user(waiting) is not None)

# ── Hardening values for owners only (PO decision 2026-09-24) ─────────────────────────────
# Without that an admin would tighten the lockout thresholds and lock the owner out with a few
# failed attempts under his name — a detour around “an owner cannot be locked”.
auth_h, app_h = _app()
auth_h.ensure_admin("chefin-h", PW)
auth_h.create_user("admin-h", password=PW, is_admin=True)
_before_h = auth_h.all_security()
_admin_h = _client(app_h, "admin-h")
_declined_h = _admin_h.post("/auth/admin/api/security", json={"max_login_attempts": 1})
r.check("hardening: an admin without owner role does not change the values (403, nothing stored)",
        _declined_h.status_code == 403 and auth_h.all_security() == _before_h,
        f"HTTP {_declined_h.status_code}")
r.check("… he may still read them",
        _admin_h.get("/auth/admin/api/security").json() == _before_h)
_owner_h = _client(app_h, "chefin-h")
_ok_h = _owner_h.post("/auth/admin/api/security", json={"max_login_attempts": 7})
r.check("… the owner changes them", _ok_h.status_code == 200 and auth_h.all_security()["max_login_attempts"] == 7,
        f"HTTP {_ok_h.status_code}")
auth_o, app_o = _app()
auth_o.create_user("nur-admin", password=PW, is_admin=True)
auth_o.store._exec("UPDATE users SET is_owner=0")              # existing data without owner
_free_o = _client(app_o, "nur-admin").post("/auth/admin/api/security", json={"max_login_attempts": 9})
r.check("… if there is no owner, every admin changes them (otherwise they would be unreachable)",
        _free_o.status_code == 200 and auth_o.all_security()["max_login_attempts"] == 9,
        f"HTTP {_free_o.status_code}")
# (Mutation probe: remove the owner check in `security_set` → first check red;
#  `owner_count() > 0` remove → last one red.)

# ── Emergency path via the CLI ────────────────────────────────────────────────────────────
from tinysesam.__main__ import main as _cli  # noqa: E402
emergency = auth.create_user("notfall", password=PW)
_code = 0
with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    try:
        _cli(["owner", "--db", auth.cfg.db_path, "notfall"])
    except SystemExit as e:
        _code = e.code or 0
r.check("`tinysesam owner` makes an account owner (when nobody can get at it any more)",
        _code == 0 and auth.store.get_user(emergency)["is_owner"] == 1)
with sqlite3.connect(auth.cfg.db_path) as _db:
    _line = _db.execute("SELECT detail FROM audit WHERE event='owner_grant' ORDER BY id DESC LIMIT 1").fetchone()
r.check("… with a row in the audit log", _line is not None and "cli" in (_line[0] or ""))
# (Mutation probes: remove the owner check in `delete_user` → “do not delete” red;
#  `owner_protection` empty → “no password/key/passkey” red; remove the `owner_count(without=…) == 0` check in
#  `set_owner` → “the last owner” red; remove `_first_owner` in the bootstrap paths
#  → first two red; remove `is_admin=1` in `Store.set_owner` → “IdP … keeps it” red.)

sys.exit(r.done())

"""The account API for applications, stage A: an application manages the accounts it created itself — create (with a
one-time link until the first sign-in), read, change display name and allowlist roles, lock and unlock.

One block per row of the acceptance table (draft "account API" §11 A); the mutation that turns each red is named next
to it and was run for the pull request:

 1. A person's key, a `human` key, a foreign service account's key → 403; a session alone → 401.
                                                                  (`is_service` check / match with `apps[…].account`)
 2. Session + the service account's key → only the key counts; a session alone is refused.  (`current_user()`)
 3. Foreign, missing, admin, owner, service and delegate accounts → 404 everywhere, also with a broken body.
                                                                  (target after the body / admin exclusion)
 4. An application account with a foreign role: GET works, disable/link/display name → 409 `account_shared`.
                                                                  (strict whole-account check removed)
 5. `roles` with `admin`, a delegate role or a foreign role → 400, nothing written.        (allowlist loosened)
 6. PATCH roles keeps foreign roles; a panel change between check and write is not lost.   (`set_roles(wanted)`)
 7. PATCH email/username/is_admin/password → 400.                                          (field let through)
 8. A name or address from `admin_identifiers` → 409 like "taken".                         (check removed)
 9. The link only in the create answer — never in the audit, never in a log.               (link in the audit)
10. A new link before the first sign-in works and kills the old one; afterwards 409.      (first-login check / revoke)
11. `enable` lifts 3, not 1 or 2; `disable` never downgrades 2 to 3.                       (`WHERE disabled=3` / `=0`)
12. `last_login_at` on every complete sign-in, `first_login_at` once.                      (set only the first time)
13. Limits: the 61st creation, the 31st collision → 429; the counter is shared by two workers. (in-process counter)
14. Without the actor header → 400; a service account as actor → 400; audit `actor_claimed=` beside the service
    account.                                                                               (actor optional / as actor=)
15. `config_check`: admin, delegate role, mapped role, unknown role, double account, admin_path='/auth', users:invite
    without magic link → errors; a role without the app prefix → warning.                  (each check removed)
16. Service account missing or a person → the API stays shut, one security-log line.       (start check removed)
17. `may_manage` is one rule for the panel's delegates and the application (test_delegates.py stays green).
                                                                                           (delegate branch apart)
18. `disabled=3` signs in nowhere: password, passkey, sign-in link, OIDC, API key.
Plus: listing with filters and pages, the self-description, the quota, the migration from schema 22, and "without an
application nothing changes".
"""
import base64
import hashlib
import importlib.util
import io
import json
import logging
import os
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check  # noqa: E402
from tinysesam import provisioning as prov  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"
CSRF = "csrfProbeToken0123456789abcdefgh"
ROLES = ["example-member", "example-editor", "example-teamadmin", "staff", "teamadmin", "editors"]
ALLOW = ["example-member", "example-editor", "example-teamadmin"]
SCOPES = ["users:read", "users:invite", "users:update", "users:disable"]


def ok(name):
    print(f"  ✓ {name}")


def apps(account="svc-example", **block):
    p = {"roles": list(ALLOW), "scopes": list(SCOPES)}
    p.update(block)
    return {"example": {"account": account, "name": {"en": "Example", "de": "Example"}, "provisioning": p}}


def build(db=None, **over):
    cfg = dict(lang="en", db_path=db or os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, base_url=BASE, magiclink_enabled=True,
               available_roles=list(ROLES), admin_delegates={"teamadmin": {"roles": ["editors"]}}, apps=apps())
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def client(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def H(key, actor="-"):
    h = {"X-Api-Key": key}
    if actor is not None:
        h["TinySesam-On-Behalf-Of"] = str(actor)
    return h


def audit(auth, event=None):
    return [a for a in auth.store.recent_audit(5000) if event is None or a["event"] == event]


def roles_of(auth, uid):
    return sorted(auth.user_roles(auth.store.get_user(uid)))


auth, app = build()
c = client(app)
svc = auth.create_service("svc-example")
key = auth.create_api_key(svc, name="example")["key"]
boss = auth.create_user("boss", password=PW, is_admin=True)
anna = auth.create_user("anna", password=PW)                      # a person the application acts for
seq = [0]


def create(c_, key_, **body):
    """Create through the API — on the main instance in the name of anna, elsewhere as a job (`-`)."""
    seq[0] += 1
    body.setdefault("username", f"user{seq[0]}")
    body.setdefault("roles", ["example-member"])
    return c_.post("/auth/api/users", headers=H(key_, anna if key_ == key else "-"), json=body)


lena = create(c, key, username="lena", email="lena@example.org", display_name="Lena M.").json()
LENA = lena["id"]
assert lena["username"] == "lena" and lena["signin_url"].startswith(f"{BASE}/auth/magic/")
row = auth.store.get_user(LENA)
assert row["managed_by"] == "example" and row["email_verified"] == 0 and not row["is_admin"] and not row["is_service"]
assert roles_of(auth, LENA) == ["example-member"] and row["display_name"] == "Lena M."
assert not auth.store.get_password_hash(LENA)
ok("create: 201, managed_by=example, address unverified, no admin, no service, no password, link from base_url")

# ══ 1. who may call ═════════════════════════════════════════════════════════════════════════════════════════════
c1 = client(app)
person_key = auth.create_api_key(anna, name="own")["key"]
assert c1.get(f"/auth/api/users/{LENA}", headers=H(person_key)).status_code == 403
assert c1.get(f"/auth/api/users/{LENA}", headers=H(person_key)).json()["error"] == "not_a_provisioning_app"
other_svc = auth.create_service("svc-other")
other_key = auth.create_api_key(other_svc, name="other")["key"]
assert c1.get(f"/auth/api/users/{LENA}", headers=H(other_key)).status_code == 403
try:
    human_svc_key = auth.create_api_key(svc, name="human", kind="human")["key"]
except Exception:
    human_svc_key = None
if human_svc_key is None:      # the library refuses a human key for a service account: write the row as a foreign writer
    raw_human = "tsk_" + "h" * 40
    auth.store._exec("INSERT INTO api_key(user_id, name, prefix, key_hash, kind, created_at) VALUES (?,?,?,?,?,?)",
                     (svc, "human", raw_human[:8], hashlib.sha256(raw_human.encode()).hexdigest(), "human",
                      int(time.time())))
    human_svc_key = raw_human
assert c1.get(f"/auth/api/users/{LENA}", headers=H(human_svc_key)).status_code == 403
# The configured account is a PERSON: the name matches, the kind does not.
a1h, app1h = build(apps=apps(account="petra"))
petra = a1h.create_user("petra", password=PW)
petra_key = a1h.create_api_key(petra, name="k")["key"]
r = client(app1h).post("/auth/api/users", headers=H(petra_key), json={"username": "x", "roles": ["example-member"]})
assert r.status_code == 403 and r.json()["error"] == "not_a_provisioning_app", r.text
assert not a1h.store.get_user_by_name("x")
s1 = client(app)
s1.cookies.set(auth.session_cookie_name, auth.store.create_session(boss, 86400, True, "password",
                                                                   factors=["password"]))
s1.cookies.set(auth.csrf_cookie_name, CSRF)
r = s1.get(f"/auth/api/users/{LENA}", headers={"X-CSRF-Token": CSRF})
assert r.status_code == 401 and r.json()["error"] == "unauthenticated", r.text
assert c1.get(f"/auth/api/users/{LENA}").status_code == 401
assert c1.get(f"/auth/api/users/{LENA}", headers={"Authorization": "Bearer not-a-key"}).status_code == 401
ok("1: a person's key, a foreign service account's key, a human key, a person named as account → 403; "
   "a session alone, no key → 401")

# ══ 2. session + key: only the key counts ═══════════════════════════════════════════════════════════════════════
r = s1.get(f"/auth/api/users/{LENA}", headers=H(key))
assert r.status_code == 200 and r.json()["username"] == "lena", r.text
r = s1.post("/auth/api/users", headers=H(key, anna), json={"username": "withsession", "roles": ["example-member"]})
assert r.status_code == 201, r.text
line = [a for a in audit(auth, "user_create") if "withsession" in (a["detail"] or "")][0]
assert line["username"] == "svc-example" and "boss" not in (line["detail"] or ""), dict(line)
ok("2: a session beside the key changes nothing — the service account acts, the admin session is ignored")

# ══ 3. 404 for everything the application does not own — before any field ═══════════════════════════════════════
foreign = auth.create_user("fritz", password=PW, roles=["example-member"])        # not created by the application
admin_app = create(c, key).json()["id"]
auth.store.set_admin(admin_app, True)                                                  # an application account made admin
owner_app = create(c, key).json()["id"]
auth.store._exec("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (owner_app,))
svc_app = create(c, key).json()["id"]
auth.store._exec("UPDATE users SET is_service=1 WHERE id=?", (svc_app,))
deleg_app = create(c, key).json()["id"]
auth.store._exec("UPDATE users SET roles=? WHERE id=?", (json.dumps(["example-member", "teamadmin"]), deleg_app))
for target in (foreign, admin_app, owner_app, svc_app, deleg_app, 99999, "abc", 0):
    for method, path, body in (("get", "", None), ("patch", "", "{broken"), ("patch", "", {"email": "x@example.org"}),
                               ("post", "/disable", None), ("post", "/enable", None), ("post", "/signin-link", None)):
        kw = {"headers": H(key, anna)}
        if isinstance(body, str):
            kw["content"] = body
            kw["headers"] = {**kw["headers"], "Content-Type": "application/json"}
        elif body is not None:
            kw["json"] = body
        r = getattr(c, method)(f"/auth/api/users/{target}{path}", **kw)
        assert r.status_code == 404 and r.json() == {"error": "not_found"}, (target, method, path, r.status_code, r.text)
listed = {u["id"] for u in c.get("/auth/api/users", headers=H(key)).json()["users"]}
assert LENA in listed and not listed & {foreign, admin_app, owner_app, svc_app, deleg_app}, listed
assert not auth.store.get_user(foreign)["disabled"] and auth.store.get_user(admin_app)["is_admin"]
ok("3: a foreign, missing, admin, owner, service or delegate account → 404 on every route, also with a broken body "
   "or a forbidden field; the list hides them")

# ══ 4. shared account: visible, but no whole-account action ════════════════════════════════════════════════════
shared = create(c, key, roles=["example-member"]).json()["id"]
auth.store._exec("UPDATE users SET roles=? WHERE id=?", (json.dumps(["example-member", "staff"]), shared))
v = c.get(f"/auth/api/users/{shared}", headers=H(key)).json()
assert v["roles"] == ["example-member"] and v["other_roles"] is True and "staff" not in json.dumps(v), v
for path, body in (("/disable", None), ("/signin-link", None)):
    r = c.post(f"/auth/api/users/{shared}{path}", headers=H(key, anna))
    assert r.status_code == 409 and r.json()["error"] == "account_shared", (path, r.text)
r = c.patch(f"/auth/api/users/{shared}", headers=H(key, anna), json={"display_name": "New"})
assert r.status_code == 409 and r.json()["error"] == "account_shared"
assert not auth.store.get_user(shared)["disabled"] and auth.store.get_user(shared)["display_name"] != "New"
r = c.patch(f"/auth/api/users/{shared}", headers=H(key, anna), json={"roles": ["example-editor"]})
assert r.status_code == 200 and roles_of(auth, shared) == ["example-editor", "staff"], r.text
ok("4: an application account with a foreign role: GET shows only allowlist roles + other_roles; lock, link and "
   "display name → 409 account_shared; its allowlist roles stay changeable")

# ══ 5. roles only from the allowlist, nothing written on refusal ════════════════════════════════════════════════
before = auth.store.count_managed("example")
for bad in (["admin"], ["teamadmin"], ["staff"], ["example-member", "editors"], [], "example-member", [1]):
    r = create(c, key, roles=bad)
    assert r.status_code == 400 and r.json()["error"] in ("role_not_allowed", "invalid"), (bad, r.text)
r = create(c, key, roles=["admin"])
assert r.json()["roles"] == ALLOW, r.json()
assert auth.store.count_managed("example") == before
for bad in (["admin"], ["teamadmin"], ["staff"]):
    r = c.patch(f"/auth/api/users/{LENA}", headers=H(key, anna), json={"roles": bad, "display_name": "Changed"})
    assert r.status_code == 400 and r.json()["error"] == "role_not_allowed", r.text
assert roles_of(auth, LENA) == ["example-member"] and auth.store.get_user(LENA)["display_name"] == "Lena M."
assert not any(auth.store.get_user(u["id"])["is_admin"] for u in c.get("/auth/api/users", headers=H(key)).json()["users"])
ok("5: admin, a delegate role, a foreign role, none, a string → 400 with the allowlist; nothing created, nothing "
   "changed (not even the display name of the same request)")

# ══ 6. PATCH roles: foreign roles stay; a panel change in between is not lost ═══════════════════════════════════
mixed = create(c, key).json()["id"]
auth.store._exec("UPDATE users SET roles=? WHERE id=?", (json.dumps(["example-member", "staff"]), mixed))
r = c.patch(f"/auth/api/users/{mixed}", headers=H(key, anna), json={"roles": ["example-editor", "example-teamadmin"]})
assert r.status_code == 200 and roles_of(auth, mixed) == ["example-editor", "example-teamadmin", "staff"]
assert r.json()["roles"] == ["example-editor", "example-teamadmin"]
r = c.patch(f"/auth/api/users/{mixed}", headers=H(key, anna), json={"roles": []})
assert r.status_code == 200 and roles_of(auth, mixed) == ["staff"] and auth.store.get_user(mixed)["managed_by"] == "example"
# A second worker (the panel) changes the roles after the API resolved the account and before it writes.
panel_worker = TinySesam(TinySesamConfig(**{**{k: getattr(auth.cfg, k) for k in ("lang", "db_path", "passkey_enabled",
                                                                                  "oidc_enabled", "base_url",
                                                                                  "magiclink_enabled",
                                                                                  "available_roles", "apps")}}))
service = auth._provisioning()
real_target = service.target


def target_then_panel(app_, uid_, whole=False):
    found = real_target(app_, uid_, whole)
    panel_worker.set_roles(mixed, sorted(set(panel_worker.store.get_roles(mixed)) | {"editors"}))
    return found


service.target = target_then_panel
try:
    r = c.patch(f"/auth/api/users/{mixed}", headers=H(key, anna), json={"roles": ["example-member"]})
finally:
    service.target = real_target
assert r.status_code == 200 and roles_of(auth, mixed) == ["editors", "example-member", "staff"], roles_of(auth, mixed)
ok("6: PATCH roles replaces only allowlist roles, [] keeps the account the application's; a panel change between "
   "check and write survives (read and write in one transaction)")

# ══ 7. not changeable: address, name, admin flag, password ══════════════════════════════════════════════════════
for field, value in (("email", "evil@example.org"), ("username", "renamed"), ("is_admin", True),
                     ("password", PW), ("is_service", True), ("unknown", 1)):
    r = c.patch(f"/auth/api/users/{LENA}", headers=H(key, anna), json={field: value})
    assert r.status_code == 400 and r.json()["error"] == "invalid", (field, r.text)
row = auth.store.get_user(LENA)
assert row["email"] == "lena@example.org" and row["username"] == "lena" and not row["is_admin"]
assert not auth.store.get_password_hash(LENA)
for field, value in (("password", PW), ("is_admin", True), ("is_service", True)):
    assert create(c, key, **{field: value}).status_code == 400, field
ok("7: PATCH email/username/is_admin/password/unknown → 400 invalid; create refuses password/is_admin/is_service")

# ══ 8. admin_identifiers answer like "taken" ════════════════════════════════════════════════════════════════════
a8, app8 = build(admin_identifiers=["chief", "chief@example.org"])
s8 = a8.create_service("svc-example")
k8 = a8.create_api_key(s8, name="k")["key"]
c8 = client(app8)
taken_name = create(c8, k8, username="boss8").status_code
a8.create_user("held", password=PW)
r_taken = create(c8, k8, username="held")
r_allow = create(c8, k8, username="chief")
r_allow_mail = create(c8, k8, username="someone", email="chief@example.org")
assert r_taken.status_code == r_allow.status_code == 409 and r_allow.json() == r_taken.json(), (r_allow.text, r_taken.text)
assert r_allow_mail.status_code == 409 and r_allow_mail.json()["error"] == "email_taken"
assert not a8.store.get_user_by_name("chief") and not a8.store.get_user_by_name("someone")
ok("8: a name or address from admin_identifiers → 409 exactly like a taken one; nothing created")

# ══ 9. the link exists only in the answer ═══════════════════════════════════════════════════════════════════════
buf = io.StringIO()
handler = logging.StreamHandler(buf)
handler.setLevel(logging.DEBUG)
root = logging.getLogger()
old_level = root.level
root.addHandler(handler)
root.setLevel(logging.DEBUG)
try:
    made = create(c, key, username="linkcheck").json()
    again = c.post(f"/auth/api/users/{made['id']}/signin-link", headers=H(key, anna)).json()
finally:
    root.removeHandler(handler)
    root.setLevel(old_level)
for link in (made["signin_url"], again["signin_url"]):
    token = link.rsplit("/", 1)[1]
    assert token not in buf.getvalue(), "the link is in a log"
    assert not any(token in (a["detail"] or "") or token in (a["username"] or "") for a in audit(auth)), "link in audit"
    assert token not in json.dumps([dict(r) for r in auth.store._all("SELECT * FROM magic_token")])
assert c.get(f"/auth/api/users/{made['id']}", headers=H(key)).json().get("signin_url") is None
ok("9: the one-time link only in the answer — not in a log line (all loggers), not in the audit, only its hash stored")

# ══ 10. a new link only before the first sign-in; the old one dies ══════════════════════════════════════════════
fresh = create(c, key, username="newlink").json()
first_token = fresh["signin_url"].rsplit("/", 1)[1]
r = c.post(f"/auth/api/users/{fresh['id']}/signin-link", headers=H(key, anna))
assert r.status_code == 200, r.text
second_token = r.json()["signin_url"].rsplit("/", 1)[1]
assert second_token != first_token
assert not auth.peek_magic(first_token, purpose="login") and auth.peek_magic(second_token, purpose="login")
auth.store.mark_login(fresh["id"], int(time.time()))
r = c.post(f"/auth/api/users/{fresh['id']}/signin-link", headers=H(key, anna))
assert r.status_code == 409 and r.json()["error"] == "already_signed_in", r.text
assert auth.peek_magic(second_token, purpose="login"), "the refused request discarded the open link"
ok("10: a new link before the first sign-in (the old one is dead), after it 409 already_signed_in")

# ══ 11. the application's lock: 3 only ══════════════════════════════════════════════════════════════════════════
target = create(c, key, username="locky").json()["id"]
lk = auth.create_api_key(target, name="theirs")["key"]
r = c.post(f"/auth/api/users/{target}/disable", headers=H(key, anna))
assert r.status_code == 200 and r.json()["state"] == "disabled" and auth.store.get_user(target)["disabled"] == 3
assert auth.verify_api_key(lk)[0] is None and not auth.store.list_api_keys(target)[0]["revoked"] == 0
r = c.post(f"/auth/api/users/{target}/enable", headers=H(key, anna))
assert r.status_code == 200 and r.json()["state"] == "active" and auth.store.get_user(target)["disabled"] == 0
for mark in (1, 2):
    auth.store._exec("UPDATE users SET disabled=? WHERE id=?", (mark, target))
    r = c.post(f"/auth/api/users/{target}/enable", headers=H(key, anna))
    assert r.status_code == 409 and r.json()["error"] == "disabled_by_operator", (mark, r.text)
    assert auth.store.get_user(target)["disabled"] == mark
    r = c.post(f"/auth/api/users/{target}/disable", headers=H(key, anna))
    assert r.status_code == 200 and r.json()["state"] == "disabled_operator", r.text
    assert auth.store.get_user(target)["disabled"] == mark, "the application downgraded a lock"
auth.set_disabled(target, False)
assert c.post(f"/auth/api/users/{target}/disable", headers=H(key, anna)).json()["state"] == "disabled"
assert auth.set_disabled(target, False) and auth.store.get_user(target)["disabled"] == 0
ok("11: disable sets 3 (keys end), enable lifts only 3; 1 and 2 stay (409 disabled_by_operator, disable keeps them); "
   "the operator lifts 3")

# ══ 12. last_login_at every time, first_login_at once ══════════════════════════════════════════════════════════
import tinysesam.manager as _manager  # noqa: E402

who = auth.create_user("loginprobe", password=PW)
real_now = _manager._now
t0 = int(time.time())
try:
    _manager._now = lambda: t0
    auth.start_session(who, "password")
    _manager._now = lambda: t0 + 120
    auth.start_session(who, "password")
finally:
    _manager._now = real_now
row = auth.store.get_user(who)
assert row["first_login_at"] == t0 and row["last_login_at"] == t0 + 120, (row["first_login_at"], row["last_login_at"])
lc = client(app)
lc.cookies.set(auth.csrf_cookie_name, CSRF)
lr = lc.post("/auth/login", data={"username": "loginprobe", "password": PW, "_csrf": CSRF})
assert lr.status_code in (200, 303), lr.status_code
assert auth.store.get_user(who)["last_login_at"] >= t0 and auth.store.get_user(who)["first_login_at"] == t0
ok("12: last_login_at on every complete sign-in, first_login_at stays the first")

# ══ 13. limits: in the database, shared by workers, with a test clock ══════════════════════════════════════════
fixed = (int(time.time()) // 3600) * 3600 + 600
real_prov_now = prov._now
prov._now = lambda: fixed
try:
    db13 = os.path.join(tempfile.mkdtemp(), "l.db")
    w1, w1app = build(db=db13)
    svc13 = w1.create_service("svc-example")
    k13 = w1.create_api_key(svc13, name="k")["key"]
    w2, w2app = build(db=db13)                      # a second worker on the same file
    c13a, c13b = client(w1app), client(w2app)
    for i in range(60):
        r = create(c13a if i % 2 else c13b, k13)
        assert r.status_code == 201, (i, r.text)
    r = create(c13a, k13)
    assert r.status_code == 429 and r.json()["error"] == "limit" and r.json()["error_description"] == "create_per_hour"
    assert 1 <= int(r.headers["retry-after"]) <= 3000, r.headers
    assert w1.store.count_managed("example") == 60
    assert audit(w1, "provision_throttled"), "no audit line provision_throttled"
    w1.create_user("taken0", password=PW)
    for i in range(30):
        r = create(c13a if i % 2 else c13b, k13, username="taken0")
        assert r.status_code == 409 and r.json()["error"] == "username_taken", (i, r.text)
    r = create(c13b, k13, username="taken0")
    assert r.status_code == 429 and r.json()["error_description"] == "taken_per_hour", r.text
    r = create(c13a, k13, username="free-but-throttled")
    assert r.status_code == 429, "after the collision limit even a free name answers 429 (no oracle)"
    assert len(audit(w1, "provision_name_taken")) == 30
    info = c13a.get("/auth/api/provisioning", headers=H(k13)).json()
    assert info["remaining"]["create_per_hour"] == 0 and info["remaining"]["taken_per_hour"] == 0, info
    prov._now = lambda: fixed + 3600                 # the next hour: a new window
    assert create(c13a, k13).status_code == 201
finally:
    prov._now = real_prov_now
ok("13: the 61st creation and the 31st collision → 429 with Retry-After, across two workers on one file; "
   "a new hour opens a new window")

# ══ 14. the actor the application claims ════════════════════════════════════════════════════════════════════════
r = c.post("/auth/api/users", headers=H(key, None), json={"username": "noactor", "roles": ["example-member"]})
assert r.status_code == 400 and r.json()["error"] == "actor_required", r.text
for actor in (svc, other_svc, 99999, "abc", "17x"):
    r = c.post("/auth/api/users", headers=H(key, actor), json={"username": "badactor", "roles": ["example-member"]})
    assert r.status_code == 400 and r.json()["error"] == "actor_invalid", (actor, r.text)
for path in ("/disable", "/enable", "/signin-link"):
    assert c.post(f"/auth/api/users/{LENA}{path}", headers=H(key, None)).json()["error"] == "actor_required"
assert c.patch(f"/auth/api/users/{LENA}", headers=H(key, None), json={"display_name": "x"}).status_code == 400
assert c.get(f"/auth/api/users/{LENA}", headers=H(key, None)).status_code == 200      # reading needs none
r = c.patch(f"/auth/api/users/{LENA}", headers=H(key, anna), json={"display_name": "Lena Meier"})
assert r.status_code == 200 and r.json()["display_name"] == "Lena Meier"
line = audit(auth, "provision_display_name")[0]
assert line["username"] == "svc-example" and f"actor_claimed=anna#{anna}" in line["detail"] and "app=example" in line[
    "detail"], dict(line)
assert " actor=anna" not in (line["detail"] or "")
link_line = [a for a in audit(auth, "signin_link_issue") if a["username"] == "newlink"][0]
assert "actor=svc-example" in link_line["detail"] and f"actor_claimed=anna#{anna}" in link_line["detail"], dict(link_line)
job = c.post(f"/auth/api/users/{LENA}/disable", headers=H(key, "-"))
assert job.status_code == 200 and "actor_claimed=-" in audit(auth, "user_disable")[0]["detail"]
c.post(f"/auth/api/users/{LENA}/enable", headers=H(key, "-"))
ok("14: no actor → 400 actor_required, a service account or unknown id → 400 actor_invalid; the audit names the "
   "service account as actor and the claim as actor_claimed=<name>#<id> (or -)")

# ══ 15. config_check ════════════════════════════════════════════════════════════════════════════════════════════


def findings(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE, magiclink_enabled=True,
               available_roles=list(ROLES), admin_delegates={"teamadmin": {"roles": ["editors"]}}, apps=apps())
    cfg.update(over)
    return config_check.check_config(TinySesamConfig(**cfg))


def errors(**over):
    return findings(**over)[0]


assert not [e for e in errors() if "apps" in e], errors()
assert any("\"admin\" is never grantable" in e for e in errors(apps=apps(roles=["example-member", "admin"]),
                                                                available_roles=ROLES + ["admin"]))
assert any("'teamadmin' is a delegate role" in e for e in errors(apps=apps(roles=["teamadmin"])))
assert any("is assigned by a group map" in e for e in errors(oidc_group_role_map={"grp": "example-member"}))
assert any("'example-ghost' is not in available_roles" in e for e in errors(apps=apps(roles=["example-ghost"])))
double = apps()
double["other"] = {"account": "SVC-example", "provisioning": {"roles": ["example-member"], "scopes": ["users:read"]}}
assert any("name the same service account" in e for e in errors(apps=double))
assert any("admin_path='/auth'" in e for e in errors(admin_path="/auth"))
assert any("admin_path='/auth'" in e for e in errors(admin_path="/auth/"))
assert any("needs magiclink_enabled=True" in e for e in errors(magiclink_enabled=False))
assert any("needs base_url" in e for e in errors(base_url=""))
assert any("apikey_enabled=False" in e for e in errors(apikey_enabled=False))
assert any("'staff' does not begin with 'example-'" in w for w in findings(apps=apps(roles=["staff"]))[1])
assert not [w for w in findings()[1] if "does not begin with" in w]
for bad in ({"Example": apps()["example"]}, {"example": {"account": ""}}, {"example": {"account": "svc", "x": 1}},
            apps(scopes=["users:remove"]), apps(scopes=[]), apps(roles=[]), apps(link_ttl_min=0),
            apps(link_ttl_min=24 * 60 + 1), apps(max_accounts=0), apps(limits={"create_per_hour": 0}),
            apps(limits={"delete_per_week": 5}), apps(delete_grace_days=31), apps(delete_grace_days=-1),
            apps(delete_grace_days=True), apps(roles=["example-a,b"]), "nope"):
    assert any(e.startswith("apps") for e in errors(apps=bad)), bad
de = config_check.check_config(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), lang="de",
                                               base_url=BASE, available_roles=list(ROLES), apps=apps()))[0]
assert any("braucht magiclink_enabled=True" in e for e in de), de
ok("15: config_check — admin, delegate role, mapped role, unknown role, double account, admin_path='/auth', "
   "users:invite without magic link or base_url, keys off, malformed entries → errors; no app prefix → warning; German")

# ══ 16. the service account must exist and be a service account ════════════════════════════════════════════════
stream = io.StringIO()
sec_handler = logging.StreamHandler(stream)
logging.getLogger("tinysesam.security").addHandler(sec_handler)
try:
    db16 = os.path.join(tempfile.mkdtemp(), "s.db")
    a16, _ = build(db=db16)
    first = stream.getvalue()
    a16.create_user("svc-example", password=PW)                    # a PERSON under the service account's name
    stream.truncate(0), stream.seek(0)
    a16b, app16b = build(db=db16)
    second = stream.getvalue()
finally:
    logging.getLogger("tinysesam.security").removeHandler(sec_handler)
assert "Account API for application example is shut" in first and "does not exist" in first, first
assert "is not a service account" in second, second
assert a16b._check_app_accounts() == ["example"] and auth._check_app_accounts() == []
pk16 = a16b.create_api_key(a16b.store.get_user_by_name("svc-example")["id"], name="k")["key"]
assert client(app16b).get("/auth/api/provisioning", headers=H(pk16)).status_code == 403
ok("16: service account missing or a person → a security-log line at start, and its key opens nothing")

# ══ 17. one rule for delegates and applications ═════════════════════════════════════════════════════════════════
calls = []
real_may = config_check.may_manage


def spy(*a, **k):
    calls.append(("app" if a[1] is None else "panel"))
    return real_may(*a, **k)


config_check.may_manage = spy
try:
    from tinysesam.admin import PanelActions
    PanelActions(auth).fits(auth.store.get_user(foreign), {"id": boss}, frozenset({"example-member"}))
    c.post(f"/auth/api/users/{LENA}/disable", headers=H(key, anna))
    c.post(f"/auth/api/users/{LENA}/enable", headers=H(key, anna))
finally:
    config_check.may_manage = real_may
assert "panel" in calls and "app" in calls, calls
assert config_check.delegate_may_manage(frozenset({"a"}), 1, {"id": 2, "is_admin": 0, "is_owner": 0, "is_service": 0},
                                        []) is False, "a delegate manages an account without roles"
assert config_check.may_manage(frozenset({"a"}), None, {"id": 2, "is_admin": 0, "is_owner": 0, "is_service": 0}, [],
                               without_roles=True) is True
assert config_check.may_manage(frozenset({"a"}), None, {"id": 2, "is_admin": 0, "is_owner": 0, "is_service": 0},
                               ["a", "teamadmin"], delegate_roles=frozenset({"teamadmin"})) is False
ok("17: the panel's delegates and the application go through the one may_manage; an account without roles counts "
   "only for the application (owner by managed_by)")

# ══ 18. disabled=3 signs in nowhere ═════════════════════════════════════════════════════════════════════════════
locked = auth.create_user("lockedprobe", password=PW)
locked_key = auth.create_api_key(locked, name="k")["key"]
auth.store._exec("UPDATE users SET disabled=3 WHERE id=?", (locked,))
pc = client(app)
pc.cookies.set(auth.csrf_cookie_name, CSRF)
r = pc.post("/auth/login", data={"username": "lockedprobe", "password": PW, "_csrf": CSRF})
assert r.status_code >= 400 and not pc.cookies.get(auth.session_cookie_name), r.status_code
assert auth.verify_api_key(locked_key)[0] is None
assert client(app).get("/auth/apikeys", headers={"X-Api-Key": locked_key}).status_code == 401
raw_link = auth.create_magic_token("login", user_id=locked, ttl_min=10, payload={"next": "/", "issued": "operator"})
mc = client(app)
mc.cookies.set(auth.csrf_cookie_name, CSRF)
r = mc.post(f"/auth/magic/{raw_link}", data={"_csrf": CSRF})
assert r.status_code >= 400 and not mc.cookies.get(auth.session_cookie_name), r.status_code
with_passkey = importlib.util.find_spec("webauthn") is not None and importlib.util.find_spec("cbor2") is not None
if with_passkey:
    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    def b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    ORIGIN, RP = "http://localhost:8000", "localhost"
    ap, app_p = build(passkey_enabled=True, rp_id=RP, rp_name="Probe", origin=ORIGIN)
    pu = ap.create_user("passkeyprobe", password=PW)
    pkey = ec.generate_private_key(ec.SECP256R1())
    nums = pkey.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
    cred = os.urandom(32)
    ap.store.add_webauthn(pu, b64u(cred), b64u(cose), 0, ["internal"], "probe")
    counter = [0]

    def passkey_login():
        cc = client(app_p)
        cc.cookies.set(ap.csrf_cookie_name, CSRF)
        opts = cc.post("/auth/passkey/login/begin", headers={"X-CSRF-Token": CSRF}).json()
        counter[0] += 1
        auth_data = hashlib.sha256(RP.encode()).digest() + bytes([0x01 | 0x04]) + counter[0].to_bytes(4, "big")
        client_data = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": ORIGIN,
                                  "crossOrigin": False}).encode()
        sig = pkey.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        body = json.dumps({"id": b64u(cred), "rawId": b64u(cred), "type": "public-key",
                           "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                                        "signature": b64u(sig), "userHandle": None}})
        return cc, cc.post("/auth/passkey/login/finish", headers={"X-CSRF-Token": CSRF,
                                                                  "Content-Type": "application/json"}, content=body)

    cc, r = passkey_login()
    assert r.status_code == 200 and cc.cookies.get(ap.session_cookie_name), (r.status_code, r.text)  # the probe works
    ap.store._exec("UPDATE users SET disabled=3 WHERE id=?", (pu,))
    cc, r = passkey_login()
    assert r.status_code >= 400 and not cc.cookies.get(ap.session_cookie_name), (r.status_code, r.text)
else:
    print("  - 18 passkey skipped: extra [passkey] or cbor2 missing (a skip is not a green — check.sh installs it)")
with_oidc = all(importlib.util.find_spec(m) is not None for m in ("authlib", "httpx"))
if with_oidc:
    IDP = "https://idp.example.com"

    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    ao, app_o = build(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret")
    ao.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                     "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
    from tinysesam.oidc import OIDCClient
    ao.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)

    def provider_round():
        co = client(app_o)
        claims = {"sub": "fed-3", "preferred_username": "olga", "name": "Olga", "auth_time": int(time.time())}
        ao.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
            _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
        start = co.get("/auth/oidc/start?next=/")
        query = parse_qs(urlparse(start.headers["location"]).query)
        return co, co.get(f"/auth/oidc/callback?code=x&state={query['state'][0]}")

    co, r = provider_round()
    assert co.cookies.get(ao.session_cookie_name), (r.status_code, r.text[:200])                       # the probe works
    olga = ao.store.get_user_by_name("olga")["id"]
    ao.store._exec("UPDATE users SET disabled=3 WHERE id=?", (olga,))
    co, r = provider_round()
    assert r.status_code == 403 and not co.cookies.get(ao.session_cookie_name), (r.status_code, r.text[:200])
else:
    print("  - 18 OIDC skipped: extra [oidc] missing (a skip is not a green — check.sh installs it)")
ok("18: disabled=3 — no sign-in by password, passkey, sign-in link, OIDC; an API key is dead (401)")

# ══ listing, self-description, quota ════════════════════════════════════════════════════════════════════════════
page1 = c.get("/auth/api/users?limit=2", headers=H(key)).json()
assert len(page1["users"]) == 2 and page1["next"] == page1["users"][-1]["id"]
page2 = c.get(f"/auth/api/users?limit=2&after={page1['next']}", headers=H(key)).json()
assert page2["users"][0]["id"] > page1["next"]
everything = c.get("/auth/api/users?limit=200", headers=H(key)).json()
assert everything["next"] is None and all(u["state"] in prov.STATES for u in everything["users"])
editors = c.get("/auth/api/users?role=example-editor", headers=H(key)).json()["users"]
assert editors and all("example-editor" in u["roles"] for u in editors)
assert c.post(f"/auth/api/users/{LENA}/disable", headers=H(key, anna)).status_code == 200
assert [u["id"] for u in c.get("/auth/api/users?state=disabled", headers=H(key)).json()["users"]] == [LENA]
c.post(f"/auth/api/users/{LENA}/enable", headers=H(key, anna))
for bad in ("limit=0", "limit=201", "after=x", "state=gone", "foo=1"):
    assert c.get(f"/auth/api/users?{bad}", headers=H(key)).status_code == 400, bad
r = c.get("/auth/api/users", headers=H(key))
assert r.headers["cache-control"] == "no-store" and "access-control-allow-origin" not in r.headers
info = c.get("/auth/api/provisioning", headers=H(key)).json()
assert info["app"] == "example" and info["roles"] == ALLOW and info["scopes"] == SCOPES
assert info["accounts"] == auth.store.count_managed("example") and info["name"] == {"en": "Example", "de": "Example"}
aq, appq = build(apps=apps(max_accounts=1))
kq = aq.create_api_key(aq.create_service("svc-example"), name="k")["key"]
assert create(client(appq), kq).status_code == 201
r = create(client(appq), kq)
assert r.status_code == 409 and r.json()["error"] == "quota_reached", r.text
ar, appr = build(apps=apps(scopes=["users:read"]))
kr = ar.create_api_key(ar.create_service("svc-example"), name="k")["key"]
r = create(client(appr), kr)
assert r.status_code == 403 and r.json() == {"error": "scope_missing", "error_description": "users:invite"}
assert client(appr).get("/auth/api/users", headers=H(kr)).status_code == 200
ok("list: pages (limit/after/next), filters role/state, 400 for bad parameters, no-store and no CORS; "
   "self-description; quota → 409 quota_reached; a missing scope → 403 scope_missing")

# ══ email mode: the name follows the address ════════════════════════════════════════════════════════════════════
am, appm = build(login_identifier="email")
km = am.create_api_key(am.create_service("svc-example"), name="k")["key"]
r = client(appm).post("/auth/api/users", headers=H(km), json={"email": "Mia@Example.org", "roles": ["example-member"]})
assert r.status_code == 201 and r.json()["username"] == "mia@example.org", r.text
assert client(appm).post("/auth/api/users", headers=H(km), json={"username": "other", "email": "o@example.org",
                                                                   "roles": ["example-member"]}).status_code == 400
assert create(c, key, username="has@sign").status_code == 400
ok("email mode: the username follows the address; outside it a name with @ is refused")

# ══ without an application nothing changes ══════════════════════════════════════════════════════════════════════
off, off_app = build(apps={})
k_off = off.create_api_key(off.create_service("svc-example"), name="k")["key"]
assert not [r.path for r in off_app.routes if getattr(r, "path", "").startswith(("/auth/api/users",
                                                                                  "/auth/api/provisioning"))]
assert client(off_app).get("/auth/api/users", headers=H(k_off)).status_code == 404
assert off._check_app_accounts() == []
ok("off: without apps no routes, no start line")

print("OK test_accounts_api")

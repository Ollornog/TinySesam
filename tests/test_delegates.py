"""Delegated admins (T-74): team leads manage the accounts of their team in the admin panel without being
administrators — in a hierarchy (`manages`) and with a part of the actions (`can`).

* Allowed: create accounts and invitations, issue a sign-in link, lock and unlock, set or remove the managed roles —
  only on accounts whose roles ALL stand in the managed roles of one delegate role (no admin, owner or service
  account, never their own). A delegate role above appoints and removes the delegate roles below it.
* Never sideways or upwards: a delegate of the same level, of another branch or above is out of scope (404), the own
  delegate role and every role above it are never granted.
* Everything else of the panel stays admin-only — pinned for every route of the router (class protection), so a new
  route is admin-only unless it asks for the delegate scope.
* Only a browser session counts: an API key, an OAuth token and an app password neither open the panel nor carry a
  delegate role (E4, like `is_admin`, R6-5).
* The same step-up as administrators; creating, inviting and sign-in links always from a fresh confirmation.
* `config_check`: shape, every role known, no delegate role in a `roles` list, `manages` only to delegate roles and
  without a cycle, `can` only known actions, not `admin`.

Each guard has its mutation in the PR (named next to the check).
"""
import base64
import hashlib
import os
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check  # noqa: E402

BASE = "https://auth.example.com"
APP = "app.example.com"
DAV = "dav.example.com"
RESOURCE = f"https://{APP}/mcp"
CB = "http://127.0.0.1:33418/callback"
JSON = {"Accept": "application/json"}
A = "/auth/admin"
STALE = 100000
ROLES = ["A", "A-read", "B", "B-read", "C", "X", "area-admin", "team-a-admin", "team-b-admin", "team-c-admin"]


def delegates():
    return {"area-admin": {"roles": ["X"], "manages": ["team-a-admin", "team-b-admin"]},
            "team-a-admin": {"roles": ["A", "A-read"]},
            "team-b-admin": {"roles": ["B", "B-read"], "can": ["create", "disable", "roles"]},
            "team-c-admin": {"roles": ["C"]}}


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
               passkey_enabled=False, oidc_enabled=False, cookie_secure=False, base_url=BASE,
               apikey_enabled=True, magiclink_enabled=True, stepup_max_age_sec=900,
               forward_auth_enabled=True, trusted_redirect_hosts=[APP, DAV],
               forward_apps={DAV: {"name": "Files", "app_passwords": True}},
               available_roles=list(ROLES), admin_delegates=delegates(),
               topbar_links=[("Adm", "/adm", {"admin": True}), ("Team", "/team", {"role": "team-a-admin"})])
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid, *, age=0, full=True):
    """A session for `uid` whose sign-in and last confirmation lie `age` seconds back; `full=False` = a half session."""
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, full, "password", factors=["password"])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def row(uid):
    return auth.store.get_user(uid)


def roles_of(uid):
    return sorted(auth.user_roles(row(uid)))


def names(resp):
    assert resp.status_code == 200, (resp.status_code, resp.text)
    return sorted(u["username"] for u in resp.json())


def audit(event):
    return [a for a in auth.store.recent_audit(500) if a["event"] == event]


auth, app = build()
assert auth.ensure_admin("admin", "admin-pw-12345")
admin = auth.store.get_user_by_name("admin")["id"]
user = {}
for name, roles in (("area", ["area-admin"]), ("lead", ["team-a-admin"]), ("leadb", ["team-b-admin"]),
                    ("leadc", ["team-c-admin"]), ("both", ["area-admin", "team-a-admin"]),
                    ("m1", ["A"]), ("m2", ["A", "A-read"]), ("mb", ["B"]), ("mab", ["A", "B"]),
                    ("mixed", ["A", "C"]), ("cteam", ["C"]), ("x1", ["X"]), ("norole", []),
                    ("dl", ["team-a-admin", "A"])):
    user[name] = auth.create_user(name, password=f"{name}-pw-123456789", roles=roles)
user["svc"] = auth.create_service("svc", roles=["A"])
user["adm2"] = auth.create_user("adm2", password="adm2-pw-123456", is_admin=True, roles=["A"])
user["admin"] = admin
U = user

c_admin = session_client(auth, app, admin)
c = {n: session_client(auth, app, U[n]) for n in ("area", "lead", "leadb", "leadc", "both", "m1")}

# =====================================================================================
# What a delegate sees and may do (red before T-74: every request was 403)
# =====================================================================================
assert names(c["lead"].get(f"{A}/api/users", headers=JSON)) == ["m1", "m2"]
assert names(c["leadb"].get(f"{A}/api/users", headers=JSON)) == ["mb"]
assert names(c["leadc"].get(f"{A}/api/users", headers=JSON)) == ["cteam"]
assert names(c["area"].get(f"{A}/api/users", headers=JSON)) == ["dl", "lead", "leadb", "m1", "m2", "mab", "mb", "x1"]
assert names(c["both"].get(f"{A}/api/users", headers=JSON)) == ["leadb", "m1", "m2", "mab", "mb", "x1"]
assert c["m1"].get(f"{A}/api/users", headers=JSON).status_code == 403
assert len(c_admin.get(f"{A}/api/users", headers=JSON).json()) == len(auth.store.list_users())
ok("lists: a team lead sees their team; the area admin the teams below and their leads; an account holding "
   "area-admin AND team-a-admin treats other team-a-admins as peers; a plain account 403; the admin all")
# (Mutation: `scopes is None or visible(...)` → `True` in users() → red.)

lead_c = c["lead"]
r = lead_c.post(f"{A}/api/users", json={"username": "n1", "roles": ["A", "A-read"]})
assert r.status_code == 200, (r.status_code, r.text)
n1 = r.json()["id"]
assert roles_of(n1) == ["A", "A-read"] and not row(n1)["is_admin"] and not row(n1)["is_service"]
r = lead_c.post(f"{A}/api/users/{U['m1']}/disable", json={"disabled": True})
assert r.status_code == 200 and row(U["m1"])["disabled"], (r.status_code, r.text)
assert lead_c.post(f"{A}/api/users/{U['m1']}/disable", json={"disabled": False}).status_code == 200
assert not row(U["m1"])["disabled"]
assert lead_c.post(f"{A}/api/users/{U['m1']}/roles", json={"roles": ["A", "A-read"]}).status_code == 200
assert roles_of(U["m1"]) == ["A", "A-read"]
r = lead_c.post(f"{A}/api/users/{U['m1']}/signin-link", json={})
assert r.status_code == 200 and r.json()["url"].startswith(BASE), (r.status_code, r.text)
r = lead_c.post(f"{A}/api/invite", json={"roles": ["A"]})
assert r.status_code == 200 and r.json()["url"].startswith(BASE), (r.status_code, r.text)
assert lead_c.post(f"{A}/api/users/{U['m1']}/roles", json={"roles": ["A"]}).status_code == 200
ok("a team lead creates, invites, locks and unlocks, sets managed roles, issues a sign-in link")

line = next(a for a in audit("user_create") if a["detail"].startswith("n1 "))
assert line["username"] == "lead" and "as=team-a-admin" in line["detail"], dict(line)
line = audit("user_roles")[0]
assert line["username"] == "lead" and "as=team-a-admin" in line["detail"], dict(line)
assert any(a["username"] == "lead" and a["detail"].startswith(f"uid={U['m1']}") for a in audit("user_disable"))
assert any("actor=lead" in (a["detail"] or "") for a in audit("signin_link_issue"))
ok("audit: every delegate action names the acting account (actor=), the panel's lines also the role (as=)")
# (Mutation: drop the `as=` lines in log() → red.)

assert lead_c.post(f"{A}/api/users/{n1}/roles", json={"roles": []}).status_code == 200
assert roles_of(n1) == [] and "n1" not in names(lead_c.get(f"{A}/api/users"))
ok("E6: a delegate may remove every role; the account leaves their scope")

# =====================================================================================
# Hierarchy
# =====================================================================================
area_c = c["area"]
assert area_c.post(f"{A}/api/users/{U['m1']}/roles", json={"roles": ["A", "team-a-admin"]}).status_code == 200
assert roles_of(U["m1"]) == ["A", "team-a-admin"]
assert "m1" not in names(lead_c.get(f"{A}/api/users")), "a newly appointed team lead is the lead's peer"
assert lead_c.post(f"{A}/api/users/{U['m1']}/disable", json={"disabled": True}).status_code == 404
assert area_c.post(f"{A}/api/users/{U['m1']}/roles", json={"roles": ["A"]}).status_code == 200
assert roles_of(U["m1"]) == ["A"]
for wanted in (["A", "area-admin"], ["area-admin"], ["A", "team-c-admin"], ["C"]):
    r = area_c.post(f"{A}/api/users/{U['m1']}/roles", json={"roles": wanted})
    assert r.status_code == 400 and roles_of(U["m1"]) == ["A"], (wanted, r.status_code, r.text)
r = area_c.post(f"{A}/api/users", json={"username": "n2", "roles": ["B", "team-b-admin"]})
assert r.status_code == 200 and roles_of(r.json()["id"]) == ["B", "team-b-admin"], r.text
assert area_c.post(f"{A}/api/users", json={"username": "n3", "roles": ["area-admin"]}).status_code == 400
ok("hierarchy: the area admin appoints a team lead and removes them again; never the own role, never another branch")
# (Mutation: drop `barred` in _delegate_scopes → `both` red; `desc` out of `eff` in delegation_graph → red.)

for who, uid in (("same level", "leadb"), ("same role", "dl"), ("upwards", "area"), ("other branch", "leadc"),
                 ("area + team-a", "both"), ("two teams", "mab")):
    for path, body in (("disable", {"disabled": True}), ("roles", {"roles": ["A"]})):
        r = lead_c.post(f"{A}/api/users/{U[uid]}/{path}", json=body)
        assert r.status_code == 404, (who, path, r.status_code, r.text)
assert not row(U["area"])["disabled"] and roles_of(U["leadb"]) == ["team-b-admin"]
assert area_c.post(f"{A}/api/users/{U['mab']}/disable", json={"disabled": True}).status_code == 200
assert area_c.post(f"{A}/api/users/{U['mab']}/disable", json={"disabled": False}).status_code == 200
assert area_c.post(f"{A}/api/users/{U['leadc']}/disable", json={"disabled": True}).status_code == 404
assert c["both"].post(f"{A}/api/users/{U['lead']}/disable", json={"disabled": True}).status_code == 404
assert c["both"].post(f"{A}/api/users/{U['leadb']}/disable", json={"disabled": False}).status_code == 200
ok("never sideways or up: team lead → other lead, same role, area admin, other branch → 404; an account with A and B "
   "only for the area admin")
# (Mutation: `fits` → `return True` → red.)

# `can`: team-b-admin may create, lock and set roles — no sign-in link, no invitation
leadb_c = c["leadb"]
assert leadb_c.post(f"{A}/api/users/{U['mb']}/signin-link", json={}).status_code == 403
assert leadb_c.post(f"{A}/api/invite", json={"roles": ["B"]}).status_code == 403
assert leadb_c.post(f"{A}/api/users/{U['mb']}/disable", json={"disabled": True}).status_code == 200
assert leadb_c.post(f"{A}/api/users/{U['mb']}/disable", json={"disabled": False}).status_code == 200
assert leadb_c.post(f"{A}/api/users/{U['mb']}/roles", json={"roles": ["B", "B-read"]}).status_code == 200
assert '"can": ["create", "disable", "roles"]' in leadb_c.get(A).text
ok("can: team-b-admin without signin_link/invite → 403, its own actions go through; the panel gets its actions")
# (Mutation: `allowed()` returning all scopes → red.)

# A `manages` taken out (or a cycle put in) at runtime acts on the next request
auth.cfg.admin_delegates = {**delegates(), "area-admin": {"roles": ["X"]}}
assert names(area_c.get(f"{A}/api/users")) == ["x1"]
assert area_c.post(f"{A}/api/users/{U['lead']}/disable", json={"disabled": True}).status_code == 404
auth.cfg.admin_delegates["area-admin"]["manages"] = ["team-a-admin"]          # changed in place
assert names(area_c.get(f"{A}/api/users")) == ["dl", "lead", "m1", "m2", "x1"]
auth.cfg.admin_delegates = {**delegates(), "team-a-admin": {"roles": ["A"], "manages": ["area-admin"]}}
assert area_c.get(f"{A}/api/users", headers=JSON).status_code == 403
assert lead_c.get(f"{A}/api/users", headers=JSON).status_code == 403
auth.cfg.admin_delegates = delegates()
assert names(area_c.get(f"{A}/api/users"))[:2] == ["dl", "lead"]
ok("runtime: `manages` removed (also in place) shrinks the scope at once; a cycle leaves its roles without rights")

# =====================================================================================
# Attacks
# =====================================================================================
count = len(auth.store.list_users())
for body, code, why in (({"username": "x1x", "roles": ["C"]}, 400, "role outside the list"),
                        ({"username": "x2", "roles": ["A", "C"]}, 400, "one role outside the list"),
                        ({"username": "x3", "roles": ["team-a-admin"]}, 400, "own delegate role"),
                        ({"username": "x4", "roles": ["team-c-admin"]}, 400, "another delegate role"),
                        ({"username": "x5", "roles": []}, 400, "no role: nobody's account"),
                        ({"username": "x6"}, 400, "roles missing"),
                        ({"username": "x7", "roles": "A"}, 400, "roles as a string"),
                        ({"username": "x8", "roles": ["A"], "is_admin": True}, 403, "admin flag"),
                        ({"username": "x9", "roles": ["A"], "is_service": True}, 403, "service account")):
    r = lead_c.post(f"{A}/api/users", json=body)
    assert r.status_code == code, (why, r.status_code, r.text)
    r = lead_c.post(f"{A}/api/invite", json={k: v for k, v in body.items() if k != "username"})
    assert r.status_code == code, ("invite", why, r.status_code, r.text)
assert len(auth.store.list_users()) == count
ok("create/invite: role outside, delegate role, no role, string, admin flag, service → refused, nothing made")
# (Mutation: drop `delegate_roles_in(b, scope, …)` in user_create / invite → red.)

before = roles_of(U["m2"])
for body, code, why in (({"roles": ["A", "C"]}, 400, "a forbidden role among allowed ones (all or nothing)"),
                        ({"roles": ["team-a-admin"]}, 400, "own delegate role to another"),
                        ({"roles": ["A"], "is_admin": True}, 403, "admin flag"),
                        ({"roles": ["A"], "is_admin": False}, 403, "admin flag, even unchanged")):
    r = lead_c.post(f"{A}/api/users/{U['m2']}/roles", json=body)
    assert r.status_code == code, (why, r.status_code, r.text)
    assert roles_of(U["m2"]) == before and not row(U["m2"])["is_admin"], why
ok("roles: a list with one forbidden role writes nothing; delegate role or admin flag (even false) refused")
# (Mutation: drop the `set(roles) <= s[1]` check in user_roles → red; drop the `"is_admin" in b` check → red.)

forbidden = ["admin", "adm2", "leadc", "dl", "svc", "mixed", "cteam", "norole", "area"]
for who in forbidden + [None]:
    uid = U[who] if who else 999999
    snapshot = dict(row(uid)) if row(uid) else None
    for path, body in (("disable", {"disabled": True}), ("roles", {"roles": ["A"]}), ("roles", {"roles": []}),
                       ("signin-link", {})):
        r = lead_c.post(f"{A}/api/users/{uid}/{path}", json=body)
        assert r.status_code == 404, (who, path, r.status_code, r.text)
    assert snapshot == (dict(row(uid)) if row(uid) else None), who
ok("target admin, owner, delegate, service, other team, mixed, no role, unknown → 404 alike, nothing changed")

assert lead_c.post(f"{A}/api/users/{U['lead']}/disable", json={"disabled": True}).status_code == 400
assert lead_c.post(f"{A}/api/users/{U['lead']}/roles", json={"roles": ["A"]}).status_code == 404
assert lead_c.post(f"{A}/api/users/{U['lead']}/signin-link", json={}).status_code == 404
assert area_c.post(f"{A}/api/users/{U['area']}/roles", json={"roles": ["X"]}).status_code == 404
assert roles_of(U["lead"]) == ["team-a-admin"] and not row(U["lead"])["disabled"]
ok("own account: no self-lock, no own roles, no own sign-in link")

solo, solo_app = build()
solo.ensure_admin("root", "root-pw-123456")
root = solo.store.get_user_by_name("root")["id"]
tl = solo.create_user("tl", password="tl-pw-12345678", roles=["area-admin"])
c_tl = session_client(solo, solo_app, tl)
for path, body in (("roles", {"roles": []}), ("roles", {"roles": ["A"], "is_admin": False}),
                   ("disable", {"disabled": True})):
    assert c_tl.post(f"{A}/api/users/{root}/{path}", json=body).status_code == 404
assert solo.store.get_user(root)["is_admin"] and not solo.store.get_user(root)["disabled"]
ok("the last admin: a delegate's roles/flag/lock request → 404, the admin stays admin")

OPEN = {("GET", ""), ("GET", "/api/users"), ("POST", "/api/users"), ("POST", "/api/users/{uid}/disable"),
        ("POST", "/api/users/{uid}/roles"), ("POST", "/api/users/{uid}/signin-link"), ("POST", "/api/invite")}
seen, closed = set(), set()
fill = {"uid": str(U["m2"]), "cid": "1", "kid": "1", "grant_id": "1", "client_id": "x", "pw_id": "1", "name": "x"}
for route in auth.admin_router().routes:
    for method in sorted(route.methods - {"HEAD"}):
        key = (method, route.path)
        if key in OPEN:
            seen.add(key)
            continue
        url = A + re.sub(r"\{(\w+)\}", lambda m: fill[m.group(1)], route.path)
        for who in ("lead", "area"):
            r = c[who].request(method, url, headers=JSON, json={})
            assert r.status_code == 403, (who, key, r.status_code, r.text)
        closed.add(key)
assert seen == OPEN, OPEN - seen
must = {("POST", "/api/users/{uid}/password"), ("POST", "/api/users/{uid}/delete"), ("GET", "/api/users/{uid}/keys"),
        ("POST", "/api/users/{uid}/keys"), ("GET", "/api/sessions"), ("GET", "/api/audit"), ("POST", "/api/security"),
        ("POST", "/api/users/{uid}/owner"), ("GET", "/api/app-passwords"), ("GET", "/api/users/{uid}/passkeys")}
assert must <= closed, must - closed
assert roles_of(U["m2"]) == ["A", "A-read"] and not row(U["m2"])["disabled"]
ok(f"class protection: {len(closed)} admin-only routes answer every delegate 403; the {len(OPEN)} open ones exist")
# (Mutation: `delegates=False` → `True` in guard() → red.)

half = session_client(auth, app, U["lead"], full=False)
assert half.get(f"{A}/api/users", headers=JSON).status_code in (401, 403)
ok("a half session of a delegate gets nothing")

# =====================================================================================
# Machine credentials (E4): no panel, no delegate role
# =====================================================================================
key = auth.create_api_key(U["lead"], name="ci", roles=["team-a-admin"])["key"]
r = TestClient(app).get(f"{A}/api/users", headers={"Authorization": f"Bearer {key}", **JSON})
assert r.status_code == 403, (r.status_code, r.text)
r = TestClient(app).post(f"{A}/api/users", json={"username": "viakey", "roles": ["A"]},
                         headers={"X-API-Key": key, **JSON})
assert r.status_code == 403 and auth.store.get_user_by_name("viakey") is None
fwd = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": APP, "X-Forwarded-Uri": "/", "X-Forwarded-Method": "GET"}
gate = TestClient(app)
r = gate.get("/auth/forward", headers={**fwd, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and "team-a-admin" not in r.headers["Remote-Groups"].split(","), dict(r.headers)
assert gate.get("/auth/forward?roles=team-a-admin", headers={**fwd, "Authorization": f"Bearer {key}"}).status_code == 403
r = lead_c.get("/auth/forward", headers=fwd)
assert r.status_code == 200 and "team-a-admin" in r.headers["Remote-Groups"].split(","), dict(r.headers)
ok("automation API key of a delegate: panel 403, no delegate role at the gate (the session keeps it)")
# (Mutation: drop `_strip_delegate_roles` in the API key branch → red.)

# Second layer, independent of the stripping above: an account that reaches the check by any way other than a full
# browser session — whatever roles it still carries — is no delegate.
lead_row = dict(row(U["lead"]))
assert auth._delegate_scopes({**lead_row, "_via": "session"}) is not None
for via in ("apikey", "oauth", "app_password", None):
    assert auth._delegate_scopes({**lead_row, "_via": via}) is None, via
assert auth._delegate_scopes(lead_row) is None, "a row without `_via` (not from a session) is no delegate"
assert not auth._admin_panel_visible({**lead_row, "_via": "apikey"})
ok("only a full browser session makes a delegate — a key, a token, an app password or a bare row never")
# (Mutation: drop the `via != "session"` check in _delegate_scopes → red.)

secret = auth.create_app_password(U["lead"], "Phone", hosts=[DAV])["secret"]
basic = "Basic " + base64.b64encode(f"lead:{secret}".encode()).decode()
r = gate.get("/auth/forward", headers={**fwd, "X-Forwarded-Host": DAV, "Authorization": basic})
assert r.status_code == 200 and r.headers["Remote-User"] == "lead", (r.status_code, dict(r.headers))
assert "team-a-admin" not in r.headers["Remote-Groups"].split(","), r.headers["Remote-Groups"]
assert TestClient(app).get(f"{A}/api/users", headers={"Authorization": basic, **JSON}).status_code in (401, 403)
ok("app password of a delegate: no delegate role at the gate, no panel")
# (Mutation: drop `_strip_delegate_roles` in _app_password_user → red.)


def pkce():
    v = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")


oa, oa_app = build(csrf_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE])
ol = oa.create_user("ol", password="ol-pw-12345678", roles=["team-a-admin"])
oc = TestClient(oa_app, base_url="http://testserver", follow_redirects=False)
cid = oc.post("/auth/oauth/register", json={"client_name": "Tool", "redirect_uris": [CB],
                                            "grant_types": ["authorization_code"], "response_types": ["code"],
                                            "token_endpoint_auth_method": "none"}).json()["client_id"]
tok, _ = oa.start_session(ol, "password")
oc.cookies.set(oa.session_cookie_name, tok)
verifier, challenge = pkce()
r = oc.get("/auth/oauth/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": CB,
                                            "code_challenge": challenge, "code_challenge_method": "S256",
                                            "state": "s", "scope": "mcp", "resource": RESOURCE})
loc = r.headers["location"]
page = oc.get(loc)
csrf = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
r = oc.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": parse_qs(urlsplit(loc).query)["txn"][0],
                                         "decision": "allow"})
code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
at = oc.post("/auth/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                        "code_verifier": verifier, "client_id": cid}).json()["access_token"]
assert TestClient(oa_app).get(f"{A}/api/users", headers={"Authorization": f"Bearer {at}", **JSON}).status_code \
    in (401, 403)
r = TestClient(oa_app).get("/auth/forward", headers={**fwd, "X-Forwarded-Uri": "/mcp", "X-Forwarded-Method": "POST",
                                                     "Authorization": f"Bearer {at}"})
assert r.status_code == 200 and "team-a-admin" not in r.headers["Remote-Groups"].split(","), dict(r.headers)
ok("OAuth token of a delegate: panel refused, no delegate role at the gate")
# (Mutation: drop `_strip_delegate_roles` in oauth.user_for → red.)

# =====================================================================================
# Step-up and CSRF
# =====================================================================================
stale = session_client(auth, app, U["lead"], age=STALE)
r = stale.get(f"{A}/api/users", headers=JSON)
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), (r.status_code, dict(r.headers))
assert session_client(auth, app, U["m1"], age=STALE).get(f"{A}/api/users", headers=JSON).headers.get(
    "X-TinySesam-Reauth") is None, "a plain account gets its 403, not a detour through the reauth page"
ok("admin_require_mfa: a stale delegate session → 403 + reauth; a plain account 403 without reauth")
# (Mutation: drop the step-up lines in actor_scope → red.)

lax, lax_app = build(admin_require_mfa=False)
lx = lax.create_user("lx", password="lx-pw-12345678", roles=["team-a-admin"])
lm = lax.create_user("lm", password="lm-pw-12345678", roles=["A"])
c_lx = session_client(lax, lax_app, lx, age=STALE)
assert c_lx.get(f"{A}/api/users", headers=JSON).status_code == 200
for path, body in (("/api/users", {"username": "late", "roles": ["A"]}), ("/api/invite", {"roles": ["A"]}),
                   (f"/api/users/{lm}/signin-link", {})):
    r = c_lx.post(A + path, headers=JSON, json=body)
    assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), (path, r.status_code, r.text)
assert lax.store.get_user_by_name("late") is None
assert c_lx.post(f"{A}/api/users/{lm}/roles", json={"roles": ["A", "A-read"]}).status_code == 200
ok("admin_require_mfa=False: a stale delegate session lists and sets roles, but creates/invites/links only fresh")
# (Mutation: drop `auth._require_fresh(request, person)` in the delegate branch of user_create → red.)

strict, strict_app = build(csrf_enabled=True)
st = strict.create_user("st", password="st-pw-12345678", roles=["team-a-admin"])
sm = strict.create_user("sm", password="sm-pw-12345678", roles=["A"])
c_st = session_client(strict, strict_app, st)
assert c_st.get(A).status_code == 200
assert c_st.post(f"{A}/api/users/{sm}/disable", json={"disabled": True}).status_code == 403
assert c_st.post(f"{A}/api/users/{sm}/disable", json={"disabled": True},
                 headers={"X-CSRF-Token": "forged"}).status_code == 403
assert not strict.store.get_user(sm)["disabled"]
tok = c_st.cookies.get(strict.csrf_cookie_name)
assert c_st.post(f"{A}/api/users/{sm}/disable", json={"disabled": True},
                 headers={"X-CSRF-Token": tok}).status_code == 200
ok("CSRF: a delegate's write without or with a forged token → 403, with the token → 200")

# =====================================================================================
# Runtime changes, admin + delegate role
# =====================================================================================
auth.set_roles(U["leadc"], [])
assert c["leadc"].get(f"{A}/api/users", headers=JSON).status_code == 403
auth.set_roles(U["leadc"], ["team-c-admin"])
assert c["leadc"].get(f"{A}/api/users", headers=JSON).status_code == 200
adm3 = auth.create_user("adm3", password="adm3-pw-123456", is_admin=True, roles=["team-a-admin"])
assert len(session_client(auth, app, adm3).get(f"{A}/api/users", headers=JSON).json()) == len(auth.store.list_users())
ok("a removed delegate role acts on the next request; admin + delegate role = admin view")

# =====================================================================================
# Panel, top bar, account page
# =====================================================================================
c["m1"] = session_client(auth, app, U["m1"])     # its first session ended when the lead locked the account
html = area_c.get(A).text
view = re.search(r"const SCOPE=([^;]*);", html).group(1)
assert '"roles": ["A", "A-read", "B", "B-read", "X", "team-a-admin", "team-b-admin"]' in view, view
assert 'const ROLES=["A", "A-read", "B", "B-read", "X", "team-a-admin", "team-b-admin"]' in html
assert "const SCOPE=null" in c_admin.get(A).text
assert c["m1"].get(A, headers={"Accept": "text/html"}).status_code == 403
ok("panel page: a delegate gets their managed roles (incl. the delegate roles they appoint); the admin all; "
   "a plain account 403")

bar = lead_c.get("/auth/topbar.json").json()
assert bar["admin_panel"]["shown"] is True and bar["admin_panel"]["href"].endswith(A), bar
assert [link["title"] for link in bar["links"]] == ["Team"], bar["links"]
bar = c["m1"].get("/auth/topbar.json").json()
assert bar["admin_panel"]["shown"] is False and bar["links"] == [], bar
assert "Admin panel" in lead_c.get("/auth/account").text and "Admin panel" not in c["m1"].get("/auth/account").text
assert f"href='{A}'" in lead_c.get("/auth/account").text
ok("top bar and account page: a delegate sees \"Admin panel\", a plain account not; an {admin: True} link stays "
   "admin-only")
# (Mutation: `_admin_panel_visible` → only `is_admin` → red.)

# =====================================================================================
# config_check
# =====================================================================================


def check(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), available_roles=list(ROLES),
               admin_delegates=delegates())
    cfg.update(over)
    return config_check.check_config(TinySesamConfig(**cfg))


errors, warnings = check()
assert not [e for e in errors if "admin_delegates" in e], errors
assert not [w for w in warnings if "admin_delegates" in w], warnings
D = delegates()
for over, part in (({"admin_delegates": {**D, "team-a-admin": {"roles": ["A", "Z"]}}}, "'Z' is not in available_roles"),
                   ({"available_roles": ["A", "X"], "admin_delegates": {"area-admin": {"roles": ["X"]}}},
                    "'area-admin' is not in available_roles"),
                   ({"admin_delegates": {**D, "team-a-admin": {"roles": ["A", "team-a-admin"]}}},
                    "'team-a-admin' stands in the roles of 'team-a-admin'"),
                   ({"admin_delegates": {**D, "area-admin": {"roles": ["X", "team-c-admin"]}}},
                    "'team-c-admin' stands in the roles of 'area-admin'"),
                   ({"admin_delegates": {**D, "team-a-admin": {"roles": ["A"], "manages": ["team-a-admin"]}}},
                    "'team-a-admin' manages itself"),
                   ({"admin_delegates": {**D, "team-a-admin": {"roles": ["A"], "manages": ["area-admin"]}}},
                    "'area-admin' manages itself"),
                   ({"admin_delegates": {**D, "team-c-admin": {"roles": ["C"], "manages": ["X"]}}},
                    "'team-c-admin' manages 'X', which is not a delegate role"),
                   ({"admin_delegates": {**D, "team-c-admin": {"roles": ["C"], "can": ["delete"]}}},
                    "'team-c-admin' can 'delete', which is no action"),
                   ({"available_roles": ROLES + ["admin"], "admin_delegates": {"admin": {"roles": ["A"]}}},
                    "'admin' is not a delegate role"),
                   ({"admin_delegates": {"team-a-admin": {"roles": []}}}, "at least one role"),
                   ({"admin_delegates": {"team-a-admin": {"roles": "A"}}}, "at least one role"),
                   ({"admin_delegates": {"team-a-admin": {"roles": ["A"], "can": []}}}, "at least one role"),
                   ({"admin_delegates": {"team-a-admin": {"roles": ["A"], "scope": ["x"]}}}, "at least one role"),
                   ({"admin_delegates": ["team-a-admin"]}, "a mapping of delegate role")):
    errors, _ = check(**over)
    assert any(part in e for e in errors), (over, part, errors)
three = {"r1": {"roles": ["A"], "manages": ["r2"]}, "r2": {"roles": ["B"], "manages": ["r3"]},
         "r3": {"roles": ["C"], "manages": ["r1"]}}
errors, _ = check(available_roles=ROLES + ["r1", "r2", "r3"], admin_delegates=three)
assert sum("manages itself" in e for e in errors) == 3, errors
assert config_check.delegation_graph(three) == {}
assert check(admin_delegates={"area-admin": {"roles": [], "manages": ["team-a-admin"]},
                              "team-a-admin": {"roles": ["A"]}})[0] == []
_, warnings = check(admin_enabled=False)
assert any("admin_delegates is set, but admin_enabled=False" in w for w in warnings), warnings
de, _ = check(lang="de", admin_delegates={"team-a-admin": {"roles": ["Z"]}})
assert any("steht nicht in available_roles" in e for e in de), de
ok("config_check: unknown role, delegate role in roles, cycle (self, two, three steps), manages a non-delegate, "
   "unknown can, `admin`, bad shape → error; a cycle grants nothing at runtime; German text")
# (Mutation: drop the cycle loop in _admin_delegates → red; `usable` = all in delegation_graph → red.)

# The computation is pure — a delegation, an account's roles, a target — so it can be called per delegation (a tenant
# later) without the configuration or the database.
G = config_check.delegation_graph(delegates())
assert sorted(G["area-admin"]["eff"]) == ["A", "A-read", "B", "B-read", "X", "team-a-admin", "team-b-admin"]
assert G["team-a-admin"]["anc"] == {"area-admin"} and G["area-admin"]["desc"] == {"team-a-admin", "team-b-admin"}
assert config_check.delegate_scopes(G, ["A"]) == []
both = config_check.delegate_scopes(G, ["area-admin", "team-a-admin"])
assert [r for r, _, _ in both] == ["area-admin", "team-a-admin"]
assert "team-a-admin" not in both[0][1] and "team-b-admin" in both[0][1], both
plain = {"id": 7, "is_admin": 0, "is_owner": 0, "is_service": 0}
assert config_check.delegate_may_manage(G["team-a-admin"]["eff"], 1, plain, ["A"])
assert not config_check.delegate_may_manage(G["team-a-admin"]["eff"], 7, plain, ["A"]), "own account"
assert not config_check.delegate_may_manage(G["team-a-admin"]["eff"], 1, plain, ["A", "B"])
assert not config_check.delegate_may_manage(G["team-a-admin"]["eff"], 1, plain, [])
assert not config_check.delegate_may_manage(G["team-a-admin"]["eff"], 1, {**plain, "is_admin": 1}, ["A"])
ok("pure functions: delegation_graph, delegate_scopes, delegate_may_manage need neither configuration nor database")

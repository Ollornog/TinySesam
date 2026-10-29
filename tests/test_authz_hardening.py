"""Permission pitfalls that showed up while building a real app:
Admin satisfies every role · bootstrap token without local admins · group match by substring.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Depends
from fastapi.responses import Response
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

HTML = {"accept": "text/html"}
JSON = {"accept": "application/json"}


def build(**over):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    base = dict(db_path=db, csrf_enabled=False, lang="de", passkey_enabled=False, cookie_secure=False)
    base.update(over)
    return TinySesam(TinySesamConfig(**base)), db


def login(c, u="chef", pw="geheim12345"):
    return c.post("/auth/login", data={"username": u, "password": pw, "next": "/"}, follow_redirects=False)


# ---------- 1) Admin satisfies every role — can be switched off ----------
auth, db = build()
uid = auth.create_user("chef", password="geheim12345", is_admin=True)
admin = auth.store.get_user(uid)
assert auth.has_role(admin, "editor"), "Default: admin satisfies every role"
assert not auth.has_role(admin, "editor", admin_implies=False), "can be switched off per call"
os.unlink(db)

auth, db = build(admin_implies_roles=False)
uid = auth.create_user("chef", password="geheim12345", is_admin=True)
admin = auth.store.get_user(uid)
assert not auth.has_role(admin, "editor"), "config switches the implication off"
auth.set_roles(uid, ["editor"])
assert auth.has_role(auth.store.get_user(uid), "editor"), "a real role still counts"
os.unlink(db)

# … and the guards pass it through
auth, db = build()
auth.create_user("chef", password="geheim12345", is_admin=True)
app = FastAPI()
app.include_router(auth.router())


@app.get("/lax")
def lax(u=Depends(auth.require_role("editor"))):
    return {"ok": True}


@app.get("/strikt")
def strict(u=Depends(auth.require_role("editor", admin_implies=False))):
    return {"ok": True}


c = TestClient(app, headers=JSON)
assert login(c).status_code == 303
assert c.get("/lax").status_code == 200, "admin gets through (default)"
assert c.get("/strikt").status_code == 403, "…but not without a real role"
os.unlink(db)
print("  has_role: admin implication can be switched off via config AND via guard ok")


# ---------- 1b) require_role with several roles: one of them suffices ----------
# Same OR meaning as ?roles=a,b in forward-auth — otherwise the same question would mean
# something different depending on the operating mode. Until 2026-09 require_role took exactly one role.
auth, db = build(admin_implies_roles=False)
auth.create_user("anna", password="geheim12345", roles=["lektorat"])
auth.create_user("bob", password="geheim12345", roles=["vertrieb"])
app = FastAPI()
app.include_router(auth.router())


@app.get("/eine-von")
def one_of(u=Depends(auth.require_role("redaktion", "lektorat"))):
    return {"ok": True}


@app.get("/aus-liste")
def from_items(u=Depends(auth.require_role(["redaktion", "lektorat"]))):
    return {"ok": True}


@app.get("/beide", dependencies=[Depends(auth.require_role("lektorat")),
                                 Depends(auth.require_role("vertrieb"))])
def both():
    return {"ok": True}


ca = TestClient(app, headers=JSON)
assert login(ca, "anna").status_code == 303
assert ca.get("/eine-von").status_code == 200, "one of the named roles suffices"
assert ca.get("/aus-liste").status_code == 200, "a list instead of single arguments works too"
assert ca.get("/beide").status_code == 403, "stacked guards require ALL roles"

cb = TestClient(app, headers=JSON)
assert login(cb, "bob").status_code == 303
r = cb.get("/eine-von")
assert r.status_code == 403, "none of the roles → 403"
assert "redaktion" in r.text and "lektorat" in r.text, "the message names both roles"

# require(role=[...]) understands the same
assert auth.require(role=["redaktion", "lektorat"]) and auth.require(role="lektorat")

# An old positional call require_role("x", True) meant mfa=True — now keyword-only.
# Fail loudly instead of silently treating True as a role.
for broken in ((), ("editor", True)):
    try:
        auth.require_role(*broken)
        raise AssertionError(f"require_role{broken} should have failed")
    except (ValueError, TypeError):
        pass
os.unlink(db)
print("  require_role: several roles = one suffices; stacking requires all ok")


# ---------- 2) Bootstrap token only if local admins are intended ----------
auth, db = build()                       # admin_enabled default True
assert auth.admin_claim_token(), "with panel: token exists"
os.unlink(db)

auth, db = build(admin_enabled=False)    # pure OIDC app without panel
assert auth.admin_claim_token() is None, "without panel: no token"
uid = auth.create_user("wer", password="geheim12345")
assert not auth._consume_admin_claim("egal", auth.store.get_user(uid)), "and nothing to redeem"
os.unlink(db)

auth, db = build(admin_claim_ttl_min=0)
assert auth.admin_claim_token() is None, "ttl=0 switches it off"
os.unlink(db)
print("  First-admin token: only with admin_enabled and ttl>0 ok")


# ---------- 3) Group mapping compares exactly ----------
auth, db = build()
assert auth.cfg.group_match == "exact"
uid = auth.create_user("u", password="geheim12345")
auth.apply_idp_groups(uid, ["nicht-admin"], {"admin": "__admin__"})
assert not auth.store.get_user(uid)["is_admin"], "'admin' must not match 'nicht-admin'"
auth.apply_idp_groups(uid, ["nicht-admin"], {"admin": "editor"})
assert auth.store.get_roles(uid) == [], "no role from partial matches either"
auth.apply_idp_groups(uid, ["admin"], {"admin": "__admin__"})
assert auth.store.get_user(uid)["is_admin"], "exact match applies"
os.unlink(db)

# Substring stays possible — for LDAP DNs
auth, db = build(group_match="substring")
uid = auth.create_user("u", password="geheim12345")
auth.apply_idp_groups(uid, ["cn=staff,ou=groups,dc=example,dc=com"], {"cn=staff": "editor"})
assert auth.store.get_roles(uid) == ["editor"], "DN partial match applies"
os.unlink(db)

auth, db = build()
uid = auth.create_user("u", password="geheim12345")
auth.apply_idp_groups(uid, ["cn=staff,ou=g"], {"cn=staff": "editor"}, substring=True)
assert auth.store.get_roles(uid) == ["editor"], "can be forced per call (LDAP uses this)"
os.unlink(db)
print("  apply_idp_groups: exact as default, substring only where wanted ok")


# ---------- 4) issue_csrf for custom templates ----------
auth, db = build(csrf_enabled=True)
resp = Response()
token = auth.issue_csrf(resp)
assert token and auth.cfg.csrf_cookie in resp.headers.get("set-cookie", "")
os.unlink(db)

auth, db = build(csrf_enabled=False)
resp = Response()
assert auth.issue_csrf(resp) == "" and not resp.headers.get("set-cookie")
os.unlink(db)
print("  issue_csrf: sets cookie + returns token, no-op when CSRF is off ok")


# ---------- 5) OIDC callback path configurable ----------
cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), oidc_callback_path="/sso/cb")
assert cfg.oidc_callback_path == "/sso/cb"
assert TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei")).oidc_callback_path == "/auth/oidc/callback"
print("  oidc_callback_path: configurable, default unchanged ok")

print("OK test_authz_hardening")

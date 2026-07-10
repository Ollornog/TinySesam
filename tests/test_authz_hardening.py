"""Rechte-Fallen, die beim Bau einer echten App auffielen:
Admin erfüllt jede Rolle · Bootstrap-Token ohne lokale Admins · Gruppen-Match per Teilstring.
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
    db = tempfile.mktemp(suffix=".db")
    base = dict(db_path=db, csrf_enabled=False, lang="de", passkey_enabled=False, cookie_secure=False)
    base.update(over)
    return TinySesam(TinySesamConfig(**base)), db


def login(c, u="chef", pw="geheim12345"):
    return c.post("/auth/login", data={"username": u, "password": pw, "next": "/"}, follow_redirects=False)


# ---------- 1) Admin erfüllt jede Rolle — abschaltbar ----------
auth, db = build()
uid = auth.create_user("chef", password="geheim12345", is_admin=True)
admin = auth.store.get_user(uid)
assert auth.has_role(admin, "editor"), "Default: Admin erfüllt jede Rolle"
assert not auth.has_role(admin, "editor", admin_implies=False), "Per Aufruf abschaltbar"
os.unlink(db)

auth, db = build(admin_implies_roles=False)
uid = auth.create_user("chef", password="geheim12345", is_admin=True)
admin = auth.store.get_user(uid)
assert not auth.has_role(admin, "editor"), "Config schaltet die Implikation ab"
auth.set_roles(uid, ["editor"])
assert auth.has_role(auth.store.get_user(uid), "editor"), "echte Rolle zählt weiterhin"
os.unlink(db)

# … und die Guards reichen es durch
auth, db = build()
auth.create_user("chef", password="geheim12345", is_admin=True)
app = FastAPI()
app.include_router(auth.router())


@app.get("/lax")
def lax(u=Depends(auth.require_role("editor"))):
    return {"ok": True}


@app.get("/strikt")
def strikt(u=Depends(auth.require_role("editor", admin_implies=False))):
    return {"ok": True}


c = TestClient(app, headers=JSON)
assert login(c).status_code == 303
assert c.get("/lax").status_code == 200, "Admin kommt durch (Default)"
assert c.get("/strikt").status_code == 403, "…aber nicht ohne echte Rolle"
os.unlink(db)
print("  has_role: Admin-Implikation per Config UND per Guard abschaltbar ok")


# ---------- 2) Bootstrap-Token nur, wenn lokale Admins vorgesehen sind ----------
auth, db = build()                       # admin_enabled Default True
assert auth.admin_claim_token(), "mit Panel: Token existiert"
os.unlink(db)

auth, db = build(admin_enabled=False)    # reine OIDC-App ohne Panel
assert auth.admin_claim_token() is None, "ohne Panel: kein Token"
uid = auth.create_user("wer", password="geheim12345")
assert not auth.consume_admin_claim("egal", auth.store.get_user(uid)), "und nichts einzulösen"
os.unlink(db)

auth, db = build(admin_claim_ttl_min=0)
assert auth.admin_claim_token() is None, "ttl=0 schaltet es ab"
os.unlink(db)
print("  Erst-Admin-Token: nur mit admin_enabled und ttl>0 ok")


# ---------- 3) Gruppen-Mapping vergleicht exakt ----------
auth, db = build()
assert auth.cfg.group_match == "exact"
uid = auth.create_user("u", password="geheim12345")
auth.apply_idp_groups(uid, ["nicht-admin"], {"admin": "__admin__"})
assert not auth.store.get_user(uid)["is_admin"], "'admin' darf nicht auf 'nicht-admin' passen"
auth.apply_idp_groups(uid, ["nicht-admin"], {"admin": "editor"})
assert auth.store.get_roles(uid) == [], "auch keine Rolle aus Teiltreffern"
auth.apply_idp_groups(uid, ["admin"], {"admin": "__admin__"})
assert auth.store.get_user(uid)["is_admin"], "exakter Treffer greift"
os.unlink(db)

# Teilstring bleibt möglich — für LDAP-DNs
auth, db = build(group_match="substring")
uid = auth.create_user("u", password="geheim12345")
auth.apply_idp_groups(uid, ["cn=staff,ou=groups,dc=example,dc=com"], {"cn=staff": "editor"})
assert auth.store.get_roles(uid) == ["editor"], "DN-Teiltreffer greift"
os.unlink(db)

auth, db = build()
uid = auth.create_user("u", password="geheim12345")
auth.apply_idp_groups(uid, ["cn=staff,ou=g"], {"cn=staff": "editor"}, substring=True)
assert auth.store.get_roles(uid) == ["editor"], "je Aufruf erzwingbar (LDAP nutzt das)"
os.unlink(db)
print("  apply_idp_groups: exakt als Standard, Teilstring nur wo gewollt ok")


# ---------- 4) issue_csrf für eigene Templates ----------
auth, db = build(csrf_enabled=True)
resp = Response()
token = auth.issue_csrf(resp)
assert token and auth.cfg.csrf_cookie in resp.headers.get("set-cookie", "")
os.unlink(db)

auth, db = build(csrf_enabled=False)
resp = Response()
assert auth.issue_csrf(resp) == "" and not resp.headers.get("set-cookie")
os.unlink(db)
print("  issue_csrf: setzt Cookie + gibt Token, no-op wenn CSRF aus ok")


# ---------- 5) OIDC-Callback-Pfad konfigurierbar ----------
cfg = TinySesamConfig(db_path=tempfile.mktemp(), oidc_callback_path="/sso/cb")
assert cfg.oidc_callback_path == "/sso/cb"
assert TinySesamConfig(db_path=tempfile.mktemp()).oidc_callback_path == "/auth/oidc/callback"
print("  oidc_callback_path: konfigurierbar, Default unverändert ok")

print("OK test_authz_hardening")

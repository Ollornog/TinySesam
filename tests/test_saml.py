"""F1: SAML 2.0 SP — login redirect, ACS→user/session, group gate, metadata.
ACS flow with a forged client (no real signed assertion needed); metadata with a real onelogin."""

# This suite tests the SAML path — without python3-saml there is nothing to test. The promise
# lives here and not in the runner: only the suite itself knows what it needs.
from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("onelogin", extra="saml")
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


DUMMY_CERT = "MIID...dummy...cert"   # merely non-empty; the fake does not test real signature verification


class FakeSAML:
    def __init__(self, nameid="alice", attrs=None, valid=True):
        self.nameid, self.attrs, self.valid = nameid, (attrs or {}), valid
        self.contexts = []

    def login_url(self, req, base, return_to="/"):
        self.contexts.append(req)
        return (f"https://idp.example.com/sso?SAMLRequest=abc&RelayState={return_to}",
                "_authnreq-id-4711")

    def process(self, req, base, request_id=""):
        # The stand-in represents the real client AFTER a successful check — the comparison of
        # InResponseTo is covered by tests/test_security_findings.py. The `req` set is
        # recorded: python3-saml computes its own address from it and compares it
        # with the `Destination` of the assertion (F-16).
        self.contexts.append(req)
        self.seen_request_id = request_id
        return {"nameid": self.nameid, "attrs": self.attrs} if self.valid else None

    def metadata(self, base):
        self.metadata_base = base
        return "<md:EntityDescriptor/>"


def build(**cfgkw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(
        db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
        csrf_enabled=False, base_url=cfgkw.pop("base_url", "https://app.example.com"),
        saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
        saml_idp_x509cert=DUMMY_CERT, saml_attr_email="email", saml_attr_name="displayName",
        saml_attr_groups="groups", **cfgkw))
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def secret_text(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, app


JSON = {"Accept": "application/json"}

# ---------- Login page shows SAML button; /login redirects to the IdP ----------
db, auth, app = build()
assert auth.saml is not None
c = TestClient(app)
assert ">SAML</a>" in c.get("/auth/login").text
auth.saml = FakeSAML()
r = c.get("/auth/saml/login?next=/geheim", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/sso")
assert "RelayState=/geheim" in r.headers["location"]
ok("Login page shows SAML button; /auth/saml/login → redirect to the IdP (RelayState=next)")

# ---------- ACS: verified assertion → create user + logged in ----------
auth.saml = FakeSAML(nameid="alice", attrs={"email": ["alice@corp"], "displayName": ["Alice"],
                                            "groups": ["staff"]})
r = c.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim", r.headers.get("location")
assert c.get("/geheim", headers=JSON).json() == {"u": "alice"}
u = auth.store.get_user_by_name("alice")
# `saml_email_trusted` is off by default (PO decision 2026-09-24): the address from the
# assertion is not used, like H-3 for OIDC. The display name still comes through.
assert not u["email"] and u["display_name"] == "Alice", dict(u)
ok("ACS: valid assertion → local user (auto-create, display name, NO unproven address) + logged in")

# ---------- ACS: invalid assertion → 400 ----------
c2 = TestClient(app)
auth.saml = FakeSAML(valid=False)
r = c2.post("/auth/saml/acs", data={"SAMLResponse": "x"})
assert r.status_code == 400
ok("ACS: invalid/unverified assertion → 400")
os.remove(db)

# ---------- Group gate ----------
db, auth, app = build(saml_allowed_groups=["staff"])
c = TestClient(app)
auth.saml = FakeSAML(nameid="eve", attrs={"groups": ["extern"]})
r = c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
assert r.status_code == 403
ok("Group gate: missing allowed group → 403")
os.remove(db)

# ---------- real SP metadata via onelogin ----------
db, auth, app = build()
from tinysesam.saml_ import SAMLClient
md = SAMLClient(auth.cfg).metadata("https://app.example.com")
assert "EntityDescriptor" in md and "app.example.com/auth/saml/acs" in md
# via the route
assert TestClient(app).get("/auth/saml/metadata").status_code == 200
ok("SP metadata (onelogin) contains ACS URL + is retrievable via /auth/saml/metadata")
os.remove(db)

# ---------- Rejected assertion: diagnosable and not shown as "invalid link" ----------
# On the first run against a real IdP (Keycloak) a rejected assertion ended up on the
# magic-link error page, and the reason was nowhere to be found. Both are now part of the contract.
import io
import logging

db, auth, app = build()
auth.saml = FakeSAML(valid=False)
c = TestClient(app, headers={"Accept": "text/html"})

buffer = io.StringIO()
h = logging.StreamHandler(buffer)
seclog = logging.getLogger("tinysesam.security")
seclog.addHandler(h)
try:
    r = c.post("/auth/saml/acs", data={"SAMLResponse": "kaputt"})
finally:
    seclog.removeHandler(h)

assert r.status_code == 400, r.status_code
assert "link" not in r.text.lower(), "SAML error must not appear as a link problem"
ok("rejected assertion → 400 without a misleading magic-link page")

# The real client (not the stand-in) writes the reason to the security log — without it a
# failed sign-in cannot be explained from outside or from inside.
from tinysesam.saml_ import SAMLClient


class BrokenAuth:
    def process_response(self, request_id=None):
        pass

    def get_errors(self):
        return ["invalid_response"]

    def get_last_error_reason(self):
        return "Invalid issuer in the Assertion/Response"

    def is_authenticated(self):
        return False


client = SAMLClient(auth.cfg)
client._auth = lambda req, base: BrokenAuth()
buffer = io.StringIO()
h = logging.StreamHandler(buffer)
seclog.addHandler(h)
try:
    assert client.process({}, "https://app.example.com") is None
finally:
    seclog.removeHandler(h)
line = buffer.getvalue()
assert "invalid_response" in line and "Invalid issuer" in line, line
ok("Reason for the rejection is in the tinysesam.security logger (errors + reason)")
os.remove(db)

# ---------- F-14: an allowlist ADDRESS does not become first admin via SAML ----------
# SAML has no `email_verified`: no standard attribute says that the IdP verified the
# address. An IdP with self-registration (or a second tenant) therefore put
# `email=boss@example.com` into the assertion and was first admin of the instance on the first login —
# the bolt from F-14 hung on the OIDC callback alone. Now the ACS explicitly passes on
# "no proof", and `saml` counts as a federated factor (fail-closed).
db, auth, app = build(admin_identifiers=["boss@example.com"])
auth.saml = FakeSAML(nameid="angreifer", attrs={"email": ["boss@example.com"]})
c = TestClient(app)
r = c.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"}, follow_redirects=False)
assert r.status_code == 303, r.status_code          # the sign-in itself remains allowed
u = auth.store.get_user_by_name("angreifer")
assert u is not None and not u["is_admin"], dict(u) if u else None
assert not auth.admin_exists(), "the instance now has an admin — via an assertion attribute"
ok("F-14: an allowlist ADDRESS from the assertion does not promote (SAML has no proof)")
os.remove(db)

# Control: the allowlist NAME still counts. It is allowed only without auto-create (otherwise
# the constructor guard forbids it) — the operator then created the account themselves.
db, auth, app = build(admin_identifiers=["chefin"], saml_auto_create=False)
uid = auth.create_user("chefin", email="chefin@example.com")
auth.saml = FakeSAML(nameid="chefin", attrs={"email": ["chefin@example.com"]})
r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                         follow_redirects=False)
assert r.status_code == 303, r.status_code
assert auth.get_user(uid)["is_admin"], "the documented bootstrap path via the name is closed"
ok("... the allowlist NAME of a previously created account still promotes")
os.remove(db)

# ---------- B-bypass-1: the bolt also holds the SECOND login ----------
# The refusal above closes only THIS sign-in path. If the ACS created the account with the default
# `email_verified=1`, the account would show "proven" although the assertion proves nothing — and a
# factor the attacker sets up themselves in their freshly signed-in session (PIN,
# passkey) arrives without proof, reads the note and promotes after all.
db, auth, app = build(admin_identifiers=["boss@example.com"], pin_enabled=True, pin_login=True)
auth.saml = FakeSAML(nameid="mallory", attrs={"email": ["boss@example.com"]})
c = TestClient(app)
assert c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False).status_code == 303
mallory = auth.store.get_user_by_name("mallory")
assert not mallory["email_verified"], "SAML creates with a proof the assertion never carries"
assert c.post("/auth/pin/set", json={"pin": "246813"}).status_code == 200   # own session
c.get("/auth/logout")
c.cookies.clear()
r = c.post("/auth/pin", data={"username": "mallory", "pin": "246813"}, follow_redirects=False)
assert r.status_code == 303, r.status_code                   # the PIN login itself works
assert not auth.get_user(mallory["id"])["is_admin"], "first admin via the second hop"
assert not auth.admin_exists()
ok("B-bypass-1: ... a second factor set up by oneself does not promote the address either")
os.remove(db)

# ---------- B-bypass-10: the two SAML locks measured INDIVIDUALLY ----------
# Two bolts secure the same path: (1) the ACS route explicitly passes on "no proof",
# (2) `saml` is in `FEDERATED_FACTORS` and requires an explicit `True` there.
# As long as both exist, removing a single one goes unnoticed anywhere — whoever later
# rebuilds one loses it unnoticed. Each probe therefore detaches the other one.

# Lock 1 alone: `FEDERATED_FACTORS` empty, account with REAL proof (created by the
# operator). Now only the route's pass-through holds.
db, auth, app = build(admin_identifiers=["boss@example.com"])
uid = auth.create_user("angreifer", email="boss@example.com")
assert auth.store.get_user(uid)["email_verified"] == 1, "precondition: the account is proven"
auth._FEDERATED_FACTORS = ()                 # lock 2 detached
auth.saml = FakeSAML(nameid="angreifer", attrs={"email": ["boss@example.com"]})
assert TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                            follow_redirects=False).status_code == 303
assert not auth.get_user(uid)["is_admin"], \
    "the ACS route no longer passes on \"no proof\" — SAML promotes again"
ok("B-bypass-10: lock 1 alone — the ACS route passes on \"no proof\" (without FEDERATED_FACTORS)")
# Control: without the pass-through the same note promotes immediately — this measures that above
# the route REALLY decided.
assert auth._maybe_promote_admin(auth.get_user(uid), factor="saml") is True, \
    "even without both locks nothing promotes — then the check above measures nothing"
ok("... control: without both locks the note on the account promotes immediately")
os.remove(db)

# Lock 2 alone: without the route, directly at the source. A caller that simply forgets the proof
# (`email_confirmed=None`) must not promote via a federated factor.
db, auth, app = build(admin_identifiers=["boss@example.com"])
uid = auth.create_user("angreifer", email="boss@example.com")     # proof on the account: yes
assert auth._maybe_promote_admin(auth.get_user(uid), factor="saml") is False, \
    "the 'saml' factor no longer requires an explicit proof"
ok("B-bypass-10: lock 2 alone — the 'saml' factor does not promote without an explicit proof")
assert auth._maybe_promote_admin(auth.get_user(uid), email_confirmed=True, factor="saml") is True, \
    "even with proof the factor does not promote — then the check above measures nothing"
ok("... control: with an explicit proof the same call promotes")
os.remove(db)

# ---------- R4-12: a SAML identity does not occupy a local identifier ----------
# Username and email are ONE identifier space. The cross-check in `create_user` also
# hits the auto-create from SAML — and must arrive as a clean 403, not a 500. Measured with
# `saml_email_trusted=True`: only then do address and address-name get into the account at all (the
# default does not use them, see below).
for was, nameid, attrs in (
        ("deren Adresse lokal schon Kennung ist", "eve", {"email": ["chef@example.com"]}),
        ("deren Name lokal schon Adresse ist", "chef@example.com", {"email": ["eve@example.com"]})):
    db, auth, app = build(saml_email_trusted=True)
    local = auth.create_user("chef", password="lokal12345", email="chef@example.com")
    auth.saml = FakeSAML(nameid=nameid, attrs=attrs)
    r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
    assert r.status_code == 403, f"HTTP {r.status_code} — 303 would be an occupied identifier, 500 a defect"
    assert auth.store.get_user_by_name(nameid) is None, "the account was created despite the rejection"
    assert (auth.find_user("chef@example.com") or {})["id"] == local, "the identifier was taken over"
    assert any(z["event"] == "saml_ident_taken" for z in auth.store.recent_audit(20)), \
        "no audit entry — the rejection is invisible"
    ok(f"R4-12: a SAML identity, {was}, creates no account (403, no 500)")
    os.remove(db)

# Counter-check: free identifiers still create accounts.
db, auth, app = build()
auth.create_user("chef", password="lokal12345", email="chef@example.com")
auth.saml = FakeSAML(nameid="neu", attrs={"email": ["neu@example.com"]})
r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
assert r.status_code == 303 and auth.store.get_user_by_name("neu") is not None, r.status_code
ok("... with free identifiers SAML still creates")
os.remove(db)

# ---------- saml_email_trusted=False (default, PO decision 2026-09-24): like H-3 for OIDC ----------
# The unproven address of an assertion is not used: no account attribute, and an
# account name with `@` (NameID emailAddress) yields to a substitute name — otherwise it would occupy as
# `Remote-User` the identifier of the real owner.
db, auth, app = build(admin_identifiers=["chef@example.com"])
local = auth.create_user("chef", password="lokal12345", email="chef@example.com")
auth.saml = FakeSAML(nameid="chef＠example.com", attrs={"email": ["chef@example.com"]})   # Vollbreite
r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
new = [u for u in auth.store.list_users() if u["id"] != local]
assert r.status_code == 303 and len(new) == 1, (r.status_code, [dict(u) for u in new])
assert new[0]["username"].startswith("saml-") and not new[0]["email"], dict(new[0])
assert (auth.find_user("chef@example.com") or {})["id"] == local and not new[0]["is_admin"]
ok("saml_email_trusted=False: address not used, `@` name (also `＠`) → substitute name, no first admin")
os.remove(db)
db, auth, app = build(saml_email_trusted=True)
auth.saml = FakeSAML(nameid="bea@corp.example", attrs={"email": ["bea@corp.example"]})
assert TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                            follow_redirects=False).status_code == 303
process = auth.store.get_user_by_name("bea@corp.example")
assert process is not None and process["email"] == "bea@corp.example" and process["email_verified"], process
ok("saml_email_trusted=True: name and address from the assertion, the address counts as proven")
os.remove(db)

# ---------- F-16: the SP identity comes from base_url, not from the Host header ----------
# python3-saml builds from `https`, `http_host` and `script_name` the address it considers
# its own, and compares the `Destination` of the assertion against it. If scheme and host came from
# X-Forwarded-Proto/Host, the requester co-determined this comparison: they presented an assertion
# whose Destination names THEIR host, and set the header to match. Together
# with the binding via the bare username (F-11) this was an account takeover.
db16, auth16, app16 = build()
auth16.saml = FakeSAML()
c16 = TestClient(app16)
FOREIGN = {"X-Forwarded-Proto": "http", "X-Forwarded-Host": "angreifer.example",
         "Host": "angreifer.example"}

auth16.saml.contexts.clear()
c16.get("/auth/saml/login", headers=FOREIGN, follow_redirects=False)
_k = auth16.saml.contexts[-1]
assert _k["http_host"] == "app.example.com", f"foreign host in the SAML context: {_k}"
assert _k["https"] == "on", _k
ok("F-16: the AuthnRequest names the host from base_url, not the one from the header")

auth16.saml.contexts.clear()
c16.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"}, headers=FOREIGN,
         follow_redirects=False)
_k = auth16.saml.contexts[-1]
assert _k["http_host"] == "app.example.com", f"foreign host at the ACS: {_k}"
ok("F-16: …and the ACS computes its own address the same way")

# The metadata builds entity ID and ACS URL — they come from the same verified base, otherwise
# the document the IdP reads would contain the requester's name.
c16.get("/auth/saml/metadata", headers=FOREIGN)
assert auth16.saml.metadata_base == "https://app.example.com", auth16.saml.metadata_base
ok("F-16: …also the metadata the IdP reads")

# The path part of an app mounted under a subpath belongs in the self address,
# otherwise it deviates from the ACS URL in the settings and the Destination check fails.
db16b, auth16b, app16b = build(base_url="https://app.example.com/sso")
auth16b.saml = FakeSAML()
c16b = TestClient(app16b)
auth16b.saml.contexts.clear()
c16b.get("/auth/saml/login", follow_redirects=False)
_kb = auth16b.saml.contexts[-1]
assert _kb["script_name"] == "/sso/auth/saml/login", _kb
ok("F-16: the subpath from base_url is in the computed self address")

# And it is not appended twice if it is already in the path (ASGI mount).
from tinysesam.saml_ import request_context                                # noqa: E402
_direct = request_context("https://app.example.com/sso", "/sso/auth/saml/acs")
assert _direct["script_name"] == "/sso/auth/saml/acs", _direct
ok("F-16: …and not twice if it is already in the path")

for _d in (db16, db16b):
    os.remove(_d)

# ---------- F-11: the NameID binds, not the name ----------
# With SAML the stable identifier is the NameID (or an attribute if the IdP sends transient
# NameIDs). Without it the mapping hung on the username from an attribute — and whoever
# changes that in the directory got a foreign local account.
db11, auth11, app11 = build(saml_attr_username="uid")
c11 = TestClient(app11)


def _saml_sign_in(auth, app, nameid, attrs):
    auth.saml = FakeSAML(nameid=nameid, attrs=attrs)
    return TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                                follow_redirects=False)


# (1) A new account is bound to the NameID.
assert _saml_sign_in(auth11, app11, "nid-alice", {"uid": ["alice"]}).status_code == 303
_uid_a = auth11.store.get_user_by_name("alice")["id"]
assert auth11.store.get_federated_identifier("saml", _uid_a) == "nid-alice"
ok("F-11: an account created via SAML is bound to the NameID")

# (2) The IdP names the same person differently — same NameID, same account.
assert _saml_sign_in(auth11, app11, "nid-alice", {"uid": ["alice.neu"]}).status_code == 303
assert auth11.store.get_user_by_name("alice.neu") is None, "a second account was created"
ok("F-11: a new name with the same NameID leads to the same account")

# (3) The attack: foreign NameID under the old name.
_r = _saml_sign_in(auth11, app11, "nid-FREMD", {"uid": ["alice"]})
assert _r.status_code == 403, f"HTTP {_r.status_code} — the foreign account got through"
assert any(e["event"] == "saml_identifier_change" for e in auth11.store.recent_audit(limit=10))
ok("F-11: a foreign NameID under an old name is rejected")

# (4) `saml_attr_id`: if the IdP sends transient NameIDs, an attribute binds.
db11b, auth11b, app11b = build(saml_attr_username="uid", saml_attr_id="employeeNumber")
assert _saml_sign_in(auth11b, app11b, "transient-4711",
                      {"uid": ["bob"], "employeeNumber": ["p-0815"]}).status_code == 303
_uid_b = auth11b.store.get_user_by_name("bob")["id"]
assert auth11b.store.get_federated_identifier("saml", _uid_b) == "p-0815", \
    "the transient NameID was bound instead of the attribute"
# On the next login the NameID is a different one — the attribute stays.
assert _saml_sign_in(auth11b, app11b, "transient-9999",
                      {"uid": ["bob"], "employeeNumber": ["p-0815"]}).status_code == 303
assert auth11b.store.get_user_by_name("bob")["id"] == _uid_b
ok("F-11: saml_attr_id binds the attribute — a transient NameID changes on every login")

for _d in (db11, db11b):
    os.remove(_d)

# ---------- F-22: the ACS is rate-limited, and every rejection is in the audit log ----------
# Until 0.20.0 the ACS was the only sign-in route without throttling — and the most expensive: every POST goes
# through the XML signature check. Business rejections (group, no account, locked) ended
# silently in a 403; "I can't get in" could not be answered server-side.
db22, auth22, app22 = build(saml_allowed_groups=["staff"])
auth22.set_security("rate_limit_max", 3)
c22 = TestClient(app22)
auth22.saml = FakeSAML(nameid="eve", attrs={"groups": ["extern"]})
_reply22 = [c22.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False).status_code
           for _ in range(5)]
assert _reply22[:3] == [403, 403, 403] and _reply22[3:] == [429, 429], _reply22
ok("F-22: the ACS is rate-limited (after rate_limit_max → 429, before the signature check)")
_z22 = auth22.store.recent_audit(50)
assert any(z["event"] == "saml_denied" and z["username"] == "eve" and "reason=group" in (z["detail"] or "")
           and z["ip"] for z in _z22), [dict(z) for z in _z22][:5]
ok("F-22: group rejection → audit line saml_denied with reason and IP")
os.remove(db22)

db22b, auth22b, app22b = build(saml_auto_create=False)
auth22b.saml = FakeSAML(nameid="unbekannt", attrs={})
assert TestClient(app22b).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                               follow_redirects=False).status_code == 403
assert any(z["event"] == "saml_denied" and "reason=no_account" in (z["detail"] or "")
           for z in auth22b.store.recent_audit(20))
_uid22 = auth22b.create_user("gesperrt")
auth22b.store._exec("UPDATE users SET disabled=1 WHERE id=?", (_uid22,))
auth22b.saml = FakeSAML(nameid="gesperrt", attrs={})
assert TestClient(app22b).post("/auth/saml/acs", data={"SAMLResponse": "x"},
                               follow_redirects=False).status_code == 403
assert any(z["event"] == "saml_denied" and z["username"] == "gesperrt"
           and "reason=account_locked" in (z["detail"] or "") for z in auth22b.store.recent_audit(20))
auth22b.saml = FakeSAML(valid=False)
assert TestClient(app22b).post("/auth/saml/acs", data={"SAMLResponse": "x"}).status_code == 400
assert any(z["event"] == "saml_invalid" for z in auth22b.store.recent_audit(20))
ok("F-22: no account, locked account and rejected assertion each leave an audit line")
os.remove(db22b)

# ---------- F-21: SHA-1 in signature or digest is rejected ----------
# Measured against REAL python3-saml with a really signed assertion: only this proves that
# the switch in the settings also arrives where the signature is checked.
from onelogin.saml2.settings import OneLogin_Saml2_Settings  # noqa: E402
from tinysesam.saml_ import SAMLClient, request_context       # noqa: E402

_cfg21 = TinySesamConfig(db_path=":memory:", saml_enabled=True, passkey_enabled=False,
                         saml_idp_sso_url="https://idp.example.com/sso",
                         saml_idp_x509cert=DUMMY_CERT, base_url="https://app.example.com")
_st21 = OneLogin_Saml2_Settings(SAMLClient(_cfg21).settings("https://app.example.com"),
                                sp_validation_only=True)
assert _st21.get_security_data().get("rejectDeprecatedAlgorithm") is True, _st21.get_security_data()
ok("F-21: rejectDeprecatedAlgorithm is set in the effective python3-saml settings")

import importlib.util as _ilu21  # noqa: E402
if _ilu21.find_spec("cryptography") and _ilu21.find_spec("lxml"):
    import base64 as _b64
    import datetime as _dt
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from lxml import etree as _etree
    from onelogin.saml2.utils import OneLogin_Saml2_Utils as _Utils
    from onelogin.saml2.constants import OneLogin_Saml2_Constants as _K

    _key_name = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _now = _dt.datetime.now(_dt.timezone.utc)
    _name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "idp.example.com")])
    _cert = (_x509.CertificateBuilder().subject_name(_name).issuer_name(_name)
             .public_key(_key_name.public_key()).serial_number(1)
             .not_valid_before(_now - _dt.timedelta(days=1))
             .not_valid_after(_now + _dt.timedelta(days=30)).sign(_key_name, _hashes.SHA256()))
    _key_pem = _key_name.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                         _ser.NoEncryption()).decode()
    _cert_pem = _cert.public_bytes(_ser.Encoding.PEM).decode()
    _BASE, _IDP = "https://app.example.com", "https://idp.example.com/sso"
    _ACS, _SP = _BASE + "/auth/saml/acs", _BASE + "/auth/saml/metadata"

    def _signed_response(sig, dig, rid="_req-21"):
        prior = (_now - _dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        after = (_now + _dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r21" Version="2.0" '
            f'IssueInstant="{prior}" Destination="{_ACS}" InResponseTo="{rid}">'
            f'<saml:Issuer>{_IDP}</saml:Issuer><samlp:Status><samlp:StatusCode '
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'<saml:Assertion ID="_a21" Version="2.0" IssueInstant="{prior}"><saml:Issuer>{_IDP}</saml:Issuer>'
            '<saml:Subject><saml:NameID>alice</saml:NameID><saml:SubjectConfirmation '
            'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData '
            f'NotOnOrAfter="{after}" Recipient="{_ACS}" InResponseTo="{rid}"/></saml:SubjectConfirmation>'
            f'</saml:Subject><saml:Conditions NotBefore="{prior}" NotOnOrAfter="{after}">'
            f'<saml:AudienceRestriction><saml:Audience>{_SP}</saml:Audience></saml:AudienceRestriction>'
            f'</saml:Conditions><saml:AuthnStatement AuthnInstant="{prior}" SessionIndex="_s21">'
            '<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:'
            'Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            '<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>'
            'alice@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
            '</saml:Assertion></samlp:Response>')
        doc = _etree.fromstring(xml.encode())
        claim = doc.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        doc.replace(claim, _etree.fromstring(_Utils.add_sign(
            _etree.tostring(claim), _key_pem, _cert_pem, sign_algorithm=sig, digest_algorithm=dig)))
        return _b64.b64encode(_etree.tostring(doc)).decode()

    _real21 = SAMLClient(TinySesamConfig(
        db_path=":memory:", saml_enabled=True, passkey_enabled=False, saml_idp_sso_url=_IDP,
        saml_idp_x509cert="".join(_cert_pem.strip().splitlines()[1:-1]), base_url=_BASE))

    def _check21(sig, dig):
        req = request_context(_BASE, "/auth/saml/acs", form={"SAMLResponse": _signed_response(sig, dig)})
        return _real21.process(req, _BASE, request_id="_req-21")

    _good21 = _check21(_K.RSA_SHA256, _K.SHA256)
    assert _good21 and _good21["nameid"] == "alice", \
        f"precondition: a SHA-256-signed assertion must pass, otherwise the rest measures nothing: {_good21}"
    assert _check21(_K.RSA_SHA1, _K.SHA1) is None, "rsa-sha1 + sha1 was accepted"
    assert _check21(_K.RSA_SHA1, _K.SHA256) is None, "rsa-sha1 as signature method was accepted"
    assert _check21(_K.RSA_SHA256, _K.SHA1) is None, "sha1 as digest was accepted"
    ok("F-21: really signed assertion — SHA-256 passes, SHA-1 in signature OR digest does not")
else:                                                    # pragma: no cover
    print("  – F-21 not run against a really signed assertion (cryptography/lxml missing); "
          "only the settings switch is measured above")

# ---------- Proof attribute (PO decision 2026-09-25): acts like the switch, also for the first admin ----------
# Until here a proof travelled in via the ACS only with `saml_email_trusted`. With the attribute
# the proof was on the account, but the sign-in itself did not promote — only the
# next one via a local factor. Config check and runtime said different things.
for value, should in (("true", True), ("false", False)):
    db, auth, app = build(admin_identifiers=["boss@example.com"], saml_attr_email_verified="email_verified")
    auth.saml = FakeSAML(nameid="bossin", attrs={"email": ["boss@example.com"], "email_verified": [value]})
    r = TestClient(app).post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                             follow_redirects=False)
    u = auth.store.get_user_by_name("bossin")
    assert r.status_code == 303 and bool(u["is_admin"]) is should, (value, r.status_code, dict(u))
    os.remove(db)
ok("Proof attribute \"true\" promotes the allowlist address like the switch, \"false\" does not")

print("\nSAML OK ✅")

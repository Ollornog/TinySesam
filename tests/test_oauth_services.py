"""OAuth for services (T-60, ADR-13): pairing code, client_credentials with private_key_jwt, key rotation, revocation.

One negative test per rule — each names the rule it pins; the mutation that turns it red is listed in the PR. The
reference client (`tinysesam.client`) runs against the real routes through a transport into the test client.
"""
from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("joserfc", extra="services")

import base64
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
import time
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from joserfc import jws
from joserfc.jwk import OKPKey

from tinysesam import ConfigError, TinySesam, TinySesamConfig
from tinysesam import client as SC
from tinysesam import oauth_services as OS

BASE = "https://auth.example.com"
RESOURCE = "https://app.example.com/api"
RESOURCE2 = "https://other.example.com/api"
TOKEN_URL = BASE + "/auth/oauth/token"


def ok(msg):
    print("  ✓", msg)


def make(**over):
    d = tempfile.mkdtemp()
    cfg = dict(db_path=os.path.join(d, "t.db"), base_url=BASE, cookie_secure=False, passkey_enabled=False,
               forward_auth_enabled=True, oauth_enabled=True, oauth_service_clients=True,
               oauth_resources=[RESOURCE, RESOURCE2], trusted_redirect_hosts=["app.example.com", "other.example.com"],
               available_roles=["backup", "reader", "editor"], stepup_max_age_sec=900, lang="en")
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, TestClient(app, base_url="http://testserver", follow_redirects=False)


auth, app, c = make()
events = []
auth.on_security_event = lambda ev, acc, det: events.append((ev, acc["username"], det))
svc_uid = auth.create_service("backup", roles=["backup", "reader"])
alice = auth.create_user("alice", password="alice-pw-12345", is_admin=True, roles=["editor"])
bob = auth.create_user("bob", password="bob-pw-123456")
KEYDIR = tempfile.mkdtemp()


def transport_for(client):
    def transport(method, url, headers, body):
        u = urlsplit(url)
        path = u.path + (("?" + u.query) if u.query else "")
        r = client.request(method, path, headers=headers, content=body or None)
        return SC.Response(r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content)
    return transport


T = transport_for(c)


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def keyfile(name):
    return os.path.join(KEYDIR, name, "client.json")


def code_for(uid=svc_uid, **kw):
    kw.setdefault("name", "backup-job")
    kw.setdefault("resources", [RESOURCE])
    return auth.create_service_pairing(uid, **kw)["code"]


def forward(token_value=None, uri="/api/things", host="app.example.com", roles=None):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host, "X-Forwarded-Uri": uri, "X-Forwarded-Method": "GET"}
    if token_value:
        h["Authorization"] = f"Bearer {token_value}"
    if roles:
        h["X-TinySesam-Roles"] = roles
    return TestClient(app, base_url="http://testserver").get("/auth/forward", headers=h)


def audit_details(event):
    return [e["detail"] or "" for e in auth.store.recent_audit(1000) if e["event"] == event]


def token_form(assertion, **extra):
    f = {"grant_type": "client_credentials", "client_assertion_type": OS.ASSERTION_TYPE,
         "client_assertion": assertion}
    f.update(extra)
    return c.post("/auth/oauth/token", data=f)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def raw_jws(header, claims, sign_with=None):
    """A compact JWS assembled by hand (for headers joserfc would never produce)."""
    h = b64u(json.dumps(header).encode())
    p = b64u(json.dumps(claims).encode())
    sig = sign_with(f"{h}.{p}".encode()) if sign_with else b""
    return f"{h}.{p}.{b64u(sig)}"


def claims_for(cid, **over):
    now = int(time.time())
    d = {"iss": cid, "sub": cid, "aud": BASE, "iat": now, "exp": now + 60, "jti": os.urandom(12).hex()}
    d.update(over)
    return {k: v for k, v in d.items() if v is not None}


# ---------------------------------------------------------------- discovery
m = c.get("/.well-known/oauth-authorization-server").json()
assert "client_credentials" in m["grant_types_supported"], m
assert "private_key_jwt" in m["token_endpoint_auth_methods_supported"]
assert set(m["token_endpoint_auth_signing_alg_values_supported"]) == {"Ed25519", "EdDSA", "ES256"}
ok("RFC 8414: client_credentials, private_key_jwt and the algorithm list are advertised")

# ---------------------------------------------------------------- pairing
code = code_for()
assert len(code) == 19 and code.count("-") == 3, code
pair_issued = audit_details("oauth_pairing_issued")
assert pair_issued and code not in pair_issued[0] and code.replace("-", "") not in pair_issued[0]
row = auth.store._one("SELECT * FROM magic_token WHERE purpose='oauth_pairing'")
assert row["token_hash"] == auth.store.token_digest(OS.code_digest(OS.normalize_code(code)), "magic") and code not in json.dumps(dict(row))
ok("pairing code: 80 bits in groups, only its digest stored, not in the audit line")

sc = SC.ServiceClient.pair(BASE, code, keyfile("a"), transport=T)
cid = sc.client_id
assert cid.startswith("tss_")
mode = stat.S_IMODE(os.stat(keyfile("a")).st_mode)
assert mode == 0o600, oct(mode)
assert stat.S_IMODE(os.stat(os.path.dirname(keyfile("a"))).st_mode) == 0o700
state = read_json(keyfile("a"))
assert "d" in state["key"]["jwk"], "the private key lives in the key file"
stored = auth.store.oauth_client_keys(cid)
assert len(stored) == 1 and "d" not in stored[0]["jwk"] and stored[0]["kid"] == sc.kid
assert not any(k in json.dumps(auth.store._all("SELECT * FROM oauth_client_key")[0]["jwk"]) for k in ('"d"',))
assert ("oauth_service_paired", "backup", {"client_id": cid, "client_name": "backup-job",
                                           "resources": [RESOURCE]}) in events
ok("pair: the client makes the key, TinySesam stores only the public JWK; key file 0600 in a 0700 directory")

# The code is single use.
try:
    SC.ServiceClient.pair(BASE, code, keyfile("a2"), transport=T)
    raise AssertionError("a used pairing code paired again")
except SC.ServiceError as e:
    assert e.status == 400 and e.error == "invalid_grant", e
assert not os.path.exists(keyfile("a2"))
ok("pairing code: single use")

# Expired.
code2 = code_for()
auth.store._exec("UPDATE magic_token SET expires_at=? WHERE token_hash=?",
                 (int(time.time()) - 1, auth.store.token_digest(OS.code_digest(OS.normalize_code(code2)), "magic")))
try:
    SC.ServiceClient.pair(BASE, code2, keyfile("exp"), transport=T)
    raise AssertionError("an expired pairing code paired")
except SC.ServiceError as e:
    assert e.status == 400 and e.error == "invalid_grant", e
ok("pairing code: expired → refused")


def pair_raw(code, key, proof_key=None, nonce_code=None, aud=BASE, typ=OS.PAIRING_TYP, jwk=None):
    pk = proof_key or key
    nonce = OS.code_binding(OS.normalize_code(nonce_code or code))
    claims = {"aud": aud, "iat": int(time.time()), "exp": int(time.time()) + 60, "jti": "x" * 12, "nonce": nonce}
    proof = SC.sign(dict(pk, alg=pk["alg"]), typ, claims)
    return c.post("/auth/oauth/pair", json={"code": code, "jwk": jwk or SC.public_jwk(key), "proof": proof})


# Proof of possession: signed with another key than the one sent, bound to another code, wrong aud or type.
code3 = code_for()
k_real, k_other = SC.new_key(), SC.new_key()
r = pair_raw(code3, k_real, proof_key=k_other)
assert r.status_code == 400 and r.json()["error"] == "invalid_request", r.text
r = pair_raw(code3, k_real, nonce_code=code_for())
assert r.status_code == 400, r.text
r = pair_raw(code3, k_real, aud=TOKEN_URL)
assert r.status_code == 400, r.text
r = pair_raw(code3, k_real, typ="JWT")
assert r.status_code == 400, r.text
r = c.post("/auth/oauth/pair", json={"code": code3, "jwk": SC.public_jwk(k_real)})
assert r.status_code == 400, r.text
r = pair_raw(code3, k_real, jwk=dict(k_real["jwk"]))     # with the private part
assert r.status_code == 400 and "private" in r.json()["error_description"], r.text
assert any("reason=proof" in d for d in audit_details("oauth_pair_denied"))
# None of these burned the code: the rightful client still pairs with it.
r = pair_raw(code3, k_real)
assert r.status_code == 201, r.text
ok("pair: no proof, a proof of another key, code, audience or type, or a private JWK → refused")

# A code of a locked account pairs nothing.
code4 = code_for(bob, resources=[RESOURCE])
auth.set_disabled(bob, True)
r = pair_raw(code4, SC.new_key())
assert r.status_code == 400 and r.json()["error"] == "invalid_grant", r.text
ok("pair: a code whose account was locked meanwhile → refused (lock discards open codes)")

# Rate limit per address.
auth_rl, app_rl, c_rl = make()
for _ in range(OS.PAIR_PER_IP_HOUR):
    c_rl.post("/auth/oauth/pair", json={"code": "AAAA-AAAA-AAAA-AAAA"})
r = c_rl.post("/auth/oauth/pair", json={"code": "AAAA-AAAA-AAAA-AAAA"})
assert r.status_code == 429, r.status_code
ok(f"pair: throttled — {OS.PAIR_PER_IP_HOUR} attempts per address and hour")

# ---------------------------------------------------------------- tokens and forward auth
tok = sc.token()
r = forward(tok)
assert r.status_code == 200, (r.status_code, r.headers)
assert r.headers["remote-user"] == "backup"
assert set(r.headers["remote-groups"].split(",")) == {"backup", "reader"}, r.headers["remote-groups"]
assert forward(tok, host="other.example.com").status_code == 401, "token for RESOURCE used at RESOURCE2"
raw = c.post("/auth/oauth/token", data={"grant_type": "client_credentials", "client_assertion_type": OS.ASSERTION_TYPE,
                                         "client_assertion": sc._assertion(sc._state["key"])}).json()
assert raw["token_type"] == "Bearer" and "refresh_token" not in raw and raw["expires_in"] == 900, raw
assert raw["key_expires_at"] > time.time() + 80 * 86400
ok("client_credentials: opaque token, 15 min, no refresh token; forward auth sets Remote-* for the service account")

# Assertion rules — each refused with 401 invalid_client and its reason in the audit log.
key = sc._state["key"]


def refused(assertion, reason_part, **extra):
    r = token_form(assertion, **extra)
    assert r.status_code == 401 and r.json()["error"] == "invalid_client", (r.status_code, r.text)
    assert "client authentication failed" == r.json().get("error_description"), r.text
    hits = [d for d in audit_details("oauth_client_auth_failed") if reason_part in d]
    assert hits, (reason_part, audit_details("oauth_client_auth_failed")[:3])


foreign = SC.new_key()
refused(SC.sign(dict(foreign, kid=key["kid"]), OS.ASSERTION_TYP, claims_for(cid)), "signature_invalid")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, aud=TOKEN_URL)), "aud_must_be_the_issuer")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, aud=[BASE, RESOURCE])), "aud_must_be_the_issuer")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, exp=int(time.time()) - 120)), "assertion_expired")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, exp=int(time.time()) + 3600)), "s_ahead")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, exp=None)), "exp_missing")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, jti=None)), "jti_missing")
once = SC.sign(key, OS.ASSERTION_TYP, claims_for(cid))
assert token_form(once).status_code == 200
refused(once, "replayed")
refused(raw_jws({"alg": "none", "typ": "JWT"}, claims_for(cid)), "malformed")
refused(raw_jws({"alg": "none", "kid": key["kid"]}, claims_for(cid), sign_with=lambda m: b"x"), "algorithm_not_allowed")
pub = SC.public_jwk(key)
for secret in (json.dumps(pub).encode(), base64.urlsafe_b64decode(pub["x"] + "=="), pub["x"].encode()):
    refused(raw_jws({"alg": "HS256", "kid": key["kid"]}, claims_for(cid),
                    sign_with=lambda m: hmac.new(secret, m, hashlib.sha256).digest()), "algorithm_not_allowed")
attacker = OKPKey.generate_key("Ed25519")
emb = jws.serialize_compact({"alg": "Ed25519", "jwk": attacker.as_dict(private=False)},
                            json.dumps(claims_for(cid)).encode(), attacker, algorithms=["Ed25519"])
refused(emb, "signature_invalid")
emb_kid = jws.serialize_compact({"alg": "Ed25519", "kid": key["kid"], "jwk": attacker.as_dict(private=False),
                                 "jku": "https://evil.example/jwks"},
                                json.dumps(claims_for(cid)).encode(), attacker, algorithms=["Ed25519"])
refused(emb_kid, "signature_invalid")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid, sub="tss_other")), "iss_and_sub")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid)), "client_id_does_not_match", client_id="tss_other")
refused(SC.sign(key, "tinysesam-gate+jwt", claims_for(cid)), "wrong_JWT_type")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid)), "client_secret", client_secret="x")
refused(SC.sign(key, OS.ASSERTION_TYP, claims_for(cid)), "jwt-bearer", client_assertion_type="x")
r = c.post("/auth/oauth/token", data={"grant_type": "client_credentials"},
           headers={"Authorization": "Basic " + base64.b64encode(f"{cid}:x".encode()).decode()})
assert r.status_code == 401
ok("assertion: foreign key, token-endpoint aud, aud list, expired, far exp, no exp/jti, replayed jti, alg none, "
   "HS256 with the public key, embedded jwk/jku, iss≠sub, other client_id, other typ, secret → refused")

# A `typ` of plain JWT or none at all is accepted (RFC 10070: servers should not refuse untyped).
for hdr_typ in ("JWT", None):
    h = {"alg": "Ed25519", "kid": key["kid"]}
    if hdr_typ:
        h["typ"] = hdr_typ
    k_obj = OKPKey.import_key(key["jwk"])
    t2 = jws.serialize_compact(h, json.dumps(claims_for(cid)).encode(), k_obj, algorithms=["Ed25519"])
    assert token_form(t2).status_code == 200, hdr_typ
ok("assertion: typ JWT or none accepted (RFC 10070 §4)")

# Resources and scope.
r = token_form(sc._assertion(key), resource=RESOURCE2)
assert r.status_code == 400 and r.json()["error"] == "invalid_target", r.text
r = token_form(sc._assertion(key), resource="https://unknown.example.com/x")
assert r.status_code == 400 and r.json()["error"] == "invalid_target", r.text
r = token_form(sc._assertion(key), scope="mcp offline_access")
assert r.status_code == 400 and r.json()["error"] == "invalid_scope", r.text
ok("resource not allowed for the client or unknown → invalid_target; offline_access → invalid_scope")

# A service's client ID never starts an authorization or uses the person's grants.
r = c.get("/auth/oauth/authorize", params={"response_type": "code", "client_id": cid,
                                           "redirect_uri": "http://localhost:1/cb", "code_challenge": "x" * 43,
                                           "code_challenge_method": "S256", "resource": RESOURCE})
assert r.status_code == 400 and "location" not in r.headers
r = c.post("/auth/oauth/token", data={"grant_type": "refresh_token", "client_id": cid, "refresh_token": "tsrt_x"})
assert r.status_code == 401 and r.json()["error"] == "invalid_client"
ok("a service's client ID is refused at /authorize and for the person's grant types")

# ---------------------------------------------------------------- roles, never admin
alice_c = TestClient(app, base_url="http://testserver", follow_redirects=False)
tok_s = auth.store.create_session(alice, 86400, True, "password", factors=["password"])
alice_c.cookies.set(auth.session_cookie_name, tok_s)
alice_c.get("/auth/account")
csrf = alice_c.cookies.get(auth.csrf_cookie_name)
r = alice_c.post("/auth/oauth/services/pairing", json={"name": "my-script", "resources": [RESOURCE2]},
                 headers={"X-CSRF-Token": csrf})
assert r.status_code == 200, r.text
own = SC.ServiceClient.pair(BASE, r.json()["code"], keyfile("alice"), transport=T)
t_alice = own.token()
assert forward(t_alice, host="other.example.com").status_code == 200
assert forward(t_alice, host="other.example.com", roles="admin").status_code == 403
u, why = auth._oauth.user_for(t_alice, RESOURCE2 + "/x", "198.51.100.1")
assert u["is_admin"] == 0 and u["_oauth_service"] is True, u
ok("never admin: an admin's own service acts as the account without the admin flag")

scoped = auth.create_service_pairing(svc_uid, name="reader-only", resources=[RESOURCE], roles=["reader", "nope"])
assert scoped["roles"] == ["reader"] and scoped["dropped_roles"] == ["nope"]
sc_r = SC.ServiceClient.pair(BASE, scoped["code"], keyfile("scoped"), transport=T)
r = forward(sc_r.token())
assert r.status_code == 200 and r.headers["remote-groups"] == "reader", r.headers.get("remote-groups")
assert forward(sc_r.token(), roles="backup").status_code == 403
try:
    auth.create_service_pairing(svc_uid, resources=[RESOURCE], roles=["nope"])
    raise AssertionError("an empty scope became a code")
except ConfigError:
    pass
ok("role scope: trimmed to the account's roles, never widened, empty scope refused")

# ---------------------------------------------------------------- self-service and panel
r = alice_c.get("/auth/oauth/services")
assert [s["client_id"] for s in r.json()] == [own.client_id]
stale = TestClient(app, base_url="http://testserver")
tok_old = auth.store.create_session(alice, 86400, True, "password", factors=["password"])
then = int(time.time()) - 3600
auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                 (then, then, auth.store.session_hash(tok_old)))
stale.cookies.set(auth.session_cookie_name, tok_old)
stale.get("/auth/account")
r = stale.post("/auth/oauth/services/pairing", json={"resources": [RESOURCE]},
               headers={"X-CSRF-Token": stale.cookies.get(auth.csrf_cookie_name)})
assert r.status_code == 403, r.status_code
key_alice = auth.create_api_key(alice, name="ci")["key"]
r = c.post("/auth/oauth/services/pairing", json={"resources": [RESOURCE]}, headers={"Authorization": "Bearer " + key_alice})
assert r.status_code in (401, 403), r.status_code
r = c.post(f"/auth/oauth/services/{cid}/revoke", headers={"Authorization": "Bearer " + key_alice})
assert r.status_code in (401, 403)
r = alice_c.post(f"/auth/oauth/services/{cid}/revoke", headers={"X-CSRF-Token": csrf})
assert r.status_code == 404, "a foreign service was revoked from the account page"
ok("self-service: own list; pairing needs a fresh session (not an API key); a foreign service is not revocable")

page = alice_c.get("/auth/account").text
assert "id=svsec" in page and "sv_res" in page
admin_list = alice_c.get(auth.cfg.admin_path + "/api/oauth/services").json()
assert {s["client_id"] for s in admin_list} >= {cid, own.client_id}
r = alice_c.post(auth.cfg.admin_path + f"/api/users/{svc_uid}/service-pairing",
                 json={"name": "panel", "resources": [RESOURCE]}, headers={"X-CSRF-Token": csrf})
assert r.status_code == 200 and r.json()["code"], r.text
ok("account page section and admin panel: list, pairing code")

# ---------------------------------------------------------------- key rotation without an outage
before = sc.token()
old_key = dict(sc._state["key"])
new_kid = sc.rotate_key()
assert new_kid != old_key["kid"] and sc.kid == new_kid
kid_on_disk = read_json(keyfile("a"))["key"]["kid"]
assert sc._state["pending"] is None and kid_on_disk == new_kid
assert forward(before).status_code == 200, "a token issued before the rotation stopped working"
assert forward(sc.token()).status_code == 200
assert token_form(SC.sign(old_key, OS.ASSERTION_TYP, claims_for(cid))).status_code == 200, "overlap"
keys = auth.store.oauth_client_keys(cid)
assert keys[0]["kid"] == new_kid and keys[0]["retire_at"] is None
assert keys[1]["retire_at"] and keys[1]["retire_at"] <= int(time.time()) + OS.KEY_OVERLAP_SEC
# The same new key again (an answer got lost): success, nothing changes.
form = {"client_assertion_type": OS.ASSERTION_TYPE, "client_assertion": sc._assertion(sc._state["key"]),
        "jwk": json.dumps(SC.public_jwk(sc._state["key"])),
        "proof": SC.sign(sc._state["key"], OS.KEY_TYP, claims_for(cid, iss=None))}
r = c.post("/auth/oauth/service/keys", data=form)
assert r.status_code == 200 and r.json()["kid"] == new_kid, r.text
# A new key without proof of possession (proof signed by the old key) → refused.
k3 = SC.new_key()
form = {"client_assertion_type": OS.ASSERTION_TYPE, "client_assertion": sc._assertion(sc._state["key"]),
        "jwk": json.dumps(SC.public_jwk(k3)), "proof": SC.sign(sc._state["key"], OS.KEY_TYP, claims_for(cid, iss=None))}
r = c.post("/auth/oauth/service/keys", data=form)
assert r.status_code == 400, r.text
# Rotation without client authentication → refused.
form = {"jwk": json.dumps(SC.public_jwk(k3)), "proof": SC.sign(k3, OS.KEY_TYP, claims_for(cid, iss=None))}
assert c.post("/auth/oauth/service/keys", data=form).status_code == 401
# After the overlap the old key is dead.
auth.store._exec("UPDATE oauth_client_key SET retire_at=? WHERE client_id=? AND kid=?",
                 (int(time.time()) - 1, cid, old_key["kid"]))
refused(SC.sign(old_key, OS.ASSERTION_TYP, claims_for(cid)), "unknown_kid")
assert token_form(sc._assertion(sc._state["key"])).status_code == 200
ok("key rotation: new key proven and signed with the old; old tokens and the old key keep working for the overlap, "
   "then the old key is refused; repeating is a success")

# Key lifetime: an expired key is refused; the client rotates at half of it by itself.
auth.store._exec("UPDATE oauth_client_key SET expires_at=? WHERE client_id=? AND kid=?",
                 (int(time.time()) - 1, cid, sc.kid))
refused(sc._assertion(sc._state["key"]), "no_valid_key")
auth.store._exec("UPDATE oauth_client_key SET expires_at=? WHERE client_id=? AND kid=?",
                 (int(time.time()) + 86400, cid, sc.kid))
st = read_json(keyfile("a"))
st["key"]["created_at"] = int(time.time()) - 50 * 86400
st["key"]["expires_at"] = int(time.time()) + 40 * 86400
SC._write_private(keyfile("a"), st)
sc.invalidate()
kid_before = st["key"]["kid"]
sc.token()
assert sc.kid != kid_before, "the client did not rotate past half the key lifetime"
ok("key lifetime: an expired key is refused; the reference client rotates at half of it on its own")

# The new key is on disk BEFORE the server learns it: a rotation whose request fails leaves it as pending.
def failing_keys(method, url, headers, body):
    if url.endswith("/auth/oauth/service/keys"):
        raise ConnectionError("the network went away")
    return T(method, url, headers, body)


sc_fail = SC.ServiceClient(keyfile("a"), transport=failing_keys)
kid_fail = sc_fail.kid
try:
    sc_fail.rotate_key()
    raise AssertionError("the rotation did not fail")
except ConnectionError:
    pass
on_disk = read_json(keyfile("a"))
assert on_disk["pending"] and on_disk["key"]["kid"] == kid_fail, "the new key was not saved before the request"
on_disk["pending"] = None
SC._write_private(keyfile("a"), on_disk)
ok("rotation: the new key is written as pending before the server learns it")

# A crash between "pending written" and "server knows it": the next token request completes the rotation.
st = read_json(keyfile("a"))
st["pending"] = SC.new_key()
SC._write_private(keyfile("a"), st)
sc2 = SC.ServiceClient(keyfile("a"), transport=T)
sc2.token()
pending_on_disk = read_json(keyfile("a"))["pending"]
assert sc2.kid == st["pending"]["kid"] and pending_on_disk is None
ok("rotation survives a crash: the pending key is completed with the next request")

# The other crash: the server took the new key, the client died before it saved that. On disk the old key is still
# "current" (on the server it is in its overlap) — the retry with its assertion must still succeed, although a key in
# its overlap may not rotate (A-2): the proof shows possession of the key that is current on the server.
auth.store._exec("UPDATE oauth_client_key SET retire_at=? WHERE client_id=? AND retire_at IS NOT NULL",
                 (int(time.time()) - 1, cid))           # the earlier rotations' overlaps are over (at most 3 keys)
st = read_json(keyfile("a"))
st["pending"] = SC.new_key()
form = {"client_assertion_type": OS.ASSERTION_TYPE, "client_assertion": SC.sign(st["key"], OS.ASSERTION_TYP,
                                                                               claims_for(cid)),
        "jwk": json.dumps(SC.public_jwk(st["pending"])),
        "proof": SC.sign(st["pending"], OS.KEY_TYP, claims_for(cid, iss=None))}
r = c.post("/auth/oauth/service/keys", data=form)
assert r.status_code == 200, r.text      # the server knows it, the disk not
SC._write_private(keyfile("a"), st)
sc3 = SC.ServiceClient(keyfile("a"), transport=T)
sc3.token()
assert sc3.kid == st["pending"]["kid"] and read_json(keyfile("a"))["pending"] is None
assert auth.store.oauth_client_keys(cid)[0]["kid"] == st["pending"]["kid"]
ok("rotation survives a crash after the server took the key: the retry with the replaced key's assertion succeeds")

# A-2 (attack round 2026-11-21): only the CURRENT key may rotate. With a copy of the key file (backup, image layer, CI
# cache) taken before the operator rotated, a stranger signed the rotation with the old key — still within its hour
# of overlap — rotated in a key of their own, and the rightful new key was put on the overlap clock instead.
auth.store._exec("UPDATE oauth_client_key SET retire_at=? WHERE client_id=? AND retire_at IS NOT NULL",
                 (int(time.time()) - 1, cid))
stolen = dict(read_json(keyfile("a"))["key"])           # the copy the attacker took
sc3.rotate_key()                                        # the operator rotates — the copy should now run out
current = sc3.kid
mine = SC.new_key()
form = {"client_assertion_type": OS.ASSERTION_TYPE,
        "client_assertion": SC.sign(stolen, OS.ASSERTION_TYP, claims_for(cid)),
        "jwk": json.dumps(SC.public_jwk(mine)), "proof": SC.sign(mine, OS.KEY_TYP, claims_for(cid, iss=None))}
r = c.post("/auth/oauth/service/keys", data=form)
keys = {k["kid"]: k for k in auth.store.oauth_client_keys(cid)}
assert keys[current]["retire_at"] is None, "the rightful current key was put on the overlap clock by the old key"
assert mine["kid"] not in keys, "a key in its overlap rotated in a key of its own"
assert r.status_code == 401, (r.status_code, r.text)
assert any(a["event"] == "oauth_service_key_rotate_refused" for a in auth.store.recent_audit(20))
# … while the old key still gets tokens during its overlap (that is what the overlap is for).
assert token_form(SC.sign(stolen, OS.ASSERTION_TYP, claims_for(cid))).status_code == 200
ok("A-2: a key within its overlap may not rotate (refused, audited); it still gets tokens until the overlap ends")

# ---------------------------------------------------------------- revocation
# Forward auth reads account and service on every request — also when only the row says so (a write by another
# process or an older version that did not delete the tokens).
t_live = sc2.token()
now_s = int(time.time())
auth.store._exec("UPDATE oauth_service_client SET revoked_at=? WHERE client_id=?", (now_s, cid))
assert forward(t_live).status_code == 401, "a token of a revoked service still worked"
auth.store._exec("UPDATE oauth_service_client SET revoked_at=NULL WHERE client_id=?", (cid,))
auth.store._exec("UPDATE users SET disabled=2 WHERE id=?", (svc_uid,))
assert forward(t_live).status_code == 401, "a token of a locked account still worked"
auth.store._exec("UPDATE users SET disabled=0 WHERE id=?", (svc_uid,))
assert forward(t_live).status_code == 200
ok("forward auth reads the service row and the account on every request")


assert forward(t_live).status_code == 200
auth.set_disabled(svc_uid, True)
assert forward(t_live).status_code == 401, "a token of a locked service account still worked"
assert auth.store.oauth_service(cid)["revoked_at"] is not None
refused(sc2._assertion(sc2._state["key"]), "client_revoked")
assert auth.store.oauth_client_keys(cid) == []
ok("service account locked → its tokens stop at once, the service is revoked, its keys are deleted")

# "End all sessions" (and an admin password reset) revoke an account's services like its API keys.
code_end = code_for(alice, resources=[RESOURCE2], name="ends-with-sessions")
ends = SC.ServiceClient.pair(BASE, code_end, keyfile("ends"), transport=T)
end_c = TestClient(app, base_url="http://testserver")
end_c.cookies.set(auth.session_cookie_name, auth.store.create_session(alice, 86400, True, "password",
                                                                      factors=["password"]))
end_c.get("/auth/account")
r = end_c.post("/auth/sessions/revoke", json={"scope": "all"}, headers={"X-CSRF-Token": end_c.cookies.get(auth.csrf_cookie_name)})
assert r.status_code == 200, r.text
assert auth.store.oauth_service(ends.client_id)["revoked_at"] is not None, "end all sessions kept the service"
assert auth.store.oauth_service(own.client_id)["revoked_at"] is not None
ok("end all sessions revokes the account's services (the API-key path)")
# alice's session ended with it — sign in again for what follows.
tok_s = auth.store.create_session(alice, 86400, True, "password", factors=["password"])
alice_c.cookies.set(auth.session_cookie_name, tok_s)
alice_c.get("/auth/account")
csrf = alice_c.cookies.get(auth.csrf_cookie_name)
code_own = code_for(alice, resources=[RESOURCE2], name="my-script")
own = SC.ServiceClient.pair(BASE, code_own, keyfile("alice2"), transport=T)

t_own = own.token()
r = alice_c.post(f"/auth/oauth/services/{own.client_id}/revoke", headers={"X-CSRF-Token": csrf})
assert r.status_code == 200
assert forward(t_own, host="other.example.com").status_code == 401
assert ("oauth_service_revoked", "alice", {"client_id": own.client_id, "client_name": "my-script",
                                           "reason": "user"}) in events
ok("revoked from the account page → the next request is refused")

# ---------------------------------------------------------------- housekeeping and the switch
code5 = code_for(alice, resources=[RESOURCE2], name="gc-test")
g = SC.ServiceClient.pair(BASE, code5, keyfile("gc"), transport=T)
auth.store._exec("UPDATE oauth_client SET created_at=?, last_used=? WHERE client_id=?",
                 (1, 1, g.client_id))
auth.gc()
assert auth.store.oauth_service(g.client_id) is not None, "gc removed a live service"
assert auth.store._one("SELECT COUNT(*) AS n FROM oauth_assertion WHERE expires_at <= ?", (int(time.time()),))["n"] == 0
ok("gc keeps a live service without a recent token; expired replay entries go")

t_g = g.token()
auth_off = TinySesam(TinySesamConfig(**dict(auth.cfg.__dict__, oauth_service_clients=False)))
app_off = FastAPI()
app_off.include_router(auth_off.router())
h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "other.example.com", "X-Forwarded-Uri": "/api/x",
     "Authorization": "Bearer " + t_g}
assert TestClient(app_off).get("/auth/forward", headers=h).status_code == 401
r = TestClient(app_off).post("/auth/oauth/token", data={"grant_type": "client_credentials"})
assert r.json()["error"] == "unsupported_grant_type"
assert TestClient(app_off).post("/auth/oauth/pair", json={}).status_code in (404, 405)
ok("switch off: no grant type, no pairing route, existing service tokens refused")

# ---------------------------------------------------------------- configuration
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "x.db"), oauth_service_clients=True))
    raise AssertionError("services without the OAuth server were accepted")
except ConfigError as e:
    assert "oauth_enabled" in str(e)
# Without the extra: a warning at the start (like every extra), and pairing and tokens fail closed.
import importlib.util as _ilu
import logging as _logging
_real = _ilu.find_spec
_seen = []


class _Catch(_logging.Handler):
    def emit(self, record):
        _seen.append(record.getMessage())


_h = _Catch()
_logging.getLogger("tinysesam.security").addHandler(_h)
_ilu.find_spec = lambda name, *a, **k: None if name == "joserfc" else _real(name, *a, **k)
try:
    auth_nx, app_nx, c_nx = make()
finally:
    _ilu.find_spec = _real
    _logging.getLogger("tinysesam.security").removeHandler(_h)
assert any("[services]" in m and "joserfc" in m for m in _seen), _seen
_saved = {k: sys.modules.get(k) for k in list(sys.modules) if k == "joserfc" or k.startswith("joserfc.")}
for k in _saved:
    sys.modules[k] = None          # the import fails as without the extra
try:
    r = c_nx.post("/auth/oauth/pair", json={"code": "AAAA-AAAA-AAAA-AAAA", "jwk": {"kty": "OKP", "crv": "Ed25519",
                                                                                     "x": "A" * 43}, "proof": "x"})
    assert r.status_code == 500 and r.json()["error"] == "server_error", r.text
finally:
    for k, v in _saved.items():
        sys.modules[k] = v
ok("configuration: services need oauth_enabled; without the extra [services] a warning, and pairing fails closed")

print("all OAuth-for-services tests passed")

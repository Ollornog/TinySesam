"""OAuth 2.1 authorization server for MCP clients (T-36, ADR-11): the flow, and one negative test per rule.

The rules come from the research behind ADR-11 (token format and storage, code, PKCE, redirect, refresh rotation
and reuse, open registration, consent, resource). Each block names the rule it pins; the mutation that turns it
red is listed in the PR. A happy path alone would prove nothing here — most of the code is about refusing.
"""
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import ConfigError, TinySesam, TinySesamConfig
from tinysesam import oauth as O

RESOURCE = "https://app.example.com/mcp"
BASE = "https://auth.example.com"
CB = "http://localhost:43123/callback"


def ok(msg):
    print("  ✓", msg)


def make(**over):
    d = tempfile.mkdtemp()
    cfg = dict(db_path=os.path.join(d, "t.db"), base_url=BASE, cookie_secure=False, passkey_enabled=False,
               forward_auth_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE],
               trusted_redirect_hosts=["app.example.com"], lang="en")
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, TestClient(app, base_url="http://testserver", follow_redirects=False)


auth, c = make()
events = []
auth.on_security_event = lambda ev, acc, det: events.append((ev, acc["username"], det))
alice = auth.create_user("alice", password="alice-pw-12345")
bob = auth.create_user("bob", password="bob-pw-123456")


def sign_in(client, uid):
    tok, _ = auth.start_session(uid, "password")
    client.cookies.set(auth.session_cookie_name, tok)


def register(client=c, **meta):
    body = {"client_name": "Claude Code (test)", "redirect_uris": [CB],
            "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
            "token_endpoint_auth_method": "none"}
    body.update(meta)
    return client.post("/auth/oauth/register", json=body)


def pkce():
    v = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")


def authorize_params(cid, challenge, **over):
    p = {"response_type": "code", "client_id": cid, "redirect_uri": CB, "code_challenge": challenge,
         "code_challenge_method": "S256", "state": "st-123", "scope": "mcp offline_access", "resource": RESOURCE}
    p.update(over)
    return {k: v for k, v in p.items() if v is not None}


def consent(client, cid, challenge, decision="allow", **over):
    """authorize → consent page → answer; returns the redirect Location to the client."""
    r = client.get("/auth/oauth/authorize", params=authorize_params(cid, challenge, **over))
    assert r.status_code == 303, (r.status_code, r.text[:300])
    loc = r.headers["location"]
    assert "/auth/oauth/consent?txn=" in loc, loc
    page = client.get(loc)
    assert page.status_code == 200, (page.status_code, page.text[:300])
    csrf = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
    txn = parse_qs(urlsplit(loc).query)["txn"][0]
    r = client.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": txn, "decision": decision})
    assert r.status_code == 303, (r.status_code, r.text[:300])
    return r.headers["location"], page


def get_code(client, cid, challenge, **over):
    loc, _ = consent(client, cid, challenge, **over)
    q = parse_qs(urlsplit(loc).query)
    return q["code"][0], q


def token(client=c, **form):
    return client.post("/auth/oauth/token", data=form)


def full_flow(client, uid=None):
    cid = register(client).json()["client_id"]
    if uid is not None:
        sign_in(client, uid)
    v, ch = pkce()
    code, _ = get_code(client, cid, ch)
    r = token(client, grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=v, client_id=cid)
    assert r.status_code == 200, r.text
    return cid, r.json()


def forward(token_value=None, uri="/mcp", host="app.example.com", roles=None):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host, "X-Forwarded-Uri": uri,
         "X-Forwarded-Method": "POST"}
    if token_value:
        h["Authorization"] = f"Bearer {token_value}"
    if roles:
        h["X-TinySesam-Roles"] = roles
    fc = TestClient(c.app, base_url="http://testserver")
    return fc.get("/auth/forward", headers=h)


def audit_events():
    return [e["event"] for e in auth.store.recent_audit(500)]


# ---------------------------------------------------------------- discovery
m = c.get("/.well-known/oauth-authorization-server").json()
assert m["issuer"] == BASE and m["token_endpoint"] == BASE + "/auth/oauth/token"
assert m["code_challenge_methods_supported"] == ["S256"]
assert m["authorization_response_iss_parameter_supported"] is True
assert "offline_access" in m["scopes_supported"] and m["token_endpoint_auth_methods_supported"] == ["none"]
assert not any("client_id_metadata" in k for k in m), "CIMD must not be advertised (offline)"
assert c.get("/.well-known/oauth-authorization-server/x").json()["issuer"] == BASE
ok("RFC 8414 metadata: S256 only, iss flag, offline_access, no CIMD")

prm = c.get("/.well-known/oauth-protected-resource/mcp",
            headers={"X-Forwarded-Host": "app.example.com", "X-Forwarded-Proto": "https"})
assert prm.status_code == 200 and prm.json()["resource"] == RESOURCE and prm.json()["authorization_servers"] == [BASE]
assert c.get("/.well-known/oauth-protected-resource/other",
             headers={"X-Forwarded-Host": "app.example.com", "X-Forwarded-Proto": "https"}).status_code == 404
assert c.get("/.well-known/oauth-protected-resource/mcp",
             headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"}).status_code == 404
ok("RFC 9728 metadata only for a configured resource (path and host)")

r = forward()
assert r.status_code == 401
assert r.headers["www-authenticate"] == \
    'Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp"'
assert "x-tinysesam-location" not in {k.lower() for k in r.headers}
r = forward("tsat_" + "A" * 49)
assert r.status_code == 401 and 'error="invalid_token"' in r.headers["www-authenticate"]
r = forward(uri="/elsewhere")
assert r.status_code == 401 and "x-tinysesam-location" in {k.lower() for k in r.headers}
ok("401 at a resource carries the RFC 9728 challenge (error=invalid_token with a bad token), elsewhere the login")

# ---------------------------------------------------------------- registration (rule DCR)
rr = register()
assert rr.status_code == 201, rr.text
reg = rr.json()
assert reg["client_id"].startswith("tsc_") and reg["token_endpoint_auth_method"] == "none"
assert all(v is not None and v != "" for v in reg.values()), "no null/empty fields (Claude Code's zod schema)"
assert "client_secret" not in reg
for bad in (["https://evil.example/cb"], ["javascript:alert(1)"], ["data:text/html,x"],
            ["http://127.0.0.1@evil.example/cb"], ["http://localhost:1234/cb#frag"], ["http://evil.example/cb"],
            ["http://localhost:99999/cb"], ["http://localhost:1/c b"], ["http://localhost\\@evil/"], [], "x",
            ["http://localhost:1/cb"] * 6, ["http://LOCALHOST.evil.example/cb"]):
    r = register(redirect_uris=bad)
    assert r.status_code == 400 and r.json()["error"] in ("invalid_redirect_uri", "invalid_client_metadata"), (bad, r.text)
assert register(token_endpoint_auth_method="client_secret_basic").json()["error"] == "invalid_client_metadata"
assert register(grant_types=["client_credentials"]).status_code == 400
assert register(grant_types=["refresh_token"]).status_code == 400
assert register(response_types=["token"]).status_code == 400
assert register(scope="admin").json()["error"] == "invalid_scope"
assert register(client_name=["x"]).status_code == 400
long_name = register(client_name="N" * 500 + "‮\x07").json()["client_name"]
assert len(long_name) == O.MAX_NAME_LEN and "‮" not in long_name and "\x07" not in long_name
assert c.post("/auth/oauth/register", content="{}", headers={"Content-Type": "text/plain"}).status_code == 400
assert c.post("/auth/oauth/register", content=b"{" + b" " * 20000 + b"}",
              headers={"Content-Type": "application/json"}).status_code == 413
r = register(logo_uri="http://127.0.0.1:1/never-fetched", client_uri="", contacts=None)
assert r.status_code == 201 and "logo_uri" not in r.json() and "contacts" not in r.json()
ok("DCR: loopback http only (no https/javascript:/data:/userinfo/fragment/foreign host), none only, "
   "grant/response types and lengths capped, URLs never echoed or fetched")

d2 = tempfile.mkdtemp()
auth_rl, c_rl = make(db_path=os.path.join(d2, "rl.db"))
codes = [register(c_rl).status_code for _ in range(O.REGISTER_PER_IP_HOUR + 1)]
assert codes[:-1] == [201] * O.REGISTER_PER_IP_HOUR and codes[-1] == 429, codes
_old_cap = O.IDLE_CLIENTS_MAX
O.IDLE_CLIENTS_MAX = 3
auth_cap, c_cap = make(db_path=os.path.join(d2, "cap.db"))
caps = [register(c_cap).status_code for _ in range(4)]
O.IDLE_CLIENTS_MAX = _old_cap
assert caps == [201, 201, 201, 429], caps
tok_codes = [c_rl.post("/auth/oauth/token", data={"grant_type": "refresh_token", "refresh_token": "x",
                                                  "client_id": "tsc_x"}).status_code
             for _ in range(O.REQUESTS_PER_IP_MINUTE + 1)]
assert tok_codes[-1] == 429 and 429 not in tok_codes[:-1], tok_codes[-3:]
ok("DCR and token rate limit per address and a cap on registrations without a grant")

# ---------------------------------------------------------------- authorize: redirect rules
cid = reg["client_id"]
v, ch = pkce()


def authz(**over):
    return c.get("/auth/oauth/authorize", params=authorize_params(cid, ch, **over))


for bad_cid in ("tsc_unknown", None):
    r = c.get("/auth/oauth/authorize", params=authorize_params(bad_cid or "", ch, client_id=bad_cid))
    assert r.status_code == 400 and "location" not in r.headers, r.status_code
for bad_uri in (CB + "/extra", "http://localhost:43123/callback?x=1", "http://127.0.0.1:43123/callback",
                "http://localhost:43123/Callback", "http://127.0.0.1@evil.example/callback", "https://evil.example/cb",
                CB + "#f", None):
    r = authz(redirect_uri=bad_uri)
    assert r.status_code == 400 and "location" not in r.headers, (bad_uri, r.status_code, r.headers.get("location"))
ok("unknown client_id or unregistered redirect URI (path appended, other host, userinfo, fragment, missing): "
   "error page, never a redirect")

r = authz(redirect_uri="http://localhost:50999/callback")
assert r.status_code == 303 and "/auth/oauth/consent" in r.headers["location"]
ok("loopback: only the port may differ (RFC 8252 §7.3)")


def redirect_error(r):
    assert r.status_code == 303, r.status_code
    loc = r.headers["location"]
    assert loc.startswith(CB + "?"), loc
    q = parse_qs(urlsplit(loc).query)
    assert q["iss"] == [BASE] and q["state"] == ["st-123"], q
    return q["error"][0]


assert redirect_error(authz(code_challenge_method="plain")) == "invalid_request"
assert redirect_error(authz(code_challenge_method="plain", code_challenge=v)) == "invalid_request"
assert redirect_error(authz(code_challenge_method=None)) == "invalid_request"
assert redirect_error(authz(code_challenge=None)) == "invalid_request"
assert redirect_error(authz(code_challenge="short")) == "invalid_request"
assert redirect_error(authz(response_type="token")) == "unsupported_response_type"
assert redirect_error(authz(scope="mcp admin")) == "invalid_scope"
assert redirect_error(authz(resource="https://app.example.com/other")) == "invalid_target"
assert redirect_error(authz(resource="https://evil.example/mcp")) == "invalid_target"
assert redirect_error(authz(resource=None)) == "invalid_target"
r = c.get("/auth/oauth/authorize", params=list(authorize_params(cid, ch).items()) + [("resource", RESOURCE)])
assert redirect_error(r) == "invalid_target"
r = c.get("/auth/oauth/authorize", params=list(authorize_params(cid, ch).items()) + [("state", "two")])
assert r.status_code == 400 and "location" not in r.headers
ok("PKCE S256 required (plain/missing/short → invalid_request), unknown scope/resource → error to the client "
   "with state and iss; a parameter twice → refused")

# ---------------------------------------------------------------- consent
r = authz()
loc = r.headers["location"]
assert c.get(loc).status_code == 303 and "/auth/login?next=" in c.get(loc).headers["location"]
ok("consent without a session → sign-in with next back to the consent")

key = auth.create_api_key(alice, name="k")["key"]
r = c.get(loc, headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
ok("an API key never reaches the consent (tokens only from an interactive session)")

sign_in(c, alice)
page = c.get(loc)
assert page.status_code == 200
csp = page.headers["content-security-policy"]
assert "frame-ancestors 'none'" in csp and "frame-ancestors 'self'" not in csp
assert "form-action 'self'" in csp and "http://localhost:43123" in csp.split("form-action", 1)[1].split(";")[0]
assert page.headers["x-frame-options"] == "DENY"
assert "Claude Code (test)" in page.text and "localhost:43123" in page.text and "not verified" in page.text
ok("consent page: frame-ancestors 'none' + X-Frame-Options DENY, form-action names the loopback origin, "
   "shows client (unverified) and redirect host")

other = TestClient(c.app, base_url="http://testserver", follow_redirects=False)
sign_in(other, alice)
assert other.get(loc).status_code == 400
other.cookies.set(auth.flow_cookie_name("tinysesam_oauth"), "x" * 32)
assert other.get(loc).status_code == 400, "a foreign browser secret must not open the consent"
ok("the consent belongs to the browser that started the request (flow cookie)")

csrf = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
txn = parse_qs(urlsplit(loc).query)["txn"][0]
assert c.post("/auth/oauth/consent", data={"txn": txn, "decision": "allow"}).status_code == 403
assert c.post("/auth/oauth/consent", data={"_csrf": "x" + csrf, "txn": txn, "decision": "allow"}).status_code == 403
r = c.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": txn, "decision": "allow"})
assert r.status_code == 303 and r.headers["location"].startswith(CB + "?")
q = parse_qs(urlsplit(r.headers["location"]).query)
assert q["state"] == ["st-123"] and q["iss"] == [BASE] and q["code"][0].startswith("tsac_")
code1 = q["code"][0]
assert c.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": txn, "decision": "allow"}).status_code == 400
_loc = authz().headers["location"]
_txn = parse_qs(urlsplit(_loc).query)["txn"][0]
_req = auth._oauth.pending(_txn, c.cookies.get(auth.flow_cookie_name("tinysesam_oauth")))
assert _req is not None
auth._oauth.decide(_txn, _req, auth.get_user(alice), True, None)
try:
    auth._oauth.decide(_txn, _req, auth.get_user(alice), True, None)
except O.OAuthError:
    pass
else:
    raise AssertionError("two answers to the same consent request (a race) must not both get a code")
ok("consent POST needs the CSRF token, answers once, returns code + unchanged state + iss (RFC 9207)")

loc_d, _ = consent(c, cid, ch, decision="deny")
qd = parse_qs(urlsplit(loc_d).query)
assert qd["error"] == ["access_denied"] and "code" not in qd and qd["state"] == ["st-123"]
ok("deny → access_denied, no code")

# ---------------------------------------------------------------- code rules
assert token(grant_type="authorization_code", code=code1, redirect_uri=CB, code_verifier=v,
             client_id=cid).status_code == 200
r = token(grant_type="authorization_code", code=code1, redirect_uri=CB, code_verifier=v, client_id=cid)
assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
first = None
for g in auth.store.oauth_grants(10**10, live_only=False):
    if g["client_id"] == cid:
        first = g
assert first["revoked_reason"] == "code_reuse", dict(first)
assert "oauth_code_reuse" in audit_events() and any(e[0] == "oauth_token_reuse" and e[2]["kind"] == "code"
                                                    for e in events)
ok("code used twice → invalid_grant and the grant from the first exchange is revoked (audit + event)")


def fresh_code(**over):
    v_, ch_ = pkce()
    code_, _ = get_code(c, cid, ch_, **over)
    return code_, v_


code, vv = fresh_code()
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, client_id=cid).json()["error"] == "invalid_grant"
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=vv,
             client_id=cid).json()["error"] == "invalid_grant"
ok("no verifier for a code with a challenge → invalid_grant, and the code is consumed")

code, vv = fresh_code()
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=pkce()[0],
             client_id=cid).json()["error"] == "invalid_grant"
code, vv = fresh_code()
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=vv[:42],
             client_id=cid).json()["error"] == "invalid_grant"
code, vv = fresh_code()
assert token(grant_type="authorization_code", code=code, redirect_uri="http://localhost:1/callback",
             code_verifier=vv, client_id=cid).json()["error"] == "invalid_grant"
cid2 = register().json()["client_id"]
code, vv = fresh_code()
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=vv,
             client_id=cid2).json()["error"] == "invalid_grant"
code, vv = fresh_code()
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=vv, client_id=cid,
             resource="https://app.example.com/other").json()["error"] == "invalid_target"
code, vv = fresh_code()
auth.store._exec("UPDATE oauth_code SET expires_at = 1")
assert token(grant_type="authorization_code", code=code, redirect_uri=CB, code_verifier=vv,
             client_id=cid).json()["error"] == "invalid_grant"
v42 = "a" * 42
ch42 = base64.urlsafe_b64encode(hashlib.sha256(v42.encode()).digest()).decode().rstrip("=")
code42, _ = get_code(c, cid, ch42)
assert token(grant_type="authorization_code", code=code42, redirect_uri=CB, code_verifier=v42,
             client_id=cid).json()["error"] == "invalid_grant", "a 42-character verifier must not pass (RFC 7636: 43–128)"
ok("wrong verifier, short verifier, other redirect_uri, other client, other resource, expired code → refused")

code, vv = fresh_code()
assert auth.store.oauth_code(auth._oauth.digest(code))["expires_at"] - \
    auth.store.oauth_code(auth._oauth.digest(code))["created_at"] == 60
ok("code lifetime 60 s")

assert token(grant_type="client_credentials", client_id=cid).json()["error"] == "unsupported_grant_type"
assert token(grant_type="authorization_code", code="x", client_id="tsc_nope").status_code == 401
assert token(grant_type="authorization_code", code="x", client_id=cid, client_secret="s").json()["error"] == "invalid_client"
assert c.post("/auth/oauth/token", json={"grant_type": "authorization_code"}).json()["error"] == "invalid_request"
assert c.post("/auth/oauth/token", content="grant_type=refresh_token&grant_type=authorization_code&client_id=" + cid,
              headers={"Content-Type": "application/x-www-form-urlencoded"}).json()["error"] == "invalid_request"
assert c.post("/auth/oauth/token", data={"grant_type": "x"}, headers={"Authorization": "Basic eDp5"}).status_code == 401
ok("token endpoint: form only, parameters once, public clients only, known grant types only")

# ---------------------------------------------------------------- tokens: format, storage, resource
cid_a, tok = full_flow(c)
at, rt = tok["access_token"], tok["refresh_token"]
assert tok["token_type"] == "Bearer" and tok["expires_in"] == 3600 and set(tok["scope"].split()) == {"mcp", "offline_access"}
assert O.shape_ok(at, "tsat_") and O.shape_ok(rt, "tsrt_") and len(at) == 54
assert not O.shape_ok(at[:-1] + ("A" if at[-1] != "A" else "B"), "tsat_"), "checksum must catch a typo"
raw = open(auth.cfg.db_path, "rb").read() + (open(auth.cfg.db_path + "-wal", "rb").read()
                                             if os.path.exists(auth.cfg.db_path + "-wal") else b"")
assert at.encode() not in raw and rt.encode() not in raw
assert hashlib.sha256(at.encode()).hexdigest().encode() not in raw, "digest must be keyed (HMAC with pepper)"
assert auth.store.oauth_token(auth._oauth.digest(at)) is not None
ok("tokens: prefix + 256 bit + CRC32, only an HMAC digest (with pepper) in the database")

r = forward(at)
assert r.status_code == 200 and r.headers["remote-user"] == "alice", (r.status_code, dict(r.headers))
assert forward(at, uri="/mcp/tools").status_code == 200
for bad_uri in ("/mcpx", "/other", "/mcp/../admin", "/mcp/%2e%2e/admin", "/mcp/..;/admin", "/mcp%2fx"):
    assert forward(at, uri=bad_uri).status_code == 401, bad_uri
assert forward(at, host="other.example.com").status_code == 401
ok("access token valid only for its resource and below (audience), dot segments and encoded separators never")

auth.set_roles(alice, ["editor"])
assert forward(at, roles="editor").status_code == 200
auth.set_roles(alice, [])
assert forward(at, roles="editor").status_code == 403
ok("role withdrawn → effective at the next request")

auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (alice,))
assert "admin" not in forward(at).headers.get("remote-groups", "")
auth.store._exec("UPDATE users SET is_admin=0 WHERE id=?", (alice,))
ok("a token never carries the admin flag")

# ---------------------------------------------------------------- refresh rules
r = token(grant_type="refresh_token", refresh_token=rt, client_id=cid_a)
assert r.status_code == 200, r.text
at2, rt2 = r.json()["access_token"], r.json()["refresh_token"]
assert rt2 != rt and at2 != at
assert forward(at).status_code == 401 and forward(at2).status_code == 200
_used = auth.store.oauth_token(auth._oauth.digest(rt))
assert auth.store.oauth_rotate(auth._oauth.digest(rt), _used["grant_id"], 1, None, [], None) is False, \
    "the rotation must be atomic: a used refresh token is never marked used a second time"
ok("refresh rotates both tokens; the old access token is revoked")

r = token(grant_type="refresh_token", refresh_token=rt2, client_id=cid_a, scope="mcp offline_access admin")
assert r.json()["error"] == "invalid_scope"
r = token(grant_type="refresh_token", refresh_token=rt2, client_id=cid_a, scope="mcp")
assert r.status_code == 200 and r.json()["scope"] == "mcp"
rt3 = r.json()["refresh_token"]
r = token(grant_type="refresh_token", refresh_token=rt3, client_id=cid_a)
assert r.status_code == 200 and set(r.json()["scope"].split()) == {"mcp", "offline_access"}
rt4, at4 = r.json()["refresh_token"], r.json()["access_token"]
ok("refresh may narrow the scope, never widen it; the refresh token keeps the grant's scope")

assert token(grant_type="refresh_token", refresh_token=rt4, client_id=cid2).json()["error"] == "invalid_grant"
assert token(grant_type="refresh_token", refresh_token=rt4, client_id=cid_a,
             resource="https://app.example.com/other").json()["error"] == "invalid_target"
ok("refresh bound to its client and resource")

events.clear()
r = token(grant_type="refresh_token", refresh_token=rt, client_id=cid_a)
assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
assert forward(at4).status_code == 401
assert token(grant_type="refresh_token", refresh_token=rt4, client_id=cid_a).json()["error"] == "invalid_grant"
assert "oauth_refresh_reuse" in audit_events()
assert any(e[0] == "oauth_token_reuse" and e[2]["kind"] == "refresh" for e in events)
ok("an old refresh token again → whole family revoked (current tokens dead), audit + security event")

# grace window: the same successor, only for the immediate predecessor
d3 = tempfile.mkdtemp()
auth_g, c_g = make(db_path=os.path.join(d3, "g.db"), oauth_refresh_grace_sec=30)
ug = auth_g.create_user("gina", password="gina-pw-12345")
_auth, _c = auth, c
auth, c = auth_g, c_g
cid_g, tg = full_flow(c_g, ug)
r1 = token(c_g, grant_type="refresh_token", refresh_token=tg["refresh_token"], client_id=cid_g).json()
r2 = token(c_g, grant_type="refresh_token", refresh_token=tg["refresh_token"], client_id=cid_g).json()
assert r1 == r2 and "refresh_token" in r1, (r1, r2)
r3 = token(c_g, grant_type="refresh_token", refresh_token=r1["refresh_token"], client_id=cid_g).json()
assert "access_token" in r3
r4 = token(c_g, grant_type="refresh_token", refresh_token=tg["refresh_token"], client_id=cid_g).json()
assert r4.get("error") == "invalid_grant", "grace only while the successor is still current"
assert token(c_g, grant_type="refresh_token", refresh_token=r3["refresh_token"], client_id=cid_g).json()["error"] == "invalid_grant"
auth.store._exec("UPDATE oauth_token SET successor=NULL")
auth, c = _auth, _c
ok("grace window returns the SAME successor to the immediate predecessor; afterwards reuse revokes")

cid_s, ts_ = full_flow(c)
token(grant_type="refresh_token", refresh_token=ts_["refresh_token"], client_id=cid_s)
assert auth.store.oauth_token(auth._oauth.digest(ts_["refresh_token"]))["successor"] is None, \
    "grace 0: no successor is stored"
ok("grace 0 (default): no successor kept")

# expiry: idle and absolute
cid_e, te = full_flow(c)
auth.store._exec("UPDATE oauth_token SET expires_at = 1 WHERE kind='refresh'")
assert token(grant_type="refresh_token", refresh_token=te["refresh_token"], client_id=cid_e).json()["error"] == "invalid_grant"
cid_e, te = full_flow(c)
g = auth.store._one("SELECT * FROM oauth_grant ORDER BY id DESC LIMIT 1")
assert g["expires_at"] - g["created_at"] == 180 * 86400, "absolute maximum 180 days by default"
auth.store._exec("UPDATE oauth_grant SET expires_at = 1 WHERE id=?", (g["id"],))
assert token(grant_type="refresh_token", refresh_token=te["refresh_token"], client_id=cid_e).json()["error"] == "invalid_grant"
assert forward(te["access_token"]).status_code == 401
cid_e, te = full_flow(c)
rt_row = auth.store.oauth_token(auth._oauth.digest(te["refresh_token"]))
assert rt_row["expires_at"] - rt_row["created_at"] == 90 * 86400
ok("refresh expires after 90 idle days (sliding) and at the absolute maximum (default 180 days)")

d4 = tempfile.mkdtemp()
auth_n, c_n = make(db_path=os.path.join(d4, "n.db"), oauth_refresh_max_days=0)
un = auth_n.create_user("nora", password="nora-pw-12345")
_auth, _c = auth, c
auth, c = auth_n, c_n
full_flow(c_n, un)
assert auth_n.store._one("SELECT expires_at FROM oauth_grant")["expires_at"] is None
auth, c = _auth, _c
ok("oauth_refresh_max_days=0 → no absolute maximum (on purpose only)")

# no offline_access → no refresh token
v5, ch5 = pkce()
code5, _ = get_code(c, cid, ch5, scope="mcp")
r = token(grant_type="authorization_code", code=code5, redirect_uri=CB, code_verifier=v5, client_id=cid)
assert r.status_code == 200 and "refresh_token" not in r.json()
ok("without offline_access no refresh token")

# ---------------------------------------------------------------- revocation (RFC 7009)
cid_r, tr = full_flow(c)
assert c.post("/auth/oauth/revoke", data={"token": tr["refresh_token"], "client_id": cid2}).status_code == 200
assert forward(tr["access_token"]).status_code == 200, "a foreign client revokes nothing"
assert c.post("/auth/oauth/revoke", data={"token": "tsrt_unknown", "client_id": cid_r}).status_code == 200
assert c.post("/auth/oauth/revoke", data={"token": tr["refresh_token"], "client_id": cid_r,
                                          "token_type_hint": "refresh_token"}).status_code == 200
assert forward(tr["access_token"]).status_code == 401
assert token(grant_type="refresh_token", refresh_token=tr["refresh_token"], client_id=cid_r).json()["error"] == "invalid_grant"
assert c.post("/auth/oauth/revoke", data={"token": "x"}).status_code == 401
ok("RFC 7009 without a client secret: the family ends; unknown or foreign tokens → 200 without effect")

# ---------------------------------------------------------------- account state
cid_x, tx = full_flow(c)
events.clear()
auth.set_disabled(alice, True)
assert auth._oauth.devices(alice) == [], "locking must revoke every grant right away, not only at the next refresh"
assert forward(tx["access_token"]).status_code == 401
assert token(grant_type="refresh_token", refresh_token=tx["refresh_token"], client_id=cid_x).json()["error"] == "invalid_grant"
auth.set_disabled(alice, False)
assert forward(tx["access_token"]).status_code == 401, "unlocking does not revive a device"
sign_in(c, alice)   # locking ended the session too
assert any(e[0] == "oauth_device_revoked" and e[2]["reason"] == "account_disabled" for e in events)
ok("account locked → every device disconnected at once, unlocking does not bring them back")

cid_y, ty = full_flow(c)
auth.store._exec("UPDATE users SET disabled=2 WHERE id=?", (alice,))   # a lock written past set_disabled
assert forward(ty["access_token"]).status_code == 401
assert token(grant_type="refresh_token", refresh_token=ty["refresh_token"], client_id=cid_y).json()["error"] == "invalid_grant"
auth.store._exec("UPDATE users SET disabled=0 WHERE id=?", (alice,))
assert token(grant_type="refresh_token", refresh_token=ty["refresh_token"], client_id=cid_y).json()["error"] == "invalid_grant"
ok("the account is checked on every request and every refresh (a refresh of a locked account revokes)")

# ---------------------------------------------------------------- devices: account page and panel
cid_z, tz = full_flow(c)
page = c.get("/auth/account")
assert page.status_code == 200 and "Connected programs" in page.text and cid_z in page.text
gid = re.findall(r"/auth/oauth/devices/(\d+)/revoke", page.text)
assert gid
csrf = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
mine = [d for d in auth._oauth.devices(alice) if d["client_id"] == cid_z][0]
assert mine["last_ip"] and mine["created_at"] and mine["client_name"] == "Claude Code (test)"
bobc = TestClient(c.app, base_url="http://testserver", follow_redirects=False)
sign_in(bobc, bob)
bp = bobc.get("/auth/account")
bcsrf = bobc.cookies.get(auth.csrf_cookie_name)
assert bcsrf
assert cid_z not in bp.text
bobc.post(f"/auth/oauth/devices/{mine['id']}/revoke", data={"_csrf": bcsrf})
assert forward(tz["access_token"]).status_code == 200, "someone else's device cannot be revoked"
assert c.post(f"/auth/oauth/devices/{mine['id']}/revoke", data={}).status_code == 403
r = c.post(f"/auth/oauth/devices/{mine['id']}/revoke", data={"_csrf": csrf})
assert r.status_code == 303 and forward(tz["access_token"]).status_code == 401
assert token(grant_type="refresh_token", refresh_token=tz["refresh_token"], client_id=cid_z).json()["error"] == "invalid_grant"
ok("account page lists the own devices (name, client, created, last used, IP) and disconnects at once (CSRF)")

cid_w, tw = full_flow(c)
admin = auth.create_user("root", password="root-pw-12345", is_admin=True)
adm = TestClient(c.app, base_url="http://testserver", follow_redirects=False)
sign_in(adm, admin)
adm.get("/auth/account")
ac = adm.cookies.get(auth.csrf_cookie_name)
lst = adm.get("/auth/admin/api/oauth/devices").json()
w = [d for d in lst if d["client_id"] == cid_w][0]
assert w["username"] == "alice"
assert adm.post(f"/auth/admin/api/oauth/devices/{w['id']}/revoke", headers={"X-CSRF-Token": ac}).json()["ok"]
assert forward(tw["access_token"]).status_code == 401
assert "oauth_devices_read" in audit_events()
auth.store._exec("UPDATE users SET is_owner=1 WHERE id=?", (alice,))
cid_v, tv = full_flow(c)
vv_ = [d for d in adm.get("/auth/admin/api/oauth/devices").json() if d["client_id"] == cid_v][0]
assert adm.post(f"/auth/admin/api/oauth/devices/{vv_['id']}/revoke", headers={"X-CSRF-Token": ac}).status_code == 403
auth.store._exec("UPDATE users SET is_owner=0 WHERE id=?", (alice,))
ok("admin panel lists all devices and disconnects them (an owner's only by an owner), reading is audited")

for ev in ("oauth_client_registered", "oauth_authorize", "oauth_consent", "oauth_token", "oauth_refresh",
           "oauth_revoked", "oauth_authorize_denied"):
    assert ev in audit_events(), ev
ok("audit: register, authorize, consent, token, refresh, reuse, revoke")

# ---------------------------------------------------------------- pepper
auth._oauth._pepper = b"another-pepper-of-32-bytes-or-so!"
assert forward(tv["access_token"]).status_code == 401
ok("another pepper → the stored digests no longer match (the pepper keys them)")

# ---------------------------------------------------------------- gc
auth.store._exec("UPDATE oauth_token SET expires_at = 1")
auth.store._exec("UPDATE oauth_client SET created_at = 1, last_used = 1")
n = auth.gc()
assert n["oauth_tokens"] > 0 and n["oauth_grants"] > 0 and n["oauth_clients"] > 0, n
assert auth.store._one("SELECT COUNT(*) AS n FROM oauth_token")["n"] == 0
ok("gc(): expired tokens, grants without tokens, registrations without a grant")

# ---------------------------------------------------------------- configuration
for over, word in ((dict(base_url=""), "base_url"), (dict(oauth_resources=[]), "oauth_resources"),
                   (dict(forward_auth_enabled=False), "forward_auth_enabled"),
                   (dict(oauth_resources=["https://auth.example.com/mcp"]), "address of TinySesam"),
                   (dict(oauth_resources=["http://app.example.com/mcp"]), "clear text"),
                   (dict(oauth_resources=["https://app.example.com/mcp?x=1"]), "no absolute"),
                   (dict(csrf_enabled=False), "csrf_enabled"),
                   (dict(oauth_refresh_grace_sec=61), "oauth_refresh_grace_sec")):
    try:
        make(**over)
    except ConfigError as e:
        assert word in str(e), (word, str(e))
    else:
        raise AssertionError(f"no ConfigError for {over}")
from tinysesam import config_check as CC
_e, _w = CC.check_config(TinySesamConfig(base_url=BASE, forward_auth_enabled=True, oauth_enabled=True,
                                         oauth_resources=[RESOURCE], oauth_refresh_max_days=0))
assert not _e and any("V10.4.8" in x for x in _w) and any("pepper" in x for x in _w), (_e, _w)
os.environ[O.PEPPER_ENV] = base64.b64encode(os.urandom(32)).decode()
_e, _w = CC.check_config(TinySesamConfig(base_url=BASE, forward_auth_enabled=True, oauth_enabled=True,
                                         oauth_resources=[RESOURCE]))
assert not _e and not any("pepper" in x or "V10.4.8" in x for x in _w), _w
os.environ[O.PEPPER_ENV] = "c2hvcnQ="
try:
    make()
except ConfigError as e:
    assert "32 bytes" in str(e)
else:
    raise AssertionError("short pepper accepted")
del os.environ[O.PEPPER_ENV]
assert TinySesamConfig().oauth_refresh_max_days == 180 and TinySesamConfig().oauth_enabled is False
ok("config_check: base_url, resources (https, not the own host), forward auth, CSRF required; "
   "max 0 and missing pepper are warnings; default max 180 days; short pepper refused")

d5 = tempfile.mkdtemp()
plain = TinySesam(TinySesamConfig(db_path=os.path.join(d5, "p.db"), cookie_secure=False, passkey_enabled=False))
pa = FastAPI()
pa.include_router(plain.router())
pc = TestClient(pa)
assert pc.get("/.well-known/oauth-authorization-server").status_code == 404
assert pc.post("/auth/oauth/register", json={}).status_code in (404, 405)
ok("switch off (default): no OAuth route exists")

print("OAuth authorization server: all checks green")

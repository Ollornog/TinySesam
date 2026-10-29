"""Gate token (ADR-9, T-19): issuing in /auth/forward, audience, claims, keys, verification.

The path through a real Caddy with caddy-jwt is in `tests/test_gate_caddy.py`. Here it is about
the TinySesam side: when a token is created, what is in it, and that a verifier that checks it
like the proxy rejects every forgery.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, ConfigError
from tinysesam import gate, config_check


def ok(name):
    print(f"  ✓ {name}")


ISS = "https://auth.example.com"
PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/x"}


def instance(**extra):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    values = dict(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
                 oidc_enabled=False, cookie_secure=False, forward_auth_enabled=True, base_url=ISS,
                 trusted_redirect_hosts=["app.example.com"], gate_token_enabled=True)
    values.update(extra)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def token_from(r):
    head = r.headers.get("X-TinySesam-Gate-Cookie")
    if not head:
        return None, None
    name, rest = head.split("=", 1)
    return name, rest.split(";", 1)[0]


def sign_in(app, name="anna", pw="geheim123"):
    c = TestClient(app)
    r = c.post("/auth/login", data={"username": name, "password": pw, "next": "/"}, follow_redirects=False)
    assert r.status_code in (302, 303), r.status_code
    return c


auth, app = instance()
auth.ensure_admin("admin", "geheim123")
uid = auth.create_user("anna", "geheim123", roles=["redaktion"])
auth.store._exec("UPDATE users SET email=?, display_name=? WHERE id=?",
                 ("anna@example.com", "Anna Berg", uid))
PUB = base64.b64decode(auth.gate_public_key())
assert len(PUB) == 32


def check_config(tok, aud="app.example.com", now=None):
    return gate.check(PUB, tok, aud=aud, iss=ISS, now=int(time.time()) if now is None else now)


# ---------- Issuing ----------
c = sign_in(app)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200
name, tok = token_from(r)
assert name == "__Host-tinysesam_gate", name
head = r.headers["X-TinySesam-Gate-Cookie"]
for part in ("Path=/", "Max-Age=300", "Secure", "HttpOnly", "SameSite=Lax"):
    assert part in head, (part, head)
assert "domain" not in head.lower(), head
content = check_config(tok)
assert content, "the fresh token does not pass the check"
assert content["sub"] == str(uid) and content["ts_user"] == "anna" and content["ts_id"] == str(uid)
assert content["ts_name"] == "Anna Berg" and content["ts_email"] == "anna@example.com"
assert content["ts_groups"] == "redaktion"
assert content["exp"] - content["iat"] == 300 and content["nbf"] == content["iat"]
ok("session → 200 with gate cookie (__Host-, Secure, HttpOnly, without Domain); claims = forward headers")

# The same identity on both paths: what the headers say, the claims say.
assert r.headers["Remote-User"] == content["ts_user"]
assert r.headers["Remote-Id"] == content["ts_id"]
ok("headers and claims name the same identity")

# No token for a host that this installation does not protect.
r = c.get("/auth/forward", headers={**PROXY, "X-Forwarded-Host": "fremd.example.net"})
assert token_from(r) == (None, None)
ok("foreign host → no gate token")

# No token without sign-in.
r = TestClient(app).get("/auth/forward", headers=PROXY)
assert r.status_code == 401 and token_from(r) == (None, None)
ok("without sign-in → 401, no gate token")

# No token for an API key: an automation holds no cookie, and one from a key would survive
# im Browser dessen Widerruf.
key = auth.create_api_key(uid, name="k")["key"]
r = TestClient(app).get("/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and token_from(r) == (None, None)
ok("API key → 200, but no gate token")

# Missing role → 403, no token.
r = c.get("/auth/forward?roles=chef", headers=PROXY)
assert r.status_code == 403 and token_from(r) == (None, None)
ok("role missing → 403, no gate token")

# ---------- Audience with roles ----------
r = c.get("/auth/forward?roles=redaktion,chef", headers=PROXY)
_, tok_r = token_from(r)
assert check_config(tok_r) is None, "a token from a check WITH roles applies on the path without roles"
assert check_config(tok_r, aud="app.example.com|roles=chef,redaktion")
ok("roles are in the audience (canonically sorted)")

# Conversely the actual attack: a token without role information must not apply on a path with roles
# — the proxy sees only the audience.
assert check_config(tok, aud="app.example.com|roles=redaktion") is None
ok("token without role information does not apply on a path with roles")

assert gate.audience("App.Example.com.", [["b", "a", "a"], ["c"], []]) == "app.example.com|roles=a,b;c"
assert gate.audience("app.example.com", [["c"], ["a", "b"]]) == gate.audience("app.example.com", [["b", "a"], ["c"]])
ok("zielgruppe(): upper/lower case, trailing dot, duplicates and order change nothing")

# ---------- Check as at the proxy: every forgery fails ----------
k, i, s = tok.split(".")
now = int(time.time())


def new_signed(content_new, head_new=None, key_name=None):
    kk = gate._b64u(json.dumps(head_new or {"alg": "EdDSA", "typ": "JWT"}).encode())
    ii = gate._b64u(json.dumps(content_new).encode())
    sig = (key_name or auth._gate_key_name).sign(f"{kk}.{ii}".encode())
    return f"{kk}.{ii}.{gate._b64u(sig)}"


base = json.loads(gate._read_b64u(i))
foreign = gate.derive_key_name(b"\x00" * 32)
cases = {
    # Flip a BYTE of the signature, do not replace the last characters: the last base64 characters
    # carry padding bits, and `…AA` instead of `…AB` is sometimes the same signature (1 in 256 runs).
    "signature altered": f"{k}.{i}." + gate._b64u(bytes([gate._read_b64u(s)[0] ^ 1]) + gate._read_b64u(s)[1:]),
    "content altered (other account)": f"{k}.{gate._b64u(json.dumps({**base, 'sub': '1'}).encode())}.{s}",
    "alg none": f"{gate._b64u(json.dumps({'alg': 'none'}).encode())}.{i}.",
    "alg HS256": f"{gate._b64u(json.dumps({'alg': 'HS256'}).encode())}.{i}.{s}",
    # Validly signed, but the header names another algorithm: only the comparison with
    # `EdDSA` catches that — the signature itself is correct.
    "alg HS256, validly signed": new_signed(base, head_new={"alg": "HS256", "typ": "JWT"}),
    "foreign key": new_signed(base, key_name=foreign),
    "expired": new_signed({**base, "exp": now - 1}),
    "not yet valid": new_signed({**base, "nbf": now + 60}),
    "other issuer": new_signed({**base, "iss": "https://evil.example"}),
    "other audience": new_signed({**base, "aud": "wiki.example.com"}),
    "no token": "",
    "nonsense": "a.b.c",
}
for was, wrong in cases.items():
    assert check_config(wrong) is None, was
assert check_config(new_signed(base)), "the counter-check (re-signed unchanged) must pass"
ok(f"check rejects {len(cases)} forgeries, the unchanged counter-check passes")

# Independent counter-check: a foreign JOSE implementation (authlib, extra [oidc]) reads the token
# the same way. If it is missing, only this part is omitted — otherwise the suite checks the format itself.
try:
    from authlib.jose import JsonWebToken, OKPKey
except ImportError:
    print("  – authlib missing: counter-check with foreign JOSE implementation omitted")
else:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    claims = JsonWebToken(["EdDSA"]).decode(tok, OKPKey.import_key(Ed25519PublicKey.from_public_bytes(PUB)))
    claims.validate()
    assert claims["ts_user"] == "anna" and claims["aud"] == "app.example.com"
    ok("authlib (foreign JOSE implementation) checks the token and reads the same claims")

# ---------- Claims follow forward_headers ----------
auth2, app2 = instance(forward_headers={"user": "X-WEBAUTH-USER"})
auth2.create_user("bea", "geheim123")
r = sign_in(app2, "bea").get("/auth/forward", headers=PROXY)
_, t2 = token_from(r)
content2 = gate.check(base64.b64decode(auth2.gate_public_key()), t2, aud="app.example.com", iss=ISS,
                    now=int(time.time()))
assert {k for k in content2 if k.startswith("ts_")} == {"ts_user"}, content2
ok("forward_headers is the complete list — also for the claims (no address if it is missing)")

# Names beyond ASCII and with control characters (come from the foreign IdP with OIDC/SAML). Directly
# at `_gate_cookie`: the TestClient (httpx) rejects headers outside ASCII and could not read
# the response with `Remote-Name` at all — the path over the wire is in test_gate_caddy.py.
from starlette.requests import Request  # noqa: E402


def gate_direct():
    session = c.cookies.get(auth.session_cookie_name)
    scope = {"type": "http", "method": "GET", "path": "/auth/forward", "query_string": b"",
             "headers": [(b"cookie", f"{auth.session_cookie_name}={session}".encode())],
             "client": ("127.0.0.1", 1), "server": ("testserver", 80), "scheme": "http"}
    head = auth._gate_cookie(Request(scope), auth._as_dict(auth.store.get_user(uid)),
                             "https://app.example.com/x", [])
    return check_config(head.split(";", 1)[0].split("=", 1)[1])


for raw, should in (("Anna Ärger", "Anna Ärger"), ("Иван", "Иван"),
                  ("Anna\r\nRemote-User: admin", "AnnaRemote-User: admin"), ("A\x7fB\x01", "AB")):
    auth.store._exec("UPDATE users SET display_name=? WHERE id=?", (raw, uid))
    assert gate_direct()["ts_name"] == should, (raw, gate_direct()["ts_name"])
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Anna Berg", uid))
ok("claims: umlauts and Cyrillic unchanged (UTF-8), control characters drop out")

# ---------- Switched off ----------
auth.cfg.gate_token_enabled = False
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200 and token_from(r) == (None, None)
auth.cfg.gate_token_enabled = True
ok("gate_token_enabled=False → /auth/forward as before, without gate token")

# ---------- Keys ----------
# The same base key → the same signing key (all workers, every restart); a different one
# → a different one. The proxy key therefore changes exactly when the base key changes.
old = os.environ.get("TINYSESAM_SECRETS_KEY")
try:
    os.environ["TINYSESAM_SECRETS_KEY"] = base64.b64encode(b"\x07" * 32).decode()
    a1, _ = instance()
    a2, _ = instance()
    os.environ["TINYSESAM_SECRETS_KEY"] = base64.b64encode(b"\x08" * 32).decode()
    a3, _ = instance()
finally:
    if old is None:
        os.environ.pop("TINYSESAM_SECRETS_KEY", None)
    else:
        os.environ["TINYSESAM_SECRETS_KEY"] = old
assert a1.gate_public_key() == a2.gate_public_key() != a3.gate_public_key()
ok("signing key follows the base key: same for the same, different for a different one")

# The signing key is derived, not the base key itself: whoever knows it (say from
# a memory dump of the signing) does not thereby know the key of the TOTP secrets.
g = b"\x07" * 32
from cryptography.hazmat.primitives import serialization  # noqa: E402
seed = gate.derive_key_name(g).private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                 serialization.NoEncryption())
assert seed != g and len(seed) == 32
ok("signing key is derived (HKDF with its own context), not the base key")

# ---------- CLI: tinysesam gate-key ----------
db = auth.cfg.db_path
env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
env.pop("TINYSESAM_SECRETS_KEY", None)
r = subprocess.run([sys.executable, "-m", "tinysesam", "gate-key", "--db", db],
                   capture_output=True, text=True, env=env, timeout=60)
assert r.returncode == 0, r.stderr
assert r.stdout.strip() == auth.gate_public_key()
ok("`tinysesam gate-key` prints the same public key as the service")

empty = os.path.join(tempfile.mkdtemp(), "x.db")
r = subprocess.run([sys.executable, "-m", "tinysesam", "gate-key", "--db", empty],
                   capture_output=True, text=True, env=env, timeout=60)
assert r.returncode == 1 and not os.path.exists(empty + ".key"), (r.returncode, r.stderr)
ok("`gate-key` without base key: error, and it creates NO new one")

# ---------- Configuration check ----------
def findings(**extra):
    values = dict(db_path=":memory:", forward_auth_enabled=True, gate_token_enabled=True)
    values.update(extra)
    return config_check.check_config(TinySesamConfig(**values))[0]


assert not [b for b in findings() if "gate" in b]
assert any("forward_auth_enabled" in b for b in findings(forward_auth_enabled=False))
for name in ("tinysesam_gate", "__Secure-tinysesam_gate", "__Host-gate", "__Host-tinysesam_", "__Host-tinysesam_a;b"):
    assert any("gate_cookie_name" in b for b in findings(gate_cookie_name=name)), name
for ttl in (29, 3601, True):
    assert any("gate_token_ttl_sec" in b for b in findings(gate_token_ttl_sec=ttl)), ttl
assert not [b for b in findings(gate_token_ttl_sec=30) + findings(gate_token_ttl_sec=3600) if "gate" in b]
try:
    TinySesamConfig(db_path=":memory:", gate_token_enabled=True)
    TinySesam(TinySesamConfig(db_path=":memory:", gate_token_enabled=True))
except ConfigError as e:
    assert "forward_auth_enabled" in str(e)
else:
    raise AssertionError("gate_token_enabled without forward_auth_enabled starts")
ok("configuration check: without forward_auth, wrong cookie name, lifetime outside 30–3600")

# ---------- Template: the proxy sets the identity, not the browser ----------
# Every header that TinySesam sends as identity is removed from the request first in the template.
# In behaviour that is invisible as long as both paths set it afterwards — it is the
# safeguard for the day someone deletes a `header_up` line or takes a field out of
# forward_headers. Therefore here as a guard over the file, not as a probe.
import pathlib  # noqa: E402
import re  # noqa: E402
template = (pathlib.Path(__file__).resolve().parent.parent / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
code = "\n".join(z.split("#", 1)[0] for z in template.splitlines())
site = code[code.index("app.example.com {"):]
for header_name in TinySesam.FORWARD_HEADERS_DEFAULT.values():
    assert re.search(rf"^\trequest_header -{header_name}\s*$", site, re.M), f"template does not remove {header_name}"
    assert re.search(rf"header_up {header_name} \{{http\.auth\.user\.ts_", site), f"fast path does not set {header_name}"
    assert f"request_header {header_name} {{rp.header.{header_name}}}" in site, f"rollback path does not set {header_name}"
assert site.index("request_header -Remote-User") < site.index("route {"), "removal only after forwarding"
assert re.search(r"^\t\t\tsign_alg EdDSA\s*$", site, re.M), "jwtauth without fixed algorithm"
assert "from_cookies __Host-tinysesam_gate" in site
ok("template: every Remote-* header is removed first, then set on both paths; sign_alg fixed")

# Share exception (T-20), in BOTH templates: off as long as nobody sets it; and without identity —
# the normal template, too, otherwise removes the Remote-* headers nowhere before the application.
_locks = {}
for _file in ("deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate"):
    _t = (pathlib.Path(__file__).resolve().parent.parent / _file).read_text(encoding="utf-8")
    _code = "\n".join(z.split("#", 1)[0] if not z.lstrip().startswith("header_up Cookie") else z
                      for z in _t.splitlines())
    _block = re.search(r"handle @share \{(.*?)\n\t\}", _code, re.S)
    assert _block, f"{_file}: no handle @share"
    assert "{$TS_SHARE_PREFIX:^$}" in _code, f"{_file}: the share exception is not off by itself"
    assert "vars_regexp share {http.request.orig_uri.path}" in _code, f"{_file}: share does not check the raw path"
    _lock = re.search(r"not vars_regexp \{http\.request\.orig_uri\.path\} (\S+)", _code)
    assert _lock, f"{_file}: without a block for path tricks"
    _locks[_file] = _lock.group(1)
    for header_name in TinySesam.FORWARD_HEADERS_DEFAULT.values():
        assert f"header_up -{header_name}" in _block.group(1), f"{_file}: share passes {header_name} through from the browser"
    assert _code.index("handle @share") < _code.index("route {"), f"{_file}: share only after the gate"
assert len(set(_locks.values())) == 1, f"the two templates block path tricks differently: {_locks}"
ok("templates: share exception off by itself, checks the raw path, passes no identity through")

print("Gate-Token OK")

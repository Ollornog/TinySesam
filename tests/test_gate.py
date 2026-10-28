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


def instanz(**extra):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    werte = dict(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
                 oidc_enabled=False, cookie_secure=False, forward_auth_enabled=True, base_url=ISS,
                 trusted_redirect_hosts=["app.example.com"], gate_token_enabled=True)
    werte.update(extra)
    auth = TinySesam(TinySesamConfig(**werte))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def token_aus(r):
    kopf = r.headers.get("X-TinySesam-Gate-Cookie")
    if not kopf:
        return None, None
    name, rest = kopf.split("=", 1)
    return name, rest.split(";", 1)[0]


def anmelden(app, name="anna", pw="geheim123"):
    c = TestClient(app)
    r = c.post("/auth/login", data={"username": name, "password": pw, "next": "/"}, follow_redirects=False)
    assert r.status_code in (302, 303), r.status_code
    return c


auth, app = instanz()
auth.ensure_admin("admin", "geheim123")
uid = auth.create_user("anna", "geheim123", roles=["redaktion"])
auth.store._exec("UPDATE users SET email=?, display_name=? WHERE id=?",
                 ("anna@example.com", "Anna Berg", uid))
PUB = base64.b64decode(auth.gate_public_key())
assert len(PUB) == 32


def check_config(tok, aud="app.example.com", jetzt=None):
    return gate.pruefen(PUB, tok, aud=aud, iss=ISS, jetzt=int(time.time()) if jetzt is None else jetzt)


# ---------- Ausstellen ----------
c = anmelden(app)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200
name, tok = token_aus(r)
assert name == "__Host-tinysesam_gate", name
kopf = r.headers["X-TinySesam-Gate-Cookie"]
for teil in ("Path=/", "Max-Age=300", "Secure", "HttpOnly", "SameSite=Lax"):
    assert teil in kopf, (teil, kopf)
assert "domain" not in kopf.lower(), kopf
inhalt = check_config(tok)
assert inhalt, "the fresh token does not pass the check"
assert inhalt["sub"] == str(uid) and inhalt["ts_user"] == "anna" and inhalt["ts_id"] == str(uid)
assert inhalt["ts_name"] == "Anna Berg" and inhalt["ts_email"] == "anna@example.com"
assert inhalt["ts_groups"] == "redaktion"
assert inhalt["exp"] - inhalt["iat"] == 300 and inhalt["nbf"] == inhalt["iat"]
ok("session → 200 with gate cookie (__Host-, Secure, HttpOnly, without Domain); claims = forward headers")

# The same identity on both paths: what the headers say, the claims say.
assert r.headers["Remote-User"] == inhalt["ts_user"]
assert r.headers["Remote-Id"] == inhalt["ts_id"]
ok("headers and claims name the same identity")

# No token for a host that this installation does not protect.
r = c.get("/auth/forward", headers={**PROXY, "X-Forwarded-Host": "fremd.example.net"})
assert token_aus(r) == (None, None)
ok("foreign host → no gate token")

# No token without sign-in.
r = TestClient(app).get("/auth/forward", headers=PROXY)
assert r.status_code == 401 and token_aus(r) == (None, None)
ok("without sign-in → 401, no gate token")

# No token for an API key: an automation holds no cookie, and one from a key would survive
# im Browser dessen Widerruf.
key = auth.create_api_key(uid, name="k")["key"]
r = TestClient(app).get("/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and token_aus(r) == (None, None)
ok("API key → 200, but no gate token")

# Missing role → 403, no token.
r = c.get("/auth/forward?roles=chef", headers=PROXY)
assert r.status_code == 403 and token_aus(r) == (None, None)
ok("role missing → 403, no gate token")

# ---------- Audience with roles ----------
r = c.get("/auth/forward?roles=redaktion,chef", headers=PROXY)
_, tok_r = token_aus(r)
assert check_config(tok_r) is None, "a token from a check WITH roles applies on the path without roles"
assert check_config(tok_r, aud="app.example.com|roles=chef,redaktion")
ok("roles are in the audience (canonically sorted)")

# Conversely the actual attack: a token without role information must not apply on a path with roles
# — the proxy sees only the audience.
assert check_config(tok, aud="app.example.com|roles=redaktion") is None
ok("token without role information does not apply on a path with roles")

assert gate.zielgruppe("App.Example.com.", [["b", "a", "a"], ["c"], []]) == "app.example.com|roles=a,b;c"
assert gate.zielgruppe("app.example.com", [["c"], ["a", "b"]]) == gate.zielgruppe("app.example.com", [["b", "a"], ["c"]])
ok("zielgruppe(): upper/lower case, trailing dot, duplicates and order change nothing")

# ---------- Check as at the proxy: every forgery fails ----------
k, i, s = tok.split(".")
jetzt = int(time.time())


def neu_signiert(inhalt_neu, kopf_neu=None, schluessel=None):
    kk = gate._b64u(json.dumps(kopf_neu or {"alg": "EdDSA", "typ": "JWT"}).encode())
    ii = gate._b64u(json.dumps(inhalt_neu).encode())
    sig = (schluessel or auth._gate_schluessel).sign(f"{kk}.{ii}".encode())
    return f"{kk}.{ii}.{gate._b64u(sig)}"


basis = json.loads(gate._b64u_lesen(i))
fremd = gate.schluessel_ableiten(b"\x00" * 32)
faelle = {
    # Flip a BYTE of the signature, do not replace the last characters: the last base64 characters
    # carry padding bits, and `…AA` instead of `…AB` is sometimes the same signature (1 in 256 runs).
    "Signatur verändert": f"{k}.{i}." + gate._b64u(bytes([gate._b64u_lesen(s)[0] ^ 1]) + gate._b64u_lesen(s)[1:]),
    "Inhalt verändert (anderes Konto)": f"{k}.{gate._b64u(json.dumps({**basis, 'sub': '1'}).encode())}.{s}",
    "alg none": f"{gate._b64u(json.dumps({'alg': 'none'}).encode())}.{i}.",
    "alg HS256": f"{gate._b64u(json.dumps({'alg': 'HS256'}).encode())}.{i}.{s}",
    # Validly signed, but the header names another algorithm: only the comparison with
    # `EdDSA` catches that — the signature itself is correct.
    "alg HS256, gültig signiert": neu_signiert(basis, kopf_neu={"alg": "HS256", "typ": "JWT"}),
    "fremder Schlüssel": neu_signiert(basis, schluessel=fremd),
    "abgelaufen": neu_signiert({**basis, "exp": jetzt - 1}),
    "noch nicht gültig": neu_signiert({**basis, "nbf": jetzt + 60}),
    "anderer Aussteller": neu_signiert({**basis, "iss": "https://evil.example"}),
    "andere Zielgruppe": neu_signiert({**basis, "aud": "wiki.example.com"}),
    "kein Token": "",
    "Unsinn": "a.b.c",
}
for was, falsch in faelle.items():
    assert check_config(falsch) is None, was
assert check_config(neu_signiert(basis)), "the counter-check (re-signed unchanged) must pass"
ok(f"check rejects {len(faelle)} forgeries, the unchanged counter-check passes")

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

# ---------- Claims folgen forward_headers ----------
auth2, app2 = instanz(forward_headers={"user": "X-WEBAUTH-USER"})
auth2.create_user("bea", "geheim123")
r = anmelden(app2, "bea").get("/auth/forward", headers=PROXY)
_, t2 = token_aus(r)
inh2 = gate.pruefen(base64.b64decode(auth2.gate_public_key()), t2, aud="app.example.com", iss=ISS,
                    jetzt=int(time.time()))
assert {k for k in inh2 if k.startswith("ts_")} == {"ts_user"}, inh2
ok("forward_headers is the complete list — also for the claims (no address if it is missing)")

# Names beyond ASCII and with control characters (come from the foreign IdP with OIDC/SAML). Directly
# at `_gate_cookie`: the TestClient (httpx) rejects headers outside ASCII and could not read
# the response with `Remote-Name` at all — the path over the wire is in test_gate_caddy.py.
from starlette.requests import Request  # noqa: E402


def gate_direkt():
    sitzung = c.cookies.get(auth.session_cookie_name)
    scope = {"type": "http", "method": "GET", "path": "/auth/forward", "query_string": b"",
             "headers": [(b"cookie", f"{auth.session_cookie_name}={sitzung}".encode())],
             "client": ("127.0.0.1", 1), "server": ("testserver", 80), "scheme": "http"}
    kopf = auth._gate_cookie(Request(scope), auth._als_dict(auth.store.get_user(uid)),
                             "https://app.example.com/x", [])
    return check_config(kopf.split(";", 1)[0].split("=", 1)[1])


for roh, soll in (("Anna Ärger", "Anna Ärger"), ("Иван", "Иван"),
                  ("Anna\r\nRemote-User: admin", "AnnaRemote-User: admin"), ("A\x7fB\x01", "AB")):
    auth.store._exec("UPDATE users SET display_name=? WHERE id=?", (roh, uid))
    assert gate_direkt()["ts_name"] == soll, (roh, gate_direkt()["ts_name"])
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Anna Berg", uid))
ok("claims: umlauts and Cyrillic unchanged (UTF-8), control characters drop out")

# ---------- Ausgeschaltet ----------
auth.cfg.gate_token_enabled = False
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200 and token_aus(r) == (None, None)
auth.cfg.gate_token_enabled = True
ok("gate_token_enabled=False → /auth/forward as before, without gate token")

# ---------- Keys ----------
# The same base key → the same signing key (all workers, every restart); a different one
# → a different one. The proxy key therefore changes exactly when the base key changes.
alt = os.environ.get("TINYSESAM_SECRETS_KEY")
try:
    os.environ["TINYSESAM_SECRETS_KEY"] = base64.b64encode(b"\x07" * 32).decode()
    a1, _ = instanz()
    a2, _ = instanz()
    os.environ["TINYSESAM_SECRETS_KEY"] = base64.b64encode(b"\x08" * 32).decode()
    a3, _ = instanz()
finally:
    if alt is None:
        os.environ.pop("TINYSESAM_SECRETS_KEY", None)
    else:
        os.environ["TINYSESAM_SECRETS_KEY"] = alt
assert a1.gate_public_key() == a2.gate_public_key() != a3.gate_public_key()
ok("signing key follows the base key: same for the same, different for a different one")

# The signing key is derived, not the base key itself: whoever knows it (say from
# a memory dump of the signing) does not thereby know the key of the TOTP secrets.
g = b"\x07" * 32
from cryptography.hazmat.primitives import serialization  # noqa: E402
saat = gate.schluessel_ableiten(g).private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                 serialization.NoEncryption())
assert saat != g and len(saat) == 32
ok("signing key is derived (HKDF with its own context), not the base key")

# ---------- CLI: tinysesam gate-key ----------
db = auth.cfg.db_path
umg = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
umg.pop("TINYSESAM_SECRETS_KEY", None)
r = subprocess.run([sys.executable, "-m", "tinysesam", "gate-key", "--db", db],
                   capture_output=True, text=True, env=umg, timeout=60)
assert r.returncode == 0, r.stderr
assert r.stdout.strip() == auth.gate_public_key()
ok("`tinysesam gate-key` prints the same public key as the service")

leer = os.path.join(tempfile.mkdtemp(), "x.db")
r = subprocess.run([sys.executable, "-m", "tinysesam", "gate-key", "--db", leer],
                   capture_output=True, text=True, env=umg, timeout=60)
assert r.returncode == 1 and not os.path.exists(leer + ".key"), (r.returncode, r.stderr)
ok("`gate-key` without base key: error, and it creates NO new one")

# ---------- Configuration check ----------
def befunde(**extra):
    werte = dict(db_path=":memory:", forward_auth_enabled=True, gate_token_enabled=True)
    werte.update(extra)
    return config_check.check_config(TinySesamConfig(**werte))[0]


assert not [b for b in befunde() if "gate" in b]
assert any("forward_auth_enabled" in b for b in befunde(forward_auth_enabled=False))
for name in ("tinysesam_gate", "__Secure-tinysesam_gate", "__Host-gate", "__Host-tinysesam_", "__Host-tinysesam_a;b"):
    assert any("gate_cookie_name" in b for b in befunde(gate_cookie_name=name)), name
for ttl in (29, 3601, True):
    assert any("gate_token_ttl_sec" in b for b in befunde(gate_token_ttl_sec=ttl)), ttl
assert not [b for b in befunde(gate_token_ttl_sec=30) + befunde(gate_token_ttl_sec=3600) if "gate" in b]
try:
    TinySesamConfig(db_path=":memory:", gate_token_enabled=True)
    TinySesam(TinySesamConfig(db_path=":memory:", gate_token_enabled=True))
except ConfigError as e:
    assert "forward_auth_enabled" in str(e)
else:
    raise AssertionError("gate_token_enabled ohne forward_auth_enabled startet")
ok("configuration check: without forward_auth, wrong cookie name, lifetime outside 30–3600")

# ---------- Template: the proxy sets the identity, not the browser ----------
# Every header that TinySesam sends as identity is removed from the request first in the template.
# In behaviour that is invisible as long as both paths set it afterwards — it is the
# safeguard for the day someone deletes a `header_up` line or takes a field out of
# forward_headers. Therefore here as a guard over the file, not as a probe.
import pathlib  # noqa: E402
import re  # noqa: E402
vorlage = (pathlib.Path(__file__).resolve().parent.parent / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
code = "\n".join(z.split("#", 1)[0] for z in vorlage.splitlines())
site = code[code.index("app.example.com {"):]
for kopfname in TinySesam.FORWARD_HEADERS_DEFAULT.values():
    assert re.search(rf"^\trequest_header -{kopfname}\s*$", site, re.M), f"template does not remove {kopfname}"
    assert re.search(rf"header_up {kopfname} \{{http\.auth\.user\.ts_", site), f"fast path does not set {kopfname}"
    assert f"request_header {kopfname} {{rp.header.{kopfname}}}" in site, f"rollback path does not set {kopfname}"
assert site.index("request_header -Remote-User") < site.index("route {"), "removal only after forwarding"
assert re.search(r"^\t\t\tsign_alg EdDSA\s*$", site, re.M), "jwtauth without fixed algorithm"
assert "from_cookies __Host-tinysesam_gate" in site
ok("template: every Remote-* header is removed first, then set on both paths; sign_alg fixed")

# Share exception (T-20), in BOTH templates: off as long as nobody sets it; and without identity —
# the normal template, too, otherwise removes the Remote-* headers nowhere before the application.
for _datei in ("deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate"):
    _t = (pathlib.Path(__file__).resolve().parent.parent / _datei).read_text(encoding="utf-8")
    _code = "\n".join(z.split("#", 1)[0] if not z.lstrip().startswith("header_up Cookie") else z
                      for z in _t.splitlines())
    _block = re.search(r"handle @share \{(.*?)\n\t\}", _code, re.S)
    assert _block, f"{_datei}: no handle @share"
    assert "{$TS_SHARE_PRAEFIX:^$}" in _code, f"{_datei}: the share exception is not off by itself"
    assert "vars_regexp share {http.request.orig_uri.path}" in _code, f"{_datei}: share does not check the raw path"
    assert re.search(r"not vars_regexp \{http\.request\.orig_uri\.path\} ", _code), f"{_datei}: without a block for path tricks"
    for kopfname in TinySesam.FORWARD_HEADERS_DEFAULT.values():
        assert f"header_up -{kopfname}" in _block.group(1), f"{_datei}: share passes {kopfname} through from the browser"
    assert _code.index("handle @share") < _code.index("route {"), f"{_datei}: share only after the gate"
ok("templates: share exception off by itself, checks the raw path, passes no identity through")

print("Gate-Token OK")

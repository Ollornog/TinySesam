"""T-86: the Python gate client `tinysesam.gate_client` beyond the vectors.

`tests/test_gate_vectors.py` runs every vector of `spec/vectors/` against the client. This suite covers what the
vectors cannot carry (spec §5, `clients/README.md`): a JWKS server that accepts and never answers, a body above
64 KiB, concurrent requests sharing one fetch, redirects; plus the configuration errors that stop the start, the token
sources, the WSGI and ASGI middleware with their guards, failing closed, logs without credential material, the top
bar fetch, the import without FastAPI, and a seeded property test over mutated tokens. No network beyond loopback.
"""
import asyncio
import base64
import http.server
import io
import json
import logging
import os
import random
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

from tinysesam import gate_client as gc  # noqa: E402
from tinysesam import gate  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402

ISSUER, AUDIENCE, NOW = "https://auth.example.com", "app.example.com", 1767225600


def ok(name):
    print(f"  ✓ {name}")


def load(name):
    with open(os.path.join(ROOT, "spec", "vectors", name), encoding="utf-8") as f:
        return json.load(f)


KEYS = load("keys.json")["keys"]
TOKENS = {v["id"]: v for v in load("token.json")["vectors"]}
VALID = TOKENS["valid-session"]["input"]["jws"]
KEY_A = KEYS["A"]["sign_key_base64"]


def private(label):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    d = KEYS[label]["d"]
    return Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))


def mint(label="A", now=NOW, **claims):
    base = {"user": "anna", "name": "Anna Berg", "groups": "editors", "id": "1", "auth": "session"}
    base.update(claims)
    return gate.issue(private(label), iss=ISSUER, aud=AUDIENCE, sub=base["id"], claims=base, ttl=300, now=now)


def token_client(**kw):
    cfg = {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A]}
    cfg.update(kw)
    return gc.GateClient(**cfg)


def refused(fn, kind):
    try:
        fn()
    except gc.GateError as e:
        assert e.kind == kind, (e.kind, kind)
        return e
    raise AssertionError(f"accepted, expected {kind}")


def raises(exception, fn) -> bool:
    """True when `fn()` raises `exception`."""
    try:
        fn()
    except exception:
        return True
    return False


def config_error(**kw):
    try:
        gc.GateClient(**kw)
    except ConfigError:
        return True
    raise AssertionError(f"accepted configuration {kw}")


# ---------- import without FastAPI ----------
blocker = (
    "import sys\n"
    "class Block:\n"
    "    def find_spec(self, name, path=None, target=None):\n"
    "        if name.split('.')[0] in ('fastapi', 'starlette', 'pydantic'):\n"
    "            raise ImportError('blocked ' + name)\n"
    "sys.meta_path.insert(0, Block())\n"
    "from tinysesam import gate_client as gc\n"
    "i = gc.GateClient(mode='header').identify({'Remote-User': 'anna', 'Remote-Auth': 'session'})\n"
    "assert i.user == 'anna' and i.is_session()\n"
    "assert not any(m.split('.')[0] in ('fastapi', 'starlette') for m in sys.modules), sorted(sys.modules)\n"
    "import tinysesam\n"
    "try:\n"
    "    tinysesam.TinySesam\n"
    "except ImportError:\n"
    "    print('lazy')\n"
)
r = subprocess.run([sys.executable, "-c", blocker], cwd=ROOT, capture_output=True, text=True, timeout=60)
assert r.returncode == 0 and r.stdout.strip() == "lazy", (r.returncode, r.stdout, r.stderr[-2000:])
import tinysesam  # noqa: E402
assert tinysesam.TinySesam.__name__ == "TinySesam" and "TinySesam" in dir(tinysesam)
ok("tinysesam.gate_client imports and works without FastAPI; `tinysesam.TinySesam` loads on first use")

# ---------- configuration errors stop the start ----------
for bad in (
        {"mode": "auto"}, {"mode": None},
        {"mode": "header", "issuer": ISSUER}, {"mode": "header", "gate_keys": [KEY_A]}, {"mode": "header", "leeway": 5},
        {"mode": "header", "cookie_name": "x"}, {"mode": "header", "trusted_proxies": []},
        {"mode": "header", "trusted_proxies": ["not-an-address"]},
        {"mode": "header", "header_names": {"user": "Remote-User", "name": "remote-user"}},
        {"mode": "header", "header_names": {"role": "X-Role"}}, {"mode": "header", "header_names": {"user": "Bad Name"}},
        {"mode": "token", "audience": AUDIENCE, "gate_keys": [KEY_A]},
        {"mode": "token", "issuer": "", "audience": AUDIENCE, "gate_keys": [KEY_A]},
        {"mode": "token", "issuer": ISSUER, "audience": "", "gate_keys": [KEY_A]},
        {"mode": "auto", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A]},
        {"mode": "Token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A]},
        {"mode": "token", "issuer": ISSUER, "gate_keys": [KEY_A]},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A],
         "jwks_url": "https://auth.example.com/auth/gate/jwks.json"},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": ["c2hvcnQ="]},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": ["not base64!"]},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": []},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "jwks_url": "http://auth.example.com/jwks.json"},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "jwks_url": "ftp://auth.example.com/jwks.json"},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "jwks_url": "https:///jwks.json"},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A], "leeway": 61},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A], "cookie_name": "a",
         "token_header": "X-Gate"},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A], "token_header": "X Gate"},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A], "trusted_proxies": ["::1"]},
        {"mode": "token", "issuer": ISSUER, "audience": AUDIENCE, "gate_keys": [KEY_A],
         "header_names": {"user": "X-User"}},
):
    config_error(**bad)
for good in ("http://127.0.0.1:8080/jwks.json", "http://localhost/jwks.json", "http://[::1]/jwks.json",
             "https://auth.example.com/auth/gate/jwks.json"):
    assert token_client(gate_keys=None, jwks_url=good)._may_block
assert not token_client()._may_block and token_client(gate_keys=KEY_A, leeway=60)
assert raises(ConfigError, lambda: gc.GateClient(mode="header").verify(VALID)), "verify() in header mode"
ok("configuration errors: no or unknown mode, mixed settings, missing issuer/audience/key source, bad keys, a JWKS URL "
   "that is not https (http only to loopback), leeway above 60, two token sources, bad header names")

# ---------- header mode ----------
hm = gc.GateClient(mode="header", trusted_proxies=["127.0.0.1", "198.51.100.0/24", "::1"])
heads = {"Remote-User": "anna", "Remote-Groups": "editors", "Remote-Auth": "session", "Remote-Id": "1"}
assert hm.identify(heads, peer="127.0.0.1").user == "anna"
assert hm.identify(heads, peer="198.51.100.3").id == "1"
assert hm.identify(heads, peer="::ffff:127.0.0.1").is_session()
assert hm.identify(list(heads.items()), peer="::1").has_role("editors")
for peer in (None, "", "192.0.2.1", "2001:db8::1", "garbage"):
    refused(lambda: hm.identify(heads, peer=peer), "untrusted_peer")
renamed = gc.GateClient(mode="header", header_names={"user": "X-Auth-User", "auth": "X-Auth-Kind"})
got = renamed.identify({"X-Auth-User": "anna", "X-Auth-Kind": "session", "Remote-User": "admin"})
assert got.user == "anna" and got.is_session(), got
refused(lambda: renamed.identify({"Remote-User": "admin"}), "unauthenticated")
refused(lambda: gc.GateClient(mode="header").identify([("Remote-User", "anna"), ("REMOTE-USER", "admin")]), "header")
refused(lambda: gc.GateClient(mode="header").identify([(b"remote-user", b"anna"), (b"Remote-User", b"anna")]),
        "header")
assert gc.GateClient(mode="header").identify([(b"remote-user", "Jürgen".encode())]).user == "Jürgen"
refused(lambda: gc.GateClient(mode="header").identify({"Remote-User": "Jürgen€"}), "header")   # not octets
assert gc.GateClient(mode="header").identify({"Remote-User": "anna", "X-Forwarded-User": "admin"}).user == "anna"
ok("header mode: trusted proxies (IPv4, networks, IPv6, mapped), renamed headers ignore the defaults, repeats in any "
   "spelling refused, bytes and octet strings, no other identity header read")

# ---------- token sources ----------
tc = token_client()
cookie = f"a=1; {gc.DEFAULT_GATE_COOKIE}={VALID}; b=2"
assert tc.identify({"Cookie": cookie}, now=NOW).user == "anna"
assert tc.identify([("cookie", "a=1"), ("cookie", f"{gc.DEFAULT_GATE_COOKIE}={VALID}")], now=NOW).id == "1"
refused(lambda: tc.identify({"Cookie": f"{gc.DEFAULT_GATE_COOKIE}={VALID}; {gc.DEFAULT_GATE_COOKIE}={VALID}"},
                            now=NOW), "malformed")
refused(lambda: tc.identify({"Cookie": "a=1"}, now=NOW), "unauthenticated")
refused(lambda: tc.identify({"Remote-User": "admin", "Remote-Groups": "admin", "Remote-Auth": "session"}, now=NOW),
        "unauthenticated")
mixed = tc.identify({"Cookie": cookie, "Remote-User": "admin", "Remote-Groups": "admin"}, now=NOW)
assert mixed.user == "anna" and not mixed.has_role("admin"), mixed
th = token_client(token_header="X-Gate-Token")
assert th.identify({"X-Gate-Token": VALID}, now=NOW).user == "anna"
refused(lambda: th.identify({"Cookie": cookie}, now=NOW), "unauthenticated")
refused(lambda: th.identify([("X-Gate-Token", VALID), ("x-gate-token", VALID)], now=NOW), "malformed")
named = token_client(cookie_name="gate")
assert named.identify({"Cookie": f"gate={VALID}"}, now=NOW).user == "anna"
refused(lambda: tc.identify({"Authorization": f"Bearer {VALID}"}, now=NOW), "unauthenticated")
identity, claims = tc.verify(VALID, now=NOW)
assert claims["sub"] == identity.id == "1" and identity.groups == ("editors",)
ok("token sources: the gate cookie (one, never two), a configured header, never Authorization; Remote-* ignored in "
   "token mode")

# ---------- errors carry the class and the kid, never the token ----------
e = refused(lambda: tc.verify(TOKENS["attack-signature-bitflip"]["input"]["jws"], now=NOW), "signature")
assert e.kid == KEYS["A"]["public_jwk"]["kid"] and VALID.split(".")[2][:20] not in str(e), (e.kid, str(e))
e = refused(lambda: tc.verify(VALID, now=NOW + 3600), "expired")
assert isinstance(e, gc.Expired) and isinstance(e, gc.TokenError) and e.kid, e
e = refused(lambda: tc.verify(TOKENS["attack-kid-path"]["input"]["jws"], now=NOW), "kid")
assert e.kid == "", "a malformed kid must not be reported (it may be a path or SQL)"
classes = {c.kind for c in (gc.Unauthenticated, gc.UntrustedPeer, gc.HeaderError, gc.InternalError, gc.MalformedToken,
                            gc.KidError, gc.SignatureError, gc.KeyUnavailable, gc.ClaimsError, gc.IssuerError,
                            gc.AudienceError, gc.LifetimeError, gc.NotYetValid, gc.Expired)}
assert len(classes) == 14 and all(issubclass(getattr(gc, n), gc.GateError) for n in gc.__all__ if n.endswith("Error"))
ok("errors: one exception per class under GateError/TokenError, `kid` only when well-formed, no token in the message")


# ---------- JWKS over HTTP (loopback) ----------

class Server:
    """A loopback HTTP server whose handler is a function of (handler, server)."""

    def __init__(self, respond):
        outer = self
        self.hits = 0
        self.lock = threading.Lock()

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with outer.lock:
                    outer.hits += 1
                respond(self, outer)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def jwks_doc(*labels):
    return {"keys": [KEYS[lb]["public_jwk"] for lb in labels]}


def send_json(h, doc, status=200, cc="max-age=300", extra=b""):
    body = json.dumps(doc).encode() + extra
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Cache-Control", cc)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


def jwks_client(url, **kw):
    return token_client(gate_keys=None, jwks_url=url + "/jwks.json", **kw)


now = int(time.time())
live = mint(now=now)
s = Server(lambda h, srv: send_json(h, jwks_doc("A", "B")))
c = jwks_client(s.url)
assert c.verify(live)[0].user == "anna" and c.verify(live)[0].user == "anna"
assert s.hits == 1, s.hits
s.close()
ok("JWKS: fetched once from the configured URL, then served from the cache")

# A server that accepts the connection and never answers: the request returns within the deadline (5 s).
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(8)
accepted = []
threading.Thread(target=lambda: accepted.append(listener.accept()), daemon=True).start()
c = jwks_client(f"http://127.0.0.1:{listener.getsockname()[1]}")
t0 = time.monotonic()
refused(lambda: c.verify(live), "key_unavailable")
took = time.monotonic() - t0
assert 4.5 <= took < 6.5, took
t0 = time.monotonic()
refused(lambda: c.verify(live), "key_unavailable")          # within 10 s: no new attempt, no waiting
assert time.monotonic() - t0 < 0.5
listener.close()
ok(f"JWKS: a server that accepts and never answers — refused after {took:.1f} s (deadline 5 s), the next request "
   "does not wait")

# The deadline covers the body too: a server that drips one byte at a time.
def drip(h, srv):
    h.send_response(200)
    h.send_header("Content-Length", "100000")
    h.end_headers()
    try:
        for _ in range(100):
            h.wfile.write(b" ")
            h.wfile.flush()
            time.sleep(0.2)
    except OSError:
        return          # the client hung up at its deadline — what this server is for


old = gc._FETCH_TIMEOUT
gc._FETCH_TIMEOUT = 1.0
try:
    s = Server(drip)
    t0 = time.monotonic()
    refused(lambda: jwks_client(s.url).verify(live), "key_unavailable")
    assert time.monotonic() - t0 < 2.0, time.monotonic() - t0
    # The fetch itself stops at its deadline too, not only the waiting request.
    end = time.monotonic() + 3.0
    while any(t.name == "tinysesam-jwks" for t in threading.enumerate()) and time.monotonic() < end:
        time.sleep(0.05)
    assert not any(t.name == "tinysesam-jwks" for t in threading.enumerate()), "the fetch outlived its deadline"
    s.close()
finally:
    gc._FETCH_TIMEOUT = old
ok("JWKS: a body that drips in byte by byte is cut at the deadline (the request and the fetch)")

# A fetcher that hangs (whatever the socket does): the request still returns at the cache's deadline.
hanging = gc._JWKSCache(lambda: (time.sleep(3), gc._FetchResult(error="late"))[1], wait=0.5)
t0 = time.monotonic()
refused(lambda: hanging.lookup(KEYS["A"]["public_jwk"]["kid"], NOW), "key_unavailable")
assert time.monotonic() - t0 < 1.0, time.monotonic() - t0
t0 = time.monotonic()
refused(lambda: hanging.lookup(KEYS["A"]["public_jwk"]["kid"], NOW + 1), "key_unavailable")
assert time.monotonic() - t0 < 0.2, "a request waited for a fetch past its deadline"
ok("JWKS: a hanging fetcher — the request returns at the deadline, the next one does not wait for it")

# 64 KiB: one byte above fails, exactly 64 KiB is accepted.
base_body = json.dumps(jwks_doc("A")).encode()
for size, verdict in ((gc._MAX_JWKS_BYTES + 1, "key_unavailable"), (gc._MAX_JWKS_BYTES, None)):
    pad = b" " * (size - len(base_body))
    s = Server(lambda h, srv, pad=pad: send_json(h, jwks_doc("A"), extra=pad))
    c = jwks_client(s.url)
    if verdict:
        refused(lambda: c.verify(live), verdict)
    else:
        assert c.verify(live)[0].user == "anna"
    s.close()
ok("JWKS: a body of 64 KiB + 1 is a failed fetch, exactly 64 KiB is read")

# 32 concurrent requests share one fetch.
def slow(h, srv):
    time.sleep(0.5)
    send_json(h, jwks_doc("A"))


s = Server(slow)
c = jwks_client(s.url)
results = []
threads = [threading.Thread(target=lambda: results.append(c.verify(live)[0].user)) for _ in range(32)]
for t in threads:
    t.start()
for t in threads:
    t.join(10)
assert results == ["anna"] * 32 and s.hits == 1, (len(results), s.hits)
s.close()
ok("JWKS: 32 concurrent requests share one running fetch (one hit on the server)")

# Redirects: to the same host followed, to another host not.
target = Server(lambda h, srv: send_json(h, jwks_doc("A")))


def redirect_to(location):
    def respond(h, srv):
        if h.path == "/jwks.json":
            h.send_response(302)
            h.send_header("Location", location)
            h.end_headers()
        else:
            send_json(h, jwks_doc("A"))
    return respond


same = Server(redirect_to("/moved.json"))
assert jwks_client(same.url).verify(live)[0].user == "anna"
other = Server(redirect_to(target.url.replace("127.0.0.1", "localhost") + "/jwks.json"))
refused(lambda: jwks_client(other.url).verify(live), "key_unavailable")
assert target.hits == 0, "followed a redirect to another host"
for srv in (target, same, other):
    srv.close()
ok("JWKS: a redirect is followed only to the same host")

# Failures keep the cached set; a status other than 200 is a failed fetch.
state = {"status": 200}
s = Server(lambda h, srv: send_json(h, jwks_doc("A"), status=state["status"], cc="max-age=60"))
cache_client = jwks_client(s.url)
cache_client.verify(live, now=now)
state["status"] = 503
assert cache_client.verify(live, now=now + 61)[0].user == "anna"          # stale-if-error
assert s.hits == 2
s.close()
ok("JWKS: a 503 on refresh keeps the last good set")
good_body = json.dumps(jwks_doc("A")).encode()
assert gc._interpret(gc._FetchResult(status=200, body=good_body)) is not None
for status in (203, 204, 301, 404, 503):
    assert gc._interpret(gc._FetchResult(status=status, body=good_body)) is None, status
ok("JWKS: a valid key set with a status other than 200 is a failed fetch")


# ---------- WSGI middleware and guards ----------

def wsgi_app(environ, start_response):
    who = gc.current_identity()
    assert who is environ["tinysesam.identity"] and who is gc.current_identity(environ)
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [(who.user if who else "-").encode()]


def call_wsgi(app, headers, peer="127.0.0.1"):
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "REMOTE_ADDR": peer, "wsgi.input": io.BytesIO()}
    for k, v in headers.items():
        environ["HTTP_" + k.upper().replace("-", "_")] = v
    seen = {}

    def start_response(status, response_headers, exc_info=None):
        seen["status"], seen["headers"] = status, dict(response_headers)
    body = b"".join(app(environ, start_response))
    return seen["status"], seen["headers"], body


session = {"Remote-User": "anna", "Remote-Groups": "editors", "Remote-Auth": "session"}
api_key = {"Remote-User": "anna", "Remote-Groups": "editors", "Remote-Auth": "apikey"}
hgate = gc.GateClient(mode="header", trusted_proxies=["127.0.0.1"])
mw = gc.WSGIMiddleware(wsgi_app, hgate)
assert call_wsgi(mw, session)[2] == b"anna"
assert call_wsgi(mw, {})[2] == b"-"
assert call_wsgi(mw, session, peer="192.0.2.7")[2] == b"-"
assert gc.current_identity() is None, "the identity leaked out of the request"
for guard, headers, want in (
        (gc.require_auth, {}, "401"), (gc.require_auth, session, "200"),
        (gc.require_role("editors"), api_key, "200"), (gc.require_role("admin"), session, "403"),
        (gc.require_role("Editors"), session, "403"), (gc.require_session, api_key, "403"),
        (gc.require_session, session, "200"), (gc.require_session, {}, "401")):
    status, hdrs, body = call_wsgi(gc.WSGIMiddleware(guard(wsgi_app), hgate), headers)
    assert status.startswith(want), (guard, headers, status)
    if want != "200":
        assert hdrs["Cache-Control"] == "no-store" and body in (b"Unauthorized", b"Forbidden"), (hdrs, body)
status, _h, _b = call_wsgi(gc.require_auth(wsgi_app), session)          # no middleware in front
assert status.startswith("401"), status
ok("WSGI: identity in environ and current_identity() for the request only; guards 401/403 with no-store and no "
   "reason; untrusted peer and missing middleware refused")


# Fail closed with a log line that carries the class and the kid only.
class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


cap = Capture()
logging.getLogger("tinysesam.gate_client").addHandler(cap)
logging.getLogger("tinysesam.gate_client").setLevel(logging.INFO)
tgate = token_client()
tmw = gc.WSGIMiddleware(wsgi_app, tgate)
bad = TOKENS["attack-signature-bitflip"]["input"]["jws"]
assert call_wsgi(tmw, {"Cookie": f"{gc.DEFAULT_GATE_COOKIE}={bad}"})[2] == b"-"
assert cap.lines and "class=signature" in cap.lines[-1] and KEYS["A"]["public_jwk"]["kid"] in cap.lines[-1]
broken = token_client()
broken.identify = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret detail " + VALID))
assert call_wsgi(gc.WSGIMiddleware(wsgi_app, broken), {"Cookie": f"{gc.DEFAULT_GATE_COOKIE}={VALID}"})[2] == b"-"
assert "class=internal" in cap.lines[-1]
assert not any(VALID[:30] in line or bad[:30] in line or "secret detail" in line for line in cap.lines), cap.lines
ok("fail closed: a refused token and an exception inside the client give no identity; the log names class and kid, "
   "never the token or the error text")


# ---------- ASGI middleware ----------

async def asgi_app(scope, receive, send):
    who = gc.current_identity()
    assert who is scope["tinysesam.identity"]
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": (who.user if who else "-").encode()})


async def call_asgi(app, headers, scope_type="http", client=("127.0.0.1", 5000)):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)
    scope = {"type": scope_type, "path": "/", "headers": [(k.lower().encode(), v.encode("latin-1"))
                                                           for k, v in headers], "client": client}
    await app(scope, receive, send)
    return sent


def asgi_result(app, headers, **kw):
    sent = asyncio.run(call_asgi(app, headers, **kw))
    if sent[0]["type"] == "websocket.close":
        return "close", None, b""
    return sent[0]["status"], dict(sent[0]["headers"]), b"".join(m.get("body", b"") for m in sent[1:])


amw = gc.ASGIMiddleware(asgi_app, hgate)
assert asgi_result(amw, list(session.items()))[2] == b"anna"
assert asgi_result(amw, [("Remote-User", "anna"), ("remote-user", "admin")])[2] == b"-"     # repeat refused
assert asgi_result(amw, list(session.items()), client=None)[2] == b"-"                      # no peer: untrusted
for guard, headers, want in ((gc.require_auth, [], 401), (gc.require_role("editors"), list(session.items()), 200),
                             (gc.require_session, list(api_key.items()), 403)):
    status, hdrs, body = asgi_result(gc.ASGIMiddleware(guard(asgi_app), hgate), headers)
    assert status == want, (guard, status)
    if want != 200:
        assert hdrs[b"cache-control"] == b"no-store", hdrs
assert asgi_result(gc.ASGIMiddleware(gc.require_auth(asgi_app), hgate), [], scope_type="websocket")[0] == "close"


async def lifespan_probe():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])
    await gc.ASGIMiddleware(inner, hgate)({"type": "lifespan"}, None, None)
    return seen


assert asyncio.run(lifespan_probe()) == ["lifespan"]
s = Server(lambda h, srv: send_json(h, jwks_doc("A")))
jmw = gc.ASGIMiddleware(asgi_app, jwks_client(s.url))
assert asgi_result(jmw, [("Cookie", f"{gc.DEFAULT_GATE_COOKIE}={live}")])[2] == b"anna"
s.close()
ok("ASGI: identity in the scope and current_identity(); repeats refused; guards for HTTP and WebSocket; lifespan "
   "passed through; with JWKS the check runs off the event loop")

# Starlette, if installed: add_middleware with keyword arguments, request.scope in current_identity.
try:
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient
except ImportError:
    print("  - Starlette not installed: the add_middleware probe is skipped (the plain ASGI tests above ran)")
else:
    def home(request):
        who = gc.current_identity(request)
        return PlainTextResponse(who.user if who else "-")
    star = Starlette(routes=[Route("/", home)])
    star.add_middleware(gc.ASGIMiddleware, gate=gc.GateClient(mode="header"))
    with TestClient(star) as tc_client:
        assert tc_client.get("/", headers={"Remote-User": "anna"}).text == "anna"
        assert tc_client.get("/").text == "-"
    ok("Starlette: app.add_middleware(ASGIMiddleware, gate=…) and current_identity(request)")


# ---------- current_identity and guard_status ----------
class Req:
    def __init__(self, **kw):
        self.__dict__.update(kw)


anna = gc.GateClient(mode="header").identify(session)
for holder in (Req(environ={"tinysesam.identity": anna}), Req(META={"tinysesam.identity": anna}),
               Req(scope={"tinysesam.identity": anna}), {"tinysesam.identity": anna}):
    assert gc.current_identity(holder) is anna
assert gc.current_identity({"tinysesam.identity": "anna"}) is None and gc.current_identity(object()) is None
assert gc.guard_status(None) == 401 and gc.guard_status(anna) is None
assert gc.guard_status(anna, role="admin") == 403 and gc.guard_status(anna, role="editors") is None
token_identity = gc.GateClient(mode="header").identify(api_key)
assert gc.guard_status(token_identity, session=True) == 403 and not token_identity.is_session()
assert raises(ConfigError, lambda: gc.require_role("")), "empty role accepted"
assert raises(AttributeError, lambda: setattr(anna, "user", "admin")), "Identity is mutable"
ok("current_identity reads environ, META, scope or a mapping; guard_status 401/403/None; Identity is frozen")

# ---------- top bar fetch ----------
seen_cookie = {}


def topbar(h, srv):
    seen_cookie["value"] = h.headers.get("Cookie")
    send_json(h, {"brand": "Example", "signed_in": True, "name": "Anna", "links": [{"title": "x", "href": "/x"}],
                  "logout": {"href": "/auth/logout"}})


s = Server(topbar)
tb = gc.fetch_topbar(s.url + "/auth/topbar.json", "other=1; tinysesam_session=abc; __Host-tinysesam_gate=t; x=2")
assert tb.signed_in and tb.name == "Anna" and tb.links == (gc.TopbarLink("x", "/x"),), tb
assert seen_cookie["value"] == "tinysesam_session=abc; __Host-tinysesam_gate=t", seen_cookie
s.close()
s = Server(lambda h, srv: send_json(h, {"signed_in": True, "name": "Anna"}, status=500))
assert gc.fetch_topbar(s.url + "/auth/topbar.json") == gc.Topbar()
s.close()
assert gc.parse_topbar({"signed_in": True, "name": "A", "brand": 5}).brand == ""
ok("top bar: fetched server-side with only TinySesam's cookies; an error status is signed out")

# ---------- property test: mutated tokens ----------
rng = random.Random(4711)
client = token_client()
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/ \n\x00é"
accepted_changes = 0
for i in range(3000):
    chars = list(VALID)
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        pos = rng.randrange(len(chars) + 1)
        if op < 0.4 and chars:
            chars[min(pos, len(chars) - 1)] = rng.choice(alphabet)
        elif op < 0.7:
            chars.insert(pos, rng.choice(alphabet))
        elif chars:
            del chars[min(pos, len(chars) - 1)]
    mutated = "".join(chars)
    try:
        client.verify(mutated, now=NOW)
    except gc.GateError:
        continue
    assert mutated == VALID, f"a changed token was accepted: {mutated!r}"
    accepted_changes += 1
ok(f"property: 3000 seeded random mutations of a valid token — every changed one refused with a GateError "
   f"({accepted_changes} mutations happened to restore it)")

# ---------- the examples ----------
# Flask and Django are no dependency of TinySesam: the examples are compiled always and driven when the framework is
# installed (the probe below runs them through their own WSGI entry with a fake proxy request).
EXAMPLES = os.path.join(ROOT, "examples", "gate_client")
PROBE = r'''
import importlib.util, io, sys
spec = importlib.util.spec_from_file_location("example", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
sys.modules["example"] = mod          # Django's ROOT_URLCONF names the module itself
spec.loader.exec_module(mod)
app = mod.app.wsgi_app if hasattr(mod, "app") else mod.application
def call(path, headers, peer="127.0.0.1", method="GET"):
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "SERVER_NAME": "127.0.0.1", "SERVER_PORT": "8081",
           "REMOTE_ADDR": peer, "wsgi.input": io.BytesIO(), "wsgi.url_scheme": "http", "wsgi.errors": sys.stderr,
           "HTTP_HOST": "127.0.0.1", "QUERY_STRING": "", "SERVER_PROTOCOL": "HTTP/1.1"}
    env.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in headers.items()})
    out = {}
    body = b"".join(app(env, lambda s, h, e=None: out.setdefault("s", s)))
    return int(out["s"][:3]), body
editor = {"Remote-User": "anna", "Remote-Groups": "editors", "Remote-Auth": "session", "Remote-Name": "<Anna>"}
assert call("/", editor) == (200, "Signed in as <bdi>&lt;Anna&gt;</bdi> (account ).".encode()), call("/", editor)
assert call("/reports", editor)[0] == 200
assert call("/reports", {})[0] == 401
assert call("/reports", dict(editor, **{"Remote-Groups": "readers"}))[0] == 403
assert call("/reports", editor, peer="192.0.2.1")[0] == 401
print("ok")
'''
driven = []
for name, framework in (("flask_app.py", "flask"), ("django_app.py", "django")):
    path = os.path.join(EXAMPLES, name)
    compile(open(path, encoding="utf-8").read(), path, "exec")
    interpreter = os.environ.get("TINYSESAM_EXAMPLE_PYTHON", sys.executable)
    has = subprocess.run([interpreter, "-c", f"import {framework}"], capture_output=True).returncode == 0
    if not has:
        continue
    r = subprocess.run([interpreter, "-c", PROBE, path], capture_output=True, text=True, timeout=120,
                       env=dict(os.environ, PYTHONPATH=ROOT))
    assert r.returncode == 0 and r.stdout.strip() == "ok", (name, r.stdout, r.stderr[-1500:])
    driven.append(framework)
ok(f"examples: both compile; driven with {', '.join(driven) or 'none (Flask and Django not installed)'} — escaped "
   "name, 200/401/403, untrusted peer")

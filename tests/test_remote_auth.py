"""T-75: `Remote-Auth` — how the request signed in, in the forward-auth answer, the gate token and every proxy template.

An application behind the gate gets different `Remote-Groups` depending on how a request signed in (a token never
carries `admin`) and could not tell why. `/auth/forward` now says it: `Remote-Auth: session | oauth | apikey |
app-password`. A gate token is issued only for a session and carries `ts_auth = "session"` as a signed claim, so the
fast path at the proxy says the same as the way back. The header is a slot of `forward_headers` like the others
(renamed, or left out). The templates strip a `Remote-Auth` sent by the client and set TinySesam's.

A1–A7 are the acceptance tests of a deployment that asked for it; the real Caddy is measured in
`tests/test_gate_caddy.py` (A5/A6 through the proxy itself).
"""
import base64
import hashlib
import os
import pathlib
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig, gate  # noqa: E402

BASE = "https://auth.example.com"
APP = "app.example.com"
DAV = "dav.example.com"
RESOURCE = f"https://{APP}/mcp"
CB = "http://localhost:43123/callback"
PW = "a long test password 4711"


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, base_url=BASE, forward_auth_enabled=True,
               trusted_redirect_hosts=[APP, DAV], apikey_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE],
               forward_apps={DAV: {"name": "Files", "app_passwords": True}})
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok, _ = auth.start_session(uid, "password")
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def forward(app, headers=None, host=APP, uri="/", client=None):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host, "X-Forwarded-Uri": uri, "X-Forwarded-Method": "GET"}
    h.update(headers or {})
    return (client or TestClient(app, base_url="http://testserver")).get("/auth/forward", headers=h)


def oauth_token(auth, app, uid):
    """A real access token for RESOURCE through the authorization-code flow (PKCE, consent)."""
    c = session_client(auth, app, uid)
    cid = c.post("/auth/oauth/register", json={
        "client_name": "Agent (test)", "redirect_uris": [CB], "grant_types": ["authorization_code"],
        "response_types": ["code"], "token_endpoint_auth_method": "none"}).json()["client_id"]
    verifier = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = c.get("/auth/oauth/authorize", params={
        "response_type": "code", "client_id": cid, "redirect_uri": CB, "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "s", "scope": "mcp", "resource": RESOURCE})
    loc = r.headers["location"]
    page = c.get(loc)
    csrf = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
    r = c.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": parse_qs(urlsplit(loc).query)["txn"][0],
                                            "decision": "allow"})
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    r = c.post("/auth/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                          "code_verifier": verifier, "client_id": cid})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


auth, app = build()
boss = auth.create_user("boss", password=PW, roles=["editors"])
auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (boss,))
anna = auth.create_user("anna", password=PW, roles=["editors"])
assert TinySesam.FORWARD_HEADERS_DEFAULT["auth"] == "Remote-Auth"

# ══ A1: a full session ═══════════════════════════════════════════════════════════════════════════════════════════
r = forward(app, client=session_client(auth, app, anna))
assert r.status_code == 200 and r.headers["Remote-Auth"] == "session", (r.status_code, dict(r.headers))
assert r.headers["Remote-User"] == "anna"
r = forward(app, client=session_client(auth, app, boss))
assert r.headers["Remote-Auth"] == "session" and "admin" in r.headers["Remote-Groups"].split(",")
ok("A1: session cookie → 200, Remote-Auth: session (an admin's groups carry admin)")

# ══ A2: an OAuth access token for the resource ══════════════════════════════════════════════════════════════════
for uid, name in ((anna, "anna"), (boss, "boss")):
    at = oauth_token(auth, app, uid)
    assert at.startswith("tsat_")
    r = TestClient(app, base_url="http://testserver").get(
        "/auth/forward", headers={"X-Original-URL": RESOURCE, "Authorization": f"Bearer {at}"})
    assert r.status_code == 200 and r.headers["Remote-Auth"] == "oauth", (r.status_code, dict(r.headers))
    assert r.headers["Remote-User"] == name
    assert "admin" not in r.headers["Remote-Groups"].split(","), r.headers["Remote-Groups"]
    assert "editors" in r.headers["Remote-Groups"].split(",")
ok("A2: tsat_ token at its resource (X-Original-URL) → 200, Remote-Auth: oauth, Remote-Groups without admin, "
   "also for an admin account")

# ══ A3: an API key, as Bearer and as X-Api-Key ══════════════════════════════════════════════════════════════════
key = auth.create_api_key(boss, name="ci")["key"]
assert key.startswith("tsk_"), key[:6]
for head in ({"Authorization": f"Bearer {key}"}, {"X-Api-Key": key}):
    r = forward(app, head)
    assert r.status_code == 200 and r.headers["Remote-Auth"] == "apikey", (head.keys(), r.status_code, dict(r.headers))
    assert "admin" not in r.headers["Remote-Groups"].split(","), "an automation key never carries admin"
ok("A3: API key per Bearer tsk_… and per X-Api-Key → Remote-Auth: apikey each")

# ══ A4: an app password by Basic auth ═══════════════════════════════════════════════════════════════════════════
secret = auth.create_app_password(anna, "Phone calendar", hosts=[DAV])["secret"]
basic = "Basic " + base64.b64encode(f"anna:{secret}".encode()).decode()
r = forward(app, {"Authorization": basic}, host=DAV, uri="/remote.php/dav/")
assert r.status_code == 200 and r.headers["Remote-Auth"] == "app-password", (r.status_code, dict(r.headers))
ok("A4: app password per Basic → Remote-Auth: app-password")

# A request with nothing gets no Remote-Auth (401, no identity).
r = forward(app)
assert r.status_code == 401 and "remote-auth" not in {k.lower() for k in r.headers}
ok("no credential → 401 without Remote-Auth")

# ══ A5: the gate token says `session` — signed, the same value as the way back ══════════════════════════════════
auth_g, app_g = build(gate_token_enabled=True)
anna_g = auth_g.create_user("anna", password=PW, roles=["editors"])
r = forward(app_g, client=session_client(auth_g, app_g, anna_g))
cookie = r.headers["X-TinySesam-Gate-Cookie"]
token = cookie.split(";", 1)[0].split("=", 1)[1]
claims = gate.check(base64.b64decode(auth_g.gate_public_key()), token, aud=APP, iss=BASE, now=int(time.time()))
assert claims, "the gate token does not pass the check"
assert claims["ts_auth"] == "session" == r.headers["Remote-Auth"], (claims.get("ts_auth"), r.headers["Remote-Auth"])
# The claim is covered by the signature: changing it breaks the token.
head, body, sig = token.split(".")
content = gate._read_b64u(body).decode().replace('"ts_auth":"session"', '"ts_auth":"apikey"')
assert '"ts_auth":"apikey"' in content
forged = head + "." + gate._b64u(content.encode()) + "." + sig
assert gate.check(base64.b64decode(auth_g.gate_public_key()), forged, aud=APP, iss=BASE, now=int(time.time())) is None
# An API key never gets a gate token — the `session` claim exists only for sessions.
key_g = auth_g.create_api_key(anna_g, name="ci")["key"]
r = forward(app_g, {"X-Api-Key": key_g})
assert r.headers["Remote-Auth"] == "apikey" and "x-tinysesam-gate-cookie" not in {k.lower() for k in r.headers}
# The token stands for the session row it was issued for — even when the account dict came in another way.
_tok_s, _ = auth_g.start_session(anna_g, "password")
_row = auth_g.store.get_session(_tok_s)
_dict = {**dict(auth_g._as_dict(auth_g.store.get_user(anna_g))), "_via": "apikey"}
_cookie = auth_g._gate_cookie(None, _dict, f"https://{APP}/", [], session=_row)
_claims = gate.check(base64.b64decode(auth_g.gate_public_key()), _cookie.split(";", 1)[0].split("=", 1)[1],
                     aud=APP, iss=BASE, now=int(time.time()))
assert _claims["ts_auth"] == "session", _claims.get("ts_auth")
ok("A5: gate token carries ts_auth=session (signed, a changed claim fails), the same as the header; "
   "no gate token for an API key; the claim follows the session row, not the way the account dict came in")

# ══ A7: a slot of forward_headers — renamed or left out ═════════════════════════════════════════════════════════
auth_r, app_r = build(gate_token_enabled=True, forward_headers={"user": "Remote-User", "auth": "X-Auth-Kind"})
uid_r = auth_r.create_user("anna", password=PW)
r = forward(app_r, client=session_client(auth_r, app_r, uid_r))
names = {k.lower() for k in r.headers}
assert r.headers["X-Auth-Kind"] == "session" and "remote-auth" not in names and "remote-groups" not in names
tok_r = r.headers["X-TinySesam-Gate-Cookie"].split(";", 1)[0].split("=", 1)[1]
claims_r = gate.check(base64.b64decode(auth_r.gate_public_key()), tok_r, aud=APP, iss=BASE, now=int(time.time()))
assert claims_r["ts_auth"] == "session"
auth_o, app_o = build(gate_token_enabled=True, forward_headers={"user": "Remote-User", "id": "Remote-Id"})
uid_o = auth_o.create_user("anna", password=PW)
r = forward(app_o, client=session_client(auth_o, app_o, uid_o))
assert r.status_code == 200 and "remote-auth" not in {k.lower() for k in r.headers}
tok_o = r.headers["X-TinySesam-Gate-Cookie"].split(";", 1)[0].split("=", 1)[1]
claims_o = gate.check(base64.b64decode(auth_o.gate_public_key()), tok_o, aud=APP, iss=BASE, now=int(time.time()))
assert "ts_auth" not in claims_o, claims_o
auth_m, app_m = build(forward_headers={"auth": ["Remote-Auth", "X-Auth-Request-Kind"]})
uid_m = auth_m.create_user("anna", password=PW)
r = forward(app_m, client=session_client(auth_m, app_m, uid_m))
assert r.headers["Remote-Auth"] == r.headers["X-Auth-Request-Kind"] == "session"
try:
    build(forward_headers={"auth": "Bad Header"})
except ConfigError as e:
    assert "forward_headers['auth']" in str(e), e
else:
    raise AssertionError("an invalid header name for the auth slot starts")
ok("A7: forward_headers renames the slot (header and claim follow), leaves it out (no header, no claim), "
   "takes a list, checks the name")

# Unknown way in → empty value, the header carries nothing (fail-closed: no invented kind).
_values = auth._forward_values({**dict(auth._as_dict(auth.store.get_user(anna))), "_via": "something"})
assert _values["auth"] == ""
ok("an unknown way in gives an empty kind, never a guessed one")


# ══ A6 (text): every template strips a client's Remote-Auth and sets TinySesam's ═══════════════════════════════
def code_of(text: str) -> str:
    return "\n".join(z.split("#", 1)[0] for z in text.splitlines())


DEFAULT = list(TinySesam.FORWARD_HEADERS_DEFAULT.values())
CADDYFILES = ("deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate", "deploy/home-network/Caddyfile",
              "deploy/quickstart/Caddyfile")


def caddy_gaps(text: str) -> list:
    code = code_of(text)
    gaps = []
    for h in DEFAULT:
        if not re.search(rf"^\s*request_header -{h}\s*$", code, re.M):
            gaps.append(f"does not strip {h}")
        matcher = re.search(rf"request_header (@\w+) {h} \{{rp\.header\.{h}\}}", code)
        if not matcher or not re.search(rf"^\s*{matcher.group(1)} not vars \{{rp\.header\.{h}\}} \"\"\s*$", code, re.M):
            gaps.append(f"way back does not set {h} from the answer")
    return gaps


def nginx_gaps(text: str) -> list:
    code = code_of(text)
    gaps = []
    for h in DEFAULT:
        var = "upstream_http_" + h.lower().replace("-", "_")
        got = re.search(rf"auth_request_set \$(\w+)\s+\${var};", code)
        if not got:
            gaps.append(f"does not read {h}")
            continue
        if not re.search(rf"proxy_set_header {h} \${got.group(1)};", code):
            gaps.append(f"does not set {h}")
    return gaps


def fastcgi_gaps(text: str) -> list:
    """nginx-path.conf: PHP sees a header only as fastcgi_param — set behind the gate, EMPTIED in the open remainder,
    otherwise the client's own `Remote-…` arrives as $_SERVER['HTTP_REMOTE_…']."""
    code = code_of(text)
    gaps = []
    for h in DEFAULT:
        param = "HTTP_" + h.upper().replace("-", "_")
        var = "upstream_http_" + h.lower().replace("-", "_")
        got = re.search(rf"auth_request_set \$(\w+)\s+\${var};", code)
        if not got or not re.search(rf"fastcgi_param {param}\s+\${got.group(1)};", code):
            gaps.append(f"protected PHP does not get {h}")
        if not re.search(rf"fastcgi_param {param}\s+\"\";", code):
            gaps.append(f"open PHP does not empty {h}")
    return gaps


def traefik_gaps(text: str) -> list:
    code = code_of(text)
    blocks = re.findall(r"authResponseHeaders:\n((?:\s+- \"[^\"]+\"\n)+)", code)
    gaps = [] if len(blocks) == 2 else [f"{len(blocks)} authResponseHeaders lists instead of 2"]
    for i, block in enumerate(blocks):
        listed = re.findall(r"- \"([^\"]+)\"", block)
        gaps += [f"list {i + 1} does not carry {h}" for h in DEFAULT if h not in listed]
    return gaps


def gate_fast_path_gaps(text: str) -> list:
    code = code_of(text)
    meta = re.search(r"meta_claims ([^\n]+)", code)
    gaps = []
    for slot, h in TinySesam.FORWARD_HEADERS_DEFAULT.items():
        if not meta or f"ts_{slot}" not in meta.group(1).split():
            gaps.append(f"meta_claims without ts_{slot}")
        if not re.search(rf"header_up {h} \{{http\.auth\.user\.ts_{slot}\}}", code):
            gaps.append(f"fast path does not set {h} from ts_{slot}")
    return gaps


CHECKS = [(f, caddy_gaps) for f in CADDYFILES] + [
    ("deploy/forward-auth/Caddyfile.gate", gate_fast_path_gaps),
    ("deploy/forward-auth/nginx.conf", nginx_gaps),
    ("deploy/forward-auth/nginx-path.conf", fastcgi_gaps),
    ("deploy/forward-auth/traefik.yml", traefik_gaps),
]
found = {}
for rel, rule in CHECKS:
    gaps = rule((ROOT / rel).read_text(encoding="utf-8"))
    if gaps:
        found[f"{rel} ({rule.__name__})"] = gaps
assert not found, found
# Self-probes: each rule sees a missing Remote-Auth line.
_c = (ROOT / CADDYFILES[0]).read_text(encoding="utf-8")
assert caddy_gaps(_c.replace("request_header -Remote-Auth", "", 1)), "Caddy rule blind for the strip"
assert caddy_gaps(_c.replace("request_header @ts_auth Remote-Auth", "request_header @ts_auth X-Other", 1))
_g = (ROOT / CADDYFILES[1]).read_text(encoding="utf-8")
assert gate_fast_path_gaps(_g.replace(" ts_auth\n", "\n", 1)), "gate rule blind for meta_claims"
assert gate_fast_path_gaps(_g.replace("header_up Remote-Auth {http.auth.user.ts_auth}", "", 1))
_n = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
assert nginx_gaps(_n.replace("proxy_set_header Remote-Auth $ts_auth;", "", 1)), "nginx rule blind"
_p = (ROOT / "deploy/forward-auth/nginx-path.conf").read_text(encoding="utf-8")
assert fastcgi_gaps(_p.replace('fastcgi_param HTTP_REMOTE_AUTH   "";', "", 1)), "FastCGI rule blind (open part)"
assert fastcgi_gaps(_p.replace("fastcgi_param HTTP_REMOTE_ID     $ts_id;", "", 1)), "FastCGI rule blind (Remote-Id)"
_t = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
assert traefik_gaps(_t.replace('          - "Remote-Auth"\n', "", 1)), "Traefik rule blind"
ok(f"A6 (templates): {len(CHECKS)} checks over Caddy ×4, the gate fast path, nginx, nginx/FastCGI and Traefik — "
   "every Remote-* incl. Remote-Auth stripped and set from TinySesam; self-probes see a missing line")

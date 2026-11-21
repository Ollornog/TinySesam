"""Attack round A (2026-11-21): OAuth AS, OAuth for services, app passwords, key management.

Every check here reproduces a finding of the round and FAILS while the gap is open — it is not a skip and not a
"known issue" marker: the suite is meant to be red until the fix lands. Each block names the rule it breaks and the
attacker it assumes; the evaluation (severity, fix) is in the round's report, not here.

    python tests/run_all.py test_attack_round_a.py
"""
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import oauth as O  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Attack round A — OAuth, services, app passwords, keys")

BASE = "https://auth.example.com"
RESOURCE = "https://app.example.com/mcp"
CB = "http://localhost:43123/callback"
PW = "Attack-Round-Pw15x"


def make(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), base_url=BASE, cookie_secure=False,
               passkey_enabled=False, forward_auth_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE],
               trusted_redirect_hosts=["app.example.com"], lang="en")
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def pkce():
    v = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")


def sign_in(auth, client, uid):
    tok, _ = auth.start_session(uid, "password")
    client.cookies.set(auth.session_cookie_name, tok)


def code_for(auth, client, cid, challenge):
    """authorize → consent page → allow; returns the authorization code."""
    q = {"response_type": "code", "client_id": cid, "redirect_uri": CB, "code_challenge": challenge,
         "code_challenge_method": "S256", "state": "s", "scope": "mcp offline_access", "resource": RESOURCE}
    resp = client.get("/auth/oauth/authorize", params=q)
    assert resp.status_code == 303, (resp.status_code, resp.text[:200])
    loc = resp.headers["location"]
    page = client.get(loc)
    assert page.status_code == 200, (page.status_code, page.text[:200])
    m = re.search(r"name=_csrf value='([^']*)'", page.text)
    txn = parse_qs(urlsplit(loc).query)["txn"][0]
    resp = client.post("/auth/oauth/consent", data={"_csrf": m.group(1) if m else "", "txn": txn, "decision": "allow"})
    assert resp.status_code == 303, (resp.status_code, resp.text[:200])
    return parse_qs(urlsplit(resp.headers["location"]).query)["code"][0]


def connect_device(auth, app, uid):
    """A program (MCP client) connected for `uid`: (client_id, token answer)."""
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    sign_in(auth, c, uid)
    cid = c.post("/auth/oauth/register", json={"client_name": "tool", "redirect_uris": [CB],
                                               "token_endpoint_auth_method": "none"}).json()["client_id"]
    v, ch = pkce()
    code = code_for(auth, c, cid, ch)
    t = c.post("/auth/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                          "code_verifier": v, "client_id": cid})
    assert t.status_code == 200, t.text
    return cid, t.json()


CSRF = "attack-round-a-csrf-token-0123456789abcdef"


def with_csrf(auth, client):
    """Double-submit: the CSRF cookie and the same value in the header/form (what the built-in pages do)."""
    client.cookies.set(auth.csrf_cookie_name, CSRF)
    client.headers["X-CSRF-Token"] = CSRF
    return client


def forward_status(app, access_token):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/mcp",
         "Authorization": f"Bearer {access_token}"}
    return TestClient(app).get("/auth/forward", headers=h).status_code


def refresh_status(app, cid, refresh_token):
    return TestClient(app).post("/auth/oauth/token", data={"grant_type": "refresh_token", "client_id": cid,
                                                           "refresh_token": refresh_token}).status_code


# ---------------------------------------------------------------- A-1 panic button leaves OAuth devices connected
# Attacker: has taken over the session once (stolen password + TOTP, or a stolen cookie with a fresh confirmation)
# and connected an MCP client — a refresh token for up to 180 days. The holder notices and pulls every lever the
# account offers: "end all sessions", "forgot password", an admin resets the password. API keys, app passwords and
# services die with each of these (`_keys_revoked`); the person's OAuth grants survive all three.
def a1_end_all_sessions():
    auth, app = make()
    uid = auth.create_user("victim", password=PW)
    cid, tok = connect_device(auth, app, uid)
    c = with_csrf(auth, TestClient(app))
    sign_in(auth, c, uid)
    resp = c.post("/auth/sessions/revoke", json={"scope": "all"})
    assert resp.status_code == 200, resp.text
    assert forward_status(app, tok["access_token"]) == 401, "access token still opens the resource after 'end all'"
    assert refresh_status(app, cid, tok["refresh_token"]) == 400, "refresh token still works after 'end all'"


def a1_password_reset():
    auth, app = make(password_reset_enabled=True)
    uid = auth.create_user("victim", password=PW, email="victim@example.com")
    cid, tok = connect_device(auth, app, uid)
    raw = auth.create_magic_token("reset_password", user_id=uid, email="victim@example.com")
    resp = with_csrf(auth, TestClient(app)).post("/auth/reset", data={"token": raw, "password": "Whole-New-Pw15xq",
                                                                     "_csrf": CSRF})
    assert resp.status_code in (200, 303) and auth.peek_magic(raw, purpose="reset_password") is None, \
        (resp.status_code, resp.text[:200])
    assert forward_status(app, tok["access_token"]) == 401, "access token still opens the resource after a reset"
    assert refresh_status(app, cid, tok["refresh_token"]) == 400, "refresh token still works after a reset"


def a1_admin_password_reset():
    auth, app = make()
    boss = auth.create_user("boss", password=PW, is_admin=True)
    uid = auth.create_user("victim", password=PW)
    cid, tok = connect_device(auth, app, uid)
    c = with_csrf(auth, TestClient(app))
    sign_in(auth, c, boss)
    resp = c.post(f"/auth/admin/api/users/{uid}/password", json={"password": "Admin-Sets-Pw15xq"})
    assert resp.status_code == 200, (resp.status_code, resp.text[:200])
    assert forward_status(app, tok["access_token"]) == 401, "access token still opens the resource after admin reset"
    assert refresh_status(app, cid, tok["refresh_token"]) == 400, "refresh token still works after admin reset"


r.run("A-1a 'end all sessions' disconnects the account's OAuth devices", a1_end_all_sessions)
r.run("A-1b password reset ('forgot password') disconnects the account's OAuth devices", a1_password_reset)
r.run("A-1c admin password reset disconnects the account's OAuth devices", a1_admin_password_reset)


# ---------------------------------------------------------------- A-2 rotation with a key in its overlap
# Attacker: copied the service's key file (backup, image layer, a leaked CI cache). The service rotates — ADR-13:
# "Rotation limits how long a copy works", the old key is accepted one more hour for assertions in flight. But the
# key endpoint accepts an assertion of ANY key that is still within its overlap: with the copied old key the
# attacker rotates in a key of their own; it becomes current, and the rightful service's NEW key is put on the
# one-hour clock instead. After an hour the attacker owns the service, the operator's rotation achieved the opposite.
def a2_rotation_with_retiring_key():
    try:
        import joserfc  # noqa: F401
    except ImportError:
        raise AssertionError("joserfc missing — install the extra [services] to run this check")
    from tinysesam import client as SC
    from tinysesam import oauth_services as OS
    auth, app = make(oauth_service_clients=True, oauth_resources=["https://app.example.com/api"],
                     available_roles=["backup"])
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)

    def transport(method, url, headers, body):
        u = urlsplit(url)
        resp = c.request(method, u.path + (("?" + u.query) if u.query else ""), headers=headers, content=body or None)
        return SC.Response(resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.content)

    svc = auth.create_service("backup", roles=["backup"])
    code = auth.create_service_pairing(svc, name="job", resources=["https://app.example.com/api"])["code"]
    sc = SC.ServiceClient.pair(BASE, code, os.path.join(tempfile.mkdtemp(), "k", "client.json"), transport=transport)
    cid = sc.client_id
    stolen = dict(sc._state["key"])          # the copy the attacker took
    sc.rotate_key()                          # the operator rotates — the copy should now run out
    current = sc.kid

    def claims(**over):
        now = int(time.time())
        d = {"iss": cid, "sub": cid, "aud": BASE, "iat": now, "exp": now + 60, "jti": os.urandom(12).hex()}
        d.update(over)
        return {k: v for k, v in d.items() if v is not None}

    mine = SC.new_key()
    form = {"client_assertion_type": OS.ASSERTION_TYPE,
            "client_assertion": SC.sign(stolen, OS.ASSERTION_TYP, claims()),
            "jwk": json.dumps(SC.public_jwk(mine)), "proof": SC.sign(mine, OS.KEY_TYP, claims(iss=None))}
    resp = c.post("/auth/oauth/service/keys", data=form)
    keys = {k["kid"]: k for k in auth.store.oauth_client_keys(cid)}
    assert keys[current]["retire_at"] is None, "the rightful current key was put on the overlap clock by the old key"
    assert mine["kid"] not in keys, "a key in its overlap rotated in a key of its own"
    assert resp.status_code in (400, 401), (resp.status_code, resp.text[:200])


r.run("A-2 only the CURRENT service key may rotate (a key within its overlap may not)", a2_rotation_with_retiring_key)


# ---------------------------------------------------------------- A-3 templates hand bearer secrets to the app
# Attacker: reads what the application sees — its access log with headers, a debug page, an error report, or the
# application itself is the weaker party. SECURITY.md promises "the template strips the header before the
# application (`header_up -Authorization`)", but the shipped templates only mention it in a comment. Measured with
# Caddy 2.11.9 and the templates word for word: the app receives `Authorization: Basic <user:app password>`; the same
# path carries `Bearer tsat_…` (OAuth) and `Bearer tsk_…` (an API key — valid at every host and at TinySesam's API).
def _caddy_app_blocks(text):
    """The bodies of every `reverse_proxy {$TS_APP_UPSTREAM…}` block (the application upstream)."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith("reverse_proxy {$TS_APP_UPSTREAM"):
            continue
        if not s.endswith("{") or s.count("{") == s.count("}"):
            out.append((i + 1, ""))          # no block at all → nothing is stripped
            continue
        depth, body = 0, []
        for z in lines[i:]:
            depth += z.count("{") - z.count("}")
            body.append(z)
            if depth <= 0:
                break
        out.append((i + 1, "\n".join(body)))
    return out


def a3_caddy(name):
    def check():
        text = (ROOT / name).read_text(encoding="utf-8")
        blocks = _caddy_app_blocks(text)
        assert blocks, f"{name}: no application upstream found"
        missing = [ln for ln, body in blocks if not re.search(r"^\s*header_up\s+-Authorization\s*$", body, re.M)]
        assert not missing, f"{name}: application upstream at line(s) {missing} passes Authorization through"
    return check


for name in ("deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate", "deploy/quickstart/Caddyfile",
             "deploy/home-network/Caddyfile"):
    r.run(f"A-3 {name}: Authorization never reaches the application", a3_caddy(name))


def a3_nginx():
    text = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
    app_loc = text[text.index("location / {"):text.index("location @tinysesam_login")]
    assert re.search(r'proxy_set_header\s+Authorization\s+""', app_loc), \
        "nginx.conf: `location /` (the app) passes Authorization through"


def a3_nginx_php():
    text = (ROOT / "deploy/forward-auth/nginx-path.conf").read_text(encoding="utf-8")
    protected = text[text.index("location ^~ /intern/"):text.index("# ── Open remainder")]
    assert re.search(r'fastcgi_param\s+HTTP_AUTHORIZATION\s+""', protected), \
        "nginx-path.conf: the protected PHP location passes Authorization (PHP_AUTH_USER/PW) through"


def a3_traefik():
    text = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
    assert re.search(r'customRequestHeaders:\s*\n(\s+\S+:.*\n)*?\s+Authorization:\s*""', text), \
        "traefik.yml: no middleware removes Authorization before the app"


r.run("A-3 deploy/forward-auth/nginx.conf: Authorization never reaches the application", a3_nginx)
r.run("A-3 deploy/forward-auth/nginx-path.conf: Authorization never reaches PHP", a3_nginx_php)
r.run("A-3 deploy/forward-auth/traefik.yml: Authorization never reaches the application", a3_traefik)


# ---------------------------------------------------------------- A-4 open registration: one /64 fills the cap
# Attacker: anyone on the internet with an IPv6 prefix (every home line has a /64, a VPS often a /48). The limit of
# open registration counts per full address (`oauth_register` + /128), the cap on registrations without a grant is
# global (1000) and lasts a day. Fifty addresses of one /64 fill it; from then on no person can connect a new MCP
# client (Claude Code registers anew on every logout and port collision) — until `gc` runs, and then again.
def a4_dcr_per_prefix():
    auth, app = make(trusted_proxies=[])
    accepted = 0
    for i in range(O.REGISTER_PER_IP_HOUR + 5):
        c = TestClient(app, base_url="http://testserver", client=(f"2001:db8:1:2::{i + 1:x}", 50000))
        resp = c.post("/auth/oauth/register", json={"client_name": "x", "redirect_uris": [CB],
                                                    "token_endpoint_auth_method": "none"})
        accepted += resp.status_code == 201
    assert accepted <= O.REGISTER_PER_IP_HOUR, \
        f"{accepted} registrations from ONE IPv6 /64 (limit {O.REGISTER_PER_IP_HOUR} per hour)"


r.run("A-4 open registration is limited per IPv6 /64, not per /128", a4_dcr_per_prefix)


# ---------------------------------------------------------------- A-5 plain text passes the vault
# Attacker: can write the SQLite file but has neither the vault key nor the gate key (ADR-12: "then it takes the
# database AND the vault key"). The table `key_material` exists only since 0.26 and was encrypted from its first row
# — yet the vault hands back any value without a `v1:`/`v2:` prefix as plain text. A planted plain-text gate seed
# with its matching kid is loaded as a gate key and published at /auth/gate/jwks.json: the proxy then accepts gate
# tokens the attacker signs for any account. The same fallback lets a plain-text TOTP secret pass at runtime.
def a5_plaintext_key_material():
    from tinysesam import keys as K
    auth, app = make(gate_token_enabled=True, forward_apps={"app.example.com": {"name": "App"}})
    before = auth.store.key_ring_rows(K.GATE)
    assert before, "no gate keyring in the database"
    seed = os.urandom(32)
    kid = K.kid_for(K.GATE, seed)
    auth.store._exec("INSERT INTO key_material(purpose, kid, material, created_at, since, note) VALUES (?,?,?,?,?,?)",
                     (K.GATE, kid, base64.b64encode(seed).decode("ascii"), int(time.time()),
                      int(time.time()) + 10 * 365 * 86400, ""))
    try:
        rows = auth.store.key_ring_rows(K.GATE)
    except Exception:
        return                                # refused — the fix
    assert kid not in [k.kid for k in rows], "a plain-text gate seed planted in key_material is loaded as a gate key"


r.run("A-5 key_material refuses a value that is not vault ciphertext", a5_plaintext_key_material)


# ---------------------------------------------------------------- A-6 code reuse inside the first exchange
# Attacker: intercepted the authorization code (local malware listening on the loopback port, a proxy log). RFC 9700
# §4.2.4 / ADR-11: "reuse ... revoking the grant it produced". The code is consumed first, the grant is written in a
# second transaction; a second exchange that lands in between finds `grant_id` still empty, revokes nothing, and the
# first (possibly the attacker's) grant lives on.
def a6_code_reuse_race():
    auth, app = make()
    uid = auth.create_user("victim", password=PW)
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    sign_in(auth, c, uid)
    cid = c.post("/auth/oauth/register", json={"client_name": "tool", "redirect_uris": [CB],
                                               "token_endpoint_auth_method": "none"}).json()["client_id"]
    v, ch = pkce()
    code = code_for(auth, c, cid, ch)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": CB, "code_verifier": v, "client_id": cid}
    original = auth.store.oauth_create_grant
    second = {}

    def interleaved(*a, **kw):
        second["status"] = TestClient(app).post("/auth/oauth/token", data=form).status_code
        return original(*a, **kw)

    auth.store.oauth_create_grant = interleaved
    try:
        first = TestClient(app).post("/auth/oauth/token", data=form)
    finally:
        auth.store.oauth_create_grant = original
    assert second.get("status") == 400, second
    assert first.status_code == 200, first.text
    assert forward_status(app, first.json()["access_token"]) == 401, \
        "a reused code (second exchange during the first) left the grant of the first exchange alive"


r.run("A-6 a code reused while the first exchange runs still revokes what it produced", a6_code_reuse_race)

sys.exit(r.done())

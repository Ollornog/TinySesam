"""Attack round A (2026-11-21): OAuth AS, OAuth for services, app passwords, key management.

Each block reproduced a finding of the round and failed while the gap was open; since the fixes they guard them.
Each block names the rule it pins and the attacker it assumes; the evaluation (severity, fix) is in the round's
report (backlog T-69). Further checks of the same fixes live with their surface: tests/test_cli.py (offline reset
revokes, A-1), tests/test_oauth_services.py (A-2 and the crash during a rotation), tests/test_gate_caddy.py (A-3
through a real Caddy), tests/test_oauth.py (cap and /48, A-4), tests/test_keys.py ((g), A-5).

    python tests/run_all.py test_attack_round_a.py
"""
import base64
import hashlib
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
# Lives in tests/test_oauth_services.py ("A-2"): it needs the extra [services], and that suite skips cleanly without
# it — here it would have failed the minimal install.


# ---------------------------------------------------------------- A-3 templates hand bearer secrets to the app
# Attacker: reads what the application sees — its access log with headers, a debug page, an error report, or the
# application itself is the weaker party. SECURITY.md promised "the template strips the header before the
# application (`header_up -Authorization`)", but the shipped templates only mentioned it in a comment. Measured with
# Caddy 2.11.9 and the templates word for word: the app received `Authorization: Basic <user:app password>`; the same
# path carries `Bearer tsat_…` (OAuth) and `Bearer tsk_…` / `X-Api-Key: tsk_…` (an API key — valid at every host and
# at TinySesam's API). Live through a real Caddy: tests/test_gate_caddy.py ("A-3").
#
# EVERY proxy template under deploy/ is found by its content, not by a list: a new template falls under the rule
# without anyone remembering this test. The named ones must be among the found (the scan cannot silently miss them).
#   Caddy   every `reverse_proxy` that is not TinySesam (`TS_AUTH_UPSTREAM`) drops both headers;
#   nginx   every location behind `auth_request` (itself or an enclosing one) that passes to an upstream empties
#           both (`proxy_set_header … ""`, for FastCGI `fastcgi_param HTTP_… ""`);
#   Traefik every router with a forwardAuth middleware has, AFTER it, a headers middleware emptying both.
CRED = ("Authorization", "X-Api-Key")


def _blocks(text, opener):
    """(line number, opening line, body incl. nested blocks) of every block whose opening line matches `opener`."""
    lines = [z.split("#", 1)[0] if not z.lstrip().startswith("#") else "" for z in text.splitlines()]
    out = []
    for i, line in enumerate(lines):
        if not re.match(opener, line.strip()):
            continue
        if "{" not in line:
            out.append((i + 1, line.strip(), ""))
            continue
        depth, body = 0, []
        for z in lines[i:]:
            depth += z.count("{") - z.count("}")
            body.append(z)
            if depth <= 0:
                break
        out.append((i + 1, line.strip(), "\n".join(body)))
    return out


def caddy_gaps(text):
    gaps = []
    for ln, head, body in _blocks(text, r"reverse_proxy\s"):
        if "TS_AUTH_UPSTREAM" in head:
            continue                       # TinySesam itself: the check NEEDS the credentials
        for h in CRED:
            if not re.search(rf"^\s*header_up\s+-{h}\s*$", body, re.M):
                gaps.append(f"line {ln}: {h}")
    return gaps


def nginx_gaps(text):
    gaps = []
    locs = _blocks(text, r"location\s")
    for ln, head, body in locs:
        passes = re.search(r"^\s*(proxy_pass|fastcgi_pass)\s", body, re.M)
        if not passes:
            continue
        # behind the gate: this location or one that encloses it asks auth_request
        gated = any(re.search(r"^\s*auth_request\s", b, re.M) and body in b for _, _, b in locs)
        if not gated or re.search(r"location\s[^{]*\{", body.split("\n", 1)[-1]):
            continue                       # not gated, or a parent whose nested locations are checked themselves
        for h in CRED:
            fcgi = "HTTP_" + h.upper().replace("-", "_")
            if not (re.search(rf'^\s*proxy_set_header\s+{h}\s+""\s*;', body, re.M | re.I)
                    or re.search(rf'^\s*fastcgi_param\s+{fcgi}\s+""\s*;', body, re.M)):
                gaps.append(f"line {ln} ({head}): {h}")
    return gaps


def traefik_gaps(text):
    text = "\n".join(z for z in text.splitlines() if not z.lstrip().startswith("#"))
    mw = {}
    for m in re.finditer(r"^    ([\w-]+):\n((?:      .*\n?|\s*\n)*)", text, re.M):
        mw[m.group(1)] = m.group(2)
    auth = {n for n, b in mw.items() if "forwardAuth:" in b}
    strip = {n for n, b in mw.items() if all(re.search(rf'^\s+{h}:\s*""\s*$', b, re.M) for h in CRED)}
    gaps = []
    for m in re.finditer(r"^    ([\w-]+):\n\s+rule:.*\n\s+middlewares:\n((?:\s+- .*\n)+)", text, re.M):
        chain = [z.strip()[2:].split("#")[0].strip() for z in m.group(2).splitlines()]
        firsts = [i for i, n in enumerate(chain) if n in auth]
        if firsts and not any(n in strip for n in chain[firsts[0] + 1:]):
            gaps.append(f"router {m.group(1)}")
    return gaps, auth


def proxy_templates():
    """{path: kind} of every proxy template under deploy/, recognised by its content."""
    found = {}
    for f in sorted((ROOT / "deploy").rglob("*")):
        if not f.is_file() or f.suffix in (".py", ".go", ".sum", ".mod", ".sh", ".txt", ".in", ".md"):
            continue
        t = f.read_text(encoding="utf-8", errors="replace")
        rel = str(f.relative_to(ROOT))
        if re.search(r"^\s*reverse_proxy\s", t, re.M):
            found[rel] = "caddy"
        elif re.search(r"^\s*(proxy_pass|fastcgi_pass)\s", t, re.M):
            found[rel] = "nginx"
        elif "forwardAuth:" in t:
            found[rel] = "traefik"
    return found


def a3_every_template():
    found = proxy_templates()
    named = {"deploy/forward-auth/Caddyfile", "deploy/forward-auth/Caddyfile.gate", "deploy/quickstart/Caddyfile",
             "deploy/home-network/Caddyfile", "deploy/forward-auth/nginx.conf", "deploy/forward-auth/nginx-path.conf",
             "deploy/forward-auth/traefik.yml"}
    assert named <= set(found), f"the scan misses templates: {sorted(named - set(found))}"
    gaps = {}
    for rel, kind in found.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        g = caddy_gaps(text) if kind == "caddy" else nginx_gaps(text) if kind == "nginx" else traefik_gaps(text)[0]
        if g:
            gaps[rel] = g
    assert not gaps, f"credentials reach the application: {gaps}"


def a3_scan_can_fail():
    """Self-probe: the rules see a gap where there is one (a check that cannot fail proves nothing)."""
    c = (ROOT / "deploy/forward-auth/Caddyfile").read_text(encoding="utf-8")
    assert caddy_gaps(c.replace("header_up -X-Api-Key\n", "", 1)), "Caddy rule blind"
    n = (ROOT / "deploy/forward-auth/nginx.conf").read_text(encoding="utf-8")
    assert nginx_gaps(n.replace('proxy_set_header Authorization "";', "", 1)), "nginx rule blind"
    p = (ROOT / "deploy/forward-auth/nginx-path.conf").read_text(encoding="utf-8")
    assert nginx_gaps(p.replace('fastcgi_param HTTP_AUTHORIZATION "";', "", 1)), "nginx/FastCGI rule blind"
    # … and the open remainder of nginx-path.conf (not behind the gate, its own Authorization) is no gap.
    assert not nginx_gaps(p), nginx_gaps(p)
    t = (ROOT / "deploy/forward-auth/traefik.yml").read_text(encoding="utf-8")
    gaps, auth = traefik_gaps(t)
    assert auth and not gaps, (auth, gaps)
    assert traefik_gaps(t.replace("        - tinysesam-strip-credentials", "        # -", 1))[0], "Traefik rule blind"
    # Swap the check and the credential strip in the chain (whatever stands before them, e.g. tinysesam-strip-client).
    order = re.sub(r"(?m)^(\s+- tinysesam-auth\b.*\n)(\s+- tinysesam-strip-credentials\b.*\n)", r"\2\1", t, count=1)
    assert order != t and traefik_gaps(order)[0], "Traefik rule does not see a strip BEFORE the check"


r.run("A-3 every proxy template under deploy/: Authorization and X-Api-Key never reach the application",
      a3_every_template)
r.run("A-3 self-probe: the template rules see a gap where there is one", a3_scan_can_fail)


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
    # Stricter than "the grant is revoked": the first exchange issues nothing at all once the code came back during
    # it — no token answer, no live grant of the account (RFC 9700 §4.2.4: everything the code produced is void).
    assert first.status_code == 400 and "access_token" not in first.text, first.text
    assert not auth.store.oauth_user_grant_ids(uid), \
        "a reused code (second exchange during the first) left the grant of the first exchange alive"
    # Counter-check: the plain flow still connects (the reuse mark does not refuse every exchange).
    v2, ch2 = pkce()
    code2 = code_for(auth, c, cid, ch2)
    ok = TestClient(app).post("/auth/oauth/token", data=dict(form, code=code2, code_verifier=v2))
    assert ok.status_code == 200 and forward_status(app, ok.json()["access_token"]) == 200, ok.text


r.run("A-6 a code reused while the first exchange runs still revokes what it produced", a6_code_reuse_race)

sys.exit(r.done())

"""T-91, stage E2: the own account's security state as data — `auth.account_overview(user, …)`, `GET /auth/account.json`
and `GET /.tinysesam/account.json`.

An application that draws its own settings page shows sign-in methods, sessions and connected programs from here and
links to TinySesam's account page (with anchors) for every change. Rules (draft §4, §9, accepted by the PO):
only a full browser session reads (an API key, an OAuth token, an app password, a half session → 401); no parameter
chooses an account; `no-store`, `Vary: Cookie`, no CORS; 60 reads per account and minute, a refusal is a
`failed verification` line; read only (POST/DELETE → 405). The account page reads the same function.
"""
import base64
import hashlib
import logging
import os
import re
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, security  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "tests"))
from voraussetzung import braucht_modul  # noqa: E402

braucht_modul("webauthn", extra="passkey")      # A6 compares the passkeys with the account page's list

HTML = {"Accept": "text/html"}
BASE = "https://auth.example.com"
APP = "team.example.com"
PW = "a long test password 4711"
RESOURCE = f"https://{APP}/mcp"
CB = "http://localhost:43123/callback"
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=[APP, "dav.example.com"], account_enabled=True,
               forward_auth_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE],
               forward_apps={APP: {"name": "Example", "home": "/"},
                             "dav.example.com": {"name": "Files", "app_passwords": True}})
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session(auth, uid, ua=UA_FIREFOX, ip="192.0.2.10", full=True):
    if full:
        tok, _ = auth.start_session(uid, "password", ip=ip, ua=ua)
    else:
        tok = auth._create_session(uid, 3600, False, "password", ip, ua)
    return tok


def client(auth, app, tok=None, host=None):
    c = TestClient(app, base_url=f"https://{host or 'auth.example.com'}", follow_redirects=False)
    if tok:
        c.cookies.set(auth.session_cookie_name, tok)
    return c


auth, app = make()
anna = auth.create_user("anna", password=PW, display_name="Anna Example")
bob = auth.create_user("bob", password=PW)
tok_a = session(auth, anna)
tok_a2 = session(auth, anna, ua="curl/8.0", ip="192.0.2.11")
ca = client(auth, app, tok_a)

# ══ A1: a session → 200, no-store, Vary: Cookie, no CORS ════════════════════════════════════════════════════════
r = ca.get("/auth/account.json", headers={"Origin": "https://evil.example"})
assert r.status_code == 200 and r.headers["content-type"].startswith("application/json"), r.status_code
assert r.headers["cache-control"] == "no-store" and "cookie" in r.headers.get("vary", "").lower(), dict(r.headers)
assert not [k for k in r.headers if k.lower().startswith("access-control-")], dict(r.headers)
j = r.json()
assert isinstance(j, dict) and j["signed_in"] is True and j["account"] == {"username": "anna",
                                                                           "display_name": "Anna Example"}, j
ok("A1: a full session → 200, an object, Cache-Control: no-store, Vary: Cookie, no Access-Control-* (also with Origin)")

# ══ A2: API key (Bearer, X-Api-Key), OAuth token, app password, half session → 401 ════════════════════════════
key = auth.create_api_key(anna, name="probe")["key"]
ap = auth.create_app_password(anna, "Phone", hosts=["dav.example.com"])["secret"]


def oauth_token(uid):
    c = client(auth, app, session(auth, uid))
    cid = c.post("/auth/oauth/register", json={"client_name": "Probe client", "redirect_uris": [CB],
                                               "grant_types": ["authorization_code", "refresh_token"],
                                               "response_types": ["code"],
                                               "token_endpoint_auth_method": "none"}).json()["client_id"]
    v = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    ch = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    r = c.get("/auth/oauth/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": CB,
                                               "code_challenge": ch, "code_challenge_method": "S256",
                                               "state": "s", "scope": "mcp", "resource": RESOURCE})
    loc = r.headers["location"]
    page = c.get(loc).text
    csrf = re.search(r"name=_csrf value='([^']*)'", page).group(1)
    txn = parse_qs(urlsplit(loc).query)["txn"][0]
    r = c.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": txn, "decision": "allow"})
    code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
    r = c.post("/auth/oauth/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                          "code_verifier": v, "client_id": cid})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


at = oauth_token(anna)
half = session(auth, anna, full=False)
anon = client(auth, app)
for was, c, head in (("Bearer API key", anon, {"Authorization": f"Bearer {key}"}),
                     ("X-Api-Key", anon, {"X-Api-Key": key}),
                     ("OAuth token", anon, {"Authorization": f"Bearer {at}"}),
                     ("app password", anon,
                      {"Authorization": "Basic " + base64.b64encode(f"anna:{ap}".encode()).decode()}),
                     ("half session", client(auth, app, half), {}),
                     ("nothing", anon, {})):
    for path in ("/auth/account.json", "/.tinysesam/account.json"):
        r = c.get(path, headers={**head, "X-Forwarded-Host": APP})
        assert r.status_code == 401, (was, path, r.status_code, r.text[:200])
        assert r.json() == {"authenticated": False, "signed_in": False}, (was, r.text)
        assert r.headers["cache-control"] == "no-store", (was, dict(r.headers))
assert anon.get("/auth/me", headers={"Authorization": f"Bearer {key}"}).status_code == 200, "probe: the key works"
ok("A2: Bearer and X-Api-Key, OAuth access token, app password (Basic), half session, nothing → 401 "
   "{authenticated: false, signed_in: false}, no-store — on both routes (probe: the key is valid for /auth/me)")

# ══ A3: a locked account with a still valid cookie → 401; the function says None ═════════════════════════════
locked = auth.create_user("lotte", password=PW)
tok_l = session(auth, locked)
auth.store._exec("UPDATE users SET disabled=1 WHERE id=?", (locked,))
assert client(auth, app, tok_l).get("/auth/account.json").status_code == 401
assert auth.account_overview({"id": locked}) is None and auth.account_overview({"id": 999999}) is None
svc = auth.create_user("svc-bot", is_service=True)
assert auth.account_overview({"id": svc}) is None, "a service account has no security page"
ok("A3: a locked account with a valid cookie → 401; account_overview(locked | unknown | service) → None")

# ══ A4: no parameter chooses an account ═════════════════════════════════════════════════════════════════════════
for q in (f"?user={bob}", f"?id={bob}", f"?user_id={bob}&username=bob", "?username=bob"):
    j = ca.get("/auth/account.json" + q).json()
    assert j["account"]["username"] == "anna", (q, j["account"])
ok("A4: ?user=, ?id=, ?user_id=, ?username= change nothing — always the own account")

# ══ A5: /.tinysesam/account.json — 404 on an unprotected host, links with app= on a protected one ═══════════════
r = client(auth, app, tok_a).get("/.tinysesam/account.json", headers={"X-Forwarded-Host": "evil.example"})
assert r.status_code == 404, r.status_code
r = client(auth, app, tok_a).get("/.tinysesam/account.json", headers={"X-Forwarded-Host": APP})
assert r.status_code == 200 and r.headers["cache-control"] == "no-store", r.status_code
links = r.json()["links"]
assert links["account"] == f"{BASE}/auth/account?app={APP}", links
assert links["sessions"] == f"{BASE}/auth/account?app={APP}#sessions", links
j = ca.get("/auth/account.json").json()
assert j["links"]["account"] == f"{BASE}/auth/account" and j["links"]["totp"] == f"{BASE}/auth/account#totp", j
r = client(auth, app, tok_a).get("/.tinysesam/account.json", headers={"X-Forwarded-Host": "dav.example.com"})
assert r.status_code == 200 and r.json()["links"]["account"] == f"{BASE}/auth/account", "no frame → no app="
ok("A5: /.tinysesam/account.json → 404 for an unprotected host; on a host with a frame the links carry app=<host> "
   "(anchors stay); without a frame and on /auth/account.json none")

# ══ A6: the same numbers as the account page — recovery codes, sessions, passkeys ══════════════════════════════
import pyotp  # noqa: E402

from _totp_clock import previous_code  # noqa: E402

secret = auth.totp_begin(anna)["secret"]
assert auth.totp_confirm(anna, previous_code(pyotp.TOTP(secret)))
codes = auth.generate_recovery_codes(anna)
truth = len(codes) - 3
assert all(auth._verify_recovery_code(anna, code) for code in codes[:3])
assert auth.recovery_codes_remaining(anna) == truth, (auth.recovery_codes_remaining(anna), truth)
j = ca.get("/auth/account.json").json()
page = ca.get("/auth/account", headers=HTML).text
assert j["sign_in"]["totp"] == {"enabled": True, "recovery_left": truth, "recovery_low": truth <= 3}, j["sign_in"]
shown = re.search(r"<div id=rc_left class='rcleft [a-z]+'>([^<]*)</div>", page).group(1)
assert str(truth) in shown, (shown, truth)
listed = ca.get("/auth/sessions").json()
assert j["sessions"]["count"] == len(listed) == len(j["sessions"]["items"]) >= 2, (j["sessions"]["count"], len(listed))
ok(f"A6: recovery_left = {truth} = the account page's line = the truth after using three codes; the session count "
   "= /auth/sessions")

# Passkeys: the count and names equal the account page's list route.
auth_p, app_p = make(passkey_enabled=True)
u = auth_p.create_user("pia", password=PW)
auth_p.store.add_webauthn(u, b"cred-1", b"pk", 0, "[]", "Laptop")
auth_p.store.add_webauthn(u, b"cred-2", b"pk", 0, "[]", "Phone")
cp = client(auth_p, app_p, session(auth_p, u))
j = cp.get("/auth/account.json").json()
lst = cp.get("/auth/passkey/list").json()
assert j["sign_in"]["passkeys"]["count"] == len(lst) == 2, (j["sign_in"]["passkeys"], lst)
assert [p["name"] for p in j["sign_in"]["passkeys"]["items"]] == [p["name"] for p in lst]
assert j["links"]["passkeys"] == f"{BASE}/auth/account#passkeys"
ok("A6: passkeys — count and names equal /auth/passkey/list (the account page's list)")

# ══ A7: a feature off → null, on and empty → [] ═════════════════════════════════════════════════════════════════
j = client(auth, app, session(auth, bob)).get("/auth/account.json").json()
assert j["programs"]["oauth"] == [] and j["programs"]["app_passwords"] == [], j["programs"]
assert j["sign_in"]["totp"] == {"enabled": False, "recovery_left": None, "recovery_low": False}
assert j["links"]["devices"] and j["links"]["app_passwords"] and j["links"]["passkeys"] is None
auth_off, app_off = make(oauth_enabled=False, oauth_resources=[], totp_enabled=False, apikey_enabled=False,
                         forward_apps={APP: {"name": "Example", "home": "/"}}, trusted_redirect_hosts=[APP])
u = auth_off.create_user("otto", password=PW)
j = client(auth_off, app_off, session(auth_off, u)).get("/auth/account.json").json()
assert j["programs"] == {"oauth": None, "services": None, "app_passwords": None, "api_keys_active": None}, j
assert j["sign_in"]["totp"] is None and j["sign_in"]["passkeys"] is None and j["sign_in"]["pin"] is None, j
assert j["approvals"] is None and j["links"]["devices"] is None and j["links"]["totp"] is None, j
assert j["links"]["sessions"] == f"{BASE}/auth/account#sessions"
ok("A7: off → null (oauth, services, app passwords, API keys, TOTP, passkeys, PIN, approvals, their links); "
   "on and empty → []")

# ══ A8: never a hash, a secret, a key prefix, an address or a raw browser string ═══════════════════════════════
raw = ca.get("/auth/account.json").text
forbidden = {"session token": tok_a, "session hash": auth.store.session_hash(tok_a), "TOTP secret": secret,
             "API key": key, "key prefix": key[:12], "app password": ap, "address": "192.0.2.10",
             "browser string": UA_FIREFOX, "OAuth token": at}
for row in auth.store._all("SELECT key_hash FROM api_key WHERE user_id=?", (anna,)):
    forbidden["key hash"] = row["key_hash"]
for name, value in forbidden.items():
    assert value and value not in raw, name
assert "token_hash" not in raw and '"ip"' not in raw and "user_agent" not in raw and "client_id" not in raw
ok("A8: the answer carries no session token or hash, TOTP secret, API key, key hash or prefix, app password, OAuth "
   "token, address or browser string")

# ══ A9: the 61st read in a minute → 429 with Retry-After and a `failed verification` line ══════════════════════
class _Lines(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, rec):
        self.lines.append(rec.getMessage())


rec = _Lines()
security.seclog.addHandler(rec)
try:
    auth_r, app_r = make()
    ur = auth_r.create_user("rita", password=PW)
    cr = client(auth_r, app_r, session(auth_r, ur))
    codes_seen = [cr.get("/auth/account.json").status_code for _ in range(60)]
    assert set(codes_seen) == {200}, codes_seen
    r = cr.get("/auth/account.json")
    assert r.status_code == 429 and r.headers.get("retry-after") == "60", (r.status_code, dict(r.headers))
    assert r.headers["cache-control"] == "no-store"
    mine = [z for z in rec.lines if "ratelimit_account_json" in z]
    assert mine and all(z.startswith(security.LOG_CHECK) for z in mine), rec.lines[-3:]
    assert not [z for z in mine if security.LOG_SIGN_IN in z], "a `failed login` line would feed the fail2ban jail"
    other = auth_r.create_user("ruth", password=PW)
    assert client(auth_r, app_r, session(auth_r, other)).get("/auth/account.json").status_code == 200, \
        "the limit is per account"
finally:
    security.seclog.removeHandler(rec)
ok("A9: 60 reads → 200, the 61st → 429 with Retry-After: 60 and a `failed verification` line (no `failed login`); "
   "another account is not affected")

# ══ A10: only GET ═══════════════════════════════════════════════════════════════════════════════════════════════
for path in ("/auth/account.json", "/.tinysesam/account.json"):
    for method in ("POST", "DELETE", "PUT", "PATCH"):
        r = ca.request(method, path, headers={"X-Forwarded-Host": APP, "X-CSRF-Token": "x"})
        assert r.status_code == 405, (method, path, r.status_code)
ok("A10: POST, DELETE, PUT, PATCH on both routes → 405")

# ══ A11: the fields of draft §9 — current, last_seen, a coarse device; name and last_used per program ══════════
j = ca.get("/auth/account.json").json()
items = j["sessions"]["items"]
assert all(set(s) == {"created_at", "last_seen", "method", "device", "current"} for s in items), items
mine = [s for s in items if s["current"] is True]
assert len(mine) == 1 and mine[0]["device"] == "Firefox · Linux", items
assert any(s["device"] == "curl" and s["current"] is False for s in items), items
assert all(isinstance(s["last_seen"], int) for s in items), items
progs = j["programs"]
assert [p["name"] for p in progs["oauth"]] == ["Probe client"] and set(progs["oauth"][0]) == {
    "name", "created_at", "last_used"}, progs["oauth"]
assert [p["name"] for p in progs["app_passwords"]] == ["Phone"], progs["app_passwords"]
assert set(progs["app_passwords"][0]) == {"name", "created_at", "last_used", "expires_at"}
assert progs["api_keys_active"] == 1, progs
assert set(j["links"]) == {"account", "sessions", "totp", "passkeys", "devices", "app_passwords", "services",
                           "approvals"}, j["links"]
ok("A11: per session created_at, last_seen, method, a coarse device ('Firefox · Linux', 'curl'), current; per program "
   "name, created_at, last_used; anchor links per section")

# ══ A12: the library function for a wrapper — no request → current null; app_host → app= ═════════════════════
v = auth.account_overview(auth.get_user(anna))
assert all(s["current"] is None for s in v["sessions"]["items"]), "without the request no session is 'this one'"
assert v["links"]["account"] == f"{BASE}/auth/account"
v = auth.account_overview(auth.get_user(anna), app_host=APP, base="https://gw.example.com")
assert v["links"]["account"] == f"https://gw.example.com/auth/account?app={APP}", v["links"]
v = auth.account_overview(auth.get_user(anna), app_host="unknown.example")
assert v["links"]["account"] == f"{BASE}/auth/account", "an unknown app_host adds nothing"
assert "signed_in" not in v, "the function returns the overview; signed_in belongs to the route"
ok("A12: account_overview(user) for a wrapper — without the request current is null; app_host with a frame adds "
   "app=, an unknown one nothing; base replaces base_url")

# ══ A13: the account page reads the same function ══════════════════════════════════════════════════════════════
calls = []
real = auth.account_overview


def spy(*a, **k):
    calls.append(k)
    return real(*a, **k)


auth.account_overview = spy
try:
    assert ca.get("/auth/account", headers=HTML).status_code == 200
finally:
    del auth.account_overview
assert calls, "the account page does not read account_overview"
ok("A13: the account page builds its state from account_overview (one source)")

print("account overview OK")

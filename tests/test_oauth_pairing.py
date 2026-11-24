"""Pairing code for people's programs (ADR-14): the consent given in advance, spent by ONE matching authorization.

The account fetches a code in its own fresh browser session, a setup script redeems it without a session, and the
next authorization of that account — dynamically registered client, loopback redirect, matching resource, opened
by the person's browser itself (`Sec-Fetch-Site: none`), the same account signed in — skips the consent page once.
Every block pins one rule; most of them are about what does NOT skip the page and does NOT spend the consent. The
mutation that turns each red is listed in the PR.
"""
import base64
import concurrent.futures
import hashlib
import html as html_lib
import io
import json
import logging
import os
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import ConfigError, TinySesam, TinySesamConfig
from tinysesam import oauth as O
from tinysesam.store import Store

RESOURCE = "https://app.example.com/mcp"
RESOURCE2 = "https://other.example.com/mcp"
BASE = "https://auth.example.com"
CB = "http://localhost:43123/callback"
NONE = {"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1"}


def ok(msg):
    print("  ✓", msg)


def make(**over):
    d = tempfile.mkdtemp()
    cfg = dict(db_path=os.path.join(d, "t.db"), base_url=BASE, cookie_secure=False, passkey_enabled=False,
               forward_auth_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE, RESOURCE2],
               oauth_pairing_consent_enabled=True, apikey_enabled=True,
               forward_apps={"app.example.com": {"name": "Doc Hub"}},
               trusted_redirect_hosts=["app.example.com"], lang="en")
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


auth, app = make()
events = []
auth.on_security_event = lambda ev, acc, det: events.append((ev, acc["username"], det))
alice = auth.create_user("alice", password="alice-pw-12345")
bob = auth.create_user("bob", password="bob-pw-123456")

seclog = io.StringIO()
_handler = logging.StreamHandler(seclog)
logging.getLogger("tinysesam.security").addHandler(_handler)
logging.getLogger("tinysesam.security").setLevel(logging.INFO)


def client():
    return TestClient(app, base_url="http://testserver", follow_redirects=False)


def browser(uid, age=0):
    """A browser with a FULL session of `uid`; sign-in and last confirmation `age` seconds back."""
    c = client()
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    if age:
        then = int(time.time()) - age
        auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                         (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    c.get("/auth/account")
    return c


def fresh_budget():
    """The suite issues and redeems far more than a person does in an hour: the limits are pinned on their own
    instances below (A-1 and the issuing block); here each call starts with a full budget."""
    for k in [k for k in auth.rl._hits if isinstance(k, tuple) and str(k[0]).startswith("oauth_consent")]:
        del auth.rl._hits[k]


def create(c, **body):
    fresh_budget()
    return c.post("/auth/oauth/pairing", json=body, headers={"X-CSRF-Token": c.cookies.get(auth.csrf_cookie_name) or ""})


def redeem(code, c=None):
    fresh_budget()
    return (c or client()).post("/auth/oauth/pairing/redeem", json={"code": code})


def register(c, uris=None, name="Claude Code"):
    r = c.post("/auth/oauth/register", json={"client_name": name, "redirect_uris": uris or [CB],
                                             "token_endpoint_auth_method": "none"})
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def pkce():
    v = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")


def authorize(c, cid, challenge, headers=NONE, redirect_uri=CB, resource=RESOURCE, **extra):
    """/authorize as Claude Code sends it (prompt=consent, mcp offline_access, resource) → the consent URL."""
    params = {"response_type": "code", "client_id": cid, "redirect_uri": redirect_uri, "code_challenge": challenge,
              "code_challenge_method": "S256", "state": "st-1", "scope": "mcp offline_access", "resource": resource,
              "prompt": "consent"}
    params.update(extra)
    r = c.get("/auth/oauth/authorize", params={k: v for k, v in params.items() if v is not None},
              headers=headers or {})
    assert r.status_code == 303 and "/auth/oauth/consent?txn=" in r.headers["location"], (r.status_code, r.text[:200])
    return r.headers["location"]


def consent_get(c, loc):
    """The consent step: ("code", query) when it went straight back to the program, ("page", response) otherwise."""
    r = c.get(loc)
    assert r.status_code != 303 or not r.headers["location"].startswith("http://localhost:"), \
        "a 303 to the loopback is stopped by Chrome after a sign-in form (form-action): the return page hands over"
    m = re.search(r"<meta http-equiv=refresh content='0;url=([^']*)'>", r.text) if r.status_code == 200 else None
    if m:
        url = html_lib.unescape(m.group(1))
        link = html_lib.unescape(re.search(r"id=oareturnlink href='([^']*)'", r.text).group(1))
        assert url == link and url.startswith("http://localhost:"), (url, link)
        assert auth.flow_cookie_name("tinysesam_oauth") in r.headers.get("set-cookie", ""), "flow cookie deleted"
        return "code", parse_qs(urlsplit(url).query)
    return "page", r


def armed_row(uid):
    return auth.store.oauth_armed_consent_pairing(uid, int(time.time()))


def audit(event=None):
    rows = auth.store.recent_audit(1000)
    return [r for r in rows if event is None or r["event"] == event]


def exchange(code, verifier, cid, **over):
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": CB, "code_verifier": verifier,
            "client_id": cid}
    form.update(over)
    return client().post("/auth/oauth/token", data={k: v for k, v in form.items() if v is not None})


# ================================================================ issuing: only the account itself, fresh
anon = client()
anon.get("/auth/login")
assert create(anon).status_code == 401
key = auth.create_api_key(alice, name="k")["key"]
r = client().post("/auth/oauth/pairing", json={}, headers={"Authorization": f"Bearer {key}"})
assert r.status_code in (401, 403), r.status_code
stale = browser(alice, age=3600)
r = create(stale)
assert r.status_code == 403 and r.headers.get("x-tinysesam-reauth"), (r.status_code, r.headers)
a_c = browser(alice)
assert a_c.post("/auth/oauth/pairing", json={}).status_code == 403, "without the CSRF token"
assert a_c.post("/auth/oauth/pairing", json={},
                headers={"X-CSRF-Token": a_c.cookies.get(auth.csrf_cookie_name),
                         "Origin": "https://evil.example.net"}).status_code == 403, "a foreign origin"
r = create(a_c)
assert r.status_code == 201, r.text
out = r.json()
code = out["code"]
assert re.fullmatch(r"[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}", code), code
assert out["redeem_url"] == BASE + "/auth/oauth/pairing/redeem" and out["resource"] is None
assert out["expires_at"] - int(time.time()) in range(15 * 60 - 5, 15 * 60 + 1)
assert r.headers["cache-control"] == "no-store"
raw = auth.store._all("SELECT * FROM magic_token WHERE user_id=? AND purpose=?", (alice, Store.CONSENT_PAIRING))
assert len(raw) == 1 and raw[0]["token_hash"] == auth.store.token_digest(O.code_digest(O.normalize_code(code)), "magic")
dump = json.dumps([dict(x) for x in auth.store._all("SELECT * FROM magic_token")])
assert code not in dump and O.normalize_code(code) not in dump, "the code itself must never be stored"
assert audit("oauth_consent_pairing_issued")[0]["username"] == "alice"
ok("issuing: only the own fresh browser session with CSRF (no session 401, API key refused, stale → reauth, "
   "foreign origin 403); 80-bit code, only its digest stored, no-store")

r = create(a_c, resource="https://APP.example.com:443/mcp/")
assert r.status_code == 201 and r.json()["resource"] == RESOURCE, r.text
r = create(a_c, resource="https://unknown.example.com/mcp")
assert r.status_code == 400 and "unknown resource" in r.json()["detail"], r.text
assert len(auth.store._all("SELECT * FROM magic_token WHERE user_id=? AND used_at IS NULL AND purpose IN (?, ?)",
                           (alice, Store.CONSENT_PAIRING, Store.CONSENT_ARMED))) == 1
assert redeem(code).status_code == 400, "a newer code replaces the older one"
ok("binding to one resource (normalized), an unknown one refused; a new code replaces the older open one")

# Rate limit on issuing: 10 per account and hour.
rl_auth, rl_app = make()
rl_uid = rl_auth.create_user("rita", password="rita-pw-123456")
rl_c = TestClient(rl_app, base_url="http://testserver", follow_redirects=False)
rl_c.cookies.set(rl_auth.session_cookie_name, rl_auth.store.create_session(rl_uid, 86400, True, "password",
                                                                         factors=["password"]))
rl_c.get("/auth/account")
codes_rl = [rl_c.post("/auth/oauth/pairing", json={},
                      headers={"X-CSRF-Token": rl_c.cookies.get(rl_auth.csrf_cookie_name)}).status_code
            for _ in range(O.CONSENT_PAIRING_ISSUE_PER_HOUR + 1)]
assert codes_rl[:-1] == [201] * O.CONSENT_PAIRING_ISSUE_PER_HOUR and codes_rl[-1] == 429, codes_rl
ok(f"issuing is limited to {O.CONSENT_PAIRING_ISSUE_PER_HOUR} codes per account and hour")

# ================================================================ redeeming: no session, once, generic answer
code = create(a_c, resource=RESOURCE).json()["code"]
r = redeem(code.lower().replace("-", " "))
assert r.status_code == 200 and r.json() == {"armed": True, "expires_at": r.json()["expires_at"],
                                              "resource": RESOURCE}, r.text
assert r.headers["cache-control"] == "no-store"
assert armed_row(alice) is not None
again = redeem(code)
assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
assert again.json() == redeem("ABCD-EFGH-JKLM-NPQR").json() == redeem("nonsense").json(), \
    "used, unknown and malformed must answer alike"
assert client().post("/auth/oauth/pairing/redeem", data={"code": code}).status_code == 400, "JSON only"
assert [a["detail"] for a in audit("oauth_consent_pairing_denied")][:3] == ["reason=malformed", "reason=unknown",
                                                                            "reason=used"]
assert audit("oauth_consent_pairing_redeemed")[0]["username"] == "alice"
everything = json.dumps([dict(x) for x in auth.store.recent_audit(1000)]) + seclog.getvalue()
assert O.normalize_code(code) not in everything.upper().replace("-", ""), "the code must never be logged"
ok("redeem: without a session, case/blank tolerant, once; used/unknown/malformed answer the same; reasons only "
   "in the audit log; the code never in a log")

# A redeemed or unknown kind of code: a service pairing code (T-60) is never taken here and stays usable.
svc_hash = auth.store.token_digest(O.code_digest("ABCDEFGHJKLMNPQR"), "magic")
auth.store.add_magic_token(svc_hash, "oauth_pairing", int(time.time()) + 600, bob, None, {"resources": [RESOURCE]})
assert redeem("ABCD-EFGH-JKLM-NPQR").status_code == 400
row = auth.store.get_magic_token(svc_hash)
assert row["purpose"] == "oauth_pairing" and row["used_at"] is None
assert audit("oauth_consent_pairing_denied")[0]["detail"] == "reason=kind"
ok("a service pairing code is refused and left untouched (purpose is part of the rule)")

# Expired.
code_x = create(browser(bob)).json()["code"]
auth.store._exec("UPDATE magic_token SET expires_at=? WHERE token_hash=?",
                 (int(time.time()) - 1, auth.store.token_digest(O.code_digest(O.normalize_code(code_x)), "magic")))
assert redeem(code_x).status_code == 400 and audit("oauth_consent_pairing_denied")[0]["detail"] == "reason=expired"
assert armed_row(bob) is None
ok("an expired code is refused")

# ================================================================ the consent given in advance: exactly once
cid = register(a_c)
v1, ch1 = pkce()
loc = authorize(a_c, cid, ch1)
kind, q = consent_get(a_c, loc)
assert kind == "code", (kind, getattr(q, "text", q)[:200] if kind == "page" else q)
assert q["state"] == ["st-1"] and q["iss"] == [BASE] and q["code"][0].startswith("tsac_")
assert armed_row(alice) is None, "the consent must be spent"
r = exchange(q["code"][0], v1, cid)
assert r.status_code == 200 and r.json()["access_token"].startswith("tsat_") and "refresh_token" in r.json(), r.text
tok1 = r.json()["access_token"]
line = audit("oauth_consent")[0]["detail"]
assert "decision=allow" in line and "via=pairing" in line and "fetch_site=none" in line, line
assert "fetch_site=none" in audit("oauth_authorize")[0]["detail"]
ev = [e for e in events if e[0] == "oauth_device_connected"][-1]
assert ev[1] == "alice" and ev[2]["via"] == "pairing", ev
devs = auth._oauth.devices(alice)
assert len(devs) == 1 and devs[0]["via"] == "pairing" and devs[0]["client_id"] == cid
assert auth.store.oauth_grant(devs[0]["id"])["consent_via"] == "pairing"
acc_page = a_c.get("/auth/account").text
assert "via pairing code" in acc_page and cid in acc_page
ok("redeemed → the next authorization (prompt=consent, mcp offline_access) goes straight to the program; audit "
   "via=pairing fetch_site=none, security event and device list say „via pairing code“")

v2, ch2 = pkce()
kind, page = consent_get(a_c, authorize(a_c, cid, ch2))
assert kind == "page" and page.status_code == 200 and 'id=oaallow' in page.text
ok("the second authorization shows the consent page again (logout/expiry/new login)")

# Freshly registered program after the first: the page, too (one consent = one program).
cid_b = register(a_c, name="Claude Code 2")
kind, page = consent_get(a_c, authorize(a_c, cid_b, pkce()[1]))
assert kind == "page"
ok("one pairing code allows exactly one authorization — another client afterwards sees the page")

# Revoke under „Connected programs“ ends it at once.
fwd = client().get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com",
                                            "X-Forwarded-Uri": "/mcp", "Authorization": f"Bearer {tok1}"})
assert fwd.status_code == 200
csrf = re.search(r"name=_csrf value='([^']*)'", acc_page).group(1)
r = a_c.post(f"/auth/oauth/devices/{devs[0]['id']}/revoke", data={"_csrf": csrf})
assert r.status_code == 303
fwd = client().get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com",
                                            "X-Forwarded-Uri": "/mcp", "Authorization": f"Bearer {tok1}"})
assert fwd.status_code == 401 and auth._oauth.devices(alice) == []
ok("„Disconnect“ on the account page revokes a program connected by pairing code at once")


# ================================================================ what does NOT spend it (and shows the page)
def arm(c, **body):
    code_ = create(c, **body).json()["code"]
    assert redeem(code_).status_code == 200
    return code_


def stays_armed(uid, what):
    assert armed_row(uid) is not None, f"{what} spent the consent"


a_c = browser(alice)
arm(a_c, resource=RESOURCE)
cid2 = register(a_c)

for label, hdr in (("cross-site", {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}),
                   ("same-site", {"Sec-Fetch-Site": "same-site"}), ("same-origin", {"Sec-Fetch-Site": "same-origin"}),
                   ("missing", None)):
    kind, page = consent_get(a_c, authorize(a_c, cid2, pkce()[1], headers=hdr))
    assert kind == "page" and page.status_code == 200, label
    stays_armed(alice, f"Sec-Fetch-Site {label}")
assert "reason=fetch_site" in audit("oauth_consent_pairing_unused")[0]["detail"]
ok("a website's navigation (cross-site), same-site, same-origin or no Sec-Fetch-Site → the page, nothing spent")

kind, page = consent_get(a_c, authorize(a_c, cid2, pkce()[1], resource=RESOURCE2))
assert kind == "page"
stays_armed(alice, "another resource")
assert "reason=resource" in audit("oauth_consent_pairing_unused")[0]["detail"]
ok("another resource than the code's → the page, nothing spent")

# A client with a redirect URI that leaves the computer (none can register so today: written directly).
auth.store.oauth_add_client("tsc_webclient", "Web client", ["https://app.example.com/cb"], int(time.time()), None)
kind, page = consent_get(a_c, authorize(a_c, "tsc_webclient", pkce()[1], redirect_uri="https://app.example.com/cb"))
assert kind == "page"
stays_armed(alice, "a non-loopback redirect")
assert "reason=redirect" in audit("oauth_consent_pairing_unused")[0]["detail"]
ok("a non-loopback redirect URI → the page, nothing spent (loopback only)")

# A service's client never starts an authorization (`check_authorize`); the pairing rule refuses it on its own as well.
auth.store._exec("INSERT INTO oauth_service_client(client_id, user_id, resources) VALUES (?, ?, ?)",
                 ("tsc_webclient", alice, json.dumps([RESOURCE])))
_req = {"params": {"fetch_site": "none", "redirect_uri": CB, "resource": RESOURCE},
        "client": {"client_id": "tsc_webclient"}}
assert auth._oauth.pairing_mismatch(_req, armed_row(alice)) == "client"
_req["client"] = {"client_id": cid2}
assert auth._oauth.pairing_mismatch(_req, armed_row(alice)) == ""
auth.store._exec("DELETE FROM oauth_service_client WHERE client_id='tsc_webclient'")
ok("a service's client is never covered by a pairing (rule of its own, behind check_authorize)")

b_c = browser(bob)
kind, page = consent_get(b_c, authorize(b_c, register(b_c), pkce()[1]))
assert kind == "page" and "bob" in page.text
stays_armed(alice, "another account's session")
ok("another account signed in in the browser → its own page; the code's account keeps its consent")

no_session = client()
loc = authorize(no_session, cid2, pkce()[1])
r = no_session.get(loc)
assert r.status_code == 303 and "/auth/login?next=" in r.headers["location"]
stays_armed(alice, "a request without a session")
stale = browser(alice, age=3600)
loc = authorize(stale, cid2, pkce()[1])
r = stale.get(loc)
assert r.status_code == 303 and "/auth/reauth?next=" in r.headers["location"], r.headers.get("location")
stays_armed(alice, "a stale session")
auth.store._exec("UPDATE session SET mfa_at=? WHERE user_id=?", (int(time.time()), alice))
kind, q = consent_get(stale, loc)
assert kind == "code", "after the confirmation the same request uses the consent"
ok("no session → sign-in, stale → reauth, neither spends it; after the confirmation the same request goes through")

# prompt=none: TinySesam never answers silently without a consent — with or without a pairing.
kind, page = consent_get(a_c, authorize(a_c, cid2, pkce()[1], prompt="none"))
assert kind == "page"
arm(a_c)
kind, page = consent_get(a_c, authorize(a_c, cid2, pkce()[1], prompt="none",
                                        headers={"Sec-Fetch-Site": "cross-site"}))
assert kind == "page"
stays_armed(alice, "prompt=none from a website")
ok("prompt=none: no silent code without a pairing; from a website the pairing is not spent either")

# Expired while armed.
auth.store._exec("UPDATE magic_token SET expires_at=? WHERE user_id=? AND purpose=?",
                 (int(time.time()) - 1, alice, Store.CONSENT_ARMED))
kind, page = consent_get(a_c, authorize(a_c, cid2, pkce()[1]))
assert kind == "page"
ok("an armed consent past its window → the page")

# Lock / password change: the open pairing goes with the account's other one-time tokens.
arm(a_c)
auth.store.revoke_user_magic_tokens(alice)
assert armed_row(alice) is None
ok("ending the account's open links (lock, reset, password change) ends an armed pairing too")

# ================================================================ attacks
# A-1 guessing: the address is throttled long before 80 bits fall.
g_auth, g_app = make()
gc_ = TestClient(g_app, base_url="http://testserver", follow_redirects=False)
answers = [gc_.post("/auth/oauth/pairing/redeem", json={"code": f"ABCD-EFGH-JKLM-{i:04d}".replace("0", "2")
                                                                .replace("1", "3")}).status_code
           for i in range(O.CONSENT_PAIRING_REDEEM_PER_IP_HOUR + 2)]
assert answers[:O.CONSENT_PAIRING_REDEEM_PER_IP_HOUR] == [400] * O.CONSENT_PAIRING_REDEEM_PER_IP_HOUR, answers
assert answers[-1] == 429
u_g = g_auth.create_user("gina", password="gina-pw-123456")
g_auth.store.oauth_replace_consent_pairing(g_auth.store.token_digest(O.code_digest("WXYZWXYZWXYZWXYZ"), "magic"), u_g, int(time.time()),
                                           int(time.time()) + 600, {"resource": None})
assert gc_.post("/auth/oauth/pairing/redeem", json={"code": "WXYZ-WXYZ-WXYZ-WXYZ"}).status_code == 429
assert "oauth_consent_redeem_ratelimit" in seclog.getvalue() and "oauth_consent_redeem_unknown" in seclog.getvalue()
ok(f"A-1 guessing: {O.CONSENT_PAIRING_REDEEM_PER_IP_HOUR} tries per address and hour, then 429 even for the right "
   "code; every failure is a security-log line for fail2ban")

# A-2 the same code redeemed at once from many places: exactly one arms it.
code_r = create(a_c).json()["code"]


def _race(_):
    return TestClient(app, base_url="http://testserver").post("/auth/oauth/pairing/redeem",
                                                               json={"code": code_r},
                                                               headers={"X-Forwarded-For": "203.0.113.9"}).status_code


with concurrent.futures.ThreadPoolExecutor(8) as ex:
    results = list(ex.map(_race, range(8)))
assert sorted(results) == [200] + [400] * 7, results
ok("A-2 double redemption in parallel: exactly one wins (atomic UPDATE)")

# A-3 the armed consent spent by two authorizations at once: exactly one gets the code.
_armed_hash = armed_row(alice)["token_hash"]
spent = [auth.store.oauth_use_consent_pairing(_armed_hash, int(time.time())) for _ in range(2)]
assert spent == [True, False]
arm(a_c)
locs = [authorize(a_c, cid2, pkce()[1]) for _ in range(2)]
kinds = [consent_get(a_c, x)[0] for x in locs]
assert sorted(kinds) == ["code", "page"], kinds
ok("A-3 two authorizations racing for one consent: one code, one page")

# A-4 a website in the window: it starts an authorization through the victim's browser (cross-site) — the consent
# is neither used nor spent, and the real program right after still goes through.
arm(a_c)
evil = authorize(a_c, register(client(), name="Totally Claude"), pkce()[1],
                 headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Referer": "https://evil.example.net/"})
assert consent_get(a_c, evil)[0] == "page"
stays_armed(alice, "a website")
v_ok, ch_ok = pkce()
kind, q = consent_get(a_c, authorize(a_c, cid2, ch_ok))
assert kind == "code"
ok("A-4 a website in the window cannot use or spend the consent; the person's program still goes through")

# A-5 a code from another account: redeeming bob's code arms only bob; alice's browser sees the page.
code_b = create(browser(bob)).json()["code"]
assert redeem(code_b).status_code == 200
assert armed_row(alice) is None and armed_row(bob) is not None
assert consent_get(a_c, authorize(a_c, cid2, pkce()[1]))[0] == "page"
stays_armed(bob, "another account's authorization")
ok("A-5 a code arms only the account that fetched it; another account's browser gets the page")

# A-6 the token exchange is unchanged: PKCE is required for a code that came through a pairing.
arm(a_c)
v6, ch6 = pkce()
kind, q6 = consent_get(a_c, authorize(a_c, cid2, ch6))
assert kind == "code"
r = exchange(q6["code"][0], None, cid2)
assert r.status_code == 400 and r.json()["error"] == "invalid_grant"
r = exchange(q6["code"][0], v6, cid2)
assert r.status_code == 400 and r.json()["error"] == "invalid_grant", "a failed exchange consumes the code"
arm(a_c)
v7, ch7 = pkce()
kind, q7 = consent_get(a_c, authorize(a_c, cid2, ch7))
assert exchange(q7["code"][0], pkce()[0], cid2).status_code == 400
arm(a_c)
r = a_c.get("/auth/oauth/authorize", params={"response_type": "code", "client_id": cid2, "redirect_uri": CB,
                                              "code_challenge": ch7, "code_challenge_method": "plain",
                                              "resource": RESOURCE}, headers=NONE)
assert r.status_code == 303 and "error=invalid_request" in r.headers["location"]
stays_armed(alice, "a request without S256")
ok("A-6 token exchange unchanged: no verifier, a wrong one or plain PKCE fail; the consent is not spent by an "
   "invalid request")

# ================================================================ switch off: everything 404, nothing skipped
off_auth, off_app = make(oauth_pairing_consent_enabled=False)
oc = TestClient(off_app, base_url="http://testserver", follow_redirects=False)
u_off = off_auth.create_user("otto", password="otto-pw-123456")
oc.cookies.set(off_auth.session_cookie_name, off_auth.store.create_session(u_off, 86400, True, "password",
                                                                         factors=["password"]))
oc.get("/auth/account")
assert oc.post("/auth/oauth/pairing", json={},
               headers={"X-CSRF-Token": oc.cookies.get(off_auth.csrf_cookie_name)}).status_code == 404
assert oc.post("/auth/oauth/pairing/redeem", json={"code": "ABCD-EFGH-JKLM-NPQR"}).status_code == 404
off_auth.store.oauth_replace_consent_pairing(off_auth.store.token_digest(O.code_digest("ABCDEFGHJKLMNPQR"), "magic"), u_off, int(time.time()),
                                             int(time.time()) + 600, {"resource": None})
assert off_auth.store.oauth_arm_consent_pairing(off_auth.store.token_digest(O.code_digest("ABCDEFGHJKLMNPQR"), "magic"), int(time.time()))
r = oc.post("/auth/oauth/register", json={"client_name": "x", "redirect_uris": [CB], "token_endpoint_auth_method": "none"})
r = oc.get("/auth/oauth/authorize", params={"response_type": "code", "client_id": r.json()["client_id"],
                                           "redirect_uri": CB, "code_challenge": pkce()[1],
                                           "code_challenge_method": "S256", "resource": RESOURCE}, headers=NONE)
page = oc.get(r.headers["location"])
assert page.status_code == 200 and "id=oaallow" in page.text
assert "Connect a program" not in oc.get("/auth/account").text
ok("switch off: both routes 404, the account page offers nothing, an armed row (older data) skips nothing")

# ================================================================ configuration
for bad in (dict(oauth_pairing_consent_enabled=True, oauth_enabled=False), dict(oauth_pairing_consent_minutes=0),
            dict(oauth_pairing_consent_minutes=61)):
    try:
        make(**bad)
    except ConfigError as e:
        assert "oauth_pairing_consent" in str(e), e
    else:
        raise AssertionError(f"accepted: {bad}")
assert TinySesamConfig().oauth_pairing_consent_enabled is False and TinySesamConfig().oauth_pairing_consent_minutes == 15
ok("config_check: switch without oauth_enabled, window outside 1–60 minutes refused; default off, 15 minutes")

# ================================================================ consent page for laypeople
p_c = browser(bob)
loc = authorize(p_c, register(p_c), pkce()[1], headers=None)
page = p_c.get(loc)
html = page.text
assert page.status_code == 200 and "Allow access?" in html
assert re.search(r"<p class=oalead id=oalead><bdi>Claude Code</bdi> wants to work in <bdi>Doc Hub</bdi> as "
                 r"<bdi>bob</bdi>\.</p>", html), html[html.find("oalead") - 20:html.find("oalead") + 200]
assert html.index("id=oaallow") < html.index("<details id=oadetails>") < html.index("id=oaclient")
assert "not verified" in html and "localhost:43123" in html and "mcp offline_access" in html
assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
assert " style=" not in html and "onclick" not in html
de_auth, de_app = make(lang="de")
de_c = TestClient(de_app, base_url="http://testserver", follow_redirects=False)
u_de = de_auth.create_user("dora", password="dora-pw-123456")
de_c.cookies.set(de_auth.session_cookie_name, de_auth.store.create_session(u_de, 86400, True, "password",
                                                                         factors=["password"]))
r = de_c.post("/auth/oauth/register", json={"client_name": "Claude Code", "redirect_uris": [CB],
                                            "token_endpoint_auth_method": "none"})
loc = authorize(de_c, r.json()["client_id"], pkce()[1], headers=None)
html_de = de_c.get(loc).text
assert "Zugriff erlauben?" in html_de and "möchte als <bdi>dora</bdi> in <bdi>Doc Hub</bdi> arbeiten" in html_de
assert ">Erlauben<" in html_de and "<summary>Details</summary>" in html_de and "Programm verbinden" in de_c.get(
    "/auth/account").text
ok("consent page: one sentence with the app's name, a large „Allow“ before the folded details; en/de; strict CSP")

logging.getLogger("tinysesam.security").removeHandler(_handler)
print("test_oauth_pairing: all green")

"""Re-enacted attacks from the maturity review of 2026-09-21 (and the rounds after it).

Every check here records an attack that once worked. They are deliberately named after the
ATTACK, not after the function — whoever sees one of them red should immediately know what is
possible again.

Everything runs on default values. A finding that only occurs under a configuration nobody
chooses would not have been one.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, StateError, TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Security — follow-up attacks")


def _app(**cfg):
    """An instance on default values, only with its own database path."""
    tmp = tempfile.mkdtemp()
    reason = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False)
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── Role escalation via self-issued API keys ───────────────────────────────────
# Attack: A signed-in user without any role calls POST /auth/apikeys with
# {"roles": ["buchhaltung"]} and gets a key that carries exactly this role.
# The scope overwrote the account roles instead of intersecting them.
auth, app = _app()
auth.create_user("employee", password="Secret12345!abc")
user = auth.store.get_user_by_name("employee")


@app.get("/only-accounting")
def _protected(u=Depends(auth.require_role("accounting"))):
    return {"seen_from": u["username"]}


r.check("Starting point: the account has no roles", auth.user_roles(user) == [])

# Since the second audit the attempt is rejected already at ISSUING, not only at checking.
# Reason: a scope shrunk to `[]` meant "no scope, inherits everything" in the database — so the
# trimming would have made the key more powerful instead of weaker. An error is the only honest
# answer here; only the caller knows what was meant.
try:
    auth.create_api_key(user["id"], name="probe", roles=["accounting"])
    rejected = None
except ConfigError as e:
    rejected = e
r.check("a key with a role the owner does not have is not created in the first place",
        rejected is not None,
        "the key was issued — and an empty scope inherits ALL roles in the database")
r.check("and the message names the requested role", "accounting" in str(rejected or ""),
        f"{str(rejected)[:80]!r}")

# The key must not come into being via the HTTP route either — that is where the request comes from.
with TestClient(app) as c:
    c.cookies.set(auth.cfg.session_cookie,
                  auth.store.create_session(user["id"], 3600, True, "password"))
    over_http = c.post("/auth/apikeys", json={"name": "probe", "roles": ["accounting"]})
r.check("it is not created via POST /auth/apikeys either", over_http.status_code >= 400,
        f"HTTP {over_http.status_code} — the way the attack ran")

# Counter-check: whoever really has the role also gets it in the key — otherwise the fix would be
# a brake on functionality instead of a safeguard.
auth.set_roles(user["id"], ["accounting"]) if hasattr(auth, "set_roles") else None
user2 = auth.store.get_user_by_name("employee")
if auth.user_roles(user2) == ["accounting"]:
    key2 = auth.create_api_key(user2["id"], name="real", roles=["accounting"])
    r.check("whoever has the role keeps it in the key", key2.get("roles") == ["accounting"])
    with TestClient(app) as c:
        a2 = c.get("/only-accounting", headers={"Authorization": f"Bearer {key2['key']}"})
    r.check("and gets through with it", a2.status_code == 200, f"HTTP {a2.status_code}")

# ── OIDC: the flow must be bound to the browser ───────────────────────────────
# Attack: The attacker starts the flow on their side, signs in at the IdP as themselves and
# lures the victim to the callback URL. The victim silently lands in the attacker's account. An
# ordinary top-level GET suffices — SameSite does not help, because no cookie is needed at all.
# What is tested is the binding itself; a real IdP is not needed for that.
auth_o, app_o = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                     oidc_client_id="probe", oidc_client_secret="secret",
                     base_url="http://testserver")
# Pre-fill the metadata so that no network is needed: what is tested is the browser binding,
# not the discovery. Otherwise `meta()` fetches the well-known URL on the first call.
auth_o.oidc._meta = {
    "issuer": "https://idp.example.invalid",
    "authorization_endpoint": "https://idp.example.invalid/authorize",
    "token_endpoint": "https://idp.example.invalid/token",
    "userinfo_endpoint": "https://idp.example.invalid/userinfo",
    "jwks_uri": "https://idp.example.invalid/jwks",
}

with TestClient(app_o) as c:
    start = c.get("/auth/oidc/start", follow_redirects=False)
r.check("the start sets a flow cookie", "tinysesam_oidc_flow" in start.headers.get("set-cookie", ""),
        f"none set: {start.headers.get('set-cookie', '—')[:60]}")
r.check("and it is httponly (no access from JavaScript)",
        "httponly" in start.headers.get("set-cookie", "").lower())

# Read the state from the redirect — exactly what an attacker can do.
from urllib.parse import parse_qs, urlparse  # noqa: E402
state = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
r.check("the state is in the redirect as expected", bool(state))

# Callback from a FOREIGN browser (own cookie jar, without the flow cookie).
with TestClient(app_o) as foreign:
    response = foreign.get(f"/auth/oidc/callback?code=whatever&state={state}", follow_redirects=False)
r.check("a callback without a matching flow cookie is rejected",
        response.status_code == 400,
        f"HTTP {response.status_code} — the account substitution is back")

# The same substitution via cookie tossing (A-1): a neighbouring subdomain can set a cookie
# `Domain=.example.com` — but none with `__Host-`. So the flow cookie must carry the
# prefix, otherwise it plants the attacker's flow, value included, on the victim, and the
# victim lands in the attacker's account despite the prefixed session cookie.
auth_s, app_s = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                     oidc_client_id="probe", oidc_client_secret="secret", cookie_secure=True,
                     base_url="https://auth.example.com")
auth_s.oidc._meta = dict(auth_o.oidc._meta)
with TestClient(app_s, base_url="https://auth.example.com") as attacker:
    start = attacker.get("/auth/oidc/start", follow_redirects=False)
    flow_value = attacker.cookies.get("__Host-tinysesam_oidc_flow")
r.check("with Secure the flow cookie is called __Host-tinysesam_oidc_flow", bool(flow_value),
        f"set: {start.headers.get('set-cookie', '—')[:60]}")
state_s = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
with TestClient(app_s, base_url="https://auth.example.com") as victim_b:
    victim_b.cookies.set("tinysesam_oidc_flow", flow_value or "")   # what a neighbouring subdomain can set
    response = victim_b.get(f"/auth/oidc/callback?code=whatever&state={state_s}", follow_redirects=False)
r.check("an unprefixed (planted) flow cookie does not bind the callback",
        response.status_code == 400 and auth_s.t("api.oidc_browser") in response.text,
        f"HTTP {response.status_code} {response.text[:80]} — login CSRF via cookie tossing")
# Counter-check: with the real, prefixed cookie the callback gets past the binding
# (and only fails at the exchange with the dummy-less IdP) — otherwise the case above tested nothing.
with TestClient(app_s, base_url="https://auth.example.com") as itself:
    start = itself.get("/auth/oidc/start", follow_redirects=False)
    state_s = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
    try:
        response = itself.get(f"/auth/oidc/callback?code=whatever&state={state_s}", follow_redirects=False)
        text = response.text
    except Exception as e:      # the exchange with idp.example.invalid may raise
        text = repr(e)
r.check("…the prefixed cookie of the own browser still binds it",
        auth_s.t("api.oidc_browser") not in text, text[:80])
r.check("SAML and passkey flow cookies carry the prefix as well",
        auth_s.flow_cookie_name("tinysesam_saml_flow") == "__Host-tinysesam_saml_flow"
        and auth_s.flow_cookie_name("tinysesam_waflow") == "__Host-tinysesam_waflow")

# ── Writing routes without CSRF check ─────────────────────────────────────────
# Attack: A <form method=POST> on a foreign page, without body, without preflight.
# `POST /auth/totp/disable` thereby deleted TOTP AND all recovery codes — without confirmation,
# without fresh factor confirmation and without an audit entry.
auth_c, app_c = _app(pin_enabled=True)
auth_c.create_user("victim", password="Secret12345!abc")
victim = auth_c.store.get_user_by_name("victim")
auth_c.totp_enable(victim["id"], auth_c.totp_new_secret()) if hasattr(auth_c, "totp_new_secret") else None

WITHOUT_CSRF = ("/auth/totp/disable", "/auth/totp/recovery", "/auth/pin/disable")
with TestClient(app_c) as c:
    c.post("/auth/login", data={"username": "victim", "password": "Secret12345!abc"},
           follow_redirects=False)
    for path in WITHOUT_CSRF:
        response = c.post(path)          # no X-CSRF-Token, no body — like a foreign form
        r.check(f"{path} requires a CSRF token", response.status_code == 403,
                f"HTTP {response.status_code} — got through without a token")

# Disabling the second factor must leave a trace. Without an entry it cannot be reconstructed
# afterwards that someone lost their second factor.
auth_c.totp_disable(victim["id"])
events = [e["event"] for e in auth_c.store.recent_audit(limit=20)]
r.check("disabling TOTP is logged", "totp_disable" in events,
        f"no entry — found: {events[:6]}")
auth_c.disable_pin(victim["id"])
r.check("disabling the PIN likewise",
        "pin_disable" in [e["event"] for e in auth_c.store.recent_audit(limit=20)])

# ── Brute-force lockout resettable by a successful first factor ───────────────
# Attack: Whoever knows the password (leak, reuse, phishing) signs in correctly once before every
# TOTP guess. The success deleted ALL failed attempts of the account — including those
# of the TOTP attempts. The lockout thus never applied to the second factor.
auth_b, _app_b = _app()
auth_b.create_user("target", password="Secret12345!abc")

# Five failed attempts at the second factor …
for _ in range(5):
    auth_b._record_login("target", "203.0.113.9", success=False, method="totp")
unclosed_before = len(auth_b.store.recent_fails("target")) if hasattr(auth_b.store, "recent_fails") else None

# … then a SUCCESSFUL password login.
auth_b._record_login("target", "203.0.113.9", success=True, method="password")

# The failed TOTP attempts must remain.
rest = auth_b.store._all(
    "SELECT method FROM login_attempt WHERE username=? COLLATE NOCASE AND success=0", ("target",))
totp_left = [z["method"] for z in rest].count("totp")
r.check("a password success does NOT clear the failed TOTP attempts", totp_left == 5,
        f"{totp_left} of 5 left — the second factor is guessable again")

# Counter-check: it does clear failed password attempts, otherwise the fix would be a brake.
for _ in range(3):
    auth_b._record_login("target2", "203.0.113.9", success=False, method="password")
auth_b._record_login("target2", "203.0.113.9", success=True, method="password")
pw_left = [z["method"] for z in auth_b.store._all(
    "SELECT method FROM login_attempt WHERE username=? COLLATE NOCASE AND success=0",
    ("target2",))].count("password")
r.check("own failed attempts are still cleared by a success", pw_left == 0,
        f"{pw_left} left — the fix brakes more than necessary")


# ── Hijacking the first admin: allowlist name + open self-registration ─────────
# `admin_identifiers` only vouches for WHICH name becomes admin — not for who gets it. With
# `allow_signup=True` the first one to guess the address registers exactly under it and is admin
# at the first login. The constructor no longer permits this combination.
def _builds(**cfg):
    """(built?, error text) — without turning the check into a failure of the suite."""
    tmp = tempfile.mkdtemp()
    reason = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False)
    reason.update(cfg)
    try:
        TinySesam(TinySesamConfig(**reason))
        return True, ""
    except ValueError as e:
        return False, str(e)


built, text = _builds(admin_identifiers=["chef"], allow_signup=True)
r.check("allowlist USERNAME + allow_signup is rejected", not built,
        "the instance builds — whoever registers as 'chef' becomes first admin")
r.check("the rejection names the affected entry", "chef" in text,
        f"message does not name it: {text[:80]!r}")

# An e-mail is not enough either as long as nobody confirms it: at registration it is
# a freely typeable field.
built, _ = _builds(admin_identifiers=["chef@example.com"], allow_signup=True,
                  signup_require_email=True, signup_verify_email=False)
r.check("allowlist E-MAIL without mandatory confirmation is rejected", not built,
        "the instance builds — the address is unconfirmed and thus freely choosable")

# Counter-checks — the guard must not take the viable setups down with it.
built, text = _builds(admin_identifiers=["chef@example.com"], allow_signup=True,
                     signup_require_email=True, signup_verify_email=True,
                     # Mandatory since the base_url rework; without it the setup would fail for
                     # a reason that has nothing to do with the first-admin guard.
                     base_url="https://auth.example.com")
r.check("confirmed e-mail + open registration stays allowed", built,
        f"too strict, the proven path is closed: {text[:120]}")

built, text = _builds(admin_identifiers=["chef"], allow_signup=False)
r.check("allowlist without self-registration stays allowed", built,
        f"too strict, the normal case is closed: {text[:120]}")


# ── Planted SAML assertion (login CSRF / unsolicited response) ─────────────────
# The ACS accepted every signed assertion. `InResponseTo` bound it to nothing: python3-saml
# only checks the field if it is there — a response without it went through. An attacker with
# a valid assertion for THEIR account could thus POST it into the victim's browser.
from tinysesam.saml_ import SAMLClient  # noqa: E402


class _Response:
    """An IdP whose assertion passes signature and conditions — only the reference changes."""

    def __init__(self, in_response_to):
        self.irt = in_response_to
        self.seen = "__never_set__"

    def process_response(self, request_id=None):
        self.seen = request_id

    def get_errors(self):
        return []

    def get_last_error_reason(self):
        return ""

    def is_authenticated(self):
        return True

    def get_last_response_in_response_to(self):
        return self.irt

    def get_nameid(self):
        return "attacker@example.com"

    def get_attributes(self):
        return {}


def _saml_execution(in_response_to, request_id):
    auth_s, _ = _app()
    client = SAMLClient(auth_s.cfg)
    idp = _Response(in_response_to)
    client._auth = lambda req, base: idp
    return client.process({}, "https://app.example.com", request_id=request_id), idp


data, _ = _saml_execution(None, "_mine-id")
r.check("assertion WITHOUT InResponseTo is rejected", data is None,
        "accepted — every signed assertion logs everybody in (login CSRF)")

data, _ = _saml_execution("_foreign-id", "_mine-id")
r.check("assertion with a FOREIGN InResponseTo is rejected", data is None,
        "accepted — the response belongs to a different sign-in attempt")

data, _ = _saml_execution("_mine-id", "")
r.check("without a requested request the ACS stays closed", data is None,
        "accepted — nothing may be redeemed without an own request")

# Counter-check: the regular path must get through, otherwise the fix is a wall.
data, idp = _saml_execution("_mine-id", "_mine-id")
r.check("the requested assertion still gets through", data is not None,
        "the regular SAML login is closed")
r.check("the request ID is also passed on to the library", idp.seen == "_mine-id",
        f"process_response saw {idp.seen!r} — the check would only run in TinySesam, not in python3-saml")


# And the anchor must be WIRED: the router stores the request ID and hands it back again.
class _FakeSAML:
    def __init__(self):
        self.seen_request_id = "__never_set__"

    def login_url(self, req, base, return_to="/"):
        return ("https://idp.example.com/sso?SAMLRequest=abc", "_authnreq-4711")

    def process(self, req, base, request_id=""):
        self.seen_request_id = request_id
        return None          # the rest of the flow does not matter here

    def metadata(self, base):
        return "<md:EntityDescriptor/>"


auth_r, app_r = _app(saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
                     saml_idp_x509cert="MIIB", base_url="https://app.example.com")
auth_r.saml = _FakeSAML()
app_r = FastAPI()
app_r.include_router(auth_r.router())
cr = TestClient(app_r)

response = cr.get("/auth/saml/login?next=/", follow_redirects=False)
cookie = response.cookies.get("tinysesam_saml_flow")
r.check("the login stores the request ID in a flow cookie", cookie == "_authnreq-4711",
        f"cookie is {cookie!r} — without storage there is nothing to compare at the ACS")
r.check("the flow cookie is httponly", "httponly" in response.headers.get("set-cookie", "").lower(),
        "readable via JavaScript")

cr.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
r.check("the ACS passes the stored request ID on to the check",
        auth_r.saml.seen_request_id == "_authnreq-4711",
        f"it saw {auth_r.saml.seen_request_id!r} — the anchor is attached to no wire")


# ── Taking over sessions: from the file or from the admin panel ────────────────
# Session tokens lay in plain text in the database, and `GET /admin/api/sessions` also handed
# them to the browser. Both together mean: whoever reads the file (it was 0644) or sees a panel
# response signs in as any user. Now only the sha256 is stored; the panel gets this handle, with
# which one can terminate but not sign in.
auth_t, app_t = _app()
auth_t.create_user("victim", password="dummy12345")
victim_id = auth_t.store.get_user_by_name("victim")["id"]
# `create_session` returns what goes into the cookie — exactly the value in question.
cookie_value = auth_t.store.create_session(victim_id, 3600, True, "password")

stored = [z["token_hash"] for z in auth_t.store._all("SELECT token_hash FROM session")]
# Compute the sha256 ourselves: a test that asks `store.session_hash()` measures against the same
# function it is checking — and would stay green if that mutated to the identity.
expected = hashlib.sha256(cookie_value.encode()).hexdigest()
r.check("no plain-text token is in the database", stored == [expected],
        f"stored: {stored[:1]} — the sha256 of the cookie was expected")
r.check("the cookie is NOT the stored value",
        bool(cookie_value) and cookie_value not in stored,
        "whoever reads the file has the sign-in token")

# The handle must not be usable as a cookie.
handle = stored[0]
r.check("the handle is no good as a session cookie",
        auth_t.store.get_session(handle) is None,
        "the stored value signs in — then the hashing is ineffective")
r.check("the real cookie still signs in",
        auth_t.store.get_session(cookie_value) is not None,
        "the session cannot be found at all — then the test measures nothing")

# And the panel hands out exactly this handle, not the token.
panel = [z["token_hash"] for z in auth_t.store.list_sessions()]
r.check("the admin panel only gets to see handles", panel == [handle],
        f"list_sessions returns {panel[:1]}")

# ... but it works for terminating, otherwise the panel would be broken.
auth_t.store.delete_session_by_handle(handle)
r.check("the handle still terminates the session",
        auth_t.store.get_session(cookie_value) is None,
        "the panel can no longer terminate any session")

# And a plain-text token at a handle position is an error, not a silent no-op:
# an UPDATE that hits no row would let a confirmed factor vanish silently.
try:
    auth_t.store.set_session_mfa("not-a-hash", True)
    silent = True
except ValueError:
    silent = False
r.check("a plain-text token at a handle position is noticed", not silent,
        "runs into nothing — the session would silently keep its old state")


# The switchover must not throw anybody out: the hash is computable from the plain text, so existing
# rows can be migrated. Rebuild a database in the old format and open it.
import sqlite3 as _sq  # noqa: E402

from tinysesam.store import Store  # noqa: E402

old_path = str(Path(tempfile.mkdtemp()) / "alt.db")
auth_old, _ = _app(db_path=old_path)
auth_old.create_user("existing", password="dummy12345")
old_token = auth_old.store.create_session(
    auth_old.store.get_user_by_name("existing")["id"], 3600, True, "password")
old_handle = hashlib.sha256(old_token.encode()).hexdigest()
auth_old.store.db.close()

# back to the format before 0.18.0: the column is called `token` and holds the plain text
raw = _sq.connect(old_path)
raw.execute("ALTER TABLE session RENAME COLUMN token_hash TO token")
raw.execute("UPDATE session SET token=?", (old_token,))
raw.commit()
raw.close()

new_store = Store(old_path)
columns = {z[1] for z in new_store.db.execute("PRAGMA table_info(session)")}
r.check("the old column `token` is migrated to `token_hash`",
        "token_hash" in columns and "token" not in columns,
        f"columns: {sorted(columns)}")
r.check("existing sign-ins survive the switchover",
        new_store.get_session(old_token) is not None,
        "the old cookie is no longer valid — an update would have logged out all users")
r.check("and the plain text is gone from the file afterwards",
        [z["token_hash"] for z in new_store._all("SELECT token_hash FROM session")] == [old_handle],
        "the plain text is still in the database")


# ── The auth database was open (0644) ─────────────────────────────────────────
# It contains password hashes, TOTP secrets and e-mail addresses. On a shared host every other
# account could read it — WAL and SHM with the same data likewise.
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402

folder = tempfile.mkdtemp()
path = str(Path(folder) / "rights.db")
auth_d, _ = _app(db_path=path)
auth_d.create_user("wer", password="dummy12345")
auth_d.store.create_session(auth_d.store.get_user_by_name("wer")["id"], 3600, True, "password")


def _mode(file):
    return _stat.S_IMODE(_os.stat(file).st_mode)


unclosed = {f: oct(_mode(Path(folder) / f)) for f in sorted(_os.listdir(folder))
         if _mode(Path(folder) / f) & 0o077}
r.check("database, WAL and SHM are readable only by the own user", not unclosed,
        f"readable by others: {unclosed}")
r.check("the check saw a WAL file at all",
        any(f.endswith("-wal") for f in _os.listdir(folder)),
        f"only {_os.listdir(folder)} — then the test says nothing about WAL/SHM")

# An existing, too open database is NOT rewritten (a deliberate group share is the
# operator's decision) — but it is named loudly.
auth_d.store.db.close()
_os.chmod(path, 0o644)
buffer = io.StringIO()
check = logging.StreamHandler(buffer)
log_ts = logging.getLogger("tinysesam")
log_ts.addHandler(check)
try:
    Store(path)
finally:
    log_ts.removeHandler(check)
r.check("an existing, open database is reported", "chmod 600" in buffer.getvalue(),
        f"no warning: {buffer.getvalue()[:100]!r}")
r.check("and not changed behind one's back", _mode(path) == 0o644,
        f"changed to {oct(_mode(path))} — that overrides a deliberate share")


# ── API keys as a second door: locking out did not lock them out ──────────────
# A key hangs on no session. Whoever reset or blocked an account only closed the front door up to
# 0.18.0. (The key of a DEACTIVATED account was always worthless — `verify_api_key`
# checks the flag; this is about reset, block and the user's panic button.)
auth_k, app_k = _app(apikey_enabled=True)
uid_k = auth_k.create_user("bot-halter", password="dummy12345")


def _key_applies(auth_obj, key_name):
    # verify_api_key returns (user, roles) — a tuple is ALWAYS truthy. Only [0] counts.
    return auth_obj.verify_api_key(key_name)[0] is not None


key_name = auth_k.create_api_key(uid_k, "bot")["key"]
r.check("a fresh API key is valid", _key_applies(auth_k, key_name), "even the starting point is missing")

# Own password change deliberately leaves it in place — otherwise every routine disables the
# automations. But the state must be queryable, otherwise "deliberately" is only "unnoticed".
auth_k.set_password(uid_k, "nochgeheimer99")
r.check("the own password change lets automations run", _key_applies(auth_k, key_name),
        "the key is dead — every password routine disables the integrations")
r.check("and the number of keys that remain valid is queryable",
        auth_k.store.count_active_api_keys(uid_k) == 1,
        f"counted: {auth_k.store.count_active_api_keys(uid_k)}")

# The mass revocation invalidates, and it says how many.
count = auth_k.store.revoke_user_api_keys(uid_k)
r.check("the mass revocation names the number", count == 1, f"reported {count}")
r.check("afterwards the key is no longer valid", not _key_applies(auth_k, key_name),
        "revoked and still valid")
r.check("a second revocation does not count anything twice",
        auth_k.store.revoke_user_api_keys(uid_k) == 0,
        "counts already revoked keys again")

# Admin password reset: there the intent is locking out. CSRF is switched off for this block
# — the panel's protection has its own check further up, here it is about the keys.
auth_a, _ = _app(apikey_enabled=True, csrf_enabled=False)
uid_a = auth_a.create_user("bot-halter", password="dummy12345")
second = auth_a.create_api_key(uid_a, "bot2")["key"]
admin_a = auth_a.create_user("boss", password="dummy12345", is_admin=True)
app_a = FastAPI()
app_a.include_router(auth_a.router())          # admin panel hangs under /auth/admin via auto-mount
ca = TestClient(app_a)
ca.cookies.set(auth_a.cfg.session_cookie,
               auth_a.store.create_session(admin_a, 3600, True, "password"))

response = ca.post(f"/auth/admin/api/users/{uid_a}/password", json={"password": "ganzneu12345abc"})
r.check("the admin reset goes through at all", response.status_code == 200,
        f"HTTP {response.status_code}: {response.text[:120]}")
r.check("the admin reset invalidates the API keys of the account", not _key_applies(auth_a, second),
        "key remains valid — locking out only closed the front door")
r.check("and says how many there were", response.json().get("api_keys_revoked") == 1,
        f"response: {response.text[:120]}")

# Blocking an account: keys are dead anyway via the `disabled` flag — but they must also
# BE revoked, otherwise they revive on unblocking.
third = auth_a.create_api_key(uid_a, "bot3")["key"]
ca.post(f"/auth/admin/api/users/{uid_a}/disable", json={"disabled": True})
ca.post(f"/auth/admin/api/users/{uid_a}/disable", json={"disabled": False})
r.check("a key does not revive after blocking and unblocking", not _key_applies(auth_a, third),
        "the key is valid again — blocked and unblocked is no free pass")


# ── Admin actions without actor and without IP ────────────────────────────────
# The log recorded THAT an account was blocked — not by whom and from where. With several
# admins that is exactly the question one asks afterwards.
auth_p, _ = _app(csrf_enabled=False)
victim_p = auth_p.create_user("affected", password="dummy12345")
boss_p = auth_p.create_user("boss2", password="dummy12345", is_admin=True)
app_p = FastAPI()
app_p.include_router(auth_p.router())
cp = TestClient(app_p)
cp.cookies.set(auth_p.cfg.session_cookie,
               auth_p.store.create_session(boss_p, 3600, True, "password"))

cp.post(f"/auth/admin/api/users/{victim_p}/disable", json={"disabled": True},
        headers={"X-Forwarded-For": "203.0.113.42"})
entry = next((z for z in auth_p.store.recent_audit(50) if z["event"] == "user_disable"), None)
r.check("the blocking appears in the log at all", entry is not None,
        "no row — then the test says nothing about the rest")
r.check("and names the admin who did it",
        bool(entry) and entry["username"] == "boss2",
        f"username={entry['username'] if entry else None!r}")
r.check("and the IP it came from", bool(entry) and bool(entry["ip"]),
        f"ip={entry['ip'] if entry else None!r}")

# Not only this one route: the password reset as well.
cp.post(f"/auth/admin/api/users/{victim_p}/password", json={"password": "ganzneu12345abc"})
reset = next((z for z in auth_p.store.recent_audit(50) if z["event"] == "user_password_reset"), None)
r.check("the admin password reset also names actor and IP",
        bool(reset) and reset["username"] == "boss2" and bool(reset["ip"]),
        f"{dict(reset) if reset else None}")


# ── The guard that stops guarding after the first log rotation ─────────────────
# `logging.FileHandler` keeps the inode open. logrotate renames and creates anew — from then on
# the process writes into the RENAMED file, the fail2ban jail reads the empty new one.
import os as _os2  # noqa: E402

from tinysesam.security import attach_security_log, seclog  # noqa: E402

log_folder = tempfile.mkdtemp()
log_file = str(Path(log_folder) / "security.log")
attach_security_log(log_file)
seclog.warning("failed login user=before ip=203.0.113.1 method=password")
_os2.rename(log_file, log_file + ".1")          # exactly what logrotate does
open(log_file, "w").close()
seclog.warning("failed login user=after ip=203.0.113.2 method=password")

r.check("after a log rotation the next line lands in the NEW file",
        "after" in Path(log_file).read_text(encoding="utf-8"),
        "it is in the renamed file — from now on the jail reads into the void")
r.check("and no longer in the rotated one",
        "after" not in Path(log_file + ".1").read_text(encoding="utf-8"),
        "the old inode keeps receiving lines")


# ── The app lockout blinded fail2ban ─────────────────────────────────────────
# As long as it was locked, nobody called `record_login()` any more: the app answered 429 and wrote
# no line. The log fell silent exactly when the IP should have been banned.
auth_l, _ = _app()
auth_l.create_user("target3", password="dummy12345")
for _ in range(10):
    auth_l._record_login("target3", "203.0.113.77", success=False, method="password")

buffer_l = io.StringIO()
check_l = logging.StreamHandler(buffer_l)
seclog.addHandler(check_l)
try:
    locked = auth_l._is_locked("target3", "203.0.113.77")
finally:
    seclog.removeHandler(check_l)
line_l = buffer_l.getvalue()

r.check("the account is locked at all", locked, "no lockout — then the test measures nothing")
r.check("the rejection writes a line to the security log", "failed login" in line_l,
        f"log is silent: {line_l[:80]!r} — fail2ban sees no reason to ban")
r.check("and names the reason", "reason=lockout" in line_l, f"without reason: {line_l[:100]!r}")
r.check("the line matches the shipped fail2ban filter",
        bool(re.search(r"failed login user=.* ip=(\S+) method=.*", line_l)),
        f"filter does not match: {line_l[:100]!r}")

# The rate limit must not reject silently either.
buffer_r = io.StringIO()
check_r = logging.StreamHandler(buffer_r)
seclog.addHandler(check_r)
try:
    for _ in range(int(auth_l._sec("rate_limit_max")) + 2):
        auth_l._rate_ok("203.0.113.78")
finally:
    seclog.removeHandler(check_r)
r.check("a rate-limit hit is in the log as well",
        "reason=ratelimit" in buffer_r.getvalue(),
        f"silent: {buffer_r.getvalue()[:80]!r}")


# ── Behind the proxy: all users under one IP ──────────────────────────────────
# In the container the proxy is another container, i.e. not 127.0.0.1. The default does not fit
# then, X-Forwarded-For is discarded, and EVERYONE appears under the proxy IP: lockout
# and rate limit act collectively from then on. None of this looks like an error.
#
# The proxy address here is 192.0.2.x (RFC 5737, for documentation) instead of a real
# Docker bridge address: the behaviour depends solely on whether the peer is in `trusted_proxies`,
# not on the address range — and the hygiene test catches bare RFC1918 host addresses, rightly so.
# In a real compose file the network of the proxy stands there (see deploy/forward-auth/).
from tinysesam import security as _sec  # noqa: E402


class _RequestStub:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def _with_log(fn):
    """(Return value, log text) — and the marker is cleared beforehand so that the checks do
    not take the message away from each other (each warning comes only once per peer)."""
    _sec._REPORTED_PEERS.clear()
    buffer = io.StringIO()
    check = logging.StreamHandler(buffer)
    _sec.seclog.addHandler(check)
    try:
        return fn(), buffer.getvalue()
    finally:
        _sec.seclog.removeHandler(check)


real_ip, log_a = _with_log(lambda: _sec.client_ip(_RequestStub("192.0.2.5", "203.0.113.9"),
                                                  ["127.0.0.1/32"]))
r.check("with the default behind a container proxy it stays at the proxy IP",
        real_ip == "192.0.2.5", f"yielded {real_ip} — then the test measures the wrong thing")
r.check("...and this is reported instead of silently accepted",
        "trusted_proxies" in log_a and "is ignored" in log_a,
        f"no hint: {log_a[:90]!r}")

# 0.0.0.0/0 sounds generous and devalues XFF completely: if every address counts as a proxy,
# none is left as a client.
everything, log_b = _with_log(lambda: _sec.client_ip(_RequestStub("192.0.2.7", "203.0.113.9"),
                                               ["0.0.0.0/0"]))
r.check("0.0.0.0/0 does NOT yield the client IP", everything == "192.0.2.7",
        f"yielded {everything} — then XFF would be forgeable")
r.check("...and this is reported too", "devalues XFF" in log_b,
        f"no hint: {log_b[:90]!r}")

# Configured correctly the real address comes through — and then there is nothing to report.
correct, log_c = _with_log(lambda: _sec.client_ip(_RequestStub("192.0.2.5", "203.0.113.9"),
                                                 ["192.0.2.0/24"]))
r.check("with the network of the proxy the real client IP arrives", correct == "203.0.113.9",
        f"yielded {correct}")
r.check("and normal operation stays silent", log_c.strip() == "",
        f"warns without cause: {log_c[:90]!r}")

# The message comes once per peer, not per request — otherwise it floods the log.
_sec._REPORTED_PEERS.clear()
buffer_w = io.StringIO()
check_w = logging.StreamHandler(buffer_w)
_sec.seclog.addHandler(check_w)
try:
    for _ in range(5):
        _sec.client_ip(_RequestStub("192.0.2.9", "203.0.113.9"), ["127.0.0.1/32"])
finally:
    _sec.seclog.removeHandler(check_w)
# MESSAGES are counted, not words: the message itself names `trusted_proxies` twice
# (once as finding, once in the advice), so a word counter would always stand at 2.
_lines = [z for z in buffer_w.getvalue().splitlines() if "X-Forwarded-For" in z]
r.check("the warning comes once per peer, not at every request", len(_lines) == 1,
        f"{len(_lines)} messages for 5 requests")

# SSO and passkey login wrote the raw peer IP into the session and into the log.
for module in ("oidc.py", "webauthn_.py"):
    source = (Path(__file__).resolve().parent.parent / "tinysesam" / module).read_text(encoding="utf-8")
    code = "\n".join(z for z in source.splitlines() if not z.lstrip().startswith("#"))
    r.check(f"{module} uses client_ip, not the raw peer IP",
            "request.client.host" not in code and "client_ip(request)" in code,
            "accesses request.client directly again — behind a proxy that is the proxy")

# And the shipped compose file must not pretend what has just been refuted here.
compose = (Path(__file__).resolve().parent.parent / "deploy" / "forward-auth"
           / "docker-compose.yml").read_text(encoding="utf-8")
r.check("the compose example does not set trusted_proxies to 0.0.0.0/0",
        'TINYSESAM_TRUSTED_PROXIES: "0.0.0.0/0"' not in compose,
        "the example turns every client IP into the proxy IP")


# ── Forward-auth: the display name went raw into an HTTP header ────────────────
# With OIDC/SAML the name comes from the foreign IdP. Two things broke on it: a line break
# (header injection — h11 catches it, but with an abort, i.e. self-lockout) and a name
# beyond Latin-1 (500, entirely without an attacker).
auth_h, _ = _app(forward_auth_enabled=True)
uid_h = auth_h.create_user("intl", password="dummy12345")


def _header_value(raw):
    auth_h.store._exec("UPDATE users SET display_name=? WHERE id=?", (raw, uid_h))
    head = auth_h._forward_response_headers(auth_h.store.get_user(uid_h))
    return head["Remote-Name"]


boes = _header_value("Bose\r\nX-Remote-Groups: admin")
r.check("line breaks are removed from the header value",
        "\r" not in boes and "\n" not in boes, f"{boes!r}")

# The value must go through a REAL HTTP serializer, not only through the TestClient:
# the in-process client also lets through what would never arrive on the wire.
import h11  # noqa: E402


def _goes_out(value):
    try:
        h11.Response(status_code=200, headers=[("Remote-Name", value.encode("latin-1"))])
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


for raw, was in (("Bose\r\nX-Remote-Groups: admin", "Line break"),
                 ("Müller", "Umlaut"), ("Иван", "Cyrillic"), ("测试 Wang", "Chinese")):
    value = _header_value(raw)
    goes, error = _goes_out(value)
    r.check(f"{was} in the display name gets through the HTTP serializer", goes, error)

# And losslessly: the app reads the header as UTF-8 and has the name back.
for raw in ("Müller", "Иван", "测试 Wang", "alice"):
    back = _header_value(raw).encode("latin-1").decode("utf-8")
    r.check(f"{raw!r} arrives unchanged at the recipient", back == raw,
            f"became {back!r}")

# The encoding is UNIFORM — otherwise no app would know what it currently has.
r.check("even a Latin-1-capable name goes over the wire as UTF-8",
        _header_value("Müller").encode("latin-1") == "Müller".encode("utf-8"),
        "sometimes Latin-1, sometimes UTF-8 — the app cannot tell them apart")


# ── A security switch that never did anything ─────────────────────────────────
# `totp_required` stood in the config, in both READMEs ("enforce 2FA") and on the website —
# and was read nowhere in the code. Whoever set it believed the second factor
# enforced and did not have it.
built, text = _builds(totp_required=True)
r.check("totp_required=True is rejected instead of silently ignored", not built,
        "the instance builds — the operator keeps believing in a protection that does not exist")
r.check("and the message names the way that really applies", "login_chain" in text,
        f"without hint: {text[:90]!r}")

# The switch must not be advertised anywhere any more either. `web/` exists only in the repo, not in the
# source package — what is there gets checked, and the check says what it saw.
root = Path(__file__).resolve().parent.parent
seen = []
for file in ("README.md", "i18n/README.de.md", "web/flows.py"):
    path = root / file
    if not path.exists():
        continue
    seen.append(file)
    r.check(f"{file} no longer advertises totp_required",
            "totp_required" not in path.read_text(encoding="utf-8"),
            "the dead switch is still touted as 2FA")
r.check("both READMEs were among them",
        {"README.md", "i18n/README.de.md"} <= set(seen), f"only saw: {seen}")

# The factor chain is the advertised way — so it must work.
built, text = _builds(login_chain=["password", "totp"], login_chain_strict=True)
r.check("the recommended factor chain builds", built, f"recommended and broken: {text[:110]}")


# ── set_template accepted names that did not exist ────────────────────────────
# The docstring named 'magic_sent' and 'resource_pin' — neither ever existed — and left out
# seven real pages. A typo stayed silently without consequence: registered, never called.
auth_tpl, _ = _app()
try:
    auth_tpl.set_template("magic_sent", lambda *a, **k: "x")
    still = True
except ValueError:
    still = False
r.check("an unknown page name is noticed", not still,
        "accepted and never called — one looks for the error elsewhere")

try:
    auth_tpl.set_template("login", lambda *a, **k: "x")
    real_goes = True
except ValueError:
    real_goes = False
r.check("a real page name still works", real_goes, "the list is too narrow")

# The list in the code must match the pages that render_page really serves — otherwise it
# silently goes stale again.
source = "\n".join((root / "tinysesam" / f).read_text(encoding="utf-8")
                    for f in ("router.py", "manager.py", "admin.py"))
rendered = set(re.findall(r'render_page\(\s*"([a-z_]+)"', source))
absent = sorted(rendered - set(auth_tpl.PAGES))
r.check("every rendered page is in TinySesam.PAGES", not absent,
        f"not replaceable although it exists: {absent}")


# ── German error texts with lang="en" ──────────────────────────────────────────
# 32 HTTP responses carried fixed German text — even in an installation set to English. The UI
# was bilingual, the responses to machines and proxies were not.
auth_en, app_en = _app(lang="en")
auth_en.create_user("someone", password="dummy12345")
cen = TestClient(app_en)

# Measure real responses, do not query the translation table. That needs a signed-in
# session: without it every endpoint answers 401 "Unauthorized", and the test would look
# green without ever having seen a translated message.
def _responses(auth_obj, app_obj, user):
    client = TestClient(app_obj)
    uid = auth_obj.store.get_user_by_name(user)["id"]
    client.cookies.set(auth_obj.cfg.session_cookie,
                       auth_obj.store.create_session(uid, 3600, True, "password"))
    return [
        ("CSRF missing", client.post("/auth/apikeys", json={"name": "x"})),
        ("resource unknown", client.get("/auth/resource/gibtsnicht")),
    ]


responses = _responses(auth_en, app_en, "someone")
umlauts = "äöüßÄÖÜ"
german = [f"{was}: {a.text[:70]}" for was, a in responses
           if any(z in (a.text or "") for z in umlauts)
           or "nötig" in (a.text or "") or "ungültig" in (a.text or "")]
r.check("with lang='en' no German text comes from the endpoints", not german,
        " | ".join(german))
r.check("and the responses carry a message of their own at all",
        all(a.status_code >= 400 for _, a in responses)
        and any("Unauthorized" not in (a.text or "") for _, a in responses),
        f"Status {[a.status_code for _, a in responses]}, texts "
        f"{[(a.text or '')[:40] for _, a in responses]} — otherwise measures nothing")

# And with German, German must still come out, otherwise the translation would only be moved.
auth_de, app_de = _app(lang="de")
auth_de.create_user("someone", password="dummy12345")
german_ones = " ".join((a.text or "") for _, a in _responses(auth_de, app_de, "someone"))
r.check("with lang='de' German still comes out",
        any(z in german_ones for z in umlauts) or "nötig" in german_ones,
        f"{german_ones[:100]!r}")

# Hygiene: no raw text in an HTTPException any more — otherwise the gap grows back by itself.
raw = []
for module in ("manager.py", "router.py", "admin.py", "oidc.py", "webauthn_.py", "saml_.py"):
    source = (Path(__file__).resolve().parent.parent / "tinysesam" / module).read_text(encoding="utf-8")
    for nr, line in enumerate(source.splitlines(), 1):
        if re.search(r'HTTPException\(\s*\d+\s*,\s*[fr]?"', line):
            raw.append(f"{module}:{nr}")
r.check("no HTTPException with fixed text any more", not raw, ", ".join(raw[:5]))


# ── Recovery codes carried 48 bits ────────────────────────────────────────────
# A recovery code REPLACES the second factor and is valid until used. A TOTP code has only
# a million possibilities, but is worthless after 30 seconds — the comparison does not hold.
auth_rc, _ = _app()
uid_rc = auth_rc.create_user("rc", password="dummy12345")
codes = auth_rc.generate_recovery_codes(uid_rc)
hex_chars = sum(1 for z in codes[0] if z in "0123456789abcdef")
r.check("a recovery code carries at least 64 bits", hex_chars * 4 >= 64,
        f"{codes[0]} = {hex_chars * 4} bits")
r.check("the codes differ from one another", len(set(codes)) == len(codes),
        f"{len(codes)} codes, {len(set(codes))} distinct")
r.check("and a freshly generated code satisfies the second factor",
        auth_rc._verify_recovery_code(uid_rc, codes[0]),
        "the code is not accepted — then the test only measures characters")
r.check("a code is valid exactly once", not auth_rc._verify_recovery_code(uid_rc, codes[0]),
        "the same code works a second time")


# ── There were no error types one can react to ────────────────────────────────
# What was raised was `ValueError` (configuration) and `RuntimeError` (missing extra). Whoever
# wanted to distinguish at startup whether the configuration is wrong or a package is missing had to
# read the message text — and that is translated since this version.
from tinysesam import ConfigError, MissingExtra, TinySesamError  # noqa: E402

try:
    _app(totp_required=True)
    kind = None
except Exception as e:
    kind = e
r.check("a configuration error is a ConfigError", isinstance(kind, ConfigError),
        f"{type(kind).__name__}")
r.check("...and still a ValueError (existing code catches it)",
        isinstance(kind, ValueError), "existing `except ValueError` breaks")
r.check("...and a TinySesamError", isinstance(kind, TinySesamError), f"{type(kind).__mro__}")

# The extra guard, two-stage. It may only raise where it can never be wrong: a client is
# replaceable (`auth.ldap = own_client`, four own suites work that way), so the setup does
# NOT abort — it warns. It raises at the lazy import, i.e. on the first real use.
import importlib  # noqa: E402


class _Blocked:
    """An import finder that deliberately "does not find" exactly one module."""

    def __init__(self, name):
        self.name = name

    def find_spec(self, fullname, path=None, destination=None):
        if fullname == self.name or fullname.startswith(self.name + "."):
            raise ModuleNotFoundError(f"No module named '{fullname}'", name=fullname)
        return None


def _without_module(name, fn):
    """Run `fn()` as if `name` were not installed."""
    blocker = _Blocked(name)
    sys.meta_path.insert(0, blocker)
    away = {n: m for n, m in list(sys.modules.items()) if n == name or n.startswith(name + ".")}
    for n in away:
        del sys.modules[n]
    try:
        return fn()
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(away)
        importlib.invalidate_caches()


buffer_x = io.StringIO()
check_x = logging.StreamHandler(buffer_x)
_sec.seclog.addHandler(check_x)
try:
    # `password_enabled` stays on: LDAP checks passwords and satisfies the `password` factor —
    # without the switch there would be no sign-in method at all, and the configuration check
    # aborts (rightly) beforehand. This is about the missing extra, not about that.
    # `ldap_allow_plaintext=True`: since F-12 `ldap://` without TLS is a setup error. Here, however,
    # the MISSING EXTRA is to be measured, not the transport — without the switch the
    # setup would abort for the other reason and the check below would be green without measuring.
    auth_x, _ = _without_module("ldap3", lambda: _app(
        ldap_enabled=True, ldap_url="ldap://ldap.example.com", ldap_allow_plaintext=True))
    built_x = True
except Exception as e:
    auth_x, built_x = None, e
finally:
    _sec.seclog.removeHandler(check_x)

r.check("a missing extra does NOT abort the setup", built_x is True,
        f"{type(built_x).__name__} — then nobody can set their own client any more")
r.check("...but it is reported at startup", "tinysesam[ldap]" in buffer_x.getvalue(),
        f"silent: {buffer_x.getvalue()[:90]!r}")

# And on the first real use a readable error instead of a bare ModuleNotFoundError.
from tinysesam.ldap_ import LDAPClient  # noqa: E402

client = LDAPClient(auth_x.cfg if auth_x else None)
try:
    _without_module("ldap3", client._server)
    use = None
except Exception as e:
    use = e
r.check("on use a MissingExtra is raised", isinstance(use, MissingExtra),
        f"{type(use).__name__}: {str(use)[:70]}")
r.check("...with a machine-readable extra name", getattr(use, "extra", None) == "ldap",
        f"extra={getattr(use, 'extra', None)!r}")
r.check("...and still a RuntimeError", isinstance(use, RuntimeError),
        "existing `except RuntimeError` breaks")

# Counter-check: whoever leaves the method incomplete brings the client along themselves.
built, text = _builds(ldap_enabled=True)
r.check("a half-configured method stays buildable (own client)", built,
        f"rejected: {text[:110]}")

# After the counter-check the normal case must build again — otherwise the test would have returned the
# table broken and everything that follows would be nonsense.
built, _ = _builds()
r.check("the table is intact again after the counter-check", built,
        "the test did not reset the state cleanly")


# ── The database carried no schema stamp ──────────────────────────────────────
# Which state a file had could only be guessed from its column names. A file from a
# NEWER version opened an older version silently — with tables it does not
# know, and writes that leave gaps.
stamp_path = str(Path(tempfile.mkdtemp()) / "stamp.db")
st = Store(stamp_path)
stamped = int(st.db.execute("PRAGMA user_version").fetchone()[0] or 0)
r.check("a fresh database carries the schema version",
        stamped == Store.SCHEMA_VERSION and stamped > 0,
        f"user_version={stamped}, expected {Store.SCHEMA_VERSION}")
st.db.close()

# A file from the future must speak up.
raw_st = _sq.connect(stamp_path)
raw_st.execute(f"PRAGMA user_version = {Store.SCHEMA_VERSION + 50}")
raw_st.commit()
raw_st.close()
buffer_st = io.StringIO()
check_st = logging.StreamHandler(buffer_st)
log_st = logging.getLogger("tinysesam")
log_st.addHandler(check_st)
try:
    future = Store(stamp_path)
finally:
    log_st.removeHandler(check_st)
r.check("a file from a newer version is reported",
        "from a newer version" in buffer_st.getvalue(),
        f"silent: {buffer_st.getvalue()[:80]!r}")
r.check("...and the higher stamp is NOT reset",
        int(future.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION + 50,
        "the version was stamped down — at the next open the warning is missing")


# ── Contradictions were only noticed at login ─────────────────────────────────
# An app without a single sign-in method started without complaint; a `login_chain` naming a
# disabled method is unsatisfiable and sends the user in circles.
built, text = _builds(password_enabled=False)
r.check("an instance without any sign-in method is rejected", not built,
        "builds — nobody can sign in, and nothing says so")
r.check("...with a hint which switches there would be", "password_enabled=True" in text,
        f"{text[:90]!r}")

built, text = _builds(login_chain=["password", "pin"], pin_enabled=False)
r.check("an unsatisfiable factor chain is rejected", not built,
        "builds — the user ends up in a loop")
r.check("...and names the blocking step", "pin_enabled=False" in text, f"{text[:90]!r}")

built, text = _builds(login_chain=["password", "gibtsnicht"])
r.check("an unknown step in the chain is rejected", not built,
        "a typo in the chain would stay silently without consequence")

# All findings at once — whoever has three things wrong should read them once.
built, text = _builds(password_enabled=False, login_chain=["password", "pin"], pin_enabled=False)
r.check("several contradictions are reported together", text.count("\n  - ") >= 2,
        f"only one: {text[:120]!r}")

# What can still come later is a warning — not an abort. `set_mailer` after the
# constructor is a perfectly common order. `base_url` is the opposite case and is therefore
# here: it must be present at setup (error, not warning — see R4-01 rework),
# otherwise "forgot password" would silently run into nothing.
buffer_k = io.StringIO()
check_k = logging.StreamHandler(buffer_k)
_sec.seclog.addHandler(check_k)
try:
    built, text = _builds(magiclink_enabled=True, base_url="https://auth.example.com")
finally:
    _sec.seclog.removeHandler(check_k)
r.check("a missing mailer does NOT prevent startup", built,
        f"aborts: {text[:90]} — set_mailer() often comes only afterwards")
r.check("...but it is reported", "smtp_host" in buffer_k.getvalue(),
        f"silent: {buffer_k.getvalue()[:80]!r}")

# And the normal case must neither break nor make noise.
buffer_n = io.StringIO()
check_n = logging.StreamHandler(buffer_n)
_sec.seclog.addHandler(check_n)
try:
    built, text = _builds()
finally:
    _sec.seclog.removeHandler(check_n)
r.check("the default configuration builds without finding", built, text[:110])
r.check("...and without configuration warning", "Configuration:" not in buffer_n.getvalue(),
        f"warns without cause: {buffer_n.getvalue()[:90]!r}")


# ── complete_mfa promised more than the method does ───────────────────────────
# The docstring itself called the name "backwards compatible" — and it nevertheless remained the
# only one. MFA is the whole chain; the method appends exactly one factor.
auth_cm, _ = _app()
r.check("the clear name complete_totp exists", hasattr(auth_cm, "complete_totp"),
        "only the old name — then nothing is gained")
r.check("the old name complete_mfa is kept until 1.0", hasattr(auth_cm, "complete_mfa"),
        "removed — that breaks existing calls for the sake of a name")

# And the alias must really do the same, not only exist. Since 0.22.0 it is level C:
# It warns when called (wording and target are checked by the guard tests/test_api_surface.py).
import warnings as _warnings  # noqa: E402

uid_cm = auth_cm.create_user("cm", password="dummy12345")
tok_old = auth_cm.store.create_session(uid_cm, 3600, False, "password")
with _warnings.catch_warnings(record=True) as _warned:
    _warnings.simplefilter("always")
    auth_cm.complete_mfa(tok_old)
r.check("complete_mfa warns as a deprecated alias of complete_totp",
        [w.category for w in _warned] == [DeprecationWarning]
        and "complete_totp" in str(_warned[0].message),
        [str(w.message) for w in _warned])
tok_new = auth_cm.store.create_session(uid_cm, 3600, False, "password")
auth_cm.complete_totp(tok_new)
import json as _json  # noqa: E402

factors = [sorted(_json.loads(auth_cm.store.get_session(t)["factors_done"] or "[]"))
            for t in (tok_old, tok_new)]
r.check("both names append the same factor", factors[0] == factors[1] == ["totp"],
        f"old={factors[0]} new={factors[1]} — an alias that does something else is worse "
        "than two methods")


# ── The Host header poisoned the reset, sign-in and confirmation link (R4-01/R8-4) ──────────
# Attack: The attacker triggers "forgot password" for a FOREIGN mailbox and sets the raw `Host`
# header while doing so. TinySesam built the mail address from `str(request.base_url)`, i.e. from
# exactly this header — the victim received a real mail from the real app with a valid token
# in a link to the attacker's server (CWE-644). `trusted_redirect_hosts` only protected
# `?next=`, not this path; `X-Forwarded-Host` is not needed for it.
EVIL = "attacker.example"
REAL = "https://auth.example.com"


def _mailapp(**cfg):
    post: list = []
    # `base_url` is now part of the basic equipment: since the rework it is mandatory as soon as
    # a mail path is on — an instance without it no longer exists (check for that further down).
    reason = dict(csrf_enabled=False, magiclink_enabled=True, password_reset_enabled=True,
                 signup_verify_email=True, allow_signup=True, signup_require_email=True,
                 passkey_enabled=False, trusted_redirect_hosts=["only-this-here.example"],
                 base_url=REAL)
    reason.update(cfg)
    auth, app = _app(**reason)
    auth.set_mailer(lambda to, subject, text, html=None: post.append(text))
    auth.create_user("victim", password="Secret12345!abc", email="victim@example.com")
    return auth, TestClient(app), post


def _links(post) -> list[str]:
    return re.findall(r"https?://[^\s]+", "\n".join(post))


# Precondition: without this check "no mail to the attacker host" would be green even if
# the mailer is not wired at all — the attack would then prove nothing.
_a, _c, _post = _mailapp()
_c.post("/auth/forgot", data={"email": "victim@example.com"})
r.check("precondition: the path works at all (mail goes out)",
        len(_post) == 1 and _links(_post)[0].startswith(REAL + "/auth/reset"),
        f"{_post!r} — without this assurance the attack below checks nothing")

# The attack itself, at all three places that send a mail with a token.
for path, data, name in (
        ("/auth/forgot", {"email": "victim@example.com"}, "Reset-Link"),
        ("/auth/magic/request", {"email": "victim@example.com", "next": "/"}, "Magic-Link"),
        ("/auth/register", {"username": "new", "password": "Secret12345!abc",
                            "email": "new@example.com"}, "Confirmation link")):
    auth_x, c_x, post_x = _mailapp()
    response_x = c_x.post(path, data=data, headers={"host": EVIL})
    r.check(f"{name}: forged Host header produces no mail to {EVIL}",
            not any(EVIL in u for u in _links(post_x)),
            f"{_links(post_x)!r} — the victim would get a valid token at {EVIL}")
    r.check(f"...and the path stays intact (mail to {REAL}, HTTP {response_x.status_code})",
            len(post_x) == 1 and _links(post_x)[0].startswith(REAL),
            f"{_links(post_x)!r} — base_url wins, the header does not count")

# ── Rework N1: the Host header must not choose even among SEVERAL own hosts ──
# Finding A-bypass-4: `base_url` was only a warning. If it stayed empty and — with
# forward-auth/SSO the normal case — several names stood in `trusted_redirect_hosts`, the
# runtime check accepted EACH of them: the attacker triggered "forgot password" for a foreign mailbox
# and set `Host:` to another co-trusted host. If that one is weaker (foreign team,
# open redirect, captured access log), the reset token leaks there. Now `base_url`
# is mandatory and always wins — the header no longer has a say.
auth_m, c_m, post_m = _mailapp(trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"])
c_m.post("/auth/forgot", data={"email": "victim@example.com"},
         headers={"host": "app-b.example.com"})
r.check("a second co-trusted host in the header does not win against base_url",
        len(post_m) == 1 and _links(post_m)[0].startswith(REAL + "/auth/reset"),
        f"{_links(post_m)!r} — the reset token would go to the host chosen by the attacker")

# Finding A-regression-1/A-vollstaendigkeit-3: without a base `/auth/forgot` and
# `/auth/magic/request` kept rendering the SUCCESS page — HTTP 200, "mail is on its way", no mail.
# The total failure was visible only in a log line. Two locks against it:
#
# (1) The configuration check no longer lets this setup come into being (error, not warning).
from tinysesam import config_check as _kp  # noqa: E402

for _slot, _addition in (("magiclink_enabled", {}),
                       ("password_reset_enabled", {"magiclink_enabled": True}),
                       ("signup_verify_email", {"signup_require_email": True}),
                       ("oidc_enabled", {"oidc_issuer": "https://idp.example.com",
                                         "oidc_client_id": "c", "oidc_client_secret": "s"}),
                       ("saml_enabled", {"saml_idp_sso_url": "https://idp.example.com/sso",
                                         "saml_idp_x509cert": "PEM"})):
    _f, _w = _kp.check_config(TinySesamConfig(db_path=":memory:", **{_slot: True}, **_addition))
    r.check(f"without base_url {_slot} is an ERROR, not a warning",
            any("base_url is empty" in x for x in _f),
            f"only warnings: {[x[:60] for x in _w]!r} — a warning starts up anyway")
_f_hosts, _w_hosts = _kp.check_config(TinySesamConfig(
    db_path=":memory:", magiclink_enabled=True,
    trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"]))
r.check("trusted_redirect_hosts does NOT replace base_url",
        any("base_url is empty" in x for x in _f_hosts),
        "with several co-trusted hosts the header chooses otherwise (A-bypass-4)")
_built_without, _text_without = _builds(magiclink_enabled=True, password_reset_enabled=True)
r.check("...and the constructor aborts with it (ConfigError instead of silent operation)",
        not _built_without and "base_url" in _text_without, f"built={_built_without}")
r.check("...the message says what to enter",
        "base_url=" in _text_without, f"only diagnosis, no remedy: {_text_without[:160]!r}")
# Counter-check: the guard must not hit every setup. Only password/PIN needs no base.
_f_pw, _w_pw = _kp.check_config(TinySesamConfig(db_path=":memory:"))
r.check("without a link-building function nobody demands a base_url",
        not any("base_url" in x for x in _f_pw + _w_pw), f"{(_f_pw, _w_pw)!r}")
# Forward-auth alone stays a warning: without a base the redirect stays relative and hits
# the same browser, nothing goes out to third parties.
_f_fa, _w_fa = _kp.check_config(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True))
r.check("forward_auth alone stays a warning (the redirect stays relative)",
        not any("base_url" in x for x in _f_fa) and any("base_url" in x for x in _w_fa),
        f"errors={[x[:50] for x in _f_fa]!r} warnings={[x[:50] for x in _w_fa]!r}")

# (2) Second lock for the config that was changed AFTER the constructor (it is read at
# request time): no silent success, but an abort with a clear message — since the
# rework for "base_url cleared after the constructor" as HTTP 503 from the route
# (`router._mail_base`), no longer as an uncaught ConfigError.
from tinysesam import ConfigError as _CfgErr  # noqa: E402

for _path, _data, _name in (("/auth/forgot", {"email": "victim@example.com"}, "Passwort vergessen"),
                             ("/auth/magic/request", {"email": "victim@example.com", "next": "/"},
                              "Magic-Link")):
    auth_l, c_l, post_l = _mailapp()
    auth_l.cfg.base_url = ""            # mutation probe: the base drops away at runtime
    try:
        _response_l = c_l.post(_path, data=_data)
        _result = f"HTTP {_response_l.status_code}, Erfolgsseite: {'unterwegs' in _response_l.text}"
        _hart = _response_l.status_code == 503 and "unterwegs" not in _response_l.text
    except _CfgErr as _e:
        _result, _hart = f"ungefangen: {str(_e)[:60]}", False
    r.check(f"{_name} without a base: 503 instead of \"mail is on its way\" (and instead of a 500)",
            _hart and not post_l,
            f"{_result} — 200 with a success page hides the total failure (A-regression-1)")

# And what the operator REALLY gets to see in this case — in operation, without a TestClient that passes
# an exception through. Until the rework no route caught the `ConfigError`, and the ASGI server
# turned it into an HTTP 500 (so it said in the CHANGELOG). Now `_mail_base()` catches it and
# answers 503: the service is not ready for use like this, and the answer says so. Both are
# measured: no silent success, and exactly 503 — not 500, not 200.
# (Mutation probe: replace `_mail_base` by `auth.require_public_base(request)` → 500, red.)
auth_500, app_500 = _app(csrf_enabled=False, magiclink_enabled=True, password_reset_enabled=True,
                         passkey_enabled=False, base_url=REAL)
_post_500: list = []
auth_500.set_mailer(lambda to, subject, text, html=None: _post_500.append(text))
auth_500.create_user("victim", password="Secret12345!abc", email="victim@example.com")
auth_500.cfg.base_url = ""              # the situation the second lock is built for
_c500 = TestClient(app_500, raise_server_exceptions=False)
_response_500 = _c500.post("/auth/forgot", data={"email": "victim@example.com"})
r.check("no silent success: without a base /auth/forgot does not report \"mail is on its way\"",
        _response_500.status_code != 200 and not _post_500,
        f"HTTP {_response_500.status_code}, mails={len(_post_500)} — the same answer prevents "
        "user enumeration and therefore hid the total failure (A-regression-1)")
r.check("...but HTTP 503 from the route, no uncaught 500",
        _response_500.status_code == 503,
        f"HTTP {_response_500.status_code} — 500 means: the ConfigError runs uncaught again "
        "up to the ASGI server (change the CHANGELOG sentence accordingly)")
# Invitation from the panel: the same class, the same bolt.
auth_inv, app_inv = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                         base_url=REAL)
auth_inv.set_mailer(lambda *a, **k: None)
auth_inv.ensure_admin("boss", "Secret12345!abc")
_ci = TestClient(app_inv, raise_server_exceptions=False)
_ci.post("/auth/login", data={"username": "boss", "password": "Secret12345!abc"})
auth_inv.cfg.base_url = ""
_inv = _ci.post("/auth/admin/api/invite", json={"email": "guest@example.com"})
r.check("admin invitation without a base: 503, no 500 and no link",
        _inv.status_code == 503 and "claim" not in _inv.text and "/auth/" not in _inv.text,
        f"HTTP {_inv.status_code}: {_inv.text[:120]!r}")

# Finding A-regression-4: the same places otherwise answered with 500 in the middle of a sign-in attempt —
# `/auth/oidc/start` is the entry point to which a gateway sends every visitor. Now the
# abort happens at setup, i.e. before a user clicks.
for _name, _an in (("OIDC", dict(oidc_enabled=True, oidc_issuer="https://idp.example.com",
                                 oidc_client_id="c", oidc_client_secret="s")),
                   ("SAML", dict(saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
                                 saml_idp_x509cert="PEM")),
                   ("Invitation/Magic", dict(magiclink_enabled=True))):
    _built, _text = _builds(**_an)
    r.check(f"{_name} without base_url: abort at setup, no 500 at runtime",
            not _built and "base_url" in _text, f"built={_built}: {_text[:90]!r}")

# The legitimate path stays: with a committed base_url the mail goes out, and the forged
# host is not in it. Without this check the fix "never a mail again" would be green too.
auth_ok, c_ok, post_ok = _mailapp(base_url=REAL)
c_ok.post("/auth/forgot", data={"email": "victim@example.com"}, headers={"host": EVIL})
r.check("legitimate path: base_url set → mail goes out and carries the real address",
        len(post_ok) == 1 and _links(post_ok)[0].startswith(REAL + "/auth/reset"),
        f"{_links(post_ok)!r}")
r.check("and the forged host appears nowhere", EVIL not in "\n".join(post_ok),
        f"{post_ok!r}")

# The invitation link of the admin panel likewise goes by mail to a third party and carries a
# token — it came from the same line and was left lying in an earlier round of patching.
auth_inv, app_inv = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                         base_url=REAL)
auth_inv.set_mailer(lambda *a, **k: None)
auth_inv.create_user("chef", password="Secret12345!abc", is_admin=True)
with TestClient(app_inv) as c_inv:
    c_inv.cookies.set(auth_inv.cfg.session_cookie,
                      auth_inv.store.create_session(auth_inv.store.get_user_by_name("chef")["id"],
                                                    3600, True, "password"))
    invitation = c_inv.post("/auth/admin/api/invite", json={"email": "guest@example.com"},
                           headers={"host": EVIL})
r.check("admin invitation: the link comes from base_url, not from the Host header",
        invitation.status_code == 200 and EVIL not in invitation.text
        and REAL + "/auth/invite/" in invitation.text,
        f"HTTP {invitation.status_code}: {invitation.text[:120]!r}")

# The rule itself, checked directly — it also decides for the OIDC redirect URI, SAML metadata
# and the forward-auth redirect, which all go through `public_base()`.
from tinysesam import security as _sec  # noqa: E402

r.check("a foreign host does not count as own", _sec.own_host(EVIL, []) is False)
r.check("a host from trusted_redirect_hosts counts", _sec.own_host("a.example.com", ["a.example.com"]))
r.check("loopback counts (the link only benefits the recipient themselves)",
        _sec.own_host("127.0.0.1", []) and _sec.own_host("::1", []))
r.check("user info in the host does not fool the check",
        _sec.secure_base("https://a.example.com@" + EVIL, ["a.example.com"]) == "",
        "urlsplit reads the host behind the @ here — the check must see exactly that")
r.check("and the checked base carries no user info on",
        _sec.secure_base("https://wer@a.example.com:8443", ["a.example.com"])
        == "https://a.example.com:8443")
auth_pb, _app_pb = _app(passkey_enabled=False)
r.check("public_base() returns empty instead of guessing (fail closed)",
        auth_pb.public_base(candidate="https://" + EVIL) == "")
try:
    auth_pb.require_public_base(candidate="https://" + EVIL)
    _pb_hart = False
except _CfgErr:
    _pb_hart = True
r.check("require_public_base() raises instead of guessing",
        _pb_hart, "whoever NEEDS a base must not get an empty string")

# Finding A-regression-12: the server's `root_path` was dropped — an app mounted under a subpath
# sent mail links without prefix, i.e. 404 instead of the reset form.
_auth_path = TinySesam(TinySesamConfig(db_path=":memory:",
                                      base_url="https://app.example.com/sso/"))
r.check("the subpath (root_path) comes along from base_url",
        _auth_path.public_base() == "https://app.example.com/sso",
        f"{_auth_path.public_base()!r} — mail links without prefix end up in a 404")
r.check("...and from a derived base as well",
        _sec.secure_base("https://a.example.com/sso/", ["a.example.com"])
        == "https://a.example.com/sso",
        "up to 0.18.x secure_base dropped the path")
r.check("...but nothing we cannot assemble cleanly (fail closed)",
        all(_sec.secure_base("https://a.example.com" + _p, ["a.example.com"]) == ""
            for _p in ("/../etc", "/sso/../x", "/a//b", "/s so", "/a%2fb")),
        "a half-guessed prefix would go into every outgoing mail")

# Finally: the configuration check was completely silent on `base_url` — whoever left the gap open
# learned it nowhere.
from tinysesam import config_check as _kp  # noqa: E402

_error, _warn = _kp.check_config(TinySesamConfig(password_reset_enabled=True))
r.check("config_check names the missing base_url",
        any("base_url is empty" in f for f in _error), f"{_error!r}")
_error2, _warn2 = _kp.check_config(auth_ok.cfg)
r.check("with base_url set it stays silent about it",
        not any("base_url is empty" in m for m in _error2 + _warn2), f"{_error2!r} {_warn2!r}")

# The warning is measured for EVERY switch that builds an absolute address — not only for
# the mail paths. Before, the suite covered three of the six entries: `REQUIRES_BASE_URL` could
# be shortened by `oidc_enabled`, `saml_enabled` and `forward_auth_enabled` without a
# single check turning red (mutation probe N4, full suite 46/46 green).
#
# The six switches are therefore WRITTEN OUT, not a loop over the table itself:
# a loop over `REQUIRES_BASE_URL` would only check the entries still in it — whoever removes
# one would take the check away with it. (Exactly that was noticed when reproducing the
# mutation probe.) What is asked is a bare config, no instance: `check_config` only reads
# fields, and so the line needs neither [oidc] nor [saml].
#
# Since rework N1 the message is separated by severity: the five paths that hand an absolute
# address into FOREIGN hands (mail, IdP) are an **error** — the setup fails, because a
# warning starts up and `/auth/forgot` otherwise keeps rendering the success page without a mail.
# Forward-auth stays a **warning**: without a base the redirect stays relative, hits the same
# browser and gives nothing to third parties. Both tables are measured here, each in its severity.
_REQUIRES_BASE = ("magiclink_enabled", "password_reset_enabled", "signup_verify_email",
                  "oidc_enabled", "saml_enabled")
_RECOMMENDS_BASE = ("forward_auth_enabled",)
r.check("the table names all six functions that build absolute addresses",
        set(_REQUIRES_BASE) <= set(_kp.REQUIRES_BASE_URL)
        and set(_RECOMMENDS_BASE) <= set(_kp.BASE_URL_RECOMMENDED),
        f"not named: {sorted((set(_REQUIRES_BASE) - set(_kp.REQUIRES_BASE_URL)) | (set(_RECOMMENDS_BASE) - set(_kp.BASE_URL_RECOMMENDED)))}")
for _slot in _REQUIRES_BASE:
    _f3, _w3 = _kp.check_config(TinySesamConfig(**{_slot: True}))
    r.check(f"config_check reports {_slot} without base_url as an ERROR",
            any("base_url is empty" in f for f in _f3),
            f"{_f3!r} — this switch hands an absolute address out of hand but tells nobody")
for _slot in _RECOMMENDS_BASE:
    _f3, _w3 = _kp.check_config(TinySesamConfig(**{_slot: True}))
    r.check(f"config_check warns for {_slot} without base_url (not an error)",
            any("base_url is empty" in w for w in _w3)
            and not any("base_url is empty" in f for f in _f3),
            f"E={_f3!r} W={_w3!r} — the redirect stays relative, this must not refuse the start")

# ── R4-01, the six places without mail: OIDC, SAML, forward-auth ───────────────
# The same rule, other paths. Up to here only the four mail paths were tested; the remaining
# places behaved correctly, but unmeasured — each could be rebuilt to the old form
# `cfg.base_url or <from the request>` without the full suite turning red
# (mutation probes N5–N8, 46/46 green each). F-16, which concerns the SAML SP
# identity, continues to work exactly here: without these checks a rework silently reopens R4-01.
from urllib.parse import unquote, urlsplit  # noqa: E402

_OIDC_META = {
    "issuer": "https://idp.example.invalid",
    "authorization_endpoint": "https://idp.example.invalid/authorize",
    "token_endpoint": "https://idp.example.invalid/token",
    "jwks_uri": "https://idp.example.invalid/jwks",
    "end_session_endpoint": "https://idp.example.invalid/logout",
}


def _oidc_app(**cfg):
    cfg.setdefault("base_url", REAL)
    auth_x, app_x = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                         oidc_client_id="probe", oidc_client_secret="secret",
                         csrf_enabled=False, passkey_enabled=False, **cfg)
    auth_x.oidc._meta = dict(_OIDC_META)   # no network needed: what is checked is the base, not discovery
    return auth_x, app_x


def _oidc_app_without_base(**cfg):
    """The same app, but with an empty base at REQUEST time.

    Since N1 the constructor flatly refuses `oidc_enabled` without `base_url` — this situation
    can therefore no longer be built at all. What is measured is the second lock, which is there
    for exactly that: a config changed after the constructor (it is read at request time).
    Without this lock the router would fall back to the Host header.
    """
    auth_x, app_x = _oidc_app(**cfg)
    auth_x.cfg.base_url = ""
    return auth_x, app_x


# (1) OIDC redirect URI. It decides where the IdP sends the authorization code — derived from the
# Host header, an IdP with loosely maintained redirect URIs would deliver the code to the
# attacker's host.
def _aborts(call):
    """(aborted with ConfigError, text of the response or of the exception).

    Since N1 these paths raise `ConfigError` instead of `HTTPException(500)`: a server error in the middle
    of a sign-in attempt was the wrong place for a problem that was already settled at setup.
    What is measured is therefore the abort, no longer a status line — and in both cases that
    the foreign host does not show through anywhere.
    """
    try:
        response = call()
    except _CfgErr as e:
        return True, str(e)
    return False, getattr(response, "text", "") + str(getattr(response, "headers", ""))


_a_oi, _app_oi = _oidc_app_without_base()
with TestClient(_app_oi) as _c:
    _oi_from, _oi_text = _aborts(
        lambda: _c.get("/auth/oidc/start", headers={"host": EVIL}, follow_redirects=False))
r.check("OIDC start: forged host builds no redirect URI (fail closed)",
        _oi_from and EVIL not in unquote(_oi_text),
        f"aborted={_oi_from}: {_oi_text[:160]!r}")

_a_oi2, _app_oi2 = _oidc_app(base_url=REAL)
with TestClient(_app_oi2) as _c:
    _start_good = _c.get("/auth/oidc/start", headers={"host": EVIL}, follow_redirects=False)
_destination_good = unquote(_start_good.headers.get("location", ""))
r.check("...and with base_url the flow continues, on the own address",
        _start_good.status_code == 303 and REAL + "/auth/oidc/callback" in _destination_good
        and EVIL not in _destination_good,
        f"HTTP {_start_good.status_code}: {_destination_good[:160]!r} — otherwise the line above only checks "
        "that the start is broken at all")

# (2) OIDC post-logout. The `post_logout_redirect_uri` goes to the IdP; derived from the Host
# header, the IdP sends the victim to the attacker's server after signing out.
def _sign_out(auth_x, app_x):
    uid = auth_x.create_user("wer", password="Secret12345!abc")
    tok = auth_x.store.create_session(uid, 3600, True, "oidc")
    with TestClient(app_x) as c:
        c.cookies.set(auth_x.cfg.session_cookie, tok)
        return c.get("/auth/logout", headers={"host": EVIL}, follow_redirects=False)


_a_pl, _app_pl = _oidc_app_without_base(oidc_rp_logout=True)
_logout_evil = _sign_out(_a_pl, _app_pl)
_loc_evil = unquote(_logout_evil.headers.get("location", ""))
r.check("OIDC logout: no post_logout_redirect_uri from the Host header",
        EVIL not in _loc_evil and _loc_evil == _a_pl.cfg.logout_redirect,
        f"{_loc_evil!r} — the IdP then sent the victim to the attacker")

_a_pl2, _app_pl2 = _oidc_app(oidc_rp_logout=True, base_url=REAL)
_loc_good = unquote(_sign_out(_a_pl2, _app_pl2).headers.get("location", ""))
r.check("...and with base_url the provider logout still signs out (the path lives)",
        _loc_good.startswith("https://idp.example.invalid/logout")
        and REAL + _a_pl2.cfg.logout_redirect in _loc_good and EVIL not in _loc_good,
        f"{_loc_good!r}")


# (3) SAML: entity ID and ACS URL. Both are the IDENTITY of the SP — a foreign name in them
# travels into the AuthnRequest and into the metadata that the operator registers at the IdP.
# The dummy stands for the real client: what is checked is the base the router gives it,
# not the signature work of python3-saml. So this line does not need the [saml] extra —
# a skip would not be a green here.
class _SamlStub:
    def login_url(self, req, base, return_to="/"):
        return f"https://idp.example.invalid/sso?sp={base}&RelayState={return_to}", "rid-1"

    def process(self, req, base, request_id=""):
        return None      # "assertion rejected" → 400; a 500 would mean: there was no base at all

    def metadata(self, base):
        return f'<EntityDescriptor entityID="{base}/auth/saml/metadata"/>'


def _saml_app(**cfg):
    tmp = tempfile.mkdtemp()
    reason = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False)
    reason.update(cfg)
    auth_x = TinySesam(TinySesamConfig(**reason))
    auth_x.saml = _SamlStub()    # BEFORE router(): the SAML routes hang on auth.saml
    app_x = FastAPI()
    app_x.include_router(auth_x.router())
    return auth_x, app_x


_a_sa, _app_sa = _saml_app()
with TestClient(_app_sa) as _c:
    _md_from, _md_text = _aborts(lambda: _c.get("/auth/saml/metadata", headers={"host": EVIL}))
    _lg_from, _lg_text = _aborts(
        lambda: _c.get("/auth/saml/login", headers={"host": EVIL}, follow_redirects=False))
    _acs_from, _ = _aborts(
        lambda: _c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, headers={"host": EVIL}))
r.check("SAML metadata: no entity ID from the Host header",
        _md_from and EVIL not in _md_text, f"aborted={_md_from}: {_md_text[:160]!r}")
r.check("SAML login: no AuthnRequest with a foreign SP address",
        _lg_from and EVIL not in unquote(_lg_text),
        f"aborted={_lg_from}: {_lg_text[:160]!r}")
r.check("SAML ACS: aborts before an assertion is checked against a foreign ACS URL",
        _acs_from, "the assertion would have been checked against a foreign ACS URL")

_a_sa2, _app_sa2 = _saml_app(base_url=REAL)
with TestClient(_app_sa2) as _c:
    _md_good = _c.get("/auth/saml/metadata", headers={"host": EVIL})
    _lg_good = _c.get("/auth/saml/login", headers={"host": EVIL}, follow_redirects=False)
    _acs_good = _c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, headers={"host": EVIL})
r.check("...and with base_url SAML carries the own address (metadata, login, ACS live)",
        _md_good.status_code == 200 and f'entityID="{REAL}/auth/saml/metadata"' in _md_good.text
        and _lg_good.status_code == 303 and f"sp={REAL}" in unquote(_lg_good.headers["location"])
        and _acs_good.status_code == 400 and EVIL not in _md_good.text,
        f"Metadata HTTP {_md_good.status_code}: {_md_good.text[:90]!r}; Login HTTP "
        f"{_lg_good.status_code}; ACS HTTP {_acs_good.status_code} (400 = base was there, assertion "
        "rejected; 500 = no base)")

# (4) Forward-auth redirect. The proxy sends every non-signed-in visitor to the
# address from `X-TinySesam-Location` — if a foreign host stood there, the proxy would itself lead the victim
# to the attacker's sign-in page. What is checked is the HOST of the redirect: the `next=`
# carries the requested URL and may do so, `safe_next` discards it later.
_a_fa, _app_fa = _app(forward_auth_enabled=True, csrf_enabled=False, passkey_enabled=False,
                      trusted_redirect_hosts=["app.example.com"])
with TestClient(_app_fa) as _c:
    _fa_evil = _c.get("/auth/forward", headers={"host": EVIL, "x-forwarded-host": EVIL,
                                                 "x-forwarded-proto": "https",
                                                 "x-forwarded-uri": "/secret"})
    _fa_good = _c.get("/auth/forward", headers={"host": "app.example.com",
                                               "x-forwarded-host": "app.example.com",
                                               "x-forwarded-proto": "https",
                                               "x-forwarded-uri": "/secret"})
_loc_fa = _fa_evil.headers.get("X-TinySesam-Location", "")
r.check("Forward-Auth: the 401 redirect points to no foreign host",
        _fa_evil.status_code == 401 and not (urlsplit(_loc_fa).hostname or "")
        and _loc_fa.startswith(_a_fa.cfg.login_path + "?next="),
        f"HTTP {_fa_evil.status_code}: {_loc_fa[:140]!r} — the proxy itself led the victim there")
_loc_fa_good = _fa_good.headers.get("X-TinySesam-Location", "")
r.check("...and on a host from trusted_redirect_hosts it stays absolute (cookie host)",
        _fa_good.status_code == 401
        and _loc_fa_good.startswith("https://app.example.com" + _a_fa.cfg.login_path),
        f"HTTP {_fa_good.status_code}: {_loc_fa_good[:140]!r}")

# ── The same ONE rule for the documented methods, not only for the routes ───
# `public_base()` sat only in the routes. An app with its own "forgot password" form —
# the path shown in both READMEs and in API.md — called `send_password_reset(mail, base)`
# itself and was still fully attackable with `str(request.base_url)`, while the
# built-in route had long since been fixed. The check now sits in `magic_url()`, where all
# four mail paths converge, and additionally before the token is issued in every sender.
#
# What is measured is the RULE, not its mechanism: If `base_url` is set, it wins — even against
# a second co-trusted name. That was exactly finding B-bypass-3: Here the
# passed host still decided as long as it was in `trusted_redirect_hosts`. The `Host` header thus
# still chose which of the own names ends up in the reset link — the core of R4-01, one level
# deeper. Without `base_url` — the only setup in which anything is derived at all — it stays
# with the hard `ConfigError`.
_a_api, _app_api = _app(magiclink_enabled=True, password_reset_enabled=True, passkey_enabled=False,
                        base_url=REAL,
                        trusted_redirect_hosts=["auth.example.com", "app-b.example.com"])
_mails_api: list = []
_a_api.set_mailer(lambda to, subject, text, html=None: _mails_api.append(text))
_a_api.create_user("victim", password="Secret12345!abc", email="victim@example.com")
# This round sends a dozen mails to the same address; what is measured is the base, not the
# throttle per target address (R4-04, own test in test_magic.py) — it gets room here.
_a_api.set_security("mail_per_address_max", 100)


def _token_lines(auth_x) -> int:
    return auth_x.store._exec("SELECT COUNT(*) FROM magic_token").fetchone()[0]


def _send(send):
    """Run the send that `_verify_mail` returns (None: no mailer)."""
    return send() if send else send


def _paths(auth_x, base):
    """The documented paths, all with the SAME passed base."""
    return (
        ("magic_url", lambda: auth_x.magic_url("rohtoken", base, "reset_password")),
        ("send_password_reset", lambda: auth_x.send_password_reset("victim@example.com", base)),
        ("send_login_link", lambda: auth_x.send_login_link("victim@example.com", base)),
        ("send_verify_email", lambda: auth_x.send_verify_email(1, "victim@example.com", base)),
        # Registration creates the token in the request and sends later (T-13 attack,
        # mail × operation) — it calls `_verify_mail` directly, so it is also measured directly.
        ("_verify_mail", lambda: _send(auth_x._verify_mail(1, "victim@example.com", base))),
        ("create_invite", lambda: auth_x.create_invite("guest@example.com", base)),
        # R4-03: the notice to the owner of a taken address carries the way to sign in.
        ("_send_signup_notice", lambda: auth_x._send_signup_notice("victim@example.com", base)),
        # Self-service (2026-09-25): the link to the NEW address; the confirmation path for
        # addresses from LDAP/SAML also runs through here (`_address_proven_by_source`).
        ("request_email_change", lambda: _send(auth_x.request_email_change(
            auth_x.store.get_user_by_name("victim")["id"], "victim-new@example.com", base))),
        # …and since the attack round of 2026-09-26 via the wrapper with the source that
        # `_address_proven_by_source` calls (detail `konto=<id> quelle=…`). The same link.
        ("_request_change", lambda: _send(auth_x._request_change(
            auth_x.store.get_user_by_name("victim")["id"], "victim-source@example.com", base,
            source="ldap"))),
    )


def _trace(erg, mails) -> str:
    """Everything the call gave to the outside: return value plus sent mail texts."""
    return repr(erg) + " " + " ".join(mails)


for _foreign, _was in (("https://" + EVIL, "a foreign host"),
                     ("https://app-b.example.com", "a SECOND own name")):
    for _name, _call in _paths(_a_api, _foreign):
        _mails_api.clear()
        try:                            # a ConfigError would be a finding here too, not an abort
            _s = _trace(_call(), _mails_api)
        except ConfigError as e:
            _s = f"ConfigError: {e}"[:140]
        r.check(f"{_name}: base_url wins against {_was}",
                (urlsplit(_foreign).hostname or "") not in _s and REAL in _s,
                f"{_s[:140]!r} — otherwise the Host header chooses what goes into the link")

# Without `base_url` it stays with the hard abort: no link, no mail, no token. This setup
# is the only one that `config_check` lets through without `base_url` (no mail switch on), and exactly it
# is named by the finding as the occasion — an embedding app with its own form.
_a_without, _app_without = _app(passkey_enabled=False, trusted_redirect_hosts=["auth.example.com"])
_mails_without: list = []
_a_without.set_mailer(lambda to, subject, text, html=None: _mails_without.append(text))
_a_without.create_user("victim", password="Secret12345!abc", email="victim@example.com")
for _name, _call in _paths(_a_without, "https://" + EVIL):
    try:
        _rejected, _like = False, repr(_call())
    except ConfigError as e:
        _rejected, _like = True, str(e)[:60]
    r.check(f"without base_url: {_name}(foreign base) is rejected, not delivered",
            _rejected, f"got through: {_like} — the app with its own form stays attackable")

r.check("no mail goes out in the process", _mails_without == [], f"{_mails_without!r}")
r.check("and no unusable token remains in the database",
        _token_lines(_a_without) == 0,
        f"{_token_lines(_a_without)} rows — the check happens before the token is issued, not after")

# The legitimate path of the app: the promised base. Without this promise, "never a link again"
# would also be green. The host of the own base_url suffices — an `http://` from a TLS-terminating
# proxy is lifted to the configured address instead of silently staying unencrypted.
_mails_api.clear()
r.check("legitimate path: base_url supplies the link",
        _a_api.magic_url("rohtoken", REAL, "reset_password") == REAL + "/auth/reset?token=rohtoken",
        _a_api.magic_url("rohtoken", REAL, "reset_password"))
r.check("str(request.base_url) on the own host stays usable — and does not become http",
        _a_api.magic_url("rohtoken", "http://auth.example.com/", "reset_password")
        == REAL + "/auth/reset?token=rohtoken",
        _a_api.magic_url("rohtoken", "http://auth.example.com/", "reset_password"))
r.check("and the sender sends with it again (the method lives)",
        _a_api.send_password_reset("victim@example.com", REAL) is True
        and len(_mails_api) == 1 and REAL + "/auth/reset" in _mails_api[0],
        f"{_mails_api!r}")
r.check("the legitimate path works even without base_url (derived, proven base)",
        _a_without.magic_url("rohtoken", "https://auth.example.com", "reset_password")
        == REAL + "/auth/reset?token=rohtoken",
        _a_without.magic_url("rohtoken", "https://auth.example.com", "reset_password"))

# Finding B-regression-2: The path part appeared FOUR times in the sent link. `secure_base()`
# has returned it itself since N1, `_checked_base()` still appended it once more — and
# because the four senders check themselves first and `magic_url()` a second time afterwards,
# `https://portal.example.com/portal` grew to `…/portal/portal/portal/portal/auth/reset?token=…`.
# The mail went out, the recipient clicked, the link was 404: no error, no log line.
# Therefore COUNTING is used, not `startswith` — exactly that kept the finding hidden.
_UNDER = "https://portal.example.com/portal"
_a_path, _app_path = _app(passkey_enabled=False, trusted_redirect_hosts=["portal.example.com"])
_mails_path: list = []
_a_path.set_mailer(lambda to, subject, text, html=None: _mails_path.append(text))
_a_path.create_user("victim", password="Secret12345!abc", email="victim@example.com")
_a_path.set_security("mail_per_address_max", 100)   # as above: the path is measured, not R4-04
def _links(texts) -> list:
    """All addresses on the subpath host that a call gave to the outside."""
    return [g for t in texts for g in re.findall(r"https://portal\.example\.com[^\s'\"]*", t)]


for _name, _call in _paths(_a_path, _UNDER):
    _mails_path.clear()
    _erg = _call()
    _found = _links([repr(_erg)] + list(_mails_path))
    # Counting happens in the PATH, not in the whole string: "https://portal…" already contains "/portal"
    # through the "//" — a count over that would also have let the fourfold link through.
    _count = [urlsplit(u).path.count("/portal") for u in _found]
    r.check(f"{_name}: the subpath appears exactly ONCE in the link",
            bool(_count) and all(z == 1 for z in _count)
            and all(u.startswith(_UNDER + "/auth/") for u in _found),
            f"{_count} occurrences in {[u[:90] for u in _found]!r}")
r.check("the check is idempotent (applied twice, the path does not grow)",
        _a_path._checked_base(_a_path._checked_base(_UNDER)) == _UNDER,
        f"{_a_path._checked_base(_a_path._checked_base(_UNDER))!r} — the four senders "
        "check before the token is issued, magic_url once more afterwards")

# Finding B-regression-3: What a mount under a subpath REALLY carries — measured on
# a real mount (`FastAPI(root_path="/sso")`), not on a replicated URL. The
# sent link carries the prefix exactly once; since T-15 the built-in pages
# and their redirects carry it too (`auth.path`, placeholder `__TS_P__` in `templates.py`). Until then the
# limit was in README, CONFIGURATION and CHANGELOG, and this test kept it honest; the full
# measurement (mount and uvicorn --root-path, all pages) is in tests/test_subpath.py.
_a_mnt = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"),
                                   cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                                   password_reset_enabled=True,
                                   base_url="https://example.com/sso"))
_mails_mnt: list = []
_a_mnt.set_mailer(lambda to, subject, text, html=None: _mails_mnt.append(text))
_a_mnt.create_user("anna", password="Secret12345!abc", email="anna@example.com")
_app_mnt = FastAPI(root_path="/sso")
_app_mnt.include_router(_a_mnt.router())
_c_mnt = TestClient(_app_mnt, root_path="/sso", follow_redirects=False)
_c_mnt.post("/auth/forgot", data={"email": "anna@example.com"}, headers={"accept": "text/html"})
_link_mnt = [w for w in " ".join(_mails_mnt).split() if w.startswith("http")]
r.check("real mount under /sso: the mail link carries the prefix exactly once",
        len(_link_mnt) == 1 and _link_mnt[0].startswith("https://example.com/sso/auth/reset?")
        and urlsplit(_link_mnt[0]).path.count("/sso") == 1,
        f"{_link_mnt!r} — without prefix it is a 404, repeated too")
_page_html_mnt = _c_mnt.get("/auth/login", headers={"accept": "text/html"}).text
_destination_mnt = _c_mnt.get("/auth/account", headers={"accept": "text/html"}).headers.get("location", "")
_root_mnt = re.findall(r"(?:href|action)='(/[^']*)'", _page_html_mnt)
r.check("...and the built-in pages carry it too (T-15): form, links, redirect",
        "action='/sso/auth/login'" in _page_html_mnt and _root_mnt
        and all(z.startswith("/sso/") for z in _root_mnt)
        and _destination_mnt.startswith("/sso/auth/login?next=/sso/auth/account"),
        f"{_destination_mnt!r} / without prefix: {[z for z in _root_mnt if not z.startswith('/sso/')]}")

# And the rule itself, mechanically: Where `public_base()` supplies a base,
# `_checked_base()` supplies EXACTLY the same, and where it stays empty, the method raises. Two paths,
# one result — otherwise they are two rules again, and the gap sits in the difference.
for _lab, _auth_x in (("with base_url", _a_api), ("without base_url", _a_path)):
    for _case in (REAL, "http://auth.example.com/", "https://app-b.example.com",
                  "https://" + EVIL, _UNDER, ""):
        _pb = _auth_x.public_base(candidate=_case)
        try:
            _gb, _threw = _auth_x._checked_base(_case), False
        except ConfigError:
            _gb, _threw = "", True
        r.check(f"one rule ({_lab}): public_base == _checked_base for {_case!r}",
                _gb == _pb and _threw == (not _pb),
                f"public_base={_pb!r} _checked_base={_gb!r} raised={_threw}")

# ── A foreign registration occupied the login identifier of an account ────────
# Finding R4-12 (third audit). Registration checked the two name spaces only SEPARATELY:
# `email_taken` against users.email, `get_user_by_name` against users.username. But `find_user` in the
# default mode "both" searches BOTH columns and lets the e-mail win with an @. Thereby
# a stranger occupied the identifier of an existing account — the owner (even an admin) got
# 401 despite the correct password, and /auth/password from then on checked a foreign secret.

PW_HOLDER, PW_EVE = "Secret12345!abc", "Attacker12345!x"


def _sign_in(client, identifier, password=PW_HOLDER):
    return client.post("/auth/login", data={"username": identifier, "password": password, "next": "/"},
                       follow_redirects=False)


# Direction 1: the stranger's E-MAIL is the owner's username.
auth_n1, app_n1 = _app(allow_signup=True, signup_require_email=True, csrf_enabled=False)
boss1 = auth_n1.create_user("chef@example.com", password=PW_HOLDER, is_admin=True)
c_n1 = TestClient(app_n1)
r.check("precondition: the owner gets in with his identifier",
        _sign_in(c_n1, "chef@example.com").status_code == 303,
        "without this starting point the rest of the check says nothing")
c_n1.cookies.clear()

attack1 = c_n1.post("/auth/register",
                     data={"username": "eve", "password": PW_EVE,
                           "email": "chef@example.com", "next": "/"}, follow_redirects=False)
r.check("a registration whose E-MAIL is the username of an account is rejected",
        attack1.status_code == 409, f"HTTP {attack1.status_code} — the identifier is taken")
r.check("...and creates no account", auth_n1.store.get_user_by_name("eve") is None,
        "the account is in the database despite the rejection")
r.check("...the identifier still points to the owner",
        (auth_n1.find_user("chef@example.com") or {}).get("id") == boss1,
        "find_user resolves to a foreign account")
r.check("...and the owner can still sign in",
        _sign_in(c_n1, "chef@example.com").status_code == 303,
        "locked out — with the correct password")

# Direction 2 (the more dangerous one): the stranger's USERNAME is the owner's e-mail.
auth_n2, app_n2 = _app(allow_signup=True, signup_require_email=True, csrf_enabled=False)
boss2 = auth_n2.create_user("chef", password=PW_HOLDER, email="chef@example.com", is_admin=True)
c_n2 = TestClient(app_n2)
attack2 = c_n2.post("/auth/register",
                     data={"username": "chef@example.com", "password": PW_EVE,
                           "email": "eve@example.com", "next": "/"}, follow_redirects=False)
r.check("a registration whose USERNAME is the e-mail of an account is rejected",
        attack2.status_code == 409, f"HTTP {attack2.status_code} — the identifier is taken")
r.check("...and the e-mail identifier still points to the owner",
        (auth_n2.find_user("chef@example.com") or {}).get("id") == boss2,
        "the identifier was taken over")

# The legitimate path stays open — otherwise the guard would just be a broken registration.
fresh = c_n2.post("/auth/register",
                   data={"username": "new", "password": "New12345!abcdxx",
                         "email": "new@example.com", "next": "/"}, follow_redirects=False)
r.check("a registration with free identifiers still goes through", fresh.status_code == 303,
        f"HTTP {fresh.status_code}: {fresh.text[:120]}")

# And the same character string in both columns of the SAME account is no collision — in
# e-mail mode the address is the username, that is the intended path.
auth_n3, app_n3 = _app(allow_signup=True, signup_require_email=True,
                       login_identifier="email", csrf_enabled=False)
solo = TestClient(app_n3).post("/auth/register",
                               data={"password": "Single-Path-2468!", "email": "solo@example.com",
                                     "next": "/"}, follow_redirects=False)
r.check("in e-mail mode the address remains the username at the same time", solo.status_code == 303,
        f"HTTP {solo.status_code}: {solo.text[:120]}")

# The guard sits in create_user, not only in the route: CLI, invitation and creation from
# OIDC/LDAP/SAML pass through here.
for was, call in (("a username that is a foreign e-mail",
                  lambda: auth_n2.create_user("chef@example.com", password=PW_EVE)),
                 ("an e-mail that is a foreign username",
                  lambda: auth_n2.create_user("secondaccount", password=PW_EVE, email="chef"))):
    try:
        call()
        arisen = True
    except ConfigError:
        arisen = False
    r.check(f"create_user does not accept {was}", not arisen,
            "the account is created — then the check in the route alone does not help")

# The collision must not arise via the admin panel either.
c_adm = TestClient(app_n2)
c_adm.cookies.set(auth_n2.cfg.session_cookie,
                  auth_n2.store.create_session(boss2, 3600, True, "password"))
for slot, body in (("E-Mail", {"username": "eve2", "email": "chef@example.com"}),
                      ("Benutzername", {"username": "chef@example.com", "email": "e2@example.com"})):
    response_adm = c_adm.post("/auth/admin/api/users", json=body)
    r.check(f"the admin API rejects a taken identifier in the field {slot}",
            response_adm.status_code == 409,
            f"HTTP {response_adm.status_code}: {response_adm.text[:120]}")

# Invitation: The address comes from the token there, not from the form — the guard must
# hit this path too, otherwise an invitation creates an account on a taken identifier.
# Since N6 the base must itself be proven (`_checked_base`) — a freely invented host
# no longer goes into a sent link. Loopback stands for it here; only the token is checked
# anyway, not the link.
_invitation = auth_n2.create_invite("chef@example.com", "http://127.0.0.1:8000")["token"]
response_inv = c_n2.post("/auth/register",
                        data={"username": "eve3", "password": PW_EVE, "invite": _invitation,
                              "next": "/"}, follow_redirects=False)
r.check("an invitation to a taken identifier is rejected",
        response_inv.status_code == 409,
        f"HTTP {response_inv.status_code}: {response_inv.text[:120]}")
r.check("...and creates no account", auth_n2.store.get_user_by_name("eve3") is None,
        "the account is in the database despite the rejection")

# And the machine path: a service account has no login, but its name is still an
# identifier in the shared space (`find_user` searches it too).
try:
    auth_n2.create_service("chef@example.com")
    _service_arose = True
except ConfigError:
    _service_arose = False
r.check("create_service does not accept a taken identifier", not _service_arose,
        "the service account is created — and occupies the admin's identifier")

# Legacy stock: in a database from BEFORE the fix the collision is already there. Then
# /auth/password at least must not check the other person's secret (chain R4-12 + R4-10).
auth_old, app_old = _app(csrf_enabled=False)
victim_old = auth_old.create_user("chef", password=PW_HOLDER, email="chef@example.com")
# Past the guard = legacy stock: a raw INSERT without bucket (since G12c the store
# itself rejects the collision — the path of a foreign writer remains).
from tinysesam.store import now as _now  # noqa: E402
eve_old = auth_old.store._exec("INSERT INTO users(username, display_name, created_at) VALUES (?,?,?)",
                               ("chef@example.com", "chef@example.com", _now())).lastrowid
auth_old.set_password(eve_old, PW_EVE)
r.check("precondition: the attacker's identifier resolves to the foreign account",
        (auth_old.find_user("chef@example.com") or {}).get("id") == victim_old,
        "without this ambiguity the test checks nothing")
c_old = TestClient(app_old)
c_old.cookies.set(auth_old.cfg.session_cookie,
                  auth_old.store.create_session(eve_old, 3600, True, "password"))
foreign = c_old.post("/auth/password", json={"current": PW_HOLDER, "new": "New12345!abcdxx"})
r.check("/auth/password does not accept the password of a FOREIGN account",
        foreign.status_code == 403,
        f"HTTP {foreign.status_code} — the route is an oracle for foreign passwords")
r.check("...and the foreign password remains valid unchanged",
        auth_old._check_password("chef", PW_HOLDER) is not None,
        "the victim's secret was overwritten")
own = c_old.post("/auth/password", json={"current": PW_EVE, "new": "New12345!abcdxx"})
r.check("...but still checks the own one", own.status_code == 200,
        f"HTTP {own.status_code}: {own.text[:120]}")

# And the stock itself? New collisions have been prevented by the database since G12c (trigger over the
# counting buckets, tests/test_identifier_space.py); one that is already in there (here: raw INSERT of a
# foreign writer) the guard can only REPORT, and exactly that it must do at startup: Without a
# line, a locked-out owner stays inexplicable.


def _start_log(db_path):
    """Build an instance on this database and record what it says at startup."""
    buffer = io.StringIO()
    check = logging.StreamHandler(buffer)
    seclog.addHandler(check)
    try:
        TinySesam(TinySesamConfig(db_path=db_path, cookie_secure=False))
    finally:
        seclog.removeHandler(check)
    return buffer.getvalue()


# The foreign writer's row without bucket again, as directly after the raw INSERT: Since then
# another path has filled it in (since G2 every successful sign-in cleans up from the account's watermark
# and looks it up via `account_by_bucket`). Without this the probe no longer measures whether
# `identifier_collisions` fills it in itself.
auth_old.store._exec("UPDATE users SET folded_name = NULL, folded_mail = NULL WHERE id = ?", (eve_old,))
r.check("precondition: the cross collision really is in the database",
        len(auth_old.store.identifier_collisions()) == 1,
        f"{[dict(z) for z in auth_old.store.identifier_collisions()]} — then the test measures nothing")
_text_k = _start_log(auth_old.cfg.db_path)
r.check("startup reports an identifier collision in the existing stock", "identifier collision(s) in existing data" in _text_k,
        f"silent: {_text_k[:120]!r} — nobody learns why an account can no longer get in")
r.check("...and names both accounts involved",
        f"user_id={eve_old}" in _text_k and f"user_id={victim_old}" in _text_k,
        f"without IDs the message cannot be worked through: {_text_k[:200]!r}")
# B-regression-7: Until this round the same message advised "Change one of the two identifiers
# (admin panel or CLI)" — and neither of them can do that. The admin API knows create, lock,
# roles, password and keys, but no route for renaming; the CLI does not create accounts
# at all. The operator to whom startup had just reported a collision thus ran into two
# doors that do not exist. Therefore not the wording is measured, but that the named
# paths exist. Since self-service (2026-09-25) there is `change_username` — the message
# names it instead of the `UPDATE users` by hand, and the path really resolves the collision (below).
r.check("...and names paths that really exist (change_username, store.set_email)",
        "store.set_email" in _text_k and hasattr(auth_old.store, "set_email")
        and "auth.change_username" in _text_k and hasattr(auth_old, "change_username"),
        f"{_text_k[:320]!r}")
r.check("...and no longer sends anybody to the UPDATE by hand",
        "UPDATE users" not in _text_k, f"{_text_k[:320]!r}")
# Since G13 (2026-09-26) panel and CLI can rename — the message names both, and what is measured
# again is that the named paths exist: the route in the admin router and the command in the CLI.
# Until then this check recorded the opposite ("neither in the admin panel nor in the CLI"), because it
# was true at the time.
from tinysesam.admin import build_admin_router as _bar  # noqa: E402
import tinysesam.__main__ as _cli_module  # noqa: E402
_routes_k = {getattr(_rt, "path", "") for _rt in _bar(auth_old).routes}
r.check("...and names panel and CLI — both paths really exist",
        "/api/users/<id>/username" in _text_k and "/api/users/{uid}/username" in _routes_k
        and "tinysesam rename" in _text_k and callable(getattr(_cli_module, "_rename", None))
        and "neither in the admin panel nor in the CLI" not in _text_k,
        f"{_text_k[:420]!r}, routes: {sorted(p for p in _routes_k if 'username' in p)}")
# The named path works: renaming resolves the collision, startup is silent afterwards.
auth_old.change_username(eve_old, "eve-renamed")
r.check("...and auth.change_username really resolves the collision",
        not auth_old.store.identifier_collisions()
        and "identifier collision(s) in existing data" not in _start_log(auth_old.cfg.db_path),
        f"{[dict(z) for z in auth_old.store.identifier_collisions()]}")

# Integration of the round: The message names `store.set_email(...)` — and exactly this method takes
# the confirmation note ALONG since B-bypass-8 (default: unconfirmed). Whoever follows the message to
# resolve a collision on an admin's account thereby incidentally deletes the proof of his address.
# That is fail-closed and right — but it must not surprise the operator, and `verified=True`
# is the way to keep a real proof. Both are measured together: the sentence in the
# message AND the behavior behind it. If either goes away, the check turns red.
r.check("...and says that store.set_email takes the confirmation note along",
        "email_verified=0" in _text_k and "verified=True" in _text_k,
        f"{_text_k[:400]!r} — the operator follows the message and silently loses the proof")
auth_old.store.set_email_verified(victim_old, True)
auth_old.store.set_email(victim_old, "chief-new@example.com")
r.check("...and so it is: the named path stores the new address unconfirmed",
        auth_old.store.get_user(victim_old)["email_verified"] == 0,
        "set_email leaves the proof of the OLD address in place — then the message is wrong, "
        "and an address change is a bootstrap path again (B-bypass-8)")
auth_old.store.set_email(victim_old, "chief-taken@example.com", verified=True)
r.check("...and verified=True keeps it, as the message promises",
        auth_old.store.get_user(victim_old)["email_verified"] == 1,
        "verified=True does not carry the proof — then the message names a path that does not exist")

# Counter-check, otherwise the message would be noise: In auth_n2 ONE account carries the same value in
# both own columns (chef / chef@example.com) — that is the intended path, no collision.
r.check("a database without cross collision stays silent",
        "identifier collision(s) in existing data" not in _start_log(auth_n2.cfg.db_path),
        "the same character string in both columns of the SAME account is reported as a collision")
# ── A GET removes the confirmed second factor (B2-1, audit round 3) ────
# Attack: The victim is fully signed in (password + TOTP) and clicks a link to /auth/totp/setup
# on a foreign page. The page called `totp_begin()` unconditionally and thereby wrote a
# new, unconfirmed secret over the old one: TOTP fell back to "unconfirmed", the ten
# recovery codes stayed orphaned, no audit line was created — and afterwards the
# password alone sufficed. CSRF protects nothing here: A GET carries no token, and `SameSite=Lax`
# (default) sends the session cookie along with a top-level navigation.
import pyotp  # noqa: E402
import time

auth_b21, app_b21 = _app()
uid_b21 = auth_b21.create_user("nina", password="dummy12345", email="nina@example.com")
secret_text_b21 = auth_b21.totp_begin(uid_b21)["secret"]
auth_b21.totp_confirm(uid_b21, pyotp.TOTP(secret_text_b21).at(time.time() - 30))
codes_b21 = auth_b21.generate_recovery_codes(uid_b21)
c_b21 = TestClient(app_b21, base_url="https://app.example.com")
c_b21.get("/auth/login")
c_b21.post("/auth/login", data={"username": "nina", "password": "dummy12345", "next": "/",
                                "_csrf": c_b21.cookies.get(auth_b21.cfg.csrf_cookie)},
           follow_redirects=False)
c_b21.post("/auth/totp", data={"code": pyotp.TOTP(secret_text_b21).now(), "next": "/",
                               "_csrf": c_b21.cookies.get(auth_b21.cfg.csrf_cookie)},
           follow_redirects=False)
session_b21 = auth_b21.store.get_session(c_b21.cookies.get(auth_b21.cfg.session_cookie))

# Precondition: Without these three lines the attack below measures nothing. They establish that
# a fully valid second factor really stands here that COULD be lost.
r.check("precondition: the second factor is confirmed",
        auth_b21.store.has_confirmed_totp(uid_b21), "without TOTP the attack checks nothing")
r.check("precondition: ten recovery codes are present",
        auth_b21.store.count_recovery_codes(uid_b21) == len(codes_b21) == 10,
        f"{auth_b21.store.count_recovery_codes(uid_b21)}")
r.check("precondition: the session is fully valid (CSRF on, SameSite=Lax)",
        bool(session_b21 and session_b21["mfa_ok"]) and auth_b21.cfg.csrf_enabled
        and auth_b21.cfg.cookie_samesite == "lax",
        f"mfa_ok={session_b21 and session_b21['mfa_ok']} csrf={auth_b21.cfg.csrf_enabled}")

ant_b21 = c_b21.get("/auth/totp/setup", headers={"Sec-Fetch-Site": "cross-site",
                                                 "Sec-Fetch-Mode": "navigate"})
r.check("a GET on the setup page does not revoke a confirmed TOTP",
        ant_b21.status_code == 409,
        f"HTTP {ant_b21.status_code} — otherwise a click on a foreign link suffices")
r.check("...the second factor is still there afterwards", auth_b21.store.has_confirmed_totp(uid_b21),
        "TOTP fell back to unconfirmed, the password alone suffices again")
r.check("...and the recovery codes still belong to a valid factor",
        auth_b21.store.count_recovery_codes(uid_b21) == 10
        and auth_b21.store.has_confirmed_totp(uid_b21)
        and auth_b21._verify_recovery_code(uid_b21, codes_b21[0]),
        f"{auth_b21.store.count_recovery_codes(uid_b21)} codes without confirmed TOTP = orphaned")

# Not only the route: The guard sits in the manager so that no own interface bypasses it.
try:
    auth_b21.totp_begin(uid_b21)
    thrown = ""
except StateError as exc:
    thrown = str(exc)
r.check("totp_begin() itself also refuses the overwrite", bool(thrown),
        "the method still writes through — every own interface opens the same gap")
r.check("the repelled attempt appears in the audit log",
        any(z["event"] == "totp_setup_denied" for z in auth_b21.store.recent_audit(50)),
        "the attempt leaves no trace")

# ── The same door, second half: the GET still generated secrets ─────────
# The finding text on B2-1 demands TWO things: refuse with confirmed TOTP **and** begin the
# setup only on explicit request (POST with CSRF token). At first only the
# first was implemented: For an account WITHOUT confirmed TOTP, every GET on
# /auth/totp/setup generated a fresh secret and thereby replaced a running
# setup attempt. No factor loss — but a foreign link invalidated the QR image just
# scanned (the confirmation then failed inexplicably) and triggered audit lines
# from outside.
auth_b7, app_b7 = _app()
uid_b7 = auth_b7.create_user("paul", password="dummy12345")
c_b7 = TestClient(app_b7, base_url="https://app.example.com")
c_b7.cookies.set(auth_b7.cfg.session_cookie,
                 auth_b7.store.create_session(uid_b7, 3600, True, "password"))
r.check("precondition: CSRF is on and the session cookie is SameSite=Lax",
        auth_b7.cfg.csrf_enabled and auth_b7.cfg.cookie_samesite == "lax",
        "without this situation a foreign link does not carry the cookie along — the test measures nothing")
page_html_b7 = c_b7.get("/auth/totp/setup")
r.check("a GET on the setup page generates no secret",
        page_html_b7.status_code == 200 and auth_b7.store.get_totp(uid_b7) is None,
        f"HTTP {page_html_b7.status_code}, secret={auth_b7.store.get_totp(uid_b7) is not None} "
        "— a GET that writes can be triggered from outside")
r.check("...the page shows instead the button that starts it explicitly",
        "/auth/totp/setup/start" in page_html_b7.text, "without the button the setup is walled off")
r.check("...and leaves no audit line",
        not any(z["event"] == "totp_setup_start" for z in auth_b7.store.recent_audit(20)),
        "audit noise that anybody can produce from outside")
csrf_b7 = c_b7.cookies.get(auth_b7.cfg.csrf_cookie)
start_b7 = c_b7.post("/auth/totp/setup/start", data={"_csrf": csrf_b7})
line_b7 = auth_b7.store.get_totp(uid_b7)
r.check("the POST with CSRF token sets up", start_b7.status_code == 200 and line_b7 is not None,
        f"HTTP {start_b7.status_code}: {start_b7.text[:120]}")
# B2-1 also promised the audit line — until 0.18.x the TOTP setup was invisible.
r.check("...and the setup appears in the audit log",
        any(z["event"] == "totp_setup_start" for z in auth_b7.store.recent_audit(20)),
        "the setup of a second factor leaves no trace")
before_b7 = line_b7["secret"]
foreign_b7 = c_b7.post("/auth/totp/setup/start", data={})           # no token = foreign page
r.check("a POST without CSRF token does not replace the running secret",
        foreign_b7.status_code == 403 and auth_b7.store.get_totp(uid_b7)["secret"] == before_b7,
        f"HTTP {foreign_b7.status_code} — the scanned QR image can be invalidated from outside")
across_b7 = c_b7.get("/auth/totp/setup", headers={"Sec-Fetch-Site": "cross-site",
                                                "Sec-Fetch-Mode": "navigate"})
r.check("...and a click on a foreign link just as little",
        across_b7.status_code == 200 and auth_b7.store.get_totp(uid_b7)["secret"] == before_b7,
        "the GET replaced the secret")
r.check("...the confirmation with the code from THIS secret arms it",
        auth_b7.totp_confirm(uid_b7, pyotp.TOTP(before_b7).at(time.time() - 30))
        and auth_b7.store.has_confirmed_totp(uid_b7),
        "the legitimate path is interrupted")

# The legitimate path must remain: set up where nothing exists yet …
auth_ok, app_ok = _app(csrf_enabled=False)
uid_ok = auth_ok.create_user("tom", password="dummy12345")
c_ok = TestClient(app_ok, follow_redirects=False)
c_ok.cookies.set(auth_ok.cfg.session_cookie,
                 auth_ok.store.create_session(uid_ok, 3600, True, "password"))
r.check("without set-up TOTP the setup page is still reachable",
        c_ok.get("/auth/totp/setup").status_code == 200, "the setup is walled off")
r.check("...and the start button sets up",
        c_ok.post("/auth/totp/setup/start").status_code == 200
        and auth_ok.store.get_totp(uid_ok) is not None, "the setup is walled off")
new_ok = auth_ok.store.get_totp(uid_ok)["secret"]
r.check("...and the confirmation arms the factor",
        auth_ok.totp_confirm(uid_ok, pyotp.TOTP(new_ok).at(time.time() - 30))
        and auth_ok.store.has_confirmed_totp(uid_ok))

# … and set up again after the regular switch-off (otherwise the fix would be a dead end).
auth_ok.totp_disable(uid_ok)
r.check("after the regular switch-off the setup is open again",
        c_ok.get("/auth/totp/setup").status_code == 200
        and c_ok.post("/auth/totp/setup/start").status_code == 200,
        "changing the authenticator would be impossible")

# Orphaned recovery codes (secret gone, codes still there) are cleaned up by the setup.
auth_v, _ = _app()
uid_v = auth_v.create_user("vera", password="dummy12345")
secret_text_v = auth_v.totp_begin(uid_v)["secret"]
auth_v.totp_confirm(uid_v, pyotp.TOTP(secret_text_v).at(time.time() - 30))
auth_v.generate_recovery_codes(uid_v)
auth_v.store.delete_totp(uid_v)          # only the secret gone — the codes remain
auth_v.totp_begin(uid_v)
r.check("a new setup leaves no orphaned recovery codes",
        auth_v.store.count_recovery_codes(uid_v) == 0,
        f"{auth_v.store.count_recovery_codes(uid_v)} codes remain valid, "
        "although they no longer fit any authenticator")
# ── A backward jump of the clock revived expired things (B6-9) ──────────────────
# NTP correction, a Pi without a backup battery, a VM snapshot: The wall clock jumps back, and
# every deadline in the database was renegotiated — expired sessions counted again, an
# expired magic link could be redeemed, an old step-up was "fresh" again.
from tinysesam import store as _store_mod  # noqa: E402

# The clock on its own, with set wall and monotonic time.
_w, _m = [1000.0], [0.0]
_u = _store_mod._Clock(wall=lambda: _w[0], mono=lambda: _m[0])
_sequence = [_u.now()]
_w[0], _m[0] = 400.0, 10.0          # jump 600 s back, 10 s really elapsed
_sequence.append(_u.now())
_w[0], _m[0] = 2000.0, 20.0         # the wall clock jumps forward (NTP after boot)
_sequence.append(_u.now())
r.check("after a backward jump the clock keeps counting monotonically and follows forward",
        _sequence == [1000, 1010, 2000], f"{_sequence}")

auth_u, _ = _app()
uid_u = auth_u.create_user("time_of_day", password="dummy12345")
tok_u = auth_u.store.create_session(uid_u, 3600, True, "password")
raw_magic = auth_u.create_magic_token("login", user_id=uid_u, ttl_min=10)
now_u = _store_mod.now()
# Both expired 60 s ago …
auth_u.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (now_u - 60, auth_u.store.session_hash(tok_u)))
auth_u.store._exec("UPDATE magic_token SET expires_at=?", (now_u - 60,))
# … and then the wall clock jumps back an hour.
_real = _store_mod._CLOCK.wall
_store_mod._CLOCK.wall = lambda: _real() - 3600
try:
    r.check("an expired session stays expired after a backward jump",
            auth_u.store.get_session(tok_u) is None, "the session revives")
    r.check("an expired magic link stays expired",
            auth_u.redeem_magic(raw_magic, "login") is None, "the link can be redeemed again")
finally:
    _store_mod._CLOCK.wall = _real

# Across a restart: The database carries the state. Fresh clock, wall clock back an hour.
auth_n, _ = _app()
uid_n = auth_n.create_user("restart", password="dummy12345")
tok_n = auth_n.store.create_session(uid_n, 3600, True, "password")
now_n = _store_mod.now()
auth_n.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (now_n - 60, auth_n.store.session_hash(tok_n)))
auth_n.store.db.close()
_old_clock = _store_mod._CLOCK
_store_mod._CLOCK = _store_mod._Clock(wall=lambda: _real() - 3600)
_clock_log = io.StringIO()
_clock_h = logging.StreamHandler(_clock_log)
logging.getLogger("tinysesam").addHandler(_clock_h)
try:
    st_n = _store_mod.Store(auth_n.cfg.db_path)
    r.check("after a restart with the clock set back, the session stays expired",
            st_n.get_session(tok_n) is None, "the restart forgot the deadline")
    r.check("…and the lag of the system clock appears in the log",
            "system clock" in _clock_log.getvalue(), _clock_log.getvalue()[:200])
    st_n.db.close()
finally:
    _store_mod._CLOCK = _old_clock
    logging.getLogger("tinysesam").removeHandler(_clock_h)

# Across a restart up to the last SAVED state, not only up to the last event
# (A-B6-9-restart): A link and a session, expired two hours before the restart, without
# anything having been created afterwards. The Pi boots with a date a year back. Before, `Store()`
# knew only MAX(created_at/ts) and raised the clock to the time of creation — both counted
# again for their full remaining period.
_T = 1_800_000_000.0
_wall_n = [_T]


def _restart_after_2h(secure):
    """Creates link + session at T, lets 2 h pass, `secure(store)` saves (or not),
    restarts with the clock set back a year. → (link valid?, session valid?, clock_state)"""
    _store_mod._CLOCK = _store_mod._Clock(wall=lambda: _wall_n[0])
    _wall_n[0] = _T
    a = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "n.db"),
                                  cookie_secure=False))
    uid = a.create_user("pi", password="dummy12345")
    raw = a.create_magic_token("login", user_id=uid, ttl_min=15)
    tok = a.store.create_session(uid, 1800, False, "password")
    _wall_n[0] = _T + 7200
    secure(a.store)
    a.store.db.close()
    _store_mod._CLOCK = _store_mod._Clock(wall=lambda: _T - 365 * 86400)
    a.store = _store_mod.Store(a.cfg.db_path)
    applies = (a.peek_magic(raw, purpose="login") is not None, a.store.get_session(tok) is not None)
    # A writer whose clock is NOT raised (a second process on the same file, started before
    # the backup) must not overwrite the saved state downwards.
    _store_mod._CLOCK = _store_mod._Clock(wall=lambda: _T - 365 * 86400)
    a.store.CLOCK_SECURE_SEC = 0
    a.create_user("after-dem-boot")
    state = int(a.store.get_setting(a.store.CLOCK_STATE) or 0)
    a.store.db.close()
    return applies + (state,)


def _per_healthcheck(st):
    st._written = None                   # the probe is due, like every 30 s in the container
    st.write_probe()


def _per_write_access(st):
    st.CLOCK_SECURE_SEC = 0                   # "a minute has passed"
    st.set_setting("something", "1")


logging.getLogger("tinysesam").addHandler(_clock_h)
try:
    _hc = _restart_after_2h(_per_healthcheck)
    _sz = _restart_after_2h(_per_write_access)
finally:
    _store_mod._CLOCK = _old_clock
    logging.getLogger("tinysesam").removeHandler(_clock_h)
r.check("after a restart, what expired AFTER the last event stays expired "
        "(state from the write probe of the healthcheck)",
        _hc[:2] == (False, False), f"link valid: {_hc[0]}, session valid: {_hc[1]}")
r.check("…likewise with the state that an ordinary write access saves along",
        _sz[:2] == (False, False), f"link valid: {_sz[0]}, session valid: {_sz[1]}")
r.check("a writer with a non-raised clock does not reset the saved state",
        _hc[2] >= _T + 7200 and _sz[2] >= _T + 7200, f"clock_state={_hc[2]}/{_sz[2]}")

# `time.time` is not bound at import (A-B6-9-zeitpatch): An embedding app that sets the time forward
# in its tests thereby also sets TinySesam's clock forward. Bound, TinySesam never saw the
# patch — sessions and tokens never expired in the app's test.
from unittest import mock  # noqa: E402
import time as _time  # noqa: E402
_store_mod._CLOCK = _store_mod._Clock()          # fresh clock: the jump should not remain in the process
try:
    auth_p, _ = _app()
    uid_p = auth_p.create_user("zeitpatch", password="dummy12345")
    tok_p = auth_p.store.create_session(uid_p, 60, False, "password")
    _real_t = _time.time()
    with mock.patch("time.time", lambda: _real_t + 3600):
        _applies_p = auth_p.store.get_session(tok_p) is not None
finally:
    _store_mod._CLOCK = _old_clock
r.check("mock.patch('time.time') forward lets a session expire",
        not _applies_p, "TinySesam does not see the patched time (bound at import)")

# freezegun also replaces `time.monotonic` — by the frozen time on the EPOCH scale
# (`calendar.timegm`, ≈1.8e9), not by the uptime (T-13 attack, note on B6-9). The
# clock carried this step forward as elapsed time and jumped about 57 years ahead; on
# leaving freeze_time it fell back, and `clock_state` raised every later opening of the database
# permanently into the year 2083. Reproduced with set sources, exactly in freezegun values.
_T21, _OPERATION = 1_790_000_000.0, 200_000.0     # wall clock / real monotonic time (uptime)
_w21, _m21 = [_T21], [_OPERATION]
_u21 = _store_mod._Clock(wall=lambda: _w21[0], mono=lambda: _m21[0])
_f21 = [_u21.now()]
_w21[0] = _m21[0] = _T21 + 3600                  # with freeze_time(+1 h): both sources frozen
_f21.append(_u21.now())
_w21[0] = _m21[0] = _T21 + 3660                  # freezer.tick(60)
_f21.append(_u21.now())
_w21[0], _m21[0] = _T21 + 5, _OPERATION + 5        # left freeze_time: real sources are back
_f21.append(_u21.now())
r.check("freezegun (monotonic on the epoch scale) sets the clock forward exactly and not by decades",
        _f21[1:3] == [int(_T21) + 3600, int(_T21) + 3660],
        f"{[int(x - _T21) for x in _f21]} s from start — expected [0, 3600, 3660, …]")
r.check("…and after leaving it does not run backwards",
        _f21[3] >= _f21[2], f"{[int(x - _T21) for x in _f21]} s ab Start")
# (Mutation probe: remove the plausibility check of the monotonic step in `_Clock.now` →
# both red; check only the upper limit, i.e. carry a negative step forward → the second red.)

# The counter-check to the plausibility limit: The protection from B6-9 also holds after a long
# pause. Months without a request, and meanwhile the wall clock jumps back an hour — the
# clock carries the real elapsed time forward instead of following the wall clock that jumped back.
_w22, _m22 = [_T21], [_OPERATION]
_u22 = _store_mod._Clock(wall=lambda: _w22[0], mono=lambda: _m22[0])
_u22.now()
_pause = 200 * 86400
_w22[0], _m22[0] = _T21 + _pause - 3600, _OPERATION + _pause
r.check("after a 200-day pause the clock still protects against a backward jump",
        _u22.now() == int(_T21) + _pause, f"{_u22.now() - int(_T21) - _pause} s off")
# (Mutation probe: set the limit to one day → red.)

# The same class in the store (second attack round, konfig): `_clock_secured` and `_written`
# keep their own monotonic stamps. After a write under freezegun they stood on the
# epoch scale (≈1.8e9); afterwards the distance to the real monotonic time was negative and thus always
# "shorter than the period" — `clock_state` was no longer saved in the whole process (arithmetically
# for 57 years), and the write probe of /healthz checked only the connection.
_st23 = _store_mod.Store(str(Path(tempfile.mkdtemp()) / "clock23.db"))
_st23.set_setting("x", "0")


def _write_under_freezegun():
    # freezegun supplies `time.monotonic` on the epoch scale; reproduced without the dependency.
    with mock.patch("time.monotonic", _time.time):
        _st23.set_setting("x", "fg")


def _clock_state_back():
    # As if `clock_state` had last been saved two minutes ago (without `_exec`, so that
    # the stamps stay as the write under freezegun left them).
    _st23.db.execute("UPDATE setting SET value=? WHERE key=?",
                     (str(_store_mod.now() - 120), _st23.CLOCK_STATE))
    _st23.db.commit()
    return _store_mod.now() - 120


_write_under_freezegun()
_old23 = _clock_state_back()
_st23.write_probe()
r.check("after a write access under freezegun the write probe of /healthz writes again",
        int(_st23.get_setting(_st23.CLOCK_STATE)) > _old23,
        f"clock_state stayed {int(_st23.get_setting(_st23.CLOCK_STATE)) - _store_mod.now()} s behind — "
        "only the connection checked")
_write_under_freezegun()
_old23 = _clock_state_back()
_st23.set_setting("x", "1")
r.check("…and an ordinary write access saves clock_state along again",
        int(_st23.get_setting(_st23.CLOCK_STATE)) > _old23,
        f"clock_state stayed {int(_st23.get_setting(_st23.CLOCK_STATE)) - _store_mod.now()} s behind")
_st23.db.close()
# (Mutation probe: remove the condition `0 <=` in `Store._fresh` → both red.)


# ── pop_flow returned the same challenge twice (R3-8) ────────────────────
# Reading and deleting were two steps. Two callbacks with the same OIDC `state` (two
# threads, two workers on the same file) both read before one deleted. Reproduced
# deterministically: Between the SELECT of the first and its DELETE, a second
# worker (own connection, same file) consumes the same key.
auth_f, _ = _app()
st_a = auth_f.store
st_b = _store_mod.Store(auth_f.cfg.db_path)
st_a.put_flow("oidc:state", {"nonce": "n-1"})


class _Between:
    """Connection that lets the second worker take its turn after the flow is read."""

    def __init__(self, db):
        self._db, self.second = db, None

    def execute(self, sql, *args):
        cur = self._db.execute(sql, *args)
        if sql.startswith("SELECT data, expires_at FROM flow") and self.second is None:
            self.second = st_b.pop_flow("oidc:state")
        return cur

    def __getattr__(self, name):
        return getattr(self._db, name)


_zw = _Between(st_a.db)
st_a.db = _zw
first = st_a.pop_flow("oidc:state")
st_a.db = _zw._db
r.check("the second worker gets the flow state", _zw.second == {"nonce": "n-1"}, f"{_zw.second}")
r.check("…and the first then no longer — exactly one wins",
        first is None, f"both got {first}: challenge/state consumed twice")
st_a.put_flow("oidc:simple", {"x": 1})
r.check("without a race the flow comes out exactly once",
        st_a.pop_flow("oidc:simple") == {"x": 1} and st_a.pop_flow("oidc:simple") is None)
st_b.db.close()


# ── SQLite waited according to an unconscious default (B6-11) ─────────────────────
# How long a second writer waits before a sign-in fails with "database is locked"
# was Python's silent default (5 s). Now explicit — and readable on the connection.
import sqlite3 as _sqlite3  # noqa: E402
import threading as _threading  # noqa: E402

auth_b, _ = _app()
bt = auth_b.store.db.execute("PRAGMA busy_timeout").fetchone()[0]
r.check("busy_timeout is set deliberately (Store.BUSY_TIMEOUT_MS, above Python's 5 s)",
        bt == _store_mod.Store.BUSY_TIMEOUT_MS and bt > 5000, f"busy_timeout={bt}")
foreign = _sqlite3.connect(auth_b.cfg.db_path, isolation_level=None, check_same_thread=False)
foreign.execute("BEGIN IMMEDIATE")                  # a second writer holds the lock …
_free = _threading.Timer(0.5, lambda: foreign.execute("COMMIT"))
_free.start()
try:
    auth_b.store.put_flow("wait", {"ok": True})  # … and this writer waits instead of failing
    waited = True
except _sqlite3.OperationalError as e:
    waited = str(e)
_free.join(timeout=5)
foreign.close()
r.check("a writer waits for a briefly held lock instead of aborting",
        waited is True, f"{waited}")

# ── H-18 (a): a locked account gets a session via NO path ────────
# Every path had its own `disabled` check — or none: Sign-in link and passkey
# created a session for a locked account (only `current_user()` discarded it again),
# and an open confirmation link from registration even lifted the operator's lock.
# What is measured is therefore the class: all paths, then the question "is there a new session?".
from fastapi import HTTPException as _HTTPException  # noqa: E402
from starlette.requests import Request as _Request  # noqa: E402

auth_g, app_g = _app(csrf_enabled=False, pin_enabled=True, pin_login=True,
                     magiclink_enabled=True, apikey_enabled=True, passkey_enabled=False,
                     allow_signup=True, signup_require_email=True, signup_verify_email=True,
                     base_url=REAL)
auth_g.set_mailer(lambda to, subject, text, html=None: None)
uid_g = auth_g.create_user("gesperrt", password="Secret12345!abc", email="locked@example.com")
auth_g.set_pin(uid_g, "471193")
key_g = auth_g.create_api_key(uid_g, "bot")["key"]
old_g = auth_g.store.create_session(uid_g, 3600, True, "password")
magic_g = auth_g.create_magic_token("login", user_id=uid_g, email="locked@example.com")
# Locked directly in the store, not via the panel: The tokens and the old session thus
# remain — what is checked is that no PATH can use them, not that the panel cleans up.
auth_g.store.set_disabled(uid_g, True)


@app_g.get("/protected")
def _protected_g(u=Depends(auth_g.require_user)):
    return {"u": u["username"]}


def _sessions_g():
    return {z["token_hash"] for z in auth_g.store.list_sessions(uid_g)}


before_g = _sessions_g()
cg = TestClient(app_g)
cg.post("/auth/login", data={"username": "gesperrt", "password": "Secret12345!abc", "next": "/"},
        follow_redirects=False)
cg.post("/auth/pin", data={"username": "gesperrt", "pin": "471193", "next": "/"},
        follow_redirects=False)
magic_response = cg.post(f"/auth/magic/{magic_g}", follow_redirects=False)   # R4-02: POST redeems
r.check("sign-in link of a locked account is rejected",
        magic_response.status_code == 403, f"HTTP {magic_response.status_code}")

# The paths that do not run as a route here (passkey, OIDC, SAML, LDAP, chain) all end in
# `apply_factor` — the guard for the whole class sits there.
_empty = _Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
_through = []
for _factor in ("password", "pin", "passkey", "oidc", "saml", "magic", "totp"):
    try:
        auth_g.apply_factor(_empty, uid_g, _factor, "198.51.100.7")
        _through.append(_factor)
    except _HTTPException as e:
        if e.status_code != 403:
            _through.append(f"{_factor}:{e.status_code}")
r.check("apply_factor refuses every factor to a locked account", not _through,
        f"let through: {_through}")
r.check("…and every rejected attempt appears in the audit log (login_disabled)",
        sum(z["event"] == "login_disabled" for z in auth_g.store.recent_audit(50)) >= 8,
        f"{[z['event'] for z in auth_g.store.recent_audit(20)]}")
r.check("…and no new session arose via any path", _sessions_g() == before_g,
        f"{len(_sessions_g() - before_g)} new session(s) for a locked account")
cg.cookies.set(auth_g.cfg.session_cookie, old_g)
r.check("a session from before the lock opens nothing any more",
        cg.get("/protected").status_code == 401)
cg.cookies.clear()
r.check("an API key of the locked account opens nothing",
        cg.get("/protected", headers={"X-API-Key": key_g}).status_code == 401)

# The half session (first factor provided, TOTP open) does not become fully valid after a lock.
uid_h = auth_g.create_user("half", password="Secret12345!abc")
half_tok = auth_g.store.create_session(uid_h, 3600, False, "password")
auth_g.store.set_disabled(uid_h, True)
r.check("a half session does not become fully valid via TOTP after the lock",
        auth_g.complete_totp(half_tok) is None and auth_g.store.get_session(half_tok) is None,
        "complete_totp issued a full session to a locked account")

# The operator's lock holds against an open confirmation link.
admin_g = auth_g.create_user("boss-g", password="Secret12345!abc", is_admin=True)
uid_v = auth_g.create_user("pending", password="Secret12345!abc", email="pending@example.com")
auth_g.store.set_disabled(uid_v, True)                      # as after registration
verify_g = auth_g.create_magic_token("verify_email", user_id=uid_v, email="pending@example.com")
ca_g = TestClient(app_g)
ca_g.cookies.set(auth_g.cfg.session_cookie, auth_g.store.create_session(admin_g, 3600, True, "password"))
ca_g.post(f"/auth/admin/api/users/{uid_v}/disable", json={"disabled": True})
cv = TestClient(app_g)
r.check("the lock by the operator discards the open confirmation link",
        auth_g.peek_magic(verify_g, purpose="verify_email") is None,
        "the confirmation token can still be redeemed after the lock")
# (Mutation probe: `auth.store.revoke_user_magic_tokens(uid)` in admin.user_disable → `pass` → red.
# The check below stays green: Since the second attack round the lock holds even without
# the revocation, because `/auth/verify` no longer lifts an operator's lock — two guards.)
# POST, not GET: Since R4-02, GET only shows the confirmation page and redeems nothing.
cv.post(f"/auth/verify/{verify_g}", follow_redirects=False)
r.check("a confirmation link does not lift an operator's lock",
        bool(auth_g.store.get_user(uid_v)["disabled"]),
        "the link from registration unlocked the locked account again")

# The same via the real registration, with a waiting outbox (T-13 attack, mail × operation):
# The confirmation token arose only in the mail worker. If the admin locked the new account while
# the job was waiting (busy workers, slow mail server), the lock found nothing to
# discard — afterwards the token arose, the mail went out, and the link lifted the lock.
# Reproduced without threads: The job is held instead of started and executed only after the
# lock — exactly the order that a backlog produces.
_jobs_w: list = []


async def _nothing_w():
    return None


def _record_w(job, at_overflow=None):
    _jobs_w.append(job)
    return _nothing_w


_mails_w: list = []
auth_g.set_mailer(lambda to, subject, text, html=None: _mails_w.append((to, text)))
auth_g._outbox.afterwards = _record_w
try:
    TestClient(app_g).post("/auth/register", data={
        "username": "waits-still", "password": "New-Password-long-7xx", "email": "waits@example.org"})
    _new_w = auth_g.store.get_user_by_name("waits-still")
    _tok_w = auth_g.store._all("SELECT 1 FROM magic_token WHERE user_id=? AND purpose='verify_email' "
                               "AND used_at IS NULL", (_new_w["id"],)) if _new_w else []
    r.check("the confirmation token exists when the registration response goes out",
            bool(_new_w) and len(_jobs_w) == 1 and bool(_tok_w),
            f"account={bool(_new_w)}, jobs={len(_jobs_w)}, token={len(_tok_w)} — "
            "if it arises only in the outbox, a lock in the waiting window finds nothing")
    # (Mutation probe: create the token in `_dispatch` again — `auth.send_verify_email(...)` in the
    # job instead of `_verify_mail` in the request → red, here and in the mail check below. The
    # lock itself holds even then since the second attack round: `/auth/verify` no longer lifts a lock
    # of the operator — the second guard, checked via the public API below.)
    ca_g.post(f"/auth/admin/api/users/{_new_w['id']}/disable", json={"disabled": True})
    for _a in _jobs_w:
        _a()                                     # only now is the mail worker's turn
    _link_w = [re.search(r"/auth/verify/([\w\-]+)", t) for to, t in _mails_w if to == "waits@example.org"]
    for _m in filter(None, _link_w):
        cv.post(f"/auth/verify/{_m.group(1)}", follow_redirects=False)
    r.check("a lock in the outbox's waiting window holds against the confirmation link",
            bool(auth_g.store.get_user(_new_w["id"])["disabled"])
            and not auth_g.store.list_sessions(_new_w["id"]),
            "the belatedly created token lifted the operator's lock")
    r.check("…and no mail with a dead link goes out for the discarded token",
            not _link_w, f"{len(_link_w)} confirmation mail(s) sent after the lock")
    # (Mutation probe: remove the check for an open token in `_token_mail` → red.)
finally:
    del auth_g._outbox.afterwards              # back to the class method

# The same via the PUBLIC API (second attack round, konfig): An embedding app with
# its own registration has only `create_user`, `store.set_disabled` and `after_response(…
# send_verify_email …)` — exactly the pattern the core itself used until T-13. The token
# still arises in the mail worker there, i.e. AFTER a lock in the waiting window, and the lock
# finds nothing to discard. The cause sat in `/auth/verify`: It set `disabled`
# unconditionally to 0, whether the lock came from the operator or the confirmation was merely outstanding.
from fastapi.responses import PlainTextResponse as _TextResponse  # noqa: E402

_jobs_p: list = []
_mails_p: list = []


def _record_p(job, at_overflow=None):
    _jobs_p.append(job)
    return _nothing_w


@app_g.post("/app/signup")
def _app_signup_p(name: str):
    _uid = auth_g.create_user(name, password="New-Password#long-7xx", email=f"{name}@example.org")
    auth_g.store.set_disabled(_uid, True)                   # waits for the confirmation
    return auth_g.after_response(
        _TextResponse("Mail unterwegs"),
        lambda: auth_g.send_verify_email(_uid, f"{name}@example.org", REAL))


def _app_link_p(name):
    _t = [t for to, t in _mails_p if to == f"{name}@example.org"]
    _m = re.search(r"/auth/verify/([\w\-]+)", _t[-1]) if _t else None
    return _m.group(1) if _m else None


auth_g.set_mailer(lambda to, subject, text, html=None: _mails_p.append((to, text)))
auth_g._outbox.afterwards = _record_p
try:
    TestClient(app_g).post("/app/signup", params={"name": "app-locked"})
    _uid_p = auth_g.store.get_user_by_name("app-locked")["id"]
    ca_g.post(f"/auth/admin/api/users/{_uid_p}/disable", json={"disabled": True})
    for _a in _jobs_p:
        _a()                                     # the mail worker creates the token only now
    _jobs_p.clear()
    _link_p = _app_link_p("app-locked")
    r.check("Guard: the app sends its confirmation link only after the lock",
            bool(_link_p), f"Mails: {len(_mails_p)}")
    _response_p = cv.post(f"/auth/verify/{_link_p}", follow_redirects=False) if _link_p else None
    r.check("a confirmation link created AFTER the lock does not lift the operator's lock",
            bool(auth_g.store.get_user(_uid_p)["disabled"]) and not auth_g.store.list_sessions(_uid_p),
            f"HTTP {getattr(_response_p, 'status_code', None)}, disabled="
            f"{auth_g.store.get_user(_uid_p)['disabled']}, sessions={len(auth_g.store.list_sessions(_uid_p))}")
    r.check("…the attempt appears in the audit log (verify_blocked)",
            any(z["event"] == "verify_blocked" and z["username"] == "app-locked"
                for z in auth_g.store.recent_audit(30)),
            f"{[z['event'] for z in auth_g.store.recent_audit(8)]}")
    # (Mutation probe: in `/auth/verify` again `auth.store.set_disabled(uid, False)` instead of
    # `confirmation_enable` → red.)

    # Counter-check: Without an operator lock the same path unlocks the account — the
    # public API keeps its promise.
    TestClient(app_g).post("/app/signup", params={"name": "app-free"})
    _uid_f = auth_g.store.get_user_by_name("app-free")["id"]
    for _a in _jobs_p:
        _a()
    _link_f = _app_link_p("app-free")
    _response_f = TestClient(app_g).post(f"/auth/verify/{_link_f}", follow_redirects=False)
    r.check("…without an operator lock the link unlocks the app's account and signs in",
            _response_f.status_code == 303 and not auth_g.store.get_user(_uid_f)["disabled"]
            and bool(auth_g.store.list_sessions(_uid_f)),
            f"HTTP {_response_f.status_code}, disabled={auth_g.store.get_user(_uid_f)['disabled']}")
    # A renewed lock without operator note (`set_disabled(uid, True)`) does not downgrade an operator's
    # lock to "waiting for confirmation".
    auth_g.store.set_disabled(_uid_p, True)
    auth_g.send_verify_email(_uid_p, "app-locked@example.org", REAL)
    cv.post(f"/auth/verify/{_app_link_p('app-locked')}", follow_redirects=False)
    r.check("…and a later set_disabled(uid, True) does not turn the operator lock into a liftable one",
            bool(auth_g.store.get_user(_uid_p)["disabled"]),
            f"disabled={auth_g.store.get_user(_uid_p)['disabled']}")
    # (Mutation probe: `set_disabled` without `through_operator` sets a blind 1 again → red.)
finally:
    del auth_g._outbox.afterwards


# ── H-18 (c): every mail link arises from `base_url` — future ones too ─────────────
# The paths above (`_paths`) are a list by hand. A sixth sender would not be noticed
# there. Therefore mechanically: Every function in the package that calls `send_mail()` or `magic_url()`
# must be in this list — otherwise it sends links whose base nobody has measured.
import ast as _ast  # noqa: E402

# `_token_mail` is only the wrapper around `send_mail` (B6-12: token expires if sending
# fails) — the text including the link is built by its callers, and those are in `_paths`.
_MEASURED = {name for name, _ in _paths(_a_api, REAL)} | {"send_mail", "magic_url", "_token_mail"}
# The lock notice (ASVS 6.3.5, `_lockout_notice` with the inner `_send`) carries NO link — there
# is no base to measure. That this stays so is checked by tests/test_t13_decisions.py (no "://").
_MEASURED |= {"_lockout_notice", "_send"}
# Likewise the notice to the OLD address after a change (`confirm_email_change` with the inner
# `notice`, ASVS 6.3.7) — without a link; tests/test_self_service.py checks that (no "://").
_MEASURED |= {"confirm_email_change", "notice", "_change_request_notice"}
_sender = set()
for _file in sorted((ROOT / "tinysesam").glob("*.py")):
    _tree = _ast.parse(_file.read_text(encoding="utf-8"))
    for _fn in _ast.walk(_tree):
        if not isinstance(_fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        for _k in _ast.walk(_fn):
            if (isinstance(_k, _ast.Call) and isinstance(_k.func, _ast.Attribute)
                    and _k.func.attr in ("send_mail", "magic_url")):
                _sender.add(_fn.name)
r.check("Guard: it finds the known senders at all",
        {"send_password_reset", "send_login_link", "_verify_mail", "create_invite"} <= _sender,
        f"found: {sorted(_sender)} — without a hit the line below checks nothing")
r.check("every sender of mail links is in the measured list",
        _sender <= _MEASURED, f"unmeasured: {sorted(_sender - _MEASURED)} — add to `_paths`")


# ── Configuration check, T-13 area "Admin and configuration" ──────────────
from tinysesam import config_check as _kp2, security as _sec2  # noqa: E402


def _finding(**cfg):
    """(errors, warnings) for a config with a throwaway database."""
    cfg.setdefault("db_path", ":memory:")
    return _kp2.check_config(TinySesamConfig(**cfg))


def _names(items, *words):
    return any(all(w in x for w in words) for x in items)


# B3-3: an invalid trusted_proxies entry no longer invalidates the whole list …
r.check("B3-3: a valid entry works next to an invalid one",
        _sec2.is_trusted("198.51.100.7", ["proxy.intern", "198.51.100.0/24"]),
        "a hostname in the list raised, and the real proxy counted as foreign")
# (Mutation probe: is_trusted with a `try` around the whole any() again → red.)
r.check("...and the configuration check rejects the list",
        _names(_finding(trusted_proxies=["proxy.intern", "198.51.100.0/24"])[0], "trusted_proxies", "proxy.intern"))
r.check("...the default and real networks remain without finding",
        not _names(sum(_finding(trusted_proxies=["198.51.100.0/24", "::1"]), []), "trusted_proxies"))

# B3-6: stepup_methods is checked — a typo no longer silently removes the second factor.
r.check("B3-6: unknown step-up method is an error",
        _names(_finding(stepup_methods=["topt"])[0], "stepup_methods", "topt"))
r.check("...a switched-off one likewise (pin without pin_enabled)",
        _names(_finding(stepup_methods=["pin"])[0], "pin_enabled=False"))
r.check("...valid values remain without finding",
        not _names(sum(_finding(stepup_methods=["totp", "pin"], pin_enabled=True), []), "stepup_methods"))
try:
    TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), stepup_methods=["topt"]))
    _b36 = False
except _CfgErr:
    _b36 = True
r.check("...and the setup fails on it", _b36)

# B3-10: rp_id/origin are examined.
r.check("B3-10: rp_id that does not match the origin is an error",
        _names(_finding(passkey_enabled=True, rp_id="example.org", origin="https://auth.example.com")[0],
               "rp_id", "does not match"))
r.check("...origin with path is not an origin",
        _names(_finding(passkey_enabled=True, rp_id="example.com",
                       origin="https://auth.example.com/login")[0], "is not an origin"))
r.check("...developer values next to a public base_url are reported",
        _names(_finding(passkey_enabled=True, base_url="https://auth.example.com")[1], "origin", "base_url"))
r.check("...matching values remain without finding",
        not _names(sum(_finding(passkey_enabled=True, rp_id="example.com", origin="https://auth.example.com",
                               base_url="https://auth.example.com"), []), "origin"))

# B3-12: number fields with limits.
for _slot, _value in (("session_ttl_hours", 0), ("magiclink_ttl_min", 0), ("recovery_code_count", 0),
                     ("stepup_max_age_sec", -1), ("smtp_port", 70000), ("pin_min_length", 2),
                     ("session_ttl_hours", True)):
    r.check(f"B3-12: {_slot}={_value!r} is an error", _names(_finding(**{_slot: _value})[0], _slot))
r.check("...the defaults themselves all lie within their limits",
        not any(f in x for x in _finding()[0] for f in _kp2.NUMBER_LIMITS))
# (Mutation probe: comment out `_number_limits(config, error)` in check_config() → red.)

# T-13 attack (audit × configuration): `audit_retention_days` was added after NUMBER LIMITS and
# was not in it — its own check rejected only `< 0`. `True` counted as one day (gc()
# deleted the audit log down to the last day), seconds instead of days defeated the period,
# 10**20 made gc() abort with OverflowError. `oidc_revalidate_minutes` was missing likewise. Therefore
# now the class: Every number field of the config has a limit or stands here, with a reason.
import dataclasses as _dc  # noqa: E402
import typing as _typing  # noqa: E402

_WITHOUT_NUMBER_LIMIT: dict = {}      # field → reason. Empty: Every number field has a limit.
_types_cfg = _typing.get_type_hints(TinySesamConfig)
_number_fields = {f.name for f in _dc.fields(TinySesamConfig) if _types_cfg[f.name] in (int, float)}
r.check("Guard: it finds number fields of the config at all",
        {"session_ttl_hours", "smtp_port"} <= _number_fields, f"{sorted(_number_fields)}")
r.check("every number field of the config has a limit in NUMBER_LIMITS (or a justified exception)",
        not (_number_fields - set(_kp2.NUMBER_LIMITS) - set(_WITHOUT_NUMBER_LIMIT)),
        f"without limit: {sorted(_number_fields - set(_kp2.NUMBER_LIMITS) - set(_WITHOUT_NUMBER_LIMIT))}")
r.check("…and the exception list names only number fields without limit, each with a reason",
        all(f in _number_fields and f not in _kp2.NUMBER_LIMITS and str(g).strip()
            for f, g in _WITHOUT_NUMBER_LIMIT.items()), f"{_WITHOUT_NUMBER_LIMIT!r}")
# (Mutation probe: remove `audit_retention_days` from NUMBER_LIMITS → red.)
for _slot, _value in (("audit_retention_days", True), ("audit_retention_days", 30 * 86400),
                     ("audit_retention_days", 10 ** 20), ("audit_retention_days", -1),
                     ("oidc_revalidate_minutes", True), ("oidc_revalidate_minutes", 86400),
                     ("oidc_revalidate_minutes", -1)):
    r.check(f"{_slot}={_value!r} is an error", _names(_finding(**{_slot: _value})[0], _slot))
for _slot, _value in (("audit_retention_days", 3650), ("oidc_revalidate_minutes", 60)):
    r.check(f"…{_slot}={_value} remains without error", not _names(_finding(**{_slot: _value})[0], _slot))

# The upper limit (43200) catches a period in seconds only from one day (86400) — the preset's
# default, one hour, written in seconds (3600) passed silently: revalidation every 60
# hours instead of every hour, a revocation at the provider arrived 60 times later (second attack round,
# konfig). A period over one day therefore gets a warning that asks about the unit.
# 300 or 900 (five or 15 minutes in seconds) is caught by no limit — the docs now say so too.
def _rv_finding(minutes):
    return _kp2.check_config(TinySesamConfig.oidc_gateway(
        issuer="https://id.example.com", client_id="g", client_secret="s", base_url=REAL,
        db_path=":memory:", clients={"app.example.com": {"client_id": "a", "client_secret": "b"}},
        revalidate_minutes=minutes))


for _min in (3600, 7200, 43200):
    _f, _w = _rv_finding(_min)
    r.check(f"oidc_revalidate_minutes={_min} (over a day) warns about seconds instead of minutes",
            _names(_w, "oidc_revalidate_minutes", "seconds") and not _names(_f, "oidc_revalidate_minutes"),
            f"warnings: {[x[:80] for x in _w]}")
for _min in (60, 1440):
    r.check(f"…{_min} minutes remain without warning",
            not _names(_rv_finding(_min)[1], "oidc_revalidate_minutes"))
# (Mutation probe: remove the warning in `check_config` → red; set the threshold to 43200 → red.)
_rv_broken = "no Number"
try:
    _rv_hit = _names(_finding(oidc_revalidate_minutes=_rv_broken)[0], "oidc_revalidate_minutes")
except Exception as e:   # noqa: BLE001 — a crash of the check is the finding here
    _rv_hit = f"{type(e).__name__}: {e}"
r.check("…and a text instead of a number is a finding, not a crash of the check",
        _rv_hit is True, f"{_rv_hit!r}")

# The same class in the remaining combination checks that read a NUMBER_LIMITS field (second
# attack round, konfig): `int()` on `admin_claim_ttl_min` and `mfa_enrollment_grace_days` crashed
# before `_number_limits` could report the type — `TinySesam(cfg)` raised ValueError or
# OverflowError instead of a collected ConfigError. Until the final round this probe covered only
# the three fields known at the time; a new combination with `int()` via an intermediate variable
# (`w = getattr(config, "magiclink_ttl_min", 15); int(w)`) made check_config() crash again, and
# the suite stayed green (final finding konfig-3). Now over EVERY field from NUMBER_LIMITS, each with
# text, inf and nan, once with defaults and once behind the switches behind which today's
# combination checks lie (`_GATES`). Limit: A new combination behind a switch
# that is not in `_GATES` is reached only by the syntax-tree guard further below.
_GATES = {"admin_claim_token_file": "/run/x/admin.token", "mfa_enrollment": "grace"}
for _slot in _kp2.NUMBER_LIMITS:
    _crashes = []
    for _value in ("seven", float("inf"), float("nan")):
        for _to_it in ({}, _GATES):
            try:
                _kf = _names(_finding(**{_slot: _value}, **_to_it)[0], _slot, "is not an integer")
            except Exception as e:   # noqa: BLE001 — a crash of the check is the finding here
                _kf = f"{type(e).__name__}: {e}"
            try:
                TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "k.db"),
                                          **{_slot: _value}, **_to_it))
                _kb = "builds"
            except ConfigError as e:
                _kb = _slot in str(e) or "ConfigError without the field"
            except Exception as e:   # noqa: BLE001
                _kb = f"{type(e).__name__}: {e}"
            if _kf is not True or _kb is not True:
                _crashes.append(f"{_value!r}{' with switches' if _to_it else ''}: check_config {_kf!r} · startup {_kb!r}")
    r.check(f"{_slot}=text/inf/nan: collected ConfigError instead of a crash of the check",
            not _crashes, "; ".join(_crashes[:3]))
r.check("…the probe runs over the fields from NUMBER_LIMITS (not over an empty list)", len(_kp2.NUMBER_LIMITS) >= 10,
        f"{len(_kp2.NUMBER_LIMITS)} fields")
# (Mutation probe: the finding mutation `_mt = getattr(config, "magiclink_ttl_min", 15)` +
# `if int(_mt) > 600:` in check_config → red, `magiclink_ttl_min … ValueError`.)
# The combination checks themselves still apply:
r.check("…mfa_enrollment='grace' with 0 days remains an error",
        _names(_finding(mfa_enrollment="grace", mfa_enrollment_grace_days=0)[0], "mfa_enrollment='grace'"))
r.check("…admin_claim_token_file with admin_claim_ttl_min=0 remains a warning",
        _names(_finding(admin_claim_token_file="/run/x/admin.token", admin_claim_ttl_min=0)[1],
               "admin_claim_token_file"))
# (Mutation probe: replace `_integer` with `int(getattr(config, slot, 0) or 0)` → red.)
# The class in the code: A field from NUMBER_LIMITS is read by the check only via `_integer` (an
# integer or None) or in `_number_limits` itself. What a combination does afterwards (int(),
# comparison, calculation) then happens with an integer. Until the final round the
# guard reported an int() only if getattr(config, …) stood directly in it — the intermediate variable got
# through (final finding konfig-3). Now on the syntax tree by class, not by spelling:
# 1. A string that names exactly one NUMBER_LIMITS field stands as a key in NUMBER_LIMITS or
#    as a field name in `_integer(config, "<slot>")` — otherwise something else reads it (`getattr`,
#    `_an`, `vars(config)[…]`, `attrgetter`, a tuple over which a loop runs).
# 2. No attribute `.<slot>`, no matter under which name the config stands.
# 3. A `getattr` with a field name at runtime uses the value only as a truth value or text
#    (directly in `bool()`/`str()` or in a condition, also via `and`/`or`) — that crashes with
#    no value. `vars`, `__dict__`, `asdict`, `attrgetter`, `__getattribute__` are forbidden.
# 4. No `int()`/`float()`, regardless of on what.
# `_integer` and `_number_limits` are excluded from this: They ARE the read path.
# Limit: A field name that arises only at runtime and goes through a truth-value helper
# (`_an(config, name)`) does not crash but is evaluated wrongly; a helper outside
# config_check.py to which the check passes `config` lies outside this tree. Only
# the function probe above sees both — and only without switch or with `_GATES`.
import ast as _ast_k  # noqa: E402

_KP_READ_PATH = {"_integer", "_number_limits"}
_KP_FORBIDDEN = {"vars", "__dict__", "asdict", "attrgetter", "__getattribute__"}


def _kp_raw_numbers(tree):
    """Places in config_check.py that read or convert a number field past the read path."""
    fields = set(_kp2.NUMBER_LIMITS)
    parents = {c: k for k in _ast_k.walk(tree) for c in _ast_k.iter_child_nodes(k)}

    def function(k):
        while k in parents:
            k = parents[k]
            if isinstance(k, (_ast_k.FunctionDef, _ast_k.AsyncFunctionDef)):
                return k.name
        return "<module>"

    def only_truth_or_text(k):
        while isinstance(parents.get(k), _ast_k.BoolOp):
            k = parents[k]
        p = parents.get(k)
        if isinstance(p, _ast_k.Call) and isinstance(p.func, _ast_k.Name) and p.func.id in ("str", "bool"):
            return k in p.args
        if isinstance(p, (_ast_k.If, _ast_k.While, _ast_k.IfExp, _ast_k.Assert)):
            return p.test is k
        return isinstance(p, _ast_k.UnaryOp) and isinstance(p.op, _ast_k.Not)

    def is_limits_key_name(k):
        d = parents.get(k)
        z = parents.get(d)
        return (isinstance(d, _ast_k.Dict) and k in d.keys and isinstance(z, _ast_k.Assign)
                and any(getattr(t, "id", "") == "NUMBER_LIMITS" for t in z.targets))

    findings = []
    for k in _ast_k.walk(tree):
        where = function(k)
        if where in _KP_READ_PATH:
            continue
        p = parents.get(k)
        if isinstance(k, _ast_k.Constant) and isinstance(k.value, str) and k.value in fields:
            over_integer = (isinstance(p, _ast_k.Call) and isinstance(p.func, _ast_k.Name)
                              and p.func.id == "_integer" and len(p.args) >= 2 and p.args[1] is k)
            if not (over_integer or is_limits_key_name(k)):
                findings.append(f"{k.lineno}: {k.value!r} in {where} not read via _integer")
        elif isinstance(k, _ast_k.Attribute) and (k.attr in fields or k.attr in _KP_FORBIDDEN):
            findings.append(f"{k.lineno}: .{k.attr} in {where}")
        elif isinstance(k, _ast_k.Name) and k.id in _KP_FORBIDDEN:
            findings.append(f"{k.lineno}: {k.id} in {where}")
        elif isinstance(k, _ast_k.Call) and isinstance(k.func, _ast_k.Name):
            if k.func.id in ("int", "float"):
                findings.append(f"{k.lineno}: {k.func.id}() in {where}")
            elif (k.func.id == "getattr" and not (len(k.args) > 1 and isinstance(k.args[1], _ast_k.Constant))
                  and not only_truth_or_text(k)):
                findings.append(f"{k.lineno}: getattr with runtime name in {where}, value not only used as truth value/text")
    return findings


_kp_tree = _ast_k.parse((ROOT / "tinysesam" / "config_check.py").read_text(encoding="utf-8"))
_kp_getattr = [k for k in _ast_k.walk(_kp_tree) if isinstance(k, _ast_k.Call)
               and isinstance(k.func, _ast_k.Name) and k.func.id == "getattr"]
_kp_integer = [k for k in _ast_k.walk(_kp_tree) if isinstance(k, _ast_k.Call)
                and isinstance(k.func, _ast_k.Name) and k.func.id == "_integer"]
r.check("Guard: it finds the read accesses of the check at all",
        len(_kp_getattr) >= 20 and len(_kp_integer) >= 3, f"getattr {len(_kp_getattr)}, _integer {len(_kp_integer)}")
_kp_raw = _kp_raw_numbers(_kp_tree)
r.check("no combination check reads a number field past the read path _integer or converts itself",
        not _kp_raw, f"{_kp_raw}")


# Self-probe on the syntax tree (without text anchor): Every spelling is inserted at the front of check_config();
# only the findings it brings NEW are counted (a finding in the existing stock would otherwise carry the probe).
def _kp_with(snippet):
    tree = _ast_k.parse((ROOT / "tinysesam" / "config_check.py").read_text(encoding="utf-8"))
    fn = next(k for k in tree.body if isinstance(k, _ast_k.FunctionDef) and k.name == "check_config")
    fn.body[0:0] = _ast_k.parse(snippet).body
    return set(_kp_raw_numbers(tree)) - set(_kp_raw)


_kp_overlooked = [x for x in (
    '_mt = getattr(config, "magiclink_ttl_min", 15)\nif int(_mt) > 600:\n    pass',   # the finding
    '_mt = getattr(config, "magiclink_ttl_min", 15)\nif _mt > 600:\n    pass',        # without int()
    'if config.magiclink_ttl_min > 600:\n    pass',
    '_f = "smtp_port"\nif getattr(config, _f) > 1:\n    pass',
    'for _f in ("smtp_port",):\n    if getattr(config, _f) > 1:\n        pass',
    'for _f in fields_from_elsewhere():\n    if getattr(config, _f) > 1:\n        pass',
    'if vars(config)["pin_min_length"] > 4:\n    pass',
    'if config.__dict__.get(name, 0) > 4:\n    pass',
    'for _k, _v in vars(config).items():\n    if _v > 4:\n        pass',
    'if asdict(config).get(name, 0) > 4:\n    pass',
    'if operator.attrgetter("pin_min_length")(config) > 4:\n    pass',
    'if _an(config, "smtp_timeout"):\n    pass',
    'if float(str(getattr(config, "admin_path", ""))) > 1:\n    pass',
    'n = getattr(config, name, 0) or 0\nif n > 5:\n    pass') if not _kp_with(x)]
r.check("Guard self-probe: every spelling of a raw number read path is noticed",
        not _kp_overlooked, f"overlooked: {_kp_overlooked}")
_kp_false_alarm = [x for x in (
    '_x = _integer(config, "magiclink_ttl_min")\nif _x is not None and _x > 600:\n    pass',
    'if str(getattr(config, name, "") or "").strip():\n    pass',
    'if not getattr(config, name, None) or _an(config, "demo_mode"):\n    pass') if _kp_with(x)]
r.check("…and the read path itself remains without finding", not _kp_false_alarm, f"false alarm: {_kp_false_alarm}")
# (Mutation probes, each individually → red: remove rule 1; remove rule 2; remove rule 3;
# skip the forbidden names (`vars`, `asdict`); take `int`/`float` out of rule 4;
# `only_truth_or_text` always true; remove the deduction of the stock in `_kp_with`; in
# `_combinations` `getattr(config, "session_ttl_hours", 0)` again → the guard names the line;
# in check_config `if (getattr(config, "smtp_timeout", 0) or 0) > 200:` (comparison without int()) → red.)

# H-11 / B3-9: deny-by-default at the forward-auth gate.
_gw = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="g", client_secret="s",
                                   base_url="https://auth.example.com", db_path=":memory:")
r.check("H-11/B3-9: gateway preset without groups and without clients warns about the open gate",
        _names(_kp2.check_config(_gw)[1], "open gate", "OIDC"))
_gw2 = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="g", client_secret="s",
                                    base_url="https://auth.example.com", db_path=":memory:",
                                    allowed_groups=["employee"])
r.check("...with allowed_groups the warning stays silent", not _names(_kp2.check_config(_gw2)[1], "open gate"))
r.check("...open registration in front of forward-auth is reported",
        _names(_finding(forward_auth_enabled=True, allow_signup=True)[1], "self-registration"))
r.check("...without forward-auth no gate, no message",
        not _names(_finding(allow_signup=True)[1], "self-registration"))

# B3-16: combinations.
r.check("B3-16: e-mail confirmation without mandatory address is an error",
        _names(_finding(allow_signup=True, signup_verify_email=True, signup_require_email=False,
                       base_url="https://auth.example.com")[0], "signup_require_email=False"))
r.check("...cookie_domain that does not cover base_url is an error",
        _names(_finding(cookie_domain=".example.org", base_url="https://auth.example.com")[0], "cookie_domain"))
r.check("...admin_path without leading slash is an error",
        _names(_finding(admin_path="admin")[0], "admin_path"))
r.check("...a shorter session without \"stay signed in\" than with it is reported",
        _names(_finding(session_ttl_hours=2, session_ttl_transient_hours=12)[1], "session_ttl_transient_hours"))
# `True` is not an hour count: `_number_limits` reports the type error, a combination warning
# "longer than session_ttl_hours=True" was nevertheless added until the final round (the combination read
# past the read path `_integer`). (Mutation probe: in `_combinations` again
# `getattr(config, "session_ttl_hours", 0)` with `isinstance(…, int)` → red.)
_tt_f, _tt_w = _finding(session_ttl_hours=True, session_ttl_transient_hours=12)
r.check("...session_ttl_hours=True: only the type error, no combination warning beside it",
        _names(_tt_f, "session_ttl_hours=True", "is not an integer") and not _names(_tt_w, "is longer than"),
        f"errors {_tt_f} · warnings {_tt_w}")

# B3-8: demo mode has technical barriers.
r.check("B3-8: demo_mode next to a real sign-in path is an error",
        _names(_finding(demo_mode=True, forward_auth_enabled=True)[0], "demo_mode"))
_demo_db = str(Path(tempfile.mkdtemp()) / "t.db")
_inventory = TinySesam(TinySesamConfig(db_path=_demo_db))
_inventory.create_user("real", password="Secret12345!abc")
try:
    TinySesam(TinySesamConfig(db_path=_demo_db, demo_mode=True))
    _b38 = False
except _CfgErr:
    _b38 = True
r.check("...demo_mode on a database with existing accounts fails at setup",
        _b38 and _inventory.store.get_user_by_name("demoadmin") is None,
        "before, an admin with a known password silently arose there")
# Counter-check: A real demo starts again, even with visitors registered in the meantime.
_demo_db2 = str(Path(tempfile.mkdtemp()) / "t.db")
_d1 = TinySesam(TinySesamConfig(db_path=_demo_db2, demo_mode=True))
_d1.create_user("visitor", password="Secret12345!abc")
try:
    TinySesam(TinySesamConfig(db_path=_demo_db2, demo_mode=True))
    _b38b = True
except _CfgErr:
    _b38b = False
r.check("...a real demo restarts nevertheless (also with visitors)", _b38b)
# (Mutation probe: remove the existing-stock check before seed_demo in the constructor → red.)

# B3-14: validate() has a caller — router() checks again before building.
_a314, _ = _app()
_a314.cfg.cookie_samesite = "Strict"
try:
    _a314.router()
    _b314 = False
except _CfgErr as _e:
    _b314 = "cookie_samesite" in str(_e)
r.check("B3-14: a config broken after the constructor fails at router()", _b314)
_a314b, _ = _app()
_a314b.cfg.base_url = "https://auth.example.com"          # permitted change
_a314b.cfg.lang = "de"
try:
    _a314b.router()
    _b314b = True
except _CfgErr:
    _b314b = False
r.check("...a permitted change (language, address) still builds", _b314b)
r.check("...and validate() still returns a list (errors + warnings)",
        isinstance(TinySesamConfig(db_path=":memory:").validate(), list))
# (Mutation probe: remove `self._recheck()` in router() → red.)

# A2: The constructor's guards also apply before router()/admin_router(), not only config_check.
# Attack: admin_identifiers=["chef"] is safe as long as accounts do not arise by themselves. Whoever
# switched on allow_signup AFTER the constructor still built a router — the first visitor
# registered as "chef" and was first admin with access to the admin API.
def _retroactive(change, **cfg):
    a, _ = _app(**cfg)
    for k, v in change.items():
        setattr(a.cfg, k, v)
    result = []
    for build in (a.router, a.admin_router):
        try:
            build()
            result.append("")
        except _CfgErr as e:
            result.append(str(e))
    return result


for _title, _change, _cfg, _word in (
        ("admin_identifiers + allow_signup", {"allow_signup": True}, {"admin_identifiers": ["chef"]},
         "admin_identifiers"),
        ("admin_identifiers + oidc_auto_create", {"oidc_enabled": True, "oidc_auto_create": True},
         {"admin_identifiers": ["chef"], "base_url": "https://auth.example.com"}, "admin_identifiers"),
        ("login_identifier='bogus'", {"login_identifier": "bogus"}, {}, "login_identifier"),
        ("forward_headers with a line break", {"forward_headers": {"user": "X-User\r\nSet-Cookie: a=b"}}, {},
         "forward_headers"),
        ("totp_required=True", {"totp_required": True}, {}, "totp_required")):
    _erg = _retroactive(_change, **_cfg)
    r.check(f"A2: {_title} added afterwards fails at router() and admin_router()",
            all(_word in x and "after construction" in x for x in _erg), f"{_erg}")
# The attack itself: With the guard, no router arises at all, so no registration either.
_a2, _ = _app(admin_identifiers=["chef"], csrf_enabled=False, signup_require_email=False)
_a2.cfg.allow_signup = True
_admin_api = None
try:
    _app2 = FastAPI()
    _app2.include_router(_a2.router())
    with TestClient(_app2) as _c2:
        _c2.post("/auth/register", data={"username": "chef", "password": "Foreign-123456"})
        _c2.post("/auth/login", data={"username": "chef", "password": "Foreign-123456"})
        _admin_api = _c2.get("/auth/admin/api/users").status_code
except _CfgErr:
    pass   # the setup may be rejected — what is checked below is that nobody became admin
_boss = _a2.store.get_user_by_name("chef")
r.check("...and nobody registers as 'chef' to become first admin",
        (_boss is None or not _boss["is_admin"]) and _admin_api != 200,
        f"account={dict(_boss) if _boss else None}, Admin-API={_admin_api}")
r.check("...a permitted change next to admin_identifiers still builds",
        _retroactive({"lang": "en"}, admin_identifiers=["chef"]) == ["", ""])
# (Mutation probe: remove the `_bolt` call in _recheck → red.)

# A5: origin may be a list — py_webauthn also accepts several as expected_origin.
_two = ["https://a.example.com", "https://b.example.com"]
_f5, _w5 = _finding(passkey_enabled=True, rp_id="example.com", origin=_two, base_url="https://a.example.com")
r.check("A5: origin as a list of matching origins is no error",
        not _names(_f5, "origin") and not _names(_w5, "origin"), f"{_f5} {_w5}")
# (Mutation probe: in _proxies_and_passkey check `str(origin)` instead of the list again → red.)
r.check("...a bad entry in the list remains an error",
        _names(_finding(passkey_enabled=True, rp_id="example.com",
                       origin=["https://a.example.com", "https://b.example.com/path"])[0], "is not an origin"))
r.check("...an entry outside the rp_id likewise",
        _names(_finding(passkey_enabled=True, rp_id="example.com",
                       origin=["https://a.example.com", "https://a.example.org"])[0], "does not match"))
r.check("...an empty list too",
        _names(_finding(passkey_enabled=True, rp_id="example.com", origin=[])[0], "empty list"))
r.check("...and base_url outside the list is still reported",
        _names(_finding(passkey_enabled=True, rp_id="example.com", origin=_two,
                       base_url="https://c.example.com")[1], "base_url"))

# R5-1: scheme and user information of the login URL no longer come unchecked from the request.
_a51, _app51 = _app(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                    cookie_secure=True)
with TestClient(_app51) as _c51:
    _l1 = _c51.get("/auth/forward", headers={"x-forwarded-proto": "http",
                                             "x-forwarded-host": "app.example.com",
                                             "x-forwarded-uri": "/x"}).headers.get("x-tinysesam-location", "")
    _l2 = _c51.get("/auth/forward", headers={"host": "127.0.0.1",
                                             "x-original-url": "http://foreign.example@app.example.com/x"}
                   ).headers.get("x-tinysesam-location", "")
r.check("R5-1: X-Forwarded-Proto: http does not downgrade the login URL with cookie_secure",
        _l1.startswith("https://app.example.com/auth/login"), _l1)
r.check("...user information from X-Original-URL does not end up in front of the host of the login URL",
        _l2.startswith("https://app.example.com/auth/login") and "foreign.example@" not in _l2.split("?")[0],
        _l2)
_a51b, _app51b = _app(forward_auth_enabled=True, cookie_secure=False)
with TestClient(_app51b) as _c51b:
    _l3 = _c51b.get("/auth/forward", headers={"host": "127.0.0.1:8000", "x-forwarded-proto": "http"}
                    ).headers.get("x-tinysesam-location", "")
r.check("...local (loopback, without certificate) http remains allowed", _l3.startswith("http://127.0.0.1:8000/"), _l3)
# (Mutation probe: replace `_login_schema` with the raw scheme → the first two red.)
sys.exit(r.done())

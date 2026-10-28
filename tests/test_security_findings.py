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

r = Report("Sicherheit — nachgestellte Angriffe")


def _app(**cfg):
    """An instance on default values, only with its own database path."""
    tmp = tempfile.mkdtemp()
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False)
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── Role escalation via self-issued API keys ───────────────────────────────────
# Attack: A signed-in user without any role calls POST /auth/apikeys with
# {"roles": ["buchhaltung"]} and gets a key that carries exactly this role.
# The scope overwrote the account roles instead of intersecting them.
auth, app = _app()
auth.create_user("mitarbeiter", password="Geheim12345!abc")
nutzer = auth.store.get_user_by_name("mitarbeiter")


@app.get("/nur-buchhaltung")
def _geschuetzt(u=Depends(auth.require_role("buchhaltung"))):
    return {"gesehen_von": u["username"]}


r.check("Starting point: the account has no roles", auth.user_roles(nutzer) == [])

# Since the second audit the attempt is rejected already at ISSUING, not only at checking.
# Reason: a scope shrunk to `[]` meant "no scope, inherits everything" in the database — so the
# trimming would have made the key more powerful instead of weaker. An error is the only honest
# answer here; only the caller knows what was meant.
try:
    auth.create_api_key(nutzer["id"], name="probe", roles=["buchhaltung"])
    abgewiesen = None
except ConfigError as e:
    abgewiesen = e
r.check("a key with a role the owner does not have is not created in the first place",
        abgewiesen is not None,
        "the key was issued — and an empty scope inherits ALL roles in the database")
r.check("and the message names the requested role", "buchhaltung" in str(abgewiesen or ""),
        f"{str(abgewiesen)[:80]!r}")

# The key must not come into being via the HTTP route either — that is where the request comes from.
with TestClient(app) as c:
    c.cookies.set(auth.cfg.session_cookie,
                  auth.store.create_session(nutzer["id"], 3600, True, "password"))
    ueber_http = c.post("/auth/apikeys", json={"name": "probe", "roles": ["buchhaltung"]})
r.check("it is not created via POST /auth/apikeys either", ueber_http.status_code >= 400,
        f"HTTP {ueber_http.status_code} — the way the attack ran")

# Counter-check: whoever really has the role also gets it in the key — otherwise the fix would be
# a brake on functionality instead of a safeguard.
auth.set_roles(nutzer["id"], ["buchhaltung"]) if hasattr(auth, "set_roles") else None
nutzer2 = auth.store.get_user_by_name("mitarbeiter")
if auth.user_roles(nutzer2) == ["buchhaltung"]:
    key2 = auth.create_api_key(nutzer2["id"], name="echt", roles=["buchhaltung"])
    r.check("whoever has the role keeps it in the key", key2.get("roles") == ["buchhaltung"])
    with TestClient(app) as c:
        a2 = c.get("/nur-buchhaltung", headers={"Authorization": f"Bearer {key2['key']}"})
    r.check("and gets through with it", a2.status_code == 200, f"HTTP {a2.status_code}")

# ── OIDC: the flow must be bound to the browser ───────────────────────────────
# Attack: The attacker starts the flow on their side, signs in at the IdP as themselves and
# lures the victim to the callback URL. The victim silently lands in the attacker's account. An
# ordinary top-level GET suffices — SameSite does not help, because no cookie is needed at all.
# What is tested is the binding itself; a real IdP is not needed for that.
auth_o, app_o = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                     oidc_client_id="probe", oidc_client_secret="geheim",
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
with TestClient(app_o) as fremd:
    antwort = fremd.get(f"/auth/oidc/callback?code=egal&state={state}", follow_redirects=False)
r.check("a callback without a matching flow cookie is rejected",
        antwort.status_code == 400,
        f"HTTP {antwort.status_code} — the account substitution is back")

# The same substitution via cookie tossing (A-1): a neighbouring subdomain can set a cookie
# `Domain=.example.com` — but none with `__Host-`. So the flow cookie must carry the
# prefix, otherwise it plants the attacker's flow, value included, on the victim, and the
# victim lands in the attacker's account despite the prefixed session cookie.
auth_s, app_s = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                     oidc_client_id="probe", oidc_client_secret="geheim", cookie_secure=True,
                     base_url="https://auth.example.com")
auth_s.oidc._meta = dict(auth_o.oidc._meta)
with TestClient(app_s, base_url="https://auth.example.com") as angreifer:
    start = angreifer.get("/auth/oidc/start", follow_redirects=False)
    flow_wert = angreifer.cookies.get("__Host-tinysesam_oidc_flow")
r.check("with Secure the flow cookie is called __Host-tinysesam_oidc_flow", bool(flow_wert),
        f"set: {start.headers.get('set-cookie', '—')[:60]}")
state_s = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
with TestClient(app_s, base_url="https://auth.example.com") as opfer_b:
    opfer_b.cookies.set("tinysesam_oidc_flow", flow_wert or "")   # what a neighbouring subdomain can set
    antwort = opfer_b.get(f"/auth/oidc/callback?code=egal&state={state_s}", follow_redirects=False)
r.check("an unprefixed (planted) flow cookie does not bind the callback",
        antwort.status_code == 400 and auth_s.t("api.oidc_browser") in antwort.text,
        f"HTTP {antwort.status_code} {antwort.text[:80]} — login CSRF via cookie tossing")
# Counter-check: with the real, prefixed cookie the callback gets past the binding
# (and only fails at the exchange with the dummy-less IdP) — otherwise the case above tested nothing.
with TestClient(app_s, base_url="https://auth.example.com") as selbst:
    start = selbst.get("/auth/oidc/start", follow_redirects=False)
    state_s = parse_qs(urlparse(start.headers["location"]).query).get("state", [""])[0]
    try:
        antwort = selbst.get(f"/auth/oidc/callback?code=egal&state={state_s}", follow_redirects=False)
        text = antwort.text
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
auth_c.create_user("opfer", password="Geheim12345!abc")
opfer = auth_c.store.get_user_by_name("opfer")
auth_c.totp_enable(opfer["id"], auth_c.totp_new_secret()) if hasattr(auth_c, "totp_new_secret") else None

OHNE_CSRF = ("/auth/totp/disable", "/auth/totp/recovery", "/auth/pin/disable")
with TestClient(app_c) as c:
    c.post("/auth/login", data={"username": "opfer", "password": "Geheim12345!abc"},
           follow_redirects=False)
    for pfad in OHNE_CSRF:
        antwort = c.post(pfad)          # no X-CSRF-Token, no body — like a foreign form
        r.check(f"{pfad} requires a CSRF token", antwort.status_code == 403,
                f"HTTP {antwort.status_code} — got through without a token")

# Disabling the second factor must leave a trace. Without an entry it cannot be reconstructed
# afterwards that someone lost their second factor.
auth_c.totp_disable(opfer["id"])
ereignisse = [e["event"] for e in auth_c.store.recent_audit(limit=20)]
r.check("disabling TOTP is logged", "totp_disable" in ereignisse,
        f"no entry — found: {ereignisse[:6]}")
auth_c.disable_pin(opfer["id"])
r.check("disabling the PIN likewise",
        "pin_disable" in [e["event"] for e in auth_c.store.recent_audit(limit=20)])

# ── Brute-force lockout resettable by a successful first factor ───────────────
# Attack: Whoever knows the password (leak, reuse, phishing) signs in correctly once before every
# TOTP guess. The success deleted ALL failed attempts of the account — including those
# of the TOTP attempts. The lockout thus never applied to the second factor.
auth_b, _app_b = _app()
auth_b.create_user("ziel", password="Geheim12345!abc")

# Five failed attempts at the second factor …
for _ in range(5):
    auth_b._record_login("ziel", "203.0.113.9", success=False, method="totp")
offen_vorher = len(auth_b.store.recent_fails("ziel")) if hasattr(auth_b.store, "recent_fails") else None

# … then a SUCCESSFUL password login.
auth_b._record_login("ziel", "203.0.113.9", success=True, method="password")

# The failed TOTP attempts must remain.
rest = auth_b.store._all(
    "SELECT method FROM login_attempt WHERE username=? COLLATE NOCASE AND success=0", ("ziel",))
totp_übrig = [z["method"] for z in rest].count("totp")
r.check("a password success does NOT clear the failed TOTP attempts", totp_übrig == 5,
        f"{totp_übrig} of 5 left — the second factor is guessable again")

# Counter-check: it does clear failed password attempts, otherwise the fix would be a brake.
for _ in range(3):
    auth_b._record_login("ziel2", "203.0.113.9", success=False, method="password")
auth_b._record_login("ziel2", "203.0.113.9", success=True, method="password")
pw_übrig = [z["method"] for z in auth_b.store._all(
    "SELECT method FROM login_attempt WHERE username=? COLLATE NOCASE AND success=0",
    ("ziel2",))].count("password")
r.check("own failed attempts are still cleared by a success", pw_übrig == 0,
        f"{pw_übrig} left — the fix brakes more than necessary")


# ── Hijacking the first admin: allowlist name + open self-registration ─────────
# `admin_identifiers` only vouches for WHICH name becomes admin — not for who gets it. With
# `allow_signup=True` the first one to guess the address registers exactly under it and is admin
# at the first login. The constructor no longer permits this combination.
def _baut(**cfg):
    """(built?, error text) — without turning the check into a failure of the suite."""
    tmp = tempfile.mkdtemp()
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False)
    grund.update(cfg)
    try:
        TinySesam(TinySesamConfig(**grund))
        return True, ""
    except ValueError as e:
        return False, str(e)


gebaut, text = _baut(admin_identifiers=["chef"], allow_signup=True)
r.check("allowlist USERNAME + allow_signup is rejected", not gebaut,
        "the instance builds — whoever registers as 'chef' becomes first admin")
r.check("the rejection names the affected entry", "chef" in text,
        f"message does not name it: {text[:80]!r}")

# An e-mail is not enough either as long as nobody confirms it: at registration it is
# a freely typeable field.
gebaut, _ = _baut(admin_identifiers=["chef@example.com"], allow_signup=True,
                  signup_require_email=True, signup_verify_email=False)
r.check("allowlist E-MAIL without mandatory confirmation is rejected", not gebaut,
        "the instance builds — the address is unconfirmed and thus freely choosable")

# Counter-checks — the guard must not take the viable setups down with it.
gebaut, text = _baut(admin_identifiers=["chef@example.com"], allow_signup=True,
                     signup_require_email=True, signup_verify_email=True,
                     # Mandatory since the base_url rework; without it the setup would fail for
                     # a reason that has nothing to do with the first-admin guard.
                     base_url="https://auth.example.com")
r.check("confirmed e-mail + open registration stays allowed", gebaut,
        f"too strict, the proven path is closed: {text[:120]}")

gebaut, text = _baut(admin_identifiers=["chef"], allow_signup=False)
r.check("allowlist without self-registration stays allowed", gebaut,
        f"too strict, the normal case is closed: {text[:120]}")


# ── Planted SAML assertion (login CSRF / unsolicited response) ─────────────────
# The ACS accepted every signed assertion. `InResponseTo` bound it to nothing: python3-saml
# only checks the field if it is there — a response without it went through. An attacker with
# a valid assertion for THEIR account could thus POST it into the victim's browser.
from tinysesam.saml_ import SAMLClient  # noqa: E402


class _Antwort:
    """An IdP whose assertion passes signature and conditions — only the reference changes."""

    def __init__(self, in_response_to):
        self.irt = in_response_to
        self.gesehen = "__nie_gesetzt__"

    def process_response(self, request_id=None):
        self.gesehen = request_id

    def get_errors(self):
        return []

    def get_last_error_reason(self):
        return ""

    def is_authenticated(self):
        return True

    def get_last_response_in_response_to(self):
        return self.irt

    def get_nameid(self):
        return "angreifer@example.com"

    def get_attributes(self):
        return {}


def _saml_lauf(in_response_to, request_id):
    auth_s, _ = _app()
    client = SAMLClient(auth_s.cfg)
    idp = _Antwort(in_response_to)
    client._auth = lambda req, base: idp
    return client.process({}, "https://app.example.com", request_id=request_id), idp


daten, _ = _saml_lauf(None, "_meine-id")
r.check("assertion WITHOUT InResponseTo is rejected", daten is None,
        "accepted — every signed assertion logs everybody in (login CSRF)")

daten, _ = _saml_lauf("_fremde-id", "_meine-id")
r.check("assertion with a FOREIGN InResponseTo is rejected", daten is None,
        "accepted — the response belongs to a different sign-in attempt")

daten, _ = _saml_lauf("_meine-id", "")
r.check("without a requested request the ACS stays closed", daten is None,
        "accepted — nothing may be redeemed without an own request")

# Counter-check: the regular path must get through, otherwise the fix is a wall.
daten, idp = _saml_lauf("_meine-id", "_meine-id")
r.check("the requested assertion still gets through", daten is not None,
        "the regular SAML login is closed")
r.check("the request ID is also passed on to the library", idp.gesehen == "_meine-id",
        f"process_response saw {idp.gesehen!r} — the check would only run in TinySesam, not in python3-saml")


# And the anchor must be WIRED: the router stores the request ID and hands it back again.
class _FakeSAML:
    def __init__(self):
        self.gesehene_request_id = "__nie_gesetzt__"

    def login_url(self, req, base, return_to="/"):
        return ("https://idp.example.com/sso?SAMLRequest=abc", "_authnreq-4711")

    def process(self, req, base, request_id=""):
        self.gesehene_request_id = request_id
        return None          # the rest of the flow does not matter here

    def metadata(self, base):
        return "<md:EntityDescriptor/>"


auth_r, app_r = _app(saml_enabled=True, saml_idp_sso_url="https://idp.example.com/sso",
                     saml_idp_x509cert="MIIB", base_url="https://app.example.com")
auth_r.saml = _FakeSAML()
app_r = FastAPI()
app_r.include_router(auth_r.router())
cr = TestClient(app_r)

antwort = cr.get("/auth/saml/login?next=/", follow_redirects=False)
keks = antwort.cookies.get("tinysesam_saml_flow")
r.check("the login stores the request ID in a flow cookie", keks == "_authnreq-4711",
        f"cookie is {keks!r} — without storage there is nothing to compare at the ACS")
r.check("the flow cookie is httponly", "httponly" in antwort.headers.get("set-cookie", "").lower(),
        "readable via JavaScript")

cr.post("/auth/saml/acs", data={"SAMLResponse": "x"}, follow_redirects=False)
r.check("the ACS passes the stored request ID on to the check",
        auth_r.saml.gesehene_request_id == "_authnreq-4711",
        f"it saw {auth_r.saml.gesehene_request_id!r} — the anchor is attached to no wire")


# ── Taking over sessions: from the file or from the admin panel ────────────────
# Session tokens lay in plain text in the database, and `GET /admin/api/sessions` also handed
# them to the browser. Both together mean: whoever reads the file (it was 0644) or sees a panel
# response signs in as any user. Now only the sha256 is stored; the panel gets this handle, with
# which one can terminate but not sign in.
auth_t, app_t = _app()
auth_t.create_user("opfer", password="geheim12345")
opfer_id = auth_t.store.get_user_by_name("opfer")["id"]
# `create_session` returns what goes into the cookie — exactly the value in question.
cookie_wert = auth_t.store.create_session(opfer_id, 3600, True, "password")

gespeichert = [z["token_hash"] for z in auth_t.store._all("SELECT token_hash FROM session")]
# Compute the sha256 ourselves: a test that asks `store.session_hash()` measures against the same
# function it is checking — and would stay green if that mutated to the identity.
erwartet = hashlib.sha256(cookie_wert.encode()).hexdigest()
r.check("no plain-text token is in the database", gespeichert == [erwartet],
        f"stored: {gespeichert[:1]} — the sha256 of the cookie was expected")
r.check("the cookie is NOT the stored value",
        bool(cookie_wert) and cookie_wert not in gespeichert,
        "whoever reads the file has the sign-in token")

# The handle must not be usable as a cookie.
handle = gespeichert[0]
r.check("the handle is no good as a session cookie",
        auth_t.store.get_session(handle) is None,
        "the stored value signs in — then the hashing is ineffective")
r.check("the real cookie still signs in",
        auth_t.store.get_session(cookie_wert) is not None,
        "the session cannot be found at all — then the test measures nothing")

# And the panel hands out exactly this handle, not the token.
panel = [z["token_hash"] for z in auth_t.store.list_sessions()]
r.check("the admin panel only gets to see handles", panel == [handle],
        f"list_sessions returns {panel[:1]}")

# ... but it works for terminating, otherwise the panel would be broken.
auth_t.store.delete_session_by_handle(handle)
r.check("the handle still terminates the session",
        auth_t.store.get_session(cookie_wert) is None,
        "the panel can no longer terminate any session")

# And a plain-text token at a handle position is an error, not a silent no-op:
# an UPDATE that hits no row would let a confirmed factor vanish silently.
try:
    auth_t.store.set_session_mfa("nicht-ein-hash", True)
    lautlos = True
except ValueError:
    lautlos = False
r.check("a plain-text token at a handle position is noticed", not lautlos,
        "runs into nothing — the session would silently keep its old state")


# The switchover must not throw anybody out: the hash is computable from the plain text, so existing
# rows can be migrated. Rebuild a database in the old format and open it.
import sqlite3 as _sq  # noqa: E402

from tinysesam.store import Store  # noqa: E402

alt_pfad = str(Path(tempfile.mkdtemp()) / "alt.db")
auth_alt, _ = _app(db_path=alt_pfad)
auth_alt.create_user("bestand", password="geheim12345")
altes_token = auth_alt.store.create_session(
    auth_alt.store.get_user_by_name("bestand")["id"], 3600, True, "password")
altes_handle = hashlib.sha256(altes_token.encode()).hexdigest()
auth_alt.store.db.close()

# back to the format before 0.18.0: the column is called `token` and holds the plain text
roh = _sq.connect(alt_pfad)
roh.execute("ALTER TABLE session RENAME COLUMN token_hash TO token")
roh.execute("UPDATE session SET token=?", (altes_token,))
roh.commit()
roh.close()

neu_store = Store(alt_pfad)
spalten = {z[1] for z in neu_store.db.execute("PRAGMA table_info(session)")}
r.check("the old column `token` is migrated to `token_hash`",
        "token_hash" in spalten and "token" not in spalten,
        f"columns: {sorted(spalten)}")
r.check("existing sign-ins survive the switchover",
        neu_store.get_session(altes_token) is not None,
        "the old cookie is no longer valid — an update would have logged out all users")
r.check("and the plain text is gone from the file afterwards",
        [z["token_hash"] for z in neu_store._all("SELECT token_hash FROM session")] == [altes_handle],
        "the plain text is still in the database")


# ── The auth database was open (0644) ─────────────────────────────────────────
# It contains password hashes, TOTP secrets and e-mail addresses. On a shared host every other
# account could read it — WAL and SHM with the same data likewise.
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402

ordner = tempfile.mkdtemp()
pfad = str(Path(ordner) / "rechte.db")
auth_d, _ = _app(db_path=pfad)
auth_d.create_user("wer", password="geheim12345")
auth_d.store.create_session(auth_d.store.get_user_by_name("wer")["id"], 3600, True, "password")


def _modus(datei):
    return _stat.S_IMODE(_os.stat(datei).st_mode)


offen = {f: oct(_modus(Path(ordner) / f)) for f in sorted(_os.listdir(ordner))
         if _modus(Path(ordner) / f) & 0o077}
r.check("database, WAL and SHM are readable only by the own user", not offen,
        f"readable by others: {offen}")
r.check("the check saw a WAL file at all",
        any(f.endswith("-wal") for f in _os.listdir(ordner)),
        f"only {_os.listdir(ordner)} — then the test says nothing about WAL/SHM")

# An existing, too open database is NOT rewritten (a deliberate group share is the
# operator's decision) — but it is named loudly.
auth_d.store.db.close()
_os.chmod(pfad, 0o644)
puffer = io.StringIO()
haken = logging.StreamHandler(puffer)
log_ts = logging.getLogger("tinysesam")
log_ts.addHandler(haken)
try:
    Store(pfad)
finally:
    log_ts.removeHandler(haken)
r.check("an existing, open database is reported", "chmod 600" in puffer.getvalue(),
        f"no warning: {puffer.getvalue()[:100]!r}")
r.check("and not changed behind one's back", _modus(pfad) == 0o644,
        f"changed to {oct(_modus(pfad))} — that overrides a deliberate share")


# ── API keys as a second door: locking out did not lock them out ──────────────
# A key hangs on no session. Whoever reset or blocked an account only closed the front door up to
# 0.18.0. (The key of a DEACTIVATED account was always worthless — `verify_api_key`
# checks the flag; this is about reset, block and the user's panic button.)
auth_k, app_k = _app(apikey_enabled=True)
uid_k = auth_k.create_user("bot-halter", password="geheim12345")


def _key_gilt(auth_obj, schluessel):
    # verify_api_key returns (user, roles) — a tuple is ALWAYS truthy. Only [0] counts.
    return auth_obj.verify_api_key(schluessel)[0] is not None


schluessel = auth_k.create_api_key(uid_k, "bot")["key"]
r.check("a fresh API key is valid", _key_gilt(auth_k, schluessel), "even the starting point is missing")

# Own password change deliberately leaves it in place — otherwise every routine disables the
# automations. But the state must be queryable, otherwise "deliberately" is only "unnoticed".
auth_k.set_password(uid_k, "nochgeheimer99")
r.check("the own password change lets automations run", _key_gilt(auth_k, schluessel),
        "the key is dead — every password routine disables the integrations")
r.check("and the number of keys that remain valid is queryable",
        auth_k.store.count_active_api_keys(uid_k) == 1,
        f"counted: {auth_k.store.count_active_api_keys(uid_k)}")

# The mass revocation invalidates, and it says how many.
anzahl = auth_k.store.revoke_user_api_keys(uid_k)
r.check("the mass revocation names the number", anzahl == 1, f"reported {anzahl}")
r.check("afterwards the key is no longer valid", not _key_gilt(auth_k, schluessel),
        "revoked and still valid")
r.check("a second revocation does not count anything twice",
        auth_k.store.revoke_user_api_keys(uid_k) == 0,
        "counts already revoked keys again")

# Admin password reset: there the intent is locking out. CSRF is switched off for this block
# — the panel's protection has its own check further up, here it is about the keys.
auth_a, _ = _app(apikey_enabled=True, csrf_enabled=False)
uid_a = auth_a.create_user("bot-halter", password="geheim12345")
zweit = auth_a.create_api_key(uid_a, "bot2")["key"]
admin_a = auth_a.create_user("chefin", password="geheim12345", is_admin=True)
app_a = FastAPI()
app_a.include_router(auth_a.router())          # admin panel hangs under /auth/admin via auto-mount
ca = TestClient(app_a)
ca.cookies.set(auth_a.cfg.session_cookie,
               auth_a.store.create_session(admin_a, 3600, True, "password"))

antwort = ca.post(f"/auth/admin/api/users/{uid_a}/password", json={"password": "ganzneu12345abc"})
r.check("the admin reset goes through at all", antwort.status_code == 200,
        f"HTTP {antwort.status_code}: {antwort.text[:120]}")
r.check("the admin reset invalidates the API keys of the account", not _key_gilt(auth_a, zweit),
        "key remains valid — locking out only closed the front door")
r.check("and says how many there were", antwort.json().get("api_keys_revoked") == 1,
        f"response: {antwort.text[:120]}")

# Blocking an account: keys are dead anyway via the `disabled` flag — but they must also
# BE revoked, otherwise they revive on unblocking.
dritt = auth_a.create_api_key(uid_a, "bot3")["key"]
ca.post(f"/auth/admin/api/users/{uid_a}/disable", json={"disabled": True})
ca.post(f"/auth/admin/api/users/{uid_a}/disable", json={"disabled": False})
r.check("a key does not revive after blocking and unblocking", not _key_gilt(auth_a, dritt),
        "the key is valid again — blocked and unblocked is no free pass")


# ── Admin actions without actor and without IP ────────────────────────────────
# The log recorded THAT an account was blocked — not by whom and from where. With several
# admins that is exactly the question one asks afterwards.
auth_p, _ = _app(csrf_enabled=False)
opfer_p = auth_p.create_user("betroffen", password="geheim12345")
chef_p = auth_p.create_user("chefin2", password="geheim12345", is_admin=True)
app_p = FastAPI()
app_p.include_router(auth_p.router())
cp = TestClient(app_p)
cp.cookies.set(auth_p.cfg.session_cookie,
               auth_p.store.create_session(chef_p, 3600, True, "password"))

cp.post(f"/auth/admin/api/users/{opfer_p}/disable", json={"disabled": True},
        headers={"X-Forwarded-For": "203.0.113.42"})
eintrag = next((z for z in auth_p.store.recent_audit(50) if z["event"] == "user_disable"), None)
r.check("the blocking appears in the log at all", eintrag is not None,
        "no row — then the test says nothing about the rest")
r.check("and names the admin who did it",
        bool(eintrag) and eintrag["username"] == "chefin2",
        f"username={eintrag['username'] if eintrag else None!r}")
r.check("and the IP it came from", bool(eintrag) and bool(eintrag["ip"]),
        f"ip={eintrag['ip'] if eintrag else None!r}")

# Not only this one route: the password reset as well.
cp.post(f"/auth/admin/api/users/{opfer_p}/password", json={"password": "ganzneu12345abc"})
reset = next((z for z in auth_p.store.recent_audit(50) if z["event"] == "user_password_reset"), None)
r.check("the admin password reset also names actor and IP",
        bool(reset) and reset["username"] == "chefin2" and bool(reset["ip"]),
        f"{dict(reset) if reset else None}")


# ── The guard that stops guarding after the first log rotation ─────────────────
# `logging.FileHandler` keeps the inode open. logrotate renames and creates anew — from then on
# the process writes into the RENAMED file, the fail2ban jail reads the empty new one.
import os as _os2  # noqa: E402

from tinysesam.security import attach_security_log, seclog  # noqa: E402

log_ordner = tempfile.mkdtemp()
log_datei = str(Path(log_ordner) / "security.log")
attach_security_log(log_datei)
seclog.warning("failed login user=vorher ip=203.0.113.1 method=password")
_os2.rename(log_datei, log_datei + ".1")          # exactly what logrotate does
open(log_datei, "w").close()
seclog.warning("failed login user=nachher ip=203.0.113.2 method=password")

r.check("after a log rotation the next line lands in the NEW file",
        "nachher" in Path(log_datei).read_text(encoding="utf-8"),
        "it is in the renamed file — from now on the jail reads into the void")
r.check("and no longer in the rotated one",
        "nachher" not in Path(log_datei + ".1").read_text(encoding="utf-8"),
        "the old inode keeps receiving lines")


# ── The app lockout blinded fail2ban ─────────────────────────────────────────
# As long as it was locked, nobody called `record_login()` any more: the app answered 429 and wrote
# no line. The log fell silent exactly when the IP should have been banned.
auth_l, _ = _app()
auth_l.create_user("ziel3", password="geheim12345")
for _ in range(10):
    auth_l._record_login("ziel3", "203.0.113.77", success=False, method="password")

puffer_l = io.StringIO()
haken_l = logging.StreamHandler(puffer_l)
seclog.addHandler(haken_l)
try:
    gesperrt = auth_l._is_locked("ziel3", "203.0.113.77")
finally:
    seclog.removeHandler(haken_l)
zeile_l = puffer_l.getvalue()

r.check("the account is locked at all", gesperrt, "no lockout — then the test measures nothing")
r.check("the rejection writes a line to the security log", "failed login" in zeile_l,
        f"log is silent: {zeile_l[:80]!r} — fail2ban sees no reason to ban")
r.check("and names the reason", "reason=lockout" in zeile_l, f"without reason: {zeile_l[:100]!r}")
r.check("the line matches the shipped fail2ban filter",
        bool(re.search(r"failed login user=.* ip=(\S+) method=.*", zeile_l)),
        f"filter does not match: {zeile_l[:100]!r}")

# The rate limit must not reject silently either.
puffer_r = io.StringIO()
haken_r = logging.StreamHandler(puffer_r)
seclog.addHandler(haken_r)
try:
    for _ in range(int(auth_l._sec("rate_limit_max")) + 2):
        auth_l._rate_ok("203.0.113.78")
finally:
    seclog.removeHandler(haken_r)
r.check("a rate-limit hit is in the log as well",
        "reason=ratelimit" in puffer_r.getvalue(),
        f"silent: {puffer_r.getvalue()[:80]!r}")


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


class _Anfrage:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def _mit_log(fn):
    """(Return value, log text) — and the marker is cleared beforehand so that the checks do
    not take the message away from each other (each warning comes only once per peer)."""
    _sec._GEMELDETE_PEERS.clear()
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    _sec.seclog.addHandler(haken)
    try:
        return fn(), puffer.getvalue()
    finally:
        _sec.seclog.removeHandler(haken)


echte_ip, log_a = _mit_log(lambda: _sec.client_ip(_Anfrage("192.0.2.5", "203.0.113.9"),
                                                  ["127.0.0.1/32"]))
r.check("with the default behind a container proxy it stays at the proxy IP",
        echte_ip == "192.0.2.5", f"yielded {echte_ip} — then the test measures the wrong thing")
r.check("...and this is reported instead of silently accepted",
        "trusted_proxies" in log_a and "ignoriert" in log_a,
        f"no hint: {log_a[:90]!r}")

# 0.0.0.0/0 sounds generous and devalues XFF completely: if every address counts as a proxy,
# none is left as a client.
alles, log_b = _mit_log(lambda: _sec.client_ip(_Anfrage("192.0.2.7", "203.0.113.9"),
                                               ["0.0.0.0/0"]))
r.check("0.0.0.0/0 does NOT yield the client IP", alles == "192.0.2.7",
        f"yielded {alles} — then XFF would be forgeable")
r.check("...and this is reported too", "entwertet" in log_b,
        f"no hint: {log_b[:90]!r}")

# Configured correctly the real address comes through — and then there is nothing to report.
richtig, log_c = _mit_log(lambda: _sec.client_ip(_Anfrage("192.0.2.5", "203.0.113.9"),
                                                 ["192.0.2.0/24"]))
r.check("with the network of the proxy the real client IP arrives", richtig == "203.0.113.9",
        f"yielded {richtig}")
r.check("and normal operation stays silent", log_c.strip() == "",
        f"warns without cause: {log_c[:90]!r}")

# The message comes once per peer, not per request — otherwise it floods the log.
_sec._GEMELDETE_PEERS.clear()
puffer_w = io.StringIO()
haken_w = logging.StreamHandler(puffer_w)
_sec.seclog.addHandler(haken_w)
try:
    for _ in range(5):
        _sec.client_ip(_Anfrage("192.0.2.9", "203.0.113.9"), ["127.0.0.1/32"])
finally:
    _sec.seclog.removeHandler(haken_w)
# MESSAGES are counted, not words: the message itself names `trusted_proxies` twice
# (once as finding, once in the advice), so a word counter would always stand at 2.
_zeilen = [z for z in puffer_w.getvalue().splitlines() if "X-Forwarded-For" in z]
r.check("the warning comes once per peer, not at every request", len(_zeilen) == 1,
        f"{len(_zeilen)} messages for 5 requests")

# SSO and passkey login wrote the raw peer IP into the session and into the log.
for modul in ("oidc.py", "webauthn_.py"):
    quelle = (Path(__file__).resolve().parent.parent / "tinysesam" / modul).read_text(encoding="utf-8")
    code = "\n".join(z for z in quelle.splitlines() if not z.lstrip().startswith("#"))
    r.check(f"{modul} uses client_ip, not the raw peer IP",
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
uid_h = auth_h.create_user("intl", password="geheim12345")


def _kopfwert(roh):
    auth_h.store._exec("UPDATE users SET display_name=? WHERE id=?", (roh, uid_h))
    kopf = auth_h._forward_response_headers(auth_h.store.get_user(uid_h))
    return kopf["Remote-Name"]


boes = _kopfwert("Bose\r\nX-Remote-Groups: admin")
r.check("line breaks are removed from the header value",
        "\r" not in boes and "\n" not in boes, f"{boes!r}")

# The value must go through a REAL HTTP serializer, not only through the TestClient:
# the in-process client also lets through what would never arrive on the wire.
import h11  # noqa: E402


def _geht_raus(wert):
    try:
        h11.Response(status_code=200, headers=[("Remote-Name", wert.encode("latin-1"))])
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


for roh, was in (("Bose\r\nX-Remote-Groups: admin", "Zeilenumbruch"),
                 ("Müller", "Umlaut"), ("Иван", "Kyrillisch"), ("测试 Wang", "Chinesisch")):
    wert = _kopfwert(roh)
    geht, fehler = _geht_raus(wert)
    r.check(f"{was} in the display name gets through the HTTP serializer", geht, fehler)

# And losslessly: the app reads the header as UTF-8 and has the name back.
for roh in ("Müller", "Иван", "测试 Wang", "alice"):
    zurueck = _kopfwert(roh).encode("latin-1").decode("utf-8")
    r.check(f"{roh!r} arrives unchanged at the recipient", zurueck == roh,
            f"became {zurueck!r}")

# The encoding is UNIFORM — otherwise no app would know what it currently has.
r.check("even a Latin-1-capable name goes over the wire as UTF-8",
        _kopfwert("Müller").encode("latin-1") == "Müller".encode("utf-8"),
        "sometimes Latin-1, sometimes UTF-8 — the app cannot tell them apart")


# ── A security switch that never did anything ─────────────────────────────────
# `totp_required` stood in the config, in both READMEs ("enforce 2FA") and on the website —
# and was read nowhere in the code. Whoever set it believed the second factor
# enforced and did not have it.
gebaut, text = _baut(totp_required=True)
r.check("totp_required=True is rejected instead of silently ignored", not gebaut,
        "the instance builds — the operator keeps believing in a protection that does not exist")
r.check("and the message names the way that really applies", "login_chain" in text,
        f"without hint: {text[:90]!r}")

# The switch must not be advertised anywhere any more either. `web/` exists only in the repo, not in the
# source package — what is there gets checked, and the check says what it saw.
wurzel = Path(__file__).resolve().parent.parent
gesehen = []
for datei in ("README.md", "i18n/README.de.md", "web/flows.py"):
    pfad = wurzel / datei
    if not pfad.exists():
        continue
    gesehen.append(datei)
    r.check(f"{datei} no longer advertises totp_required",
            "totp_required" not in pfad.read_text(encoding="utf-8"),
            "the dead switch is still touted as 2FA")
r.check("both READMEs were among them",
        {"README.md", "i18n/README.de.md"} <= set(gesehen), f"only saw: {gesehen}")

# The factor chain is the advertised way — so it must work.
gebaut, text = _baut(login_chain=["password", "totp"], login_chain_strict=True)
r.check("the recommended factor chain builds", gebaut, f"recommended and broken: {text[:110]}")


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
    echte_geht = True
except ValueError:
    echte_geht = False
r.check("a real page name still works", echte_geht, "the list is too narrow")

# The list in the code must match the pages that render_page really serves — otherwise it
# silently goes stale again.
quelle = "\n".join((wurzel / "tinysesam" / f).read_text(encoding="utf-8")
                    for f in ("router.py", "manager.py", "admin.py"))
gerendert = set(re.findall(r'render_page\(\s*"([a-z_]+)"', quelle))
fehlend = sorted(gerendert - set(auth_tpl.PAGES))
r.check("every rendered page is in TinySesam.PAGES", not fehlend,
        f"not replaceable although it exists: {fehlend}")


# ── German error texts with lang="en" ──────────────────────────────────────────
# 32 HTTP responses carried fixed German text — even in an installation set to English. The UI
# was bilingual, the responses to machines and proxies were not.
auth_en, app_en = _app(lang="en")
auth_en.create_user("someone", password="geheim12345")
cen = TestClient(app_en)

# Measure real responses, do not query the translation table. That needs a signed-in
# session: without it every endpoint answers 401 "Unauthorized", and the test would look
# green without ever having seen a translated message.
def _antworten(auth_obj, app_obj, benutzer):
    klient = TestClient(app_obj)
    uid = auth_obj.store.get_user_by_name(benutzer)["id"]
    klient.cookies.set(auth_obj.cfg.session_cookie,
                       auth_obj.store.create_session(uid, 3600, True, "password"))
    return [
        ("CSRF fehlt", klient.post("/auth/apikeys", json={"name": "x"})),
        ("Ressource unbekannt", klient.get("/auth/resource/gibtsnicht")),
    ]


antworten = _antworten(auth_en, app_en, "someone")
umlaute = "äöüßÄÖÜ"
deutsch = [f"{was}: {a.text[:70]}" for was, a in antworten
           if any(z in (a.text or "") for z in umlaute)
           or "nötig" in (a.text or "") or "ungültig" in (a.text or "")]
r.check("with lang='en' no German text comes from the endpoints", not deutsch,
        " | ".join(deutsch))
r.check("and the responses carry a message of their own at all",
        all(a.status_code >= 400 for _, a in antworten)
        and any("Unauthorized" not in (a.text or "") for _, a in antworten),
        f"Status {[a.status_code for _, a in antworten]}, texts "
        f"{[(a.text or '')[:40] for _, a in antworten]} — otherwise measures nothing")

# And with German, German must still come out, otherwise the translation would only be moved.
auth_de, app_de = _app(lang="de")
auth_de.create_user("jemand", password="geheim12345")
deutsche = " ".join((a.text or "") for _, a in _antworten(auth_de, app_de, "jemand"))
r.check("with lang='de' German still comes out",
        any(z in deutsche for z in umlaute) or "nötig" in deutsche,
        f"{deutsche[:100]!r}")

# Hygiene: no raw text in an HTTPException any more — otherwise the gap grows back by itself.
roh = []
for modul in ("manager.py", "router.py", "admin.py", "oidc.py", "webauthn_.py", "saml_.py"):
    quelle = (Path(__file__).resolve().parent.parent / "tinysesam" / modul).read_text(encoding="utf-8")
    for nr, zeile in enumerate(quelle.splitlines(), 1):
        if re.search(r'HTTPException\(\s*\d+\s*,\s*[fr]?"', zeile):
            roh.append(f"{modul}:{nr}")
r.check("no HTTPException with fixed text any more", not roh, ", ".join(roh[:5]))


# ── Recovery codes carried 48 bits ────────────────────────────────────────────
# A recovery code REPLACES the second factor and is valid until used. A TOTP code has only
# a million possibilities, but is worthless after 30 seconds — the comparison does not hold.
auth_rc, _ = _app()
uid_rc = auth_rc.create_user("rc", password="geheim12345")
codes = auth_rc.generate_recovery_codes(uid_rc)
hexzeichen = sum(1 for z in codes[0] if z in "0123456789abcdef")
r.check("a recovery code carries at least 64 bits", hexzeichen * 4 >= 64,
        f"{codes[0]} = {hexzeichen * 4} bits")
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
    art = None
except Exception as e:
    art = e
r.check("a configuration error is a ConfigError", isinstance(art, ConfigError),
        f"{type(art).__name__}")
r.check("...and still a ValueError (existing code catches it)",
        isinstance(art, ValueError), "existing `except ValueError` breaks")
r.check("...and a TinySesamError", isinstance(art, TinySesamError), f"{type(art).__mro__}")

# The extra guard, two-stage. It may only raise where it can never be wrong: a client is
# replaceable (`auth.ldap = own_client`, four own suites work that way), so the setup does
# NOT abort — it warns. It raises at the lazy import, i.e. on the first real use.
import importlib  # noqa: E402


class _Blockiert:
    """An import finder that deliberately "does not find" exactly one module."""

    def __init__(self, name):
        self.name = name

    def find_spec(self, fullname, pfad=None, ziel=None):
        if fullname == self.name or fullname.startswith(self.name + "."):
            raise ModuleNotFoundError(f"No module named '{fullname}'", name=fullname)
        return None


def _ohne_modul(name, fn):
    """Run `fn()` as if `name` were not installed."""
    blocker = _Blockiert(name)
    sys.meta_path.insert(0, blocker)
    weg = {n: m for n, m in list(sys.modules.items()) if n == name or n.startswith(name + ".")}
    for n in weg:
        del sys.modules[n]
    try:
        return fn()
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(weg)
        importlib.invalidate_caches()


puffer_x = io.StringIO()
haken_x = logging.StreamHandler(puffer_x)
_sec.seclog.addHandler(haken_x)
try:
    # `password_enabled` stays on: LDAP checks passwords and satisfies the `password` factor —
    # without the switch there would be no sign-in method at all, and the configuration check
    # aborts (rightly) beforehand. This is about the missing extra, not about that.
    # `ldap_allow_plaintext=True`: since F-12 `ldap://` without TLS is a setup error. Here, however,
    # the MISSING EXTRA is to be measured, not the transport — without the switch the
    # setup would abort for the other reason and the check below would be green without measuring.
    auth_x, _ = _ohne_modul("ldap3", lambda: _app(
        ldap_enabled=True, ldap_url="ldap://ldap.example.com", ldap_allow_plaintext=True))
    gebaut_x = True
except Exception as e:
    auth_x, gebaut_x = None, e
finally:
    _sec.seclog.removeHandler(haken_x)

r.check("a missing extra does NOT abort the setup", gebaut_x is True,
        f"{type(gebaut_x).__name__} — then nobody can set their own client any more")
r.check("...but it is reported at startup", "tinysesam[ldap]" in puffer_x.getvalue(),
        f"silent: {puffer_x.getvalue()[:90]!r}")

# And on the first real use a readable error instead of a bare ModuleNotFoundError.
from tinysesam.ldap_ import LDAPClient  # noqa: E402

klient = LDAPClient(auth_x.cfg if auth_x else None)
try:
    _ohne_modul("ldap3", klient._server)
    gebrauch = None
except Exception as e:
    gebrauch = e
r.check("on use a MissingExtra is raised", isinstance(gebrauch, MissingExtra),
        f"{type(gebrauch).__name__}: {str(gebrauch)[:70]}")
r.check("...with a machine-readable extra name", getattr(gebrauch, "extra", None) == "ldap",
        f"extra={getattr(gebrauch, 'extra', None)!r}")
r.check("...and still a RuntimeError", isinstance(gebrauch, RuntimeError),
        "existing `except RuntimeError` breaks")

# Counter-check: whoever leaves the method incomplete brings the client along themselves.
gebaut, text = _baut(ldap_enabled=True)
r.check("a half-configured method stays buildable (own client)", gebaut,
        f"rejected: {text[:110]}")

# After the counter-check the normal case must build again — otherwise the test would have returned the
# table broken and everything that follows would be nonsense.
gebaut, _ = _baut()
r.check("the table is intact again after the counter-check", gebaut,
        "the test did not reset the state cleanly")


# ── The database carried no schema stamp ──────────────────────────────────────
# Which state a file had could only be guessed from its column names. A file from a
# NEWER version opened an older version silently — with tables it does not
# know, and writes that leave gaps.
stempel_pfad = str(Path(tempfile.mkdtemp()) / "stempel.db")
st = Store(stempel_pfad)
gestempelt = int(st.db.execute("PRAGMA user_version").fetchone()[0] or 0)
r.check("a fresh database carries the schema version",
        gestempelt == Store.SCHEMA_VERSION and gestempelt > 0,
        f"user_version={gestempelt}, expected {Store.SCHEMA_VERSION}")
st.db.close()

# A file from the future must speak up.
roh_st = _sq.connect(stempel_pfad)
roh_st.execute(f"PRAGMA user_version = {Store.SCHEMA_VERSION + 50}")
roh_st.commit()
roh_st.close()
puffer_st = io.StringIO()
haken_st = logging.StreamHandler(puffer_st)
log_st = logging.getLogger("tinysesam")
log_st.addHandler(haken_st)
try:
    zukunft = Store(stempel_pfad)
finally:
    log_st.removeHandler(haken_st)
r.check("a file from a newer version is reported",
        "neueren Version" in puffer_st.getvalue(),
        f"silent: {puffer_st.getvalue()[:80]!r}")
r.check("...and the higher stamp is NOT reset",
        int(zukunft.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION + 50,
        "the version was stamped down — at the next open the warning is missing")


# ── Contradictions were only noticed at login ─────────────────────────────────
# An app without a single sign-in method started without complaint; a `login_chain` naming a
# disabled method is unsatisfiable and sends the user in circles.
gebaut, text = _baut(password_enabled=False)
r.check("an instance without any sign-in method is rejected", not gebaut,
        "builds — nobody can sign in, and nothing says so")
r.check("...with a hint which switches there would be", "password_enabled=True" in text,
        f"{text[:90]!r}")

gebaut, text = _baut(login_chain=["password", "pin"], pin_enabled=False)
r.check("an unsatisfiable factor chain is rejected", not gebaut,
        "builds — the user ends up in a loop")
r.check("...and names the blocking step", "pin_enabled=False" in text, f"{text[:90]!r}")

gebaut, text = _baut(login_chain=["password", "gibtsnicht"])
r.check("an unknown step in the chain is rejected", not gebaut,
        "a typo in the chain would stay silently without consequence")

# All findings at once — whoever has three things wrong should read them once.
gebaut, text = _baut(password_enabled=False, login_chain=["password", "pin"], pin_enabled=False)
r.check("several contradictions are reported together", text.count("\n  - ") >= 2,
        f"only one: {text[:120]!r}")

# What can still come later is a warning — not an abort. `set_mailer` after the
# constructor is a perfectly common order. `base_url` is the opposite case and is therefore
# here: it must be present at setup (error, not warning — see R4-01 rework),
# otherwise "forgot password" would silently run into nothing.
puffer_k = io.StringIO()
haken_k = logging.StreamHandler(puffer_k)
_sec.seclog.addHandler(haken_k)
try:
    gebaut, text = _baut(magiclink_enabled=True, base_url="https://auth.example.com")
finally:
    _sec.seclog.removeHandler(haken_k)
r.check("a missing mailer does NOT prevent startup", gebaut,
        f"aborts: {text[:90]} — set_mailer() often comes only afterwards")
r.check("...but it is reported", "smtp_host" in puffer_k.getvalue(),
        f"silent: {puffer_k.getvalue()[:80]!r}")

# And the normal case must neither break nor make noise.
puffer_n = io.StringIO()
haken_n = logging.StreamHandler(puffer_n)
_sec.seclog.addHandler(haken_n)
try:
    gebaut, text = _baut()
finally:
    _sec.seclog.removeHandler(haken_n)
r.check("the default configuration builds without finding", gebaut, text[:110])
r.check("...and without configuration warning", "Konfiguration:" not in puffer_n.getvalue(),
        f"warns without cause: {puffer_n.getvalue()[:90]!r}")


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
import warnings as _warnungen  # noqa: E402

uid_cm = auth_cm.create_user("cm", password="geheim12345")
tok_alt = auth_cm.store.create_session(uid_cm, 3600, False, "password")
with _warnungen.catch_warnings(record=True) as _gewarnt:
    _warnungen.simplefilter("always")
    auth_cm.complete_mfa(tok_alt)
r.check("complete_mfa warns as a deprecated alias of complete_totp",
        [w.category for w in _gewarnt] == [DeprecationWarning]
        and "complete_totp" in str(_gewarnt[0].message),
        [str(w.message) for w in _gewarnt])
tok_neu = auth_cm.store.create_session(uid_cm, 3600, False, "password")
auth_cm.complete_totp(tok_neu)
import json as _json  # noqa: E402

faktoren = [sorted(_json.loads(auth_cm.store.get_session(t)["factors_done"] or "[]"))
            for t in (tok_alt, tok_neu)]
r.check("both names append the same factor", faktoren[0] == faktoren[1] == ["totp"],
        f"old={faktoren[0]} new={faktoren[1]} — an alias that does something else is worse "
        "than two methods")


# ── The Host header poisoned the reset, sign-in and confirmation link (R4-01/R8-4) ──────────
# Attack: The attacker triggers "forgot password" for a FOREIGN mailbox and sets the raw `Host`
# header while doing so. TinySesam built the mail address from `str(request.base_url)`, i.e. from
# exactly this header — the victim received a real mail from the real app with a valid token
# in a link to the attacker's server (CWE-644). `trusted_redirect_hosts` only protected
# `?next=`, not this path; `X-Forwarded-Host` is not needed for it.
BOESE = "angreifer.example"
ECHT = "https://auth.example.com"


def _mailapp(**cfg):
    post: list = []
    # `base_url` is now part of the basic equipment: since the rework it is mandatory as soon as
    # a mail path is on — an instance without it no longer exists (check for that further down).
    grund = dict(csrf_enabled=False, magiclink_enabled=True, password_reset_enabled=True,
                 signup_verify_email=True, allow_signup=True, signup_require_email=True,
                 passkey_enabled=False, trusted_redirect_hosts=["nur-das-hier.example"],
                 base_url=ECHT)
    grund.update(cfg)
    auth, app = _app(**grund)
    auth.set_mailer(lambda to, betreff, text, html=None: post.append(text))
    auth.create_user("opfer", password="Geheim12345!abc", email="opfer@example.com")
    return auth, TestClient(app), post


def _links(post) -> list[str]:
    return re.findall(r"https?://[^\s]+", "\n".join(post))


# Precondition: without this check "no mail to the attacker host" would be green even if
# the mailer is not wired at all — the attack would then prove nothing.
_a, _c, _post = _mailapp()
_c.post("/auth/forgot", data={"email": "opfer@example.com"})
r.check("precondition: the path works at all (mail goes out)",
        len(_post) == 1 and _links(_post)[0].startswith(ECHT + "/auth/reset"),
        f"{_post!r} — without this assurance the attack below checks nothing")

# The attack itself, at all three places that send a mail with a token.
for pfad, daten, name in (
        ("/auth/forgot", {"email": "opfer@example.com"}, "Reset-Link"),
        ("/auth/magic/request", {"email": "opfer@example.com", "next": "/"}, "Magic-Link"),
        ("/auth/register", {"username": "neu", "password": "Geheim12345!abc",
                            "email": "neu@example.com"}, "Bestätigungslink")):
    auth_x, c_x, post_x = _mailapp()
    antwort_x = c_x.post(pfad, data=daten, headers={"host": BOESE})
    r.check(f"{name}: forged Host header produces no mail to {BOESE}",
            not any(BOESE in u for u in _links(post_x)),
            f"{_links(post_x)!r} — the victim would get a valid token at {BOESE}")
    r.check(f"...and the path stays intact (mail to {ECHT}, HTTP {antwort_x.status_code})",
            len(post_x) == 1 and _links(post_x)[0].startswith(ECHT),
            f"{_links(post_x)!r} — base_url wins, the header does not count")

# ── Rework N1: the Host header must not choose even among SEVERAL own hosts ──
# Finding A-umgehung-4: `base_url` was only a warning. If it stayed empty and — with
# forward-auth/SSO the normal case — several names stood in `trusted_redirect_hosts`, the
# runtime check accepted EACH of them: the attacker triggered "forgot password" for a foreign mailbox
# and set `Host:` to another co-trusted host. If that one is weaker (foreign team,
# open redirect, captured access log), the reset token leaks there. Now `base_url`
# is mandatory and always wins — the header no longer has a say.
auth_m, c_m, post_m = _mailapp(trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"])
c_m.post("/auth/forgot", data={"email": "opfer@example.com"},
         headers={"host": "app-b.example.com"})
r.check("a second co-trusted host in the header does not win against base_url",
        len(post_m) == 1 and _links(post_m)[0].startswith(ECHT + "/auth/reset"),
        f"{_links(post_m)!r} — the reset token would go to the host chosen by the attacker")

# Finding A-regression-1/A-vollstaendigkeit-3: without a base `/auth/forgot` and
# `/auth/magic/request` kept rendering the SUCCESS page — HTTP 200, "mail is on its way", no mail.
# The total failure was visible only in a log line. Two locks against it:
#
# (1) The configuration check no longer lets this setup come into being (error, not warning).
from tinysesam import config_check as _kp  # noqa: E402

for _feld, _zusatz in (("magiclink_enabled", {}),
                       ("password_reset_enabled", {"magiclink_enabled": True}),
                       ("signup_verify_email", {"signup_require_email": True}),
                       ("oidc_enabled", {"oidc_issuer": "https://idp.example.com",
                                         "oidc_client_id": "c", "oidc_client_secret": "s"}),
                       ("saml_enabled", {"saml_idp_sso_url": "https://idp.example.com/sso",
                                         "saml_idp_x509cert": "PEM"})):
    _f, _w = _kp.check_config(TinySesamConfig(db_path=":memory:", **{_feld: True}, **_zusatz))
    r.check(f"without base_url {_feld} is an ERROR, not a warning",
            any("base_url ist leer" in x for x in _f),
            f"only warnings: {[x[:60] for x in _w]!r} — a warning starts up anyway")
_f_hosts, _w_hosts = _kp.check_config(TinySesamConfig(
    db_path=":memory:", magiclink_enabled=True,
    trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"]))
r.check("trusted_redirect_hosts does NOT replace base_url",
        any("base_url ist leer" in x for x in _f_hosts),
        "with several co-trusted hosts the header chooses otherwise (A-umgehung-4)")
_gebaut_ohne, _text_ohne = _baut(magiclink_enabled=True, password_reset_enabled=True)
r.check("...and the constructor aborts with it (ConfigError instead of silent operation)",
        not _gebaut_ohne and "base_url" in _text_ohne, f"built={_gebaut_ohne}")
r.check("...the message says what to enter",
        "base_url=" in _text_ohne, f"only diagnosis, no remedy: {_text_ohne[:160]!r}")
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
# (`router._mail_basis`), no longer as an uncaught ConfigError.
from tinysesam import ConfigError as _CfgErr  # noqa: E402

for _pfad, _daten, _name in (("/auth/forgot", {"email": "opfer@example.com"}, "Passwort vergessen"),
                             ("/auth/magic/request", {"email": "opfer@example.com", "next": "/"},
                              "Magic-Link")):
    auth_l, c_l, post_l = _mailapp()
    auth_l.cfg.base_url = ""            # mutation probe: the base drops away at runtime
    try:
        _antwort_l = c_l.post(_pfad, data=_daten)
        _ergebnis = f"HTTP {_antwort_l.status_code}, Erfolgsseite: {'unterwegs' in _antwort_l.text}"
        _hart = _antwort_l.status_code == 503 and "unterwegs" not in _antwort_l.text
    except _CfgErr as _e:
        _ergebnis, _hart = f"ungefangen: {str(_e)[:60]}", False
    r.check(f"{_name} without a base: 503 instead of \"mail is on its way\" (and instead of a 500)",
            _hart and not post_l,
            f"{_ergebnis} — 200 with a success page hides the total failure (A-regression-1)")

# And what the operator REALLY gets to see in this case — in operation, without a TestClient that passes
# an exception through. Until the rework no route caught the `ConfigError`, and the ASGI server
# turned it into an HTTP 500 (so it said in the CHANGELOG). Now `_mail_basis()` catches it and
# answers 503: the service is not ready for use like this, and the answer says so. Both are
# measured: no silent success, and exactly 503 — not 500, not 200.
# (Mutation probe: replace `_mail_basis` by `auth.require_public_base(request)` → 500, red.)
auth_500, app_500 = _app(csrf_enabled=False, magiclink_enabled=True, password_reset_enabled=True,
                         passkey_enabled=False, base_url=ECHT)
_post_500: list = []
auth_500.set_mailer(lambda to, betreff, text, html=None: _post_500.append(text))
auth_500.create_user("opfer", password="Geheim12345!abc", email="opfer@example.com")
auth_500.cfg.base_url = ""              # the situation the second lock is built for
_c500 = TestClient(app_500, raise_server_exceptions=False)
_antwort_500 = _c500.post("/auth/forgot", data={"email": "opfer@example.com"})
r.check("no silent success: without a base /auth/forgot does not report \"mail is on its way\"",
        _antwort_500.status_code != 200 and not _post_500,
        f"HTTP {_antwort_500.status_code}, mails={len(_post_500)} — the same answer prevents "
        "user enumeration and therefore hid the total failure (A-regression-1)")
r.check("...but HTTP 503 from the route, no uncaught 500",
        _antwort_500.status_code == 503,
        f"HTTP {_antwort_500.status_code} — 500 means: the ConfigError runs uncaught again "
        "up to the ASGI server (change the CHANGELOG sentence accordingly)")
# Invitation from the panel: the same class, the same bolt.
auth_inv, app_inv = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                         base_url=ECHT)
auth_inv.set_mailer(lambda *a, **k: None)
auth_inv.ensure_admin("chefin", "Geheim12345!abc")
_ci = TestClient(app_inv, raise_server_exceptions=False)
_ci.post("/auth/login", data={"username": "chefin", "password": "Geheim12345!abc"})
auth_inv.cfg.base_url = ""
_inv = _ci.post("/auth/admin/api/invite", json={"email": "gast@example.com"})
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
                   ("Einladung/Magic", dict(magiclink_enabled=True))):
    _gebaut, _text = _baut(**_an)
    r.check(f"{_name} without base_url: abort at setup, no 500 at runtime",
            not _gebaut and "base_url" in _text, f"built={_gebaut}: {_text[:90]!r}")

# The legitimate path stays: with a committed base_url the mail goes out, and the forged
# host is not in it. Without this check the fix "never a mail again" would be green too.
auth_ok, c_ok, post_ok = _mailapp(base_url=ECHT)
c_ok.post("/auth/forgot", data={"email": "opfer@example.com"}, headers={"host": BOESE})
r.check("legitimate path: base_url set → mail goes out and carries the real address",
        len(post_ok) == 1 and _links(post_ok)[0].startswith(ECHT + "/auth/reset"),
        f"{_links(post_ok)!r}")
r.check("and the forged host appears nowhere", BOESE not in "\n".join(post_ok),
        f"{post_ok!r}")

# The invitation link of the admin panel likewise goes by mail to a third party and carries a
# token — it came from the same line and was left lying in an earlier round of patching.
auth_inv, app_inv = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                         base_url=ECHT)
auth_inv.set_mailer(lambda *a, **k: None)
auth_inv.create_user("chef", password="Geheim12345!abc", is_admin=True)
with TestClient(app_inv) as c_inv:
    c_inv.cookies.set(auth_inv.cfg.session_cookie,
                      auth_inv.store.create_session(auth_inv.store.get_user_by_name("chef")["id"],
                                                    3600, True, "password"))
    einladung = c_inv.post("/auth/admin/api/invite", json={"email": "gast@example.com"},
                           headers={"host": BOESE})
r.check("admin invitation: the link comes from base_url, not from the Host header",
        einladung.status_code == 200 and BOESE not in einladung.text
        and ECHT + "/auth/invite/" in einladung.text,
        f"HTTP {einladung.status_code}: {einladung.text[:120]!r}")

# The rule itself, checked directly — it also decides for the OIDC redirect URI, SAML metadata
# and the forward-auth redirect, which all go through `public_base()`.
from tinysesam import security as _sec  # noqa: E402

r.check("a foreign host does not count as own", _sec.eigener_host(BOESE, []) is False)
r.check("a host from trusted_redirect_hosts counts", _sec.eigener_host("a.example.com", ["a.example.com"]))
r.check("loopback counts (the link only benefits the recipient themselves)",
        _sec.eigener_host("127.0.0.1", []) and _sec.eigener_host("::1", []))
r.check("user info in the host does not fool the check",
        _sec.sichere_basis("https://a.example.com@" + BOESE, ["a.example.com"]) == "",
        "urlsplit reads the host behind the @ here — the check must see exactly that")
r.check("and the checked base carries no user info on",
        _sec.sichere_basis("https://wer@a.example.com:8443", ["a.example.com"])
        == "https://a.example.com:8443")
auth_pb, _app_pb = _app(passkey_enabled=False)
r.check("public_base() returns empty instead of guessing (fail closed)",
        auth_pb.public_base(candidate="https://" + BOESE) == "")
try:
    auth_pb.require_public_base(candidate="https://" + BOESE)
    _pb_hart = False
except _CfgErr:
    _pb_hart = True
r.check("require_public_base() raises instead of guessing",
        _pb_hart, "whoever NEEDS a base must not get an empty string")

# Finding A-regression-12: the server's `root_path` was dropped — an app mounted under a subpath
# sent mail links without prefix, i.e. 404 instead of the reset form.
_auth_pfad = TinySesam(TinySesamConfig(db_path=":memory:",
                                      base_url="https://app.example.com/sso/"))
r.check("the subpath (root_path) comes along from base_url",
        _auth_pfad.public_base() == "https://app.example.com/sso",
        f"{_auth_pfad.public_base()!r} — mail links without prefix end up in a 404")
r.check("...and from a derived base as well",
        _sec.sichere_basis("https://a.example.com/sso/", ["a.example.com"])
        == "https://a.example.com/sso",
        "up to 0.18.x sichere_basis dropped the path")
r.check("...but nothing we cannot assemble cleanly (fail closed)",
        all(_sec.sichere_basis("https://a.example.com" + _p, ["a.example.com"]) == ""
            for _p in ("/../etc", "/sso/../x", "/a//b", "/s so", "/a%2fb")),
        "a half-guessed prefix would go into every outgoing mail")

# Finally: the configuration check was completely silent on `base_url` — whoever left the gap open
# learned it nowhere.
from tinysesam import config_check as _kp  # noqa: E402

_fehler, _warn = _kp.check_config(TinySesamConfig(password_reset_enabled=True))
r.check("config_check names the missing base_url",
        any("base_url ist leer" in f for f in _fehler), f"{_fehler!r}")
_fehler2, _warn2 = _kp.check_config(auth_ok.cfg)
r.check("with base_url set it stays silent about it",
        not any("base_url ist leer" in m for m in _fehler2 + _warn2), f"{_fehler2!r} {_warn2!r}")

# The warning is measured for EVERY switch that builds an absolute address — not only for
# the mail paths. Before, the suite covered three of the six entries: `BRAUCHT_BASE_URL` could
# be shortened by `oidc_enabled`, `saml_enabled` and `forward_auth_enabled` without a
# single check turning red (mutation probe N4, full suite 46/46 green).
#
# The six switches are therefore WRITTEN OUT, not a loop over the table itself:
# a loop over `BRAUCHT_BASE_URL` would only check the entries still in it — whoever removes
# one would take the check away with it. (Exactly that was noticed when reproducing the
# mutation probe.) What is asked is a bare config, no instance: `check_config` only reads
# fields, and so the line needs neither [oidc] nor [saml].
#
# Since rework N1 the message is separated by severity: the five paths that hand an absolute
# address into FOREIGN hands (mail, IdP) are an **error** — the setup fails, because a
# warning starts up and `/auth/forgot` otherwise keeps rendering the success page without a mail.
# Forward-auth stays a **warning**: without a base the redirect stays relative, hits the same
# browser and gives nothing to third parties. Both tables are measured here, each in its severity.
_BRAUCHT_BASIS = ("magiclink_enabled", "password_reset_enabled", "signup_verify_email",
                  "oidc_enabled", "saml_enabled")
_EMPFIEHLT_BASIS = ("forward_auth_enabled",)
r.check("the table names all six functions that build absolute addresses",
        set(_BRAUCHT_BASIS) <= set(_kp.BRAUCHT_BASE_URL)
        and set(_EMPFIEHLT_BASIS) <= set(_kp.BASE_URL_EMPFOHLEN),
        f"not named: {sorted((set(_BRAUCHT_BASIS) - set(_kp.BRAUCHT_BASE_URL)) | (set(_EMPFIEHLT_BASIS) - set(_kp.BASE_URL_EMPFOHLEN)))}")
for _feld in _BRAUCHT_BASIS:
    _f3, _w3 = _kp.check_config(TinySesamConfig(**{_feld: True}))
    r.check(f"config_check reports {_feld} without base_url as an ERROR",
            any("base_url ist leer" in f for f in _f3),
            f"{_f3!r} — this switch hands an absolute address out of hand but tells nobody")
for _feld in _EMPFIEHLT_BASIS:
    _f3, _w3 = _kp.check_config(TinySesamConfig(**{_feld: True}))
    r.check(f"config_check warns for {_feld} without base_url (not an error)",
            any("base_url ist leer" in w for w in _w3)
            and not any("base_url ist leer" in f for f in _f3),
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
    cfg.setdefault("base_url", ECHT)
    auth_x, app_x = _app(oidc_enabled=True, oidc_issuer="https://idp.example.invalid",
                         oidc_client_id="probe", oidc_client_secret="geheim",
                         csrf_enabled=False, passkey_enabled=False, **cfg)
    auth_x.oidc._meta = dict(_OIDC_META)   # no network needed: what is checked is the base, not discovery
    return auth_x, app_x


def _oidc_app_ohne_basis(**cfg):
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
def _bricht_ab(ruf):
    """(aborted with ConfigError, text of the response or of the exception).

    Since N1 these paths raise `ConfigError` instead of `HTTPException(500)`: a server error in the middle
    of a sign-in attempt was the wrong place for a problem that was already settled at setup.
    What is measured is therefore the abort, no longer a status line — and in both cases that
    the foreign host does not show through anywhere.
    """
    try:
        antwort = ruf()
    except _CfgErr as e:
        return True, str(e)
    return False, getattr(antwort, "text", "") + str(getattr(antwort, "headers", ""))


_a_oi, _app_oi = _oidc_app_ohne_basis()
with TestClient(_app_oi) as _c:
    _oi_ab, _oi_text = _bricht_ab(
        lambda: _c.get("/auth/oidc/start", headers={"host": BOESE}, follow_redirects=False))
r.check("OIDC start: forged host builds no redirect URI (fail closed)",
        _oi_ab and BOESE not in unquote(_oi_text),
        f"aborted={_oi_ab}: {_oi_text[:160]!r}")

_a_oi2, _app_oi2 = _oidc_app(base_url=ECHT)
with TestClient(_app_oi2) as _c:
    _start_gut = _c.get("/auth/oidc/start", headers={"host": BOESE}, follow_redirects=False)
_ziel_gut = unquote(_start_gut.headers.get("location", ""))
r.check("...and with base_url the flow continues, on the own address",
        _start_gut.status_code == 303 and ECHT + "/auth/oidc/callback" in _ziel_gut
        and BOESE not in _ziel_gut,
        f"HTTP {_start_gut.status_code}: {_ziel_gut[:160]!r} — otherwise the line above only checks "
        "that the start is broken at all")

# (2) OIDC post-logout. The `post_logout_redirect_uri` goes to the IdP; derived from the Host
# header, the IdP sends the victim to the attacker's server after signing out.
def _abmelden(auth_x, app_x):
    uid = auth_x.create_user("wer", password="Geheim12345!abc")
    tok = auth_x.store.create_session(uid, 3600, True, "oidc")
    with TestClient(app_x) as c:
        c.cookies.set(auth_x.cfg.session_cookie, tok)
        return c.get("/auth/logout", headers={"host": BOESE}, follow_redirects=False)


_a_pl, _app_pl = _oidc_app_ohne_basis(oidc_rp_logout=True)
_logout_boese = _abmelden(_a_pl, _app_pl)
_loc_boese = unquote(_logout_boese.headers.get("location", ""))
r.check("OIDC logout: no post_logout_redirect_uri from the Host header",
        BOESE not in _loc_boese and _loc_boese == _a_pl.cfg.logout_redirect,
        f"{_loc_boese!r} — the IdP then sent the victim to the attacker")

_a_pl2, _app_pl2 = _oidc_app(oidc_rp_logout=True, base_url=ECHT)
_loc_gut = unquote(_abmelden(_a_pl2, _app_pl2).headers.get("location", ""))
r.check("...and with base_url the provider logout still signs out (the path lives)",
        _loc_gut.startswith("https://idp.example.invalid/logout")
        and ECHT + _a_pl2.cfg.logout_redirect in _loc_gut and BOESE not in _loc_gut,
        f"{_loc_gut!r}")


# (3) SAML: entity ID and ACS URL. Both are the IDENTITY of the SP — a foreign name in them
# travels into the AuthnRequest and into the metadata that the operator registers at the IdP.
# The dummy stands for the real client: what is checked is the base the router gives it,
# not the signature work of python3-saml. So this line does not need the [saml] extra —
# a skip would not be a green here.
class _SamlAttrappe:
    def login_url(self, req, base, return_to="/"):
        return f"https://idp.example.invalid/sso?sp={base}&RelayState={return_to}", "rid-1"

    def process(self, req, base, request_id=""):
        return None      # "assertion rejected" → 400; a 500 would mean: there was no base at all

    def metadata(self, base):
        return f'<EntityDescriptor entityID="{base}/auth/saml/metadata"/>'


def _saml_app(**cfg):
    tmp = tempfile.mkdtemp()
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False)
    grund.update(cfg)
    auth_x = TinySesam(TinySesamConfig(**grund))
    auth_x.saml = _SamlAttrappe()    # BEFORE router(): the SAML routes hang on auth.saml
    app_x = FastAPI()
    app_x.include_router(auth_x.router())
    return auth_x, app_x


_a_sa, _app_sa = _saml_app()
with TestClient(_app_sa) as _c:
    _md_ab, _md_text = _bricht_ab(lambda: _c.get("/auth/saml/metadata", headers={"host": BOESE}))
    _lg_ab, _lg_text = _bricht_ab(
        lambda: _c.get("/auth/saml/login", headers={"host": BOESE}, follow_redirects=False))
    _acs_ab, _ = _bricht_ab(
        lambda: _c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, headers={"host": BOESE}))
r.check("SAML metadata: no entity ID from the Host header",
        _md_ab and BOESE not in _md_text, f"aborted={_md_ab}: {_md_text[:160]!r}")
r.check("SAML login: no AuthnRequest with a foreign SP address",
        _lg_ab and BOESE not in unquote(_lg_text),
        f"aborted={_lg_ab}: {_lg_text[:160]!r}")
r.check("SAML ACS: aborts before an assertion is checked against a foreign ACS URL",
        _acs_ab, "the assertion would have been checked against a foreign ACS URL")

_a_sa2, _app_sa2 = _saml_app(base_url=ECHT)
with TestClient(_app_sa2) as _c:
    _md_gut = _c.get("/auth/saml/metadata", headers={"host": BOESE})
    _lg_gut = _c.get("/auth/saml/login", headers={"host": BOESE}, follow_redirects=False)
    _acs_gut = _c.post("/auth/saml/acs", data={"SAMLResponse": "x"}, headers={"host": BOESE})
r.check("...and with base_url SAML carries the own address (metadata, login, ACS live)",
        _md_gut.status_code == 200 and f'entityID="{ECHT}/auth/saml/metadata"' in _md_gut.text
        and _lg_gut.status_code == 303 and f"sp={ECHT}" in unquote(_lg_gut.headers["location"])
        and _acs_gut.status_code == 400 and BOESE not in _md_gut.text,
        f"Metadata HTTP {_md_gut.status_code}: {_md_gut.text[:90]!r}; Login HTTP "
        f"{_lg_gut.status_code}; ACS HTTP {_acs_gut.status_code} (400 = base was there, assertion "
        "rejected; 500 = no base)")

# (4) Forward-auth redirect. The proxy sends every non-signed-in visitor to the
# address from `X-TinySesam-Location` — if a foreign host stood there, the proxy would itself lead the victim
# to the attacker's sign-in page. What is checked is the HOST of the redirect: the `next=`
# carries the requested URL and may do so, `safe_next` discards it later.
_a_fa, _app_fa = _app(forward_auth_enabled=True, csrf_enabled=False, passkey_enabled=False,
                      trusted_redirect_hosts=["app.example.com"])
with TestClient(_app_fa) as _c:
    _fa_boese = _c.get("/auth/forward", headers={"host": BOESE, "x-forwarded-host": BOESE,
                                                 "x-forwarded-proto": "https",
                                                 "x-forwarded-uri": "/geheim"})
    _fa_gut = _c.get("/auth/forward", headers={"host": "app.example.com",
                                               "x-forwarded-host": "app.example.com",
                                               "x-forwarded-proto": "https",
                                               "x-forwarded-uri": "/geheim"})
_loc_fa = _fa_boese.headers.get("X-TinySesam-Location", "")
r.check("Forward-Auth: the 401 redirect points to no foreign host",
        _fa_boese.status_code == 401 and not (urlsplit(_loc_fa).hostname or "")
        and _loc_fa.startswith(_a_fa.cfg.login_path + "?next="),
        f"HTTP {_fa_boese.status_code}: {_loc_fa[:140]!r} — the proxy itself led the victim there")
_loc_fa_gut = _fa_gut.headers.get("X-TinySesam-Location", "")
r.check("...and on a host from trusted_redirect_hosts it stays absolute (cookie host)",
        _fa_gut.status_code == 401
        and _loc_fa_gut.startswith("https://app.example.com" + _a_fa.cfg.login_path),
        f"HTTP {_fa_gut.status_code}: {_loc_fa_gut[:140]!r}")

# ── The same ONE rule for the documented methods, not only for the routes ───
# `public_base()` sat only in the routes. An app with its own "forgot password" form —
# the path shown in both READMEs and in API.md — called `send_password_reset(mail, basis)`
# itself and was still fully attackable with `str(request.base_url)`, while the
# built-in route had long since been fixed. The check now sits in `magic_url()`, where all
# four mail paths converge, and additionally before the token is issued in every sender.
#
# What is measured is the RULE, not its mechanism: If `base_url` is set, it wins — even against
# a second co-trusted name. That was exactly finding B-umgehung-3: Here the
# passed host still decided as long as it was in `trusted_redirect_hosts`. The `Host` header thus
# still chose which of the own names ends up in the reset link — the core of R4-01, one level
# deeper. Without `base_url` — the only setup in which anything is derived at all — it stays
# with the hard `ConfigError`.
_a_api, _app_api = _app(magiclink_enabled=True, password_reset_enabled=True, passkey_enabled=False,
                        base_url=ECHT,
                        trusted_redirect_hosts=["auth.example.com", "app-b.example.com"])
_mails_api: list = []
_a_api.set_mailer(lambda to, betreff, text, html=None: _mails_api.append(text))
_a_api.create_user("opfer", password="Geheim12345!abc", email="opfer@example.com")
# This round sends a dozen mails to the same address; what is measured is the base, not the
# throttle per target address (R4-04, own test in test_magic.py) — it gets room here.
_a_api.set_security("mail_per_address_max", 100)


def _tokenzeilen(auth_x) -> int:
    return auth_x.store._exec("SELECT COUNT(*) FROM magic_token").fetchone()[0]


def _versende(senden):
    """Run the send that `_verify_mail` returns (None: no mailer)."""
    return senden() if senden else senden


def _wege(auth_x, basis):
    """The documented paths, all with the SAME passed base."""
    return (
        ("magic_url", lambda: auth_x.magic_url("rohtoken", basis, "reset_password")),
        ("send_password_reset", lambda: auth_x.send_password_reset("opfer@example.com", basis)),
        ("send_login_link", lambda: auth_x.send_login_link("opfer@example.com", basis)),
        ("send_verify_email", lambda: auth_x.send_verify_email(1, "opfer@example.com", basis)),
        # Registration creates the token in the request and sends later (T-13 attack,
        # mail × operation) — it calls `_verify_mail` directly, so it is also measured directly.
        ("_verify_mail", lambda: _versende(auth_x._verify_mail(1, "opfer@example.com", basis))),
        ("create_invite", lambda: auth_x.create_invite("gast@example.com", basis)),
        # R4-03: the notice to the owner of a taken address carries the way to sign in.
        ("_send_signup_notice", lambda: auth_x._send_signup_notice("opfer@example.com", basis)),
        # Self-service (2026-09-25): the link to the NEW address; the confirmation path for
        # addresses from LDAP/SAML also runs through here (`_adresse_aus_quelle_belegen`).
        ("request_email_change", lambda: _versende(auth_x.request_email_change(
            auth_x.store.get_user_by_name("opfer")["id"], "opfer-neu@example.com", basis))),
        # …and since the attack round of 2026-09-26 via the wrapper with the source that
        # `_adresse_aus_quelle_belegen` calls (detail `konto=<id> quelle=…`). The same link.
        ("_wechsel_beantragen", lambda: _versende(auth_x._wechsel_beantragen(
            auth_x.store.get_user_by_name("opfer")["id"], "opfer-quelle@example.com", basis,
            quelle="ldap"))),
    )


def _spur(erg, mails) -> str:
    """Everything the call gave to the outside: return value plus sent mail texts."""
    return repr(erg) + " " + " ".join(mails)


for _fremd, _was in (("https://" + BOESE, "einen fremden Host"),
                     ("https://app-b.example.com", "einen ZWEITEN eigenen Namen")):
    for _name, _ruf in _wege(_a_api, _fremd):
        _mails_api.clear()
        try:                            # a ConfigError would be a finding here too, not an abort
            _s = _spur(_ruf(), _mails_api)
        except ConfigError as e:
            _s = f"ConfigError: {e}"[:140]
        r.check(f"{_name}: base_url wins against {_was}",
                (urlsplit(_fremd).hostname or "") not in _s and ECHT in _s,
                f"{_s[:140]!r} — otherwise the Host header chooses what goes into the link")

# Without `base_url` it stays with the hard abort: no link, no mail, no token. This setup
# is the only one that `config_check` lets through without `base_url` (no mail switch on), and exactly it
# is named by the finding as the occasion — an embedding app with its own form.
_a_ohne, _app_ohne = _app(passkey_enabled=False, trusted_redirect_hosts=["auth.example.com"])
_mails_ohne: list = []
_a_ohne.set_mailer(lambda to, betreff, text, html=None: _mails_ohne.append(text))
_a_ohne.create_user("opfer", password="Geheim12345!abc", email="opfer@example.com")
for _name, _ruf in _wege(_a_ohne, "https://" + BOESE):
    try:
        _abgewiesen, _wie = False, repr(_ruf())
    except ConfigError as e:
        _abgewiesen, _wie = True, str(e)[:60]
    r.check(f"without base_url: {_name}(foreign base) is rejected, not delivered",
            _abgewiesen, f"got through: {_wie} — the app with its own form stays attackable")

r.check("no mail goes out in the process", _mails_ohne == [], f"{_mails_ohne!r}")
r.check("and no unusable token remains in the database",
        _tokenzeilen(_a_ohne) == 0,
        f"{_tokenzeilen(_a_ohne)} rows — the check happens before the token is issued, not after")

# The legitimate path of the app: the promised base. Without this promise, "never a link again"
# would also be green. The host of the own base_url suffices — an `http://` from a TLS-terminating
# proxy is lifted to the configured address instead of silently staying unencrypted.
_mails_api.clear()
r.check("legitimate path: base_url supplies the link",
        _a_api.magic_url("rohtoken", ECHT, "reset_password") == ECHT + "/auth/reset?token=rohtoken",
        _a_api.magic_url("rohtoken", ECHT, "reset_password"))
r.check("str(request.base_url) on the own host stays usable — and does not become http",
        _a_api.magic_url("rohtoken", "http://auth.example.com/", "reset_password")
        == ECHT + "/auth/reset?token=rohtoken",
        _a_api.magic_url("rohtoken", "http://auth.example.com/", "reset_password"))
r.check("and the sender sends with it again (the method lives)",
        _a_api.send_password_reset("opfer@example.com", ECHT) is True
        and len(_mails_api) == 1 and ECHT + "/auth/reset" in _mails_api[0],
        f"{_mails_api!r}")
r.check("the legitimate path works even without base_url (derived, proven base)",
        _a_ohne.magic_url("rohtoken", "https://auth.example.com", "reset_password")
        == ECHT + "/auth/reset?token=rohtoken",
        _a_ohne.magic_url("rohtoken", "https://auth.example.com", "reset_password"))

# Finding B-regression-2: The path part appeared FOUR times in the sent link. `sichere_basis()`
# has returned it itself since N1, `_gepruefte_basis()` still appended it once more — and
# because the four senders check themselves first and `magic_url()` a second time afterwards,
# `https://portal.example.com/portal` grew to `…/portal/portal/portal/portal/auth/reset?token=…`.
# The mail went out, the recipient clicked, the link was 404: no error, no log line.
# Therefore COUNTING is used, not `startswith` — exactly that kept the finding hidden.
_UNTER = "https://portal.example.com/portal"
_a_pfad, _app_pfad = _app(passkey_enabled=False, trusted_redirect_hosts=["portal.example.com"])
_mails_pfad: list = []
_a_pfad.set_mailer(lambda to, betreff, text, html=None: _mails_pfad.append(text))
_a_pfad.create_user("opfer", password="Geheim12345!abc", email="opfer@example.com")
_a_pfad.set_security("mail_per_address_max", 100)   # as above: the path is measured, not R4-04
def _links(texte) -> list:
    """All addresses on the subpath host that a call gave to the outside."""
    return [g for t in texte for g in re.findall(r"https://portal\.example\.com[^\s'\"]*", t)]


for _name, _ruf in _wege(_a_pfad, _UNTER):
    _mails_pfad.clear()
    _erg = _ruf()
    _gefunden = _links([repr(_erg)] + list(_mails_pfad))
    # Counting happens in the PATH, not in the whole string: "https://portal…" already contains "/portal"
    # through the "//" — a count over that would also have let the fourfold link through.
    _zaehl = [urlsplit(u).path.count("/portal") for u in _gefunden]
    r.check(f"{_name}: the subpath appears exactly ONCE in the link",
            bool(_zaehl) and all(z == 1 for z in _zaehl)
            and all(u.startswith(_UNTER + "/auth/") for u in _gefunden),
            f"{_zaehl} occurrences in {[u[:90] for u in _gefunden]!r}")
r.check("the check is idempotent (applied twice, the path does not grow)",
        _a_pfad._gepruefte_basis(_a_pfad._gepruefte_basis(_UNTER)) == _UNTER,
        f"{_a_pfad._gepruefte_basis(_a_pfad._gepruefte_basis(_UNTER))!r} — the four senders "
        "check before the token is issued, magic_url once more afterwards")

# Finding B-regression-3: What a mount under a subpath REALLY carries — measured on
# a real mount (`FastAPI(root_path="/sso")`), not on a replicated URL. The
# sent link carries the prefix exactly once; since T-15 the built-in pages
# and their redirects carry it too (`auth.pfad`, placeholder `__TS_P__` in `templates.py`). Until then the
# limit was in README, CONFIGURATION and CHANGELOG, and this test kept it honest; the full
# measurement (mount and uvicorn --root-path, all pages) is in tests/test_subpath.py.
_a_mnt = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"),
                                   cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                                   password_reset_enabled=True,
                                   base_url="https://example.com/sso"))
_mails_mnt: list = []
_a_mnt.set_mailer(lambda to, betreff, text, html=None: _mails_mnt.append(text))
_a_mnt.create_user("anna", password="Geheim12345!abc", email="anna@example.com")
_app_mnt = FastAPI(root_path="/sso")
_app_mnt.include_router(_a_mnt.router())
_c_mnt = TestClient(_app_mnt, root_path="/sso", follow_redirects=False)
_c_mnt.post("/auth/forgot", data={"email": "anna@example.com"}, headers={"accept": "text/html"})
_link_mnt = [w for w in " ".join(_mails_mnt).split() if w.startswith("http")]
r.check("real mount under /sso: the mail link carries the prefix exactly once",
        len(_link_mnt) == 1 and _link_mnt[0].startswith("https://example.com/sso/auth/reset?")
        and urlsplit(_link_mnt[0]).path.count("/sso") == 1,
        f"{_link_mnt!r} — without prefix it is a 404, repeated too")
_seite_mnt = _c_mnt.get("/auth/login", headers={"accept": "text/html"}).text
_ziel_mnt = _c_mnt.get("/auth/account", headers={"accept": "text/html"}).headers.get("location", "")
_wurzel_mnt = re.findall(r"(?:href|action)='(/[^']*)'", _seite_mnt)
r.check("...and the built-in pages carry it too (T-15): form, links, redirect",
        "action='/sso/auth/login'" in _seite_mnt and _wurzel_mnt
        and all(z.startswith("/sso/") for z in _wurzel_mnt)
        and _ziel_mnt.startswith("/sso/auth/login?next=/sso/auth/account"),
        f"{_ziel_mnt!r} / without prefix: {[z for z in _wurzel_mnt if not z.startswith('/sso/')]}")

# And the rule itself, mechanically: Where `public_base()` supplies a base,
# `_gepruefte_basis()` supplies EXACTLY the same, and where it stays empty, the method raises. Two paths,
# one result — otherwise they are two rules again, and the gap sits in the difference.
for _lab, _auth_x in (("mit base_url", _a_api), ("ohne base_url", _a_pfad)):
    for _fall in (ECHT, "http://auth.example.com/", "https://app-b.example.com",
                  "https://" + BOESE, _UNTER, ""):
        _pb = _auth_x.public_base(candidate=_fall)
        try:
            _gb, _warf = _auth_x._gepruefte_basis(_fall), False
        except ConfigError:
            _gb, _warf = "", True
        r.check(f"one rule ({_lab}): public_base == _gepruefte_basis for {_fall!r}",
                _gb == _pb and _warf == (not _pb),
                f"public_base={_pb!r} _gepruefte_basis={_gb!r} raised={_warf}")

# ── A foreign registration occupied the login identifier of an account ────────
# Finding R4-12 (third audit). Registration checked the two name spaces only SEPARATELY:
# `email_taken` against users.email, `get_user_by_name` against users.username. But `find_user` in the
# default mode "both" searches BOTH columns and lets the e-mail win with an @. Thereby
# a stranger occupied the identifier of an existing account — the owner (even an admin) got
# 401 despite the correct password, and /auth/password from then on checked a foreign secret.

PW_INHABER, PW_EVE = "Geheim12345!abc", "Angreifer12345!"


def _anmelden(client, kennung, passwort=PW_INHABER):
    return client.post("/auth/login", data={"username": kennung, "password": passwort, "next": "/"},
                       follow_redirects=False)


# Direction 1: the stranger's E-MAIL is the owner's username.
auth_n1, app_n1 = _app(allow_signup=True, signup_require_email=True, csrf_enabled=False)
chef1 = auth_n1.create_user("chef@example.com", password=PW_INHABER, is_admin=True)
c_n1 = TestClient(app_n1)
r.check("precondition: the owner gets in with his identifier",
        _anmelden(c_n1, "chef@example.com").status_code == 303,
        "without this starting point the rest of the check says nothing")
c_n1.cookies.clear()

angriff1 = c_n1.post("/auth/register",
                     data={"username": "eve", "password": PW_EVE,
                           "email": "chef@example.com", "next": "/"}, follow_redirects=False)
r.check("a registration whose E-MAIL is the username of an account is rejected",
        angriff1.status_code == 409, f"HTTP {angriff1.status_code} — the identifier is taken")
r.check("...and creates no account", auth_n1.store.get_user_by_name("eve") is None,
        "the account is in the database despite the rejection")
r.check("...the identifier still points to the owner",
        (auth_n1.find_user("chef@example.com") or {}).get("id") == chef1,
        "find_user resolves to a foreign account")
r.check("...and the owner can still sign in",
        _anmelden(c_n1, "chef@example.com").status_code == 303,
        "locked out — with the correct password")

# Direction 2 (the more dangerous one): the stranger's USERNAME is the owner's e-mail.
auth_n2, app_n2 = _app(allow_signup=True, signup_require_email=True, csrf_enabled=False)
chef2 = auth_n2.create_user("chef", password=PW_INHABER, email="chef@example.com", is_admin=True)
c_n2 = TestClient(app_n2)
angriff2 = c_n2.post("/auth/register",
                     data={"username": "chef@example.com", "password": PW_EVE,
                           "email": "eve@example.com", "next": "/"}, follow_redirects=False)
r.check("a registration whose USERNAME is the e-mail of an account is rejected",
        angriff2.status_code == 409, f"HTTP {angriff2.status_code} — the identifier is taken")
r.check("...and the e-mail identifier still points to the owner",
        (auth_n2.find_user("chef@example.com") or {}).get("id") == chef2,
        "the identifier was taken over")

# The legitimate path stays open — otherwise the guard would just be a broken registration.
frisch = c_n2.post("/auth/register",
                   data={"username": "neu", "password": "Neues12345!abcd",
                         "email": "neu@example.com", "next": "/"}, follow_redirects=False)
r.check("a registration with free identifiers still goes through", frisch.status_code == 303,
        f"HTTP {frisch.status_code}: {frisch.text[:120]}")

# And the same character string in both columns of the SAME account is no collision — in
# e-mail mode the address is the username, that is the intended path.
auth_n3, app_n3 = _app(allow_signup=True, signup_require_email=True,
                       login_identifier="email", csrf_enabled=False)
solo = TestClient(app_n3).post("/auth/register",
                               data={"password": "Einzel-Weg-2468!", "email": "solo@example.com",
                                     "next": "/"}, follow_redirects=False)
r.check("in e-mail mode the address remains the username at the same time", solo.status_code == 303,
        f"HTTP {solo.status_code}: {solo.text[:120]}")

# The guard sits in create_user, not only in the route: CLI, invitation and creation from
# OIDC/LDAP/SAML pass through here.
for was, ruf in (("einen Benutzernamen, der fremde E-Mail ist",
                  lambda: auth_n2.create_user("chef@example.com", password=PW_EVE)),
                 ("eine E-Mail, die fremder Benutzername ist",
                  lambda: auth_n2.create_user("zweitkonto", password=PW_EVE, email="chef"))):
    try:
        ruf()
        entstanden = True
    except ConfigError:
        entstanden = False
    r.check(f"create_user does not accept {was}", not entstanden,
            "the account is created — then the check in the route alone does not help")

# The collision must not arise via the admin panel either.
c_adm = TestClient(app_n2)
c_adm.cookies.set(auth_n2.cfg.session_cookie,
                  auth_n2.store.create_session(chef2, 3600, True, "password"))
for feld, koerper in (("E-Mail", {"username": "eve2", "email": "chef@example.com"}),
                      ("Benutzername", {"username": "chef@example.com", "email": "e2@example.com"})):
    antwort_adm = c_adm.post("/auth/admin/api/users", json=koerper)
    r.check(f"the admin API rejects a taken identifier in the field {feld}",
            antwort_adm.status_code == 409,
            f"HTTP {antwort_adm.status_code}: {antwort_adm.text[:120]}")

# Invitation: The address comes from the token there, not from the form — the guard must
# hit this path too, otherwise an invitation creates an account on a taken identifier.
# Since N6 the base must itself be proven (`_gepruefte_basis`) — a freely invented host
# no longer goes into a sent link. Loopback stands for it here; only the token is checked
# anyway, not the link.
_einladung = auth_n2.create_invite("chef@example.com", "http://127.0.0.1:8000")["token"]
antwort_inv = c_n2.post("/auth/register",
                        data={"username": "eve3", "password": PW_EVE, "invite": _einladung,
                              "next": "/"}, follow_redirects=False)
r.check("an invitation to a taken identifier is rejected",
        antwort_inv.status_code == 409,
        f"HTTP {antwort_inv.status_code}: {antwort_inv.text[:120]}")
r.check("...and creates no account", auth_n2.store.get_user_by_name("eve3") is None,
        "the account is in the database despite the rejection")

# And the machine path: a service account has no login, but its name is still an
# identifier in the shared space (`find_user` searches it too).
try:
    auth_n2.create_service("chef@example.com")
    _dienst_entstand = True
except ConfigError:
    _dienst_entstand = False
r.check("create_service does not accept a taken identifier", not _dienst_entstand,
        "the service account is created — and occupies the admin's identifier")

# Legacy stock: in a database from BEFORE the fix the collision is already there. Then
# /auth/password at least must not check the other person's secret (chain R4-12 + R4-10).
auth_alt, app_alt = _app(csrf_enabled=False)
opfer_alt = auth_alt.create_user("chef", password=PW_INHABER, email="chef@example.com")
# Past the guard = legacy stock: a raw INSERT without bucket (since G12c the store
# itself rejects the collision — the path of a foreign writer remains).
from tinysesam.store import jetzt as _jetzt  # noqa: E402
eve_alt = auth_alt.store._exec("INSERT INTO users(username, display_name, created_at) VALUES (?,?,?)",
                               ("chef@example.com", "chef@example.com", _jetzt())).lastrowid
auth_alt.set_password(eve_alt, PW_EVE)
r.check("precondition: the attacker's identifier resolves to the foreign account",
        (auth_alt.find_user("chef@example.com") or {}).get("id") == opfer_alt,
        "without this ambiguity the test checks nothing")
c_alt = TestClient(app_alt)
c_alt.cookies.set(auth_alt.cfg.session_cookie,
                  auth_alt.store.create_session(eve_alt, 3600, True, "password"))
fremd = c_alt.post("/auth/password", json={"current": PW_INHABER, "new": "Neues12345!abcd"})
r.check("/auth/password does not accept the password of a FOREIGN account",
        fremd.status_code == 403,
        f"HTTP {fremd.status_code} — the route is an oracle for foreign passwords")
r.check("...and the foreign password remains valid unchanged",
        auth_alt._check_password("chef", PW_INHABER) is not None,
        "the victim's secret was overwritten")
eigen = c_alt.post("/auth/password", json={"current": PW_EVE, "new": "Neues12345!abcd"})
r.check("...but still checks the own one", eigen.status_code == 200,
        f"HTTP {eigen.status_code}: {eigen.text[:120]}")

# And the stock itself? New collisions have been prevented by the database since G12c (trigger over the
# counting buckets, tests/test_identifier_space.py); one that is already in there (here: raw INSERT of a
# foreign writer) the guard can only REPORT, and exactly that it must do at startup: Without a
# line, a locked-out owner stays inexplicable.


def _start_log(db_pfad):
    """Build an instance on this database and record what it says at startup."""
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    seclog.addHandler(haken)
    try:
        TinySesam(TinySesamConfig(db_path=db_pfad, cookie_secure=False))
    finally:
        seclog.removeHandler(haken)
    return puffer.getvalue()


# The foreign writer's row without bucket again, as directly after the raw INSERT: Since then
# another path has filled it in (since G2 every successful sign-in cleans up from the account's watermark
# and looks it up via `konto_mit_topf`). Without this the probe no longer measures whether
# `kennungs_kollisionen` fills it in itself.
auth_alt.store._exec("UPDATE users SET topf_name = NULL, topf_mail = NULL WHERE id = ?", (eve_alt,))
r.check("precondition: the cross collision really is in the database",
        len(auth_alt.store.kennungs_kollisionen()) == 1,
        f"{[dict(z) for z in auth_alt.store.kennungs_kollisionen()]} — then the test measures nothing")
_text_k = _start_log(auth_alt.cfg.db_path)
r.check("startup reports an identifier collision in the existing stock", "Kennungs-Kollision" in _text_k,
        f"silent: {_text_k[:120]!r} — nobody learns why an account can no longer get in")
r.check("...and names both accounts involved",
        f"user_id={eve_alt}" in _text_k and f"user_id={opfer_alt}" in _text_k,
        f"without IDs the message cannot be worked through: {_text_k[:200]!r}")
# B-regression-7: Until this round the same message advised "Change one of the two identifiers
# (admin panel or CLI)" — and neither of them can do that. The admin API knows create, lock,
# roles, password and keys, but no route for renaming; the CLI does not create accounts
# at all. The operator to whom startup had just reported a collision thus ran into two
# doors that do not exist. Therefore not the wording is measured, but that the named
# paths exist. Since self-service (2026-09-25) there is `change_username` — the message
# names it instead of the `UPDATE users` by hand, and the path really resolves the collision (below).
r.check("...and names paths that really exist (change_username, store.set_email)",
        "store.set_email" in _text_k and hasattr(auth_alt.store, "set_email")
        and "auth.change_username" in _text_k and hasattr(auth_alt, "change_username"),
        f"{_text_k[:320]!r}")
r.check("...and no longer sends anybody to the UPDATE by hand",
        "UPDATE users" not in _text_k, f"{_text_k[:320]!r}")
# Since G13 (2026-09-26) panel and CLI can rename — the message names both, and what is measured
# again is that the named paths exist: the route in the admin router and the command in the CLI.
# Until then this check recorded the opposite ("neither in the admin panel nor in the CLI"), because it
# was true at the time.
from tinysesam.admin import build_admin_router as _bar  # noqa: E402
import tinysesam.__main__ as _cli_modul  # noqa: E402
_routen_k = {getattr(_rt, "path", "") for _rt in _bar(auth_alt).routes}
r.check("...and names panel and CLI — both paths really exist",
        "/api/users/<id>/username" in _text_k and "/api/users/{uid}/username" in _routen_k
        and "tinysesam rename" in _text_k and callable(getattr(_cli_modul, "_rename", None))
        and "weder im Admin-Panel noch im CLI" not in _text_k,
        f"{_text_k[:420]!r}, routes: {sorted(p for p in _routen_k if 'username' in p)}")
# The named path works: renaming resolves the collision, startup is silent afterwards.
auth_alt.change_username(eve_alt, "eve-umbenannt")
r.check("...and auth.change_username really resolves the collision",
        not auth_alt.store.kennungs_kollisionen()
        and "Kennungs-Kollision" not in _start_log(auth_alt.cfg.db_path),
        f"{[dict(z) for z in auth_alt.store.kennungs_kollisionen()]}")

# Integration of the round: The message names `store.set_email(...)` — and exactly this method takes
# the confirmation note ALONG since B-umgehung-8 (default: unconfirmed). Whoever follows the message to
# resolve a collision on an admin's account thereby incidentally deletes the proof of his address.
# That is fail-closed and right — but it must not surprise the operator, and `verified=True`
# is the way to keep a real proof. Both are measured together: the sentence in the
# message AND the behavior behind it. If either goes away, the check turns red.
r.check("...and says that store.set_email takes the confirmation note along",
        "email_verified=0" in _text_k and "verified=True" in _text_k,
        f"{_text_k[:400]!r} — the operator follows the message and silently loses the proof")
auth_alt.store.set_email_verified(opfer_alt, True)
auth_alt.store.set_email(opfer_alt, "chef-neu@example.com")
r.check("...and so it is: the named path stores the new address unconfirmed",
        auth_alt.store.get_user(opfer_alt)["email_verified"] == 0,
        "set_email leaves the proof of the OLD address in place — then the message is wrong, "
        "and an address change is a bootstrap path again (B-umgehung-8)")
auth_alt.store.set_email(opfer_alt, "chef-belegt@example.com", verified=True)
r.check("...and verified=True keeps it, as the message promises",
        auth_alt.store.get_user(opfer_alt)["email_verified"] == 1,
        "verified=True does not carry the proof — then the message names a path that does not exist")

# Counter-check, otherwise the message would be noise: In auth_n2 ONE account carries the same value in
# both own columns (chef / chef@example.com) — that is the intended path, no collision.
r.check("a database without cross collision stays silent",
        "Kennungs-Kollision" not in _start_log(auth_n2.cfg.db_path),
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
uid_b21 = auth_b21.create_user("nina", password="geheim12345", email="nina@example.com")
geheim_b21 = auth_b21.totp_begin(uid_b21)["secret"]
auth_b21.totp_confirm(uid_b21, pyotp.TOTP(geheim_b21).at(time.time() - 30))
codes_b21 = auth_b21.generate_recovery_codes(uid_b21)
c_b21 = TestClient(app_b21, base_url="https://app.example.com")
c_b21.get("/auth/login")
c_b21.post("/auth/login", data={"username": "nina", "password": "geheim12345", "next": "/",
                                "_csrf": c_b21.cookies.get(auth_b21.cfg.csrf_cookie)},
           follow_redirects=False)
c_b21.post("/auth/totp", data={"code": pyotp.TOTP(geheim_b21).now(), "next": "/",
                               "_csrf": c_b21.cookies.get(auth_b21.cfg.csrf_cookie)},
           follow_redirects=False)
sitzung_b21 = auth_b21.store.get_session(c_b21.cookies.get(auth_b21.cfg.session_cookie))

# Precondition: Without these three lines the attack below measures nothing. They establish that
# a fully valid second factor really stands here that COULD be lost.
r.check("precondition: the second factor is confirmed",
        auth_b21.store.has_confirmed_totp(uid_b21), "without TOTP the attack checks nothing")
r.check("precondition: ten recovery codes are present",
        auth_b21.store.count_recovery_codes(uid_b21) == len(codes_b21) == 10,
        f"{auth_b21.store.count_recovery_codes(uid_b21)}")
r.check("precondition: the session is fully valid (CSRF on, SameSite=Lax)",
        bool(sitzung_b21 and sitzung_b21["mfa_ok"]) and auth_b21.cfg.csrf_enabled
        and auth_b21.cfg.cookie_samesite == "lax",
        f"mfa_ok={sitzung_b21 and sitzung_b21['mfa_ok']} csrf={auth_b21.cfg.csrf_enabled}")

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
    geworfen = ""
except StateError as exc:
    geworfen = str(exc)
r.check("totp_begin() itself also refuses the overwrite", bool(geworfen),
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
uid_b7 = auth_b7.create_user("paul", password="geheim12345")
c_b7 = TestClient(app_b7, base_url="https://app.example.com")
c_b7.cookies.set(auth_b7.cfg.session_cookie,
                 auth_b7.store.create_session(uid_b7, 3600, True, "password"))
r.check("precondition: CSRF is on and the session cookie is SameSite=Lax",
        auth_b7.cfg.csrf_enabled and auth_b7.cfg.cookie_samesite == "lax",
        "without this situation a foreign link does not carry the cookie along — the test measures nothing")
seite_b7 = c_b7.get("/auth/totp/setup")
r.check("a GET on the setup page generates no secret",
        seite_b7.status_code == 200 and auth_b7.store.get_totp(uid_b7) is None,
        f"HTTP {seite_b7.status_code}, secret={auth_b7.store.get_totp(uid_b7) is not None} "
        "— a GET that writes can be triggered from outside")
r.check("...the page shows instead the button that starts it explicitly",
        "/auth/totp/setup/start" in seite_b7.text, "without the button the setup is walled off")
r.check("...and leaves no audit line",
        not any(z["event"] == "totp_setup_start" for z in auth_b7.store.recent_audit(20)),
        "audit noise that anybody can produce from outside")
csrf_b7 = c_b7.cookies.get(auth_b7.cfg.csrf_cookie)
start_b7 = c_b7.post("/auth/totp/setup/start", data={"_csrf": csrf_b7})
zeile_b7 = auth_b7.store.get_totp(uid_b7)
r.check("the POST with CSRF token sets up", start_b7.status_code == 200 and zeile_b7 is not None,
        f"HTTP {start_b7.status_code}: {start_b7.text[:120]}")
# B2-1 also promised the audit line — until 0.18.x the TOTP setup was invisible.
r.check("...and the setup appears in the audit log",
        any(z["event"] == "totp_setup_start" for z in auth_b7.store.recent_audit(20)),
        "the setup of a second factor leaves no trace")
vorher_b7 = zeile_b7["secret"]
fremd_b7 = c_b7.post("/auth/totp/setup/start", data={})           # no token = foreign page
r.check("a POST without CSRF token does not replace the running secret",
        fremd_b7.status_code == 403 and auth_b7.store.get_totp(uid_b7)["secret"] == vorher_b7,
        f"HTTP {fremd_b7.status_code} — the scanned QR image can be invalidated from outside")
quer_b7 = c_b7.get("/auth/totp/setup", headers={"Sec-Fetch-Site": "cross-site",
                                                "Sec-Fetch-Mode": "navigate"})
r.check("...and a click on a foreign link just as little",
        quer_b7.status_code == 200 and auth_b7.store.get_totp(uid_b7)["secret"] == vorher_b7,
        "the GET replaced the secret")
r.check("...the confirmation with the code from THIS secret arms it",
        auth_b7.totp_confirm(uid_b7, pyotp.TOTP(vorher_b7).at(time.time() - 30))
        and auth_b7.store.has_confirmed_totp(uid_b7),
        "the legitimate path is interrupted")

# The legitimate path must remain: set up where nothing exists yet …
auth_ok, app_ok = _app(csrf_enabled=False)
uid_ok = auth_ok.create_user("tom", password="geheim12345")
c_ok = TestClient(app_ok, follow_redirects=False)
c_ok.cookies.set(auth_ok.cfg.session_cookie,
                 auth_ok.store.create_session(uid_ok, 3600, True, "password"))
r.check("without set-up TOTP the setup page is still reachable",
        c_ok.get("/auth/totp/setup").status_code == 200, "the setup is walled off")
r.check("...and the start button sets up",
        c_ok.post("/auth/totp/setup/start").status_code == 200
        and auth_ok.store.get_totp(uid_ok) is not None, "the setup is walled off")
neu_ok = auth_ok.store.get_totp(uid_ok)["secret"]
r.check("...and the confirmation arms the factor",
        auth_ok.totp_confirm(uid_ok, pyotp.TOTP(neu_ok).at(time.time() - 30))
        and auth_ok.store.has_confirmed_totp(uid_ok))

# … and set up again after the regular switch-off (otherwise the fix would be a dead end).
auth_ok.totp_disable(uid_ok)
r.check("after the regular switch-off the setup is open again",
        c_ok.get("/auth/totp/setup").status_code == 200
        and c_ok.post("/auth/totp/setup/start").status_code == 200,
        "changing the authenticator would be impossible")

# Orphaned recovery codes (secret gone, codes still there) are cleaned up by the setup.
auth_v, _ = _app()
uid_v = auth_v.create_user("vera", password="geheim12345")
geheim_v = auth_v.totp_begin(uid_v)["secret"]
auth_v.totp_confirm(uid_v, pyotp.TOTP(geheim_v).at(time.time() - 30))
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
_u = _store_mod._Uhr(wand=lambda: _w[0], mono=lambda: _m[0])
_folge = [_u.jetzt()]
_w[0], _m[0] = 400.0, 10.0          # jump 600 s back, 10 s really elapsed
_folge.append(_u.jetzt())
_w[0], _m[0] = 2000.0, 20.0         # the wall clock jumps forward (NTP after boot)
_folge.append(_u.jetzt())
r.check("after a backward jump the clock keeps counting monotonically and follows forward",
        _folge == [1000, 1010, 2000], f"{_folge}")

auth_u, _ = _app()
uid_u = auth_u.create_user("uhrzeit", password="geheim12345")
tok_u = auth_u.store.create_session(uid_u, 3600, True, "password")
roh_magic = auth_u.create_magic_token("login", user_id=uid_u, ttl_min=10)
jetzt_u = _store_mod.jetzt()
# Both expired 60 s ago …
auth_u.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (jetzt_u - 60, auth_u.store.session_hash(tok_u)))
auth_u.store._exec("UPDATE magic_token SET expires_at=?", (jetzt_u - 60,))
# … and then the wall clock jumps back an hour.
_echt = _store_mod._UHR.wand
_store_mod._UHR.wand = lambda: _echt() - 3600
try:
    r.check("an expired session stays expired after a backward jump",
            auth_u.store.get_session(tok_u) is None, "the session revives")
    r.check("an expired magic link stays expired",
            auth_u.redeem_magic(roh_magic, "login") is None, "the link can be redeemed again")
finally:
    _store_mod._UHR.wand = _echt

# Across a restart: The database carries the state. Fresh clock, wall clock back an hour.
auth_n, _ = _app()
uid_n = auth_n.create_user("neustart", password="geheim12345")
tok_n = auth_n.store.create_session(uid_n, 3600, True, "password")
jetzt_n = _store_mod.jetzt()
auth_n.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (jetzt_n - 60, auth_n.store.session_hash(tok_n)))
auth_n.store.db.close()
_alte_uhr = _store_mod._UHR
_store_mod._UHR = _store_mod._Uhr(wand=lambda: _echt() - 3600)
_uhr_log = io.StringIO()
_uhr_h = logging.StreamHandler(_uhr_log)
logging.getLogger("tinysesam").addHandler(_uhr_h)
try:
    st_n = _store_mod.Store(auth_n.cfg.db_path)
    r.check("after a restart with the clock set back, the session stays expired",
            st_n.get_session(tok_n) is None, "the restart forgot the deadline")
    r.check("…and the lag of the system clock appears in the log",
            "Systemuhr" in _uhr_log.getvalue(), _uhr_log.getvalue()[:200])
    st_n.db.close()
finally:
    _store_mod._UHR = _alte_uhr
    logging.getLogger("tinysesam").removeHandler(_uhr_h)

# Across a restart up to the last SAVED state, not only up to the last event
# (A-B6-9-neustart): A link and a session, expired two hours before the restart, without
# anything having been created afterwards. The Pi boots with a date a year back. Before, `Store()`
# knew only MAX(created_at/ts) and raised the clock to the time of creation — both counted
# again for their full remaining period.
_T = 1_800_000_000.0
_wand_n = [_T]


def _neustart_nach_2h(sichern):
    """Creates link + session at T, lets 2 h pass, `sichern(store)` saves (or not),
    restarts with the clock set back a year. → (link valid?, session valid?, uhr_stand)"""
    _store_mod._UHR = _store_mod._Uhr(wand=lambda: _wand_n[0])
    _wand_n[0] = _T
    a = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "n.db"),
                                  cookie_secure=False))
    uid = a.create_user("pi", password="geheim12345")
    roh = a.create_magic_token("login", user_id=uid, ttl_min=15)
    tok = a.store.create_session(uid, 1800, False, "password")
    _wand_n[0] = _T + 7200
    sichern(a.store)
    a.store.db.close()
    _store_mod._UHR = _store_mod._Uhr(wand=lambda: _T - 365 * 86400)
    a.store = _store_mod.Store(a.cfg.db_path)
    gilt = (a.peek_magic(roh, purpose="login") is not None, a.store.get_session(tok) is not None)
    # A writer whose clock is NOT raised (a second process on the same file, started before
    # the backup) must not overwrite the saved state downwards.
    _store_mod._UHR = _store_mod._Uhr(wand=lambda: _T - 365 * 86400)
    a.store.UHR_SICHERN_SEK = 0
    a.create_user("nach-dem-boot")
    stand = int(a.store.get_setting(a.store.UHR_STAND) or 0)
    a.store.db.close()
    return gilt + (stand,)


def _per_healthcheck(st):
    st._geschrieben = None                   # the probe is due, like every 30 s in the container
    st.schreibprobe()


def _per_schreibzugriff(st):
    st.UHR_SICHERN_SEK = 0                   # "a minute has passed"
    st.set_setting("irgendwas", "1")


logging.getLogger("tinysesam").addHandler(_uhr_h)
try:
    _hc = _neustart_nach_2h(_per_healthcheck)
    _sz = _neustart_nach_2h(_per_schreibzugriff)
finally:
    _store_mod._UHR = _alte_uhr
    logging.getLogger("tinysesam").removeHandler(_uhr_h)
r.check("after a restart, what expired AFTER the last event stays expired "
        "(state from the write probe of the healthcheck)",
        _hc[:2] == (False, False), f"link valid: {_hc[0]}, session valid: {_hc[1]}")
r.check("…likewise with the state that an ordinary write access saves along",
        _sz[:2] == (False, False), f"link valid: {_sz[0]}, session valid: {_sz[1]}")
r.check("a writer with a non-raised clock does not reset the saved state",
        _hc[2] >= _T + 7200 and _sz[2] >= _T + 7200, f"uhr_stand={_hc[2]}/{_sz[2]}")

# `time.time` is not bound at import (A-B6-9-zeitpatch): An embedding app that sets the time forward
# in its tests thereby also sets TinySesam's clock forward. Bound, TinySesam never saw the
# patch — sessions and tokens never expired in the app's test.
from unittest import mock  # noqa: E402
import time as _time  # noqa: E402
_store_mod._UHR = _store_mod._Uhr()          # fresh clock: the jump should not remain in the process
try:
    auth_p, _ = _app()
    uid_p = auth_p.create_user("zeitpatch", password="geheim12345")
    tok_p = auth_p.store.create_session(uid_p, 60, False, "password")
    _echt_t = _time.time()
    with mock.patch("time.time", lambda: _echt_t + 3600):
        _gilt_p = auth_p.store.get_session(tok_p) is not None
finally:
    _store_mod._UHR = _alte_uhr
r.check("mock.patch('time.time') forward lets a session expire",
        not _gilt_p, "TinySesam does not see the patched time (bound at import)")

# freezegun also replaces `time.monotonic` — by the frozen time on the EPOCH scale
# (`calendar.timegm`, ≈1.8e9), not by the uptime (T-13 attack, note on B6-9). The
# clock carried this step forward as elapsed time and jumped about 57 years ahead; on
# leaving freeze_time it fell back, and `uhr_stand` raised every later opening of the database
# permanently into the year 2083. Reproduced with set sources, exactly in freezegun values.
_T21, _BETRIEB = 1_790_000_000.0, 200_000.0     # wall clock / real monotonic time (uptime)
_w21, _m21 = [_T21], [_BETRIEB]
_u21 = _store_mod._Uhr(wand=lambda: _w21[0], mono=lambda: _m21[0])
_f21 = [_u21.jetzt()]
_w21[0] = _m21[0] = _T21 + 3600                  # with freeze_time(+1 h): both sources frozen
_f21.append(_u21.jetzt())
_w21[0] = _m21[0] = _T21 + 3660                  # freezer.tick(60)
_f21.append(_u21.jetzt())
_w21[0], _m21[0] = _T21 + 5, _BETRIEB + 5        # left freeze_time: real sources are back
_f21.append(_u21.jetzt())
r.check("freezegun (monotonic on the epoch scale) sets the clock forward exactly and not by decades",
        _f21[1:3] == [int(_T21) + 3600, int(_T21) + 3660],
        f"{[int(x - _T21) for x in _f21]} s from start — expected [0, 3600, 3660, …]")
r.check("…and after leaving it does not run backwards",
        _f21[3] >= _f21[2], f"{[int(x - _T21) for x in _f21]} s ab Start")
# (Mutation probe: remove the plausibility check of the monotonic step in `_Uhr.jetzt` →
# both red; check only the upper limit, i.e. carry a negative step forward → the second red.)

# The counter-check to the plausibility limit: The protection from B6-9 also holds after a long
# pause. Months without a request, and meanwhile the wall clock jumps back an hour — the
# clock carries the real elapsed time forward instead of following the wall clock that jumped back.
_w22, _m22 = [_T21], [_BETRIEB]
_u22 = _store_mod._Uhr(wand=lambda: _w22[0], mono=lambda: _m22[0])
_u22.jetzt()
_pause = 200 * 86400
_w22[0], _m22[0] = _T21 + _pause - 3600, _BETRIEB + _pause
r.check("after a 200-day pause the clock still protects against a backward jump",
        _u22.jetzt() == int(_T21) + _pause, f"{_u22.jetzt() - int(_T21) - _pause} s off")
# (Mutation probe: set the limit to one day → red.)

# The same class in the store (second attack round, konfig): `_uhr_gesichert` and `_geschrieben`
# keep their own monotonic stamps. After a write under freezegun they stood on the
# epoch scale (≈1.8e9); afterwards the distance to the real monotonic time was negative and thus always
# "shorter than the period" — `uhr_stand` was no longer saved in the whole process (arithmetically
# for 57 years), and the write probe of /healthz checked only the connection.
_st23 = _store_mod.Store(str(Path(tempfile.mkdtemp()) / "uhr23.db"))
_st23.set_setting("x", "0")


def _unter_freezegun_schreiben():
    # freezegun supplies `time.monotonic` on the epoch scale; reproduced without the dependency.
    with mock.patch("time.monotonic", _time.time):
        _st23.set_setting("x", "fg")


def _uhr_stand_zurueck():
    # As if `uhr_stand` had last been saved two minutes ago (without `_exec`, so that
    # the stamps stay as the write under freezegun left them).
    _st23.db.execute("UPDATE setting SET value=? WHERE key=?",
                     (str(_store_mod.jetzt() - 120), _st23.UHR_STAND))
    _st23.db.commit()
    return _store_mod.jetzt() - 120


_unter_freezegun_schreiben()
_alt23 = _uhr_stand_zurueck()
_st23.schreibprobe()
r.check("after a write access under freezegun the write probe of /healthz writes again",
        int(_st23.get_setting(_st23.UHR_STAND)) > _alt23,
        f"uhr_stand stayed {int(_st23.get_setting(_st23.UHR_STAND)) - _store_mod.jetzt()} s behind — "
        "only the connection checked")
_unter_freezegun_schreiben()
_alt23 = _uhr_stand_zurueck()
_st23.set_setting("x", "1")
r.check("…and an ordinary write access saves uhr_stand along again",
        int(_st23.get_setting(_st23.UHR_STAND)) > _alt23,
        f"uhr_stand stayed {int(_st23.get_setting(_st23.UHR_STAND)) - _store_mod.jetzt()} s behind")
_st23.db.close()
# (Mutation probe: remove the condition `0 <=` in `Store._frisch` → both red.)


# ── pop_flow returned the same challenge twice (R3-8) ────────────────────
# Reading and deleting were two steps. Two callbacks with the same OIDC `state` (two
# threads, two workers on the same file) both read before one deleted. Reproduced
# deterministically: Between the SELECT of the first and its DELETE, a second
# worker (own connection, same file) consumes the same key.
auth_f, _ = _app()
st_a = auth_f.store
st_b = _store_mod.Store(auth_f.cfg.db_path)
st_a.put_flow("oidc:zustand", {"nonce": "n-1"})


class _Dazwischen:
    """Connection that lets the second worker take its turn after the flow is read."""

    def __init__(self, db):
        self._db, self.zweiter = db, None

    def execute(self, sql, *args):
        cur = self._db.execute(sql, *args)
        if sql.startswith("SELECT data, expires_at FROM flow") and self.zweiter is None:
            self.zweiter = st_b.pop_flow("oidc:zustand")
        return cur

    def __getattr__(self, name):
        return getattr(self._db, name)


_zw = _Dazwischen(st_a.db)
st_a.db = _zw
erster = st_a.pop_flow("oidc:zustand")
st_a.db = _zw._db
r.check("the second worker gets the flow state", _zw.zweiter == {"nonce": "n-1"}, f"{_zw.zweiter}")
r.check("…and the first then no longer — exactly one wins",
        erster is None, f"both got {erster}: challenge/state consumed twice")
st_a.put_flow("oidc:einfach", {"x": 1})
r.check("without a race the flow comes out exactly once",
        st_a.pop_flow("oidc:einfach") == {"x": 1} and st_a.pop_flow("oidc:einfach") is None)
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
fremd = _sqlite3.connect(auth_b.cfg.db_path, isolation_level=None, check_same_thread=False)
fremd.execute("BEGIN IMMEDIATE")                  # a second writer holds the lock …
_frei = _threading.Timer(0.5, lambda: fremd.execute("COMMIT"))
_frei.start()
try:
    auth_b.store.put_flow("warten", {"ok": True})  # … and this writer waits instead of failing
    gewartet = True
except _sqlite3.OperationalError as e:
    gewartet = str(e)
_frei.join(timeout=5)
fremd.close()
r.check("a writer waits for a briefly held lock instead of aborting",
        gewartet is True, f"{gewartet}")

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
                     base_url=ECHT)
auth_g.set_mailer(lambda to, betreff, text, html=None: None)
uid_g = auth_g.create_user("gesperrt", password="Geheim12345!abc", email="gesperrt@example.com")
auth_g.set_pin(uid_g, "471193")
key_g = auth_g.create_api_key(uid_g, "bot")["key"]
alt_g = auth_g.store.create_session(uid_g, 3600, True, "password")
magic_g = auth_g.create_magic_token("login", user_id=uid_g, email="gesperrt@example.com")
# Locked directly in the store, not via the panel: The tokens and the old session thus
# remain — what is checked is that no PATH can use them, not that the panel cleans up.
auth_g.store.set_disabled(uid_g, True)


@app_g.get("/geschuetzt")
def _geschuetzt_g(u=Depends(auth_g.require_user)):
    return {"u": u["username"]}


def _sitzungen_g():
    return {z["token_hash"] for z in auth_g.store.list_sessions(uid_g)}


vorher_g = _sitzungen_g()
cg = TestClient(app_g)
cg.post("/auth/login", data={"username": "gesperrt", "password": "Geheim12345!abc", "next": "/"},
        follow_redirects=False)
cg.post("/auth/pin", data={"username": "gesperrt", "pin": "471193", "next": "/"},
        follow_redirects=False)
magic_antwort = cg.post(f"/auth/magic/{magic_g}", follow_redirects=False)   # R4-02: POST redeems
r.check("sign-in link of a locked account is rejected",
        magic_antwort.status_code == 403, f"HTTP {magic_antwort.status_code}")

# The paths that do not run as a route here (passkey, OIDC, SAML, LDAP, chain) all end in
# `apply_factor` — the guard for the whole class sits there.
_leer = _Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""})
_durch = []
for _faktor in ("password", "pin", "passkey", "oidc", "saml", "magic", "totp"):
    try:
        auth_g.apply_factor(_leer, uid_g, _faktor, "198.51.100.7")
        _durch.append(_faktor)
    except _HTTPException as e:
        if e.status_code != 403:
            _durch.append(f"{_faktor}:{e.status_code}")
r.check("apply_factor refuses every factor to a locked account", not _durch,
        f"let through: {_durch}")
r.check("…and every rejected attempt appears in the audit log (login_disabled)",
        sum(z["event"] == "login_disabled" for z in auth_g.store.recent_audit(50)) >= 8,
        f"{[z['event'] for z in auth_g.store.recent_audit(20)]}")
r.check("…and no new session arose via any path", _sitzungen_g() == vorher_g,
        f"{len(_sitzungen_g() - vorher_g)} new session(s) for a locked account")
cg.cookies.set(auth_g.cfg.session_cookie, alt_g)
r.check("a session from before the lock opens nothing any more",
        cg.get("/geschuetzt").status_code == 401)
cg.cookies.clear()
r.check("an API key of the locked account opens nothing",
        cg.get("/geschuetzt", headers={"X-API-Key": key_g}).status_code == 401)

# The half session (first factor provided, TOTP open) does not become fully valid after a lock.
uid_h = auth_g.create_user("halb", password="Geheim12345!abc")
halb_tok = auth_g.store.create_session(uid_h, 3600, False, "password")
auth_g.store.set_disabled(uid_h, True)
r.check("a half session does not become fully valid via TOTP after the lock",
        auth_g.complete_totp(halb_tok) is None and auth_g.store.get_session(halb_tok) is None,
        "complete_totp issued a full session to a locked account")

# The operator's lock holds against an open confirmation link.
admin_g = auth_g.create_user("chefin-g", password="Geheim12345!abc", is_admin=True)
uid_v = auth_g.create_user("wartend", password="Geheim12345!abc", email="wartend@example.com")
auth_g.store.set_disabled(uid_v, True)                      # as after registration
verify_g = auth_g.create_magic_token("verify_email", user_id=uid_v, email="wartend@example.com")
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
_auftraege_w: list = []


async def _nichts_w():
    return None


def _festhalten_w(auftrag, bei_ueberlauf=None):
    _auftraege_w.append(auftrag)
    return _nichts_w


_mails_w: list = []
auth_g.set_mailer(lambda to, betreff, text, html=None: _mails_w.append((to, text)))
auth_g._postausgang.nachher = _festhalten_w
try:
    TestClient(app_g).post("/auth/register", data={
        "username": "wartet-noch", "password": "Neues-Passwort-lang-7", "email": "wartet@example.org"})
    _neu_w = auth_g.store.get_user_by_name("wartet-noch")
    _tok_w = auth_g.store._all("SELECT 1 FROM magic_token WHERE user_id=? AND purpose='verify_email' "
                               "AND used_at IS NULL", (_neu_w["id"],)) if _neu_w else []
    r.check("the confirmation token exists when the registration response goes out",
            bool(_neu_w) and len(_auftraege_w) == 1 and bool(_tok_w),
            f"account={bool(_neu_w)}, jobs={len(_auftraege_w)}, token={len(_tok_w)} — "
            "if it arises only in the outbox, a lock in the waiting window finds nothing")
    # (Mutation probe: create the token in `_versand` again — `auth.send_verify_email(...)` in the
    # job instead of `_verify_mail` in the request → red, here and in the mail check below. The
    # lock itself holds even then since the second attack round: `/auth/verify` no longer lifts a lock
    # of the operator — the second guard, checked via the public API below.)
    ca_g.post(f"/auth/admin/api/users/{_neu_w['id']}/disable", json={"disabled": True})
    for _a in _auftraege_w:
        _a()                                     # only now is the mail worker's turn
    _link_w = [re.search(r"/auth/verify/([\w\-]+)", t) for to, t in _mails_w if to == "wartet@example.org"]
    for _m in filter(None, _link_w):
        cv.post(f"/auth/verify/{_m.group(1)}", follow_redirects=False)
    r.check("a lock in the outbox's waiting window holds against the confirmation link",
            bool(auth_g.store.get_user(_neu_w["id"])["disabled"])
            and not auth_g.store.list_sessions(_neu_w["id"]),
            "the belatedly created token lifted the operator's lock")
    r.check("…and no mail with a dead link goes out for the discarded token",
            not _link_w, f"{len(_link_w)} confirmation mail(s) sent after the lock")
    # (Mutation probe: remove the check for an open token in `_token_mail` → red.)
finally:
    del auth_g._postausgang.nachher              # back to the class method

# The same via the PUBLIC API (second attack round, konfig): An embedding app with
# its own registration has only `create_user`, `store.set_disabled` and `after_response(…
# send_verify_email …)` — exactly the pattern the core itself used until T-13. The token
# still arises in the mail worker there, i.e. AFTER a lock in the waiting window, and the lock
# finds nothing to discard. The cause sat in `/auth/verify`: It set `disabled`
# unconditionally to 0, whether the lock came from the operator or the confirmation was merely outstanding.
from fastapi.responses import PlainTextResponse as _TextAntwort  # noqa: E402

_auftraege_p: list = []
_mails_p: list = []


def _festhalten_p(auftrag, bei_ueberlauf=None):
    _auftraege_p.append(auftrag)
    return _nichts_w


@app_g.post("/app/signup")
def _app_signup_p(name: str):
    _uid = auth_g.create_user(name, password="Neues-Passwort#lang-7", email=f"{name}@example.org")
    auth_g.store.set_disabled(_uid, True)                   # waits for the confirmation
    return auth_g.after_response(
        _TextAntwort("Mail unterwegs"),
        lambda: auth_g.send_verify_email(_uid, f"{name}@example.org", ECHT))


def _app_link_p(name):
    _t = [t for to, t in _mails_p if to == f"{name}@example.org"]
    _m = re.search(r"/auth/verify/([\w\-]+)", _t[-1]) if _t else None
    return _m.group(1) if _m else None


auth_g.set_mailer(lambda to, betreff, text, html=None: _mails_p.append((to, text)))
auth_g._postausgang.nachher = _festhalten_p
try:
    TestClient(app_g).post("/app/signup", params={"name": "app-gesperrt"})
    _uid_p = auth_g.store.get_user_by_name("app-gesperrt")["id"]
    ca_g.post(f"/auth/admin/api/users/{_uid_p}/disable", json={"disabled": True})
    for _a in _auftraege_p:
        _a()                                     # the mail worker creates the token only now
    _auftraege_p.clear()
    _link_p = _app_link_p("app-gesperrt")
    r.check("Guard: the app sends its confirmation link only after the lock",
            bool(_link_p), f"Mails: {len(_mails_p)}")
    _antwort_p = cv.post(f"/auth/verify/{_link_p}", follow_redirects=False) if _link_p else None
    r.check("a confirmation link created AFTER the lock does not lift the operator's lock",
            bool(auth_g.store.get_user(_uid_p)["disabled"]) and not auth_g.store.list_sessions(_uid_p),
            f"HTTP {getattr(_antwort_p, 'status_code', None)}, disabled="
            f"{auth_g.store.get_user(_uid_p)['disabled']}, sessions={len(auth_g.store.list_sessions(_uid_p))}")
    r.check("…the attempt appears in the audit log (verify_blocked)",
            any(z["event"] == "verify_blocked" and z["username"] == "app-gesperrt"
                for z in auth_g.store.recent_audit(30)),
            f"{[z['event'] for z in auth_g.store.recent_audit(8)]}")
    # (Mutation probe: in `/auth/verify` again `auth.store.set_disabled(uid, False)` instead of
    # `bestaetigung_freischalten` → red.)

    # Counter-check: Without an operator lock the same path unlocks the account — the
    # public API keeps its promise.
    TestClient(app_g).post("/app/signup", params={"name": "app-frei"})
    _uid_f = auth_g.store.get_user_by_name("app-frei")["id"]
    for _a in _auftraege_p:
        _a()
    _link_f = _app_link_p("app-frei")
    _antwort_f = TestClient(app_g).post(f"/auth/verify/{_link_f}", follow_redirects=False)
    r.check("…without an operator lock the link unlocks the app's account and signs in",
            _antwort_f.status_code == 303 and not auth_g.store.get_user(_uid_f)["disabled"]
            and bool(auth_g.store.list_sessions(_uid_f)),
            f"HTTP {_antwort_f.status_code}, disabled={auth_g.store.get_user(_uid_f)['disabled']}")
    # A renewed lock without operator note (`set_disabled(uid, True)`) does not downgrade an operator's
    # lock to "waiting for confirmation".
    auth_g.store.set_disabled(_uid_p, True)
    auth_g.send_verify_email(_uid_p, "app-gesperrt@example.org", ECHT)
    cv.post(f"/auth/verify/{_app_link_p('app-gesperrt')}", follow_redirects=False)
    r.check("…and a later set_disabled(uid, True) does not turn the operator lock into a liftable one",
            bool(auth_g.store.get_user(_uid_p)["disabled"]),
            f"disabled={auth_g.store.get_user(_uid_p)['disabled']}")
    # (Mutation probe: `set_disabled` without `durch_betreiber` sets a blind 1 again → red.)
finally:
    del auth_g._postausgang.nachher


# ── H-18 (c): every mail link arises from `base_url` — future ones too ─────────────
# The paths above (`_wege`) are a list by hand. A sixth sender would not be noticed
# there. Therefore mechanically: Every function in the package that calls `send_mail()` or `magic_url()`
# must be in this list — otherwise it sends links whose base nobody has measured.
import ast as _ast  # noqa: E402

# `_token_mail` is only the wrapper around `send_mail` (B6-12: token expires if sending
# fails) — the text including the link is built by its callers, and those are in `_wege`.
_GEMESSEN = {name for name, _ in _wege(_a_api, ECHT)} | {"send_mail", "magic_url", "_token_mail"}
# The lock notice (ASVS 6.3.5, `_sperrhinweis` with the inner `_senden`) carries NO link — there
# is no base to measure. That this stays so is checked by tests/test_t13_decisions.py (no "://").
_GEMESSEN |= {"_sperrhinweis", "_senden"}
# Likewise the notice to the OLD address after a change (`confirm_email_change` with the inner
# `hinweis`, ASVS 6.3.7) — without a link; tests/test_self_service.py checks that (no "://").
_GEMESSEN |= {"confirm_email_change", "hinweis", "_wechsel_antrag_hinweis"}
_absender = set()
for _datei in sorted((ROOT / "tinysesam").glob("*.py")):
    _baum = _ast.parse(_datei.read_text(encoding="utf-8"))
    for _fn in _ast.walk(_baum):
        if not isinstance(_fn, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            continue
        for _k in _ast.walk(_fn):
            if (isinstance(_k, _ast.Call) and isinstance(_k.func, _ast.Attribute)
                    and _k.func.attr in ("send_mail", "magic_url")):
                _absender.add(_fn.name)
r.check("Guard: it finds the known senders at all",
        {"send_password_reset", "send_login_link", "_verify_mail", "create_invite"} <= _absender,
        f"found: {sorted(_absender)} — without a hit the line below checks nothing")
r.check("every sender of mail links is in the measured list",
        _absender <= _GEMESSEN, f"unmeasured: {sorted(_absender - _GEMESSEN)} — add to `_wege`")


# ── Configuration check, T-13 area "Admin and configuration" ──────────────
from tinysesam import config_check as _kp2, security as _sec2  # noqa: E402


def _befund(**cfg):
    """(errors, warnings) for a config with a throwaway database."""
    cfg.setdefault("db_path", ":memory:")
    return _kp2.check_config(TinySesamConfig(**cfg))


def _nennt(liste, *woerter):
    return any(all(w in x for w in woerter) for x in liste)


# B3-3: an invalid trusted_proxies entry no longer invalidates the whole list …
r.check("B3-3: a valid entry works next to an invalid one",
        _sec2.is_trusted("198.51.100.7", ["proxy.intern", "198.51.100.0/24"]),
        "a hostname in the list raised, and the real proxy counted as foreign")
# (Mutation probe: is_trusted with a `try` around the whole any() again → red.)
r.check("...and the configuration check rejects the list",
        _nennt(_befund(trusted_proxies=["proxy.intern", "198.51.100.0/24"])[0], "trusted_proxies", "proxy.intern"))
r.check("...the default and real networks remain without finding",
        not _nennt(sum(_befund(trusted_proxies=["198.51.100.0/24", "::1"]), []), "trusted_proxies"))

# B3-6: stepup_methods is checked — a typo no longer silently removes the second factor.
r.check("B3-6: unknown step-up method is an error",
        _nennt(_befund(stepup_methods=["topt"])[0], "stepup_methods", "topt"))
r.check("...a switched-off one likewise (pin without pin_enabled)",
        _nennt(_befund(stepup_methods=["pin"])[0], "pin_enabled=False"))
r.check("...valid values remain without finding",
        not _nennt(sum(_befund(stepup_methods=["totp", "pin"], pin_enabled=True), []), "stepup_methods"))
try:
    TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), stepup_methods=["topt"]))
    _b36 = False
except _CfgErr:
    _b36 = True
r.check("...and the setup fails on it", _b36)

# B3-10: rp_id/origin are examined.
r.check("B3-10: rp_id that does not match the origin is an error",
        _nennt(_befund(passkey_enabled=True, rp_id="example.org", origin="https://auth.example.com")[0],
               "rp_id", "passt nicht"))
r.check("...origin with path is not an origin",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com",
                       origin="https://auth.example.com/login")[0], "ist kein Origin"))
r.check("...developer values next to a public base_url are reported",
        _nennt(_befund(passkey_enabled=True, base_url="https://auth.example.com")[1], "origin", "base_url"))
r.check("...matching values remain without finding",
        not _nennt(sum(_befund(passkey_enabled=True, rp_id="example.com", origin="https://auth.example.com",
                               base_url="https://auth.example.com"), []), "origin"))

# B3-12: number fields with limits.
for _feld, _wert in (("session_ttl_hours", 0), ("magiclink_ttl_min", 0), ("recovery_code_count", 0),
                     ("stepup_max_age_sec", -1), ("smtp_port", 70000), ("pin_min_length", 2),
                     ("session_ttl_hours", True)):
    r.check(f"B3-12: {_feld}={_wert!r} is an error", _nennt(_befund(**{_feld: _wert})[0], _feld))
r.check("...the defaults themselves all lie within their limits",
        not any(f in x for x in _befund()[0] for f in _kp2.ZAHLENGRENZEN))
# (Mutation probe: comment out `_zahlengrenzen(config, fehler)` in check_config() → red.)

# T-13 attack (audit × configuration): `audit_retention_days` was added after NUMBER LIMITS and
# was not in it — its own check rejected only `< 0`. `True` counted as one day (gc()
# deleted the audit log down to the last day), seconds instead of days defeated the period,
# 10**20 made gc() abort with OverflowError. `oidc_revalidate_minutes` was missing likewise. Therefore
# now the class: Every number field of the config has a limit or stands here, with a reason.
import dataclasses as _dc  # noqa: E402
import typing as _typing  # noqa: E402

_OHNE_ZAHLENGRENZE: dict = {}      # field → reason. Empty: Every number field has a limit.
_typen_cfg = _typing.get_type_hints(TinySesamConfig)
_zahlfelder = {f.name for f in _dc.fields(TinySesamConfig) if _typen_cfg[f.name] in (int, float)}
r.check("Guard: it finds number fields of the config at all",
        {"session_ttl_hours", "smtp_port"} <= _zahlfelder, f"{sorted(_zahlfelder)}")
r.check("every number field of the config has a limit in ZAHLENGRENZEN (or a justified exception)",
        not (_zahlfelder - set(_kp2.ZAHLENGRENZEN) - set(_OHNE_ZAHLENGRENZE)),
        f"without limit: {sorted(_zahlfelder - set(_kp2.ZAHLENGRENZEN) - set(_OHNE_ZAHLENGRENZE))}")
r.check("…and the exception list names only number fields without limit, each with a reason",
        all(f in _zahlfelder and f not in _kp2.ZAHLENGRENZEN and str(g).strip()
            for f, g in _OHNE_ZAHLENGRENZE.items()), f"{_OHNE_ZAHLENGRENZE!r}")
# (Mutation probe: remove `audit_retention_days` from ZAHLENGRENZEN → red.)
for _feld, _wert in (("audit_retention_days", True), ("audit_retention_days", 30 * 86400),
                     ("audit_retention_days", 10 ** 20), ("audit_retention_days", -1),
                     ("oidc_revalidate_minutes", True), ("oidc_revalidate_minutes", 86400),
                     ("oidc_revalidate_minutes", -1)):
    r.check(f"{_feld}={_wert!r} is an error", _nennt(_befund(**{_feld: _wert})[0], _feld))
for _feld, _wert in (("audit_retention_days", 3650), ("oidc_revalidate_minutes", 60)):
    r.check(f"…{_feld}={_wert} remains without error", not _nennt(_befund(**{_feld: _wert})[0], _feld))

# The upper limit (43200) catches a period in seconds only from one day (86400) — the preset's
# default, one hour, written in seconds (3600) passed silently: revalidation every 60
# hours instead of every hour, a revocation at the provider arrived 60 times later (second attack round,
# konfig). A period over one day therefore gets a warning that asks about the unit.
# 300 or 900 (five or 15 minutes in seconds) is caught by no limit — the docs now say so too.
def _rv_befund(minuten):
    return _kp2.check_config(TinySesamConfig.oidc_gateway(
        issuer="https://id.example.com", client_id="g", client_secret="s", base_url=ECHT,
        db_path=":memory:", clients={"app.example.com": {"client_id": "a", "client_secret": "b"}},
        revalidate_minutes=minuten))


for _min in (3600, 7200, 43200):
    _f, _w = _rv_befund(_min)
    r.check(f"oidc_revalidate_minutes={_min} (over a day) warns about seconds instead of minutes",
            _nennt(_w, "oidc_revalidate_minutes", "Sekunden") and not _nennt(_f, "oidc_revalidate_minutes"),
            f"warnings: {[x[:80] for x in _w]}")
for _min in (60, 1440):
    r.check(f"…{_min} minutes remain without warning",
            not _nennt(_rv_befund(_min)[1], "oidc_revalidate_minutes"))
# (Mutation probe: remove the warning in `check_config` → red; set the threshold to 43200 → red.)
_rv_kaputt = "keine Zahl"
try:
    _rv_fund = _nennt(_befund(oidc_revalidate_minutes=_rv_kaputt)[0], "oidc_revalidate_minutes")
except Exception as e:   # noqa: BLE001 — a crash of the check is the finding here
    _rv_fund = f"{type(e).__name__}: {e}"
r.check("…and a text instead of a number is a finding, not a crash of the check",
        _rv_fund is True, f"{_rv_fund!r}")

# The same class in the remaining combination checks that read a ZAHLENGRENZEN field (second
# attack round, konfig): `int()` on `admin_claim_ttl_min` and `mfa_enrollment_grace_days` crashed
# before `_zahlengrenzen` could report the type — `TinySesam(cfg)` raised ValueError or
# OverflowError instead of a collected ConfigError. Until the final round this probe covered only
# the three fields known at the time; a new combination with `int()` via an intermediate variable
# (`w = getattr(config, "magiclink_ttl_min", 15); int(w)`) made check_config() crash again, and
# the suite stayed green (final finding konfig-3). Now over EVERY field from ZAHLENGRENZEN, each with
# text, inf and nan, once with defaults and once behind the switches behind which today's
# combination checks lie (`_TORE`). Limit: A new combination behind a switch
# that is not in `_TORE` is reached only by the syntax-tree guard further below.
_TORE = {"admin_claim_token_file": "/run/x/admin.token", "mfa_enrollment": "grace"}
for _feld in _kp2.ZAHLENGRENZEN:
    _abstuerze = []
    for _wert in ("sieben", float("inf"), float("nan")):
        for _dazu in ({}, _TORE):
            try:
                _kf = _nennt(_befund(**{_feld: _wert}, **_dazu)[0], _feld, "keine ganze Zahl")
            except Exception as e:   # noqa: BLE001 — a crash of the check is the finding here
                _kf = f"{type(e).__name__}: {e}"
            try:
                TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "k.db"),
                                          **{_feld: _wert}, **_dazu))
                _kb = "baut"
            except ConfigError as e:
                _kb = _feld in str(e) or "ConfigError ohne das Feld"
            except Exception as e:   # noqa: BLE001
                _kb = f"{type(e).__name__}: {e}"
            if _kf is not True or _kb is not True:
                _abstuerze.append(f"{_wert!r}{' mit Schaltern' if _dazu else ''}: check_config {_kf!r} · Aufbau {_kb!r}")
    r.check(f"{_feld}=text/inf/nan: collected ConfigError instead of a crash of the check",
            not _abstuerze, "; ".join(_abstuerze[:3]))
r.check("…the probe runs over the fields from ZAHLENGRENZEN (not over an empty list)", len(_kp2.ZAHLENGRENZEN) >= 10,
        f"{len(_kp2.ZAHLENGRENZEN)} fields")
# (Mutation probe: the finding mutation `_mt = getattr(config, "magiclink_ttl_min", 15)` +
# `if int(_mt) > 600:` in check_config → red, `magiclink_ttl_min … ValueError`.)
# The combination checks themselves still apply:
r.check("…mfa_enrollment='grace' with 0 days remains an error",
        _nennt(_befund(mfa_enrollment="grace", mfa_enrollment_grace_days=0)[0], "mfa_enrollment='grace'"))
r.check("…admin_claim_token_file with admin_claim_ttl_min=0 remains a warning",
        _nennt(_befund(admin_claim_token_file="/run/x/admin.token", admin_claim_ttl_min=0)[1],
               "admin_claim_token_file"))
# (Mutation probe: replace `_ganzzahl` with `int(getattr(config, feld, 0) or 0)` → red.)
# The class in the code: A field from ZAHLENGRENZEN is read by the check only via `_ganzzahl` (an
# integer or None) or in `_zahlengrenzen` itself. What a combination does afterwards (int(),
# comparison, calculation) then happens with an integer. Until the final round the
# guard reported an int() only if getattr(config, …) stood directly in it — the intermediate variable got
# through (final finding konfig-3). Now on the syntax tree by class, not by spelling:
# 1. A string that names exactly one ZAHLENGRENZEN field stands as a key in ZAHLENGRENZEN or
#    as a field name in `_ganzzahl(config, "<feld>")` — otherwise something else reads it (`getattr`,
#    `_an`, `vars(config)[…]`, `attrgetter`, a tuple over which a loop runs).
# 2. No attribute `.<feld>`, no matter under which name the config stands.
# 3. A `getattr` with a field name at runtime uses the value only as a truth value or text
#    (directly in `bool()`/`str()` or in a condition, also via `and`/`or`) — that crashes with
#    no value. `vars`, `__dict__`, `asdict`, `attrgetter`, `__getattribute__` are forbidden.
# 4. No `int()`/`float()`, regardless of on what.
# `_ganzzahl` and `_zahlengrenzen` are excluded from this: They ARE the read path.
# Limit: A field name that arises only at runtime and goes through a truth-value helper
# (`_an(config, name)`) does not crash but is evaluated wrongly; a helper outside
# config_check.py to which the check passes `config` lies outside this tree. Only
# the function probe above sees both — and only without switch or with `_TORE`.
import ast as _ast_k  # noqa: E402

_KP_LESEWEG = {"_ganzzahl", "_zahlengrenzen"}
_KP_VERBOTEN = {"vars", "__dict__", "asdict", "attrgetter", "__getattribute__"}


def _kp_rohe_zahlen(baum):
    """Places in config_check.py that read or convert a number field past the read path."""
    felder = set(_kp2.ZAHLENGRENZEN)
    eltern = {c: k for k in _ast_k.walk(baum) for c in _ast_k.iter_child_nodes(k)}

    def funktion(k):
        while k in eltern:
            k = eltern[k]
            if isinstance(k, (_ast_k.FunctionDef, _ast_k.AsyncFunctionDef)):
                return k.name
        return "<modul>"

    def nur_wahrheit_oder_text(k):
        while isinstance(eltern.get(k), _ast_k.BoolOp):
            k = eltern[k]
        p = eltern.get(k)
        if isinstance(p, _ast_k.Call) and isinstance(p.func, _ast_k.Name) and p.func.id in ("str", "bool"):
            return k in p.args
        if isinstance(p, (_ast_k.If, _ast_k.While, _ast_k.IfExp, _ast_k.Assert)):
            return p.test is k
        return isinstance(p, _ast_k.UnaryOp) and isinstance(p.op, _ast_k.Not)

    def ist_grenzen_schluessel(k):
        d = eltern.get(k)
        z = eltern.get(d)
        return (isinstance(d, _ast_k.Dict) and k in d.keys and isinstance(z, _ast_k.Assign)
                and any(getattr(t, "id", "") == "ZAHLENGRENZEN" for t in z.targets))

    befunde = []
    for k in _ast_k.walk(baum):
        wo = funktion(k)
        if wo in _KP_LESEWEG:
            continue
        p = eltern.get(k)
        if isinstance(k, _ast_k.Constant) and isinstance(k.value, str) and k.value in felder:
            ueber_ganzzahl = (isinstance(p, _ast_k.Call) and isinstance(p.func, _ast_k.Name)
                              and p.func.id == "_ganzzahl" and len(p.args) >= 2 and p.args[1] is k)
            if not (ueber_ganzzahl or ist_grenzen_schluessel(k)):
                befunde.append(f"{k.lineno}: {k.value!r} in {wo} nicht über _ganzzahl gelesen")
        elif isinstance(k, _ast_k.Attribute) and (k.attr in felder or k.attr in _KP_VERBOTEN):
            befunde.append(f"{k.lineno}: .{k.attr} in {wo}")
        elif isinstance(k, _ast_k.Name) and k.id in _KP_VERBOTEN:
            befunde.append(f"{k.lineno}: {k.id} in {wo}")
        elif isinstance(k, _ast_k.Call) and isinstance(k.func, _ast_k.Name):
            if k.func.id in ("int", "float"):
                befunde.append(f"{k.lineno}: {k.func.id}() in {wo}")
            elif (k.func.id == "getattr" and not (len(k.args) > 1 and isinstance(k.args[1], _ast_k.Constant))
                  and not nur_wahrheit_oder_text(k)):
                befunde.append(f"{k.lineno}: getattr mit Laufzeit-Namen in {wo}, Wert nicht nur als Wahrheitswert/Text")
    return befunde


_kp_baum = _ast_k.parse((ROOT / "tinysesam" / "config_check.py").read_text(encoding="utf-8"))
_kp_getattr = [k for k in _ast_k.walk(_kp_baum) if isinstance(k, _ast_k.Call)
               and isinstance(k.func, _ast_k.Name) and k.func.id == "getattr"]
_kp_ganzzahl = [k for k in _ast_k.walk(_kp_baum) if isinstance(k, _ast_k.Call)
                and isinstance(k.func, _ast_k.Name) and k.func.id == "_ganzzahl"]
r.check("Guard: it finds the read accesses of the check at all",
        len(_kp_getattr) >= 20 and len(_kp_ganzzahl) >= 3, f"getattr {len(_kp_getattr)}, _ganzzahl {len(_kp_ganzzahl)}")
_kp_roh = _kp_rohe_zahlen(_kp_baum)
r.check("no combination check reads a number field past the read path _ganzzahl or converts itself",
        not _kp_roh, f"{_kp_roh}")


# Self-probe on the syntax tree (without text anchor): Every spelling is inserted at the front of check_config();
# only the findings it brings NEW are counted (a finding in the existing stock would otherwise carry the probe).
def _kp_mit(schnipsel):
    baum = _ast_k.parse((ROOT / "tinysesam" / "config_check.py").read_text(encoding="utf-8"))
    fn = next(k for k in baum.body if isinstance(k, _ast_k.FunctionDef) and k.name == "check_config")
    fn.body[0:0] = _ast_k.parse(schnipsel).body
    return set(_kp_rohe_zahlen(baum)) - set(_kp_roh)


_kp_uebersehen = [x for x in (
    '_mt = getattr(config, "magiclink_ttl_min", 15)\nif int(_mt) > 600:\n    pass',   # the finding
    '_mt = getattr(config, "magiclink_ttl_min", 15)\nif _mt > 600:\n    pass',        # without int()
    'if config.magiclink_ttl_min > 600:\n    pass',
    '_f = "smtp_port"\nif getattr(config, _f) > 1:\n    pass',
    'for _f in ("smtp_port",):\n    if getattr(config, _f) > 1:\n        pass',
    'for _f in felder_von_woanders():\n    if getattr(config, _f) > 1:\n        pass',
    'if vars(config)["pin_min_length"] > 4:\n    pass',
    'if config.__dict__.get(name, 0) > 4:\n    pass',
    'for _k, _v in vars(config).items():\n    if _v > 4:\n        pass',
    'if asdict(config).get(name, 0) > 4:\n    pass',
    'if operator.attrgetter("pin_min_length")(config) > 4:\n    pass',
    'if _an(config, "smtp_timeout"):\n    pass',
    'if float(str(getattr(config, "admin_path", ""))) > 1:\n    pass',
    'n = getattr(config, name, 0) or 0\nif n > 5:\n    pass') if not _kp_mit(x)]
r.check("Guard self-probe: every spelling of a raw number read path is noticed",
        not _kp_uebersehen, f"overlooked: {_kp_uebersehen}")
_kp_fehlalarm = [x for x in (
    '_x = _ganzzahl(config, "magiclink_ttl_min")\nif _x is not None and _x > 600:\n    pass',
    'if str(getattr(config, name, "") or "").strip():\n    pass',
    'if not getattr(config, name, None) or _an(config, "demo_mode"):\n    pass') if _kp_mit(x)]
r.check("…and the read path itself remains without finding", not _kp_fehlalarm, f"false alarm: {_kp_fehlalarm}")
# (Mutation probes, each individually → red: remove rule 1; remove rule 2; remove rule 3;
# skip the forbidden names (`vars`, `asdict`); take `int`/`float` out of rule 4;
# `nur_wahrheit_oder_text` always true; remove the deduction of the stock in `_kp_mit`; in
# `_kombinationen` `getattr(config, "session_ttl_hours", 0)` again → the guard names the line;
# in check_config `if (getattr(config, "smtp_timeout", 0) or 0) > 200:` (comparison without int()) → red.)

# H-11 / B3-9: deny-by-default at the forward-auth gate.
_gw = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="g", client_secret="s",
                                   base_url="https://auth.example.com", db_path=":memory:")
r.check("H-11/B3-9: gateway preset without groups and without clients warns about the open gate",
        _nennt(_kp2.check_config(_gw)[1], "offenem Tor", "OIDC"))
_gw2 = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="g", client_secret="s",
                                    base_url="https://auth.example.com", db_path=":memory:",
                                    allowed_groups=["mitarbeiter"])
r.check("...with allowed_groups the warning stays silent", not _nennt(_kp2.check_config(_gw2)[1], "offenem Tor"))
r.check("...open registration in front of forward-auth is reported",
        _nennt(_befund(forward_auth_enabled=True, allow_signup=True)[1], "Selbst-Registrierung"))
r.check("...without forward-auth no gate, no message",
        not _nennt(_befund(allow_signup=True)[1], "Selbst-Registrierung"))

# B3-16: combinations.
r.check("B3-16: e-mail confirmation without mandatory address is an error",
        _nennt(_befund(allow_signup=True, signup_verify_email=True, signup_require_email=False,
                       base_url="https://auth.example.com")[0], "signup_require_email=False"))
r.check("...cookie_domain that does not cover base_url is an error",
        _nennt(_befund(cookie_domain=".example.org", base_url="https://auth.example.com")[0], "cookie_domain"))
r.check("...admin_path without leading slash is an error",
        _nennt(_befund(admin_path="admin")[0], "admin_path"))
r.check("...a shorter session without \"stay signed in\" than with it is reported",
        _nennt(_befund(session_ttl_hours=2, session_ttl_transient_hours=12)[1], "session_ttl_transient_hours"))
# `True` is not an hour count: `_zahlengrenzen` reports the type error, a combination warning
# "longer than session_ttl_hours=True" was nevertheless added until the final round (the combination read
# past the read path `_ganzzahl`). (Mutation probe: in `_kombinationen` again
# `getattr(config, "session_ttl_hours", 0)` with `isinstance(…, int)` → red.)
_tt_f, _tt_w = _befund(session_ttl_hours=True, session_ttl_transient_hours=12)
r.check("...session_ttl_hours=True: only the type error, no combination warning beside it",
        _nennt(_tt_f, "session_ttl_hours=True", "keine ganze Zahl") and not _nennt(_tt_w, "länger als"),
        f"errors {_tt_f} · warnings {_tt_w}")

# B3-8: demo mode has technical barriers.
r.check("B3-8: demo_mode next to a real sign-in path is an error",
        _nennt(_befund(demo_mode=True, forward_auth_enabled=True)[0], "demo_mode"))
_demo_db = str(Path(tempfile.mkdtemp()) / "t.db")
_bestand = TinySesam(TinySesamConfig(db_path=_demo_db))
_bestand.create_user("echt", password="Geheim12345!abc")
try:
    TinySesam(TinySesamConfig(db_path=_demo_db, demo_mode=True))
    _b38 = False
except _CfgErr:
    _b38 = True
r.check("...demo_mode on a database with existing accounts fails at setup",
        _b38 and _bestand.store.get_user_by_name("demoadmin") is None,
        "before, an admin with a known password silently arose there")
# Counter-check: A real demo starts again, even with visitors registered in the meantime.
_demo_db2 = str(Path(tempfile.mkdtemp()) / "t.db")
_d1 = TinySesam(TinySesamConfig(db_path=_demo_db2, demo_mode=True))
_d1.create_user("besucher", password="Geheim12345!abc")
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
# (Mutation probe: remove `self._nachpruefen()` in router() → red.)

# A2: The constructor's guards also apply before router()/admin_router(), not only config_check.
# Attack: admin_identifiers=["chef"] is safe as long as accounts do not arise by themselves. Whoever
# switched on allow_signup AFTER the constructor still built a router — the first visitor
# registered as "chef" and was first admin with access to the admin API.
def _nachtraeglich(aenderung, **cfg):
    a, _ = _app(**cfg)
    for k, v in aenderung.items():
        setattr(a.cfg, k, v)
    ergebnis = []
    for bau in (a.router, a.admin_router):
        try:
            bau()
            ergebnis.append("")
        except _CfgErr as e:
            ergebnis.append(str(e))
    return ergebnis


for _titel, _aend, _cfg, _wort in (
        ("admin_identifiers + allow_signup", {"allow_signup": True}, {"admin_identifiers": ["chef"]},
         "admin_identifiers"),
        ("admin_identifiers + oidc_auto_create", {"oidc_enabled": True, "oidc_auto_create": True},
         {"admin_identifiers": ["chef"], "base_url": "https://auth.example.com"}, "admin_identifiers"),
        ("login_identifier='bogus'", {"login_identifier": "bogus"}, {}, "login_identifier"),
        ("forward_headers mit Zeilenumbruch", {"forward_headers": {"user": "X-User\r\nSet-Cookie: a=b"}}, {},
         "forward_headers"),
        ("totp_required=True", {"totp_required": True}, {}, "totp_required")):
    _erg = _nachtraeglich(_aend, **_cfg)
    r.check(f"A2: {_titel} added afterwards fails at router() and admin_router()",
            all(_wort in x and "nach dem Aufbau" in x for x in _erg), f"{_erg}")
# The attack itself: With the guard, no router arises at all, so no registration either.
_a2, _ = _app(admin_identifiers=["chef"], csrf_enabled=False, signup_require_email=False)
_a2.cfg.allow_signup = True
_admin_api = None
try:
    _app2 = FastAPI()
    _app2.include_router(_a2.router())
    with TestClient(_app2) as _c2:
        _c2.post("/auth/register", data={"username": "chef", "password": "Fremder-123456"})
        _c2.post("/auth/login", data={"username": "chef", "password": "Fremder-123456"})
        _admin_api = _c2.get("/auth/admin/api/users").status_code
except _CfgErr:
    pass   # the setup may be rejected — what is checked below is that nobody became admin
_chef = _a2.store.get_user_by_name("chef")
r.check("...and nobody registers as 'chef' to become first admin",
        (_chef is None or not _chef["is_admin"]) and _admin_api != 200,
        f"account={dict(_chef) if _chef else None}, Admin-API={_admin_api}")
r.check("...a permitted change next to admin_identifiers still builds",
        _nachtraeglich({"lang": "en"}, admin_identifiers=["chef"]) == ["", ""])
# (Mutation probe: remove the `_riegel` call in _nachpruefen → red.)

# A5: origin may be a list — py_webauthn also accepts several as expected_origin.
_zwei = ["https://a.example.com", "https://b.example.com"]
_f5, _w5 = _befund(passkey_enabled=True, rp_id="example.com", origin=_zwei, base_url="https://a.example.com")
r.check("A5: origin as a list of matching origins is no error",
        not _nennt(_f5, "origin") and not _nennt(_w5, "origin"), f"{_f5} {_w5}")
# (Mutation probe: in _proxies_und_passkey check `str(origin)` instead of the list again → red.)
r.check("...a bad entry in the list remains an error",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com",
                       origin=["https://a.example.com", "https://b.example.com/pfad"])[0], "ist kein Origin"))
r.check("...an entry outside the rp_id likewise",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com",
                       origin=["https://a.example.com", "https://a.example.org"])[0], "passt nicht"))
r.check("...an empty list too",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com", origin=[])[0], "leere Liste"))
r.check("...and base_url outside the list is still reported",
        _nennt(_befund(passkey_enabled=True, rp_id="example.com", origin=_zwei,
                       base_url="https://c.example.com")[1], "base_url"))

# R5-1: scheme and user information of the login URL no longer come unchecked from the request.
_a51, _app51 = _app(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                    cookie_secure=True)
with TestClient(_app51) as _c51:
    _l1 = _c51.get("/auth/forward", headers={"x-forwarded-proto": "http",
                                             "x-forwarded-host": "app.example.com",
                                             "x-forwarded-uri": "/x"}).headers.get("x-tinysesam-location", "")
    _l2 = _c51.get("/auth/forward", headers={"host": "127.0.0.1",
                                             "x-original-url": "http://fremd.example@app.example.com/x"}
                   ).headers.get("x-tinysesam-location", "")
r.check("R5-1: X-Forwarded-Proto: http does not downgrade the login URL with cookie_secure",
        _l1.startswith("https://app.example.com/auth/login"), _l1)
r.check("...user information from X-Original-URL does not end up in front of the host of the login URL",
        _l2.startswith("https://app.example.com/auth/login") and "fremd.example@" not in _l2.split("?")[0],
        _l2)
_a51b, _app51b = _app(forward_auth_enabled=True, cookie_secure=False)
with TestClient(_app51b) as _c51b:
    _l3 = _c51b.get("/auth/forward", headers={"host": "127.0.0.1:8000", "x-forwarded-proto": "http"}
                    ).headers.get("x-tinysesam-location", "")
r.check("...local (loopback, without certificate) http remains allowed", _l3.startswith("http://127.0.0.1:8000/"), _l3)
# (Mutation probe: replace `_login_schema` with the raw scheme → the first two red.)
sys.exit(r.done())

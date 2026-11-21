"""H4 — sign-in hardening (security review 2026-11-20): T-49, T-51, T-56, T-57, T-63.

* **T-57** (RFC 6238 §5.2, ASVS 5.0 6.5.5): a TOTP code counts from the current and the previous step only
  (`totp_window="previous"`); `"current"` and the old `"previous_and_next"` are switches.
* **T-56** (WebAuthn L3 §7.1, §14.6.1): the registration demands user verification like the sign-in, a refused
  answer is a 400 (no 500); the user handle of a new passkey is 64 bytes that reveal neither the account ID nor
  the number of accounts — the same for every passkey of one account.
* **T-51** (ASVS 5.0 6.5.5, NIST SP 800-63B-4 §4.2.2): one-time links live 10 minutes by default; an issued
  sign-in link at most `signin_link_max_ttl_min` (default 24 h, up to a week on purpose).
* **T-63** (ASVS 5.0 6.3.5): a complete sign-in after at least three consecutive failed attempts reaches the holder
  — event, audit line on the account page, mail with `notify_login_failures`.
* **T-49** (ASVS 5.0 6.8.4, OIDC Core §3.1.2.1): the provider's `auth_time` decides about freshness — the
  confirmation page asks the provider for an active sign-in (`prompt=login`, `max_age=0`), a silent round no
  longer refreshes a full session, a new session counts from the provider's sign-in.

The software authenticator below builds real WebAuthn registration answers (attestation "none", P-256): the
library's real verification runs, nothing of it is replaced.
"""
import base64
import hashlib
import json
import os
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
import _totp_clock  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check, totp as _totp  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
               passkey_enabled=False, oidc_enabled=False, cookie_secure=False, base_url=BASE,
               stepup_max_age_sec=900)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def errors_of(**over):
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), **over)
    return config_check.check_config(cfg)[0]


# ══ T-57: TOTP window ═══════════════════════════════════════════════════════════════════════════
def totp_account(window=None):
    over = {} if window is None else {"totp_window": window}
    auth, _ = build(**over)
    uid = auth.create_user("tina", password=PW)
    secret = auth.totp_begin(uid)["secret"]
    auth.store.confirm_totp(uid)          # confirmed without consuming a step: every step is still free
    return auth, uid, pyotp.TOTP(secret)


def mid_step():
    """Wait out the last seconds of a 30-second step (`tests/_totp_clock.py`): a code computed just before the change
    and checked just after it would land one step off (a wobble under load, not a finding)."""
    _totp_clock.safe_moment()


def accepted(window, offset_steps):
    auth, uid, gen = totp_account(window)
    return auth._verify_totp(uid, _totp_clock.code(gen, offset_steps))


assert TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "d.db")).totp_window == "previous"
assert accepted(None, 0) and accepted(None, -1), "default: the current and the previous step count"
assert not accepted(None, 1), "default: the NEXT step no longer counts (T-57)"
assert not accepted(None, -2), "two steps back never counted"
assert accepted("current", 0) and not accepted("current", -1) and not accepted("current", 1)
assert accepted("previous_and_next", 1) and accepted("previous_and_next", -1), "the switch keeps the old window"
# Single use stays: the same code a second time is refused.
_a, _u, _g = totp_account()
mid_step()
_code = _g.now()
assert _a._verify_totp(_u, _code) and not _a._verify_totp(_u, _code)
# The setup confirmation uses the same window (complete path through `totp_confirm`).
_a2, _ = build()
_u2 = _a2.create_user("tom", password=PW)
_s2 = _a2.totp_begin(_u2)["secret"]
mid_step()
assert not _a2.totp_confirm(_u2, _totp_clock.next_code(_s2)), "setup: the next step is refused"
assert _a2.totp_confirm(_u2, _totp_clock.previous_code(_s2)), "setup: the previous step counts"
assert any("totp_window" in e for e in errors_of(totp_window="both")), "unknown window: config error"
assert not any("totp_window" in e for e in errors_of(totp_window="current"))
mid_step()
_now2 = _totp_clock.safe_moment()
assert _totp.verify(_s2, pyotp.TOTP(_s2).at(_now2)) and not _totp.verify(_s2, pyotp.TOTP(_s2).at(_now2 + 30))
ok("T-57: current + previous step by default, next step only with the switch, single use, setup alike")


# ══ T-56: passkey registration ══════════════════════════════════════════════════════════════════
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def software_registration(options: dict, origin: str, rp_id: str, uv: bool) -> dict:
    """A real attestation-"none" registration answer of a P-256 authenticator, user verification as given."""
    import cbor2
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
    cred_id = os.urandom(32)
    flags = 0x01 | 0x40 | (0x04 if uv else 0)          # UP, AT, UV
    auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
                 + bytes(16) + len(cred_id).to_bytes(2, "big") + cred_id + cose)
    attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data = json.dumps({"type": "webauthn.create", "challenge": options["challenge"],
                              "origin": origin, "crossOrigin": False}).encode()
    return {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
            "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(attestation),
                         "transports": ["internal"]}}


try:
    import cbor2  # noqa: F401
    import webauthn  # noqa: F401
    HAS_PASSKEY = True
except ModuleNotFoundError:
    HAS_PASSKEY = False

if HAS_PASSKEY:
    ORIGIN, RP = "http://localhost:8000", "localhost"

    def passkey_app(**over):
        auth, app = build(passkey_enabled=True, rp_id=RP, rp_name="Probe", origin=ORIGIN, **over)
        return auth, app

    def signed_in(auth, app, name):
        uid = auth.create_user(name, password=PW)
        c = TestClient(app, raise_server_exceptions=False)
        assert c.post("/auth/login", data={"username": name, "password": PW},
                      follow_redirects=False).status_code == 303
        return uid, c

    def register(c, uv):
        begin = c.post("/auth/passkey/register/begin")
        assert begin.status_code == 200, begin.text
        options = begin.json()
        answer = software_registration(options, ORIGIN, RP, uv=uv)
        return options, c.post("/auth/passkey/register/finish?name=probe", content=json.dumps(answer))

    auth, app = passkey_app()
    uid, c = signed_in(auth, app, "paula")
    options, r = register(c, uv=False)
    assert r.status_code == 400, (r.status_code, r.text[:200])
    assert r.json()["detail"] == auth.t("api.passkey_reg_failed")
    assert auth.store.list_webauthn(uid) == [], "a passkey without user verification was registered"
    assert any(z["event"] == "passkey_create_failed" for z in auth.store.recent_audit(20))
    options2, r = register(c, uv=True)
    assert r.status_code == 200 and r.json()["ok"], (r.status_code, r.text[:200])
    assert len(auth.store.list_webauthn(uid)) == 1
    ok("T-56: registration without user verification → 400 and no passkey; with it → registered")

    handle = unb64u(options["user"]["id"])
    assert len(handle) == 64, len(handle)
    assert handle != str(uid).encode()
    assert unb64u(options2["user"]["id"]) == handle, "every passkey of one account carries the same handle"
    other_uid, c_other = signed_in(auth, app, "otto")
    other_handle = unb64u(register(c_other, uv=True)[0]["user"]["id"])
    assert other_handle != handle and len(other_handle) == 64
    # Another instance numbers alike but hands out other handles (instance salt).
    auth_b, app_b = passkey_app()
    _uid_b, c_b = signed_in(auth_b, app_b, "paula")
    assert _uid_b == uid and unb64u(register(c_b, uv=True)[0]["user"]["id"]) != handle
    ok("T-56: user handle = 64 bytes, stable per account, different per account and per instance")

    auth_p, app_p = passkey_app(passkey_user_verification="preferred")
    uid_p, c_p = signed_in(auth_p, app_p, "petra")
    assert register(c_p, uv=False)[1].status_code == 200 and len(auth_p.store.list_webauthn(uid_p)) == 1
    ok("T-56: passkey_user_verification='preferred' still registers an authenticator without verification")
else:
    print("  - T-56 skipped: extra [passkey] or cbor2 missing (a skip is not a green — check.sh installs it)")


# ══ T-51: link lifetimes ════════════════════════════════════════════════════════════════════════
auth, app = build(magiclink_enabled=True)
assert auth.cfg.magiclink_ttl_min == 10 and auth.cfg.signin_link_max_ttl_min == 24 * 60
uid = auth.create_user("lena", password=PW)
before = time.time()
raw = auth.create_magic_token("login", user_id=uid)
row = auth.store._one("SELECT expires_at FROM magic_token WHERE token_hash=?",
                      (hashlib.sha256(raw.encode()).hexdigest(),))
assert before + 600 - 5 <= row["expires_at"] <= time.time() + 600 + 5, row["expires_at"] - before
assert auth.create_signin_link(uid, ttl_min=24 * 60)["expires_at"] <= time.time() + 24 * 3600 + 5
for bad in (24 * 60 + 1, 7 * 24 * 60):
    try:
        auth.create_signin_link(uid, ttl_min=bad)
        raise AssertionError(f"ttl_min={bad} above the bound was accepted")
    except ValueError as e:
        assert "1440" in str(e), str(e)
auth_w, _ = build(magiclink_enabled=True, signin_link_max_ttl_min=7 * 24 * 60)
uid_w = auth_w.create_user("lena", password=PW)
assert auth_w.create_signin_link(uid_w, ttl_min=7 * 24 * 60)["url"]
assert any("signin_link_max_ttl_min" in e for e in errors_of(signin_link_max_ttl_min=7 * 24 * 60 + 1))
assert any("signin_link_max_ttl_min" in e for e in errors_of(signin_link_max_ttl_min=0))
assert any("below magiclink_ttl_min" in e
           for e in errors_of(magiclink_enabled=True, signin_link_max_ttl_min=5, magiclink_ttl_min=10))
assert not any("below magiclink_ttl_min" in e for e in errors_of(magiclink_enabled=True))
ok("T-51: one-time links 10 min by default; issued link at most 24 h, a week only on purpose")


# ══ T-63: sign-in after failed attempts ════════════════════════════════════════════════════════
def failures_app(**over):
    auth, app = build(**over)
    events, mails = [], []
    auth.on_security_event = lambda event, account, details: events.append((event, details))
    auth.set_mailer(lambda to, subject, text, html=None: mails.append((to, subject, text)))
    uid = auth.create_user("fred", password=PW, email="fred@example.com")
    return auth, app, uid, events, mails


def sign_in(app, password):
    c = TestClient(app)
    return c.post("/auth/login", data={"username": "fred", "password": password}, follow_redirects=False)


# Three DIFFERENT wrong passwords: the same wrong one repeated counts once (NIST SP 800-63B-4 §3.2.2).
auth, app, uid, events, mails = failures_app()
for i in range(3):
    assert sign_in(app, f"wrong password {i}").status_code == 401
assert sign_in(app, PW).status_code == 303
after = [d for e, d in events if e == "signed_in_after_failures"]
assert after and after[0]["failures"] == 3 and after[0]["ip"] == "testclient", events
assert any(ev["event"] == "login_after_failures" for ev in auth.own_events(uid)), "not on the account page"
auth._notice_outcome.wait()            # the outbox sends in the background
assert mails and "after 3 failed attempts" in mails[0][1], mails
# The streak is over: the next sign-in reports nothing.
events.clear()
assert sign_in(app, PW).status_code == 303
assert not [e for e, _ in events if e == "signed_in_after_failures"], events
ok("T-63: three failed attempts, then a sign-in → event, account page, mail; the next sign-in is quiet")

auth, app, uid, events, mails = failures_app()
for i in range(2):
    sign_in(app, f"wrong password {i}")
assert sign_in(app, PW).status_code == 303
assert not [e for e, _ in events if e == "signed_in_after_failures"], "two typos are the holder's own"
auth, app, uid, events, mails = failures_app(notify_login_failures=False)
for i in range(3):
    sign_in(app, f"wrong password {i}")
assert sign_in(app, PW).status_code == 303
assert [e for e, _ in events if e == "signed_in_after_failures"], "the hook always gets the event"
auth._notice_outcome.wait()
assert not mails, "notify_login_failures=False sends no mail"
ok("T-63: two typos stay quiet; notify_login_failures=False keeps the hook, sends no mail")


# ══ T-49: auth_time / max_age ═══════════════════════════════════════════════════════════════════
import importlib.util  # noqa: E402

HAS_OIDC = all(importlib.util.find_spec(m) is not None for m in ("authlib", "httpx"))


def t49():
    global IDP
    IDP = "https://idp.example.com"

    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    def oidc_app(**over):
        auth, app = build(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret",
                          password_enabled=True, **over)
        auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                           "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                           "jwks_uri": IDP + "/jwks"}
        from tinysesam.oidc import OIDCClient
        auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
        return auth, app

    def provider_round(auth, c, auth_time="none", reauth=False, nxt="/"):
        """Once through the real start and callback; `auth_time` None = claim missing."""
        claims = {"sub": "fed-1", "preferred_username": "fiona", "name": "Fiona"}
        if auth_time != "none" and auth_time is not None:
            claims["auth_time"] = auth_time
        auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
            _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
        start = c.get("/auth/oidc/start?next=" + nxt + ("&reauth=1" if reauth else ""), follow_redirects=False)
        query = parse_qs(urlparse(start.headers["location"]).query)
        r = c.get(f"/auth/oidc/callback?code=x&state={query['state'][0]}", follow_redirects=False)
        return query, r

    def session_row(auth, c):
        return auth.store.get_session(c.cookies.get(auth.session_cookie_name))

    def age_session(auth, c, seconds):
        h = auth.store.session_hash(c.cookies.get(auth.session_cookie_name))
        auth.store._exec("UPDATE session SET mfa_at=mfa_at-?, created_at=created_at-? WHERE token_hash=?",
                         (seconds, seconds, h))

    class _Req:
        def __init__(self, c, auth):
            self.cookies = {auth.session_cookie_name: c.cookies.get(auth.session_cookie_name)}
            self.headers = {}

    def fresh(auth, c):
        req = _Req(c, auth)
        u = auth.store.get_user(session_row(auth, c)["user_id"])
        return auth.login_fresh(req, dict(u) | {"_via": "session"})

    # (1) A normal sign-in sends no prompt; a silent one (auth_time an hour old) is not fresh.
    auth, app = oidc_app()
    c = TestClient(app)
    query, r = provider_round(auth, c, auth_time=int(time.time()) - 3600)
    assert r.status_code == 303 and "prompt" not in query and "max_age" not in query, query
    row = session_row(auth, c)
    assert row and row["mfa_ok"] and time.time() - row["mfa_at"] >= 3590, "the session counts from the round instead of auth_time"
    assert not fresh(auth, c), "a silent sign-in an hour after the last one counts as fresh"
    ok("T-49: a new session through a running provider session counts from the provider's auth_time")

    # (2) Without auth_time (documented fallback) and with a fresh one the session is fresh.
    for at in (None, int(time.time())):
        a2, app2 = oidc_app()
        c2 = TestClient(app2)
        assert provider_round(a2, c2, auth_time=at)[1].status_code == 303
        assert fresh(a2, c2), at
    ok("T-49: without auth_time the sign-in counts from now (fallback); a fresh auth_time is fresh")

    # (3) The confirmation page offers the provider; a purely federated account is sent there, not told to sign out.
    age_session(a2, c2, 2000)
    uid_f = session_row(a2, c2)["user_id"]
    page = c2.get("/auth/reauth?next=/auth/account")
    assert page.status_code == 200 and "id=reauthoidc" in page.text and "reauth=1" in page.text, page.text[:400]
    assert a2.t("err.stepup_provider") in page.text
    api = c2.post("/auth/apikeys", json={"name": "x"})
    assert api.status_code == 403 and api.headers.get("x-tinysesam-reauth"), (api.status_code, api.headers)
    ok("T-49: confirmation page shows 'Confirm with <provider>'; a stale federated session is sent there")

    # (4) reauth=1: prompt=login + max_age=0; a stale answer does not confirm, a fresh one does.
    query, r = provider_round(a2, c2, auth_time=int(time.time()) - 3600, reauth=True, nxt="/auth/account")
    assert query.get("prompt") == ["login"] and query.get("max_age") == ["0"], query
    assert r.status_code == 401 and a2.t("err.oidc_reauth_stale") in r.text, (r.status_code, r.text[:300])
    assert not fresh(a2, c2), "a stale answer to reauth=1 refreshed the session"
    assert any(z["event"] == "oidc_reauth_stale" for z in a2.store.recent_audit(20))
    query, r = provider_round(a2, c2, auth_time=None, reauth=True)
    assert r.status_code == 401 and not fresh(a2, c2), "an answer without auth_time confirmed"
    query, r = provider_round(a2, c2, auth_time=int(time.time()), reauth=True, nxt="/auth/account")
    assert r.status_code == 303 and r.headers["location"].endswith("/auth/account"), (r.status_code, r.headers)
    assert fresh(a2, c2) and session_row(a2, c2)["user_id"] == uid_f, "a fresh sign-in at the provider did not confirm"
    ok("T-49: reauth=1 sends prompt=login/max_age=0; stale or missing auth_time → 401, fresh → confirmed")

    # (5) Any other round on a full session (approval for another app) with a stale auth_time: no step-up.
    age_session(a2, c2, 2000)
    token_before = c2.cookies.get(a2.session_cookie_name)
    query, r = provider_round(a2, c2, auth_time=int(time.time()) - 3600)
    assert r.status_code == 303 and "prompt" not in query
    assert not fresh(a2, c2) and c2.cookies.get(a2.session_cookie_name) == token_before
    assert any(z["event"] == "stepup_not_counted" and "no_fresh_auth_time" in (z["detail"] or "")
               for z in a2.store.recent_audit(20))
    ok("T-49: a silent round on a full session no longer refreshes it (audit stepup_not_counted)")

    # (6) The switch keeps the old behaviour.
    a3, app3 = oidc_app(oidc_reauth_check=False)
    c3 = TestClient(app3)
    provider_round(a3, c3, auth_time=int(time.time()) - 3600)
    assert fresh(a3, c3), "oidc_reauth_check=False: a new session counts from now, as before"
    age_session(a3, c3, 2000)
    query, r = provider_round(a3, c3, auth_time=int(time.time()) - 3600, reauth=True)
    assert "prompt" not in query and r.status_code == 303 and fresh(a3, c3)
    assert "id=reauthoidc" not in c3.get("/auth/reauth").text
    ok("T-49: oidc_reauth_check=False — no prompt, auth_time ignored, no provider button (behaviour up to 0.25.x)")


if HAS_OIDC:
    t49()
else:
    print("  - T-49 skipped: extra [oidc] missing (a skip is not a green — check.sh installs it)")

print("H4: all checks green")

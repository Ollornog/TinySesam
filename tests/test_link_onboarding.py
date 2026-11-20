"""T-34: "the admin creates the account, a link signs it in, the chain says what it sets up".

Factor chains get alternatives per step (`"password|passkey"`), and a sign-in link of an account that
lacks factors for the chain leads into a setup pass: set up what is missing, only then fully signed
in. The switch `magiclink_first_login_only` limits links to that first sign-in.

Each safety boundary from the backlog entry is pinned here (and proven by mutation, see T-34):
* a half session in the pass reaches nothing but the setup — no protected route, no admin, no key;
* the pass opens only right after a link sign-in and expires with the step-up window; a factor the
  account has is never replaced;
* one factor never satisfies two steps;
* `magiclink_require_second_factor` and `login_chain_strict` stay coherent;
* disabling the account or a password reset during the pass ends it.

Real CSRF throughout (the default), so the routes are measured as the browser meets them.
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import _chain  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


BASE = "https://auth.example.com"
JSON = {"Accept": "application/json"}

try:
    import webauthn as _webauthn
    HAS_PASSKEY = True
except ImportError:          # the browser job installs the core only — the passkey part is skipped there
    HAS_PASSKEY = False


class _Verified:
    """What py_webauthn's verifiers return — the crypto is not under test here, the pass is."""

    def __init__(self, cred_id=b"cred-1"):
        self.credential_id = cred_id
        self.credential_public_key = b"pk"
        self.sign_count = 0
        self.new_sign_count = 1


if HAS_PASSKEY:
    _webauthn.verify_registration_response = lambda **kw: _Verified(
        json.loads(kw["credential"]).get("rawId", "cred-1").encode())
    _webauthn.verify_authentication_response = lambda **kw: _Verified()


def build(chain, **over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, lang="en",
               passkey_enabled=False, magiclink_enabled=True, magiclink_self_request=False,
               base_url=BASE, login_chain=list(chain) if chain is not None else [],
               rp_id="testserver", origin="http://testserver")
    cfg.update(over)
    a = TinySesam(TinySesamConfig(**cfg))
    a.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(a.router())

    @app.get("/who")
    def who(u=Depends(a.require_user)):
        return {"u": u["username"]}
    return a, app


def csrf(c, a):
    return c.cookies.get(a.csrf_cookie_name) or ""


def redeem(a, app, url, c=None):
    """Open the link like a browser: confirmation page, then the POST that redeems it."""
    c = c or TestClient(app)
    tok = re.search(r"/auth/magic/([\w\-]+)$", url).group(1)
    page = c.get(f"/auth/magic/{tok}")
    assert page.status_code == 200, (page.status_code, page.text[:200])
    field = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
    return c, c.post(f"/auth/magic/{tok}", data={"_csrf": field}, follow_redirects=False)


def who(c):
    r = c.get("/who", headers=JSON)
    return r.json().get("u") if r.status_code == 200 else None


def post_json(c, a, path, body):
    return c.post(path, json=body, headers={"X-CSRF-Token": csrf(c, a)})


def setup_totp(c, a, next_="/who"):
    """Walk the built-in TOTP setup: page → start (secret) → confirm. Returns (response, secret)."""
    page = c.get(f"/auth/totp/setup?next={next_}")
    assert page.status_code == 200, (page.status_code, page.text[:200])
    shown_next = re.search(r"name=next value='([^']*)'", page.text).group(1)
    started = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, a), "next": shown_next})
    assert started.status_code == 200, (started.status_code, started.text[:200])
    secret = re.search(r"class=mono>([A-Z2-7]+)<", started.text).group(1)
    data_next = re.search(r"data-next='([^']*)'", started.text).group(1)
    r = c.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret).now(), "next": data_next},
               headers={"X-CSRF-Token": csrf(c, a)})
    return r, secret


def events(a, name):
    return [e for e in a.store.recent_audit(300) if e["event"] == name]


def age_session(a, c, seconds):
    """Move the sign-in of this browser's session into the past (the clock is not under test)."""
    h = a.store.session_hash(c.cookies.get(a.session_cookie_name))
    a.store._exec("UPDATE session SET created_at=created_at-? WHERE token_hash=?", (seconds, h))


# =====================================================================================
# 0) Alternatives in a chain — the matching rules (pure functions)
# =====================================================================================
assert _chain.steps(["password | passkey", "totp"]) == [("password", "passkey"), ("totp",)]
assert _chain.satisfied(["password|passkey"], ["passkey"], True)
assert _chain.satisfied(["password|passkey", "totp|passkey"], ["password", "passkey"], True)
assert not _chain.satisfied(["password|passkey", "totp|passkey"], ["passkey"], False), \
    "one passkey satisfied two steps"
assert not _chain.satisfied(["password", "totp|pin"], ["pin", "password"], True), "strict order lost"
assert _chain.satisfied(["password", "totp|pin"], ["pin", "password"], False)
# Legacy chains: the same answers as the old engine.
assert _chain.satisfied(["password", "totp"], ["password", "totp"], True)
assert not _chain.satisfied(["password", "totp"], ["totp", "password"], True)
assert _chain.next_options(["password", "totp"], ["password"]) == ["totp"]
assert _chain.next_options(["password", "totp"], []) == ["password"]
assert _chain.next_options(["password|passkey", "passkey"], ["passkey"]) == ["password"], \
    "the open step must be the one a new factor can still fill"
assert _chain.uncovered(["password|passkey", "totp|passkey"], {"passkey"}) == [1]
assert not _chain.assignable(["password", "password"]) and _chain.assignable(["totp|passkey", "passkey"])
ok("chains: alternatives per step, a factor fills one step, strict order kept, legacy answers unchanged")

for bad, why in ((["password|", "totp"], "empty alternative"), (["", "totp"], "empty step"),
                 (["password", "password"], "one factor for two steps"),
                 (["password|bogus"], "unknown name in an alternative")):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), login_chain=bad))
    except ConfigError:
        continue
    raise AssertionError(f"config_check let through: {bad} ({why})")
cfg_ok = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), login_chain=["password|pin", "totp"],
                         pin_enabled=True)
TinySesam(cfg_ok)
assert cfg_ok.pin_as_first_factor() is True, "pin as an alternative of the FIRST step is a first factor"
assert TinySesamConfig(login_chain=["password", "totp|pin"], pin_enabled=True).pin_as_first_factor() is False
ok("config_check: empty steps/alternatives, unknown names and unsatisfiable chains are errors")


# =====================================================================================
# 1) The PO's example: ["password", "totp"] — link → password → TOTP → in; later password + TOTP
# =====================================================================================
auth, app = build(["password", "totp"])
auth.ensure_admin("boss", "boss-pw-123456")
dave = auth.create_user("dave", email="dave@example.com")
link = auth.create_signin_link(dave, next="/who")
c, r = redeem(auth, app, link["url"])
assert r.status_code == 303 and r.headers.get("location", "<no redirect>").startswith("/auth/setup?next="), r.headers.get("location")
assert who(c) is None, "the link alone must not sign in fully"
assert events(auth, "setup_pass_start"), "the pass leaves no audit line"
ok("link of an account without factors → /auth/setup, half session")

page = c.get("/auth/setup?next=/who")
assert page.status_code == 200 and "id=ob_password" in page.text, page.text[:300]
assert "id=ob_totp" not in page.text and "id=ob_pin" not in page.text, "only the current step is offered"
assert "Still to set up: 2" in page.text, "the page names how many steps are left"
ok("setup page: offers the password first (the first step), two steps left")

# --- S1: the half session in the pass reaches nothing but the setup ---
r = c.get("/who", headers=JSON)
assert r.status_code == 401 and r.headers.get("x-tinysesam-factor") == "setup", (r.status_code, r.headers)
r = c.get("/who", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers.get("location", "<no redirect>").startswith("/auth/setup"), r.headers.get("location")
assert c.get("/auth/me").status_code == 401
assert c.get("/auth/account", follow_redirects=False).status_code == 303
assert c.get(f"{auth.cfg.admin_path}/api/users", headers=JSON).status_code in (401, 403)
assert post_json(c, auth, "/auth/apikeys", {"name": "x"}).status_code in (401, 403, 404)
assert not auth.list_api_keys(dave), "an API key came into being from a half session"
assert post_json(c, auth, "/auth/password", {"current": "", "new": "x-123456789"}).status_code in (400, 401)
ok("half session: protected route → step `setup`, no /auth/me, account page, admin API or API key")

# --- S2c / S10: only the factor offered NOW, nothing else ---
r = post_json(c, auth, "/auth/pin/set", {"pin": "1234"})
assert r.status_code == 404, f"PIN off here — its route must not exist: {r.status_code}"
r = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, auth), "next": "/who"})
assert r.status_code == 200, "TOTP is a missing step too — the chain's own enrollment path stays usable"
ok("setup routes accept the half session only for factors the chain is missing")

r = post_json(c, auth, "/auth/password/set", {"new": "dave-first-2468", "next": "/who"})
assert r.status_code == 200 and r.json()["ok"], (r.status_code, r.text[:200])
assert r.json()["next"].startswith("/auth/setup?next="), r.json()
assert auth.store.get_password_hash(dave), "password not set"
assert who(c) is None, "half way: the password alone completes nothing (TOTP is missing)"
assert any("setup_pass=1" in (e["detail"] or "") for e in events(auth, "password_set"))
page = c.get("/auth/setup?next=/who")
assert "id=ob_totp" in page.text and "id=ob_password" not in page.text, page.text[:300]
r = post_json(c, auth, "/auth/password/set", {"new": "other-pw-13579", "next": "/who"})
assert r.status_code in (401, 409), f"a second password over the first: {r.status_code}"
ok("password set in the pass (audit setup_pass=1); a second one is refused, TOTP comes next")

r, secret = setup_totp(c, auth)
j = r.json()
assert r.status_code == 200 and j["ok"] and j["next"] == "/who", j
assert len(j.get("recovery_codes") or []) == auth.cfg.recovery_code_count, "B-9a: codes with the factor"
assert who(c) == "dave", "TOTP set up — the sign-in must be complete now"
assert events(auth, "setup_pass_done"), "the end of the pass leaves no audit line"
assert auth.store.get_user(dave)["first_login_at"] is not None
ok("TOTP set up → fully signed in under a new token; recovery codes shown; first sign-in noted")

# Later: the regular chain, no link needed.
c2 = TestClient(app)
c2.get("/auth/login")
r = c2.post("/auth/login", data={"username": "dave", "password": "dave-first-2468", "next": "/who",
                                 "_csrf": csrf(c2, auth)}, follow_redirects=False)
assert r.status_code == 303 and r.headers.get("location", "<no redirect>").startswith("/auth/totp"), r.headers.get("location")
import time  # noqa: E402
step = pyotp.TOTP(secret)
code = step.at(time.time() + 30)        # the setup consumed the current step
r = c2.post("/auth/totp", data={"code": code, "next": "/who", "_csrf": csrf(c2, auth)}, follow_redirects=False)
assert who(c2) == "dave", (r.status_code, r.headers.get("location"))
ok("afterwards: password + TOTP as usual")

# A link for the now complete account opens no pass (and, without the switch, still redeems as before).
c3, r = redeem(auth, app, auth.create_signin_link(dave)["url"])
assert who(c3) is None
assert c3.get("/auth/setup", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path), \
    "a complete account must not get a setup pass"
ok("a complete account's link: no pass (S2: only for what is missing)")

# S2c: the link replaces no factor the account HAS — an admin-set password is typed before the setup.
sam = auth.create_user("sam", password="sam-start-13579")
c, r = redeem(auth, app, auth.create_signin_link(sam, next="/who")["url"])
assert r.headers.get("location", "<no redirect>").startswith(auth.cfg.login_path), r.headers.get("location")
assert c.get("/auth/setup?next=/who", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path)
r = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, auth), "next": "/who"}, follow_redirects=False)
assert r.status_code in (303, 401) and auth.store.get_totp(sam) is None, \
    f"TOTP set up with the link alone, past the account's password: {r.status_code}"
r = post_json(c, auth, "/auth/password/set", {"new": "sam-mine-246800"})
assert r.status_code in (401, 409) and auth._verify_user_password(sam, "sam-start-13579"), \
    "the existing password was replaced"
r = c.post("/auth/login", data={"username": "sam", "password": "sam-start-13579", "next": "/who",
                                "_csrf": csrf(c, auth)}, follow_redirects=False)
assert r.headers.get("location", "<no redirect>").startswith("/auth/setup"), r.headers.get("location")
r = post_json(c, auth, "/auth/password/set", {"new": "sam-other-97531"})
assert r.status_code == 401 and auth._verify_user_password(sam, "sam-start-13579"), \
    f"the pass replaced the password the account has: {r.status_code}"
r, _ = setup_totp(c, auth)
assert r.json()["ok"] and who(c) == "sam", r.text[:200]
ok("account with a password: link → own password first → then TOTP (the link replaces nothing it has)")


# =====================================================================================
# 2) S2: the pass only right after a LINK sign-in, and only while fresh
# =====================================================================================
auth, app = build(["password", "pin"], pin_enabled=True, pin_login=False, stepup_max_age_sec=600)
erin = auth.create_user("erin", password="erin-pw-123456")
c = TestClient(app)
c.get("/auth/login")
r = c.post("/auth/login", data={"username": "erin", "password": "erin-pw-123456", "next": "/who",
                                "_csrf": csrf(c, auth)}, follow_redirects=False)
assert r.status_code == 303 and who(c) is None
assert c.get("/auth/setup", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path)
r = post_json(c, auth, "/auth/pin/set", {"pin": "2468"})
assert r.status_code == 401 and not auth.has_pin(erin), f"half session after a password set a PIN: {r.status_code}"
ok("a half session from a password sign-in gets no pass (PIN set refused)")

fred = auth.create_user("fred")
c, r = redeem(auth, app, auth.create_signin_link(fred)["url"])
assert "id=ob_password" in c.get("/auth/setup").text
r = post_json(c, auth, "/auth/pin/set", {"pin": "2468"})
assert r.status_code == 401 and not auth.has_pin(fred), \
    f"the pass set the PIN (step 2) while it offers the password (step 1): {r.status_code}"
ok("the pass sets only what it offers NOW (PIN refused while the password is the step)")
age_session(auth, c, 601)
assert c.get("/auth/setup", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path), \
    "an expired pass still shows the setup"
r = post_json(c, auth, "/auth/password/set", {"new": "fred-late-24680"})
assert r.status_code == 401 and not auth.store.get_password_hash(fred), r.status_code
ok("the pass expires with the step-up window — nothing set afterwards")


# =====================================================================================
# 3) S3: one factor never two steps — ["password|passkey", "totp|passkey"]
# =====================================================================================
if HAS_PASSKEY:
    auth, app = build(["password|passkey", "totp|passkey"], passkey_enabled=True)
    gina = auth.create_user("gina")
    auth.store.add_webauthn(gina, "cred-gina", "pk", 0, None, "Laptop")
    assert not auth._session_ok(gina, ["passkey"]), "one passkey satisfied both steps"
    assert auth._session_ok(gina, ["passkey", "totp"])
    c = TestClient(app)
    c.get("/auth/login")
    begin = c.post("/auth/passkey/login/begin", headers={"X-CSRF-Token": csrf(c, auth)})
    assert begin.status_code == 200
    r = c.post("/auth/passkey/login/finish?next=/who", json={"id": "cred-gina", "rawId": "cred-gina"},
               headers={"X-CSRF-Token": csrf(c, auth)})
    assert r.status_code == 200 and who(c) is None, "a passkey alone signed in a two-step chain"
    ok("[password|passkey, totp|passkey]: a passkey alone is not full (engine and real route)")

    # A fresh account in this chain: link → choose → passkey → the second step still needs its own factor.
    hank = auth.create_user("hank")
    c, r = redeem(auth, app, auth.create_signin_link(hank, next="/who")["url"])
    page = c.get("/auth/setup?next=/who").text
    assert "id=ob_password" in page and "id=ob_passkey" in page and "Choose one" in page, page[:400]
    b = c.post("/auth/passkey/register/begin", headers={"X-CSRF-Token": csrf(c, auth)})
    assert b.status_code == 200, (b.status_code, b.text[:200])
    r = c.post("/auth/passkey/register/finish?next=/who", json={"rawId": "cred-hank"},
               headers={"X-CSRF-Token": csrf(c, auth)})
    assert r.status_code == 200 and r.json()["next"].startswith("/auth/setup"), (r.status_code, r.text[:200])
    assert who(c) is None, "S3: the passkey set up for step 1 completed step 2 as well"
    page = c.get("/auth/setup?next=/who").text
    assert "id=ob_totp" in page and "id=ob_passkey" not in page, "step 2: TOTP only (the passkey is taken)"
    r, _ = setup_totp(c, auth)
    assert r.json()["ok"] and who(c) == "hank", r.text[:200]
    ok("fresh account: passkey for step 1, then TOTP for step 2 — only then full")

    # S5 (blocker): an account that HAS a passkey shows it before anything is set up.
    ida = auth.create_user("ida")
    auth.store.add_webauthn(ida, "cred-ida", "pk", 0, None, "Phone")
    c, r = redeem(auth, app, auth.create_signin_link(ida, next="/who")["url"])
    loc = c.get("/auth/setup?next=/who", follow_redirects=False).headers.get("location", "<no redirect>")
    assert loc.startswith(auth.cfg.login_path), f"the existing passkey must come first: {loc}"
    r = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, auth)}, follow_redirects=False)
    assert r.status_code in (303, 401) and auth.store.get_totp(ida) is None, \
        f"TOTP set up past the existing passkey: {r.status_code}"
    c.post("/auth/passkey/login/begin", headers={"X-CSRF-Token": csrf(c, auth)})
    r = c.post("/auth/passkey/login/finish?next=/who", json={"id": "cred-ida"}, headers={"X-CSRF-Token": csrf(c, auth)})
    assert r.status_code == 200 and r.json()["redirect"].startswith("/auth/setup"), r.text[:200]
    r, _ = setup_totp(c, auth)
    assert who(c) == "ida", r.text[:200]
    ok("account with a passkey: passkey first, then the missing TOTP")
else:
    print("  - passkey part skipped (extra [passkey] not installed)")


# =====================================================================================
# 4) S5: magiclink_require_second_factor — an existing TOTP comes first
# =====================================================================================
auth, app = build(["password"])
jack = auth.create_user("jack")
sec = auth.totp_begin(jack)["secret"]
assert auth.totp_confirm(jack, pyotp.TOTP(sec).now())
c, r = redeem(auth, app, auth.create_signin_link(jack, next="/who")["url"])
loc = c.get("/auth/setup?next=/who", follow_redirects=False).headers.get("location", "<no redirect>")
assert loc.startswith("/auth/totp"), f"the existing TOTP must come before the setup: {loc}"
r = post_json(c, auth, "/auth/password/set", {"new": "jack-first-2468"})
assert r.status_code == 401 and not auth.store.get_password_hash(jack), "password set past the TOTP"
r = c.post("/auth/totp", data={"code": pyotp.TOTP(sec).at(time.time() + 30), "next": "/who",
                               "_csrf": csrf(c, auth)}, follow_redirects=False)
assert r.status_code == 303 and r.headers.get("location", "<no redirect>").startswith("/auth/setup"), r.headers.get("location")
r = post_json(c, auth, "/auth/password/set", {"new": "jack-first-2468", "next": "/who"})
assert r.status_code == 200 and r.json()["next"] == "/who" and who(c) == "jack", r.text[:200]
ok("account with TOTP, chain [password]: TOTP first, then the password — then full")


# =====================================================================================
# 5) S4: disabled or reset during the pass → the pass is over
# =====================================================================================
auth, app = build(["password", "totp"], password_reset_enabled=True)
kim = auth.create_user("kim")
c, r = redeem(auth, app, auth.create_signin_link(kim)["url"])
assert "id=ob_password" in c.get("/auth/setup").text
auth.store.set_disabled(kim, True)                       # a lock that leaves the session row standing
assert c.get("/auth/setup", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path)
assert post_json(c, auth, "/auth/password/set", {"new": "kim-pw-1234567"}).status_code in (401, 403)
assert not auth.store.get_password_hash(kim)
auth.store.set_disabled(kim, False)
auth.set_disabled(kim, True)                              # the operator's lock ends the sessions
assert auth.store.get_session(c.cookies.get(auth.session_cookie_name)) is None
ok("account locked during the pass: no setup page, nothing set")

lou = auth.create_user("lou", email="lou@example.com")
c, r = redeem(auth, app, auth.create_signin_link(lou)["url"])
assert "id=ob_password" in c.get("/auth/setup").text
# "Forgot password" from elsewhere (the mailbox), through the real reset route.
reset_tok = auth.create_magic_token("reset_password", user_id=lou)
other = TestClient(app)
form = other.get(f"/auth/reset?token={reset_tok}")
r = other.post("/auth/reset", data={"token": reset_tok, "password": "lou-reset-13579",
                                    "_csrf": re.search(r"name=_csrf value='([^']*)'", form.text).group(1)},
               follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:200])
assert c.get("/auth/setup", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path)
assert post_json(c, auth, "/auth/password/set", {"new": "lou-mine-24680"}).status_code == 401
ok("password reset during the pass: the pass ends with the sessions")


# =====================================================================================
# 6) magiclink_first_login_only
# =====================================================================================
auth, app = build(["password", "totp"], magiclink_first_login_only=True)
mia = auth.create_user("mia")
spare = auth.create_signin_link(mia)["url"]                # issued while the account is new
c, r = redeem(auth, app, auth.create_signin_link(mia, next="/who")["url"])
post_json(c, auth, "/auth/password/set", {"new": "mia-first-24680"})
setup_totp(c, auth)
assert who(c) == "mia"
try:
    auth.create_signin_link(mia)
    raise AssertionError("an admin link for a complete account was issued")
except ValueError as e:
    assert "first sign-in" in str(e), e
c4, r = redeem(auth, app, spare)
assert r.status_code == 403 and "only for the first sign-in" in r.text and who(c4) is None, r.status_code
assert c4.cookies.get(auth.session_cookie_name) is None, "a refused link left a session"
assert events(auth, "magic_first_login_only")
ok("first-login-only: complete account → no admin link, an older link is refused (403, no session)")

# The way back for a lost factor: the operator removes it and opens a setup window.
auth.totp_disable(mia)
try:
    auth.create_signin_link(mia)
    raise AssertionError("without a window the account may not set up — the link must be refused")
except ValueError:
    pass
auth.grant_mfa_enrollment(mia, 30)
c5, r = redeem(auth, app, auth.create_signin_link(mia, next="/who")["url"])
assert r.headers.get("location", "<no redirect>").startswith(auth.cfg.login_path), \
    f"the account HAS a password — the link does not replace it: {r.headers.get('location')}"
r = c5.post("/auth/login", data={"username": "mia", "password": "mia-first-24680", "next": "/who",
                                 "_csrf": csrf(c5, auth)}, follow_redirects=False)
assert r.headers.get("location", "<no redirect>").startswith("/auth/setup"), r.headers.get("location")
page = c5.get("/auth/setup?next=/who").text
assert "id=ob_totp" in page and "id=ob_password" not in page, "the pass offers only the lost TOTP"
setup_totp(c5, auth)
assert who(c5) == "mia"
ok("first-login-only: factor removed + setup window → link, own password, then only the lost TOTP")

# Mail self-request: no mail for a complete account.
sent = []
auth2, app2 = build(["password", "totp"], magiclink_first_login_only=True, magiclink_self_request=True)
auth2.set_mailer(lambda to, subject, text, html=None: sent.append(to))
nia = auth2.create_user("nia", email="nia@example.com", password="nia-pw-1234567")
auth2.store.mark_first_login(nia, 1)
assert auth2.send_login_link("nia@example.com", BASE) is False and not sent
ola = auth2.create_user("ola", email="ola@example.com")
assert auth2.send_login_link("ola@example.com", BASE) is True
ok("first-login-only: a requested link goes out only to accounts that may use it")


# =====================================================================================
# 7) S2/S9: no pass where self-setup is not allowed; classic mode unchanged
# =====================================================================================
auth, app = build(["password", "totp"], mfa_enrollment="strict")
pia = auth.create_user("pia")
c, r = redeem(auth, app, auth.create_signin_link(pia)["url"])
assert c.get("/auth/setup", follow_redirects=False).headers.get("location", "<no redirect>").startswith(auth.cfg.login_path)
assert any("via=link" in (e["detail"] or "") for e in events(auth, "mfa_enrollment_denied"))
ok("mfa_enrollment='strict': the link opens no pass (audit mfa_enrollment_denied via=link)")

auth, app = build(None)
quin = auth.create_user("quin")
c, r = redeem(auth, app, auth.create_signin_link(quin, next="/who")["url"])
assert r.headers.get("location", "<no redirect>") == "/who" and who(c) == "quin", "classic mode: the link signs in as before"
assert not events(auth, "setup_pass_start")
ok("without a chain: the link signs in as before, no pass")

# Order in the regular sign-in stays strict with alternatives.
auth, app = build(["password", "totp|pin"], pin_enabled=True, pin_login=False)
rosa = auth.create_user("rosa", password="rosa-pw-1234567")
auth.set_pin(rosa, "2468")
assert not auth._session_ok(rosa, ["pin", "password"]) and auth._session_ok(rosa, ["password", "pin"])
c = TestClient(app)
c.get("/auth/login")
r = c.post("/auth/login", data={"username": "rosa", "password": "rosa-pw-1234567", "next": "/who",
                                "_csrf": csrf(c, auth)}, follow_redirects=False)
assert r.headers.get("location", "<no redirect>").startswith("/auth/pin"), \
    f"the alternative the account has (PIN) must be asked, not TOTP: {r.headers.get('location')}"
r = c.post("/auth/pin", data={"pin": "2468", "next": "/who", "_csrf": csrf(c, auth)}, follow_redirects=False)
assert who(c) == "rosa", (r.status_code, r.headers.get("location"))
ok("[password, totp|pin]: strict order kept; the next page is the alternative the account has")

print("OK test_link_onboarding")

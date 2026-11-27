"""T-99 acceptance (ADR-18 "every origin is equal"): the same scenario once with a local account, once with an OIDC
account and once with a SAML account (the suite's test identity provider, really signed assertions) — the same result.

The scenario, run for each origin through its real sign-in path:

1. Sign in; the account's `source` is that origin.
2. Role: an administrator grants `editors` in the panel — a route guarded by `require_role("editors")` lets the account
   in, before it did not.
3. Admin action: the account is made administrator; from a stale session the panel refuses (403, reauth) until the
   account confirms with ITS way (password, a fresh provider sign-in) — a stale provider answer or a wrong password
   confirms nothing; then it locks an account.
4. Approval: the account's API key asks to lock another account; the person confirms in the browser with ITS step-up
   of THAT approval (password, OIDC `max_age=0`, SAML `ForceAuthn`) — without, stale, or reused it stays pending; then
   it is executed once, and `stepup_amr` names the way.

Each step records a result; the three records must be equal. The provider legs need the extras `[oidc]` and `[saml]`:
without them the suite skips with the reason (a skip is not a green — `scripts/check.sh` installs them).
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("onelogin", extra="saml")
braucht_modul("authlib", extra="oidc")
braucht_modul("cryptography")
braucht_modul("lxml")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import _saml_idp  # noqa: E402
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://app.example.com"
OIDC_IDP = "https://oidc.example.com"
PW = "a long probe password 4711"
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


class _Claims(dict):
    def validate(self, *a, **k):
        pass


idp = _saml_idp.IdP(BASE)
auth = TinySesam(TinySesamConfig(
    lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), base_url=BASE, cookie_secure=False,
    passkey_enabled=False, apikey_enabled=True, approvals_enabled=True, stepup_max_age_sec=900,
    available_roles=["editors"], oidc_enabled=True, oidc_issuer=OIDC_IDP, oidc_client_id="probe",
    oidc_client_secret="secret", **idp.config()))
auth.oidc._meta = {"issuer": OIDC_IDP, "authorization_endpoint": OIDC_IDP + "/authorize",
                   "token_endpoint": OIDC_IDP + "/token", "userinfo_endpoint": OIDC_IDP + "/userinfo",
                   "jwks_uri": OIDC_IDP + "/jwks"}
auth.oidc.userinfo = lambda at, expected_sub="": {}
OIDC = {"claims": {}}
auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({**OIDC["claims"], "nonce": nonce}), {"access_token": "at"})

app = FastAPI()
app.include_router(auth.router())


@app.get("/editors")
def editors_only(u=Depends(auth.require_role("editors", admin_implies=False))):
    return {"user": u["username"]}


def browser():
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    c.get("/auth/login")            # the CSRF cookie, as a browser gets it
    return c


def tok(c):
    """The browser's current CSRF token (a sign-in renews it)."""
    return c.cookies.get(auth.csrf_cookie_name) or ""


def make_stale(c):
    then = int(time.time()) - STALE
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(c.cookies.get(auth.session_cookie_name))))


def session_user(c):
    s = auth.store.get_session(c.cookies.get(auth.session_cookie_name))
    return int(s["user_id"]) if s else None


def panel(c, path, body):
    return c.post("/auth/admin/api" + path, json=body, headers={"X-CSRF-Token": tok(c)})


def oidc_round(c, sub, query, age=0):
    OIDC["claims"] = {"sub": sub, "preferred_username": sub, "auth_time": int(time.time()) - age}
    start = c.get("/auth/oidc/start?" + query)
    assert start.status_code == 303, start.status_code
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={state}")


class Local:
    """A local account: a password at the login form, the password at the confirmation and the approval."""
    name, amr = "local", ["pwd"]

    def sign_in(self, c):
        auth.create_user("lou", password=PW)
        r = c.post("/auth/login", data={"username": "lou", "password": PW, "_csrf": tok(c)})
        return r.status_code

    def confirm(self, c, good):
        return c.post("/auth/reauth", data={"password": PW if good else "wrong password 0000", "next": "/",
                                            "_csrf": tok(c)}).status_code

    def approve(self, c, aid, good):
        return decide(c, aid, password=PW if good else "wrong password 0000")


class Oidc:
    """An OIDC account: the provider at sign-in, `reauth=1` and `approval=<id>` with a fresh `auth_time`."""
    name, amr = "oidc", ["oidc"]

    def sign_in(self, c):
        return oidc_round(c, "olga", "next=/").status_code

    def confirm(self, c, good):
        return oidc_round(c, "olga", "reauth=1&next=/", age=0 if good else 3600).status_code

    def approve(self, c, aid, good):
        oidc_round(c, "olga", f"approval={aid}&next=/", age=0 if good else 3600)
        return decide(c, aid, method="oidc")


class Saml:
    """A SAML account: the test identity provider at sign-in, `ForceAuthn` with a fresh `AuthnInstant` at the
    confirmation and the approval."""
    name, amr = "saml", ["saml"]

    def sign_in(self, c):
        return _saml_idp.round_trip(c, idp, "sami").status_code

    def confirm(self, c, good):
        rid, req = _saml_idp.start(c, "reauth=1&next=/")
        assert 'ForceAuthn="true"' in req, req[:300]
        return _saml_idp.acs(c, idp, rid, "sami", time.time() - (0 if good else 3600)).status_code

    def approve(self, c, aid, good):
        rid, req = _saml_idp.start(c, f"approval={aid}&next=/")
        assert 'ForceAuthn="true"' in req, "the approval's provider button did not force a sign-in"
        r = _saml_idp.acs(c, idp, rid, "sami", time.time() - (0 if good else 3600))
        if not good:      # back to the approval page, which says why — no silent success
            assert r.headers["location"].endswith(f"/auth/approvals/{aid}?stepup=stale-saml"), r.headers
            assert auth.t("err.saml_reauth_stale") in c.get(r.headers["location"]).text
        return decide(c, aid, method="saml")


def page_hash(c, aid):
    p = c.get(f"/auth/approvals/{aid}")
    assert p.status_code == 200, (p.status_code, p.text[:300])
    return re.search(r"name=payload_hash value='([^']+)'", p.text).group(1)


def decide(c, aid, **extra):
    form = {"_csrf": tok(c), "decision": "approve", "payload_hash": page_hash(c, aid), **extra}
    return outcome(c.post(f"/auth/approvals/{aid}", data=form).status_code)


def outcome(status):
    """A status as the scenario compares it: success codes as they are, every refusal as "refused" — a missing
    password field (400) and a provider grant that is not there (403) are the same result for the person."""
    return status if status < 400 else "refused"


def approval_state(aid):
    return auth.store.get_approval(aid)["state"]


# The administrator who grants the role and the admin flag: local, signed in fresh.
boss = int(auth.create_user("boss", password=PW, is_admin=True))
admin = browser()
admin.post("/auth/login", data={"username": "boss", "password": PW, "_csrf": tok(admin)})
assert session_user(admin) == boss

records = {}
for origin in (Local(), Oidc(), Saml()):
    rec = []
    c = browser()
    # 1. sign in through the origin's own path
    rec.append(("sign-in", origin.sign_in(c)))
    uid = session_user(c)
    assert uid, f"{origin.name}: no session after the sign-in"
    assert auth.store.account_sources([uid])[uid] == [origin.name], auth.store.account_sources([uid])
    # 2. a role granted in the panel takes effect
    rec.append(("role before", c.get("/editors").status_code))
    rec.append(("grant role", panel(admin, f"/users/{uid}/roles", {"roles": ["editors"]}).status_code))
    rec.append(("role after", c.get("/editors").status_code))
    rec.append(("has_role", auth.has_role(auth.get_user(uid), "editors")))
    # 3. admin action: stale → refused until the origin's own confirmation
    rec.append(("make admin", panel(admin, f"/users/{uid}/roles", {"roles": ["editors"], "is_admin": True})
                .status_code))
    target = int(auth.create_user(f"target-{origin.name}", password=PW))
    make_stale(c)
    r = panel(c, f"/users/{target}/disable", {"disabled": True})
    rec.append(("stale admin action", r.status_code, "x-tinysesam-reauth" in {k.lower() for k in r.headers}))
    origin.confirm(c, good=False)
    rec.append(("after a stale/wrong confirmation", panel(c, f"/users/{target}/disable", {"disabled": True})
                .status_code))
    origin.confirm(c, good=True)
    rec.append(("after the confirmation", panel(c, f"/users/{target}/disable", {"disabled": True}).status_code))
    rec.append(("target locked", bool(auth.store.get_user(target)["disabled"])))
    # 4. approval: the key asks, the person confirms with the origin's step-up of THAT approval
    key = c.post("/auth/apikeys", json={"name": "probe"}, headers={"X-CSRF-Token": tok(c)})
    rec.append(("api key", key.status_code))
    assert key.status_code == 200, (origin.name, key.status_code, key.text[:300], rec)
    second = int(auth.create_user(f"second-{origin.name}", password=PW))
    machine = TestClient(app, base_url=BASE, follow_redirects=False)
    asked = machine.post("/auth/api/approvals", headers={"X-Api-Key": key.json()["key"]},
                         json={"type": "tinysesam.account.disable", "fields": {"account": str(second)}})
    rec.append(("request", asked.status_code))
    aid = asked.json()["id"]
    rec.append(("without a step-up", decide(c, aid), approval_state(aid)))
    rec.append(("stale/wrong step-up", origin.approve(c, aid, good=False), approval_state(aid)))
    rec.append(("step-up", origin.approve(c, aid, good=True), approval_state(aid)))
    rec.append(("second locked", bool(auth.store.get_user(second)["disabled"])))
    row = auth.store.get_approval(aid)
    assert json.loads(row["stepup_amr"]) == origin.amr, (origin.name, row["stepup_amr"])
    records[origin.name] = rec
    ok(f"{origin.name}: sign-in, role, admin action and approval ran through ({len(rec)} results)")

local = records["local"]
for name in ("oidc", "saml"):
    for mine, theirs in zip(records[name], local):
        assert mine == theirs, f"{name} differs from local at {mine[0]!r}: {mine} vs {theirs}"
    assert len(records[name]) == len(local)
print("    " + " · ".join(f"{r[0]}={r[1:]}" for r in local))
ok("the same scenario gives the same result for a local, an OIDC and a SAML account")
assert local[-4][1:] == ("refused", "pending") and local[-3][1:] == ("refused", "pending"), local[-4:]
assert local[-2][1:] == (200, "consumed") and local[-1][1] is True
ok("the approval stays pending without, with a stale or a wrong step-up, and is executed once after the right one")

# A provider confirmation of one approval does not confirm a second one, for OIDC and SAML alike.
for origin, who in ((Oidc(), "olga"), (Saml(), "sami")):
    c = browser()
    origin.sign_in(c)
    uid = session_user(c)
    key = auth.create_api_key(uid, name=f"again-{origin.name}")["key"]
    machine = TestClient(app, base_url=BASE, follow_redirects=False)
    ids = []
    for _ in range(2):
        victim = int(auth.create_user(f"v{len(ids)}-{origin.name}", password=PW))
        r = machine.post("/auth/api/approvals", headers={"X-Api-Key": key},
                         json={"type": "tinysesam.account.disable", "fields": {"account": str(victim)}})
        ids.append(r.json()["id"])
    assert origin.approve(c, ids[0], good=True) == 200 and approval_state(ids[0]) == "consumed"
    assert decide(c, ids[1], method=origin.name) != 200 and approval_state(ids[1]) == "pending", \
        f"{origin.name}: one provider sign-in confirmed two approvals"
ok("one provider sign-in confirms exactly one approval (OIDC and SAML)")

# The SAML approval button appears only for an account bound at the SAML provider, and a foreign account's
# provider round leaves no grant for the approval.
c = browser()
c.post("/auth/login", data={"username": "lou", "password": PW, "_csrf": tok(c)})
lou = session_user(c)
lou_key = auth.create_api_key(lou, name="lou-2")["key"]
vic = int(auth.create_user("v-lou", password=PW))
aid = TestClient(app, base_url=BASE).post("/auth/api/approvals", headers={"X-Api-Key": lou_key}, json={
    "type": "tinysesam.account.disable", "fields": {"account": str(vic)}}).json()["id"]
page = c.get(f"/auth/approvals/{aid}").text
assert "id=apvsaml" not in page and "id=apvoidc" not in page, "a provider button for a local account"
rid, _ = _saml_idp.start(c, f"approval={aid}&next=/")
_saml_idp.acs(c, idp, rid, "sami")                 # signs in as sami: another account, no step-up of lou's session
assert auth.store._one("SELECT 1 FROM flow WHERE key=?", ("apvsaml:" + aid,)) is None, "a grant for another account"
c2 = browser()
c2.post("/auth/login", data={"username": "lou", "password": PW, "_csrf": tok(c2)})
assert decide(c2, aid, method="saml") != 200 and approval_state(aid) == "pending"
ok("a local account sees no provider button; a SAML round of another account confirms nothing")

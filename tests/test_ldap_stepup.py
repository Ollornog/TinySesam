"""T-99: LDAP step-up by a fresh bind.

An LDAP account has no local password: up to now it had nothing to confirm with (`stepup_options` empty), so new
access (`_require_fresh`) asked for a new sign-in. Now the confirmation page offers it the password field, and
`confirm_password` checks it by a fresh bind through `_check_ldap` — the one directory check — which must lead to THIS
account. Throttled and counted in the `reauth` bucket like any confirmation; a directory outage is not a failed attempt
(503, taken back, as at sign-in, F-23).
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.ldap_ import DirectoryNotReachable  # noqa: E402

STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


class FakeLDAP:
    """A directory stub: {name: {password, id, groups}}; `down` raises the outage."""

    def __init__(self, users):
        self.users, self.down, self.binds = users, False, 0

    def authenticate(self, username, password):
        self.binds += 1
        if self.down:
            raise DirectoryNotReachable("connection refused")
        u = self.users.get(username)
        if not u or u["password"] != password:
            return None
        return {"username": username, "email": None, "name": username, "groups": u.get("groups", []),
                "id": u["id"]}


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
               base_url="https://auth.example.com", passkey_enabled=False, oidc_enabled=False, ldap_enabled=True,
               ldap_url="ldap://dummy", ldap_allow_plaintext=True, apikey_enabled=True, stepup_max_age_sec=900)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def signed_in(auth, app, name, password):
    c = TestClient(app)
    r = c.post("/auth/login", data={"username": name, "password": password}, follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    return c


def make_stale(auth, c):
    tok = c.cookies.get(auth.session_cookie_name)
    then = int(time.time()) - STALE
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))


def attempts(auth):
    return auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE method='reauth'")["n"]


def fresh(auth, c):
    return c.post("/auth/apikeys", json={"name": "probe"}, headers={"Accept": "application/json"}).status_code


auth, app = build()
ldap = FakeLDAP({"alice": {"password": "directory pw 1", "id": "guid-alice"},
                 "bob": {"password": "directory pw 2", "id": "guid-bob"}})
auth.ldap = ldap
c = signed_in(auth, app, "alice", "directory pw 1")
alice = auth.store.get_user_by_name("alice")
assert auth.store.get_password_hash(alice["id"]) is None
assert "password" in auth.stepup_options(dict(alice)), auth.stepup_options(dict(alice))
make_stale(auth, c)
assert fresh(auth, c) == 403, "a stale directory session created an API key"
page = c.get("/auth/reauth").text
assert 'name="password"' in page or "name=password" in page, "the confirmation page offers no password field"
ok("an LDAP account without a local password is offered the password on the confirmation page; stale → 403")

# ---------- a wrong directory password is a counted failed attempt ----------
before, binds = attempts(auth), ldap.binds
r = c.post("/auth/reauth", data={"password": "wrong"}, follow_redirects=False)
assert r.status_code == 401 and attempts(auth) == before + 1 and ldap.binds == binds + 1, (r.status_code,)
assert fresh(auth, c) == 403
ok("wrong directory password: 401, one bind, one counted reauth attempt, still not fresh")

# ---------- an outage is not a failed attempt ----------
ldap.down = True
before = attempts(auth)
r = c.post("/auth/reauth", data={"password": "directory pw 1"}, follow_redirects=False)
assert r.status_code == 503 and attempts(auth) == before, (r.status_code, attempts(auth), before)
assert auth.store._one("SELECT 1 AS x FROM audit WHERE event='ldap_unavailable'"), "no audit line for the outage"
ldap.down = False
# After an outage the directory is left alone for a pause (`ldap_.FailureMarker`); the pause is over here.
from tinysesam.ldap_ import FailureMarker  # noqa: E402
auth._ldap_failure = FailureMarker()
ok("directory outage: 503, nothing counted, audit ldap_unavailable")

# ---------- the right password confirms ----------
r = c.post("/auth/reauth", data={"password": "directory pw 1"}, follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:200])
assert fresh(auth, c) == 200, "a fresh directory confirmation did not satisfy _require_fresh"
ok("right directory password: 303, the session is fresh, new access (API key) works")

# ---------- the directory entry must lead to THIS account ----------
c_bob = signed_in(auth, app, "bob", "directory pw 2")
make_stale(auth, c_bob)
bob = auth.store.get_user_by_name("bob")
# Someone renames entries in the directory: the name `bob` now belongs to alice's entry (her identifier). A bind with
# alice's password under the name `bob` leads to alice's account, not to bob's session.
ldap.users["bob"] = {"password": "directory pw 1", "id": "guid-alice"}
r = c_bob.post("/auth/reauth", data={"password": "directory pw 1"}, follow_redirects=False)
assert r.status_code == 401 and fresh(auth, c_bob) == 403, r.status_code
ok("an entry that leads to another account does not confirm (401, still not fresh)")
ldap.users["bob"] = {"password": "directory pw 2", "id": "guid-bob"}
# `_check_ldap` refuses that case itself (one identifier, one account); the step-up compares the account once more —
# a directory check that ever answered with another account must not confirm this session.
real_check = auth._check_ldap
auth._check_ldap = lambda name, password: auth.store.get_user_by_name("alice")
r = c_bob.post("/auth/reauth", data={"password": "directory pw 2"}, follow_redirects=False)
auth._check_ldap = real_check
assert r.status_code == 401 and fresh(auth, c_bob) == 403, r.status_code
assert auth.store._one("SELECT 1 AS x FROM audit WHERE event='ldap_reauth_other_account'"), "no audit line"
ok("second guard: a directory answer with another account is refused (audit ldap_reauth_other_account)")

# ---------- the group gate applies to the confirmation too ----------
auth2, app2 = build(ldap_allowed_groups=["cn=staff,ou=groups,dc=example,dc=com"])
ldap2 = FakeLDAP({"carol": {"password": "directory pw 3", "id": "guid-carol",
                            "groups": ["cn=staff,ou=groups,dc=example,dc=com"]}})
auth2.ldap = ldap2
c2 = signed_in(auth2, app2, "carol", "directory pw 3")
make_stale(auth2, c2)
ldap2.users["carol"]["groups"] = []
r = c2.post("/auth/reauth", data={"password": "directory pw 3"}, follow_redirects=False)
assert r.status_code == 401 and fresh(auth2, c2) == 403, r.status_code
ok("removed from the allowed group: the fresh bind does not confirm")

# ---------- a local account on the same installation keeps its local password ----------
auth.create_user("dora", password="a long local password 4711")
c3 = signed_in(auth, app, "dora", "a long local password 4711")
make_stale(auth, c3)
binds = ldap.binds
r = c3.post("/auth/reauth", data={"password": "a long local password 4711"}, follow_redirects=False)
assert r.status_code == 303 and ldap.binds == binds, (r.status_code, ldap.binds, binds)
ok("a local account confirms with its local hash, the directory is not asked")

# ---------- without a directory client nothing is offered ----------
auth.ldap = None
assert "password" not in auth.stepup_options(dict(alice)), "offered without a directory to bind against"
ok("no directory client: the directory password is not offered")

print("OK test_ldap_stepup")

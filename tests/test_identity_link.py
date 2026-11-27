"""T-99, ADR-18: the person links a directory (LDAP) identity and unlinks any provider identity herself.

Linking a directory account (`POST /auth/ldap/link`): the CSRF token from the account page, a fresh confirmation here,
the directory password checked by a bind (`_ldap_bind`, shared with the sign-in) — booked like a sign-in under the typed
name (throttled, counted, `failed login`), an outage is no attempt. The attack tests: a link without the token, from a
stale session, with a wrong password, for an entry another account holds, under the name of another local account, or
a second time binds nothing.

Unlinking (`POST /auth/identities/unlink`, OIDC, SAML and LDAP alike): CSRF, a fresh confirmation, never the last way
in. A directory identity the person released is never bound back by the name at the next sign-in
(`unlinked_by_holder`) — until she links again.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.ldap_ import DirectoryNotReachable, FailureMarker  # noqa: E402

BASE = "https://auth.example.com"
IDP = "https://idp.example.invalid"
PW = "a long local password 4711"
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


auth = TinySesam(TinySesamConfig(
    lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, base_url=BASE,
    passkey_enabled=False, ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
    oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret", stepup_max_age_sec=900))
directory = FakeLDAP({"lena.dir": {"password": "dir pw lena", "id": "uuid-lena"},
                      "kim": {"password": "dir pw kim", "id": "uuid-kim"},
                      "max": {"password": "dir pw max", "id": "uuid-max"},
                      "ina": {"password": "dir pw ina", "id": "uuid-ina"},
                      "solo": {"password": "dir pw solo", "id": "uuid-solo"}})
auth.ldap = directory
auth.set_security("rate_limit_max", 1000)      # this suite signs in often from one address; the throttle is not its topic
app = FastAPI()
app.include_router(auth.router())


def tok(c):
    return c.cookies.get(auth.csrf_cookie_name) or ""


def browser(name, password):
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    c.get("/auth/login")
    r = c.post("/auth/login", data={"username": name, "password": password, "_csrf": tok(c)})
    assert r.status_code == 303, (name, r.status_code, r.text[:200])
    return c


def make_stale(c):
    then = int(time.time()) - STALE
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(c.cookies.get(auth.session_cookie_name))))


def link(c, name, password, csrf=True):
    data = {"username": name, "password": password}
    if csrf:
        data["_csrf"] = tok(c)
    return c.post("/auth/ldap/link", data=data)


def unlink(c, source, csrf=True):
    data = {"source": source}
    if csrf:
        data["_csrf"] = tok(c)
    return c.post("/auth/identities/unlink", data=data)


def audited(event):
    return [a for a in auth.store.recent_audit(300) if a["event"] == event]


def failed_attempts(name):
    return auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE username=? AND method='password' "
                           "AND success=0 AND pending=0", (name,))["n"]


# ======================= linking a directory account =======================
lena = int(auth.create_user("lena", password=PW))
c = browser("lena", PW)
page = c.get("/auth/account").text
assert "action='/auth/ldap/link'" in page and "name=_csrf" in page and "name=password" in page, \
    "the account page offers no directory link form"
assert link(c, "lena.dir", "dir pw lena", csrf=False).status_code == 403
assert c.get("/auth/ldap/link").status_code in (404, 405)
ok("the account page offers the directory link as a form with the CSRF token; without the token 403, no GET route")

make_stale(c)
r = link(c, "lena.dir", "dir pw lena")
assert r.status_code == 403 and "x-tinysesam-reauth" in {k.lower() for k in r.headers}, (r.status_code, r.headers)
assert auth.store.get_federated_user("ldap", "uuid-lena") is None
c = browser("lena", PW)
ok("a stale session is sent to confirm first (403 with X-TinySesam-Reauth), nothing bound")

before = failed_attempts("lena.dir")
r = link(c, "lena.dir", "wrong directory password")
assert r.status_code == 401 and auth.store.get_federated_user("ldap", "uuid-lena") is None, r.status_code
assert failed_attempts("lena.dir") == before + 1, "a wrong directory password at the link was not counted"
assert [a for a in audited("login_fail") if a["username"] == "lena.dir"], "no login_fail line for fail2ban"
ok("a wrong directory password: 401, nothing bound, counted as a failed sign-in under the typed name")

directory.down = True
before, binds = failed_attempts("lena.dir"), directory.binds
r = link(c, "lena.dir", "dir pw lena")
assert r.status_code == 503 and failed_attempts("lena.dir") == before and directory.binds == binds + 1
assert auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE pending=1")["n"] == 0, "pre-booking left open"
directory.down = False
auth._ldap_failure = FailureMarker()
ok("a directory outage: 503, no attempt counted, nothing left pending")

kim_c = browser("kim", "dir pw kim")                      # kim signs in by LDAP: the entry is kim's account's
kim = int(auth.store.get_federated_user("ldap", "uuid-kim"))
r = link(c, "kim", "dir pw kim")
assert r.status_code == 409 and auth.store.get_federated_user("ldap", "uuid-kim") == kim, r.status_code
auth.store._exec("UPDATE users SET username='kimberly' WHERE id=?", (kim,))     # renamed here: the typed name is free
r = link(c, "kim", "dir pw kim")
assert r.status_code == 409 and auth.store.get_federated_user("ldap", "uuid-kim") == kim, r.status_code
assert [a for a in audited("ldap_link_refused") if "identity_taken" in (a["detail"] or "")]
ok("attack: a directory entry another account holds is not moved (409 identity_taken), even with its password")

maxi = int(auth.create_user("max", password=PW))         # a LOCAL account named like a directory entry
r = link(c, "max", "dir pw max")
assert r.status_code == 409 and auth.store.get_federated_user("ldap", "uuid-max") is None, r.status_code
assert auth.store.get_federated_identifier("ldap", maxi) is None
ok("attack: the typed name of another local account binds nothing (one identifier, one account)")

r = link(c, "lena.dir", "dir pw lena")
assert r.status_code == 303 and r.headers["location"].endswith("/auth/account"), (r.status_code, r.text[:200])
assert auth.store.get_federated_user("ldap", "uuid-lena") == lena and audited("ldap_linked")
assert auth.store.account_sources([lena])[lena] == ["local", "ldap"]
again = browser("lena.dir", "dir pw lena")
assert auth.store.get_session(again.cookies.get(auth.session_cookie_name))["user_id"] == lena
assert link(c, "lena.dir", "dir pw lena").status_code == 409, "a second directory identity"
ok("the link binds the entry's stable identifier; the directory sign-in lands in the account; a second link 409")

# ======================= unlinking by the person =======================
assert "action='/auth/identities/unlink'" in c.get("/auth/account").text and "id=idl_ldap" in c.get("/auth/account").text
assert unlink(c, "ldap", csrf=False).status_code == 403
make_stale(c)
r = unlink(c, "ldap")
assert r.status_code == 403 and "x-tinysesam-reauth" in {k.lower() for k in r.headers}
assert auth.store.get_federated_user("ldap", "uuid-lena") == lena
c = browser("lena", PW)
assert unlink(c, "nonsense").status_code == 400 and unlink(c, "saml").status_code == 400
assert unlink(c, "oidc").status_code == 404
ok("unlink: without the token 403, stale → reauth, an unknown or switched-off provider 400, a provider not linked 404")

r = unlink(c, "ldap")
assert r.status_code == 303 and auth.store.get_federated_identifier("ldap", lena) is None and audited("ldap_unlinked")
assert auth.store.account_sources([lena])[lena] == ["local"]
ok("the person unlinks the directory identity (a password stays): 303, binding gone, audit ldap_unlinked")

# The last way in stays: an account the directory created, without a password of its own.
solo_c = browser("solo", "dir pw solo")
solo = int(auth.store.get_federated_user("ldap", "uuid-solo"))
page = solo_c.get("/auth/account").text
assert "id=idl_ldap" in page and auth.t("acc.identity_last") in page.replace("&#x27;", "'"), \
    "the page does not say why the only way in cannot be unlinked"
assert not re.search(r"name=source value='ldap'", page), "an unlink button for the last way in"
r = unlink(solo_c, "ldap")
assert r.status_code == 409 and auth.store.get_federated_user("ldap", "uuid-solo") == solo, r.status_code
assert [a for a in audited("ldap_unlink_refused") if "last_way_in" in (a["detail"] or "")]
ok("the last way in is not unlinked (409), and the page shows the reason instead of a button")

# A released directory identity is never bound back by the name — until the person links again.
browser("ina", "dir pw ina")
ina = int(auth.store.get_federated_user("ldap", "uuid-ina"))
auth.set_password(ina, PW)
ina_c = browser("ina", PW)
assert unlink(ina_c, "ldap").status_code == 303 and auth.store.get_federated_identifier("ldap", ina) is None
probe = TestClient(app, base_url=BASE, follow_redirects=False)
probe.get("/auth/login")
r = probe.post("/auth/login", data={"username": "ina", "password": "dir pw ina", "_csrf": tok(probe)})
assert r.status_code != 303 and auth.store.get_federated_identifier("ldap", ina) is None, \
    "the next directory sign-in bound the released identity back by the name"
assert [a for a in audited("ldap_name_binding_closed") if "unlinked_by_holder" in (a["detail"] or "")]
r = link(ina_c, "ina", "dir pw ina")
assert r.status_code == 303, (r.status_code, r.text[:300])
assert auth.store.get_federated_user("ldap", "uuid-ina") == ina
assert not auth.store.name_binding_closed("ldap", ina), "linking again leaves the marker"
browser("ina", "dir pw ina")
ok("a released directory identity is not bound back by the name at the next sign-in; linking again lifts that")

# OIDC: the same rule — unlink with another way in, never the only one.
auth.store.link_oidc(IDP, "lena-sub", lena)
assert unlink(c, "oidc").status_code == 303 and not auth.store.is_oidc_account(lena) and audited("oidc_unlinked")
only = int(auth.create_user("oliver"))
auth.store.link_oidc(IDP, "oliver-sub", only)
tok_o = auth.store.create_session(only, 86400, True, "oidc", factors=["oidc"])
oc = TestClient(app, base_url=BASE, follow_redirects=False)
oc.get("/auth/login")
oc.cookies.set(auth.session_cookie_name, tok_o)
assert unlink(oc, "oidc").status_code == 409 and auth.store.is_oidc_account(only)
ok("OIDC: unlinked with a password left; an account with only the provider keeps it (409)")

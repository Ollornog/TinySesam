"""Binding via the name: grace period, existing-account binding, self-chosen names (G1, G2-N from T-13).

Accounts from the time before the identifiers (F-11) bind themselves at the next sign-in via LDAP/SAML
via their name (situation 4). Until 2026-09-26 without any limit: a dormant account — someone left
the company — fell, including its admin right, to the next person who gets the same name
in the directory (G1). And a local account that renamed itself after someone from the directory
received that person's identifier and groups at their sign-in (G2-N). The attack round 2026-09-26 found the same
via a name that OIDC or SAML brought along on creation (a1-01, `users.name_source`).

What is measured is the effect: who ends up in which account after a sign-in, which binding stands,
which role the account carries, what is in the audit and security log — plus the existing-account binding
(`federation_bind_existing`) with a stand-in and against ldap3 (MOCK_SYNC), the startup message and
the back-fill for existing accounts.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check as _kp  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.ldap_ import LDAPClient, DirectoryNotReachable  # noqa: E402
from tinysesam.oidc import OIDCClient  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from tinysesam.store import SCHEMA, Store, now  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Binding via the name — grace period, existing-account binding, self-chosen names (G1, G2-N)")
TAG = 86400
PW = "Kiefer-Spur-478"


class Recording:
    """Record the security log (without timestamp)."""

    def __enter__(self):
        self.buffer = io.StringIO()
        self.check = logging.StreamHandler(self.buffer)
        self.check.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        seclog.addHandler(self.check)
        return self

    def __exit__(self, *_):
        seclog.removeHandler(self.check)

    def lines(self, word=""):
        return [z for z in self.buffer.getvalue().splitlines() if word in z]


class Directory:
    """Stand-in for the LDAP client: `authenticate` after a successful bind, `entry_search` like the
    existing-account search (list of hits). A list value = several entries under the name."""

    def __init__(self, entries=None, failure_at=None):
        self.entries = entries or {}
        self.failure_at = failure_at
        self.asked: list = []

    @staticmethod
    def _info(name, e):
        return {"username": name, "email": e.get("email"), "name": e.get("name", name),
                "groups": e.get("groups", []), "id": e.get("id")}

    def authenticate(self, username, password):
        e = self.entries.get(username)
        if not e or isinstance(e, list) or e.get("pw", "pw") != password:
            return None
        return self._info(username, e)

    def entry_search(self, username):
        self.asked.append(username)
        if username == self.failure_at:
            raise DirectoryNotReachable("Dummy: directory down")
        e = self.entries.get(username)
        if e is None:
            return []
        return [self._info(username, x) for x in (e if isinstance(e, list) else [e])]


def _db():
    return str(Path(tempfile.mkdtemp()) / "t.db")


def _ldap(db=None, **cfg):
    reason = dict(db_path=db or _db(), cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                 lang="de", ldap_enabled=True, ldap_url="ldap://directory.example.com",
                 ldap_allow_plaintext=True, ldap_auto_create=True,
                 ldap_group_role_map={"cn=chefs": "chef"})
    reason.update(cfg)
    return TinySesam(TinySesamConfig(**reason))


def _saml(db=None, **cfg):
    reason = dict(db_path=db or _db(), cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                 lang="de", base_url="https://app.example.com", saml_enabled=True,
                 saml_attr_username="uid", saml_auto_create=True)
    reason.update(cfg)
    return TinySesam(TinySesamConfig(**reason))


def _alternate(auth, *uids, source="ldap", days=31):
    """The grace period is over: marker of the source set back `days`, the accounts two years old."""
    auth.store._exec("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                     (f"federation_since:{source}", str(now() - days * TAG)))
    for uid in uids:
        auth.store._exec("UPDATE users SET created_at=? WHERE id=?", (now() - 730 * TAG, uid))


def _audit(auth, event):
    return [dict(z) for z in auth.store._all("SELECT * FROM audit WHERE event=? ORDER BY id", (event,))]


def _flag(auth, uid):
    return auth.store._one("SELECT name_self_chosen AS f FROM users WHERE id=?", (uid,))["f"]


def _sign_in(auth, name, entry, pw="pw"):
    auth.ldap = Directory({name: dict(entry, pw=pw)})
    return auth._check_ldap(name, pw)


# ══ G1: grace period for binding via the name ═══════════════════════════════════════════════════
a = _ldap()
r.check("Default: federation_name_binding_days = 30", a.cfg.federation_name_binding_days == 30)
r.check("The source marker exists right after construction (ldap_enabled), SAML without switch does not",
        a.store.get_setting("federation_since:ldap") is not None
        and a.store.get_setting("federation_since:saml") is None)

# (1) Dormant account with admin right, grace period over, new entry with a foreign identifier.
js = a.create_user("jsmith", is_admin=True)
_alternate(a, js)
with Recording() as log:
    u = _sign_in(a, "jsmith", {"id": "uuid-new", "groups": ["cn=chefs"]})
to = _audit(a, "ldap_name_binding_closed")
r.check("Grace period over: the new jsmith from the directory does NOT take over the dormant account",
        u is None and a.store.get_federated_identifier("ldap", js) is None, str(u))
r.check("… the account keeps its admin right and gets no role from the directory",
        a.get_user(js)["is_admin"] == 1 and a.user_roles(a.store.get_user(js)) == [])
r.check("… audit `ldap_name_binding_closed` with reason and identifier",
        len(to) == 1 and to[0]["username"] == "jsmith" and to[0]["detail"] == "reason=binding_window_expired identifier=uuid-new",
        str(to))
r.check("… the log line names identifier and remedy (federation_unbind, federation_bind_existing)",
        any("uuid-new" in z and f"federation_unbind('ldap', {js})" in z
            and "federation_bind_existing('ldap')" in z for z in log.lines("jsmith")), log.buffer.getvalue()[-600:])

# (4) The operator opens the binding explicitly — the next sign-in binds.
away = a.federation_unbind("ldap", js)
unclosed = a.store._one("SELECT until FROM name_binding WHERE source='ldap' AND user_id=?", (js,))
r.check("federation_unbind on an unbound account: 0 released, binding via the name opened",
        away == 0 and unclosed is not None and unclosed["until"] > now() + 29 * TAG, str(unclosed and dict(unclosed)))
u = _sign_in(a, "jsmith", {"id": "uuid-new"})
r.check("… afterwards the next sign-in binds via the name, even after the grace period",
        u is not None and u["id"] == js and a.store.get_federated_identifier("ldap", js) == "uuid-new")
r.check("… and the opening is used up (row gone)",
        a.store._one("SELECT 1 AS x FROM name_binding WHERE user_id=?", (js,)) is None)
u = _sign_in(a, "jsmith", {"id": "uuid-third"})
r.check("… a further foreign identifier under the name stays out (situation 3, door closed again)",
        u is None and a.store.get_federated_identifier("ldap", js) == "uuid-new")

# (1b) Replacement of an origin placeholder after the grace period.
quay = a.create_user("ken")
a.store.link_federated("ldap", f"{Store.WITHOUT_IDENTIFIER}{quay}", quay, now())
_alternate(a, quay)
u = _sign_in(a, "ken", {"id": "uuid-ken-new"})
r.check("Placeholder after the grace period: no new identifier, the placeholder stays",
        u is None and a.store.get_federated_identifier("ldap", quay) == f"{Store.WITHOUT_IDENTIFIER}{quay}",
        str(a.store.get_federated_identifier("ldap", quay)))

# (2) Pre-creation: freshly created account, the source's grace period long over — own grace period from creation.
vera = a.create_user("vera")
u = _sign_in(a, "vera", {"id": "uuid-vera"})
r.check("Pre-creation in the panel (fresh): binds via the name, even if the marker is old",
        u is not None and u["id"] == vera and a.store.get_federated_identifier("ldap", vera) == "uuid-vera")

# (2b) Control for existing accounts within the grace period: old account, fresh marker.
b = _ldap()
old = b.create_user("altbestand")
b.store._exec("UPDATE users SET created_at=? WHERE id=?", (now() - 730 * TAG, old))
u = _sign_in(b, "altbestand", {"id": "uuid-alt"})
r.check("Existing account (no password, not self-named) within the grace period: still binds afterwards",
        u is not None and u["id"] == old and _audit(b, "ldap_identifier_bound")[-1]["detail"]
        == "bound later at sign-in")

# (3) -1 = old behaviour, 0 = explicit only, -2 = construction error.
c1 = _ldap(federation_name_binding_days=-1)
x = c1.create_user("xaver")
_alternate(c1, x, days=4000)
u = _sign_in(c1, "xaver", {"id": "uuid-x"})
r.check("federation_name_binding_days=-1: binds without limit (behaviour up to 0.20.x)",
        u is not None and u["id"] == x)
c0 = _ldap(federation_name_binding_days=0)
y = c0.create_user("yara")
u = _sign_in(c0, "yara", {"id": "uuid-y"})
r.check("federation_name_binding_days=0: even a fresh account does not bind itself",
        u is None and c0.store.get_federated_identifier("ldap", y) is None)
c0.federation_unbind("ldap", y)
u = _sign_in(c0, "yara", {"id": "uuid-y"})
r.check("… only explicitly (federation_unbind opens for at least one day)",
        u is not None and u["id"] == y)
try:
    _ldap(federation_name_binding_days=-2)
    _throws = False
except ConfigError as e:
    _throws = "federation_name_binding_days" in str(e)
r.check("federation_name_binding_days=-2: ConfigError on construction", _throws)

# (5) The marker arises exactly once — also across a restart.
path = _db()
m1 = _ldap(path)
_alternate(m1, days=40)
before = m1.store.get_setting("federation_since:ldap")
m1.store.db.close()
m2 = _ldap(path)
r.check("Marker once only: a second start does not set it anew (otherwise every restart would grant a grace period)",
        m2.store.get_setting("federation_since:ldap") == before, f"{before} → {m2.store.get_setting('federation_since:ldap')}")

# (1c) SAML: the same via the NameID.
s = _saml()
r.check("SAML: the marker exists after construction", s.store.get_setting("federation_since:saml") is not None)
sam = s.create_user("sam", is_admin=True)
_alternate(s, sam, source="saml")
u = s._check_saml("nid-new", {"uid": ["sam"]})
r.check("SAML after the grace period: a new NameID under the name does not take over the dormant account",
        u is None and s.store.get_federated_identifier("saml", sam) is None
        and [z["detail"] for z in _audit(s, "saml_name_binding_closed")] == ["reason=binding_window_expired identifier=nid-new"])
sina = s.create_user("sina")
u = s._check_saml("nid-sina", {"uid": ["sina"]})
r.check("SAML pre-creation: binds", u is not None and u["id"] == sina)

# (10) Without identifier: the FIRST assignment of an existing account goes through the same door.
n = _ldap()
otto = n.create_user("otto")
_alternate(n, otto)
u = _sign_in(n, "otto", {})
r.check("Without identifier, grace period over: the existing account is not assigned via the name",
        u is None and n.store.get_federated_identifier("ldap", otto) is None)
pia = n.create_user("pia")
u = _sign_in(n, "pia", {})
r.check("Without identifier, fresh account: assigned, origin recorded",
        u is not None and u["id"] == pia
        and n.store.get_federated_identifier("ldap", pia) == f"{Store.WITHOUT_IDENTIFIER}{pia}")
_alternate(n, pia)
u = _sign_in(n, "pia", {})
r.check("… an account the source already knows (placeholder) still signs in after the grace period",
        u is not None and u["id"] == pia)

# ══ G2-N: self-chosen names never bind via the name ══════════════════════════════════════
# The finding as a test: `eve` renames herself to `manager`, a name that exists only in the directory.
g = _ldap()
eve = g.create_user("eve", password=PW)
r.check("Account created by the operator: marker 0", _flag(g, eve) == 0)
# Alongside LDAP nobody renames themselves any more since 2026-09-27; the marker remains the second
# safeguard for existing accounts and for accounts that a foreign writer renamed.
g.store.set_username(eve, "boss", itself_chosen=True)
r.check("Self-renamed (existing): marker 1", _flag(g, eve) == 1)
with Recording() as log:
    u = _sign_in(g, "boss", {"id": "uuid-boss", "groups": ["cn=chefs"]}, pw="ldap-pw")
to = _audit(g, "ldap_name_binding_closed")
r.check("PoC: the real boss from the directory does NOT land in eve's account, no binding",
        u is None and g.store.get_federated_identifier("ldap", eve) is None, str(u))
r.check("… eve then has no role `chef`, not even via her local password",
        g._check_password("boss", PW) is not None
        and "chef" not in g.user_roles(g.store.get_user(eve)))
r.check("… rejection like situation 3: audit with reason and identifier, log line with the way out",
        [z["detail"] for z in to] == ["reason=self_chosen_name identifier=uuid-boss"]
        and any("uuid-boss" in z and f"federation_unbind('ldap', {eve})" in z
                for z in log.lines("chosen by the user")), str(to))
g.federation_unbind("ldap", eve)
u = _sign_in(g, "boss", {"id": "uuid-boss"}, pw="ldap-pw")
r.check("The operator decides explicitly (federation_unbind): then it binds",
        u is not None and u["id"] == eve)

# Renaming by the operator: the name stands for the operator.
op = g.create_user("olaf", password=PW)
g.store.set_username(op, "olga", itself_chosen=True)
g.change_username(op, "oskar", by_operator=True)
u = _sign_in(g, "oskar", {"id": "uuid-oskar"})
r.check("Renamed by the operator (by_operator=True): marker 0, binds",
        _flag(g, op) == 0 and u is not None and u["id"] == op)
r.check("… the audit row says by=operator",
        _audit(g, "username_changed")[-1]["detail"] == "old=olga by=operator")

# SAML and without identifier: the same rule.
s2 = _saml()
sv = s2.create_user("svenja", password=PW)
s2.change_username(sv, "saskia")
u = s2._check_saml("nid-saskia", {"uid": ["saskia"]})
r.check("SAML: a self-renamed account is not bound via the name",
        u is None and s2.store.get_federated_identifier("saml", sv) is None)
n2 = _ldap()
nv = n2.create_user("nora", password=PW)
n2.store.set_username(nv, "nele", itself_chosen=True)
u = _sign_in(n2, "nele", {})
r.check("LDAP without identifier: a self-renamed account is not assigned via the name",
        u is None and n2.store.get_federated_identifier("ldap", nv) is None)

# Registration (allow_signup) and renaming via the account page. Alongside LDAP the
# registration no longer exists since 2026-09-27 (construction error); alongside SAML it does — there the
# registered account carries the marker, and the SAML sign-in of the same identifier does not bind it.
try:
    _ldap(allow_signup=True, signup_verify_email=False, base_url="http://testserver")
    _ldap_reg = "built"
except ConfigError as e:
    _ldap_reg = str(e)
r.check("allow_signup alongside LDAP: construction error (PO decision 2026-09-27)",
        "allow_signup" in _ldap_reg and "ldap_enabled" in _ldap_reg, _ldap_reg[:160])
reg = _saml(allow_signup=True, signup_verify_email=False, base_url="http://testserver")
app = FastAPI()
app.include_router(reg.router())
c = TestClient(app)
response = c.post("/auth/register", data={"username": "boss", "password": PW,
                                         "email": "boss.private@example.com"}, follow_redirects=False)
rid = reg.store.get_user_by_name("boss")
r.check("Registration (SAML instance): the account carries the marker",
        response.status_code in (200, 303) and rid is not None and _flag(reg, rid["id"]) == 1,
        f"HTTP {response.status_code}")
u = reg._check_saml("nid-boss", {"uid": ["boss"]})
r.check("… the SAML boss does not take over the registered account",
        (u is None or u["id"] != rid["id"]) and reg.store.get_federated_identifier("saml", rid["id"]) is None,
        str(u))
ks = reg.create_user("konrad", password=PW)
c2 = TestClient(app)
c2.post("/auth/login", data={"username": "konrad", "password": PW}, follow_redirects=False)
response = c2.post("/auth/account/username", json={"username": "karla"})
r.check("Renaming via the account page (/auth/account/username): marker 1",
        response.status_code == 200 and _flag(reg, ks) == 1, f"HTTP {response.status_code} {response.text[:120]}")

# ══ Attack round 2026-09-26: a name from ANOTHER source never binds ══════════════════════
# Finding a1-01: G2-N marked only registration and renaming. An account that OIDC or SAML
# creates, however, also carries a name that the person may have chosen themselves — `preferred_username`
# or `uid` with an IdP with self-registration. Whoever chose `manager` there got, at the first
# LDAP sign-in of the real boss, her identifier and roles into their own account and signed in
# further via OIDC. Creation now remembers the source (`users.name_source`).
IDP = "https://idp.example.com"


class _Claims(dict):
    def validate(self, *a, **k):
        pass


def _with_oidc(**cfg):
    auth = _ldap(base_url="http://testserver", oidc_enabled=True, oidc_issuer=IDP,
                 oidc_client_id="probe", oidc_client_secret="secret", **cfg)
    app = FastAPI()
    app.include_router(auth.router())
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                       "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                       "jwks_uri": IDP + "/jwks"}
    auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
    return auth, app


def _oidc_sign_in(auth, app, claims):
    """Via the real callback; returns HTTP status and `/auth/me`."""
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
    cl = TestClient(app, raise_server_exceptions=False)
    start = cl.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    response = cl.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)
    me = cl.get("/auth/me")
    return response.status_code, (me.json() if me.status_code == 200 else None)


def _source(auth, uid):
    return auth.store._one("SELECT name_source AS q FROM users WHERE id=?", (uid,))["q"]


# (a) OIDC creates `manager`, then the real boss signs in via LDAP (PoC a1-01, variant A).
qa, qapp = _with_oidc()
st, me = _oidc_sign_in(qa, qapp, {"sub": "attacker-sub", "preferred_username": "boss"})
oc = qa.store.get_user_by_name("boss")
r.check("OIDC creates `boss` (preferred_username): origin oidc, no marker \"self-chosen\"",
        st == 303 and oc is not None and _source(qa, oc["id"]) == "oidc" and _flag(qa, oc["id"]) == 0,
        f"HTTP {st} {dict(oc) if oc else None}")
with Recording() as log:
    u = _sign_in(qa, "boss", {"id": "uuid-boss", "groups": ["cn=chefs"]}, pw="ldap-pw")
to = _audit(qa, "ldap_name_binding_closed")
r.check("PoC a1-01 (OIDC): the real boss does NOT land in the OIDC account — no identifier, no role",
        u is None and qa.store.get_federated_identifier("ldap", oc["id"]) is None
        and qa.user_roles(qa.store.get_user(oc["id"])) == [], str(u))
r.check("… rejection like situation 3: audit with reason name_aus_quelle, log line with the way out",
        [z["detail"] for z in to] == ["reason=name_from_other_source identifier=uuid-boss"]
        and any("uuid-boss" in z and f"federation_unbind('ldap', {oc['id']})" in z
                for z in log.lines("another source")), str(to))
st, me = _oidc_sign_in(qa, qapp, {"sub": "attacker-sub", "preferred_username": "boss"})
r.check("… and via OIDC the attacker still only gets into their own account, without a role",
        st == 303 and me is not None and me["id"] == oc["id"] and me["roles"] == [], str(me))

# The existing-account binding asks the same decision.
st, _ = _oidc_sign_in(qa, qapp, {"sub": "olli-sub", "preferred_username": "olli"})
bb = qa.federation_bind_existing("ldap", mapping={"olli": "uuid-olli"})
r.check("federation_bind_existing: an OIDC account is not bound via the name "
        "(name_from_other_source; in the audit still `reason=name_from_other_source`)",
        [(e["username"], e["reason"]) for e in bb["refused"]] == [("olli", "name_from_other_source")]
        and bb["bound"] == [], str(bb))

# The operator decides explicitly: then it binds.
qa.federation_unbind("ldap", oc["id"])
u = _sign_in(qa, "boss", {"id": "uuid-boss"}, pw="ldap-pw")
r.check("federation_unbind also opens for a name from another source",
        u is not None and u["id"] == oc["id"] and qa.store.get_federated_identifier("ldap", oc["id"]) == "uuid-boss")

# Renaming: the new name no longer comes from the source.
st, _ = _oidc_sign_in(qa, qapp, {"sub": "otto-sub", "preferred_username": "otto"})
ot = qa.store.get_user_by_name("otto")["id"]
qa.change_username(ot, "ottilie", by_operator=True)
u = _sign_in(qa, "ottilie", {"id": "uuid-ottilie"})
r.check("Renamed by the operator: origin deleted, the name stands for the operator and binds",
        _source(qa, ot) is None and _flag(qa, ot) == 0 and u is not None and u["id"] == ot)
st, _ = _oidc_sign_in(qa, qapp, {"sub": "uwe-sub", "preferred_username": "uwe"})
uw = qa.store.get_user_by_name("uwe")["id"]
qa.store.set_username(uw, "ulla", itself_chosen=True)
r.check("Self-renamed: origin deleted, marker \"self-chosen\" set",
        _source(qa, uw) is None and _flag(qa, uw) == 1)

# (b) SAML creates `manager`; the real boss from the directory is admin (PoC a1-01, variant B).
_ldap_to_it = dict(ldap_enabled=True, ldap_url="ldap://directory.example.com", ldap_allow_plaintext=True,
                  ldap_auto_create=True)
qs = _saml(ldap_group_role_map={"cn=admins": "__admin__"}, **_ldap_to_it)
qs.create_user("owner", password=PW, is_admin=True)
sa = qs._check_saml("nid-attacker", {"uid": ["boss"]})
u = _sign_in(qs, "boss", {"id": "uuid-boss", "groups": ["cn=admins"]}, pw="ldap-pw")
sa2 = qs._check_saml("nid-attacker", {"uid": ["boss"]})
r.check("PoC a1-01 (SAML): origin saml; the directory admin does not land in the SAML account, "
        "and the attacker is not an admin afterwards",
        _source(qs, sa["id"]) == "saml" and u is None and sa2 is not None and sa2["id"] == sa["id"]
        and not sa2["is_admin"] and qs.store.get_federated_identifier("ldap", sa["id"]) is None,
        f"{u} {sa2 and sa2['is_admin']}")

# (c) Opposite direction: LDAP has created `manager`, a SAML self-registrant chooses `uid=chefin`.
# Without the bolt this would not have been a privilege escalation but the takeover of the account itself.
gr = _saml(**_ldap_to_it)
real = _sign_in(gr, "boss", {"id": "uuid-boss"}, pw="ldap-pw")
given = gr._check_saml("nid-attacker", {"uid": ["boss"]})
r.check("Opposite direction: a SAML name does not bind the account created by LDAP (no takeover)",
        real is not None and _source(gr, real["id"]) == "ldap" and given is None
        and gr.store.get_federated_identifier("saml", real["id"]) is None, str(given))

# (d) The same source is excepted: LDAP without identifier creates (placeholder), later the
# directory supplies one — it replaces the placeholder. A marker "self-chosen" would break exactly this for
# every federated creation (the form recommended in the finding): the way the startup message recommends
# (setting `ldap_attr_id`) would then end in a rejection.
ps = _saml(**_ldap_to_it)
pit = _sign_in(ps, "pit", {})
r.check("LDAP without identifier creates: origin ldap, placeholder",
        pit is not None and _source(ps, pit["id"]) == "ldap"
        and ps.store.get_federated_identifier("ldap", pit["id"]) == f"{Store.WITHOUT_IDENTIFIER}{pit['id']}")
r.check("… another source (SAML) does not bind it via the name",
        ps._check_saml("nid-foreign", {"uid": ["pit"]}) is None)
u = _sign_in(ps, "pit", {"id": "uuid-pit"})
r.check("… the same source replaces its placeholder with the real identifier",
        u is not None and u["id"] == pit["id"] and ps.store.get_federated_identifier("ldap", pit["id"]) == "uuid-pit",
        str(ps.store.get_federated_identifier("ldap", pit["id"])))

# ══ The shared decision: name = unproven mail value ══════════════════════════════════════
# Sign-in and existing-account binding ask the same helper (`_ldap_name_proven`) — the existing-account binding
# is below (gina); here the sign-in: if the typed name is the unproven `mail` value of the
# entry, the local account of the same name is not assigned. Until 2026-09-27 the sign-in then
# created an account `ldap-…`; since the review round (p1-d) it rejects — the identifier `gerda` belongs
# to an account locally, and an identifier never checks the secrets of two accounts.
ge = _ldap()
gl = ge.create_user("gerda")
_n_ge = ge.store.user_count()
u = _sign_in(ge, "gerda", {"id": "u-gerda", "email": "gerda"})
r.check("Sign-in: name = unproven mail value → no access to the local account of the same name",
        u is None and ge.store.get_federated_identifier("ldap", gl) is None
        and ge.store.get_federated_user("ldap", "u-gerda") is None and ge.store.user_count() == _n_ge
        and bool(_audit(ge, "ldap_identifier_rejected")), str(u and u["username"]))

# ══ Existing-account binding: federation_bind_existing ════════════════════════════════════════════════════
m = _ldap()
ids = {n: m.create_user(n) for n in ("anna", "bert", "cara", "dora", "emil", "fritz", "gina", "ida",
                                      "jo", "kim", "lea")}
ids["hans"] = m.create_user("hans", password=PW)
ids["ina"] = m.create_user("ina", self_chosen_name=True)
m.create_service("service")
m.store.link_federated("ldap", "u-fritz", ids["fritz"], now())
m.store.link_federated("ldap", f"{Store.WITHOUT_IDENTIFIER}{ids['lea']}", ids["lea"], now())
m.store.set_disabled(ids["jo"], True, through_operator=True)
_alternate(m, ids["kim"])          # grace period over — the existing-account binding is the explicit way
vz = Directory({
    "anna": {"id": "u-anna", "name": "Anna A.", "email": "anna@example.com"},
    "cara": {},                                                   # entry without a stable identifier
    "dora": [{"id": "u-dora-1"}, {"id": "u-dora-2"}],               # two entries
    "emil": {"id": "u-fritz"},                                     # identifier belongs to fritz
    "gina": {"id": "u-gina", "email": "gina"},                      # name = unproven mail value
    "hans": {"id": "u-hans"}, "ina": {"id": "u-ina"}, "jo": {"id": "u-jo"},
    "kim": {"id": "u-kim"}, "lea": {"id": "u-lea"}, "ida": {"id": "u-ida"},
})
m.ldap = vz


def _names(report, part):
    return sorted(e["username"] for e in report[part])


def _bound(auth):
    return {z["user_id"]: z["identifier"] for z in auth.store._all("SELECT * FROM federated_identity")}


before = _bound(m)
tr = m.federation_bind_existing("ldap")
r.check("Dry run (default): nothing written", _bound(m) == before and tr["applied"] is False
        and tr["source"] == "ldap"
        and not _audit(m, "ldap_identifier_bound"))
r.check("… reports what would be bound (also after the grace period and the placeholders)",
        _names(tr, "bound") == ["anna", "ida", "kim", "lea"], str(_names(tr, "bound")))
anna = next(e for e in tr["bound"] if e["username"] == "anna")
r.check("… with display name and address here and in the directory side by side",
        anna["directory"] == {"name": "Anna A.", "email": "anna@example.com"}
        and anna["local"]["name"] == "anna" and anna["identifier"] == "u-anna", str(anna))
r.check("… conflict (identifier belongs to another account) with the owner",
        [(e["username"], e["bound_to"]) for e in tr["conflict"]] == [("emil", ids["fritz"])], str(tr["conflict"]))
r.check("… ambiguous, not in the directory, without identifier",
        _names(tr, "ambiguous") == ["dora"] and tr["ambiguous"][0]["matches"] == 2
        and _names(tr, "not_in_directory") == ["bert"] and _names(tr, "no_identifier") == ["cara"])
r.check("… rejected with reason: unproven mail value as name, self-chosen, disabled",
        sorted((e["username"], e["reason"]) for e in tr["refused"])
        == [("gina", "address_as_name"), ("ina", "self_chosen_name"), ("jo", "disabled")],
        str(tr["refused"]))
r.check("… account with local password only reported; service accounts and bound ones not asked at all",
        _names(tr, "local_password") == ["hans"] and "service" not in vz.asked and "fritz" not in vz.asked,
        str(vz.asked))
with Recording() as log:
    start_from = m.federation_bind_existing("ldap", apply=True)
now_bound = _bound(m)
r.check("apply=True: bound as announced, the placeholder is replaced",
        all(now_bound.get(ids[n]) == f"u-{n}" for n in ("anna", "ida", "kim", "lea"))
        and _names(start_from, "bound") == ["anna", "ida", "kim", "lea"], str(now_bound))
r.check("… nothing else: no binding for hans, ina, gina, emil, jo",
        all(ids[n] not in now_bound for n in ("hans", "ina", "gina", "emil", "jo"))
        and now_bound[ids["fritz"]] == "u-fritz")
r.check("… per binding audit `ldap_identifier_bound detail=migration`, one summary line in the log",
        sorted(z["username"] for z in _audit(m, "ldap_identifier_bound") if z["detail"] == "migration")
        == ["anna", "ida", "kim", "lea"] and len(log.lines("federation_bind_existing(ldap): 4 bound")) == 1,
        log.buffer.getvalue()[-400:])
u = _sign_in(m, "kim", {"id": "u-kim"})
r.check("… afterwards the bound account signs in (situation 1)", u is not None and u["id"] == ids["kim"])
r.check("Second run: the bound ones are no longer candidates",
        m.federation_bind_existing("ldap")["bound"] == [])

# An outage in the middle of the run: nothing written.
w = _ldap()
w.create_user("wim"), w.create_user("wolf")
w.ldap = Directory({"wim": {"id": "u-wim"}, "wolf": {"id": "u-wolf"}}, failure_at="wolf")
try:
    w.federation_bind_existing("ldap", apply=True)
    _abort = False
except DirectoryNotReachable:
    _abort = True
r.check("Directory outage: the run aborts before anything is bound",
        _abort and _bound(w) == {})

# Mapping (SAML from an export of the IdP).
z = _saml()
sara, tom, udo = z.create_user("sara"), z.create_user("tom"), z.create_user("udo")
zb = z.create_user("zeno", self_chosen_name=True)
z.store.link_federated("saml", "nid-udo", udo, now())
empty = z.create_user("leer")
zr = z.federation_bind_existing("saml", mapping={"sara": "nid-sara", "tom": "nid-udo", "nobody": "nid-x",
                                                 "zeno": "nid-zeno", "leer": ""}, apply=True)
r.check("SAML with mapping: binds, refuses the identifier of another account, reports the unknown",
        _bound(z).get(sara) == "nid-sara" and tom not in _bound(z) and empty not in _bound(z)
        and [e["username"] for e in zr["conflict"]] == ["tom"] and _names(zr, "no_identifier") == ["leer"]
        and sorted((e["username"], e["reason"]) for e in zr["refused"])
        == [("nobody", "no_account"), ("zeno", "self_chosen_name")], str(zr))
u = z._check_saml("nid-sara", {"uid": ["sara"]})
r.check("… afterwards sara signs in via the NameID", u is not None and u["id"] == sara)
zd = _saml()
zd.create_user("double1"), zd.create_user("double2")
zdr = zd.federation_bind_existing("saml", mapping={"double1": "nid-d", "double2": "nid-d"}, apply=True)
r.check("Mapping with duplicate (two accounts, one identifier): none bound",
        _bound(zd) == {} and sorted(e["username"] for e in zdr["conflict"]) == ["double1", "double2"])
try:
    zd.federation_bind_existing("saml")
    _saml_without = False
except ValueError:
    _saml_without = True
foreign = _ldap()
foreign.ldap = type("OnlySignin", (), {"authenticate": lambda self, u, p: None})()
try:
    foreign.federation_bind_existing("ldap")
    _without_search = False
except ConfigError:
    _without_search = True
r.check("SAML without mapping → ValueError; a client without entry_search → ConfigError",
        _saml_without and _without_search)

# Atomic against a sign-in that bound between the check and the write.
st = _ldap()
k1, k2 = st.create_user("k1"), st.create_user("k2")
st.store.link_federated("ldap", "u-k", k1, now())
r.check("Store.nachbinden does not take an identifier away from any account (no INSERT OR REPLACE)",
        st.store.rebind("ldap", "u-k", k2, now()) is False and _bound(st) == {k1: "u-k"})
st.store.link_federated("ldap", "u-k2", k2, now())
r.check("… and binds no account a second time",
        st.store.rebind("ldap", "u-k2b", k2, now()) is False
        and st.store.get_federated_user("ldap", "u-k2b") is None)

# ── The real search path against ldap3 (MOCK_SYNC) ────────────────────────────────────────────────
# Needs the extra [ldap]. Without it the rest of the suite runs (the job `minimal`), this part
# says so visibly — like the F-21 part in tests/test_saml.py.
try:
    import ldap3  # noqa: E402
except ImportError:
    ldap3 = None
if ldap3 is not None:

    GUID = bytes(range(16))
    _srv = ldap3.Server("mock-directory", get_info=ldap3.NONE)
    _fill = ldap3.Connection(_srv, client_strategy=ldap3.MOCK_SYNC)
    _fill.strategy.add_entry("cn=svc,dc=example,dc=com", {"objectClass": "person", "userPassword": "svc-pw"})
    _fill.strategy.add_entry("uid=alice,ou=people,dc=example,dc=com",
                              {"objectClass": "person", "uid": "alice", "cn": "Alice A.",
                               "mail": "alice@example.com", "objectGUID": GUID, "userPassword": "pw-alice"})
    _fill.strategy.add_entry("uid=carl,ou=people,dc=example,dc=com",
                              {"objectClass": "person", "uid": "carl", "entryUUID": "e-carl"})
    _fill.strategy.add_entry("uid=bob,ou=people,dc=example,dc=com",
                              {"objectClass": "person", "uid": "bob", "entryUUID": "e-bob-1"})
    _fill.strategy.add_entry("uid=bob,ou=extern,ou=people,dc=example,dc=com",
                              {"objectClass": "person", "uid": "bob", "entryUUID": "e-bob-2"})
    _Real = ldap3.Connection


    class _MockConnection(_Real):
        """Every connection of the client goes to the prepared in-memory directory."""

        def __init__(self, server, *args, **kw):
            kw["client_strategy"] = ldap3.MOCK_SYNC
            auto = kw.pop("auto_bind", None)       # MOCK_SYNC does not bind by itself with it
            super().__init__(_srv, *args, **kw)
            if auto not in (None, False, ldap3.AUTO_BIND_NONE):
                self.bind()


    ldap3.Connection = _MockConnection
    try:
        such = LDAPClient(TinySesamConfig(
            db_path=":memory:", ldap_enabled=True, ldap_url="ldap://directory.example.com",
            ldap_allow_plaintext=True, ldap_bind_dn="cn=svc,dc=example,dc=com", ldap_bind_password="svc-pw",
            ldap_user_base="ou=people,dc=example,dc=com", ldap_user_filter="(uid={username})"))
        t_alice, t_carl, t_bob, t_empty = (such.entry_search(x) for x in ("alice", "carl", "bob", "nobody"))
        r.check("ldap3: objectGUID (bytes) arrives as hex, plus name and address",
                len(t_alice) == 1 and t_alice[0]["id"] == GUID.hex() and t_alice[0]["name"] == "Alice A."
                and t_alice[0]["email"] == "alice@example.com", str(t_alice))
        r.check("ldap3: entryUUID", [t["id"] for t in t_carl] == ["e-carl"], str(t_carl))
        r.check("ldap3: two entries under the name → both (exactly one is required), none → empty",
                sorted(t["id"] for t in t_bob) == ["e-bob-1", "e-bob-2"] and t_empty == [], str(t_bob))
        tmpl = LDAPClient(TinySesamConfig(
            db_path=":memory:", ldap_enabled=True, ldap_url="ldap://directory.example.com",
            ldap_allow_plaintext=True, ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com"))
        r.check("ldap3 direct-bind template: BASE search on the built DN (anonymous), no DN → empty",
                [t["id"] for t in tmpl.entry_search("carl")] == ["e-carl"] and tmpl.entry_search("nobody") == [])
        wrong = LDAPClient(TinySesamConfig(
            db_path=":memory:", ldap_enabled=True, ldap_url="ldap://directory.example.com",
            ldap_allow_plaintext=True, ldap_bind_dn="cn=svc,dc=example,dc=com", ldap_bind_password="wrong",
            ldap_user_base="ou=people,dc=example,dc=com"))
        try:
            wrong.entry_search("alice")
            _service = False
        except DirectoryNotReachable:
            _service = True
        r.check("ldap3: a rejected service account is an outage, not \"not in the directory\"", _service)
        e2e = _ldap(ldap_url="ldap://directory.example.com", ldap_bind_dn="cn=svc,dc=example,dc=com",
                    ldap_bind_password="svc-pw", ldap_user_base="ou=people,dc=example,dc=com")
        ea, eb = e2e.create_user("alice"), e2e.create_user("bob")
        eb_ber = e2e.federation_bind_existing("ldap", apply=True)
        r.check("ldap3 end to end: alice bound to her GUID, bob ambiguous",
                _bound(e2e) == {ea: GUID.hex()} and _names(eb_ber, "ambiguous") == ["bob"], str(eb_ber))
        # The sign-in path reads the identifier the same way (`authenticate` → `_stable_identifier`): a GUID
        # that happens to be valid UTF-8 was decoded by ldap3 without a schema into text with control characters —
        # the form check rejected it, the person never got in via LDAP.
        login = _ldap(ldap_url="ldap://directory.example.com", ldap_bind_dn="cn=svc,dc=example,dc=com",
                      ldap_bind_password="svc-pw", ldap_user_base="ou=people,dc=example,dc=com")
        ul = login._check_ldap("alice", "pw-alice")
        r.check("ldap3 sign-in: the same GUID as hex, the new account is bound to it",
                ul is not None and login.store.get_federated_identifier("ldap", ul["id"]) == GUID.hex(),
                str(ul and login.store.get_federated_identifier("ldap", ul["id"])))
    finally:
        ldap3.Connection = _Real

else:                                                    # pragma: no cover
    print("  – real search path against ldap3 not run (extra [ldap] missing); the rest of the suite runs")

# ══ Startup message ═══════════════════════════════════════════════════════════════════════════════
path = _db()
sm = _ldap(path)
a1, a2 = sm.create_user("a1"), sm.create_user("a2", password=PW)
sm.create_service("svc1")
b1, p1 = sm.create_user("b1"), sm.create_user("p1")
sm.store.link_federated("ldap", "u-b1", b1, now())
sm.store.link_federated("ldap", f"{Store.WITHOUT_IDENTIFIER}{p1}", p1, now())
sm.store.db.close()
with Recording() as log:
    sm = _ldap(path)
line = log.lines("without a binding to an identifier")
r.check("Startup message: 3 accounts without identifier (service account and bound one do not count, the "
        "placeholder does), of which 2 without local password, with the way out",
        len(line) == 1 and "LDAP: 3 account(s)" in line[0] and "of which 2 without a local password" in line[0]
        and "auth.federation_bind_existing('ldap')" in line[0], str(line))
sm.ldap = Directory({"a1": {"id": "u-a1"}, "p1": {"id": "u-p1"}})
sm.federation_bind_existing("ldap", apply=True)
sm.store._exec("DELETE FROM users WHERE id=?", (a2,))
sm.store.db.close()
with Recording() as log:
    sm = _ldap(path)
r.check("… after the existing-account binding: no line any more", not log.lines("without a binding to an identifier"),
        str(log.lines("without a binding")))
sm.create_user("late")
_alternate(sm, days=31)
sm.store.db.close()
with Recording() as log:
    sm = _ldap(path)
r.check("… after the grace period it is silent (the door is closed, every rejection reports itself)",
        not log.lines("without a binding to an identifier"))
path = _db()
ss = _saml(path)
ss.create_user("s1")
ss.store.db.close()
with Recording() as log:
    _saml(path)
r.check("SAML startup message names the mapping",
        any("SAML: 1 account(s)" in z and "mapping=" in z for z in log.lines("without a binding")),
        str(log.lines("without a binding")))

# ══ Existing accounts: file at schema 11 without table and column, marker from the audit log ════════════
# Built from SCHEMA without the two novelties (a `DROP COLUMN` fails on the comments in
# the table definition) — like a state from before this commit, stamp 11.
_old, _n1 = re.subn(r"(mail_audit_from\s+INTEGER),\n.*?name_self_chosen INTEGER NOT NULL DEFAULT 0\n",
                    r"\1\n", SCHEMA, flags=re.S)
_old, _n2 = re.subn(r"CREATE TABLE IF NOT EXISTS name_binding \(.*?\n\);\n", "", _old, flags=re.S)
path = _db()
os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
raw = sqlite3.connect(path)
raw.executescript(_old)
now_ = now()
for name in ("sig", "ren", "alt", "op"):
    raw.execute("INSERT INTO users(username, created_at) VALUES (?, ?)", (name, now_ - 10 * TAG))
for event, name, prior in (("signup", "sig", 9), ("username_changed", "ren", 5), ("signup", "alt", 400),
                         ("user_create", "op", 9), ("login", "op", 8)):
    raw.execute("INSERT INTO audit(ts, event, username) VALUES (?,?,?)", (now_ - prior * TAG, event, name))
raw.execute("PRAGMA user_version = 11")
raw.commit()
_before_sp = {z[1] for z in raw.execute("PRAGMA table_info(users)")}
_before_tab = {z[0] for z in raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
raw.close()
r.check("Precondition: file at stamp 11 without `name_binding` and without `users.name_self_chosen`",
        _n1 == 1 and _n2 == 1 and "name_self_chosen" not in _before_sp
        and "name_binding" not in _before_tab and "failure_series" in _before_tab, f"{_n1}/{_n2}")
new = _ldap(path)
tab = {z["name"] for z in new.store._all("SELECT name FROM sqlite_master WHERE type='table'")}
fl = {z["username"]: z["name_self_chosen"] for z in new.store._all("SELECT * FROM users")}
r.check("Schema 11 without the novelties: table and column are added, the stamp moves to the "
        "current one (since 0.22.0: 12)",
        "name_binding" in tab and len(fl) == 4
        and int(new.store.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION >= 11)
r.check("Existing accounts: registered and self-renamed ones carry the marker, an older namesake and "
        "an operator-created account do not",
        fl == {"sig": 1, "ren": 1, "alt": 0, "op": 0}, str(fl))
u = _sign_in(new, "sig", {"id": "u-sig"})
r.check("… and the back-filled account does not bind via the name", u is None)
new.store._exec("INSERT INTO audit(ts, event, username) VALUES (?,?,?)", (now(), "username_changed", "op"))
new.store.db.close()
again = _ldap(path)
r.check("Second start: idempotent, the back-fill does not run again",
        again.store._one("SELECT name_self_chosen AS f FROM users WHERE username='op'")["f"] == 0
        and again.store.get_setting(Store.NAME_ITSELF_BACKFILLED) is not None)
lo = again.create_user("loesch")
again.federation_unbind("ldap", lo)
again.delete_user(lo)
r.check("Account deleted: its opened name binding goes with it",
        again.store._one("SELECT COUNT(*) AS n FROM name_binding")["n"] == 0)

# ══ Existing accounts: origin of the name back-filled (attack round 2026-09-26) ═══════════════════════
# A file from the state before: stamp 11, `name_self_chosen` already back-filled, but without
# `users.name_source`. Back-filling happens only where the origin is proven: OIDC (the callback creates
# every linked account itself) and an LDAP/SAML binding from the same second as the creation.
_old_q, _nq = re.subn(r"\n\s*-- From which federated source does the name originate.*?name_source\s+TEXT,", "",
                      SCHEMA, flags=re.S)
path = _db()
os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
raw = sqlite3.connect(path)
raw.executescript(_old_q)
t0 = now() - 20 * TAG
_bq = {}
for name, itself, service in (("oi", 0, 0), ("ld", 0, 0), ("ph", 0, 0), ("nb", 0, 0), ("op", 0, 0),
                             ("ren", 1, 0), ("svc", 0, 1)):
    _bq[name] = raw.execute("INSERT INTO users(username, created_at, name_self_chosen, is_service) "
                            "VALUES (?,?,?,?)", (name, t0, itself, service)).lastrowid
for name in ("oi", "ren", "svc"):
    raw.execute("INSERT INTO oidc_identity(issuer, subject, user_id) VALUES (?,?,?)",
                (IDP, f"sub-{name}", _bq[name]))
for source, identifier, name, offset in (("ldap", "u-ld", "ld", 0),
                                       ("saml", f"{Store.WITHOUT_IDENTIFIER}{_bq['ph']}", "ph", 1),
                                       ("ldap", "u-nb", "nb", 5 * TAG)):
    raw.execute("INSERT INTO federated_identity(source, identifier, user_id, bound_at) VALUES (?,?,?,?)",
                (source, identifier, _bq[name], t0 + offset))
raw.execute("INSERT INTO setting(key, value) VALUES (?, ?)", (Store.NAME_ITSELF_BACKFILLED, str(t0)))
raw.execute("PRAGMA user_version = 11")
raw.commit()
_sp_q = {z[1] for z in raw.execute("PRAGMA table_info(users)")}
raw.close()
r.check("Precondition: file at stamp 11 with `name_self_chosen`, without `users.name_source`",
        _nq == 1 and "name_source" not in _sp_q and "name_self_chosen" in _sp_q, str(_nq))
bq = _ldap(path)
_hq = {z["username"]: z["name_source"] for z in bq.store._all("SELECT username, name_source FROM users")}
r.check("Back-fill: OIDC account → oidc, binding from creation → its source (also the placeholder); "
        "a later re-binding, the operator account, a self-chosen name and a service account not",
        _hq == {"oi": "oidc", "ld": "ldap", "ph": "saml", "nb": None, "op": None, "ren": None, "svc": None},
        str(_hq))
u = _sign_in(bq, "oi", {"id": "u-oi"})
r.check("… the back-filled OIDC account does not bind via the name over LDAP",
        u is None and bq.store.get_federated_identifier("ldap", _bq["oi"]) is None)
u = _sign_in(bq, "nb", {"id": "u-nb"})
r.check("… a bound account keeps signing in (situation 1)", u is not None and u["id"] == _bq["nb"])
bq.store._exec("UPDATE users SET name_source = NULL WHERE username = 'ld'")
bq.store.db.close()
bq2 = _ldap(path)
r.check("Second start: the back-fill does not run again (marker set)",
        bq2.store._one("SELECT name_source AS q FROM users WHERE username='ld'")["q"] is None
        and bq2.store.get_setting(Store.NAME_SOURCE_BACKFILLED) is not None)

# ══ Configuration check ═════════════════════════════════════════════════════════════════════
_, warn = _kp.check_config(TinySesamConfig(db_path=":memory:", ldap_enabled=True, ldap_url="ldaps://v.example.com",
                                     federation_name_binding_days=-1))
_, warn_from = _kp.check_config(TinySesamConfig(db_path=":memory:", federation_name_binding_days=-1))
error, _ = _kp.check_config(TinySesamConfig(db_path=":memory:", federation_name_binding_days=-2))
r.check("Configuration check: -1 with LDAP warns, without a federated source it does not, -2 is an error",
        any("federation_name_binding_days=-1" in w for w in warn)
        and not any("federation_name_binding_days" in w for w in warn_from)
        and any("federation_name_binding_days=-2" in f for f in error), str(warn))

sys.exit(r.done())

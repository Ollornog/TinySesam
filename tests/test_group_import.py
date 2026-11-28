"""T-102 (ADR-18 stage 1): IdP groups become roles at sign-in.

Through the real sign-in paths (OIDC callback and re-check with a stubbed provider, LDAP with a stub directory) and the
import itself for the cases every source shares:

 1. A group arrives: a role of the same raw name on the account, a catalog row "from IdP" (`source`, `last_seen_at`).
 2. The group goes: its role goes — at the next sign-in and at the OIDC re-check; a role assigned by hand stays, and so
    does one the account held by hand before the provider delivered it.
 3. A missing OIDC claim withdraws nothing (noted); an empty one withdraws. LDAP: an absent attribute is "no groups".
 4. Collisions (attack: an IdP group takes over a local role): a role of the configuration, a map target, `admin`, a
    local catalog role, the same name in another case, a role typed in by hand on another account, a role level entry
    — each skipped, logged, noted, and never granted.
 5. Limits: more than 100 groups without a filter import nothing and withdraw nothing; a filter narrows; a prefix
    filter is no substring and no case-folding (name games).
 6. Two sources deliver the same role: one withdrawing it keeps it while the other still delivers it.
 7. The permission follows: an administrator assigns a permission to the imported role, the account has it, the group
    goes, the permission is gone.
 8. Configuration findings (English and German) and the start hint for stale imported roles.
"""
from __future__ import annotations

import io
import logging
import os
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, security  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.oidc import DEFAULT_CLIENT, OIDCClient  # noqa: E402

IDP = "https://idp.example.invalid"
PW = "a long probe password 4711"


def ok(name):
    print(f"  ✓ {name}")


class _Claims(dict):
    def validate(self, *a, **k):
        pass


class SecLog:
    """Collect the security log while the block runs."""

    def __enter__(self):
        self.buf = io.StringIO()
        self.h = logging.StreamHandler(self.buf)
        security.seclog.addHandler(self.h)
        return self

    def __exit__(self, *a):
        security.seclog.removeHandler(self.h)

    @property
    def text(self):
        return self.buf.getvalue()


def oidc_app(**cfg):
    """OIDC without network: discovery prefilled, the token exchange returns `state["claims"]` and a refresh token."""
    values = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, oidc_enabled=True,
                  oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret", base_url="http://testserver",
                  csrf_enabled=False, oidc_group_import=True)
    values.update(cfg)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                       "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
    state = {"claims": {}}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**state["claims"], "nonce": nonce}), {"access_token": "at", "refresh_token": "rt"})
    auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
    return auth, app, state


def sign_in(app, auth, state, groups=None, sub="kim-1", name="kim"):
    state["claims"] = {"sub": sub, "preferred_username": name, "email": f"{name}@example.com", "email_verified": True}
    if groups is not None:
        state["claims"]["groups"] = groups
    c = TestClient(app)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    got = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    r = c.get(f"/auth/oidc/callback?code=x&state={got}", follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    return c


def roles(auth, name="kim"):
    return sorted(auth.user_roles(auth.store.get_user_by_name(name)))


def catalog(auth):
    return {r["name"]: r for r in auth.store.catalog_roles()}


# 1 + 2 ──────────────────────────────────────────────────────────────────────────────────────────────────
auth, app, state = oidc_app(available_roles=["reviewer"])
sign_in(app, auth, state, ["team-docs", "team-ops"])
assert roles(auth) == ["team-docs", "team-ops"], roles(auth)
cat = catalog(auth)
assert cat["team-docs"]["source"] == "oidc" and cat["team-docs"]["created_by"] == "idp:oidc", cat
assert cat["team-docs"]["last_seen_at"] and auth.role_catalog()[0]["source"] == "oidc"
kim = auth.store.get_user_by_name("kim")["id"]
assert auth.store.idp_role_sources(kim) == {"team-docs": ["oidc"], "team-ops": ["oidc"]}
ok("1. the groups arrive as roles of the same name, catalogued as from the provider (source, last seen)")

auth.set_roles(kim, auth.user_roles(auth.get_user(kim)) + ["reviewer"])
sign_in(app, auth, state, ["team-docs"])
assert roles(auth) == ["reviewer", "team-docs"], roles(auth)
assert "team-ops" in catalog(auth), "the catalog row stays (the role may come back; an unused one can be deleted)"
ok("2. a group the provider no longer delivers takes its role at the next sign-in; a role set by hand stays")

# The account held an IdP role by hand before the provider delivered it to this account: the withdrawal leaves it.
sign_in(app, auth, state, ["team-x"], sub="ida-1", name="ida")         # another account brings `team-x` in
auth.set_roles(kim, auth.user_roles(auth.get_user(kim)) + ["team-x"])  # an administrator gives it to kim by hand
sign_in(app, auth, state, ["team-docs", "team-x"])
sign_in(app, auth, state, ["team-docs"])
assert "team-x" in roles(auth), "a role held by hand before the provider delivered it was withdrawn with the group"
sign_in(app, auth, state, ["team-docs", "team-x"])
assert auth.store.idp_role_deliveries()[int(kim)]["team-x"] == [
    {"source": "oidc", "seen_at": auth.store.idp_role_deliveries()[int(kim)]["team-x"][0]["seen_at"],
     "held_before": True}], "the panel would not say the role was given by hand first"
sign_in(app, auth, state, ["team-docs"])
ok("2. a role the account held by hand before the provider delivered it stays when the group goes")

auth.set_roles(kim, auth.user_roles(auth.get_user(kim)) + ["shared"])
sign_in(app, auth, state, ["team-docs", "shared"])
skipped = auth.store.idp_group_notes()["skipped"]
assert skipped.get("shared", {}).get("reason") == "accounts", skipped
assert "shared" in roles(auth), "a hand-typed role was touched"
ok("2. a role the account holds by hand (no catalog row) is local: the provider's group of that name is skipped")

# The re-check (`_oidc_swap`) withdraws too — OIDC's way to take a role away before the next sign-in.
auth2, app2, state2 = oidc_app(oidc_session_refresh_minutes=5)
c2 = sign_in(app2, auth2, state2, ["team-docs", "team-ops"])
answers = []
auth2.oidc_clients[DEFAULT_CLIENT].refresh = lambda rt, sub: answers.pop(0)


def recheck(answer):
    then = int(time.time()) - 600
    auth2.store._exec("UPDATE oidc_session SET checked_at=?", (then,))
    answers.append(answer)
    c2.get("/auth/me")
    auth2._oidc_outcome.wait()


recheck(("ok", {"sub": "kim-1", "groups": ["team-docs"]}, {"refresh_token": "rt2"}))
assert roles(auth2) == ["team-docs"], roles(auth2)
with SecLog() as log:
    recheck(("ok", {"sub": "kim-1"}, {"refresh_token": "rt3"}))
assert roles(auth2) == ["team-docs"] and "carried no group claim" in log.text, (roles(auth2), log.text)
assert "oidc" in auth2.store.idp_group_notes()["missing"]
recheck(("ok", {"sub": "kim-1", "groups": []}, {"refresh_token": "rt4"}))
assert roles(auth2) == [] and "oidc" not in auth2.store.idp_group_notes()["missing"], roles(auth2)
ok("2/3. the OIDC re-check withdraws; a missing claim there keeps (noted), an empty one withdraws (note cleared)")

# 3 ──────────────────────────────────────────────────────────────────────────────────────────────────
auth3, app3, state3 = oidc_app()
sign_in(app3, auth3, state3, ["team-docs"])
with SecLog() as log:
    sign_in(app3, auth3, state3, None)
assert roles(auth3) == ["team-docs"] and "carried no group claim" in log.text
assert auth3.store.idp_group_notes()["missing"].get("oidc")
sign_in(app3, auth3, state3, [])
assert roles(auth3) == [] and not auth3.store.idp_group_notes()["missing"]
ok("3. a sign-in without the claim withdraws nothing (logged, hinted); an empty claim withdraws")

# 4 ──────────────────────────────────────────────────────────────────────────────────────────────────
auth4, app4, state4 = oidc_app(
    available_roles=["editor"], oidc_group_role_map={"staff": "mapped-role"},
    role_levels=[{"name": "coll", "label": "Collections",
                  "levels": [{"name": "read", "role": "coll:{1}-read"}, {"name": "write", "role": "coll:{1}"}]}])
auth4.create_role("finance")                                  # a local catalog role
other = auth4.create_user("olga", password=PW)
auth4.set_roles(other, ["payroll"])                           # typed in by hand, no catalog row
evil = ["editor", "Editor", "mapped-role", "admin", "__admin__", "finance", "FINANCE", "payroll", "coll:a-read-read",
        "bad,name", "x" * 65, "zero​width", "team-docs"]
with SecLog() as log:
    sign_in(app4, auth4, state4, evil)
assert roles(auth4) == ["team-docs"], roles(auth4)
notes = auth4.store.idp_group_notes()["skipped"]
want = {"editor": "config", "Editor": "config", "mapped-role": "config", "admin": "config", "__admin__": "config",
        "finance": "catalog", "FINANCE": "catalog", "payroll": "accounts", "coll:a-read-read": "ladder",
        "bad,name": "invalid", "x" * 65: "invalid", "zero​width": "invalid"}
assert {k: v["reason"] for k, v in notes.items()} == want, notes
assert catalog(auth4)["finance"]["source"] is None, "the local catalog role was turned into an IdP role"
assert auth4.store.get_user_by_name("kim")["is_admin"] == 0, "the group admin made an administrator"
assert all(f"'{k}' skipped" in log.text or repr(k) in log.text for k in ("editor", "finance", "payroll")), log.text
ok("4. collisions are skipped and noted: configuration, map target, admin, local catalog, other case, hand-typed role, "
   "role level entry, invalid names")

# The provider's case variant of an IdP role it delivered before: the existing spelling wins, the variant is skipped.
sign_in(app4, auth4, state4, ["Team-Docs"])
assert roles(auth4) == [] and auth4.store.idp_group_notes()["skipped"]["Team-Docs"]["reason"] == "case"
sign_in(app4, auth4, state4, ["team-docs"])
assert roles(auth4) == ["team-docs"]
ok("4. a case variant of an imported role is skipped (the known spelling stays the role)")

# A configuration that names an imported role later: the configuration owns it, the import withdraws its grant.
auth4.cfg.available_roles = ["editor", "team-docs"]
sign_in(app4, auth4, state4, ["team-docs"])
assert roles(auth4) == [] and auth4.store.idp_group_notes()["skipped"]["team-docs"]["reason"] == "config"
auth4.cfg.available_roles = ["editor"]
sign_in(app4, auth4, state4, ["team-docs"])
assert roles(auth4) == ["team-docs"] and "team-docs" not in auth4.store.idp_group_notes()["skipped"]
# A hint nothing resolves (the provider stopped sending the name) fades after 30 days.
auth4.store._exec("UPDATE setting SET value=? WHERE key='idp_group_notes'", (
    __import__("json").dumps({"skipped": {k: dict(v, at=1) for k, v in auth4.store.idp_group_notes()["skipped"].items()},
                              "missing": {}, "over_limit": {}}),))
sign_in(app4, auth4, state4, ["team-docs"])
assert auth4.store.idp_group_notes()["skipped"] == {}, auth4.store.idp_group_notes()
ok("4. once the configuration names the role, the provider no longer grants it; resolved, the hint goes; an "
   "unresolved one fades after 30 days")

# 5 ──────────────────────────────────────────────────────────────────────────────────────────────────
auth5, app5, state5 = oidc_app()
sign_in(app5, auth5, state5, ["team-docs"])
many = [f"g{i:03d}" for i in range(101)]
with SecLog() as log:
    sign_in(app5, auth5, state5, many)
assert roles(auth5) == ["team-docs"], "over the limit: something was withdrawn or granted"
assert "more than 100 without a filter" in log.text and auth5.store.idp_group_notes()["over_limit"]["oidc"]["count"] == 101
assert not any(n.startswith("g0") for n in catalog(auth5))
sign_in(app5, auth5, state5, many[:100])
assert len(roles(auth5)) == 100 and not auth5.store.idp_group_notes()["over_limit"]
ok("5. more than 100 groups without a filter: nothing imported, nothing withdrawn, warned and hinted; 100 pass")

# The catalog's own limit holds for imported rows too: past it a new group is skipped ("full"), a known one still counts.
uid5 = auth5.store.get_user_by_name("kim")["id"]
room = len(auth5.store.catalog_roles()) + 1
out = auth5.store.import_idp_roles(uid5, "oidc", ["g000", "new-1", "new-2"], room)
assert out["accepted"] == ["g000", "new-1"] and out["skipped"] == {"new-2": "full"}, out
ok("5. the catalog limit holds for imported roles: past it a new group is skipped as full")

auth6, app6, state6 = oidc_app(oidc_group_import_filter=["team-*", "staff"])
sign_in(app6, auth6, state6, many + ["team-docs", "team-", "team", "xteam-a", "TEAM-ops", "staffx", "staff", "Staff"])
assert roles(auth6) == ["staff", "team-docs"], roles(auth6)
ok("5. a filter narrows (also past 100 raw groups); a prefix is no substring and no case-folding: team-, team, "
   "xteam-a, TEAM-ops, staffx, Staff stay out")

# 6 ──────────────────────────────────────────────────────────────────────────────────────────────────
auth7, app7, state7 = oidc_app(saml_group_import=True, ldap_group_import=True)
sign_in(app7, auth7, state7, ["staff"])
uid7 = auth7.store.get_user_by_name("kim")["id"]
auth7._import_idp_groups(uid7, "ldap", ["cn=staff,ou=groups,dc=example,dc=com", "CN=ops,OU=x", "cn=a\\,b,ou=g"])
assert roles(auth7) == ["ops", "staff"], roles(auth7)
assert auth7.store.idp_role_sources(uid7) == {"ops": ["ldap"], "staff": ["ldap", "oidc"]}
# T-135: the panel's account page reads the deliveries per account — source, last delivery, held by hand before.
dl = auth7.store.idp_role_deliveries()[int(uid7)]
assert {r: [d["source"] for d in v] for r, v in dl.items()} == {"ops": ["ldap"], "staff": ["ldap", "oidc"]}, dl
assert all(isinstance(d["seen_at"], int) and d["held_before"] is False for v in dl.values() for d in v), dl
assert auth7.store.idp_group_notes()["skipped"]["a\\,b"]["reason"] == "invalid"
sign_in(app7, auth7, state7, [])
assert roles(auth7) == ["ops", "staff"], "OIDC withdrew a role LDAP still delivers"
auth7._import_idp_groups(uid7, "ldap", [])
assert roles(auth7) == [], roles(auth7)
ok("6. LDAP: the DN's first value is the name (an escaped comma is refused); a role two sources deliver goes only "
   "when both stopped")

# A role removed by hand returns at the next sign-in: what the provider delivers is the truth for its roles.
sign_in(app7, auth7, state7, ["staff"])
auth7.set_roles(uid7, [])
sign_in(app7, auth7, state7, ["staff"])
assert roles(auth7) == ["staff"]
ok("6. a delivered role removed by hand comes back at the next sign-in (remove the group at the provider instead)")

# LDAP through its real sign-in path, with a stub directory: an absent attribute (no groups) withdraws.


class FakeLDAP:
    def __init__(self):
        self.groups = ["cn=team-docs,ou=g,dc=example,dc=com"]

    def authenticate(self, username, password):
        if password != PW:
            return None
        return {"username": username, "email": None, "name": username, "groups": list(self.groups), "id": "u-1"}


ldap_auth = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "l.db"), cookie_secure=False,
                                      csrf_enabled=False, passkey_enabled=False, ldap_enabled=True,
                                      ldap_url="ldap://dummy", ldap_allow_plaintext=True, ldap_group_import=True))
ldap_auth.ldap = FakeLDAP()
lapp = FastAPI()
lapp.include_router(ldap_auth.router())
lc = TestClient(lapp)
assert lc.post("/auth/login", data={"username": "lena", "password": PW}, follow_redirects=False).status_code == 303
assert roles(ldap_auth, "lena") == ["team-docs"] and catalog(ldap_auth)["team-docs"]["source"] == "ldap"
ldap_auth.ldap.groups = []
assert lc.post("/auth/login", data={"username": "lena", "password": PW}, follow_redirects=False).status_code == 303
assert roles(ldap_auth, "lena") == [], "LDAP: an entry without the group attribute kept the imported role"
ok("6. LDAP sign-in: the group arrives; an entry without the attribute (a directory stores no empty one) withdraws")

# 7 ──────────────────────────────────────────────────────────────────────────────────────────────────
auth8, app8, state8 = oidc_app(apps={"docs": {"name": "Docs", "permissions": [{"name": "docs.read"}]}})
sign_in(app8, auth8, state8, ["team-docs"])
assert not auth8.has_permission(auth8.store.get_user_by_name("kim"), "docs.read", app="docs")
assert auth8.grant_permission("team-docs", "docs.read", app="docs")
assert auth8.has_permission(auth8.store.get_user_by_name("kim"), "docs.read", app="docs")
sign_in(app8, auth8, state8, ["other"])
assert not auth8.has_permission(auth8.store.get_user_by_name("kim"), "docs.read", app="docs")
assert auth8.delete_user(auth8.store.get_user_by_name("kim")["id"]) is not False
assert auth8.store._one("SELECT COUNT(*) AS n FROM idp_role_membership")["n"] == 0, "membership outlived the account"
ok("7. a permission assigned to the imported role follows the group; deleting the account takes its rows along")

# The audit names what the provider granted and withdrew.
events = [r["detail"] for r in auth8.store._all("SELECT detail FROM audit WHERE event='idp_roles_synced' ORDER BY id")]
assert events and "granted=team-docs" in events[0] and "withdrawn=team-docs" in events[-1], events
ok("7. the audit log records each grant and withdrawal by the provider")

# 8 ──────────────────────────────────────────────────────────────────────────────────────────────────


def findings(**kw):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), **kw))
    except ConfigError as e:
        return str(e)
    return ""


text = findings(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="x", oidc_client_secret="y", base_url="http://t",
                oidc_group_import=True, oidc_group_import_filter=["*", "a*b", " team-*", ""],
                idp_group_labels={"g": "bad\nlabel"})
for part in ('\'*\' — "*" alone imports everything', "'a*b' — a \"*\" only at the end", "' team-*' — a non-empty",
             "'' — a non-empty", "idp_group_labels: 'g'"):
    assert part in text, (part, text)
assert "oidc_group_import='yes' — True or False" in findings(oidc_group_import="yes")
de = findings(lang="de", saml_group_import_filter="team-*")
assert "saml_group_import_filter" in de and "eine Liste von Gruppennamen" in de, de
ok("8. configuration errors: '*' alone, a '*' inside, spaces, empty, a label with a control character, a non-bool "
   "switch, a filter that is no list (German too)")

logbuf = io.StringIO()
lh = logging.StreamHandler(logbuf)
logging.getLogger("tinysesam").addHandler(lh)
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "w.db"), available_roles=["staff"],
                              ldap_group_import=True, saml_group_import_filter=["team-*"]))
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "w2.db"), oidc_enabled=True, oidc_issuer=IDP,
                              oidc_client_id="x", oidc_client_secret="y", oidc_group_import=True,
                              base_url="http://testserver",
                              oidc_group_import_filter=["staff"], available_roles=["staff"]))
finally:
    logging.getLogger("tinysesam").removeHandler(lh)
warned = logbuf.getvalue()
for part in ("ldap_group_import=True, but ldap_enabled is off", "saml_group_import_filter is set, but "
             "saml_group_import is off", "oidc_group_import_filter names 'staff', a role of the configuration"):
    assert part in warned, (part, warned)
ok("8. configuration warnings: a switch without its source, a filter without its switch, a filter naming a "
   "configured role")

# The start names imported roles no sign-in delivered for 90 days, and those of a source switched off.
db = auth3.cfg.db_path
auth3.store._exec("UPDATE idp_role SET last_seen_at=?", (int(time.time()) - 91 * 86400,))
logbuf = io.StringIO()
lh = logging.StreamHandler(logbuf)
logging.getLogger("tinysesam").addHandler(lh)
try:
    TinySesam(TinySesamConfig(db_path=db, oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe",
                              oidc_client_secret="secret", base_url="http://testserver"))
finally:
    logging.getLogger("tinysesam").removeHandler(lh)
assert "no sign-in delivered for 90 days: team-docs" in logbuf.getvalue(), logbuf.getvalue()
assert "source whose group import is off: team-docs" in logbuf.getvalue(), logbuf.getvalue()
ok("8. the start names stale imported roles and those of a source whose import is off")
print("OK test_group_import")

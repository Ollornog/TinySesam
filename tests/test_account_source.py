"""T-99, ADR-18: the origin of an account is a visible attribute — `source` in the panel, the account API and
`account.json`.

`Store.account_sources` names per account `local` (a password, passkey or PIN of its own, or no identity provider at all),
`oidc`, `saml`, `ldap` (bound to an identity of that provider, an origin placeholder included; without any binding the
provider that created the name). Two or more is a mixed account. No decision reads it: the same account with or without
a binding gets the same answer from every check (the equivalence rule of ADR-18) — this suite only pins what is shown.
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
from tinysesam import gate_client  # noqa: E402

BASE = "https://auth.example.com"
JSON = {"Accept": "application/json"}


def ok(name):
    print(f"  ✓ {name}")


auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                 cookie_secure=False, base_url=BASE, admin_require_mfa=False, passkey_enabled=True,
                                 pin_enabled=True))
app = FastAPI()
app.include_router(auth.router())
st = auth.store
now = int(time.time())

admin = int(auth.create_user("root", password="a long admin password 4711", is_admin=True))
local_pw = int(auth.create_user("lena", password="a long probe password 4711"))
local_link = int(auth.create_user("mara", email="mara@example.com"))     # no password: a sign-in link, still local
oidc_only = int(auth.create_user("olga"))
st.link_oidc("https://idp.example.com", "sub-olga", oidc_only)
mixed = int(auth.create_user("mixa", password="a long probe password 4711"))
st.link_oidc("https://idp.example.com", "sub-mixa", mixed)
saml_only = int(auth.create_user("sami"))
st.link_federated("saml", "nameid-sami", saml_only, now)
ldap_pin = int(auth.create_user("lars"))
st.link_federated("ldap", st.WITHOUT_IDENTIFIER + "lars", ldap_pin, now)   # the origin placeholder counts
st.set_pin_hash(ldap_pin, "pin-hash")
passkey_saml = int(auth.create_user("pia"))
st.link_federated("saml", "nameid-pia", passkey_saml, now)
st.add_webauthn(passkey_saml, b"credential-pia", b"public-key", 0, ["usb"], "Key")
named = int(auth.create_user("nora"))
st._exec("UPDATE users SET name_source='ldap' WHERE id=?", (named,))      # created by LDAP, binding not yet there

WANT = {admin: ["local"], local_pw: ["local"], local_link: ["local"], oidc_only: ["oidc"], mixed: ["local", "oidc"],
        saml_only: ["saml"], ldap_pin: ["local", "ldap"], passkey_saml: ["local", "saml"], named: ["ldap"]}

# ---------- the store: one query for all, or for some ----------
got = st.account_sources()
assert {u: got[u] for u in WANT} == WANT, got
assert st.account_sources([oidc_only, mixed]) == {oidc_only: ["oidc"], mixed: ["local", "oidc"]}
assert st.account_sources([]) == {} and st.account_sources([999999]) == {}
ok("store: local (password, link, PIN, passkey), oidc, saml, ldap (placeholder, name origin), mixed — in a fixed order")

# ---------- account.json / account_overview ----------
for uid, want in WANT.items():
    view = auth.account_overview(auth.get_user(uid), base=BASE)
    assert view["account"]["source"] == want, (uid, view["account"])
c = TestClient(app)
tok = st.create_session(mixed, 3600, True, "password", factors=["password"])
c.cookies.set(auth.session_cookie_name, tok)
body = c.get("/auth/account.json", headers=JSON).json()
assert body["signed_in"] is True and body["account"]["source"] == ["local", "oidc"], body["account"]
assert gate_client.parse_account(body)["account"]["source"] == ["local", "oidc"]
ok("account.json: `account.source` for every kind; the Python gate client keeps it")

# ---------- the panel ----------
ac = TestClient(app)
atok = st.create_session(admin, 3600, True, "password", factors=["password"])
ac.cookies.set(auth.session_cookie_name, atok)
rows = {u["id"]: u for u in ac.get("/auth/admin/api/users", headers=JSON).json()}
assert {u: rows[u]["source"] for u in WANT} == WANT, {u: rows[u]["source"] for u in WANT}
page = ac.get("/auth/admin", headers={"Accept": "text/html"}).text
assert "L.source" in page and "source.oidc" in page, "the panel's detail view does not show the origin"
ok("panel: every row of /api/users carries `source`; the detail view shows it")

# ---------- the account API ----------
view = auth._provisioning().view({"id": "example", "roles": []}, st.get_user(saml_only))
assert view["source"] == ["saml"], view
ok("account API: the account's view carries `source`")

# ---------- equivalence: a binding changes what is shown, not what is decided ----------
before = (auth.has_role(auth.get_user(local_pw), "editor"), auth.is_admin(auth.get_user(local_pw)))
st.link_oidc("https://idp.example.com", "sub-lena", local_pw)
assert st.account_sources([local_pw])[local_pw] == ["local", "oidc"]
assert (auth.has_role(auth.get_user(local_pw), "editor"), auth.is_admin(auth.get_user(local_pw))) == before
ok("equivalence: binding an identity changes the shown origin, not roles or the admin flag")

print("OK test_account_source")

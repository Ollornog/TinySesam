"""T-102: the group import through the real SAML sign-in (the suite's test identity provider, really signed assertions).

1. The groups of the assertion arrive as roles, catalogued as from the provider (`source` saml).
2. A group the assertion no longer carries takes its role at the next sign-in.
3. An assertion WITHOUT the group attribute is "no groups": the imported roles go. An assertion carries no empty
   attribute, so an absent one is the identity provider's only way to say it (the rule T-99 kept for the mapped roles);
   reading it as "missing" would keep a withdrawn group's role for good.

Needs the extra `[saml]` (and `cryptography`, `lxml`): without them the suite skips with the reason.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("onelogin", extra="saml")
braucht_modul("cryptography")
braucht_modul("lxml")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import _saml_idp  # noqa: E402
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://app.example.com"


def ok(name):
    print(f"  ✓ {name}")


idp = _saml_idp.IdP(BASE)
auth = TinySesam(TinySesamConfig(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), base_url=BASE,
                                 cookie_secure=False, passkey_enabled=False, saml_group_import=True,
                                 saml_group_import_filter=["team-*"], **idp.config()))
app = FastAPI()
app.include_router(auth.router())


def sign_in(groups):
    attrs = {"email": ["sam@example.com"]}
    if groups is not None:
        attrs["groups"] = groups
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    r = _saml_idp.round_trip(c, idp, "sam", attrs=attrs)
    assert r.status_code == 303, (r.status_code, r.text[:300])


def roles():
    return sorted(auth.user_roles(auth.store.get_user_by_name("sam")))


sign_in(["team-docs", "team-ops", "other"])
assert roles() == ["team-docs", "team-ops"], roles()
assert {r["name"]: r["source"] for r in auth.store.catalog_roles()} == {"team-docs": "saml", "team-ops": "saml"}
ok("1. the assertion's groups (through the filter) arrive as roles, catalogued as from the provider")

sign_in(["team-docs"])
assert roles() == ["team-docs"], roles()
ok("2. a group the assertion no longer carries takes its role")

sign_in(None)
assert roles() == [], "an assertion without the group attribute kept the imported role"
ok("3. an assertion without the group attribute withdraws the imported roles (no empty attribute in SAML)")
print("OK test_group_import_saml")

"""Role names without comma and control characters (T-85).

`Remote-Groups` and the claim `ts_groups` join the roles with `,` and have no escape; a gate client trims the spaces
around an entry; `_header_value` strips C0/DEL. A role `staff,admin` reached the application as `admin`, `ad\\x01min`
as `admin`, ` admin` as `admin`. Now:

* `store.role_invalid` — the one rule: not a string, empty, a comma, C0/DEL, surrounding spaces.
* `config_check` — an error for every field that names a role: `available_roles`, `signup_default_roles`, the three
  group maps and the map per OIDC client, the delegate roles with `roles` and `manages`, the roles of top bar and
  menu links (the provisioning fields and `role_levels` already had their own findings, now on the same rule).
* Writing — `create_user`, `set_roles`, `create_invite` raise `ConfigError(field="roles")` before anything is
  written; the panel answers 400 naming the role.
* The identity provider — a map target changed at runtime is skipped with a security line, the other roles apply.
* On the way out — an account that still holds such a role gets 403 at the forward check (and so no gate token),
  never the stripped role; a start warning names the roles.

Mutations in the PR description, each named next to its check.
"""
import logging
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.store import role_invalid  # noqa: E402

PW = "a long probe password 4711"
PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/page"}


def ok(name):
    print(f"  ✓ {name}")


class Lines(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


seclog = Lines()
logging.getLogger("tinysesam.security").addHandler(seclog)

# ---------- the rule ----------
# (Mutations: drop `"," in role` / the C0-DEL test / `role != role.strip()` / `not role.strip()` → each a row red.)
for bad in ("staff,admin", ",", "ad\x01min", "admin\x7f", "a\tb", "a\nb", " admin", "admin ", "", "   ", None, 3):
    assert role_invalid(bad), repr(bad)
for good in ("admin", "coll:a-read", "team a", "Équipe", "a/b", "a;b", "a​b"):
    assert not role_invalid(good), repr(good)
ok("role_invalid: comma, C0/DEL, surrounding spaces, empty and non-strings refused; inner spaces and Unicode pass")


# ---------- config_check: every field that names a role ----------
def errors(lang="en", **fields):
    cfg = TinySesamConfig(db_path=":memory:", lang=lang, **fields)
    marker = "Remote-Groups would read it as another role" if lang == "en" else "Remote-Groups"
    return [e for e in cfg._findings()[0] if marker in e]


def finding(field, role, found):
    return any(e.startswith(f"{field}: the role {role!r} is empty, holds a comma") for e in found)


BAD = "staff,admin"
assert errors(available_roles=["staff", "admin-x"]) == []
cases = [
    ("available_roles", dict(available_roles=["ok", BAD])),
    ("signup_default_roles", dict(signup_default_roles=[BAD])),
    ("oidc_group_role_map", dict(oidc_group_role_map={"g": BAD})),
    ("saml_group_role_map", dict(saml_group_role_map={"g": BAD})),
    ("ldap_group_role_map", dict(ldap_group_role_map={"cn=g": BAD})),
    ("oidc_clients['wiki'].group_role_map", dict(oidc_clients={"wiki": {"group_role_map": {"g": BAD}}})),
    ("admin_delegates", dict(admin_delegates={BAD: {"roles": ["ok"]}})),
    ("admin_delegates['lead'].roles", dict(admin_delegates={"lead": {"roles": [BAD]}})),
    ("admin_delegates['lead'].manages", dict(admin_delegates={"lead": {"roles": ["ok"], "manages": [BAD]}})),
    ("topbar_links", dict(topbar_links=[("Team", "/team", {"role": BAD})])),
    ("topbar_menu_links", dict(topbar_menu_links=[("Team", "/team", {"role": BAD})])),
]
# (Mutation: leave one source out of `config_check.configured_roles` → its row red.)
for field, fields in cases:
    found = errors(**fields)
    assert finding(field, BAD, found), (field, found)
for role in ("ad\x01min", " admin", "admin "):
    assert finding("available_roles", role, errors(available_roles=[role])), role
# `__admin__` is the flag, not a role — never a finding.
assert errors(oidc_group_role_map={"g": "__admin__"}) == []
de, en = errors(lang="de", available_roles=[BAD]), errors(available_roles=[BAD])
assert len(de) == len(en) == 1 and de != en and de[0].startswith("available_roles: ") and BAD in de[0], (de, en)
# The older findings now on the same rule: a level template and the provisioning allowlist.
cfg = TinySesamConfig(db_path=":memory:", available_roles=["x:a"], role_levels=[
    {"name": "x", "levels": [{"name": "lo", "role": " x:{1}-r"}, {"name": "hi", "role": "x:{1}"}]}])
assert any("comma or a control character" in e for e in cfg._findings()[0]), cfg._findings()[0]
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), available_roles=[BAD]))
    raise AssertionError("a comma in available_roles must stop the start")
except ConfigError as exc:
    assert "staff,admin" in str(exc), exc
ok("config_check: an error for each of the eleven role fields, English and German; the start stops")


# ---------- writing: create_user, set_roles, create_invite, the panel ----------
def build(**extra):
    values = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), csrf_enabled=False, lang="en",
                  cookie_secure=False, passkey_enabled=False, base_url="https://auth.example.com",
                  magiclink_enabled=True, forward_auth_enabled=True, gate_token_enabled=True,
                  trusted_redirect_hosts=["app.example.com"], available_roles=["staff", "editor"])
    values.update(extra)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    now = int(time.time())
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (now, now, auth.store.session_hash(tok)))
    c.cookies.set(auth.cfg.session_cookie, tok)
    return c


auth, app = build()
boss = auth.create_user("boss", password=PW, is_admin=True)
member = auth.create_user("member", password=PW, roles=["staff"])


def refused(fn):
    try:
        fn()
    except ConfigError as exc:
        return exc.field == "roles"
    return False


# (Mutation: drop `_refuse_role_names` in `_create_account` / `set_roles` / `create_invite` → its row red.)
assert refused(lambda: auth.create_user("eve", password=PW, roles=["staff", BAD]))
assert auth.store.get_user_by_name("eve") is None
assert refused(lambda: auth.set_roles(member, ["ad\x01min"]))
assert refused(lambda: auth.create_invite(None, "https://auth.example.com", roles=[" admin"]))
assert auth.user_roles(auth.store.get_user(member)) == ["staff"]
cb = session_client(auth, app, boss)
r = cb.post(f"/auth/admin/api/users/{member}/roles", json={"roles": ["staff", BAD]})
# (Mutation: drop the check in `PanelActions.roles_from` → `set_roles` raises ConfigError, no 400 → red.)
assert r.status_code == 400 and "staff,admin" in r.json()["detail"], (r.status_code, r.text)
assert auth.user_roles(auth.store.get_user(member)) == ["staff"]
r = cb.post("/auth/admin/api/users", json={"username": "newbie", "password": PW, "roles": ["a\tb"]})
assert r.status_code == 400 and auth.store.get_user_by_name("newbie") is None, (r.status_code, r.text)
r = cb.post("/auth/admin/api/invite", json={"roles": [BAD]})
assert r.status_code == 400, (r.status_code, r.text)
r = cb.post(f"/auth/admin/api/users/{member}/roles", json={"roles": ["staff", "editor"]})
assert r.status_code == 200 and sorted(auth.user_roles(auth.store.get_user(member))) == ["editor", "staff"]
ok("writing: create_user, set_roles, create_invite raise ConfigError(field='roles'); the panel answers 400, nothing "
   "written")


# ---------- the identity provider: a map changed at runtime ----------
idp = auth.create_user("idp-user", password=PW)
seclog.lines.clear()
# (Mutation: drop the filter in `apply_idp_groups` → `staff,admin` stored → red.)
auth.apply_idp_groups(idp, ["g1", "g2"], {"g1": BAD, "g2": "editor"})
assert auth.user_roles(auth.store.get_user(idp)) == ["editor"], auth.user_roles(auth.store.get_user(idp))
assert any("Role from the identity provider skipped" in x and "staff,admin" in x for x in seclog.lines), seclog.lines
ok("identity provider: a map target with a comma is skipped with a security line, the other roles apply")


# ---------- on the way out: forward check and gate token ----------
fwd = session_client(auth, app, member)
r = fwd.get("/auth/forward", headers=PROXY)
assert r.status_code == 200, (r.status_code, r.text)
assert sorted(r.headers.get("Remote-Groups").split(",")) == ["editor", "staff"], dict(r.headers)
assert "x-tinysesam-gate-cookie" in {k.lower() for k in r.headers}, dict(r.headers)
for stored in (["staff,admin"], ["ad\x01min"], [" admin"], ["staff", 7]):
    auth.store.set_roles(member, stored)                  # existing data from before the check (raw store write)
    seclog.lines.clear()
    r = fwd.get("/auth/forward", headers=PROXY)
    # (Mutation: drop the check in `_forward_values` → 200 with `Remote-Groups: staff,admin`/`admin` → red.)
    assert r.status_code == 403, (stored, r.status_code, dict(r.headers))
    assert not {"remote-groups", "x-tinysesam-gate-cookie", "set-cookie"} & {k.lower() for k in r.headers}, \
        dict(r.headers)
    assert any("role name with a comma" in x for x in seclog.lines), seclog.lines
ok("forward: an account holding such a role gets 403 and no gate token, never the stripped role")


# ---------- start warning ----------
path = auth.cfg.db_path
auth.store.set_roles(member, ["staff,admin"])
seclog.lines.clear()
TinySesam(TinySesamConfig(db_path=path, available_roles=["staff", "editor"]))
# (Mutation: drop the start check → red.)
assert any("Accounts carry role names with a comma" in x and "staff,admin" in x for x in seclog.lines), seclog.lines
ok("start: a warning names stored roles that cannot travel, nothing is rewritten")
assert auth.user_roles(auth.store.get_user(member)) == ["staff,admin"]
print("test_role_names: all checks passed")

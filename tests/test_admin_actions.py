"""T-147, surface "headless": administration actions on action pages — scope `admin`, class `each`.

An application links a person who administers accounts to `/auth/act/<admin action>?target=<account id>&app=<id>&
return=<url>&state=<s>`. Checked here:

  A. The register: eight admin actions, none in `account.json`'s `actions`; without the panel (`admin_enabled=False`)
     the pages and their POST route do not exist.
  B. Signed out: the sign-in page first, back to the same address. Neither administrator nor delegate, an unknown or
     an owner's account (for a non-owner): the same "not offered" page, no form, the way back says `unavailable`.
  C. The page: the account by name (bidi-isolated), what happens, the confirmation fields, never framed; a GET changes
     nothing.
  D. Class `each`: a fresh confirmation window is not enough — no secret, a wrong one: nothing happens, the attempt is
     audited; a ticket is used once, bound to the person and the action; a token in the request and a missing CSRF
     token are refused.
  E. Every action does what the panel does — lock, unlock, roles (unoffered roles kept), TOTP reset, revoke a key, a
     program and an app password, end one session by its handle, issue a sign-in link shown once — with the audit
     line `admin_action`, and the way back carries `done` with `state`.
  F. Rights at the moment of the POST: an administrator who lost the flag between page and POST changes nothing.
  G. A delegate: lock and roles on an account in scope; not an admin-only action, not an account out of scope.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pyotp  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import _actions  # noqa: E402

BASE = "https://auth.example.com"
APP_HOST = "docs.example.com"
PW = "a long probe password 4711"
ADMIN = ("admin_totp_reset", "admin_lock", "admin_unlock", "admin_roles", "admin_key_revoke", "admin_program_revoke",
         "admin_session_end", "admin_signin_link")


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "adm.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=[APP_HOST], forward_auth_enabled=True,
               totp_enabled=True, apikey_enabled=True, admin_enabled=True, magiclink_enabled=True,
               smtp_host="mail.example.com", available_roles=["docs-reader", "docs-editor", "team-lead"],
               oauth_enabled=True, oauth_resources=[f"https://{APP_HOST}/mcp"],
               forward_apps={APP_HOST: {"name": "Docs", "home": "/start", "app_passwords": True}},
               apps={"docs": {"name": "Documents", "hosts": [APP_HOST]}})
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session(auth, app, uid, *, age=0):
    """A full browser session; with age=0 its confirmation is FRESH (the window is open — class `each` must ask
    anyway), with an age beyond `stepup_max_age_sec` it is stale (the action's own confirmation must suffice)."""
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    if age:
        then = int(time.time()) - age
        auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                         (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def open_page(c, name, uid, **extra):
    q = {"target": uid, "app": "docs", "return": f"https://{APP_HOST}/admin", "state": "st-1", **extra}
    r = c.get(f"/auth/act/{name}", params=q)
    m = re.search(rf"action='(/auth/act/{name}/[^']+)'", r.text)
    return r, (m.group(1) if m else None)


def confirm(auth, c, form_action, **data):
    return c.post(form_action, data={"_csrf": c.cookies.get(auth.csrf_cookie_name), **data})


def back(html):
    m = re.search(r"id=ts_back class=btn2 href='([^']*)' data-state='(\w+)'", html)
    return m.group(1).replace("&amp;", "&"), m.group(2)


def audits(auth, event):
    return [a for a in auth.store.recent_audit(500) if a["event"] == event]


auth, app = make()
ada = auth.create_user("ada", password=PW)
auth.store.set_admin(ada, True)
bert = auth.create_user("bert", password=PW, display_name="Bert ‮Evil")
carl = auth.create_user("carl", password=PW)
own = auth.create_user("olga", password=PW)
auth.store.set_admin(own, True)
auth.set_owner(own, True)
c = session(auth, app, ada)

# ── A ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
names = tuple(n for n, a in _actions.ACTIONS.items() if a.scope == "admin")
assert names == ADMIN, names
assert all(_actions.ACTIONS[n].cls == "each" and _actions.ACTIONS[n].target == "account" for n in ADMIN)
view = c.get("/auth/account.json").json()
assert not set(view["actions"]) & set(ADMIN), view["actions"]
off, off_app = make(admin_enabled=False)
oa = off.create_user("ada", password=PW)
off.store.set_admin(oa, True)
oc = session(off, off_app, oa)
assert oc.get(f"/auth/act/admin_lock?target={oa}").status_code == 404
assert oc.post("/auth/act/admin_lock/x", data={}).status_code in (404, 405)
ok("register: eight admin actions of class `each`, none in account.json; without the panel no page, no POST route")

# ── B ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
anon = TestClient(app, base_url=BASE, follow_redirects=False)
r = anon.get(f"/auth/act/admin_lock?target={bert}&app=docs")
assert r.status_code == 303 and "/auth/login?next=" in r.headers["location"], r.headers.get("location")
assert parse_qs(urlsplit(r.headers["location"]).query)["next"][0] == f"/auth/act/admin_lock?target={bert}&app=docs"
plain = session(auth, app, carl)
for who, uid in ((plain, bert), (c, 99999), (c, "x"), (c, own), (c, ada)):
    r, form = open_page(who, "admin_lock", uid)
    assert r.status_code == 200 and form is None and "This is not offered here." in r.text, r.text[-800:]
    assert back(r.text)[1] == "unavailable" and "id=act_target" not in r.text
r, form = open_page(c, "admin_unlock", bert)
assert form is None and back(r.text)[1] == "unavailable", "unlocking an account that is not locked is not offered"
ok("signed out → sign-in and back; no rights, unknown or owner account, nothing to do → the same 'not offered' page")

# ── C ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
r, form = open_page(c, "admin_lock", bert)
assert r.status_code == 200 and form, r.text[-800:]
assert "<bdi>Bert ‮Evil (bert)</bdi>" in r.text.replace("&#x202e;", "‮"), "the account, bidi-isolated"
assert "Locks the account" in r.text and "name=password type=password" in r.text
assert "frame-ancestors 'none'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
assert "Documents" in r.text, "in the application's frame"
assert not auth.store.get_user(bert)["disabled"], "a GET changes nothing"
ok("page: the account bidi-isolated, what happens, the confirmation fields, the frame, never framed; GET changes nothing")

# ── D ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
before = len(audits(auth, "admin_action_denied"))
r = confirm(auth, c, form)                                            # fresh window, but no secret
assert r.status_code == 400 and not auth.store.get_user(bert)["disabled"], r.status_code
r, form = open_page(c, "admin_lock", bert)
r = confirm(auth, c, form, password="wrong password 1234")
assert r.status_code == 401 and not auth.store.get_user(bert)["disabled"]
assert len(audits(auth, "admin_action_denied")) == before + 2
r = confirm(auth, c, form, password=PW)                               # the same ticket again: used
assert r.status_code == 409 and "already used" in r.text and not auth.store.get_user(bert)["disabled"]
_, form = open_page(c, "admin_lock", bert)
other = form.replace("/admin_lock/", "/admin_roles/")
assert confirm(auth, c, other, password=PW).status_code == 409, "a ticket of another action"
assert auth.user_roles(auth.store.get_user(bert)) == [], "the other action did nothing"
_, form = open_page(c, "admin_lock", bert)
olga = session(auth, app, own)
open_page(olga, "admin_lock", carl)                                   # her own CSRF cookie
assert confirm(auth, olga, form, password=PW).status_code == 409, "a ticket of another person"
_, form = open_page(c, "admin_lock", bert)
r = c.post(form, data={"password": PW})
assert r.status_code == 403 and not auth.store.get_user(bert)["disabled"], "CSRF"
_, form = open_page(c, "admin_lock", bert)
r = c.post(form, data={"_csrf": c.cookies.get(auth.csrf_cookie_name), "password": PW},
           headers={"Authorization": "Bearer tsk_x"})
assert r.status_code == 403 and not auth.store.get_user(bert)["disabled"], "a token in the request"
ok("class each: no or a wrong secret changes nothing (audited); ticket once, per action and person; CSRF; no token")

# ── E ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
done_before = len(audits(auth, "admin_action"))


def run(name, uid, check, client=None, **data):
    client = client or c
    r, form = open_page(client, name, uid)
    assert form, f"{name}: no form — {r.text[-600:]}"
    r = confirm(auth, client, form, password=PW, **data)
    assert r.status_code == 200, f"{name}: {r.status_code} {r.text[-600:]}"
    href, st = back(r.text)
    assert st == "done" and parse_qs(urlsplit(href).query) == {
        "ts_action": [name], "ts_result": ["done"], "state": ["st-1"]}, href
    assert check(), f"{name}: no effect"
    return r


run("admin_lock", bert, lambda: auth.store.get_user(bert)["disabled"] == 2)
run("admin_unlock", bert, lambda: not auth.store.get_user(bert)["disabled"])
auth.set_roles(bert, ["docs-reader", "legacy-role"])
run("admin_roles", bert, lambda: sorted(auth.user_roles(auth.store.get_user(bert))) == ["docs-editor", "legacy-role"],
    roles=["docs-editor"])
auth.store.set_totp(bert, pyotp.random_base32(), confirmed=True)
# A stale window (an hour old): the action's own confirmation is enough, `reset_totp` asks for no window.
run("admin_totp_reset", bert, lambda: not auth.store.has_confirmed_totp(bert), client=session(auth, app, ada, age=3600))
_, form = open_page(c, "admin_totp_reset", bert)
assert form is None, "no authenticator app left: not offered"
key = auth.create_api_key(bert, "probe")
foreign = auth.create_api_key(carl, "carl's")
_, form = open_page(c, "admin_key_revoke", bert)
r = confirm(auth, c, form, password=PW, item=f"key:{foreign['id']}")
assert r.status_code == 409 and not any(k["revoked"] for k in auth.list_api_keys(carl)), "another account's key"
r = run("admin_key_revoke", bert, lambda: all(k["revoked"] for k in auth.list_api_keys(bert)),
        item=f"key:{key['id']}")
now = int(time.time())
auth.store.oauth_add_client("probe-cli", "Probe CLI", ["http://127.0.0.1/cb"], now, "192.0.2.1")
grant = auth.store.oauth_create_grant("probe-code", "probe-cli", bert, f"https://{APP_HOST}/mcp", "mcp", now,
                                      "192.0.2.1", now + 3600, [("probe-token-hash", "refresh", "mcp", now + 3600)])
run("admin_program_revoke", bert, lambda: auth.store.oauth_grant(grant)["revoked_at"], item=f"grant:{grant}")
pw = auth.create_app_password(bert, "phone", hosts=[APP_HOST])
run("admin_program_revoke", bert, lambda: auth.list_app_passwords(bert)[0]["revoked"], item=f"app_password:{pw['id']}")
auth.store.create_session(bert, 86400, True, "password", factors=["password"])
handle = auth.store.list_sessions(bert)[0]["public_handle"]
r, form = open_page(c, "admin_session_end", bert)
assert f"value='session:{handle}'" in r.text and "token_hash" not in r.text
run("admin_session_end", bert, lambda: not auth.store.list_sessions(bert), item=f"session:{handle}")
r = run("admin_signin_link", bert, lambda: audits(auth, "signin_link_issue"))
link = re.search(r"id=act_link>([^<]+)<", r.text).group(1)
assert link.startswith(f"{BASE}/auth/magic/") and link not in back(r.text)[0], "shown once, never in the way back"
assert len(audits(auth, "admin_action")) == done_before + 9
line = audits(auth, "admin_action")[0]
assert line["username"] == "ada", dict(line)
assert "act=admin_signin_link" in line["detail"] and "amr=password" in line["detail"] and f"app={APP_HOST}" in line["detail"]
_, form = open_page(c, "admin_key_revoke", bert)
assert form is None, "no active key left: not offered"
ok("every action: lock, unlock, roles (others kept), TOTP reset, key, program, app password, one session by handle, "
   "a sign-in link shown once; audited, the way back says done with state")

# ── F ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
_, form = open_page(c, "admin_lock", bert)
auth.store.set_admin(ada, False)
r = confirm(auth, c, form, password=PW)
assert r.status_code == 403 and not auth.store.get_user(bert)["disabled"], r.status_code
auth.store.set_admin(ada, True)
ok("rights at the moment of the POST: the flag gone between page and POST → nothing changes")

# ── G ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
dauth, dapp = make(available_roles=["docs-reader", "docs-editor", "team-lead", "helpdesk", "guest"],
                   admin_delegates={"team-lead": {"roles": ["docs-reader", "docs-editor"], "can": ["disable", "roles"]},
                                    "helpdesk": {"roles": ["guest"], "can": ["disable"]}})
lead = dauth.create_user("lead", password=PW, roles=["team-lead", "helpdesk"])
member = dauth.create_user("mia", password=PW, roles=["docs-reader"])
outsider = dauth.create_user("otto", password=PW, roles=["other"])
dauth.store.set_totp(member, pyotp.random_base32(), confirmed=True)
dc = session(dauth, dapp, lead)
r, form = open_page(dc, "admin_lock", member)
assert form, r.text[-600:]
assert confirm(dauth, dc, form, password=PW).status_code == 200 and dauth.store.get_user(member)["disabled"]
dauth.set_disabled(member, False)
r, form = open_page(dc, "admin_roles", member)
assert "value='docs-editor'" in r.text and "value='team-lead'" not in r.text, "only the roles in scope"
assert "value='guest'" not in r.text, "not the roles of a delegate role that may not set roles or does not hold mia"
assert confirm(dauth, dc, form, password=PW, roles=["docs-editor", "team-lead"]).status_code == 200
assert dauth.user_roles(dauth.store.get_user(member)) == ["docs-editor"], "a role out of scope is dropped"
# An administrator who is also a team lead loses the flag between page and POST: now a delegate, and an admin-only
# action is no longer theirs — the rights at the POST decide, not those of the page.
adam = dauth.create_user("adam", password=PW, roles=["team-lead"])
dauth.store.set_admin(adam, True)
ac = session(dauth, dapp, adam)
mkey = dauth.create_api_key(member, "probe")
_, form = open_page(ac, "admin_key_revoke", member)
dauth.store.set_admin(adam, False)
r = confirm(dauth, ac, form, password=PW, item=f"key:{mkey['id']}")
assert r.status_code == 409 and not any(k["revoked"] for k in dauth.list_api_keys(member)), r.status_code
for name, uid in (("admin_totp_reset", member), ("admin_lock", outsider)):
    r, form = open_page(dc, name, uid)
    assert form is None and back(r.text)[1] == "unavailable", name
ok("delegate: lock and roles in scope (only the scope's roles); an admin-only action or an account out of scope: not offered")

print("OK test_admin_actions")

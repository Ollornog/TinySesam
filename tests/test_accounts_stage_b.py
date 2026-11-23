"""The account API for applications, stage B: deletion with a grace period, restore, the cleanup, the operator's take
over / release / cancel (panel and CLI), and the application's link dying once the account is no longer wholly its own.

One block per row of the acceptance table (draft "account API" §11 B, plus the follow-up of the access reset); the
mutation that turns each red is named next to it and was run for the pull request:

 1. Never signed in → 204, gone for good; signed in → 202, locked (3), the name stays taken; `delete_grace_days=0` → 204.
                                                    (grace period for everyone / for no one)
 2. The cleanup deletes after `delete_after` through the one deletion path (audit anonymised), not before; also
    `TinySesam.gc()` and `tinysesam gc`.            (cleanup without the deadline / past `remove_account`)
 3. `restore` within the period → active; after it 404 (GET too), the store refuses as well; the operator may still.
                                                    (deadline not checked in `target` / in `cancel_deletion`)
 4. `delete_per_hour` and `delete_per_day` → 429 with Retry-After, security-log warning, audit `provision_throttled`.
                                                    (counter not raised)
 5. `tinysesam accounts adopt --with-role`: only accounts `adopt_refusal` lets through; `--dry-run` writes nothing.
                                                    (strict rule replaced by "holds an allowlist role")
 6. The panel names the managing application (also "not configured"); a delegate sees application accounts only in
    scope.                                          (filter bypassed)
 7. The whole-account rule: an account with a foreign role → DELETE/restore 409 `account_shared`.   (whole=False)
 8. During the period: enable/disable/link/PATCH → 409 `account_deleting`; the store never unlocks it by app; the
    operator's unlock ends the deletion.            (`not_deleting` removed / `AND delete_after IS NULL` removed /
                                                     `delete_after=NULL` on unlock removed)
 9. Panel: take over (rule, step-up, admins only), release, cancel deletion — audit under the account.
                                                    (`_require_fresh` removed / refusal ignored)
10. Start warning for accounts of an application that is not configured.   (start check removed)
11. Follow-up of the access reset: the application's link signs nobody in once the account holds a role outside the
    allowlist (panel, delegate), is released (CLI), or someone signed in after the link was issued; an untouched link
    still works.                                    (door check removed / the "signed in since" rule removed)
12. `tinysesam accounts release|restore|list`, the listing shows `deleting` with `delete_after`, the self-description
    names the grace period and the daily limit, `config_check` bounds `delete_grace_days`.
"""
import contextlib
import io
import json
import logging
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check  # noqa: E402
from tinysesam import provisioning as prov  # noqa: E402
from tinysesam import _accounts  # noqa: E402
from tinysesam import __main__ as cli_main  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"
ROLES = ["example-member", "example-editor", "staff", "approver", "teamadmin", "editors"]
ALLOW = ["example-member", "example-editor"]
SCOPES = ["users:read", "users:invite", "users:update", "users:disable", "users:delete"]
A = "/auth/admin"
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


def apps(**block):
    p = {"roles": list(ALLOW), "scopes": list(SCOPES)}
    p.update(block)
    return {"example": {"account": "svc-example", "name": {"en": "Example", "de": "Beispiel"}, "provisioning": p}}


def config(db=None, **over):
    cfg = dict(lang="en", db_path=db or os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, csrf_enabled=False, base_url=BASE, magiclink_enabled=True,
               stepup_max_age_sec=900, available_roles=list(ROLES),
               admin_delegates={"teamadmin": {"roles": ["example-member", "editors"]}}, apps=apps())
    cfg.update(over)
    return cfg


def build(db=None, **over):
    auth = TinySesam(TinySesamConfig(**config(db, **over)))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    svc = auth.create_service("svc-example")
    key = auth.create_api_key(svc, name="example")["key"]
    return auth, app, key


def client(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def H(key, actor="-"):
    return {"X-Api-Key": key, "TinySesam-On-Behalf-Of": actor}


def session(auth, app, uid, age=0):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def audit(auth, event=None):
    return [a for a in auth.store.recent_audit(5000) if event is None or a["event"] == event]


auth, app, key = build()
c = client(app)
seq = [0]


def create(c_=None, key_=None, **body):
    seq[0] += 1
    body.setdefault("username", f"user{seq[0]}")
    body.setdefault("roles", ["example-member"])
    r = (c_ or c).post("/auth/api/users", headers=H(key_ or key), json=body)
    assert r.status_code == 201, r.text
    return r.json()


def signed_in(uid, at=None):
    auth.store.mark_login(uid, int(at if at is not None else time.time()))


def row(uid):
    return auth.store.get_user(uid)


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = _accounts.run(argv, prog="tinysesam accounts")
    return code, out.getvalue(), err.getvalue()


# ══ 1. never signed in → for good; signed in → locked with a grace period ═══════════════════════════════════════
fresh = create(username="typo")
r = c.delete(f"/auth/api/users/{fresh['id']}", headers=H(key))
assert r.status_code == 204 and r.content == b"" and r.headers["cache-control"] == "no-store", (r.status_code, r.text)
assert row(fresh["id"]) is None
assert any(a["event"] == "user_delete" and f"uid={fresh['id']}" in (a["detail"] or "") and "app=example" in
           (a["detail"] or "") for a in audit(auth))
used = create(username="used")
signed_in(used["id"])
their_key = auth.create_api_key(used["id"], name="theirs")["key"]
before = int(time.time())
r = c.delete(f"/auth/api/users/{used['id']}", headers=H(key))
assert r.status_code == 202, r.text
body = r.json()
assert body["state"] == "deleting" and before + 7 * 86400 <= body["delete_after"] <= int(time.time()) + 7 * 86400
assert row(used["id"])["disabled"] == 3 and row(used["id"])["delete_after"] == body["delete_after"]
assert auth.verify_api_key(their_key)[0] is None, "the lock did not end the account's keys"
again = c.delete(f"/auth/api/users/{used['id']}", headers=H(key))
assert again.status_code == 202 and again.json()["delete_after"] == body["delete_after"], "asking again moved the date"
r = c.post("/auth/api/users", headers=H(key), json={"username": "used", "roles": ["example-member"]})
assert r.status_code == 409 and r.json()["error"] == "username_taken", "the name of an account in its period is free"
assert any(a["event"] == "provision_delete_scheduled" and a["username"] == "used" and "actor=svc-example" in
           (a["detail"] or "") for a in audit(auth))
a0, app0, key0 = build(apps=apps(delete_grace_days=0))
u0 = client(app0).post("/auth/api/users", headers=H(key0), json={"username": "zero", "roles": ["example-member"]})
a0.store.mark_login(u0.json()["id"], int(time.time()))
r = client(app0).delete(f"/auth/api/users/{u0.json()['id']}", headers=H(key0))
assert r.status_code == 204 and a0.store.get_user(u0.json()["id"]) is None, r.text
ok("1: never signed in → 204 and gone; signed in → 202, locked (3, keys end), the name stays taken, asking again "
   "keeps the date; delete_grace_days=0 → 204")

# ══ 2. the cleanup after the deadline, through the one deletion path ═══════════════════════════════════════════
gone = create(username="gcvictim")
signed_in(gone["id"])
auth.audit("probe_line", "gcvictim", None, "seen")
deadline = c.delete(f"/auth/api/users/{gone['id']}", headers=H(key)).json()["delete_after"]
# Only this account's deadline matters here (an earlier one of block 1 may fall in the same window).
auth.store._exec("UPDATE users SET delete_after=? WHERE id=?", (deadline + 3600, used["id"]))
auth.store.gc_provisioning(deadline - 1)
assert row(gone["id"]) is not None, "deleted before the deadline"
assert auth.store.gc_provisioning(deadline) == 1 and row(gone["id"]) is None
lines = audit(auth)
assert not any(a["username"] == "gcvictim" for a in lines), "the audit still names the deleted account"
assert any(a["event"] == "probe_line" and a["username"] == f"deleted#{gone['id']}" for a in lines)
assert any(a["event"] == "user_delete" and f"uid={gone['id']}" in (a["detail"] or "") and "reason=delete_after"
           in (a["detail"] or "") for a in lines)
# TinySesam.gc() and `tinysesam gc` (the systemd timer) run the same step.
via_gc = create(username="viagc")
signed_in(via_gc["id"])
c.delete(f"/auth/api/users/{via_gc['id']}", headers=H(key))
auth.store._exec("UPDATE users SET delete_after=? WHERE id=?", (int(time.time()) - 1, via_gc["id"]))
assert auth.gc()["provisioning_deleted"] == 1 and row(via_gc["id"]) is None
via_cli = create(username="viacli")
signed_in(via_cli["id"])
c.delete(f"/auth/api/users/{via_cli['id']}", headers=H(key))
auth.store._exec("UPDATE users SET delete_after=? WHERE id=?", (int(time.time()) - 1, via_cli["id"]))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    assert cli_main._gc(["--db", auth.cfg.db_path]) == 0
assert "provisioning_deleted=1" in out.getvalue() and row(via_cli["id"]) is None, out.getvalue()
# Released (or made admin) meanwhile: no longer the application's — the mark goes, the account stays.
kept = create(username="kept")
signed_in(kept["id"])
c.delete(f"/auth/api/users/{kept['id']}", headers=H(key))
auth.store._exec("UPDATE users SET delete_after=?, managed_by=NULL WHERE id=?", (int(time.time()) - 1, kept["id"]))
assert auth.store.gc_provisioning(int(time.time())) == 0 and row(kept["id"]) is not None
assert row(kept["id"])["delete_after"] is None and audit(auth, "provision_delete_cancelled")
ok("2: the cleanup deletes only after delete_after, through remove_account (audit anonymised, user_delete "
   "reason=delete_after); TinySesam.gc() and `tinysesam gc` do it too; a released account is kept")

# ══ 3. restore within the period; afterwards gone ══════════════════════════════════════════════════════════════
back = create(username="comeback")
signed_in(back["id"])
c.delete(f"/auth/api/users/{back['id']}", headers=H(key))
r = c.post(f"/auth/api/users/{back['id']}/restore", headers=H(key))
assert r.status_code == 200 and r.json()["state"] == "active" and r.json()["delete_after"] is None, r.text
assert row(back["id"])["disabled"] == 0 and row(back["id"])["delete_after"] is None
assert any(a["event"] == "provision_restore" and a["username"] == "comeback" for a in audit(auth))
r = c.post(f"/auth/api/users/{back['id']}/restore", headers=H(key))
assert r.status_code == 409 and r.json()["error"] == "not_deleting", r.text
deadline = c.delete(f"/auth/api/users/{back['id']}", headers=H(key)).json()["delete_after"]
real_now = prov._now
prov._now = lambda: deadline + 1
try:
    assert c.get(f"/auth/api/users/{back['id']}", headers=H(key)).status_code == 404, "visible after the deadline"
    r = c.post(f"/auth/api/users/{back['id']}/restore", headers=H(key))
    assert r.status_code == 404, r.text
    assert back["id"] not in [u["id"] for u in c.get("/auth/api/users?limit=200", headers=H(key)).json()["users"]]
finally:
    prov._now = real_now
assert auth.store.cancel_deletion(back["id"], deadline + 1) is False, "the store took a deletion back after the deadline"
assert row(back["id"])["delete_after"] == deadline
assert auth.store.cancel_deletion(back["id"]) is True and row(back["id"])["disabled"] == 0      # the operator may
ok("3: restore within the period → active (audit provision_restore), twice → 409 not_deleting; after the deadline "
   "GET, list and restore answer 404 and the store refuses; the operator may still")

# ══ 4. limits per hour and per day ═════════════════════════════════════════════════════════════════════════════
fixed = (int(time.time()) // 86400) * 86400 + 600
real_now = prov._now
prov._now = lambda: fixed
buf = io.StringIO()
handler = logging.StreamHandler(buf)
seclog = logging.getLogger("tinysesam.security")
seclog.addHandler(handler)
try:
    a4, app4, key4 = build(apps=apps(limits={"delete_per_hour": 2, "delete_per_day": 3}))
    c4 = client(app4)
    ids = [c4.post("/auth/api/users", headers=H(key4), json={"username": f"lim{i}", "roles": ["example-member"]})
           .json()["id"] for i in range(5)]
    first_two = [c4.delete(f"/auth/api/users/{i}", headers=H(key4)).status_code for i in ids[:2]]
    assert first_two == [204, 204], first_two
    r = c4.delete(f"/auth/api/users/{ids[2]}", headers=H(key4))
    assert r.status_code == 429 and r.json() == {"error": "limit", "error_description": "delete_per_hour"}, r.text
    assert int(r.headers["retry-after"]) == 3600 - 600 and a4.store.get_user(ids[2]) is not None
    assert "account API throttled app=example action=delete window=hour" in buf.getvalue(), buf.getvalue()
    assert any(a["event"] == "provision_throttled" and "action=delete" in a["detail"] for a in audit(a4))
    prov._now = lambda: fixed + 3600
    r = c4.delete(f"/auth/api/users/{ids[2]}", headers=H(key4))
    assert r.status_code == 204, r.text
    r = c4.delete(f"/auth/api/users/{ids[3]}", headers=H(key4))
    assert r.status_code == 429 and r.json()["error_description"] == "delete_per_day", r.text
    assert int(r.headers["retry-after"]) == 86400 - 600 - 3600
    info = c4.get("/auth/api/provisioning", headers=H(key4)).json()
    assert info["remaining"]["delete_per_day"] == 0 and info["limits"]["delete_per_day"] == 3
    assert info["delete_grace_days"] == 7
finally:
    prov._now = real_now
    seclog.removeHandler(handler)
ok("4: delete_per_hour and delete_per_day → 429 limit with Retry-After to the end of the window, security-log line, "
   "audit provision_throttled; the self-description counts down")

# ══ 5. adopt by CLI: only what the rule lets through; --dry-run writes nothing ══════════════════════════════════
plain = auth.create_user("plain", roles=["example-member"])
mixed = auth.create_user("mixed", roles=["example-member", "staff"])
bare = auth.create_user("bare", roles=[])
boss_like = auth.create_user("bossy", password=PW, is_admin=True, roles=["example-member"])
lead = auth.create_user("lead", roles=["example-member", "teamadmin"])
machine = auth.create_service("machine", roles=["example-member"])
other_app = auth.create_user("otherapp", roles=["example-member"])
auth.store._exec("UPDATE users SET managed_by='other' WHERE id=?", (other_app,))
cfg_file = os.path.join(tempfile.mkdtemp(), "probe_cfg.py")
with open(cfg_file, "w", encoding="utf-8") as fh:
    fh.write("from tinysesam import TinySesamConfig\n"
             f"cfg = TinySesamConfig(**{config(auth.cfg.db_path)!r})\n")
code, out, err = run_cli(["adopt", "--db", auth.cfg.db_path, "--config", f"{cfg_file}:cfg", "--app", "example",
                          "--with-role", "example-member", "--dry-run"])
assert code == 0, err
assert f"would adopt #{plain} plain" in out, out
assert not any(row(i)["managed_by"] == "example" for i in (plain, mixed, boss_like, lead, machine)), "dry run wrote"
for uid, why in ((mixed, "foreign_roles"), (boss_like, "admin"), (lead, "delegate"), (machine, "service"),
                 (other_app, "managed")):
    assert f"skipped #{uid} " in out and why in out.split(f"skipped #{uid} ")[1].split("\n")[0], (uid, why, out)
code, out, err = run_cli(["adopt", "--db", auth.cfg.db_path, "--config", f"{cfg_file}:cfg", "--app", "example",
                          "--with-role", "example-member"])
assert code == 0 and f"adopted #{plain} plain" in out, (out, err)
assert row(plain)["managed_by"] == "example" and row(mixed)["managed_by"] is None and row(lead)["managed_by"] is None
assert row(other_app)["managed_by"] == "other" and row(boss_like)["managed_by"] is None
assert any(a["event"] == "account_adopted" and a["username"] == "plain" and "source=cli" in a["detail"]
           for a in audit(auth))
code, out, err = run_cli(["adopt", "--db", auth.cfg.db_path, "--config", f"{cfg_file}:cfg", "--app", "example",
                          "--user", "bare"])
assert "skipped" in out and "no_roles" in out and row(bare)["managed_by"] is None, out
with open(cfg_file, "a", encoding="utf-8") as fh:
    fh.write("wrong = 5\n")
code, out, err = run_cli(["adopt", "--db", auth.cfg.db_path, "--config", f"{cfg_file}:wrong", "--app", "example",
                          "--user", "bare"])
assert code == 1 and "is a int" in err and "TinySesam" in err, (code, err)
code, out, err = run_cli(["adopt", "--db", auth.cfg.db_path, "--config", f"{cfg_file}:cfg", "--app", "example"])
assert code == 2 and "never takes every account" in err, (code, err)
assert prov.adopt_refusal(prov.normalize_apps(auth.cfg)["example"], row(mixed), ["example-member", "staff"]) == \
    "foreign_roles"
ok("5: adopt --with-role takes only accounts whose roles all lie in the allowlist (not mixed, admin, delegate, "
   "service, another application's, none); --dry-run writes nothing; no selector → refused; audit account_adopted")

# ══ 6. panel: the managing application; a delegate sees application accounts only in scope ════════════════════
boss = auth.create_user("boss", password=PW, is_admin=True)
admin_c = session(auth, app, boss)
assert row(used["id"])["delete_after"], "block 6 needs the account of block 1 in its grace period"
lst = {u["username"]: u for u in admin_c.get(f"{A}/api/users").json()}
assert lst["used"]["managed_by"] == "example" and lst["used"]["managed_name"] == "Example"
assert lst["used"]["managed_known"] is True and lst["used"]["delete_after"]
orphan = auth.create_user("orphan", roles=["example-member"])
auth.store._exec("UPDATE users SET managed_by='gone' WHERE id=?", (orphan,))
lst = {u["username"]: u for u in admin_c.get(f"{A}/api/users").json()}
assert lst["orphan"]["managed_by"] == "gone" and lst["orphan"]["managed_known"] is False
assert lst["orphan"]["managed_name"] == "gone" and lst["boss"]["managed_by"] is None
page = admin_c.get(A).text
assert '"managed_by": "Managed by"' in page and '"not_configured": "not configured"' in page
assert '{"id": "example", "name": "Example"}' in page, "the panel does not know the configured application"
in_scope = create(username="scoped", roles=["example-member"])
out_scope = create(username="unscoped", roles=["example-editor"])
team_lead = auth.create_user("teamlead", password=PW, roles=["teamadmin"])
lead_c = session(auth, app, team_lead)
seen = [u["username"] for u in lead_c.get(f"{A}/api/users").json()]
assert "scoped" in seen and "unscoped" not in seen and "plain" in seen and "mixed" not in seen, seen
assert lead_c.get(A).text.count('const APPS=[];') == 1, "a delegate gets the application list"

# The hint "no application could take this account over" (panel, administrators only): the rule of the Take-over action.
lst = {u["username"]: u for u in admin_c.get(f"{A}/api/users").json()}
assert lst["bare"]["no_app_fits"] is True, "an account without a role gets no hint"
assert lst["mixed"]["no_app_fits"] is True and lst["lead"]["no_app_fits"] is True, "foreign role / delegate: no hint"
assert lst["scoped"]["no_app_fits"] is False and lst["plain"]["no_app_fits"] is False, "a fitting/managed account is flagged"
assert lst["boss"]["no_app_fits"] is False and lst["machine"]["no_app_fits"] is False, "admin/service are no candidates"
assert lst["orphan"]["no_app_fits"] is False, "an account of a retired application is managed already"
for u in lead_c.get(f"{A}/api/users").json():
    assert u["no_app_fits"] is False, "a delegate must not get the hint"
assert "no_app_fits" in page and "noappfits" in page
assert prov.no_app_can_adopt({}, row(bare), []) is False, "no applications configured: no hint"
assert prov.no_app_can_adopt(prov.normalize_apps(auth.cfg), row(bare), []) is True
ok("6b: hint no_app_fits — no role, foreign role, delegate: yes; fitting, managed, admin, service, delegate view: no; "
   "no applications: no")
ok("6: the panel lists managed_by with the application's name, an unconfigured one as such; a delegate sees an "
   "application's account only when all its roles are in scope, and no application list")

# ══ 7. the whole-account rule ══════════════════════════════════════════════════════════════════════════════════
shared = create(username="shared")
signed_in(shared["id"])
auth.store._exec("UPDATE users SET roles=? WHERE id=?", (json.dumps(["example-member", "staff"]), shared["id"]))
r = c.delete(f"/auth/api/users/{shared['id']}", headers=H(key))
assert r.status_code == 409 and r.json()["error"] == "account_shared" and row(shared["id"])["delete_after"] is None
auth.store._exec("UPDATE users SET delete_after=?, disabled=3 WHERE id=?", (int(time.time()) + 999, shared["id"]))
r = c.post(f"/auth/api/users/{shared['id']}/restore", headers=H(key))
assert r.status_code == 409 and r.json()["error"] == "account_shared", r.text
for path, method in ((f"/auth/api/users/{boss}", "delete"), (f"/auth/api/users/{boss}/restore", "post"),
                     ("/auth/api/users/999999", "delete"), (f"/auth/api/users/{mixed}", "delete")):
    assert getattr(c, method)(path, headers=H(key)).status_code == 404, path
ok("7: a foreign role → DELETE and restore 409 account_shared; an admin or a missing account → 404")

# ══ 8. during the period: no unlock by the application; the operator's unlock ends the deletion ═════════════════
pend = create(username="pending")
signed_in(pend["id"])
c.delete(f"/auth/api/users/{pend['id']}", headers=H(key))
for method, path, body in (("post", "enable", None), ("post", "disable", None), ("post", "signin-link", None),
                           ("patch", "", {"display_name": "X"})):
    r = getattr(c, method)(f"/auth/api/users/{pend['id']}" + (f"/{path}" if path else ""), headers=H(key),
                           **({"json": body} if body is not None else {}))
    assert r.status_code == 409 and r.json()["error"] == "account_deleting", (path, r.status_code, r.text)
assert row(pend["id"])["disabled"] == 3 and row(pend["id"])["delete_after"]
assert auth.store.unlock_by_app(pend["id"]) is False and row(pend["id"])["disabled"] == 3
assert auth.set_disabled(pend["id"], False) and row(pend["id"])["delete_after"] is None
assert row(pend["id"])["disabled"] == 0
assert any(a["event"] == "provision_restore" and a["username"] == "pending" and "by=operator" in a["detail"]
           for a in audit(auth))
ok("8: during the period enable/disable/link/PATCH → 409 account_deleting, the store never unlocks it by app; the "
   "operator's unlock ends the deletion (audit)")

# ══ 9. panel actions: take over, release, cancel ═══════════════════════════════════════════════════════════════
cand = auth.create_user("candidate", roles=["example-member"])
wide = auth.create_user("widecand", roles=["example-member", "staff"])
stale_c = session(auth, app, boss, age=STALE)
r = stale_c.post(f"{A}/api/users/{cand}/adopt", json={"app": "example"})
assert r.status_code in (401, 403) and row(cand)["managed_by"] is None, (r.status_code, r.text)
r = lead_c.post(f"{A}/api/users/{cand}/adopt", json={"app": "example"})
assert r.status_code == 403 and row(cand)["managed_by"] is None, "a delegate took an account over"
r = admin_c.post(f"{A}/api/users/{wide}/adopt", json={"app": "example"})
assert r.status_code == 409 and "allowlist" in r.json()["detail"] and row(wide)["managed_by"] is None, r.text
assert admin_c.post(f"{A}/api/users/{cand}/adopt", json={"app": "nope"}).status_code == 400
r = admin_c.post(f"{A}/api/users/{cand}/adopt", json={"app": "example"})
assert r.status_code == 200 and row(cand)["managed_by"] == "example", r.text
assert any(a["event"] == "account_adopted" and a["username"] == "candidate" and "actor=boss" in a["detail"]
           for a in audit(auth))
assert admin_c.post(f"{A}/api/users/{cand}/adopt", json={"app": "example"}).status_code == 409
assert stale_c.post(f"{A}/api/users/{cand}/release").status_code in (401, 403) and row(cand)["managed_by"]
assert admin_c.post(f"{A}/api/users/{cand}/release").status_code == 200 and row(cand)["managed_by"] is None
assert any(a["event"] == "account_released" and a["username"] == "candidate" for a in audit(auth))
assert admin_c.post(f"{A}/api/users/{cand}/release").status_code == 409
assert admin_c.post(f"{A}/api/users/{orphan}/release").status_code == 200 and row(orphan)["managed_by"] is None
# A fresh confirmation also with admin_require_mfa=False: the panel itself asks for none then, these two still do.
a9, app9, _ = build(admin_require_mfa=False)
boss9 = a9.create_user("boss9", password=PW, is_admin=True)
cand9 = a9.create_user("cand9", roles=["example-member"])
stale9 = session(a9, app9, boss9, age=STALE)
assert stale9.get(f"{A}/api/users").status_code == 200, "the probe: a stale session opens the panel here"
r = stale9.post(f"{A}/api/users/{cand9}/adopt", json={"app": "example"})
assert r.status_code == 403 and a9.store.get_user(cand9)["managed_by"] is None, (r.status_code, r.text)
a9.store.adopt_account(cand9, "example")
r = stale9.post(f"{A}/api/users/{cand9}/release")
assert r.status_code == 403 and a9.store.get_user(cand9)["managed_by"] == "example", (r.status_code, r.text)
assert session(a9, app9, boss9).post(f"{A}/api/users/{cand9}/release").status_code == 200
canc = create(username="cancelme")
signed_in(canc["id"])
c.delete(f"/auth/api/users/{canc['id']}", headers=H(key))
assert lead_c.post(f"{A}/api/users/{canc['id']}/restore").status_code == 403
assert admin_c.post(f"{A}/api/users/{canc['id']}/restore").status_code == 200
assert row(canc["id"])["delete_after"] is None and row(canc["id"])["disabled"] == 0
assert admin_c.post(f"{A}/api/users/{canc['id']}/restore").status_code == 409
ok("9: panel — take over only by an administrator with a fresh confirmation and under the rule (409 with the "
   "reason), release (also an unconfigured application's), cancel a deletion; audit under the account")

# ══ 10. start warning for an application that is not configured ═══════════════════════════════════════════════
buf = io.StringIO()
handler = logging.StreamHandler(buf)
logging.getLogger("tinysesam").addHandler(handler)
try:
    orphaned = auth.store.get_user_by_name("otherapp")["id"]
    assert row(orphaned)["managed_by"] == "other"
    with TinySesam(TinySesamConfig(**config(auth.cfg.db_path))):
        pass                                     # the start check runs in the constructor
finally:
    logging.getLogger("tinysesam").removeHandler(handler)
assert "account(s) are managed by the application other, which is not configured" in buf.getvalue(), buf.getvalue()
assert "application example" not in buf.getvalue()
ok("10: start names an application that holds accounts but is not configured (with the number), not a configured one")

# ══ 11. the application's link dies once the account is no longer wholly its own ═══════════════════════════════


def token_of(answer):
    return answer["signin_url"].rsplit("/", 1)[1]


def redeem(token):
    cc = client(app)
    return cc, cc.post(f"/auth/magic/{token}", data={"_csrf": "x"})


untouched = create(username="untouched")
cc, r = redeem(token_of(untouched))
assert r.status_code == 303 and cc.cookies.get(auth.session_cookie_name), (r.status_code, r.text[:200])
# The operator gives a role outside the allowlist (here an approver role) in the panel.
p_panel = create(username="p4panel")
r = admin_c.post(f"{A}/api/users/{p_panel['id']}/roles", json={"roles": ["example-member", "approver"]})
assert r.status_code == 200, r.text
assert client(app).get(f"/auth/magic/{token_of(p_panel)}").status_code == 400, "the confirmation page offers it"
cc, r = redeem(token_of(p_panel))
assert r.status_code == 403 and not cc.cookies.get(auth.session_cookie_name), (r.status_code, r.text[:200])
assert any(a["event"] == "magic_app_link_refused" and a["username"] == "p4panel" for a in audit(auth))
assert not auth.peek_magic(token_of(p_panel), purpose="login"), "the refused link stays usable"
# A delegate adds a role of the team scope that is not the application's.
p_lead = create(username="p4lead")
assert lead_c.post(f"{A}/api/users/{p_lead['id']}/roles", json={"roles": ["example-member", "editors"]}) \
    .status_code == 200
cc, r = redeem(token_of(p_lead))
assert r.status_code == 403 and not cc.cookies.get(auth.session_cookie_name), r.status_code
# The operator releases it by CLI.
p_cli = create(username="p4cli")
code, out, err = run_cli(["release", "--db", auth.cfg.db_path, "--app", "example", "--user", "p4cli"])
assert code == 0 and row(p_cli["id"])["managed_by"] is None, (out, err)
cc, r = redeem(token_of(p_cli))
assert r.status_code == 403 and not cc.cookies.get(auth.session_cookie_name), r.status_code
# Someone signed in after the link was issued (an operator's link, a password): the application's link is dead.
p_after = create(username="p4after")
signed_in(p_after["id"], at=int(time.time()) + 5)
cc, r = redeem(token_of(p_after))
assert r.status_code == 403 and not cc.cookies.get(auth.session_cookie_name), r.status_code
# An operator's link for such an account works: the rule is about the application's links.
op_link = auth.create_signin_link(p_panel["id"], ttl_min=10)["url"].rsplit("/", 1)[1]
cc, r = redeem(op_link)
assert r.status_code == 303 and cc.cookies.get(auth.session_cookie_name), r.status_code
ok("11: the application's link signs nobody in after a foreign role by the operator or a delegate, a release by CLI, "
   "or a sign-in since it was issued (spent, audit magic_app_link_refused); an untouched link and the operator's "
   "own link still work")

# ══ 12. CLI release|restore|list, listing, self-description, config_check ═══════════════════════════════════════
lst_user = create(username="listme")
signed_in(lst_user["id"])
c.delete(f"/auth/api/users/{lst_user['id']}", headers=H(key))
deleting = c.get("/auth/api/users?state=deleting&limit=200", headers=H(key)).json()["users"]
entry = next(u for u in deleting if u["id"] == lst_user["id"])
assert entry["state"] == "deleting" and entry["delete_after"] == row(lst_user["id"])["delete_after"]
code, out, err = run_cli(["list", "--db", auth.cfg.db_path, "--app", "example"])
assert code == 0 and "listme" in out and "deleting until" in out, out
code, out, err = run_cli(["list", "--db", auth.cfg.db_path, "--config", f"{cfg_file}:cfg"])
assert "other (not configured)" in out and "example (not configured)" not in out, out
code, out, err = run_cli(["restore", "--db", auth.cfg.db_path, "listme"])
assert code == 0 and row(lst_user["id"])["delete_after"] is None and row(lst_user["id"])["disabled"] == 0, (out, err)
assert any(a["event"] == "provision_restore" and a["username"] == "listme" and "source=cli" in a["detail"]
           for a in audit(auth))
assert run_cli(["restore", "--db", auth.cfg.db_path, "listme"])[0] == 1
code, out, err = run_cli(["release", "--db", auth.cfg.db_path, "--app", "example", "--dry-run"])
assert code == 0 and "would release" in out and row(lst_user["id"])["managed_by"] == "example", out


def errors(**over):
    return config_check.check_config(TinySesamConfig(**config(**over)))[0]


assert any("delete_grace_days=31" in e for e in errors(apps=apps(delete_grace_days=31)))
assert any("delete_grace_days=-1" in e for e in errors(apps=apps(delete_grace_days=-1)))
assert not [e for e in errors(apps=apps(delete_grace_days=0)) if "delete_grace_days" in e]
assert prov.normalize_apps(TinySesamConfig(**config(apps=apps(delete_grace_days=99))))["example"][
    "delete_grace_days"] == 7, "a value changed at runtime out of range is not the default"
ok("12: CLI list (state, not configured), restore (audit), release --dry-run; listing state=deleting with "
   "delete_after; config_check bounds delete_grace_days 0–30")

print("OK test_accounts_stage_b")

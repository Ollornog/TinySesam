"""T-106, surface "headless": reading — the own events and API keys in `account.json`, the refusals with `error`,
Fetch Metadata, and the administration data inside the application's area (`/.tinysesam/admin/accounts.json`, spec
§8b).

  R1 `account.json` carries `events` (time, event, by_admin — never an address) and `programs.api_keys` (the active
     keys it counts in api_keys_active: name, kind, times — never the prefix or the key); a revoked key is not listed,
     an expired one shows by its expires_at; keys off → null.
  R2 every refusal names itself in `error`: signed_out (401), cross_site (403), not_found (404), rate_limited (429).
  R3 Fetch Metadata: `Sec-Fetch-Site: cross-site` or `same-site` → 403 before anything else; `same-origin`, `none`
     and no header read.
  R4 admin data, who: an administrator and a delegate of the application's area read; a delegate of another area,
     a person without rights → 403 forbidden; an API key, a half session, nobody → 401; a host of no application →
     403; an unprotected host → 404; without the panel the route does not exist; `account.json` names the data
     (`admin.accounts`) for exactly these people.
  R5 admin data, what: an administrator sees every account but service accounts, a delegate only its scope; per
     account id (text), names, source, roles, disabled, totp, the application's permissions and `actions` — the
     addresses of the administration action pages where the person may act now, null elsewhere (owner protection, a
     delegate's admin-only actions, nothing to revoke); the addresses open the page for that account.
  R6 admin data never carries a hash, a secret, a key prefix, an address or an email address; read only (POST → 405);
     its own rate limit; the library method gives the same answer.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://auth.example.com"
APP = "docs.example.com"
OTHER = "wiki.example.com"
PW = "a long probe password 4711"
ADMIN = ("admin_totp_reset", "admin_lock", "admin_unlock", "admin_roles", "admin_key_revoke", "admin_program_revoke",
         "admin_session_end", "admin_signin_link")


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "read.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=[APP, OTHER, "plain.example.com"],
               forward_auth_enabled=True, account_enabled=True, admin_enabled=True, totp_enabled=True, apikey_enabled=True,
               magiclink_enabled=True, smtp_host="mail.example.com",
               available_roles=["docs-reader", "wiki-reader", "docs-lead", "wiki-lead"],
               admin_delegates={"docs-lead": {"roles": ["docs-reader"], "apps": ["docs"]},
                                "wiki-lead": {"roles": ["wiki-reader"], "apps": ["wiki"]}},
               forward_apps={APP: {"name": "Docs", "home": "/"}, OTHER: {"name": "Wiki", "home": "/"},
                             "plain.example.com": {"name": "Plain"}},
               apps={"docs": {"name": "Documents", "hosts": [APP],
                              "permissions": [{"name": "docs.read", "suggested_roles": ["docs-reader"]}]},
                     "wiki": {"name": "Wiki", "hosts": [OTHER]}})
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_mailer(lambda *a, **k: None)        # smtp_host only switches the mail features on; nothing is sent
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def client(auth, app, uid=None, *, full=True):
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    if uid is not None:
        tok = (auth.start_session(uid, "password", ip="192.0.2.10", ua="Firefox")[0] if full
               else auth._create_session(uid, 3600, False, "password", "192.0.2.10", "Firefox"))
        c.cookies.set(auth.session_cookie_name, tok)
    return c


def admin_json(c, host=APP, **headers):
    return c.get("/.tinysesam/admin/accounts.json", headers={"X-Forwarded-Host": host, **headers})


auth, app = make()
ada = int(auth.create_user("ada", password=PW, email="ada@example.com"))
auth.store.set_admin(ada, True)
owner = int(auth.create_user("olga", password=PW))
auth.store._exec("UPDATE users SET is_owner=1 WHERE id=?", (owner,))
lou = int(auth.create_user("lou", password=PW, roles=["docs-reader"], email="lou@example.com"))
wim = int(auth.create_user("wim", password=PW, roles=["wiki-reader"]))
dora = int(auth.create_user("dora", password=PW, roles=["docs-lead"]))
walt = int(auth.create_user("walt", password=PW, roles=["wiki-lead"]))
nobody = int(auth.create_user("nora", password=PW))
svc = int(auth.create_user("svc-bot", is_service=True))
auth.grant_permission("docs-reader", "docs.read", app="docs", by="test")

# ══ R1: events and API keys in account.json ═════════════════════════════════════════════════════════════════════
kept = auth.create_api_key(lou, name="ci")
gone = auth.create_api_key(lou, name="old")
auth.revoke_api_key(gone["id"], lou)
late = auth.create_api_key(lou, name="late")
auth.store._exec("UPDATE api_key SET expires_at=? WHERE id=?", (int(time.time()) - 5, late["id"]))
cl = client(auth, app, lou)
j = cl.get("/.tinysesam/account.json", headers={"X-Forwarded-Host": APP}).json()
keys = j["programs"]["api_keys"]
assert sorted(k["name"] for k in keys) == ["ci", "late"], keys
assert all(set(k) == {"name", "kind", "created_at", "last_used", "expires_at"} for k in keys)
assert {k["kind"] for k in keys} == {"automation"}
assert [k["expires_at"] < time.time() for k in keys if k["name"] == "late"] == [True], "expired shows by expires_at"
assert j["programs"]["api_keys_active"] == len(keys) == 2, j["programs"]
events = j["events"]
assert events and all(set(e) == {"at", "event", "by_admin"} for e in events), events
assert {"login", "apikey_create", "apikey_revoke"} <= {e["event"] for e in events}, events
assert [e["at"] for e in events] == sorted((e["at"] for e in events), reverse=True), "newest first"
assert all(e["by_admin"] is False for e in events), events
raw = cl.get("/auth/account.json").text
for value in (kept["key"], kept["key"][:12], "192.0.2.10", '"prefix"', '"ip"'):
    assert value not in raw, value
own = auth.own_events(lou)
assert [(e["at"], e["event"]) for e in events] == [(e["ts"], e["event"]) for e in own], "the account page's events"
# An administrator's action on lou shows as by_admin, still without an address.
auth.audit("user_disable", "lou", "198.51.100.7", detail=f"uid={lou} actor=ada")
j = cl.get("/auth/account.json").json()
assert j["events"][0] == {"at": j["events"][0]["at"], "event": "user_disable", "by_admin": True}, j["events"][0]
assert "198.51.100.7" not in cl.get("/auth/account.json").text
auth_off, app_off = make(apikey_enabled=False)
u = int(auth_off.create_user("otto", password=PW))
j = client(auth_off, app_off, u).get("/auth/account.json").json()
assert j["programs"]["api_keys"] is None and j["programs"]["api_keys_active"] is None, j["programs"]
assert isinstance(j["events"], list) and j["events"], j["events"]
ok("R1 account.json: events (at, event, by_admin; newest first; the account page's list; no address — an admin's "
   "action is by_admin) and programs.api_keys (active keys only: name, kind, times; no prefix or key; keys off → null)")

# ══ R2 + R3: refusals with `error`, Fetch Metadata ══════════════════════════════════════════════════════════════
anon = client(auth, app)
for path in ("/auth/account.json", "/.tinysesam/account.json", "/.tinysesam/admin/accounts.json"):
    r = anon.get(path, headers={"X-Forwarded-Host": APP})
    assert r.status_code == 401 and r.json()["error"] == "signed_out", (path, r.status_code, r.text)
    assert r.headers["cache-control"] == "no-store", path
    for site in ("cross-site", "same-site"):
        for c in (anon, cl):
            r = c.get(path, headers={"X-Forwarded-Host": APP, "Sec-Fetch-Site": site, "Sec-Fetch-Mode": "cors"})
            assert r.status_code == 403 and r.json() == {"error": "cross_site"}, (path, site, r.status_code, r.text)
            assert r.headers["cache-control"] == "no-store", path
for site in ("same-origin", "none", None):
    head = {"X-Forwarded-Host": APP, **({"Sec-Fetch-Site": site} if site else {})}
    assert cl.get("/.tinysesam/account.json", headers=head).status_code == 200, site
    assert client(auth, app, ada).get("/.tinysesam/admin/accounts.json", headers=head).status_code == 200, site
for path in ("/.tinysesam/account.json", "/.tinysesam/admin/accounts.json"):
    r = cl.get(path, headers={"X-Forwarded-Host": "evil.example"})
    assert r.status_code == 404 and r.json()["error"] == "not_found", (path, r.status_code, r.text)
auth_r, app_r = make()
ur = int(auth_r.create_user("rita", password=PW))
auth_r.store.set_admin(ur, True)
cr = client(auth_r, app_r, ur)
assert {cr.get("/auth/account.json").status_code for _ in range(60)} == {200}
r = cr.get("/auth/account.json")
assert r.status_code == 429 and r.json()["error"] == "rate_limited" and r.headers["retry-after"] == "60", r.text
assert r.json()["detail"], "detail stays"
assert {admin_json(cr).status_code for _ in range(60)} == {200}, "the admin data has its own limit"
r = admin_json(cr)
assert r.status_code == 429 and r.json()["error"] == "rate_limited", r.text
ok("R2 refusals name themselves in `error`: signed_out (401), cross_site (403), not_found (404), rate_limited (429, "
   "detail kept; the admin data counts on its own) — on account.json and the admin data")
ok("R3 Fetch Metadata: Sec-Fetch-Site cross-site or same-site → 403 cross_site, signed in or not; same-origin, none "
   "and no header read")

# ══ R4: who reads the admin data ════════════════════════════════════════════════════════════════════════════════
assert admin_json(client(auth, app, ada)).status_code == 200
assert admin_json(client(auth, app, dora)).status_code == 200
for who, c in (("delegate of another area", client(auth, app, walt)), ("no rights", client(auth, app, nobody)),
               ("reader", client(auth, app, lou))):
    r = admin_json(c)
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}, (who, r.status_code, r.text)
assert admin_json(client(auth, app, walt), OTHER).status_code == 200, "walt administers the wiki's area"
assert admin_json(client(auth, app, dora), OTHER).status_code == 403, "dora does not"
key = auth.create_api_key(ada, name="adm", kind="human")["key"]
for who, c, head in (("API key", anon, {"Authorization": f"Bearer {key}"}),
                     ("half session", client(auth, app, ada, full=False), {})):
    r = admin_json(c, **head)
    assert r.status_code == 401 and r.json()["error"] == "signed_out", (who, r.status_code, r.text)
r = admin_json(client(auth, app, ada), "plain.example.com")
assert r.status_code == 403 and r.json() == {"error": "forbidden"}, "a protected host of no application"
auth_np, app_np = make(admin_enabled=False)
a2 = int(auth_np.create_user("ada", password=PW))
auth_np.store.set_admin(a2, True)
assert admin_json(client(auth_np, app_np, a2)).status_code == 404, "no panel → no route"
assert auth_np.admin_overview({**auth_np.get_user(a2), "_via": "session"}, APP) is None
locked_admin = int(auth.create_user("lena", password=PW))
auth.store.set_admin(locked_admin, True)
cla = client(auth, app, locked_admin)
stale = {**auth.get_user(locked_admin), "_via": "session"}       # a dict read while lena was an administrator
assert stale["is_admin"] and auth.admin_overview(stale, APP) is not None
auth.store.set_admin(locked_admin, False)
assert admin_json(cla).status_code == 403, "the flag is read at the request, not at the sign-in"
assert auth.admin_overview(stale, APP) is None, "the library reads the flag from the row, not from the dict handed in"
# account.json names the admin data exactly for the people who may read it, on the application's host only.
for who, uid, host, expected in (("administrator", ada, APP, True), ("delegate of docs", dora, APP, True),
                                 ("delegate of the wiki", walt, APP, False), ("delegate of the wiki", walt, OTHER, True),
                                 ("reader", lou, APP, False), ("administrator", ada, "plain.example.com", False)):
    j = client(auth, app, uid).get("/.tinysesam/account.json", headers={"X-Forwarded-Host": host}).json()
    want = {"accounts": "/.tinysesam/admin/accounts.json"} if expected else None
    assert j["admin"] == want, (who, host, j["admin"])
assert client(auth, app, ada).get("/auth/account.json").json()["admin"] is None, "not on TinySesam's origin"
assert auth.account_overview(auth.get_user(ada), app_host=APP)["admin"] is None, "only a browser session"
assert client(auth_np, app_np, a2).get("/.tinysesam/account.json",
                                       headers={"X-Forwarded-Host": APP}).json()["admin"] is None, "no panel"
ok("R4 who: an administrator and a delegate of this area read; another area's delegate, a reader, a person without "
   "rights, a former administrator → 403 forbidden; an API key, a half session, nobody → 401; a protected host of no "
   "application → 403; without the panel the route does not exist; account.json's `admin` names the data for exactly "
   "the people who may read it, on the application's host only")

# ══ R5: what the admin data holds ═══════════════════════════════════════════════════════════════════════════════
auth.store.set_totp(lou, "JBSWY3DPEHPK3PXP", confirmed=True)
adm = admin_json(client(auth, app, ada)).json()
assert adm["app"] == "docs" and adm["links"] == {"panel": f"{BASE}/auth/admin"}, adm
by = {a["username"]: a for a in adm["accounts"]}
assert set(by) == {"ada", "olga", "lou", "wim", "dora", "walt", "nora", "lena"}, sorted(by)
assert "svc-bot" not in by
lj = by["lou"]
assert set(lj) == {"id", "username", "display_name", "source", "roles", "disabled", "totp", "permissions", "actions"}
assert lj["id"] == str(lou) and lj["roles"] == ["docs-reader"] and lj["permissions"] == ["docs.read"], lj
assert lj["totp"] is True and lj["disabled"] is False and lj["source"] == ["local"], lj
assert set(lj["actions"]) == set(ADMIN), lj["actions"]
for name in ("admin_totp_reset", "admin_lock", "admin_roles", "admin_key_revoke", "admin_session_end",
             "admin_signin_link"):
    href = lj["actions"][name]
    parts = urlsplit(href)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{BASE}/auth/act/{name}", href
    assert parse_qs(parts.query) == {"app": [APP], "target": [str(lou)]}, href
assert lj["actions"]["admin_unlock"] is None and lj["actions"]["admin_program_revoke"] is None, lj["actions"]
assert by["ada"]["actions"]["admin_lock"] is None, "never lock oneself"
assert all(v is None for v in by["olga"]["actions"].values()), "the owner's account: only an owner acts on it"
assert by["wim"]["permissions"] == [] and by["wim"]["totp"] is False
# The address opens the page for that account (an administrator, the page names lou).
page = client(auth, app, ada).get(lj["actions"]["admin_lock"].replace(BASE, ""))
assert page.status_code == 200 and "lou" in page.text and "act_confirm" in page.text, page.status_code
jd = admin_json(client(auth, app, dora)).json()
assert [a["username"] for a in jd["accounts"]] == ["lou"], jd["accounts"]
acts = jd["accounts"][0]["actions"]
assert acts["admin_lock"] and acts["admin_roles"] and acts["admin_signin_link"], acts
assert acts["admin_totp_reset"] is None and acts["admin_key_revoke"] is None and acts["admin_session_end"] is None, \
    "admin-only actions are no delegate's"
auth.store._exec("UPDATE users SET disabled=2 WHERE id=?", (lou,))
lj = {a["username"]: a for a in admin_json(client(auth, app, ada)).json()["accounts"]}["lou"]
assert lj["disabled"] is True and lj["actions"]["admin_unlock"] and lj["actions"]["admin_lock"] is None, lj
auth.store._exec("UPDATE users SET disabled=0 WHERE id=?", (lou,))
auth_na, app_na = make(account_enabled=False)
a3 = int(auth_na.create_user("ada", password=PW))
auth_na.store.set_admin(a3, True)
auth_na.create_user("lou", password=PW)
jn = admin_json(client(auth_na, app_na, a3)).json()
assert jn["accounts"] and all(v is None for a in jn["accounts"] for v in a["actions"].values()), \
    "without the account page there are no action pages"
ok("R5 what: an administrator sees every account but service accounts, a delegate only its scope; per account id, "
   "names, source, roles, disabled, totp, the application's permissions and the addresses of the action pages it may "
   "use now (app=<host>, target=<id>; null for oneself's lock, the owner, admin-only actions of a delegate, nothing to "
   "revoke, without the account page); the address opens the page for that account")

# ══ R6: nothing secret, read only, the library method ═══════════════════════════════════════════════════════════
raw = admin_json(client(auth, app, ada)).text
for value in (key, key[:12], kept["key"], "JBSWY3DPEHPK3PXP", "ada@example.com", "lou@example.com", "192.0.2.10",
              '"is_admin"', '"is_owner"', '"email"', '"prefix"'):
    assert value not in raw, value
for method in ("POST", "PUT", "DELETE", "PATCH"):
    r = client(auth, app, ada).request(method, "/.tinysesam/admin/accounts.json", headers={"X-Forwarded-Host": APP})
    assert r.status_code == 405, (method, r.status_code)
viewer = {**auth.get_user(ada), "_via": "session"}
assert auth.admin_overview(viewer, APP) == admin_json(client(auth, app, ada)).json()
assert auth.admin_overview({**auth.get_user(ada), "_via": "apikey"}, APP) is None, "only a browser session"
assert auth.admin_overview(viewer, "unknown.example") is None
ok("R6 the admin data carries no key, prefix, TOTP secret, address, email, admin or owner flag; POST/PUT/DELETE/PATCH "
   "→ 405; admin_overview() gives the route's answer, None for a non-session or a host of no application")

print("OK test_headless_reading")

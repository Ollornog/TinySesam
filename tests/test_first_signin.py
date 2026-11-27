"""T-94: the first sign-in through a one-time link, made shorter for people without technical knowledge.

Three parts, each pinned here and proven by mutation (named next to the block, run for the pull request):

1. `recovery_codes_enabled=False` — the setup (link → password → TOTP) runs without the code page, creates no codes,
   and no code is accepted; codes an account already holds stay untouched (switching back on revives them). The
   account page shows no code action. `config_check` warns when no application may reset an access.
   (mutations: the guard in `_verify_recovery_code`; the router's `if cfg.recovery_codes_enabled`; the warning)
2. `totp_app_hint` — a hint per language above the QR code, escaped, bounded, without control characters.
   (mutation: the fallback order / the escaping)
3. `next` of the account API (`POST /auth/api/users`, `…/signin-link`) and `apps[…].provisioning.welcome_url` — where
   the link leads after the setup. Only the redirect circle (path, host of `base_url`, `trusted_redirect_hosts`); a bad
   target is a 400 where it is given, nothing is written; the target lives in the token, not in the link; the audit
   names the host only.  (mutation: `link_next_ok` returning True; the check before the write)
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from _totp_clock import previous_code  # noqa: E402
from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig, config_check  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


BASE = "https://auth.example.com"
APP_HOST = "app.example.com"
JSON = {"Accept": "application/json"}
PW = "a long probe password 4711"
FIRST_PW = "the first password 2468"
ROLES = ["example-member", "example-approver"]


def build(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, lang="en",
               passkey_enabled=False, magiclink_enabled=True, magiclink_self_request=False, base_url=BASE,
               login_chain=["password", "totp"], trusted_redirect_hosts=[APP_HOST], available_roles=list(ROLES))
    cfg.update(over)
    a = TinySesam(TinySesamConfig(**cfg))
    a.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(a.router())

    @app.get("/who")
    def who(u=Depends(a.require_user)):
        return {"u": u["username"]}
    return a, app


def warnings_of(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), lang="en", base_url=BASE,
               trusted_redirect_hosts=[APP_HOST], available_roles=list(ROLES))
    cfg.update(over)
    return config_check.check_config(TinySesamConfig(**cfg))


def csrf(c, a):
    return c.cookies.get(a.csrf_cookie_name) or ""


def redeem(a, app, url):
    c = TestClient(app, base_url=BASE)
    tok = re.search(r"/auth/magic/([\w\-]+)$", url).group(1)
    page = c.get(f"/auth/magic/{tok}")
    assert page.status_code == 200, (page.status_code, page.text[:200])
    field = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
    return c, c.post(f"/auth/magic/{tok}", data={"_csrf": field}, follow_redirects=False)


def walk_setup(a, app, url, chosen=FIRST_PW):
    """Open the link like a browser and walk the setup pass: password, then TOTP. Returns (client, final JSON)."""
    c, r = redeem(a, app, url)
    assert r.status_code == 303 and r.headers["location"].startswith("/auth/setup?next="), r.headers.get("location")
    setup = r.headers["location"]
    page = c.get(setup)
    nxt = re.search(r"id=obroot data-next='([^']*)'", page.text).group(1)
    r = c.post("/auth/password/set", json={"new": chosen, "next": nxt}, headers={"X-CSRF-Token": csrf(c, a)})
    assert r.status_code == 200, r.text
    page = c.get(r.json()["next"])
    totp_link = re.search(r"href='(/auth/totp/setup\?next=[^']*)'", page.text).group(1)
    page = c.get(totp_link)
    shown = re.search(r"name=next value='([^']*)'", page.text).group(1)
    started = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, a), "next": shown})
    assert started.status_code == 200, started.text[:300]
    secret = re.search(r"class=mono>([A-Z2-7]+)<", started.text).group(1)
    data_next = re.search(r"data-next='([^']*)'", started.text).group(1)
    r = c.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret).now(), "next": data_next},
               headers={"X-CSRF-Token": csrf(c, a)})
    assert r.status_code == 200 and r.json()["ok"], r.text
    return c, r.json(), started.text


def events(a, name):
    return [e for e in a.store.recent_audit(500) if e["event"] == name]


# =====================================================================================
# 1) Recovery codes switched off
# =====================================================================================
assert TinySesamConfig().recovery_codes_enabled is True, "the default must stay on"
auth, app = build()
uid = auth.create_user("dana", email="dana@example.com")
_, done, _ = walk_setup(auth, app, auth.create_signin_link(uid, next="/who")["url"])
assert len(done["recovery_codes"]) == 10 and auth.recovery_codes_remaining(uid) == 10, done
ok("default: the setup still hands out the recovery codes once")

auth, app = build(recovery_codes_enabled=False)
uid = auth.create_user("dana", email="dana@example.com")
c, done, page = walk_setup(auth, app, auth.create_signin_link(uid, next="/who")["url"])
assert done["recovery_codes"] == [] and done["next"] == "/who", done
assert auth.recovery_codes_remaining(uid) == 0 and not events(auth, "recovery_generate")
assert c.get("/who", headers=JSON).json() == {"u": "dana"}, "the setup must end fully signed in"
# The page goes straight on for an empty list (no code box to click through).
assert "if(!codes.length){go();return false}" in page
ok("off: link → password → TOTP → signed in, no code page, no code created")

r = c.post("/auth/totp/recovery", headers={"X-CSRF-Token": csrf(c, auth)})
assert r.status_code == 404, r.status_code
try:
    auth.generate_recovery_codes(uid)
    raise AssertionError("generate_recovery_codes issued codes nobody accepts")
except ConfigError:
    pass
acc = c.get("/auth/account").text
assert "data-act=recovery" not in acc and "id=rc_left" not in acc, "the account page still offers codes"
assert auth.account_overview(auth.get_user(uid))["sign_in"]["totp"]["recovery_left"] is None
ok("off: no route, no method and no account-page action issues codes")

# Codes from before the switch: neither accepted nor used up, and valid again once the switch is back on.
auth, app = build(login_chain=[], recovery_codes_enabled=True)
uid = auth.create_user("erik", password=PW)
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, previous_code(secret))
codes = auth.generate_recovery_codes(uid)
auth.cfg.recovery_codes_enabled = False
c = TestClient(app, base_url=BASE)
login_page = c.get("/auth/login")
c.post("/auth/login", data={"username": "erik", "password": PW, "next": "/who",
                            "_csrf": re.search(r"name=_csrf value='([^']*)'", login_page.text).group(1)},
       follow_redirects=False)
r = c.post("/auth/totp", data={"code": codes[0], "next": "/who", "_csrf": csrf(c, auth)}, follow_redirects=False)
assert r.status_code == 401 and c.get("/who", headers=JSON).status_code == 401, (r.status_code, r.text[:200])
assert auth.recovery_codes_remaining(uid) == len(codes), "a refused code was used up"
assert not events(auth, "recovery_used")
auth.cfg.recovery_codes_enabled = True
r = c.post("/auth/totp", data={"code": codes[0], "next": "/who", "_csrf": csrf(c, auth)}, follow_redirects=False)
assert r.status_code == 303 and c.get("/who", headers=JSON).json() == {"u": "erik"}, (r.status_code, r.text[:200])
assert auth.recovery_codes_remaining(uid) == len(codes) - 1
ok("off: an existing code is refused and kept; back on, it signs in again (the way back)")

# config_check: the warning, and exactly the configured reset ways silence it — the admin panel's TOTP reset (T-98)
# and an application's users:reset.
WARN = "recovery_codes_enabled=False, the admin panel is off and no application may reset an access"
_, w = warnings_of(recovery_codes_enabled=False, admin_enabled=False)
assert any(WARN in x for x in w) and any("tinysesam reset-totp" in x for x in w), w
_, w = warnings_of(recovery_codes_enabled=False)
assert not any(WARN in x for x in w), "the admin panel resets a TOTP (T-98)"
_, w = warnings_of(admin_enabled=False)
assert not any(WARN in x for x in w)
_, w = warnings_of(recovery_codes_enabled=False, totp_enabled=False, admin_enabled=False)
assert not any(WARN in x for x in w), "without TOTP there is nothing to lose"
reset_apps = {"example": {"account": "svc-example", "provisioning": {
    "roles": ["example-member"], "scopes": ["users:read", "users:invite", "users:reset"],
    "approver_role": "example-approver"}}}
e, w = warnings_of(recovery_codes_enabled=False, apps=reset_apps, approvals_enabled=True, magiclink_enabled=True,
                   admin_enabled=False)
assert not e and not any(WARN in x for x in w), (e, w)
no_reset = json.loads(json.dumps(reset_apps))
no_reset["example"]["provisioning"]["scopes"] = ["users:read", "users:invite"]
del no_reset["example"]["provisioning"]["approver_role"]
e, w = warnings_of(recovery_codes_enabled=False, apps=no_reset, magiclink_enabled=True, admin_enabled=False)
assert not e and any(WARN in x for x in w), (e, w)
e, _ = warnings_of(recovery_codes_enabled="no")
assert any("recovery_codes_enabled='no'" in x for x in e), e
_, w = warnings_of(recovery_codes_enabled=False, admin_enabled=False, lang="de")
assert any("recovery_codes_enabled=False, das Admin-Panel ist aus und keine Anwendung" in x for x in w), w
ok("config_check: warns without panel and users:reset (not with either, not without TOTP); a non-bool is an error; German text")

# =====================================================================================
# 2) The TOTP hint per language
# =====================================================================================
HINT = {"en": "Install <b>Example Authenticator</b> first.", "de": "Example Authenticator (de)."}
auth, app = build(login_chain=[], totp_app_hint=HINT)
uid = auth.create_user("fia", password=PW)
c = TestClient(app, base_url=BASE)
lp = c.get("/auth/login")
c.post("/auth/login", data={"username": "fia", "password": PW, "next": "/who",
                            "_csrf": re.search(r"name=_csrf value='([^']*)'", lp.text).group(1)}, follow_redirects=False)
start = c.get("/auth/totp/setup?next=/who").text
assert "<div class=hint id=totp_app_hint>Install &lt;b&gt;Example Authenticator&lt;/b&gt; first.</div>" in start, \
    start[:2000]
shown = re.search(r"name=next value='([^']*)'", start).group(1)
qr_page = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, auth), "next": shown}).text
hint_at = qr_page.find("id=totp_app_hint")
assert 0 < hint_at < qr_page.find("class=mono>"), "the hint must stand above the QR code and the secret"
assert "<b>Example" not in qr_page and "style=" not in qr_page[hint_at - 40:hint_at + 200]
auth.cfg.lang = "de"
assert "Example Authenticator (de)." in c.get("/auth/totp/setup?next=/who").text
auth.cfg.totp_app_hint = {"fr": "Pas en anglais.", "en": "English only."}
assert "English only." in c.get("/auth/totp/setup?next=/who").text, "no fallback to en"
auth.cfg.totp_app_hint = {"fr": "Seulement en français."}
assert "Seulement en français." in c.get("/auth/totp/setup?next=/who").text, "no fallback to the first entry"
auth.cfg.totp_app_hint = {"de": "bad\nline"}
assert "id=totp_app_hint" not in c.get("/auth/totp/setup?next=/who").text, "a runtime value past the check is shown"
auth.cfg.totp_app_hint = {}
assert "id=totp_app_hint" not in c.get("/auth/totp/setup?next=/who").text
ok("hint: escaped, above the QR, in the page's language, falls back to en and then the first; empty = none")

for bad in ({"en": "x" * 301}, {"en": "two\nlines"}, {"en": "tab\there"}, {"en": "bidi‮evil"},
            {"en": "zero​width"}, {"en": "   "}, {"en": ""}, {"EN!": "x"}, {"en": 5}, ["en", "x"], "text",
            {f"l{i:02d}"[:2] + chr(97 + i % 26): "x" for i in range(30)}):
    e, _ = warnings_of(totp_app_hint=bad)
    assert any(x.startswith("totp_app_hint:") for x in e), (bad, e)
e, _ = warnings_of(totp_app_hint={"en": "x" * 300, "de": "„Example“ — äöü ß.", "pt-BR": "ok"})
assert not e, e
ok("config_check: too long, control/format characters, empty, bad language tags or shapes are errors")

# =====================================================================================
# 3) Where the link leads: `next` and `welcome_url`
# =====================================================================================
WELCOME = f"https://{APP_HOST}/welcome"


def api_apps(**block):
    p = {"roles": ["example-member"], "scopes": ["users:read", "users:invite"]}
    p.update(block)
    return {"example": {"account": "svc-example", "name": "Example", "provisioning": p}}


auth, app = build(apps=api_apps(welcome_url=WELCOME))
svc = auth.create_service("svc-example")
key = auth.create_api_key(svc, name="example")["key"]
H = {"X-Api-Key": key, "TinySesam-On-Behalf-Of": "-"}
api = TestClient(app, base_url=BASE, follow_redirects=False)


def create(name, **extra):
    return api.post("/auth/api/users", headers=H, json={"username": name, "roles": ["example-member"], **extra})


# next per request wins; the target is in the token, not in the link; the audit has the host, not the path.
target = f"https://{APP_HOST}/start?tab=first#top"
r = create("gina", next=target)
assert r.status_code == 201, r.text
assert "start" not in r.json()["signin_url"] and APP_HOST not in r.json()["signin_url"], r.json()["signin_url"]
issue = events(auth, "signin_link_issue")[0]
assert f"next_host={APP_HOST}" in issue["detail"] and "start" not in issue["detail"], issue["detail"]
c, done, _ = walk_setup(auth, app, r.json()["signin_url"])
assert done["next"] == target, done
assert c.get("/who", headers=JSON).json() == {"u": "gina"}
ok("next: after password and TOTP the link leads to the request's target; not in the URL; audit names the host")

# Without next: the application's welcome_url; a path is fine as well.
r = create("hans")
_, done, _ = walk_setup(auth, app, r.json()["signin_url"])
assert done["next"] == WELCOME, done
r = create("ida", next="/who?from=link")
_, done, _ = walk_setup(auth, app, r.json()["signin_url"])
assert done["next"] == "/who?from=link", done
assert "next=path" in events(auth, "signin_link_issue")[0]["detail"]
ok("welcome_url: the default when a request names no next; a relative path is allowed")

# Attacks: every one a 400 `next_invalid`, and nothing is written (no account, no audit line, no counter).
ATTACKS = [
    "https://evil.example/", "http://evil.example", "//evil.example/x", "///evil.example", "javascript:alert(1)",
    "JavaScript:alert(1)", "data:text/html,x", "/\\evil.example", "\\\\evil.example", f"https://{APP_HOST}\\@evil.example/",
    "/x\ty", "/x\ny", "/x\ry", "/x\x00y", " /who", "/who ", f"https://{APP_HOST}@evil.example/",
    f"https://user@{APP_HOST}/", f"https://user:pw@{APP_HOST}/", "https://аpp.example.com/",
    "https://app.example.com。evil.example/", f"https://{APP_HOST}.evil.example/", f"https://{APP_HOST}:99999/",
    f"ftp://{APP_HOST}/", "/__TS_P__/evil.example", "/" + "a" * 2048, "relative/path", "?next=x", 123, ["/who"],
    {"url": "/who"}, True,
]
before = len(auth.store.list_managed("example", 0, 1000))
lines = len(auth.store.recent_audit(5000))
for bad in ATTACKS:
    r = create("mallory", next=bad)
    assert r.status_code == 400 and r.json().get("error") == "next_invalid", (bad, r.status_code, r.text)
assert len(auth.store.list_managed("example", 0, 1000)) == before and auth.store.get_user_by_name("mallory") is None
assert len(auth.store.recent_audit(5000)) == lines, "a refused target left audit lines"
ok(f"next: {len(ATTACKS)} attacks (foreign host, //, javascript:, backslash, control characters, user info, IDN, "
   "port, placeholder, length, types) → 400, nothing written")

# The signin-link route: optional body, same check, checked before the old link is revoked.
r = create("jo")
old_url, jo = r.json()["signin_url"], r.json()["id"]
assert api.post(f"/auth/api/users/{jo}/signin-link", headers=H, json={"next": "https://evil.example/"}).status_code \
    == 400
tok = re.search(r"/auth/magic/([\w\-]+)$", old_url).group(1)
assert auth.peek_magic(tok, purpose="login"), "a refused target revoked the old link"
assert api.post(f"/auth/api/users/{jo}/signin-link", headers=H, json={"extra": 1}).status_code == 400
assert api.post(f"/auth/api/users/{jo}/signin-link", headers=H, content=b"{broken").status_code == 400
r = api.post(f"/auth/api/users/{jo}/signin-link", headers=H)
assert r.status_code == 200, r.text
assert auth.peek_magic(re.search(r"/auth/magic/([\w\-]+)$", r.json()["signin_url"]).group(1),
                       purpose="login")["payload"]["next"] == WELCOME, "without a body the welcome_url is the target"
r = api.post(f"/auth/api/users/{jo}/signin-link", headers=H, json={"next": f"https://{APP_HOST}/again"})
assert r.status_code == 200, r.text
_, done, _ = walk_setup(auth, app, r.json()["signin_url"])
assert done["next"] == f"https://{APP_HOST}/again", done
# A foreign account with a broken body still answers 404 (the target before the body).
other = auth.create_user("outsider", password=PW)
assert api.post(f"/auth/api/users/{other}/signin-link", headers=H, content=b"{broken").status_code == 404
ok("signin-link: optional next, same check before the old link is revoked; a foreign account stays 404")

# The door checks once more: a host taken out of trusted_redirect_hosts after issuing falls back to login_redirect.
r = create("kim", next=f"https://{APP_HOST}/later")
auth.cfg.trusted_redirect_hosts = []
_, done, _ = walk_setup(auth, app, r.json()["signin_url"])
assert done["next"] == auth.cfg.login_redirect, done
auth.cfg.trusted_redirect_hosts = [APP_HOST]
ok("the door re-checks the stored target against the configuration of the moment")

# Library and configuration.
try:
    auth.create_signin_link(auth.create_user("lea", email="lea@example.com"), next="https://evil.example/")
    raise AssertionError("create_signin_link accepted a foreign target")
except ValueError:
    pass
for bad in ("https://evil.example/", "//evil.example", "javascript:alert(1)", 5):
    e, _ = warnings_of(magiclink_enabled=True, apps=api_apps(welcome_url=bad))
    assert any("welcome_url=" in x for x in e), (bad, e)
e, _ = warnings_of(magiclink_enabled=True, apps=api_apps(welcome_url=WELCOME))
assert not e, e
e, _ = warnings_of(magiclink_enabled=True, apps=api_apps(welcome_url="/welcome"))
assert not e, e
auth.cfg.apps = api_apps(welcome_url="https://evil.example/")
r = create("mia")
assert r.status_code == 201
_, done, _ = walk_setup(auth, app, r.json()["signin_url"])
assert done["next"] == "/", "a welcome_url changed at runtime past the check was used"
ok("create_signin_link and welcome_url are checked the same way; a bad runtime welcome_url counts for nothing")

for good in ("/", "/who", "/a/b?c=d&e=f#g", WELCOME, f"http://{APP_HOST}/", f"https://{APP_HOST}:8443/x",
             f"https://{BASE.split('//')[1]}/account", "https://APP.example.com/"):
    assert config_check.link_next_ok(TinySesamConfig(base_url=BASE, trusted_redirect_hosts=[APP_HOST]), good), good
assert not config_check.link_next_ok(TinySesamConfig(base_url=BASE), WELCOME), "a host outside the circle passed"
ok("link_next_ok: paths, the base_url host and trusted hosts (any port, any case) pass")

print("OK test_first_signin")

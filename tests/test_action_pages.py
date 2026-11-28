"""T-105, surface "headless": the action pages — one register, the way back with the result.

An application that draws everything itself sends a person to `/auth/act/<name>?app=<id>&return=<url>&state=<s>` on
TinySesam's origin to change something, and gets them back at `return` with `ts_action`, `ts_result` and `state`.
Checked here:

  A. The register and `account.json`: every own action has a member of `actions` — an address in the application's
     frame where this installation offers it, null where not; an unknown name is 404.
  B. Signed out (or by API key) the sign-in page comes first and leads back to the same address — frame, `return`
     and `state` included.
  C. The page: the heading in the application's name, the frame, only the action's sections, never framed
     (`frame-ancestors 'none'`, `X-Frame-Options: DENY`), the nonce on every script and style; a GET changes nothing.
  D. The way back: a valid `return` gets `ts_action`/`ts_result`/`state` (before a fragment, old values replaced); a
     foreign host, another trusted host than the frame's, a path in a frame, a bad `state` are replaced or dropped in
     silence; without a frame (a library) a path is the way back.
  E. Class `window` with `fresh`: a stale confirmation goes to the reauth page and back; an action without `fresh`
     opens directly. Not offered: the page says so and the way back says `unavailable`.
  F. Done: `ts_done=1` starts the way back as `done`; the setup of TOTP and the revocation of a program come back to
     the action page marked as done — the revocation only to a path of TinySesam.
  G. The account page still shows every section and leads a revocation back into its frame.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://auth.example.com"
APP_HOST = "docs.example.com"
OTHER = "wiki.example.com"
PW = "a long probe password 4711"
OWN = ("username", "email", "password", "pin", "totp", "recovery_codes", "passkeys", "api_keys", "app_passwords",
       "sessions", "programs", "services")


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "act.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=[APP_HOST, OTHER], forward_auth_enabled=True,
               totp_enabled=True, apikey_enabled=True, stepup_max_age_sec=900,
               oauth_enabled=True, oauth_resources=[f"https://{APP_HOST}/mcp"],
               forward_apps={APP_HOST: {"name": "Docs", "home": "/start"}, OTHER: {"name": "Wiki", "home": "/"}},
               apps={"docs": {"name": {"en": "Documents", "de": "Dokumente"}, "hosts": [APP_HOST]}})
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session(auth, app, uid, *, age=0):
    """A full browser session whose sign-in and last confirmation lie `age` seconds back."""
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def back(html):
    m = re.search(r"<a id=ts_back class=btn2 href='([^']*)' data-state='(\w+)' data-done='([^']*)'", html)
    assert m, html[-1500:]
    return m.group(1).replace("&amp;", "&"), m.group(2), m.group(3).replace("&amp;", "&")


def query(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query, keep_blank_values=True).items()}


auth, app = make()
ann = int(auth.create_user("ann", password=PW, email="ann@example.com"))
c = session(auth, app, ann)

# ── A. register and account.json ─────────────────────────────────────────────────────────────────────────────────────
from tinysesam import _actions  # noqa: E402

assert tuple(_actions.ACTIONS) == OWN, tuple(_actions.ACTIONS)
assert all(a.scope == "own" and a.cls in ("window", "each") for a in _actions.ACTIONS.values())
data = c.get("/auth/account.json").json()
assert set(data["actions"]) == set(OWN), data["actions"]
on = {k for k, v in data["actions"].items() if v}
# Mail is not configured, no PIN, no passkeys, no app passwords, no services; TOTP is off, so no recovery codes.
assert on == {"username", "password", "totp", "api_keys", "sessions", "programs"}, on
assert data["actions"]["password"] == f"{BASE}/auth/act/password", data["actions"]
view = auth.account_overview(auth.get_user(ann), app_host=APP_HOST)
assert view["actions"]["sessions"] == f"{BASE}/auth/act/sessions?app={APP_HOST}", view["actions"]
assert c.get("/auth/act/nope").status_code == 404
assert c.get("/auth/act/account").status_code == 404
ok("A. the register: every own action is a member of account.json `actions` — its page in the application's frame "
   "where offered, null where not; an unknown name is 404")

# ── B. signed out ────────────────────────────────────────────────────────────────────────────────────────────────────
anon = TestClient(app, base_url=BASE, follow_redirects=False)
url = f"/auth/act/password?app=docs&return=https%3A%2F%2F{APP_HOST}%2Fsettings&state=s-1"
r = anon.get(url)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login?next="), r.headers
nxt = unquote(r.headers["location"].split("next=", 1)[1])
assert urlsplit(nxt).path == "/auth/act/password" and query(nxt) == {
    "app": "docs", "return": f"https://{APP_HOST}/settings", "state": "s-1"}, nxt
key = auth.create_api_key(ann, "probe")
key = key[0] if isinstance(key, tuple) else (key.get("key") if isinstance(key, dict) else key)
r = anon.get(url, headers={"X-API-Key": key})
assert r.status_code == 303 and "/auth/login" in r.headers["location"], "an API key is no person by browser"
ok("B. signed out (or by API key): the sign-in page first, back to the same address with frame, return and state")

# ── C. the page ──────────────────────────────────────────────────────────────────────────────────────────────────────
audit_before = len(auth.store.recent_audit(500))
r = c.get(f"/auth/act/password?app=docs&return=https%3A%2F%2F{APP_HOST}%2Fsettings&state=s-1")
assert r.status_code == 200, r.status_code
html = r.text
assert "frame-ancestors 'none'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
assert "<div class=area-app>" in html and "<span>Documents</span></div><h1>Password</h1>" in html, html[:3000]
assert "tsframe" in html, "the page stands in the application's frame"
assert "<input id=pw_cur" in html and "<input id=pw_new" in html
assert "<input id=pin_new" not in html and "<input id=key_name" not in html and "id=sesslist" not in html
nonce = re.search(r"'nonce-([^']+)'", r.headers["content-security-policy"]).group(1)
for tag in re.findall(r"<(?:script|style)\b[^>]*>", html):
    assert f'nonce="{nonce}"' in tag or f"nonce={nonce}" in tag, tag
markup = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.S)
assert " style=" not in markup and not re.search(r"<[^>]*\son[a-z]+=", markup), "no style= and no inline handler"
assert len(auth.store.recent_audit(500)) == audit_before, "a GET of an action page writes nothing"
r = c.get("/auth/act/api_keys?app=docs")
assert "<input id=key_name" in r.text and "<input id=pw_cur" not in r.text
r = c.get("/auth/act/programs?app=docs")
assert "id=devlist" in r.text and "id=pcsec" not in r.text      # pairing is off in this installation
ok("C. the page: heading in the application's name, the frame, only the action's sections, never framed, the nonce "
   "on every script and style; a GET writes nothing")

# ── D. the way back ──────────────────────────────────────────────────────────────────────────────────────────────────
href, state, done = back(html)
assert state == "cancelled" and href == (f"https://{APP_HOST}/settings?ts_action=password&ts_result=cancelled"
                                         "&state=s-1"), href
assert done == f"https://{APP_HOST}/settings?ts_action=password&ts_result=done&state=s-1", done
r = c.get("/auth/act/password", params={"app": "docs", "return": f"https://{APP_HOST}/app?ts_result=done&x=1#/sec",
                                        "state": "a b"})
href, _, done = back(r.text)
assert href == f"https://{APP_HOST}/app?x=1&ts_action=password&ts_result=cancelled#/sec", href
for bad in ("https://evil.example/", f"https://{OTHER}/", "/start", f"https://ann@{APP_HOST}/",
            "javascript:alert(1)", f"//{APP_HOST}/"):
    href, _, done = back(c.get("/auth/act/password", params={"app": "docs", "return": bad, "state": "s"}).text)
    assert href == done == f"https://{APP_HOST}/start", (bad, href)
href, _, _ = back(c.get("/auth/act/password", params={"app": "docs", "return": f"https://{APP_HOST}/",
                                                      "state": "x" * 129}).text)
assert "state=" not in href, href
lib, lib_app = make(forward_auth_enabled=False, forward_apps={}, apps={}, oauth_enabled=False)
lu = int(lib.create_user("lu", password=PW))
lc = session(lib, lib_app, lu)
href, _, _ = back(lc.get("/auth/act/password", params={"return": "/settings", "state": "k"}).text)
assert href == "/settings?ts_action=password&ts_result=cancelled&state=k", href
href, _, _ = back(lc.get("/auth/act/password", params={"return": "https://evil.example/"}).text)
assert href == "/auth/account", href
ok("D. the way back: ts_action/ts_result/state on a valid return (before a fragment, old values replaced); a foreign "
   "host, another host than the frame's, a path in a frame, a user part, javascript: and a bad state are replaced or "
   "dropped; a library's path is the way back, its fallback the account page")

# ── E. step-up and not offered ───────────────────────────────────────────────────────────────────────────────────────
stale = session(auth, app, ann, age=4000)
r = stale.get("/auth/act/totp?app=docs&state=t")
assert r.status_code == 303 and r.headers["location"].startswith("/auth/reauth?next="), r.headers
assert unquote(r.headers["location"].split("next=", 1)[1]) == "/auth/act/totp?app=docs&state=t"
assert stale.get("/auth/act/password?app=docs").status_code == 200, "password proves the current one itself"
assert stale.get("/auth/act/sessions?app=docs").status_code == 200
r = stale.get("/auth/act/pin?app=docs&return=https%3A%2F%2Fdocs.example.com%2F")
assert r.status_code == 200 and "This is not offered here." in r.text and "<input id=pin_new" not in r.text
href, state, _ = back(r.text)
assert state == "unavailable" and query(href)["ts_result"] == "unavailable", href
ok("E. class window: a stale confirmation goes to the reauth page and back for a `fresh` action, an action without "
   "`fresh` opens directly; not offered: the page says so, the way back says unavailable")

# ── F. done ──────────────────────────────────────────────────────────────────────────────────────────────────────────
r = c.get(f"/auth/act/password?app=docs&return=https%3A%2F%2F{APP_HOST}%2F&ts_done=1")
href, state, _ = back(r.text)
assert state == "done" and query(href)["ts_result"] == "done", href
r = c.get(f"/auth/act/totp?app=docs&return=https%3A%2F%2F{APP_HOST}%2F")
setup = re.search(r"href='(/auth/totp/setup[^']*)'", r.text).group(1).replace("&amp;", "&")
target = query(setup)["next"]
assert urlsplit(target).path == "/auth/act/totp" and query(target) == {
    "app": "docs", "return": f"https://{APP_HOST}/", "ts_done": "1"}, target
now = int(time.time())
auth.store.oauth_add_client("probe-cli", "Probe CLI", ["http://127.0.0.1/cb"], now, "192.0.2.1")
grant = auth.store.oauth_create_grant("probe-code", "probe-cli", ann, f"https://{APP_HOST}/mcp", "mcp", now,
                                      "192.0.2.1", now + 3600, [("probe-token-hash", "refresh", "mcp", now + 3600)])
r = c.get("/auth/act/programs?app=docs")
nxt = re.search(r"name=next value='([^']*)'", r.text).group(1).replace("&amp;", "&")
assert nxt == "/auth/act/programs?app=docs&ts_done=1", nxt
csrf = c.cookies.get(auth.csrf_cookie_name)
r = c.post(f"/auth/oauth/devices/{grant}/revoke", data={"_csrf": csrf, "next": nxt})
assert r.status_code == 303 and r.headers["location"] == nxt, r.headers
assert auth.store.oauth_grant(grant)["revoked_at"], "the program is revoked"
for bad in (f"https://{APP_HOST}/", "//evil.example/", "/\\evil.example"):
    r = c.post("/auth/oauth/devices/999/revoke", data={"_csrf": csrf, "next": bad})
    assert r.headers["location"] == "/auth/account", (bad, r.headers)
ok("F. done: ts_done=1 starts the way back as done; the TOTP setup and a program's revocation come back to the action "
   "page marked done — the revocation only to a path of TinySesam")

# ── G. the account page ──────────────────────────────────────────────────────────────────────────────────────────────
auth.store.oauth_create_grant("probe-code-2", "probe-cli", ann, f"https://{APP_HOST}/mcp", "mcp", now, "192.0.2.1",
                              now + 3600, [("probe-token-hash-2", "refresh", "mcp", now + 3600)])
r = c.get("/auth/account?app=docs")
for marker in ("<input id=un_new", "<input id=pw_cur", "id=totp>", "<input id=key_name", "id=sesslist", "id=devlist",
               "id=eventlist"):
    assert marker in r.text, marker
assert f"name=next value='/auth/account?app={APP_HOST}'" in r.text, "a revocation comes back into the frame"
ok("G. the account page still shows every section and leads a revocation back into its frame")

print("OK test_action_pages")

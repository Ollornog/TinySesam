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
  F. Done: `ts_done=1` starts the way back as `done`; the setup of TOTP comes back to the action page marked as done;
     a program's revocation is sent by the page's script (the browser test sees the rest).
  G. The account page still shows every section.
  H. The session handle (schema 29): every session has one, it survives a rotation, `account.json` names it with the
     action page that ends that one session (not the current one); `POST /auth/sessions/end` wants a fresh
     confirmation, ends only an own other session (with its superseded tokens) and audits it; the action page
     `session_end` shows that session, anything else is "not offered"; a schema-28 file gets handles at the start.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from html.parser import HTMLParser
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
       "sessions", "session_end", "programs", "services")


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
assert set(data["actions"]) == set(OWN) - {"session_end"}, data["actions"]
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


class Tags(HTMLParser):
    """Every start tag of the page with its attributes — read by a parser, not by a pattern over the markup."""

    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


parsed = Tags()
parsed.feed(html)
assert all(a.get("nonce") == nonce for t_, a in parsed.tags if t_ in ("script", "style")), "a block without the nonce"
assert sum(1 for t_, _ in parsed.tags if t_ == "script") >= 2
assert not any("style" in a or any(k.startswith("on") for k in a) for _, a in parsed.tags), "style= or a handler"
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
assert f"action='/auth/oauth/devices/{grant}/revoke'" in r.text and "closest('form.devrevoke')" in r.text, "by script"
csrf = c.cookies.get(auth.csrf_cookie_name)
r = c.post(f"/auth/oauth/devices/{grant}/revoke", data={"_csrf": csrf})
assert r.status_code == 303 and auth.store.oauth_grant(grant)["revoked_at"], "the program is revoked"
ok("F. done: ts_done=1 starts the way back as done; the TOTP setup comes back to the action page marked done; a "
   "program's revocation is sent by the page's script, which then marks the way back as done")

# ── G. the account page ──────────────────────────────────────────────────────────────────────────────────────────────
auth.store.oauth_create_grant("probe-code-2", "probe-cli", ann, f"https://{APP_HOST}/mcp", "mcp", now, "192.0.2.1",
                              now + 3600, [("probe-token-hash-2", "refresh", "mcp", now + 3600)])
r = c.get("/auth/account?app=docs")
for marker in ("<input id=un_new", "<input id=pw_cur", "id=totp>", "<input id=key_name", "id=sesslist", "id=devlist",
               "id=eventlist"):
    assert marker in r.text, marker
ok("G. the account page still shows every section")

# ── H. the session handle ────────────────────────────────────────────────────────────────────────────────────────────
import sqlite3  # noqa: E402

bo = int(auth.create_user("bo", password=PW))
me = session(auth, app, bo)
phone = session(auth, app, bo)
items = me.get("/auth/account.json").json()["sessions"]["items"]
assert len(items) == 2 and all(re.fullmatch(r"[0-9a-f]{32}", i["handle"]) for i in items), items
mine_ = next(i for i in items if i["current"] is True)
other = next(i for i in items if i["current"] is False)
assert mine_["end"] is None and other["end"] == f"{BASE}/auth/act/session_end?target={other['handle']}", items
view = auth.account_overview(auth.get_user(bo), app_host=APP_HOST)
assert all(i["end"].startswith(f"{BASE}/auth/act/session_end?app={APP_HOST}&target=") for i in view["sessions"]["items"])
assert [s_["handle"] for s_ in me.get("/auth/sessions").json() if not s_["current"]] == [other["handle"]]
# A rotation keeps the handle (the session stays the same for the person), also with the grace period.
phone_tok = phone.cookies.get(auth.session_cookie_name)
auth.store.rotate_session(auth.store.session_hash(phone_tok), mercy_sec=60)
again = [i["handle"] for i in me.get("/auth/account.json").json()["sessions"]["items"]]
assert sorted(again) == sorted([mine_["handle"], other["handle"]]), (again, items)
# Ending: fresh only, never the current one, never another account's, then gone with its superseded token.
me.get("/auth/account")
JSONH = {"X-CSRF-Token": me.cookies.get(auth.csrf_cookie_name)}
stale_bo = session(auth, app, bo, age=4000)
stale_bo.get("/auth/account")
r = stale_bo.post("/auth/sessions/end", json={"handle": other["handle"]},
                   headers={"X-CSRF-Token": stale_bo.cookies.get(auth.csrf_cookie_name)})
assert r.status_code == 403 and r.headers.get("x-tinysesam-reauth"), (r.status_code, r.text)
ann_handle = next(i["handle"] for i in c.get("/auth/account.json").json()["sessions"]["items"] if i["current"])
assert me.post("/auth/sessions/end", json={"handle": ann_handle}, headers=JSONH).status_code == 404
assert me.post("/auth/sessions/end", json={"handle": "0" * 32}, headers=JSONH).status_code == 404
assert me.post("/auth/sessions/end", json={"handle": mine_["handle"]}, headers=JSONH).status_code == 400
assert c.get("/auth/account.json").status_code == 200, "ann's session is untouched"
r = c.get(f"/auth/act/session_end?app=docs&target={other['handle']}")       # ann: the handle is bo's, not hers
assert "This is not offered here." in r.text and "data-act=endsess" not in r.text
r = me.get(f"/auth/act/session_end?app=docs&target={other['handle']}&return=https%3A%2F%2F{APP_HOST}%2F")
assert f"data-act=endsess data-id='{other['handle']}'" in r.text and "<span>Documents</span></div><h1>End a session" \
    in r.text, r.text[-2500:]
for bad in (mine_["handle"], "", "nope"):
    assert "This is not offered here." in me.get(f"/auth/act/session_end?target={bad}").text, bad
before = len([a for a in auth.store.recent_audit(500) if a["event"] == "session_end"])
assert me.post("/auth/sessions/end", json={"handle": other["handle"]}, headers=JSONH).json() == {"ok": True}
assert phone.get("/auth/account.json").status_code == 401, "the phone is signed out"
assert auth.store.get_session(phone_tok) is None, "its superseded token went with it"
assert len([a for a in auth.store.recent_audit(500) if a["event"] == "session_end"]) == before + 1
assert me.get("/auth/account.json").json()["sessions"]["count"] == 2      # me + the stale probe session
# The step 28 → 29: a schema-28 file (made by this version, the step's objects dropped, stamped back) with a session.
old_dir = tempfile.mkdtemp()
old = os.path.join(old_dir, "s28.db")
a28 = TinySesam(TinySesamConfig(db_path=old, passkey_enabled=False))
uid28 = int(a28.create_user("old", password=PW))
a28.start_session(uid28, "password")
a28.store.close()
raw = sqlite3.connect(old)
raw.execute("DROP TRIGGER trg_session_handle")
raw.execute("DROP TABLE session_handle")
raw.execute("PRAGMA user_version = 28")
raw.commit()
raw.close()
a29 = TinySesam(TinySesamConfig(db_path=old, passkey_enabled=False))
rows = a29.store.list_sessions(uid28)
assert len(rows) == 1 and re.fullmatch(r"[0-9a-f]{32}", rows[0]["public_handle"] or ""), [dict(x) for x in rows]
assert int(a29.store.db.execute("PRAGMA user_version").fetchone()[0]) == 29
a29.start_session(uid28, "password")
handles = {x["public_handle"] for x in a29.store.list_sessions(uid28)}
assert len(handles) == 2 and None not in handles, handles
a29.store.close()
ok("H. the session handle: one per session, kept through a rotation, named in account.json with the page that ends it "
   "(not the current one); ending wants a fresh confirmation, ends only an own other session with its superseded "
   "token and audits it; the action page shows that session, anything else is not offered; a schema-28 file gets "
   "handles at the start")

print("OK test_action_pages")

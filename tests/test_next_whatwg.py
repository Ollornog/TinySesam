"""Attack round B (2026-11-21): open redirect through `next` where a page script follows it.

`security.safe_next()` reads the target the way Python's `urlsplit` does. The browser reads it by the WHATWG URL
standard, which first removes every ASCII tab and newline and treats `\\` like `/` in http(s) URLs:

* `/\\t/evil.example` passes as a relative path — the browser makes it `//evil.example`;
* `https://evil.example\\@app.example.com/` passes because `urlsplit` sees host `app.example.com` — the browser
  sees host `evil.example`.

In a `Location` header Starlette percent-encodes both characters, so the redirects of the forms are safe. But
several pages take the target from a JSON answer and set `location.href` themselves: passkey sign-in
(`redirect`), TOTP setup (`next`), setup pass and onboarding (`next`). A link to the real sign-in page with
such a `next` ends on the attacker's page right after a successful sign-in or setup (ASVS 3.7.2) — a good
spot for a fake "session expired, password again" page.
"""
import os
import re
import sys
import tempfile
import time
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, security

BASE = "https://auth.example.com/auth/totp/setup"
HOSTS = ["auth.example.com", "app.example.com"]


def ok(name):
    print(f"  ✓ {name}")


def browser_host(target: str) -> str:
    """The host a browser navigates to for `location.href = target` on BASE (WHATWG: tab/newline removed,
    backslash = slash in http(s))."""
    cleaned = re.sub(r"[\t\n\r]", "", target).replace("\\", "/")
    return (urlsplit(urljoin(BASE, cleaned)).hostname or "").lower()


# The helper itself must see the difference, or the checks below prove nothing.
assert browser_host("/account") == "auth.example.com"
assert browser_host("/\t/evil.example/x") == "evil.example"
assert browser_host("https://evil.example\\@app.example.com/") == "evil.example"

for target in ("/\t/evil.example/", "/\n/evil.example/", "/\r/evil.example/",
               "https://evil.example\\@app.example.com/", "https://evil.example\t\\@app.example.com/"):
    kept = security.safe_next(target, "/fallback", HOSTS)
    assert browser_host(kept) in HOSTS, (
        f"safe_next({target!r}) kept {kept!r} — a browser follows that to {browser_host(kept)!r}")
ok("safe_next does not keep a target that a browser resolves to a foreign host")

# The fix's own rules: control characters and backslashes anywhere, a user part in an absolute target, a port that is
# no number — each falls back. Ordinary targets stay.
for target in ("/a\x01b", "/a\x7fb", "/a\\b", "https://app.example.com/a\tb", "https://x@app.example.com/",
               "https://app.example.com:x/"):
    assert security.safe_next(target, "/fallback", HOSTS) == "/fallback", target
for target in ("/account?x=1#y", "https://app.example.com/a?b=c", "https://app.example.com:8443/", " /padded "):
    assert security.safe_next(target, "/fallback", HOSTS) == target.strip(), target
ok("control characters, backslashes, a user part and a broken port fall back; ordinary targets stay")

# End to end: the TOTP setup page follows `next` from its JSON answer with `location.href`.
auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
    oidc_enabled=False, cookie_secure=False, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com"]))
uid = auth.create_user("dora", password="a long probe password 4711")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)
c.post("/auth/login", data={"username": "dora", "password": "a long probe password 4711", "next": "/"},
       follow_redirects=False)
evil = "/\t/evil.example/session-expired"
r = c.post("/auth/totp/setup/start", data={"next": evil})
assert r.status_code == 200, r.status_code
secret = re.search(r"\b([A-Z2-7]{32})\b", r.text).group(1)
r = c.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret).at(time.time() - 30), "next": evil})
assert r.status_code == 200 and r.json()["ok"], r.text
nxt = r.json()["next"]
assert browser_host(nxt) in HOSTS, (
    f"the TOTP setup answers next={nxt!r}; its page sets location.href to it and the browser goes to "
    f"{browser_host(nxt)!r}")
ok("the TOTP setup does not hand its page a target on a foreign host")

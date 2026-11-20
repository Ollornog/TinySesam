"""App passwords (T-66): Basic auth at the gate for clients without a browser — WebDAV, CalDAV/CardDAV, Git.

Every protection rule has its own check here, each with the mutation that turns it red (in the comment next to it).
The end-to-end run with a real WebDAV client behind a real Caddy is `tests/test_app_passwords_e2e.py`.
"""
import base64
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, security
from tinysesam import app_passwords as AP
from tinysesam import config_check
from tinysesam import keys as K

DAV, GIT, WEB = "dav.example.com", "git.example.com", "web.example.com"
IP = "203.0.113.7"


def ok(name):
    print(f"  ✓ {name}")


class _Recording:
    """The lines of the security log in the format of the shipped file (as in test_security_log.py)."""

    def __enter__(self):
        self.buffer = io.StringIO()
        self.handler = logging.StreamHandler(self.buffer)
        self.handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        security.seclog.addHandler(self.handler)
        return self

    def __exit__(self, *_):
        security.seclog.removeHandler(self.handler)

    def lines(self):
        return [z for z in self.buffer.getvalue().splitlines() if z.strip()]


def _jail():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "deploy", "fail2ban", "tinysesam-filter.conf"), encoding="utf-8") as f:
        line = next(z for z in f if z.startswith("failregex"))
    return re.compile(line.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)"))


JAIL = _jail()


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
               passkey_enabled=False, oidc_enabled=False, cookie_secure=False, base_url="https://auth.example.com",
               forward_auth_enabled=True, trusted_redirect_hosts=[DAV, GIT, WEB], trusted_proxies=["127.0.0.1/32"],
               stepup_max_age_sec=900,
               forward_apps={DAV: {"name": "Files", "app_passwords": True},
                             GIT: {"name": "Git", "app_passwords": True},
                             WEB: {"name": "Web"}})
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid, *, age=0):
    """A full session for `uid` whose sign-in and last confirmation lie `age` seconds back."""
    c = TestClient(app, client=("198.51.100.20", 1))
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


def proxy(host, auth_header=None, browser=False, uri="/remote.php/dav/"):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host, "X-Forwarded-Uri": uri,
         "X-Forwarded-For": IP}
    if auth_header:
        h["Authorization"] = auth_header
    if browser:
        h["Sec-Fetch-Mode"] = "navigate"
        h["Accept"] = "text/html"
    return h


def fails(auth, method="app_password", ip=None):
    return auth.store.count_fails(0, username="alice", ip=ip, method=method)


# ---------- the format ----------
pw = AP.generate()
assert re.fullmatch(r"([2-9a-hj-km-np-z]{5}-){4}[2-9a-hj-km-np-z]{5}", pw), pw
assert AP.normalize(pw) == pw.replace("-", "")
assert AP.normalize(pw.upper()) == AP.normalize(pw.replace("-", " ")) == AP.normalize(pw.replace("-", ""))
assert AP.normalize("Correct-Horse-Battery-Staple-1") is None, "the main password is never an app password"
assert AP.normalize(pw + "2") is None and AP.normalize(pw[:-1]) is None
assert AP.normalize(pw[:-1] + "0") is None, "0, o, 1, l, i are not in the alphabet"
assert len(set(AP.generate() for _ in range(200))) == 200
assert len(AP.ALPHABET) == 31 and not set("01oli") & set(AP.ALPHABET)
assert AP.parse_basic(basic("al:ice", "x")) == ("al", "ice:x"), "the user ends at the first colon"
assert AP.parse_basic(basic("alice", "p:w")) == ("alice", "p:w")
assert AP.parse_basic("Basic !!!") is None and AP.parse_basic("Bearer abc") is None
assert AP.parse_basic("Basic " + base64.b64encode(b"nocolon").decode()) is None
assert AP.parse_basic(basic("a\nb", "x")) is None, "control characters in the user name"
assert AP.challenge('Fi"les') == 'Basic realm="Fi\\"les", charset="UTF-8"'
ok("format: 5×5 from 31 symbols (≈124 bits), case/hyphens ignored, main password never fits; Basic parsing")

# ---------- creation: fresh confirmation, digest only ----------
auth, app = build()
alice = auth.create_user("alice", "Alice-Password-2026", roles=["editors"])
auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (alice,))
bob = auth.create_user("bob", "Bob-Password-2026")
events = []
auth.on_security_event = lambda ev, acc, det: events.append((ev, acc["username"], det))

stale = session_client(auth, app, alice, age=3600)
r = stale.post("/auth/app-passwords", json={"name": "Phone", "hosts": [DAV]})
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), (r.status_code, r.text)
assert auth.list_app_passwords(alice) == []
ok("creation without a fresh confirmation → 403 + reauth, nothing created")
# (Mutation: drop `auth._require_fresh(...)` in app_passwords_create → 200, red.)

key = auth.create_api_key(alice, name="ci")["key"]
r = TestClient(app).post("/auth/app-passwords", json={"name": "Phone", "hosts": [DAV]},
                         headers={"Authorization": f"Bearer {key}"})
assert r.status_code in (401, 403), r.status_code
ok("an API key cannot create an app password")

c = session_client(auth, app, alice)
r = c.post("/auth/app-passwords", json={"name": "Phone calendar", "hosts": [DAV]})
assert r.status_code == 200, r.text
created = r.json()
secret = created["password"]
assert created["hosts"] == [DAV] and created["expires_at"] > time.time() + 364 * 86400
assert created["expires_at"] < time.time() + 366 * 86400, "default: a year (app_password_default_days)"
ok("creation with a fresh session → the password once, valid for the chosen application, a year")

row = auth.store._one("SELECT * FROM app_password WHERE id=?", (created["id"],))
dump = json.dumps({k: row[k] for k in row.keys()})
assert secret not in dump and AP.normalize(secret) not in dump, "plain text in the database"
assert row["digest"] == AP.digest(auth._pepper_keyring.active.material, AP.normalize(secret))
assert row["kid"] == auth._pepper_keyring.active.kid
listed = c.get("/auth/app-passwords")
assert all(not {"password", "digest", "kid"} & set(x) for x in listed.json()) and secret not in listed.text
ok("database holds an HMAC digest with the pepper keyring (ADR-12), never the password; the list neither")
# (Mutation: store `AP.normalize(secret)` as digest → red.)

assert any(e[0] == "app_password_created" and e[1] == "alice" and e[2]["hosts"] == [DAV] for e in events), events
assert "app_password_created" in auth._ACCESS_MAIL_EVENTS
assert [a for a in auth.store.recent_audit(50) if a["event"] == "app_password_create"]
ok("holder notified: event app_password_created (mail via notify_new_access), audit app_password_create")

for body, why in (({"name": "", "hosts": [DAV]}, "no name"), ({"name": "x", "hosts": [WEB]}, "app without switch"),
                  ({"name": "x", "hosts": []}, "no app"), ({"name": "x", "hosts": [DAV], "expires_days": 0},
                                                            "no expiry without permission"),
                  ({"name": "x", "hosts": [DAV], "expires_days": 4000}, "too long"),
                  ({"name": "x"}, "two apps take app passwords — the holder chooses")):
    r = c.post("/auth/app-passwords", json=body)
    assert r.status_code == 400, (why, r.status_code, r.text)
ok("refused at creation: no name, app without switch, no app, no expiry, > 10 years, no choice among several")

# ---------- the gate ----------
gate = TestClient(app, client=("127.0.0.1", 1))
r = gate.get("/auth/forward", headers=proxy(DAV, basic("alice", secret)))
assert r.status_code == 200, (r.status_code, r.headers)
assert r.headers["Remote-User"] == "alice" and "editors" in r.headers["Remote-Groups"]
assert "admin" not in r.headers["Remote-Groups"].split(","), r.headers["Remote-Groups"]
assert "X-TinySesam-Gate-Cookie" not in r.headers
ok("app password at its application → 200 + Remote-* like a session, no gate cookie")

r = gate.get("/auth/forward?roles=admin", headers=proxy(DAV, basic("alice", secret)))
assert r.status_code == 403, r.status_code
r = gate.get("/auth/forward?roles=editors", headers=proxy(DAV, basic("alice", secret.upper().replace("-", ""))))
assert r.status_code == 200, r.status_code
ok("never admin: an admin's app password carries no admin flag (role admin → 403, no `admin` group)")
# (Mutation: drop `d["is_admin"] = 0` in _app_password_user → 200 and `admin` in Remote-Groups, red.)

r = gate.get("/auth/forward", headers=proxy(DAV, basic("ALICE", secret)))
assert r.status_code == 200, "the name is looked up like at sign-in"
r = gate.get("/auth/forward", headers=proxy(DAV, basic("bob", secret)))
assert r.status_code == 401
ok("bound to its account: another user name with the same password → 401")

before = fails(auth)
with _Recording() as m:
    r = gate.get("/auth/forward", headers=proxy(DAV, basic("alice", "Alice-Password-2026")))
assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith('Basic realm="Files"'), r.headers
assert r.headers["X-TinySesam-Reason"] == "basic"
assert fails(auth) == before + 1
line = next(z for z in m.lines() if "method=app_password" in z)
assert JAIL.search(line) and JAIL.search(line).group("host") == IP, line
ok("main password by Basic → 401 Basic challenge, booked, `failed login … method=app_password` (fail2ban)")
# (Mutation: in _app_password_user look up the account's password hash when `normalized is None` → 200, red.)

r = gate.get("/auth/forward", headers=proxy(GIT, basic("alice", secret)))
assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith('Basic realm="Git"')
ok("app password at another application that takes app passwords → 401")
# (Mutation: drop `if host in hosts:` → 200, red.)

before = fails(auth)
r = gate.get("/auth/forward", headers=proxy(WEB, basic("alice", secret)))
assert r.status_code == 401 and "Remote-User" not in r.headers
assert r.headers["WWW-Authenticate"] == 'FormBased realm="TinySesam"', r.headers
assert fails(auth) == before, "nothing looked at, nothing booked"
r = gate.get("/auth/forward", headers=proxy(WEB))
assert r.headers["WWW-Authenticate"] == 'FormBased realm="TinySesam"'
ok("application without the switch: Basic ignored, no Basic challenge (as before)")
# (Mutation: `app_pw = bool(app_password_hosts)` without the per-app check → 200, red.)

r = gate.get("/auth/forward", headers=proxy(DAV))
assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Basic ")
assert r.headers.get("X-TinySesam-Location"), "an old proxy template still redirects"
r = gate.get("/auth/forward", headers=proxy(DAV, browser=True))
assert r.status_code == 401 and r.headers["WWW-Authenticate"] == 'FormBased realm="TinySesam"'
r = gate.get("/auth/forward", headers={**proxy(DAV), "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"})
assert r.headers["WWW-Authenticate"] == 'FormBased realm="TinySesam"', "a browser's fetch gets no dialog"
ok("WWW-Authenticate: Basic only at applications with the switch, only for clients without a browser")

# Under an OAuth resource (T-36) on the same host, a client without credentials still learns where to get a token.
auth_o, app_o = build(oauth_enabled=True, csrf_enabled=True, oauth_resources=[f"https://{DAV}/mcp"])
go = TestClient(app_o, client=("127.0.0.1", 1))
r = go.get("/auth/forward", headers=proxy(DAV, uri="/mcp"))
assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer "), r.headers
r = go.get("/auth/forward", headers=proxy(DAV, basic("alice", "x"), uri="/mcp"))
assert r.headers["WWW-Authenticate"].startswith("Basic "), "a refused Basic attempt is answered with Basic"
r = go.get("/auth/forward", headers=proxy(DAV, uri="/files/"))
assert r.headers["WWW-Authenticate"].startswith("Basic "), r.headers
ok("OAuth resource on the same host: Bearer challenge without credentials, Basic only after a Basic attempt")

# A session still wins: the browser of the holder is not asked for Basic.
r = c.get("/auth/forward", headers=proxy(DAV, browser=True))
assert r.status_code == 200 and r.headers["Remote-User"] == "alice" and "admin" in r.headers["Remote-Groups"]
ok("a full session at the same application stays a session (admin as before)")

# ---------- revoked, expired ----------
second = auth.create_app_password(alice, "Laptop", hosts=[DAV, GIT])
assert gate.get("/auth/forward", headers=proxy(GIT, basic("alice", second["password"]))).status_code == 200
before = fails(auth)
r = c.post(f"/auth/app-passwords/{second['id']}/revoke", json={})
assert r.status_code == 200
assert gate.get("/auth/forward", headers=proxy(GIT, basic("alice", second["password"]))).status_code == 401
assert fails(auth) == before, "a known, revoked app password is no guess — not booked"
assert auth.store.recent_audit(5, username="alice")[0]["event"] == "app_password_denied"
assert any(e[0] == "app_password_revoked" for e in events)
r = session_client(auth, app, bob).post(f"/auth/app-passwords/{created['id']}/revoke", json={})
assert r.status_code == 404, "bob cannot revoke alice's"
ok("revoked → 401 at once (not booked, audited); only the holder revokes on the account page")
# (Mutation: drop the `revoked_at` branch → 200, red.)

third = auth.create_app_password(alice, "Old", hosts=[DAV])
auth.store._exec("UPDATE app_password SET expires_at=? WHERE id=?", (int(time.time()) - 1, third["id"]))
assert gate.get("/auth/forward", headers=proxy(DAV, basic("alice", third["password"]))).status_code == 401
assert [p for p in auth.list_app_passwords(alice) if p["id"] == third["id"]][0]["expired"]
ok("expired → 401")
# (Mutation: drop the `expires_at` branch → 200, red.)

# ---------- lockout: own bucket ----------
auth2, app2 = build()
uid2 = auth2.create_user("alice", "Alice-Password-2026")
pw2 = auth2.create_app_password(uid2, "Phone", hosts=[DAV])["password"]
g2 = TestClient(app2, client=("127.0.0.1", 1))
limit = auth2._sec("max_login_attempts")
for _ in range(limit):
    assert g2.get("/auth/forward", headers=proxy(DAV, basic("alice", AP.generate()))).status_code == 401
with _Recording() as m:
    r = g2.get("/auth/forward", headers=proxy(DAV, basic("alice", pw2)))
assert r.status_code == 401, "locked: even the right app password waits for the window"
assert any("reason=lockout_app_password" in z and JAIL.search(z) for z in m.lines()), m.lines()
assert not auth2._is_locked("alice", IP), "the browser sign-in of the account stays open"
assert auth2.store.failure_series("alice") == 0, "no streak (B2-6) from app-password guesses"
login = TestClient(app2, client=(IP, 1)).post("/auth/login", data={"username": "alice",
                                                                  "password": "Alice-Password-2026"},
                                              follow_redirects=False)
assert login.status_code == 303, login.status_code
r = g2.get("/auth/forward", headers={**proxy(DAV, basic("alice", pw2)), "X-Forwarded-For": "198.51.100.99"})
assert r.status_code == 200, "another address is not in the pair bucket"
ok(f"lockout after {limit} guesses per account and address, own bucket: sign-in and streak untouched")
# (Mutation: remove "app_password" from security.SIGN_IN_OWN_LOCK → the login lockout counts the guesses, red.
#  Mutation: drop the `_is_app_password_locked` check on the success path → 200, red.)

# ---------- revocation with the API keys ----------
auth3, app3 = build(admin_require_mfa=False)
admin = auth3.create_user("root", "Root-Password-2026x")
auth3.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (admin,))
a3 = auth3.create_user("alice", "Alice-Password-2026")
ev3 = []
auth3.on_security_event = lambda ev, acc, det: ev3.append((ev, det))


def valid(pw, host=DAV):
    return TestClient(app3, client=("127.0.0.1", 1)).get(
        "/auth/forward", headers=proxy(host, basic("alice", pw))).status_code == 200


p1 = auth3.create_app_password(a3, "one", hosts=[DAV])["password"]
r = session_client(auth3, app3, a3).post("/auth/password", json={"current": "Alice-Password-2026",
                                                                  "new": "Alice-Password-2027"})
assert r.status_code == 200 and r.json()["app_passwords_active"] == 1, r.text
assert valid(p1), "the own password change keeps them (and names how many)"
r = session_client(auth3, app3, a3).post("/auth/sessions/revoke", json={"scope": "others"})
assert r.json()["app_passwords_active"] == 1 and valid(p1)
ok("own password change and \"end other sessions\": app passwords stay, the answer names the count")

r = session_client(auth3, app3, a3).post("/auth/sessions/revoke", json={"scope": "all"})
assert r.status_code == 200 and not valid(p1)
assert ("app_passwords_revoked", {"count": 1, "reason": "sessions_revoked"}) in ev3, ev3
ok("\"sign out everywhere\" revokes them (event app_passwords_revoked)")

p2 = auth3.create_app_password(a3, "two", hosts=[DAV])["password"]
panel = session_client(auth3, app3, admin)
r = panel.post(f"/auth/admin/api/users/{a3}/password", json={"password": "Fresh-Start-2026x"})
assert r.status_code == 200, r.text
assert not valid(p2)
ok("password reset by an administrator revokes them")

p3 = auth3.create_app_password(a3, "three", hosts=[DAV])["password"]
r = panel.post(f"/auth/admin/api/users/{a3}/disable", json={"disabled": True})
assert r.status_code == 200 and not valid(p3)
panel.post(f"/auth/admin/api/users/{a3}/disable", json={"disabled": False})
assert not valid(p3), "unlocking does not bring them back"
ok("locking the account revokes them (and unlocking does not revive them)")
# (Mutation: drop `self._app_passwords_revoked(...)` in `_keys_revoked` → the three above red.)

# ---------- admin panel ----------
p4 = auth3.create_app_password(a3, "four", hosts=[GIT])
r = panel.get("/auth/admin/api/app-passwords")
assert r.status_code == 200 and any(x["id"] == p4["id"] and x["username"] == "alice" for x in r.json())
assert all(not {"password", "digest", "kid"} & set(x) for x in r.json())
assert p4["password"] not in r.text and AP.normalize(p4["password"]) not in r.text
r = panel.post(f"/auth/admin/api/app-passwords/{p4['id']}/revoke", json={})
assert r.status_code == 200 and r.json()["ok"] and not valid(p4["password"], GIT)
assert session_client(auth3, app3, a3).get("/auth/admin/api/app-passwords").status_code in (401, 403)
ok("admin panel: all accounts' app passwords (no secret), revoke; not for a non-admin")

# ---------- account page and routes only with the switch ----------
page = session_client(auth3, app3, a3).get("/auth/account").text
assert "id=apsec" in page and "name=ap_host value='dav.example.com' checked" in page
assert "name=ap_host value='git.example.com'>" in page, "only the first application is ticked"
auth4, app4 = build(forward_apps={WEB: {"name": "Web"}})
u4 = auth4.create_user("alice", "Alice-Password-2026")
assert "id=apsec" not in session_client(auth4, app4, u4).get("/auth/account").text
assert session_client(auth4, app4, u4).get("/auth/app-passwords").status_code == 404
try:
    auth4.create_app_password(u4, "x")
    raise AssertionError("created without an application that takes app passwords")
except Exception as e:
    assert type(e).__name__ == "ConfigError", e
ok("account page section and routes only when an application takes app passwords")

# ---------- pepper rotation (ADR-12) ----------
auth5, app5 = build()
u5 = auth5.create_user("alice", "Alice-Password-2026")
p5 = auth5.create_app_password(u5, "Phone", hosts=[DAV])
old_kid = auth5._pepper_keyring.active.kid
auth5.store.key_ring_rotate(K.PEPPER, K.new_material(K.PEPPER))

def keys_cli(*args):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if not k.startswith("TINYSESAM_")}
    return subprocess.run([sys.executable, "-m", "tinysesam", "keys", *args, "--db", auth5.cfg.db_path],
                          capture_output=True, text=True, env=env, timeout=120, cwd=root)


# Make the previous pepper old enough that nothing else (OAuth) holds it — only the app password does.
auth5.store._exec("UPDATE key_material SET since=? WHERE purpose=? AND since IS NOT NULL",
                  (int(time.time()) - 86400, K.PEPPER))
out = keys_cli("retire", "--purpose", K.PEPPER)
assert out.returncode == 1 and "app password" in out.stderr, (out.returncode, out.stdout, out.stderr)
auth5b = TinySesam(TinySesamConfig(**{**auth5.cfg.__dict__}))
app5b = FastAPI()
app5b.include_router(auth5b.router())
assert auth5b._pepper_keyring.active.kid != old_kid
assert auth5b.store.app_passwords_with_kid(old_kid, int(time.time())) == 1
r = TestClient(app5b, client=("127.0.0.1", 1)).get("/auth/forward", headers=proxy(DAV, basic("alice", p5["password"])))
assert r.status_code == 200, "found with the previous pepper"
row = auth5b.store.app_password(p5["id"])
assert row["kid"] == auth5b._pepper_keyring.active.kid
assert auth5b.store.app_passwords_with_kid(old_kid, int(time.time())) == 0
out = keys_cli("retire", "--purpose", K.PEPPER)
assert out.returncode == 0 and old_kid in out.stdout, (out.returncode, out.stdout, out.stderr)
ok("pepper rotation: an app password stays valid, moves to the active pepper on its next use; `keys retire` "
   "refuses until then")
# (Mutation: drop the app-password refusal in `keys retire` → exit 0 before the use, red.)

# ---------- configuration ----------
errors, _ = config_check.check_config(TinySesamConfig(forward_auth_enabled=True,
                                                     forward_apps={DAV: {"app_passwords": "yes"}}))
assert any("app_passwords" in x for x in errors), errors
errors, _ = config_check.check_config(TinySesamConfig(forward_auth_enabled=True, app_password_default_days=0,
                                                     forward_apps={DAV: {"app_passwords": True}}))
assert any("app_password_default_days" in x for x in errors), errors
ok("config: forward_apps[host]['app_passwords'] must be True or False")

print("test_app_passwords: all green")

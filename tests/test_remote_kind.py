"""`Remote-Kind: user | service` — what the account is, in the forward-auth answer and the gate token (`ts_kind`).

`Remote-Auth` says how a request signed in; `Remote-Kind` says whether the account is a service account
(`users.is_service`). It is always sent: `forward_headers["kind"]` is a mandatory slot — renamed, never dropped — so a
gate client after spec v2 can fail closed when it is missing. A value of `is_service` that is neither 0 nor 1 is a
403 with a security log line, never a guessed `user`. A gate token carries `ts_kind` whatever `forward_headers` lists;
a service account never gets one (it has no session; the bolt in `_gate_cookie` keeps it so).

The templates are measured in tests/test_remote_auth.py (A6, every default header) and through real proxies in
tests/test_proxies.py and tests/test_gate_caddy.py.
"""
import base64
import importlib.util
import logging
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig, gate, security  # noqa: E402

BASE = "https://auth.example.com"
APP = "app.example.com"
DAV = "dav.example.com"
PW = "a long test password 4711"


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, base_url=BASE, forward_auth_enabled=True,
               trusted_redirect_hosts=[APP, DAV], apikey_enabled=True, gate_token_enabled=True,
               forward_apps={DAV: {"name": "Files", "app_passwords": True}})
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok, _ = auth.start_session(uid, "password")
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def forward(app, headers=None, host=APP, uri="/", client=None):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host, "X-Forwarded-Uri": uri, "X-Forwarded-Method": "GET"}
    h.update(headers or {})
    return (client or TestClient(app, base_url="http://testserver")).get("/auth/forward", headers=h)


def claims_of(auth, response):
    token = response.headers["X-TinySesam-Gate-Cookie"].split(";", 1)[0].split("=", 1)[1]
    return gate.check(base64.b64decode(auth.gate_public_key()), token, aud=APP, iss=BASE, now=int(time.time()))


auth, app = build()
anna = auth.create_user("anna", password=PW, roles=["editors"])
bot = auth.create_service("backup-bot", roles=["editors"])
assert TinySesam.FORWARD_HEADERS_DEFAULT["kind"] == "Remote-Kind"
assert TinySesam.FORWARD_HEADERS_MANDATORY == ("kind",)

# ── a service account's API key → service; every way in of a person → user ─────────────────────────────────────────
bot_key = auth.create_api_key(bot, name="nightly")["key"]
r = forward(app, {"X-Api-Key": bot_key})
assert r.status_code == 200 and r.headers["Remote-Kind"] == "service" and r.headers["Remote-Auth"] == "apikey", \
    (r.status_code, dict(r.headers))
assert "x-tinysesam-gate-cookie" not in {k.lower() for k in r.headers}
ok("a service account's API key → Remote-Kind: service, Remote-Auth: apikey, no gate token")

r = forward(app, client=session_client(auth, app, anna))
assert r.status_code == 200 and r.headers["Remote-Kind"] == "user" and r.headers["Remote-Auth"] == "session"
assert claims_of(auth, r)["ts_kind"] == "user"
for kind in ("automation", "human"):
    k = auth.create_api_key(anna, name=f"k-{kind}", kind=kind)["key"]
    headers = {"X-Api-Key": k}
    c = session_client(auth, app, anna) if kind == "human" else None      # a human key counts only with the session
    r = forward(app, headers, client=c)
    assert r.status_code == 200 and r.headers["Remote-Kind"] == "user", (kind, r.status_code, dict(r.headers))
secret = auth.create_app_password(anna, "Phone calendar", hosts=[DAV])["secret"]
r = forward(app, {"Authorization": "Basic " + base64.b64encode(f"anna:{secret}".encode()).decode()}, host=DAV,
            uri="/remote.php/dav/")
assert r.status_code == 200 and r.headers["Remote-Auth"] == "app-password" and r.headers["Remote-Kind"] == "user"
person = {**dict(auth._as_dict(auth.store.get_user(anna)))}
service = {**dict(auth._as_dict(auth.store.get_user(bot)))}
for via in ("session", "oauth", "apikey", "app_password", "something"):
    assert auth._forward_values(dict(person, _via=via))["kind"] == "user", via
    assert auth._forward_values(dict(service, _via=via))["kind"] == "service", via
ok("a person → user over session (and its gate token), automation and human API key, app password; the value follows "
   "is_service, never the way in (oauth as a person = user, oauth as a service account = service)")

# ── 401/403: no header ─────────────────────────────────────────────────────────────────────────────────────────────
r = forward(app)
assert r.status_code == 401 and "remote-kind" not in {k.lower() for k in r.headers}
ok("no credential → 401 without Remote-Kind")

# ── an unexpected is_service value is refused, never guessed ──────────────────────────────────────────────────────
records = []


class _Catch(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


security.seclog.addHandler(_Catch())
for raw in (2, -1, "1", "0", None, 1.0, b"\x01"):
    try:
        auth._forward_response_headers(dict(person, is_service=raw))
    except HTTPException as e:
        assert e.status_code == 403 and e.detail == auth.t("api.kind_invalid"), (raw, e.detail)
    else:
        raise AssertionError(f"is_service={raw!r} passed")
missing = dict(person)
del missing["is_service"]
try:
    auth._forward_response_headers(missing)
except HTTPException as e:
    assert e.status_code == 403
else:
    raise AssertionError("a missing is_service passed")
assert any("unexpected account kind" in m for m in records), records
assert auth._forward_values(dict(person, is_service=True))["kind"] == "service"
assert auth._forward_values(dict(person, is_service=False))["kind"] == "user"
# Through the route: a value SQLite cannot hold as 0/1 (a type-affinity slip) ends in 403, not in `user`.
auth.store._exec("UPDATE users SET is_service=? WHERE id=?", (7, anna))
r = forward(app, client=session_client(auth, app, anna))
assert r.status_code == 403 and "remote-kind" not in {k.lower() for k in r.headers}, (r.status_code, dict(r.headers))
auth.store._exec("UPDATE users SET is_service=0 WHERE id=?", (anna,))
assert forward(app, client=session_client(auth, app, anna)).headers["Remote-Kind"] == "user"
ok("is_service other than exactly 0/1 (2, '1', None, 1.0, missing) → 403 api.kind_invalid + security log line; "
   "through /auth/forward too")

# ── mandatory slot: an own mapping without kind still sends it; renamed, only the new name ───────────────────────────
auth_o, app_o = build(forward_headers={"user": "Remote-User", "id": "Remote-Id"})
uid_o = auth_o.create_user("anna", password=PW)
r = forward(app_o, client=session_client(auth_o, app_o, uid_o))
names = {k.lower() for k in r.headers}
assert r.headers["Remote-Kind"] == "user" and "remote-auth" not in names and "remote-groups" not in names, names
assert claims_of(auth_o, r)["ts_kind"] == "user" and "ts_auth" not in claims_of(auth_o, r)
auth_r, app_r = build(forward_headers={"user": "Remote-User", "kind": "X-Account-Kind"})
uid_r = auth_r.create_user("anna", password=PW)
r = forward(app_r, client=session_client(auth_r, app_r, uid_r))
assert r.headers["X-Account-Kind"] == "user" and "remote-kind" not in {k.lower() for k in r.headers}, dict(r.headers)
assert claims_of(auth_r, r)["ts_kind"] == "user"
auth_l, app_l = build(forward_headers={"kind": ["Remote-Kind", "X-Account-Kind"]})
uid_l = auth_l.create_user("anna", password=PW)
r = forward(app_l, client=session_client(auth_l, app_l, uid_l))
assert r.headers["Remote-Kind"] == r.headers["X-Account-Kind"] == "user"
for bad in ({"kind": []}, {"kind": ()}, {"kind": ""}, {"kind": "Bad Header"}, {"kind": None}):
    try:
        build(forward_headers=bad)
    except ConfigError as e:
        assert "forward_headers['kind']" in str(e), (bad, e)
    else:
        raise AssertionError(f"forward_headers={bad!r} starts")
ok("forward_headers without kind → Remote-Kind anyway (header and ts_kind); renamed → only that name; a list → both; "
   "{'kind': []} and an empty or invalid name stop the start")

# ── the gate token: ts_kind always, never for a service account ───────────────────────────────────────────────────
_tok_s, _ = auth.start_session(anna, "password")
row = auth.store.get_session(_tok_s)
cookie = auth._gate_cookie(None, dict(person, _via="session"), f"https://{APP}/", [], session=row)
assert cookie and gate.check(base64.b64decode(auth.gate_public_key()), cookie.split(";", 1)[0].split("=", 1)[1],
                             aud=APP, iss=BASE, now=int(time.time()))["ts_kind"] == "user"
# A session row that (impossibly) belongs to the service account: still no gate token.
fake = {"mfa_ok": 1, "user_id": bot}
assert auth._gate_cookie(None, dict(service, _via="session"), f"https://{APP}/", [], session=fake) is None
ok("gate token: ts_kind=user for a session; a service account never gets one, even with a session row")

# ── the vector generator carries the rules (spec v2) ──────────────────────────────────────────────────────────────
spec_gen = importlib.util.spec_from_file_location("_gate_vectors", ROOT / "scripts" / "_gate_vectors.py")
generator = importlib.util.module_from_spec(spec_gen)
spec_gen.loader.exec_module(generator)
assert generator.FORMAT == 2
probe = generator.Probe()
try:
    sent = probe.headers("anna")
    assert sent["Remote-Kind"] == "user", sent
    assert probe.headers("service", "apikey")["Remote-Kind"] == "service"
    assert generator.claims_of(probe.token("anna"))["ts_kind"] == "user"
    assert generator.claims_of(probe.token("anna", fields={"user": "Remote-User"}))["ts_kind"] == "user"
finally:
    probe.close()
ok("vector probe: the server's headers and tokens carry Remote-Kind / ts_kind (format 2)")

"""Paired API keys (ADR-10, T-32): pairing code, RFC 9421 signatures, renew and rotate on login, revocation.

What is measured, end to end through the HTTP routes:

* pairing: the code is single use, expires, is rate-limited, is bound to proof of possession of the key it
  registers, and dies with the account's other open links;
* signatures: a wrong, expired, future, replayed, re-targeted or body-tampered request is 401, as is a
  foreign key, a missing nonce and a request without the layer;
* `renew_on_login` renews only on a completed interactive sign-in of the OWNER, never by using the key,
  never an expired key; `rotate_on_login` marks the key, the client rotates by itself, a request in flight
  survives, the old key dies after the first use of the new one, a lost rotation answer heals;
* lockout, admin password reset and "end all sessions" revoke paired keys; an automation key carries no
  admin flag; bearer keys are unchanged;
* the reference client against a real server (uvicorn, urllib) — pairing, signing, rotation.
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from voraussetzung import braucht_modul                         # noqa: E402
braucht_modul("http_message_signatures", extra="pairing")

from fastapi import Depends, FastAPI, Request                    # noqa: E402
from fastapi.testclient import TestClient                        # noqa: E402

from tinysesam import TinySesam, TinySesamConfig                 # noqa: E402
from tinysesam import _signatures as S                           # noqa: E402
from tinysesam.client import (PairedClient, PairingError, Response, _new_key, _public,  # noqa: E402
                              sign, urllib_transport)
from tinysesam.errors import ConfigError                         # noqa: E402
from _kit.report import Report                                   # noqa: E402

import http_message_signatures as hms                            # noqa: E402
from http_message_signatures import algorithms                   # noqa: E402
from http_message_signatures.structures import CaseInsensitiveDict  # noqa: E402

r = Report("Paired API keys (ADR-10, T-32): pairing, signatures, renew/rotate on login, revocation")
PW = "dummy12345"


def make(install: bool = True, **over):
    d = tempfile.mkdtemp()
    cfg = dict(csrf_enabled=False, db_path=os.path.join(d, "t.db"), passkey_enabled=False, oidc_enabled=False,
               cookie_secure=False, apikey_pairing_enabled=True, base_url="http://testserver")
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.ensure_admin("admin", PW)
    app = FastAPI()
    app.include_router(auth.router())
    if install:
        auth.install_signatures(app)

    @app.get("/who")
    def who(u=Depends(auth.require_user)):
        return {"user": u["username"], "via": u.get("_via"), "admin": bool(u.get("is_admin"))}

    @app.post("/echo")
    async def echo(request: Request, u=Depends(auth.require_user)):
        return {"user": u["username"], "body": (await request.body()).decode()}

    @app.post("/json")
    async def json_route(request: Request, u=Depends(auth.require_user)):
        return {"user": u["username"], "data": await auth.json_body(request)}

    @app.get("/admin-only")
    def admin_only(u=Depends(auth.require_admin)):
        return {"ok": True}
    return auth, app, d


def transport(app):
    """A reference-client transport into the app — its own TestClient, so no session cookie rides along."""
    c = TestClient(app)

    def tr(method, url, headers, body):
        res = c.request(method, url, headers=headers, content=body)
        return Response(res.status_code, {k.lower(): v for k, v in res.headers.items()}, res.content)
    return tr


def login(app, user, pw=PW):
    b = TestClient(app)
    res = b.post("/auth/login", data={"username": user, "password": pw, "next": "/"}, follow_redirects=False)
    assert res.status_code in (302, 303), (user, res.status_code, res.text[:200])
    return b


def raw_sign(key, method, url, body=b"", *, created=None, nonce="n-" + "x" * 10, keyid=None, tag=S.TAG,
             with_digest=True, extra_headers=None, components=("@method", "@target-uri")):
    """Sign like the client, but with every parameter in the test's hand."""
    class Keys:
        def resolve_private_key(self, _):
            return key

    class Msg:
        def __init__(self):
            self.method, self.url = method, url
            self.headers = CaseInsensitiveDict(extra_headers or {})
    m = Msg()
    signer = hms.HTTPMessageSigner(signature_algorithm=algorithms.ED25519, key_resolver=Keys())
    kw = {}
    if nonce is not None:
        kw["nonce"] = nonce
    if tag is not None:
        kw["tag"] = tag
    signer.sign(m, key_id=keyid or S.thumbprint(S.unb64u(_public(key))),
                created=created or datetime.datetime.now(datetime.timezone.utc),
                covered_component_ids=components, body=(body if (body and with_digest) else None),
                **kw)
    return dict(m.headers.items())


def jload(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def db_set(auth, sql, args=()):
    auth.store.db.execute(sql, args)
    auth.store.db.commit()


def key_row(auth, kid):
    return auth.store.get_api_key(kid)


def pair(app, auth, uid, kf, **terms):
    code = auth.create_pairing_code(uid, **terms)["code"]
    return PairedClient.pair("http://testserver", code, kf, transport=transport(app))


def audit_has(auth, event, needle=""):
    return any(a["event"] == event and needle in (a["detail"] or "") for a in auth.store.recent_audit(limit=500))


def nowdt(delta=0):
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=delta)


auth, app, tmp = make()
api = TestClient(app)
alice = auth.create_user("alice", password=PW)
bob = auth.create_user("bob", password=PW)
daemon = auth.create_service("daemon", roles=["reader"])
U = "http://testserver"

# ── 1. Pairing ──────────────────────────────────────────────────────────────────────────────────────────
br = login(app, "alice")
res = br.post("/auth/apikeys/pairing", json={"name": "cli", "rotate_on_login": True})
r.check("self-service: a session issues a pairing code", res.status_code == 200 and len(res.json().get("code", "")) == 19,
        f"{res.status_code} {res.text[:200]}")
code = res.json().get("code", "")
bearer = auth.create_api_key(alice, name="bearer")
res = api.post("/auth/apikeys/pairing", json={"name": "x"}, headers={"X-API-Key": bearer["key"]})
r.check("a key cannot issue a pairing code (session only)", res.status_code == 403, str(res.status_code))

kf = os.path.join(tmp, "alice.json")
cl = PairedClient.pair(U, code, kf, transport=transport(app))
res = cl.request("GET", "/who")
r.check("paired client: a signed request is signed in as the owner, via apikey",
        res.status == 200 and res.json() == {"user": "alice", "via": "apikey", "admin": False}, f"{res.status} {res.body!r}")
r.check("the key file is private (0600)", (os.stat(kf).st_mode & 0o777) == 0o600, oct(os.stat(kf).st_mode))
r.check("the server stores only the public key", "private" not in json.dumps(dict(key_row(auth, jload(kf)["key_id"]))),
        "")
try:
    PairedClient.pair(U, code, os.path.join(tmp, "again.json"), transport=transport(app))
    again = None
except PairingError as e:
    again = e.status
r.check("a pairing code is single use", again == 400, str(again))

c2 = auth.create_pairing_code(alice)["code"]
db_set(auth, "UPDATE magic_token SET expires_at=? WHERE token_hash=?", (int(time.time()) - 1, S.code_hash(c2)))
try:
    PairedClient.pair(U, c2, os.path.join(tmp, "exp.json"), transport=transport(app))
    exp = None
except PairingError as e:
    exp = e.status
r.check("an expired pairing code is refused", exp == 400, str(exp))
try:
    PairedClient.pair(U, "AAAA-BBBB-CCCC-DDDD", os.path.join(tmp, "unk.json"), transport=transport(app))
    unk = None
except PairingError as e:
    unk = e.status
r.check("an unknown pairing code is refused and audited",
        unk == 400 and audit_has(auth, "apikey_pair_denied", "reason=unknown"), str(unk))

# Proof of possession: the request registers key A but is signed with key B.
c3 = auth.create_pairing_code(alice, name="pop")["code"]
ka, kb = _new_key(), _new_key()
body = json.dumps({"code": c3, "public_key": _public(ka)}).encode()
hdr = sign("POST", U + "/auth/apikeys/pair", {"Content-Type": "application/json"}, body, kb)
res = api.post("/auth/apikeys/pair", content=body, headers=hdr)
r.check("pairing without proof of possession (signed with another key) is 401", res.status_code == 401,
        str(res.status_code))
hdr = sign("POST", U + "/auth/apikeys/pair", {"Content-Type": "application/json"}, body, ka)
res = api.post("/auth/apikeys/pair", content=body, headers=hdr)
r.check("... and the code was not burnt by the failed attempt", res.status_code == 200, f"{res.status_code} {res.text[:200]}")
res = api.post("/auth/apikeys/pair", content=body,
               headers=sign("POST", U + "/auth/apikeys/pair", {"Content-Type": "application/json"}, body, ka))
r.check("the same public key cannot be paired twice", res.status_code == 400, str(res.status_code))

# Lockout discards open pairing codes with the other open links.
c4 = auth.create_pairing_code(bob)["code"]
auth.set_disabled(bob, True)
auth.set_disabled(bob, False)
try:
    PairedClient.pair(U, c4, os.path.join(tmp, "bob.json"), transport=transport(app))
    dead = None
except PairingError as e:
    dead = e.status
r.check("a lockout discards the account's open pairing codes", dead == 400, str(dead))
try:
    auth.create_pairing_code(daemon, rotate_on_login=True, expires_days=0)
    unl = False
except ConfigError:
    unl = True
r.check("a pairing code obeys the key rules (unlimited needs apikey_allow_unlimited)", unl)
res = br.post("/auth/apikeys/pairing", json={"roles": ["nope"]})
r.check("a pairing code with a scope outside the account's roles is 400", res.status_code == 400, str(res.status_code))

adm = login(app, "admin")
res = adm.post(f"/auth/admin/api/users/{daemon}/keys/pairing", json={"name": "svc", "expires_days": 30})
r.check("admin panel: a pairing code for another account", res.status_code == 200 and res.json().get("code"),
        f"{res.status_code} {res.text[:200]}")
dc = PairedClient.pair(U, res.json()["code"], os.path.join(tmp, "daemon.json"), transport=transport(app))
r.check("... the service account's client signs in", dc.request("GET", "/who").json().get("user") == "daemon")

# Throttle: a separate app, so the limiter of the main one stays clean.
auth_t, app_t, _ = make()
auth_t.set_security("rate_limit_max", 3)
ct = TestClient(app_t)
k = _new_key()
statuses = []
for i in range(6):
    b = json.dumps({"code": f"AAAA-BBBB-CCCC-{i:04d}", "public_key": _public(k)}).encode()
    statuses.append(ct.post("/auth/apikeys/pair", content=b,
                            headers=sign("POST", U + "/auth/apikeys/pair", {"Content-Type": "application/json"}, b, k)
                            ).status_code)
r.check("guessing pairing codes is rate-limited (429)", 429 in statuses and statuses[0] == 400, str(statuses))

# ── 2. Signatures ───────────────────────────────────────────────────────────────────────────────────────
dk_state = jload(os.path.join(tmp, "daemon.json"))
from tinysesam.client import _load                                  # noqa: E402
dkey = _load(dk_state["private_key"])


def call(method, path, headers, body=b""):
    return api.request(method, U + path, headers=headers, content=body).status_code


h = raw_sign(dkey, "GET", U + "/who", nonce="fresh-nonce-0001")
r.check("a correct hand-made signature is accepted", call("GET", "/who", h) == 200)
r.check("the same request again is a replay (same nonce) → 401", call("GET", "/who", h) == 401)
bad = dict(h)
sig = bad["Signature"]
bad["Signature"] = sig[:-6] + ("A" if sig[-6] != "A" else "B") + sig[-5:]
bad["Signature-Input"] = h["Signature-Input"].replace("fresh-nonce-0001", "fresh-nonce-0002")
r.check("a wrong signature → 401", call("GET", "/who", bad) == 401)
r.check("an expired signature (older than the max age) → 401",
        call("GET", "/who", raw_sign(dkey, "GET", U + "/who", created=nowdt(-120), nonce="old-nonce-0001")) == 401)
r.check("a signature from the future → 401",
        call("GET", "/who", raw_sign(dkey, "GET", U + "/who", created=nowdt(120), nonce="fut-nonce-0001")) == 401)
r.check("a re-targeted request (other path) → 401",
        call("GET", "/admin-only", raw_sign(dkey, "GET", U + "/who", nonce="tgt-nonce-0001")) == 401)
r.check("a signature that does not cover the target URI → 401 (it would be valid on every route)",
        call("GET", "/who", raw_sign(dkey, "GET", U + "/who", nonce="cov-nonce-0001", components=("@method",))) == 401)
r.check("another method → 401",
        call("POST", "/who", raw_sign(dkey, "GET", U + "/who", nonce="mth-nonce-0001")) in (401, 405))
hb = raw_sign(dkey, "POST", U + "/echo", b"amount=1", nonce="body-nonce-001")
r.check("a manipulated body → 401", call("POST", "/echo", hb, b"amount=9") == 401)
hb = raw_sign(dkey, "POST", U + "/echo", b"amount=1", nonce="body-nonce-002")
r.check("... the untouched body passes", call("POST", "/echo", hb, b"amount=1") == 200)
hn = raw_sign(dkey, "POST", U + "/echo", b"x", nonce="nodg-nonce-001", with_digest=False)
r.check("a body without a signed Content-Digest → 401", call("POST", "/echo", hn, b"x") == 401)
other = _new_key()
r.check("a foreign key under the paired keyid → 401",
        call("GET", "/who", raw_sign(other, "GET", U + "/who", keyid=dk_state["keyid"], nonce="frg-nonce-0001")) == 401)
r.check("an unknown key → 401", call("GET", "/who", raw_sign(other, "GET", U + "/who", nonce="unk-nonce-0001")) == 401)
r.check("a signature without nonce → 401",
        call("GET", "/who", raw_sign(dkey, "GET", U + "/who", nonce=None)) == 401)
r.check("a signature without the tinysesam tag → 401",
        call("GET", "/who", raw_sign(dkey, "GET", U + "/who", tag=None, nonce="tag-nonce-0001")) == 401)
akey_client = pair(app, auth, auth.find_user("admin")["id"], os.path.join(tmp, "admin.json"))
r.check("an automation key carries no admin flag: admin route with the admin's paired key → refused",
        akey_client.request("GET", "/admin-only").status in (401, 403))
r.check("... and /who works, without the admin flag",
        akey_client.request("GET", "/who").json() == {"user": "admin", "via": "apikey", "admin": False})
hk = pair(app, auth, alice, os.path.join(tmp, "human.json"), kind="human")
r.check("a paired key of kind human without a session → 401", hk.request("GET", "/who").status == 401)
r.check("bearer keys keep working next to the layer",
        api.get("/who", headers={"X-API-Key": bearer["key"]}).json().get("user") == "alice")
forged = auth.create_api_key(daemon, name="forged")
db_set(auth, "UPDATE api_key SET public_key='x' WHERE id=?", (forged["id"],))
r.check("a row with a public key is never a bearer key", api.get("/who", headers={"X-API-Key": forged["key"]}).status_code == 401)

# CSRF: a signed POST is exempt like X-API-Key (a foreign page cannot set the header); without a key it is not.
auth_c, app_c, tmp_c = make(csrf_enabled=True)
svc_c = auth_c.create_service("svc")
cc = pair(app_c, auth_c, svc_c, os.path.join(tmp_c, "c.json"))
r.check("csrf_enabled: a signed JSON POST passes the CSRF check", cc.request("POST", "/json", json={"a": 1}).status == 200)

# Without the layer: pairing refuses, a signed request authenticates nobody.
auth_n = TinySesam(TinySesamConfig(csrf_enabled=False, db_path=auth.cfg.db_path, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False, apikey_pairing_enabled=True,
                                   base_url="http://testserver"))
app_n = FastAPI()
app_n.include_router(auth_n.router())


@app_n.get("/who")
def who_n(u=Depends(auth_n.require_user)):
    return {"user": u["username"]}


cn = TestClient(app_n)
r.check("without install_signatures the pairing route refuses (503)",
        cn.post("/auth/apikeys/pair", json={"code": "x", "public_key": "y"}).status_code == 503)
r.check("without install_signatures a signed request is 401",
        cn.get("/who", headers=raw_sign(dkey, "GET", U + "/who", nonce="lay-nonce-0001")).status_code == 401)

auth_off, app_off, _ = make(apikey_pairing_enabled=False)
r.check("pairing off: the pairing route does not exist",
        TestClient(app_off).post("/auth/apikeys/pair", json={}).status_code in (404, 405))
try:
    auth_off.create_pairing_code(auth_off.create_service("s"))
    off = False
except ConfigError:
    off = True
r.check("pairing off: create_pairing_code raises ConfigError", off)
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "x.db"), apikey_pairing_minutes=0))
    lim = False
except ConfigError:
    lim = True
r.check("apikey_pairing_minutes=0 is refused at construction", lim)

# ── 3. renew_on_login ───────────────────────────────────────────────────────────────────────────────────
soon = int(time.time()) + 100
pr = pair(app, auth, alice, os.path.join(tmp, "renew.json"), renew_on_login=True, expires_days=30)
pr_id = jload(os.path.join(tmp, "renew.json"))["key_id"]
br_key = auth.create_api_key(alice, name="b-renew", expires_days=10, renew_on_login=True)
plain = auth.create_api_key(alice, name="b-plain", expires_days=10)
dead = auth.create_api_key(alice, name="b-dead", expires_days=10, renew_on_login=True)
for kid in (pr_id, br_key["id"], plain["id"]):
    db_set(auth, "UPDATE api_key SET expires_at=? WHERE id=?", (soon, kid))
db_set(auth, "UPDATE api_key SET expires_at=? WHERE id=?", (int(time.time()) - 10, dead["id"]))
pr.request("GET", "/who")
pr.request("GET", "/who")
r.check("renew_on_login: using the key does not renew it", key_row(auth, pr_id)["expires_at"] == soon)
login(app, "bob")
r.check("renew_on_login: another account's sign-in does not renew it", key_row(auth, pr_id)["expires_at"] == soon)
login(app, "alice")
now = int(time.time())
r.check("renew_on_login: the owner's interactive sign-in renews the paired key by its lifetime (30 days)",
        abs(key_row(auth, pr_id)["expires_at"] - (now + 30 * 86400)) < 5, str(key_row(auth, pr_id)["expires_at"] - now))
r.check("... and a bearer key with the option by its lifetime (10 days)",
        abs(key_row(auth, br_key["id"])["expires_at"] - (now + 10 * 86400)) < 5)
r.check("... a key without the option stays", key_row(auth, plain["id"])["expires_at"] == soon)
r.check("... an expired key is not revived", key_row(auth, dead["id"])["expires_at"] < now)
r.check("... the audit log says how many", audit_has(auth, "apikeys_login", "renewed=2"))
try:
    auth.create_api_key(alice, expires_days=0, renew_on_login=True)
    nr = False
except ConfigError:
    nr = True
r.check("renew_on_login needs an expiry", nr)

# ── 4. rotate_on_login ──────────────────────────────────────────────────────────────────────────────────
rf = os.path.join(tmp, "rotate.json")
rc = pair(app, auth, alice, rf, rotate_on_login=True)
rid = jload(rf)["key_id"]
res = rc.request("GET", "/who")
r.check("rotate_on_login: no rotation asked before a sign-in", res.status == 200 and S.ROTATE_HEADER.lower() not in res.headers)
shutil.copy(rf, rf + ".stolen")
old_key = _load(jload(rf)["private_key"])
old_keyid = rc.keyid
login(app, "alice")
r.check("rotate_on_login: the owner's sign-in marks the key", key_row(auth, rid)["rotate_pending"] == 1)
in_flight = raw_sign(old_key, "GET", U + "/who", nonce="flight-nonce-01")
res = rc.request("GET", "/who")
r.check("... the next signed answer asks for rotation (header) and the client rotates by itself",
        res.status == 200 and res.headers.get(S.ROTATE_HEADER.lower()) and rc.keyid != old_keyid,
        f"{res.headers} {rc.keyid} {old_keyid}")
row = key_row(auth, rid)
r.check("... server: new key current, old one its predecessor, no longer pending",
        row["key_hash"] == S.key_hash(rc.keyid) and row["prev_key_hash"] == S.key_hash(old_keyid)
        and row["rotate_pending"] == 0 and row["prev_until"] is None)
r.check("... a request in flight with the old key still passes (overlap)", call("GET", "/who", in_flight) == 200)
in_flight2 = raw_sign(old_key, "GET", U + "/who", nonce="flight-nonce-02")
r.check("... the first request with the new key passes", rc.request("GET", "/who").status == 200)
r.check("... and retires the predecessor", key_row(auth, rid)["prev_until"] is not None)
r.check("... a request signed with the old key BEFORE that moment still passes", call("GET", "/who", in_flight2) == 200)
time.sleep(1.2)
r.check("... the old key is dead for anything signed afterwards",
        call("GET", "/who", raw_sign(old_key, "GET", U + "/who", nonce="after-nonce-01")) == 401)
thief = PairedClient(rf + ".stolen", transport=transport(app))
r.check("... a copy of the old key file is worthless", thief.request("GET", "/who").status == 401)
r.check("... the key keeps id, name and expiry", key_row(auth, rid)["id"] == rid and audit_has(auth, "apikey_rotate", "requested=login"))

# A lost rotation answer heals: the server switched, the client did not learn it.
lf = os.path.join(tmp, "lost.json")
lc = pair(app, auth, alice, lf, rotate_on_login=True)
lid = jload(lf)["key_id"]
lose = {"once": True}
real = transport(app)


def lossy(method, url, headers, body):
    res = real(method, url, headers, body)
    if url.endswith("/auth/apikeys/rotate") and lose["once"]:
        lose["once"] = False
        return Response(502, {}, b"lost")
    return res


lc.transport = lossy
login(app, "alice")
lc.request("GET", "/who")
r.check("lost rotation answer: the server switched, the client keeps its pending key",
        jload(lf)["pending"] and key_row(auth, lid)["prev_key_hash"] == S.key_hash(lc.keyid))
res = lc.request("GET", "/who")
r.check("... the next request completes it (repeated rotation = success) and signs with the new key",
        res.status == 200 and not jload(lf)["pending"] and key_row(auth, lid)["key_hash"] == S.key_hash(lc.keyid))
r.check("rotation without a signature → 401", api.post("/auth/apikeys/rotate", json={"public_key": _public(_new_key())}).status_code == 401)

# ── 5. Options and views ────────────────────────────────────────────────────────────────────────────────
br = login(app, "alice")
res = br.post(f"/auth/apikeys/{bearer['id']}/options", json={"rotate_on_login": True})
r.check("options: rotate_on_login on a bearer key is 400", res.status_code == 400, str(res.status_code))
res = br.post(f"/auth/apikeys/{bearer['id']}/options", json={"renew_on_login": True})
r.check("options: renew_on_login on an own bearer key", res.status_code == 200 and res.json()["renew_on_login"] is True)
r.check("... a key from before schema 17 gets its lifetime from its dates",
        key_row(auth, bearer["id"])["lifetime_days"] == 90)
with open(os.path.join(tmp, "daemon.json"), encoding="utf-8") as fh:
    dc_id = json.load(fh)["key_id"]
res = br.post(f"/auth/apikeys/{dc_id}/options", json={"renew_on_login": True})
r.check("options: a foreign key is refused", res.status_code == 400, str(res.status_code))
r.check("options: a non-boolean is 400",
        br.post(f"/auth/apikeys/{bearer['id']}/options", json={"renew_on_login": "yes"}).status_code == 400)
r.check("options: not with a key",
        api.post(f"/auth/apikeys/{bearer['id']}/options", json={"renew_on_login": False},
                 headers={"X-API-Key": bearer["key"]}).status_code == 403)
res = adm.post(f"/auth/admin/api/keys/{dc_id}/options", json={"rotate_on_login": True})
r.check("admin options route", res.status_code == 200 and res.json()["rotate_on_login"] is True, res.text[:200])
views = {k["id"]: k for k in br.get("/auth/apikeys").json()}
v = views.get(rid, {})
r.check("the key list shows paired, keyid and the options, no secret",
        v.get("paired") is True and v.get("keyid") == rc.keyid and v.get("rotate_on_login") is True
        and "public_key" not in v and views[bearer["id"]]["paired"] is False, str(v))
page = br.get("/auth/account").text
r.check("account page: pairing button and option switches", "data-act=mkpair" in page and "key_rotate" in page)
panel = adm.get("/auth/admin").text
r.check("admin panel: pairing enabled for the UI", "const PAIRING=true" in panel)

# ── 6. Revocation paths hit paired keys ─────────────────────────────────────────────────────────────────
v1 = pair(app, auth, bob, os.path.join(tmp, "v1.json"))
auth.set_disabled(bob, True)
r.check("lockout: a paired key of the account → 401", v1.request("GET", "/who").status == 401)
auth.set_disabled(bob, False)
r.check("... and stays revoked after unlocking", v1.request("GET", "/who").status == 401)
v2 = pair(app, auth, bob, os.path.join(tmp, "v2.json"))
open_code = auth.create_pairing_code(bob)["code"]
res = adm.post(f"/auth/admin/api/users/{bob}/password", json={"password": "another-password-12345"})
r.check("admin password reset: paired key → 401", res.status_code == 200 and v2.request("GET", "/who").status == 401,
        f"{res.status_code} {res.text[:200]}")
try:
    PairedClient.pair(U, open_code, os.path.join(tmp, "v2b.json"), transport=transport(app))
    gone = None
except PairingError as e:
    gone = e.status
r.check("... and the open pairing code is gone", gone == 400, str(gone))
v3 = pair(app, auth, alice, os.path.join(tmp, "v3.json"))
br = login(app, "alice")
res = br.post("/auth/sessions/revoke", json={"scope": "all"})
r.check("'end all sessions': paired key → 401", res.status_code == 200 and v3.request("GET", "/who").status == 401,
        f"{res.status_code} {res.text[:200]}")
v4 = pair(app, auth, daemon, os.path.join(tmp, "v4.json"))
auth.revoke_api_key(jload(os.path.join(tmp, "v4.json"))["key_id"])
r.check("single revocation: paired key → 401", v4.request("GET", "/who").status == 401)
r.check("revoked/locked use is audited", audit_has(auth, "apikey_denied", "reason=revoked"))

# ── 7. The reference client against a real server ──────────────────────────────────────────────────────
try:
    import uvicorn
except ModuleNotFoundError:
    uvicorn = None
if uvicorn is None:
    r.skip("end to end (uvicorn)", "uvicorn missing")
else:
    auth_e, app_e, tmp_e = make(base_url="")
    owner = auth_e.create_user("erin", password=PW)
    server = uvicorn.Server(uvicorn.Config(app_e, host="127.0.0.1", port=0, log_level="warning", lifespan="off"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        code = auth_e.create_pairing_code(owner, rotate_on_login=True)["code"]
        ec = PairedClient.pair(base, code, os.path.join(tmp_e, "e.json"))
        r.check("E2E: pairing over HTTP (urllib)", ec.transport is urllib_transport)
        r.check("E2E: signed GET", ec.request("GET", "/who").json().get("user") == "erin")
        r.check("E2E: signed POST with body", ec.request("POST", "/echo", data=b"hello").json().get("body") == "hello")
        first = ec.keyid
        auth_e.start_session(owner, "password")          # the code path of every completed sign-in
        ec.request("GET", "/who")
        r.check("E2E: rotation on the owner's sign-in", ec.keyid != first)
        r.check("E2E: the new key works", ec.request("POST", "/echo", json={"x": 1}).status == 200)
    finally:
        server.should_exit = True
        th.join(10)

sys.exit(r.done())

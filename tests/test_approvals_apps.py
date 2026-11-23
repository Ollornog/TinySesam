"""Approvals, stage B (application actions): an application asks for one of ITS registered action types, the person
confirms with a step-up of THAT approval, the application picks up ONE signed confirmation and checks it.

One block per row of the acceptance table (draft §11 B, without the client row — the client helpers follow), plus the
browser entry (§5) and the audit freedom of the confirmation. The mutation that turns each red is named next to it and
was run for the pull request:

 1. The confirmation verifies against /auth/approvals/jwks.json only — never the gate keys; a gate token is no
    confirmation, a confirmation no gate token.                  (sign with the gate keyring; `typ` not checked)
 2. A second pickup carries no confirmation; two parallel reads give one.          (`approved → consumed` removed)
 3. An application asking for a foreign prefix → 403 `forbidden_type`.                   (prefix check removed)
 4. An unknown, missing or wrongly typed field → 400.                                     (schema check loosened)
 5. A `return_url` not registered exactly → 400.                                (prefix instead of exact match)
 6. The confirmation is not in the return address.                         (confirmation appended to return_url)
 7. `<script>` in a field: escaped, every value in its own `<bdi>`.                        (escaping left out)
 8. config_check: a placeholder without a field, no `en`, a bad type name, … → errors.       (checks struck)
 9. Browser entry: back to exactly the registered address with id and state (rejected, expired with `result`), the
    state as `nonce`; another account sees nothing; without a session first the sign-in.   (subject check removed)
10. Audit and log never hold the confirmation.                              (confirmation written into the audit)
Plus: step-up per approval, the pickup deadline, a type removed before the pickup, `types_from` (a second channel
gets `aud` = its own id), `types_file`, the per-application budget, withdrawal, the JWKS route, the keys CLI, the
migration to schema 24, and "without an approvals block nothing changes".
"""
import io
import json
import logging
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, approval_token, config_check  # noqa: E402
from tinysesam import approvals as apv  # noqa: E402
from tinysesam import gate, gate_client as gc  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.store import Store  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"
CSRF = "csrfProbeToken0123456789abcdefgh"
RETURN = "https://app.example.com/approvals/return"
DELETE = "example.collection.delete_permanently"
QUOTA = "example.member.set_quota"
TYPES = {
    DELETE: {"fields": {"collection": {"type": "string", "max": 64, "pattern": "^[A-Za-z0-9_-]{1,64}$"},
                        "name": {"type": "string", "max": 120}},
             "title": {"en": "Delete collection permanently", "de": "Collection endgültig löschen"},
             "summary": {"en": "Permanently delete the collection {name} ({collection}). This cannot be undone.",
                         "de": "Die Collection {name} ({collection}) endgültig löschen."},
             "irreversible": True},
    QUOTA: {"fields": {"member": {"type": "string", "max": 40}, "quota": {"type": "integer", "min": 0, "max": 100},
                       "notify": {"type": "boolean"}},
            "title": {"en": "Set a quota"}, "summary": {"en": "Set the quota of {member} to {quota}."}},
}
FIELDS = {"collection": "c_81f2", "name": "Project Alpha"}


def ok(name):
    print(f"  ✓ {name}")


def apps_cfg(**approvals):
    block = {"types": TYPES, "return_urls": [RETURN]}
    block.update(approvals)
    return {"example": {"account": "svc-example", "name": {"en": "Example", "de": "Example DE"}, "approvals": block}}


def build(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, base_url=BASE, approvals_enabled=True, apps=apps_cfg(),
               # Room for the many requests of this suite; the limits themselves are measured in test_approvals.py
               # (per account and key) and below (per application).
               approval_open_per_account=50, approval_open_per_token=50, approval_requests_per_hour=500)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def machine(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def session(auth, app, uid):
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    c.cookies.set(auth.session_cookie_name, tok)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    return c


def ask(app, key, subject, type_=DELETE, fields=None, **extra):
    body = {"type": type_, "subject": str(subject), "fields": FIELDS if fields is None else fields, **extra}
    return machine(app).post("/auth/api/approvals", headers={"X-Api-Key": key}, json=body)


def asked(app, key, subject, **kw):
    r = ask(app, key, subject, **kw)
    assert r.status_code == 201, (r.status_code, r.text)
    return r.json()


def page_hash(c, aid):
    p = c.get(f"/auth/approvals/{aid}")
    assert p.status_code == 200, (p.status_code, p.text[:300])
    return re.search(r"name=payload_hash value='([^']+)'", p.text).group(1)


def decide(c, aid, decision="approve", **extra):
    form = {"_csrf": CSRF, "decision": decision, "payload_hash": page_hash(c, aid), **extra}
    return c.post(f"/auth/approvals/{aid}", data=form)


def pickup(app, key, aid):
    r = machine(app).get(f"/auth/api/approvals/{aid}", headers={"X-Api-Key": key})
    assert r.status_code == 200, (r.status_code, r.text)
    return r.json()


def memory_store():
    seen = set()

    def store(jti, until):
        if jti in seen:
            return False
        seen.add(jti)
        return True
    return store


def check(token, keys, uid, fields=None, type_=DELETE, app_id="example", nonce=None):
    return approval_token.verify(token, keys=keys, issuer=BASE, app_id=app_id, expect_type=type_,
                                 expect_fields=FIELDS if fields is None else fields, expect_sub=str(uid),
                                 jti_store=memory_store(), expect_nonce=nonce)


def audit(auth, event=None):
    return [a for a in auth.store.recent_audit(2000) if event is None or a["event"] == event]


auth, app = build(gate_token_enabled=True, forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"])
svc = auth.create_service("svc-example")
key = auth.create_api_key(svc, name="example")["key"]
anna = auth.create_user("anna", password=PW)
bert = auth.create_user("bert", password=PW)
boss = auth.create_user("boss", password=PW, is_admin=True)
c_anna = session(auth, app, anna)

# Capture the security log and TinySesam's log for row 10.
log_buf = io.StringIO()
_handler = logging.StreamHandler(log_buf)
_handler.setLevel(logging.DEBUG)
for _name in ("tinysesam", "tinysesam.security"):
    logging.getLogger(_name).addHandler(_handler)
    logging.getLogger(_name).setLevel(logging.DEBUG)

# ══ the happy path (browser entry 1: a link) ═════════════════════════════════════════════════════════════════════
a1 = asked(app, key, anna)
assert apv.valid_id(a1["id"]) and re.fullmatch(r"\d{3} \d{3}", a1["match_code"]) and a1["state"] == "pending"
row1 = auth.store.get_approval(a1["id"])
assert row1["class"] == "app" and row1["app_id"] == "example" and row1["requester_kind"] == "app"
assert json.loads(row1["payload"]) == {"type": DELETE, **FIELDS} and row1["return_url"] is None
assert pickup(app, key, a1["id"])["state"] == "pending" and "confirmation" not in pickup(app, key, a1["id"])
r = decide(c_anna, a1["id"], password=PW)
assert r.status_code == 200 and "id=apvstate" in r.text and "can now carry out the action" in r.text, r.text[-800:]
assert auth.store.get_approval(a1["id"])["state"] == "approved"
ok("request → page → confirmed with a step-up: the row waits in `approved`, TinySesam carries nothing out")

# ══ 1. the confirmation: own key, own typ, never the gate's ══════════════════════════════════════════════════════
got = pickup(app, key, a1["id"])
token1 = got["confirmation"]
assert got["state"] == "consumed" and token1.count(".") == 2, got
approval_keys = machine(app).get("/auth/approvals/jwks.json")
assert approval_keys.status_code == 200 and approval_keys.headers["cache-control"] == "public, max-age=300"
jwks = approval_keys.json()
gate_jwks = machine(app).get("/auth/gate/jwks.json").json()
assert {k["kid"] for k in jwks["keys"]}.isdisjoint({k["kid"] for k in gate_jwks["keys"]}), "approval key = gate key"
claims = check(token1, jwks, anna)
assert claims["aud"] == "example" and claims["sub"] == str(anna) and claims["jti"] == a1["id"]
assert claims["act"] == {"sub": "app:example"} and claims["amr"] == ["pwd"] and claims["iss"] == BASE
assert claims["authorization_details"] == [{"type": DELETE, **FIELDS}] and "nonce" not in claims
assert claims["exp"] - claims["nbf"] == 120 and claims["auth_time"] <= claims["iat"]
assert claims["ts_payload_sha256"] == row1["payload_hash"]
try:
    check(token1, gate_jwks, anna)
    raise AssertionError("a confirmation verified against the GATE key set")
except gc.KidError:
    pass
# A gate token of the same installation, for the same account, is no confirmation.
u = dict(auth.get_user(anna))
u["_via"] = "session"
cookie = auth._gate_cookie(None, u, "https://app.example.com/x", (), session={"mfa_ok": 1, "user_id": anna})
gate_token = cookie.split(";", 1)[0].split("=", 1)[1]
for keys in (jwks, gate_jwks):
    try:
        check(gate_token, keys, anna)
        raise AssertionError("a gate token passed as a confirmation")
    except gc.HeaderError:
        pass
# … and the other way round: the proxy-side check refuses a confirmation even with the approval key.
raw_p = __import__("base64").urlsafe_b64decode(jwks["keys"][0]["x"] + "==")
assert gate.check(raw_p, token1, aud="example", iss=BASE, now=claims["iat"]) is None
ok("1: the confirmation verifies with /auth/approvals/jwks.json (a set of its own), not with the gate set; a gate "
   "token is refused (typ), gate.check refuses a confirmation")

# ══ 2. exactly once ══════════════════════════════════════════════════════════════════════════════════════════════
again = pickup(app, key, a1["id"])
assert again["state"] == "consumed" and "confirmation" not in again and "result" not in again, again
assert auth.store.get_approval(a1["id"])["issued_at"] is not None
# Two parallel reads (long poll) of a freshly confirmed approval: one confirmation.
a2 = asked(app, key, anna)
assert decide(c_anna, a2["id"], password=PW).status_code == 200
results: list = []
barrier = threading.Barrier(4)


def reader():
    barrier.wait()
    results.append(machine(app).get(f"/auth/api/approvals/{a2['id']}?wait=1", headers={"X-Api-Key": key}).json())


threads = [threading.Thread(target=reader) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
assert sum("confirmation" in x for x in results) == 1 and all(x["state"] == "consumed" for x in results), results
ok("2: the second pickup carries no confirmation; four parallel reads, one confirmation")

# ══ 3. only the application's own prefix ═════════════════════════════════════════════════════════════════════════
for type_ in ("other.collection.delete_permanently", "tinysesam.account.set_roles", "exampl.collection.x",
              "examplex.collection.delete_permanently", 42, None):
    r = ask(app, key, anna, type_=type_)
    assert r.status_code == 403 and r.json()["error"] == "forbidden_type", (type_, r.status_code, r.text)
r = ask(app, key, anna, type_="example.collection.unknown")
assert r.status_code == 400 and r.json()["error"] == "invalid_type", r.text
assert audit(auth, "approval_denied")[0]["detail"].startswith("app=example reason=foreign_type")
# The access reset is the one TinySesam type an application asks for — only with `provisioning` (scope users:reset).
r = ask(app, key, anna, type_="tinysesam.account.reset_access", fields={"account": str(bert)})
assert r.status_code == 403 and r.json()["error"] == "scope_missing", r.text
ok("3: a foreign prefix (`tinysesam.` and one that only starts alike) → 403 forbidden_type; an unregistered own "
   "type → 400; the access reset without provisioning → 403 scope_missing")

# ══ 4. the field schema ══════════════════════════════════════════════════════════════════════════════════════════
bad_fields = [
    {"collection": "c_81f2"},                                            # missing
    {**FIELDS, "purge": True},                                           # unknown
    {"collection": 81, "name": "x"},                                     # wrong type
    {"collection": "c 81", "name": "x"},                                 # against the pattern
    {"collection": "c_81f2", "name": "x" * 121},                         # too long
    {"collection": "c_81f2", "name": "line\nbreak"},                     # control character
    {"collection": "c_81f2", "name": "bidi ‮ override"},            # bidi control
    {"collection": "c_81f2", "name": "c1 \x85 next line"},               # C1 control
    "not an object",
]
for fields in bad_fields:
    r = ask(app, key, anna, fields=fields)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request", (fields, r.status_code, r.text)
for fields in ({"member": "m", "quota": True, "notify": False}, {"member": "m", "quota": 101, "notify": False},
               {"member": "m", "quota": "5", "notify": False}, {"member": "m", "quota": 5, "notify": 1},
               {"member": "m", "quota": 5.0, "notify": False}):
    r = ask(app, key, anna, type_=QUOTA, fields=fields)
    assert r.status_code == 400 and r.json()["error"] == "invalid_request", (fields, r.text)
assert ask(app, key, anna, type_=QUOTA, fields={"member": "m", "quota": 0, "notify": True}).status_code == 201
for extra in ({"unknown": 1}, {"state": "bad state"}, {"state": "x" * 129}, {"return_url": RETURN}):
    r = ask(app, key, anna, **extra)
    assert r.status_code == 400, (extra, r.text)
for subject in ("0", "abc", str(svc), "99999", 42):
    r = machine(app).post("/auth/api/approvals", headers={"X-Api-Key": key},
                          json={"type": DELETE, "subject": subject, "fields": FIELDS})
    assert r.status_code == 400 and r.json()["error"] in ("invalid_subject", "invalid_request"), (subject, r.text)
ok("4: missing, unknown, wrongly typed, too long, off-pattern, control/bidi/C1 characters → 400; bool ≠ int ≠ str; "
   "unknown members, a bad state, return_url without state, a service account or unknown subject → 400")

# ══ 5. return_url exactly ════════════════════════════════════════════════════════════════════════════════════════
for url in (RETURN + "/x", RETURN + "x", RETURN + "?a=1", RETURN + "#f", "https://APP.example.com/approvals/return",
            "https://app.example.com/approvals", "https://app.example.com.evil.example/approvals/return",
            "http://app.example.com/approvals/return", RETURN + "/"):
    r = ask(app, key, anna, return_url=url, state="s1")
    assert r.status_code == 400 and r.json()["error"] == "invalid_return_url", (url, r.text)
assert ask(app, key, anna, return_url=RETURN, state="s1").status_code == 201
ok("5: a return_url that is not exactly a registered one (longer, shorter, other case, query, fragment) → 400")

# ══ 6 + 9. browser entry: back with id and state, never the confirmation ═════════════════════════════════════════
a6 = asked(app, key, anna, return_url=RETURN, state="k3J-state_1.~")
assert auth.store.get_approval(a6["id"])["nonce"] == "k3J-state_1.~"
p6 = c_anna.get(f"/auth/approvals/{a6['id']}")
csp = p6.headers["content-security-policy"]
assert "https://app.example.com" in re.search(r"form-action[^;]*", csp).group(0).split(), csp
assert "frame-ancestors 'none'" in csp and p6.headers["x-frame-options"] == "DENY"
r = decide(c_anna, a6["id"], password=PW)
assert r.status_code == 303, (r.status_code, r.text[-300:])
loc = urlsplit(r.headers["location"])
assert f"{loc.scheme}://{loc.netloc}{loc.path}" == RETURN
assert parse_qs(loc.query) == {"approval": [a6["id"]], "state": ["k3J-state_1.~"]}, loc.query
assert "eyJ" not in r.headers["location"] and "confirmation" not in r.headers["location"]
token6 = pickup(app, key, a6["id"])["confirmation"]
assert token6 not in r.headers["location"]
assert check(token6, jwks, anna, nonce="k3J-state_1.~")["nonce"] == "k3J-state_1.~"
try:
    check(token6, jwks, anna, nonce="another-session")
    raise AssertionError("a confirmation of another browser session passed")
except approval_token.NonceError:
    pass
ok("6: confirmed → 303 to exactly the registered address with approval + state, no confirmation in it; the "
   "application picks it up afterwards, `nonce` = state; form-action names the return origin")

# Rejected and expired come back too, with `result`.
a6r = asked(app, key, anna, return_url=RETURN, state="s-rej")
r = decide(c_anna, a6r["id"], "reject")
assert r.status_code == 303 and parse_qs(urlsplit(r.headers["location"]).query) == {
    "approval": [a6r["id"]], "state": ["s-rej"], "result": ["rejected"]}, r.headers.get("location")
a6e = asked(app, key, anna, return_url=RETURN, state="s-exp")
h6e = page_hash(c_anna, a6e["id"])
auth.store._exec("UPDATE approval SET expires_at=? WHERE id=?", (int(time.time()) - 1, a6e["id"]))
r = c_anna.post(f"/auth/approvals/{a6e['id']}", data={"_csrf": CSRF, "decision": "approve", "payload_hash": h6e,
                                                       "password": PW})
assert r.status_code == 303 and parse_qs(urlsplit(r.headers["location"]).query)["result"] == ["expired"], r.text[:300]
closed = c_anna.get(f"/auth/approvals/{a6e['id']}")
assert closed.status_code == 200 and "id=apvreturn" in closed.text and "result=expired" in closed.text
# Another account sees nothing and cannot confirm; without a session the sign-in comes first.
a9 = asked(app, key, anna, return_url=RETURN, state="s9")
c_bert = session(auth, app, bert)
foreign = c_bert.get(f"/auth/approvals/{a9['id']}")
assert foreign.status_code == 404 and "Project Alpha" not in foreign.text and "apvform" not in foreign.text
r = c_bert.post(f"/auth/approvals/{a9['id']}", data={"_csrf": CSRF, "decision": "approve",
                                                      "payload_hash": auth.store.get_approval(a9["id"])["payload_hash"],
                                                      "password": PW})
assert r.status_code == 404 and auth.store.get_approval(a9["id"])["state"] == "pending"
anon = machine(app).get(f"/auth/approvals/{a9['id']}")
assert anon.status_code == 303 and "/login" in anon.headers["location"] and a9["id"] in anon.headers["location"]
ok("9: browser entry — rejected/expired back with result=…; another account sees nothing and cannot confirm; "
   "without a session first the sign-in, then back to the page")

# ══ step-up per approval ═════════════════════════════════════════════════════════════════════════════════════════
a_s = asked(app, key, anna)
assert decide(c_anna, a_s["id"]).status_code in (400, 401, 403) and auth.store.get_approval(a_s["id"])["state"] == "pending"
assert decide(c_anna, a_s["id"], password="wrong password 0000").status_code in (401, 403)
r = machine(app).post(f"/auth/approvals/{a_s['id']}", headers={"X-Api-Key": key},
                      data={"_csrf": CSRF, "decision": "approve", "payload_hash": "x", "password": PW})
assert r.status_code == 403 and auth.store.get_approval(a_s["id"])["state"] == "pending"
ok("step-up per approval: without one or with a wrong password nothing happens; a key never decides")

# ══ 7. the page: escaped, every value in its own <bdi> ═══════════════════════════════════════════════════════════
evil = {"collection": "c_x", "name": "<script>alert(1)</script>\" onmouseover=x אב"}
a7 = asked(app, key, anna, fields=evil)
html = c_anna.get(f"/auth/approvals/{a7['id']}").text
assert "<script>alert(1)</script>" not in html
summary = re.search(r"<p class=apvsum id=apvsum>(.*?)</p>", html, re.S).group(1)
assert summary == ("Permanently delete the collection <bdi>&lt;script&gt;alert(1)&lt;/script&gt;&quot; onmouseover=x "
                   "אב</bdi> (<bdi>c_x</bdi>). This cannot be undone."), summary
assert "<td><bdi>&lt;script&gt;alert(1)&lt;/script&gt;" in html, "the field table shows the raw value escaped"
assert "id=apvapp><bdi>Example</bdi>" in html and "<h1>Delete collection permanently</h1>" in html
assert "id=apvirrev" in html and "⚠" in html, "no ⚠ + word for an irreversible type"
auth.cfg.lang = "de"
html_de = c_anna.get(f"/auth/approvals/{a7['id']}").text
auth.cfg.lang = "en"
assert "<h1>Collection endgültig löschen</h1>" in html_de and "id=apvapp><bdi>Example DE</bdi>" in html_de
html_q = c_anna.get(f"/auth/approvals/{asked(app, key, anna, type_=QUOTA, fields={'member': 'm', 'quota': 7, 'notify': False})['id']}").text
assert "Set the quota of <bdi>m</bdi> to <bdi>7</bdi>." in html_q and "id=apvirrev" not in html_q
ok("7: the operator's text with each value escaped in its own <bdi>, the raw field table, ⚠ only when irreversible, "
   "German text with lang=de")

# ══ 10. never in the audit, never in a log ═══════════════════════════════════════════════════════════════════════
everything = json.dumps([dict(a) for a in audit(auth)])
for tok in (token1, token6):
    for part in tok.split("."):
        assert part not in everything, "a part of the confirmation is in the audit"
        assert part not in log_buf.getvalue(), "a part of the confirmation is in the log"
issued = audit(auth, "approval_issued")
assert issued and all(f"app=example" in a["detail"] and "hash=" in a["detail"] for a in issued)
assert all("Project Alpha" not in (a["detail"] or "") for a in audit(auth)), "a field value in the audit"
row_cols = dict(auth.store.get_approval(a1["id"]))
assert token1 not in json.dumps(row_cols), "the confirmation was stored"
ok("10: the confirmation is in no audit line, no log line and no database column; the audit has no field values")

# ══ pickup deadline, a type removed, withdrawal ══════════════════════════════════════════════════════════════════
a_p = asked(app, key, anna)
assert decide(c_anna, a_p["id"], password=PW).status_code == 200
assert auth.store.get_approval(a_p["id"])["expires_at"] <= int(time.time()) + auth.cfg.approval_pickup_sec + 1
auth.store._exec("UPDATE approval SET expires_at=? WHERE id=?", (int(time.time()) - 1, a_p["id"]))
late = pickup(app, key, a_p["id"])
assert late["state"] == "expired" and "confirmation" not in late
a_t = asked(app, key, anna)
assert decide(c_anna, a_t["id"], password=PW).status_code == 200
auth.cfg.apps = apps_cfg(types={QUOTA: TYPES[QUOTA]})
gone = pickup(app, key, a_t["id"])
assert gone["state"] == "consumed" and gone["result"] == "forbidden" and "confirmation" not in gone, gone
auth.cfg.apps = apps_cfg()
a_w = asked(app, key, anna)
w = machine(app).delete(f"/auth/api/approvals/{a_w['id']}", headers={"X-Api-Key": key})
assert w.status_code == 200 and w.json()["state"] == "withdrawn"
other_key = auth.create_api_key(boss, name="boss")["key"]
assert machine(app).get(f"/auth/api/approvals/{a_w['id']}", headers={"X-Api-Key": other_key}).status_code == 404
ok("pickup deadline → expired without confirmation; a type removed before the pickup → consumed/forbidden; the "
   "application withdraws; another key sees 404")

# ══ the per-application budget ═══════════════════════════════════════════════════════════════════════════════════
auth_b, app_b = build(approval_app_requests_per_hour=3)
key_b = auth_b.create_api_key(auth_b.create_service("svc-example"), name="k")["key"]
anna_b = auth_b.create_user("anna", password=PW)
codes = [ask(app_b, key_b, anna_b if i else 99999).status_code for i in range(4)]
assert codes == [400, 201, 201, 429], codes
assert any("reason=per_app_hour" in (a["detail"] or "") for a in audit(auth_b, "approval_throttled"))
ok("budget: every request counts, `invalid_subject` included — the fourth in the hour → 429")

# ══ types_from: a second channel, its own audience ═══════════════════════════════════════════════════════════════
channels = apps_cfg()
channels["example_test"] = {"account": "svc-example-test", "approvals": {"types_from": "example",
                                                                          "return_urls": [RETURN]}}
auth_c, app_c = build(apps=channels)
key_t = auth_c.create_api_key(auth_c.create_service("svc-example-test"), name="t")["key"]
anna_c = auth_c.create_user("anna", password=PW)
c_c = session(auth_c, app_c, anna_c)
ac = asked(app_c, key_t, anna_c)
assert decide(c_c, ac["id"], password=PW).status_code == 200
tok_c = pickup(app_c, key_t, ac["id"])["confirmation"]
jwks_c = machine(app_c).get("/auth/approvals/jwks.json").json()
assert check(tok_c, jwks_c, anna_c, app_id="example_test")["act"] == {"sub": "app:example_test"}
try:
    check(tok_c, jwks_c, anna_c, app_id="example")
    raise AssertionError("a confirmation of the test channel counted in the stable one")
except gc.AudienceError:
    pass
assert ask(app_c, key_t, anna_c, type_="example_test.collection.delete_permanently").status_code == 403
ok("types_from: the test channel asks for the stable types, its confirmation names only example_test")

# ══ types_file ═══════════════════════════════════════════════════════════════════════════════════════════════════
types_path = os.path.join(tempfile.mkdtemp(), "types.json")
with open(types_path, "w", encoding="utf-8") as f:
    json.dump({QUOTA: TYPES[QUOTA]}, f)
auth_f, app_f = build(apps=apps_cfg(types=None) | {"example": {"account": "svc-example", "approvals": {
    "types_file": types_path}}})
key_f = auth_f.create_api_key(auth_f.create_service("svc-example"), name="k")["key"]
anna_f = auth_f.create_user("anna", password=PW)
assert ask(app_f, key_f, anna_f, type_=QUOTA, fields={"member": "m", "quota": 1, "notify": True}).status_code == 201
assert ask(app_f, key_f, anna_f).status_code == 400
ok("types_file: the operator's file gives the types")

# ══ 8. config_check ══════════════════════════════════════════════════════════════════════════════════════════════


def findings(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "c.db"), passkey_enabled=False,
               oidc_enabled=False, base_url=BASE, approvals_enabled=True, apps=apps_cfg())
    cfg.update(over)
    try:
        TinySesam(TinySesamConfig(**cfg)).close()
    except ConfigError as e:
        return str(e)
    return ""


def with_type(name=DELETE, **change):
    spec = json.loads(json.dumps(TYPES[DELETE]))
    for k, v in change.items():
        if v is None:
            spec.pop(k, None)
        else:
            spec[k] = v
    return apps_cfg(types={name: spec})


assert findings() == ""
cases = [
    (with_type(summary={"en": "Delete {name} and {owner}."}), "the placeholder {owner} is no field"),
    (with_type(summary={"de": "Löschen {name}."}), "at least \"en\""),
    (with_type(title={"de": "Löschen"}), "title: a mapping language"),
    (with_type(name="example.delete"), "at least three segments"),
    (with_type(name="other.collection.delete"), "at least three segments"),
    (with_type(name="Example.collection.delete"), "at least three segments"),
    (with_type(name="example.collection." + "x" * 90), "at most 100 characters"),
    (with_type(summary={"en": "Delete {name!r}."}), "only {field} placeholders"),
    (with_type(summary={"en": "Delete {name.upper}."}), "only {field} placeholders"),
    (with_type(title={"en": "Delete {name}"}), "the title is fixed text"),
    (with_type(fields={"type": {"type": "string", "max": 5}}), "never \"type\""),
    (with_type(fields={"name": {"type": "string"}}), ".max: the longest value"),
    (with_type(fields={"name": {"type": "string", "max": 501}}), ".max: the longest value"),
    (with_type(fields={"name": {"type": "string", "max": 5, "pattern": "("}}), "a regular expression"),
    (with_type(fields={"name": {"type": "float"}}), "\"type\": \"boolean\""),
    (with_type(fields={"n": {"type": "integer", "min": 5, "max": 1}}), "min not above max"),
    (with_type(irreversible="yes"), "irreversible: true or false"),
    (with_type(summary={"en": "Delete\x00 {name}."}), "without control characters"),
    (apps_cfg(return_urls=["https://app.example.com/r?x=1"]), "return_urls"),
    (apps_cfg(return_urls=["http://app.example.com/r"]), "return_urls"),
    (apps_cfg(types_file="/nonexistent/types.json", types=None) | {"example": {
        "account": "svc-example", "approvals": {"types_file": "/nonexistent/types.json"}}}, "cannot be read"),
    ({"example": {"account": "svc-example", "approvals": {"types": TYPES, "types_from": "example"}}},
     "exactly one of types"),
    ({"example": {"account": "svc-example", "approvals": {"types_from": "nobody"}}}, "types_from='nobody'"),
    ({"example": {"account": "svc-example", "approvals": {"types": TYPES, "extra": 1}}}, "allowed members"),
    ({"tinysesam": {"account": "svc-x", "approvals": {"types": {}}}}, "reserved"),
]
for apps_value, needle in cases:
    text = findings(apps=apps_value)
    assert needle in text, (needle, text[:500])
for url in ("https://app.example.com:0/r", "https://app.example.com:99999/r", "https://app.example.com:x/r",
            "https://user@app.example.com/r", "ftp://app.example.com/r", "https:///r"):
    assert not config_check.approval_return_url_ok(url), url
assert config_check.approval_return_url_ok("https://app.example.com:8443/r")
assert config_check.approval_return_url_ok("http://127.0.0.1:8080/r")
assert "needs approvals_enabled=True" in findings(approvals_enabled=False, apikey_enabled=True)
assert "approval_token_ttl_sec" in findings(approval_token_ttl_sec=301)
assert "approval_pickup_sec" in findings(approval_pickup_sec=30)
de = findings(lang="de", apps=with_type(summary={"en": "Delete {owner}."}))
assert config_check._DE[config_check.APPROVAL_FINDINGS["unknown_placeholder"]].format(
    app="example", type=DELETE, lang="en", name="owner") in de, de
# Fail-closed at runtime: a type that became broken after construction is left out.
assert apv.normalize_app_approvals(TinySesamConfig(apps=with_type(summary={"en": "{owner}"})))["example"]["types"] == {}
ok(f"8: config_check refuses {len(cases)} broken approvals blocks (placeholder without field, no en, bad type name, "
   f"…), the limits, and says it in German too; a type broken at runtime is left out")

# ══ keys: CLI, rotation ═════════════════════════════════════════════════════════════════════════════════════════
from tinysesam.__main__ import _keys as keys_cli  # noqa: E402  (main() ends the process with sys.exit)
out = io.StringIO()
_stdout = sys.stdout
sys.stdout = out
try:
    assert keys_cli(["list", "--db", auth.cfg.db_path]) == 0
    assert keys_cli(["rotate", "--purpose", "approval", "--db", auth.cfg.db_path]) == 0
    assert keys_cli(["retire", "--purpose", "approval", "--db", auth.cfg.db_path]) == 1
finally:
    sys.stdout = _stdout
assert re.search(r"^approval\s+[0-9a-f]{16}\s+active", out.getvalue(), re.M), out.getvalue()
auth_r = TinySesam(TinySesamConfig(**{**auth.cfg.__dict__}))
rotated = auth_r.approval_jwks()["keys"]
assert len(rotated) == 2 and rotated[1]["kid"] == jwks["keys"][0]["kid"], rotated
auth_r.close()
ok("keys: `keys list` shows the approval key, `rotate --purpose approval` adds a new active one (the old one stays "
   "published), `retire` refuses within the overlap")

# ══ migration to schema 24 ═══════════════════════════════════════════════════════════════════════════════════════
path = os.path.join(tempfile.mkdtemp(), "old.db")
s0 = Store(path)
s0.db.close()
raw = sqlite3.connect(path)
raw.execute("ALTER TABLE approval DROP COLUMN nonce")
raw.execute("INSERT INTO users(username, display_name, created_at) VALUES ('old', 'old', 1)")
raw.execute("INSERT INTO approval(id, class, type, subject_id, requester_kind, requester_ref, payload, payload_hash, "
            "match_code, state, created_at, expires_at) VALUES ('apv_old', 'tinysesam', 'tinysesam.account.disable', "
            "1, 'apikey', '1', '{}', 'h', '000 000', 'pending', 1, 2)")
raw.execute("PRAGMA user_version = 23")
raw.commit()
raw.close()
s1 = Store(path)
assert int(s1.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION == 24
assert "nonce" in {r["name"] for r in s1.db.execute("PRAGMA table_info(approval)")}
assert s1.get_approval("apv_old")["nonce"] is None and s1.get_approval("apv_old")["state"] == "pending"
s1.db.close()
ok("migration: a schema-23 file gets approval.nonce and stamp 24; rows unchanged")

# ══ without an approvals block nothing changes ═══════════════════════════════════════════════════════════════════
off, off_app = build(approvals_enabled=False, apps={})
assert not [r.path for r in off_app.routes if getattr(r, "path", "").startswith("/auth/approvals")]
assert off._approval_keyring is None and machine(off_app).get("/auth/approvals/jwks.json").status_code == 404
plain, plain_app = build(apps={})
k_plain = plain.create_api_key(plain.create_service("svc-example"), name="k")["key"]
r = ask(plain_app, k_plain, plain.create_user("x", password=PW))
assert r.status_code == 403 and r.json()["error"] == "no_approver", r.text
ok("off: without approvals no routes and no key; a service account without an apps entry → no_approver")

print("OK test_approvals_apps")

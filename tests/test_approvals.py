"""Approvals, stage A (TinySesam actions): a token proposes, the person confirms in a browser session with a step-up
of THAT approval, TinySesam executes with the admin panel's code and the session's rights at that moment.

One block per row of the acceptance table (draft §11 A); the mutation that turns each red is named next to it and was
run for the pull request:

 1. Confirming with an API key, an OAuth token, a `human` key beside its session → 403.   (header refusal removed)
 2. Another account sees no details and cannot confirm.                                    (subject comparison removed)
 3. Without a step-up, or with only the session's fresh step-up window → refused.         (`stepup_fresh` instead)
 4. A double or parallel confirmation → exactly one transition, one execution.             (`WHERE state=?` removed)
 5. The payload changed between viewing and submitting → refused.                          (`payload_hash` check removed)
 6. A delegate who lost the role before confirming → `forbidden`.                          (rights checked at request)
 7. A service account as subject or requester → `no_approver`.                             (check removed)
 8. Limits and the rejection lock apply.                                                   (counters not counted)
 9. Expired → `expired`, confirming afterwards impossible.                                 (deadline check removed)
10. `frame-ancestors 'none'` also with `csp="off"` and an own policy.                     (header tied to `csp`)
11. A GET never confirms.                                                                  (decision taken from GET)
12. The summary is escaped and built from the database state.                              (raw value inserted)
13. The passkey challenge contains the id and the payload hash.                            (fixed challenge)
Plus: the provider step-up (`max_age=0`, `auth_time`), request validation, the three actions, the badge and
`topbar_data.approvals`, the audit without field values, the migration, and "without `approvals_enabled` nothing
changes".

The software authenticator builds real WebAuthn assertions (P-256): the library's real verification runs.
"""
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
import _totp_clock  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check  # noqa: E402
from tinysesam import approvals as apv  # noqa: E402
from tinysesam.store import Store  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"
ROLES = ["editors", "viewers", "teamadmin"]
CSRF = "csrfProbeToken0123456789abcdefgh"


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, base_url=BASE, approvals_enabled=True,
               available_roles=list(ROLES), admin_delegates={"teamadmin": {"roles": ["editors", "viewers"]}})
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session(auth, app, uid, age=0):
    """A browser: a full session of `uid` (signed in `age` seconds ago) and a CSRF cookie."""
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    if age:
        then = int(time.time()) - age
        auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                         (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    return c


def machine(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def request(auth, app, api_key, type_="tinysesam.account.set_roles", **fields):
    r = machine(app).post("/auth/api/approvals", headers={"X-Api-Key": api_key},
                          json={"type": type_, "fields": fields})
    assert r.status_code == 201, (r.status_code, r.text)
    return r.json()


def page_hash(c, aid):
    p = c.get(f"/auth/approvals/{aid}")
    assert p.status_code == 200, (p.status_code, p.text[:300])
    return re.search(r"name=payload_hash value='([^']+)'", p.text).group(1)


def decide(c, aid, decision="approve", digest=None, **extra):
    form = {"_csrf": CSRF, "decision": decision, "payload_hash": digest or page_hash(c, aid), **extra}
    return c.post(f"/auth/approvals/{aid}", data=form)


def state(auth, aid):
    return auth.store.get_approval(aid)["state"]


def audit(auth, event):
    return [a for a in auth.store.recent_audit(1000) if a["event"] == event]


def roles_of(auth, uid):
    return sorted(auth.user_roles(auth.store.get_user(uid)))


auth, app = build()
boss = auth.create_user("boss", password=PW, is_admin=True)
anna = auth.create_user("anna", password=PW, roles=["viewers"])
carol = auth.create_user("carol", password=PW)
boss_key = auth.create_api_key(boss, name="claude")["key"]

# ══ request and status (the token's side) ═══════════════════════════════════════════════════════════════════════
a1 = request(auth, app, boss_key, account=str(anna), add=["editors"], remove=["viewers"])
assert apv.valid_id(a1["id"]) and re.fullmatch(r"\d{3} \d{3}", a1["match_code"]), a1
assert a1["approve_url"] == f"{BASE}/auth/approvals/{a1['id']}" and a1["state"] == "pending"
st = machine(app).get(f"/auth/api/approvals/{a1['id']}", headers={"X-Api-Key": boss_key})
assert st.status_code == 200 and st.json()["state"] == "pending" and st.headers["cache-control"] == "no-store"
row1 = auth.store.get_approval(a1["id"])
assert row1["payload"] == apv.canonical(json.loads(row1["payload"])) and row1["payload_hash"] == apv.payload_hash(
    row1["payload"]) and row1["requester_kind"] == "apikey" and row1["class"] == "tinysesam"
ok("request: 201 with id, match code, approve_url from base_url; status for the requester, no-store")

bad = [({"type": "tinysesam.account.delete", "fields": {"account": "2"}}, "invalid_type"),
       ({"type": "tinysesam.account.disable", "fields": {"account": 2}}, "invalid_request"),
       ({"type": "tinysesam.account.disable", "fields": {"account": "2", "x": 1}}, "invalid_request"),
       ({"type": "tinysesam.account.disable", "fields": {}}, "invalid_request"),
       ({"type": "tinysesam.account.set_roles", "fields": {"account": "2"}}, "invalid_request"),
       ({"type": "tinysesam.account.set_roles", "fields": {"account": "2", "add": ["a\nb"]}}, "invalid_request"),
       ({"type": "tinysesam.account.set_roles", "fields": {"account": "2", "add": ["a,b"]}}, "invalid_request"),
       ({"type": "tinysesam.account.set_roles", "fields": {"account": "2", "add": ["x"], "remove": ["x"]}},
        "invalid_request"),
       ({"type": "tinysesam.account.disable", "fields": {"account": "2"}, "subject": "2"}, "invalid_request")]
for body, code in bad:
    r = machine(app).post("/auth/api/approvals", headers={"X-Api-Key": boss_key}, json=body)
    assert r.status_code == 400 and r.json()["error"] == code, (body, r.status_code, r.text)
r = machine(app).post("/auth/api/approvals", json={"type": "tinysesam.account.disable", "fields": {"account": "2"}})
assert r.status_code == 401, r.status_code
r = machine(app).post("/auth/api/approvals", headers={"Authorization": "Bearer an-oauth-access-token"},
                      json={"type": "tinysesam.account.disable", "fields": {"account": "2"}})
assert r.status_code == 403 and r.json()["error"] == "unsupported_token", r.text
c_boss = session(auth, app, boss)
r = c_boss.post("/auth/api/approvals", json={"type": "tinysesam.account.disable", "fields": {"account": "2"}},
                headers={"X-CSRF-Token": CSRF})
assert r.status_code == 401, "a session alone requested an approval"
carol_key = auth.create_api_key(carol, name="carol")["key"]
assert machine(app).get(f"/auth/api/approvals/{a1['id']}", headers={"X-Api-Key": carol_key}).status_code == 404
assert machine(app).delete(f"/auth/api/approvals/{a1['id']}", headers={"X-Api-Key": carol_key}).status_code == 404
ok("request: unknown type/field, wrong type, control character, comma, subject → 400; no key 401; "
   "OAuth token 403; a session alone 401; another key's id → 404")

# ══ 1. confirming with a token → 403 ════════════════════════════════════════════════════════════════════════════
digest = page_hash(c_boss, a1["id"])
form = {"_csrf": CSRF, "decision": "approve", "payload_hash": digest, "password": PW}
r1 = machine(app).post(f"/auth/approvals/{a1['id']}", headers={"X-Api-Key": boss_key}, data=form)
r2 = machine(app).post(f"/auth/approvals/{a1['id']}", headers={"Authorization": "Bearer an-oauth-access-token"},
                       data=form)
human = auth.create_api_key(boss, name="human", kind="human")["key"]
r3 = c_boss.post(f"/auth/approvals/{a1['id']}", headers={"X-Api-Key": human}, data=form)
r4 = c_boss.post(f"/auth/approvals/{a1['id']}", headers={"Authorization": f"Bearer {boss_key}"}, data=form)
assert [r1.status_code, r2.status_code, r3.status_code, r4.status_code] == [403] * 4, \
    [r1.status_code, r2.status_code, r3.status_code, r4.status_code]
assert state(auth, a1["id"]) == "pending" and roles_of(auth, anna) == ["viewers"]
assert len(audit(auth, "approval_denied")) >= 4
ok("1: confirming with an API key, an OAuth token, a human key beside its session → 403, nothing changed")

# ══ 2. another account ══════════════════════════════════════════════════════════════════════════════════════════
c_carol = session(auth, app, carol)
p = c_carol.get(f"/auth/approvals/{a1['id']}")
assert p.status_code == 404 and "anna" not in p.text and a1["match_code"] not in p.text and "editors" not in p.text \
    and "apvforeign" in p.text, p.text[:500]
assert c_carol.get("/auth/approvals/apv_" + "a" * 26).text.count("apvforeign") == 1, "unknown id answers differently"
r = c_carol.post(f"/auth/approvals/{a1['id']}", data=dict(form, password=PW))
assert r.status_code == 404 and state(auth, a1["id"]) == "pending" and roles_of(auth, anna) == ["viewers"]
ok("2: another account sees a neutral page (no summary, no code), cannot confirm (404), state unchanged")

# ══ 3. step-up per approval ═════════════════════════════════════════════════════════════════════════════════════
c_fresh = session(auth, app, boss)              # signed in this second: the session's step-up window is fresh
assert auth.stepup_fresh(type("R", (), {"cookies": {auth.session_cookie_name: c_fresh.cookies.get(
    auth.session_cookie_name)}, "headers": {}})(), dict(auth.get_user(boss), _via="session"))
r = decide(c_fresh, a1["id"])
assert r.status_code in (400, 401, 403) and state(auth, a1["id"]) == "pending", r.status_code
r = decide(c_fresh, a1["id"], password="wrong password 0000")
assert r.status_code == 401 and state(auth, a1["id"]) == "pending", r.status_code
assert any("reason=stepup" in (z["detail"] or "") for z in audit(auth, "approval_denied"))
r = decide(c_fresh, a1["id"], password=PW)
assert r.status_code == 200 and state(auth, a1["id"]) == "consumed", (r.status_code, r.text[:300])
assert auth.store.get_approval(a1["id"])["result"] == "ok" and roles_of(auth, anna) == ["editors"]
assert json.loads(auth.store.get_approval(a1["id"])["stepup_amr"]) == ["pwd"]
st = machine(app).get(f"/auth/api/approvals/{a1['id']}?wait=5", headers={"X-Api-Key": boss_key}).json()
assert st["state"] == "consumed" and st["result"] == "ok", st
ok("3: a fresh session without a secret, a wrong secret → refused; the right one → consumed, result ok, amr pwd")

# TOTP: with a confirmed TOTP and stepup_methods=["totp"] the password is not offered.
auth_t, app_t = build(stepup_methods=["totp"])
tina = auth_t.create_user("tina", password=PW, is_admin=True)
secret = auth_t.totp_begin(tina)["secret"]
auth_t.store.confirm_totp(tina)
tk = auth_t.create_api_key(tina, name="k")["key"]
at = request(auth_t, app_t, tk, "tinysesam.account.disable", account=str(auth_t.create_user("tom", password=PW)))
ct = session(auth_t, app_t, tina)
assert "name=password" not in ct.get(f"/auth/approvals/{at['id']}").text
assert decide(ct, at["id"], password=PW).status_code == 403 and state(auth_t, at["id"]) == "pending"
assert decide(ct, at["id"], code=_totp_clock.code(pyotp.TOTP(secret))).status_code == 200
assert state(auth_t, at["id"]) == "consumed" and json.loads(auth_t.store.get_approval(at["id"])["stepup_amr"]) == ["otp"]
ok("3: stepup_methods=['totp'] — the password is neither offered nor accepted, the TOTP code confirms (amr otp)")

# ══ 4. one transition ═══════════════════════════════════════════════════════════════════════════════════════════
a4 = request(auth, app, boss_key, account=str(anna), add=["viewers"])
d4 = page_hash(c_boss, a4["id"])
assert decide(c_boss, a4["id"], digest=d4, password=PW).status_code == 200
again = decide(c_boss, a4["id"], digest=d4, password=PW)
assert again.status_code == 409, again.status_code
a4b = request(auth, app, boss_key, account=str(anna), remove=["viewers"])
d4b = page_hash(c_boss, a4b["id"])
gate = threading.Barrier(2, timeout=20)
original = auth._stepup_secret


def waiting(*a, **k):
    out = original(*a, **k)
    gate.wait()           # both requests have passed the state check and the step-up before either transitions
    return out


auth._stepup_secret = waiting
codes = []
tok = c_boss.cookies.get(auth.session_cookie_name)


def one():
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    c.cookies.set(auth.session_cookie_name, tok)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    codes.append(decide(c, a4b["id"], digest=d4b, password=PW).status_code)


threads = [threading.Thread(target=one) for _ in range(2)]
for t_ in threads:
    t_.start()
for t_ in threads:
    t_.join(30)
auth._stepup_secret = original
executed = [z for z in audit(auth, "approval_executed") if a4b["id"] in z["detail"]]
assert sorted(codes) == [200, 409] and len(executed) == 1, (codes, executed)
ok("4: a second POST → 409; two parallel confirmations → one 200, one 409, one execution")

# ══ 5. payload changed between viewing and submitting ═══════════════════════════════════════════════════════════
a5 = request(auth, app, boss_key, account=str(anna), add=["teamadmin"])
d5 = page_hash(c_boss, a5["id"])
changed = apv.canonical({"type": "tinysesam.account.set_roles", "account": str(boss), "add": [], "remove": ["x"]})
auth.store._exec("UPDATE approval SET payload=?, payload_hash=? WHERE id=?", (changed, apv.payload_hash(changed), a5["id"]))
r = decide(c_boss, a5["id"], digest=d5, password=PW)
assert r.status_code == 409 and state(auth, a5["id"]) == "pending" and "teamadmin" not in roles_of(auth, anna), r.status_code
assert auth.t("apv.changed") in r.text
assert any("payload_changed" in (z["detail"] or "") for z in audit(auth, "approval_denied"))
ok("5: a payload that changed after the page was shown → 409, the page shows the current one, nothing executed")

# ══ 6. delegate: rights at confirmation time ════════════════════════════════════════════════════════════════════
dana = auth.create_user("dana", password=PW, roles=["teamadmin"])
erik = auth.create_user("erik", password=PW, roles=["viewers"])
dana_key = auth.create_api_key(dana, name="dana")["key"]
c_dana = session(auth, app, dana)
a6 = request(auth, app, dana_key, account=str(erik), add=["editors"])
assert decide(c_dana, a6["id"], password=PW).status_code == 200
assert auth.store.get_approval(a6["id"])["result"] == "ok" and roles_of(auth, erik) == ["editors", "viewers"]
a6b = request(auth, app, dana_key, account=str(erik), remove=["editors"])
d6b = page_hash(c_dana, a6b["id"])
auth.set_roles(dana, [])                         # the delegation ends between request and confirmation
r = decide(c_dana, a6b["id"], digest=d6b, password=PW)
assert r.status_code == 200 and auth.store.get_approval(a6b["id"])["result"] == "forbidden", \
    (r.status_code, auth.store.get_approval(a6b["id"])["result"])
assert state(auth, a6b["id"]) == "consumed" and roles_of(auth, erik) == ["editors", "viewers"]
auth.set_roles(dana, ["teamadmin"])
a6c = request(auth, app, dana_key, account=str(boss), add=["editors"])     # an admin: out of the delegate's scope
p = c_dana.get(f"/auth/approvals/{a6c['id']}")
assert "boss" not in p.text and f"#{boss}" in p.text, "the page named an account the delegate may not see"
assert decide(c_dana, a6c["id"], password=PW).status_code == 200
assert auth.store.get_approval(a6c["id"])["result"] == "forbidden" and roles_of(auth, boss) == []
ok("6: a delegate in scope → ok; delegation gone before confirming → forbidden; an account out of scope is named "
   "by id only and → forbidden")

# ══ 7. service account ══════════════════════════════════════════════════════════════════════════════════════════
svc = auth.create_service("backup-bot", roles=["editors"])
svc_key = auth.create_api_key(svc, name="bot")["key"]
r = machine(app).post("/auth/api/approvals", headers={"X-Api-Key": svc_key},
                      json={"type": "tinysesam.apikey.revoke", "fields": {"key": "1"}})
assert r.status_code == 403 and r.json()["error"] == "no_approver", r.text
assert any("no_approver" in (z["detail"] or "") for z in audit(auth, "approval_denied"))
ok("7: a service account's key → 403 no_approver (nobody could confirm), audited")

# ══ 8. limits and the rejection lock ════════════════════════════════════════════════════════════════════════════
auth8, app8 = build(approval_open_per_account=2, approval_open_per_token=5, approval_requests_per_hour=6,
                    approval_reject_limit=2)
u8 = auth8.create_user("lim", password=PW, is_admin=True)
k8 = auth8.create_api_key(u8, name="k")["key"]
t8 = str(auth8.create_user("t8", password=PW))
first = [request(auth8, app8, k8, "tinysesam.account.disable", account=t8) for _ in range(2)]
r = machine(app8).post("/auth/api/approvals", headers={"X-Api-Key": k8},
                       json={"type": "tinysesam.account.disable", "fields": {"account": t8}})
assert r.status_code == 429 and r.json()["error_description"] == "open_per_account" and r.headers["retry-after"]
c8 = session(auth8, app8, u8)
for a in first:
    assert decide(c8, a["id"], "reject").status_code == 200 and state(auth8, a["id"]) == "rejected"
r = machine(app8).post("/auth/api/approvals", headers={"X-Api-Key": k8},
                       json={"type": "tinysesam.account.disable", "fields": {"account": t8}})
assert r.status_code == 429 and r.json()["error_description"] == "rejections", r.text
other_type = request(auth8, app8, k8, "tinysesam.apikey.revoke", key="1")     # the lock is per type
assert machine(app8).delete(f"/auth/api/approvals/{other_type['id']}", headers={"X-Api-Key": k8}).json()["state"] \
    == "withdrawn"
auth8.store._exec("UPDATE approval SET decided_at=decided_at-4000 WHERE state='rejected'")
request(auth8, app8, k8, "tinysesam.account.disable", account=t8)           # the lock ends after the hour
auth8_ph, app8_ph = build(approval_requests_per_hour=2, approval_open_per_account=10, approval_open_per_token=10)
u8b = auth8_ph.create_user("ph", password=PW)
k8b = auth8_ph.create_api_key(u8b, name="k")["key"]
for _ in range(2):
    request(auth8_ph, app8_ph, k8b, "tinysesam.apikey.revoke", key="1")
r = machine(app8_ph).post("/auth/api/approvals", headers={"X-Api-Key": k8b},
                          json={"type": "tinysesam.apikey.revoke", "fields": {"key": "1"}})
assert r.status_code == 429 and r.json()["error_description"] == "per_hour"
auth8_tk, app8_tk = build(approval_open_per_token=1, approval_open_per_account=10)
u8c = auth8_tk.create_user("tk", password=PW)
k8c = auth8_tk.create_api_key(u8c, name="k")["key"]
request(auth8_tk, app8_tk, k8c, "tinysesam.apikey.revoke", key="1")
r = machine(app8_tk).post("/auth/api/approvals", headers={"X-Api-Key": k8c},
                          json={"type": "tinysesam.apikey.revoke", "fields": {"key": "1"}})
assert r.status_code == 429 and r.json()["error_description"] == "open_per_token"
assert machine(app8_tk).post("/auth/api/approvals", headers={"X-Api-Key": auth8_tk.create_api_key(
    u8c, name="k2")["key"]}, json={"type": "tinysesam.apikey.revoke", "fields": {"key": "1"}}).status_code == 201
assert len(audit(auth8, "approval_throttled")) == 2
ok("8: open per account, open per token, per hour and the rejection lock (per type, ends after an hour) → 429")

# ══ 9. expiry ═══════════════════════════════════════════════════════════════════════════════════════════════════
a9 = request(auth, app, boss_key, "tinysesam.account.disable", account=str(carol))
d9 = page_hash(c_boss, a9["id"])
auth.store._exec("UPDATE approval SET expires_at=? WHERE id=?", (int(time.time()) - 1, a9["id"]))
p = c_boss.get(f"/auth/approvals/{a9['id']}")
assert "apvform" not in p.text and state(auth, a9["id"]) == "pending", "the GET changed the row or offered a form"
r = decide(c_boss, a9["id"], digest=d9, password=PW)
assert r.status_code == 409 and state(auth, a9["id"]) == "expired" and not auth.store.get_user(carol)["disabled"]
assert machine(app).get(f"/auth/api/approvals/{a9['id']}", headers={"X-Api-Key": boss_key}).json()["state"] == "expired"
a9b = request(auth, app, boss_key, "tinysesam.account.disable", account=str(carol))
auth.store._exec("UPDATE approval SET expires_at=? WHERE id=?", (int(time.time()) - 1, a9b["id"]))
numbers = auth.gc()
assert numbers["approvals_expired"] >= 1 and state(auth, a9b["id"]) == "expired"
assert any(a9b["id"] in (z["detail"] or "") for z in audit(auth, "approval_expired"))
auth.store._exec("UPDATE approval SET decided_at=? WHERE id=?", (int(time.time()) - 40 * 86400, a9b["id"]))
assert auth.gc()["approvals_deleted"] >= 1 and auth.store.get_approval(a9b["id"]) is None
ok("9: past the deadline → the POST finds it expired (409), nothing executed; the gc expires and later deletes")

# ══ 10. never framed ════════════════════════════════════════════════════════════════════════════════════════════
for csp in ("strict", "off", "default-src 'self'; frame-ancestors *"):
    a10, b10 = build(csp=csp)
    u10 = a10.create_user("f", password=PW)
    k10 = a10.create_api_key(u10, name="k")["key"]
    x = request(a10, b10, k10, "tinysesam.apikey.revoke", key="1")
    c10 = session(a10, b10, u10)
    for path in (f"/auth/approvals/{x['id']}", "/auth/approvals"):
        h = c10.get(path).headers
        policy = h.get("content-security-policy", "")
        assert "frame-ancestors 'none'" in policy and "frame-ancestors *" not in policy \
            and h.get("x-frame-options") == "DENY", (csp, path, policy, h.get("x-frame-options"))
ok("10: frame-ancestors 'none' + X-Frame-Options DENY with csp strict, off and an own policy")

# ══ 11. a GET never confirms ════════════════════════════════════════════════════════════════════════════════════
a11 = request(auth, app, boss_key, "tinysesam.account.disable", account=str(carol))
d11 = page_hash(c_boss, a11["id"])
for path in (f"/auth/approvals/{a11['id']}", f"/auth/api/approvals/{a11['id']}"):
    c_boss.get(path, params={"_csrf": CSRF, "decision": "approve", "payload_hash": d11, "password": PW})
assert state(auth, a11["id"]) == "pending" and not auth.store.get_user(carol)["disabled"]
ok("11: a GET with every field of a decision decides nothing")

# ══ 12. summary escaped, from the database ══════════════════════════════════════════════════════════════════════
evil = "<img src=x onerror=alert(1)>"
a12 = request(auth, app, boss_key, account=str(anna), add=[evil])
auth.set_roles(anna, ["viewers", "editors"])        # changed AFTER the request: the page shows the state now
p = c_boss.get(f"/auth/approvals/{a12['id']}").text
assert evil not in p and "&lt;img src=x onerror=alert(1)&gt;" in p, "the role was inserted raw"
assert re.search(r"Roles now</th><td><bdi>editors, viewers</bdi>", p), "the current roles do not come from the database"
assert "<bdi>" in p and "anna (#" in p
ok("12: values escaped and bidi-isolated; the current roles come from the database at page time")

# ══ 13. passkey bound to the approval ═══════════════════════════════════════════════════════════════════════════
try:
    import cbor2  # noqa: F401
    import webauthn  # noqa: F401
    HAS_PASSKEY = True
except ModuleNotFoundError:
    HAS_PASSKEY = False


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


if HAS_PASSKEY:
    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    ORIGIN, RP = "http://localhost:8000", "localhost"
    a13, b13 = build(passkey_enabled=True, rp_id=RP, rp_name="Probe", origin=ORIGIN)
    u13 = a13.create_user("pia", password=PW, is_admin=True)
    key13 = ec.generate_private_key(ec.SECP256R1())
    nums = key13.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
    cred_id = os.urandom(32)
    a13.store.add_webauthn(u13, b64u(cred_id), b64u(cose), 0, ["internal"], "probe")
    counter = [0]

    def assertion(options: dict) -> str:
        counter[0] += 1
        auth_data = hashlib.sha256(RP.encode()).digest() + bytes([0x01 | 0x04]) + counter[0].to_bytes(4, "big")
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": ORIGIN,
                             "crossOrigin": False}).encode()
        sig = key13.sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return json.dumps({"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
                           "response": {"clientDataJSON": b64u(client), "authenticatorData": b64u(auth_data),
                                        "signature": b64u(sig), "userHandle": None}})

    k13 = a13.create_api_key(u13, name="k")["key"]
    x13 = request(a13, b13, k13, "tinysesam.account.disable", account=str(a13.create_user("vic", password=PW)))
    c13 = session(a13, b13, u13)
    page = c13.get(f"/auth/approvals/{x13['id']}").text
    assert "id=apvpk" in page
    begin = c13.post(f"/auth/approvals/{x13['id']}/passkey", headers={"X-CSRF-Token": CSRF})
    assert begin.status_code == 200, begin.text
    opts = begin.json()
    flow = json.loads(a13.store._one("SELECT data FROM flow WHERE key=?", ("apvpk:" + x13["id"],))["data"])
    digest13 = a13.store.get_approval(x13["id"])["payload_hash"]
    want = hashlib.sha256(b"tinysesam-approval:" + unb64u(flow["nonce"]) + x13["id"].encode() + digest13.encode()).digest()
    assert unb64u(opts["challenge"]) == want, "the challenge is not SHA-256(prefix ‖ nonce ‖ id ‖ payload_hash)"
    assert [c["id"] for c in opts["allowCredentials"]] == [b64u(cred_id)] and opts["userVerification"] == "required"
    other = request(a13, b13, k13, "tinysesam.apikey.revoke", key="99")
    begin_other = c13.post(f"/auth/approvals/{other['id']}/passkey", headers={"X-CSRF-Token": CSRF}).json()
    assert begin_other["challenge"] != opts["challenge"], "two approvals share a challenge"
    # The gesture for one approval does not confirm the other.
    wrong = decide(c13, other["id"], webauthn=assertion(opts))
    assert wrong.status_code == 401 and state(a13, other["id"]) == "pending", wrong.status_code
    answer = assertion(opts)
    assert decide(c13, x13["id"], webauthn=answer).status_code == 200 and state(a13, x13["id"]) == "consumed"
    assert json.loads(a13.store.get_approval(x13["id"])["stepup_amr"]) == ["hwk", "user"]
    # Used once: the same answer again (a fresh approval, no new begin) does not confirm.
    x13b = request(a13, b13, k13, "tinysesam.apikey.revoke", key="98")
    assert decide(c13, x13b["id"], webauthn=answer).status_code == 401 and state(a13, x13b["id"]) == "pending"
    assert c13.post(f"/auth/approvals/{x13['id']}/passkey", headers={"X-API-Key": k13}).status_code == 403
    ok("13: passkey challenge = SHA-256(prefix ‖ nonce ‖ id ‖ payload_hash), own credentials only, UV required; "
       "a gesture for one approval does not confirm another, nor twice")
else:
    print("  - 13 skipped: extra [passkey] or cbor2 missing (a skip is not a green — check.sh installs it)")

# ══ the provider: max_age=0, auth_time of this approval ═════════════════════════════════════════════════════════
import importlib.util  # noqa: E402

if all(importlib.util.find_spec(m) is not None for m in ("authlib", "httpx")):
    IDP = "https://idp.example.com"

    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    ao, bo = build(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret")
    ao.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                     "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
    from tinysesam.oidc import OIDCClient
    ao.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
    co = TestClient(bo, base_url=BASE, follow_redirects=False)

    def provider_round(auth_time, extra=""):
        claims = {"sub": "fed-1", "preferred_username": "fiona", "name": "Fiona"}
        if auth_time is not None:
            claims["auth_time"] = auth_time
        ao.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
            _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
        start = co.get("/auth/oidc/start?next=/" + extra)
        query = parse_qs(urlparse(start.headers["location"]).query)
        return query, co.get(f"/auth/oidc/callback?code=x&state={query['state'][0]}")

    provider_round(int(time.time()))
    fiona = ao.store.get_session(co.cookies.get(ao.session_cookie_name))["user_id"]
    ao.store.set_admin(fiona, True)
    co.cookies.set(ao.csrf_cookie_name, CSRF)
    fk = ao.create_api_key(fiona, name="k")["key"]
    xo = request(ao, bo, fk, "tinysesam.apikey.revoke", key="77")
    pg = co.get(f"/auth/approvals/{xo['id']}").text
    assert "id=apvoidc" in pg and f"approval={xo['id']}" in pg
    query, r = provider_round(int(time.time()) - 3600, f"&approval={xo['id']}")
    assert query.get("max_age") == ["0"] and query.get("prompt") == ["login"], query
    assert r.status_code == 303 and r.headers["location"].endswith(f"/auth/approvals/{xo['id']}?stepup=stale")
    assert decide(co, xo["id"], method="oidc").status_code == 401 and state(ao, xo["id"]) == "pending"
    query, r = provider_round(None, f"&approval={xo['id']}")
    assert decide(co, xo["id"], method="oidc").status_code == 401, "an answer without auth_time confirmed"
    query, r = provider_round(int(time.time()), f"&approval={xo['id']}")
    assert r.status_code == 303 and "id=apvoidcok" in co.get(f"/auth/approvals/{xo['id']}").text
    assert decide(co, xo["id"], method="oidc").status_code == 200 and state(ao, xo["id"]) == "consumed"
    assert json.loads(ao.store.get_approval(xo["id"])["stepup_amr"]) == ["oidc"]
    xo2 = request(ao, bo, fk, "tinysesam.apikey.revoke", key="78")
    assert decide(co, xo2["id"], method="oidc").status_code == 401, "one provider sign-in confirmed two approvals"
    ok("provider: max_age=0 + prompt=login; stale or missing auth_time → no confirmation; a fresh one confirms "
       "THIS approval once")
else:
    print("  - provider skipped: extra [oidc] missing (a skip is not a green — check.sh installs it)")

# ══ the three actions with the panel's code ═════════════════════════════════════════════════════════════════════
boss_key = auth.create_api_key(boss, name="claude-2")["key"]     # the first one has three open requests by now
k_anna = auth.create_api_key(anna, name="own")
anna_key = auth.create_api_key(anna, name="asker")["key"]
c_anna = session(auth, app, anna)
own = request(auth, app, anna_key, "tinysesam.apikey.revoke", key=str(k_anna["id"]))
assert "⚠" in c_anna.get(f"/auth/approvals/{own['id']}").text and "Permanent" in c_anna.get(
    f"/auth/approvals/{own['id']}").text
assert decide(c_anna, own["id"], password=PW).status_code == 200
assert auth.store.get_approval(own["id"])["result"] == "ok" and auth.store.get_api_key(k_anna["id"])["revoked"]
foreign = request(auth, app, anna_key, "tinysesam.apikey.revoke", key=str(auth.create_api_key(carol, name="c")["id"]))
assert decide(c_anna, foreign["id"], password=PW).status_code == 200
assert auth.store.get_approval(foreign["id"])["result"] == "forbidden"
ck = auth.create_api_key(carol, name="c2")["id"]
adm = request(auth, app, boss_key, "tinysesam.apikey.revoke", key=str(ck))
assert decide(c_boss, adm["id"], password=PW).status_code == 200 and auth.store.get_api_key(ck)["revoked"]
dis = request(auth, app, boss_key, "tinysesam.account.disable", account=str(carol))
assert decide(c_boss, dis["id"], password=PW).status_code == 200 and auth.store.get_user(carol)["disabled"]
self_dis = request(auth, app, boss_key, "tinysesam.account.disable", account=str(boss))
assert decide(c_boss, self_dis["id"], password=PW).status_code == 200
assert auth.store.get_approval(self_dis["id"])["result"] == "invalid" and not auth.store.get_user(boss)["disabled"]
ok("actions: own key revoked by the holder (⚠ Permanent); a foreign key → forbidden for a user, ok for an admin; "
   "disable by an admin; the panel's own refusal (no self-lock) → invalid")

# ══ badge and topbar_data ═══════════════════════════════════════════════════════════════════════════════════════
waiting_one = request(auth, app, anna_key, "tinysesam.account.disable", account=str(boss))
tb = c_anna.get("/auth/topbar.json").json()
assert tb["approvals"] == {"pending": 1, "href": f"{BASE}/auth/approvals"}, tb
html = c_anna.get("/auth/account").text
assert "Approvals (1)" in html and "class=tsbar-count" in html and "— Approvals (1)" in html
lst = c_anna.get("/auth/approvals").text
assert f"data-apv='{waiting_one['id']}'" in lst and waiting_one["match_code"] in lst
assert auth.topbar_data(auth.get_user(anna))["approvals"]["pending"] == 1
assert "approvals" not in auth.topbar_data(dict(auth.get_user(anna), _via="apikey"))
decide(c_anna, waiting_one["id"], "reject")
assert c_anna.get("/auth/topbar.json").json()["approvals"]["pending"] == 0
assert "Approvals (" not in c_anna.get("/auth/account").text and ">Approvals</a>" in c_anna.get("/auth/account").text
ok("badge: menu entry 'Approvals (1)' with number and word, count on the menu button, topbar_data.approvals, "
   "the list page; 0 → the plain entry")

# ══ audit without field values; security event ══════════════════════════════════════════════════════════════════
events = []
auth.on_security_event = lambda e, account, d: events.append((e, account["username"], d))
ev = request(auth, app, boss_key, account=str(anna), add=["teamadmin"])
assert decide(c_boss, ev["id"], password=PW).status_code == 200
lines = [z for z in auth.store.recent_audit(50) if z["event"].startswith("approval_") and ev["id"] in (z["detail"] or "")]
assert {z["event"] for z in lines} == {"approval_requested", "approval_approved", "approval_executed"}, lines
assert not any("teamadmin" in (z["detail"] or "") for z in lines), "a field value in the approval audit"
assert ("approval_approved", "boss") in [(e, n) for e, n, _ in events]
auth.on_security_event = None
ok("audit: requested/approved/executed with id, type, key, hash — no field values; security event approval_approved")

# ══ config_check ════════════════════════════════════════════════════════════════════════════════════════════════


def errors_of(**over):
    return config_check.check_config(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), **over))[0]


assert not errors_of(approvals_enabled=True, base_url=BASE)
assert any("approvals_enabled=True without base_url" in e for e in errors_of(approvals_enabled=True))
assert any("apikey_enabled=False" in e for e in errors_of(approvals_enabled=True, base_url=BASE, apikey_enabled=False))
assert any("csrf_enabled=False" in e for e in errors_of(approvals_enabled=True, base_url=BASE, csrf_enabled=False))
assert any("approval_pending_sec" in e for e in errors_of(approval_pending_sec=86400))
assert any("approval_reject_limit" in e for e in errors_of(approval_reject_limit=0))
ok("config_check: base_url, API keys and CSRF required; the limits have bounds")

# ══ migration from schema 21 ════════════════════════════════════════════════════════════════════════════════════
path = os.path.join(tempfile.mkdtemp(), "old.db")
s0 = Store(path)
s0.db.close()
raw = sqlite3.connect(path)
raw.execute("DROP TABLE approval")
raw.execute("PRAGMA user_version = 21")
raw.commit()
raw.close()
s1 = Store(path)
assert int(s1.db.execute("PRAGMA user_version").fetchone()[0]) == Store.SCHEMA_VERSION == 22
assert {r["name"] for r in s1.db.execute("PRAGMA table_info(approval)")} >= {
    "id", "class", "type", "app_id", "subject_id", "requester_kind", "requester_ref", "payload", "payload_hash",
    "match_code", "return_url", "state", "created_at", "expires_at", "decided_at", "issued_at", "stepup_amr",
    "auth_time", "result", "ip_request", "ip_decision"}
s1.db.close()
ok("migration: a schema-21 file gets the table `approval` (with the columns stage B needs) and stamp 22")

# ══ without approvals_enabled nothing changes ═══════════════════════════════════════════════════════════════════
off, off_app = build(approvals_enabled=False)
u_off = off.create_user("o", password=PW, is_admin=True)
k_off = off.create_api_key(u_off, name="k")["key"]
assert not [r.path for r in off_app.routes if "approval" in getattr(r, "path", "")]
assert machine(off_app).post("/auth/api/approvals", headers={"X-Api-Key": k_off},
                             json={"type": "tinysesam.account.disable", "fields": {"account": "1"}}).status_code == 404
c_off = session(off, off_app, u_off)
assert "approvals" not in c_off.get("/auth/topbar.json").json()
assert "approvals" not in off.topbar_data(off.get_user(u_off))
assert "/auth/approvals" not in c_off.get("/auth/account").text and "class=tsbar-count" not in c_off.get("/auth/account").text
assert not any(k.startswith("approvals") for k in off.gc())
assert off._approvals_pending(off.get_user(u_off)) is None
ok("off: no routes, no topbar member, no menu entry, no gc keys")

print("OK test_approvals")

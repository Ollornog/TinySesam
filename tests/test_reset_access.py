"""The approval type `tinysesam.account.reset_access`: an application asks, its team admin confirms with a step-up of
THAT approval, TinySesam deletes every sign-in factor of one of the application's accounts and hands the application
a new one-time link — exactly once.

One block per row of the acceptance table (draft "account API" §13); the mutation that turns each red is named next
to it and was run for the pull request:

 1. A leaked key + a straw account with every application role cannot confirm.     (`approver_role` check removed)
 2. `approver_role` in an allowlist → `config_check` error; granted by a delegate → warning.      (check removed)
 3. The role withdrawn after the request → the confirmation is `forbidden`.       (rights checked at request time)
 4. Target without `managed_by`, admin, service, delegate, shared, own account → 404 / 409 / `forbidden`, at the
    request and again at the confirmation.                                        (scope check removed)
 5. A second pick-up — also a parallel one — carries no link.                     (`approved` → `consumed` removed)
 6. The link is not in the audit, not in a log, not in the database.               (link written into the audit)
Plus: the effect (old password, TOTP, passkey, PIN, session, keys dead; the link signs in; `first_login_at` stays),
the audit line `account_access_reset`, the security event, request validation, the approval page (summary in words,
warning, the approver's right), withdrawing, and the page language.
"""
import base64
import hashlib
import importlib.util
import io
import json
import logging
import os
import re
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check  # noqa: E402
from tinysesam import approvals as apv  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"
CSRF = "csrfProbeToken0123456789abcdefgh"
ROLES = ["example-member", "example-editor", "example-approver", "staff", "teamadmin", "editors"]
ALLOW = ["example-member", "example-editor"]
SCOPES = ["users:read", "users:invite", "users:update", "users:disable", "users:reset"]
RESET = "tinysesam.account.reset_access"
HAS_PASSKEY = importlib.util.find_spec("webauthn") is not None and importlib.util.find_spec("cbor2") is not None
ORIGIN, RP = "http://localhost:8000", "localhost"


def ok(name):
    print(f"  ✓ {name}")


def apps(**block):
    p = {"roles": list(ALLOW), "scopes": list(SCOPES), "approver_role": "example-approver"}
    p.update(block)
    return {"example": {"account": "svc-example", "name": {"en": "Example", "de": "Beispiel"}, "provisioning": p}}


def build(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), oidc_enabled=False, cookie_secure=False,
               base_url=BASE, magiclink_enabled=True, approvals_enabled=True, available_roles=list(ROLES),
               admin_delegates={"teamadmin": {"roles": ["editors"]}}, apps=apps(),
               passkey_enabled=HAS_PASSKEY)
    if HAS_PASSKEY:
        cfg.update(rp_id=RP, rp_name="Probe", origin=ORIGIN)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def client(app):
    return TestClient(app, base_url=BASE, follow_redirects=False)


def session(auth, app, uid):
    c = client(app)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    c.cookies.set(auth.session_cookie_name, tok)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    return c


def ask(app, key, subject, account, status=201, **extra):
    body = {"type": RESET, "subject": str(subject), "fields": {"account": str(account)}}
    body.update(extra)
    r = client(app).post("/auth/api/approvals", headers={"X-Api-Key": key}, json=body)
    assert r.status_code == status, (r.status_code, r.text)
    return r.json()


def page_hash(c, aid):
    p = c.get(f"/auth/approvals/{aid}")
    assert p.status_code == 200, (p.status_code, p.text[:300])
    return re.search(r"name=payload_hash value='([^']+)'", p.text).group(1)


def confirm(c, aid, password=PW):
    csrf = c.cookies.get(auth.csrf_cookie_name) or CSRF     # a sign-in through the link rotated it
    return c.post(f"/auth/approvals/{aid}", data={"_csrf": csrf, "decision": "approve",
                                                  "payload_hash": page_hash(c, aid), "password": password})


def status(app, key, aid, wait=0):
    r = client(app).get(f"/auth/api/approvals/{aid}" + (f"?wait={wait}" if wait else ""), headers={"X-Api-Key": key})
    assert r.status_code == 200, (r.status_code, r.text)
    return r.json()


def row(auth, aid):
    return auth.store.get_approval(aid)


def audit(auth, event=None):
    return [a for a in auth.store.recent_audit(5000) if event is None or a["event"] == event]


def login(app, auth, username, password=PW):
    c = client(app)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    r = c.post("/auth/login", data={"username": username, "password": password, "_csrf": CSRF})
    return r.status_code in (200, 303) and bool(c.cookies.get(auth.session_cookie_name))


def redeem(app, auth, url):
    c = client(app)
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    r = c.post(urlpath(url), data={"_csrf": CSRF})
    rotated = r.cookies.get(auth.csrf_cookie_name)
    if rotated:                     # the sign-in rotated the CSRF token: keep exactly the new one in the jar
        for ck in [ck for ck in c.cookies.jar if ck.name == auth.csrf_cookie_name]:
            c.cookies.jar.clear(ck.domain, ck.path, ck.name)
        c.cookies.set(auth.csrf_cookie_name, rotated)
    return c, r


def urlpath(url):
    return url[len(BASE):]


def create(app, key, username, roles=None):
    r = client(app).post("/auth/api/users", headers={"X-Api-Key": key, "TinySesam-On-Behalf-Of": "-"},
                         json={"username": username, "roles": roles or ["example-member"]})
    assert r.status_code == 201, r.text
    return r.json()


auth, app = build()
events = []
auth.on_security_event = lambda e, account, details: events.append((e, account["id"], dict(details)))
svc = auth.create_service("svc-example")
key = auth.create_api_key(svc, name="example")["key"]
boss = auth.create_user("boss", password=PW, is_admin=True)
lead = auth.create_user("lead", password=PW, roles=["example-approver"])     # the team admin, given the role by the operator
c_lead = session(auth, app, lead)


def victim(name):
    """An application account that signed in before and has a password (and more, where asked)."""
    made = create(app, key, name)
    uid = made["id"]
    auth.set_password(uid, PW)
    auth.store.mark_login(uid, int(time.time()) - 3600)
    return uid


FAILED = []


def run(name, block):
    """Run one block; a failing block is reported and the others still run — so a mutation shows every row it
    turns red, not only the first one."""
    try:
        block()
    except Exception:  # noqa: BLE001 — every failure counts, also an unexpected exception
        import traceback
        FAILED.append(name)
        print(f"  ✗ {name}")
        traceback.print_exc()


# ══ request: 201, the row ═══════════════════════════════════════════════════════════════════════════════════════
def block_0():
    v0 = victim("vera")
    a0 = ask(app, key, lead, v0)
    assert apv.valid_id(a0["id"]) and a0["state"] == "pending" and a0["approve_url"] == f"{BASE}/auth/approvals/{a0['id']}"
    r0 = row(auth, a0["id"])
    assert (r0["requester_kind"], r0["requester_ref"], r0["app_id"], r0["subject_id"], r0["class"]) == \
        ("app", str(svc), "example", lead, "tinysesam"), dict(r0)
    assert json.loads(r0["payload"]) == {"type": RESET, "account": str(v0)}
    assert status(app, key, a0["id"])["state"] == "pending"
    assert any("reason" not in (z["detail"] or "") and "app=example" in (z["detail"] or "")
               for z in audit(auth, "approval_requested")), "the request line names the application"
    ok("request: 201, requester = the application's service account, subject = the team admin, payload {account}")

    # ══ the page: summary in words, the warning, the methods ═════════════════════════════════════════════════════════
    page = c_lead.get(f"/auth/approvals/{a0['id']}").text
    assert "Reset the access of vera (#%d) for Example" % v0 in page, page[:2000]
    assert "id=apvirrev" in page and "stop working at once" in page and "⚠" in page
    assert "Signs in now with" in page and "password" in page and "Requested by the application" in page
    assert "API keys, app passwords, services and connected programs are revoked" in page and "PIN" in page
    assert "Also ends" in page, page[:3000]
    nobody = auth.create_user("nobody", password=PW, roles=["staff"])
    a_nobody = ask(app, key, nobody, v0)
    p_nobody = session(auth, app, nobody).get(f"/auth/approvals/{a_nobody['id']}").text
    assert "vera" not in p_nobody and f"#{v0}" in p_nobody and "approver role" in p_nobody, p_nobody[:2000]
    assert client(app).delete(f"/auth/api/approvals/{a_nobody['id']}", headers={"X-Api-Key": key}).json()["state"] \
        == "withdrawn"
    ok("page: 'Reset the access of vera … for Example', ⚠ warning, methods now; without the role only #id and 'missing'")

    # ══ the effect, pick-up once, the link signs in ═════════════════════════════════════════════════════════════════
    if HAS_PASSKEY:
        import cbor2
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        def b64u(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        pkey = ec.generate_private_key(ec.SECP256R1())
        nums = pkey.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        cred = os.urandom(32)
        auth.store.add_webauthn(v0, b64u(cred), b64u(cose), 0, ["internal"], "phone")
        counter = [0]

        def passkey_login():
            cc = client(app)
            cc.cookies.set(auth.csrf_cookie_name, CSRF)
            opts = cc.post("/auth/passkey/login/begin", headers={"X-CSRF-Token": CSRF}).json()
            counter[0] += 1
            auth_data = hashlib.sha256(RP.encode()).digest() + bytes([0x01 | 0x04]) + counter[0].to_bytes(4, "big")
            client_data = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": ORIGIN,
                                      "crossOrigin": False}).encode()
            sig = pkey.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
            body = json.dumps({"id": b64u(cred), "rawId": b64u(cred), "type": "public-key",
                               "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                                            "signature": b64u(sig), "userHandle": None}})
            r = cc.post("/auth/passkey/login/finish", headers={"X-CSRF-Token": CSRF, "Content-Type": "application/json"},
                        content=body)
            return r.status_code == 200 and bool(cc.cookies.get(auth.session_cookie_name))

        assert passkey_login(), "the probe: the passkey signs in before the reset"
    auth.store.set_totp(v0, "JBSWY3DPEHPK3PXP", confirmed=True)
    auth.store.add_recovery_codes(v0, ["h1", "h2"])
    auth.set_pin(v0, "84736251")
    old_session = auth.store.create_session(v0, 86400, True, "password", factors=["password"])
    v0_key = auth.create_api_key(v0, name="theirs")["key"]
    ends = c_lead.get(f"/auth/approvals/{a0['id']}").text
    assert "1 API key(s)" in ends and "session(s)" in ends, ends[:3000]
    first_login = auth.store.get_user(v0)["first_login_at"]
    assert login(app, auth, "vera"), "the probe: the password signs in before the reset"
    events.clear()

    r = confirm(c_lead, a0["id"])
    assert r.status_code == 200 and "Done" in r.text, (r.status_code, r.text[:500])
    assert row(auth, a0["id"])["state"] == "approved" and row(auth, a0["id"])["result"] == "ok"
    u = auth.store.get_user(v0)
    assert auth.store.get_password_hash(v0) is None and not auth.store.has_confirmed_totp(v0)
    assert auth.store.get_totp(v0) is None and not auth.store.list_webauthn(v0) and not auth.store.has_pin(v0)
    assert auth.store._one("SELECT COUNT(*) AS n FROM recovery_code WHERE user_id=?", (v0,))["n"] == 0
    assert auth.store.get_session(old_session) is None, "the old session survived"
    assert auth.verify_api_key(v0_key)[0] is None, "the old API key survived"
    assert u["first_login_at"] == first_login and not u["disabled"]
    assert not login(app, auth, "vera"), "the old password still signs in"
    if HAS_PASSKEY:
        assert not passkey_login(), "the old passkey still signs in"
    line = [z for z in audit(auth, "account_access_reset") if z["username"] == "vera"]
    assert len(line) == 1 and all(w in line[0]["detail"] for w in (
        "app=example", f"approved_by=lead#{lead}", "password=1", "totp=1", "pin=1", f"approval={a0['id']}")), line
    assert ("passkeys=1" in line[0]["detail"]) == HAS_PASSKEY and "actor=lead" in line[0]["detail"], line
    reset_events = [e for e in events if e[0] == "access_reset"]
    assert len(reset_events) == 1 and reset_events[0][1] == v0 and reset_events[0][2]["app"] == "example" \
        and reset_events[0][2]["approved_by"] == "lead", events
    assert any(e[0] == "api_keys_revoked" and e[2]["reason"] == "access_reset" for e in events), events

    got = status(app, key, a0["id"], wait=3)
    assert got["state"] == "consumed" and got["result"] == "ok", got
    link = got["output"]["signin_url"]
    assert link.startswith(f"{BASE}/auth/magic/") and got["output"]["account"] == str(v0)
    assert got["output"]["expires_at"] > time.time() + 50 * 60, got
    again = status(app, key, a0["id"])
    assert again["state"] == "consumed" and "output" not in again and "signin_url" not in json.dumps(again), again
    c_v, r_v = redeem(app, auth, link)
    assert r_v.status_code in (200, 303) and c_v.cookies.get(auth.session_cookie_name), (r_v.status_code, r_v.text[:400])
    me = c_v.get("/auth/me")
    assert me.status_code == 200 and me.json().get("username") == "vera", (me.status_code, me.text[:300])
    assert auth.store.get_user(v0)["mfa_enroll_until"] > time.time(), "no setup window for the factors"
    c_v2, r_v2 = redeem(app, auth, link)
    assert not c_v2.cookies.get(auth.session_cookie_name), "the link signed in twice"
    ok("effect: password, TOTP + recovery codes, PIN, passkey, session, key gone; first_login_at stays; audit "
       "account_access_reset (app, approved_by, counts); event access_reset; the link once, it signs in once")


run('request: 201, the row', block_0)


# ══ 1. the straw account ════════════════════════════════════════════════════════════════════════════════════════
def block_1():
    v1 = victim("victor")
    straw = create(app, key, "straw", roles=list(ALLOW))
    r = client(app).patch(f"/auth/api/users/{straw['id']}", headers={"X-Api-Key": key, "TinySesam-On-Behalf-Of": "-"},
                          json={"roles": list(ALLOW) + ["example-approver"]})
    assert r.status_code == 400 and r.json()["error"] == "role_not_allowed", r.text
    c_straw, r_s = redeem(app, auth, straw["signin_url"])
    assert c_straw.cookies.get(auth.session_cookie_name), ("the straw account signs in with its link", r_s.status_code)
    auth.set_password(straw["id"], PW)          # the attacker sets a password on the account page of their session
    a1 = ask(app, key, straw["id"], v1)
    r = confirm(c_straw, a1["id"])
    assert r.status_code == 200 and row(auth, a1["id"])["state"] == "consumed", (r.status_code, r.text[:300])
    assert row(auth, a1["id"])["result"] == "forbidden", dict(row(auth, a1["id"]))
    assert login(app, auth, "victor"), "the straw account reset the victim"
    st1 = status(app, key, a1["id"])
    assert st1["result"] == "forbidden" and "output" not in st1
    assert not [z for z in audit(auth, "account_access_reset") if z["username"] == "victor"]
    ok("1: leaked key → straw account with every allowlist role, signed in by its link, confirms → forbidden, "
       "victim unchanged, no link")


run('1. the straw account', block_1)


# ══ 2. config_check ═════════════════════════════════════════════════════════════════════════════════════════════
def block_2():
    def check(**over):
        """(errors, warnings) of `config_check` for a configuration."""
        cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE, magiclink_enabled=True,
                   approvals_enabled=True, available_roles=list(ROLES), apps=apps(),
                   admin_delegates={"teamadmin": {"roles": ["editors"]}})
        cfg.update(over)
        errors, warnings = config_check.check_config(TinySesamConfig(**cfg))
        return [e for e in errors if "apps" in e], [w for w in warnings if "apps" in w]


    e, w = check()
    assert not e and not w, (e, w)
    both = apps(approver_role="example-member")
    e, _w = check(apps=both)
    assert any("stands in the allowlist of 'example'" in x for x in e), e
    two = apps()
    two["other"] = {"account": "svc-other", "provisioning": {"roles": ["example-approver"], "scopes": ["users:read"]}}
    e, _w = check(apps=two, available_roles=list(ROLES))
    assert any("approver_role: 'example-approver' stands in the allowlist of 'other'" in x for x in e), e
    _e, w = check(admin_delegates={"teamadmin": {"roles": ["editors", "example-approver"]}})
    assert any("may be granted by the delegates of 'teamadmin'" in x for x in w) and not _e, (_e, w)
    for over, needle in (({"apps": apps(approver_role=None)}, "users:reset needs provisioning.approver_role"),
                         ({"apps": apps(approver_role="admin")}, "\"admin\" is the admin flag"),
                         ({"apps": apps(approver_role="ghost")}, "'ghost' is not in available_roles"),
                         ({"apps": apps(approver_role="a,b")}, "one role name without comma"),
                         ({"approvals_enabled": False}, "users:reset needs approvals_enabled=True"),
                         ({"magiclink_enabled": False}, "users:reset needs magiclink_enabled=True"),
                         ({"magiclink_first_login_only": True}, "magiclink_first_login_only=True and no login_chain"),
                         ({"base_url": ""}, "users:reset needs base_url")):
        e, _w = check(**over)
        assert any(needle in x for x in e), (over, needle, e)
    _e, w = check(apps=apps(scopes=["users:read"]))
    assert any("the scope users:reset is missing" in x for x in w) and not _e, (_e, w)
    e, _w = check(apps=both, lang="de")
    assert any("steht in der Allowlist von 'example'" in x for x in e), e
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "x.db"), base_url=BASE,
                                  magiclink_enabled=True, approvals_enabled=True, available_roles=list(ROLES), apps=both))
        raise AssertionError("an approver role in the allowlist was accepted")
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 — ConfigError at construction
        assert "stands in the allowlist" in str(exc), exc
    from tinysesam import provisioning as prov  # noqa: E402
    norm = prov.normalize_apps(type("C", (), dict(apps=both, admin_delegates={}, available_roles=list(ROLES),
                                                     oidc_group_role_map={}, saml_group_role_map={},
                                                     ldap_group_role_map={}, oidc_clients={},
                                                     signin_link_max_ttl_min=1440)))
    assert norm["example"]["approver_role"] is None and "users:reset" not in norm["example"]["scopes"], norm
    ok("2: approver_role in any allowlist → error (en/de, also at construction; at runtime the scope counts for "
       "nothing); granted by a delegate → warning; missing/admin/unknown/malformed/no approvals/no link → errors")


run('2. config_check', block_2)


# ══ 3. the role withdrawn after the request ═════════════════════════════════════════════════════════════════════
def block_3():
    v3 = victim("vince")
    lead3 = auth.create_user("lead3", password=PW, roles=["example-approver"])
    a3 = ask(app, key, lead3, v3)
    c3 = session(auth, app, lead3)
    h3 = page_hash(c3, a3["id"])
    auth.set_roles(lead3, ["staff"])
    r = c3.post(f"/auth/approvals/{a3['id']}", data={"_csrf": CSRF, "decision": "approve", "payload_hash": h3,
                                                      "password": PW})
    assert r.status_code == 200 and row(auth, a3["id"])["result"] == "forbidden", dict(row(auth, a3["id"]))
    assert login(app, auth, "vince"), "reset by an account that lost the role"
    # … and an administrator without the role is no approver either.
    a3b = ask(app, key, boss, v3)
    assert confirm(session(auth, app, boss), a3b["id"]).status_code == 200
    assert row(auth, a3b["id"])["result"] == "forbidden" and login(app, auth, "vince")
    ok("3: the role withdrawn between request and confirmation → forbidden; an administrator without it → forbidden")


run('3. the role withdrawn after the request', block_3)


# ══ 4. scope of the target ══════════════════════════════════════════════════════════════════════════════════════
def block_4():
    plain = auth.create_user("plain", password=PW, roles=["example-member"])      # not created by the application
    deleg = victim("delly")
    auth.set_roles(deleg, ["example-member", "teamadmin"])                         # became a delegate
    shared = victim("shary")
    auth.set_roles(shared, ["example-member", "staff"])                            # a role from outside the allowlist
    made_admin = victim("addy")
    auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (made_admin,))
    for target, code, http in ((plain, "not_found", 404), (boss, "not_found", 404), (svc, "not_found", 404),
                               (deleg, "not_found", 404), (made_admin, "not_found", 404), (99999, "not_found", 404),
                               (shared, "account_shared", 409)):
        got = ask(app, key, lead, target, status=http)
        assert got["error"] == code, (target, got)
    own = victim("ownie")
    assert ask(app, key, own, own, status=403)["error"] == "forbidden"
    locked = victim("locky")
    auth.store._exec("UPDATE users SET disabled=3 WHERE id=?", (locked,))
    assert ask(app, key, lead, locked, status=409)["error"] == "account_disabled"
    assert not [z for z in audit(auth, "approval_requested") if f"account={plain} " in (z["detail"] or "")]
    # Again at the confirmation: the target became an administrator after the request.
    v4 = victim("vito")
    a4 = ask(app, key, lead, v4)
    h4 = page_hash(c_lead, a4["id"])
    auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (v4,))
    r = c_lead.post(f"/auth/approvals/{a4['id']}", data={"_csrf": CSRF, "decision": "approve", "payload_hash": h4,
                                                          "password": PW})
    assert r.status_code == 200 and row(auth, a4["id"])["result"] == "not_found", dict(row(auth, a4["id"]))
    assert auth.store.get_password_hash(v4) is not None
    auth.store._exec("UPDATE users SET is_admin=0 WHERE id=?", (v4,))
    v4b = victim("vitb")
    a4b = ask(app, key, lead, v4b)
    h4b = page_hash(c_lead, a4b["id"])
    auth.set_roles(v4b, ["example-member", "staff"])
    c_lead.post(f"/auth/approvals/{a4b['id']}", data={"_csrf": CSRF, "decision": "approve", "payload_hash": h4b,
                                                       "password": PW})
    assert row(auth, a4b["id"])["result"] == "conflict" and auth.store.get_password_hash(v4b) is not None
    ok("4: not created by the app, admin, service, delegate, unknown → 404; shared → 409; own account → forbidden; "
       "disabled → 409; at the confirmation again (became admin → not_found, shared → conflict)")


run('4. scope of the target', block_4)


# ══ 5. the second pick-up ═══════════════════════════════════════════════════════════════════════════════════════
def block_5():
    v5 = victim("vic5")
    a5 = ask(app, key, lead, v5)
    assert confirm(c_lead, a5["id"]).status_code == 200
    issued_before = len([z for z in audit(auth, "signin_link_issue") if z["username"] == "vic5"])
    outs, gate = [], threading.Barrier(2, timeout=20)


    def pick():
        gate.wait()
        outs.append(status(app, key, a5["id"]))


    threads = [threading.Thread(target=pick) for _ in range(2)]
    for t_ in threads:
        t_.start()
    for t_ in threads:
        t_.join(30)
    assert len(outs) == 2 and sorted("output" in o for o in outs) == [False, True], outs
    assert all(o["state"] == "consumed" for o in outs)
    third = status(app, key, a5["id"])
    assert third["state"] == "consumed" and "output" not in third
    assert len([z for z in audit(auth, "signin_link_issue") if z["username"] == "vic5"]) == issued_before + 1
    other_key = auth.create_api_key(svc, name="second")["key"]
    assert "output" not in status(app, other_key, a5["id"]), "another key of the application picked it up again"
    ok("5: two parallel pick-ups → one link; every later read → consumed without a link; one link issued")


run('5. the second pick-up', block_5)


# ══ 6. the link nowhere else ════════════════════════════════════════════════════════════════════════════════════
def block_6():
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        v6 = victim("vic6")
        a6 = ask(app, key, lead, v6)
        confirm(c_lead, a6["id"])
        out6 = status(app, key, a6["id"])["output"]
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
    token6 = out6["signin_url"].rsplit("/", 1)[1]
    assert token6 not in buf.getvalue(), "the link is in a log"
    assert not any(token6 in (a["detail"] or "") or token6 in (a["username"] or "") for a in audit(auth)), "link in audit"
    assert token6 not in json.dumps([dict(r) for r in auth.store._all("SELECT * FROM magic_token")])
    assert token6 not in json.dumps([dict(r) for r in auth.store._all("SELECT * FROM approval")])
    assert token6 not in json.dumps([dict(r) for r in auth.store._all("SELECT * FROM flow")])
    assert token6 not in json.dumps(events, default=str)
    assert token6 not in a6["approve_url"]
    ok("6: the link not in a log line (all loggers), not in the audit, not in a table, not in an event, not in a URL")


run('6. the link nowhere else', block_6)


# ══ request validation ══════════════════════════════════════════════════════════════════════════════════════════
def block_7():
    v7 = victim("vic7")
    human = auth.create_api_key(lead, name="mine")["key"]
    r = client(app).post("/auth/api/approvals", headers={"X-Api-Key": human},
                         json={"type": RESET, "fields": {"account": str(v7)}})
    assert r.status_code == 400 and r.json()["error"] == "invalid_type", r.text
    r = client(app).post("/auth/api/approvals", headers={"X-Api-Key": key},
                         json={"type": "tinysesam.account.disable", "subject": str(lead), "fields": {"account": str(v7)}})
    assert r.status_code == 400 and r.json()["error"] == "invalid_type", r.text
    assert ask(app, key, lead, v7, status=400, extra=1)["error"] == "invalid_request"
    r = client(app).post("/auth/api/approvals", headers={"X-Api-Key": key},
                         json={"type": RESET, "subject": lead, "fields": {"account": str(v7)}})
    assert r.status_code == 400 and r.json()["error"] == "invalid_request", r.text
    r = client(app).post("/auth/api/approvals", headers={"X-Api-Key": key},
                         json={"type": RESET, "subject": str(lead), "fields": {"account": v7}})
    assert r.status_code == 400 and r.json()["error"] == "invalid_request", r.text
    disabled_person = auth.create_user("gone", password=PW, roles=["example-approver"])
    auth.set_disabled(disabled_person, True)
    for subject in (svc, disabled_person, 99998):
        assert ask(app, key, subject, v7, status=400)["error"] == "invalid_subject", subject
    stranger = auth.create_service("svc-stranger")
    skey = auth.create_api_key(stranger, name="s")["key"]
    assert ask(app, skey, lead, v7, status=403)["error"] == "no_approver"
    a7 = ask(app, key, lead, v7)
    assert client(app).get(f"/auth/api/approvals/{a7['id']}", headers={"X-Api-Key": skey}).status_code == 403
    assert client(app).get(f"/auth/api/approvals/{a7['id']}", headers={"X-Api-Key": human}).status_code == 404
    auth_n, app_n = build(apps=apps(scopes=["users:read", "users:invite"], approver_role=None))
    svc_n = auth_n.create_service("svc-example")
    key_n = auth_n.create_api_key(svc_n, name="k")["key"]
    lead_n = auth_n.create_user("lead", password=PW, roles=["example-approver"])
    vn = create(app_n, key_n, "vn")["id"]
    assert ask(app_n, key_n, lead_n, vn, status=403)["error"] == "scope_missing"
    ok("validation: a person's key → invalid_type; another type, unknown member, numbers instead of strings → 400; "
       "subject service/disabled/unknown → invalid_subject; a foreign service account → no_approver; "
       "status only for the application; without users:reset → scope_missing")


run('request validation', block_7)


# ══ limits: open requests per application ═══════════════════════════════════════════════════════════════════
def block_8():
    auth_l, app_l = build(approval_open_per_token=2)
    svc_l = auth_l.create_service("svc-example")
    key_l = auth_l.create_api_key(svc_l, name="k")["key"]
    leads = [auth_l.create_user(f"l{i}", password=PW, roles=["example-approver"]) for i in range(3)]
    vl = create(app_l, key_l, "vl")["id"]
    ask(app_l, key_l, leads[0], vl)
    ask(app_l, key_l, leads[1], vl)
    assert ask(app_l, key_l, leads[2], vl, status=429)["error"] == "too_many_requests"
    ok("limits: approval_open_per_token counts the application's open requests (429)")


run('limits: open requests per application', block_8)


# ══ a chain, link only for the first sign-in, strict enrollment: the link opens the setup pass ════════════════════
def block_9():
    auth_c, app_c = build(login_chain=["password", "totp"], magiclink_first_login_only=True, mfa_enrollment="strict")
    svc_c = auth_c.create_service("svc-example")
    key_c = auth_c.create_api_key(svc_c, name="k")["key"]
    lead_c = auth_c.create_user("lead", password=PW, roles=["example-approver"])
    auth_c.store.set_totp(lead_c, "JBSWY3DPEHPK3PXP", confirmed=True)
    vc = create(app_c, key_c, "chained")["id"]
    auth_c.set_password(vc, PW)
    auth_c.store.set_totp(vc, "JBSWY3DPEHPK3PXP", confirmed=True)
    auth_c.store.mark_login(vc, int(time.time()) - 60)
    assert not auth_c._link_allowed(vc), "the probe: a complete account gets no link sign-in here"
    ac = ask(app_c, key_c, lead_c, vc)
    cc = session(auth_c, app_c, lead_c)
    hc = page_hash(cc, ac["id"])
    assert cc.post(f"/auth/approvals/{ac['id']}", data={"_csrf": CSRF, "decision": "approve", "payload_hash": hc,
                                                        "password": PW}).status_code == 200
    outc = status(app_c, key_c, ac["id"])
    assert outc["result"] == "ok" and outc["output"]["signin_url"], outc
    c_c = client(app_c)
    c_c.cookies.set(auth_c.csrf_cookie_name, CSRF)
    r = c_c.post(outc["output"]["signin_url"][len(BASE):], data={"_csrf": CSRF})
    assert r.status_code == 303 and "/auth/setup" in r.headers.get("location", ""), (r.status_code, r.headers)
    ok("chain password+totp, magiclink_first_login_only, mfa_enrollment=strict: the link is issued and opens the setup "
       "pass (a setup window for the link's lifetime)")


run('a chain, link only for the first sign-in, strict enrollment: the link opens the setup pass', block_9)


# ══ German page ═════════════════════════════════════════════════════════════════════════════════════════════════
def block_10():
    auth_d, app_d = build(lang="de")
    svc_d = auth_d.create_service("svc-example")
    key_d = auth_d.create_api_key(svc_d, name="k")["key"]
    lead_d = auth_d.create_user("lead", password=PW, roles=["example-approver"])
    vd = create(app_d, key_d, "vera")["id"]
    auth_d.set_password(vd, PW)
    ad = ask(app_d, key_d, lead_d, vd)
    pd = session(auth_d, app_d, lead_d).get(f"/auth/approvals/{ad['id']}").text
    assert f"Zugang von vera (#{vd}) für Beispiel zurücksetzen" in pd and "funktionieren sofort nicht mehr" in pd, pd[:1500]
    assert "Angefragt von der Anwendung „Beispiel“" in pd
    ok("page in German: the summary in words, the warning, the application's German name")


run('German page', block_10)


if FAILED:
    print("FAILED test_reset_access: " + ", ".join(FAILED))
    sys.exit(1)
print("OK test_reset_access")

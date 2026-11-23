"""T-89 stage B part 2: the example application `examples/approvals/app.py` against a real TinySesam.

The example asks for an action, sends the browser to TinySesam, comes back, picks the confirmation up, checks it with
`tinysesam.approval_token.verify`, writes the `jti` with one INSERT and runs its own rule again. Here the person's part
(sign-in, step-up, decision) happens on TinySesam's real approval page; only the transport is in-process (TestClient).

 1. The owner deletes a collection: ask → 303 to TinySesam → confirm with the password → back → deleted.
 2. The own rule before asking: another account's collection is refused, nothing is asked.
 3. The same return address twice: nothing waits any more; the confirmation itself a second time is `replay`.
 4. Another browser (no or another state cookie): refused before anything is picked up.
 5. Rejected at TinySesam: back with `result=rejected`, nothing happens.
 6. The own rule again: the owner changed between asking and coming back — confirmed, checked, but not carried out.
"""
import importlib.util
import os
import re
import sys
import tempfile
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, approval_token  # noqa: E402

BASE = "https://auth.example.com"
RETURN = "https://app.example.com/approvals/return"
PW = "a long probe password 4711"
CSRF = "csrfProbeToken0123456789abcdefgh"

spec = importlib.util.spec_from_file_location("example_approvals", os.path.join(ROOT, "examples", "approvals", "app.py"))
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)


def ok(name):
    print(f"  ✓ {name}")


auth = TinySesam(TinySesamConfig(
    lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), base_url=BASE,
    passkey_enabled=False, oidc_enabled=False, approvals_enabled=True,
    apps={example.APP_ID: {"account": "svc-example", "name": {"en": "Example"},
                           "approvals": {"types": example.TYPES, "return_urls": [RETURN]}}}))
auth.set_security("password_min_length_single_factor", 8)
fastapi_app = FastAPI()
fastapi_app.include_router(auth.router())
key = auth.create_api_key(auth.create_service("svc-example"), name="example")["key"]
anna, bert = str(auth.create_user("anna", password=PW)), str(auth.create_user("bert", password=PW))
machine = TestClient(fastapi_app, base_url=BASE, follow_redirects=False)
calls = []


def api(method, path, body=None):
    calls.append((method, path))
    r = machine.request(method, path, json=body, headers={"X-Api-Key": key})
    return r.status_code, r.json()


def browser(uid):
    c = TestClient(fastapi_app, base_url=BASE, follow_redirects=False)
    c.cookies.set(auth.session_cookie_name, auth.store.create_session(int(uid), 86400, True, "password",
                                                                       factors=["password"]))
    c.cookies.set(auth.csrf_cookie_name, CSRF)
    return c


def decide(c, approve_url, decision="approve"):
    """The person on TinySesam's page: compare, step up with the password, decide. Returns the redirect target."""
    path = urlsplit(approve_url).path
    p = c.get(path)
    assert p.status_code == 200, (p.status_code, p.text[:300])
    digest = re.search(r"name=payload_hash value='([^']+)'", p.text).group(1)
    r = c.post(path, data={"_csrf": CSRF, "decision": decision, "payload_hash": digest, "password": PW})
    assert r.status_code in (302, 303), (r.status_code, r.text[-500:])
    return r.headers["location"]


app = example.ExampleApp(api=api, keys=machine.get("/auth/approvals/jwks.json").json(), issuer=BASE, return_url=RETURN,
                         db_path=os.path.join(tempfile.mkdtemp(), "example.db"), identify=example.demo_identify)
app.db.executemany("INSERT INTO collection VALUES (?, ?, ?)",
                   [("c_81f2", "Project Alpha", anna), ("c_77aa", "Holiday photos", anna), ("c_0b5e", "Notes", bert)])


def call(method, path, *, user, query="", cookie=""):
    out = {}

    def start_response(status, headers):
        out["status"], out["headers"] = int(status.split()[0]), dict(headers)
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
               "HTTP_COOKIE": "; ".join(c for c in (cookie, f"example_demo_user={user}") if c)}
    body = b"".join(app(environ, start_response)).decode()
    return out["status"], out["headers"], body


def ask(user, collection):
    status, headers, _ = call("POST", f"/collections/{collection}/delete", user=user)
    assert status == 303, status
    return headers["Location"], headers["Set-Cookie"].split(";", 1)[0]


def collections():
    return {r[0] for r in app.db.execute("SELECT id FROM collection")}


# ══ 1. the whole flow ═══════════════════════════════════════════════════════════════════════════════════════════
approve_url, state_cookie = ask(anna, "c_81f2")
assert approve_url.startswith(f"{BASE}/auth/approvals/apv_"), approve_url
assert "state" not in approve_url and "c_81f2" not in approve_url, "the fields travel through the browser"
back = decide(browser(anna), approve_url)
assert back.startswith(RETURN + "?approval=") and "confirmation" not in back and "eyJ" not in back, back
query = urlsplit(back).query
status, _, body = call("GET", "/approvals/return", user=anna, query=query, cookie=state_cookie)
assert status == 200 and "Deleted Project Alpha" in body, (status, body)
assert "c_81f2" not in collections() and app.db.execute("SELECT COUNT(*) FROM approval_jti").fetchone()[0] == 1
assert any(m == "GET" and p.endswith("?wait=25") for m, p in calls), calls
ok("ask → TinySesam's page → confirmed with the password → back → picked up, checked, jti written, deleted")

# ══ 2. the own rule before asking ═══════════════════════════════════════════════════════════════════════════════
before = len(calls)
status, _, _ = call("POST", "/collections/c_0b5e/delete", user=anna)
assert status == 403 and len(calls) == before and "c_0b5e" in collections()
ok("another account's collection: refused before anything is asked")

# ══ 3. twice ═════════════════════════════════════════════════════════════════════════════════════════════════════
status, _, body = call("GET", "/approvals/return", user=anna, query=query, cookie=state_cookie)
assert status == 400 and "Nothing waits" in body, (status, body)
approve_url, state_cookie = ask(anna, "c_77aa")
back = decide(browser(anna), approve_url)
aid = urlsplit(back).query.split("approval=")[1].split("&")[0]
picked = api("GET", f"/auth/api/approvals/{aid}")[1]
fields = {"collection": "c_77aa", "name": "Holiday photos"}
kw = dict(keys=app.keys, issuer=BASE, app_id="example", expect_type=example.DELETE, expect_fields=fields,
          expect_sub=anna, expect_nonce=state_cookie.split("=", 1)[1], jti_store=app.remember)
approval_token.verify(picked["confirmation"], **kw)
try:
    approval_token.verify(picked["confirmation"], **kw)
    raise AssertionError("the same confirmation passed twice")
except approval_token.ReplayError:
    pass
status, _, body = call("GET", "/approvals/return", user=anna, query=urlsplit(back).query, cookie=state_cookie)
assert status == 409 and "No confirmation (consumed)" in body and "c_77aa" in collections(), (status, body)
ok("the same return address twice: nothing waits; the same confirmation twice: `replay`; picked up elsewhere: "
   "nothing to check, nothing done")

# ══ 4. another browser ═══════════════════════════════════════════════════════════════════════════════════════════
approve_url, state_cookie = ask(anna, "c_77aa")
back = decide(browser(anna), approve_url)
before = len(calls)
for cookie in ("", "example_approval_state=another-state"):
    status, _, body = call("GET", "/approvals/return", user=anna, query=urlsplit(back).query, cookie=cookie)
    assert status == 400 and "another browser session" in body, (cookie, status, body)
assert len(calls) == before, "picked up for a browser without the state"
status, _, body = call("GET", "/approvals/return", user=bert, query=urlsplit(back).query, cookie=state_cookie)
assert status == 400 and "c_77aa" in collections(), (status, body)
ok("without the state cookie, with another state or as another account: refused, nothing picked up")

# ══ 5. rejected ══════════════════════════════════════════════════════════════════════════════════════════════════
approve_url, state_cookie = ask(anna, "c_77aa")
back = decide(browser(anna), approve_url, decision="reject")
assert "result=rejected" in back, back
status, _, body = call("GET", "/approvals/return", user=anna, query=urlsplit(back).query, cookie=state_cookie)
assert status == 200 and "Not confirmed (rejected)" in body and "c_77aa" in collections(), (status, body)
ok("rejected at TinySesam: back with result=rejected, nothing happens")

# ══ 6. the own rule again ════════════════════════════════════════════════════════════════════════════════════════
approve_url, state_cookie = ask(anna, "c_77aa")
back = decide(browser(anna), approve_url)
app.db.execute("UPDATE collection SET owner = ? WHERE id = 'c_77aa'", (bert,))
jti_before = app.db.execute("SELECT COUNT(*) FROM approval_jti").fetchone()[0]
status, _, body = call("GET", "/approvals/return", user=anna, query=urlsplit(back).query, cookie=state_cookie)
assert status == 409 and "changed meanwhile" in body and "c_77aa" in collections(), (status, body)
assert app.db.execute("SELECT COUNT(*) FROM approval_jti").fetchone()[0] == jti_before + 1, "jti not written"
ok("the owner changed meanwhile: the confirmation holds (its jti is spent), the own rule refuses, nothing deleted")

print("OK test_example_approvals")

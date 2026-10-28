"""E2: cookie flags — HttpOnly/Secure/SameSite/Max-Age on every cookie TinySesam sets.

Pins down what is in the code but was held by no test so far: a refactor that loses
`httponly=True` on the session cookie would otherwise go unnoticed — the library
would stay green and hand the session to any XSS.

The RAW `Set-Cookie` header is checked, not the client's cookie jar: only it
shows what really reaches the browser. A jar swallows attributes.

Parser and check rule come from the shared kit (`_kit/headers.py`, via `repokit sync`);
only what is TinySesam's own stands here: which cookies exist and what each one has to
carry (`ERWARTUNG`). A cookie that is set and missing from `ERWARTUNG` is a
violation — whoever introduces one has to explain its flags.

The most important statement is at `tinysesam_csrf`: the cookie is DELIBERATELY not
HttpOnly — double-submit needs JS read access (see test_csrf.py). A blanket
"all cookies HttpOnly" would therefore be wrong and would complain about exactly the right cookie.
Hence one expectation per cookie, not one rule for all.

Deliberately not covered:

* `tinysesam_waflow` (webauthn_.py) only if the extra [passkey] is present (block D2c). A
  hard `webauthn` import would make run_all.py skip the WHOLE suite as soon as the extra
  is missing, and the flags above would be unchecked — so without the extra only this block is missing.
* The CSRF setter in the admin panel. Since 0.20.1 a single place writes the CSRF cookie
  (`manager._csrf_cookie_setzen`) — for `render_page`, `issue_csrf`, `ensure_csrf` and the
  panel, which goes through `ensure_csrf`. This suite checks the first two; `ensure_csrf` is measured by
  test_csrf.py against the attributes of `issue_csrf`, the panel would need the mounted panel
  (test_adminmount.py).
"""
import importlib.util
import os
import re
import sys
import tempfile
import time

from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import headers  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


def gesetzte_cookies(response) -> dict:
    """Set-Cookie headers of the response → {name: {attribute: value}}. The parser comes from the kit."""
    return headers.parse_set_cookie(headers.rohe_set_cookie(response))


# What every cookie MUST carry — individually per cookie, not as one rule for all.
# `httponly: False` on the CSRF cookie is no oversight but the condition for
# double-submit to work at all (JS has to read it, see test_csrf.py).
ERWARTUNG = {
    "__Host-tinysesam_session": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"},
    "__Host-tinysesam_csrf":    {"httponly": False, "secure": True, "samesite": "lax", "path": "/"},
    "__Host-tinysesam_runlock": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"},
}


def baue(**cfg_kw):
    """Fresh instance with its own DB. Returns (auth, client).

    base_url follows cookie_secure: httpx does not store a Secure cookie over http://
    at all (RFC 6265) — the login flow would then break at the CSRF cookie, not at the
    subject under test.
    """
    kw = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Test",
              passkey_enabled=False, oidc_enabled=False)
    kw.update(cfg_kw)
    auth = TinySesam(TinySesamConfig(**kw))
    auth.ensure_admin("admin", "geheim123")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    base = "http://testserver" if kw.get("cookie_secure") is False else "https://testserver"
    return auth, TestClient(app, base_url=base)


def login(client, remember="on"):
    """Real login via the router (double-submit). Returns the 303 response unfollowed."""
    html = client.get("/auth/login").text
    field = re.search(r"name=_csrf value='([^']+)'", html).group(1)
    return client.post("/auth/login",
                       data={"username": "admin", "password": "geheim123", "next": "/",
                             "remember": remember, "_csrf": field},
                       follow_redirects=False)


class _FakeReq:
    """Minimal request stand-in: unlock_resource() reads only .cookies."""
    cookies: dict = {}


# ---------- A. Real login flow: the flags survive the router ----------
auth, c = baue()

r = c.get("/auth/login")
gesetzt = gesetzte_cookies(r)
assert "__Host-tinysesam_csrf" in gesetzt, "login page must set the CSRF cookie"
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
ok("CSRF cookie: deliberately no HttpOnly, but Secure + SameSite=lax + Path")

r = login(c)
assert r.status_code == 303, r.status_code
gesetzt = gesetzte_cookies(r)
assert "__Host-tinysesam_session" in gesetzt, "login must set the session cookie"
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
assert "max-age" in gesetzt["__Host-tinysesam_session"], "remember=on must be persistent"
ok("Session cookie in the real login: HttpOnly + Secure + SameSite=lax + Path + Max-Age")

assert c.get("/geheim").json() == {"u": "admin"}
ok("Session holds: /geheim reachable (the cookie is real, not just a header)")


# ---------- B. Flag matrix directly on set_cookie() ----------
# Without login flow: the client's cookie jar would swallow Secure/Domain variants.
auth, _ = baue()

resp = Response()
auth.set_cookie(resp, "tok123", remember=True)
sess = gesetzte_cookies(resp)["__Host-tinysesam_session"]
assert sess["_wert"] == "tok123" and "max-age" in sess
ok("set_cookie(remember=True) → Max-Age set (persistent)")

resp = Response()
auth.set_cookie(resp, "tok123", remember=False)
sess = gesetzte_cookies(resp)["__Host-tinysesam_session"]
assert "max-age" not in sess, "remember=False must be a pure session cookie"
assert sess.get("httponly") is True, "HttpOnly must not be lost with remember=False"
ok("set_cookie(remember=False) → no Max-Age, HttpOnly stays")

auth, _ = baue(cookie_secure=False)
resp = Response()
auth.set_cookie(resp, "tok123")
sess = gesetzte_cookies(resp)["tinysesam_session"]
assert "secure" not in sess, "cookie_secure=False must omit the Secure flag"
assert sess.get("httponly") is True, "HttpOnly does NOT depend on cookie_secure"
ok("cookie_secure=False (local/demo) → no Secure, HttpOnly stays")

auth, _ = baue(cookie_samesite="strict")
resp = Response()
auth.set_cookie(resp, "tok123")
assert gesetzte_cookies(resp)["__Host-tinysesam_session"].get("samesite") == "strict"
ok("cookie_samesite is passed through (strict)")

auth, _ = baue(cookie_domain=".example.com")
resp = Response()
auth.set_cookie(resp, "tok123")
assert gesetzte_cookies(resp)["tinysesam_session"].get("domain") == ".example.com"
ok("cookie_domain is set (SSO across subdomains)")

auth, _ = baue(cookie_path="/app")
resp = Response()
auth.set_cookie(resp, "tok123")
assert gesetzte_cookies(resp)["tinysesam_session"].get("path") == "/app"
ok("cookie_path is passed through")

# issue_csrf() is the second CSRF setter: public API for foreign templates that do not run
# through render_page(). It must set the same flags as the internal path — if it did not,
# the third-party integration would be the weakest.
auth, _ = baue()
resp = Response()
tok = auth.issue_csrf(resp)
gesetzt = gesetzte_cookies(resp)
assert tok and "__Host-tinysesam_csrf" in gesetzt
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
ok("issue_csrf() sets the same flags as the internal path")

# If CSRF is off, no cookie may arise either — otherwise the response claims protection that does not exist.
auth, _ = baue(csrf_enabled=False)
resp = Response()
assert auth.issue_csrf(resp) == ""
assert gesetzte_cookies(resp) == {}
ok("csrf_enabled=False → issue_csrf() sets no cookie at all")


# ---------- C. Resource cookie ----------
auth, _ = baue()
resp = Response()
auth._unlock_resource(_FakeReq(), resp, "fotos")
gesetzt = gesetzte_cookies(resp)
assert "__Host-tinysesam_runlock" in gesetzt
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
assert "max-age" in gesetzt["__Host-tinysesam_runlock"], "resource unlock must expire"
ok("Resource cookie: HttpOnly + Secure + SameSite + Max-Age")


# ---------- D. Logout clears the cookie ----------
auth, c = baue()
login(c)
r = c.get("/auth/logout", follow_redirects=False)
sess = gesetzte_cookies(r).get("__Host-tinysesam_session")
assert sess is not None, "logout must overwrite the session cookie, not just empty the DB row"
assert sess["_wert"] in ("", '""'), f"logout must empty the cookie value, is: {sess['_wert']!r}"
# A `__Host-` Set-Cookie without Secure is discarded by the browser — the deleting one too. Without the
# flag the cookie would simply remain after logout.
assert sess.get("secure") is True and sess.get("path") == "/", sess
ok("Logout empties the session cookie at the browser (with Secure + Path, otherwise it does not accept the __Host- deletion)")

# ---------- D2. `__Host-` prefix only where the browser allows it (H-1) ----------
# A `__Host-` cookie cannot be set or shadowed by a neighbouring subdomain — that is the
# bolt against planted session, CSRF and unlock tokens (F-01, F-02). The browser
# accepts it only with Secure, without Domain and with Path=/; anywhere else the prefix would mean:
# no cookie at all.
for kw, erwartet in (({}, True), ({"cookie_samesite": "strict"}, True),
                     ({"cookie_secure": False}, False), ({"cookie_domain": ".example.com"}, False),
                     ({"cookie_path": "/app"}, False), ({"cookie_host_prefix": False}, False),
                     # A-7: path "" sends no Path attribute at all — `__Host-` requires Path=/.
                     ({"cookie_path": ""}, False)):
    a, _ = baue(**kw)
    namen = (a.session_cookie_name, a.csrf_cookie_name, a.resource_cookie_name)
    # The flow cookies (OIDC/SAML/passkey) and the CSRF cookie never set a Domain — they
    # carry the prefix even with cookie_domain set (A-1; the CSRF cookie since the
    # rework on H-1: without the prefix every neighbouring subdomain would set a matching pair).
    flow_erwartet = erwartet or kw == {"cookie_domain": ".example.com"}
    assert a.session_cookie_name.startswith("__Host-") == erwartet, (kw, namen)
    assert a.resource_cookie_name.startswith("__Host-") == erwartet, (kw, namen)
    assert a.csrf_cookie_name.startswith("__Host-") == flow_erwartet, (kw, namen)
    assert a.flow_cookie_name("tinysesam_oidc_flow").startswith("__Host-") == flow_erwartet, kw
    resp = Response()
    a.set_cookie(resp, "tok123")
    a.issue_csrf(resp)
    a._unlock_resource(_FakeReq(), resp, "fotos")
    gesetzt = gesetzte_cookies(resp)
    assert set(gesetzt) == set(namen), (kw, gesetzt.keys())
    # Every `__Host-` cookie as the browser accepts it — also the CSRF cookie next to a
    # session with Domain: if it carried a Domain itself, the browser would silently discard it.
    for n in namen:
        if n.startswith("__Host-"):
            assert gesetzt[n].get("secure") is True and gesetzt[n].get("path") == "/" \
                and "domain" not in gesetzt[n], (n, gesetzt[n])
    # No `__Host-` cookie without Path=/ — the browser silently discards that (A-7).
    for n in namen:
        assert not n.startswith("__Host-") or gesetzt[n].get("path") == "/", (kw, n, gesetzt[n])
    fr = Response()
    a._flow_cookie_setzen(fr, "tinysesam_oidc_flow", "w", max_age=60)
    f_n, f_c = next(iter(gesetzte_cookies(fr).items()))
    assert f_n == a.flow_cookie_name("tinysesam_oidc_flow") and "domain" not in f_c, (kw, f_n, f_c)
    assert not f_n.startswith("__Host-") or (f_c.get("secure") is True and f_c.get("path") == "/"), f_c
ok("__Host- on session, CSRF and unlock exactly when Secure + host-only + Path=/ (otherwise without)")
ok("A-1/A-7: flow cookies with __Host- also with cookie_domain; cookie_path='' gets no prefix")

# A cookie of the same name WITHOUT prefix — what a neighbouring subdomain can set —
# signs nobody in.
auth, c = baue()
login(c)
echt = c.cookies.get("__Host-tinysesam_session")
assert echt and c.get("/geheim").status_code == 200
c.cookies.clear()
c.cookies.set("tinysesam_session", echt)
assert c.get("/geheim").status_code in (401, 307), "unprefixed cookie must not count"
ok("an unprefixed session cookie (subdomain throw) is not read")

# ---------- D2b. TinySesam clears the legacy names from before the prefix (H-1, B-20) ----------
# After the update TinySesam reads only `__Host-…`. The cookies under the old names lay
# next to them until their expiry (session up to 7 days, unlock 12 h) — nobody deleted them,
# not even logout. Together with the new ones a browser thus carried seven and more
# tinysesam cookies, and the nginx templates passed the surplus on to the app.
# Now every response that writes the session cookie (sign-in, sign-out, step-up) deletes
# the legacy names that the browser sent along — host-only, as they were set.
# (Mutation probe: remove the call of `_altnamen_loeschen` in the route class → red;
# remove the one in `logout()` → red when signing out via an own route.)
ALT = ("tinysesam_session", "tinysesam_csrf", "tinysesam_runlock")


def geloescht(response) -> set:
    """The names this response deletes at the browser (empty value, Max-Age=0)."""
    return {n for n, c in gesetzte_cookies(response).items()
            if c["_wert"] in ("", '""') and str(c.get("max-age")) == "0"}


auth, c = baue()
_uid = auth.store.get_user_by_name("admin")["id"]
_alt_sitzung = auth.store.create_session(_uid, 3600, True, "password")   # from the time before the update
_alt_freigabe = "alte-freigabe-vor-dem-update"
auth.store.add_resource_unlock(_alt_freigabe, "fotos", int(time.time()) + 3600)
for n in ALT:
    c.cookies.set(n, "ALT")
c.cookies.set("tinysesam_session", _alt_sitzung)
c.cookies.set("tinysesam_runlock", _alt_freigabe)
assert auth.store.get_session(_alt_sitzung) and auth.store.is_resource_unlocked(_alt_freigabe, "fotos")
r = login(c)
assert r.status_code == 303 and "__Host-tinysesam_session" in gesetzte_cookies(r)
assert geloescht(r) >= set(ALT), f"login does not delete the legacy names: {geloescht(r)}"
for n in ALT:
    zeile = gesetzte_cookies(r)[n]
    assert zeile.get("path") == "/" and "domain" not in zeile, (n, zeile)
ok("H-1: the login deletes the cookies sent along under the legacy names (host-only, Path=/)")
# And the session behind it: the old token would still have signed in for seven days under the new name.
# (Mutation probe: remove delete_session/delete_resource_unlocks in `_altnamen_loeschen` → red.)
assert auth.store.get_session(_alt_sitzung) is None, "the session behind the legacy name lives on"
assert not auth.store.is_resource_unlocked(_alt_freigabe, "fotos"), "the old unlock lives on"
ok("H-1: …and ends the session and the unlocks behind it")

auth, c = baue()
login(c)
c.cookies.set("tinysesam_runlock", "ALT")
r = c.get("/auth/logout", follow_redirects=False)
assert "tinysesam_runlock" in geloescht(r) and "__Host-tinysesam_session" in geloescht(r), geloescht(r)
assert not {"tinysesam_session", "tinysesam_csrf"} & set(gesetzte_cookies(r)), \
    "only what the browser sent along is deleted"
ok("H-1: logout deletes them likewise — and only those the browser really has")

# Also a sign-out via an app's OWN route (`auth.logout()` directly, without the route class).
auth, c = baue()
_app_eigen = c.app


@_app_eigen.post("/eigen/abmelden")
def _eigen_abmelden(request: Request):
    antwort = Response()
    auth.logout(request, antwort)
    return antwort


login(c)
c.cookies.set("tinysesam_session", "ALT")
assert "tinysesam_session" in geloescht(c.post("/eigen/abmelden")), \
    "auth.logout() in an own route leaves the legacy names standing"
ok("H-1: auth.logout() in an own route clears the legacy names too")

# Likewise a step-up via the public method `auth.rotate_session(request, response)` in an
# own route: it writes the session and has the request — so the legacy names go along.
# (Mutation probe: remove the call of `_altnamen_loeschen` in `rotate_session` → red.)


@_app_eigen.post("/eigen/stepup")
def _eigen_stepup(request: Request):
    antwort = Response()
    auth.rotate_session(request, antwort)
    return antwort


login(c)
_alt_su = auth.store.create_session(auth.store.get_user_by_name("admin")["id"], 3600, True, "password")
c.cookies.set("tinysesam_session", _alt_su)
r = c.post("/eigen/stepup")
assert "__Host-tinysesam_session" in gesetzte_cookies(r), "rotate_session sets no cookie"
assert "tinysesam_session" in geloescht(r), "auth.rotate_session() leaves the legacy names standing"
assert auth.store.get_session(_alt_su) is None, "the session behind the legacy name lives on"
ok("H-1: auth.rotate_session() in an own route clears the legacy names too")

# Deleting happens only if the response writes the session. A page that merely sets the CSRF cookie
# (GET /auth/login) leaves the legacy names standing — otherwise every page view, even an
# embedded image from a foreign hand, would end the session behind the old cookie.
# (Mutation probe: remove the condition "session cookie set" in `_altnamen_loeschen` → red.)
auth, c = baue()
_alt_get = auth.store.create_session(auth.store.get_user_by_name("admin")["id"], 3600, True, "password")
for n in ALT:
    c.cookies.set(n, "ALT")
c.cookies.set("tinysesam_session", _alt_get)
r = c.get("/auth/login")
assert r.status_code == 200 and "__Host-tinysesam_csrf" in gesetzte_cookies(r), gesetzte_cookies(r)
assert not geloescht(r) and not set(ALT) & set(gesetzte_cookies(r)), gesetzte_cookies(r)
assert auth.store.get_session(_alt_get), "a mere page view ends the legacy session"
ok("H-1: a response without a session cookie (GET /auth/login) deletes no legacy names")

# With `cookie_domain` (forward auth across subdomains) the prefix applies only to the CSRF cookie — the
# legacy name is then `tinysesam_csrf`. TinySesam never set that one with a Domain before either; it is
# therefore deleted host-only. A `Domain=` attribute would hit a different cookie and leave the real one
# standing.
# (Mutation probe: in `_altnamen_loeschen` `_cookie_loeschen` instead of the host-only deletion → red.)
auth, c = baue(cookie_domain=".example.com")
assert auth.session_cookie_name == "tinysesam_session" and auth.csrf_cookie_name == "__Host-tinysesam_csrf"
assert auth._altnamen() == ["tinysesam_csrf"], auth._altnamen()
c.cookies.set("tinysesam_csrf", "ALT")
r = login(c)
assert r.status_code == 303 and "tinysesam_session" in gesetzte_cookies(r)
assert "tinysesam_csrf" in geloescht(r), f"legacy name tinysesam_csrf not deleted: {geloescht(r)}"
_zeile = gesetzte_cookies(r)["tinysesam_csrf"]
assert "domain" not in _zeile and _zeile.get("path") == "/", _zeile
assert gesetzte_cookies(r)["tinysesam_session"].get("domain") in (".example.com", "example.com")
ok("H-1: with cookie_domain the legacy name tinysesam_csrf is deleted host-only, the session stays domain-wide")

# Where the prefix does not apply, the legacy names ARE the current names — they must not fall.
auth, c = baue(cookie_secure=False)
c.cookies.set("tinysesam_runlock", "AKTUELL")
r = login(c)
assert r.status_code == 303 and not geloescht(r), geloescht(r)
assert gesetzte_cookies(r)["tinysesam_session"]["_wert"] not in ("", '""')
ok("without prefix (cookie_secure=False) the login deletes none of its own cookies")

# ---------- D2c. The passkey flow cookie ends with its flow ----------
# The flow record is used up after `finish` (pop_flow), but the cookie stayed for 300 s
# — one more tinysesam cookie that binds nothing any more and went along to every app. OIDC and
# SAML deleted theirs on the way back. The block needs the extra [passkey]; without it only
# it is missing, not the suite. The route is checked, not WebAuthn: the signature check is replaced.
# (Mutation probe: remove `_flow_cookie_loeschen` in login_finish or reg_finish → red.)
if importlib.util.find_spec("webauthn") is None:
    print("  - D2c skipped: extra [passkey] (webauthn) missing")
else:
    import json
    import types
    import webauthn
    _echt = (webauthn.verify_authentication_response, webauthn.verify_registration_response)
    webauthn.verify_authentication_response = lambda **kw: types.SimpleNamespace(new_sign_count=1)
    webauthn.verify_registration_response = lambda **kw: types.SimpleNamespace(
        credential_id=b"neu", credential_public_key=b"pk", sign_count=0)
    try:
        auth, c = baue(passkey_enabled=True, rp_id="testserver", origin="https://testserver")
    finally:
        webauthn.verify_authentication_response, webauthn.verify_registration_response = _echt
    auth.store.add_webauthn(auth.store.get_user_by_name("admin")["id"], "Y3JlZC10ZXN0", "pk", 0,
                            ["internal"], "Test")
    c.get("/auth/login")
    kopf = {"X-CSRF-Token": c.cookies.get("__Host-tinysesam_csrf"), "Content-Type": "application/json"}
    r = c.post("/auth/passkey/login/begin", headers=kopf)
    assert r.status_code == 200 and "__Host-tinysesam_waflow" in gesetzte_cookies(r), r.text[:120]
    verstoesse = headers.pruefe_cookie_flags(gesetzte_cookies(r), {
        "__Host-tinysesam_waflow": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"}})
    assert not verstoesse, verstoesse
    r = c.post("/auth/passkey/login/finish", content=json.dumps({"id": "Y3JlZC10ZXN0"}), headers=kopf)
    assert r.status_code == 200 and r.json()["ok"], r.text[:200]
    assert "__Host-tinysesam_session" in gesetzte_cookies(r)
    assert "__Host-tinysesam_waflow" in geloescht(r), f"flow cookie remains after login: {gesetzte_cookies(r)}"
    ok("Passkey login: the flow cookie (httponly, __Host-) ends with the flow")

    # The login rotated the CSRF token (0.20.1) — the one from before sign-in no longer applies.
    # Until 0.20.0 this block continued with the old one; exactly that pinned down the missing rotation.
    kopf["X-CSRF-Token"] = c.cookies.get("__Host-tinysesam_csrf")
    r = c.post("/auth/passkey/register/begin", headers=kopf)
    assert r.status_code == 200 and "__Host-tinysesam_waflow" in gesetzte_cookies(r), r.text[:120]
    r = c.post("/auth/passkey/register/finish", content=json.dumps({"id": "neu", "response": {}}),
               headers=kopf)
    assert r.status_code == 200 and r.json()["ok"], r.text[:200]
    assert "__Host-tinysesam_waflow" in geloescht(r), f"flow cookie remains after registration: {gesetzte_cookies(r)}"
    ok("Passkey registration: the flow cookie ends likewise")

# ---------- D3. cookie_secure=False over HTTPS gets noticed (F-04) ----------
import logging  # noqa: E402


class _Fang(logging.Handler):
    def __init__(self):
        super().__init__()
        self.zeilen = []

    def emit(self, record):
        self.zeilen.append(record.getMessage())


def secure_warnungen(cookie_secure, base, headers_=None, n=2):
    fang = _Fang()
    log = logging.getLogger("tinysesam.security")
    log.addHandler(fang)
    try:
        a, _ = baue(cookie_secure=cookie_secure)
        app = FastAPI()
        app.include_router(a.router())
        cl = TestClient(app, base_url=base)
        for _i in range(n):
            cl.get("/auth/login", headers=headers_ or {})
    finally:
        log.removeHandler(fang)
    return [z for z in fang.zeilen if "cookie_secure=False" in z]


assert len(secure_warnungen(False, "http://testserver",
                            {"X-Forwarded-Proto": "https"})) == 1, "TLS proxy in front: exactly one warning"
assert len(secure_warnungen(False, "https://testserver")) == 1, "direct HTTPS: exactly one warning"
assert secure_warnungen(False, "http://testserver") == [], "local without TLS is the permitted case"
assert secure_warnungen(True, "https://testserver") == [], "with Secure there is nothing to report"
ok("cookie_secure=False + HTTPS request → one warning per instance; local over HTTP silent")

# ---------- E. Contradictory config is rejected at construction ----------
# `cookie_secure=False` is right for local setups without a certificate and remains allowed.
# Together with `https_mode='force'` it contradicts itself: the app then redirects every request
# to HTTPS and still issues the session cookie without the Secure flag.
#
# Only what the app says about its OWN behaviour is checked — not what it claims about the
# outside world. `base_url='https://…' + cookie_secure=False` looks like the same
# error but is none: `base_url` is the public address (SAML/OIDC build callbacks from it),
# not the transport between browser and app. Exactly this combination is needed by
# test_saml, test_matrix, test_forward_auth and test_sessions_logout.


def baut(**kw) -> bool:
    """True if the config is accepted; False on ValueError."""
    try:
        baue(**kw)
        return True
    except ValueError:
        return False


assert baut(cookie_secure=False), "cookie_secure=False must remain allowed locally"
assert baut(cookie_secure=True, https_mode="force"), "the clean prod combination must work"
assert baut(cookie_secure=False, base_url="https://app.example.com"), \
    "HTTPS base_url + cookie_secure=False is NOT a contradiction — four suites need it"
ok("allowed: cookie_secure=False locally, cookie_secure=True + https_mode='force' in prod")

assert not baut(cookie_secure=False, https_mode="force"), \
    "https_mode='force' + cookie_secure=False must be rejected"
ok("rejected: the app redirects to HTTPS but issues the cookie without Secure")

# A typo in https_mode used to switch the HTTPS enforcement off SILENTLY: only
# `== "force"` is evaluated, everything else means "no redirect". No error, no notice.
assert not baut(https_mode="forse"), "typo in https_mode must be noticed"
assert not baut(https_mode=""), "empty https_mode must be noticed"
assert baut(https_mode="off") and baut(https_mode="warn")
ok("https_mode is validated — a typo no longer silently switches the redirect off")


# CSRF off AND SameSite=None: then nothing protects any more (F-03). Each alone remains allowed.
assert baut(csrf_enabled=False), "csrf_enabled=False alone remains allowed (SameSite=Lax carries)"
assert baut(cookie_samesite="none", cookie_secure=True), "SameSite=None with CSRF remains allowed"
assert not baut(csrf_enabled=False, cookie_samesite="none", cookie_secure=True), \
    "csrf_enabled=False + cookie_samesite='none' must be rejected"
ok("rejected: csrf_enabled=False together with cookie_samesite='none' (no CSRF protection left)")


print("\ntest_cookies: all checks green")

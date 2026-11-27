"""T-99, ADR-18: the person links a local account with a SAML identity — like OIDC, never by an address alone.

`POST /auth/saml/link` from the account page (CSRF token, a fresh confirmation here) sends an AuthnRequest with
`ForceAuthn`; the ACS binds the assertion's stable identifier (`NameID` or `saml_attr_id`) only in the session that
started it, after an active sign-in (an `AuthnInstant` from after the request), through `saml_allowed_groups`, and only
an identity of nobody else. A link flow never signs anyone in and never creates an account. Really signed assertions
from the suites' test identity provider (`tests/_saml_idp.py`) against real python3-saml.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("onelogin", extra="saml")
braucht_modul("cryptography")
braucht_modul("lxml")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import _saml_idp  # noqa: E402
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

BASE = "https://app.example.com"
PW = "a long local password 4711"
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    idp = _saml_idp.IdP(BASE)
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, base_url=BASE,
               passkey_enabled=False, stepup_max_age_sec=900, **idp.config())
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("rate_limit_max", 1000)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, idp


auth, app, idp = build()


def tok(c):
    return c.cookies.get(auth.csrf_cookie_name) or ""


def browser(name):
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    c.get("/auth/login")
    r = c.post("/auth/login", data={"username": name, "password": PW, "_csrf": tok(c)})
    assert r.status_code == 303, (name, r.status_code, r.text[:200])
    return c


def make_stale(c):
    then = int(time.time()) - STALE
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(c.cookies.get(auth.session_cookie_name))))


def start_link(c):
    """POST /auth/saml/link → (request id, the decoded AuthnRequest)."""
    import base64
    import zlib
    from urllib.parse import parse_qs, urlsplit
    r = c.post("/auth/saml/link", data={"_csrf": tok(c)})
    assert r.status_code == 303, (r.status_code, r.text[:200])
    req = parse_qs(urlsplit(r.headers["location"]).query)["SAMLRequest"][0]
    return r.cookies.get(_saml_idp.FLOW) or "", zlib.decompress(base64.b64decode(req), -15).decode()


def bound(nameid):
    return auth.store.get_federated_user("saml", nameid)


def audited(event):
    return [a for a in auth.store.recent_audit(300) if a["event"] == event]


lena = int(auth.create_user("lena", password=PW, email="lena@example.com"))
c = browser("lena")
page = c.get("/auth/account").text
assert "action='/auth/saml/link'" in page and "name=_csrf" in page, "the account page offers no SAML link form"
assert c.post("/auth/saml/link").status_code == 403
assert c.get("/auth/saml/link").status_code in (404, 405)
ok("the account page offers the SAML link as a form with the CSRF token; without the token 403, no GET route")

make_stale(c)
r = c.post("/auth/saml/link", data={"_csrf": tok(c)})
assert r.status_code == 403 and "x-tinysesam-reauth" in {k.lower() for k in r.headers}, (r.status_code, r.headers)
c = browser("lena")
ok("a stale session is sent to confirm first (403 with X-TinySesam-Reauth)")

rid, req = start_link(c)
assert 'ForceAuthn="true"' in req, "the link does not ask the provider for an active sign-in"
r = _saml_idp.acs(c, idp, rid, "lena-idp", time.time() - 3600)
assert r.status_code == 401 and bound("lena-idp") is None and audited("saml_link_refused")
ok("the link sends ForceAuthn; an old AuthnInstant binds nothing (401)")

rid, _ = start_link(c)
other = TestClient(app, base_url=BASE, follow_redirects=False)
r = other.post("/auth/saml/acs", data={"SAMLResponse": idp.response(rid, "attacker-idp"), "RelayState": "/"})
assert r.status_code == 400 and bound("attacker-idp") is None, r.status_code
r = _saml_idp.acs(other, idp, rid, "attacker-idp")      # the attacker sets the anchor cookie by hand
assert bound("attacker-idp") is None and r.status_code in (400, 403), r.status_code
ok("the ACS in another browser binds nothing (no anchor; with a forged anchor no session of the account)")

rid, _ = start_link(c)
auth.create_user("mallory", password=PW)
c.post("/auth/logout", data={"_csrf": tok(c)})
c.get("/auth/login")
c.post("/auth/login", data={"username": "mallory", "password": PW, "_csrf": tok(c)})
r = _saml_idp.acs(c, idp, rid, "lena-idp")
assert r.status_code == 403 and bound("lena-idp") is None, r.status_code
ok("an ACS in another session than the one that started the link binds nothing (403)")

kim_c = TestClient(app, base_url=BASE, follow_redirects=False)
assert _saml_idp.round_trip(kim_c, idp, "kim").status_code == 303 and bound("kim")
c = browser("lena")
rid, _ = start_link(c)
r = _saml_idp.acs(c, idp, rid, "kim")
assert r.status_code == 409 and bound("kim") != lena, r.status_code
ok("attack: an identity of another account is not moved (409 identity_taken)")

rid, _ = start_link(c)                                  # meanwhile the account got another SAML identity (a race)
auth.store.link_federated("saml", "other-idp", lena, int(time.time()))
r = _saml_idp.acs(c, idp, rid, "lena-idp")
assert r.status_code == 409 and bound("lena-idp") is None and bound("other-idp") == lena, r.status_code
auth.store.unlink_federated("saml", lena)
ok("an account that got a SAML identity between start and ACS keeps it (409 already_linked)")

users_before = auth.store._one("SELECT COUNT(*) AS n FROM users")["n"]
rid, _ = start_link(c)
r = _saml_idp.acs(c, idp, rid, "lena-idp")
assert r.status_code == 303 and r.headers["location"].endswith("/auth/account"), (r.status_code, r.text[:200])
assert bound("lena-idp") == lena and audited("saml_linked")
assert auth.store._one("SELECT COUNT(*) AS n FROM users")["n"] == users_before, "a link flow created an account"
assert auth.store.account_sources([lena])[lena] == ["local", "saml"]
fresh = TestClient(app, base_url=BASE, follow_redirects=False)
assert _saml_idp.round_trip(fresh, idp, "lena-idp").status_code == 303
assert auth.store.get_session(fresh.cookies.get(auth.session_cookie_name))["user_id"] == lena
r = c.post("/auth/saml/link", data={"_csrf": tok(c)})
assert r.status_code == 409, "a second SAML identity"
ok("the link binds in the starting session after an active sign-in; the SAML sign-in lands in the account; "
   "a second link 409")

# Unlink, and the provider's group gate also guards the link.
assert c.post("/auth/identities/unlink", data={"source": "saml", "_csrf": tok(c)}).status_code == 303
assert bound("lena-idp") is None and auth.store.name_binding_closed("saml", lena)
ok("the person unlinks the SAML identity; the name never binds it back silently")

auth2, app2, idp2 = build(saml_allowed_groups=["staff"], saml_attr_groups="groups")
auth, app, idp = auth2, app2, idp2
auth.create_user("gina", password=PW)
c = browser("gina")
rid, _ = start_link(c)
r = _saml_idp.acs(c, idp, rid, "gina-idp", attrs={"groups": ["guests"]})
assert r.status_code == 403 and bound("gina-idp") is None, r.status_code
rid, _ = start_link(c)
r = _saml_idp.acs(c, idp, rid, "gina-idp", attrs={"groups": ["staff"]})
assert r.status_code == 303 and bound("gina-idp") is not None, r.status_code
ok("saml_allowed_groups guards the link like the sign-in")

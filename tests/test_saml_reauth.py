"""T-70 (part of T-99): SAML re-authentication — `ForceAuthn` and `AuthnInstant`, the SAML twin of T-49.

Measured with really signed assertions against real python3-saml (as `tests/test_saml.py` H1): a round through the
provider's running session (an old `AuthnInstant`) no longer makes a session fresh; a new session counts as confirmed
from the `AuthnInstant`; the confirmation page's provider button sends `ForceAuthn="true"` and confirms only with an
`AuthnInstant` from after the request. `saml_reauth_check=False` keeps the behaviour up to 0.31.x.
"""
from __future__ import annotations

import base64
import datetime as dt
import os
import sys
import tempfile
import time
import zlib
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("onelogin", extra="saml")
braucht_modul("cryptography")
braucht_modul("lxml")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from lxml import etree  # noqa: E402
from onelogin.saml2.constants import OneLogin_Saml2_Constants as K  # noqa: E402
from onelogin.saml2.utils import OneLogin_Saml2_Utils as Utils  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

BASE, IDP = "https://app.example.com", "https://idp.example.com/sso"
ACS, SP = BASE + "/auth/saml/acs", BASE + "/auth/saml/metadata"
FLOW = "tinysesam_saml_flow"
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = dt.datetime.now(dt.timezone.utc)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256()))
KEY_PEM = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
CERT_PEM = cert.public_bytes(serialization.Encoding.PEM).decode()
_n = [0]


def iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def response(rid: str, nameid: str, authn: "list[float] | None") -> str:
    """A signed SAMLResponse to the request `rid` for `nameid`; `authn`: the AuthnInstant of each AuthnStatement
    (None = no AuthnStatement at all)."""
    _n[0] += 1
    t = time.time()
    prior, after = iso(t - 60), iso(t + 300)
    statements = "".join(
        f'<saml:AuthnStatement AuthnInstant="{iso(a)}" SessionIndex="_s{_n[0]}"><saml:AuthnContext>'
        '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
        '</saml:AuthnContext></saml:AuthnStatement>' for a in (authn or []))
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r{_n[0]}" Version="2.0" '
        f'IssueInstant="{prior}" Destination="{ACS}" InResponseTo="{rid}">'
        f'<saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode '
        'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="_a{_n[0]}" Version="2.0" IssueInstant="{prior}"><saml:Issuer>{IDP}</saml:Issuer>'
        f'<saml:Subject><saml:NameID>{nameid}</saml:NameID><saml:SubjectConfirmation '
        'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData '
        f'NotOnOrAfter="{after}" Recipient="{ACS}" InResponseTo="{rid}"/></saml:SubjectConfirmation>'
        f'</saml:Subject><saml:Conditions NotBefore="{prior}" NotOnOrAfter="{after}">'
        f'<saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction>'
        f'</saml:Conditions>{statements}<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>'
        f'{nameid}@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
        '</saml:Assertion></samlp:Response>')
    doc = etree.fromstring(xml.encode())
    claim = doc.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    doc.replace(claim, etree.fromstring(Utils.add_sign(etree.tostring(claim), KEY_PEM, CERT_PEM,
                                                       sign_algorithm=K.RSA_SHA256, digest_algorithm=K.SHA256)))
    return base64.b64encode(etree.tostring(doc)).decode()


def build(**over):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Test", passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, csrf_enabled=False, base_url=BASE, saml_enabled=True,
               saml_idp_sso_url=IDP, saml_idp_x509cert="".join(CERT_PEM.strip().splitlines()[1:-1]),
               apikey_enabled=True, stepup_max_age_sec=900, lang="en")
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def start(c, reauth=False):
    """GET /auth/saml/login → (request id, the decoded AuthnRequest)."""
    r = c.get("/auth/saml/login?next=/" + ("&reauth=1" if reauth else ""), follow_redirects=False)
    assert r.status_code == 303, r.status_code
    req = parse_qs(urlsplit(r.headers["location"]).query)["SAMLRequest"][0]
    return r.cookies.get(FLOW), zlib.decompress(base64.b64decode(req), -15).decode()


def acs(c, rid, nameid, authn):
    c.cookies.set(FLOW, rid)
    return c.post("/auth/saml/acs", data={"SAMLResponse": response(rid, nameid, authn), "RelayState": "/"},
                  follow_redirects=False)


def sign_in(auth, app, nameid, authn_age=0):
    c = TestClient(app, base_url=BASE)
    rid, _ = start(c)
    r = acs(c, rid, nameid, [time.time() - authn_age])
    assert r.status_code == 303, (r.status_code, r.text[:300])
    return c


def new_access(c):
    return c.post("/auth/apikeys", json={"name": "probe"}, headers={"Accept": "application/json"}).status_code


def make_stale(auth, c):
    tok = c.cookies.get(auth.session_cookie_name)
    then = int(time.time()) - STALE
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))


def audited(auth, event):
    return [a for a in auth.store.recent_audit(50) if a["event"] == event]


auth, app = build()

# ---------- a new session counts from the AuthnInstant ----------
fresh_c = sign_in(auth, app, "alice")
assert new_access(fresh_c) == 200, "a sign-in with a fresh AuthnInstant is not fresh"
silent = sign_in(auth, app, "alice", authn_age=2 * 3600)
assert new_access(silent) == 403, "a silent sign-in two hours after the provider's sign-in counted as fresh"
ok("a new session counts from the AuthnInstant: now → fresh, two hours back → not fresh for new access")

# ---------- the confirmation page offers the provider, with ForceAuthn ----------
page = silent.get("/auth/reauth").text
assert "id=reauthsaml" in page and "/auth/saml/login?reauth=1" in page, "no SAML provider button"
rid, request_xml = start(silent, reauth=True)
assert 'ForceAuthn="true"' in request_xml, request_xml[:300]
_, plain_xml = start(TestClient(app, base_url=BASE))
assert 'ForceAuthn="true"' not in plain_xml, "an ordinary sign-in forces the provider to authenticate"
ok("the confirmation page offers \"Confirm with <provider>\"; only its request carries ForceAuthn=\"true\"")

# ---------- the provider ignores ForceAuthn: an old AuthnInstant does not confirm ----------
make_stale(auth, silent)
r = acs(silent, rid, "alice", [time.time() - 3600])
assert r.status_code == 401 and "did not ask for your sign-in again" in r.text, (r.status_code, r.text[:200])
assert new_access(silent) == 403 and audited(auth, "saml_reauth_stale"), "a stale forced round confirmed"
ok("ForceAuthn ignored (old AuthnInstant): 401 page, audit saml_reauth_stale, still not fresh")

# ---------- a forced round with a fresh AuthnInstant confirms ----------
rid, _ = start(silent, reauth=True)
r = acs(silent, rid, "alice", [time.time()])
assert r.status_code == 303 and new_access(silent) == 200, (r.status_code, r.text[:200])
ok("a forced round with an AuthnInstant after the request confirms: new access works")

# ---------- any other round on a full session no longer refreshes it ----------
make_stale(auth, silent)
rid, _ = start(silent)
r = acs(silent, rid, "alice", [time.time() - 1800])
assert r.status_code == 303 and new_access(silent) == 403, (r.status_code, new_access(silent))
assert any("no_fresh_authn_instant" in (a["detail"] or "") for a in audited(auth, "stepup_not_counted"))
ok("an ordinary round through the running provider session on a stale full session: not counted")

# ---------- without an AuthnStatement nothing is confirmed; two of them: the oldest counts ----------
rid, _ = start(silent, reauth=True)
r = acs(silent, rid, "alice", None)          # python3-saml itself refuses an assertion without one (mandatory)
assert r.status_code in (400, 401) and new_access(silent) == 403, r.status_code
rid, _ = start(silent, reauth=True)
r = acs(silent, rid, "alice", [time.time(), time.time() - 3600])
assert r.status_code in (400, 401) and new_access(silent) == 403, r.status_code   # refused, or the older one counts
ok("no AuthnStatement → refused, no confirmation; two AuthnStatements → the older one counts (stale)")

# ---------- a local account gets no SAML button ----------
auth.create_user("dora", password="a long local password 4711")
c_local = TestClient(app, base_url=BASE)
assert c_local.post("/auth/login", data={"username": "dora", "password": "a long local password 4711"},
                    follow_redirects=False).status_code == 303
assert "id=reauthsaml" not in c_local.get("/auth/reauth").text
ok("an account without a SAML binding is not offered the SAML button")

# ---------- saml_reauth_check=False: the behaviour up to 0.31.x ----------
auth_off, app_off = build(saml_reauth_check=False)
old = sign_in(auth_off, app_off, "bob", authn_age=2 * 3600)
assert new_access(old) == 200, "with the switch off a silent sign-in should count as before"
assert "id=reauthsaml" not in old.get("/auth/reauth").text
ok("saml_reauth_check=False: every round counts as before, no provider button")

print("OK test_saml_reauth")

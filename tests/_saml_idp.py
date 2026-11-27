"""A SAML test identity provider for the suites: a fresh key pair and really signed responses, checked by the real
python3-saml of the service provider (no mock of the check).

Import it only after `braucht_modul("onelogin", extra="saml")` and friends: it needs `cryptography`, `lxml` and
python3-saml. `IdP(acs, sp)` builds the key; `response(...)` signs a SAMLResponse to one AuthnRequest; `cert_b64` is
the certificate as `saml_idp_x509cert` wants it; `start`/`acs` drive the two routes with a `TestClient`.
"""
from __future__ import annotations

import base64
import datetime as dt
import time
import zlib
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants as K
from onelogin.saml2.utils import OneLogin_Saml2_Utils as Utils

#: The name of the browser cookie that carries the AuthnRequest ID to the ACS (`router.py`).
FLOW = "tinysesam_saml_flow"


def _iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class IdP:
    """One identity provider `entity` for the service provider `base` (its ACS and metadata address follow)."""

    def __init__(self, base: str, entity: str = "https://idp.example.com/sso"):
        self.base, self.entity = base.rstrip("/"), entity
        self.acs_url, self.sp = self.base + "/auth/saml/acs", self.base + "/auth/saml/metadata"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
        self.key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()).decode()
        self.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        self._n = 0

    @property
    def cert_b64(self) -> str:
        """The certificate without the PEM frame — the form `saml_idp_x509cert` takes."""
        return "".join(self.cert_pem.strip().splitlines()[1:-1])

    def config(self) -> dict:
        """The `TinySesamConfig` fields that point the service provider at this identity provider."""
        return dict(saml_enabled=True, saml_idp_sso_url=self.entity, saml_idp_x509cert=self.cert_b64)

    def response(self, rid: str, nameid: str, authn_at: "float | None" = None, attrs: "dict | None" = None) -> str:
        """A signed SAMLResponse to the request `rid` for `nameid`; `authn_at`: its `AuthnInstant` (default now);
        `attrs`: {name: [values]} (default: `email` = `<nameid>@example.com`)."""
        self._n += 1
        n, t = self._n, time.time()
        prior, after = _iso(t - 60), _iso(t + 300)
        authn = _iso(t if authn_at is None else authn_at)
        if attrs is None:
            attrs = {"email": [f"{nameid}@example.com"]}
        values = "".join(
            f'<saml:Attribute Name="{k}">' + "".join(f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in vs)
            + "</saml:Attribute>" for k, vs in attrs.items())
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r{n}" Version="2.0" '
            f'IssueInstant="{prior}" Destination="{self.acs_url}" InResponseTo="{rid}">'
            f'<saml:Issuer>{self.entity}</saml:Issuer><samlp:Status><samlp:StatusCode '
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'<saml:Assertion ID="_a{n}x{int(t * 1000)}" Version="2.0" IssueInstant="{prior}">'
            f'<saml:Issuer>{self.entity}</saml:Issuer>'
            f'<saml:Subject><saml:NameID>{nameid}</saml:NameID><saml:SubjectConfirmation '
            'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData '
            f'NotOnOrAfter="{after}" Recipient="{self.acs_url}" InResponseTo="{rid}"/></saml:SubjectConfirmation>'
            f'</saml:Subject><saml:Conditions NotBefore="{prior}" NotOnOrAfter="{after}">'
            f'<saml:AudienceRestriction><saml:Audience>{self.sp}</saml:Audience></saml:AudienceRestriction>'
            f'</saml:Conditions><saml:AuthnStatement AuthnInstant="{authn}" SessionIndex="_s{n}">'
            '<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            f'<saml:AttributeStatement>{values}</saml:AttributeStatement></saml:Assertion></samlp:Response>')
        doc = etree.fromstring(xml.encode())
        claim = doc.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        doc.replace(claim, etree.fromstring(Utils.add_sign(etree.tostring(claim), self.key_pem, self.cert_pem,
                                                           sign_algorithm=K.RSA_SHA256, digest_algorithm=K.SHA256)))
        return base64.b64encode(etree.tostring(doc)).decode()


def start(c, query: str = "next=/") -> "tuple[str, str]":
    """GET /auth/saml/login?<query> → (request id from the flow cookie, the decoded AuthnRequest)."""
    r = c.get("/auth/saml/login?" + query, follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:200])
    req = parse_qs(urlsplit(r.headers["location"]).query)["SAMLRequest"][0]
    return r.cookies.get(FLOW) or c.cookies.get(FLOW) or "", zlib.decompress(base64.b64decode(req), -15).decode()


def acs(c, idp: IdP, rid: str, nameid: str, authn_at: "float | None" = None, relay: str = "/",
        attrs: "dict | None" = None):
    """POST the signed answer to `rid` to the ACS in the browser `c` (the flow cookie set as the browser would)."""
    c.cookies.set(FLOW, rid)
    return c.post("/auth/saml/acs", data={"SAMLResponse": idp.response(rid, nameid, authn_at, attrs),
                                          "RelayState": relay}, follow_redirects=False)


def round_trip(c, idp: IdP, nameid: str, query: str = "next=/", authn_at: "float | None" = None,
               attrs: "dict | None" = None):
    """`start` + `acs`: one complete round through the identity provider."""
    rid, _ = start(c, query)
    return acs(c, idp, rid, nameid, authn_at, attrs=attrs)

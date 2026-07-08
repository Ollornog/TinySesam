"""SAML 2.0 Service-Provider-Login (Extra `[saml]`, python3-saml/onelogin).

SP-initiierter Flow: /auth/saml/login → AuthnRequest (Redirect zum IdP) → IdP POSTet die signierte
Assertion an /auth/saml/acs → hier Signatur/Conditions prüfen, Attribute lesen. Signatur ersetzt CSRF
(die ACS-POST kommt vom IdP, ist also von CSRF ausgenommen). SP-Metadata unter /auth/saml/metadata.

Minimal gehalten: HTTP-Redirect fürs SSO, HTTP-POST für die ACS; wantAssertionsSigned. Für Signieren
eigener AuthnRequests / Verschlüsselung ließe sich ein SP-Cert/-Key ergänzen.
"""
from __future__ import annotations

_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


class SAMLClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def settings(self, base_url: str) -> dict:
        cfg = self.cfg
        base = (base_url or "").rstrip("/")
        sp_entity = cfg.saml_sp_entity_id or f"{base}/auth/saml/metadata"
        acs = cfg.saml_acs_url or f"{base}/auth/saml/acs"
        return {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": sp_entity,
                "assertionConsumerService": {"url": acs, "binding": _POST},
                "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified",
            },
            "idp": {
                "entityId": cfg.saml_idp_entity_id or cfg.saml_idp_sso_url,
                "singleSignOnService": {"url": cfg.saml_idp_sso_url, "binding": _REDIRECT},
                "x509cert": cfg.saml_idp_x509cert,
            },
            "security": {
                "wantAssertionsSigned": True,
                "wantMessagesSigned": False,
                "requestedAuthnContext": False,
            },
        }

    def _auth(self, req: dict, base_url: str):
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        return OneLogin_Saml2_Auth(req, old_settings=self.settings(base_url))

    def login_url(self, req: dict, base_url: str, return_to: str = "/") -> str:
        return self._auth(req, base_url).login(return_to=return_to)

    def process(self, req: dict, base_url: str):
        """ACS-Response prüfen. Gibt {nameid, attrs} oder None (ungültig/nicht authentifiziert)."""
        auth = self._auth(req, base_url)
        auth.process_response()
        if auth.get_errors() or not auth.is_authenticated():
            return None
        return {"nameid": auth.get_nameid(), "attrs": auth.get_attributes() or {}}

    def metadata(self, base_url: str) -> str:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        st = OneLogin_Saml2_Settings(self.settings(base_url), sp_validation_only=True)
        return st.get_sp_metadata()


def first(attrs: dict, name: str):
    v = attrs.get(name) if name else None
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def as_list(attrs: dict, name: str):
    v = attrs.get(name) if name else None
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]

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


from . import errors


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Aus einem nackten Importfehler eine Meldung machen, die sagt, was zu tun ist.

    Die Extras werden hier bewusst LAZY importiert (erst beim Benutzen). Der Preis dafür war
    bis 0.18.0 ein `ModuleNotFoundError: onelogin` mitten im Anmeldevorgang — für den Betreiber
    ein Defekt, dabei fehlte nur eine Zeile im Install-Befehl."""
    return errors.MissingExtra(
        "Das Extra [saml] ist nicht installiert (pip install 'tinysesam[saml]') — "
        f"es fehlt: {e.name or 'onelogin'}.", extra="saml")


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
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        return OneLogin_Saml2_Auth(req, old_settings=self.settings(base_url))

    def login_url(self, req: dict, base_url: str, return_to: str = "/"):
        """(URL zum IdP, ID des AuthnRequests).

        Die Request-ID ist der Anker gegen untergeschobene Antworten: Der Aufrufer legt sie in
        ein kurzlebiges Cookie und reicht sie bei der ACS wieder an `process()`. Früher wurde
        sie hier weggeworfen — damit nahm die ACS jede signierte Assertion an, auch eine, die
        nie angefordert wurde (Login-CSRF: der Angreifer POSTet seine eigene gültige Assertion
        in den Browser des Opfers und meldet es unter SEINEM Konto an).
        """
        auth = self._auth(req, base_url)
        url = auth.login(return_to=return_to)
        return url, auth.get_last_request_id()

    def process(self, req: dict, base_url: str, request_id: str = ""):
        """ACS-Response prüfen. Gibt {nameid, attrs} oder None (ungültig/nicht authentifiziert).

        Der **Grund** einer Ablehnung geht an den Logger `tinysesam.security`, nicht an den
        Browser: Wer die Antwort schickt, soll nicht erfahren, woran sie scheiterte (Audience?
        Signatur? Uhrzeit?) — der Betreiber schon. Vorher verschwand er ersatzlos, und eine
        fehlgeschlagene Anmeldung war von aussen wie von innen nicht unterscheidbar von
        „irgendwas ist kaputt". Gefunden 2026-09 beim ersten Lauf gegen einen echten IdP:
        Keycloaks Entity-ID ist `…/realms/<realm>`, nicht die SSO-URL — ohne
        `saml_idp_entity_id` lehnt die Prüfung jede Assertion ab, schweigend.
        """
        import secrets as _secrets

        from . import security
        auth = self._auth(req, base_url)
        auth.process_response(request_id=request_id or None)
        if auth.get_errors() or not auth.is_authenticated():
            security.seclog.warning("SAML-Antwort abgelehnt: errors=%s reason=%s authenticated=%s",
                                    auth.get_errors(), auth.get_last_error_reason(),
                                    auth.is_authenticated())
            return None
        # Die Bibliothek prüft `InResponseTo` NUR, wenn es überhaupt dasteht (python3-saml
        # 1.16, response.py: `if in_response_to is not None and request_id is not None`).
        # Eine Antwort ganz OHNE das Feld — die IdP-initiierte („unsolicited") Variante —
        # geht also durch, und mit ihr jede Assertion, die nie angefordert wurde. Diese
        # Fassung ist SP-initiiert (s. Modul-Docstring): keine Anforderung, kein Login.
        irt = auth.get_last_response_in_response_to()
        if not request_id or not irt or not _secrets.compare_digest(str(irt), str(request_id)):
            security.seclog.warning(
                "SAML-Antwort abgelehnt: InResponseTo=%r passt nicht zum angeforderten "
                "AuthnRequest (%s). Entweder nie angefordert (IdP-initiiert wird nicht "
                "unterstützt) oder das Flow-Cookie kam nicht mit — bei cookie_secure=False "
                "sendet der Browser es beim Cross-Site-POST des IdP nicht.",
                irt, "keine ID mitgegeben" if not request_id else "andere ID")
            return None
        return {"nameid": auth.get_nameid(), "attrs": auth.get_attributes() or {}}

    def metadata(self, base_url: str) -> str:
        try:
            from onelogin.saml2.settings import OneLogin_Saml2_Settings
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
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

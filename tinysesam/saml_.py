"""SAML 2.0 service provider login (extra `[saml]`, python3-saml/onelogin).

SP-initiated flow: /auth/saml/login → AuthnRequest (redirect to the IdP) → IdP POSTs the signed
assertion to /auth/saml/acs → here check signature/conditions, read attributes. The signature replaces CSRF
(the ACS POST comes from the IdP, so it is exempt from CSRF). SP metadata at /auth/saml/metadata.

Kept minimal: HTTP redirect for SSO, HTTP POST for the ACS; wantAssertionsSigned. For signing
own AuthnRequests / encryption an SP cert/key could be added.
"""
from __future__ import annotations

_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


from . import errors


def _missing_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Turn a bare import error into a message that says what to do.

    The extras are deliberately imported LAZILY here (only on use). The price for that was,
    up to 0.18.0, a `ModuleNotFoundError: onelogin` in the middle of the sign-in — for the operator
    a defect, when only one word was missing in the install command."""
    return errors.MissingExtra(
        "The extra [saml] is not installed (pip install 'tinysesam[saml]') — "
        f"missing: {e.name or 'onelogin'}.", extra="saml")


def request_context(base: str, path: str, form=None, query=None) -> dict:
    """The `req` dict for python3-saml — **from the verified base**, not from headers (F-16).

    python3-saml builds from `https`, `http_host` and `script_name` the address it takes to be
    its own, and compares the assertion's `Destination` against it. If scheme and host
    came from `X-Forwarded-Proto`/`Host`, the requester co-determined this comparison: they could
    present an assertion whose `Destination` names their own address, and set the header to
    match — the check passed although the assertion was never meant for us.
    Together with the binding via the bare username (F-11) that amounted to an
    account takeover without knowing the local password.

    The base now comes from `TinySesam.public_base()`, i.e. from `base_url` — the same
    commitment from which entity ID and ACS URL are built. So all three values say
    the same thing, and none of them listens to the requester.

    The **path part** of the base belongs in `script_name`, otherwise the destination
    check fails for an app mounted under a subpath: the ACS URL in the settings
    carries it (`base + /auth/saml/acs`), so the computed own address would have to carry it too.
    If it is already contained in the path (ASGI mount), it is not appended twice.
    """
    from urllib.parse import urlsplit
    parts = urlsplit(str(base or ""))
    prefix = (parts.path or "").rstrip("/")
    away = str(path or "/")
    if prefix and not away.startswith(prefix + "/") and away != prefix:
        away = prefix + away
    host = parts.netloc or ""
    return {"https": "on" if parts.scheme == "https" else "off",
            "http_host": host, "script_name": away,
            "get_data": dict(query or {}),
            "post_data": {k: v for k, v in (form or {}).items()}}


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
                # SHA-1 in signature or digest methods is rejected (F-21). python3-saml
                # accepts `rsa-sha1`/`dsa-sha1`/`sha1` by itself (default False) — although
                # SHA-1 collisions have been practical since SHAttered (2017) and XML-DSig has listed them as
                # deprecated since RFC 6931. Deliberately without a switch, like the ID-token
                # methods in oidc.py: every common IdP (ADFS, Entra, Keycloak, Okta)
                # has signed with SHA-256 for years; whoever still receives SHA-1 reconfigures the IdP.
                "rejectDeprecatedAlgorithm": True,
            },
        }

    def _auth(self, req: dict, base_url: str):
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ModuleNotFoundError as e:
            raise _missing_extra(e) from e
        return OneLogin_Saml2_Auth(req, old_settings=self.settings(base_url))

    def login_url(self, req: dict, base_url: str, return_to: str = "/"):
        """(URL to the IdP, ID of the AuthnRequest).

        The request ID is the anchor against planted responses: the caller puts it into
        a short-lived cookie and hands it back to `process()` at the ACS. It used to be
        thrown away here — so the ACS accepted every signed assertion, even one that was
        never requested (login CSRF: the attacker POSTs their own valid assertion
        into the victim's browser and signs the victim in under THEIR account).
        """
        auth = self._auth(req, base_url)
        url = auth.login(return_to=return_to)
        return url, auth.get_last_request_id()

    def process(self, req: dict, base_url: str, request_id: str = ""):
        """Check the ACS response. Returns {nameid, attrs} or None (invalid/not authenticated).

        The **reason** for a rejection goes to the logger `tinysesam.security`, not to the
        browser: whoever sends the response should not learn why it failed (audience?
        signature? time?) — the operator should. Before, it vanished without a trace, and a
        failed sign-in was indistinguishable, from outside and inside, from
        "something is broken". Found 2026-09 on the first run against a real IdP:
        Keycloak's entity ID is `…/realms/<realm>`, not the SSO URL — without
        `saml_idp_entity_id` the check rejects every assertion, silently.
        """
        import secrets as _secrets

        from . import security
        auth = self._auth(req, base_url)
        auth.process_response(request_id=request_id or None)
        if auth.get_errors() or not auth.is_authenticated():
            security.seclog.warning("SAML response rejected: errors=%s reason=%s authenticated=%s",
                                    auth.get_errors(), auth.get_last_error_reason(),
                                    auth.is_authenticated())
            return None
        # The library checks `InResponseTo` ONLY if it is present at all (python3-saml
        # 1.16, response.py: `if in_response_to is not None and request_id is not None`).
        # A response entirely WITHOUT the field — the IdP-initiated ("unsolicited") variant —
        # therefore passes, and with it every assertion that was never requested. This
        # version is SP-initiated (see module docstring): no request, no login.
        irt = auth.get_last_response_in_response_to()
        if not request_id or not irt or not _secrets.compare_digest(str(irt), str(request_id)):
            security.seclog.warning(
                "SAML response rejected: InResponseTo=%r does not match the requested "
                "AuthnRequest (%s). Either never requested (IdP-initiated is not "
                "supported) or the flow cookie did not come along — with cookie_secure=False "
                "the browser does not send it on the IdP's cross-site POST.",
                irt, "no ID supplied" if not request_id else "different ID")
            return None
        return {"nameid": auth.get_nameid(), "attrs": auth.get_attributes() or {}}

    def metadata(self, base_url: str) -> str:
        try:
            from onelogin.saml2.settings import OneLogin_Saml2_Settings
        except ModuleNotFoundError as e:
            raise _missing_extra(e) from e
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

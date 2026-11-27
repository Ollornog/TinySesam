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


#: Keys in the store's flow table (H1, ASVS 6.8.3). The request ID of every AuthnRequest this server sent, until
#: the response redeems it; and the ID of every accepted assertion, until it has expired for good.
REQUEST_FLOW = "samlreq:"
ASSERTION_FLOW = "samlassert:"
#: How long a sent AuthnRequest may be answered — the same 10 minutes as the flow cookie in router.py.
REQUEST_TTL_SEC = 600


class SAMLClient:
    def __init__(self, cfg, store=None):
        """`store`: where request and assertion IDs are remembered (H1). Without one (a bare client in a test)
        only the flow cookie binds the response — the replay protection needs the store."""
        self.cfg = cfg
        self.store = store

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

    def login_url(self, req: dict, base_url: str, return_to: str = "/", force_authn: bool = False):
        """(URL to the IdP, ID of the AuthnRequest).

        `force_authn` (T-70): the confirmation page's provider button — `ForceAuthn="true"`, the identity provider
        MUST authenticate the person directly instead of relying on its running session (SAML 2.0 Core §3.4.1). The
        request remembers it and the moment it was sent (`asked`); `process` hands both back with the assertion's
        `AuthnInstant`.

        The request ID is the anchor against planted responses: the caller puts it into
        a short-lived cookie and hands it back to `process()` at the ACS. It used to be
        thrown away here — so the ACS accepted every signed assertion, even one that was
        never requested (login CSRF: the attacker POSTs their own valid assertion
        into the victim's browser and signs the victim in under THEIR account).
        """
        import time as _time

        auth = self._auth(req, base_url)
        url = auth.login(return_to=return_to, force_authn=bool(force_authn))
        request_id = auth.get_last_request_id()
        if self.store is not None and request_id:
            self.store.put_flow(REQUEST_FLOW + request_id, {"reauth": bool(force_authn), "asked": int(_time.time())},
                                ttl=REQUEST_TTL_SEC)
        return url, request_id

    def process(self, req: dict, base_url: str, request_id: str = ""):
        """Check the ACS response. Returns {nameid, attrs, authn_instant, reauth, asked} or None (invalid/not
        authenticated). `authn_instant`: the `AuthnInstant` of the checked assertion's `AuthnStatement` (Unix seconds,
        at most now) or None; `reauth`/`asked`: what `login_url` remembered for this request (T-70).

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
        flow: dict = {}
        if self.store is not None:
            redeemed = self._redeem_once(auth, str(request_id))
            if redeemed is None:
                return None
            flow = redeemed
        return {"nameid": auth.get_nameid(), "attrs": auth.get_attributes() or {},
                "authn_instant": authn_instant(auth), "reauth": bool(flow.get("reauth")), "asked": flow.get("asked")}

    def _redeem_once(self, auth, request_id: str) -> "dict | None":
        """Each AuthnRequest is answered once, each assertion is accepted once (H1, ASVS 6.8.3).

        Until H1 the request ID lived only in the browser's flow cookie. Whoever got hold of a `SAMLResponse`
        (proxy log, the device, malware) set that cookie themselves — its value is the `InResponseTo` in the
        response — and signed in again, as often as they liked, until `NotOnOrAfter`. Now:

        1. The request ID must be one THIS server sent and nobody has redeemed yet (`pop_flow`, atomic like
           the OIDC `state` and the WebAuthn challenge).
        2. The assertion ID is remembered until its `NotOnOrAfter` plus the clock drift python3-saml allows;
           a second assertion with the same ID is refused even under a fresh request (an IdP that reuses IDs,
           or two responses raced in at once).
        """
        import time as _time

        from . import security
        flow = self.store.pop_flow(REQUEST_FLOW + request_id)
        if flow is None:
            security.seclog.warning(
                "SAML response rejected: the AuthnRequest %r was not sent by this server, has expired or has "
                "already been answered (replay)", request_id)
            return None
        assertion_id = str(auth.get_last_assertion_id() or "")
        if not assertion_id:
            security.seclog.warning("SAML response rejected: assertion without an ID")
            return None
        try:
            from onelogin.saml2.constants import OneLogin_Saml2_Constants
            drift = int(OneLogin_Saml2_Constants.ALLOWED_CLOCK_DRIFT)
        except (ImportError, AttributeError, TypeError, ValueError):
            drift = 300
        not_after = auth.get_last_assertion_not_on_or_after()
        ttl = (int(not_after) - int(_time.time()) if not_after else REQUEST_TTL_SEC) + drift
        if not self.store.claim_flow(ASSERTION_FLOW + assertion_id, ttl):
            security.seclog.warning("SAML response rejected: assertion %r was already used (replay)", assertion_id)
            return None
        return flow if isinstance(flow, dict) else {}

    def metadata(self, base_url: str) -> str:
        try:
            from onelogin.saml2.settings import OneLogin_Saml2_Settings
        except ModuleNotFoundError as e:
            raise _missing_extra(e) from e
        st = OneLogin_Saml2_Settings(self.settings(base_url), sp_validation_only=True)
        return st.get_sp_metadata()


def authn_instant(auth) -> "int | None":
    """The `AuthnInstant` of the checked assertion (T-70) as Unix seconds, at most now — None when it is missing or
    unreadable. python3-saml has no getter: read from the last response document (decrypted, if the assertion was
    encrypted), from the ONE assertion whose ID the library checked (`get_last_assertion_id`; it refuses a response
    with more than one), so a second, unsigned `AuthnStatement` elsewhere in the document is never read. Two
    `AuthnStatement`s in that assertion: the oldest counts (fail-closed)."""
    import time as _time

    try:
        from onelogin.saml2.utils import OneLogin_Saml2_Utils
        from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
        doc = auth.get_last_response_xml()
        aid = str(auth.get_last_assertion_id() or "")
        if not doc or not aid:
            return None
        root = OneLogin_Saml2_XML.to_etree(doc)
        ns = "urn:oasis:names:tc:SAML:2.0:assertion"
        assertions = [a for a in root.iter(f"{{{ns}}}Assertion") if a.get("ID") == aid]
        if len(assertions) != 1:
            return None
        found = [OneLogin_Saml2_Utils.parse_SAML_to_time(s.get("AuthnInstant"))
                 for s in assertions[0].findall(f"{{{ns}}}AuthnStatement") if s.get("AuthnInstant")]
    except Exception:  # noqa: BLE001 — unreadable is "missing": no fresh confirmation, never an error page
        return None
    if not found:
        return None
    return min(min(int(t) for t in found), int(_time.time()))


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

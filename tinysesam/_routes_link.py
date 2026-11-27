"""The routes of the person's own links to providers (T-99, ADR-18): unlink any of them, link SAML and LDAP.

OIDC's link route lives in `oidc.py` (`POST /auth/oidc/link`). Registered by `router.py` only with a provider switched
on (`/auth/identities/unlink`), LDAP (`/auth/ldap/link`) or SAML (`/auth/saml/link`, from the SAML block, which hands
over its checked base and request builder). Every route is a POST with the CSRF token from the account page and a
fresh confirmation (`_require_fresh`) — never a GET, never an API key; the decisions are in
`_manager_federated_link.py`.
"""
from __future__ import annotations

from fastapi import Form, HTTPException, Request
from fastapi.responses import RedirectResponse

#: The flow row of a SAML link (keyed by the AuthnRequest ID): the account and the session that started it.
SAML_LINK_FLOW = "samllink:"


def _person(auth, request: Request, csrf_tok: str, throttle: bool = True) -> dict:
    """CSRF, the IP throttle (a signed-in action, not a sign-in: `failed verification` when it bites), a browser session
    of the account (never a key) and a fresh confirmation — or the refusal. `throttle=False` for the directory link,
    whose password check books itself like a sign-in (`_link_directory`)."""
    auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
    if throttle and not auth._rate_ok(auth.client_ip(request), login=False):
        raise HTTPException(429, auth.t("err.rate"))
    u = auth.session_user(request)
    if u is None:
        raise HTTPException(401, auth.t("api.not_signed_in"))
    return auth._require_fresh(request, u)


def _done(auth, request: Request, refused):
    if refused is not None:
        raise HTTPException(refused[0], auth.t(refused[1]))
    return RedirectResponse(auth.browser_path(request, "/auth/account"), 303)


def register_routes(r, auth) -> None:
    """`/auth/identities/unlink` and, with `ldap_enabled`, `/auth/ldap/link`."""
    cfg = auth.cfg

    @r.post("/auth/identities/unlink")
    def identity_unlink(request: Request, source: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        """Release the account's identity at `source` (`oidc`, `saml`, `ldap`) — never the last way in."""
        u = _person(auth, request, csrf_tok)
        return _done(auth, request, auth._unlink_identity(u, source, auth.client_ip(request)))

    if cfg.ldap_enabled:
        @r.post("/auth/ldap/link")
        def ldap_link(request: Request, username: str = Form(""), password: str = Form(""),
                      csrf_tok: str = Form("", alias="_csrf")):
            """Link the account with a directory entry: its name and password, checked by a bind."""
            u = _person(auth, request, csrf_tok, throttle=False)
            existing = auth.store.get_federated_identifier("ldap", u["id"])
            if existing and not str(existing).startswith(auth._WITHOUT_IDENTIFIER):
                raise HTTPException(409, auth.t("api.oidc_link_exists"))
            return _done(auth, request, auth._link_directory(request, u, username, password))


def register_saml_link(r, auth, saml_req, saml_base_url, flow_cookie: str, samesite: str) -> None:
    """`POST /auth/saml/link` — from the SAML block of `router.py`, with its request builder and checked base."""

    @r.post("/auth/saml/link")
    def saml_link_start(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        """Start the link: an AuthnRequest with `ForceAuthn`; the flow remembers the account and THIS session, the ACS
        binds only for both (`_finish_saml_link`)."""
        u = _person(auth, request, csrf_tok)
        existing = auth.store.get_federated_identifier("saml", u["id"])
        if existing and not str(existing).startswith(auth._WITHOUT_IDENTIFIER):
            raise HTTPException(409, auth.t("api.oidc_link_exists"))
        s = auth._session_from_request(request)
        url, rid = auth.saml.login_url(saml_req(request), saml_base_url(request),
                                       return_to=auth.browser_path(request, "/auth/account"), force_authn=True)
        if not rid or not s:
            raise HTTPException(500, auth.t("err.saml"))
        auth.store.put_flow(SAML_LINK_FLOW + rid, {"user": int(u["id"]), "session": s["token_hash"]}, ttl=600)
        resp = RedirectResponse(url, 303)
        auth._set_flow_cookie(resp, flow_cookie, rid, max_age=600, samesite=samesite)
        return resp

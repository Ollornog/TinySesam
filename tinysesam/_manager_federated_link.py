"""The building block `federated_link` of `TinySesam`: the person links and unlinks an identity at a provider (T-99,
ADR-18).

OIDC links through `POST /auth/oidc/link` (`oidc.py`); SAML and LDAP follow the same rules here: a fresh confirmation
on this side (`_require_fresh`, in the route), an active sign-in at the provider (SAML `ForceAuthn` with a fresh
`AuthnInstant`, LDAP a bind with the directory password), only the session that started it, never an identity of
another account, never by a name or an address. Unlinking is the person's too — with a fresh confirmation, and never
the last way in.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as `self`,
exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import secrets
from typing import Optional

from . import manager as _manager
from . import security

#: The providers a person links and unlinks on the account page, and the switch each one needs.
LINK_SOURCES = {"oidc": "oidc_enabled", "saml": "saml_enabled", "ldap": "ldap_enabled"}
#: How far an `AuthnInstant` may lie before the request that asked for it (clock skew), as at the ACS (T-70).
SAML_TOLERANCE_SEC = 60


def _linked_sources(self, user_id) -> list:
    """The providers this account is bound to — a real binding or an origin placeholder — in `LINK_SOURCES` order."""
    uid = int(user_id)
    out = ["oidc"] if self.store.is_oidc_account(uid) else []
    return out + [s for s in ("saml", "ldap") if self.store.get_federated_identifier(s, uid)]


def _other_way_in(self, user_id, without: str) -> bool:
    """Does the account keep a way to sign in when its identity at `without` goes? A password, a passkey or a PIN as
    first factor this installation offers, or an identity at another provider that is switched on. A sign-in link
    does not count: it reaches only whoever holds the mailbox, and an account must not end with that alone by its own
    hand."""
    cfg, uid = self.cfg, int(user_id)
    if cfg.password_enabled and self.store.get_password_hash(uid):
        return True
    if cfg.passkey_enabled and self.store.list_webauthn(uid):
        return True
    if cfg.pin_as_first_factor() and self.store.has_pin(uid):
        return True
    return any(getattr(cfg, LINK_SOURCES[s], False) for s in self._linked_sources(uid) if s != without)


def _identities_view(self, user) -> list:
    """The account page's view: one entry per provider that is switched on — `source`, `linked`, and `can_unlink`
    (False when it is the last way in, so the page says why instead of offering a button that refuses)."""
    uid = int(user["id"])
    linked = self._linked_sources(uid)
    return [{"source": s, "linked": s in linked, "can_unlink": s in linked and self._other_way_in(uid, s)}
            for s, switch in LINK_SOURCES.items() if getattr(self.cfg, switch, False)]


def _unlink_identity(self, user, source: str, ip: Optional[str] = None) -> Optional[tuple]:
    """Release the account's identity at `source` — the person's own path (T-99); the route checked CSRF and a fresh
    confirmation. None on success, otherwise (status, message key). Never the last way in (409). A SAML or LDAP
    identity released this way is never bound back by the name alone (`close_name_binding`): the next sign-in there
    under the same name is refused until the person links again or the operator opens it (`federation_unbind`)."""
    uid, name = int(user["id"]), str(user["username"])
    if source not in LINK_SOURCES or not getattr(self.cfg, LINK_SOURCES[source], False):
        return 400, "api.link_source"
    if source not in self._linked_sources(uid):
        return 404, "api.link_none"
    if not self._other_way_in(uid, source):
        self.audit(f"{source}_unlink_refused", name, ip, "reason=last_way_in")
        return 409, "api.link_last"
    if source == "oidc":
        self.store.unlink_oidc(uid)
    else:
        self.store.unlink_federated(source, uid)
        self.store.close_name_binding(source, uid)
    self.audit(f"{source}_unlinked", name, ip, "by=holder")
    return None


def _bind_identity(self, source: str, identifier: str, user, ip: Optional[str] = None) -> Optional[tuple]:
    """Bind the identity `identifier` the provider has just proven to the account (SAML, LDAP) — only one of nobody
    else, only when the account carries no real identity of that source yet (an origin placeholder yields), in ONE
    transaction (`Store.rebind`). Never by a name or an address. None on success, otherwise (status, message key)."""
    uid, name = int(user["id"]), str(user["username"])
    raw = str(identifier or "")
    if not raw.strip() or self._identifier_form_error(raw):
        self.audit(f"{source}_link_refused", name, ip, "reason=identifier")
        return 400, "api.link_identifier"
    identifier = raw.strip()
    owner = self.store.get_federated_user(source, identifier)
    if owner is not None and int(owner) != uid:
        self.audit(f"{source}_link_refused", name, ip, f"reason=identity_taken account={int(owner)}")
        return 409, "api.oidc_link_taken"
    if owner is not None:
        return None                          # already this account's: nothing to do
    existing = self.store.get_federated_identifier(source, uid)
    if existing and not str(existing).startswith(self._WITHOUT_IDENTIFIER):
        self.audit(f"{source}_link_refused", name, ip, "reason=already_linked")
        return 409, "api.oidc_link_exists"
    if not self.store.rebind(source, identifier, uid, _manager._now()):
        # Taken between the check and the write (a sign-in, another link): the database decided.
        self.audit(f"{source}_link_refused", name, ip, "reason=identity_taken race=1")
        return 409, "api.oidc_link_taken"
    self.audit(f"{source}_linked", name, ip, "by=holder")
    return None


def _link_directory(self, request, user, username: str, password: str) -> Optional[tuple]:
    """Link the account with the directory entry `username` (T-99): the directory checks the password (a bind,
    `_ldap_bind`: the outage marker and `ldap_allowed_groups` as at sign-in), and its stable identifier is bound
    (`_bind_identity`). It is a guess at a directory password, so it is booked like a sign-in under the typed name —
    throttled, pre-booked, locked, `failed login` for fail2ban; an outage is no attempt (F-23). The typed name or
    address of ANOTHER local account is refused (one identifier, one account). None on success, otherwise (status,
    message key)."""
    from .ldap_ import DirectoryNotReachable
    uid = int(user["id"])
    ip = self.client_ip(request)
    if not username or not password:
        return 400, "err.required"
    if not self._rate_ok(ip):
        return 429, "err.rate"
    attempt = self._begin_attempt(username, ip, "password", as_pending=True)
    if attempt is None:
        return 429, "err.retry"
    try:
        info = self._ldap_bind(username, password)
    except DirectoryNotReachable as e:
        self.audit("ldap_unavailable", str(user["username"]), ip, security.for_log(str(e))[:300])
        security.seclog.error("LDAP unreachable user=%s ip=%s reason=%s", security.for_log(username),
                              security.for_log(ip), security.for_log(str(e)))
        self._revert_attempt(attempt)
        return 503, "err.directory_down"
    except BaseException:
        self._attempt_failed(attempt)
        raise
    if not info:
        self._record_login(username, ip, False, "password", attempt=attempt, source="ldap")
        self.audit("ldap_link_refused", str(user["username"]), ip, "reason=credentials")
        return 401, "err.credentials"
    self._record_login(username, ip, True, "password", attempt=attempt, account=uid)
    local = self.find_user(username)
    if local is not None and int(local["id"]) != uid:
        self.audit("ldap_link_refused", str(user["username"]), ip,
                   f"reason=identifier_of_other_account account={int(local['id'])}")
        return 409, "api.oidc_link_taken"
    refused = self._bind_identity("ldap", str(info.get("id") or ""), user, ip)
    if refused is None:
        # As at sign-in (G5): the typed name on the binding, so the series under it has a way back.
        from .store import name_invalid
        if not name_invalid(username):
            self.store.set_binding_name("ldap", uid, username)
    return refused


def _finish_saml_link(self, request, flow: dict, data: dict) -> Optional[tuple]:
    """The ACS of a link flow (`POST /auth/saml/link`): bind the assertion's identity to the flow's account — only in
    the session that started it, still full, after an active sign-in at the provider (an `AuthnInstant` from after the
    request; the request sent `ForceAuthn`), and through the group gate `saml_allowed_groups`. Never by an address.
    None on success, otherwise (status, message key)."""
    from .saml_ import as_list
    cfg = self.cfg
    ip = self.client_ip(request)
    uid = int(flow.get("user") or 0)
    account = self.store.get_user(uid) if uid else None
    name = str(account["username"]) if account else "?"
    s = self._session_from_request(request)
    if (account is None or not s or int(s["user_id"]) != uid or not s["mfa_ok"] or not flow.get("session")
            or not secrets.compare_digest(str(s["token_hash"]), str(flow["session"]))):
        self.audit("saml_link_refused", name, ip, "reason=session")
        return 403, "api.oidc_link_session"
    authenticated, asked = data.get("authn_instant"), int(data.get("asked") or flow.get("asked") or 0)
    if authenticated is None or not asked or int(authenticated) < asked - SAML_TOLERANCE_SEC:
        self.audit("saml_link_refused", name, ip,
                   f"reason=stale authn_instant={'missing' if authenticated is None else 'old'}")
        return 401, "err.saml_reauth_stale"
    attrs = data.get("attrs") or {}
    if cfg.saml_allowed_groups and not (set(cfg.saml_allowed_groups)
                                        & {str(g) for g in as_list(attrs, cfg.saml_attr_groups)}):
        self.audit("saml_link_refused", name, ip, f"reason=group required={sorted(cfg.saml_allowed_groups)}")
        return 403, "api.saml_denied"
    return self._bind_identity("saml", self._saml_identifier(data.get("nameid"), attrs), account, ip)

"""The building block `saml` of `TinySesam`: SAML sign-in (attributes to a local account).

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import contextvars
import hashlib
import sqlite3
from . import security
from .errors import ConfigError
from .store import name_invalid
from .store import norm_email
from .store import norm_identifier
from .store import valid_email
from typing import Optional
from . import manager as _manager
from .manager import (
    _proof_true,
)


# ---------- SAML (attributes → local user) ----------
def _check_saml(self, nameid, attrs, ip: Optional[str] = None) -> Optional[dict]:
    """Find/create a local user from a verified SAML assertion. Factor 'saml'.

    The address from the attribute carries no evidence (SAML has no `email_verified`).
    Since the PO decision 2026-09-24 the operator says whether they trust it
    (`saml_email_trusted`, default no). Without trust it is not used, an
    account name with `@` yields to a substitute name, and via such a name no
    existing account is ever mapped. The factor `saml` is in `_FEDERATED_FACTORS`: an allowlist ADDRESS never becomes first admin via this path,
    even if a caller does not state the evidence — and not via a second,
    self-set-up factor at the next login either (B-bypass-1 from T-13).

    Every substantive rejection leaves an audit line with a reason (F-22): up to 0.20.0
    group gate, missing account and locked account ended silently in a 403 — "I can't get
    in" could not be answered on the server side. `ip` is passed through by the ACS route."""
    from .saml_ import first, as_list
    cfg = self.cfg
    username = first(attrs, cfg.saml_attr_username) if cfg.saml_attr_username else None
    raw_name = str(username or nameid or "")
    # The UNTRIMMED value is checked: `strip()` also removes U+2028, U+0085 and Unicode
    # whitespace — `manager\u2028` would otherwise become `manager` (counter-check).
    username = raw_name.strip()
    if not username:
        self.audit("saml_denied", None, ip, "reason=no_name")
        return None
    blanket = bool(cfg.saml_email_trusted)
    _attr = security.proof_attribute(cfg, "saml")
    mail = first(attrs, cfg.saml_attr_email)
    # The evidence attribute proves the ADDRESS of this login — not the name. At an IdP with
    # self-registration (exactly what it is for) the user chooses their NameID themselves:
    # `bob@example.com` as name, confirming their own address. Here the name then counted as
    # verified and was mapped via case 4 to the local account `bob@example.com` —
    # takeover (self-service attack round, finding 1). As with OIDC (`email_verified`):
    # a name with `@` is verified only if it is EXACTLY the verified address.
    proof = bool(_attr) and _proof_true(first(attrs, _attr)) and valid_email(norm_email(mail or "") or "")
    trusted = blanket or proof
    # The stable identifier is the `NameID` — or an attribute if the IdP sends transient
    # NameIDs (`saml_attr_id`). The name is only the fallback (F-11).
    identifier = self._saml_identifier(nameid, attrs)
    # Without trust in this IdP's addresses (default) as with H-3 for OIDC: a name with `@`
    # (NameID in emailAddress format, a UPN) is the same unverified address under another
    # name — as account name and `Remote-User` it would occupy the real owner's identifier.
    # Applies only to NEW accounts; a bound one keeps its name. Checked folded
    # (`＠` U+FF20 becomes `@`, R2-1).
    new_name = username
    name_assign = True
    # The name is unverified if it is an address — or if it comes from the address attribute
    # itself (`saml_attr_username` = `saml_attr_email`): then it carries what the user
    # entered there, also `manager` without `@` (counter-check).
    unproven = (not blanket) and (
        "@" in norm_identifier(username)
        or (bool(cfg.saml_attr_username) and cfg.saml_attr_username == cfg.saml_attr_email)
    ) and not (proof and norm_identifier(username) == norm_identifier(mail or ""))
    if name_invalid(raw_name) or unproven:
        new_name = "saml-" + hashlib.sha256((identifier or username).encode()).hexdigest()[:8]
        name_assign = False
    if cfg.saml_allowed_groups:
        groups = as_list(attrs, cfg.saml_attr_groups)
        if not (set(cfg.saml_allowed_groups) & set(str(g) for g in groups)):
            self.audit("saml_denied", username, ip,
                       f"reason=group required={sorted(cfg.saml_allowed_groups)}")
            return None
    def _create():
        if not cfg.saml_auto_create:
            self.audit("saml_denied", username, ip, "reason=no_account saml_auto_create=False")
            return None
        try:
            # As with LDAP (B-bypass-1 from T-13): the address from the assertion comes without
            # evidence, so it is stored without evidence too. Otherwise the marker on the
            # account would be a free pass for every later sign-in path that itself
            # proves nothing.
            name = new_name
            i = 1
            while name != username and self.identifier_taken(name):
                i += 1
                name = f"{new_name}{i}"
            display = first(attrs, cfg.saml_attr_name) or name
            return self._create_account(name, display_name=display,
                                       email=mail if trusted else None,
                                       email_verified=trusted and bool(mail),
                                       name_source="saml")
        except ConfigError:
            # As with LDAP (finding R4-12): an already taken identifier creates no account.
            self.audit("saml_ident_taken", username)
            return None

    u = self._resolve_foreign_identity("saml", identifier, username, _create,
                                          name_assign=name_assign)
    if u and u["disabled"]:
        self.audit("saml_denied", str(u["username"]), ip, "reason=account_locked")
        return None
    if not u:
        return None     # the reason is already in the audit log (creation/identifier)
    self._address_proven_by_source(u, mail, trusted, "saml")
    self.apply_idp_groups(u["id"], as_list(attrs, cfg.saml_attr_groups), cfg.saml_group_role_map)
    if cfg.saml_group_import:
        # An assertion carries no empty attribute: an absent one is the IdP's "no groups" and withdraws the imported
        # roles at this sign-in, as it withdraws the mapped ones (T-99, T-102).
        self._import_idp_groups(u["id"], "saml", as_list(attrs, cfg.saml_attr_groups))
    return self._as_dict(self.store.get_user(u["id"]))   # fresh (mapped roles)


def _address_proven_by_source(self, u, mail, trusted, source: str = "") -> None:
    """Bring the address from a source (LDAP/SAML) to the account.

    * **Trusted** (switch or evidence attribute of this login): verifies THE SAME address on the
      account (the source says nothing about any other one; same rule as for the OIDC claim),
      upgrade only; an account without an address gets it if it is free (as H-3 for OIDC).
    * **Not trusted** (PO decision 2026-09-25): with `federation_email_confirm`, mailer and
      `base_url`, a confirmation link goes once to the address — the same path as the
      self-service mail change (`request_email_change`). Only the click makes it the
      account's address. Only for accounts WITHOUT a verified address, at most one DELIVERED
      link per day (G12a, see below).
    Silence takes the evidence from no account that the operator set themselves.

    Deliveries are counted, attempts dampened (G12a, since 2026-09-26). Until then the
    attempt itself used up the daily allowance (per process, in memory): a throttled
    target address or a failed delivery cost the link for a whole day, and
    several workers each sent one. Now the delivery is in the database
    (`federation_email_confirm … account=<id>`, only after sending, `Store.source_mail_since`).
    A taken or reserved address never gets a link; its attempt (with
    audit line `account=<id> …`) is likewise counted in the database, at most one per day. Until
    the attack round 2026-09-26 only memory dampened it — per worker and until restart:
    a free address left exactly one request on the account page, a taken one one more
    with every further worker, and an LDAP user who maintains their `mail` themselves could read from
    that whether a foreign address has an account. Memory now dampens only what
    passes — a throttle, a mail server error: after `mail_per_address_window_sec` again."""
    if not mail or not u:
        return
    address = norm_email(mail)
    account_mail = norm_email(u["email"] or "")
    if trusted:
        if account_mail == address and not u["email_verified"]:
            self.store.set_email_verified(u["id"], True)
        elif not account_mail and not self.identifier_taken(address, exclude_id=u["id"]):
            try:
                self.store.set_email(u["id"], address, verified=True)
            except sqlite3.IntegrityError:
                # Race: meanwhile identifier of another account — the account stays without an
                # address, as with the pre-check (fail-closed).
                self.audit(f"{source or 'source'}_email_taken", str(u["username"]), None,
                           "backfilled=0 race=1")
        return
    # An account with a verified address keeps it — also a different one from the source's: the
    # owner confirmed it themselves (self-service), and a link at every sign-in that wants to
    # replace it would be a nuisance. They can change it themselves via the account page.
    if u["email_verified"]:
        return
    if not (self.cfg.federation_email_confirm and self.cfg.base_url and self.mail_configured()):
        return
    # None while one is open, and at most one completed request per account and day —
    # delivered or rejected (taken, reserved), counted in the database, across all
    # workers. Otherwise every sign-in would write an audit line, and their count on the account page
    # would reveal whether the address is taken (attack round 2026-09-26). If a link lives longer
    # than a day (`email_change_ttl_min`), then that long: a delivered one holds up the next
    # attempt until its expiry anyway (`open_token`), a rejection must do the same
    # — and also when the owner discards their open link (password change).
    # Every open link of the account holds things up, whichever address it goes to (p2 F2): the line
    # `federation_email_confirm` arises only after sending. With the filter on the address
    # a second worker, while the first link was still in the outbox, would send one to a
    # different `mail` — if it arrived, the first address was free (a taken one writes its
    # rejection immediately), and the account got two links in one day.
    deadline = max(86400, int(self.cfg.email_change_ttl_min) * 60)
    if self.store.open_token(u["id"], "email_change"):
        return
    if self.store.source_mail_since(u["id"], _manager._now() - deadline):
        return
    # What passes (throttle, mail server) is dampened by memory per process (G12a): after the
    # window of the mail throttle again. Identical for every target — "taken?" is asked only
    # in `_request_change`, with the same work for both answers (G12b).
    if not self.rl.allow(f"source_mail:{u['id']}", 1, int(self._sec("mail_per_address_window_sec"))):
        return
    try:
        send = self._request_change(u["id"], address, self.cfg.base_url, source=source or "source")
    except (ValueError, ConfigError):
        return
    if send is None:
        return
    uid, name = u["id"], u["username"]
    # Write the line in the context of the request (IP as before), but only in the outbox
    # and only if the link really went out — it is the daily allowance.
    request = contextvars.copy_context()

    def _dispatch():
        if send():
            request.run(self.audit, "federation_email_confirm", name,
                        detail=f"account={uid} source={source} to={address}")
    if not self._notice_outcome.enqueue(_dispatch):
        # Queue full: the link never goes out. Its token expires at once — otherwise
        # it would hold up every new one as an open link (`open_token`) until its expiry,
        # without one ever having been delivered. The next attempt is dampened by memory as
        # after a failed delivery (`quellmail:<id>`, the window of the mail throttle).
        send.discard()


def _saml_identifier(self, nameid, attrs) -> str:
    """The stable identifier of a SAML identity: the `NameID` — or the attribute `saml_attr_id` when the identity
    provider sends transient NameIDs (F-11). The sign-in (`_check_saml`) and the link by the person (T-99) read it here."""
    from .saml_ import first
    return str((first(attrs, self.cfg.saml_attr_id) if self.cfg.saml_attr_id else nameid) or "")

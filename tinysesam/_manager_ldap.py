"""The building block `ldap` of `TinySesam`: the LDAP / lldap password backend.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from . import security
from .errors import ConfigError
from .store import name_invalid
from .store import norm_identifier
from typing import Any
from typing import Optional
from . import manager as _manager
from .manager import (
    _proof_true,
    _substring_notice,
    group_fits,
)


def _resolve_foreign_identity(self, source: str, identifier: str, username: str,
                                 create, name_assign: bool = True,
                                 only_account: Optional[int] = None) -> Optional[dict]:
    """Find, bind or create a local account for a foreign identity (F-11).

    `kennung` is the **stable** identifier from the directory (objectGUID/entryUUID for LDAP,
    NameID for SAML), `username` the name by which mapping was done alone up to 0.19.0.
    `create()` creates a new account and returns its ID or `None`.

    Four cases, and the third is the actual bolt:

    1. **The identifier is bound** → this account, even if the name has changed.
       That is exactly what the binding is for: a rename in the directory is not an account change.
    2. **Identifier unknown, name free** → create and bind.
    3. **Identifier unknown, name belongs to an account that already carries ANOTHER identifier**
       → **reject**. That is the attack: a new account arises in the directory under the name of a
       deleted person, and without this bolt it would inherit that person's local roles.
    4. **Identifier unknown, name belongs to a still unbound account** → bind afterwards. This is
       the existing-data case: accounts from before F-11 have no identifier, and at some point
       each of them has to get one. The PO explicitly approved this path for this round;
       it relies on the name once more, but only a
       single time per account, and it leaves an audit line. Since 2026-09-26 only
       through one door (`_rebinding_reason`): not after the deadline
       (`federation_name_binding_days`, G1 — otherwise a dormant account would fall to the next
       person with that name) and never for a self-chosen name
       (`users.name_self_chosen`, G2-N — otherwise a local account renames itself after
       someone from the directory and inherits their groups) and never for a name that
       another source brought along on creation (`users.name_source`, attack round
       2026-09-26 — the same attack via `preferred_username` or SAML), unless the
       operator has opened the binding for this account (`federation_unbind`). Otherwise
       it is rejected as in case 3. The same applies to the replacement of an origin placeholder.

    Without an identifier (the directory delivers none) it stays with the name — the unprotected
    state. A line per source says so, and `federation_require_stable_id=True` turns
    that into a rejection. The FIRST mapping of an existing account goes through
    the same door as case 4; an account the source already knows (placeholder) stays.

    `name_assign=False`: the name says nothing about the person — an unverified
    address from a source the operator does not trust (`*_email_trusted=False`). Then
    there is neither case 4 (binding afterwards via the name) nor a mapping without an identifier: whoever
    registers the address of a local account as a name at the IdP would otherwise take over exactly
    that account (attack on the third round). Without an identifier it is rejected, with an identifier
    bound or newly created — never via the name.

    `only_account`: the resolution may only end at THIS account (`_check_ldap`: the account whose
    local secret is checked under the same identifier). If it leads to another one — a
    binding, a name, a creation —, it is rejected before anything is written
    (`_identifier_two_accounts`). None: no restriction.
    """
    now = _manager._now()
    raw = str(identifier or "")
    identifier = raw.strip()
    form_error = self._identifier_form_error(raw)
    if form_error:
        security.seclog.warning("%s: identifier %s rejected (user=%s)", source,
                                "with edge or control characters"
                                if form_error == "edge_or_control_characters"
                                else "in placeholder form", security.for_log(username))
        self.audit(f"{source}_identifier_invalid", username, detail=form_error)
        return None
    if not identifier and not name_assign:
        security.seclog.warning(
            "%s: the name is an unverified address and there is no stable identifier (user=%s) — "
            "rejected. A mapping via this name would be a takeover. Remedy: "
            "set %s_attr_id or trust the source (%s_email_trusted).",
            source, security.for_log(username), source, source)
        self.audit(f"{source}_without_identifier", username, detail="rejected: address as name")
        return None
    if not identifier:
        if self.cfg.federation_require_stable_id:
            security.seclog.warning(
                "%s: no stable identifier in the response (user=%s) — rejected because "
                "federation_require_stable_id=True. The attribute is named in %s_attr_id.",
                source, security.for_log(username), source)
            self.audit(f"{source}_without_identifier", username, detail="rejected")
            return None
        if security.report_once(f"fed_without_identifier:{source}"):
            security.seclog.warning(
                "%s delivers no stable identifier — the mapping hangs on the username, "
                "as before 0.20.0. Whoever renames in the directory or recreates a deleted account "
                "under the same name gets the same local account. "
                "Remedy: set %s_attr_id (entryUUID, objectGUID) and then "
                "federation_require_stable_id=True.", source, source)
        bound_uid = None
    else:
        bound_uid = self.store.get_federated_user(source, identifier)

    if bound_uid:
        if only_account is not None and int(bound_uid) != int(only_account):
            self._identifier_two_accounts(source, username, only_account, bound_uid)
            return None
        u = self.store.get_user(bound_uid)
        return self._as_dict(u) if u else None

    u = self.store.get_user_by_name(username) if name_assign else None
    if only_account is not None and (u is None or int(u["id"]) != int(only_account)):
        self._identifier_two_accounts(source, username, only_account, u["id"] if u else None)
        return None
    if u is None:
        uid = create()
        if uid is None:
            return None
        self.store.link_federated(source, identifier or f"{self._WITHOUT_IDENTIFIER}{uid}", uid, now)
        new = self.store.get_user(uid)
        return self._as_dict(new) if new else None

    existing = self.store.get_federated_identifier(source, u["id"])
    # Only the origin placeholder, no identifier: treated as unbound (case 4). It is resolved
    # only when the door is open — a rejection leaves the account as it was.
    placeholder = bool(existing) and str(existing).startswith(self._WITHOUT_IDENTIFIER)
    if not identifier:
        if not existing:
            # First mapping of an existing account, via the name alone: the same door
            # as case 4 (G1, G2-N). Then record the origin (A-4) — see _WITHOUT_IDENTIFIER.
            if not self._name_binding_permitted(source, "", u, username):
                return None
            self.store.link_federated(source, f"{self._WITHOUT_IDENTIFIER}{u['id']}", u["id"], now)
            self.store.name_binding_close(source, u["id"])
    else:
        if existing and not placeholder and existing != identifier:
            # Case 3: The account belongs to someone else, even if the name is the same.
            security.seclog.warning(
                "%s: account %s is already bound to a different identifier — signing in with "
                "a new identifier under the same name is rejected. The directory "
                "was probably renamed or an account recreated. The operator releases "
                "the binding if that is intended.", source, security.for_log(username))
            self.audit(f"{source}_identifier_change", str(u["username"]),
                       detail="rejected: account already carries a different identifier")
            return None
        if not existing or placeholder:
            # Case 4: binding afterwards — a single time per account, only through the door, and it
            # is logged.
            if not self._name_binding_permitted(source, identifier, u, username):
                return None
            if placeholder:
                self.store.unlink_federated(source, u["id"])
            self.store.link_federated(source, identifier, u["id"], now)
            self.store.name_binding_close(source, u["id"])
            self.audit(f"{source}_identifier_bound", str(u["username"]),
                       detail="bound later at sign-in")
    return self._as_dict(self.store.get_user(u["id"]))


def _identifier_two_accounts(self, source: str, username: str, local_id, destination_id) -> None:
    """Reject the sign-in via `quelle`: the typed-in identifier locally belongs to account
    `local_id`, but the directory entry to another one (`destination_id`, None = it would be newly
    created). Log line with remedy, audit `<quelle>_identifier_rejected reason=identifier_of_two_accounts`.
    The caller then returns None, the route books a failed attempt (review round
    2026-09-27, p1-d)."""
    security.seclog.warning(
        "%s: sign-in under %s rejected — the identifier is the name or address of account %s, but "
        "the directory entry belongs to %s. Under one identifier TinySesam never checks the "
        "secrets of two people: the sign-in of one would otherwise clear the lockout counters under "
        "which the other is being guessed. Remedy: rename the local account (panel or "
        "`tinysesam rename`) or change the name in the directory.",
        source.upper(), security.for_log(username), local_id,
        f"account {destination_id}" if destination_id is not None else "no account (it would be newly created)")
    self.audit(f"{source}_identifier_rejected", username,
               detail=f"reason=identifier_of_two_accounts local={local_id} "
                      f"directory={destination_id if destination_id is not None else 'new'}")


def _rebinding_reason(self, source: str, identifier: str, account, *, name_proven: bool = True,
                       deadline: bool = True) -> Optional[str]:
    """May the account `account` be bound to the foreign identifier `kennung` via its name?
    `None` = yes, otherwise the reason (key from `NAME_BINDING_REFUSALS`; the same code in audit
    and security log, text in `_REBINDING_LOG`).

    ONE decision for the sign-in (case 4, replacement of a placeholder, first mapping without an
    identifier — `kennung=""`) and for the existing-data binding (`federation_bind_existing`). Copied,
    the two drifted apart, and one path would bind what the other rejects (G1).

    * `name_proven=False`: the name is the unverified `mail` value of a source that is not
      trusted (`_ldap_name_proven`) — it says nothing about the person.
    * Identifier: form (`_identifier_form_error`), not already bound to another account, the
      account does not already carry another one (case 3).
    * **Self-chosen name** (G2-N): an account that registered or was renamed itself
      (`users.name_self_chosen`) is never bound via the name. Reproduced:
      `eve` renames herself to `manager`, a name that exists only in the directory; the
      real boss signs in via LDAP, her identifier lands on eve's account, the role from
      `ldap_group_role_map` too — and eve keeps signing in with her password.
    * **Name from another source** (`users.name_source`, attack round 2026-09-26): an
      account that OIDC, SAML or LDAP created carries the name the person has THERE —
      at an IdP with self-registration a self-chosen one. Reproduced: `manager` via
      OIDC, then the real boss via LDAP; her identifier and her roles ended up in the
      OIDC account, and the attacker kept signing in via OIDC. The same source is
      exempt: it replaces its own placeholder with the real identifier.
    * **Deadline** (`frist=True`, G1): `federation_name_binding_days` from the source's marker or
      the creation of the account, whichever is later (`_name_deadline_unclosed`). The existing-data binding does not check
      it — it IS the operator's explicit path.

    * **Released by the person** (T-99, `unlinked_by_holder`): the holder unlinked this source's identity on the
      account page — a later sign-in under the same name must not bind it back silently.

    The last four are lifted by a binding opened by the operator (`federation_unbind`,
    table `name_binding`)."""
    if not name_proven or name_invalid(str(account["username"] or "")):
        return "address_as_name"
    if identifier:
        if self._identifier_form_error(identifier):
            return "invalid_identifier"
        other = self.store.get_federated_user(source, identifier)
        if other is not None and int(other) != int(account["id"]):
            return "conflict"
        existing = self.store.get_federated_identifier(source, account["id"])
        if existing and not existing.startswith(self._WITHOUT_IDENTIFIER) and existing != identifier:
            return "bound_elsewhere"
    now = _manager._now()
    if self.store.name_binding_unclosed(source, account["id"], now):
        return None
    if self.store.name_binding_closed(source, account["id"]):
        return "unlinked_by_holder"      # T-99: the person released the identity — never again by the name alone
    try:
        itself = bool(account["name_self_chosen"])
    except (IndexError, KeyError):
        itself = False       # row without the column (foreign source): like existing data
    if itself:
        return "self_chosen_name"
    try:
        origin = str(account["name_source"] or "")
    except (IndexError, KeyError):
        origin = ""        # row without the column (foreign source): like existing data
    if origin and origin != source:
        return "name_from_other_source"
    if deadline and not self._name_deadline_unclosed(source, account, now):
        return "binding_window_expired"
    return None


def _name_binding_permitted(self, source: str, identifier: str, account, username: str) -> bool:
    """The door for case 4 at sign-in: `_rebinding_reason`, and a rejection as in
    case 3 — log line with identifier and remedy, audit `<quelle>_name_binding_closed`."""
    reason = self._rebinding_reason(source, identifier, account)
    if reason is None:
        return True
    text = self._REBINDING_LOG.get(reason, reason)
    days = int(self.cfg.federation_name_binding_days)
    security.seclog.warning(
        "%s: account %s (user_id=%s) is not bound by name to the identifier %s — %s. "
        "The sign-in is rejected. If it is the same person: "
        "auth.federation_unbind('%s', %s) opens the binding for the next sign-in "
        "(%d day(s)); existing accounts are bound by auth.federation_bind_existing('%s').",
        source, security.for_log(username), account["id"],
        security.for_log(identifier) if identifier else "(none)",
        text, source, account["id"], max(days, 1), source)
    self.audit(f"{source}_name_binding_closed", str(account["username"]),
               detail=f"reason={reason} identifier={identifier or '-'}")
    return False


def _federation_since(self, source: str) -> int:
    """From when does the deadline for binding via the name apply (G1)? The source's marker
    (`Store.federation_since`), set at the first start with the source switched on — or
    here, if it is used without the switch (a client set by hand). Exactly once:
    a marker that were set anew at every start would grant every restart a new
    deadline. Only readable: then from now on."""
    try:
        return self.store.federation_since(source, _manager._now())
    except (sqlite3.OperationalError, ValueError):
        return _manager._now()


def _name_deadline_unclosed(self, source: str, account, now: int) -> bool:
    """Does the name still bind this account (G1)? `federation_name_binding_days` days from the
    source's marker or the creation of the account, whichever is later — a pre-creation in the panel
    thus has its own deadline. `-1` = always, `0` = never."""
    days = int(self.cfg.federation_name_binding_days)
    if days < 0:
        return True
    start_from = max(int(account["created_at"] or 0), self._federation_since(source))
    return now < start_from + days * 86400


def _report_name_binding_inventory(self, source: str, since: int) -> None:
    """Startup message (G1): how many accounts still carry no identifier for this source, and until
    when does the name bind them? Only as long as the door is open for existing data — afterwards
    each rejection reports itself, and a local admin would otherwise stay in the log forever."""
    days = int(self.cfg.federation_name_binding_days)
    if days <= 0:
        return            # 0: explicit only; -1: the configuration check warns
    until = since + days * 86400
    if _manager._now() >= until:
        return
    try:
        accounts = self.store.without_binding(source)
    except sqlite3.OperationalError:
        return
    if not accounts:
        return
    without_pw = sum(1 for k in accounts if not k["has_password"])
    away = (f"auth.federation_bind_existing('{source}')" if source == "ldap"
           else f"auth.federation_bind_existing('{source}', mapping={{name: identifier}})")
    security.seclog.warning(
        "%s: %d account(s) without a binding to an identifier of the source (of which %d without a local "
        "password). Until %s (federation_name_binding_days=%d) the next sign-in binds "
        "them via the name, afterwards no longer — a dormant account would otherwise fall to the next "
        "person with the same name. Bind now: %s (dry run), then with apply=True.",
        source.upper(), len(accounts), without_pw,
        time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(until)), days, away)


def federation_unbind(self, source: str, user_id: int) -> int:
    """Release an account's binding to a foreign identity (operator path) — and open the
    binding via the name for the next sign-in. Returns the number of released
    bindings (0: the account was not bound).

    Needed when the directory was really moved — then the old identifier is dead
    and the account is supposed to get the new one. That this is a deliberate step and not a
    side effect of a sign-in is the point.

    Since 2026-09-26 (G1, G2-N) the call at the same time opens the door for case 4: the next
    sign-in via this source binds the account via its name, even after the deadline
    (`federation_name_binding_days`), even with a self-chosen name and even with a name
    from another source (`users.name_source`) — for
    `max(federation_name_binding_days, 1)` days or until the binding is in place. On an
    unbound account the call thus means "open for the next sign-in" (pre-creation,
    returnee, an account that missed the deadline). The rejection in the log names the call."""
    away = self.store.unlink_federated(source, user_id)
    u = self.store.get_user(user_id)
    until = None
    if u is not None:
        until = _manager._now() + max(int(self.cfg.federation_name_binding_days), 1) * 86400
        self.store.open_name_binding(source, user_id, until)
    self.audit(f"{source}_identifier_unbound", str(u["username"]) if u else None,
               detail=f"name_binding_open_until={until}" if until else None)
    return away


def federation_bind_existing(self, source: str, *, mapping: Optional[dict] = None,
                             apply: bool = False) -> dict:
    """Bind existing accounts to their identifier in LDAP/SAML without waiting for their sign-in (G1).

    Accounts from before identifiers (F-11) bind at the next sign-in via
    their name — but only within the deadline (`federation_name_binding_days`). A dormant
    account never signs in; that is exactly what would otherwise fall to the next person with the name. This
    method binds the existing accounts explicitly. **The default is a dry run**: only with
    `apply=True` is anything written.

    * **LDAP without `mapping`**: one directory search per account without an identifier
      (`LDAPClient.entry_search`, service account or anonymous, without the user's password). It
      must be exactly ONE entry. A failure (`DirectoryNotReachable`) aborts —
      before the first write: everything is searched first, then bound.
    * **`mapping={account name: identifier}`** — for SAML (there is no search path without sign-in;
      the NameIDs e.g. from an export of the IdP) or for individual LDAP accounts. Runs without a
      directory.

    Each account is decided with the same helper as at sign-in
    (`_rebinding_reason`, without the deadline). Accounts with a local password are only reported
    (`local_password`): their name may belong to a different person than the entry in the
    directory — the operator opens them individually with `federation_unbind`.

    Returns (lists of entries with `user_id`, `username`, `local` = display name/address
    here, `directory` = the same in the directory, `identifier`, for rejections `reason`):

    * `bound` — bound (in the dry run: would be bound). **Read before `apply`**: if a
      name was already reused before the run, this method too binds the wrong person —
      `local` and `directory` side by side show it.
    * `conflict` — the identifier already belongs to another account (`bound_to`), or two
      accounts name the same one
    * `ambiguous` — more than one entry in the directory (`matches`: how many)
    * `not_in_directory`, `no_identifier` — no entry, or one without a stable identifier
      (`ldap_attr_id`)
    * `refused` — with `reason`: one from `NAME_BINDING_REFUSALS` or `no_account`,
      `service_account`, `disabled`, `already_bound`
    * `local_password` — account with a local password, only reported

    Plus `source` and `applied`. Up to 0.21.x the keys and reasons were German
    (`quelle`, `ausgefuehrt`, `bound`, `rejected`/`reason` …; PO decision 2026-09-27,
    table in the CHANGELOG for 0.22.0). Each binding writes `<source>_identifier_bound` with
    `detail=migration`, the run a summary line into the security log — both as before.
    There is no CLI command: LDAP and SAML run only embedded, and the CLI does not know the
    configuration."""
    if source not in self.FEDERATED_SOURCES:
        raise ValueError(f"source must be one of {self.FEDERATED_SOURCES}, not {source!r}")
    search = None
    if mapping is None:
        if source != "ldap":
            raise ValueError(
                "SAML has no lookup path without a sign-in — the identifiers come as "
                "mapping={account name: NameID} (e.g. from an export of the IdP).")
        if not self.ldap:
            raise ConfigError("LDAP is not set up (ldap_enabled, ldap_url) — or pass "
                              "mapping={account name: identifier}.")
        search = getattr(self.ldap, "entry_search", None)
        if not callable(search):
            raise ConfigError("The LDAP client in use cannot search (entry_search) — "
                              "pass mapping={account name: identifier}.")
    report: dict = {"source": source, "applied": bool(apply), "bound": [],
                     "conflict": [], "ambiguous": [], "not_in_directory": [],
                     "no_identifier": [], "refused": [], "local_password": []}
    # Account → identifier from the mapping (None: search in the directory).
    pairs: list[tuple[Any, Optional[str]]] = []
    if mapping is None:
        pairs = [(k, None) for k in self.store.without_binding(source)]
    else:
        for name, value in mapping.items():
            k = self.store.get_user_by_name(str(name or "").strip())
            if k is None:
                report["refused"].append({"user_id": None, "username": str(name),
                                           "reason": "no_account"})
            else:
                pairs.append((k, str(value or "")))
    plan = []
    for account, default in pairs:
        e: dict = {"user_id": int(account["id"]), "username": account["username"],
                   "local": {"name": account["display_name"], "email": account["email"]}}
        if account["is_service"] or account["disabled"]:
            report["refused"].append(dict(e, reason="service_account" if account["is_service"]
                                           else "disabled"))
            continue
        existing = self.store.get_federated_identifier(source, account["id"])
        if existing and not existing.startswith(self._WITHOUT_IDENTIFIER):
            report["refused"].append(dict(e, identifier=existing, reason=(
                "already_bound" if default is None or existing == default else "bound_elsewhere")))
            continue
        name_proven = True
        identifier = default or ""
        if search is not None:
            hit = search(account["username"])     # DirectoryNotReachable aborts
            if not hit:
                report["not_in_directory"].append(e)
                continue
            if len(hit) > 1:
                report["ambiguous"].append(dict(e, matches=len(hit)))
                continue
            info = hit[0]
            e["directory"] = {"name": info.get("name"), "email": info.get("email")}
            identifier = str(info.get("id") or "")
            name_proven = self._ldap_name_proven(account["username"], info)
        if not identifier:
            # No identifier, also an empty one in the mapping: binding would be via the name.
            report["no_identifier"].append(e)
            continue
        e["identifier"] = identifier
        reason = self._rebinding_reason(source, identifier, account, name_proven=name_proven,
                                        deadline=False)
        if reason == "conflict":
            report["conflict"].append(dict(e, bound_to=self.store.get_federated_user(source, identifier)))
        elif reason:
            report["refused"].append(dict(e, reason=reason))
        elif self.store.get_password_hash(account["id"]):
            report["local_password"].append(e)
        else:
            plan.append(e)
    # Two accounts, one identifier (mapping with a duplicate): neither.
    from collections import Counter
    double = {k for k, n in Counter(e["identifier"] for e in plan).items() if n > 1}
    report["conflict"] += [e for e in plan if e["identifier"] in double]
    plan = [e for e in plan if e["identifier"] not in double]
    if not apply:
        report["bound"] = plan
        return report
    for e in plan:
        # Atomic against a sign-in that has bound since the check (`Store.rebind`).
        if self.store.rebind(source, e["identifier"], e["user_id"], _manager._now()):
            self.audit(f"{source}_identifier_bound", str(e["username"]), detail="migration")
            report["bound"].append(e)
        else:
            report["conflict"].append(dict(e, bound_to=self.store.get_federated_user(source, e["identifier"])))
    security.seclog.warning(
        "federation_bind_existing(%s): %d bound, %d conflict, %d ambiguous, %d not in the "
        "directory, %d without identifier, %d refused, %d with local password (reported only).",
        source, len(report["bound"]), len(report["conflict"]), len(report["ambiguous"]),
        len(report["not_in_directory"]), len(report["no_identifier"]),
        len(report["refused"]), len(report["local_password"]))
    return report


def _ldap_trusted(self, info) -> bool:
    """Does the operator trust the address of this entry? Blanket (`ldap_email_trusted`) or
    verified for THIS entry (evidence attribute `ldap_attr_email_verified`)."""
    return bool(self.cfg.ldap_email_trusted) or (
        bool(security.proof_attribute(self.cfg, "ldap")) and _proof_true(info.get("email_verified")))


def _ldap_name_proven(self, username, info) -> bool:
    """Does the name say something about the person in the directory? No for control characters — and if it
    IS the entry's unverified `mail` value (source not trusted). Sign-in and
    existing-data binding ask here; only then may an account be mapped via the name.

    What matters is whether the input IS the unverified value — not whether it looks like an
    address: `mail` is a free attribute (RFC 4524), an attacker also sets it to
    `manager` (counter-check); a UPN with `@`, on the other hand, is the bind identifier and counts as verified."""
    if name_invalid(username):
        return False
    mail_value = norm_identifier(info.get("email") or "")
    return not (not self._ldap_trusted(info) and mail_value
                and norm_identifier(username) == mail_value)


def _check_ldap(self, username, password) -> Optional[dict]:
    """Check the password against LDAP. On success find/create the local user and return it.
    Counts like a password login (factor 'password').

    The adopted address (`info["email"]`) is a directory attribute without evidence — in
    many directories the user maintains it themselves. The operator says whether they trust it
    (`ldap_email_trusted`, default no since the PO decision 2026-09-25; or for this
    entry via `ldap_attr_email_verified`): then it counts as verified and carries rights. If
    they do not trust it, it is not used directly (confirmation link, see
    `_address_proven_by_source`), and a
    typed-in address does not become the account name (substitute name `ldap-…`, no mapping via the
    name). For this case — and that was the rule until then — **two**
    consequences applied and apply, both necessary:

    * A newly created account gets the address with `email_verified=False` — the marker
      on the account does not claim what nobody has verified.
    * Whoever integrates this path themselves passes `email_verified=False` on to `apply_factor`
      (the bundled login route does so). The path cannot be recognised by the factor name —
      `password` is not in `_FEDERATED_FACTORS`, because a local
      password arrives there too.

    The second alone protected only THIS login: the attacker set up a PIN or a passkey in the
    freshly signed-in session, signed in again with it
    — that factor travels without evidence —, and the marker on the account promotes them after all
    (B-bypass-1 from T-13). Otherwise an allowlist address could determine the first admin via LDAP
    (F-14).

    **One identifier, one account** (review round 2026-09-27, p1-d): the login route asks LDAP only
    after the local password of the account for the identifier (`find_user`) did not match. If
    the directory entry leads to ANOTHER account (bound, via the name or newly
    created), it is rejected before anything is written (`_identifier_two_accounts`) — the
    route books a failed attempt. Otherwise one identifier would check the secrets of two
    people, and the sign-in of one would clear the counters under which the other
    is being guessed (local `alice.neu` next to the directory name `alice.neu` of another person,
    or a registration with the directory address with a filter over `mail`). That also affects
    the sign-in of a directory third party under the address of a local account (until
    then secured only for the counters, G5-N1)."""
    if not self.ldap:
        return None
    info = self._ldap_bind(username, password)
    if not info:
        return None
    # Not trusted and the input is an address (a search filter over `mail`, "sign-in with
    # name or email"): then the name is the same unverified address — as account name and
    # `Remote-User` it would occupy the owner's identifier, and bound via the name
    # it would take over her account (attack on the third round). As with SAML: substitute name,
    # no mapping via the name.
    identifier_ldap = info.get("id") or ""
    source_trusted = self._ldap_trusted(info)
    ldap_name = username
    name_assign = True
    if not self._ldap_name_proven(username, info):
        ldap_name = "ldap-" + hashlib.sha256((identifier_ldap or username).encode()).hexdigest()[:8]
        name_assign = False

    def _create():
        if not self.cfg.ldap_auto_create:
            return None
        try:
            # Address AND evidence go into the account together: the `mail` attribute proves
            # nothing, so the marker on the account must not claim it either. If the default
            # `True` stood here, the bolt above would be shut only for THIS login — the
            # next factor the attacker sets up themselves (PIN, passkey)
            # arrives without evidence, reads the marker and promotes after all (B-bypass-1 from T-13).
            # The operator says whether they trust the directory (`ldap_email_trusted`, default
            # no, or the evidence attribute): then with evidence, otherwise not at all (H-3).
            trusted = source_trusted
            name = ldap_name
            if name == username:
                # The directory has just signed in this very entry under that name; if it still stands
                # on another account's binding, it is outdated there (p1-a) — and would
                # otherwise hold up the creation as "taken".
                self.store.release_directory_name(name)
            i = 1
            while name != username and self.identifier_taken(name):
                i += 1
                name = f"{ldap_name}{i}"
            return self._create_account(name, display_name=info.get("name") or name,
                                       email=info.get("email") if trusted else None,
                                       email_verified=trusted and bool(info.get("email")),
                                       name_source="ldap")
        except ConfigError:
            # Name or address already belong to someone locally (finding R4-12). Fail-closed:
            # better no sign-in than an account that occupies a foreign identifier.
            self.audit("ldap_ident_taken", username)
            return None

    # Mapping is done via the directory's STABLE identifier, not via the name
    # (F-11). The name remains the fallback for accounts that have no binding yet. If the
    # identifier locally belongs to an account, the resolution may end only there (p1-d, see above).
    local = self.find_user(username)
    u = self._resolve_foreign_identity("ldap", identifier_ldap, username, _create,
                                          name_assign=name_assign,
                                          only_account=int(local["id"]) if local else None)
    if not u or u["disabled"]:
        return None
    # Note the typed-in name on the binding if it is neither name nor address of the
    # account (G5): after a rename in the directory (local `alice`, there `alice.neu`)
    # the series (B2-6) counts under `alice.neu`, and without the note no way back would clear it —
    # neither the full sign-in nor the panel reset nor `tinysesam unlock`. Who else
    # it may belong to is checked by the reader (`Store.count_identifiers`), not by this writer.
    if not name_invalid(username):
        self.store.set_binding_name("ldap", u["id"], username)
    self._address_proven_by_source(u, info.get("email"), source_trusted, "ldap")
    # memberOf delivers whole DNs → comparison by components (F-19). Up to 0.20.0
    # `substring=True` was hard-wired here, and `group_match` had no effect for LDAP.
    self.apply_idp_groups(u["id"], info.get("groups"), self.cfg.ldap_group_role_map, dn=True)
    return self._as_dict(self.store.get_user(u["id"]))   # fresh (mapped roles)


def _ldap_bind(self, username, password) -> Optional[dict]:
    """The directory's answer to name and password — the entry (`id`, `name`, `email`, `groups`, …) or None (wrong,
    too long, or refused by `ldap_allowed_groups`). The one place that binds: the sign-in (`_check_ldap`) and the link
    by the person (`_link_directory`, T-99) share the outage marker and the group gate. Raises
    `ldap_.DirectoryNotReachable` on an outage (the caller takes the attempt back, F-23)."""
    if not self.ldap:
        return None
    from .ldap_ import RequestAborted, DirectoryNotReachable, input_too_long
    # Longer than any real sign-in: not to the directory, but treated like a wrong
    # password (failed attempt, `failed login`). Here and not only in the client, so that it also applies to
    # a client set by hand — and before the marker hands out a probe slot.
    # Before, the login route sent every length through: a password with 270,000 characters
    # made slapd close the connection (see `ldap_.RequestAborted`).
    if input_too_long(username, password):
        return None
    # After an outage the directory is not even asked for a while: the route
    # has already pre-booked the attempt (R7-2) and takes it back only once the outage
    # is reported — without the marker it would hang on every attempt until the timeout and
    # meanwhile lock out bystanders (rationale at `ldap_.FailureMarker`).
    marker = self._ldap_failure
    probe = marker.access()
    try:
        info = self.ldap.authenticate(username, password)
    except RequestAborted:
        # Only THIS request failed, quickly and after sending its inputs —
        # no evidence of an outage. Arming the marker would give the sender of
        # any crafted sign-in a switch that turns LDAP off for everyone. If it was the
        # probe, the next sign-in asks again.
        if probe:
            marker.release()
        raise
    except DirectoryNotReachable as e:
        marker.failed(e, was_probe=probe)
        raise
    except BaseException:
        if probe:
            marker.release()
        raise
    marker.reached()
    if not info:
        return None
    # Group gate against memberOf — by DN components, not as a substring (F-19):
    # `staff` would otherwise also let `cn=staffextern,…` through. `group_match="substring"` brings
    # back the old comparison explicitly.
    allowed = self.cfg.ldap_allowed_groups
    substring = self.cfg.group_match == "substring"
    if allowed:
        groups = info.get("groups") or []
        if not substring:
            for a in allowed:
                _substring_notice(a, groups, "ldap_allowed_groups")
        if not any(group_fits(a, g, substring, dn=True) for a in allowed for g in groups):
            self.audit("ldap_group_denied", username,
                       detail=f"required={sorted(str(a) for a in allowed)}")
            return None
    return info

"""The building block `users` of `TinySesam`: accounts and their administration: owner, users, the role catalog, the first admin, demo mode, start secrets.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from . import _chain
from . import config_check
from . import security
from .errors import ConfigError
from .errors import StateError
from .password_change_result import PasswordChangeResult
from .passwords import hash_password
from .passwords import verify_password
from .store import name_invalid
from .store import norm_email
from .store import norm_identifier
from .store import role_invalid
from fastapi import Request
from typing import Optional
from . import manager as _manager
from .manager import (
    _REQUEST,
    _on_stderr,
    _proof_on_account,
    _stderr_is_console,
    _substring_notice,
    group_fits,
)


# ---------- Owner ----------
def _first_owner(self, user_id) -> None:
    """The first admin of an instance also becomes its first owner (bootstrap paths)."""
    if self.store.owner_count() == 0:
        self.store.set_owner(user_id, True)
        u = self.store.get_user(user_id)
        self.store.audit_log("owner_grant", u["username"] if u else None, None, "source=first_admin")


def set_owner(self, user_id: int, owner: bool) -> bool:
    """Grant (`owner=True`) or give up (`False`) the owner role. False = no such account.

    Owners are admins that cannot be deleted, locked or stripped of power; there is always
    at least one, and only owners grant the role (the calling route checks that). Giving up the
    role works only if ANOTHER owner remains (`StateError`). Service accounts and
    locked accounts do not become owner (`ConfigError`) — an owner must be able to sign in."""
    u = self.store.get_user(user_id)
    if not u:
        return False
    if owner:
        if u["is_service"] or u["disabled"]:
            raise ConfigError("Only an active, interactive account can become owner.")
        if not u["is_owner"]:
            self.store.set_owner(user_id, True)
            self.audit("owner_grant", u["username"])
        return True
    if u["is_owner"]:
        if self.store.owner_count(without=user_id) == 0:
            raise StateError(f"Account {user_id} is the last owner. Appoint another owner "
                             "first, then hand over the role.")
        self.store.set_owner(user_id, False)
        self.audit("owner_revoke", u["username"])
    return True


# ---------- User management ----------
def identifier_taken(self, identifier, exclude_id=None) -> Optional[dict]:
    """Does this login identifier already belong to an account — in EITHER of the two namespaces?

    Username and email are not separate spaces: with `login_identifier="both"` (default)
    `find_user` searches **both** columns, and for an identifier with `@` the email
    wins. Whoever checks separately allows a stranger to register the email of an
    existing account as a *username* (or vice versa) — from then on the identifier resolves
    to the foreign account and the rightful owner is locked out (finding R4-12).

    The check is **always** crosswise, also in the modes "username" and "email": the mode is
    a switch an operator flips later; a collision that sleeps today would then be
    live at once. The return value is the account the identifier belongs to, otherwise None. `exclude_id`
    leaves one account out — for checks on an existing account.

    And via the **counting bucket** of the lockout counter (`Store.account_by_bucket`): `Émile` and
    `émile` are two names for SQLite NOCASE (ASCII only), one for `norm_identifier`. Two
    such accounts shared the account threshold against distributed guessing — and if one was
    removed (also triggerable anonymously: a registration that `gc()` sweeps away), the
    failed attempts of the other went with it. Such a namesake is therefore considered taken.

    **And via the name in the directory** (`federated_identity.directory_name_folded`, G5; review round
    2026-09-27): under one identifier the login route checks the local password of the account AND
    the LDAP password of the entry. If a local account was named like another person in the
    directory (self-service, registration, renaming in the panel), each of its
    sign-ins cleared the counters under which that person's LDAP password was being guessed —
    the lockouts stopped working. A name that stands on the binding of ANOTHER account is
    therefore considered taken (the identifier that stands there in the directory after renaming, and
    the old name of a renamed LDAP account, see `Store._remember_directory_name`).

    **A pre-check, the database decides** (since 2026-09-26): between this
    answer and the write a concurrent request can claim the identifier. The
    write then rejects it (trigger over the counting buckets, `Store._trigger_sql`), and the
    callers turn that into the same answer as here ("taken").
    """
    identifier = (identifier or "").strip()
    if not identifier:
        return None
    for hit in (self.store.get_user_by_name(identifier), self.store.get_user_by_email(identifier),
                    self.store.account_by_bucket(identifier, other_than=exclude_id),
                    self.store.account_with_directory_name(identifier, other_than=exclude_id)):
        if hit is not None and hit["id"] != exclude_id:
            return self._as_dict(hit)
    return None


def create_user(self, username, password=None, is_admin=False, roles=None,
                display_name=None, email=None, is_service=False,
                email_verified: bool = True, *, self_chosen_name: bool = False) -> int:
    """Create an account and return its ID. `is_service=True` for machines: no
    login, API keys only. An identifier that is already taken raises `ConfigError` — **new
    also for a duplicate username**, which up to 0.18.x came as `sqlite3.IntegrityError` from the
    database (`e.field`/`e.owner_id` say what collided).

    Username and email must be free **crosswise** (`identifier_taken`) — otherwise a new account
    occupies the login identifier of an existing one. The check sits here
    so that it applies to EVERY path: self-registration, admin API, invitation, first admin
    (`ensure_admin`), service accounts (`create_service`) and the automatic creation from
    OIDC/LDAP/SAML. The CLI is deliberately not included: it cannot create accounts; its
    `rename` (G13) does not load the manager and performs the same three lookups itself.

    `email_verified=False` stores the address as **unconfirmed**: kept and
    passed along like any other, but without weight for rights (first admin/allowlist,
    see `_maybe_promote_admin`). That is the case for every sign-in path that does not vouch for
    the address: an IdP without the `email_verified` claim, **and in principle SAML and
    LDAP** — there is no attribute at all that asserts a verification.
    The default `True` applies to the paths where the operator vouches for the address
    (admin API, first admin, service accounts, invitation to this address). Self-
    registration stores the typed-in address with `False`; the evidence is only set by the
    redeemed confirmation link (`/auth/verify`), without a confirmation requirement it stays at
    `False`. Whoever registers on their own and sends `send_verify_email` also passes
    `False` — otherwise the address counts as verified before anyone has redeemed the link.

    A taken identifier raises `ConfigError` with the text "<field> is already
    taken" (since T-29 an English runtime text) and `e.field` set (`"username"`/`"email"`) plus `e.owner_id` —
    that, not the translated text, is how a caller tells the two cases apart.

    ⚠️ **Changed compared to 0.18.x:** only a duplicate *email* raised
    `ConfigError` there. A duplicate *username* went all the way to the database and came back as
    `sqlite3.IntegrityError`; it is now caught beforehand and raises the same
    `ConfigError`. Whoever catches `IntegrityError` no longer catches this case.

    **Also in a race** (since 2026-09-26): if a concurrent request claims the identifier
    between check and creation, the database rejects the INSERT — and that too comes as the
    same `ConfigError`. `e.owner_id` may then be `None`: when the other account
    is already removed again before it is looked up here.

    `self_chosen_name=True`: the person typed the name themselves (registration,
    also with an invitation). A sign-in via LDAP/SAML then never binds this account via the
    name (G2-N, `users.name_self_chosen`). The built-in registration sets it; whoever builds
    their own passes it too. Default `False`: the operator assigns the name. Whoever
    creates accounts from their OWN foreign source (another identity provider) passes it
    too: names chosen there say nothing about who in the directory has that name."""
    return self._create_account(username, password, is_admin, roles, display_name, email,
                               is_service, email_verified, name_itself_chosen=self_chosen_name)


def _create_account(self, username, password=None, is_admin=False, roles=None, display_name=None,
                   email=None, is_service=False, email_verified: bool = True, *,
                   name_itself_chosen: bool = False, name_source: Optional[str] = None,
                   managed_by: Optional[str] = None) -> int:
    """`create_user` including the origin of the name (`users.name_source`, attack round 2026-09-26):
    creation from OIDC, SAML and LDAP. A name that a source brings along never binds the account
    via the name to ANOTHER one (`_rebinding_reason`) — `preferred_username`, NameID and
    `uid` are chosen by oneself at an IdP with self-registration. Reproduced: `manager` signs
    in via OIDC, the real boss afterwards via LDAP, and the OIDC account then carried her
    identifier and her roles. The same source may keep replacing its placeholder with the real
    identifier. Not public: whoever creates on their own uses `self_chosen_name=True` (`create_user`)."""
    username = (username or "").strip()
    email = norm_email(email)
    if name_invalid(username):
        # Central here, because every creation path ends here (registration, panel, CLI, OIDC,
        # SAML, LDAP): a name with control characters becomes a DIFFERENT name in `Remote-User`
        # (see `name_invalid`). The federated paths switch to a substitute
        # name beforehand; whoever lands here gets a rejection.
        error = ConfigError("Username contains control or format characters")
        error.field = "username"
        raise error
    self._refuse_role_names(roles)
    for slot, key_name, identifier in (("username", "username", username),
                                      ("email address", "email", email)):
        owner = self.identifier_taken(identifier) if identifier else None
        if owner:
            security.seclog.warning(
                "Account not created: %s is already the login identifier of user_id=%s", slot, owner["id"])
            # The wording is that of 0.18.x ("… is already taken", then German). Because a
            # `ConfigError` alone does not reveal WHAT collided, callers check the text —
            # the most brittle way to control a program, but a common one. A fix
            # must not pull the ground from under it. It does name the field that REALLY
            # collides, though: the new trigger (username = foreign email and vice versa)
            # carries the username OR the email text depending on direction, not always
            # the same. It can be told apart reliably by `field`/`owner_id`.
            error = ConfigError(f"{slot} is already taken")
            error.field = key_name
            error.owner_id = int(owner["id"])
            raise error
    try:
        uid = self.store.create_user(username, display_name, email, is_admin, roles, is_service,
                                     email_verified=email_verified,
                                     name_itself_chosen=name_itself_chosen,
                                     name_source=name_source, managed_by=managed_by)
    except sqlite3.IntegrityError as error_db:
        # Race (G12c): between the check above and the INSERT a concurrent
        # request claimed the identifier, and the database rejects (identifier trigger, UNIQUE on
        # name or address). Every IntegrityError of this INSERT means "taken". Which
        # identifier, a second check says — if the other account is already gone again, it stays
        # with the username without an owner.
        hit = [(slot, key_name, self.identifier_taken(identifier) if identifier else None)
                   for slot, key_name, identifier in (("username", "username", username),
                                                     ("email address", "email", email))]
        slot, key_name, owner = next((t for t in hit if t[2]), hit[0])
        security.seclog.warning(
            "Account not created (race): %s became the login identifier of user_id=%s "
            "between check and creation", slot, owner["id"] if owner else "?")
        error = ConfigError(f"{slot} is already taken")
        error.field = key_name
        error.owner_id = int(owner["id"]) if owner else None
        raise error from error_db
    if password:
        self.store.set_password_hash(uid, hash_password(password))
    return uid


# Roles (optional). Whoever only needs "signed in or not" uses require_user.
# Other projects differentiate users via is_admin + freely definable roles.
def user_roles(self, user) -> list:
    """The roles of an account as a list."""
    try:
        return json.loads(user["roles"] or "[]")
    except Exception:
        return []


def is_admin(self, user) -> bool:
    """Is this account an admin? Takes an account row, not a request."""
    return bool(user["is_admin"])


def has_role(self, user, role, admin_implies=None) -> bool:
    """Does the user have the role? An admin satisfies EVERY role by default
    (`config.admin_implies_roles`). Whoever attaches rights solely to IdP groups switches that off —
    otherwise every local admin automatically is also "editor", "viewer", … ."""
    if admin_implies is None:
        admin_implies = self.cfg.admin_implies_roles
    if admin_implies and bool(user["is_admin"]):
        return True
    return role in self.user_roles(user)


def _delegation(self) -> dict:
    """`config_check.delegation_graph` of the running `admin_delegates` (T-74) — computed once per configuration
    state and again when it changes at runtime (the fingerprint is the configuration itself, so a `manages`
    taken out acts on the next request)."""
    raw = getattr(self.cfg, "admin_delegates", None) or {}
    if not raw:
        return {}
    try:
        key = json.dumps(raw, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return {}
    cached = getattr(self, "_delegation_cache", None)
    if cached is None or cached[0] != key:
        cached = (key, config_check.delegation_graph(raw))
        self._delegation_cache = cached
    return cached[1]


def _delegate_scopes(self, user) -> Optional[list]:
    """What a delegated admin may do (T-74), one entry per delegate role the account holds — or None if `user`
    is no delegate. The one place that decides it.

    Each entry is `(role, roles, can)`: the roles it manages (`eff`, see `config_check.delegation_graph`) and
    its actions (`config_check.delegate_scopes`, a pure function). An account with several delegate roles may do
    what one of them allows — on that role's accounts, never a mix. Only a full browser session
    (`_via == "session"`) counts: an API key, an OAuth token or an app password never opens the panel, as they
    never carry the admin flag (R6-5). An administrator is no delegate (the admin scope is wider)."""
    graph = self._delegation()
    if not user or not graph:
        return None
    try:
        via, admin = user["_via"], user["is_admin"]
    except (KeyError, IndexError, TypeError):
        return None
    if via != "session" or admin:
        return None
    return config_check.delegate_scopes(graph, self.user_roles(user)) or None


def _admin_panel_visible(self, viewer) -> bool:
    """Does the top bar (`/auth/topbar.json`, `topbar_data`) and the account page offer `viewer` the admin panel?
    Administrators and delegated admins (T-74). Only a convenience: the panel checks access itself on every
    request. Like the admin flag it reads the account row (`topbar_data` takes one from `get_user`); a dict a
    machine credential produced (`_via` other than a session) never shows it."""
    if not viewer:
        return False
    try:
        if viewer["is_admin"]:
            return True
    except (KeyError, IndexError, TypeError):
        return False
    try:
        via = viewer["_via"]
    except (KeyError, IndexError, TypeError):
        via = None
    if via not in (None, "session"):
        return False
    return bool(config_check.delegate_scopes(self._delegation(), self.user_roles(viewer)))


def _strip_delegate_roles(self, d: dict) -> dict:
    """Take the delegate roles out of an account dict that a machine credential produced (T-74, E4) — an
    automation key, an OAuth token, an app password: the same places that set `is_admin = 0` (R6-5)."""
    delegates = getattr(self.cfg, "admin_delegates", None) or {}
    if delegates and isinstance(delegates, dict):
        roles = self.user_roles(d)
        if any(r in delegates for r in roles):
            d["roles"] = json.dumps([r for r in roles if r not in delegates])
    return d


def set_roles(self, user_id, roles):
    """Replace the roles of an account. A role name with a comma, a control character or surrounding spaces
    raises `ConfigError` (`field="roles"`) before anything is written (T-85): `Remote-Groups` would carry it as
    another role or as several."""
    self._refuse_role_names(roles)
    self.store.set_roles(user_id, roles)


# ---------- the role catalog (schema 25) ----------
def known_roles(self) -> list:
    """The roles the admin panel offers an administrator: `available_roles` ∪ the role catalog, sorted. Only a
    list to choose from — it grants nothing, and `set_roles` stores any valid role as before."""
    from . import _role_catalog
    return _role_catalog.known(self.cfg, self.store)


def role_catalog(self) -> list:
    """The roles administrators added (panel, `tinysesam roles`, `create_role`), sorted by name:
    `[{"name", "created_at", "created_by", "in_config"}]` — `in_config` = the configuration names the role too
    (then the configuration owns it, and the catalog row may be deleted)."""
    from . import _role_catalog
    owned = _role_catalog.config_names(self.cfg)
    return [dict(r, in_config=r["name"] in owned) for r in self.store.catalog_roles()]


def role_usage(self, name: str) -> dict:
    """Where a role is held or waits to be: `{"users", "keys", "services", "links", "approvals"}` — accounts,
    API key scopes (not revoked, not expired), OAuth service scopes, open invitations and pairing codes, pending
    approvals of `tinysesam.account.set_roles`. What `delete_role` checks."""
    return self.store.role_usage([name])[name]


def _catalog_actor(self, actor) -> Optional[str]:
    """The name the catalog records for `actor` — None for the operator's own code; `RoleError("forbidden")` for
    an actor that is no administrator (delegated admins do not change the catalog)."""
    from .errors import RoleError
    if actor is None:
        return None
    try:
        admin, name = actor["is_admin"], actor["username"]
    except (KeyError, IndexError, TypeError):
        admin, name = False, None         # not an account row: no administrator either
    if not admin:
        raise RoleError("forbidden", "Only an administrator changes the role catalog")
    return str(name)


def create_role(self, name: str, actor=None) -> dict:
    """Add a role to the catalog, so the admin panel offers it without a change of the configuration. A
    convenience: it grants nothing (the role still has to be given to accounts). `actor` (an account row or
    dict) must be an administrator; None is your own code. Refused with `RoleError` (`e.code`): `invalid` (a
    comma, a control or format character, surrounding spaces, empty, more than 64 characters, an ambiguous role
    level entry), `in_config` (the configuration names it, or `admin`), `exists` (also as another case),
    `full`, `forbidden`. Audit `role_created`. Returns `{"name"}`."""
    from . import _role_catalog
    by = self._catalog_actor(actor)
    result = _role_catalog.create(self.cfg, self.store, name, by)
    self.audit("role_created", by, None, f"name={_role_catalog.detail(name)} via=code")
    return result


def delete_role(self, name: str, actor=None) -> dict:
    """Remove an unused role from the catalog. Refused with `RoleError` (`e.code`) while it is held or waiting
    anywhere (`in_use`, `e.usage` as in `role_usage`), when it is one level of a role level entry whose other
    roles are still known (`in_ladder`), `not_found`, `forbidden`. Check and delete run in one transaction; nothing
    cascades — remove the role from accounts and keys first. Audit `role_deleted`. Returns `{"name",
    "in_config"}` (`in_config`: the configuration names it, so it stays known)."""
    from . import _role_catalog
    by = self._catalog_actor(actor)
    result = _role_catalog.delete(self.cfg, self.store, name)
    self.audit("role_deleted", by, None, f"name={_role_catalog.detail(name)} via=code")
    return result


def apply_idp_groups(self, user_id, groups, mapping: dict, substring: Optional[bool] = None,
                     dn: bool = False):
    """IdP groups → local roles (at login). Mapped roles are synchronised (removed when
    the group goes away), manually granted roles remain. Target '__admin__' sets the
    admin flag and takes it back again if it came from the provider (H-5).

    Target '__admin__' sets the admin flag — and, since H-5, also takes it back when the provider
    no longer delivers the group, but **only a flag it granted itself**
    (`is_admin=2`, `Store.set_admin_from_idp`). Until then it was "grant only": whoever was thrown
    out of the admin group at the provider stayed admin here until someone noticed it in the panel. An admin
    from the panel, the CLI, `admin_identifiers` or `/auth/claim-admin` remains untouched — otherwise
    a misconfigured provider would strip the operator of their own access. A flag
    from before H-5 does not carry the marker and therefore likewise stays in place.
    If the provider thus takes the **last** admin, `admin_identifiers` promotes
    nobody afterwards (G6); the one-time token for `/auth/claim-admin` goes to the
    operator immediately (stderr or `admin_claim_token_file`).

    By default comparison is **exact** (`config.group_match`). Otherwise `admin` would also
    match `nicht-admin`: a silent privilege escalation. `dn=True` (LDAP) compares a
    group DN by its components instead of as text (`group_fits`): whole DN, first
    RDN (`cn=staff`) or its value (`staff`) — never a substring."""
    if not mapping:
        return
    if substring is None:
        substring = self.cfg.group_match == "substring"
    gs = [str(g) for g in (groups or [])]
    matched = {role for key, role in mapping.items()
               if any(group_fits(key, g, substring, dn) for g in gs)}
    if dn and not substring:
        for key in mapping:
            _substring_notice(key, gs, "ldap_group_role_map")
    managed = {role for role in mapping.values() if role != "__admin__"}
    # A map target that cannot travel as one role (T-85) is never granted — `config_check` refuses it at
    # construction, this catches a map changed at runtime. Skipped with a security line, not stripped: `ad\x01min`
    # must not become `admin`.
    for bad in sorted(r for r in matched if r != "__admin__" and role_invalid(r)):
        security.seclog.warning("Role from the identity provider skipped: the role name %s holds a comma, a control "
                                "character or surrounding spaces (user_id=%s)", security.for_log(repr(bad)),
                                user_id)
    matched = {r for r in matched if r == "__admin__" or not role_invalid(r)}
    current = set(self.store.get_roles(user_id))
    new_roles = (current - managed) | {r for r in matched if r != "__admin__"}
    if new_roles != current:
        self.store.set_roles(user_id, sorted(new_roles))
    u = self.store.get_user(user_id)
    if "__admin__" in matched:
        if u and not u["is_admin"]:
            self.store.set_admin_from_idp(user_id)
            self.audit("idp_admin_grant", u["username"], detail="source=idp")
    elif "__admin__" in mapping.values() and u and u["is_admin"] == 2:
        # The mapping knows an admin group, the provider no longer delivers it: the flag
        # it granted goes. Loudly, because it can also be the last admin.
        self.store.set_admin(user_id, False)
        self.audit("idp_admin_revoke", u["username"], detail="source=idp group_removed=1")
        security.seclog.warning("Admin flag withdrawn: user=%s, the identity provider no longer "
                                "delivers the admin group.", security.for_log(u["username"]))
        if not self.admin_exists():
            # If it was the last admin (G6), the allowlist stays closed from now on: otherwise
            # `_maybe_promote_admin` in the same login — via `apply_factor` — would promote the person again,
            # as admin "by hand" (1) and first owner, whom no provider withdraws any more and whom
            # nobody can delete or lock. And not only her: every account with an
            # allowlist entry. Only the operator's verified route remains open — the
            # one-time token, now issued immediately (until then only at startup), and the CLI.
            # The marker applies to the instance and is never reset; it only takes effect
            # as long as there is no admin. Parallel withdrawals set it idempotently.
            self.store.set_setting("allowlist_after_idp_revocation", str(_manager._now()))
            security.seclog.warning(
                "No admin left: the identity provider has withdrawn the instance's last admin. "
                "admin_identifiers promotes nobody afterwards. Emergency route: "
                "tinysesam owner --db <file> <user> or /auth/claim-admin with the "
                "one-time token (console or admin_claim_token_file).")
            tok = self.admin_claim_token()
            if tok:
                self._admin_claim_announce(tok)


# ---------- First admin (bootstrap) ----------
# Deliberately NOT "the first registered user becomes admin": with open registration, whoever
# is there first wins — also a stranger who finds the fresh instance. Instead two
# explicit paths, both effective only WHILE there is no admin — the allowlist moreover never
# again after the identity provider has withdrawn the instance's last admin (G6).
def delete_user(self, user_id: int) -> bool:
    """Delete an account with all its credentials (B5-08) — and take it out of the audit log (H-13).

    The audit lines stay (what happened, when, from which IP), only the name becomes
    `deleted#<id>` (up to 0.24.x `gelöscht#<id>`) — also for sign-in attempts under the email address and where the name
    (`actor=`) or address appears in the detail text (see `Store.anonymize_audit`). A
    deleted account whose name still appears in every line is not deleted; a log
    with missing lines is no longer fit for follow-up.

    The sign-in attempts disappear under every spelling under which the lockout bucket
    counts them (NFKC, IDNA, see `Store.delete_attempts_for`). Exception: a bucket that a
    remaining account shares (`ｃｌａｒａ` and `clara`) — it stays until the ordinary
    cleanup, otherwise deleting one would lift the lockout of the other.

    What arose from the creation of the account onward is replaced; a VERIFIED address also in
    older lines (for instance in the invitation that led to the account) — it demonstrably
    belongs to the account (`Store.address_proven`). The address of an open account (link never
    redeemed) or of a registration without a confirmation requirement is not verified; a
    stranger may have typed it. A name belonged to nobody or to someone else before creation;
    a failed attempt under it stays as it was (see `Store.remove_account`).

    The last admin cannot be deleted (`StateError`) — otherwise the instance would be left without
    administration, and the first-admin path would open up for the next best person. Returns False
    if the account does not exist.
    """
    u = self.store.get_user(user_id)
    if not u:
        return False
    lock = self.store.deletion_guard(u)        # the same rule as `tinysesam delete`
    if lock == "owner":
        raise StateError(f"Account {user_id} is an owner and cannot be deleted — hand over the "
                         "owner role first (this requires another owner to exist).")
    if lock == "last_admin":
        raise StateError(f"Account {user_id} is the last admin and cannot be deleted.")
    # The one deletion path (`Store.remove_account`) — the same through which `gc()`, `tinysesam gc`
    # and the withdrawal of a registration delete (integration findings 12/18). Only here, in
    # the deliberate deletion, does a verified address count as the account's own even from before creation —
    # the other paths can be triggered by a stranger (`Store.address_proven`).
    removed = self.store.remove_account(user_id, address_unlimited=True)
    if removed is None:
        return False
    replacement, n = removed
    self.audit("user_delete", replacement, detail=f"uid={user_id} audit_anonymized={n}")
    return True


def set_disabled(self, user_id: int, disabled: bool) -> bool:
    """Lock or unlock an account as operator — with the same effect as the panel
    (`POST <admin_path>/api/users/{id}/disable`, which calls exactly this method).

    **Locking** (`disabled=True`):

    * with operator marker: no confirmation link lifts the lock, not even one that
      comes into being only afterwards (H-18) — only `set_disabled(user_id, False)`;
    * all sessions of the account end, its API keys are revoked (event
      `api_keys_revoked` with `reason="account_disabled"`), open one-time tokens discarded
      (sign-in, confirmation, reset, address-change link). The revocation of the keys remains
      on unlocking — otherwise a key nobody knows about any more would come back to life;
    * an **owner** cannot be locked: `StateError`, and nothing has happened.

    **Unlocking** lifts every lock, including one from a pending confirmation.

    Audit as in the panel: `user_disable` or `user_enable` with `uid=<id>` (when locking with
    keys additionally `api_keys_revoked=<n>`) — in a request under the signed-in account (the
    admin), without a request under the affected one. What depends on the caller is checked by the route: the
    panel lets nobody lock themselves and changes an owner account only by an owner.
    Returns False if the account does not exist (then nothing happens).

    Up to 0.21.x the docs showed `auth.store.set_disabled(uid, True, through_operator=True)` for this
    — that sets only the marker: sessions, keys and links stayed valid. `auth.store` is
    internals with no guarantee (PO decision 2026-09-27)."""
    u = self.store.get_user(user_id)
    if not u:
        return False
    uid = int(u["id"])
    # The marker first: with an owner the store raises before anything has happened.
    self.store.set_disabled(uid, bool(disabled), through_operator=True)
    keys = self._lock_effects(uid) if disabled else 0
    self._lock_audit(u, bool(disabled), keys)
    if not disabled and u["delete_after"]:
        # Unlocking ends a deletion by the application (`Store.set_disabled`) — said in the log.
        self.audit("provision_restore", str(u["username"]), detail=f"uid={uid} by=operator")
    return True


def _reset_access(self, user_id: int, *, app_id: str, approved_by: dict, detail: str = "") -> dict:
    """The effect of a confirmed `tinysesam.account.reset_access` (approvals): every sign-in factor TinySesam
    keeps is deleted in one transaction (password, PIN, TOTP with recovery codes, passkeys), the sessions end, the
    standing credentials are revoked (API keys, app passwords, services, connected devices — reason
    `access_reset`) and open one-time links die. `first_login_at` stays: the new one-time link the application
    picks up once is the only way back in. Audit `account_access_reset` under the account, with the application,
    the approver and the counts — never a link. The caller has checked the rights; returns the counts."""
    uid = int(user_id)
    counts = self.store.clear_sign_in_factors(uid)
    self.store.delete_user_sessions(uid)
    counts["api_keys"] = self._keys_revoked(uid, "access_reset")
    self.store.revoke_user_magic_tokens(uid)
    self.store.set_mfa_enroll_until(uid, None)
    who = f"{approved_by['username']}#{int(approved_by['id'])}"
    numbers = " ".join(f"{k}={int(v)}" for k, v in counts.items())
    self.audit("account_access_reset", self._account_name(uid),
               detail=f"app={app_id} approved_by={who} {numbers}" + (f" {detail}" if detail else ""))
    self._security_event("access_reset", uid, app=app_id, approved_by=str(approved_by["username"]),
                         password=counts["password"], pin=counts["pin"], totp=counts["totp"],
                         recovery_codes=counts["recovery_codes"], passkeys=counts["passkeys"],
                         api_keys=counts["api_keys"])
    return counts


def _lock_effects(self, uid: int) -> int:
    """What every lock does besides the marker — the operator's (`set_disabled`) and the application's (account
    API, `disabled=3`): sessions end, standing credentials are revoked, open one-time tokens discarded. Returns
    the number of revoked keys. One place, so a new kind of access ends with every kind of lock."""
    self.store.delete_user_sessions(uid)
    # `verify_api_key` already rejects keys of locked accounts. Revoke anyway: if
    # the account is released again later, a key nobody knows about any more would
    # otherwise come back to life.
    # Connected devices (OAuth, T-36), app passwords and services end with them — forward auth refuses a
    # locked account anyway, but on unlocking a device nobody remembers would otherwise come back.
    keys = self._keys_revoked(uid, "account_disabled")
    # The same for open one-time tokens: a confirmation link from registration otherwise lifted the
    # lock again (H-18, "a disabled account via no path").
    self.store.revoke_user_magic_tokens(uid)
    return keys


def _lock_audit(self, u, disabled: bool, keys: int) -> None:
    """The audit line of a lock or unlock: `user_disable`/`user_enable` with `uid=` (and `api_keys_revoked=`).
    From a request with a signed-in account (panel, own admin route) `audit()` names the actor as the account —
    the same line the panel itself wrote up to 0.21.x."""
    request = _REQUEST.get() or {}
    self.audit("user_disable" if disabled else "user_enable",
               None if request.get("actor") else str(u["username"]),
               detail=f"uid={int(u['id'])}" + (f" api_keys_revoked={keys}" if keys else ""))


def own_events(self, user_id: int, limit: int = 20) -> list:
    """The most recent audit events of an account, for the account page (H-7).

    Only time, event and IP — the detail stays with the operator: for an admin action
    it names foreign accounts, and a display for the account owner should not show more than
    their own account. Exactly what one looks for there: "Was that me?"

    If ANOTHER person triggered the line (`actor=` in the detail, see `audit()`), the IP there is
    theirs — the admin's. That is omitted; `by_admin` says instead that it was not
    the account owner.

    Counting starts only from the creation of the account (`Store.setup_limit`). The filter goes by
    the NAME, and a name may have belonged to someone else before: a deleted account
    whose lines an older version did not anonymise (integration finding 12), or
    to nobody — then the failed attempt of a stranger under the then-free name is there,
    including their IP.

    Since 2026-09-26 it is not the creation that counts but the NAME's joining (G2): whoever takes over a
    freed name (renaming) previously saw the previous owner's sign-in
    including their IP. The creation remains the fallback for existing data without a watermark.

    Likewise since 2026-09-26 it always shows an address-change request as
    `email_change_requested`, whether the address was free, taken or reserved, and
    `federation_email_confirm` not at all (`_OWN_VIEW`, G12b). A rejection ON
    CONFIRMATION (`on_confirmation=1`) keeps its name: the 409 told the person clicking
    anyway, and only whoever has the link from the mailbox gets there.

    """
    u = self.store.get_user(user_id) if user_id is not None else None
    if not u:
        return []
    from_ = []
    # The same boundary as `remove_account`: the name's watermark, otherwise the creation.
    name = str(u["username"])
    audit_from = self.store.identifier_limits(u).get(norm_identifier(name), (None, None))[1]
    since, since_id = self.store.setup_limit(u) if audit_from is None else (None, 0)
    hide = tuple(e for e, view in self._OWN_VIEW.items() if view is None)
    for z in self.store.recent_audit(max(1, int(limit)), username=name, since=since, since_id=since_id,
                                     from_id=audit_from, without_events=hide):
        detail = f' {z["detail"] or ""} '
        foreign = " actor=" in detail
        event = z["event"]
        if " on_confirmation=1 " not in detail:
            event = self._OWN_VIEW.get(event, event)
        from_.append({"ts": z["ts"], "event": event,
                    "ip": None if foreign else z["ip"], "by_admin": foreign})
    return from_


def admin_exists(self) -> bool:
    """Is there at least one admin? The two bootstrap paths apply only while there is not."""
    return any(u["is_admin"] for u in self.store.list_users())


def _maybe_promote_admin(self, user, email_confirmed: Optional[bool] = None,
                         factor: Optional[str] = None) -> bool:
    """Path 1: allowlist. Whoever is in `admin_identifiers` becomes admin at login — regardless of
    the method (also OIDC/SAML/LDAP); an allowlist ADDRESS, however, only with evidence
    that it belongs to the person signing in, and via SAML/LDAP there is none. Never again afterwards —
    not even after the identity provider has withdrawn the instance's last admin (G6).

    **An entry with `@` is checked ONLY against the email, one without ONLY against the
    username.** Before, "name OR email" applied to every entry, and that made the
    constructor guard ineffective: it demands an *email address* in the allowlist for
    open registration, on the grounds that "whoever has the mailbox has the name".
    A username, however, is a free text field — whoever registers as
    `username="chef@example.com"` and confirms THEIR OWN mailbox became
    first admin. The guard checked the configuration, but the comparison here checked something
    different; the gap had merely moved.

    `email_confirmed` is the **evidence for the address** with which the caller arrives:
    a federated sign-in path states `True`/`False` via the claim `email_verified`,
    `None` means "this sign-in path does not know". Without evidence a matching address
    does not count: otherwise an IdP with self-registration would suffice to register the
    admin address and become first admin at the first login.

    Evidence is established in two stages, both fail-closed:

    1. **Federated path without evidence is refused.** Evidence exists only for OIDC (claim
       `email_verified`, OIDC Core 5.1). **SAML and LDAP have none** — no
       standard attribute says that a directory verified the address, and in many directories the user maintains a
       `mail` attribute themselves. So that this does not depend on the
       caller's memory: `factor` from `_FEDERATED_FACTORS` demands
       `email_confirmed is True`, a forgotten argument refuses. LDAP writes the
       factor `password` and cannot be recognised by it — there the caller passes
       `email_confirmed=False`.
    2. **Otherwise the marker on the account decides** (`users.email_verified`, read by
       `_proof_on_account`). The address from an IdP without the claim is, since this version, written into the account quite
       normally (otherwise an existing installation would lose account name and
       `Remote-Email`) — it just must not carry anything. If that hung on the parameter alone, the
       protection would be a question of the sign-in path: the same record, signed in once via a local
       path (magic link, password), would come in with `None` and would have been promoted.
       The marker is in the database and therefore applies to every path.

    The username remains unaffected — the constructor guard is responsible for it,
    which forbids allowlist names as soon as accounts arise by themselves.

    **Never again after a withdrawal by the identity provider** (G6): if the provider has taken the
    instance's last admin (`apply_idp_groups`, H-5), the allowlist promotes
    nobody any more — otherwise it would make the person admin "by hand" again in the same login
    and first owner, whom no provider withdraws any more (audit `admin_bootstrap_denied
    after_idp_withdrawal`). The way back into the panel is then the one-time token (`/auth/claim-admin`,
    issued immediately) and `tinysesam owner`.
    """
    ids = {str(i).strip().lower() for i in self.cfg.admin_identifiers if str(i).strip()}
    if not ids or not user or user["is_admin"] or self.admin_exists():
        return False
    addresses = {i for i in ids if "@" in i}
    names = ids - addresses
    hits_address = str(user["email"] or "").lower() in addresses
    hits_name = str(user["username"] or "").lower() in names
    if not (hits_address or hits_name):
        return False
    if self.store.get_setting("allowlist_after_idp_revocation"):
        # G6: The identity provider has withdrawn the instance's last admin
        # (`apply_idp_groups`) — the allowlist does not open again afterwards, for nobody.
        security.seclog.warning(
            "First admin NOT granted: %s is in admin_identifiers, but the identity "
            "provider has withdrawn the instance's last admin — the allowlist does not open "
            "again afterwards. Emergency route: tinysesam owner --db <file> <user> or "
            "/auth/claim-admin.", security.for_log(user["username"]))
        self.audit("admin_bootstrap_denied", user["username"], detail="after_idp_withdrawal")
        return False
    if hits_address and not hits_name:
        # Two stages, both fail-closed: explicit evidence from the sign-in path wins.
        # If the path is silent (`None`), a federated factor refuses on principle — even
        # if it simply forgot the argument —, and otherwise the marker
        # on the account decides.
        if email_confirmed is not None:
            proven, reason = email_confirmed is True, "email_unconfirmed"
        elif (factor or "") in self._FEDERATED_FACTORS:
            proven, reason = False, f"without_proof:{factor or '?'}"
        else:
            proven, reason = _proof_on_account(user), "email_unconfirmed"
        if not proven:
            security.seclog.warning(
                "First admin NOT granted: %s carries the allowlist address %s, but there is no "
                "confirmation evidence for this sign-in path (%s) (OIDC: claim "
                "email_verified; SAML and LDAP have none; otherwise the note on the account). "
                "The address stays on the account, it just does not support this decision. "
                "Evidenced route: /auth/claim-admin.",
                security.for_log(user["username"]), security.for_log(user["email"]),
                factor or "?")
            self.audit("admin_bootstrap_denied", user["username"], detail=reason)
            return False
    self.store.set_admin(user["id"], True)
    self._first_owner(user["id"])
    self.audit("admin_bootstrap", user["username"], detail="admin_identifiers")
    security.seclog.warning("First admin granted via admin_identifiers: %s",
                            security.for_log(user["username"]))
    return True


def _claim_file_auto(self) -> str:
    """`<db_path>.claim` — where the one-time token goes when stderr is not a console (T-17).

    Next to the database, because whoever operates the service may write there anyway, and because
    `<db_path>.key` also lies there. Empty without a file (`:memory:`): then only stderr remains.
    """
    db = str(self.cfg.db_path or "").strip()
    return "" if db in ("", ":memory:") else db + ".claim"


def _claim_file_away(self) -> None:
    """Remove the automatically created token file — after redemption, and at startup
    when there is no token (any more). A self-chosen `admin_claim_token_file` stays
    in place (its path may be a mounted secret); its content is then invalid."""
    path = self._claim_file_auto()
    if path:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass  # already gone (never created or already redeemed) — exactly the target state
        except OSError as e:
            security.seclog.warning("Token file %s could not be removed (%s) — its "
                                    "content is invalid.", path, type(e).__name__)


def _admin_claim_announce(self, token: str) -> None:
    """Show the value of the first-admin one-time token to the **operator** — not to the log.

    Up to 0.18.x the token stood in plaintext in the line that `security.seclog` writes. If
    `security_log` is set, that is exactly the file the bundled fail2ban jail
    points to: it came into being without a permissions spec (measured `-rw-rw-r--`), logrotate keeps it
    for weeks and every log shipping takes it along. Whoever could read it and had any
    account on the instance called `/auth/claim-admin?token=…` and was admin (B5-03).

    The value therefore goes to **stderr** — the console of whoever starts the service, and
    the only recipient the docstring of `admin_claim_token` ever meant. Where
    stderr itself is collected (journal, container logs), the operator names a file with
    `admin_claim_token_file`; TinySesam creates it with 0600. Only **where** the token is
    goes into the log now.

    **Since 0.22.0 (T-17) also without this setting:** if stderr is not a console (container,
    journal, pipe — `sys.stderr.isatty()` false), TinySesam writes the token to
    `<db_path>.claim` (0600) and names only the path. Until then it stood there in plaintext in
    `docker logs` — directly before the line "The value is deliberately NOT in the log" (German runtime text). Without a
    database file (`:memory:`) or if the file is not created, only stderr remains, and
    the text honestly says that the value is then in the service's log. After redemption
    the file disappears (`_claim_file_away`).
    """
    ttl = self.cfg.admin_claim_ttl_min
    path = str(self.cfg.admin_claim_token_file or "").strip()
    console = _stderr_is_console()
    automatic = False
    if not path and not console:
        path = self._claim_file_auto()
        automatic = bool(path)
    # What the line in the log says must be true — also in the fallback. Up to 0.21.x it said there
    # "The value is deliberately NOT in the log" while in the container it stood two lines above.
    where_to = ("is on the console (stderr), not in this line" if console else
             "is on stderr — and stderr is NOT a console here: the value is therefore in the "
             "service's log (journal, docker logs). Remedy: set admin_claim_token_file "
             "or use a database file instead of :memory:")
    written = False
    if path:
        try:
            # Open without O_TRUNC and set the permissions on the descriptor BEFORE the secret
            # goes in: with an already existing file the mode parameter of
            # os.open ignores the default, and a chmod afterwards would leave a window open.
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                os.ftruncate(fd, 0)
                os.write(fd, (token + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            where_to = f"is in {path} (mode 0600), not in the log"
            written = True
        except OSError as e:
            # No reason to refuse startup — but the operator must get the token,
            # otherwise they cannot reach their own instance.
            name = "the token file" if automatic else "admin_claim_token_file"
            _on_stderr(f"TinySesam: {name} {path} not writable "
                        f"({type(e).__name__}) — the token is here instead:")
            where_to = f"{where_to} ({path} was not writable: {type(e).__name__})"
    if not written:
        _on_stderr(f"TinySesam: No admin exists. Set the first admin — sign in, then "
                    f"/auth/claim-admin?token={token} (valid {ttl} minutes, can be redeemed "
                    f"exactly once).")
    security.seclog.warning(
        "No admin exists. The one-time token for /auth/claim-admin %s — valid %d "
        "minutes, can be redeemed exactly once.", where_to, ttl)


def admin_claim_token(self) -> Optional[str]:
    """Path 2: one-time token. As long as no admin exists, there is a token that can be redeemed
    exactly once (`/auth/claim-admin?token=…`). The value goes to stderr at startup
    or into `admin_claim_token_file` (0600) — whoever operates the server has it; whoever merely knows the
    URL or can read the log does not (B5-03). Expires."""
    # No panel, no local admins → no token. Otherwise a pure OIDC app would have a
    # path to admin that it never provided for.
    if not self.cfg.admin_enabled or self.cfg.admin_claim_ttl_min <= 0 or self.admin_exists():
        return None
    raw = self.store.get_setting("admin_claim")
    now = _manager._now()
    if raw:
        token, exp = raw.split(":", 1)
        if int(exp) > now:
            return token
    token = secrets.token_urlsafe(24)
    self.store.set_setting("admin_claim", f"{token}:{now + self.cfg.admin_claim_ttl_min * 60}")
    return token


def _consume_admin_claim(self, token, user) -> bool:
    """Redeem the one-time token and make this account admin. Valid exactly once."""
    if not token or not user or not self.cfg.admin_enabled or self.admin_exists():
        return False
    raw = self.store.get_setting("admin_claim")
    if not raw:
        return False
    want, exp = raw.split(":", 1)
    if int(exp) <= _manager._now() or not secrets.compare_digest(token, want):
        return False
    self.store.set_setting("admin_claim", "")     # one-time
    self._claim_file_away()                        # the file now holds only invalid content (T-17)
    self.store.set_admin(user["id"], True)
    self._first_owner(user["id"])
    self.audit("admin_bootstrap", user["username"], detail="claim_token")
    security.seclog.warning("First admin granted via one-time token: %s",
                            security.for_log(user["username"]))
    return True


def _admin_claim_failure(self, username, ip) -> None:
    """Record a failed first-admin claim — audit log and security log (B5-16)."""
    self.audit("admin_claim_fail", username, ip)
    security.seclog.warning("%s user=%s ip=%s method=claim_admin", security.LOG_CHECK,
                            security.for_log(username), security.for_log(ip))


def _seed_demo(self) -> None:
    """Create sample accounts (idempotent). Requires `demo_mode=True`.

    The check has been **here** since 2026-09-21 and no longer only at the caller in the constructor.
    The docstring promised it before — the body did not keep it: a direct call
    with `demo_mode=False` created `demo` and `demoadmin`, the latter with `is_admin=1` and the
    documented default password, both able to sign in at once and without a warning in the log.
    """
    if not self.cfg.demo_mode:
        raise ConfigError(
            "seed_demo() requires demo_mode=True. Without the switch two accounts able to "
            "sign in with a known password would be created — one of them admin — and the "
            "warning in the log would be missing.")
    ids = []
    for name in self._DEMO_USERS:
        u = self.store.get_user_by_name(name)
        if u:
            ids.append(str(u["id"]))
            continue
        uid = self.create_user(name, password=self.cfg.demo_password, is_admin=(name == "demoadmin"))
        if self.cfg.pin_enabled:
            self.set_pin(uid, self.cfg.demo_pin)
        ids.append(str(uid))
    self.store.set_setting("demo_users", ",".join(ids))


def _purge_demo(self) -> int:
    """Remove the accounts created by `_seed_demo` again — exactly those, not ones of the same name."""
    raw = self.store.get_setting("demo_users") or ""
    n = 0
    for sid in filter(None, raw.split(",")):
        u = self.store.get_user(int(sid))
        if u and u["username"] in self._DEMO_USERS:
            # Via the one deletion path (H-13): if `_seed_demo` later recreates the names, the
            # new account would otherwise see the old one's events as its own (H-7).
            self.store.remove_account(u["id"])
            n += 1
    self.store.set_setting("demo_users", "")
    return n


def get_user(self, user_id) -> Optional[dict]:
    """Read an account by ID, or None."""
    return self._as_dict(self.store.get_user(user_id))


# ---------- Start secret from the administrator (T-46, ASVS 6.4.1) ----------
# A password the admin set (panel: new account, reset) signs in only halfway: after every other
# step of the sign-in the half session lands on `/auth/setup`, which asks for an own password.
# The same half-session pattern as the setup pass after a sign-in link (T-34): nothing but that
# page and `POST /auth/password/set` accept it, and it expires with the step-up window.
def _renew_session(self, s) -> bool:
    """Is this session row a half session that owes only the replacement of the start secret?"""
    if not s or s["mfa_ok"]:
        return False
    done = json.loads(s["factors_done"] or "[]")
    if self._next_login_step(s["user_id"], done, setup=self._setup_session(s)) != "password_change":
        return False
    window = int(self.cfg.stepup_max_age_sec or 0)
    if window > 0 and (_manager._now() - int(s["created_at"] or 0)) > window:
        return False
    u = self.store.get_user(s["user_id"])
    return bool(u and not u["disabled"])


def _renew_user(self, request) -> Optional[dict]:
    """The account of a half session that has to replace its start secret — otherwise None."""
    s = self._session_from_request(request)
    if not self._renew_session(s):
        return None
    u = self._as_dict(self.store.get_user(s["user_id"]))
    self._remember_request(request, u)
    return u


def _renew_password(self, request: Request, new: str, *,
                    csrf: Optional[str] = None) -> tuple[PasswordChangeResult, Optional[str]]:
    """Replace the start secret with an own password — `POST /auth/password/set` from the half
    session (T-46). The new one has to follow the rule and must not be the admin's. On success the
    sign-in completes under a NEW token (privilege change), which is returned for the cookie."""
    self.require_csrf(request, self._csrf_sent_along(request, csrf))
    u = self._renew_user(request)
    if u is None:
        return PasswordChangeResult(ok=False, reason="no_session", status=401,
                                    message=self.t("api.not_signed_in")), None
    ip = self.client_ip(request)
    if not self._rate_ok(ip, login=False):
        return PasswordChangeResult(ok=False, reason="ratelimit", status=429, message=self.t("api.too_many")), None
    defect = self.password_policy_error(new or "", username=u["username"], email=u.get("email"), api=True)
    if defect:
        return PasswordChangeResult(ok=False, reason="policy", status=400, message=defect), None
    current = self.store.get_password_hash(u["id"])
    if current and verify_password(str(new or ""), current):
        return PasswordChangeResult(ok=False, reason="policy", status=400,
                                    message=self.t("api.password_same")), None
    self.set_password(u["id"], new)              # clears the mark, event `password_changed`
    self.audit("password_renewed", u["username"], ip, "start_secret_replaced=1")
    s = self._session_from_request(request)
    done = json.loads(s["factors_done"] or "[]")
    if not self._session_ok(u["id"], done, setup=self._setup_session(s)):
        return PasswordChangeResult(ok=True, reason="ok", status=200), None
    self._sign_in_complete(u["id"], s["ip"], "password")
    self._note_login(u["id"])
    self._lift_after_sign_in(u["id"], s["ip"])
    new_token = self._create_session(u["id"], self._ttl(bool(s["remember"])), True, s["method"],
                                     s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
    self._successor(s, new_token)
    if self._setup_session(s):
        self._setup_finished(s, done)
    self.store.delete_session_by_handle(s["token_hash"])
    self._other_after_completion(s, new_token)
    return PasswordChangeResult(ok=True, reason="ok", status=200), new_token


def _session_from_request(self, request):
    """The session row for this request, or None. `row["token_hash"]` is its handle.

    An OIDC session is re-verified with the provider here every `oidc_session_refresh_minutes`
    (4a): if it refuses, the session is gone, and this request counts as not signed in."""
    s = self.store.get_session(request.cookies.get(self.session_cookie_name))
    if s is not None and not self._oidc_recheck(s):
        return None
    return s


def _remember_oidc_session(self, token, client, sub, refresh_token) -> None:
    """Store the refresh token for the (just created) session (4a) — with the client_id to
    which it went."""
    if not int(self.cfg.oidc_session_refresh_minutes or 0) or not token:
        return
    self.store.set_oidc_session(self.store.session_hash(token), client, sub, refresh_token,
                                client_id=self.oidc_clients[client].client_id)


def _mercy(self) -> int:
    """Grace period of the old token after rotation, in seconds (A-6)."""
    return max(0, int(self.cfg.session_rotation_grace_sec or 0))


def _oidc_recheck(self, s) -> bool:
    """Does the session still follow the provider? False = the session has ended (4a).

    Every `oidc_session_refresh_minutes` the refresh token is exchanged — per client of the
    session, in the background (`_oidc_swap`). This request merely claims the due exchange
    (`claim_oidc_session`, exactly one of many parallel ones) and carries on; the
    result applies from the next request. So a hanging provider blocks nothing, and two
    requests never exchange the same token (rotation at the provider). Nobody asks the provider about locked
    accounts — they do not get in anyway (F-17)."""
    deadline = int(self.cfg.oidc_session_refresh_minutes or 0) * 60
    if not deadline or self.oidc is None:
        return True
    lines = self.store.get_oidc_sessions(s["token_hash"])
    if not lines:
        return True
    account = self.store.get_user(s["user_id"])
    if not account or account["disabled"]:
        return True
    now = _manager._now()
    limit = int(self.cfg.oidc_session_max_unverified_hours or 0) * 3600
    for z in lines:
        try:
            success = z["success_at"]
        except (IndexError, KeyError):
            success = None
        # Since when has the provider not said yes? Without a value (row from the time before
        # the column) the last exchange counts.
        since = int(success if success is not None else z["checked_at"])
        if limit and now - since > limit:
            # Upper limit without a successful re-check: the session ends. That is NOT a no
            # from the provider — the API keys therefore do not go dormant (finding 8 stays with the real no).
            self.store.delete_session_by_handle(s["token_hash"])
            account_name = account["username"] if account else None
            self.store.audit_log("oidc_unconfirmed", account_name, s["ip"],
                                 f"client={z['client']} hours={limit // 3600}")
            security.seclog.warning(
                "OIDC re-check without result for over %d hours — session ended. Check: "
                "client secret/client at the provider, reachability. user=%s",
                limit // 3600, security.for_log(account_name))
            return False
        if now - int(z["checked_at"]) < deadline:
            continue
        if not self.store.claim_oidc_session(s["token_hash"], z["client"], z["checked_at"], now):
            continue          # another request is exchanging right now
        if not self._oidc_outcome.enqueue(lambda z=z: self._oidc_swap(s, z, deadline)):
            # Queue full: give the claim back, the next request tries again.
            self.store.oidc_session_checked(s["token_hash"], z["client"], z["checked_at"])
    return True


def _oidc_swap(self, s, z, deadline) -> None:
    """Exchange a refresh token at the provider and apply the result (4a, in the background).

    * if the provider refuses (locked, deleted, removed from the group, withdrawn from the application) → the
      session ends, with a line in the audit log;
    * if it delivers fresh data → groups, allowed groups and the admin flag assigned by the provider
      are re-evaluated (H-5 thus takes effect within minutes) — but only if the
      group claim is present at all: if it is missing, "no groups" would otherwise mean revoking every mapped
      role;
    * if it is unreachable → nothing changes, new attempt in a minute. An outage
      of the provider should sign nobody out."""
    handle, client = s["token_hash"], z["client"]
    account = self.store.get_user(s["user_id"])
    name = account["username"] if account else None
    try:
        issued_for = z["client_id"]
    except (IndexError, KeyError):
        issued_for = None
    if not self.oidc_clients.known(client) or (
            issued_for and issued_for != self.oidc_clients[client].client_id):
        # The application was removed from `oidc_clients`, or the client was recreated
        # at the provider (different client_id). The exchange would run with wrong credentials, the
        # provider would say no, and that would hit the account (attack on the third round and
        # counter-check). The row goes, the session stays until its expiry.
        self.store.discard_oidc_session(handle, client)
        security.seclog.warning("OIDC re-check: client %s is no longer set up (like this) — "
                                "row discarded, not counted as a no. user=%s",
                                security.for_log(client), security.for_log(name))
        return
    try:
        refresh = self.store.oidc_refresh_plain(z) or ""
    except Exception:   # noqa: BLE001 — wrong key: the start checks that; do not burn anything here
        self.store.oidc_session_checked(handle, client, _manager._now() - deadline + 60,
                                         old_encrypted=z["refresh"])
        return
    asked = _manager._now()
    status, info, tok = self.oidc_clients[client].refresh(refresh, z["sub"])
    now = _manager._now()
    # During the exchange the session may have received a new token (step-up, completion
    # of a factor) — its current handle stands at the row, found via the token.
    handle = self.store.oidc_session_handle(client, z["refresh"]) or handle
    if status == "error":
        self.store.oidc_session_checked(handle, client, now - deadline + 60, old_encrypted=z["refresh"])
        security.seclog.warning("OIDC re-check without result (%s): provider unreachable or "
                                "a client error (credentials, grant) — session stays, "
                                "new attempt in one minute. user=%s",
                                security.for_log(str(tok.get("error", "?"))), security.for_log(name))
        return
    if status == "rejected":
        self.store.delete_session_by_handle(handle)
        error = security.for_log(str(tok.get('error', '?')))
        self.store.audit_log("oidc_revoked", name, s["ip"], f"client={client} reason={error}")
        self._idp_no(s["user_id"], name, s["ip"], client, error)
        return
    lives = self.store.oidc_session_checked(handle, client, now, tok.get("refresh_token"),
                                            old_encrypted=z["refresh"], success=True)
    entry = self.oidc_clients.entry(client)
    groups = None
    if self.cfg.oidc_group_claim in info:
        raw = info.get(self.cfg.oidc_group_claim) or []
        groups = raw if isinstance(raw, list) else [raw]
        allowed = entry["allowed_groups"]
        if allowed and not (set(allowed) & set(map(str, groups))):
            self.store.delete_session_by_handle(handle)
            self.store.audit_log("oidc_revoked", name, s["ip"], f"client={client} reason=group")
            self._idp_no(s["user_id"], name, s["ip"], client, "group")
            return
        self.apply_idp_groups(s["user_id"], groups, entry["group_role_map"])
    if lives:
        # Only if the session is still there: a parallel no via another client
        # may have ended it in the meantime — then this yes confirms nothing any more.
        self.store.confirm_idp(s["user_id"], asked)
        # B-6: the yes for THIS client is also the yes for its application — it renews the
        # approval (`oidc_revalidate_minutes`). Otherwise the approval went stale after an hour
        # although the provider had just confirmed it, and the redirect hop showed a login form
        # as soon as the provider's own session had ended. With an allowed-groups rule only if the
        # claim was there and passed — a missing claim proves nothing, then the hop decides.
        if groups is not None or not entry["allowed_groups"]:
            self.store.confirm_oidc_grant(handle, client, asked, groups)


def current_user(self, request) -> Optional[dict]:
    """The signed-in account for this request — from the session OR an API key. None if nobody is signed in.

    Not the source for a route that applies a factor to the running session, refreshes it
    or ends it — there the account belongs from `session_user()` (0.20.1)."""
    # Remember the IP first, then resolve: even a rejected API key (B5-05) should appear in the log
    # with the address it came from.
    self._remember_request(request)
    u = self._determine_current_user(request)
    if u:
        self._remember_request(request, u)
    return u


def session_user(self, request) -> Optional[dict]:
    """The account of this request's full session — like `current_user()`, only never from an API key.

    **The source for every route with session effect** (0.20.1): whoever checks a factor and
    then applies it to the session (`apply_factor`, `complete_totp`), refreshes it
    (step-up) or ends it takes the account from here. Without a full session
    `current_user()` falls back to the API key. In such a route the factor then checked the
    key's account, and the effect hit the cookie: `/auth/reauth` made someone else's half session
    full, `/auth/pin` with `pin_login=False` lifted the bolt "PIN is not a first factor"
    and created a full session from machine key and PIN — including the admin flag, which
    the key alone never carries (R6-5). For these routes a key is "not signed in".

    A half session (first factor yes, chain open) yields None; `pending_user()` reads it.
    A guard in `tests/test_stepup.py` ensures that no place in the package with session effect
    takes its account from a source that accepts a key.
    The same rule applies to own routes of the app that call `apply_factor()` for "the
    signed-in account"."""
    self._remember_request(request)
    u = self._account_of_session(self._session_from_request(request))
    if u:
        self._remember_request(request, u)
    return u


def _account_of_session(self, s) -> Optional[dict]:
    """The account of a FULL session row, locked accounts excluded — or None."""
    if s and s["mfa_ok"]:
        u = self.store.get_user(s["user_id"])
        if u and not u["disabled"]:
            d: dict = self._as_dict(u) or {}
            d["_via"] = "session"
            return d
    return None


def _determine_current_user(self, request) -> Optional[dict]:
    # 1) Session (human, incl. MFA) — the same resolution as `session_user()`
    s = self._session_from_request(request)
    d = self._account_of_session(s)
    if d:
        return d
    # 2) API key (machine / daemon) — the key IS the factor, no MFA
    if self.cfg.apikey_enabled:
        key = self._extract_api_key(request)
        if key:
            u, key_roles = self.verify_api_key(key)
            kind = getattr(self, "_last_key_kind", "automation")
            if u and kind == "human":
                # A human key counts ONLY together with a session of the same account
                # (R6-5). Leaked on its own it is worthless — that is the whole difference
                # from the machine key, and for that it may carry the full rights.
                if not (s and s["mfa_ok"] and s["user_id"] == u["id"]):
                    security.seclog.warning(
                        "API key of kind 'human' presented without a matching session "
                        "(user=%s ip=%s) — rejected.",
                        security.for_log(str(u["username"])),
                        security.for_log(self.client_ip(request)))
                    return None
            if u:
                d = dict(u)
                d["_via"] = "apikey"
                d["_key_kind"] = kind
                # `!= "human"` instead of `== "automation"`: fail-closed for every kind that does not
                # exist (a typo in the column, a value from a foreign version).
                # Before, a key with `kind="Automat"` kept the admin flag (R6-6). The
                # values up to 0.21.x (`human`) arrive already mapped (`_key_kind`).
                if kind != "human" and d.get("is_admin"):
                    # The core of R6-5: a machine key does NOT carry its owner's
                    # admin flag. Before, every key of an admin was a complete
                    # admin write API — without a second factor, without a CSRF layer. The roles
                    # remain (that is what the scope is for), the flag does not.
                    d["is_admin"] = 0
                if key_roles is not None:
                    # INTERSECTION, not override: the scope narrows, it never widens.
                    # Second layer beside the limit in create_api_key — it also applies
                    # to keys that were created before the fix or that sit directly in the database.
                    # `is_admin` is left untouched, that comes from the user row.
                    d["roles"] = json.dumps(sorted(set(key_roles) & set(self.user_roles(u))))
                if kind != "human":
                    # Like the flag above: a machine key never carries a delegate role (T-74).
                    self._strip_delegate_roles(d)
                return d
    return None


def pending_user(self, request) -> Optional[dict]:
    """User of a session that is still stuck in the MFA step (mfa_ok=0)."""
    s = self._session_from_request(request)
    if not s or s["mfa_ok"]:
        return None
    u = self._as_dict(self.store.get_user(s["user_id"]))
    if u:
        self._remember_request(request, u)
    return u


def _pin_chain_step(self, request) -> Optional[dict]:
    """The account of the half session if the PIN is now its chain step — otherwise None.

    Yes only if the global `login_chain` requires the PIN, it is still missing in this session
    and, in a strict chain, it is the next step. Until 2026-09-27 any
    half session sufficed (G7-N1): in classic mode with `pin_login=False`, `/auth/pin` then checked
    the PIN for anyone who had only the password (wrong 401, right 303 — an oracle there
    that did not exist before), and in a strict chain `password → totp → pin` the PIN stood
    in the session before the TOTP. Its order could then never be fulfilled again, and every
    further sign-in in the same browser stuck to it until sign-out (p2 F1)."""
    u = self.pending_user(request)
    req, strict = self._global_chain()
    if not u or not req or "pin" not in _chain.factors(req):
        return None
    s = self._session_from_request(request)
    done = json.loads(s["factors_done"] or "[]") if s else []
    if "pin" in done or (strict and "pin" not in _chain.next_options(req, done)):
        return None
    return u


def totp_enrollment_user(self, request) -> Optional[dict]:
    """Who may set up TOTP **without** already being fully signed in? Otherwise None.

    Exactly one situation: the global `login_chain` requires `totp`, the user has provided their
    first factor (the session is stuck in the MFA step), has no confirmed TOTP yet, and the chain has a
    step that only TOTP can still cover for this account — not one it covers with a PIN or passkey it
    has (attack round B, F2).

    Without this path, `login_chain=["password","totp"]` is a **dead end** for every account without a set-up
    TOTP: the correct password leads to `/auth/totp`, which for lack of a
    secret leads back to the login page — and the setup page required a
    fully signed-in user, which can never exist under this chain. The account got neither
    in nor to the setup; the operator had to go to the database.

    Security-wise this is no concession: whoever is here has already provided the first factor,
    and without the chain (classic mode) the same password would have signed them in completely
    anyway. The setup alone signs nobody in — the factor counts only once a
    code from the fresh secret matches. That is the confirmation code itself: the route
    `POST /auth/totp/setup` completes the TOTP step with it (A-1), because the code is
    consumed and at `/auth/totp` only a failed attempt.
    """
    # The setup pass after a sign-in link (T-34) decides on its own: TOTP only when the pass
    # offers it — not before the factors the account has are provided.
    s = self._session_from_request(request)
    if self._setup_session(s):
        offered = self._setup_user(request, "totp")
        if offered is None:
            done = json.loads(s["factors_done"] or "[]")
            if self._setup_blocker(s["user_id"], done):
                self.audit("mfa_enrollment_denied", self._account_name(s["user_id"]),
                           detail="account has a second factor that is missing in this session")
        return offered
    u = self.pending_user(request)
    if not u or self.store.has_confirmed_totp(u["id"]):
        return None
    req, _ = self._global_chain()
    if not (req and "totp" in _chain.factors(req)):
        return None
    # Only for a step the account cannot cover with what it HAS (attack round B, F2) — the rule of the setup
    # pass (`_setup_missing`). With alternatives (`["password", "totp|pin"]`) the password alone otherwise set
    # up a TOTP for the step the account covers with its PIN, and the confirmation code completed the chain:
    # the PIN was never asked, and whoever knew the password kept an own second factor. A TOTP that fills an
    # uncovered step replaces nothing — every factor satisfies one step, so the ones the account has are still
    # asked (`password → totp → pin` keeps asking for the PIN after the setup). A setup window opened by the
    # operator lifts it, as for the passkey below.
    account = self.store.get_user(u["id"])
    window = account["mfa_enroll_until"] if account else None
    needed = any("totp" in options for _, options in self._setup_missing(u["id"]))
    if not needed and not (window and int(window) > _manager._now()):
        self.audit("mfa_enrollment_denied", str(account["username"]) if account else None,
                   detail="the account covers every step of the chain with the factors it has")
        return None
    if self.store.list_webauthn(u["id"]):
        # If the account already has a strong second factor (passkey), it sets up a
        # further one only if it presented it in THIS session — or in a window
        # that the operator has explicitly opened (lost device; the window wins
        # as in `mfa_enrollment_allowed`). Otherwise the mailbox would set up a second
        # factor for itself and bypass the passkey: via the sign-in link (ASVS 6.3.6, attack on the
        # third round) or via "forgot password" and then the new password (counter-check).
        # Accounts WITHOUT a second factor may continue to — that is the deliberate price of option C.
        s = self._session_from_request(request)
        done = json.loads(s["factors_done"] or "[]") if s else []
        account = self.store.get_user(u["id"])
        window = account["mfa_enroll_until"] if account else None
        if "passkey" not in done and not (window and int(window) > _manager._now()):
            self.audit("mfa_enrollment_denied", str(account["username"]) if account else None,
                       detail="account has a passkey that is missing in this session")
            return None
    if not self.mfa_enrollment_allowed(u["id"]):
        # No silent no: whoever fails here has the correct password and stands before
        # a door that does not open. The line tells the operator which route remains.
        #
        # **Without `log_event`**, i.e. without the word the fail2ban jail matches on: this
        # is not a failed attempt. Whoever gets this far has entered their correct password
        # — having them locked out for that as well would be exactly backwards. The
        # name comes from the freshly fetched account row, not from the request.
        account = self.store.get_user(u["id"])
        security.seclog.warning(
            "mfa enrollment denied user=%s kind=%s — the second factor is missing and may not "
            "be set up here any more. Route: auth.grant_mfa_enrollment(uid) or the "
            "admin panel.",
            security.for_log(str(account["username"]) if account else "?"),
            self.cfg.mfa_enrollment)
        self.audit("mfa_enrollment_denied", str(account["username"]) if account else None,
                   detail=f"kind={self.cfg.mfa_enrollment}")
        return None
    return u


def mfa_enrollment_allowed(self, user_id: int, now: Optional[int] = None) -> bool:
    """May this account set up the factor required by the chain **itself**? (R3-1)

    Three operating modes (`cfg.mfa_enrollment`), plus a window opened by the operator
    that always wins — that is the way for every account to which the operating mode would otherwise
    deny it (admin panel, invitation, `grant_mfa_enrollment`).

    The danger at stake: whoever had the password of an **existing** account used to bind
    their own authenticator. For an account that has never been used, the
    risk is a different one — there the first person to sign in is the rightful one, just as with an
    invitation link.
    """
    now = _manager._now() if now is None else int(now)
    u = self.store.get_user(user_id)
    if not u:
        return False
    window = None
    try:
        window = u["mfa_enroll_until"]
    except (IndexError, KeyError):
        window = None            # file from before schema 8
    if window and int(window) > now:
        return True
    kind = str(self.cfg.mfa_enrollment or "first_login")
    if kind == "strict":
        return False
    if kind == "grace":
        days = max(0, int(self.cfg.mfa_enrollment_grace_days or 0))
        return (now - int(u["created_at"])) <= days * 86400
    # "first_login": allowed as long as this account has never been fully signed in.
    try:
        return u["first_login_at"] is None
    except (IndexError, KeyError):
        return True               # file from before schema 8: the chance remains


def grant_mfa_enrollment(self, user_id: int, minutes: int = 60) -> int:
    """Open a setup window and return its expiry.

    The operator's way if someone has lost their device or `mfa_enrollment="strict"`
    applies. Deliberately time-limited: a permanently open window would be the old gap under a
    new name."""
    until = _manager._now() + max(1, int(minutes)) * 60
    self.store.set_mfa_enroll_until(user_id, until)
    u = self.store.get_user(user_id)
    self.audit("mfa_enrollment_granted", str(u["username"]) if u else None,
               detail=f"minutes={minutes}")
    return until


def revoke_mfa_enrollment(self, user_id: int) -> None:
    """Close an open enrollment window immediately."""
    self.store.set_mfa_enroll_until(user_id, None)
    u = self.store.get_user(user_id)
    self.audit("mfa_enrollment_revoked", str(u["username"]) if u else None)


def _rotate_csrf(self, response) -> str:
    """Set a fresh CSRF token — at login.

    The naive double-submit is considered vulnerable to *cookie injection*: whoever can set a cookie via a
    subdomain sets a matching CSRF pair along with it. The OWASP
    CSRF Prevention Cheat Sheet therefore recommends binding to "a session-dependent value
    that changes with each login". Renewing the token at sign-in is the cheap
    part of that and costs nothing.

    Since 0.20.1 `set_cookie()` calls the method itself as soon as the token belongs to a just
    signed-in session — every sign-in route, including an own route of the app with
    `start_session` + `set_cookie`. Up to 0.20.0 this happened only at the end of a TOTP step,
    although this docstring promised it for every login. Only whoever builds a
    sign-in without `set_cookie()` has to call it directly. Replaces a CSRF line that the response already carries.
    """
    return self.issue_csrf(response)

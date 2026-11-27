"""TinySesam — central auth class. Orchestrates store, password, TOTP, (optional) OIDC & passkey.

Integration:
    from tinysesam import TinySesam, TinySesamConfig
    auth = TinySesam(TinySesamConfig(db_path="app.db", rp_id="app.example.com", origin="https://app.example.com"))
    auth.ensure_admin("admin", "startpw")          # create the first admin (only if there is none)
    app.include_router(auth.router())              # /auth/* routes + login UI
    @app.get("/secret")
    def secret(user = Depends(auth.require_user)):  # protected
        return {"hi": user["username"]}
"""
from __future__ import annotations
import re
import sys
from collections import OrderedDict
import secrets
import contextlib
import contextvars
from typing import Any, Callable, Literal, NoReturn, Optional, cast

from fastapi import Request, HTTPException

from . import _features
from .errors import ConfigError
from .config import TinySesamConfig
from .store import Store, key_kind_of, name_invalid, role_invalid, norm_identifier, now as _now, wall_now as _wall_now
from . import passwords as _passwords
from . import passwords as _pw
from .templates import PREFIX_PLACEHOLDER as _PREFIX_PLACEHOLDER, Templates
from . import security
from .ldap_ import CONNECTION_TIMEOUT as _LDAP_TIMEOUT

#: IP and signed-in account of the request currently being handled (B5-02, B5-04).
#:
#: The account methods (`totp_disable`, `create_api_key`, `create_invite`, …) get no
#: request — they can also be called without one. Their audit lines therefore had no IP and
#: no account (`detail="user=5"`), and `tinysesam audit --user X` did not find them. The value
#: is set where TinySesam resolves the request anyway (`current_user` and
#: related methods); `audit()` reads it. A ContextVar, not an instance variable: it applies per
#: request (per asyncio task or per thread-pool call) and cannot leak into a parallel one.
_REQUEST: contextvars.ContextVar = contextvars.ContextVar("tinysesam_request", default=None)


# Sets nonce="…" in every <script>/<style> that has none yet. Central, instead of threading the
# nonce through every template function. Safe, because none of the built-in pages emits the
# string "<script"/"<style" INSIDE a JS string (checked) — only real tags.


def _host_from(value: str) -> str:
    """Only the host name of an address — or "" for a broken one (open IPv6 bracket etc.).

    Needed as the key for `security.report_once()`: the notice belongs to the host,
    not to the individual URL — otherwise every new path lifts the suppression and the log flood
    is back.
    """
    from urllib.parse import urlsplit
    try:
        return urlsplit(str(value or "")).hostname or ""
    except ValueError:
        return ""


class _DictHeaderLines:
    """The three accesses that `_header_lines_in` needs, on top of a plain dict.

    Lookup is case-insensitive; writes go to the key that already exists — otherwise under the
    spelling passed in. That way `exc.headers["Location"]` stays readable.
    """
    def __init__(self, d: dict):
        self.d = d

    def _key_name(self, name: str):
        return next((k for k in self.d if k.lower() == name.lower()), None)

    def get(self, name: str, default=None):
        k = self._key_name(name)
        return default if k is None else self.d[k]

    def setdefault(self, name: str, value: str):
        if self._key_name(name) is None:
            self.d[name] = value

    def __setitem__(self, name: str, value: str):
        self.d[self._key_name(name) or name] = value


#: The `hsts` values a browser understands (RFC 6797 §6.1): max-age, then optionally the two flags.
_HSTS_RE = re.compile(r"max-age=\d{1,10}([ \t]*;[ \t]*includeSubDomains)?([ \t]*;[ \t]*preload)?", re.I)


class _HSTSMiddleware:
    """Adds `Strict-Transport-Security` to every HTTPS response (`install_https`, `https_mode='force'`).

    Pure ASGI instead of `BaseHTTPMiddleware`: it only touches the start message, streaming
    responses pass through unchanged. The scheme is the one the server determined — behind a TLS
    proxy that is the forwarded one, as for the HTTPS redirect next to it."""

    def __init__(self, app, value: str):
        self.app, self.value = app, value

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("scheme") != "https":
            return await self.app(scope, receive, send)

        async def send_with_hsts(message):
            if message.get("type") == "http.response.start":
                from starlette.datastructures import MutableHeaders
                MutableHeaders(scope=message).setdefault("Strict-Transport-Security", self.value)
            await send(message)

        return await self.app(scope, receive, send_with_hsts)


def _dn_parts(value: str) -> list[str]:
    """Split a DN at the UNescaped commas (`cn=a\\,b,ou=x` has two parts, not three)."""
    parts, current, masked = [], [], False
    for char in str(value):
        if masked:
            current.append(char)
            masked = False
        elif char == "\\":
            current.append(char)
            masked = True
        elif char == ",":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    parts.append("".join(current).strip())
    return parts


def group_fits(key_name, group, substring: bool = False, dn: bool = False) -> bool:
    """Does the key from `*_group_role_map`/`ldap_allowed_groups` match this group?

    `substring=True` is the old comparison (`key_name in gruppe`) and exists only on
    explicit request (`group_match="substring"`). Up to 0.19.x it applied to LDAP ALWAYS,
    whatever `group_match` said (F-19): `admin` then matched `cn=nicht-admin,…` and
    `staff` matched `cn=staffextern,…` — whoever may name a group in the directory got
    the role and the admin flag.

    `dn=True` (LDAP, `memberOf` delivers whole DNs) compares **exactly**, but by components:
    the whole DN, a **prefix** of whole RDNs (`cn=staff` or `cn=staff,ou=groups` — the
    partial DN without the base, as the README shows it in its example) or the value of the first RDN
    (`staff`). Case does not matter there — LDAP compares names that way, and `CN=Staff,OU=Groups`
    is the same group. This keeps the familiar spelling valid, without a name fragment
    hitting a foreign group: only whole components are compared, starting at the front.
    """
    s, g = str(key_name), str(group)
    if not s:
        return False
    if substring:
        return s in g
    if s == g:
        return True
    if not dn or "=" not in g:
        return False
    g_parts = [t.lower() for t in _dn_parts(g)]
    if "=" in s:
        # Whole DN or partial DN from the front (A-3): `cn=admins,ou=g` matches
        # `cn=admins,ou=g,dc=example,dc=com`. Until the first fix of this round the substring
        # covered that; without this branch a key written that way silently dropped out after the
        # update — admin mapping gone, or, as ldap_allowed_groups, every user rejected.
        s_parts = [t.lower() for t in _dn_parts(s)]
        return g_parts[:len(s_parts)] == s_parts
    _, _, value = g_parts[0].partition("=")
    return s.strip().lower() == value.strip()


def _substring_notice(key_name, groups, slot: str) -> None:
    """Say once per key when it would only match as a substring now (A-3).

    Up to 0.19.x LDAP always compared by substring (F-19). A key that matched back then and
    no longer does costs roles after the update, silently, or — in `ldap_allowed_groups` — all
    access. It cannot be detected statically (it depends on the directory's DNs),
    so it surfaces at the first login where it happens."""
    s = str(key_name)
    if not s or not any(s in str(g) for g in groups):
        return
    if any(group_fits(s, g, dn=True) for g in groups):
        return
    if security.report_once(f"ldap_substring:{slot}:{s}"):
        security.seclog.warning(
            "LDAP: the key %r in %s only matches as a substring (%s) and has no effect since "
            "0.20.0 — comparison is by DN components. Change the spelling "
            "(whole DN, partial DN from the front like 'cn=admins,ou=groups', or just the CN) or "
            "set group_match='substring'.", security.for_log(s), slot,
            security.for_log(next(str(g) for g in groups if s in str(g)))[:200])


def _on_stderr(line: str) -> None:
    """One line to the operator, not to the log.

    The route is deliberately `sys.stderr` and not `seclog`: what is written here is meant for the
    human who starts the service — not for a file that fail2ban reads, logrotate
    archives and a log shipper takes along (B5-03). `sys.stderr` is looked up afresh on every
    call, so that a redirected stderr (tests, wrappers) really takes effect.
    """
    try:
        sys.stderr.write(line.rstrip("\n") + "\n")
        sys.stderr.flush()
    except Exception:
        pass            # no stderr (pythonw, closed descriptor) — no reason to abort


def _stderr_is_console() -> bool:
    """Is a human reading along, or is someone collecting stderr (container, journal, pipe)?

    In a container stderr IS the log (`docker logs`), under systemd the journal. What is meant
    "for the operator's console only" must then not go there (finding from operations,
    2026-09-27). Like `_on_stderr`, looked up afresh on every call.
    """
    try:
        return bool(sys.stderr is not None and sys.stderr.isatty())
    except Exception:
        return False


#: What is accepted as a CSRF token from a cookie (0.20.1). Only URL-safe characters — nothing
#: that does harm in an HTML attribute, a header or a cookie line —, at least
#: as long as what TinySesam rolls itself (`token_urlsafe(24)`: 32 characters, 192 bits),
#: at most 128. A cookie that looks different is replaced instead of written into a form.
_CSRF_FORM = re.compile(r"[A-Za-z0-9_-]{32,128}")

#: Under this key in the ASGI scope a request remembers the token it freshly rolled
#: — so that `csrf_token(request)` before rendering and `ensure_csrf(request, response)` after
#: return the same thing. The scope belongs to exactly one request; nothing leaks into another.
_CSRF_SCOPE = "tinysesam.csrf_new"

#: How many just-signed-in sessions, not yet set in the cookie, a process remembers.
#: Between `_create_session()` and `set_cookie()` lies one request; the limit only catches
#: custom routes that create a session and never set a cookie.
_FRESH_MAX = 1024


def _samesite(value: str) -> Literal["lax", "strict", "none"]:
    """The constructor allows only these three values (see TinySesam.__init__); this states it
    once more for the type checker, which does not follow the guarantee from there."""
    return cast(Literal["lax", "strict", "none"], value)


def _proof_true(value) -> bool:
    """Does an LDAP/SAML attribute say "this address is verified"? Only explicitly true values
    count (True, "true", "1", "yes", "ja"); anything else — also a missing attribute — does not."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("true", "1", "yes", "ja")


def _proof_on_account(user) -> bool:
    """The `users.email_verified` marker of an account row.

    If the column is missing — a row from a foreign source, a test setup with a
    dictionary —, "confirmed" applies: exactly the state of every installation before this column,
    so no silent tightening for existing data. Where a sign-in path knows better,
    the evidence travels along as a parameter (`_maybe_promote_admin(user, email_confirmed=…)`)
    and wins."""
    try:
        return bool(user["email_verified"])
    except (IndexError, KeyError, TypeError):
        return True


#: Which switch needs which extra — switch → (module, extra).
#: Stated here, not in the test: a copy in tests/ would silently go stale with the next new
#: method. The test now checks AGAINST this table.
SWITCH_REQUIRES_EXTRA = {
    "passkey_enabled": ("webauthn", "passkey"),
    "oidc_enabled": ("authlib", "oidc"),
    "saml_enabled": ("onelogin", "saml"),
    "ldap_enabled": ("ldap3", "ldap"),
}



def _valid_rules(rules) -> list:
    """Only the rules whose keys are populated.

    A rule "per account" without an account would otherwise silently become one "per address"
    with the wrong boundary (`count_fails` simply drops an empty filter)."""
    return [r for r in rules
            if all(r[2].get(k) for k in ("username", "ip") if k in r[2])]

def _messages_of_language(auth) -> dict:
    from .messages import MESSAGES
    return MESSAGES.get(auth.cfg.lang) or MESSAGES["en"]


#: What other modules take from here although this file does not use it: the building blocks read the clock and these
#: constants through `manager` (tests and the vector generator replace `_now`/`_wall_now` here), and the templates the
#: prefix placeholder (T-112).
__all__ = ["TinySesam", "_now", "_wall_now", "_PREFIX_PLACEHOLDER", "_HSTS_RE", "_CSRF_FORM", "_FRESH_MAX",
           "SWITCH_REQUIRES_EXTRA"]

#: Where each method of `TinySesam` that is not in this file lives: building block -> method names (T-112). A building
#: block is the module `tinysesam/_manager_<part>.py`, imported on the first use of one of its methods — a feature that
#: is switched off never calls them and never loads its code. `tests/test_store_parts.py` pins index and modules.
_PART_METHODS = {
    "account": (
        "_allowlist_address", "_change_request_notice", "_checked_base",         "_csp_report_line", "_frame_app",         "_header_lines_error", "_own_session_rows",         "_request_change", "_send_signup_notice", "account_overview",         "change_username", "confirm_email_change", "public_base", "request_email_change", "require_public_base",
        "send_login_link",
    ),
    "apikeys": (
        "_app_password_log", "_app_password_user", "_app_passwords_revoked", "_idp_no",
        "_is_app_password_locked", "_key_log", "_key_rests", "_keys_revoked", "_once_per",
        "_password_alone_possible", "_password_min_length", "_services", "_services_revoked", "api_key_kind",
        "create_api_key", "create_app_password", "create_service",
        "create_service_pairing", "list_api_keys", "list_app_passwords", "list_service_clients",
        "password_policy_error", "revoke_api_key", "revoke_app_password", "revoke_service_client",
        "set_password", "verify_api_key",
    ),
    "cookies": (
        "_cookie_name", "_csrf_dispensable", "_csrf_in_response", "_csrf_of_request", "_delete_cookie",
        "_delete_csrf_cookie", "_delete_flow_cookie", "_delete_old_names", "_old_names", "_origin_ok",
        "_own_hosts", "_set_csrf_cookie", "_set_flow_cookie", "_verify_csrf", "count_other_sessions",
        "ensure_csrf", "flow_cookie_name", "issue_csrf", "logout", "require_csrf", "rotate_session",
        "set_cookie",
    ),
    "factors": (
        "_account_factors", "_attempt_failed", "_begin_attempt", "_begin_setup", "_chain_satisfied",
        "_check_lock", "_check_password", "_check_pin", "_default_satisfied", "_deferred", "_directory_password",
        "_factor_entry",
        "_global_chain", "_is_password_change_locked", "_is_pin_locked", "_is_reauth_locked",
        "_is_resource_locked", "_is_totp_setup_locked", "_link_allowed", "_link_requires", "_mfa_pending",
        "_next_factor", "_next_login_step", "_next_login_step_factors", "_password_change_owed",
        "_password_repeated", "_rc_hash", "_revert_attempt", "_rules", "_rules_pin", "_series_full",
        "_series_reset_helps", "_series_way_out", "_session_ok", "_settable_factors", "_setup_blocker",
        "_setup_complete", "_setup_finished", "_setup_missing", "_setup_offer", "_setup_ok", "_setup_owed",
        "_setup_record", "_setup_session", "_setup_step", "_setup_user", "_setup_window", "_sign_in_complete",
        "_totp_step", "_verify_directory_password", "_verify_recovery_code", "_verify_totp", "_verify_user_password",
        "_verify_user_pin",
        "_wait_pending", "_webauthn_user_handle", "_window_start", "disable_pin", "federated_only", "find_user",
        "generate_recovery_codes", "has_pin", "json_body", "recovery_codes_remaining", "remove_passkey",
        "send_password_reset", "set_pin", "stepup_options", "totp_begin", "totp_confirm", "totp_disable",
    ),
    "fastapi": (
        "_bolt", "_install_hsts", "_is_secure", "_oauth_revoke_user", "_oauth_server",
        "_recheck", "admin_router", "close", "install_error_pages", "install_https", "router",
    ),
    "forward": (
        "_account_kind", "_approval_private", "_approval_ring", "_delete_gate_cookie", "_forward_app",
        "_forward_header_map", "_forward_login_url", "_forward_response_headers", "_forward_values",
        "_forwarded_conflict", "_forwarded_url", "_gate_cookie", "_gate_host", "_gate_hosts",
        "_gate_link_session", "_gate_link_url", "_gate_session", "_gate_set_cookie", "_login_schema",
        "_oidc_application", "_oidc_approval_valid", "_record_oidc_approval",         "approval_jwks", "gate_issuer", "gate_jwks", "gate_public_key",
    ),
    "hardening": (
        "_check_secure_flag", "_csp_header", "_csp_reporting", "_form_destinations", "_frame", "_frame_of", "_header_lines", "_header_lines_in", "_prefix", "_set_csp", "browser_path", "safe_next",
        "_account_name", "_approvals", "_approvals_pending", "_check_app_accounts",
        "_check_orphaned_app_accounts", "_check_role_catalog", "_claim_for_audit", "_cleanup_limit",
        "_end_series", "_fail_reason", "_is_locked", "_lift_after_sign_in", "_lockout_notice", "_panel_actions",
        "_provisioning", "_rate_ok", "_record_login", "_rejected", "_remember_request", "_sec", "add_messages",
        "all_security", "audit", "client_ip", "csrf_token", "gc", "lift_lockout", "render_page",
        "set_rate_limiter", "set_security", "set_template", "t", "topbar", "topbar_data", "topbar_head",
        "version",
    ),
    "ldap": (
        "_check_ldap", "_federation_since", "_identifier_two_accounts", "_ldap_bind", "_ldap_name_proven",
        "_ldap_trusted",
        "_name_binding_permitted", "_name_deadline_unclosed", "_rebinding_reason",
        "_report_name_binding_inventory", "_resolve_foreign_identity", "federation_bind_existing",
        "federation_unbind",
    ),
    "federated_link": (
        "_bind_identity", "_finish_saml_link", "_identities_view", "_link_directory", "_linked_sources",
        "_other_way_in", "_unlink_identity",
    ),
    "permissions": (
        "_known_roles", "_permission_app", "_register_config_permissions", "_sync_permissions", "app_permissions",
        "delete_permission", "grant_permission", "has_permission", "permissions_of", "register_permissions",
        "require_permission", "revoke_permission",
    ),
    "links": (
        "_app_link_refused", "_duration", "_signin_link", "_verify_mail", "create_invite", "create_magic_token",
        "create_signin_link", "magic_url", "peek_magic", "redeem_magic", "send_verify_email",
    ),
    "mail": (
        "_access_notice", "_mail_destination_ok", "_security_event", "_token_hash", "_token_mail",
        "_token_rejected", "after_response", "ensure_admin", "mail_configured", "send_mail", "set_mailer",
    ),
    "qr": (
        "_qr_approve", "_qr_deny", "_qr_hash", "_qr_links", "_qr_may_approve", "_qr_own", "_qr_peek",
        "_qr_redeem", "_qr_start",
    ),
    "resource": (
        "_check_resource", "_unlock_resource", "list_resource_secrets", "remove_resource_secret",
        "require_resource", "resource_unlocked", "set_resource_secret",
    ),
    "saml": (
        "_address_proven_by_source", "_check_saml", "_saml_identifier",
    ),
    "signin": (
        "_extract_api_key", "app_password_hosts",
        "_after_the_factor", "_confirm", "_confirms_at_oidc", "_confirms_at_provider", "_confirms_at_saml",
        "_counts_as_stepup", "_create_session",
        "_enforce", "_enforce_route_chain", "_first_password", "_fresh_enough", "_login_redirect_after",
        "_note_login", "_only_with_session", "_other_after_completion", "_reauth_target", "_redeem_sign_in",
        "_redirect_factor", "_require_fresh", "_reserve_sign_in", "_setup_password", "_sign_in_locked",
        "_sign_in_no", "_signed_in", "_stay_chosen", "_stepup_secret", "_successor", "_ttl", "apply_factor",
        "change_password", "complete_totp", "confirm_password", "confirm_pin", "confirm_totp", "login_fresh",
        "login_password", "login_pin", "login_totp", "require", "require_admin", "require_mfa", "require_role",
        "require_session", "require_user", "set_initial_password", "start_session", "stepup_fresh",
    ),
    "group_import": ("_check_idp_catalog", "_import_idp_groups"),
    "users": (
        "_account_of_session", "_admin_claim_announce", "_admin_claim_failure", "_admin_panel_visible",
        "_catalog_actor", "_claim_file_auto", "_claim_file_away", "_consume_admin_claim", "_create_account",
        "_delegate_scopes", "_delegation", "_determine_current_user", "_first_owner", "_lock_audit",
        "_lock_effects", "_maybe_promote_admin", "_mercy", "_oidc_recheck", "_oidc_swap", "_pin_chain_step",
        "_purge_demo", "_precreated_by_mail", "_remember_oidc_session", "_renew_password", "_renew_session", "_renew_user",
        "_reset_access", "_rotate_csrf", "_seed_demo", "_session_from_request", "_strip_delegate_roles",
        "admin_claim_token", "admin_exists", "apply_idp_groups", "create_role", "create_user", "current_user",
        "delete_role", "delete_user", "get_user", "grant_mfa_enrollment", "has_role", "identifier_taken",
        "is_admin", "known_roles", "mfa_enrollment_allowed", "own_events", "pending_user",
        "revoke_mfa_enrollment", "role_catalog", "role_usage", "session_user", "set_disabled", "set_owner",
        "set_roles", "totp_enrollment_user", "user_roles",
    ),
}
_PARTS = {name: part for part, names in _PART_METHODS.items() for name in names}


class _BuildingBlocks(type):
    """Loads a building block on the first access to one of its methods (on the class or on an instance), fixes the
    method on the class, and lists the indexed names in `dir()` so introspection sees the whole class (T-112)."""

    def __getattr__(cls, name):
        part = _PARTS.get(name)
        if part is None:
            raise AttributeError(f"type object {cls.__name__!r} has no attribute {name!r}")
        import importlib
        setattr(cls, name, getattr(importlib.import_module(f"{__package__}._manager_{part}"), name))
        return getattr(cls, name)

    def __dir__(cls):
        return sorted(set(super().__dir__()) | set(_PARTS))


class TinySesam(metaclass=_BuildingBlocks):
    # Raising helpers stay in the class (typed `NoReturn`): type checkers narrow after them in every building block.
    def _deny(self, request: Request) -> NoReturn:
        # HTML browser → redirect to login; otherwise (API/JSON) → 401
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.browser_path(request, self.cfg.login_path)}?next={nxt}"})
        raise HTTPException(401, self.t("api.not_signed_in"))

    def _deny_stepup(self, request: Request) -> NoReturn:
        # signed in, but factor not fresh. Browser → redirect to /auth/reauth; otherwise 403 + hint header.
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.browser_path(request, '/auth/reauth')}?next={nxt}"})
        raise HTTPException(403, self.t("api.stepup"),
                            headers={"X-TinySesam-Reauth": self.browser_path(request, "/auth/reauth")})

    def _refuse_derived_keys(self) -> None:
        """Refuse to start while a gate key or pepper derived from the vault key (≤ 0.25.x) is still in a keyring.

        0.26–0.30 kept it as a previous key, so tokens and connections of 0.25.x ran out instead of being cut. Since
        the schema baseline (T-111) nothing derives it any more — and as long as it stays, whoever holds the vault
        key alone can compute it: a gate key a proxy may still trust, a pepper that looks up stored digests. The
        message names the key and the command that removes it (`tinysesam keys retire`, docs/OPERATIONS.md
        "Updating")."""
        from .errors import ConfigError
        from . import keys as _keys
        found = []
        for ring in (self._gate_keyring, self._pepper_keyring):
            for k in ring.keys:
                if k.note != self._BASE_KEY_NOTE:
                    continue
                if ring.origin in ("environment", "file"):
                    where = (f"remove it from {_keys.ENV[ring.purpose]}_PREVIOUS" if ring.origin == "environment"
                             else f"remove its line from {ring.path}")
                else:
                    where = (f"tinysesam keys retire --db {self.cfg.db_path} --purpose {ring.purpose} --kid {k.kid}"
                             + (" --force" if ring.purpose == _keys.PEPPER else ""))
                found.append(f"{ring.purpose} {k.kid}: {where}")
        if found:
            raise ConfigError("A key derived from the vault key by a version up to 0.25.x is still in a keyring (note "
                              f"{self._BASE_KEY_NOTE}); this version no longer starts with it. Remove it, then start "
                              "again — `tinysesam keys list` shows the keys:\n  " + "\n  ".join(found))

    def __getattr__(self, name) -> Any:
        """A method of a building block (`_PARTS`): the class loads it, the instance gets it bound (T-112)."""
        if name not in _PARTS:
            raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")
        getattr(type(self), name)
        return object.__getattribute__(self, name)

    def __init__(self, config: TinySesamConfig):
        self._bolt(config, on_setup=True)
        self.cfg = config
        self.store = Store(config.db_path)
        # The building blocks of the features this configuration switches on (T-112); the others never load.
        _features.load_enabled(config)
        self.store.idle_sec = (max(0, int(config.session_idle_minutes or 0)) * 60,
                                   max(0, int(config.session_idle_minutes_remember or 0)) * 60)
        # Secrets at rest only encrypted (H-14/H-15, mandatory). The vault keyring comes from the environment, the
        # configuration or next to the database; a wrong one aborts startup (`extract_secrets`, BEFORE anything else
        # reads or writes an encrypted value).
        from . import keys as _keys
        from . import vault as _vault
        self._vault_keyring = _keys.load_vault(config.db_path, config.secrets_key_file)
        self._key_name_origin = self._vault_keyring.origin
        self.store.vault = _vault.Vault(self._vault_keyring,
                                        reload=_keys.reloader(config.db_path, config.secrets_key_file))
        self.store.extract_secrets()
        # Gate token (ADR-9, T-19) — since T-48 a random key of its own, never derived from the vault key: whoever
        # reads the vault key alone mints no gate token. Always loaded, even when the gate is off: `tinysesam
        # gate-key` should be able to prepare the proxy before the switch is flipped.
        self._gate_keyring = _keys.load_stored(_keys.GATE, self.store, str(config.gate_key_file or ""))
        self._gate_key_name = _keys.gate_private(self._gate_keyring.active.material)
        # Approvals of application actions (stage B): the confirmations get a key of their OWN (purpose `approval`,
        # ADR-12) — never the gate key, which the proxy trusts without checking `typ`. Loaded (and on the first start
        # created) only with approvals switched on; `_approval_ring` loads it later if the switch is set afterwards.
        self._approval_keyring: Any = None
        if config.approvals_enabled:
            self._approval_ring()
        # Key for the password fingerprints, per process and only in memory: a leaked memory dump is no
        # dictionary target against the typos of the real passwords without it — and it never touches the vault.
        self._pw_repetition_key_name = secrets.token_bytes(32)
        # OAuth (T-36): the pepper of the token digests, a key of its own like the gate key (ADR-12). The server
        # itself is built with the router (`_oauth_server`) — the switch may be set after construction.
        self._pepper_keyring = _keys.load_stored(_keys.PEPPER, self.store, str(config.oauth_pepper_file or ""))
        self._refuse_derived_keys()
        # Session handles (T-71): an HMAC with the same keyring instead of a plain sha256, so that write access to
        # the file alone no longer mints a session.
        self.store.session_peppers = tuple(k.material for k in self._pepper_keyring.keys)
        self._oauth: Any = None
        if config.oauth_enabled:
            self._oauth_server()
        # B6-8: Without the [argon2] extra every sign-in against an argon2 hash fails — until
        # now without a word, the account just looked like "wrong password" to the user.
        # At startup, count and say how many it affects; startup itself stays possible
        # (passkey, OIDC and SSO do not depend on it, and a service that no longer comes up
        # at all because of a missing package would be the bigger outage).
        if not _passwords.argon2_available():
            affected = self.store.count_argon2_hashes()
            if affected:
                security.seclog.error("%s (%d affected hashes)", _passwords.ARGON2_MISSING, affected)
        self.store.audit_ip_pseudonym = bool(config.audit_ip_pseudonymize)
        self._log_throttle: dict = {}   # see `_once_per`
        # Just fully signed-in sessions (handle) whose cookie is not set yet — see
        # `_create_session` and `set_cookie` (CSRF rotation at sign-in, 0.20.1).
        from collections import OrderedDict
        import threading
        self._fresh_sign_ins: "OrderedDict[str, None]" = OrderedDict()
        self._fresh_lock = threading.Lock()
        self.templates = Templates()
        self._messages: dict = {}
        self._mailer_override = None
        from .mailer import Outbox
        self._outbox = Outbox()
        # Own small outbox for lockout notices (ASVS 6.3.5): it is filled by whoever sends
        # failed attempts — a flood must not displace sign-in links and resets in the main outbox.
        self._notice_outcome = Outbox(worker=1, max_unclosed=50)
        # The OIDC re-check (4a) exchanges refresh tokens in the background: a hanging provider
        # would otherwise hold every due request until the timeout — from `async` routes including the event loop
        # (attack on the second round, finding 6, same class as B6-6).
        self._oidc_outcome = Outbox(worker=2, max_unclosed=200)
        self._closed = False          # `close()` (T-67)
        #: Opt-in notification for security events on one's own account (finding B2-2,
        #: recommendation H-6) — see `SECURITY_EVENTS`. Call `hook(event, account,
        #: details)`; `account` has `id`, `username`, `email`, `display_name`. TinySesam
        #: sends nothing itself: which mail, which channel, which language is decided by
        #: the app.
        self.on_security_event: Optional[Callable[[str, dict, dict], Any]] = None
        self._blocklist = self._load_blocklist(config.password_blocklist_file)
        # Attempt ID → (identifier, method, series state after booking) for the series
        # pre-booked in `_begin_attempt` (B2-6). In memory is enough: if the process dies
        # in between, the pre-booking remains as a failed attempt — stricter in doubt.
        self._series_prebookings: dict = {}
        # Fingerprints of wrong passwords per (account, IP) — memory only, never on disk (`_password_repeated`).
        self._pw_repetition: "OrderedDict[tuple, list]" = OrderedDict()
        self._pw_repetition_lock = threading.Lock()
        # Waiting slots for sign-ins that would not get further only because of pending
        # pre-bookings (G9, `_begin_attempt`) — capped, so waiters do not occupy all worker threads.
        self._pending_places = threading.BoundedSemaphore(self._PENDING_WAIT_SLOTS)
        self.oidc = None
        self.webauthn = None
        self.ldap = None
        # The failure marker hangs on the manager, not on the client: it also applies to a client
        # set by hand (`auth.ldap = own_client`) — rationale at `FailureMarker`.
        from .ldap_ import FailureMarker
        self._ldap_failure = FailureMarker()
        self.saml = None
        if config.security_log:
            security.attach_security_log(config.security_log)
        # Both limiters have the same `allow()` interface; `Any` says that without introducing
        # a Protocol for two implementations.
        self.rl: Any = security.RateLimiter()
        if config.redis_url:
            try:
                self.rl = security.RedisRateLimiter(config.redis_url)
            except Exception:
                security.seclog.warning("Redis rate limit unavailable → in-memory fallback")
        # A missing extra here is an operational error and not a subtlety: the setup
        # fails with the name of the package instead of a ModuleNotFoundError from the depths
        # or — worse — only at the first sign-in attempt as a 500.
        #
        # Checked here and not in the constructor head, on the condition "is the method
        # COMPLETELY configured": whoever sets `oidc_enabled=True` but no
        # `issuer` obviously wants to bring the client themselves (`auth.oidc = …`) — four
        # own suites work that way. A guard that triggers on the switch already forbids
        # that route. That a half-configured method gets noticed is done by config_check.
        # `find_spec` instead of an import attempt: the extras are imported LAZILY everywhere
        # (only on connect, on token exchange, when checking an assertion). A missing
        # package therefore did not show at setup but at the first sign-in attempt — as a
        # 500 from inside the library.
        # Warn, do not raise. A client can be replaced (`auth.ldap = own_client`),
        # and four own suites work exactly that way — a guard that aborts here forbids
        # that. Raising happens at the place where it can never be wrong: at the lazy import
        # in the respective module. The operator thus sees it at startup in the log and, if they
        # overlook that, at the first sign-in attempt as a readable `MissingExtra` instead of a 500.
        def _demand(module, switch, extra):
            import importlib.util as _ilu
            try:
                da = _ilu.find_spec(module) is not None
            except (ImportError, ValueError):
                da = False
            if not da:
                security.seclog.warning(
                    "%s=True, but the extra [%s] is not installed (pip install "
                    "'tinysesam[%s]') — the module '%s' is missing. Unless the client is set "
                    "separately, sign-in via this method will fail.",
                    switch, extra, extra, module)

        if config.ldap_enabled and config.ldap_url:
            _demand("ldap3", "ldap_enabled", "ldap")
            from .ldap_ import LDAPClient
            self.ldap = LDAPClient(config)
        if config.saml_enabled and config.saml_idp_sso_url and config.saml_idp_x509cert:
            _demand("onelogin", "saml_enabled", "saml")
            from .saml_ import SAMLClient
            self.saml = SAMLClient(config, store=self.store)   # store: replay protection (H1)
        if config.oauth_enabled and config.oauth_service_clients:
            # Services (T-60): every token request is a signed assertion — without the library nothing can be
            # checked, and pairing and token requests answer `server_error` (fail-closed). Warned like every extra.
            _demand("joserfc", "oauth_service_clients", "services")
        if config.oidc_enabled and config.oidc_issuer and config.oidc_client_id:
            _demand("authlib", "oidc_enabled", "oidc")
            from .oidc import OIDCClients, DEFAULT_CLIENT
            # `self.oidc` stays the single client and with it the public surface of 0.18.0
            # (tests and foreign code access it). `self.oidc_clients` is the mapping
            # host → client; without `cfg.oidc_clients` it contains exactly this one (T-14).
            self.oidc_clients = OIDCClients(config)
            self.oidc = self.oidc_clients[DEFAULT_CLIENT]
        if config.passkey_enabled:
            # Passkey has no incomplete configuration: whoever flips the switch means it.
            _demand("webauthn", "passkey_enabled", "passkey")
            from . import webauthn_ as wa
            self.webauthn = wa
        if config.demo_mode and not self.store.get_setting("demo_users") \
                and self.store.user_count() > 0:
            # The one technical barrier a genuine demo never hits (B3-8): a demo
            # starts on an EMPTY database — there it creates its accounts and remembers them
            # (`demo_users`), every later start recognises them, even with visitors registered
            # in the meantime. Whoever switches `demo_mode` on for the first time on a database
            # that already has accounts, switches it on for existing data — i.e. in
            # production. Before, that silently created an admin account with a known password.
            raise ConfigError(
                "demo_mode=True on a database that already has accounts and was never a demo "
                f"({config.db_path!r}). The demo creates an admin account with a known password — "
                "on existing data that is a backdoor. For a demo use a separate, empty "
                "database (db_path).")
        if config.demo_mode:
            security.seclog.warning(
                "DEMO MODE active: example accounts %s with a known password. DO NOT run in production.",
                ", ".join(self._DEMO_USERS))
            self._seed_demo()
        elif self.store.get_setting("demo_users"):
            n = self._purge_demo()                       # demo mode switched off → accounts are gone
            if n:
                security.seclog.warning("Demo mode off: %d example account(s) deleted.", n)
        # Forward auth across several hosts, but without cookie_domain: the session cookie is
        # host-only, so there is NO shared SSO — every host demands its own sign-in.
        # The login URL is built per host (see forward_login_url), so that at least no silent
        # redirect loop results. This is provable in advance, without guessing about the outside
        # world: the hosts are in our own configuration.
        # With the code exchange (T-26) host-only is exactly what is wanted: the app hosts get a
        # connection, not their own sign-in — the warning would be a false alarm there.
        if (config.forward_auth_enabled and config.base_url and not config.cookie_domain
                and not getattr(config, "gate_link_enabled", False)):
            # By host name, not the raw entry: a cookie does not separate by port (RFC 6265, 8.5), so
            # `auth.example.com:8443` shares the host-only cookie of `https://auth.example.com`.
            own = security.host_name(config.base_url)
            foreign = sorted({security.host_name(h) for h in (config.trusted_redirect_hosts or [])} - {own, ""})
            if foreign:
                security.seclog.warning(
                    "Forward auth without cookie_domain: the session cookie is host-only on %s, "
                    "not on %s. Each of these hosts demands its own sign-in (the login page "
                    "is built there). For shared SSO across subdomains set cookie_domain, "
                    "e.g. '.%s'.", own or "?", ", ".join(foreign),
                    ".".join(own.split(".")[-2:]) if own.count(".") >= 1 else "example.com")
        # Roles in accounts, but no list of known roles: the admin panel offers a free-text field for roles, and a
        # typo there silently creates a role nothing checks. The group maps are reported by config_check; this is the
        # database side.
        # Roles stored by an older version or a raw write that cannot travel as one role (T-85): named once at start,
        # never rewritten silently. The forward check refuses such an account until an administrator removes the role.
        broken = [r for r in self.store.roles_in_use() if role_invalid(r)]
        if broken:
            security.seclog.warning(
                "Accounts carry role names with a comma, a control character or surrounding spaces: %s. Forward auth "
                "refuses these accounts (403) until the role is removed in the admin panel.",
                security.for_log(", ".join(repr(r) for r in broken)))
        if config.admin_enabled and not self.known_roles():
            stored = self.store.roles_in_use()
            if stored:
                security.seclog.warning(
                    "Accounts carry the roles %s, but available_roles and the role catalog are empty: the admin panel "
                    "offers a free-text field instead of checkboxes. List the roles in available_roles or add them "
                    "to the catalog (admin panel, Roles).",
                    security.for_log(", ".join(stored)))
        self._check_role_catalog()
        # The account API (`apps`): an application whose service account is missing or is a person stays shut — the
        # API checks the key's account on every request (fail-closed); here it is said once, at start.
        self._check_app_accounts()
        self._check_orphaned_app_accounts()
        # Collisions in the identifier space from existing data: the database has prevented new ones
        # since 2026-09-26 (trigger over the counting buckets, `Store._trigger_sql`), but one from an
        # older version, from a raw UPDATE or from a row of a foreign writer
        # is still in there. It is not harmless: `find_user` then resolves the identifier ambiguously,
        # the rightful owner may be locked out, and two accounts share the
        # lockout threshold. Cleanup is by hand (which account keeps the name cannot be decided by
        # any library) — it is said at startup, and completely: until then the
        # message only saw "name = foreign address" via NOCASE, not `Alice`/`alice` or two
        # spellings of the same address (`bucket_collisions`).
        collisions = self.store.bucket_collisions()
        if collisions:
            examples = "; ".join(
                f"identifier '{security.for_log(z['identifier'])}': "
                + ", ".join(f"user_id={i}" for i in z["ids"]) for z in collisions[:5])
            security.seclog.warning(
                "%d identifier collision(s) in existing data: username and email are ONE "
                "identifier space (find_user searches both columns, namesakes like Alice/alice "
                "share the lockout threshold). The database prevents new ones; these date from "
                "the time before and stay until one of the identifiers is changed. Signing in "
                "with this identifier is ambiguous, the rightful owner may be locked "
                "out. Affected: %s%s. One of the identifiers has to change. The username: in the "
                "admin panel (\"Rename\", POST <admin_path>/api/users/<id>/username), with "
                "tinysesam rename --db <file> '#<user_id>' <new-name>, the owner themselves on "
                "the account page, or from the embedding service "
                "auth.change_username(user_id, new_username, by_operator=True) — all check both "
                "namespaces (in login_identifier='email' mode the name follows the address). The "
                "email from the embedding service via "
                "store.set_email(user_id, address) (raises sqlite3.IntegrityError if the new "
                "address is already the identifier of another account). Note on the email: "
                "store.set_email() stores the new address as UNCONFIRMED by default "
                "(users.email_verified=0) — the evidence for the old address does not carry over to a "
                "different one. Whoever has evidence for the new one passes verified=True.",
                len(collisions), examples,
                " (more follow)" if len(collisions) > 5 else "")
        # Account names with control/format characters (no longer creatable since 2026-09-24) in existing data:
        # forward auth rejects those whose characters the header sanitising would remove (otherwise
        # `Remote-User` would be a foreign name). It is said at startup, not only per request.
        conspicuous = [z for z in self.store._all("SELECT id, username FROM users")
                      if name_invalid(z["username"])]
        if conspicuous:
            security.seclog.warning(
                "%d account name(s) with control or format characters in existing data (user_id %s). "
                "TinySesam no longer creates new ones; names with C0 control characters get no "
                "approval at forward auth (Remote-User would be a different name). Rename: in the "
                "admin panel (\"Rename\"), with tinysesam rename --db <file> '#<user_id>' "
                "<new-name>, the owner themselves on the account page, or from the embedding "
                "service auth.change_username(user_id, new_username, by_operator=True) — all check "
                "that the new name is free among usernames AND addresses.",
                len(conspicuous), ", ".join(str(z["id"]) for z in conspicuous[:10]))
        # Binding by name (G1): the grace period starts per source at the first start at which it is
        # switched on — for existing data thus with the update — and exactly once (the marker
        # stays, see `Store.federation_since`). After that, one line per source for as long as there are
        # accounts that would bind via the name and the door is still open.
        for _source, _an in (("ldap", config.ldap_enabled), ("saml", config.saml_enabled)):
            if _an:
                self._report_name_binding_inventory(_source, self._federation_since(_source))
        # Permissions (T-100): the configuration's manifests — and an empty one where configured ones are gone.
        if any(isinstance(e, dict) and "permissions" in e for e in (config.apps or {}).values()) \
                or self.store.permission_apps("config"):
            self._register_config_permissions()
        tok = self.admin_claim_token()
        if tok:
            self._admin_claim_announce(tok)
        else:
            self._claim_file_away()          # a leftover from a run without admin (T-17)

    @staticmethod
    def _refuse_role_names(roles) -> None:
        """`ConfigError` (`field="roles"`) for the first role in `roles` that cannot travel as one role
        (`store.role_invalid`, T-85) — the one check of every path that stores roles on an account or a key."""
        for role in roles or []:
            if role_invalid(role):
                error = ConfigError(f"Role name not allowed (comma, control character, surrounding spaces or empty): "
                                    f"{role!r}")
                error.field = "roles"
                raise error

    #: The kinds of an API key (R6-5), English since 0.22.0: `automation` works alone and
    #: never carries the admin flag, `human` applies only together with a session of the same account.
    _KEY_KINDS = ("automation", "human")
    @staticmethod
    def _key_kind(row) -> str:
        """The kind of a key row: `automation` or `human`. Empty means `automation`; anything else stays as it is,
        and counts as an automation key because it is not `human` (fail-closed, R6-6)."""
        return key_kind_of(row)

    #: How long the same key use (key, IP, outcome) is not written to the audit log again (B5-05).
    #: A key exists for automations that present it every second; one line per request
    #: would bury the rest of the log. One per hour and address answers the questions one asks after
    #: a leak: since when, from where, and did a NEW address join.
    _APIKEY_AUDIT_WINDOW = 3600
    _THROTTLE_MAX = 10000

    #: Why all keys of an account were revoked — `reason` in the event `api_keys_revoked`
    #: (`on_security_event`). Up to 0.21.x German (`lock`, `admin_passwort`, `passwort_reset`,
    #: `sitzungen_beendet`), with the keys `anzahl`/`reason` instead of `count`/`reason`.
    _KEYS_REVOKED_REASONS = ("account_disabled", "admin_password_reset", "password_reset",
                                "sessions_revoked", "access_reset")

    #: How long the same app-password use or refusal (row, IP, outcome) is not written to the audit log again —
    #: a WebDAV client sends the password with every request (like `_APIKEY_AUDIT_WINDOW`).
    _APP_PASSWORD_AUDIT_WINDOW = 3600
    #: How often `last_used` is written at most per app password: a sync of a thousand files is not a thousand
    #: writes.
    _APP_PASSWORD_TOUCH_SEC = 60

    @staticmethod
    def _load_blocklist(path) -> frozenset:
        """Read in the operator blocklist (`password_blocklist_file`) — once, at startup.

        If the file is missing, startup aborts (`ConfigError`) instead of silently continuing
        without a list: whoever specifies a list relies on it. Lines that are not
        UTF-8 are read by `read_blocklist` as Latin-1 — otherwise a raw
        `UnicodeDecodeError` came here instead of a usable list (A-3)."""
        if not path:
            return frozenset()
        try:
            return _pw.read_blocklist(path)
        except OSError as e:
            raise ConfigError(f"password_blocklist_file {path!r} cannot be read: {e}") from e

    # ---------- Notification on security events (opt-in) ----------
    #: The events for which `on_security_event` is called — everything that creates, changes,
    #: removes or consumes a sign-in factor of the account. Since T-13 (limit e) also the
    #: revocation of API keys: individually (`api_key_revoked`) and collectively on reset, lockout and
    #: `sessions/revoke` (`api_keys_revoked`, with count and reason). NIST SP 800-63B demands notifying the owner of such changes;
    #: until T-13 they learned of none (finding B2-2): an attacker with a
    #: session could switch off TOTP, add a passkey or change the password, and the
    #: owner saw it only at the next login — if at all. The details (third argument
    #: of the hook), with English keys since 0.22.0: `api_key_created` `key_id`, `name`;
    #: `api_key_revoked` `key_id`; `api_keys_revoked` `count`, `reason` (`account_disabled`,
    #: `admin_password_reset`, `password_reset`, `sessions_revoked`); `totp_disabled`
    #: `recovery_codes_deleted`; `recovery_codes_generated` `count`; `recovery_code_used`
    #: `remaining`; `passkey_added` `name`; `passkey_removed` `passkey_id`; `username_changed`
    #: and `email_changed` `old`, `new`; the rest none.
    #: Since H2 (T-47, NIST SP 800-63B-4 §4.1.2.1) also the NEW ways into the account that are not a
    #: factor of its own: `signin_link_issued` (`ttl_min`, `by_operator`) — a sign-in link was issued
    #: for the account; `device_signed_in` (`method`, `ip`, `agent`) — a device signed in through a
    #: cross-device approval; and `password_changed` carries `by_operator` (an administrator set it).
    #: Since T-66 the app passwords: `app_password_created` (`app_password_id`, `name`, `hosts`),
    #: `app_password_revoked` (`app_password_id`), `app_passwords_revoked` (`count`, `reason` — the same reasons as
    #: `api_keys_revoked`).
    #: Since T-60 the services: `oauth_service_paired` (`client_id`, `client_name`, `resources`) — a service was paired
    #: to act as the account; `oauth_service_revoked` (`client_id`, `client_name`, `reason`).
    #: Since T-63 `signed_in_after_failures` (`failures`, `ip`): a complete sign-in ended a streak of at least
    #: `_AFTER_FAILURES_MIN` consecutive failed attempts (ASVS 5.0 6.3.5) — by mail with `notify_login_failures`.
    #: Since the approvals (stage A) `approval_approved` (`approval_id`, `type`, `result`): the holder confirmed an
    #: action a token had asked for, and TinySesam executed it — not mailed by TinySesam (the hook may).
    #: Since the approval type `tinysesam.account.reset_access` `access_reset` (`app`, `approved_by`, and the counts
    #: `password`, `pin`, `totp`, `recovery_codes`, `passkeys`, `api_keys`): an application's approver reset the
    #: account's access — every factor gone, sessions ended, a new one-time link handed to the application; mailed
    #: with `notify_new_access` (a reset the holder did not ask for is how a misused approver right shows).
    #: `api_keys_revoked` and the others then carry the reason `access_reset`.
    SECURITY_EVENTS = (
        "password_changed", "pin_set", "pin_disabled", "totp_enabled", "totp_disabled",
        "recovery_codes_generated", "recovery_code_used", "passkey_added", "passkey_removed",
        "api_key_created", "api_key_revoked", "api_keys_revoked",
        "email_changed", "username_changed",
        "oauth_device_connected", "oauth_device_revoked", "oauth_token_reuse",
        "signin_link_issued", "device_signed_in",
        "app_password_created", "app_password_revoked", "app_passwords_revoked",
        "oauth_service_paired", "oauth_service_revoked",
        "signed_in_after_failures",
        "approval_approved",
        "access_reset",
    )

    #: The events that mean NEW access to the account — they go to the owner by mail as well
    #: (`notify_new_access`, T-47), if delivery is configured. A password change counts only when an
    #: administrator made it (`by_operator`): the holder's own change is no news to the holder.
    _ACCESS_MAIL_EVENTS = ("passkey_added", "totp_enabled", "pin_set", "api_key_created",
                           "device_signed_in", "signin_link_issued", "password_changed",
                           "oauth_device_connected", "oauth_token_reuse", "app_password_created",
                           "oauth_service_paired", "access_reset")

    #: Events mailed under `notify_login_failures` instead of `notify_new_access` (T-63).
    _FAILURE_MAIL_EVENTS = ("signed_in_after_failures",)

    @staticmethod
    def _request_ip():
        """The IP of the running request, as `audit()` records it — or None outside a request."""
        a = _REQUEST.get()
        return a.get("ip") if a else None

    #: How the account page names an event when it is not its own name (G12b). The
    #: request for a taken or an allowlist address appears like any request — otherwise
    #: the account page would show what the response withholds. `None` hides it:
    #: `federation_email_confirm` arises only if the link went out to a FREE address, and
    #: would betray the same to an LDAP user who sets their `mail` attribute themselves. Likewise
    #: `ldap_identifier_rejected` (up to 0.24.x `ldap_kennung_abgewiesen`; review round 2026-09-27): the line
    #: is under the typed-in identifier and arises only if the LDAP password of the OTHER entry was right — on the
    #: local owner's account page it would be exactly the oracle that the rejection closes. The
    #: operator's audit log keeps the real names.
    _OWN_VIEW = {"email_change_taken": "email_change_requested",
                       "email_change_reserved": "email_change_requested",
                       "federation_email_confirm": None,
                       "ldap_identifier_rejected": None}

    #: Factors through which the identity comes from a FOREIGN provider. For them `_maybe_promote_admin`
    #: applies fail-closed: without explicit evidence an allowlist address there
    #: carries no first-admin decision — a new federated path that forgets to
    #: pass the evidence therefore does not promote but refuses.
    #: `ldap` is deliberately not here: LDAP writes the factor `password` (see `_check_ldap`),
    #: so it cannot be recognised by the factor name — its caller passes the evidence, which does not exist there
    #: at all, explicitly as `False`.
    _FEDERATED_FACTORS = ("oidc", "saml")

    # ---------- Demo mode ----------
    _DEMO_USERS = ("demo", "demoadmin")

    #: What an account dict of the public surface carries (`current_user`, `session_user`,
    #: `pending_user`, `get_user`, `find_user`, `identifier_taken`, `verify_api_key`,
    #: `LoginResult.user`, the `require_*` guards) — the columns that describe the account. The
    #: store's bookkeeping stays outside: counting buckets (`folded_name`, `folded_mail`),
    #: watermarks (`name_attempt_from` …), origin and self-choice of the name (`name_source`,
    #: `name_self_chosen`), the last confirmation by the IdP (`idp_confirmed_at`). Up to
    #: 0.21.x the whole row went out, with German column names; since 0.22.0 the
    #: public surface is English (PO decision 2026-09-27), and internals do not belong in
    #: its guarantee. A list of the allowed rather than the forbidden columns: a new column of the
    #: store does not silently become part of the guarantee. Depending on the path, `_via` and `_key_kind` are added.
    _ACCOUNT_FIELDS = ("id", "username", "display_name", "email", "email_verified", "is_admin",
                     "is_owner", "roles", "is_service", "disabled", "first_login_at",
                     "mfa_enroll_until", "created_at")

    @classmethod
    def _as_dict(cls, line) -> Optional[dict]:
        """Return an account row as what the signature promises — a `dict` with the
        fields from `_ACCOUNT_FIELDS`.

        The user-facing methods have always been annotated `-> Optional[dict]` and returned
        a `sqlite3.Row`. The package carries `Typing :: Typed` and a `py.typed` — the guarantee
        was just never measured. In practice it shows as soon as someone believes the annotation:
        `u.get("email")` does not exist on a Row, and the `AttributeError` comes from a
        line that, according to the type, cannot be wrong. At the store level the Row remains — there
        it is documented and intended, with all columns.
        """
        if line is None:
            return None
        da = set(line.keys())
        return {k: line[k] for k in cls._ACCOUNT_FIELDS if k in da}

    # ---------- LDAP / lldap (password backend) ----------
    #: Sources that bind a foreign identity via a stable identifier (F-11). OIDC is not
    #: among them: with `issuer`+`sub` it has always had its own, more stable mapping.
    FEDERATED_SOURCES = ("ldap", "saml")
    #: Placeholder identifier for an account that came via a source WITHOUT a stable identifier (A-4).
    #: The row in `federated_identity` merely says "this account comes from LDAP/SAML" — otherwise
    #: it would count as local for `federated_only()` and would get a reset link whose password
    #: then wins over the directory. Unique per account (primary key source+identifier),
    #: never read for a mapping, and a real identifier replaces it at the next login —
    #: through the same door as case 4 (`_rebinding_reason`).
    _WITHOUT_IDENTIFIER = Store.WITHOUT_IDENTIFIER

    @classmethod
    def _identifier_form_error(cls, raw) -> Optional[str]:
        """Is this value usable as a foreign identifier? None = yes, otherwise the reason (sign-in and
        existing-data binding check with the SAME function).

        * Leading/trailing whitespace or control characters: trimmed, the identifier would fall on the binding of
          ANOTHER account (`manager\u2028` → `manager`, counter-check). Something like that does not
          come from a real directory — reject instead of making it fit.
        * The form of the origin placeholder: via `get_federated_user` it would hit exactly the
          account whose ID it names. A directory delivers UUID/GUID — so a manipulated
          attribute."""
        raw = str(raw or "")
        if raw != raw.strip() or name_invalid(raw):
            return "edge_or_control_characters"
        if raw.startswith(cls._WITHOUT_IDENTIFIER):
            return "placeholder_form"
        return None

    #: Why an account is not bound via the name (`_rebinding_reason`) — short code and
    #: explanation, for the report of `federation_bind_existing` (`reason`). English since 0.22.0
    #: (PO decision 2026-09-27); the codes up to 0.21.x remain in audit and security log.
    NAME_BINDING_REFUSALS = {
        "address_as_name": "the name says nothing about the person (control characters, or the "
                           "unverified mail value of a source that is not trusted)",
        "invalid_identifier": "the identifier is unusable (leading/trailing or control characters, "
                              "or placeholder form)",
        "conflict": "the identifier already belongs to another account",
        "bound_elsewhere": "the account already carries a different identifier",
        "self_chosen_name": "the name was chosen by the person (sign-up or rename) and says nothing "
                            "about who has that name in the directory",
        "name_from_other_source": "the name comes from another source that created the account "
                                  "(OIDC, SAML or LDAP) and says nothing about who has that name "
                                  "in this one",
        "binding_window_expired": "the window for binding by name has passed "
                                  "(federation_name_binding_days)",
        "unlinked_by_holder": "the person unlinked this source's identity from the account themselves",
    }
    #: The same reasons in the security log (the audit line `<source>_name_binding_closed … reason=` carries
    #: the code itself).
    _REBINDING_LOG = {
        "address_as_name": "the name says nothing about the person "
                           "(control characters, or the unverified mail value of a source that "
                           "is not trusted)",
        "invalid_identifier": "the identifier is unusable (edge/control characters "
                              "or placeholder form)",
        "conflict": "the identifier already belongs to another account",
        "bound_elsewhere": "the account already carries a different identifier",
        "self_chosen_name": "the name was chosen by the user (registration "
                            "or rename) and says nothing about who has that name in the directory",
        "name_from_other_source": "the name comes from another source that created the "
                                  "account (OIDC, SAML or LDAP) and says nothing about who has "
                                  "that name in this one",
        "binding_window_expired": "the window for binding by name has "
                                  "passed (federation_name_binding_days)",
        "unlinked_by_holder": "the person unlinked this source's identity from the account themselves",
    }

    @staticmethod
    def _bucket(username, method) -> str:
        """Under which name an attempt counts: the identifier folded the way `find_user` reads it.

        Up to the third round, attempts were counted under the RAW typed text, but looked up
        trimmed and case-insensitively. `' victim'`, `'victim '`, `'\tvictim'` hit
        the same account and each filled a bucket of its own — the account threshold against distributed
        guessing (R7-6/H-8) thus bound nothing. The exception is the realm pseudo-name
        `res:<name>`: the server sets it from a realm that has to exist."""
        return username if method == "resource" else norm_identifier(username)

    _SERIES_PREBOOKINGS_MAX = 10000

    #: Pending pre-bookings (G9, `_begin_attempt`): how many sign-ins per process may
    #: wait at the same time, for how long at most (one directory question up to its timeout
    #: and some headroom) and at what interval they ask again. Every re-ask takes the write lock
    #: (`BEGIN IMMEDIATE`) — at full occupancy at most about 40 short transactions per second.
    _PENDING_WAIT_SLOTS = 8
    _PENDING_DEADLINE_SEC = _LDAP_TIMEOUT + 2
    _PENDING_BEAT_SEC = 0.2

    #: Maximum number of remembered (account, IP) pairs per process — after that the oldest drops out. An attacker with many
    #: addresses can thereby only displace entries, i.e. make failed attempts COUNT again, never fewer.
    _PW_REPETITION_PAIRS = 10000
    #: PBKDF2 rounds of the fingerprint: noticeable for someone trying out a memory dump, but only a few
    #: milliseconds per failed attempt (measured 2026-10-09 on the development machine).
    _PW_REPETITION_ROUNDS = 20000

    # ---------- Recovery codes (2FA substitute for a lost authenticator) ----------
    #: Random bytes per half of a recovery code. Two halves of 7 bytes = **112 bits**.
    #: Before, it was 3 bytes (48 bits), then 4 (64). Both are too tight for a code that
    #: REPLACES the second factor and stays valid indefinitely: a TOTP code has only a
    #: million possibilities, but is valid for 30 seconds — a recovery code is valid until it is used.
    #: 112 bits is the threshold from which NIST SP 800-63B lets a simple
    #: one-way hash suffice for a "look-up secret"; below that it requires salt and a password hashing scheme. The
    #: codes are stored as an HMAC with the pepper (`Store.token_digest`, kind `recovery`), never as a plain hash.
    _RECOVERY_BYTES = 7
    #: At this few remaining codes the account page shows a warning and the
    #: security log a line — whoever uses them up should generate new ones in time.
    _RECOVERY_WARN_THRESHOLD = 3

    @staticmethod
    def _rc_norm(code) -> str:
        """A recovery code as typed (spaces, capitals) in the one form its digest is made of."""
        return str(code or "").strip().lower().replace(" ", "")

    # ---------- Factor-chain engine ----------
    _IDENTIFYING = ("password", "pin", "oidc", "passkey", "magic", "saml")  # factors that identify the user

    #: Factors that the setup pass (T-34) can create for an account.
    _SETTABLE = ("password", "totp", "passkey", "pin")

    # ---------- Setup pass after a sign-in link (T-34) ----------
    # "The admin creates the account and hands out a link": registration is off, the account has no
    # factor yet, and the chain demands e.g. password + TOTP. The link signs the account in only
    # halfway; the pass then asks to set up exactly what the chain needs and the account lacks —
    # and only then is the sign-in full. The rules:
    #
    # * The pass begins only at a link sign-in (`magic`: mailed, admin-issued, app-issued, QR) of an
    #   account that cannot satisfy the chain with what it has (`_setup_missing`), only with a global
    #   chain, and only if self-setup is allowed (`mfa_enrollment`, `mfa_enroll_until`).
    # * It is bound to that very session (a `flow` row keyed by its handle) and expires with the
    #   step-up window (`stepup_max_age_sec`, measured from the link sign-in): a pass does not wait
    #   for days. Disabling the account or a password reset ends all sessions, and the pass with them.
    # * A half session in the pass can do nothing but set up the factors offered (the setup routes
    #   accept it, nothing else does: `current_user()`/`session_user()` stay None).
    # * The link identifies the account and opens the door to setting up. It replaces no factor
    #   the account HAS: every step the account can already satisfy is provided first, as at a
    #   regular sign-in — before anything is set up. A factor set up in the pass counts as provided.
    #   So the session is full once the chain is satisfied by provided plus freshly set-up factors.
    #   Order is not enforced inside the pass — the server dictates the steps.
    # * If the account already has TOTP or a passkey, that comes first as well, even if the chain
    #   does not name it: a mailbox never sets up factors past an existing authenticator (as
    #   `totp_enrollment_user`, ASVS 6.3.6).
    # * A factor the account has is never replaced: the pass offers only missing ones.
    _SETUP_FLOW = "setup:"

    @staticmethod
    def _csrf_new(request) -> str:
        token = secrets.token_urlsafe(24)
        scope = getattr(request, "scope", None)
        if isinstance(scope, dict):
            scope[_CSRF_SCOPE] = token
        return token

    @staticmethod
    def _remove_set_cookie(response, name: str) -> None:
        """Take the Set-Cookie lines for exactly this name out of the response. The list is changed
        in place: `response.headers` holds a reference to the same list."""
        raw = getattr(response, "raw_headers", None)
        if raw is None:
            return
        prefix = name.encode("latin-1") + b"="
        raw[:] = [(k, v) for k, v in raw if not (k.lower() == b"set-cookie" and v.startswith(prefix))]

    #: Cap for `token_invalid` lines in the audit log: at most this many per window (global).
    _TOKEN_AUDIT_MAX = 20
    _TOKEN_AUDIT_WINDOW_SEC = 60

    #: Where a token is redeemed — a separate endpoint per purpose. Up to 0.15 all four ran
    #: via /auth/magic/{token}: whoever switched off the magic link thereby also lost email
    #: confirmation and invitation, which have nothing to do with it.
    TOKEN_PATHS = {
        "login": "/auth/magic/{t}",
        "verify_email": "/auth/verify/{t}",
        "invite": "/auth/invite/{t}",
        "reset_password": "/auth/reset?token={t}",
        "email_change": "/auth/email/{t}",
    }

    # ---------- Self-service: username and address (PO decision 2026-09-25) ----------
    #: Longer is no longer a name but a payload (header, log lines, panel).
    NAME_MAX = 150

    # ---------- Sign-in link without mail (T-33) ----------
    # The upper bound for an issued link is `signin_link_max_ttl_min` (T-51, default 24 h); up to 0.25.x it was a
    # fixed week (`_SIGNIN_LINK_MAX_TTL_MIN`), which `config_check` keeps as the largest value allowed.

    # ---------- Cross-device sign-in (QR code, T-33) ----------
    # One row in `magic_token` per request (purpose `qr_login`), no token system of its own. The key
    # is the hash of the SHORT code — the approving device knows only that. The new device
    # additionally holds a long secret (in its page, never on screen); only its hash is in the
    # payload. Whoever sees the code on the screen can approve it for their own account at most,
    # never take over the session that the approval creates.
    _QR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # no I/L/O/0/1 — read off a screen
    _QR_LENGTH = 8

    @classmethod
    def _qr_code_norm(cls, code) -> str:
        """The short code in its stored form (upper case, without separators) — or ""."""
        c = re.sub(r"[^A-Z0-9]", "", str(code or "").upper())
        return c if len(c) == cls._QR_LENGTH and all(ch in cls._QR_ALPHABET for ch in c) else ""

    #: Factors that confirm a full session although `stepup_options()` does not name them: each signs the account in
    #: on its own (a passkey with user verification, a sign-in at the provider) — what the reauth page cannot offer.
    _STEPUP_SIGN_INS = ("passkey", "oidc", "saml")

    # ---------- Signing in for own pages (stage A, 0.22.0) ----------
    # PO finding 2026-09-26: the README showed `check_password` + `start_session` as building blocks
    # of an own login page. The inner checkers do not throttle — lock, counter, streak and
    # the fail2ban lines existed only in the routes. These three methods ARE now the routes:
    # `POST /auth/login`, `/auth/pin` and `/auth/totp` call them and only render the
    # result. One source, no drift — `tests/test_sign_in.py` ensures via AST that none
    # of the three routes calls an inner checker itself, and checks own pages against the
    # built-in ones (the same audit and log lines).

    @staticmethod
    def _csrf_sent_along(request, csrf: Optional[str]) -> Optional[str]:
        """The submitted CSRF token: the argument, otherwise the header `X-CSRF-Token`."""
        return request.headers.get("x-csrf-token") if csrf is None else csrf

    # ---------- Step-up and password change for own pages (stage A, 0.22.0) ----------
    # PO decision 2026-09-27: the same pattern as `login_*` for confirmation before sensitive
    # actions (until then only the built-in page `/auth/reauth`) and for the own
    # password change (until then only `POST /auth/password`). The inner checkers
    # (`_verify_user_password`, `_verify_user_pin`, `_verify_totp`) do not throttle; these methods
    # do what the routes do — because the routes call them. `tests/test_confirm.py` ensures via AST
    # that neither of the two routes calls an inner checker itself, and measures own pages
    # against the built-in ones (the same status, audit, log and counter lines).

    #: Whoever attempts a confirmation or a password change without a session gets `no_session`.
    #: If the request shows an API key instead of a session, that means 403 with this text — the
    #: key is not checked in the process, it simply does not count here (0.20.1).
    _WITHOUT_SESSION_KEY = {"reauth": "api.stepup_session", "password_change": "api.password_needs_session"}

    #: The permitted values of `cfg.mfa_enrollment` — as a list so that a typo during
    #: construction is noticed and not only when someone is standing at the door.
    MFA_ENROLLMENT_MODES = ("first_login", "grace", "strict")

    @property
    def session_cookie_name(self) -> str:
        """The actual name of the session cookie (with `__Host-` where possible)."""
        return self._cookie_name(self.cfg.session_cookie)

    @property
    def csrf_cookie_name(self) -> str:
        """The actual name of the CSRF cookie — own JS gets it from the page.

        JS cannot read this property: the page passes the name along (template variable
        or `<meta>`), or the JS takes the token from the form field `_csrf`, which
        `ensure_csrf()` supplies.

        With `__Host-` even when `cookie_domain` is set: TinySesam never sets the CSRF cookie
        with a domain (`issue_csrf`, `render_page`, admin panel), it is always host-only. Without a
        prefix, in the forward-auth setup every protected app could set a `tinysesam_csrf` for the
        whole domain and pass the double-submit with its own value."""
        return self._cookie_name(self.cfg.csrf_cookie, host_only=True)

    @property
    def resource_cookie_name(self) -> str:
        """The actual name of the unlock cookie of the realm PIN."""
        return self._cookie_name(self.cfg.resource_cookie)

    # Rejection happens at eleven places in the router; reporting happens HERE, in the check itself.
    # Reason: as long as the app lockout applied, nobody called `_record_login()` any more — the app
    # answered 429 and wrote no line. The security log thus fell silent at exactly the
    # moment when fail2ban should have banned the IP: the app lockout blinded the guard
    # that is supposed to take over from it. Patching the eleven call sites one by one would mean that the
    # next new route is silent again.
    #
    # The format is deliberately the same as for a real failed attempt — the bundled
    # fail2ban filter (`failed login user=… ip=<HOST> method=.*`) thereby applies immediately, even
    # in installations that never touch their filter file. `reason=` says why.
    #
    # `login=False` for the rejections of the non-login buckets: they carry the other
    # event word (`security.LOG_CHECK`) and thus pass by the bundled jail
    # — otherwise a signed-in user would ban themselves at firewall level with a few typos on their
    # own account page, and every further click after the
    # app lock would speed up the ban (rationale at `security.LOG_SIGN_IN`).
    #: Lock reasons that concern an ACCOUNT (not an address or the rate limit): only they trigger
    #: the notice to the owner (ASVS 6.3.5).
    _ACCOUNT_LOCKS = ("lockout_user", "lockout_account", "lockout_series", "lockout_pin")

    #: Which shares of the streak (B2-6) a self-service reset clears: those of the FIRST factors.
    #: Anyone can produce them without knowing a secret — a stranger locks, with wrong PINs,
    #: an account whose owner does not even have a PIN. If they stayed, the reset the message
    #: advises would no longer help (attack on the fixes, R2-2). TOTP wrong guesses, by contrast,
    #: arise only for whoever already has the password; only a complete sign-in or the
    #: operator clears those (R4-13). Likewise a PIN AFTER an already provided factor (chain step of the
    #: half session, route chain of the full one): it books under `_PIN_CHAIN_SERIES` and stays
    #: like TOTP (G7). Until 2026-09-26 the kind did not know the position — in a chain
    #: `password → pin` the reset cleared the second factor's wrong guesses too.
    _SERIES_RESET_KINDS = ("password", "pin")
    #: The kind of the streak for a PIN behind an already provided factor (G7). `login_attempt`
    #: and the PIN bucket keep counting it as `pin`; only the self-service reset distinguishes.
    _PIN_CHAIN_SERIES = "pin_chain"

    #: From how many consecutive failed attempts a complete sign-in is reported to the holder (T-63, ASVS 5.0 6.3.5:
    #: "a successful authentication after several unsuccessful attempts"). One or two typos are the holder's own.
    _AFTER_FAILURES_MIN = 3

    # ---------- Forward auth (reverse proxy) ----------
    #: Default: the set that Authelia/Traefik setups expect.
    #: `Remote-Id` is the account ID — the only value that survives a rename and an email
    #: change (PO decision 2026-09-25: "hang everything on the ID"). An app that assigns users by it
    #: confuses nobody after a change.
    #: `Remote-Auth` (T-75) says HOW the request signed in — an application whose `Remote-Groups` differ between a
    #: browser session and a token (a token never carries `admin`) can tell why.
    #: `Remote-Kind` says WHAT the account is: `service` for a service account (`is_service`), otherwise `user`. It is
    #: always sent (see `FORWARD_HEADERS_MANDATORY`): a gate client after spec v2 refuses a request without it.
    FORWARD_HEADERS_DEFAULT = {"user": "Remote-User", "name": "Remote-Name",
                               "email": "Remote-Email", "groups": "Remote-Groups", "id": "Remote-Id",
                               "auth": "Remote-Auth", "kind": "Remote-Kind"}
    #: Slots sent even when an own `forward_headers` mapping leaves them out — under their default name. A slot here
    #: can be renamed (`{"kind": "X-Account-Kind"}`), never dropped: failing closed at the client works only when the
    #: server always delivers the value. The account kind is no personal data, so it needs no switch to omit it.
    FORWARD_HEADERS_MANDATORY = ("kind",)
    #: The value of `Remote-Kind` per value of `users.is_service` (a `NOT NULL DEFAULT 0` column). Anything else is
    #: refused, never guessed as `user`.
    _ACCOUNT_KINDS = {0: "user", 1: "service"}
    #: The value of `Remote-Auth` per way in (`_via` of the account dict). A gate token is issued only for a session
    #: and carries `session` as a signed claim. An unknown way gives an empty value, never a guessed kind (the templates
    #: set nothing for an empty value, T-58).
    _FORWARD_AUTH_KINDS = {"session": "session", "oauth": "oauth", "apikey": "apikey", "app_password": "app-password"}

    #: The note 0.26–0.30 put on a gate key or pepper it took over from the single base key of 0.25.x (derived from the
    #: vault key by HKDF). Such a key is refused at start (`_refuse_derived_keys`).
    _BASE_KEY_NOTE = "derived-v1"

    _GATE_LINK_COOKIE = "__Host-tinysesam_link"
    _GATE_LINKFLOW_COOKIE = "__Host-tinysesam_linkflow"

    @staticmethod
    def _header_value(value: str) -> str:
        """Prepare a value so that it passes as an HTTP header.

        Up to 0.18.0 it went out raw, and two things broke on it:

        1. **Line breaks.** A display name like `"Bose\r\nX-Remote-Groups: admin"` — with OIDC
           or SAML the name comes from the foreign IdP — would be header injection. `h11` does
           catch it, but with `LocalProtocolError`: the response aborts, and the person
           affected no longer gets through the forward auth at all. An injection thus becomes
           a self-lockout with a cryptic message.
        2. **Names beyond Latin-1.** HTTP headers are Latin-1; `"Иван"` or `"测试"` are
           not encodable, and the ASGI server answers with 500. That is no attack, that is
           a Tuesday in an international company — the user simply cannot use the protected
           app.

        Control characters are dropped. The rest goes **always as UTF-8 over the wire** (the bytes
        are passed through Latin-1-transparently) — lossless, and the downstream app reads
        the header as UTF-8.

        Deliberately *always*, not only in an emergency: switching depending on content would be the worse
        solution. "Müller" would then arrive as Latin-1 and "Иван" as UTF-8, and no app could
        know what it has. For pure ASCII — the normal case — nothing changes, because
        ASCII has the same bytes in both encodings.
        """
        clean = "".join(z for z in str(value or "") if z >= " " and z != "\x7f")
        return clean.encode("utf-8").decode("latin-1")

    @staticmethod
    def _url_rest(url: str) -> str:
        """Path and query of an absolute URL exactly as written (no fragment), "" when there is none."""
        from urllib.parse import urlsplit
        try:
            parts = urlsplit(url)
        except ValueError:
            return ""
        rest = url.split("://", 1)[1][len(parts.netloc):].split("#", 1)[0]
        return rest if rest.startswith(("/", "?")) else ""

    @staticmethod
    def _is_page_view(request: Optional[Request]) -> bool:
        """Is the browser loading a PAGE here (and not a script, an image, an XHR)?

        `Sec-Fetch-Mode: navigate` says so explicitly; the proxy passes the request's headers on to
        `/auth/forward`. Without the header (older browsers, tools) `Accept: text/html` counts.
        Why: only a page load may go directly to the provider. A background fetch that is
        redirected there can do nothing with the provider's sign-in page — and each one
        would start an OIDC flow of its own (database row, rate limit)."""
        if request is None:
            return False
        h = request.headers
        mode = (h.get("sec-fetch-mode") or "").strip().lower()
        if mode:
            return mode == "navigate"
        return "text/html" in (h.get("accept") or "").lower()

    # ---------- Views / redirect safety ----------
    #: The pages that can be replaced — the same list that `render_page()` serves.
    #: The docstring used to name 'magic_sent' and 'resource_pin', neither of which ever existed, and
    #: left out seven real ones. A typo thereby remained silently without consequence: the own page
    #: was registered and never called.
    PAGES = ("account", "account_setup", "error", "forgot", "gate_logged_out", "gate_logout", "gateway_home", "login", "logout",
             "magic_confirm", "magic_invalid",
              "magic_request", "pin", "qr_approve", "qr_login", "reauth", "register", "reset",
              "resource_unlock", "totp", "totp_setup")

    # ---------- The app frame (T-91) ----------
    #: The query members that may name the application a person comes from: `app=<host>` directly, or the target
    #: of a round trip (`next`, `return_url`) — absolute with the host, or relative with `app=<host>` in its query.
    _FRAME_TARGETS = ("next", "return_url")

    # ---------- Self-service: the own account as data (T-91) ----------
    #: The rate of `GET /auth/account.json` and `/.tinysesam/account.json`: reads per account and minute.
    _ACCOUNT_JSON_PER_MINUTE = 60
    #: The sections of the account page an application can link to (`#…`), as named in `account_overview()["links"]`.
    _ACCOUNT_ANCHORS = {"sessions": "sessions", "totp": "totp", "passkeys": "passkeys", "devices": "devices",
                       "app_passwords": "app-passwords", "services": "services"}

    @staticmethod
    def _coarse_agent(agent) -> Optional[str]:
        """A coarse "browser on system" from a User-Agent (draft §9: where a session comes from, never the raw string
        and never the address) — None when nothing is recognized."""
        ua = str(agent or "")
        if not ua:
            return None
        browser = next((name for needle, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                                  ("Chrome/", "Chrome"), ("Chromium/", "Chromium"),
                                                  ("Safari/", "Safari"), ("curl/", "curl")) if needle in ua), None)
        system = next((name for needle, name in (("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"),
                                                 ("Windows", "Windows"), ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"),
                                                 ("Linux", "Linux")) if needle in ua), None)
        if browser and system:
            return f"{browser} · {system}"
        return browser or system

    _secure_flag_reported = False

    #: Path of the own CSP report endpoint (`csp_report`, T-52) and the endpoint name in `Reporting-Endpoints`.
    _CSP_REPORT_PATH = "/auth/csp-report"
    _CSP_REPORT_GROUP = "tinysesam-csp"
    #: Reports per IP and minute, reports in the log per minute in total, bytes per report body.
    _CSP_REPORT_PER_IP = 10
    _CSP_REPORT_LOG_PER_MINUTE = 60
    _CSP_REPORT_MAX_BYTES = 8192

    #: What may serve as a mount prefix (`root_path`) in pages and redirects (T-15). The value comes
    #: from the ASGI server (`--root-path`) or from a Starlette mount, not from the browser — but it
    #: lands unmasked in attributes and scripts, hence only these characters.
    _PREFIX_FORM = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")

    @contextlib.asynccontextmanager
    async def lifespan(self, app=None):
        """FastAPI lifespan that calls `close()` at shutdown: `FastAPI(lifespan=auth.lifespan)` (T-67).

        `close()` waits for background jobs; it runs in a worker thread so that the event loop keeps serving
        the background tasks it waits for. With a lifespan of your own, nest it:
        `async with auth.lifespan(app): yield`."""
        try:
            yield
        finally:
            import asyncio
            await asyncio.to_thread(self.close)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()






























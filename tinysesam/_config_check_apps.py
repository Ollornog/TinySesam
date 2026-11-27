"""Configuration rules for applications: forward-auth apps and their frame, the gate, approvals, registered apps with provisioning and approval types.

Split from `config_check.py` (T-112); `config_check` re-exports what other modules and the tests take from it
(its `__all__`), so they keep `config_check.<name>`.
"""
from __future__ import annotations

import re
from . import security
from .store import role_invalid

from ._config_check_base import (
    _an,
    _frame_target_ok,
    _integer,
    _t,
    _topbar_link_findings,
)
from ._config_check_roles import (
    _mapped_roles,
    configured_roles,
)


FORWARD_APP_KEY_NAME = ("name", "login", "logout", "app_passwords", "home", "links")
#: The members of a `forward_apps[host]` entry that make up the app frame (T-91) — read by the library too.
FORWARD_FRAME_KEYS = ("home", "links")
#: More frame links than this would no longer fit next to the name on a desktop (a warning, not an error).
FORWARD_FRAME_LINKS_MAX = 8
FORWARD_LOGIN = ("page", "direct")
FORWARD_LOGOUT = ("all", "app", "ask")


def _forward_apps(config, error: list, warnings: list) -> None:
    """Login mode and settings per application in front of the gate (T-21)."""
    mode = getattr(config, "forward_login", "page")
    if mode not in FORWARD_LOGIN:
        error.append(_t(
            config,
            "forward_login={mode!r}: allowed are {allowed}.",
            mode=mode, allowed=', '.join(FORWARD_LOGIN)))
    sign_out = getattr(config, "forward_logout", "all")
    if sign_out not in FORWARD_LOGOUT:
        error.append(_t(
            config,
            "forward_logout={mode!r}: allowed are {allowed}.",
            mode=sign_out, allowed=', '.join(FORWARD_LOGOUT)))
    apps = getattr(config, "forward_apps", None) or {}
    if not isinstance(apps, dict):
        error.append(_t(
            config,
            "forward_apps must be a dict: {{\"app.example.com\": {{\"name\": …, \"login\": "
            "…}}}}."))
        return
    direct = [("forward_login", mode)] if mode == "direct" else []
    trusted = {str(h).strip().lower() for h in (getattr(config, "trusted_redirect_hosts", None) or [])}
    for host, e in apps.items():
        where = f"forward_apps[{host!r}]"
        if not isinstance(e, dict):
            error.append(_t(
                config,
                "{where} must be a dict.",
                where=where))
            continue
        foreign = sorted(set(e) - set(FORWARD_APP_KEY_NAME))
        if foreign:
            # A mistyped key (`logn`) would otherwise silently not apply — the application would get
            # the global mode, and nobody would know why.
            error.append(_t(
                config,
                "{where} does not know {keys} (allowed: {allowed}).",
                where=where, keys=', '.join(foreign), allowed=', '.join(FORWARD_APP_KEY_NAME)))
        if "login" in e and e["login"] not in FORWARD_LOGIN:
            error.append(_t(
                config,
                "{where}['login']={value!r}: allowed are {allowed}.",
                where=where, value=e['login'], allowed=', '.join(FORWARD_LOGIN)))
        if "logout" in e and e["logout"] not in FORWARD_LOGOUT:
            error.append(_t(
                config,
                "{where}['logout']={value!r}: allowed are {allowed}.",
                where=where, value=e['logout'], allowed=', '.join(FORWARD_LOGOUT)))
        if "app_passwords" in e and not isinstance(e["app_passwords"], bool):
            # `"yes"` or `1` read as "on" would be a guess; `"false"` read as on would open Basic auth on an
            # application whose operator meant the opposite (T-66).
            error.append(_t(
                config,
                "{where}['app_passwords']={value!r}: expected True or False.",
                where=where, value=e['app_passwords']))
        if e.get("login") == "direct":
            direct.append((where, "direct"))
        _forward_frame(config, where, str(host).strip().lower().rstrip("."), e, error, warnings)
        if trusted and str(host).strip().lower() not in trusted:
            warnings.append(_t(
                config,
                "{where} is not in trusted_redirect_hosts — there is no redirect back for this "
                "host, the setting never takes effect.",
                where=where))
    # The app frame (T-91) is read by the library as well; only an entry WITHOUT a frame is moot without forward auth.
    if (apps and not _an(config, "forward_auth_enabled")
            and any(isinstance(e, dict) and not (set(e) & set(FORWARD_FRAME_KEYS)) for e in apps.values())):
        warnings.append(_t(
            config,
            "forward_apps is set, but forward_auth_enabled is False — only forward auth reads "
            "the per-application settings."))
    _forward_frame_default(config, apps, error, warnings)
    # "Sign out everywhere" without the provider, in front of a gate that sends directly to the provider: the
    # next page request silently signs in again — signing out looks like a reload.
    sign_outs = [sign_out] + [str(e.get("logout")) for e in apps.values() if isinstance(e, dict) and e.get("logout")]
    if (direct and _an(config, "oidc_enabled") and not _an(config, "oidc_rp_logout")
            and any(a in ("all", "ask") for a in sign_outs)):
        warnings.append(_t(
            config,
            "forward_login='direct' and sign-out (\"all\"/\"ask\"), but oidc_rp_logout=False: "
            "the session at the provider remains, and the next page request signs in again "
            "without any action. Set oidc_rp_logout=True (oidc_gateway() does that)."))
    if direct and _an(config, "forward_auth_enabled"):
        try:
            methods = list(config.enabled_methods())
        except Exception:
            methods = []
        if methods != ["oidc"]:
            error.append(_t(
                config,
                "{where}='direct' leads straight to the identity provider — that only works if "
                "OIDC is the only login method (enabled: {enabled}). Otherwise the other "
                "methods would have no way onto the login page.",
                where=direct[0][0], enabled=', '.join(methods) or _t(config, "none")))


def _forward_frame(config, where: str, host: str, e: dict, error: list, warnings: list) -> None:
    """The app frame of one `forward_apps` entry (T-91): `home` and `links` lie on exactly this host, and a frame has a
    name — the bar of a frame shows nothing else on the left."""
    if not set(e) & set(FORWARD_FRAME_KEYS):
        return
    if not (isinstance(e.get("name"), str) and e["name"].strip()):
        error.append(_t(
            config,
            "{where} has an app frame (home/links) but no name — the frame shows the application's name and "
            "nothing else on the left. Set {where}['name'].",
            where=where))
    if "home" in e and not _frame_target_ok(e["home"], {host}):
        error.append(_t(
            config,
            "{where}['home']={value!r}: a path (\"/\", on this host) or an https address on exactly this host, "
            "without quotation marks, angle brackets, backslash and spaces.",
            where=where, value=e["home"]))
    if "links" in e:
        links = e["links"]
        if not isinstance(links, (list, tuple)):
            error.append(_t(
                config,
                "{where}['links']={value!r}: a list of (title, target) pairs like topbar_links.",
                where=where, value=links))
            return
        roles_known = set(getattr(config, "available_roles", None) or [])
        _topbar_link_findings(config, f"{where}['links']", links, {host}, roles_known, error, warnings, frame=True)
        if len(links) > FORWARD_FRAME_LINKS_MAX:
            warnings.append(_t(
                config,
                "{where}['links'] has {n} entries — more than {limit} no longer fit next to the name on a desktop.",
                where=where, n=len(links), limit=FORWARD_FRAME_LINKS_MAX))
    if not getattr(config, "topbar_enabled", True):
        warnings.append(_t(
            config,
            "{where} has an app frame (home/links), but topbar_enabled=False — the frame is a form of the top bar "
            "and is not shown.",
            where=where))


def _forward_frame_default(config, apps: dict, error: list, warnings: list) -> None:
    """`forward_frame_default` (T-91) names a host of `forward_apps` whose entry has a frame."""
    raw = getattr(config, "forward_frame_default", "")
    if raw in (None, ""):
        return
    if not isinstance(raw, str):
        return                 # the type check reports it
    host = raw.strip().lower().rstrip(".")
    entry = next((e for h, e in apps.items() if str(h).strip().lower().rstrip(".") == host), None)
    if not isinstance(entry, dict) or not set(entry) & set(FORWARD_FRAME_KEYS):
        error.append(_t(
            config,
            "forward_frame_default={value!r} names no forward_apps entry with an app frame (home or links) — "
            "the default frame would be empty.",
            value=raw))


def _delegates_and_app_allowlists(config, warnings: list) -> None:
    """Delegated administration next to an application's account API (T-91, draft §5): when the roles a delegate role
    manages overlap with an `apps[id].provisioning.roles` allowlist, the panel and the application manage the same
    accounts — `may_manage` does not look at `managed_by` for delegates. Both may run side by side in one gateway, so
    it is a warning."""
    delegates = getattr(config, "admin_delegates", None)
    apps = getattr(config, "apps", None)
    if not isinstance(delegates, dict) or not isinstance(apps, dict):
        return
    for app_id, entry in apps.items():
        block = entry.get("provisioning") if isinstance(entry, dict) else None
        allow = block.get("roles") if isinstance(block, dict) else None
        if not isinstance(allow, (list, tuple)):
            continue
        allowed = {r for r in allow if isinstance(r, str)}
        for owner, spec in delegates.items():
            roles = spec.get("roles") if isinstance(spec, dict) else None
            if not isinstance(roles, (list, tuple)):
                continue
            shared = sorted(allowed & {r for r in roles if isinstance(r, str)})
            if shared:
                warnings.append(_t(
                    config,
                    "admin_delegates[{owner!r}] manages {roles}, which apps[{app!r}].provisioning.roles grants as "
                    "well — the admin panel and the application then manage the same accounts. Keep delegates "
                    "for applications without an account API.",
                    owner=owner, roles=", ".join(shared), app=app_id))


def _gate(config, error: list, warnings: list) -> None:
    """Gate token (ADR-9, T-19): only as part of forward auth, only with a cookie that the
    browser returns exclusively to the application's host."""
    if _an(config, "gate_link_enabled"):
        # Code exchange (T-26): it replaces the session cookie on the parent domain. Both at once
        # would mean sending the session to every app after all — and the exchange would be only a detour.
        if not _an(config, "gate_token_enabled"):
            error.append(_t(
                config,
                "gate_link_enabled=True without gate_token_enabled=True: the code exchange "
                "gives the app host a connection with which it gets gate tokens — without a "
                "gate token it has no purpose."))
        if str(getattr(config, "cookie_domain", "") or "").strip():
            error.append(_t(
                config,
                "gate_link_enabled=True together with cookie_domain: the code exchange is "
                "meant to NOT have the session cookie on the parent domain — otherwise it "
                "reaches every app below it. Leave cookie_domain empty."))
        if not str(getattr(config, "base_url", "") or "").strip():
            error.append(_t(
                config,
                "gate_link_enabled=True without base_url: the app hosts send to the address of "
                "the gateway for the sign-in — that is in base_url."))
    if not _an(config, "gate_token_enabled"):
        return
    if not _an(config, "forward_auth_enabled"):
        error.append(_t(
            config,
            "gate_token_enabled=True without forward_auth_enabled=True: the gate token arises "
            "in the response of /auth/forward — without the route there is none, and the proxy "
            "would fall back on every request to a check that does not exist."))
    name = str(getattr(config, "gate_cookie_name", "") or "")
    # `__Host-`: the browser accepts the cookie only with Secure, Path=/ and WITHOUT Domain — it then applies
    # to exactly the host that set it. Without the prefix only our own
    # Set-Cookie line prevents a domain cookie; with it, the browser prevents it.
    # `tinysesam_` after it: the templates strip every `tinysesam_*` cookie before the request
    # reaches the application (B-20). A differently named gate cookie would be read along by the application.
    if not re.fullmatch(r"__Host-tinysesam_[A-Za-z0-9_]+", name):
        error.append(_t(
            config,
            "gate_cookie_name={name!r} must have the form __Host-tinysesam_<name>: __Host- "
            "binds the cookie to the host of the application (the browser accepts it only "
            "without a Domain attribute), and tinysesam_ makes sure the proxy templates remove "
            "it in front of the application.",
            name=name))
    ttl = _integer(config, "gate_token_ttl_sec", None)
    if ttl is not None and 900 < ttl <= 3600:
        warnings.append(_t(
            config,
            "gate_token_ttl_sec={ttl}: for this long, neither a sign-out in another "
            "application nor a block nor an approval withdrawn at the provider takes effect at "
            "the proxy. Up to 300 s the difference to a check per request is hardly "
            "noticeable; above 15 minutes it is a revocation delay that one should want "
            "deliberately.",
            ttl=ttl))
    hosts = [h for h in (getattr(config, "trusted_redirect_hosts", None) or []) if h] + \
            [h for h in (getattr(config, "oidc_clients", None) or {}) if h]
    if not hosts and not str(getattr(config, "base_url", "") or "").strip():
        warnings.append(_t(
            config,
            "gate_token_enabled=True, but no protected host: neither trusted_redirect_hosts "
            "nor oidc_clients nor base_url. A gate token arises only for these hosts — so for "
            "none, and the proxy keeps asking on every request."))


def _approvals(config, error: list) -> None:
    """Approvals (stage A): a token asks, the person confirms in a browser session with a step-up."""
    if not _an(config, "approvals_enabled"):
        return
    if not _an(config, "apikey_enabled"):
        error.append(_t(
            config,
            "approvals_enabled=True with apikey_enabled=False: an approval is requested with an API key of the "
            "account — without keys nobody can ask."))
    if not _an(config, "csrf_enabled"):
        error.append(_t(
            config,
            "approvals_enabled=True with csrf_enabled=False: the approval page needs the CSRF protection — "
            "otherwise a foreign page could confirm an action in the name of the signed-in person."))
    if not security.normalize_base(str(getattr(config, "base_url", "") or "").strip()):
        error.append(_t(
            config,
            "approvals_enabled=True without base_url: the link handed to the requester is built from base_url "
            "— never from the Host header of a request."))


#: The id of an application in `apps` — the same rule as the first segment of an approval type.
APP_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: The members of one `apps` entry: the account API (`provisioning`), the approvals of the application's own
#: actions (`approvals`, stage B), its permissions (`permissions`, T-100), the hosts it is served on (`hosts`) and what
#: its service account may do with the permission API (`permission_scopes`, T-101).
APP_KEYS = ("account", "name", "provisioning", "approvals", "permissions", "hosts", "permission_scopes")
#: The scopes of the permission API (T-101): register the manifest (`PUT /auth/api/apps/{id}/permissions`), read the
#: permissions of an account for the application (`GET /auth/api/users/{id}/permissions?app=`).
PERMISSION_SCOPES = ("permissions:register", "permissions:read")
#: A host of `apps[id].hosts`: lower case, no port, no scheme, no trailing dot — what forward auth compares against.
APP_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
APP_HOSTS_MAX = 32
#: The members of `apps[…].provisioning` and the scopes an application may hold (account API, stages A and B).
PROVISIONING_KEYS = ("roles", "scopes", "link_ttl_min", "max_accounts", "limits", "approver_role", "delete_grace_days",
                     "welcome_url")
#: `users:reset` asks for the approval type `tinysesam.account.reset_access` — a person holding `approver_role`
#: confirms it; the scope alone resets nothing. `users:delete` deletes (with a grace period) and restores.
PROVISIONING_SCOPES = ("users:read", "users:invite", "users:update", "users:disable", "users:delete", "users:reset")
#: Default and upper bound of the per-application limits (per hour, `delete_per_day` per day); `taken` counts answers
#: "name/address taken".
PROVISIONING_LIMITS = {"create_per_hour": 60, "disable_per_hour": 60, "link_per_hour": 30, "taken_per_hour": 30,
                       "delete_per_hour": 20, "delete_per_day": 100}
PROVISIONING_LIMIT_MAX = 100000
PROVISIONING_DEFAULTS = {"link_ttl_min": 60, "max_accounts": 1000, "delete_grace_days": 7}
PROVISIONING_MAX_ACCOUNTS = 100000
#: The longest grace period of a deletion by an application (days); 0 = at once and for good.
PROVISIONING_GRACE_MAX = 30


def _plain_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _apps(config, error: list, warnings: list) -> None:
    """The application register `apps` (account API for applications, stage A): id, service account, name and the
    `provisioning` block — allowlist, scopes, link lifetime, quota, limits.

    The allowlist is the boundary of what a leaked application key can grant: never `admin` (forward auth reads it as
    the admin flag), never a delegate role (a key would appoint delegates, rule E4), never a role a group map assigns
    (the next sign-in would overwrite it — two sources of one truth), only listed roles, no comma or control
    character (T-85)."""
    raw = getattr(config, "apps", None)
    if not raw:
        return
    if not isinstance(raw, dict):
        error.append(_t(config, "apps: {v!r} — a mapping of application id → {{\"account\": service account, "
                                "\"name\": …, \"provisioning\": {{…}}}}", v=raw))
        return
    known = set(getattr(config, "available_roles", None) or [])
    delegates = set((getattr(config, "admin_delegates", None) or {}) if isinstance(
        getattr(config, "admin_delegates", None), dict) else {})
    mapped = set(_mapped_roles(config))
    accounts: dict = {}
    role_owner: dict = {}
    host_owner: dict = {}
    provisioning = False
    permission_api = False
    max_ttl = _integer(config, "signin_link_max_ttl_min", 24 * 60) or 24 * 60
    for app_id, entry in raw.items():
        if not isinstance(app_id, str) or not APP_ID.match(app_id):
            error.append(_t(config, "apps: the id {app!r} — lower-case letters, digits and _ , starting with a letter, "
                                    "at most 32 characters", app=app_id))
            continue
        if not isinstance(entry, dict) or set(entry) - set(APP_KEYS):
            error.append(_t(config, "apps[{app!r}]: {v!r} — allowed members are {keys}",
                            app=app_id, v=entry, keys=", ".join(APP_KEYS)))
            continue
        manifest = entry.get("permissions")
        if manifest is not None:
            from . import _permissions
            problem = _permissions.manifest_error(manifest)
            if problem:
                error.append(_t(config, "apps[{app!r}].permissions: {problem}", app=app_id, problem=problem))
            else:
                held = {r for _, r in configured_roles(config)}
                for spec in manifest:
                    for role in spec.get("suggested_roles", []):
                        if role not in held:
                            warnings.append(_t(config, "apps[{app!r}].permissions: {perm} suggests the role {role!r}, "
                                                       "which the configuration does not name — the panel "
                                                       "shows the hint anyway, it grants nothing", app=app_id,
                                               perm=spec["name"], role=role))
        hosts = entry.get("hosts")
        if hosts is not None:
            if (not isinstance(hosts, list) or not hosts or len(hosts) > APP_HOSTS_MAX
                    or not all(isinstance(h, str) and APP_HOST.match(h) for h in hosts)):
                error.append(_t(config, "apps[{app!r}].hosts: a non-empty list of at most {max} host names in lower "
                                        "case, without scheme, port or trailing dot (\"docs.example.com\")",
                                app=app_id, max=APP_HOSTS_MAX))
            else:
                for host in hosts:
                    other = host_owner.get(host)
                    if other is not None and other != app_id:
                        error.append(_t(config, "apps: {a!r} and {b!r} both name the host {host!r} — a host belongs to "
                                                "at most one application (its permissions travel with the requests "
                                                "to it)", a=other, b=app_id, host=host))
                    host_owner.setdefault(host, app_id)
        scopes_api = entry.get("permission_scopes")
        if scopes_api is not None:
            permission_api = True
            if (not isinstance(scopes_api, list) or not scopes_api
                    or not all(isinstance(x, str) and x in PERMISSION_SCOPES for x in scopes_api)):
                error.append(_t(config, "apps[{app!r}].permission_scopes: a non-empty list of {scopes}",
                                app=app_id, scopes=", ".join(PERMISSION_SCOPES)))
        account = entry.get("account")
        if account is None and not {"provisioning", "approvals", "permission_scopes"} & set(entry):
            pass                    # an entry that only declares permissions (or a name) speaks through no key
        elif (not isinstance(account, str) or not account.strip() or account != account.strip()
                or any(ord(z) < 32 or ord(z) == 127 for z in account)):
            error.append(_t(config, "apps[{app!r}]: \"account\" must name the service account (is_service) whose "
                                    "automation keys speak for the application", app=app_id))
        else:
            other = accounts.get(account.lower())
            if other is not None:
                error.append(_t(config, "apps: {a!r} and {b!r} name the same service account {account!r} — it would "
                                        "be unclear for which application a key speaks",
                                a=other, b=app_id, account=account))
            accounts.setdefault(account.lower(), app_id)
        name = entry.get("name")
        if name is not None and not (
                (isinstance(name, str) and name.strip())
                or (isinstance(name, dict) and name and all(isinstance(k, str) and isinstance(v, str) and v.strip()
                                                             for k, v in name.items()))):
            error.append(_t(config, "apps[{app!r}]: \"name\" is a text or a mapping language → text "
                                    "({{\"en\": \"Example\", \"de\": \"Example\"}})", app=app_id))
        block = entry.get("provisioning")
        if block is None:
            continue
        provisioning = True
        if not isinstance(block, dict) or set(block) - set(PROVISIONING_KEYS):
            error.append(_t(config, "apps[{app!r}].provisioning: {v!r} — allowed members are {keys}",
                            app=app_id, v=block, keys=", ".join(PROVISIONING_KEYS)))
            continue
        roles = block.get("roles")
        if not isinstance(roles, list) or not roles or not all(isinstance(r, str) and r.strip() for r in roles):
            error.append(_t(config, "apps[{app!r}].provisioning.roles: a non-empty list of roles the application "
                                    "may grant (its allowlist)", app=app_id))
            roles = []
        for role in roles:
            if role == "admin":
                error.append(_t(config, "apps[{app!r}].provisioning.roles: \"admin\" is never grantable by an "
                                        "application — forward auth reads it as the admin flag", app=app_id))
            elif role in delegates:
                error.append(_t(config, "apps[{app!r}].provisioning.roles: {role!r} is a delegate role "
                                        "(admin_delegates) — an application key never appoints delegates",
                                app=app_id, role=role))
            elif role in mapped:
                error.append(_t(config, "apps[{app!r}].provisioning.roles: {role!r} is assigned by a group map — the "
                                        "next sign-in would overwrite what the application set (two sources of one "
                                        "truth)", app=app_id, role=role))
            elif role_invalid(role):
                error.append(_t(config, "apps[{app!r}].provisioning.roles: {role!r} contains a comma, a control "
                                        "character or surrounding spaces — Remote-Groups would read it as other "
                                        "roles", app=app_id, role=role))
            elif role not in known:
                error.append(_t(config, "apps[{app!r}].provisioning.roles: {role!r} is not in available_roles",
                                app=app_id, role=role))
            else:
                if not role.startswith(app_id + "-"):
                    warnings.append(_t(config, "apps[{app!r}].provisioning.roles: {role!r} does not begin with "
                                               "{prefix!r} — such a role may also open something else, e.g. a gate "
                                               "rule of another application", app=app_id, role=role,
                                       prefix=app_id + "-"))
                if role in role_owner and role_owner[role] != app_id:
                    warnings.append(_t(config, "apps: {a!r} and {b!r} share the role {role!r} — each application "
                                               "grants what opens the other", a=role_owner[role], b=app_id,
                                       role=role))
                role_owner.setdefault(role, app_id)
        scopes = block.get("scopes")
        if (not isinstance(scopes, list) or not scopes
                or not all(isinstance(s, str) and s in PROVISIONING_SCOPES for s in scopes)):
            error.append(_t(config, "apps[{app!r}].provisioning.scopes: a non-empty list of {scopes}",
                            app=app_id, scopes=", ".join(PROVISIONING_SCOPES)))
            scopes = []
        if "users:invite" in scopes:
            if not _an(config, "magiclink_enabled"):
                error.append(_t(config, "apps[{app!r}]: the scope users:invite needs magiclink_enabled=True — "
                                        "otherwise no route redeems the one-time link", app=app_id))
            if not security.normalize_base(str(getattr(config, "base_url", "") or "").strip()):
                error.append(_t(config, "apps[{app!r}]: the scope users:invite needs base_url — the one-time link "
                                        "is built from it, never from the Host header", app=app_id))
        welcome = block.get("welcome_url")
        if welcome is not None and not link_next_ok(config, welcome):
            error.append(_t(config, "apps[{app!r}].provisioning.welcome_url={v!r} — a path (/…) or an http(s) address "
                                    "on the host of base_url or in trusted_redirect_hosts, printable ASCII without "
                                    "user part, at most {max} characters", app=app_id, v=welcome, max=LINK_NEXT_MAX))
        ttl = block.get("link_ttl_min", PROVISIONING_DEFAULTS["link_ttl_min"])
        if not _plain_int(ttl) or not 1 <= ttl <= max_ttl:
            error.append(_t(config, "apps[{app!r}].provisioning.link_ttl_min={v!r} — 1 to signin_link_max_ttl_min "
                                    "({max})", app=app_id, v=ttl, max=max_ttl))
        quota = block.get("max_accounts", PROVISIONING_DEFAULTS["max_accounts"])
        if not _plain_int(quota) or not 1 <= quota <= PROVISIONING_MAX_ACCOUNTS:
            error.append(_t(config, "apps[{app!r}].provisioning.max_accounts={v!r} — 1 to {max}",
                            app=app_id, v=quota, max=PROVISIONING_MAX_ACCOUNTS))
        grace = block.get("delete_grace_days", PROVISIONING_DEFAULTS["delete_grace_days"])
        if not _plain_int(grace) or not 0 <= grace <= PROVISIONING_GRACE_MAX:
            error.append(_t(config, "apps[{app!r}].provisioning.delete_grace_days={v!r} — 0 (at once) to {max} days",
                            app=app_id, v=grace, max=PROVISIONING_GRACE_MAX))
        limits = block.get("limits", {})
        if not isinstance(limits, dict) or set(limits) - set(PROVISIONING_LIMITS) or not all(
                _plain_int(v) and 1 <= v <= PROVISIONING_LIMIT_MAX for v in limits.values()):
            error.append(_t(config, "apps[{app!r}].provisioning.limits: {v!r} — numbers from 1 to {max} for {keys}",
                            app=app_id, v=limits, max=PROVISIONING_LIMIT_MAX, keys=", ".join(PROVISIONING_LIMITS)))
    _approver_roles(config, raw, known, error, warnings)
    if permission_api and not _an(config, "apikey_enabled"):
        error.append(_t(config, "apps with permission_scopes and apikey_enabled=False: an application calls the "
                                "permission API with an automation key of its service account"))
    if not provisioning and not permission_api:
        return
    if not provisioning:
        if str(getattr(config, "admin_path", "") or "").rstrip("/") == "/auth":
            error.append(_t(config, "admin_path='/auth' with apps: /auth/api/ is reserved for the machine APIs — the "
                                    "panel's JSON would lie under /auth/api/users, the path of the account API"))
        return
    if not _an(config, "apikey_enabled"):
        error.append(_t(config, "apps with provisioning and apikey_enabled=False: an application calls the account "
                                "API with an automation key of its service account"))
    if str(getattr(config, "admin_path", "") or "").rstrip("/") == "/auth":
        error.append(_t(config, "admin_path='/auth' with apps: /auth/api/ is reserved for the machine APIs — the "
                                "panel's JSON would lie under /auth/api/users, the path of the account API"))



#: The longest target a sign-in link may carry to the end of the first sign-in (`next`, `welcome_url`, T-94).
LINK_NEXT_MAX = 2048
#: The longest `totp_app_hint` text and the most languages it may hold.
TOTP_APP_HINT_MAX = 300
TOTP_APP_HINT_LANGS = 20
_LANG_TAG = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
#: The placeholder of the mount prefix in the built-in pages (`manager._PREFIX_PLACEHOLDER`): never part of a target.
_PREFIX_MARK = "__TS_P__"


def link_next_ok(config, value) -> bool:
    """May a sign-in link lead here once the first sign-in is complete (`next` of the account API, `welcome_url`)?

    The circle of every redirect of TinySesam (`TinySesam.safe_next`): a relative path (one leading `/`), or an
    absolute `http(s)` address whose host is the host of `base_url` or stands in `trusted_redirect_hosts` — never one
    from the `Host` header. Stricter than `safe_next`, which falls back to `login_redirect` in silence: here the value
    must pass UNCHANGED, so a wrong target is refused where it is given (400), not dropped at the door. Printable ASCII
    only (an international domain name in its `xn--` form): no control character, no space, no backslash, no user part
    (`https://app.example.com@evil.example`), no protocol-relative `//host`, no other scheme (`javascript:`)."""
    if not isinstance(value, str) or not value or len(value) > LINK_NEXT_MAX:
        return False
    if any(not 0x21 <= ord(z) <= 0x7e for z in value) or _PREFIX_MARK in value:
        return False
    hosts = [n for n in (security.host_name(h) for h in (getattr(config, "trusted_redirect_hosts", None) or [])) if n]
    own = security.host_name(getattr(config, "base_url", "") or "")
    if own and own not in hosts:
        hosts.append(own)
    sentinel = "\x00refused"
    return security.safe_next(value, sentinel, hosts or None) == value


def totp_app_hint_ok(text) -> bool:
    """One text of `totp_app_hint`: 1 to `TOTP_APP_HINT_MAX` characters, not only spaces, no control or format
    character (line breaks, bidirectional overrides and zero-width characters included)."""
    import unicodedata
    return (isinstance(text, str) and bool(text.strip()) and len(text) <= TOTP_APP_HINT_MAX
            and not any(unicodedata.category(z) in ("Cc", "Cf", "Zl", "Zp") for z in text))


def _first_sign_in(config, error: list, warnings: list) -> None:
    """The first sign-in through a one-time link (T-94): the TOTP hint, and recovery codes switched off without a
    way back for a lost authenticator."""
    hints = getattr(config, "totp_app_hint", None)
    if hints not in (None, {}):
        if (not isinstance(hints, dict) or len(hints) > TOTP_APP_HINT_LANGS
                or not all(isinstance(k, str) and _LANG_TAG.match(k) and totp_app_hint_ok(v)
                           for k, v in hints.items())):
            error.append(_t(config, "totp_app_hint: a mapping language → text (at most {langs} languages such as "
                                    "\"en\", \"de\"), each text 1 to {max} characters of plain text without control "
                                    "characters or line breaks", langs=TOTP_APP_HINT_LANGS, max=TOTP_APP_HINT_MAX))
    codes = getattr(config, "recovery_codes_enabled", True)
    if not isinstance(codes, bool):
        error.append(_t(config, "recovery_codes_enabled={v!r} — True or False", v=codes))
        return
    if codes or not _an(config, "totp_enabled") or _an(config, "admin_enabled"):
        return
    # The configured ways that reset a lost authenticator: the admin panel's TOTP reset (T-98, checked above) and an
    # application's `reset_access` (an approval). Without both, the operator's CLI on the database file and the
    # application's own code (`totp_disable` + `grant_mfa_enrollment` + a link) remain — invisible here, so the text
    # names them.
    raw = getattr(config, "apps", None)
    reset = _an(config, "approvals_enabled") and isinstance(raw, dict) and any(
        isinstance(e, dict) and isinstance(e.get("provisioning"), dict)
        and isinstance(e["provisioning"].get("scopes"), list) and "users:reset" in e["provisioning"]["scopes"]
        and e["provisioning"].get("approver_role") for e in raw.values())
    if not reset:
        warnings.append(_t(config, "recovery_codes_enabled=False, the admin panel is off and no application may reset "
                                   "an access (apps[…].provisioning with the scope users:reset): whoever loses their "
                                   "authenticator app is locked out until the operator runs `tinysesam reset-totp` on "
                                   "the database or the application's own code removes the TOTP (totp_disable, "
                                   "grant_mfa_enrollment, create_signin_link)."))


def _approver_roles(config, raw: dict, known: set, error: list, warnings: list) -> None:
    """`apps[…].provisioning.approver_role` and the scope `users:reset` (approval type
    `tinysesam.account.reset_access`): who may confirm that an application resets the access of one of its accounts.

    The role is the whole protection against a leaked application key: the key may create accounts and give them
    every role of the allowlist, sign in through their one-time link — so a role an application can grant must never
    be the one that confirms (straw-account attack). Hence an error when it stands in the allowlist of ANY application
    with provisioning, and only a warning (a hint) when a delegate may grant it: then the operator has chosen that
    delegates appoint approvers."""
    allowlists: dict = {}
    for app_id, entry in raw.items():
        block = entry.get("provisioning") if isinstance(entry, dict) else None
        if isinstance(block, dict) and isinstance(block.get("roles"), list):
            allowlists[app_id] = [r for r in block["roles"] if isinstance(r, str)]
    raw_delegates = getattr(config, "admin_delegates", None)
    granted_by_delegates: dict = {}
    if isinstance(raw_delegates, dict):
        for d_role, d_entry in raw_delegates.items():
            roles = d_entry.get("roles") if isinstance(d_entry, dict) else None
            for r in roles if isinstance(roles, list) else []:
                if isinstance(r, str):
                    granted_by_delegates.setdefault(r, d_role)
    for app_id, entry in raw.items():
        block = entry.get("provisioning") if isinstance(entry, dict) else None
        if not isinstance(app_id, str) or not APP_ID.match(app_id) or not isinstance(block, dict):
            continue
        raw_scopes = block.get("scopes")
        scopes: list = raw_scopes if isinstance(raw_scopes, list) else []
        role = block.get("approver_role")
        if role is None:
            if "users:reset" in scopes:
                error.append(_t(config, "apps[{app!r}]: the scope users:reset needs provisioning.approver_role — the "
                                        "role of the people who may confirm a reset", app=app_id))
            continue
        if role_invalid(role):
            error.append(_t(config, "apps[{app!r}].provisioning.approver_role={v!r} — one role name without comma, "
                                    "control character or surrounding spaces", app=app_id, v=role))
            continue
        if role == "admin":
            error.append(_t(config, "apps[{app!r}].provisioning.approver_role: \"admin\" is the admin flag, not a "
                                    "role — name the role of the people who confirm a reset", app=app_id))
            continue
        if role not in known:
            error.append(_t(config, "apps[{app!r}].provisioning.approver_role: {role!r} is not in available_roles",
                            app=app_id, role=role))
        for other, allow in sorted(allowlists.items(), key=lambda kv: str(kv[0])):
            if role in allow:
                error.append(_t(config, "apps[{app!r}].provisioning.approver_role: {role!r} stands in the allowlist "
                                        "of {other!r} — an application key could give it to an account it created, "
                                        "sign in with that account's one-time link and confirm the reset itself",
                                app=app_id, role=role, other=other))
        if role in granted_by_delegates:
            warnings.append(_t(config, "apps[{app!r}].provisioning.approver_role: {role!r} may be granted by the "
                                       "delegates of {delegate!r} (admin_delegates) — they appoint who confirms a "
                                       "reset of the application's accounts", app=app_id, role=role,
                               delegate=granted_by_delegates[role]))
        if "users:reset" not in scopes:
            warnings.append(_t(config, "apps[{app!r}].provisioning.approver_role is set, but the scope users:reset "
                                       "is missing — nobody can ask for a reset, the role has no effect here",
                               app=app_id))
            continue
        if not _an(config, "approvals_enabled"):
            error.append(_t(config, "apps[{app!r}]: the scope users:reset needs approvals_enabled=True — the reset is "
                                    "an approval the approver confirms in the browser", app=app_id))
        if not _an(config, "magiclink_enabled"):
            error.append(_t(config, "apps[{app!r}]: the scope users:reset needs magiclink_enabled=True — the new "
                                    "one-time link is the only way back into the account", app=app_id))
        elif _an(config, "magiclink_first_login_only") and not list(getattr(config, "login_chain", None) or []):
            error.append(_t(config, "apps[{app!r}]: the scope users:reset with magiclink_first_login_only=True and "
                                    "no login_chain — the door would refuse the new link of an account that has "
                                    "signed in before", app=app_id))
        if not security.normalize_base(str(getattr(config, "base_url", "") or "").strip()):
            error.append(_t(config, "apps[{app!r}]: the scope users:reset needs base_url — the one-time link is "
                                    "built from it, never from the Host header", app=app_id))

#: The members of `apps[…].approvals` (approvals of the application's own actions, stage B).
APPROVAL_KEYS = ("types", "types_file", "return_urls", "types_from")
#: An application action type: ASCII, dot namespace, at least three segments, the first the application's id.
APPROVAL_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){2,5}$")
APPROVAL_TYPE_MAX = 100
#: The members of one type and the name rule of its fields (`type` is the entry's own member, RFC 9396).
APPROVAL_TYPE_KEYS = ("fields", "title", "summary", "irreversible")
APPROVAL_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: Field kinds and their members; a string field must name its longest value.
APPROVAL_FIELD_KEYS = {"string": ("type", "max", "pattern"), "integer": ("type", "min", "max"), "boolean": ("type",)}
APPROVAL_STRING_MAX = 500
APPROVAL_PATTERN_MAX = 200
APPROVAL_FIELDS_MAX = 16
APPROVAL_TYPES_MAX = 100
APPROVAL_TITLE_MAX = 120
APPROVAL_SUMMARY_MAX = 1000
APPROVAL_RETURN_URLS_MAX = 20
APPROVAL_URL_MAX = 2000
#: JSON-safe integers in every language (±(2^53 − 1)).
APPROVAL_INT_LIMIT = 2 ** 53 - 1
_LANG = re.compile(r"^[a-z]{2}$")


def _bad_text(text) -> bool:
    return not isinstance(text, str) or not text.strip() or any(ord(z) < 32 or 127 <= ord(z) < 160 for z in text)


def _placeholders(template: str):
    """The field names a template names — or None when it is no plain `{name}` template (a format spec, a
    conversion, an attribute or index, an unbalanced brace)."""
    import string
    names = []
    try:
        for _literal, name, spec, conversion in string.Formatter().parse(template):
            if name is None:
                continue
            if spec or conversion or not APPROVAL_FIELD.match(name):
                return None
            names.append(name)
    except ValueError:
        return None
    return names


#: The findings of `approval_type_findings` — key → English template (German in `_DE`).
APPROVAL_FINDINGS = {
    "type_name": (
        "apps[{app!r}].approvals.types: {type!r} — ASCII, at least three segments separated by dots, the "
        "first one the application's id ({app}.<thing>.<action>), at most 100 characters"),
    "type_members": (
        "apps[{app!r}].approvals.types[{type!r}]: allowed members are {keys}; \"fields\", \"title\" and "
        "\"summary\" are required"),
    "fields_shape": (
        "apps[{app!r}].approvals.types[{type!r}].fields: a mapping field name → schema, at most {max} fields"),
    "field_name": (
        "apps[{app!r}].approvals.types[{type!r}].fields: {field!r} — lower-case letters, digits and _ , "
        "starting with a letter, at most 32 characters, never \"type\""),
    "field_schema": (
        "apps[{app!r}].approvals.types[{type!r}].fields[{field!r}]: {{\"type\": \"string\", \"max\": …, \"pattern\": "
        "…}}, {{\"type\": \"integer\", \"min\": …, \"max\": …}} or {{\"type\": \"boolean\"}}"),
    "string_max": (
        "apps[{app!r}].approvals.types[{type!r}].fields[{field!r}].max: the longest value, 1 to {max} "
        "characters"),
    "pattern": (
        "apps[{app!r}].approvals.types[{type!r}].fields[{field!r}].pattern: a regular expression of at most "
        "{max} characters (it must match the whole value)"),
    "integer_range": (
        "apps[{app!r}].approvals.types[{type!r}].fields[{field!r}]: min and max are integers within ±(2^53 − "
        "1), min not above max"),
    "texts_shape": (
        "apps[{app!r}].approvals.types[{type!r}].{member}: a mapping language → text with at least \"en\" "
        "({{\"en\": …, \"de\": …}})"),
    "text": (
        "apps[{app!r}].approvals.types[{type!r}].{member}[{lang!r}]: a text of at most {max} characters "
        "without control characters"),
    "title_placeholder": (
        "apps[{app!r}].approvals.types[{type!r}].title[{lang!r}]: the title is fixed text — no placeholder"),
    "summary_placeholders": (
        "apps[{app!r}].approvals.types[{type!r}].summary[{lang!r}]: only {{field}} placeholders (no format, "
        "no attribute; a literal brace is written {{{{ or }}}})"),
    "unknown_placeholder": (
        "apps[{app!r}].approvals.types[{type!r}].summary[{lang!r}]: the placeholder {{{name}}} is no field "
        "of the type"),
    "irreversible": (
        "apps[{app!r}].approvals.types[{type!r}].irreversible: true or false"),
}


def approval_type_findings(app_id: str, name, spec) -> list:
    """Why the action type `name` of application `app_id` is unusable — a list of (key of `APPROVAL_FINDINGS`, values), empty
    when it is fine. Pure: `config_check` turns each into a message, `approvals.normalize_app_approvals` leaves a type
    with findings out (fail-closed for a configuration changed at runtime)."""
    out: list = []
    if (not isinstance(name, str) or len(name) > APPROVAL_TYPE_MAX or not APPROVAL_TYPE.match(name)
            or name.split(".", 1)[0] != app_id):
        out.append(("type_name", {}))
        return out
    if not isinstance(spec, dict) or set(spec) - set(APPROVAL_TYPE_KEYS) or "fields" not in spec:
        out.append(("type_members", {"keys": ", ".join(APPROVAL_TYPE_KEYS)}))
        return out
    fields = spec.get("fields")
    if not isinstance(fields, dict) or len(fields) > APPROVAL_FIELDS_MAX:
        out.append(("fields_shape", {"max": APPROVAL_FIELDS_MAX}))
        fields = {}
    for field_name, schema in fields.items():
        kind = schema.get("type") if isinstance(schema, dict) else None
        if not isinstance(field_name, str) or not APPROVAL_FIELD.match(field_name) or field_name == "type":
            out.append(("field_name", {"field": field_name}))
            continue
        if kind not in APPROVAL_FIELD_KEYS or set(schema) - set(APPROVAL_FIELD_KEYS[kind]):
            out.append(("field_schema", {"field": field_name}))
            continue
        if kind == "string":
            top = schema.get("max")
            if not _plain_int(top) or not 1 <= top <= APPROVAL_STRING_MAX:
                out.append(("string_max", {"field": field_name, "max": APPROVAL_STRING_MAX}))
            if "pattern" in schema:
                pattern = schema["pattern"]
                compiled = None
                if isinstance(pattern, str) and 0 < len(pattern) <= APPROVAL_PATTERN_MAX:
                    try:
                        compiled = re.compile(pattern)
                    except re.error:
                        compiled = None
                if compiled is None:
                    out.append(("pattern",
                                {"field": field_name, "max": APPROVAL_PATTERN_MAX}))
        elif kind == "integer":
            low, high = schema.get("min", -APPROVAL_INT_LIMIT), schema.get("max", APPROVAL_INT_LIMIT)
            if (not _plain_int(low) or not _plain_int(high) or not -APPROVAL_INT_LIMIT <= low <= high <= APPROVAL_INT_LIMIT):
                out.append(("integer_range", {"field": field_name}))
    names = {f for f in fields if isinstance(f, str)}
    for member, limit in (("title", APPROVAL_TITLE_MAX), ("summary", APPROVAL_SUMMARY_MAX)):
        texts = spec.get(member)
        if (not isinstance(texts, dict) or "en" not in texts
                or not all(isinstance(k, str) and _LANG.match(k) for k in texts)):
            out.append(("texts_shape", {"member": member}))
            continue
        for lang, text in texts.items():
            if _bad_text(text) or len(text) > limit:
                out.append(("text", {"member": member, "lang": lang, "max": limit}))
                continue
            used = _placeholders(text)
            if member == "title" and ("{" in text or "}" in text):
                out.append(("title_placeholder", {"lang": lang}))
            elif used is None:
                out.append(("summary_placeholders", {"lang": lang}))
            else:
                for placeholder in used:
                    if placeholder not in names:
                        out.append(("unknown_placeholder", {"lang": lang, "name": placeholder}))
    if "irreversible" in spec and not isinstance(spec["irreversible"], bool):
        out.append(("irreversible", {}))
    return out


def approval_return_url_ok(url) -> bool:
    """A registered return address of the browser entry: absolute `https` (plain `http` only to a loopback host), no
    user info, no query, no fragment, no whitespace or control character, at most 2000 characters. Compared exactly."""
    from urllib.parse import urlsplit
    if not isinstance(url, str) or not url or len(url) > APPROVAL_URL_MAX or any(ord(z) <= 32 or ord(z) >= 127 for z in url):
        return False
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        if p.port == 0:          # reading the port also raises ValueError for a malformed one
            return False
    except ValueError:
        return False
    if p.scheme == "http":
        if host not in ("127.0.0.1", "::1", "localhost"):
            return False
    elif p.scheme != "https":
        return False
    return bool(host) and "@" not in p.netloc and not p.query and not p.fragment and "?" not in url and "#" not in url


def read_approval_types_file(path) -> tuple:
    """(types, None) from a `types_file` — a JSON object type name → definition — or (None, reason)."""
    import json
    if not isinstance(path, str) or not path.strip():
        return None, "not a path"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        return None, type(e).__name__
    if not isinstance(data, dict):
        return None, "not a JSON object"
    return data, None


def _app_approvals(config, error: list) -> None:
    """`apps[…].approvals` (approvals of application actions, stage B): the operator's action types with their fixed
    texts and field schemas, the exact return addresses of the browser entry, and `types_from` for a second channel.

    The texts are the protection against phishing: what the person reads comes from the operator, never from the
    application, which only sends field values (shown escaped and bidi-isolated). Hence types only from this
    configuration (or a file the operator names), never registered through an API."""
    raw = getattr(config, "apps", None)
    if not isinstance(raw, dict):
        return
    blocks = {a: e["approvals"] for a, e in raw.items()
              if isinstance(a, str) and APP_ID.match(a) and isinstance(e, dict) and "approvals" in e}
    for app_id, block in sorted(blocks.items()):
        if not isinstance(block, dict) or set(block) - set(APPROVAL_KEYS):
            error.append(_t(config, "apps[{app!r}].approvals: {v!r} — allowed members are {keys}",
                            app=app_id, v=block, keys=", ".join(APPROVAL_KEYS)))
            continue
        if not _an(config, "approvals_enabled"):
            error.append(_t(config, "apps[{app!r}].approvals needs approvals_enabled=True", app=app_id))
        if app_id == "tinysesam":
            error.append(_t(config, "apps: the id 'tinysesam' is reserved for TinySesam's own approval types — name "
                                    "the application differently"))
        sources = [k for k in ("types", "types_file", "types_from") if k in block]
        if len(sources) != 1:
            error.append(_t(config, "apps[{app!r}].approvals: exactly one of types, types_file and types_from",
                            app=app_id))
        types = block.get("types")
        if "types_file" in block:
            types, why = read_approval_types_file(block["types_file"])
            if types is None:
                error.append(_t(config, "apps[{app!r}].approvals.types_file {path!r} cannot be read as a JSON object "
                                        "type name → definition ({why})", app=app_id, path=block["types_file"],
                                why=why))
        if "types" in block or ("types_file" in block and types is not None):
            if not isinstance(types, dict) or len(types) > APPROVAL_TYPES_MAX:
                error.append(_t(config, "apps[{app!r}].approvals.types: a mapping type name → definition, at most "
                                        "{max}", app=app_id, max=APPROVAL_TYPES_MAX))
            else:
                for name, spec in types.items():
                    for key, values in approval_type_findings(app_id, name, spec):
                        error.append(_t(config, APPROVAL_FINDINGS[key], app=app_id, type=name, **values))
        if "types_from" in block:
            other = block["types_from"]
            target = blocks.get(other) if isinstance(other, str) else None
            if other == app_id or not isinstance(target, dict) or not ({"types", "types_file"} & set(target)):
                error.append(_t(config, "apps[{app!r}].approvals.types_from={v!r} — the id of another application "
                                        "whose approvals block has types or types_file", app=app_id, v=other))
        urls = block.get("return_urls", [])
        if (not isinstance(urls, list) or len(urls) > APPROVAL_RETURN_URLS_MAX
                or not all(approval_return_url_ok(u) for u in urls)):
            error.append(_t(config, "apps[{app!r}].approvals.return_urls: at most {max} absolute https addresses "
                                    "(http only to 127.0.0.1, ::1 or localhost) without query, fragment or user info — "
                                    "compared exactly", app=app_id, max=APPROVAL_RETURN_URLS_MAX))

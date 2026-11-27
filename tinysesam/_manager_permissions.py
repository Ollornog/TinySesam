"""The building block `permissions` of `TinySesam` (T-100, ADR-17): what an application declares it can do, and who may.

The application declares its permissions — in the configuration (`apps[id].permissions`) or by calling
`register_permissions` — and that is all it can do: registering grants nothing. The operator assigns permissions to roles
(the panel, `grant_permission`), per application. `has_permission(user, "docs.delete", app="docs")` is then the union
over the account's roles for that application only; an API key's scope narrows the roles first, so a service gets the
intersection. An administrator holds no permission by the flag alone unless `admin_implies_permissions` says so.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as `self`,
exactly as it did inside the class (T-112).
"""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request

from . import _permissions, security
from .errors import ConfigError
from .store import role_invalid


def _permission_app(self, app) -> str:
    """`app` as an application id of `apps` — or `ConfigError` (a typo must not answer "no" forever)."""
    apps = self.cfg.apps if isinstance(getattr(self.cfg, "apps", None), dict) else {}
    if not isinstance(app, str) or app not in apps:
        raise ConfigError(f"permissions: {app!r} is no application in `apps` (known: {', '.join(sorted(apps)) or '-'})")
    return app


def register_permissions(self, app: str, permissions: list) -> dict:
    """Declare the permissions of the application `app` (an id in `apps`) — its whole manifest, idempotent.

    Each entry: `{"name": "docs.delete", "label": {"en": …, "de": …}, "description": …, "danger": bool,
    "suggested_roles": [...]}` (`name` required, rule `^[a-z][a-z0-9_-]{0,31}(\\.[a-z0-9_-]{1,32}){1,3}$`, at most 200
    per application). A new name is added and grants nothing until an administrator assigns it; a name this manifest
    no longer contains becomes *orphaned* — it grants nothing, stays visible in the panel and can be deleted there; when
    it comes back its old assignments stay suspended (never silently re-granted). Names the configuration declares
    stay the configuration's. Returns `{"added", "updated", "returned", "orphaned"}`; `ValueError` for an invalid
    manifest, `ConfigError` for an unknown application."""
    return self._sync_permissions(_permission_app(self, app), "app", permissions)


def _sync_permissions(self, app: str, source: str, permissions) -> dict:
    error = _permissions.manifest_error(permissions)
    if error:
        raise ValueError(f"register_permissions({app!r}): {error}")
    specs = [_permissions.normalized(p) for p in permissions]
    others = self.store.active_permission_count(app, source)
    if others + len(specs) > _permissions.MAX_PER_APP:
        raise ValueError(f"register_permissions({app!r}): {others + len(specs)} permissions together with the other "
                         f"manifest — at most {_permissions.MAX_PER_APP} per application")
    out = self.store.sync_permissions(app, source, specs)
    if any(out.values()):
        self.audit("permissions_registered", None, None,
                   f"app={app} source={source} " + " ".join(f"{k}={','.join(v)}" for k, v in out.items() if v))
    return out


def _register_config_permissions(self) -> None:
    """At start: the configuration's manifests (`apps[id].permissions`) — and an empty one for every application whose
    configured permissions are gone (they become orphaned, never deleted silently)."""
    apps = self.cfg.apps if isinstance(getattr(self.cfg, "apps", None), dict) else {}
    declared = {a: e["permissions"] for a, e in apps.items() if isinstance(e, dict) and "permissions" in e}
    for app in sorted(set(declared) | set(self.store.permission_apps("config"))):
        self._sync_permissions(app, "config", declared.get(app, []))


def permissions_of(self, user, *, app: str) -> list:
    """The permissions of `app` this account holds, sorted: the union over its roles (an API key's scope narrows
    them first), every current one for an administrator with `admin_implies_permissions`."""
    app = _permission_app(self, app)
    if user is None:
        return []
    if self.cfg.admin_implies_permissions and bool(user["is_admin"]):
        return self.store.current_permissions(app)
    roles = self.user_roles(user)
    if roles:
        # B-19: a role that left the configuration and the catalog grants nothing, even before the next start
        # suspends its assignments (an account may still carry it in `users.roles`).
        known = self._known_roles()
        roles = [r for r in roles if r in known]
    return self.store.effective_permissions(roles, app)


def has_permission(self, user, permission: str, *, app: str) -> bool:
    """Does this account hold `permission` of the application `app`? Only assigned, current permissions of THAT
    application count (see `permissions_of`); an unknown or orphaned permission is no."""
    return isinstance(permission, str) and permission in self.permissions_of(user, app=app)


def require_permission(self, permission: str, *, app: str, mfa: bool = False):
    """FastAPI dependency factory: signed in and holding `permission` of `app` —
    `Depends(auth.require_permission("docs.delete", app="docs"))`. `mfa=True` additionally wants a fresh confirmation.
    The application id is checked here, when the route is built: a typo fails at the start, not as a 403 forever."""
    app = _permission_app(self, app)

    def dep(request: Request) -> dict:
        u = self._enforce(request, mfa=mfa)
        if not self.has_permission(u, permission, app=app):
            raise HTTPException(403, self.t("api.permission", permission=permission))
        return u
    return dep


def _known_roles(self) -> set:
    """The roles a permission can be assigned to: the configuration's (`available_roles`, the group maps' targets …)
    and the role catalog's."""
    from . import _role_catalog, config_check
    configured = {r for _, r in config_check.configured_roles(self.cfg) if isinstance(r, str)}
    return (configured | set(_role_catalog.catalog_names(self.store))) - set(_role_catalog.RESERVED)


def _suspend_removed_role_permissions(self) -> list:
    """At start (B-19): the assignments of roles that are neither in the configuration nor in the catalog any more.
    Active ones are suspended (`active` = 0, audit `permissions_suspended reason=role_removed`): they grant nothing,
    and a role created later under the same name does not inherit them — an administrator assigns again. Every such
    row is named in a security-log warning at each start until an administrator withdraws it (the panel shows it).
    Returns the rows (`role`, `app`, `name`, `suspended` = just now)."""
    rows = self.store.suspend_assignments_of_removed_roles(self._known_roles())
    if not rows:
        return rows
    fresh = [r for r in rows if r["suspended"]]
    if fresh:
        self.audit("permissions_suspended", None, None, "reason=role_removed " + " ".join(
            f"{r['role']}:{r['app']}/{r['name']}" for r in fresh[:20]) + (" …" if len(fresh) > 20 else ""))
    security.seclog.warning(
        "%d permission assignment(s) of role(s) no longer in the configuration or the catalog: %s%s. They grant "
        "nothing (suspended; a role created again under the same name does not take them over). Withdraw them in the "
        "admin panel (Permissions) or with auth.revoke_permission(role, permission, app=…); assign anew to give them "
        "back.", len(rows), ", ".join(security.for_log(f"{r['role']} → {r['app']}/{r['name']}") for r in rows[:10]),
        " (more follow)" if len(rows) > 10 else "")
    return rows


def grant_permission(self, role: str, permission: str, *, app: str, by: Optional[str] = None) -> bool:
    """Assign `permission` of `app` to `role` (the operator's call; the panel uses it) — True if it was not held
    before. Only a declared, current permission, only a known role; a suspended assignment becomes active again.
    `ValueError` otherwise. `by` names the actor in the audit."""
    app = _permission_app(self, app)
    if role_invalid(role) or role not in self._known_roles():
        raise ValueError(f"grant_permission: {role!r} is no role of this installation (configuration or catalog)")
    outcome = self.store.grant_role_permission(role, app, str(permission), by)
    if outcome in ("missing", "orphaned"):
        raise ValueError(f"grant_permission: {permission!r} of {app!r} is {'not declared' if outcome == 'missing' else 'orphaned'}")
    if outcome == "ok":
        self.audit("permission_granted", by, None, f"app={app} permission={permission} role={role}")
    return outcome == "ok"


def revoke_permission(self, role: str, permission: str, *, app: str, by: Optional[str] = None) -> bool:
    """Withdraw `permission` of `app` from `role` (also a suspended assignment) — True if there was one."""
    app = _permission_app(self, app)
    done = self.store.revoke_role_permission(str(role), app, str(permission))
    if done:
        self.audit("permission_revoked", by, None, f"app={app} permission={permission} role={role}")
    return done


def delete_permission(self, permission: str, *, app: str, by: Optional[str] = None) -> bool:
    """Delete an orphaned permission of `app` with its assignments — True if it was deleted. A permission its manifest
    still declares is refused (`ValueError`): it would only come back at the next registration."""
    app = _permission_app(self, app)
    outcome = self.store.delete_orphaned_permission(app, str(permission))
    if outcome == "current":
        raise ValueError(f"delete_permission: {permission!r} of {app!r} is still declared — only an orphaned one goes")
    if outcome == "ok":
        self.audit("permission_deleted", by, None, f"app={app} permission={permission}")
    return outcome == "ok"


def app_permissions(self, app: str) -> list:
    """The declared permissions of `app` for a view (the panel): `name`, `label` and `description` (language → text),
    `danger`, `suggested_roles`, `source`, `orphaned` (bool), `roles` (assigned, active) and `suspended_roles` (assigned
    before it was orphaned — they grant nothing until an administrator assigns them anew), sorted by name."""
    rows = self.store.app_permission_rows(_permission_app(self, app))
    for r in rows:
        r["orphaned"] = r.pop("orphaned_at") is not None
    return rows

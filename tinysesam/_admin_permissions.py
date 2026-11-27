"""The admin panel's permission matrix (T-100, ADR-17): per application, which role holds which permission.

Registered by `admin.build_admin_router` on the panel's router. Administrators see every application with declared
permissions and assign to every known role; an area administrator (a delegate role with `apps` and the action
`permissions`, T-74) sees only the applications of its area and assigns only to the roles it manages. A `danger`
permission needs a fresh confirmation for everyone (`_require_fresh`), also with `admin_require_mfa=False`. Orphaned
permissions are shown with the roles that held them (suspended); an administrator deletes them. Every change is
audited (`permission_granted`, `permission_revoked`, `permission_deleted` with the actor).
"""
from __future__ import annotations

from fastapi import HTTPException, Request


def area(auth, scopes) -> "tuple[set, set]":
    """(applications, roles) a delegate may assign permissions in — from every delegate role it holds that has the
    action `permissions`; empty when none."""
    graph = auth._delegation()
    apps, roles = set(), set()
    for role, managed, can in scopes or []:
        if "permissions" in can:
            apps |= set(graph.get(role, {}).get("apps", ()))
            roles |= set(managed)
    return apps, roles


def register(ar, auth, team, json_body_of) -> None:
    """`GET <admin>/api/permissions`, `POST <admin>/api/permissions/assign`, `POST <admin>/api/permissions/delete`."""

    def apps_named() -> dict:
        apps = auth.cfg.apps if isinstance(getattr(auth.cfg, "apps", None), dict) else {}
        return {a: e for a, e in apps.items() if isinstance(e, dict)}

    def actor(request: Request):
        """(account, allowed applications or None = all, allowed roles or None = all)."""
        me, scopes = team(request)
        if scopes is None:
            return me, None, None
        apps, roles = area(auth, scopes)
        if not apps:
            raise HTTPException(403, auth.t("api.delegate_action"))
        return me, apps, roles

    @ar.get("/api/permissions")
    def permissions_view(request: Request):
        me, apps_ok, roles_ok = actor(request)
        known = sorted(auth._known_roles() - {"admin"})
        roles = [r for r in known if roles_ok is None or r in roles_ok]
        out = []
        for app_id, entry in sorted(apps_named().items()):
            if apps_ok is not None and app_id not in apps_ok:
                continue
            rows = auth.app_permissions(app_id)
            if not rows:
                continue
            name = entry.get("name") or app_id
            out.append({"id": app_id, "name": name, "permissions": rows})
        return {"apps": out, "roles": roles, "area": apps_ok is not None}

    @ar.post("/api/permissions/assign")
    async def permissions_assign(request: Request):
        me, apps_ok, roles_ok = actor(request)
        b = await json_body_of(request)
        app_id, perm, role, on = b.get("app"), b.get("permission"), b.get("role"), b.get("granted")
        if not all(isinstance(v, str) for v in (app_id, perm, role)) or not isinstance(on, bool):
            raise HTTPException(400, auth.t("api.invalid", reason="app, permission, role, granted"))
        if app_id not in apps_named() or (apps_ok is not None and app_id not in apps_ok):
            raise HTTPException(404, auth.t("api.not_found"))
        if roles_ok is not None and role not in roles_ok:
            raise HTTPException(403, auth.t("api.delegate_roles", roles=", ".join(sorted(roles_ok))))
        row = auth.store.get_app_permission(app_id, perm)
        if row is None:
            raise HTTPException(404, auth.t("api.not_found"))
        if row["danger"]:
            auth._require_fresh(request, me)          # a dangerous permission: a fresh confirmation, for everyone
        try:
            if on:
                changed = auth.grant_permission(role, perm, app=app_id, by=str(me["username"]))
            else:
                changed = auth.revoke_permission(role, perm, app=app_id, by=str(me["username"]))
        except ValueError as e:
            raise HTTPException(409, auth.t("api.invalid", reason=str(e)))
        return {"ok": True, "changed": changed}

    @ar.post("/api/permissions/delete")
    async def permissions_delete(request: Request):
        me, apps_ok, _ = actor(request)
        if apps_ok is not None:                        # deleting is the administrators'
            raise HTTPException(403, auth.t("api.admin"))
        b = await json_body_of(request)
        app_id, perm = b.get("app"), b.get("permission")
        if not isinstance(app_id, str) or app_id not in apps_named() or not isinstance(perm, str):
            raise HTTPException(404, auth.t("api.not_found"))
        try:
            done = auth.delete_permission(perm, app=app_id, by=str(me["username"]))
        except ValueError as e:
            raise HTTPException(409, auth.t("api.invalid", reason=str(e)))
        if not done:
            raise HTTPException(404, auth.t("api.not_found"))
        return {"ok": True}

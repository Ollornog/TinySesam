"""The permission API for applications (T-101, ADR-17): register the manifest, read an account's permissions.

    TinySesamConfig(apikey_enabled=True,
                    apps={"docs": {"account": "svc-docs", "hosts": ["docs.example.com"],
                                   "permission_scopes": ["permissions:register", "permissions:read"]}})

The application calls TinySesam directly (not through the proxy) with an automation key of its service account:

    PUT /auth/api/apps/{id}/permissions               register the whole manifest (permissions:register)
    GET /auth/api/users/{id}/permissions?app={id}     the account's permissions for the application (permissions:read)

Registering is all the service path may do: it grants nothing (an administrator assigns permissions to roles), and a
name that leaves the manifest is orphaned, never deleted silently (`TinySesam.register_permissions`). An application
speaks only for itself: the key's service account must be `apps[id].account` of exactly the application in the path or
the query. Reading answers 404 for an account that does not exist, is locked or is a service account — the same answer,
so the route tells nothing more than whether a person exists, at most `READS_PER_MINUTE` times per application and
minute. JSON only, `Cache-Control: no-store`, errors as `{"error": <code>, "error_description": …}` like the account
API.
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse

#: Reads of `GET /auth/api/users/{id}/permissions` per application and minute.
READS_PER_MINUTE = 300
_ID = re.compile(r"^[0-9]{1,18}$")


class PermissionApiError(Exception):
    def __init__(self, code: str, status: int, detail: str = ""):
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail


def caller(auth, request: Request, app_id: Optional[str], scope: str) -> str:
    """The application `app_id` — when the request's API key is an automation key of its service account
    (`apps[id].account`, `is_service == 1`) and `apps[id].permission_scopes` holds `scope`. Resolved through
    `verify_api_key` alone (a session cookie is no caller), like the account API."""
    key = auth._extract_api_key(request) if getattr(auth.cfg, "apikey_enabled", False) else None
    if not key:
        raise PermissionApiError("unauthenticated", 401, "an automation key of the application's service account")
    auth._remember_request(request)
    u, _scope = auth.verify_api_key(key)
    if u is None:
        raise PermissionApiError("unauthenticated", 401, "an automation key of the application's service account")
    auth._remember_request(request, u)
    apps = auth.cfg.apps if isinstance(getattr(auth.cfg, "apps", None), dict) else {}
    entry = apps.get(app_id) if isinstance(app_id, str) else None
    account = entry.get("account") if isinstance(entry, dict) else None
    if (not isinstance(app_id, str) or not isinstance(entry, dict) or auth.api_key_kind(key) != "automation"
            or u.get("is_service") != 1 or not isinstance(account, str)
            or str(u.get("username") or "").lower() != account.lower()):
        auth.audit("permission_api_denied", u["username"], auth.client_ip(request),
                   f"app={str(app_id)[:40]} reason=not_this_app")
        raise PermissionApiError("not_this_app", 403, "the key does not belong to the service account of this "
                                                      "application")
    scopes = entry.get("permission_scopes")
    if not isinstance(scopes, list) or scope not in scopes:
        auth.audit("permission_api_denied", u["username"], auth.client_ip(request), f"app={app_id} scope={scope}")
        raise PermissionApiError("scope_missing", 403, scope)
    return app_id


def register_routes(r, auth) -> None:
    """The two routes on TinySesam's router — only when an application in `apps` has `permission_scopes`."""

    def error(e: PermissionApiError) -> JSONResponse:
        body = {"error": e.code}
        if e.detail:
            body["error_description"] = e.detail
        headers = {"Cache-Control": "no-store"}
        if e.status == 429:
            headers["Retry-After"] = "60"
        return JSONResponse(body, status_code=e.status, headers=headers)

    @r.put("/auth/api/apps/{app_id}/permissions")
    async def permissions_register(request: Request, app_id: str):
        try:
            app = caller(auth, request, app_id, "permissions:register")
            try:
                body = await request.json()
            except Exception:
                raise PermissionApiError("invalid", 400, "a JSON list of permissions or {\"permissions\": [...]}")
            manifest = body.get("permissions") if isinstance(body, dict) else body
            try:
                out = auth.register_permissions(app, manifest)
            except ValueError as e:
                raise PermissionApiError("invalid", 400, str(e)[:300])
        except PermissionApiError as e:
            return error(e)
        return JSONResponse({"app": app, **out}, headers={"Cache-Control": "no-store"})

    @r.get("/auth/api/users/{uid}/permissions")
    def permissions_read(request: Request, uid: str):
        try:
            app = caller(auth, request, request.query_params.get("app"), "permissions:read")
            if not auth.rl.allow(f"permission_api_read:{app}", READS_PER_MINUTE, 60):
                raise PermissionApiError("too_many", 429, f"at most {READS_PER_MINUTE} reads per minute")
            row = auth.store.get_user(int(uid)) if _ID.match(uid or "") else None
            if row is None or row["disabled"] or row["is_service"]:
                raise PermissionApiError("not_found", 404)
        except PermissionApiError as e:
            return error(e)
        return JSONResponse({"app": app, "user": int(row["id"]), "permissions": auth.permissions_of(row, app=app)},
                            headers={"Cache-Control": "no-store"})

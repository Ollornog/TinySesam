"""The own account and the administration data as JSON for an application's page (T-91, T-106, spec §8a/§8b).

`add_routes` registers `GET /auth/account.json` and returns the two answer builders the routes on an application's
host use (`_routes_forward`: `/.tinysesam/account.json`, `/.tinysesam/admin/accounts.json`). Every read shares one set
of refusals (`_data_refused`): Fetch Metadata, a full browser session, the rate per account — each naming itself in
`error`.
"""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

from . import security


def add_routes(r, auth, cfg):
    """Register `/auth/account.json`; return `(account_json, admin_json)` for the routes on an application's host."""
    _DATA_HEADERS = {"Cache-Control": "no-store", "Vary": "Cookie"}

    def _data_refused(viewer, request: Request, limit_key: str, reason: str):
        """The refusals every read of TinySesam's data for an application's page shares (`account.json`, T-91;
        `admin/*.json`, T-106) — a JSONResponse, or None to go on. Every refusal names itself in `error` (spec §8a):
        `cross_site` (403) — Fetch Metadata: a browser says the request comes from another site (`Sec-Fetch-Site:
        cross-site` or `same-site`); the page of the application's own host is `same-origin`, a server-side fetch
        sends no such header —, `signed_out` (401: no full browser session), `rate_limited` (429)."""
        site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if site in ("cross-site", "same-site"):
            return JSONResponse({"error": "cross_site"}, 403, headers=_DATA_HEADERS)
        if not viewer:
            return JSONResponse({"authenticated": False, "signed_in": False, "error": "signed_out"}, 401,
                                headers=_DATA_HEADERS)
        if not auth.rl.allow(f"{limit_key}:{int(viewer['id'])}", auth._ACCOUNT_JSON_PER_MINUTE, 60):
            auth._rejected(viewer["username"], auth.client_ip(request), reason, login=False)
            return JSONResponse({"detail": auth.t("api.too_many"), "error": "rate_limited"}, 429,
                                headers={**_DATA_HEADERS, "Retry-After": "60"})
        return None

    def _account_json(viewer, request: Request, app_host: str = ""):
        """The account page's state for the account of this request's FULL browser session — an API key, an OAuth
        token, an app password or a half session is "not signed in" (401). No parameter chooses an account. Like the
        bar: `no-store` + `Vary: Cookie`, no CORS header (another origin's page cannot read it), and a request a
        browser marks as another site's is refused (Fetch Metadata, T-106); read only. 60 reads per account and
        minute (`_ACCOUNT_JSON_PER_MINUTE`); a refusal is a `failed verification` line, never a `failed login` (the
        fail2ban jail stays quiet). Reading is not audited — the own data, and every change goes through the audited
        routes of the account page. Every refusal carries `error` (`_data_refused`)."""
        refused = _data_refused(viewer, request, "account_json", "ratelimit_account_json")
        if refused is not None:
            return refused
        base = (security.normalize_base(str(cfg.base_url or "").strip()) or "").rstrip("/") or auth._prefix(request)
        view = auth.account_overview(viewer, base=base, app_host=app_host or None, request=request)
        if view is None:
            return JSONResponse({"authenticated": False, "signed_in": False, "error": "signed_out"}, 401,
                                headers=_DATA_HEADERS)
        return JSONResponse({"signed_in": True, **view}, headers=_DATA_HEADERS)

    def _admin_json(viewer, request: Request, app_host: str):
        """The administration data of the application of `app_host` (T-106, spec §8b, `admin_overview`) for a person
        who administers accounts inside its area — the same refusals as `account.json`, and `forbidden` (403) for
        anyone else: no answer tells an application without administrators from a person who is none of them."""
        refused = _data_refused(viewer, request, "admin_json", "ratelimit_admin_json")
        if refused is not None:
            return refused
        base = (security.normalize_base(str(cfg.base_url or "").strip()) or "").rstrip("/") or auth._prefix(request)
        data = auth.admin_overview(viewer, app_host, base=base)
        if data is None:
            return JSONResponse({"error": "forbidden"}, 403, headers=_DATA_HEADERS)
        return JSONResponse(data, headers=_DATA_HEADERS)

    @r.get("/auth/account.json")
    def account_json(request: Request):
        return _account_json(auth.session_user(request), request)

    return _account_json, _admin_json

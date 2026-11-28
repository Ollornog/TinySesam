"""The route of the TinySesam area (T-104, `_area.py`): registered with the account page (`account_enabled`)."""
from __future__ import annotations

from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import _area


def add_routes(r, auth, cfg) -> None:
    @r.get("/auth/area", response_class=HTMLResponse)
    def area_page(request: Request, app: str = "", next: str = ""):
        """`/auth/area?app=<id>`: the tiles of the own account in the application's frame (`_area`). Signed out, the
        sign-in page comes first and leads back here — in the same frame, it reads `app=` inside `next`."""
        u = auth.current_user(request)
        here = auth.browser_path(request, "/auth/area") + (f"?app={quote(app[:253], safe='')}" if app else "")
        if not u:
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={quote(here, safe='')}", 303)
        ctx = _area.context(auth, request, app, next)
        host = ctx["frame"]["host"] if ctx["frame"] else None
        view = auth.account_overview(u, app_host=host, request=request) or {}
        return auth.render_page("area", request=request, user=u, view=view,
                                administers=_administers(auth, u, ctx["area_app"]), **ctx)


def _administers(auth, user, app_id: str) -> bool:
    """Does the area show the panel? An administrator, or an area administrator (`admin_delegates[role].apps`, T-100)
    whose area holds this application. A convenience: the panel checks access itself on every request."""
    if not auth._admin_panel_visible(user):
        return False
    if user["is_admin"]:
        return True
    delegates = getattr(auth.cfg, "admin_delegates", None) or {}
    return bool(app_id) and any(app_id in ((delegates.get(role) or {}).get("apps") or [])
                                for role in auth.user_roles(user))

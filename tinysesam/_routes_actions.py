"""The account page's state and the action pages' route (T-105, `_actions.py`): registered with the account page
(`account_enabled`), on TinySesam's origin only — never under `/.tinysesam/`, where an application's host counts as
TinySesam's own origin."""
from __future__ import annotations

from urllib.parse import quote, urlencode

from fastapi import HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import _actions, _area


def account_ctx(auth, request: Request, u, view: dict) -> dict:
    """What the account page and every action page render from: the sections' state for the account `u`, read from
    `account_overview` (`view`) — the same function behind `/auth/account.json`, so page and data cannot drift apart."""
    cfg = auth.cfg
    sign_in = view.get("sign_in") or {}
    totp = sign_in.get("totp") or {}
    return dict(
        methods=_actions.account_methods(auth),
        # B-10: without a password the page offers to set one, without the field for the current one (not with a
        # directory: `set_initial_password`).
        password_initial=sign_in.get("password") == "unset",
        # A directory account without a local password changes it in the directory.
        password_directory=sign_in.get("password") == "directory",
        # T-99: link this account with an identity at the OIDC provider (not yet linked).
        oidc_link=bool(cfg.oidc_enabled and not auth.store.is_oidc_account(u["id"])),
        # …and with SAML, LDAP; the linked ones with "Unlink" (never the last way in).
        identities=(auth._identities_view(u) if cfg.oidc_enabled or cfg.saml_enabled or cfg.ldap_enabled else []),
        has_totp=bool(totp.get("enabled")),
        recovery_left=totp.get("recovery_left"),
        recovery_warn=auth._RECOVERY_WARN_THRESHOLD,
        has_pin=bool(sign_in.get("pin")),
        is_admin=bool(u["is_admin"]), admin_path=cfg.admin_path,
        # The link to the panel: administrators and delegated admins (T-74).
        admin_panel=auth._admin_panel_visible(u),
        events=auth.own_events(u["id"]),
        # Connected programs (OAuth, T-36) — None leaves the section out.
        oauth_devices=auth._oauth_server().devices(u["id"]) if cfg.oauth_enabled else None,
        # Pairing code for a program (ADR-14) — None leaves the section out.
        oauth_pairing=({"minutes": int(cfg.oauth_pairing_consent_minutes),
                        "resources": [(r, auth._forward_app(r)["name"]) for r in auth._oauth_server().resources()]}
                       if cfg.oauth_enabled and cfg.oauth_pairing_consent_enabled else None),
        # Services (T-60) — the resources a pairing code may name; None leaves the section out.
        service_resources=(auth._oauth_server().resources()
                           if cfg.oauth_enabled and cfg.oauth_service_clients else None),
        # App passwords (T-66) — None leaves the section out.
        app_passwords=({"apps": auth.app_password_hosts(), "default_days": int(cfg.app_password_default_days),
                        "allow_unlimited": bool(cfg.app_password_allow_unlimited)}
                       if auth.app_password_hosts() else None),
        username_change=(cfg.self_service_username_change and cfg.login_identifier != "email"
                         and not cfg.ldap_enabled),
        email_change=(cfg.self_service_email_change and auth.mail_configured()))


def add_routes(r, auth, cfg) -> None:
    @r.get("/auth/act/{name}", response_class=HTMLResponse)
    def action_page(request: Request, name: str, app: str = "", return_: str = Query("", alias="return"),
                    state: str = "", target: str = ""):
        """`/auth/act/<name>?app=<id>&return=<url>&state=<opaque>`: one action of the own account in the
        application's frame, with the way back (`_actions`). A GET changes nothing; the page's buttons call the same
        routes as the account page, each with its own CSRF and step-up checks."""
        action = _actions.ACTIONS.get(name)
        if action is None or action.scope != "own":
            raise HTTPException(404)
        path = auth.browser_path(request, f"/auth/act/{name}")
        query = [(k, v) for k, v in request.query_params.multi_items() if k not in ("revoke_others", "ts_done")]
        here = path + (f"?{urlencode(query)}" if query else "")
        # A person by browser only: an API key or a half session first signs in — and comes back here, in the frame.
        u = auth.session_user(request)
        if not u:
            return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={quote(here, safe='')}", 303)
        ctx = _area.context(auth, request, app, "")
        host = ctx["frame"]["host"] if ctx["frame"] else None
        view = auth.account_overview(u, app_host=host, request=request) or {}
        available = name in _actions.offered(auth, view)
        target_session = None
        if action.target == "session":
            # One session of this account by its handle — not the current one (that is signing out): anything else
            # is "not offered", the same answer for a foreign handle as for an invented one.
            target_session = next((s for s in (view.get("sessions") or {}).get("items") or []
                                   if target and s.get("handle") == target and s.get("current") is not True), None)
            available = available and target_session is not None
        if available and action.fresh:
            # Class `window`: a stale confirmation goes to the reauth page first and comes back here (the frame rides
            # along inside `next`).
            target = auth._reauth_target(request, here)
            if target:
                return RedirectResponse(target, 303)
        done_here = path + "?" + urlencode(query + [("ts_done", "1")])
        ctx.update(account_ctx(auth, request, u, view))
        ctx.update(action=action, available=available, target_session=target_session, done=request.query_params.get("ts_done") == "1",
                   way_back=_actions.way_back(auth, request, ctx, name, return_, state),
                   totp_next=done_here)
        return _actions.no_framing(auth.render_page("action", request=request, user=u, **ctx))

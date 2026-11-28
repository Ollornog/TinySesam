"""Administration actions on action pages (T-147, surface "headless"): scope `admin`, class `each`.

An application that draws its own administration links a person who administers accounts to
`/auth/act/<name>?target=<account id>&app=<id>&return=<url>&state=<opaque>` on TinySesam's origin — the register of
`_actions.ACTIONS` (scope `admin`). The page names the account (from the database, bidi-isolated), says what the
action does (TinySesam's text, never text from the request), asks what it needs (the roles, the key, the program,
the session) and a confirmation for THIS action: the password, TOTP code or PIN of the person, checked by the one
step-up checker (`_stepup_secret`: offered methods only, throttled, logged). A fresh confirmation window is not
enough (class `each`): every action asks again, so a link alone never acts.

Order of a POST: no token in the request (403, a person by browser only); CSRF; the ticket the page issued (one use,
bound to the person, the action and the account: a confirmation never carries over to another action or account);
the step-up; then the rights at THIS moment (an administrator, or a delegate whose role may do the action on that
account — `PanelActions.target`, the panel's rule); then the panel's code (`PanelActions`, the same lines in the
audit) and one line `admin_action` with action, account, method and frame. The page then shows the result and the
way back with `done`; a sign-in link is shown there once and never travels to the application.

This module holds the rules and the execution; the routes live in `_routes_actions` (registered with the account page
and the admin panel, `account_enabled` and `admin_enabled`, never under `/.tinysesam/`), the page in `_actions`
(`admin_page`). It imports neither of them, nor the panel (`auth._panel_actions()`): no import cycle. Not here: the admin flag, owner, deletion, the role catalog, new credentials other than a sign-in
link — they stay in the panel. A passkey or a provider as the confirmation of an action: not yet (a person with
only those confirms in the panel).
"""
from __future__ import annotations

import secrets
import time
from typing import Optional

from fastapi import HTTPException, Request

#: How long a page's ticket stays valid: the time to read the page and confirm.
TICKET_TTL = 600
FLOW = "actadm:"
#: action → the delegate action word (`admin_delegates[...]["can"]`) that lets a delegate do it; None = admins only.
DELEGATE_WORD = {"admin_lock": "disable", "admin_unlock": "disable", "admin_roles": "roles",
                 "admin_signin_link": "signin_link"}
#: The actions that act on one object of the account, chosen on the page (`item`).
ITEMS = ("admin_key_revoke", "admin_program_revoke", "admin_session_end")


def actor(auth, request: Request):
    """`(account, scopes)` of the person on the page — scopes None for an administrator — or None: no full browser
    session, or neither an administrator nor a delegate."""
    u = auth.session_user(request)
    if u is None or u.get("_via") != "session":
        return None
    if auth.is_admin(u):
        return u, None
    scopes = auth._delegate_scopes(u)
    return (u, scopes) if scopes else None


def _panel(auth):
    return auth._panel_actions()       # the manager's factory: this module imports neither the panel nor the router


def account_for(auth, me, scopes, name: str, uid) -> Optional[dict]:
    """The account `name` may act on, with the rights of `me` at this moment — or None (no oracle: an account out of
    reach and one that does not exist look the same)."""
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return None
    # An admin-only action keeps its own name as the word: no delegate role can do it, `target` refuses (403).
    word = DELEGATE_WORD.get(name, name)
    try:
        account = _panel(auth).target(me, scopes, uid, word)
    except HTTPException:
        return None
    return dict(account) if account is not None else None


def items(auth, name: str, uid: int) -> list:
    """`[(value, label)]` the page offers for an action on one object of account `uid`: its active API keys, its
    connected programs, services and app passwords, its sessions (by handle — the session's hash never leaves)."""
    cfg = auth.cfg
    out = []
    if name == "admin_key_revoke":
        for k in auth.list_api_keys(uid):
            if not k["revoked"] and not (k["expires_at"] and k["expires_at"] <= _now()):
                out.append((f"key:{int(k['id'])}", f"{k['name'] or '—'} · {_when(k['created_at'])}"))
    elif name == "admin_program_revoke":
        if cfg.oauth_enabled:
            for g in auth._oauth_server().devices(uid):
                out.append((f"grant:{int(g['id'])}", f"{g['client_name'] or g['client_id']} · {_when(g['created_at'])}"))
            if cfg.oauth_service_clients:
                for s in auth.list_service_clients(uid):
                    out.append((f"service:{s['client_id']}", f"{s.get('name') or s['client_id']}"))
        if auth.app_password_hosts():
            for p in auth.list_app_passwords(uid):
                if not p["revoked"] and not p["expired"]:
                    out.append((f"app_password:{int(p['id'])}", f"{p['name'] or '—'} · {_when(p['created_at'])}"))
    elif name == "admin_session_end":
        for s in auth.store.list_sessions(uid):
            if s["public_handle"]:
                out.append((f"session:{s['public_handle']}",
                            f"{s['method'] or '—'} · {_device(s['user_agent'])} · {_when(s['created_at'])}"))
    return out


def roles_offered(auth, me, scopes, account) -> list:
    """The roles the page lets `me` set: every known role for an administrator; for a delegate the roles of the
    delegate roles that may set roles and hold this account."""
    if scopes is None:
        return list(auth.known_roles())
    pa = _panel(auth)
    mine = [s for s in scopes if "roles" in s[2] and pa.fits(account, me, s[1])]
    return sorted({r for _, roles, _ in mine for r in roles})


def offered(auth, me, scopes, name: str, account: Optional[dict]) -> bool:
    """Does this installation offer `name` for `account` now? The same conditions as the panel's buttons."""
    if account is None:
        return False
    cfg = auth.cfg
    uid = int(account["id"])
    if name == "admin_totp_reset":
        return bool(cfg.totp_enabled and auth.store.has_confirmed_totp(uid))
    if name == "admin_lock":
        return not account["disabled"] and not account["is_owner"] and uid != int(me["id"])
    if name == "admin_unlock":
        return bool(account["disabled"])
    if name == "admin_roles":
        return bool(roles_offered(auth, me, scopes, account))
    if name == "admin_signin_link":
        return bool(cfg.magiclink_enabled and not account["is_service"] and not account["disabled"])
    if name in ITEMS:
        return bool(items(auth, name, uid))
    return False


def _now() -> int:
    return int(time.time())


def _when(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(ts))) if ts else "—"


def _device(ua) -> str:
    ua = str(ua or "")
    for name in ("Firefox", "Edg", "Chrome", "Safari"):
        if name in ua:
            return {"Edg": "Edge"}.get(name, name)
    return "—"


def execute(auth, request: Request, me, scopes, name: str, account: dict, form: dict) -> tuple:
    """Run the confirmed action with the panel's code. `(ok, extra)`: extra is the sign-in link of
    `admin_signin_link` (shown once on the page), else None. A refusal of the panel's rules raises HTTPException."""
    pa = _panel(auth)
    uid = int(account["id"])
    if name == "admin_totp_reset":
        pa.reset_totp(request, me, uid, confirmed=True)
    elif name in ("admin_lock", "admin_unlock"):
        pa.disable(me, scopes, uid, name == "admin_lock")
    elif name == "admin_roles":
        allowed = set(roles_offered(auth, me, scopes, account))
        wanted = [r for r in form.get("roles", []) if r in allowed]
        # Roles the page did not offer stay as they are: an administrator's list covers every known role, a
        # delegate's only the roles in scope — the rest of the account's roles is not theirs to drop.
        kept = [r for r in auth.user_roles(account) if r not in allowed]
        pa.set_roles(request, me, scopes, uid, {"roles": kept + wanted} if scopes is None else {"roles": wanted})
    elif name == "admin_signin_link":
        return True, auth.create_signin_link(uid)["url"]
    elif name in ITEMS:
        value = str(form.get("item") or "")
        if value not in {v for v, _ in items(auth, name, uid)}:
            raise HTTPException(409, auth.t("act.admin_gone"))
        kind, _, ref = value.partition(":")
        if kind == "key":
            pa.revoke_key(me, int(ref))
        elif kind == "grant":
            auth._oauth_server().revoke_grant(int(ref), "admin", auth.client_ip(request))
        elif kind == "service":
            auth.revoke_service_client(ref, uid)
        elif kind == "app_password":
            auth.revoke_app_password(int(ref), uid, by_operator=True)
        elif kind == "session":
            pa.owner_protection(me, uid)
            if not auth.store.end_session_by_public_handle(uid, ref):
                raise HTTPException(409, auth.t("act.admin_gone"))
            pa.log(request, "session_revoke", f"user_id={uid} one session")
    return True, None


#: The administration actions in the order of the register — the members of `actions` per account in `overview`.
NAMES = ("admin_totp_reset", "admin_lock", "admin_unlock", "admin_roles", "admin_key_revoke", "admin_program_revoke",
         "admin_session_end", "admin_signin_link")


def area_actor(auth, viewer, app: str):
    """`(account, scopes)` of a person who administers accounts inside the area of application `app` (T-106) — scopes
    None for an administrator, else only the delegate scopes whose role names `app` in `admin_delegates[role].apps`
    (the area of `_routes_area._administers`) — or None. Only a full browser session (`_via == "session"`), read
    from the account row at this moment."""
    if not isinstance(viewer, dict) or viewer.get("_via") != "session" or not app:
        return None
    row = auth.store.get_user(viewer.get("id"))
    if row is None or row["disabled"] or row["is_service"]:
        return None
    me = {**auth._as_dict(row), "_via": "session"}
    if me["is_admin"]:
        return me, None
    delegates = getattr(auth.cfg, "admin_delegates", None) or {}
    scopes = [s for s in (auth._delegate_scopes(me) or [])
              if app in ((delegates.get(s[0]) or {}).get("apps") or [])]
    return (me, scopes) if scopes else None


def overview(auth, viewer, app_host: str, base: str) -> Optional[dict]:
    """The administration data of the application whose `apps[id].hosts` name `app_host`, for `viewer` (T-106, spec
    §8b) — None when the host belongs to no application or `viewer` administers nothing in its area (`area_actor`).

    `accounts`: every account the person may administer — an administrator all but service accounts, a delegate the
    accounts of its scopes (`PanelActions.visible`, the panel's list) — with `id` (text, the claim `ts_id`), `username`,
    `display_name`, `source`, `roles`, `disabled`, `totp` (a confirmed authenticator app; None with TOTP off),
    `permissions` (its permissions for this application) and `actions`: each administration action → the address of its
    page (`/auth/act/<name>?app=<host>&target=<id>`), None where the person may not do it on this account now (the
    page decides again on every request). `links.panel`: the panel, a link only. Reading only; the admin flag, the
    owner, the role catalog, hardening and configuration are not part of it."""
    from urllib.parse import quote
    cfg = auth.cfg
    app = auth._app_of_host(app_host)
    if not app or not cfg.admin_enabled:
        return None
    who = area_actor(auth, viewer, app)
    if who is None:
        return None
    me, scopes = who
    pa = _panel(auth)
    frame = auth._frame_of(app_host)
    query = f"app={quote(frame['host'], safe='')}&" if frame else ""
    sources = auth.store.account_sources()
    accounts = []
    for row in auth.store.list_users():
        if row["is_service"] or (scopes is not None and not pa.visible(row, me, scopes)):
            continue
        uid = int(row["id"])
        acts = {}
        for name in NAMES:
            account = account_for(auth, me, scopes, name, uid) if cfg.account_enabled else None
            acts[name] = (f"{base}/auth/act/{name}?{query}target={uid}"
                          if account is not None and offered(auth, me, scopes, name, account) else None)
        accounts.append({"id": str(uid), "username": row["username"],
                         "display_name": row["display_name"] or row["username"],
                         "source": sources.get(uid, ["local"]), "roles": [str(r) for r in auth.user_roles(row)],
                         "disabled": bool(row["disabled"]),
                         "totp": bool(auth.store.has_confirmed_totp(uid)) if cfg.totp_enabled else None,
                         "permissions": auth.permissions_of(row, app=app), "actions": acts})
    panel = f"{base}{cfg.admin_path}" if cfg.admin_ui_enabled else None
    return {"app": app, "accounts": accounts, "links": {"panel": panel}}


def issue(auth, me, name: str, uid: int, ctx_args: dict) -> str:
    ticket = secrets.token_urlsafe(18)
    auth.store.put_flow(FLOW + ticket, {"actor": int(me["id"]), "name": name, "uid": int(uid), **ctx_args},
                        ttl=TICKET_TTL)
    return ticket

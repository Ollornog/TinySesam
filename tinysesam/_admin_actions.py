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

Registered with the account page and the admin panel (`account_enabled` and `admin_enabled`), never under
`/.tinysesam/`. Not here: the admin flag, owner, deletion, the role catalog, new credentials other than a sign-in
link — they stay in the panel. A passkey or a provider as the confirmation of an action: not yet (a person with
only those confirms in the panel).
"""
from __future__ import annotations

import secrets
import time
from typing import Optional
from urllib.parse import quote, urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from . import _actions, _area

#: How long a page's ticket stays valid: the time to read the page and confirm.
TICKET_TTL = 600
_FLOW = "actadm:"
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
    from .admin import PanelActions
    return PanelActions(auth)


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


def _issue(auth, me, name: str, uid: int, ctx_args: dict) -> str:
    ticket = secrets.token_urlsafe(18)
    auth.store.put_flow(_FLOW + ticket, {"actor": int(me["id"]), "name": name, "uid": int(uid), **ctx_args},
                        ttl=TICKET_TTL)
    return ticket


def _render(auth, request, me, scopes, name, uid, account, args: dict, *, error: str = "", done: bool = False,
            link: str = "", status: int = 200):
    """The page: in the frame `args["app"]`, with a new ticket while the action is open."""
    action = _actions.ACTIONS[name]
    ctx = _area.context(auth, request, args.get("app") or "", "")
    available = offered(auth, me, scopes, name, account) or done
    ctx.update(action=action, account=account, available=available, done=done, link=link, error=error,
               methods=auth.stepup_options(me) if available and not done else [],
               items=items(auth, name, int(account["id"])) if account and name in ITEMS and not done else [],
               roles=roles_offered(auth, me, scopes, account) if account and name == "admin_roles" else [],
               held=[str(r) for r in auth.user_roles(account)] if account and name == "admin_roles" else [],
               way_back=_actions.way_back(auth, request, ctx, name, args.get("return") or "", args.get("state") or ""))
    if available and not done:
        ctx["ticket"] = _issue(auth, me, name, uid, args)
    return _actions.no_framing(auth.render_page("action", status=status, request=request, user=me, **ctx))


def get_page(auth, request: Request, name: str, app: str, return_: str, state: str, target: str):
    """`GET /auth/act/<admin action>` — changes nothing. Signed out: the sign-in page first, and back here."""
    cfg = auth.cfg
    path = auth.browser_path(request, f"/auth/act/{name}")
    query = list(request.query_params.multi_items())
    here = path + (f"?{urlencode(query)}" if query else "")
    me = auth.session_user(request)
    if me is None:
        return RedirectResponse(f"{auth.browser_path(request, cfg.login_path)}?next={quote(here, safe='')}", 303)
    # Neither an administrator nor a delegate (or by API key): "not offered", the same page as for an account out of
    # reach — no oracle.
    who = actor(auth, request)
    scopes = who[1] if who else None
    account = account_for(auth, me, scopes, name, target) if who else None
    return _render(auth, request, me, scopes, name, int(account["id"]) if account else 0, account,
                   {"app": app, "return": return_, "state": state})


async def post_action(auth, request: Request, name: str, ticket: str):
    """`POST /auth/act/<admin action>/<ticket>` — the confirmed action (see the module for the order)."""
    if request.headers.get("authorization") or request.headers.get("x-api-key"):
        raise HTTPException(403, auth.t("apv.token_refused"))
    form = await request.form()
    fields = {"roles": [str(v) for v in form.getlist("roles")]}
    fields.update({k: v for k, v in form.items() if isinstance(v, str) and k != "roles"})
    auth.require_csrf(request, fields.get("_csrf"))
    who = actor(auth, request)
    flow = auth.store.pop_flow(_FLOW + ticket) if isinstance(ticket, str) and 0 < len(ticket) <= 64 else None
    if who is None:
        raise HTTPException(403, auth.t("api.admin"))
    me, scopes = who
    if not flow or flow.get("actor") != int(me["id"]) or flow.get("name") != name:
        # An old, used or foreign ticket: the page again, from the start (nothing was done).
        account = account_for(auth, me, scopes, name, (flow or {}).get("uid"))
        args = {k: (flow or {}).get(k) or "" for k in ("app", "return", "state")}
        return _render(auth, request, me, scopes, name, int(account["id"]) if account else 0, account, args,
                       error=auth.t("act.admin_expired"), status=409)
    args = {k: flow.get(k) or "" for k in ("app", "return", "state")}
    uid = int(flow["uid"])
    account = account_for(auth, me, scopes, name, uid)
    if not offered(auth, me, scopes, name, account):
        return _render(auth, request, me, scopes, name, uid, account, args, status=409)
    methods = auth.stepup_options(me)
    procedure = ("totp" if fields.get("code") else "pin" if fields.get("pin") else "password")
    secret = fields.get("code") or fields.get("pin") or fields.get("password") or ""
    refused = auth._stepup_secret(request, me, procedure, secret, "/") if methods else None
    if not methods or refused is not None:
        auth.audit("admin_action_denied", me["username"], auth.client_ip(request),
                   f"act={name} uid={uid} reason=stepup")
        message = refused.message if refused is not None else auth.t("act.admin_no_method")
        return _render(auth, request, me, scopes, name, uid, account, args, error=message,
                       status=refused.status if refused is not None else 403)
    try:
        _, link = execute(auth, request, me, scopes, name, account, fields)
    except HTTPException as e:
        return _render(auth, request, me, scopes, name, uid, account_for(auth, me, scopes, name, uid), args,
                       error=str(e.detail), status=e.status_code)
    frame = _area.context(auth, request, args["app"], "").get("frame")
    auth.audit("admin_action", me["username"], auth.client_ip(request),
               f"act={name} uid={uid} amr={procedure}" + (f" app={frame['host']}" if frame else ""))
    return _render(auth, request, me, scopes, name, uid, account_for(auth, me, scopes, name, uid) or account, args,
                   done=True, link=link or "")


def add_routes(r, auth) -> None:
    @r.post("/auth/act/{name}/{ticket}", response_class=HTMLResponse)
    async def admin_action_post(request: Request, name: str, ticket: str):
        action = _actions.ACTIONS.get(name)
        if action is None or action.scope != "admin":
            raise HTTPException(404)
        return await post_action(auth, request, name, ticket)


# ---------- the page ----------

_CSS = """
.tsmain .act-target{margin:0 0 10px}
.tsmain .act-what{margin:0 0 14px}
.tsmain .act-choice{display:flex;align-items:center;gap:10px;min-height:44px}
.tsmain .act-choice input{width:auto;min-height:0}
.tsmain .act-link{word-break:break-all;user-select:all}
.tsmain #actform button[type=submit]{min-height:44px}
"""


def page(auth, ctx: dict) -> str:
    """An administration action page: the heading in the application's name, the account, what happens, the
    choices, the confirmation of this action, the way back (template `action`, built here for scope `admin`)."""
    from . import templates as _t
    t, e = auth.t, _t._e
    action = ctx["action"]
    account = ctx.get("account")
    body = [_area.heading(auth, ctx, t(f"act.{action.name}"))]
    hrefs = ctx["way_back"]["href"]
    name = ctx.get("app_title") or ""
    if account is not None and ctx.get("available"):
        who = f"{account['display_name'] or account['username']} ({account['username']})"
        body.append(f"<p class=act-target id=act_target>{e(t('act.admin_account'))}: <bdi>{e(who)}</bdi></p>")
    msgs = [("error", ctx.get("error"))]
    if ctx.get("done"):
        msgs.append(("ok", t(f"act.{action.name}.done")))
    elif not ctx.get("available"):
        msgs.append(("info", t("act.unavailable")))
    body.append(_t._messages(msgs))
    if ctx.get("done") and ctx.get("link"):
        body.append(f"<p>{e(t('act.admin_link_once'))}</p><p class=act-link id=act_link>{e(ctx['link'])}</p>")
    if ctx.get("available") and not ctx.get("done"):
        choices = ""
        if action.name == "admin_roles":
            held = set(ctx.get("held") or [])
            choices = "".join(
                f"<label class=act-choice><input type=checkbox name=roles value='{e(r)}'"
                f"{' checked' if r in held else ''}><bdi>{e(r)}</bdi></label>" for r in ctx.get("roles") or [])
        elif action.name in ITEMS:
            choices = "".join(
                f"<label class=act-choice><input type=radio name=item value='{e(v)}' required"
                f"{' checked' if i == 0 else ''}><bdi>{e(label)}</bdi></label>"
                for i, (v, label) in enumerate(ctx.get("items") or []))
        methods = [m for m in ctx.get("methods") or [] if m in ("totp", "pin", "password")]
        fields = f"<div class=or>{e(t('or'))}</div>".join(
            _t._stepup_field(auth, m, i == 0) for i, m in enumerate(methods))
        if methods:
            confirm = (f"<p class=hint>{e(t('act.admin_confirm_hint'))}</p>{fields}"
                       f"<button type=submit id=act_confirm>{e(t(f'act.{action.name}.button'))}</button>")
        else:
            confirm = f"<div class=warnbar id=act_nomethod>{e(t('act.admin_no_method'))}</div>"
        target = f"__TS_P__/auth/act/{e(action.name)}/{e(ctx.get('ticket') or '')}"
        body.append(f"<p class=act-what id=act_what>{e(t(f'act.{action.name}.what'))}</p>"
                    f"<form method=post id=actform action='{target}'>{_t._cf(ctx)}{choices}{confirm}</form>")
    first = "done" if ctx.get("done") else ("cancelled" if ctx.get("available") else "unavailable")
    label = (t("act.done", name=name) if name else t("act.done_plain")) if first == "done" else \
        (t("act.back", name=name) if name else t("act.back_plain"))
    body.append(f"<p class=act-back><a id=ts_back class=btn2 href='{e(hrefs[first])}' data-state='{first}'>"
                f"{e(label)}</a></p>")
    head = f"<style>{_area._CSS}{_actions._CSS}{_CSS}</style>"
    return _t._page(auth, t(f"act.{action.name}"), "".join(body), card=False, head=head, ctx=ctx, current="account")

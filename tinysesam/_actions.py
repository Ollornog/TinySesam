"""Action pages (T-105, surface "headless"): one register of the writing actions, the way back with the result.

An application that draws everything itself — a single-page app behind the server, say — reads the account's state
from `/.tinysesam/account.json` and changes nothing itself: every write goes by navigation to an action page on
TinySesam's origin, `/auth/act/<name>?app=<id>&return=<url>&state=<opaque>`, in the application's frame (`_area`), and
back to `return` with `ts_action=<name>&ts_result=<result>&state=<opaque>`. Secrets — a password, a TOTP code, a
recovery code, an API key, an app password, a pairing code — are typed or shown on TinySesam's page only and never
travel through the application.

The register (`ACTIONS`) holds every action with its scope (`own`: the own account; `admin`: an account the viewer
administers, `_admin_actions`, T-147), its step-up class (`window`: the window of a
fresh confirmation, `_require_fresh`; `each`: one step-up per action, the confirmation of the approvals), the sections of
the account page it shows (`templates.account_sections`: the page does exactly what the account page does, with the
same script and the same routes behind it) and whether it asks the step-up as it opens (`fresh`; the routes behind it
ask anyway).

`ts_result` is a hint, not a proof: `done` once a change worked on the page, `cancelled` when the person went back
without one, `unavailable` when this installation or account does not offer the action. The application reads the
state again afterwards; whoever needs a binding confirmation takes the approvals.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from . import _chain
from ._config_check_apps import link_next_ok

#: The results an action page hands back in `ts_result`.
RESULTS = ("done", "cancelled", "unavailable")
#: `state`: printable ASCII, at most this long — passed through, never read; anything else is dropped.
STATE_MAX = 128
#: The query keys of the way back; a `return` that already carries them loses them first.
_BACK_KEYS = ("ts_action", "ts_result", "state")


@dataclass(frozen=True)
class Action:
    name: str
    scope: str
    cls: str
    sections: tuple
    fresh: bool = False
    target: str = ""      # the kind of object `?target=` names (`session`: a session handle); "" for none


#: The register, in the order of the account page.
ACTIONS: dict = {a.name: a for a in (
    Action("username", "own", "window", ("username",), fresh=True),
    Action("email", "own", "window", ("email",), fresh=True),
    Action("password", "own", "window", ("password",)),
    Action("pin", "own", "window", ("pin",), fresh=True),
    Action("totp", "own", "window", ("totp",), fresh=True),
    Action("recovery_codes", "own", "window", ("recovery_codes",), fresh=True),
    Action("passkeys", "own", "window", ("passkeys",), fresh=True),
    Action("api_keys", "own", "window", ("api_keys",)),
    Action("app_passwords", "own", "window", ("app_passwords",)),
    Action("sessions", "own", "window", ("sessions",)),
    Action("session_end", "own", "window", ("session_end",), target="session"),
    Action("programs", "own", "window", ("programs", "pairing")),
    Action("services", "own", "window", ("services",)),
    # Scope `admin` (T-147, `_admin_actions`): an account the viewer administers, `?target=<account id>`; class
    # `each` — a confirmation for every single action, typed on the page.
    Action("admin_totp_reset", "admin", "each", (), target="account"),
    Action("admin_lock", "admin", "each", (), target="account"),
    Action("admin_unlock", "admin", "each", (), target="account"),
    Action("admin_roles", "admin", "each", (), target="account"),
    Action("admin_key_revoke", "admin", "each", (), target="account"),
    Action("admin_program_revoke", "admin", "each", (), target="account"),
    Action("admin_session_end", "admin", "each", (), target="account"),
    Action("admin_signin_link", "admin", "each", (), target="account"),
)}


def account_methods(auth) -> list:
    """The sign-in methods the account page maintains: what the login page starts with, plus a PIN that a strict chain
    permits only as a follow-up factor (G7) or that the chain demands (with `pin_login=False`)."""
    cfg = auth.cfg
    methods = cfg.enabled_methods()
    if (cfg.pin_enabled and (cfg.pin_login or "pin" in _chain.factors(cfg.login_chain))
            and "pin" not in methods):
        methods.append("pin")
    return methods


def offered(auth, view: dict) -> set:
    """The own actions this installation offers this account — from `account_overview` (`view`), with the same
    conditions as the sections of the account page. Empty without the account page."""
    cfg = auth.cfg
    if not cfg.account_enabled or not view:
        return set()
    sign_in, programs = view.get("sign_in") or {}, view.get("programs") or {}
    totp = sign_in.get("totp")
    out = {"sessions", "session_end"}
    if sign_in.get("password") in ("set", "unset"):
        out.add("password")
    if totp is not None:
        out.add("totp")
        if totp.get("enabled") and cfg.recovery_codes_enabled:
            out.add("recovery_codes")
    if sign_in.get("passkeys") is not None:
        out.add("passkeys")
    if "pin" in account_methods(auth):
        out.add("pin")
    for key in ("app_passwords", "services"):
        if programs.get(key) is not None:
            out.add(key)
    if programs.get("oauth") is not None:
        out.add("programs")
    if programs.get("api_keys_active") is not None:
        out.add("api_keys")
    if cfg.self_service_email_change and auth.mail_configured():
        out.add("email")
    if cfg.self_service_username_change and cfg.login_identifier != "email" and not cfg.ldap_enabled:
        out.add("username")
    return out


def links(auth, view: dict, base: str, query: str) -> dict:
    """The member `actions` of `account_overview`: every own action → the address of its page, or None where it is
    not offered. `query` is `?app=<host>` in an app frame, else ""; the application adds `return` and `state`. An
    action on one object (`target`) has its address beside the object instead (`sessions.items[].end`)."""
    on = offered(auth, view)
    return {name: (f"{base}/auth/act/{name}{query}" if name in on else None)
            for name, a in ACTIONS.items() if a.scope == "own" and not a.target}


def state_ok(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= STATE_MAX and all(0x21 <= ord(z) <= 0x7e for z in value)


def checked_return(auth, frame: Optional[dict], value) -> Optional[str]:
    """`return` if it may be the way back, else None: it passes `link_next_ok` (a path, or `http(s)` on the host of
    `base_url` or of `trusted_redirect_hosts`, printable ASCII, no user part) and, in an app frame, lies on exactly the
    frame's host — an application sends its people back to itself, never to a neighbour."""
    if not link_next_ok(auth.cfg, value):
        return None
    if frame:
        try:
            host = (urlsplit(value).hostname or "").lower()
        except ValueError:
            return None
        return value if host == frame["host"] else None
    return value


def with_result(target: str, name: str, result: str, state: str) -> str:
    """`target` with `ts_action`, `ts_result` and, if given, `state` in its query (before a fragment)."""
    parts = urlsplit(target)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in _BACK_KEYS]
    query += [("ts_action", name), ("ts_result", result)] + ([("state", state)] if state else [])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def way_back(auth, request, ctx: dict, name: str, value: str, state: str) -> dict:
    """The way back of an action page: `{"href": {result: address}, "replaced": bool}`. A valid `return` gets the
    result; an invalid or missing one is replaced in silence — the frame's home, else the account page in the frame —
    without a result (the application's link is no stored token: refusing it would only strand the person)."""
    target = checked_return(auth, ctx.get("frame"), value) if value else None
    state = state if state_ok(state) else ""
    if target:
        return {"href": {r: with_result(target, name, r, state) for r in RESULTS}, "replaced": False}
    frame = ctx.get("frame")
    home = ctx.get("back") or (auth.browser_path(request, "/auth/account")
                              + (f"?app={quote(frame['host'], safe='')}" if frame else ""))
    return {"href": dict.fromkeys(RESULTS, home), "replaced": bool(value)}


def no_framing(resp, form_origin: Optional[str] = None):
    """The pages of a decision or an action are never framed (clickjacking) — `frame-ancestors 'none'` and
    `X-Frame-Options: DENY` whatever `csp` says: with `csp="off"` (the proxy sets the policy) and with an own policy
    as well.

    `form_origin`: the origin of a registered return address (browser entry of an approval). The decision is a form
    POST that redirects there, and Chrome checks that redirect against the page's `form-action` — so exactly that
    origin is added to an existing `form-action`, nothing else."""
    policy = resp.headers.get("content-security-policy", "")
    parts = [d.strip() for d in policy.split(";") if d.strip()]
    out = [d for d in parts if d.split(None, 1)[0].lower() != "frame-ancestors"]
    if form_origin:
        out = [f"{d} {form_origin}" if d.split(None, 1)[0].lower() == "form-action" else d for d in out]
    out.append("frame-ancestors 'none'")
    resp.headers["Content-Security-Policy"] = "; ".join(out)
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


_CSS = """
.tsmain .act-back{margin:18px 0 0}
.tsmain .act-back .btn2{display:inline-flex;align-items:center;width:auto;min-height:44px;padding:10px 18px}
.tsmain .sec button,.tsmain .btnlink{min-height:44px}
"""

#: Marks the way back as done after the first change that worked (`done()` of the account script) — and the address,
#: so a reload of the page (several sections reload after a change) keeps it.
_DONE_JS = """<script>
function tsActionDone(){const a=document.getElementById('ts_back');if(!a||a.dataset.state==='done')return;
  a.href=a.dataset.done;a.textContent=a.dataset.doneLabel;a.dataset.state='done';
  const q=new URLSearchParams(location.search);if(q.get('ts_done')!=='1'){q.set('ts_done','1');
  history.replaceState(null,'',location.pathname+'?'+q.toString()+location.hash)}}
</script>"""


def page(auth, ctx: dict) -> str:
    """An action page (template `action`, replaceable with `auth.set_template("action", fn)`): the heading in the
    application's name, the sections of the action, the way back. ctx: everything of the account page (`user`,
    `methods`, …), the frame of `_area.context`, `action` (the register entry), `available`, `way_back`, `done`."""
    from . import _area
    from . import templates as _templates
    t = auth.t
    action: Action = ctx["action"]
    if action.scope == "admin":
        return admin_page(auth, ctx)
    sections = _templates.account_sections(auth, ctx)
    body = [_area.heading(auth, ctx, t(f"act.{action.name}"))]
    if ctx.get("available"):
        body += [sections.get(s) or "" for s in action.sections]
    else:
        body.append(_templates._messages([("info", t("act.unavailable"))]))
    hrefs = ctx["way_back"]["href"]
    name = ctx.get("app_title") or ""
    cancel_label = t("act.back", name=name) if name else t("act.back_plain")
    done_label = t("act.done", name=name) if name else t("act.done_plain")
    first = "done" if ctx.get("done") else ("cancelled" if ctx.get("available") else "unavailable")
    e = _templates._e
    body.append(f"<p class=act-back><a id=ts_back class=btn2 href='{e(hrefs[first])}' data-state='{first}' "
                f"data-done='{e(hrefs['done'])}' data-done-label='{e(done_label)}'>"
                f"{e(done_label if first == 'done' else cancel_label)}</a></p>")
    if ctx.get("available"):
        body.append(_DONE_JS + _templates.account_script(
            auth, ctx, "location.pathname+(location.search?location.search+'&':'?')+'revoke_others=1'"))
    head = f"<style>{_templates.ACCOUNT_CSS}{_area._CSS}{_CSS}</style>"
    return _templates._page(auth, t(f"act.{action.name}"), "".join(body), card=False, head=head, ctx=ctx,
                            current="account")


# ---------- the page of an administration action (T-147, `_admin_actions`) ----------

_ADMIN_CSS = """
.tsmain .act-target{margin:0 0 10px}
.tsmain .act-what{margin:0 0 14px}
.tsmain .act-choice{display:flex;align-items:center;gap:10px;min-height:44px}
.tsmain .act-choice input{width:auto;min-height:0}
.tsmain .act-link{word-break:break-all;user-select:all}
.tsmain #actform button[type=submit]{min-height:44px}
"""


def admin_page(auth, ctx: dict) -> str:
    """An administration action page: the heading in the application's name, the account, what happens, the
    choices, the confirmation of this action, the way back (template `action`, built here for scope `admin`)."""
    from . import _area
    from . import templates as _t
    from ._admin_actions import ITEMS
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
    head = f"<style>{_area._CSS}{_CSS}{_ADMIN_CSS}</style>"
    return _t._page(auth, t(f"act.{action.name}"), "".join(body), card=False, head=head, ctx=ctx, current="account")

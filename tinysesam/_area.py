"""The TinySesam area of an application (T-104, surface "hybrid"): `/auth/area?app=<id>`.

The application draws its own navigation and links one entry, say *Account*, to this page; everything of TinySesam
sits behind it — tiles for the account, security, sessions, programs, approvals and, for the application's
administrators, the panel — framed with the application's name, its icon and its links, with a way back.

The frame and the way back are building blocks of their own, for every page that opens in an application's name
(T-105's action pages use them too):

* `context(auth, request, app, next_)` — what such a page needs in its ctx: `frame` (the app frame of `forward_apps`
  for the application's host, or None), `area_app` (the application id, or ""), `app_title` and `app_icon` (from
  `apps[id]`, ADR-19), `back` (where the way back leads: the frame's home, else a checked `next`, else None).
* `heading(auth, ctx, title)` — the page heading: the application's icon and name above the title.
* `back_link(auth, ctx)` — the way back as a link "Back to <application>", empty without one.

Nothing of the request becomes a link target unchecked: the frame comes from the configuration, `next` passes
`safe_next` (a path or a host of `trusted_redirect_hosts`). An unknown application changes nothing — the page shows
the tiles without a frame, so no answer tells configured from invented ids.
"""
from __future__ import annotations

import html
from typing import Optional

from . import topbar as _topbar
from ._config_check_apps import APP_ID
from .provisioning import app_name


def _e(s) -> str:
    return html.escape(str(s or ""))


def context(auth, request, app: str, next_: str = "") -> dict:
    """The ctx of a page in an application's name (see the module): frame, application, name, icon, way back."""
    cfg = auth.cfg
    apps = cfg.apps if isinstance(getattr(cfg, "apps", None), dict) else {}
    value = str(app or "").strip().lower()[:253]
    frame = auth._frame_of(value) if value else None
    app_id = value if APP_ID.match(value) and isinstance(apps.get(value), dict) else ""
    if not app_id and frame:
        app_id = frame.get("app") or ""
    entry = apps.get(app_id) if app_id else None
    title = app_name(entry, app_id, str(cfg.lang or "en")) if entry else (frame["name"] if frame else "")
    icon = entry.get("icon") if isinstance(entry, dict) else None
    back: Optional[str] = frame["home"] if frame else None
    if back is None and next_:
        checked = auth.safe_next(next_, request)
        back = checked if checked and checked == next_ else None
    return {"frame": frame, "area_app": app_id, "app_title": title,
            "app_icon": icon if isinstance(icon, str) else None, "back": back}


def heading(auth, ctx: dict, title: str) -> str:
    """The heading of a page in an application's name: icon and name of the application above `title`."""
    name = ctx.get("app_title") or ""
    if not name:
        return f"<h1>{_e(title)}</h1>"
    return (f"<div class=area-app>{_topbar.app_icon(ctx.get('app_icon'), 40, 'app-icon')}"
            f"<span>{_e(name)}</span></div><h1>{_e(title)}</h1>")


def back_link(auth, ctx: dict) -> str:
    """The way back to the application, or "" without one (no frame, no checked `next`)."""
    back = ctx.get("back")
    if not back:
        return ""
    label = auth.t("bar.back", name=ctx.get("app_title") or auth.t("area.the_app"))
    return f"<p class=area-back><a class=btn2 href='{_e(back)}'>{_e(label)}</a></p>"


_CSS = """
.tsmain .card.area{width:min(760px,92vw)}
.tsmain .area-app{display:flex;align-items:center;justify-content:center;gap:10px;color:var(--ts-muted);
     font-size:14px;margin:0 0 6px}
.tsmain .area-app .app-icon{margin:0}
.tsmain .tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin:18px 0 0}
.tsmain .tile{display:flex;flex-direction:column;gap:4px;min-height:88px;padding:14px 16px;border-radius:10px;
     border:1px solid var(--ts-line);background:var(--ts-surface);color:var(--ts-ink);text-decoration:none}
.tsmain .tile:hover,.tsmain .tile:focus-visible{border-color:var(--ts-accent)}
.tsmain .tile b{font-size:15px}
.tsmain .tile span{font-size:13px;color:var(--ts-muted)}
.tsmain .area-back{margin:18px 0 0}
.tsmain .area-back .btn2{display:inline-flex;align-items:center;width:auto;min-height:44px;padding:10px 18px}
"""


def tiles(auth, ctx: dict) -> list:
    """(key, title, state, href) of the tiles this person sees — from `account_overview` (the same source as the
    account page and `/auth/account.json`), a section only where TinySesam offers it."""
    t = auth.t
    view = ctx.get("view") or {}
    links = view.get("links") or {}
    out = []
    account = view.get("account") or {}
    if links.get("account"):
        out.append(("account", t("area.account"), account.get("display_name") or "", links["account"]))
    sign_in = view.get("sign_in") or {}
    states = []
    if sign_in.get("password") in ("set", "directory"):
        states.append(t("area.password_set"))
    totp = sign_in.get("totp")
    if totp is not None:
        states.append(t("area.totp_on") if totp.get("enabled") else t("area.totp_off"))
    passkeys = sign_in.get("passkeys")
    if passkeys is not None:
        states.append(t("area.passkeys", n=passkeys.get("count", 0)))
    security = links.get("totp") or links.get("passkeys") or links.get("account")
    if security:
        out.append(("security", t("bar.security"), " · ".join(states), security))
    if links.get("sessions"):
        out.append(("sessions", t("acc.sessions"), t("area.sessions", n=(view.get("sessions") or {}).get("count", 0)),
                    links["sessions"]))
    programs = view.get("programs") or {}
    target = links.get("devices") or links.get("services") or links.get("app_passwords")
    if target:
        count = sum(len(programs.get(k) or []) for k in ("oauth", "services", "app_passwords"))
        out.append(("programs", t("area.programs"), t("area.programs_n", n=count), target))
    approvals = view.get("approvals")
    if approvals is not None and links.get("approvals"):
        n = approvals.get("pending") or 0
        out.append(("approvals", t("bar.approvals"), t("bar.approvals_n", n=n) if n else t("area.none_pending"),
                    links["approvals"]))
    if ctx.get("administers") and getattr(auth.cfg, "admin_ui_enabled", True):
        out.append(("admin", t("acc.admin"), t("area.admin_hint"), "__TS_P__" + auth.cfg.admin_path))
    return out


def page(auth, ctx: dict) -> str:
    """The area page (template `area`, replaceable with `auth.set_template("area", fn)`)."""
    from . import templates as _templates
    t = auth.t
    body = [heading(auth, ctx, t("area.title")), "<nav class=tiles aria-label='" + _e(t("area.title")) + "'>"]
    for key, title, state, href in tiles(auth, ctx):
        body.append(f"<a class=tile data-tile={key} href='{_e(href)}'><b>{_e(title)}</b>"
                    f"<span>{_e(state)}</span></a>")
    body.append("</nav>")
    body.append(back_link(auth, ctx))
    content = f"<div class='card area'>{''.join(body)}</div>"
    head = f"<style>{_CSS}</style>"
    return _templates._page(auth, t("area.title"), content, card=False, head=head, ctx=ctx, current="account")

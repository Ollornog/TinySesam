"""The top bar of the built-in pages (T-64): logo, name, links — and on the right the account menu.

One building block for the account page, the admin panel, the setup, reauth and consent pages; the sign-in and error
pages show only logo and name. An app builds its own pages with the same bar through `auth.topbar_head()` (into
`<head>`) and `auth.topbar(request)` (first thing in `<body>`).

* **Left:** the application logo (`brand_icon` when it is a path or a `data:image/…` address, otherwise the
  built-in mark drawn in `--ts-accent`), the name (`gate_brand`, else `rp_name`) and the links of `topbar_links`.
* **Right:** the account menu — account name, "Account", "Admin panel" (admins and delegated admins, T-74), Light / Dark / System and
  "Sign out" (a POST with the CSRF field, like the sign-out confirmation page).
* **Phone:** below 640 px the links move into the menu; every tap target is at least 44 px high.
* **Keyboard:** the menu button carries `aria-expanded`; Escape closes and puts the focus back on the button, a click
  or the focus outside closes it too. The menu is a disclosure (links and buttons in a list), not an ARIA
  `role=menu` — Tab walks through it like through the page.
* **Light/dark:** the C22 switch (`theme.THEME_JS`): class `dark` on `<html>`, the choice in
  `localStorage.themeMode`, "System" removes it. The chosen entry carries `aria-pressed=true` and a check mark — never
  colour alone.

Everything is scoped to `.tsbar` (no bare selectors — they would reach the host page) and styled only through the
`--ts-*` tokens; no inline handlers, the `<style>`/`<script>` get the response's nonce.
"""
from __future__ import annotations

import html

from .theme import TOKENS, c22_css, c22_head, theme_head

#: The built-in pages that show the account menu (for a signed-in viewer); every other page shows logo and name.
MENU_PAGES = frozenset({"account", "account_setup", "gateway_home", "oauth_consent", "qr_approve", "reauth",
                        "totp_setup"})

#: Below this width the links move into the menu.
NARROW_PX = 640

#: The built-in mark: a rounded tile with a keyhole ("open sesame"). Drawn with `currentColor` for the tile and
#: the class `tsbar-hole` for the keyhole, so it follows the tokens (and C22) in light and dark.
_MARK = ("<svg class=tsbar-logo viewBox='0 0 32 32' aria-hidden=true focusable=false>"
         "<rect width='32' height='32' rx='8' fill='currentColor'/>"
         "<g class=tsbar-hole><circle cx='16' cy='13' r='4.5'/><path d='M14 15.5h4l1.4 8.5h-6.8z'/></g></svg>")

CSS = f"""
.tsbar{{position:sticky;top:0;z-index:30;background:var(--ts-surface);color:var(--ts-ink);
  border-bottom:1px solid var(--ts-line);font-family:var(--ts-font);font-size:14px;line-height:1.3}}
.tsbar *{{box-sizing:border-box}}
.tsbar .tsbar-in{{max-width:1100px;margin:0 auto;min-height:56px;padding:0 16px;display:flex;align-items:center;
  gap:16px}}
.tsbar a{{text-decoration:none}}
.tsbar .tsbar-brand{{display:flex;align-items:center;gap:10px;min-height:44px;min-width:0;color:var(--ts-ink);
  font-weight:600;font-size:15px;letter-spacing:.01em}}
.tsbar .tsbar-brand span{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.tsbar .tsbar-logo{{display:block;flex:0 0 26px;width:26px;height:26px;border-radius:7px;object-fit:contain}}
.tsbar svg.tsbar-logo{{color:var(--ts-accent)}}
.tsbar .tsbar-hole{{fill:var(--ts-accent-ink)}}
.tsbar .tsbar-links{{display:flex;align-items:center;gap:2px;min-width:0;overflow:hidden}}
.tsbar .tsbar-links a{{display:flex;align-items:center;min-height:44px;padding:0 10px;border-radius:8px;
  color:var(--ts-muted);white-space:nowrap}}
.tsbar .tsbar-links a:hover{{color:var(--ts-ink);background:var(--ts-surface-2)}}
.tsbar .tsbar-links a[aria-current=page]{{color:var(--ts-ink);text-decoration:underline;text-underline-offset:6px}}
.tsbar .tsbar-menu{{position:relative;margin-left:auto;flex:0 0 auto}}
.tsbar .tsbar-btn{{display:flex;align-items:center;gap:8px;min-height:44px;margin:0;padding:0 10px 0 6px;
  border:1px solid transparent;border-radius:999px;background:transparent;color:var(--ts-ink);font:inherit;
  cursor:pointer;width:auto}}
.tsbar .tsbar-btn:hover,.tsbar .tsbar-btn[aria-expanded=true]{{background:var(--ts-surface-2);
  border-color:var(--ts-line)}}
.tsbar .tsbar-av{{display:grid;place-items:center;width:30px;height:30px;border-radius:50%;
  background:var(--ts-chip);color:var(--ts-ink);border:1px solid var(--ts-line);font-weight:600;font-size:13px;
  text-transform:uppercase}}
.tsbar .tsbar-name{{max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.tsbar .tsbar-chev{{width:14px;height:14px;color:var(--ts-muted);transition:transform .15s}}
.tsbar .tsbar-btn[aria-expanded=true] .tsbar-chev{{transform:rotate(180deg)}}
.tsbar .tsbar-pop{{position:absolute;right:0;top:calc(100% + 6px);width:264px;max-width:calc(100vw - 24px);
  display:flex;flex-direction:column;padding:6px;background:var(--ts-surface);border:1px solid var(--ts-line);
  border-radius:var(--ts-radius)}}
.tsbar .tsbar-pop[hidden]{{display:none}}
.tsbar .tsbar-who{{padding:8px 12px 10px;font-size:12px;color:var(--ts-muted)}}
.tsbar .tsbar-who b{{display:block;margin-top:2px;color:var(--ts-ink);font-size:14px;font-weight:600;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.tsbar .tsbar-item{{display:flex;align-items:center;gap:10px;width:100%;min-height:44px;margin:0;padding:0 12px;
  border:0;border-radius:8px;background:none;color:var(--ts-ink);font:inherit;text-align:left;cursor:pointer}}
.tsbar .tsbar-item:hover{{background:var(--ts-surface-2)}}
.tsbar .tsbar-item[aria-current=page]{{font-weight:600}}
.tsbar .tsbar-item svg{{flex:0 0 18px;width:18px;height:18px;color:var(--ts-muted)}}
.tsbar .tsbar-sep{{height:1px;margin:6px 4px;background:var(--ts-line-soft)}}
.tsbar .tsbar-mlinks{{display:none;flex-direction:column}}
.tsbar .tsbar-label{{padding:6px 12px 4px;font-size:12px;color:var(--ts-muted)}}
.tsbar .tsbar-theme{{display:grid;grid-template-columns:repeat(3,1fr);gap:4px;margin:0 4px 2px;padding:3px;
  border:1px solid var(--ts-line);border-radius:10px}}
.tsbar .tsbar-theme button{{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;
  min-height:48px;margin:0;padding:4px 2px;border:1px solid transparent;border-radius:7px;background:none;
  color:var(--ts-muted);font:inherit;font-size:12px;cursor:pointer;width:auto}}
.tsbar .tsbar-theme button svg{{width:16px;height:16px}}
.tsbar .tsbar-theme button:hover{{color:var(--ts-ink)}}
.tsbar .tsbar-theme button[aria-pressed=true]{{background:var(--ts-surface-2);border-color:var(--ts-line);
  color:var(--ts-ink);font-weight:600}}
.tsbar .tsbar-theme button[aria-pressed=true] .tsbar-label-t::after{{content:" \\2713"}}
.tsbar form{{margin:0}}
.tsbar a:focus-visible,.tsbar button:focus-visible{{outline:2px solid var(--ts-link);outline-offset:2px}}
@media(max-width:{NARROW_PX}px){{
  .tsbar .tsbar-in{{gap:10px;padding:0 12px}}
  .tsbar .tsbar-links,.tsbar .tsbar-name{{display:none}}
  .tsbar .tsbar-mlinks{{display:flex}}
}}
@media(prefers-reduced-motion:reduce){{.tsbar .tsbar-chev{{transition:none}}}}
"""

# One IIFE per page, idempotent. Menu: disclosure with aria-expanded, Escape/outside click/focus leaving closes.
# Theme: the C22 switch — class `dark` on <html>, `localStorage.themeMode`, "system" removes the entry; follows a
# change of the system setting and of another tab live.
JS = """
(function(){
var bar=document.querySelector('.tsbar');if(!bar||bar.getAttribute('data-ready'))return;bar.setAttribute('data-ready','1');
var root=document.documentElement,menu=bar.querySelector('.tsbar-menu'),btn=bar.querySelector('.tsbar-btn'),
    pop=bar.querySelector('.tsbar-pop'),mq=matchMedia('(prefers-color-scheme: dark)');
function setOpen(open,back){if(!btn)return;pop.hidden=!open;btn.setAttribute('aria-expanded',open?'true':'false');
  if(!open&&back)btn.focus();}
if(btn){
  btn.addEventListener('click',function(){setOpen(pop.hidden);});
  document.addEventListener('click',function(e){if(!pop.hidden&&!menu.contains(e.target))setOpen(false);});
  document.addEventListener('keydown',function(e){if(e.key==='Escape'&&!pop.hidden){e.preventDefault();setOpen(false,true);}});
  menu.addEventListener('focusout',function(e){if(e.relatedTarget&&!menu.contains(e.relatedTarget))setOpen(false);});
}
function mode(){var m=null;try{m=localStorage.getItem('themeMode');}catch(e){}return m==='light'||m==='dark'?m:'system';}
function apply(){var m=mode();root.classList.toggle('dark',m==='dark'||(m==='system'&&mq.matches));
  bar.querySelectorAll('[data-theme-mode]').forEach(function(b){
    b.setAttribute('aria-pressed',b.getAttribute('data-theme-mode')===m?'true':'false');});}
bar.querySelectorAll('[data-theme-mode]').forEach(function(b){b.addEventListener('click',function(){
  var m=b.getAttribute('data-theme-mode');
  try{if(m==='system')localStorage.removeItem('themeMode');else localStorage.setItem('themeMode',m);}catch(e){}
  apply();});});
if(mq.addEventListener)mq.addEventListener('change',apply);
addEventListener('storage',function(e){if(e.key==='themeMode')apply();});
apply();
})();
"""

#: Icons (24 grid, strokes, currentColor) — nothing is fetched.
_ICON = {
    "chev": "<path d='M6 9l6 6 6-6'/>",
    "user": "<circle cx='12' cy='8' r='4'/><path d='M4 21c0-4 3.6-7 8-7s8 3 8 7'/>",
    "admin": "<path d='M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z'/>",
    "light": "<circle cx='12' cy='12' r='4'/><path d='M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2"
             "M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'/>",
    "dark": "<path d='M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z'/>",
    "system": "<rect x='3' y='4' width='18' height='12' rx='2'/><path d='M8 20h8M12 16v4'/>",
    "out": "<path d='M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3'/><path d='M10 17l-5-5 5-5M5 12h11'/>",
    "link": "<path d='M9 6l6 6-6 6'/>",
}


def _svg(name: str, cls: str = "") -> str:
    c = f" class={cls}" if cls else ""
    return (f"<svg{c} viewBox='0 0 24 24' fill=none stroke=currentColor stroke-width=2 stroke-linecap=round "
            f"stroke-linejoin=round aria-hidden=true focusable=false>{_ICON[name]}</svg>")


def _e(s) -> str:
    return html.escape(str(s or ""))


def _field(row, key):
    """A field of an account row — a dict or a `sqlite3.Row`; None if it has none."""
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return None


def logo(cfg) -> str:
    """The logo in the bar: `brand_icon` as an image when it is a path on the own origin or a `data:image/…`
    address (what the strict CSP's img-src allows), nothing with "none", else the built-in mark."""
    icon = getattr(cfg, "brand_icon", "") or ""
    if icon == "none":
        return ""
    if (icon.startswith("/") and not icon.startswith("//")) or icon.startswith("data:image/"):
        return f"<img class=tsbar-logo src='{_e(icon)}' alt='' width=26 height=26>"
    return _MARK


def link_visible(auth, viewer, rule) -> bool:
    """May `viewer` see a link with this visibility rule (T-76)? No rule = everyone who sees the bar's links.

    `{"admin": True}` — accounts with the admin flag. `{"role": "editors"}` — accounts with the role, decided by
    `auth.has_role`, so `admin_implies_roles` (default on) lets an admin see role links too — the same answer the
    target's own `require(role=…)` gives. Visibility is a convenience, not a protection: the target checks access
    itself. An unknown rule hides the link (fail-closed); `config_check` refuses one at the start."""
    if not rule:
        return True
    if viewer is None or not isinstance(rule, dict):
        return False
    if set(rule) == {"admin"} and rule["admin"] is True:
        return bool(_field(viewer, "is_admin"))
    if set(rule) == {"role"} and isinstance(rule["role"], str) and rule["role"]:
        return bool(auth.has_role(viewer, rule["role"]))
    return False


def visible_links(auth, viewer) -> list:
    """The (title, target) pairs of `topbar_links` that `viewer` may see — one filter for the bar, the phone menu and
    `/auth/topbar.json`. An entry is `(title, target)` (everyone) or `(title, target, rule)` (`link_visible`)."""
    out = []
    for entry in getattr(auth.cfg, "topbar_links", None) or []:
        if not isinstance(entry, (list, tuple)) or len(entry) not in (2, 3):
            continue
        if link_visible(auth, viewer, entry[2] if len(entry) == 3 else None):
            out.append((entry[0], entry[1]))
    return out


def data(auth, viewer, *, base: str) -> dict:
    """The bar as data for an application that draws its own (T-76, `GET /auth/topbar.json`): what `render` would show
    `viewer`. `base` is put in front of TinySesam's own paths (the origin of `base_url` plus the mount prefix), so a
    page on another host links back correctly. Without a viewer: no links, no menu — like the bar."""
    cfg = auth.cfg
    out: dict = {"brand": getattr(cfg, "gate_brand", "") or cfg.rp_name, "signed_in": bool(viewer), "name": None,
           "links": [], "account": {"shown": False, "href": None}, "admin_panel": {"shown": False, "href": None},
           "logout": None}
    if not viewer:
        return out
    out["name"] = str(_field(viewer, "display_name") or _field(viewer, "username") or "")
    out["links"] = [{"title": title, "href": href} for title, href in visible_links(auth, viewer)]
    if getattr(cfg, "account_enabled", True):
        out["account"] = {"shown": True, "href": f"{base}/auth/account"}
    if auth._admin_panel_visible(viewer) and getattr(cfg, "admin_ui_enabled", True):
        out["admin_panel"] = {"shown": True, "href": f"{base}{cfg.admin_path}"}
    out["logout"] = {"href": f"{base}/auth/logout"}
    return out


def render(auth, *, viewer=None, menu: bool = True, csrf: str = "", current: str = "") -> str:
    """HTML of the bar (without CSS/JS — see `CSS`, `JS`). App paths carry `__TS_P__` (the mount prefix).

    `viewer` is the signed-in account (a row with `username`, `display_name`, `is_admin`); without one, or with
    `menu=False`, only logo and name. `csrf` goes into the sign-out form, `current` ("account" | "admin" | a link
    path) marks the entry of the page shown with `aria-current=page`."""
    cfg = auth.cfg
    t = auth.t
    name = getattr(cfg, "gate_brand", "") or cfg.rp_name
    brand = (f"<a class=tsbar-brand href='__TS_P__/'>{logo(cfg)}<span>{_e(name)}</span></a>")
    if not (menu and viewer):
        return f"<header class=tsbar><div class=tsbar-in>{brand}</div></header>"
    links = visible_links(auth, viewer)

    def cur(key):
        return " aria-current=page" if key and key == current else ""

    bar_links = "".join(f"<a href='{_e(h)}'{cur(h)}>{_e(title)}</a>" for title, h in links)
    nav = f"<nav class=tsbar-links aria-label='{_e(t('bar.links'))}'>{bar_links}</nav>" if links else ""
    shown = _field(viewer, "display_name") or _field(viewer, "username") or "?"
    items = []
    if links:
        items.append("<div class=tsbar-mlinks>"
                     + "".join(f"<a class=tsbar-item href='{_e(h)}'{cur(h)}>{_svg('link')}{_e(title)}</a>"
                               for title, h in links)
                     + "<div class=tsbar-sep></div></div>")
    if getattr(cfg, "account_enabled", True):
        items.append(f"<a class=tsbar-item href='__TS_P__/auth/account'{cur('account')}>{_svg('user')}"
                     f"{_e(t('bar.account'))}</a>")
    if auth._admin_panel_visible(viewer) and getattr(cfg, "admin_ui_enabled", True):
        items.append(f"<a class=tsbar-item href='{_e('__TS_P__' + cfg.admin_path)}'{cur('admin')}>{_svg('admin')}"
                     f"{_e(t('acc.admin'))}</a>")
    if items:
        items.append("<div class=tsbar-sep></div>")
    theme = "".join(f"<button type=button data-theme-mode={m} aria-pressed=false>{_svg(m)}"
                    f"<span class=tsbar-label-t>{_e(t('bar.' + m))}</span></button>"
                    for m in ("light", "dark", "system"))
    items.append(f"<div class=tsbar-label id=tsbar-tl>{_e(t('bar.theme'))}</div>"
                 f"<div class=tsbar-theme role=group aria-labelledby=tsbar-tl>{theme}</div>"
                 "<div class=tsbar-sep></div>")
    items.append(f"<form method=post action='__TS_P__/auth/logout'>"
                 f"<input type=hidden name=_csrf value='{_e(csrf)}'>"
                 f"<button type=submit class=tsbar-item>{_svg('out')}{_e(t('logout'))}</button></form>")
    menu_html = (f"<div class=tsbar-menu>"
                 f"<button type=button class=tsbar-btn aria-expanded=false aria-controls=tsbar-pop "
                 f"aria-label='{_e(t('bar.menu', name=shown))}'>"
                 f"<span class=tsbar-av aria-hidden=true>{_e(str(shown)[:1])}</span>"
                 f"<span class=tsbar-name>{_e(shown)}</span>{_svg('chev', 'tsbar-chev')}</button>"
                 f"<div class=tsbar-pop id=tsbar-pop hidden>"
                 f"<div class=tsbar-who>{_e(t('bar.signed_in_as'))}<b>{_e(shown)}</b></div>"
                 + "".join(items) + "</div></div>")
    return f"<header class=tsbar><div class=tsbar-in>{brand}{nav}{menu_html}</div></header>"


def assets() -> str:
    """`<style>` + `<script>` of the bar for a built-in page (TOKENS are already on it)."""
    return f"<style>{CSS}</style><script>{JS}</script>"


def head_for_app(cfg) -> str:
    """What an app puts into its own page's `<head>` to use the bar: the light/dark restore, the tokens (plus
    the C22 adapter and stylesheet when `c22_stylesheet` is set) and the bar's CSS. `brand_css` is left out —
    it may carry rules for TinySesam's own pages; an app sets its `--ts-*` values in its own stylesheet."""
    return f"{theme_head()}{c22_head(cfg)}<style>{TOKENS}{c22_css(cfg)}{CSS}</style>"
